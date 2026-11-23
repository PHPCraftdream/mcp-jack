//! The closed code, status and fixed-message table of the receiver
//! (spec 06 section 3, R3.1-R3.18, R4.5, R4.6, R7.6): every rejection the
//! receiver can answer with, its HTTP status, its retryability and the one
//! sentence of its error answer.
//!
//! This module mirrors the `ERRORS` object of
//! `spec/tools/modern/webhooks/ref/receiver.mjs` entry for entry, so no code
//! outside the table is ever used and every message is a fixed literal. A
//! message therefore cannot name the selected secret, a header value, an
//! earlier response body or any other byte the receiver holds, which is the
//! spec 06 section 3 rule this module exists to keep: **no secret in an
//! error**. The error body carries exactly the `code` and that fixed
//! `message`, under one `error` member, and nothing else.

use serde_json::{json, Value};

use crate::webhook::{codes, WebhookError};

/// The largest raw body a receiver accepts, in bytes (spec 06 R1.2, R3.6).
///
/// It is the sender's `delivery::MAX_BODY_BYTES`; a larger body, or a larger
/// declared `Content-Length`, is `413 body_too_large` and is refused before
/// the body is read.
pub const MAX_BODY_BYTES: usize = crate::webhook::delivery::MAX_BODY_BYTES;

/// The status of a code that is not in the closed table.
///
/// The receiver never answers with it: `rejection` is called with a table
/// code only, so this is the defensive branch of a programmer error.
const UNKNOWN_CODE_STATUS: u16 = 500;

/// The fixed message of a code that is not in the closed table
/// (spec 06 section 3).
const UNKNOWN_CODE_MESSAGE: &str = "unknown receiver code";

/// Returns the HTTP status and the fixed message of one closed code
/// (spec 06 section 3, the `ERRORS` table of R3.1-R3.18).
///
/// The strings are copied verbatim from the reference receiver, so
/// `body_too_large` answers `body or declared length above the limit` and
/// `subscription_not_routed` answers `the subscription is not routed`. A code
/// outside the table yields `None`; `rejection` turns that into its documented
/// fallback.
fn table(code: &str) -> Option<(u16, &'static str)> {
    Some(match code {
        codes::MISSING_WEBHOOK_HEADER => (400, "a required header is absent"),
        codes::DUPLICATE_WEBHOOK_HEADER => (400, "a required header is repeated"),
        codes::MALFORMED_WEBHOOK_ID => (400, "webhook-id grammar"),
        codes::MALFORMED_WEBHOOK_TIMESTAMP => (400, "webhook-timestamp grammar"),
        codes::MALFORMED_SUBSCRIPTION_ID => (400, "subscription id grammar"),
        codes::BODY_TOO_LARGE => (413, "body or declared length above the limit"),
        codes::UNKNOWN_SUBSCRIPTION => (401, "no secret applies to the subscription"),
        codes::SUBSCRIPTION_NOT_ROUTED => (503, "the subscription is not routed"),
        codes::SUBSCRIPTION_TERMINATED => (410, "the subscription is terminated"),
        codes::STALE_TIMESTAMP => (401, "timestamp too old"),
        codes::FUTURE_TIMESTAMP => (401, "timestamp too far ahead"),
        codes::MALFORMED_SIGNATURE_HEADER => (400, "signature header grammar"),
        codes::UNSUPPORTED_SIGNATURE_SCHEME => (400, "unsupported signature scheme"),
        codes::MALFORMED_SIGNATURE => (400, "signature value length"),
        codes::BAD_SIGNATURE => (401, "signature does not verify"),
        codes::BAD_SERVER_SIGNATURE => (401, "server signature does not verify"),
        codes::NO_SERVER_KEYS => (503, "no accepted server key"),
        codes::MISSING_JACK_AUTH => (401, "jack header absent"),
        codes::MALFORMED_JACK_AUTH => (400, "jack header grammar"),
        codes::WEBHOOK_KEY_IS_SERVER_KEY => (401, "the webhook key is the mcp server key"),
        codes::UNKNOWN_WEBHOOK_KEY => (401, "unknown webhook key"),
        codes::JACK_TIMESTAMP_OUT_OF_WINDOW => (401, "jack timestamp outside the window"),
        codes::BAD_JACK_SIGNATURE => (401, "jack signature does not verify"),
        codes::WEBHOOK_KEY_MISMATCH => (401, "the webhook key sources disagree"),
        codes::WEBHOOK_KEY_MISSING => (401, "the webhook key source is missing"),
        codes::ENQUEUE_FAILED => (503, "durable enqueue failed"),
        codes::MALFORMED_BODY => (400, "body is not a json object"),
        codes::UNKNOWN_ENVELOPE_TYPE => (400, "unknown envelope type"),
        _ => return None,
    })
}

/// Builds the rejection of one closed code, with the exact status and the
/// exact fixed message the table assigns it (spec 06 section 3).
///
/// The returned [`WebhookError`] carries the code, that status and that
/// literal message, so rendering it can never expose a secret, a header value
/// or a body byte: the message is a constant and the code is a wire name.
/// A code outside the closed table is a programmer error; it yields HTTP
/// `500` with the fixed message `unknown receiver code` rather than a panic,
/// and no receiver path passes such a code.
pub fn rejection(code: &'static str) -> WebhookError {
    match table(code) {
        Some((status, message)) => WebhookError::new(status, code, message),
        None => WebhookError::new(UNKNOWN_CODE_STATUS, code, UNKNOWN_CODE_MESSAGE),
    }
}

/// Returns the HTTP status of a closed code, or `None` for a code the
/// receiver never answers with (spec 06 section 3).
pub fn code_status(code: &str) -> Option<u16> {
    table(code).map(|(status, _)| status)
}

/// Reports whether a closed code is retryable (spec 06 section 3).
///
/// Exactly three codes are retryable: `subscription_not_routed`,
/// `no_server_keys` and `enqueue_failed`, all answered `503`. Every other code
/// is final for that message, and a code outside the table is not retryable
/// either.
pub fn code_is_retryable(code: &str) -> bool {
    matches!(
        code,
        codes::SUBSCRIPTION_NOT_ROUTED | codes::NO_SERVER_KEYS | codes::ENQUEUE_FAILED
    )
}

/// Returns the sender-side `lastError` category of a closed code's answer
/// (spec 06 R1.7, R1.9).
///
/// A `4xx` answer, including the final `410` and `413`, is `http_4xx`, and a
/// `5xx` answer, including the retryable `503`, is `http_5xx`; the mapping is
/// the one `delivery::last_error_of` applies to every attempt. A code outside
/// the table has no category and yields `None`. The category is a fixed
/// literal, so it never carries a secret, a header value or a body byte
/// (spec 06 section 3).
pub fn code_last_error(code: &str) -> Option<crate::webhook::delivery::LastError> {
    code_status(code).and_then(crate::webhook::delivery::last_error_of)
}

/// The answer of one delivery: the status, the JSON body, the message
/// objects forwarded to the application, the code on a rejection and whether
/// the `webhook-id` was recorded (spec 06 section 3, R3.16-R3.18).
///
/// A rejection body is exactly `{"error":{"code":..,"message":..}}` with the
/// table's fixed message, so it never names the selected secret, a header
/// value or a body byte. `recorded` is `true` only after the durable enqueue
/// succeeded and the `2xx` was returned (spec 06 R1.10, R3.16).
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryOutcome {
    /// The HTTP status of the answer (spec 06 section 3).
    pub status: u16,
    /// The JSON body of the answer (spec 06 section 3).
    pub body: Value,
    /// The parsed message objects forwarded unchanged; empty on a rejection,
    /// on a duplicate and on a `verification` echo (spec 06 R3.18).
    pub delivered: Vec<Value>,
    /// The wire code on a rejection, `None` on a `2xx` (spec 06 section 3).
    pub code: Option<String>,
    /// Whether the `webhook-id` is now recorded, so a retry answers
    /// `duplicate` (spec 06 R1.10, R3.16).
    pub recorded: bool,
}

impl DeliveryOutcome {
    /// Builds the `2xx` answer of one accepted delivery (spec 06 R3.18).
    pub(crate) fn ok(status: u16, body: Value, recorded: bool) -> Self {
        Self {
            status,
            body,
            delivered: Vec::new(),
            code: None,
            recorded,
        }
    }

    /// Builds the error answer of one rejection: the table's status and fixed
    /// message under exactly one `error` member, and nothing else
    /// (spec 06 section 3).
    ///
    /// Only the code and the fixed message are copied, so the answer never
    /// leaks the selected `WebhookSecret` or any other receiver-held byte.
    pub(crate) fn from_error(error: &WebhookError) -> Self {
        Self {
            status: error.http_status,
            body: json!({
                "error": {
                    "code": error.code,
                    "message": error.message,
                }
            }),
            delivered: Vec::new(),
            code: Some(error.code.to_owned()),
            recorded: false,
        }
    }
}
