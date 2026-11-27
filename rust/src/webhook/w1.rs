//! The Jack `w1` signature of spec 06 section 4 (R4.1-R4.6): the header
//! grammar, the seven-line signing string, signing, and the receiver-side
//! check of step 15 of the section 3 order table.
//!
//! Everything here is pure: no clock, no I/O, no logging. `verify` takes
//! `now` and `window` from the caller, tries its checks in the spec order and
//! stops at the first failure; every rejection carries the spec-assigned
//! status and code, and its message is a fixed literal, so no header value,
//! key byte or body byte can reach an error (spec 06 section 3, R4.1).
//!
//! Unlike the Standard Webhooks values of section 2, the Jack values are
//! canonical unpadded base64url (spec 06 R4.1, R4.2).

use crate::user_key::ServerSigningKey;

use crate::encoding::{body_hash, decode_b64url_fixed, encode_b64url};
use crate::webhook::signatures::ServerKey;
use crate::webhook::{codes, WebhookError};

/// The `w1` scheme literal (spec 06 R4.1).
pub const W1_SCHEME: &str = "w1";

/// The exact `kid` length in characters, i.e. the length of the unpadded
/// base64url of a SHA-256 digest (spec 06 R4.1, R4.5).
pub const KID_LEN: usize = 43;

/// The exact `sig` length in characters, i.e. the length of the unpadded
/// base64url of a 64-byte Ed25519 signature (spec 06 R4.1, R4.2).
pub const SIG_LEN: usize = 86;

/// The single SP between the scheme and the parameters (spec 06 R4.1).
const SP: char = ' ';

/// The decoded length of a `w1` Ed25519 signature (spec 06 R4.2).
const SIG_BYTES: usize = 64;

/// The literal first line of the signing string (spec 06 R4.2).
const SIGNING_STRING_FIRST_LINE: &str = "mcp-jack/webhook1/delivery";

/// The longest timestamp, in characters, that `^(0|[1-9][0-9]{0,11})$`
/// admits (spec 06 R4.2, R4.4).
const TIMESTAMP_MAX_DIGITS: usize = 12;

/// The fixed `missing_jack_auth` message (spec 06 R4.6).
const MISSING_MESSAGE: &str = "the Jack-Webhook-Auth header is required";

/// The fixed `malformed_jack_auth` message (spec 06 R4.1).
const MALFORMED_MESSAGE: &str = "the Jack-Webhook-Auth header is malformed";

/// The fixed `webhook_key_is_server_key` message (spec 06 R4.5).
const SERVER_KEY_MESSAGE: &str = "the w1 kid names the MCP server key";

/// The fixed `unknown_webhook_key` message (spec 06 R4.5).
const UNKNOWN_KEY_MESSAGE: &str = "the w1 kid is not an accepted webhook key";

/// The fixed `jack_timestamp_out_of_window` message (spec 06 R4.4).
const OUT_OF_WINDOW_MESSAGE: &str = "the w1 timestamp is outside the Jack window";

/// The fixed `bad_jack_signature` message (spec 06 R4.2).
const BAD_SIGNATURE_MESSAGE: &str = "the w1 signature does not verify";

/// The fields a `w1` signature covers, borrowed from the delivery
/// (spec 06 R4.2, R4.3).
///
/// Every field is signed as sent: `aud` comes from the receiver
/// configuration, the subscription id from `X-MCP-Subscription-Id`, the
/// timestamp and webhook id from their headers, and `callback_url` is the
/// exact `delivery.url` byte string; none of them is normalized here
/// (spec 06 R4.3). The body is kept as raw bytes and never parsed,
/// re-serialized or normalized (spec 06 R4.2).
#[derive(Debug, Clone, Copy)]
pub struct JackSigningParts<'a> {
    /// The Jack audience the receiver is configured with, never taken from
    /// the request (spec 06 R4.3).
    pub aud: &'a str,
    /// The subscription id from `X-MCP-Subscription-Id` (spec 06 R4.3).
    pub subscription_id: &'a str,
    /// The `webhook-id` header value, verbatim (spec 06 R4.2).
    pub webhook_id: &'a str,
    /// The `webhook-timestamp` header value, verbatim (spec 06 R4.2).
    pub timestamp: &'a str,
    /// The exact `delivery.url` the subscription was created with
    /// (spec 06 R4.3).
    pub callback_url: &'a str,
    /// The raw request body bytes, unmodified (spec 06 R4.2).
    pub body: &'a [u8],
}

/// Returns the seven-line signing string of `w1` (spec 06 R4.2).
///
/// The lines are the literal `mcp-jack/webhook1/delivery`, then `aud`, the
/// subscription id, `webhook-id`, `webhook-timestamp`, `callback-url` and
/// `body-hash`, joined with LF and with no trailing LF. `body-hash` is
/// `base64url(SHA-256(raw body bytes))` (spec 06 R4.2).
pub fn signing_string(parts: &JackSigningParts<'_>) -> String {
    let hash = body_hash(parts.body);
    [
        SIGNING_STRING_FIRST_LINE,
        parts.aud,
        parts.subscription_id,
        parts.webhook_id,
        parts.timestamp,
        parts.callback_url,
        hash.as_str(),
    ]
    .join("\n")
}

/// Renders the `Jack-Webhook-Auth` value of a delivery (spec 06 R4.2).
///
/// The signing string is signed with the webhook signing key and the 64-byte
/// signature is rendered as canonical unpadded base64url, which always gives
/// the 86 characters R4.1 requires; the result is
/// `"w1 kid=<kid>,sig=<sig>"` (spec 06 R4.1, R4.2).
pub fn sign(key: &ServerSigningKey, kid: &str, parts: &JackSigningParts<'_>) -> String {
    let message = signing_string(parts);
    let signature = key.sign(message.as_bytes());
    format!("{W1_SCHEME} kid={kid},sig={}", encode_b64url(&signature))
}

/// The two parameters of a parsed `Jack-Webhook-Auth` value (spec 06 R4.1).
///
/// Both values stay encoded: the grammar never decodes, so the signature is
/// decoded only at the verification step of R4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JackHeader {
    /// The `kid` value, 43 characters of unpadded base64url (spec 06 R4.1).
    pub kid: String,
    /// The `sig` value, 86 characters of unpadded base64url (spec 06 R4.1).
    pub sig: String,
}

/// Parses a `Jack-Webhook-Auth` value (spec 06 R4.1).
///
/// Accepts the literal scheme `w1`, exactly one SP, then parameters separated
/// by a single `,` with no whitespace: the set is exactly `kid` and `sig`,
/// once each, in any order, each value matching `[A-Za-z0-9_-]+` with `kid`
/// 43 characters and `sig` 86 characters. Any violation — including an empty
/// or non-`w1` value — is `400 malformed_jack_auth`, with no header byte in
/// the error.
pub fn parse_header(value: &str) -> Result<JackHeader, WebhookError> {
    let rest = match value.strip_prefix(W1_SCHEME) {
        Some(rest) => rest,
        None => return Err(malformed()),
    };
    let rest = match rest.strip_prefix(SP) {
        Some(rest) => rest,
        None => return Err(malformed()),
    };
    if rest.is_empty() || rest.chars().any(char::is_whitespace) {
        return Err(malformed());
    }
    let mut kid: Option<String> = None;
    let mut sig: Option<String> = None;
    for part in rest.split(',') {
        let equals = match part.find('=') {
            Some(equals) if equals > 0 && equals < part.len() - 1 => equals,
            _ => return Err(malformed()),
        };
        let (name, value) = part.split_at(equals);
        let param_value = &value[1..];
        let slot = match name {
            "kid" => &mut kid,
            "sig" => &mut sig,
            _ => return Err(malformed()),
        };
        if !param_value.bytes().all(is_b64url_byte) {
            return Err(malformed());
        }
        if slot.replace(param_value.to_owned()).is_some() {
            return Err(malformed());
        }
    }
    match (kid, sig) {
        (Some(kid), Some(sig)) if kid.len() == KID_LEN && sig.len() == SIG_LEN => {
            Ok(JackHeader { kid, sig })
        }
        _ => Err(malformed()),
    }
}

/// Checks a `w1` header and returns its `kid` on success (spec 06 R4.2-R4.6,
/// step 15 of the section 3 order table).
///
/// The checks run in the order of the spec and the first failure wins:
/// an absent header is `401 missing_jack_auth` (R4.6); a grammar violation is
/// `400 malformed_jack_auth` (R4.1); a `kid` equal to `mcp_server_kid` is
/// `401 webhook_key_is_server_key`, before any key lookup (R4.5); a `kid`
/// that is not an accepted key is `401 unknown_webhook_key` (R4.5); a
/// timestamp outside `^(0|[1-9][0-9]{0,11})$` or with `|now - ts| > window`
/// is `401 jack_timestamp_out_of_window` (R4.4); and a signature that does
/// not decode to 64 bytes or does not verify under the selected key is
/// `401 bad_jack_signature` (R4.2).
pub fn verify<K: ServerKey>(
    header_value: Option<&str>,
    parts: &JackSigningParts<'_>,
    keys: &[K],
    now: i64,
    window: i64,
    mcp_server_kid: Option<&str>,
) -> Result<String, WebhookError> {
    let value = match header_value {
        Some(value) => value,
        None => return Err(missing()),
    };
    let header = parse_header(value)?;
    if mcp_server_kid == Some(header.kid.as_str()) {
        return Err(WebhookError::new(
            401,
            codes::WEBHOOK_KEY_IS_SERVER_KEY,
            SERVER_KEY_MESSAGE,
        ));
    }
    let key = match keys.iter().find(|key| key.kid() == header.kid) {
        Some(key) => key,
        None => {
            return Err(WebhookError::new(
                401,
                codes::UNKNOWN_WEBHOOK_KEY,
                UNKNOWN_KEY_MESSAGE,
            ))
        }
    };
    if !timestamp_ok(parts.timestamp) || !within_window(parts.timestamp, now, window) {
        return Err(out_of_window());
    }
    let signature = match decode_b64url_fixed(&header.sig, SIG_BYTES) {
        Ok(signature) => signature,
        Err(_) => return Err(bad_signature()),
    };
    let message = signing_string(parts);
    if !key.verify(message.as_bytes(), &signature) {
        return Err(bad_signature());
    }
    Ok(header.kid)
}

/// Reports whether `byte` is in the base64url alphabet of the R4.1 values,
/// padding excluded (spec 06 R4.1).
fn is_b64url_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'_'
}

/// Reports whether `timestamp` matches `^(0|[1-9][0-9]{0,11})$`
/// (spec 06 R4.2, R4.4).
///
/// The accepted form is a single `0` or one to twelve decimal digits with no
/// leading zero: enough to express any second-based instant and small enough
/// that the value always fits an `i64`.
fn timestamp_ok(timestamp: &str) -> bool {
    let bytes = timestamp.as_bytes();
    if bytes == b"0" {
        return true;
    }
    !bytes.is_empty()
        && bytes.len() <= TIMESTAMP_MAX_DIGITS
        && bytes[0] != b'0'
        && bytes.iter().all(u8::is_ascii_digit)
}

/// Reports whether `|now - timestamp| <= window` (spec 06 R4.4).
///
/// `timestamp` must already have passed `timestamp_ok`; the difference is
/// taken in `i128` so neither a large timestamp nor a large `now` can
/// overflow. A negative `window` admits nothing.
fn within_window(timestamp: &str, now: i64, window: i64) -> bool {
    let seconds = match timestamp.parse::<i64>() {
        Ok(seconds) => seconds,
        Err(_) => return false,
    };
    let difference = i128::from(now) - i128::from(seconds);
    difference.abs() <= i128::from(window)
}

/// Builds the `missing_jack_auth` rejection (spec 06 R4.6).
fn missing() -> WebhookError {
    WebhookError::new(401, codes::MISSING_JACK_AUTH, MISSING_MESSAGE)
}

/// Builds the `malformed_jack_auth` rejection with a fixed literal message
/// (spec 06 R4.1).
fn malformed() -> WebhookError {
    WebhookError::new(400, codes::MALFORMED_JACK_AUTH, MALFORMED_MESSAGE)
}

/// Builds the `jack_timestamp_out_of_window` rejection (spec 06 R4.4).
fn out_of_window() -> WebhookError {
    WebhookError::new(
        401,
        codes::JACK_TIMESTAMP_OUT_OF_WINDOW,
        OUT_OF_WINDOW_MESSAGE,
    )
}

/// Builds the `bad_jack_signature` rejection (spec 06 R4.2).
fn bad_signature() -> WebhookError {
    WebhookError::new(401, codes::BAD_JACK_SIGNATURE, BAD_SIGNATURE_MESSAGE)
}
