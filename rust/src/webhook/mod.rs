//! Webhook delivery profile of spec 06: the Standard Webhooks secret and
//! signature rules (section 2), the Jack `w1` signature (section 4) and its
//! receiver-side check (section 3, step 15), the subscription lifecycle
//! (section 8), endpoint verification (section 5), the SSRF-hardened delivery
//! path (section 6), the server-neutral receiver (section 3) and Server Card
//! key discovery (section 7), as laid out in
//! `docs/design/mcp-2026-07-28.md` section 6.1.
//!
//! The wrapped MCP server owns subscriptions, events and cursors, and this
//! module supplies only the building blocks a Jack sender and receiver are
//! made of: the canonical subscription key and id, the TTL grant,
//! active-secret selection with grace, the `gap` and `terminated` envelopes,
//! the sender, the receiver, endpoint verification, the SSRF-hardened delivery
//! path and Server Card discovery (spec 06, design section 6.1). It
//! deliberately provides no authenticated subscribe/unsubscribe endpoint and
//! no subscription store.
//!
//! Submodules, one line each:
//!
//! * [`subscription`] — the canonical subscription key and `sub_` id, the TTL
//!   grant with `refreshBefore`, secret rotation and the exact `gap` and
//!   `terminated` bodies (section 8).
//! * [`delivery`] — the sender's timeout caps, closed `lastError` categories,
//!   retry schedule and accept/retry/abandon decision (R1.6-R1.10).
//! * [`signatures`] — the `v1`/`v1a`/`v2a` signing content and
//!   `webhook-signature` header grammar (section 2).
//! * [`w1`] — the Jack `w1` header, signing string, signer and check
//!   (section 4).
//! * [`encoding`] — canonical standard base64, SHA-256, HMAC-SHA-256,
//!   constant-time comparison and the delivery secret (section 2).
//! * [`ssrf`] — the delivery-time host, address and url rules plus the
//!   `ConnectTarget` decision (section 6).
//! * [`verification`] — the endpoint verification routes, their cache and the
//!   per-pair delivery gate (section 5).
//! * [`receiver`] — the framework-neutral receiver: bounded body collection,
//!   the verification order, deduplication and the answer rendering
//!   (section 3).
//! * [`card`] — Server Card discovery and the operational signing key source
//!   with its R7.3 validator and R7.6 cross-check (section 7).
//! * `http` (feature `http`) — the spawn-free sender loop, the well-known
//!   document fetcher, the request/response adapters and the hardened
//!   delivery decision; its `https` submodule (feature `client-http`) adds the
//!   concrete TLS dialer.
//!
//! Features follow the pure/impure split: the pure layer — `subscription`,
//! `delivery`, `signatures`, `w1`, `encoding`, `ssrf`, `verification`,
//! `receiver` and `card` — compiles with no feature at all; `http` adds the
//! spawn-free sender, document fetcher and adapters; `client-http` adds the
//! concrete TLS dialer (`SystemResolver`, `HttpsTransport` and
//! `HttpCardTransport`).
//!
//! Nothing on an acceptance path parses an unverified body, logs a header
//! value or puts request bytes into an error: every rejection carries the
//! status and code the spec assigns and a message that is a fixed literal
//! (spec 06 section 3).

pub mod card;
pub mod delivery;
pub mod encoding;
#[cfg(feature = "http")]
pub mod http;
pub mod receiver;
pub mod signatures;
pub mod ssrf;
pub mod subscription;
pub mod verification;
pub mod w1;

#[cfg(test)]
mod tests;

use std::fmt;

/// A webhook rejection with the HTTP status and code the spec assigns
/// (spec 06 section 3s closed code list).
///
/// `reason` is an optional machine-readable discriminator that only some
/// codes carry; it is a fixed literal, never a request byte, so it is safe to
/// log. `message` is free text and MUST NOT name a secret, a header value or
/// a body byte (spec 06 section 3, error answer rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookError {
    /// HTTP status of the rejection (spec 06 section 3).
    pub http_status: u16,
    /// Wire code of the rejection (spec 06 section 3).
    pub code: &'static str,
    /// Optional fixed-literal discriminator, e.g. the secret reason of R2.1.
    pub reason: Option<String>,
    /// Human-readable text; never derived from request bytes.
    pub message: String,
}

impl WebhookError {
    /// Builds a rejection without a reason (spec 06 section 3).
    pub fn new(http_status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            http_status,
            code,
            reason: None,
            message: message.into(),
        }
    }

    /// Builds a rejection with a fixed-literal reason, e.g. the R2.1
    /// `prefix|alphabet|padding|canonical|length` discriminator.
    pub fn with_reason(
        http_status: u16,
        code: &'static str,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            http_status,
            code,
            reason: Some(reason.into()),
            message: message.into(),
        }
    }

    /// Returns the wire code (spec 06 section 3).
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the optional fixed-literal reason, never a request byte
    /// (spec 06 section 2, R2.1).
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl fmt::Display for WebhookError {
    /// Prints the code, the optional reason and the message only: a webhook
    /// error must never render a secret or a body byte (spec 06 section 3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "jack: webhook: {} ({reason})", self.code)?,
            None => write!(f, "jack: webhook: {}", self.code)?,
        }
        if self.message.is_empty() {
            Ok(())
        } else {
            write!(f, ": {}", self.message)
        }
    }
}

impl std::error::Error for WebhookError {}

/// Error codes of the webhook profile; the string values are the wire codes
/// of the spec 06 section 3 table.
pub mod codes {
    /// A required delivery header is absent (HTTP 400, spec 06 R3.1).
    pub const MISSING_WEBHOOK_HEADER: &str = "missing_webhook_header";
    /// A required delivery header is repeated (HTTP 400, spec 06 R3.2).
    pub const DUPLICATE_WEBHOOK_HEADER: &str = "duplicate_webhook_header";
    /// The `webhook-id` header violates `^[A-Za-z0-9_-]{8,128}$`
    /// (HTTP 400, spec 06 R1.4, R3.3).
    pub const MALFORMED_WEBHOOK_ID: &str = "malformed_webhook_id";
    /// The `webhook-timestamp` header violates `^(0|[1-9][0-9]{0,11})$`
    /// (HTTP 400, spec 06 R1.5, R3.4).
    pub const MALFORMED_WEBHOOK_TIMESTAMP: &str = "malformed_webhook_timestamp";
    /// The `X-MCP-Subscription-Id` header is outside `^sub_[0-9a-f]{16}$`
    /// (HTTP 400, spec 06 R3.5).
    pub const MALFORMED_SUBSCRIPTION_ID: &str = "malformed_subscription_id";
    /// The raw body or the declared `Content-Length` is above 262144 bytes
    /// (HTTP 413, spec 06 R1.2, R3.6).
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    /// Neither a registered nor a pending secret applies to the subscription
    /// id (HTTP 401, spec 06 R3.7).
    pub const UNKNOWN_SUBSCRIPTION: &str = "unknown_subscription";
    /// An event or forwarded envelope arrived for an id not routed yet
    /// (HTTP 503, spec 06 R3.8).
    pub const SUBSCRIPTION_NOT_ROUTED: &str = "subscription_not_routed";
    /// A delivery arrived for a subscription id marked terminated
    /// (HTTP 410, spec 06 R3.17).
    pub const SUBSCRIPTION_TERMINATED: &str = "subscription_terminated";
    /// The `webhook-timestamp` is more than the window old (HTTP 401,
    /// spec 06 R3.9).
    pub const STALE_TIMESTAMP: &str = "stale_timestamp";
    /// The `webhook-timestamp` is more than the window ahead (HTTP 401,
    /// spec 06 R3.9).
    pub const FUTURE_TIMESTAMP: &str = "future_timestamp";
    /// Identity is enforced and the accepted key set is empty (HTTP 503,
    /// spec 06 R3.14).
    pub const NO_SERVER_KEYS: &str = "no_server_keys";
    /// The durable enqueue failed, so the message is not acknowledged
    /// (HTTP 503, spec 06 R1.10, R3.17).
    pub const ENQUEUE_FAILED: &str = "enqueue_failed";
    /// The body is not a JSON object, or an envelope field fails validation
    /// (HTTP 400, spec 06 R1.3, R3.18).
    pub const MALFORMED_BODY: &str = "malformed_body";
    /// The `type` member is present but is not `gap`, `terminated` or
    /// `verification` (HTTP 400, spec 06 R1.3, R3.18).
    pub const UNKNOWN_ENVELOPE_TYPE: &str = "unknown_envelope_type";
    /// The `delivery.secret` is not `whsec_` plus canonical standard base64
    /// of 24-64 bytes (HTTP 400, spec 06 section 2, R2.1).
    pub const INVALID_SECRET: &str = "invalid_secret";
    /// The `webhook-signature` header violates the R2.4 grammar (HTTP 400).
    pub const MALFORMED_SIGNATURE_HEADER: &str = "malformed_signature_header";
    /// A signature scheme is not `v1`, `v1a` or `v2a` (HTTP 400, spec 06 R3.11).
    pub const UNSUPPORTED_SIGNATURE_SCHEME: &str = "unsupported_signature_scheme";
    /// A signature value is not canonical standard base64 of 32 (`v1`) or 64
    /// (`v1a`, `v2a`) bytes (HTTP 400, spec 06 R3.12).
    pub const MALFORMED_SIGNATURE: &str = "malformed_signature";
    /// No `v1` entry verifies with the selected secret (HTTP 401, spec 06 R3.13).
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// No `v1a` or `v2a` entry verifies with an accepted key (HTTP 401,
    /// spec 06 R3.14).
    pub const BAD_SERVER_SIGNATURE: &str = "bad_server_signature";
    /// `w1` is configured and the header is absent (HTTP 401, spec 06 R4.6).
    pub const MISSING_JACK_AUTH: &str = "missing_jack_auth";
    /// The header is outside the R4.1 grammar (HTTP 400, spec 06 R4.1).
    pub const MALFORMED_JACK_AUTH: &str = "malformed_jack_auth";
    /// The `w1` `kid` names the configured MCP server key (HTTP 401,
    /// spec 06 R4.5).
    pub const WEBHOOK_KEY_IS_SERVER_KEY: &str = "webhook_key_is_server_key";
    /// The `kid` is not an accepted card key (HTTP 401, spec 06 R4.5).
    pub const UNKNOWN_WEBHOOK_KEY: &str = "unknown_webhook_key";
    /// The `w1` timestamp is outside the Jack window (HTTP 401, spec 06 R4.4).
    pub const JACK_TIMESTAMP_OUT_OF_WINDOW: &str = "jack_timestamp_out_of_window";
    /// The `w1` signature does not verify (HTTP 401, spec 06 R4.2).
    pub const BAD_JACK_SIGNATURE: &str = "bad_jack_signature";
    /// The card url is not an `https` url (spec 06 R7.2).
    pub const NOT_HTTPS: &str = "not_https";
    /// The card url is not the MCP endpoint's origin (spec 06 R7.2).
    pub const CROSS_ORIGIN: &str = "cross_origin";
    /// The card fetch was answered with a redirect (spec 06 R7.2).
    pub const REDIRECT_REFUSED: &str = "redirect_refused";
    /// The card fetch was answered with a status outside `2xx`
    /// (spec 06 R7.2).
    pub const HTTP_STATUS: &str = "http_status";
    /// The card fetch exceeded the 10 s wall-clock cap (spec 06 R7.2).
    pub const TIMEOUT: &str = "timeout";
    /// The card body exceeded the 65536-byte cap (spec 06 R7.2).
    pub const TOO_LARGE: &str = "too_large";
    /// The card body is not a JSON object (spec 06 R7.2).
    pub const BAD_JSON: &str = "bad_json";
    /// The card has no remote whose url is the MCP endpoint (spec 06 R7.1).
    pub const NO_REMOTE: &str = "no_remote";
    /// The required `jack.server.webhook_key` cross-check disagrees with the
    /// card (HTTP 401, spec 06 R7.6).
    pub const WEBHOOK_KEY_MISMATCH: &str = "webhook_key_mismatch";
    /// The cross-check is required and the server returned no tool result
    /// (HTTP 401, spec 06 R7.6).
    pub const WEBHOOK_KEY_MISSING: &str = "webhook_key_missing";
    /// The challenge echo or the challenge attempt did not verify
    /// (spec 06 R5.3, R5.4).
    pub const CHALLENGE_FAILED: &str = "challenge_failed";
    /// The well-known receiver document is not acceptable
    /// (spec 06 R5.9).
    pub const INVALID_DOCUMENT: &str = "invalid_document";
    /// The well-known receiver document fetch failed (spec 06 R5.9).
    pub const DOCUMENT_FETCH_FAILED: &str = "document_fetch_failed";
}

/// The kind of one delivered message: an `EventOccurrence` or one of the
/// three control envelopes (spec 06 section 1, R1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A JSON object without `type`, carrying the four `EventOccurrence`
    /// members (spec 06 R1.3).
    Event,
    /// The `{"type":"gap",...}` control envelope (spec 06 R1.3).
    Gap,
    /// The `{"type":"terminated",...}` control envelope (spec 06 R1.3).
    Terminated,
    /// The `{"type":"verification",...}` control envelope (spec 06 R1.3).
    Verification,
}

impl MessageKind {
    /// Returns the `type` discriminator of the kind, or `event` for a body
    /// that carries no `type` (spec 06 R1.3).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Gap => "gap",
            Self::Terminated => "terminated",
            Self::Verification => "verification",
        }
    }

    /// Maps a control envelope `type` value to its kind; `event` is the
    /// absence of `type`, never a value, so it is not accepted here
    /// (spec 06 R1.3).
    pub fn from_type(value: &str) -> Option<Self> {
        match value {
            "gap" => Some(Self::Gap),
            "terminated" => Some(Self::Terminated),
            "verification" => Some(Self::Verification),
            _ => None,
        }
    }
}
