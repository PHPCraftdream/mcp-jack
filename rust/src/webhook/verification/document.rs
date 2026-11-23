//! The well-known document route of spec 06 section 5 (R5.9, R5.10): the
//! `/.well-known/mcp-webhook-receiver.json` url of an origin, the fetch
//! verdict, the document shape, the per-origin cache TTL and the path
//! coverage match.
//!
//! The fetch runs over the same hardened path as a delivery (section 6): the
//! caller supplies the resolver answers and the recheck, and this module
//! decides before it judges the response. Everything here is pure and
//! mirrors `spec/tools/modern/webhooks/ref/verification.mjs` exactly.

use serde_json::Value;

use crate::webhook::ssrf::delivery::{delivery_decision, DeliveryDecision, DeliveryInput};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::{codes, WebhookError};

/// The largest receiver document accepted, in bytes (spec 06 R5.9).
///
/// The constant lives here because this module owns the R5.9 body cap; the
/// HTTP layer re-exports it so the fetch path and the verdict judge the same
/// number (spec 06 R5.9, R5.12).
pub const MAX_DOCUMENT_BYTES: usize = 8192;

/// The largest number of `receivers` entries (spec 06 R5.9).
const MAX_RECEIVERS: usize = 64;

/// The longest `receivers` entry, in characters (spec 06 R5.9).
const MAX_RECEIVER_PATH: usize = 1024;

/// The longest a receiver document is cached, in seconds (spec 06 R5.9).
const MAX_DOCUMENT_TTL_SECONDS: i64 = 300;

/// The cache lifetime used when `max-age` is absent or unusable
/// (spec 06 R5.9).
const DEFAULT_DOCUMENT_TTL_SECONDS: i64 = 300;

/// The default `https` port, never rendered in the well-known url
/// (spec 06 R5.9).
const DEFAULT_PORT: u16 = 443;

/// The reserved well-known receiver document path (spec 06 R5.9).
const WELL_KNOWN_PATH: &str = "/.well-known/mcp-webhook-receiver.json";

/// The status of a sender-side refusal: R5.9 answers the subscribe call, not
/// a receiver request, so no wire status is reported (spec 06 R5.9).
const NO_HTTP_STATUS: u16 = 0;

/// The `invalid_document` reason of a body that is not JSON
/// (spec 06 R5.9).
const REASON_JSON: &str = "json";

/// The `invalid_document` reason of a body without a `receivers` array
/// (spec 06 R5.9).
const REASON_RECEIVERS: &str = "receivers";

/// The `invalid_document` reason of a `receivers` count outside 1-64
/// (spec 06 R5.9).
const REASON_COUNT: &str = "count";

/// The `invalid_document` reason of a malformed `receivers` entry
/// (spec 06 R5.9).
const REASON_ENTRY: &str = "entry";

/// The `invalid_document` reason of a `.` or `..` path segment
/// (spec 06 R5.9).
const REASON_SEGMENT: &str = "segment";

/// The `document_fetch_failed` reason of a response that is not HTTP 200
/// (spec 06 R5.9).
const REASON_STATUS: &str = "status";

/// The `document_fetch_failed` reason of a body above 8192 bytes
/// (spec 06 R5.9).
const REASON_TOO_LARGE: &str = "too_large";

/// A parsed receiver document (spec 06 R5.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverDocument {
    /// The covered path prefixes, in document order, 1 to 64 of them
    /// (spec 06 R5.9, R5.10).
    pub receivers: Vec<String>,
}

/// Parses the body of a receiver document, reporting the first offending
/// check as the fixed-literal reason (spec 06 R5.9).
///
/// The reasons are `json` for a body that is not JSON, `receivers` for a
/// body that is not an object with a `receivers` array, `count` for a count
/// outside 1-64, `entry` for an entry that is not a `/`-rooted string of at
/// most 1024 characters without `?`, `#` or a control character, and
/// `segment` for a `.` or `..` segment (spec 06 R5.9).
pub fn parse_receiver_doc(text: &str) -> Result<ReceiverDocument, WebhookError> {
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        return Err(invalid_document(REASON_JSON));
    };
    if !parsed.is_object() {
        return Err(invalid_document(REASON_RECEIVERS));
    }
    let Some(Value::Array(receivers)) = parsed.get("receivers") else {
        return Err(invalid_document(REASON_RECEIVERS));
    };
    if receivers.is_empty() || receivers.len() > MAX_RECEIVERS {
        return Err(invalid_document(REASON_COUNT));
    }
    let mut entries = Vec::with_capacity(receivers.len());
    for entry in receivers {
        let Some(text) = entry.as_str() else {
            return Err(invalid_document(REASON_ENTRY));
        };
        if text.chars().count() > MAX_RECEIVER_PATH || !text.starts_with('/') {
            return Err(invalid_document(REASON_ENTRY));
        }
        if has_control_or_mark(text) {
            return Err(invalid_document(REASON_ENTRY));
        }
        if text
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(invalid_document(REASON_SEGMENT));
        }
        entries.push(text.to_string());
    }
    Ok(ReceiverDocument { receivers: entries })
}

/// Judges one well-known document fetch on status, body size and shape
/// (spec 06 R5.9).
///
/// Anything but HTTP 200 is `document_fetch_failed` with reason
/// `status_<n>`, a body above 8192 bytes is `document_fetch_failed` with
/// reason `too_large`, and the body itself is judged by
/// [`parse_receiver_doc`] (spec 06 R5.9).
pub fn check_document_fetch(
    status: u16,
    body_text: &str,
) -> Result<ReceiverDocument, WebhookError> {
    if status != 200 {
        return Err(document_fetch_failed(&format!("{REASON_STATUS}_{status}")));
    }
    if body_text.len() > MAX_DOCUMENT_BYTES {
        return Err(document_fetch_failed(REASON_TOO_LARGE));
    }
    parse_receiver_doc(body_text)
}

/// One well-known document response, before the R5.9 verdict
/// (spec 06 R5.9).
///
/// The transport reports the framing it saw, so the verdict can refuse an
/// oversized document from the declaration or the overflow flag alone,
/// without re-reading a buffered body (spec 06 R5.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentResponse<'a> {
    /// The response status (spec 06 R5.9).
    pub status: u16,
    /// The response body bytes exactly as received (spec 06 R5.9).
    pub body: &'a [u8],
    /// The response's declared `Content-Length`, when one was present
    /// (spec 06 R5.9).
    pub declared_length: Option<u64>,
    /// True when the transport observed more body than the cap allowed and
    /// truncated it (spec 06 R5.9).
    pub overflow: bool,
}

/// Runs the well-known document verdict over one response (spec 06 R5.9).
///
/// An overflowed read, a `Content-Length` above [`MAX_DOCUMENT_BYTES`] or a
/// body above it is `document_fetch_failed` with reason `too_large` before
/// any byte is parsed; otherwise the body is judged by
/// [`check_document_fetch`], which owns the status and shape rules
/// (spec 06 R5.9).
pub fn document_verdict(response: &DocumentResponse<'_>) -> Result<ReceiverDocument, WebhookError> {
    let cap = MAX_DOCUMENT_BYTES as u64;
    if response.overflow
        || response.declared_length.is_some_and(|length| length > cap)
        || response.body.len() > MAX_DOCUMENT_BYTES
    {
        return Err(document_fetch_failed(REASON_TOO_LARGE));
    }
    check_document_fetch(response.status, &String::from_utf8_lossy(response.body))
}

/// Fetches the well-known receiver document of one origin (spec 06 R5.9,
/// R5.12).
///
/// The implementation performs the only network I/O of route 4: it fetches
/// `/.well-known/mcp-webhook-receiver.json` over the hardened path of
/// section 6, with no redirect, and returns the verdict of
/// [`document_verdict`]. A failure is a route that did not count, never a
/// verification success (spec 06 R5.9).
pub trait DocumentFetcher: Send + Sync {
    /// Fetches and judges the document of `canonical_url`'s origin
    /// (spec 06 R5.9, R5.12).
    fn fetch(&self, canonical_url: &str) -> Result<ReceiverDocument, WebhookError>;
}

/// The inputs of one well-known document attempt (spec 06 R5.9, R5.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRequestInput<'a> {
    /// The well-known url exactly as supplied (spec 06 R5.9).
    pub url: &'a str,
    /// The resolver answers, in resolver order (spec 06 R6.8).
    pub answers: &'a [String],
    /// The operator override ranges of R6.11.
    pub allowed_ranges: &'a [String],
    /// The answers of the re-resolution before connect (spec 06 R6.9).
    pub recheck: &'a [String],
    /// The final status of the response, when one was already received: any
    /// value here is a `3xx` and is never followed (spec 06 R6.10).
    pub redirect_status: Option<u16>,
    /// The final status of the document response (spec 06 R5.9).
    pub status: u16,
    /// The document body text (spec 06 R5.9).
    pub body_text: &'a str,
}

/// Takes one well-known document attempt: the hardened delivery decision of
/// section 6 first, then the fetch verdict (spec 06 R5.9, R5.12).
///
/// A refused delivery decision keeps its own code and reason, so a document
/// fetched off the hardened path never contributes route 4
/// (spec 06 R5.9, R5.12).
pub fn document_request(
    input: &DocumentRequestInput<'_>,
) -> Result<ReceiverDocument, WebhookError> {
    let decision = delivery_decision(&DeliveryInput {
        url: input.url,
        answers: input.answers,
        recheck: input.recheck,
        allowed_ranges: input.allowed_ranges,
        redirect_status: input.redirect_status,
    });
    if let DeliveryDecision::Reject { code, reason } = decision {
        return Err(WebhookError::with_reason(
            NO_HTTP_STATUS,
            code,
            reason,
            "the document fetch is refused",
        ));
    }
    check_document_fetch(input.status, input.body_text)
}

/// Returns the per-origin document cache lifetime, capped at 300 s and 300 s
/// when the `max-age` is absent or negative (spec 06 R5.9).
pub fn document_cache_ttl(max_age_seconds: Option<i64>) -> i64 {
    match max_age_seconds {
        Some(seconds) if seconds >= 0 => seconds.min(MAX_DOCUMENT_TTL_SECONDS),
        _ => DEFAULT_DOCUMENT_TTL_SECONDS,
    }
}

/// Returns the well-known receiver document url of the delivery origin, or
/// `None` when the canonical url does not parse (spec 06 R5.9).
///
/// The url keeps the origin's own host and port and always uses `https`;
/// the default port is never rendered (spec 06 R5.9).
pub fn well_known_url(canonical_url: &str) -> Option<String> {
    let checked = check_url(canonical_url).ok()?;
    let suffix = if checked.port == DEFAULT_PORT {
        String::new()
    } else {
        format!(":{}", checked.port)
    };
    Some(format!("https://{}{suffix}{WELL_KNOWN_PATH}", checked.host))
}

/// Returns true when `entry` is a byte prefix of `url_path` at a segment
/// boundary (spec 06 R5.10).
///
/// The comparison is case-sensitive, at a byte offset, with no
/// percent-decoding, normalization or trailing-slash insertion: an entry
/// ending in `/` covers every path under it, `/hooks` covers `/hooks` and
/// `/hooks/a` but not `/hooksx`, and `/hooks/` does not cover `/hooks`
/// (spec 06 R5.10).
pub fn covers_path(entry: &str, url_path: &str) -> bool {
    if !url_path.starts_with(entry) {
        return false;
    }
    entry.ends_with('/')
        || url_path.len() == entry.len()
        || url_path.as_bytes().get(entry.len()) == Some(&b'/')
}

/// Returns the first `receivers` entry of the document that covers the url
/// path, in document order, or `None` when none does (spec 06 R5.10).
pub fn document_covers(document: &ReceiverDocument, url_path: &str) -> Option<String> {
    document
        .receivers
        .iter()
        .find(|entry| covers_path(entry, url_path))
        .cloned()
}

/// Returns true for a `?`, a `#`, a control character or DEL anywhere in an
/// entry (spec 06 R5.9).
fn has_control_or_mark(text: &str) -> bool {
    text.chars()
        .any(|character| matches!(character, '?' | '#' | '\0'..='\u{1f}' | '\u{7f}'))
}

/// Builds the `invalid_document` rejection of R5.9 (spec 06 R5.9).
fn invalid_document(reason: &str) -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        codes::INVALID_DOCUMENT,
        reason,
        "the receiver document is not acceptable",
    )
}

/// Builds the `document_fetch_failed` rejection of R5.9 (spec 06 R5.9).
fn document_fetch_failed(reason: &str) -> WebhookError {
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        codes::DOCUMENT_FETCH_FAILED,
        reason,
        "the receiver document fetch failed",
    )
}
