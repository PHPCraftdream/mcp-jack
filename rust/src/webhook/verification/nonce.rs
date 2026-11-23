//! Challenge nonces and echo checks of spec 06 section 5 (R5.3, R5.4): the
//! 22-character unpadded base64url form of 16 CSPRNG bytes, the `2xx` JSON
//! echo verdict, the attempt pairing and the value, freshness, single-use,
//! pairing order of `acceptEcho`.
//!
//! Everything here is pure: `now` is an argument, the only entropy is the
//! slice a caller supplies (or `getrandom` for [`random_nonce`]), and no
//! verdict carries an endpoint byte. Every instant and lifetime here is in
//! MILLISECONDS of Unix time, the one unit of the sender's clock
//! (spec 06 R5.3). The module mirrors
//! `spec/tools/modern/webhooks/ref/verification.mjs` exactly.

use crate::encoding::encode_b64url;
use crate::webhook::encoding::constant_time_eq;
use crate::webhook::{codes, WebhookError};

use serde_json::Value;

/// The lifetime of a nonce from issue, in MILLISECONDS of Unix time: 600 s
/// (spec 06 R5.3).
pub const NONCE_TTL_MS: i64 = 600_000;

/// The number of CSPRNG bytes a nonce is built from (spec 06 R5.3).
const NONCE_BYTES: usize = 16;

/// The exact length of a base64url nonce, unpadded (spec 06 R5.3).
const NONCE_LEN: usize = 22;

/// The largest echo body accepted, in bytes (spec 06 R5.4).
pub const MAX_ECHO_BYTES: usize = 4096;

/// The fixed `challenge_failed` reason of a non-`2xx` echo (spec 06 R5.4).
const REASON_STATUS: &str = "status";

/// The fixed `challenge_failed` reason of an absent or non-object echo body
/// (spec 06 R5.4).
const REASON_BODY: &str = "body";

/// The fixed `challenge_failed` reason of an echo body above 4096 bytes
/// (spec 06 R5.4).
const REASON_TOO_LARGE: &str = "too_large";

/// The fixed `challenge_failed` reason of an echo body that is not JSON
/// (spec 06 R5.4).
const REASON_JSON: &str = "json";

/// The fixed `challenge_failed` reason of an echo without a string
/// `challenge` member (spec 06 R5.4).
const REASON_MISSING: &str = "missing";

/// The fixed `challenge_failed` reason of a wrong, expired or reused echo
/// (spec 06 R5.3, R5.4).
const REASON_MISMATCH: &str = "mismatch";

/// The fixed `challenge_failed` reason of a nonce past its 600 s life
/// (spec 06 R5.3).
const REASON_EXPIRED: &str = "expired";

/// The fixed `challenge_failed` reason of a second echo of the same nonce
/// (spec 06 R5.3).
const REASON_REUSED: &str = "reused";

/// The fixed `challenge_failed` reason of an echo for another pair
/// (spec 06 R5.3).
const REASON_PAIR: &str = "pair";

/// The outcome of one challenge check (spec 06 R5.3, R5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoVerdict {
    /// True when the challenge is accepted (spec 06 R5.3, R5.4).
    pub ok: bool,
    /// The `challenge_failed` code on a rejection, `None` on success
    /// (spec 06 R5.4).
    pub code: Option<&'static str>,
    /// The fixed-literal reason on a rejection, never an endpoint byte
    /// (spec 06 R5.3, R5.4).
    pub reason: Option<String>,
}

impl EchoVerdict {
    /// Builds the success verdict of an accepted challenge (spec 06 R5.3,
    /// R5.4).
    fn accept() -> Self {
        Self {
            ok: true,
            code: None,
            reason: None,
        }
    }

    /// Builds the `challenge_failed` verdict with the given fixed-literal
    /// reason (spec 06 R5.4).
    fn fail(reason: &'static str) -> Self {
        Self {
            ok: false,
            code: Some(codes::CHALLENGE_FAILED),
            reason: Some(reason.to_string()),
        }
    }
}

/// Returns true for exactly 22 base64url characters, the unpadded form of 16
/// CSPRNG bytes (spec 06 R5.3).
pub fn nonce_ok(value: &str) -> bool {
    value.len() == NONCE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Returns the unpadded base64url form of the 16 supplied CSPRNG bytes
/// (spec 06 R5.3).
pub fn new_nonce(entropy: &[u8; 16]) -> String {
    encode_b64url(entropy)
}

/// Returns a fresh nonce from the operating-system CSPRNG (spec 06 R5.3).
pub fn random_nonce() -> Result<String, WebhookError> {
    let mut entropy = [0u8; NONCE_BYTES];
    getrandom::fill(&mut entropy)
        .map_err(|_| WebhookError::new(500, "internal_error", "internal error"))?;
    Ok(new_nonce(&entropy))
}

/// Judges one echo response whose `challenge` member must equal the nonce:
/// status, size, json, object, member and then value, in that order
/// (spec 06 R5.4).
///
/// The size check refuses a body the transport flagged as `overflow` (the
/// body is a truncated prefix), a `declared_length` above
/// [`MAX_ECHO_BYTES`], and a stored `body` above it, all as `too_large`
/// (spec 06 R5.4). The comparisons are byte-exact, so a body that is not
/// UTF-8 is never a JSON echo.
pub fn challenge_response(
    status: u16,
    body: &[u8],
    declared_length: Option<u64>,
    overflow: bool,
    nonce: &str,
) -> EchoVerdict {
    if !(200..=299).contains(&status) {
        return EchoVerdict::fail(REASON_STATUS);
    }
    if overflow
        || declared_length.is_some_and(|length| length > MAX_ECHO_BYTES as u64)
        || body.len() > MAX_ECHO_BYTES
    {
        return EchoVerdict::fail(REASON_TOO_LARGE);
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return EchoVerdict::fail(REASON_JSON);
    };
    if !parsed.is_object() {
        return EchoVerdict::fail(REASON_BODY);
    }
    let Some(echo) = parsed.get("challenge").and_then(Value::as_str) else {
        return EchoVerdict::fail(REASON_MISSING);
    };
    if !constant_time_eq(echo.as_bytes(), nonce.as_bytes()) {
        return EchoVerdict::fail(REASON_MISMATCH);
    }
    EchoVerdict::accept()
}

/// Judges one `2xx` text echo, the form the verification vectors drive: a
/// thin delegate of [`challenge_response`] with no declared length and no
/// overflow, so an echo above [`MAX_ECHO_BYTES`] is still `too_large`
/// (spec 06 R5.4).
pub fn challenge_echo(status: u16, body_text: &str, nonce: &str) -> EchoVerdict {
    challenge_response(status, body_text.as_bytes(), None, false, nonce)
}

/// Returns the two members of an attempt pair as one comparable value,
/// whatever object carries them, or `None` when it is not two non-empty
/// strings (spec 06 R5.3).
///
/// The array form is exactly two members; the object form reads `principal`
/// and `url`. An absent, `null`, one-element or non-string pair is never a
/// pair, and neither is a pair with a zero-length member, so two unusable
/// pairs never compare equal (spec 06 R5.3).
pub fn pair_key(pair: Option<&Value>) -> Option<String> {
    let pair = pair?;
    let (principal, url) = if let Some(items) = pair.as_array() {
        if items.len() != 2 {
            return None;
        }
        (items[0].as_str()?, items[1].as_str()?)
    } else if pair.is_object() {
        (
            pair.get("principal").and_then(Value::as_str)?,
            pair.get("url").and_then(Value::as_str)?,
        )
    } else {
        return None;
    };
    if principal.is_empty() || url.is_empty() {
        return None;
    }
    serde_json::to_string(&[principal, url]).ok()
}

/// One issued nonce that has not been forgotten yet: its issue time in
/// MILLISECONDS of Unix time, the `(principal, canonical_url)` pair it is
/// bound to and whether an accepted echo already spent it (spec 06 R5.3).
///
/// The pair is the two members as owned strings; the gate renders it as a
/// two-element array for [`accept_echo`], so both sides of the pair check
/// pass through [`pair_key`] (spec 06 R5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNonce {
    /// The Unix time the nonce was issued, in MILLISECONDS (spec 06 R5.3).
    pub issued_at: i64,
    /// The principal and canonical url the nonce is bound to, both non-empty
    /// (spec 06 R5.3).
    pub pair: (String, String),
    /// True once an accepted echo spent the nonce, so a second echo is
    /// `reused` (spec 06 R5.3).
    pub consumed: bool,
}

/// The inputs of one accept decision (spec 06 R5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoAttempt<'a> {
    /// The nonce the endpoint echoed (spec 06 R5.3, R5.4).
    pub nonce: Option<&'a str>,
    /// The nonce the sender issued for this attempt (spec 06 R5.3).
    pub expected: Option<&'a str>,
    /// The Unix time the nonce was issued, in MILLISECONDS (spec 06 R5.3).
    pub issued_at: i64,
    /// The Unix time of the check in MILLISECONDS, sampled after the echo
    /// response arrived (spec 06 R5.3, R5.4).
    pub now: i64,
    /// The nonce lifetime in MILLISECONDS, 600 s from issue
    /// (spec 06 R5.3).
    pub ttl: i64,
    /// True when the nonce was already spent by an earlier success
    /// (spec 06 R5.3).
    pub consumed: bool,
    /// The pair the echo claims (spec 06 R5.3).
    pub pair: Option<&'a Value>,
    /// The pair the attempt was issued for (spec 06 R5.3).
    pub expected_pair: Option<&'a Value>,
}

/// Accepts an echo on value, freshness, single use and attempt pairing, in
/// that order (spec 06 R5.3).
///
/// `issued_at`, `now` and `ttl` are all in MILLISECONDS of Unix time, and the
/// rule is `now - issued_at > ttl`. A mismatch is `mismatch`, a nonce past
/// `ttl` is `expired`, a second echo of the same nonce is `reused` and a pair
/// that is not the attempt's pair, or is not two non-empty strings, is `pair`
/// (spec 06 R5.3).
pub fn accept_echo(attempt: &EchoAttempt<'_>) -> EchoVerdict {
    let (Some(nonce), Some(expected)) = (attempt.nonce, attempt.expected) else {
        return EchoVerdict::fail(REASON_MISMATCH);
    };
    if !constant_time_eq(nonce.as_bytes(), expected.as_bytes()) {
        return EchoVerdict::fail(REASON_MISMATCH);
    }
    let age = i128::from(attempt.now) - i128::from(attempt.issued_at);
    if age > i128::from(attempt.ttl) {
        return EchoVerdict::fail(REASON_EXPIRED);
    }
    if attempt.consumed {
        return EchoVerdict::fail(REASON_REUSED);
    }
    let Some(key) = pair_key(attempt.pair) else {
        return EchoVerdict::fail(REASON_PAIR);
    };
    if Some(key) != pair_key(attempt.expected_pair) {
        return EchoVerdict::fail(REASON_PAIR);
    }
    EchoVerdict::accept()
}
