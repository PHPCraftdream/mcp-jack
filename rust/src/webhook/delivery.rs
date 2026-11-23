//! Sender-side delivery rules of spec 06 section 1 (R1.6-R1.10): the timeout
//! caps, the closed `lastError` category list, the exact retry schedule and the
//! one accept/retry/abandon decision taken after each attempt.
//!
//! Everything here is pure: the caller supplies the attempt's status, its
//! transport failure, its `Retry-After` and the clock values `t0` and
//! `response_time`. The decision mirrors `senderDecision` of
//! `spec/tools/modern/webhooks/ref/receiver.mjs` exactly, so a schedule can be
//! reproduced from the rule alone.

use crate::webhook::WebhookError;

/// The four attempt offsets in seconds since `t0`: `attempt(k) = t0 +
/// [0, 30, 270, 870][k-1]` for `k = 1..4`, no jitter (spec 06 R1.8).
pub const ATTEMPT_OFFSETS: [i64; 4] = [0, 30, 270, 870];

/// The hard cap on the whole schedule: no attempt is ever later than
/// `t0 + 900 s` (spec 06 R1.8).
pub const RETRY_CAP_SECONDS: i64 = 900;

/// The number of attempts of one message, after which it is abandoned
/// (spec 06 R1.8).
pub const MAX_ATTEMPTS: u32 = 4;

/// The largest body a sender sends and a receiver accepts, in bytes
/// (spec 06 R3.6).
pub const MAX_BODY_BYTES: usize = 262_144;

/// The connect phase cap of one attempt: 10 s (spec 06 R1.6).
pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;

/// The response phase cap of one attempt: 10 s after the request is written
/// (spec 06 R1.6).
pub const RESPONSE_TIMEOUT_SECONDS: u64 = 10;

/// The cap on one whole attempt: 20 s (spec 06 R1.6).
pub const ATTEMPT_TIMEOUT_SECONDS: u64 = 20;

/// The `stale_timestamp` wire code of a timestamp too far in the past
/// (spec 06 R3.9).
const STALE_TIMESTAMP: &str = "stale_timestamp";

/// The `future_timestamp` wire code of a timestamp too far ahead
/// (spec 06 R3.9).
const FUTURE_TIMESTAMP: &str = "future_timestamp";

/// The fixed `stale_timestamp` message (spec 06 R3.9); it never names an
/// input byte.
const STALE_MESSAGE: &str = "timestamp too old";

/// The fixed `future_timestamp` message (spec 06 R3.9); it never names an
/// input byte.
const FUTURE_MESSAGE: &str = "timestamp too far ahead";

/// One category of the closed `lastError` list (spec 06 R1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastError {
    /// A DNS, connect or reserved-address refusal; `blocked_address` and
    /// `dns_rebinding` map here (spec 06 R1.9).
    ConnectionRefused,
    /// An attempt that exceeded one of the caps of R1.6 (spec 06 R1.9).
    Timeout,
    /// A TLS handshake or certificate failure (spec 06 R1.9).
    TlsError,
    /// A `3xx` or `4xx` answer, including the final `410` and `413`
    /// (spec 06 R1.7, R1.9).
    Http4xx,
    /// A `5xx` answer, retryable apart from nothing (spec 06 R1.7, R1.9).
    Http5xx,
    /// Endpoint verification failed (spec 06 R1.9).
    ChallengeFailed,
}

impl LastError {
    /// Returns the wire spelling of the category (spec 06 R1.9):
    /// `connection_refused`, `timeout`, `tls_error`, `http_4xx`, `http_5xx`
    /// or `challenge_failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::TlsError => "tls_error",
            Self::Http4xx => "http_4xx",
            Self::Http5xx => "http_5xx",
            Self::ChallengeFailed => "challenge_failed",
        }
    }
}

/// Returns the classification category of one HTTP status, or `None` for a
/// `2xx` and for any status outside `3xx..=5xx` (spec 06 R1.7).
pub fn last_error_of(status: u16) -> Option<LastError> {
    if (200..=299).contains(&status) {
        return None;
    }
    if (500..=599).contains(&status) {
        return Some(LastError::Http5xx);
    }
    if (300..=499).contains(&status) {
        return Some(LastError::Http4xx);
    }
    None
}

/// What the sender does after one attempt (spec 06 R1.7, R1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderAction {
    /// The `2xx` acceptance: the message is done (spec 06 R1.7).
    Accept,
    /// Another attempt is scheduled at `next_at` unix seconds
    /// (spec 06 R1.8).
    Retry {
        /// The absolute time of the next attempt, never past `t0 + 900 s`
        /// (spec 06 R1.8).
        next_at: i64,
    },
    /// The message is abandoned for this `webhook-id` (spec 06 R1.7).
    Final,
}

/// The outcome of one attempt: the action and, unless accepted, the
/// `lastError` category recorded for it (spec 06 R1.7, R1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderDecision {
    /// The accept, retry or abandon decision (spec 06 R1.7, R1.8).
    pub action: SenderAction,
    /// The recorded category, absent only on `Accept` (spec 06 R1.9).
    pub last_error: Option<LastError>,
}

/// One finished attempt as the decision function sees it (spec 06 R1.7,
/// R1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderAttempt {
    /// The HTTP status, when a response was read (spec 06 R1.7).
    pub status: Option<u16>,
    /// The transport category, when no response was read (spec 06 R1.9).
    pub transport: Option<LastError>,
    /// The `Retry-After` delay in seconds, when the response carried one;
    /// a negative value or `None` postpones nothing (spec 06 R1.8).
    pub retry_after: Option<i64>,
    /// The number of the attempt that just finished, 1-based
    /// (spec 06 R1.8).
    pub attempt: u32,
    /// The schedule origin, in unix seconds (spec 06 R1.8).
    pub t0: i64,
    /// When the attempt's response or failure was observed, in unix seconds
    /// (spec 06 R1.8).
    pub response_time: i64,
}

/// Decides the fate of one message after one attempt (spec 06 R1.7, R1.8).
///
/// A `2xx` is the only acceptance. A transport failure or a `425`, `429` or
/// `5xx` answer is retried while fewer than four attempts have finished, at
/// `t0 + ATTEMPT_OFFSETS[attempt]`, postponed to
/// `max(scheduled, response_time + retry_after)` when a positive
/// `Retry-After` is present, never past `t0 + 900 s`, and abandoned when that
/// capped slot is already at or before `response_time`. `410`, `413` and every
/// other non-retryable outcome are final, recording the category of the
/// attempt (spec 06 R1.7, R1.8).
pub fn sender_decision(attempt: &SenderAttempt) -> SenderDecision {
    let last_error = attempt
        .transport
        .or_else(|| attempt.status.and_then(last_error_of))
        .unwrap_or(LastError::Http4xx);
    let abandoned = SenderDecision {
        action: SenderAction::Final,
        last_error: Some(last_error),
    };
    if attempt.transport.is_none() {
        match attempt.status {
            Some(status) if (200..=299).contains(&status) => {
                return SenderDecision {
                    action: SenderAction::Accept,
                    last_error: None,
                };
            }
            Some(410 | 413) => return abandoned,
            _ => {}
        }
    }
    let retryable = attempt.transport.is_some()
        || matches!(attempt.status, Some(425 | 429))
        || attempt
            .status
            .is_some_and(|status| (500..=599).contains(&status));
    if !retryable {
        return abandoned;
    }
    // The fourth attempt is always the last one (spec 06 R1.8).
    if attempt.attempt >= MAX_ATTEMPTS {
        return abandoned;
    }
    let slot = (attempt.attempt as usize).min(ATTEMPT_OFFSETS.len() - 1);
    let mut next_at = attempt.t0.saturating_add(ATTEMPT_OFFSETS[slot]);
    if let Some(retry_after) = attempt.retry_after {
        if retry_after > 0 {
            let postponed = attempt.response_time.saturating_add(retry_after);
            if postponed > next_at {
                next_at = postponed;
            }
        }
    }
    let cap = attempt.t0.saturating_add(RETRY_CAP_SECONDS);
    if next_at > cap {
        next_at = cap;
    }
    // A capped slot that is already past cannot be retried (spec 06 R1.8).
    if next_at <= attempt.response_time {
        return abandoned;
    }
    SenderDecision {
        action: SenderAction::Retry { next_at },
        last_error: Some(last_error),
    }
}

/// Returns the four absolute attempt times from `t0`, in unix seconds
/// (spec 06 R1.8).
pub fn retry_schedule(t0: i64) -> [i64; 4] {
    [
        t0.saturating_add(ATTEMPT_OFFSETS[0]),
        t0.saturating_add(ATTEMPT_OFFSETS[1]),
        t0.saturating_add(ATTEMPT_OFFSETS[2]),
        t0.saturating_add(ATTEMPT_OFFSETS[3]),
    ]
}

/// Reports whether `status` is final for that one delivery: only `410` and
/// `413`, which never change the subscription or its routing
/// (spec 06 R1.7, R1.8).
pub fn status_is_final_for_delivery(status: u16) -> bool {
    matches!(status, 410 | 413)
}

/// Checks the freshness window of the receiver clock (spec 06 R3.9).
///
/// `now - timestamp > window` is `stale_timestamp` (HTTP 401) and
/// `timestamp - now > window` is `future_timestamp` (HTTP 401). The window is
/// symmetric and the differences are taken in `i128`, so neither value can
/// overflow. A receiver evaluates this only after the HMAC of step 12
/// verified (spec 06 R3.9).
pub fn freshness(now: i64, timestamp: i64, window: i64) -> Result<(), WebhookError> {
    let difference = i128::from(now) - i128::from(timestamp);
    let window = i128::from(window);
    if difference > window {
        return Err(WebhookError::new(401, STALE_TIMESTAMP, STALE_MESSAGE));
    }
    if -difference > window {
        return Err(WebhookError::new(401, FUTURE_TIMESTAMP, FUTURE_MESSAGE));
    }
    Ok(())
}

/// Maps one of Jack's internal outcomes to the closed `lastError` list of
/// R1.9.
///
/// `blocked_address` and `dns_rebinding` are `connection_refused`,
/// `redirect_refused` is `http_4xx`, and `timeout`, `tls_error`,
/// `connection_refused` and `challenge_failed` map to their own category.
/// Any other string has no category and yields `None` (spec 06 R1.9).
pub fn map_internal_outcome(outcome: &str) -> Option<LastError> {
    match outcome {
        "blocked_address" | "dns_rebinding" | "connection_refused" => {
            Some(LastError::ConnectionRefused)
        }
        "redirect_refused" => Some(LastError::Http4xx),
        "timeout" => Some(LastError::Timeout),
        "tls_error" => Some(LastError::TlsError),
        "challenge_failed" => Some(LastError::ChallengeFailed),
        _ => None,
    }
}
