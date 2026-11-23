//! The bounded body collector of spec 06 R1.2 and R3.6: the framework-neutral
//! reader a receiver buffers a delivery with.
//!
//! The collector is the only place where request bytes accumulate, so the
//! 262144-byte cap of R1.2 is enforced twice and before any verification:
//! against the declared `Content-Length` when the adapter supplies one, and
//! against the running length on every pushed chunk. A chunk that would cross
//! the limit is refused before the excess is buffered, so the buffer never
//! holds more than `limit` bytes. Everything is pure: no I/O, no clock, and an
//! error carries only the section 3 code and its fixed literal message.

use crate::webhook::receiver::errors::{rejection, MAX_BODY_BYTES};
use crate::webhook::{codes, WebhookError};

/// The wire code of a receiver configuration refused before any delivery is
/// read: the requested body limit is above the profile maximum
/// (spec 06 R1.2).
pub const INVALID_PARAMS: &str = "invalid_params";

/// The status of [`INVALID_PARAMS`]: a configuration refusal is not an answer
/// to a delivery, so it carries no HTTP status (spec 06 R1.2).
const INVALID_PARAMS_STATUS: u16 = 0;

/// The fixed-literal message of a body limit above the profile maximum
/// (spec 06 R1.2).
const LIMIT_MESSAGE: &str = "the body limit is above the profile maximum";

/// Buffers one delivery body under the R1.2 byte limit (spec 06 R1.2, R3.6).
///
/// The declared length and the pushed chunks are refused with
/// `413 body_too_large` as soon as either would cross the limit; the declared
/// length alone is never trusted, so a sender that understates it is still
/// stopped by [`BodyCollector::push`] (spec 06 R1.2, R3.6).
#[derive(Debug, Clone)]
pub struct BodyCollector {
    /// The largest body this collector buffers, in bytes (spec 06 R1.2).
    limit: usize,
    /// The bytes accepted so far, never more than `limit` (spec 06 R1.2).
    buffer: Vec<u8>,
    /// The declared `Content-Length` of R3.6, `None` when absent.
    declared: Option<u64>,
}

impl BodyCollector {
    /// Builds a collector for a body of at most `limit` bytes
    /// (spec 06 R1.2).
    ///
    /// A limit above [`MAX_BODY_BYTES`] is refused with status `0`, code
    /// `invalid_params` and a fixed message, because no receiver may accept a
    /// larger body than the profile maximum (spec 06 R1.2).
    pub fn new(limit: usize) -> Result<Self, WebhookError> {
        if limit > MAX_BODY_BYTES {
            return Err(WebhookError::new(
                INVALID_PARAMS_STATUS,
                INVALID_PARAMS,
                LIMIT_MESSAGE,
            ));
        }
        Ok(Self {
            limit,
            buffer: Vec::new(),
            declared: None,
        })
    }

    /// Checks the declared `Content-Length` before the body is read
    /// (spec 06 R1.2, R3.6).
    ///
    /// A declared length above the limit is `413 body_too_large`; an absent
    /// one is accepted and remembered as `None`. The declared value never
    /// raises the limit, it only refuses earlier (spec 06 R1.2).
    pub fn check_declared(&mut self, declared: Option<u64>) -> Result<(), WebhookError> {
        if declared.is_some_and(|length| length > self.limit as u64) {
            return Err(rejection(codes::BODY_TOO_LARGE));
        }
        self.declared = declared;
        Ok(())
    }

    /// Appends one chunk, refusing the whole chunk before buffering any of it
    /// when it would cross the limit (spec 06 R1.2, R3.6).
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), WebhookError> {
        let total = self
            .buffer
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| rejection(codes::BODY_TOO_LARGE))?;
        if total > self.limit {
            return Err(rejection(codes::BODY_TOO_LARGE));
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Returns the buffered body, which is at most `limit` bytes
    /// (spec 06 R1.2).
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Returns the limit this collector enforces, in bytes (spec 06 R1.2).
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the declared `Content-Length` last checked, `None` when absent
    /// (spec 06 R3.6).
    pub fn declared(&self) -> Option<u64> {
        self.declared
    }
}
