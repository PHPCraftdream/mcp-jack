//! The verified `s1` stream (spec 05 section 4): the 1.4 routing and the open
//! header (4.2) are checked once, then the incremental machine of 4.3-4.5 runs
//! over an incremental body, handing out only verified data values (4.7).
//!
//! Every terminal failure is delivered exactly once, after the messages that
//! verified before it, and nothing after it is read or delivered (4.3, 4.4).

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client::transport::{is_redirect_status, TransportError};
use crate::error::JackError;
use crate::stream::{
    is_event_stream, OpenAuth, StreamCode, StreamFailure, StreamStep, StreamVerifier,
    StreamVerifierConfig, DEFAULT_STREAM_IDLE_MS,
};

use super::source::{ChunkRead, StreamBody, StreamResponse};

/// A verified `s1` stream: a blocking iterator over the data values that passed verification,
/// in order, followed by at most one terminal `StreamFailure` (4.6). Dropping it closes the body.
pub struct VerifiedStream {
    verifier: StreamVerifier,
    open_auth: OpenAuth,
    body: Box<dyn StreamBody + Send>,
    /// Verified data values the consumer has not seen yet, in order.
    pending: VecDeque<String>,
    /// The terminal failure, delivered once after the pending messages.
    terminal: Option<StreamFailure>,
    /// The body reached its end (or a terminal): no further read happens.
    done: bool,
    /// The resolved 4.5 `streamIdleMs`; the verifier keeps its own copy without exposing it.
    idle_ms: i64,
    /// Milliseconds clock; Unix milliseconds of the system clock unless replaced.
    millis: Box<dyn Fn() -> i64 + Send + Sync>,
    /// The clock value at which the open header was verified; 4.5 deadlines run from it.
    open_ms: i64,
    /// `frames_verified()` as of the last update: when it grows, 4.5 restarts.
    frames_seen: usize,
    last_verified_ms: i64,
}

impl VerifiedStream {
    /// 1.4 routing, 4.2 open header then the incremental machine of 4.3-4.5 over `response.body`.
    /// A non-200 status or a non-`text/event-stream` media type is refused before any byte is read
    /// (the caller must use the v1 response path for it).
    pub fn from_response(
        response: StreamResponse,
        config: StreamVerifierConfig,
    ) -> Result<Self, TransportError> {
        // 1.4 routing: the same local no-follow guard as `SigningTransport`, the Location is
        // ignored. A redirect is never verified against the old target.
        if is_redirect_status(response.status) {
            return Err(TransportError::Client(format!(
                "jack client: redirect (status {}) refused: the client never follows redirects (301, 302, 303, 307, 308) (spec 05 section 1.4)",
                response.status
            )));
        }
        if response.status != 200 || !is_event_stream(&response.headers) {
            return Err(TransportError::Client(format!(
                "jack client: status {} is not a signed stream (spec 05 section 1.4): a stream is exactly 200 with a text/event-stream media type, every other response goes through the v1 response path",
                response.status
            )));
        }
        // The verifier clamps a non-positive idle value to the default but does not expose the
        // resolved one, so this module keeps its own copy for the 4.5 deadline.
        let idle_ms = if config.stream_idle_ms > 0 {
            config.stream_idle_ms
        } else {
            DEFAULT_STREAM_IDLE_MS
        };
        let mut verifier = StreamVerifier::new(config);
        verifier
            .open(response.status, &response.headers)
            .map_err(|failure| {
                TransportError::Protocol(JackError::new(
                    0,
                    failure.code.as_str(),
                    "stream open header refused",
                ))
            })?;
        let open_auth = verifier
            .open_auth()
            .expect("a verified open header")
            .clone();
        let millis: Box<dyn Fn() -> i64 + Send + Sync> = Box::new(system_millis);
        let open_ms = millis();
        Ok(VerifiedStream {
            verifier,
            open_auth,
            body: response.body,
            pending: VecDeque::new(),
            terminal: None,
            done: false,
            idle_ms,
            millis,
            open_ms,
            frames_seen: 0,
            last_verified_ms: open_ms,
        })
    }

    /// The verified open header.
    pub fn open_auth(&self) -> &OpenAuth {
        &self.open_auth
    }

    /// Count of events that passed verification, the end frame included (4.3).
    pub fn frames_verified(&self) -> usize {
        self.verifier.frames_verified()
    }

    /// The stream id the open header carries (2.4).
    pub fn sid(&self) -> &str {
        &self.open_auth.sid
    }

    /// Replaces the millisecond clock used for 4.5 arrival times and idle deadlines
    /// (default: Unix milliseconds of the system clock).
    ///
    /// The new clock is sampled once here to establish the deadline baseline, so call it
    /// before the first read.
    pub fn with_millis_clock(mut self, clock: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.millis = clock;
        let now = (self.millis)();
        self.open_ms = now;
        self.last_verified_ms = now;
        self
    }

    /// 4.5: the chunk arrival in the verifier's stream-relative milliseconds (its deadline runs
    /// from 0 at the open header).
    fn arrived(&self, now_ms: i64) -> i64 {
        (now_ms - self.open_ms).max(0)
    }

    /// Queues one step's messages and terminal, and restarts the 4.5 deadline when the verifier
    /// counted a new verified frame.
    fn absorb(&mut self, step: StreamStep, now_ms: i64) {
        if self.verifier.frames_verified() != self.frames_seen {
            self.frames_seen = self.verifier.frames_verified();
            self.last_verified_ms = now_ms;
        }
        self.pending.extend(step.messages);
        if self.terminal.is_none() {
            self.terminal = step.terminal;
        }
        if self.terminal.is_some() {
            self.done = true;
        }
    }
}

impl Iterator for VerifiedStream {
    type Item = Result<String, StreamFailure>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Some(Ok(message));
            }
            if let Some(failure) = self.terminal.take() {
                return Some(Err(failure));
            }
            if self.done {
                return None;
            }
            let now_ms = (self.millis)();
            let remaining = (self.last_verified_ms + self.idle_ms - now_ms).max(0);
            let deadline = Instant::now() + Duration::from_millis(remaining as u64);
            match self.body.next_chunk(deadline) {
                Ok(ChunkRead::Data(bytes)) => {
                    let step = self.verifier.push(&bytes, self.arrived(now_ms));
                    self.absorb(step, now_ms);
                }
                Ok(ChunkRead::Timeout) => {
                    // 4.5: a live timeout is not an end-of-body flush. Keep the verifier's
                    // incremental SSE state intact; only the local idle deadline is terminal.
                    let timeout_ms = now_ms;
                    if timeout_ms - self.last_verified_ms > self.idle_ms {
                        self.terminal = Some(StreamFailure::new(
                            StreamCode::Idle,
                            self.verifier.frames_verified(),
                        ));
                        self.done = true;
                    }
                }
                Ok(ChunkRead::End) => {
                    // 4.4: the body ended; the verifier reports Truncated unless an end frame
                    // was verified.
                    let step = self.verifier.finish(None);
                    self.absorb(step, now_ms);
                    self.done = true;
                }
                Err(_) => {
                    // 4.4: a broken connection is a body that ended.
                    self.terminal = Some(StreamFailure::new(
                        StreamCode::Truncated,
                        self.verifier.frames_verified(),
                    ));
                    self.done = true;
                }
            }
        }
    }
}

/// The default millisecond clock: Unix milliseconds, negative before the epoch (the same
/// convention as the transport's second clock).
fn system_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis() as i64,
        Err(error) => -(error.duration().as_millis() as i64),
    }
}
