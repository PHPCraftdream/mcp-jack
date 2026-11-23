//! Incremental client verification of an `s1` stream (spec 05 sections 4 and
//! 5.2), order-exact with `spec/tools/modern/streams/reference.mjs`.
//!
//! The caller routes a response here by 1.4, calls [`StreamVerifier::open`]
//! once, then feeds body chunks with [`StreamVerifier::push`] and finally
//! [`StreamVerifier::finish`]. Every failure is terminal and carries the
//! number of frames verified at that moment (4.3); nothing after a failure is
//! read, delivered or verified.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::rotation_auth::RotationResponseKey;
use crate::client::transport::Clock;
use crate::ed25519::{validate_public_key, verify};
use crate::encoding::{decode_b64url_fixed, key_id};

use super::grammar::{
    data_hash, frame_signing_string, open_signing_string, parse_frame, parse_open_auth,
    parse_signal, FrameKind, JackFrame, OpenAuth,
};
use super::sse::{SseEvent, SseReader};
use super::{StreamCode, StreamFailure, DEFAULT_FRAME_MAX_BYTES, DEFAULT_STREAM_IDLE_MS};

/// Response window `W` in seconds (spec 01 section 4) used when the config
/// carries no positive value (4.2 step 5, 4.3 step 3).
const DEFAULT_WINDOW_SECONDS: i64 = 30;

/// Which consumer the verified data values are delivered to (6.1, 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamConsumer {
    /// The MCP layer: one verified data value per message (6.1).
    #[default]
    Message,
    /// A stdio bridge: one stdout line per value, so a raw CR or LF aborts (6.2).
    Stdio,
}

/// Everything the verifier needs besides the bytes: the trusted keys, the
/// bound request signature, the window, the caps and the clock.
pub struct StreamVerifierConfig {
    /// Every key the client trusts, by kid: the pinned server key and every rotation-known key.
    /// `known_cutoff` is the successor activation A of 5.2; `not_before` is not a stream rule.
    pub keys: BTreeMap<String, RotationResponseKey>,
    /// The `sig` of the request that opened the stream (bound by the open signing string, 2.5).
    pub request_sig: String,
    /// Response window W in seconds; <= 0 means 30.
    pub window_seconds: i64,
    /// 2.17 cap on the data value; 0 means DEFAULT_FRAME_MAX_BYTES.
    pub frame_max_bytes: usize,
    /// 4.5 idle timeout in milliseconds; <= 0 means DEFAULT_STREAM_IDLE_MS.
    pub stream_idle_ms: i64,
    /// 6.1 or 6.2.
    pub consumer: StreamConsumer,
    /// Clock in Unix seconds sampled at open and once per frame (4.3 step 3).
    pub now: Clock,
}

impl StreamVerifierConfig {
    /// Spec defaults plus the given trusted keys and request signature.
    pub fn new(
        keys: BTreeMap<String, RotationResponseKey>,
        request_sig: impl Into<String>,
    ) -> Self {
        StreamVerifierConfig {
            keys,
            request_sig: request_sig.into(),
            window_seconds: DEFAULT_WINDOW_SECONDS,
            frame_max_bytes: DEFAULT_FRAME_MAX_BYTES,
            stream_idle_ms: DEFAULT_STREAM_IDLE_MS,
            consumer: StreamConsumer::Message,
            now: Arc::new(system_now_seconds),
        }
    }

    /// One pinned key and no rotation knowledge.
    pub fn pinned(
        kid: impl Into<String>,
        public_key: [u8; 32],
        request_sig: impl Into<String>,
    ) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(
            kid.into(),
            RotationResponseKey {
                public_key,
                not_before: 0,
                known_cutoff: None,
            },
        );
        StreamVerifierConfig::new(keys, request_sig)
    }
}

/// The default clock: Unix seconds of the system time.
fn system_now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// The outcome of one `push`: the messages delivered before any failure, and the terminal
/// failure that ended the stream, if one occurred.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamStep {
    pub messages: Vec<String>,
    pub terminal: Option<StreamFailure>,
}

impl StreamStep {
    /// Whether this step ended the stream.
    pub fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}

/// The incremental client state machine of 4.2-4.5.
pub struct StreamVerifier {
    config: StreamVerifierConfig,
    reader: SseReader,
    window_seconds: i64,
    idle_ms: i64,
    frame_max_bytes: usize,
    /// The open header, once step 7 of 4.2 passed.
    open_auth: Option<OpenAuth>,
    /// The stream key of 3.1: the one that opened the stream.
    public_key: [u8; 32],
    /// The successor activation A of 5.2 for that key.
    cutoff: Option<i64>,
    sid: String,
    /// Sticky terminal failure: the stream is over, nothing more is read.
    terminal: Option<StreamFailure>,
    frames_verified: usize,
    expected_seq: u64,
    expected_prev: String,
    previous_ts: Option<i64>,
    last_verified_ms: i64,
    ended: bool,
    started: bool,
}

impl StreamVerifier {
    /// Builds a verifier; no clock is sampled here.
    pub fn new(config: StreamVerifierConfig) -> Self {
        let window_seconds = if config.window_seconds > 0 {
            config.window_seconds
        } else {
            DEFAULT_WINDOW_SECONDS
        };
        let idle_ms = if config.stream_idle_ms > 0 {
            config.stream_idle_ms
        } else {
            DEFAULT_STREAM_IDLE_MS
        };
        let frame_max_bytes = if config.frame_max_bytes == 0 {
            DEFAULT_FRAME_MAX_BYTES
        } else {
            config.frame_max_bytes
        };
        StreamVerifier {
            config,
            reader: SseReader::new(),
            window_seconds,
            idle_ms,
            frame_max_bytes,
            open_auth: None,
            public_key: [0u8; 32],
            cutoff: None,
            sid: String::new(),
            terminal: None,
            frames_verified: 0,
            expected_seq: 0,
            expected_prev: String::new(),
            previous_ts: None,
            last_verified_ms: 0,
            ended: false,
            started: false,
        }
    }

    /// 4.2 in order. `headers` are the response header name/value pairs in order (name compared
    /// case-insensitively); `status` is the response status. Steps 1-3 come from
    /// `parse_open_auth`; 4 kid unknown/invalid; 5 window; 6 successor cutoff; 7 signature.
    /// No clock is sampled before step 4 has passed. A failure here is frames_verified 0.
    pub fn open(
        &mut self,
        status: u16,
        headers: &[(String, String)],
    ) -> Result<&OpenAuth, StreamFailure> {
        let mut values: Vec<&str> = Vec::new();
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("jack-auth") {
                values.push(value.as_str());
            }
        }
        match self.verify_open(status, &values) {
            Ok(()) => Ok(self.open_auth.as_ref().expect("a verified open header")),
            Err(code) => {
                // 4.1: no frame is read and no message is delivered.
                let failure = StreamFailure::new(code, 0);
                self.terminal = Some(failure);
                self.frames_verified = 0;
                Err(failure)
            }
        }
    }

    /// Steps 4.2.1-4.2.7; on success the state machines starts at the open header.
    fn verify_open(&mut self, status: u16, values: &[&str]) -> Result<(), StreamCode> {
        // 4.2 steps 1-3.
        let auth = parse_open_auth(values)?;
        // 4.2 step 4: the kid must be trusted and name a usable Ed25519 point.
        let key = self
            .config
            .keys
            .get(&auth.kid)
            .ok_or(StreamCode::UnknownServerKey)?;
        if validate_public_key(&key.public_key).is_err() || key_id(&key.public_key) != auth.kid {
            return Err(StreamCode::UnknownServerKey);
        }
        let (public_key, cutoff) = (key.public_key, key.known_cutoff);
        // 4.2 step 5: the one clock sample of the open header.
        let now = (self.config.now)();
        if now.abs_diff(auth.ts) > self.window_seconds as u64 {
            return Err(StreamCode::OutOfWindow);
        }
        // 4.2 step 6.
        if cutoff.is_some_and(|activation| auth.ts >= activation) {
            return Err(StreamCode::AfterCutoff);
        }
        // 4.2 step 7.
        let signing_string = open_signing_string(
            status,
            &self.config.request_sig,
            &auth.kid,
            auth.ts,
            &auth.sid,
        );
        if !self.signature_ok(&public_key, &signing_string, &auth.sig) {
            return Err(StreamCode::BadSignature);
        }
        self.public_key = public_key;
        self.cutoff = cutoff;
        self.sid = auth.sid.clone();
        self.expected_seq = 0;
        self.expected_prev = auth.sig.clone();
        self.previous_ts = None;
        self.last_verified_ms = 0;
        self.frames_verified = 0;
        self.ended = false;
        self.open_auth = Some(auth);
        self.terminal = None;
        self.started = true;
        Ok(())
    }

    /// Feeds one chunk that arrived `arrived_at_ms` milliseconds after the open header was
    /// verified; returns the messages completed by it plus any terminal failure. 4.3 in order:
    /// idle (4.5) first, then "anything after the end frame" (2.16), then grammar (2.6-2.13),
    /// then the 2.17 size, then seq continuity, then the per-frame clock sample with the window
    /// and non-decreasing ts, then the successor cutoff, then the chained signature, then 4.3
    /// step 6 (a verified 2.18 signal ends the stream with its code and is never delivered), then
    /// 2.16 (end frame), then the 6.2 stdio rule (raw CR/LF aborts with BadFrame after the frame
    /// counted). A failure is terminal and sticky.
    pub fn push(&mut self, chunk: &[u8], arrived_at_ms: i64) -> StreamStep {
        if let Some(failure) = self.terminal {
            return StreamStep {
                messages: Vec::new(),
                terminal: Some(failure),
            };
        }
        if !self.started {
            // 4.1: without a verified open header no frame may be read.
            return StreamStep {
                messages: Vec::new(),
                terminal: Some(StreamFailure::new(StreamCode::Truncated, 0)),
            };
        }
        let events = self.reader.push(chunk, arrived_at_ms);
        let mut messages = Vec::new();
        let terminal = self.consume(&events, &mut messages);
        StreamStep { messages, terminal }
    }

    /// End of body. `None` means the body ended: a stream without a verified end frame is
    /// Truncated, unless the 4.5 trailing-silence rule says Idle first. `Some(ms)` models a live
    /// connection that stayed open for `ms` after the last byte: Idle when
    /// `last_byte_time - last_verified + ms > stream_idle_ms`, otherwise a clean live observation.
    /// An end frame already verified yields no terminal. A terminal failure is sticky and repeated.
    pub fn finish(&mut self, silent_after_ms: Option<i64>) -> StreamStep {
        if let Some(failure) = self.terminal {
            return StreamStep {
                messages: vec![],
                terminal: Some(failure),
            };
        }
        if !self.started {
            let failure = StreamFailure::new(StreamCode::Truncated, 0);
            self.terminal = Some(failure);
            return StreamStep {
                messages: vec![],
                terminal: Some(failure),
            };
        }
        // 2.14: a trailing lone CR is a terminator; an unterminated line is
        // discarded. Such a flush can still complete one last event, whose
        // messages are delivered like any other.
        let events = self.reader.finish();
        let mut messages = Vec::new();
        if let Some(failure) = self.consume(&events, &mut messages) {
            return StreamStep {
                messages,
                terminal: Some(failure),
            };
        }
        if self.ended {
            return StreamStep {
                messages,
                terminal: None,
            };
        }
        // 4.4 and 4.5: the deadline runs from the last verified frame to the
        // last byte the client received, plus any measured trailing silence.
        let total = self.reader.total_bytes();
        let last_byte_ms = if total > 0 {
            self.reader.arrival_at(total - 1)
        } else {
            0
        };
        if last_byte_ms - self.last_verified_ms + silent_after_ms.unwrap_or(0) > self.idle_ms {
            let failure = self.fail(StreamCode::Idle);
            self.terminal = Some(failure);
            return StreamStep {
                messages,
                terminal: Some(failure),
            };
        }
        if silent_after_ms.is_some() {
            // A live connection the harness stopped reading has not ended.
            return StreamStep {
                messages,
                terminal: None,
            };
        }
        let failure = self.fail(StreamCode::Truncated);
        self.terminal = Some(failure);
        StreamStep {
            messages,
            terminal: Some(failure),
        }
    }

    /// Count of events that passed verification, the end frame included (4.3).
    pub fn frames_verified(&self) -> usize {
        self.frames_verified
    }

    /// The verified open header, once step 7 passed.
    pub fn open_auth(&self) -> Option<&OpenAuth> {
        self.open_auth.as_ref()
    }

    /// Runs every event through 4.3 in order, remembering the first failure.
    fn consume(
        &mut self,
        events: &[SseEvent],
        messages: &mut Vec<String>,
    ) -> Option<StreamFailure> {
        for event in events {
            if let Some(failure) = self.consume_event(event, messages) {
                self.terminal = Some(failure);
                return Some(failure);
            }
        }
        None
    }

    /// One event through 4.3, returning its terminal failure.
    fn consume_event(
        &mut self,
        event: &SseEvent,
        messages: &mut Vec<String>,
    ) -> Option<StreamFailure> {
        // 4.5 first: an event completes at its blank line, so that byte's
        // arrival is the time that is late or not.
        let arrived_at = self.reader.arrival_at(event.end - 1);
        if arrived_at - self.last_verified_ms > self.idle_ms {
            return Some(self.fail(StreamCode::Idle));
        }
        // 2.16: nothing may follow the end frame.
        if self.ended {
            return Some(self.fail(StreamCode::OutOfOrder));
        }
        // 4.3 step 1: the frame grammar of 2.6-2.13.
        let frame = match parse_frame(&event.lines) {
            Ok(frame) => frame,
            Err(code) => return Some(self.fail(code)),
        };
        // 2.17: the cap bounds the data value, not the wire bytes.
        if frame.data.len() > self.frame_max_bytes {
            return Some(self.fail(StreamCode::FrameTooLarge));
        }
        // 4.3 step 2.
        if frame.seq != self.expected_seq {
            return Some(self.fail(StreamCode::OutOfOrder));
        }
        // 4.3 step 3: one fresh clock sample per frame, then the window and
        // the non-decreasing ts rule.
        let now = (self.config.now)();
        let regressed = self.previous_ts.is_some_and(|previous| frame.ts < previous);
        if regressed || now.abs_diff(frame.ts) > self.window_seconds as u64 {
            return Some(self.fail(StreamCode::StaleFrame));
        }
        // 4.3 step 4.
        if self.cutoff.is_some_and(|activation| frame.ts >= activation) {
            return Some(self.fail(StreamCode::AfterCutoff));
        }
        // 4.3 step 5.
        if !self.frame_signature_ok(&frame) {
            return Some(self.fail(StreamCode::BadSignature));
        }
        // Verified: it counts, restarts the idle deadline and extends the chain.
        self.frames_verified += 1;
        self.last_verified_ms = arrived_at;
        self.expected_seq += 1;
        self.previous_ts = Some(frame.ts);
        self.expected_prev = frame.sig.clone();
        // 4.3 step 6: only a message frame can be a signal; it is never
        // delivered and no later event is read.
        if frame.kind == FrameKind::Message {
            if let Some(code) = parse_signal(&frame.data) {
                return Some(self.fail(code));
            }
        }
        // 2.16: the end frame delivers nothing.
        if frame.kind == FrameKind::End {
            self.ended = true;
            return None;
        }
        // 6.2: one stdout line per data value, so a raw CR or LF aborts.
        if self.config.consumer == StreamConsumer::Stdio
            && (frame.data.contains('\n') || frame.data.contains('\r'))
        {
            return Some(self.fail(StreamCode::BadFrame));
        }
        // 4.7: only a fully verified frame reaches the consumer.
        messages.push(frame.data);
        None
    }

    /// The 4.3 step 5 signature over 2.15 with the chained `prev`.
    fn frame_signature_ok(&self, frame: &JackFrame) -> bool {
        let signing_string = frame_signing_string(
            &self.sid,
            frame.seq,
            frame.ts,
            &self.expected_prev,
            &data_hash(&frame.data),
        );
        self.signature_ok(&self.public_key, &signing_string, &frame.sig)
    }

    /// Strict 64-byte signature check over the exact signing-string bytes.
    fn signature_ok(&self, public_key: &[u8; 32], message: &str, sig: &str) -> bool {
        let Ok(signature) = decode_b64url_fixed(sig, 64) else {
            return false;
        };
        verify(public_key, message.as_bytes(), &signature)
    }

    /// A terminal failure carrying the frames verified so far.
    fn fail(&self, code: StreamCode) -> StreamFailure {
        StreamFailure::new(code, self.frames_verified)
    }
}
