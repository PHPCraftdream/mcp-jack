//! The signer pump of spec 05 sections 3.2, 3.4, 5.1 and 6.3: it turns the
//! handler's SSE bytes into signed `s1` frames, enforces the size cap, the
//! maximum duration and the key cutoff, and always ends with the 2.16 end
//! frame.
//!
//! The caller signs the open header (2.5); the builder's `open_sig` is the chain root and its
//! `open_ts` is the first frame's floor. Every method takes the arrival time from the caller, so
//! the pump is deterministic and holds no clock.

use std::sync::Arc;

use crate::stream::{signal_data, SseEvent, SseReader, StreamBuilder, StreamCode, StreamSigner};

use super::close::{events_stream_result, is_final_response};
use super::options::StreamLimits;

/// Why the pump stopped (3.2, 3.4, 5.1 and the two defect paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeStop {
    /// 3.2: the signalled transport frame was written and the stream closed.
    Signal(StreamCode),
    /// 3.4: the duration was reached and the stream closed.
    Duration,
    /// 5.1: the signing key's successor activation would be reached; closed
    /// before it.
    Cutoff,
    /// The signer refused a signature (a retired key); nothing further can be
    /// signed.
    SignerRefused,
    /// A handler event was not valid UTF-8; the stream was closed with an end
    /// frame.
    HandlerInvalid,
}

pub(crate) struct StreamPipeConfig {
    pub(crate) sid: String,
    pub(crate) open_sig: String,
    pub(crate) open_ts: i64,
    pub(crate) limits: StreamLimits,
    pub(crate) request_id: Option<String>,
    pub(crate) method: String,
    pub(crate) cutoff: Option<i64>,
    pub(crate) started_ms: i64,
    pub(crate) signer: Arc<dyn StreamSigner>,
}

/// Replaces `StreamPipeConfig` literals and `StreamPipe::new(config)` because
/// this crate is unpublished.
pub struct StreamPipeBuilder {
    sid: String,
    open_sig: String,
    open_ts: i64,
    limits: StreamLimits,
    request_id: Option<String>,
    method: String,
    cutoff: Option<i64>,
    started_ms: i64,
    signer: Arc<dyn StreamSigner>,
}
impl StreamPipeBuilder {
    pub fn new(
        sid: String,
        open_sig: String,
        open_ts: i64,
        limits: StreamLimits,
        method: String,
        started_ms: i64,
        signer: Arc<dyn StreamSigner>,
    ) -> Self {
        Self {
            sid,
            open_sig,
            open_ts,
            limits,
            request_id: None,
            method,
            cutoff: None,
            started_ms,
            signer,
        }
    }
    pub fn request_id(mut self, v: Option<String>) -> Self {
        self.request_id = v;
        self
    }
    pub fn cutoff(mut self, v: Option<i64>) -> Self {
        self.cutoff = v;
        self
    }
    pub fn build(self) -> StreamPipe {
        let builder = StreamBuilder::resume(&self.sid, &self.open_sig);
        StreamPipe {
            builder,
            reader: SseReader::with_max_pending_bytes(self.limits.frame_max_bytes),
            limits: self.limits,
            request_id: self.request_id,
            method: self.method,
            cutoff: self.cutoff,
            started_ms: self.started_ms,
            signer: self.signer,
            last_ts: self.open_ts,
            frames_written: 0,
            stopped: None,
            ended: false,
            last_message_is_final: false,
        }
    }
}

/// The frame pump of one stream. Feed it handler bytes with
/// [`StreamPipe::push`], advance the timer with [`StreamPipe::tick`] and close
/// it with [`StreamPipe::finish`].
pub struct StreamPipe {
    builder: StreamBuilder,
    reader: SseReader,
    limits: StreamLimits,
    request_id: Option<String>,
    method: String,
    cutoff: Option<i64>,
    started_ms: i64,
    signer: Arc<dyn StreamSigner>,
    /// The `ts` of the last written frame, starting at the open header's.
    last_ts: i64,
    frames_written: u64,
    stopped: Option<PipeStop>,
    /// The end frame was written by [`StreamPipe::finish`].
    ended: bool,
    last_message_is_final: bool,
}

impl StreamPipe {
    pub(crate) fn new(config: StreamPipeConfig) -> Self {
        StreamPipeBuilder::new(
            config.sid,
            config.open_sig,
            config.open_ts,
            config.limits,
            config.method,
            config.started_ms,
            config.signer,
        )
        .request_id(config.request_id)
        .cutoff(config.cutoff)
        .build()
    }
    /// Feeds handler SSE bytes that arrived at `now_ms` and appends signed
    /// events to `out`. Returns true while the stream may continue (false once
    /// stopped).
    pub fn push(&mut self, chunk: &[u8], now_ms: i64, out: &mut Vec<u8>) -> bool {
        if !self.running() {
            return false;
        }
        // 3.4: at the deadline the server stops forwarding, even bytes that
        // arrived with this call.
        if self.duration_reached(now_ms) {
            self.close_duration(now_ms, out);
            return self.running();
        }
        for event in self.reader.push(chunk, now_ms) {
            if !self.handle_event(&event, now_ms, out) {
                break;
            }
        }
        // Size applies to the joined data value, so permit framing metadata plus
        // a finite number of data-line prefixes while rejecting a huge line early.
        if self.reader.too_large() && self.running() {
            self.close_oversize(now_ms, out);
        }
        self.running()
    }

    /// Bytes retained by the framing reader plus arrival metadata, for cap accounting.
    pub fn reader_memory_bytes(&self) -> usize {
        self.reader
            .buffered_bytes()
            .saturating_add(self.reader.arrival_metadata_bytes())
    }

    pub fn update_cutoff(&mut self, cutoff: Option<i64>) {
        self.cutoff = cutoff;
    }

    /// Advances the clock without handler bytes (3.4 duration); may close the
    /// stream.
    pub fn tick(&mut self, now_ms: i64, out: &mut Vec<u8>) -> bool {
        if !self.running() {
            return false;
        }
        if self.duration_reached(now_ms) {
            self.close_duration(now_ms, out);
        } else if self
            .cutoff
            .is_some_and(|activation| self.next_ts(now_ms).saturating_add(1) >= activation)
        {
            self.close_cutoff(out);
        }
        self.running()
    }

    /// Writes the signed end frame once (2.16, 5.1) and stops forwarding;
    /// idempotent.
    pub fn finish(&mut self, now_ms: i64, out: &mut Vec<u8>) {
        if !self.running() {
            return;
        }
        // 5.1: a fresh ts is cut back to the last signed one when it would
        // reach the successor activation.
        let ts = self.cutoff_safe_ts(now_ms);
        if self.write_end(ts, out) {
            self.ended = true;
        }
    }

    /// Why the pump stopped; `None` while it may still write and after a clean
    /// [`StreamPipe::finish`].
    pub fn stopped(&self) -> Option<PipeStop> {
        self.stopped
    }

    /// Number of written events: messages, the signal and the end frame.
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// 6.3: the last message written was a JSON-RPC response of the opening
    /// request.
    pub fn last_message_is_final(&self) -> bool {
        self.last_message_is_final
    }

    fn running(&self) -> bool {
        self.stopped.is_none() && !self.ended
    }

    /// 3.4: whether the duration has been reached at `now_ms`.
    fn duration_reached(&self, now_ms: i64) -> bool {
        let elapsed = now_ms.saturating_sub(self.started_ms);
        elapsed >= 0 && elapsed as u64 >= self.limits.max_stream_duration_ms
    }

    /// 2.15: seconds, never below the last frame's `ts`.
    fn next_ts(&self, now_ms: i64) -> i64 {
        now_ms.div_euclid(1000).max(self.last_ts)
    }

    /// The `next_ts` cut back to `last_ts` when it would reach the 5.1
    /// activation.
    fn cutoff_safe_ts(&self, now_ms: i64) -> i64 {
        let ts = self.next_ts(now_ms);
        match self.cutoff {
            Some(activation) if ts >= activation => self.last_ts,
            _ => ts,
        }
    }

    /// One handler event: 2.10 joins its `data` values with LF; `id`, `retry`,
    /// `event` and every unknown field are dropped.
    fn handle_event(&mut self, event: &SseEvent, now_ms: i64, out: &mut Vec<u8>) -> bool {
        let mut pieces: Vec<&str> = Vec::with_capacity(event.lines.len());
        for line in &event.lines {
            if line.name != b"data" {
                continue;
            }
            match std::str::from_utf8(&line.value) {
                Ok(value) => pieces.push(value),
                Err(_) => {
                    self.close_handler_invalid(now_ms, out);
                    return false;
                }
            }
        }
        if pieces.is_empty() {
            return true;
        }
        let data = pieces.join("\n");
        // 2.9: the empty data value is the end frame, which only `finish`
        // writes; a handler event that carries it writes nothing.
        if data.is_empty() {
            return true;
        }
        // 3.2: the cap bounds the data value, not the wire bytes.
        if data.len() > self.limits.frame_max_bytes {
            self.close_oversize(now_ms, out);
            return false;
        }
        self.write_message(&data, now_ms, out)
    }

    /// Signs one ordinary message frame and appends its bytes.
    fn write_message(&mut self, data: &str, now_ms: i64, out: &mut Vec<u8>) -> bool {
        let ts = self.next_ts(now_ms);
        // 5.1: never sign at or after the successor activation.
        if self.cutoff.is_some_and(|activation| ts >= activation) {
            self.close_cutoff(out);
            return false;
        }
        let Some((_, wire)) = self.builder.frame(ts, data, &*self.signer) else {
            self.stopped = Some(PipeStop::SignerRefused);
            return false;
        };
        out.extend_from_slice(wire.as_bytes());
        self.last_ts = ts;
        self.frames_written += 1;
        // 6.3: only the opening request's response completes the stream.
        self.last_message_is_final = self
            .request_id
            .as_deref()
            .is_some_and(|id| is_final_response(data, id));
        true
    }

    /// Signs the 2.16 end frame at `ts` and appends its bytes.
    fn write_end(&mut self, ts: i64, out: &mut Vec<u8>) -> bool {
        let Some((_, wire)) = self.builder.frame(ts, "", &*self.signer) else {
            self.stopped = Some(PipeStop::SignerRefused);
            return false;
        };
        out.extend_from_slice(wire.as_bytes());
        self.last_ts = ts;
        self.frames_written += 1;
        true
    }

    /// 5.1: the end frame at `last_ts`, which is below the activation.
    fn close_cutoff(&mut self, out: &mut Vec<u8>) {
        if self.write_end(self.last_ts, out) {
            self.stopped = Some(PipeStop::Cutoff);
        }
    }

    /// 3.2: the signal frame, then the end frame, then the stream is over.
    fn close_oversize(&mut self, now_ms: i64, out: &mut Vec<u8>) {
        let cap = self.limits.frame_max_bytes as u64;
        if let Some(data) = signal_data(StreamCode::FrameTooLarge, cap) {
            if self.write_message(&data, now_ms, out) {
                self.close_with_end(now_ms, PipeStop::Signal(StreamCode::FrameTooLarge), out);
            }
        }
    }

    /// 3.4: write the 6.3 final response when it is still owed, then the end
    /// frame.
    fn close_duration(&mut self, now_ms: i64, out: &mut Vec<u8>) {
        if !self.last_message_is_final && self.method == "events/stream" {
            if let Some(id) = self.request_id.clone() {
                let result = events_stream_result(&id);
                if !self.write_message(&result, now_ms, out) {
                    // The cutoff or a refusing signer already stopped it.
                    return;
                }
            }
        }
        self.close_with_end(now_ms, PipeStop::Duration, out);
    }

    /// The invalid-UTF-8 path: the end frame, then `HandlerInvalid`.
    fn close_handler_invalid(&mut self, now_ms: i64, out: &mut Vec<u8>) {
        self.close_with_end(now_ms, PipeStop::HandlerInvalid, out);
    }

    /// Writes the end frame at a cutoff-safe fresh `ts` and records `stop`.
    fn close_with_end(&mut self, now_ms: i64, stop: PipeStop, out: &mut Vec<u8>) {
        let ts = self.cutoff_safe_ts(now_ms);
        if self.write_end(ts, out) {
            self.stopped = Some(stop);
        }
    }
}
