//! Signed streams (`s1`) of spec 05: the pure header, frame and SSE layer.
//!
//! This module is transport-free and builds with `--no-default-features`. It
//! parses the `Jack-Auth` open value (spec 05 section 2.2), both signing
//! strings (2.5, 2.15), the frame grammar (2.6-2.13), the transport signal
//! template (2.18), the `Jack-Accept` opt-in (1.1) and the `text/event-stream`
//! routing rule (1.4). The key, window, cutoff and signature checks of 4.2
//! steps 4-7 belong to the verifier built on top of this foundation.
//!
//! The behaviour mirrors `spec/tools/modern/streams/reference.mjs` exactly:
//! the canonical-decimal rules, the parameter grammar, the byte-exact signal
//! template and the incremental WHATWG SSE reader of 2.14. On top of that
//! foundation [`StreamBuilder`] signs the open header and the frame chain,
//! [`StaticStreamSigner`] is the Ed25519 key capability they sign with, and
//! [`StreamVerifier`] is the incremental client state machine that verifies
//! and delivers the stream.

mod builder;
mod grammar;
mod signer;
mod sse;
mod verifier;

#[cfg(test)]
mod tests;

pub use builder::{SignedFrame, SignedOpen, StreamBuilder};
pub use grammar::{
    accepts_s1, data_hash, format_open_auth, frame_signing_string, is_event_stream,
    open_signing_string, parse_frame, parse_jack_accept, parse_open_auth, parse_signal,
    serialize_frame, signal_data, FrameKind, JackAccept, JackFrame, OpenAuth,
};
pub use signer::{StaticStreamSigner, StreamSigner};
pub use sse::{SseEvent, SseField, SseReader};
pub use verifier::{StreamConsumer, StreamStep, StreamVerifier, StreamVerifierConfig};

/// The `s1` opt-in token of the `Jack-Accept` header (spec 05 section 1.1).
pub const ACCEPT_TOKEN: &str = "s1";
/// First line of the open signing string (spec 05 section 2.5).
pub const OPEN_DOMAIN: &str = "mcp-jack/stream1/open";
/// First line of the frame signing string (spec 05 section 2.15).
pub const FRAME_DOMAIN: &str = "mcp-jack/stream1/frame";
/// JSON-RPC method of the transport signal (spec 05 section 2.18).
pub const SIGNAL_METHOD: &str = "notifications/jack/stream_error";
/// Default `frameMaxBytes` of spec 05 section 3.2 (1 MiB).
pub const DEFAULT_FRAME_MAX_BYTES: usize = 1_048_576;
/// Smallest legal `frameMaxBytes` (spec 05 section 3.2).
pub const MIN_FRAME_MAX_BYTES: usize = 1024;
/// Default `maxConcurrentStreams` (spec 05 section 3.3).
pub const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 4;
/// Default `maxStreamDurationMs` (spec 05 section 3.4).
pub const DEFAULT_MAX_STREAM_DURATION_MS: u64 = 3_600_000;
/// Default `streamIdleMs` (spec 05 section 4.5).
pub const DEFAULT_STREAM_IDLE_MS: i64 = 90_000;
/// Largest integer a JSON number may carry without loss (spec 05 section 2.18).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Closed set of spec 05 section 4.6 codes (client-side only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamCode {
    MissingAuth,
    MalformedAuth,
    UnsupportedVersion,
    UnknownServerKey,
    OutOfWindow,
    BadSignature,
    BadFrame,
    OutOfOrder,
    StaleFrame,
    Truncated,
    Idle,
    FrameTooLarge,
    AfterCutoff,
}

impl StreamCode {
    /// Every code, in the order of spec 05 section 4.6.
    pub const ALL: [StreamCode; 13] = [
        StreamCode::MissingAuth,
        StreamCode::MalformedAuth,
        StreamCode::UnsupportedVersion,
        StreamCode::UnknownServerKey,
        StreamCode::OutOfWindow,
        StreamCode::BadSignature,
        StreamCode::BadFrame,
        StreamCode::OutOfOrder,
        StreamCode::StaleFrame,
        StreamCode::Truncated,
        StreamCode::Idle,
        StreamCode::FrameTooLarge,
        StreamCode::AfterCutoff,
    ];

    /// The wire code, exactly as spec 05 section 4.6 spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            StreamCode::MissingAuth => "stream_missing_auth",
            StreamCode::MalformedAuth => "stream_malformed_auth",
            StreamCode::UnsupportedVersion => "stream_unsupported_version",
            StreamCode::UnknownServerKey => "stream_unknown_server_key",
            StreamCode::OutOfWindow => "stream_out_of_window",
            StreamCode::BadSignature => "stream_bad_signature",
            StreamCode::BadFrame => "stream_bad_frame",
            StreamCode::OutOfOrder => "stream_out_of_order",
            StreamCode::StaleFrame => "stream_stale_frame",
            StreamCode::Truncated => "stream_truncated",
            StreamCode::Idle => "stream_idle",
            StreamCode::FrameTooLarge => "stream_frame_too_large",
            StreamCode::AfterCutoff => "stream_after_cutoff",
        }
    }

    /// The inverse of [`StreamCode::as_str`]; `None` for anything else.
    pub fn from_code(code: &str) -> Option<Self> {
        StreamCode::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == code)
    }
}

impl std::fmt::Display for StreamCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One terminal stream failure (spec 05 section 4.6) plus the number of
/// verified frames at the moment of the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFailure {
    pub code: StreamCode,
    pub frames_verified: usize,
}

impl StreamFailure {
    pub fn new(code: StreamCode, frames_verified: usize) -> Self {
        StreamFailure {
            code,
            frames_verified,
        }
    }
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "jack: stream {} after {} frames",
            self.code, self.frames_verified
        )
    }
}

impl std::error::Error for StreamFailure {}
