//! Deployment options of the signed-stream profile (spec 05 sections 3.2-3.5
//! and the 3.8 defaults table): the configured values and the resolved limits
//! the pump enforces.

use crate::stream::{
    DEFAULT_FRAME_MAX_BYTES, DEFAULT_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_STREAM_DURATION_MS,
    MIN_FRAME_MAX_BYTES,
};

/// Response window `W` in seconds used when the server configures none
/// (spec 05 sections 3.4 and 3.5).
const DEFAULT_WINDOW_SECONDS: i64 = 30;

/// Deployment options of the signed-stream profile (spec 05 section 3.8 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOptions {
    /// `frameMaxBytes` of 3.2; 0 means the default (1 MiB).
    pub frame_max_bytes: usize,
    /// `maxConcurrentStreams` of 3.3; 0 means the default (4).
    pub max_concurrent_streams: usize,
    /// `maxStreamDurationMs` of 3.4; 0 means the default (1 h).
    pub max_stream_duration_ms: u64,
    /// Client `heartbeatMs` suggestion of 3.5; `None` grants the ceiling.
    pub heartbeat_ms: Option<u64>,
}

impl Default for StreamOptions {
    fn default() -> Self {
        StreamOptions {
            frame_max_bytes: DEFAULT_FRAME_MAX_BYTES,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            max_stream_duration_ms: DEFAULT_MAX_STREAM_DURATION_MS,
            heartbeat_ms: None,
        }
    }
}

/// Resolved numeric limits (defaults applied, 3.2 minimum enforced).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    /// 2.17 cap on the data value of one message frame (3.2).
    pub frame_max_bytes: usize,
    /// 3.3 per-identity concurrent stream ceiling.
    pub max_concurrent_streams: usize,
    /// 3.4 maximum stream duration in milliseconds.
    pub max_stream_duration_ms: u64,
    /// The 3.5 heartbeat value granted to the client.
    pub heartbeat_ms: u64,
}

impl StreamOptions {
    /// Applies the defaults and the 3.2 minimum: 0 means the default, a value
    /// below `MIN_FRAME_MAX_BYTES` is raised to it, 0 concurrent means the
    /// default, 0 duration means the default. `response_window_seconds` is the
    /// server's own `W` of spec 01 section 4 (`<= 0` means 30) and fixes the
    /// heartbeat grant of 3.5.
    pub fn limits(&self, response_window_seconds: i64) -> StreamLimits {
        StreamLimits {
            frame_max_bytes: if self.frame_max_bytes == 0 {
                DEFAULT_FRAME_MAX_BYTES
            } else {
                self.frame_max_bytes.max(MIN_FRAME_MAX_BYTES)
            },
            max_concurrent_streams: if self.max_concurrent_streams == 0 {
                DEFAULT_MAX_CONCURRENT_STREAMS
            } else {
                self.max_concurrent_streams
            },
            max_stream_duration_ms: if self.max_stream_duration_ms == 0 {
                DEFAULT_MAX_STREAM_DURATION_MS
            } else {
                self.max_stream_duration_ms
            },
            heartbeat_ms: self.granted_heartbeat_ms(response_window_seconds),
        }
    }

    /// 3.5 grant alone: `floor(W * 500)` with `W <= 0` meaning 30, clamped
    /// suggestion.
    pub fn granted_heartbeat_ms(&self, response_window_seconds: i64) -> u64 {
        let window = if response_window_seconds <= 0 {
            DEFAULT_WINDOW_SECONDS
        } else {
            response_window_seconds
        };
        let ceiling = window.saturating_mul(500).max(0) as u64;
        match self.heartbeat_ms {
            Some(suggestion) => suggestion.min(ceiling),
            None => ceiling,
        }
    }
}
