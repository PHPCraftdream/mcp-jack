//! Options tests: the 3.8 defaults, the 3.2 minimum and the 3.5 grant.

use crate::server::stream::{StreamLimits, StreamOptions};
use crate::stream::{
    DEFAULT_FRAME_MAX_BYTES, DEFAULT_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_STREAM_DURATION_MS,
    MIN_FRAME_MAX_BYTES,
};

#[test]
fn default_options_are_the_38_table() {
    assert_eq!(
        StreamOptions::default(),
        StreamOptions {
            frame_max_bytes: 1_048_576,
            max_concurrent_streams: 4,
            max_stream_duration_ms: 3_600_000,
            heartbeat_ms: None,
        }
    );
    assert_eq!(DEFAULT_FRAME_MAX_BYTES, 1_048_576);
    assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 4);
    assert_eq!(DEFAULT_MAX_STREAM_DURATION_MS, 3_600_000);
    assert_eq!(MIN_FRAME_MAX_BYTES, 1024);
}

#[test]
fn default_limits_apply_the_spec_defaults() {
    assert_eq!(
        StreamOptions::default().limits(30),
        StreamLimits {
            frame_max_bytes: 1_048_576,
            max_concurrent_streams: 4,
            max_stream_duration_ms: 3_600_000,
            heartbeat_ms: 15_000,
        }
    );
}

#[test]
fn zero_means_the_default() {
    let options = StreamOptions {
        frame_max_bytes: 0,
        max_concurrent_streams: 0,
        max_stream_duration_ms: 0,
        heartbeat_ms: None,
    };
    assert_eq!(options.limits(30), StreamOptions::default().limits(30));
}

#[test]
fn frame_cap_below_1024_is_raised() {
    let options = StreamOptions {
        frame_max_bytes: 10,
        ..StreamOptions::default()
    };
    assert_eq!(options.limits(30).frame_max_bytes, MIN_FRAME_MAX_BYTES);
    let at_minimum = StreamOptions {
        frame_max_bytes: 1024,
        ..StreamOptions::default()
    };
    assert_eq!(at_minimum.limits(30).frame_max_bytes, 1024);
    let above = StreamOptions {
        frame_max_bytes: 2048,
        ..StreamOptions::default()
    };
    assert_eq!(above.limits(30).frame_max_bytes, 2048);
}

#[test]
fn heartbeat_grant_is_floor_of_w_times_500() {
    assert_eq!(StreamOptions::default().granted_heartbeat_ms(30), 15_000);
    assert_eq!(StreamOptions::default().granted_heartbeat_ms(1), 500);
    assert_eq!(StreamOptions::default().granted_heartbeat_ms(120), 60_000);
    assert_eq!(StreamOptions::default().granted_heartbeat_ms(0), 15_000);
    assert_eq!(StreamOptions::default().granted_heartbeat_ms(-7), 15_000);
    assert_eq!(StreamOptions::default().limits(1).heartbeat_ms, 500);
}

#[test]
fn heartbeat_suggestion_is_clamped_or_honoured() {
    let clamping = StreamOptions {
        heartbeat_ms: Some(99_999),
        ..StreamOptions::default()
    };
    assert_eq!(clamping.granted_heartbeat_ms(30), 15_000);
    assert_eq!(clamping.limits(30).heartbeat_ms, 15_000);
    let honoured = StreamOptions {
        heartbeat_ms: Some(100),
        ..StreamOptions::default()
    };
    assert_eq!(honoured.granted_heartbeat_ms(30), 100);
    assert_eq!(honoured.limits(30).heartbeat_ms, 100);
}
