//! Iteration tests of `VerifiedStream`: the clean and truncated ends (4.4), a bad frame and a
//! verified signal mid-stream (4.3), a body error, the idle deadline (4.5), the stdio consumer
//! (6.2) and the 6.3 final response delivered as an ordinary message.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::client::stream::VerifiedStream;
use crate::client::transport::TransportError;
use crate::stream::{signal_data, StreamCode, StreamConsumer, StreamFailure, StreamVerifierConfig};

use super::source::{state, stream_headers, stream_response, Script};
use super::{config, frame_bytes, open_builder, MSG_A, MSG_B, OPEN_TS, REQUEST_SIG, SID};

/// Milliseconds clock with one sample per call; the last sample repeats. The first sample is
/// consumed by `with_millis_clock` and is the open-header baseline.
fn millis_clock(samples: &[i64]) -> Box<dyn Fn() -> i64 + Send + Sync> {
    let samples = samples.to_vec();
    let index = Arc::new(Mutex::new(0usize));
    Box::new(move || {
        let mut index = index.lock().expect("millis clock lock");
        let sample = samples
            .get(*index)
            .copied()
            .unwrap_or_else(|| *samples.last().unwrap_or(&0));
        if *index + 1 < samples.len() {
            *index += 1;
        }
        sample
    })
}

/// A verified stream over the fixture open header whose body replays `script`.
fn stream(
    script: Vec<Script>,
    config: StreamVerifierConfig,
    millis: &[i64],
) -> (VerifiedStream, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
    let (dropped, log) = state();
    let (_, open) = open_builder(REQUEST_SIG, OPEN_TS);
    let response = stream_response(
        200,
        stream_headers(open.jack_auth),
        script,
        Arc::clone(&log),
        Arc::clone(&dropped),
    );
    let stream = VerifiedStream::from_response(response, config)
        .expect("the fixture open header verifies")
        .with_millis_clock(millis_clock(millis));
    (stream, dropped, log)
}

/// How many body chunks the stream actually read.
fn data_reads(log: &Arc<Mutex<Vec<String>>>) -> usize {
    log.lock()
        .expect("log lock")
        .iter()
        .filter(|entry| entry.starts_with("data "))
        .count()
}

#[test]
fn clean_stream_delivers_messages_then_none() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let mut bytes = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 1, MSG_B));
    bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 2, ""));
    let (mut stream, _dropped, _log) = stream(
        vec![Script::Data(bytes), Script::End],
        config(&[OPEN_TS]),
        &[0, 0, 0],
    );
    assert_eq!(stream.sid(), SID);
    assert_eq!(stream.open_auth().sid, SID);
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(outcomes, vec![Ok(MSG_A.to_string()), Ok(MSG_B.to_string())]);
    assert_eq!(stream.frames_verified(), 3);
}

#[test]
fn truncated_body_delivers_messages_then_truncated() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let mut bytes = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 1, MSG_B));
    let (mut stream, _dropped, _log) = stream(
        vec![Script::Data(bytes), Script::End],
        config(&[OPEN_TS]),
        &[0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![
            Ok(MSG_A.to_string()),
            Ok(MSG_B.to_string()),
            Err(StreamFailure::new(StreamCode::Truncated, 2)),
        ]
    );
    assert_eq!(stream.frames_verified(), 2);
}

#[test]
fn bad_frame_stops_the_stream_after_the_verified_messages() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let first = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    // A message event without its jack line violates the frame grammar (4.3 step 1).
    let garbage = b"event: message\ndata: x\n\n".to_vec();
    let later = frame_bytes(&mut builder, OPEN_TS + 2, MSG_B);
    let (mut stream, _dropped, log) = stream(
        vec![
            Script::Data(first),
            Script::Data(garbage),
            Script::Data(later),
            Script::End,
        ],
        config(&[OPEN_TS]),
        &[0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![
            Ok(MSG_A.to_string()),
            Err(StreamFailure::new(StreamCode::BadFrame, 1)),
        ]
    );
    assert_eq!(
        data_reads(&log),
        2,
        "nothing after the failing frame is read"
    );
}

#[test]
fn verified_signal_ends_the_stream_without_delivery() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let first = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    let signal = signal_data(StreamCode::FrameTooLarge, 1_048_576).expect("a signalled code");
    let signal = frame_bytes(&mut builder, OPEN_TS + 1, &signal);
    let later = frame_bytes(&mut builder, OPEN_TS + 2, MSG_B);
    let (mut stream, _dropped, log) = stream(
        vec![
            Script::Data(first),
            Script::Data(signal),
            Script::Data(later),
            Script::End,
        ],
        config(&[OPEN_TS]),
        &[0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![
            Ok(MSG_A.to_string()),
            Err(StreamFailure::new(StreamCode::FrameTooLarge, 2)),
        ],
        "the signal counts as a verified frame but is never delivered"
    );
    assert_eq!(data_reads(&log), 2, "nothing after the signal is read");
}

#[test]
fn body_error_delivers_messages_then_truncated() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let mut bytes = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    bytes.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 1, MSG_B));
    let (mut stream, _dropped, _log) = stream(
        vec![
            Script::Data(bytes),
            Script::Error("jack client: connection reset".to_string()),
        ],
        config(&[OPEN_TS]),
        &[0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![
            Ok(MSG_A.to_string()),
            Ok(MSG_B.to_string()),
            Err(StreamFailure::new(StreamCode::Truncated, 2)),
        ],
        "a broken connection is a body that ended (4.4)"
    );
}

#[test]
fn idle_silence_ends_a_live_stream() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let first = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    let (mut stream, _dropped, _log) = stream(
        vec![Script::Data(first), Script::Timeout],
        config(&[OPEN_TS]),
        &[0, 0, 90_001],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![
            Ok(MSG_A.to_string()),
            Err(StreamFailure::new(StreamCode::Idle, 1)),
        ]
    );
}

#[test]
fn brief_silence_is_a_live_observation() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let first = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    let second = frame_bytes(&mut builder, OPEN_TS + 1, MSG_B);
    let end = frame_bytes(&mut builder, OPEN_TS + 2, "");
    let (mut stream, _dropped, log) = stream(
        vec![
            Script::Data(first),
            Script::Timeout,
            Script::Data(second),
            Script::Data(end),
            Script::End,
        ],
        config(&[OPEN_TS]),
        &[0, 0, 80_000, 80_000, 80_000],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![Ok(MSG_A.to_string()), Ok(MSG_B.to_string())],
        "a timeout without a terminal keeps the stream open"
    );
    assert_eq!(stream.frames_verified(), 3);
    assert_eq!(data_reads(&log), 3);
}

#[test]
fn timeout_preserves_partial_event_until_later_chunk() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let mut frame = frame_bytes(&mut builder, OPEN_TS, MSG_A);
    frame.extend_from_slice(&frame_bytes(&mut builder, OPEN_TS + 1, ""));
    let split = frame.len() / 2;
    let (mut stream, _dropped, _log) = stream(
        vec![
            Script::Data(frame[..split].to_vec()),
            Script::Timeout,
            Script::Data(frame[split..].to_vec()),
            Script::End,
        ],
        config(&[OPEN_TS]),
        &[0, 0, 0, 0, 0, 0],
    );
    assert_eq!(stream.next(), Some(Ok(MSG_A.to_string())));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.frames_verified(), 2);
}

#[test]
fn stdio_consumer_aborts_on_a_raw_lf() {
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    // 6.2: one stdout line per value, so a raw LF inside the verified data aborts.
    let frame = frame_bytes(&mut builder, OPEN_TS, "a\nb");
    let end = frame_bytes(&mut builder, OPEN_TS + 1, "");
    let mut config = config(&[OPEN_TS]);
    config.consumer = StreamConsumer::Stdio;
    let (mut stream, _dropped, log) = stream(
        vec![Script::Data(frame), Script::Data(end), Script::End],
        config,
        &[0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        outcomes,
        vec![Err(StreamFailure::new(StreamCode::BadFrame, 1))],
        "the frame is counted, then aborted without a message"
    );
    assert_eq!(data_reads(&log), 1, "nothing after the abort is read");
}

#[test]
fn final_response_is_an_ordinary_message() {
    // The 6.3-shaped final response is delivered like any other verified data value.
    const FINAL: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}"#;
    let (mut builder, _) = open_builder(REQUEST_SIG, OPEN_TS);
    let final_frame = frame_bytes(&mut builder, OPEN_TS, FINAL);
    let end = frame_bytes(&mut builder, OPEN_TS + 1, "");
    let (mut stream, _dropped, log) = stream(
        vec![Script::Data(final_frame), Script::Data(end), Script::End],
        config(&[OPEN_TS]),
        &[0, 0, 0, 0],
    );
    let outcomes: Vec<_> = stream.by_ref().collect();
    assert_eq!(outcomes, vec![Ok(FINAL.to_string())]);
    assert_eq!(
        stream.frames_verified(),
        2,
        "the response and the end frame"
    );
    assert_eq!(data_reads(&log), 2);
}
/// The error of routing `status`/`headers` into `from_response`, plus the proof that the body
/// was dropped without a single byte being read.
fn off_path(status: u16, headers: Vec<(String, String)>) -> TransportError {
    let (dropped, log) = state();
    let response = stream_response(
        status,
        headers,
        vec![Script::Data(b"leak".to_vec())],
        Arc::clone(&log),
        Arc::clone(&dropped),
    );
    let error = match VerifiedStream::from_response(response, config(&[OPEN_TS])) {
        Ok(_) => panic!("the response must not open a stream"),
        Err(error) => error,
    };
    assert!(
        dropped.load(Ordering::SeqCst),
        "the refused body must be dropped"
    );
    assert!(
        log.lock().expect("log lock").is_empty(),
        "no byte may be read from a refused response"
    );
    error
}

#[test]
fn from_response_refuses_every_other_response() {
    // 1.4: a redirect is refused by the no-follow guard, and a non-200 or non-stream response
    // belongs to the v1 path; both name the routing rule.
    for status in [301u16, 302, 303, 307, 308] {
        match off_path(status, stream_headers("s1 kid=x".to_string())) {
            TransportError::Client(message) => {
                assert!(message.contains("spec 05 section 1.4"), "{message}");
                assert!(message.contains(&status.to_string()), "{message}");
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }
    for (status, headers) in [
        (
            200u16,
            vec![("Content-Type".to_string(), "application/json".to_string())],
        ),
        (
            501,
            vec![("Content-Type".to_string(), "text/event-stream".to_string())],
        ),
    ] {
        match off_path(status, headers) {
            TransportError::Client(message) => {
                assert!(message.contains("spec 05 section 1.4"), "{message}");
                assert!(message.contains(&status.to_string()), "{message}");
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }
}
