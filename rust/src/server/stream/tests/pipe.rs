//! Pipe tests: handler bytes in, signed frames out, every body checked with
//! [`StreamVerifier`].

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::client::rotation_auth::RotationResponseKey;
use crate::server::stream::{
    events_stream_result, PipeStop, StreamLimits, StreamOptions, StreamPipe, StreamPipeConfig,
};
use crate::stream::{
    parse_frame, signal_data, FrameKind, SignedOpen, SseReader, StaticStreamSigner, StreamBuilder,
    StreamCode, StreamSigner, StreamVerifier, StreamVerifierConfig, MIN_FRAME_MAX_BYTES,
};

// TEST ONLY: spec/fixtures/keys.json ("svc").
const SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";
const KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";
const REQUEST_SIG: &str =
    "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw";
const SID: &str = "q9nUNYuH-Xf_cgJBVu4_Dg";
const OPEN_TS: i64 = 1767225600;
const NOTIFY: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#;
const NOTIFY_2: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":2}}"#;
const FINAL: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

fn hex_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, pair) in SEED_HEX.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).expect("ASCII hex");
        seed[index] = u8::from_str_radix(text, 16).expect("hex byte");
    }
    seed
}

fn signer() -> Arc<StaticStreamSigner> {
    Arc::new(StaticStreamSigner::new(
        SigningKey::from_bytes(&hex_seed()),
        None,
    ))
}

/// Milliseconds since the Unix epoch for `offset_seconds` after the open.
fn ms(offset_seconds: i64) -> i64 {
    OPEN_TS * 1000 + offset_seconds * 1000
}

fn limits() -> StreamLimits {
    StreamOptions::default().limits(30)
}

fn open(signer: &StaticStreamSigner) -> SignedOpen {
    StreamBuilder::open(200, REQUEST_SIG, KID, OPEN_TS, SID, signer)
        .expect("open header signed")
        .1
}

fn pipe(
    signer: &Arc<StaticStreamSigner>,
    limits: StreamLimits,
    method: &str,
    request_id: Option<&str>,
    cutoff: Option<i64>,
) -> (StreamPipe, SignedOpen) {
    let open = open(signer.as_ref());
    let concrete = Arc::clone(signer);
    let signer: Arc<dyn StreamSigner> = concrete;
    let pipe = StreamPipe::new(StreamPipeConfig {
        sid: SID.to_string(),
        open_sig: open.sig.clone(),
        open_ts: OPEN_TS,
        limits,
        request_id: request_id.map(str::to_string),
        method: method.to_string(),
        cutoff,
        started_ms: ms(0),
        signer,
    });
    (pipe, open)
}

fn verifier(open: &SignedOpen, cutoff: Option<i64>) -> StreamVerifier {
    let mut config = StreamVerifierConfig::pinned(KID, signer().verifying_key(), REQUEST_SIG);
    // Every frame of these tests is within the 30 s window of the open ts.
    config.now = Arc::new(|| OPEN_TS);
    if let Some(activation) = cutoff {
        config.keys = BTreeMap::from([(
            KID.to_string(),
            RotationResponseKey {
                public_key: signer().verifying_key(),
                not_before: 0,
                known_cutoff: Some(activation),
            },
        )]);
    }
    let mut verifier = StreamVerifier::new(config);
    verifier
        .open(200, &[("Jack-Auth".to_string(), open.jack_auth.clone())])
        .expect("valid open header");
    verifier
}

/// Verifies the whole body: messages, terminal code and verified frames.
fn verified(
    open: &SignedOpen,
    out: &[u8],
    cutoff: Option<i64>,
) -> (Vec<String>, Option<StreamCode>, usize) {
    let mut verifier = verifier(open, cutoff);
    let step = verifier.push(out, 0);
    let mut messages = step.messages;
    let mut terminal = step.terminal.map(|failure| failure.code);
    if terminal.is_none() {
        let step = verifier.finish(None);
        messages.extend(step.messages);
        terminal = step.terminal.map(|failure| failure.code);
    }
    (messages, terminal, verifier.frames_verified())
}

fn frames(out: &[u8]) -> Vec<crate::stream::JackFrame> {
    let mut reader = SseReader::new();
    reader
        .push(out, 0)
        .iter()
        .map(|event| parse_frame(&event.lines).expect("frame grammar"))
        .collect()
}

#[test]
fn one_message_then_end() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    let chunk = format!("data: {NOTIFY}\n\n");
    assert!(pipe.push(chunk.as_bytes(), ms(0), &mut out));
    assert!(!pipe.last_message_is_final());
    pipe.finish(ms(1), &mut out);
    assert_eq!(pipe.stopped(), None);
    assert_eq!(pipe.frames_written(), 2);
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(messages, vec![NOTIFY.to_string()]);
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 2);
}

#[test]
fn multi_line_data_is_joined_with_lf() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(
        b"data: {\"a\":\ndata: 1}\n\ndata: [1,2]\n\n",
        ms(0),
        &mut out
    ));
    pipe.finish(ms(1), &mut out);
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(
        messages,
        vec!["{\"a\":\n1}".to_string(), "[1,2]".to_string()]
    );
    assert_eq!(terminal, None);
}

#[test]
fn handler_id_and_retry_are_dropped() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(b"id: 7\nretry: 50\ndata: hello\n\n", ms(0), &mut out));
    pipe.finish(ms(1), &mut out);
    let wire = String::from_utf8(out.clone()).expect("UTF-8 wire");
    assert!(!wire.contains("id:"));
    assert!(!wire.contains("retry:"));
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec!["hello".to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn comments_are_ignored() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(b": keep-alive\n\ndata: hi\n\n", ms(0), &mut out));
    pipe.finish(ms(1), &mut out);
    let wire = String::from_utf8(out.clone()).expect("UTF-8 wire");
    assert!(!wire.contains("keep-alive"));
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec!["hi".to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn crlf_handler_output_is_normalised_to_lf() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(b"data: a\r\ndata: b\r\n\r\n", ms(0), &mut out));
    pipe.finish(ms(1), &mut out);
    assert!(!out.contains(&b'\r'));
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec!["a\nb".to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn oversize_handler_message_writes_the_signal_then_the_end() {
    let signer = signer();
    let limits = StreamLimits {
        frame_max_bytes: MIN_FRAME_MAX_BYTES,
        ..limits()
    };
    let (mut pipe, open) = pipe(&signer, limits, "tools/call", Some("1"), None);
    let mut out = Vec::new();
    let big = "x".repeat(MIN_FRAME_MAX_BYTES + 1);
    let chunk = format!("data: {big}\n\n");
    assert!(!pipe.push(chunk.as_bytes(), ms(0), &mut out));
    assert_eq!(
        pipe.stopped(),
        Some(PipeStop::Signal(StreamCode::FrameTooLarge))
    );
    assert_eq!(pipe.frames_written(), 2);
    let parsed = frames(&out);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].kind, FrameKind::Message);
    assert_eq!(
        parsed[0].data,
        signal_data(StreamCode::FrameTooLarge, MIN_FRAME_MAX_BYTES as u64).expect("signalled")
    );
    assert_eq!(parsed[1].kind, FrameKind::End);
    // The client ends at the signal; the end frame that follows is not read.
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(messages, Vec::<String>::new());
    assert_eq!(terminal, Some(StreamCode::FrameTooLarge));
    assert_eq!(frames_verified, 1);
}

#[test]
fn message_exactly_at_the_cap_is_accepted() {
    let signer = signer();
    let limits = StreamLimits {
        frame_max_bytes: MIN_FRAME_MAX_BYTES,
        ..limits()
    };
    let (mut pipe, open) = pipe(&signer, limits, "tools/call", Some("1"), None);
    let mut out = Vec::new();
    let big = "y".repeat(MIN_FRAME_MAX_BYTES);
    let chunk = format!("data: {big}\n\n");
    assert!(pipe.push(chunk.as_bytes(), ms(0), &mut out));
    pipe.finish(ms(1), &mut out);
    assert_eq!(pipe.stopped(), None);
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(messages, vec![big]);
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 2);
}

#[test]
fn duration_close_writes_the_events_stream_result_then_the_end() {
    let signer = signer();
    let limits = StreamLimits {
        max_stream_duration_ms: 1_000,
        ..limits()
    };
    let (mut pipe, open) = pipe(&signer, limits, "events/stream", Some("1"), None);
    let mut out = Vec::new();
    let chunk = format!("data: {NOTIFY}\n\n");
    assert!(pipe.push(chunk.as_bytes(), ms(0), &mut out));
    assert!(!pipe.tick(ms(1), &mut out));
    assert_eq!(pipe.stopped(), Some(PipeStop::Duration));
    assert_eq!(pipe.frames_written(), 3);
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(
        messages,
        vec![NOTIFY.to_string(), events_stream_result("1")]
    );
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 3);
}

#[test]
fn duration_close_writes_nothing_extra_after_the_final_response() {
    let signer = signer();
    let limits = StreamLimits {
        max_stream_duration_ms: 1_000,
        ..limits()
    };
    let (mut pipe, open) = pipe(&signer, limits, "events/stream", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(format!("data: {FINAL}\n\n").as_bytes(), ms(0), &mut out));
    assert!(pipe.last_message_is_final());
    assert!(!pipe.tick(ms(1), &mut out));
    assert_eq!(pipe.stopped(), Some(PipeStop::Duration));
    assert_eq!(pipe.frames_written(), 2);
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec![FINAL.to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn duration_close_writes_nothing_for_another_method() {
    let signer = signer();
    let limits = StreamLimits {
        max_stream_duration_ms: 1_000,
        ..limits()
    };
    let (mut pipe, open) = pipe(&signer, limits, "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(format!("data: {NOTIFY}\n\n").as_bytes(), ms(0), &mut out));
    assert!(!pipe.tick(ms(1), &mut out));
    assert_eq!(pipe.stopped(), Some(PipeStop::Duration));
    assert_eq!(pipe.frames_written(), 2);
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec![NOTIFY.to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn cutoff_close_ends_below_the_activation() {
    let signer = signer();
    let activation = OPEN_TS + 2;
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), Some(activation));
    let mut out = Vec::new();
    assert!(pipe.push(format!("data: {NOTIFY}\n\n").as_bytes(), ms(0), &mut out));
    assert!(!pipe.push(format!("data: {NOTIFY_2}\n\n").as_bytes(), ms(2), &mut out));
    assert_eq!(pipe.stopped(), Some(PipeStop::Cutoff));
    assert_eq!(pipe.frames_written(), 2);
    let parsed = frames(&out);
    assert_eq!(parsed.len(), 2);
    for frame in &parsed {
        assert!(
            frame.ts < activation,
            "frame ts {} at or after {activation}",
            frame.ts
        );
    }
    assert_eq!(parsed[1].kind, FrameKind::End);
    // A later close must not write anything more.
    let len = out.len();
    pipe.finish(ms(5), &mut out);
    assert_eq!(out.len(), len);
    let (messages, terminal, frames_verified) = verified(&open, &out, Some(activation));
    assert_eq!(messages, vec![NOTIFY.to_string()]);
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 2);
}

#[test]
fn finish_is_idempotent() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.push(format!("data: {NOTIFY}\n\n").as_bytes(), ms(0), &mut out));
    pipe.finish(ms(1), &mut out);
    let len = out.len();
    pipe.finish(ms(2), &mut out);
    assert_eq!(out.len(), len);
    assert_eq!(pipe.frames_written(), 2);
    assert_eq!(pipe.stopped(), None);
    // A finished pipe writes nothing more on any path.
    assert!(!pipe.push(format!("data: {NOTIFY_2}\n\n").as_bytes(), ms(2), &mut out));
    assert!(!pipe.tick(ms(3), &mut out));
    assert_eq!(out.len(), len);
    let (messages, terminal, _) = verified(&open, &out, None);
    assert_eq!(messages, vec![NOTIFY.to_string()]);
    assert_eq!(terminal, None);
}

#[test]
fn tick_without_bytes_keeps_the_stream_open() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(pipe.tick(ms(1), &mut out));
    assert!(out.is_empty());
    assert_eq!(pipe.frames_written(), 0);
    assert_eq!(pipe.stopped(), None);
    pipe.finish(ms(2), &mut out);
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(messages, Vec::<String>::new());
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 1);
}

#[test]
fn invalid_utf8_stops_after_an_end_frame() {
    let signer = signer();
    let (mut pipe, open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    assert!(!pipe.push(b"data: \xff\n\n", ms(0), &mut out));
    assert_eq!(pipe.stopped(), Some(PipeStop::HandlerInvalid));
    assert_eq!(pipe.frames_written(), 1);
    let parsed = frames(&out);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].kind, FrameKind::End);
    let len = out.len();
    assert!(!pipe.push(b"data: ok\n\n", ms(1), &mut out));
    assert_eq!(out.len(), len);
    let (messages, terminal, frames_verified) = verified(&open, &out, None);
    assert_eq!(messages, Vec::<String>::new());
    assert_eq!(terminal, None);
    assert_eq!(frames_verified, 1);
}

#[test]
fn frames_written_counts_messages_signal_and_end() {
    let signer = signer();
    let (mut pipe, _open) = pipe(&signer, limits(), "tools/call", Some("1"), None);
    let mut out = Vec::new();
    let chunk = format!("data: {NOTIFY}\n\ndata: {NOTIFY_2}\n\n");
    assert!(pipe.push(chunk.as_bytes(), ms(0), &mut out));
    assert_eq!(pipe.frames_written(), 2);
    pipe.finish(ms(1), &mut out);
    assert_eq!(pipe.frames_written(), 3);
}
