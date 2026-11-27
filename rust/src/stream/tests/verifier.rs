//! Verifier tests: the open-header steps of 4.2, the frame steps of 4.3, the
//! signal rule of 2.18, truncation (4.4), idle (4.5), the stdio consumer
//! (6.2) and the 6.3 close lookalikes. Every positive body is fed three ways:
//! one push, one byte per push, and one chunk per completed event.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::user_key::ServerSigningKey;

use crate::client::rotation_auth::RotationResponseKey;
use crate::client::transport::Clock;
use crate::encoding::encode_b64url;
use crate::stream::{
    data_hash, format_open_auth, frame_signing_string, serialize_frame, signal_data, FrameKind,
    OpenAuth, SignedOpen, SseReader, StaticStreamSigner, StreamBuilder, StreamCode, StreamConsumer,
    StreamFailure, StreamSigner, StreamVerifier, StreamVerifierConfig,
};
use StreamCode::*;

// TEST ONLY: spec/fixtures/keys.json ("svc").
const SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";
const KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";
const REQUEST_SIG: &str =
    "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw";
const SID: &str = "q9nUNYuH-Xf_cgJBVu4_Dg";
const OPEN_SIG: &str =
    "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ";
const OPEN_TS: i64 = 1767225600;
const WINDOW: i64 = 30;

const MSG_A: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#;
const MSG_B: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":2}}"#;
const MSG_C: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

fn hex_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, pair) in SEED_HEX.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).expect("ASCII hex");
        seed[index] = u8::from_str_radix(text, 16).expect("hex byte");
    }
    seed
}

fn signer() -> StaticStreamSigner {
    StaticStreamSigner::new(ServerSigningKey::from_bytes(&hex_seed()), None)
}

/// Scripted clock: `samples[0]` is the open sample, then one per frame; the
/// last sample repeats.
fn clock(samples: &[i64]) -> Clock {
    let state = Arc::new(Mutex::new((samples.to_vec(), 0usize)));
    Arc::new(move || {
        let mut state = state.lock().expect("clock lock");
        let index = state.1;
        if index + 1 < state.0.len() {
            state.1 += 1;
        }
        state.0.get(index).copied().unwrap_or(0)
    })
}

fn config(samples: &[i64]) -> StreamVerifierConfig {
    let mut config = StreamVerifierConfig::pinned(KID, signer().verifying_key(), REQUEST_SIG);
    config.now = clock(samples);
    config
}

fn with_key(samples: &[i64], key: RotationResponseKey) -> StreamVerifierConfig {
    let mut config = config(samples);
    config.keys = BTreeMap::from([(KID.to_string(), key)]);
    config
}

fn with_cutoff(samples: &[i64], cutoff: i64) -> StreamVerifierConfig {
    with_key(
        samples,
        RotationResponseKey {
            public_key: signer().verifying_key(),
            not_before: 0,
            known_cutoff: Some(cutoff),
        },
    )
}

fn opened() -> (StreamBuilder, SignedOpen) {
    StreamBuilder::open(200, REQUEST_SIG, KID, OPEN_TS, SID, &signer()).expect("open header signed")
}

fn headers(values: &[String]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|value| ("Jack-Auth".to_string(), value.clone()))
        .collect()
}

fn started(config: StreamVerifierConfig) -> StreamVerifier {
    let mut verifier = StreamVerifier::new(config);
    let open = opened().1;
    verifier
        .open(200, &headers(&[open.jack_auth]))
        .expect("valid open header");
    verifier
}

fn open_value(kid: &str, ts: i64, sid: &str, sig: &str) -> String {
    format_open_auth(&OpenAuth {
        kid: kid.to_string(),
        ts,
        sid: sid.to_string(),
        sig: sig.to_string(),
    })
}

fn open_outcome(config: StreamVerifierConfig, values: &[&str]) -> (Option<StreamCode>, usize) {
    let values: Vec<String> = values.iter().map(|value| value.to_string()).collect();
    let mut verifier = StreamVerifier::new(config);
    match verifier.open(200, &headers(&values)) {
        Ok(_) => (None, verifier.frames_verified()),
        Err(failure) => (Some(failure.code), failure.frames_verified),
    }
}

fn open_err(values: &[&str], config: StreamVerifierConfig, code: StreamCode) {
    assert_eq!(
        open_outcome(config, values),
        (Some(code), 0),
        "values {values:?}"
    );
}

fn open_ok(values: &[&str], config: StreamVerifierConfig) {
    assert_eq!(open_outcome(config, values), (None, 0), "values {values:?}");
}

/// Replaces one base64url character, keeping a decodable 64-byte signature.
fn corrupt(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn wires(input: &[(i64, &str)]) -> Vec<String> {
    let signer = signer();
    let (mut builder, _) = opened();
    input
        .iter()
        .map(|&(ts, data)| builder.frame(ts, data, &signer).expect("frame signed").1)
        .collect()
}

fn body(wires: &[String]) -> Vec<u8> {
    wires.concat().into_bytes()
}

fn body_of(input: &[(i64, &str)]) -> Vec<u8> {
    body(&wires(input))
}

fn samples_of(input: &[(i64, &str)]) -> Vec<i64> {
    std::iter::once(OPEN_TS)
        .chain(input.iter().map(|&(ts, _)| ts))
        .collect()
}

fn jack_line(wire: &str) -> String {
    wire.lines()
        .find(|line| line.starts_with("jack: "))
        .expect("a jack line")
        .to_string()
}

fn sign_wire(sid: &str, seq: u64, ts: i64, prev: &str, data: &str) -> String {
    let hash = data_hash(data);
    let signing_string = frame_signing_string(sid, seq, ts, prev, &hash);
    let sig = encode_b64url(&signer().sign(signing_string.as_bytes()).expect("signed"));
    let kind = if data.is_empty() {
        FrameKind::End
    } else {
        FrameKind::Message
    };
    serialize_frame(kind, data, seq, ts, &sig)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    messages: Vec<String>,
    terminal: Option<StreamCode>,
    frames: usize,
}

fn run(
    chunks: &[(usize, usize, i64)],
    body: &[u8],
    config: StreamVerifierConfig,
    silent: Option<i64>,
) -> Outcome {
    let mut verifier = started(config);
    let mut messages = Vec::new();
    let mut terminal = None;
    for &(start, end, arrived) in chunks {
        let step = verifier.push(&body[start..end], arrived);
        messages.extend(step.messages);
        if let Some(failure) = step.terminal {
            terminal = Some(failure.code);
            break;
        }
    }
    if terminal.is_none() {
        let step = verifier.finish(silent);
        messages.extend(step.messages);
        terminal = step.terminal.map(|failure| failure.code);
    }
    Outcome {
        messages,
        terminal,
        frames: verifier.frames_verified(),
    }
}

/// Split points just past every event the SSE reader completes.
fn event_chunks(body: &[u8]) -> Vec<(usize, usize)> {
    let mut reader = SseReader::new();
    let mut cuts: Vec<usize> = reader.push(body, 0).iter().map(|event| event.end).collect();
    cuts.extend(reader.finish().iter().map(|event| event.end));
    let mut chunks = Vec::new();
    let mut start = 0;
    for cut in cuts {
        if cut > start {
            chunks.push((start, cut));
            start = cut;
        }
    }
    if start < body.len() {
        chunks.push((start, body.len()));
    }
    chunks
}

fn three_ways(
    body: &[u8],
    arrive: &dyn Fn(usize) -> i64,
    make: &dyn Fn() -> StreamVerifierConfig,
) -> Outcome {
    let whole = vec![(0, body.len(), arrive(0))];
    let bytes: Vec<(usize, usize, i64)> = (0..body.len()).map(|i| (i, i + 1, arrive(i))).collect();
    let events: Vec<(usize, usize, i64)> = event_chunks(body)
        .into_iter()
        .map(|(start, end)| (start, end, arrive(start)))
        .collect();
    let first = run(&whole, body, make(), None);
    assert_eq!(first, run(&bytes, body, make(), None), "byte splits differ");
    assert_eq!(
        first,
        run(&events, body, make(), None),
        "event splits differ"
    );
    first
}

fn check_with(
    body: &[u8],
    make: &dyn Fn() -> StreamVerifierConfig,
    code: Option<StreamCode>,
    frames: usize,
    messages: &[&str],
) {
    let out = three_ways(body, &|offset| offset as i64, make);
    let messages: Vec<String> = messages.iter().map(|message| message.to_string()).collect();
    assert_eq!(out.messages, messages);
    assert_eq!(out.terminal, code);
    assert_eq!(out.frames, frames);
}

fn check(body: &[u8], samples: &[i64], code: Option<StreamCode>, frames: usize, messages: &[&str]) {
    let make = || config(samples);
    check_with(body, &make, code, frames, messages);
}

#[test]
fn open_header_codes_and_order() {
    let value = open_value(KID, OPEN_TS, SID, OPEN_SIG);
    let value_ref = value.as_str();
    let samples = [OPEN_TS];
    open_err(&[], config(&samples), MissingAuth);
    open_err(&[value_ref, value_ref], config(&samples), MalformedAuth);
    // 15-byte sid, a fifth parameter, and a 15-byte kid are grammar failures.
    let short_sid = open_value(KID, OPEN_TS, &encode_b64url(&[2u8; 15]), OPEN_SIG);
    open_err(&[&short_sid], config(&samples), MalformedAuth);
    open_err(
        &[&format!("{value},nonce=abc")],
        config(&samples),
        MalformedAuth,
    );
    let short_kid = open_value(&encode_b64url(&[7u8; 31]), OPEN_TS, SID, OPEN_SIG);
    open_err(&[&short_kid], config(&samples), MalformedAuth);
    // 2.3: the scheme is read before the parameter rules.
    open_err(
        &[&format!("s2{}", &value[2..])],
        config(&samples),
        UnsupportedVersion,
    );
    open_err(
        &[&format!("v1{}", &value[2..])],
        config(&samples),
        UnsupportedVersion,
    );
    open_err(
        &[&format!("x1{}", &value[2..])],
        config(&samples),
        MalformedAuth,
    );
    // 4.2 step 4: an unknown kid, an invalid pinned point, and a kid mismatch.
    let unknown = open_value(&encode_b64url(&[7u8; 32]), OPEN_TS, SID, OPEN_SIG);
    open_err(&[&unknown], config(&samples), UnknownServerKey);
    let invalid = RotationResponseKey {
        public_key: [0u8; 32],
        not_before: 0,
        known_cutoff: None,
    };
    open_err(&[value_ref], with_key(&samples, invalid), UnknownServerKey);
    let other_key = ServerSigningKey::from_bytes(&[3u8; 32])
        .verifying_key()
        .to_bytes();
    let mismatch = RotationResponseKey {
        public_key: other_key,
        not_before: 0,
        known_cutoff: None,
    };
    open_err(&[value_ref], with_key(&samples, mismatch), UnknownServerKey);
    // 4.2 step 5: both sides at exactly W are inside, one more is out.
    open_ok(&[value_ref], config(&[OPEN_TS + WINDOW]));
    open_ok(&[value_ref], config(&[OPEN_TS - WINDOW]));
    open_err(&[value_ref], config(&[OPEN_TS + WINDOW + 1]), OutOfWindow);
    open_err(&[value_ref], config(&[OPEN_TS - WINDOW - 1]), OutOfWindow);
    // 4.2 step 6: at the activation is refused, one below is accepted.
    open_err(&[value_ref], with_cutoff(&samples, OPEN_TS), AfterCutoff);
    open_ok(&[value_ref], with_cutoff(&samples, OPEN_TS + 1));
    // 4.2 step 7: a corrupted signature and an open signed for another request.
    let bad_sig = open_value(KID, OPEN_TS, SID, &corrupt(OPEN_SIG));
    open_err(&[&bad_sig], config(&samples), BadSignature);
    let mut spliced = config(&samples);
    spliced.request_sig = encode_b64url(&[9u8; 64]);
    open_err(&[value_ref], spliced, BadSignature);
}

#[test]
fn frame_grammar_codes() {
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, MSG_B), (OPEN_TS + 2, "")];
    let samples = samples_of(&input);
    // Two jack lines on frame 0.
    let mut w = wires(&input);
    let jack = jack_line(&w[0]);
    w[0] = w[0].replacen(&format!("{jack}\n"), &format!("{jack}\n{jack}\n"), 1);
    check(&body(&w), &samples, Some(BadFrame), 0, &[]);
    // An id or retry field on frame 1.
    let mut w = wires(&input);
    w[1] = w[1].replacen("jack: ", "id: 1\njack: ", 1);
    check(&body(&w), &samples, Some(BadFrame), 1, &[MSG_A]);
    let mut w = wires(&input);
    w[1] = w[1].replacen("jack: ", "retry: 100\njack: ", 1);
    check(&body(&w), &samples, Some(BadFrame), 1, &[MSG_A]);
    // An unknown event on frame 1.
    let mut w = wires(&input);
    w[1] = w[1].replacen("event: message", "event: notice", 1);
    check(&body(&w), &samples, Some(BadFrame), 1, &[MSG_A]);
    // The end event with data, and a message event with the empty value.
    let mut w = wires(&input);
    w[2] = w[2].replacen("event: jack-end\ndata:\n", "event: jack-end\ndata: x\n", 1);
    check(&body(&w), &samples, Some(BadFrame), 2, &[MSG_A, MSG_B]);
    let mut w = wires(&input);
    w[0] = w[0].replacen(&format!("data: {MSG_A}\n"), "", 1);
    check(&body(&w), &samples, Some(BadFrame), 0, &[]);
    // A fourth jack parameter on frame 1.
    let mut w = wires(&input);
    let jack = jack_line(&w[1]);
    w[1] = w[1].replacen(&jack, &format!("{jack},kid=x"), 1);
    check(&body(&w), &samples, Some(BadFrame), 1, &[MSG_A]);
    // Data bytes that are not UTF-8 on frame 0.
    let utf8 = [
        b"event: message\ndata: {\"\xC3(\"}\njack: seq=0,ts=1767225600,sig=".as_slice(),
        OPEN_SIG.as_bytes(),
        b"\n\n",
    ]
    .concat();
    check(&utf8, &[OPEN_TS], Some(BadFrame), 0, &[]);
    // Non-canonical seq and ts encodings on frame 0.
    let mut w = wires(&input);
    w[0] = w[0].replacen("seq=0,", "seq=00,", 1);
    check(&body(&w), &samples, Some(BadFrame), 0, &[]);
    let mut w = wires(&input);
    w[0] = w[0].replacen("ts=1767225600,", "ts=1767225600.0,", 1);
    check(&body(&w), &samples, Some(BadFrame), 0, &[]);
    let mut w = wires(&input);
    w[0] = w[0].replacen("ts=1767225600,", "ts=01767225600,", 1);
    check(&body(&w), &samples, Some(BadFrame), 0, &[]);
}

#[test]
fn frame_size_boundary() {
    let big = "a".repeat(1024);
    let input = [(OPEN_TS, big.as_str()), (OPEN_TS, "")];
    let samples = samples_of(&input);
    let capped = || {
        let mut config = config(&samples);
        config.frame_max_bytes = 1024;
        config
    };
    check_with(&body_of(&input), &capped, None, 2, &[big.as_str()]);
    // 2.17 bounds the data value: one byte over is frame_too_large.
    let over = "a".repeat(1025);
    let input = [(OPEN_TS, over.as_str()), (OPEN_TS, "")];
    check_with(&body_of(&input), &capped, Some(FrameTooLarge), 0, &[]);
    // A late oversize frame keeps the earlier message.
    let input = [
        (OPEN_TS, MSG_A),
        (OPEN_TS + 1, over.as_str()),
        (OPEN_TS + 2, ""),
    ];
    let samples = samples_of(&input);
    let capped = || {
        let mut config = config(&samples);
        config.frame_max_bytes = 1024;
        config
    };
    check_with(&body_of(&input), &capped, Some(FrameTooLarge), 1, &[MSG_A]);
}

#[test]
fn frame_seq_rules() {
    let input = [(OPEN_TS, MSG_A), (OPEN_TS, MSG_B), (OPEN_TS, "")];
    let samples = samples_of(&input);
    // First frame not seq 0.
    let mut w = wires(&input);
    w[0] = w[0].replacen("seq=0,", "seq=1,", 1);
    check(&body(&w), &samples, Some(OutOfOrder), 0, &[]);
    // A gap.
    let mut w = wires(&input);
    w[1] = w[1].replacen("seq=1,", "seq=2,", 1);
    check(&body(&w), &samples, Some(OutOfOrder), 1, &[MSG_A]);
    // A repeat signed over the chain predecessor.
    let mut w = wires(&input);
    w[1] = w[1].replacen("seq=1,", "seq=0,", 1);
    check(&body(&w), &samples, Some(OutOfOrder), 1, &[MSG_A]);
    // Frames delivered 0, 2, 1.
    let mut w = wires(&input);
    w.swap(1, 2);
    check(&body(&w), &samples, Some(OutOfOrder), 1, &[MSG_A]);
}

#[test]
fn frame_ts_rules() {
    // Frame 1 ts below frame 0 ts.
    let input = [(OPEN_TS, MSG_A), (OPEN_TS - 1, MSG_B), (OPEN_TS - 1, "")];
    let samples = [OPEN_TS, OPEN_TS, OPEN_TS - 1];
    check(&body_of(&input), &samples, Some(StaleFrame), 1, &[MSG_A]);
    // Frame 0 is exactly W behind its sample; frame 1 is 31 s behind its own.
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, MSG_B), (OPEN_TS + 1, "")];
    let samples = [OPEN_TS, OPEN_TS + WINDOW, OPEN_TS + WINDOW + 2];
    check(&body_of(&input), &samples, Some(StaleFrame), 1, &[MSG_A]);
}

#[test]
fn completed_event_precedes_oversized_unterminated_data_line_in_same_push() {
    let mut config = config(&[OPEN_TS, OPEN_TS]);
    config.frame_max_bytes = 1024;
    let mut verifier = started(config);
    let frame = wires(&[(OPEN_TS, MSG_A)]).concat();
    let oversized_line = format!("data: {}", "x".repeat(1025));
    let chunk = format!("{frame}{oversized_line}");

    let step = verifier.push(chunk.as_bytes(), 0);

    assert_eq!(step.messages, vec![MSG_A]);
    let failure = step
        .terminal
        .expect("oversized incomplete line is terminal");
    assert_eq!(failure.code, FrameTooLarge);
    assert_eq!(failure.frames_verified, 1);
    assert_eq!(verifier.frames_verified(), 1);
}

#[test]
fn oversized_unterminated_line_fails_incrementally_as_frame_too_large() {
    let mut config = config(&[OPEN_TS]);
    config.frame_max_bytes = 1024;
    let mut verifier = started(config);
    let mut terminal = None;
    for _ in 0..(1024 + 4097) {
        let step = verifier.push(b"x", 0);
        if step.terminal.is_some() {
            terminal = step.terminal;
            break;
        }
    }
    assert_eq!(terminal.map(|failure| failure.code), Some(FrameTooLarge));
    assert_eq!(verifier.frames_verified(), 0);
}

#[test]
fn frame_cutoff_rules() {
    // A frame at the cutoff.
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, MSG_B)];
    let samples = [OPEN_TS, OPEN_TS, OPEN_TS + 1];
    let make = || with_cutoff(&samples, OPEN_TS + 1);
    check_with(&body_of(&input), &make, Some(AfterCutoff), 1, &[MSG_A]);
    // The end frame itself at the cutoff, after a valid message.
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, "")];
    check_with(&body_of(&input), &make, Some(AfterCutoff), 1, &[MSG_A]);
}

#[test]
fn frame_signature_rules() {
    let input = [(OPEN_TS, MSG_A), (OPEN_TS, MSG_B), (OPEN_TS, "")];
    let samples = samples_of(&input);
    // Frame 1 signed over the open sig instead of frame 0's sig.
    let mut w = wires(&input);
    w[1] = sign_wire(SID, 1, OPEN_TS, OPEN_SIG, MSG_B);
    check(&body(&w), &samples, Some(BadSignature), 1, &[MSG_A]);
    // Frame 1 data changed after signing, its signature kept.
    let mut w = wires(&input);
    w[1] = w[1].replacen(MSG_B, MSG_C, 1);
    check(&body(&w), &samples, Some(BadSignature), 1, &[MSG_A]);
    // Frame 0 signed with another sid.
    let other_sid = encode_b64url(&[4u8; 16]);
    let mut w = wires(&input);
    w[0] = sign_wire(&other_sid, 0, OPEN_TS, OPEN_SIG, MSG_A);
    check(&body(&w), &samples, Some(BadSignature), 0, &[]);
}

#[test]
fn frame_after_end_is_out_of_order() {
    let input = [(OPEN_TS, MSG_A), (OPEN_TS, ""), (OPEN_TS, MSG_B)];
    check(
        &body_of(&input),
        &samples_of(&input),
        Some(OutOfOrder),
        2,
        &[MSG_A],
    );
}

#[test]
fn signal_and_lookalikes() {
    let head = r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":"#;
    let signal = signal_data(FrameTooLarge, 1024).expect("signalled code");
    // The exact template is a signal: counted, never delivered, ends the stream.
    let input = [(OPEN_TS, signal.as_str()), (OPEN_TS + 1, "")];
    check(
        &body_of(&input),
        &samples_of(&input),
        Some(FrameTooLarge),
        1,
        &[],
    );
    let zero = signal_data(FrameTooLarge, 0).expect("signalled code");
    let input = [(OPEN_TS, zero.as_str())];
    check(
        &body_of(&input),
        &samples_of(&input),
        Some(FrameTooLarge),
        1,
        &[],
    );
    // Every lookalike stays an ordinary message.
    let look = |tail: &str| [head, tail].concat();
    let lookalikes = [
        look(r#"1024}}"#).replacen("stream_error", "stream_errors", 1),
        look(r#"1024,"extra":true}}"#),
        look(r#"1024}}"#).replacen("stream_frame_too_large", "stream_idle", 1),
        look(r#""1024"}}"#),
        look("1e3}}"),
        look("1000.0}}"),
        look("01000}}"),
        look(r#"1024}}"#).replacen(r#"{"jsonrpc":"2.0""#, r#"{"jsonrpc": "2.0""#, 1),
        look(r#"1024}}"#).replacen(r#""code":"stream_frame_too_large""#, r#""code":1024"#, 1),
    ];
    for lookalike in lookalikes {
        let input = [(OPEN_TS, lookalike.as_str()), (OPEN_TS, "")];
        check(
            &body_of(&input),
            &samples_of(&input),
            None,
            2,
            &[lookalike.as_str()],
        );
    }
}

#[test]
fn truncation_shapes() {
    // Messages already verified stay delivered; no end frame is truncated.
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, MSG_B)];
    check(
        &body_of(&input),
        &samples_of(&input),
        Some(Truncated),
        2,
        &[MSG_A, MSG_B],
    );
    // Empty body.
    check(b"", &[OPEN_TS], Some(Truncated), 0, &[]);
    // Body ends inside the end frame; its unterminated line is discarded.
    let full = body_of(&[(OPEN_TS, MSG_A), (OPEN_TS + 1, "")]);
    check(
        &full[..full.len() - 5],
        &[OPEN_TS, OPEN_TS],
        Some(Truncated),
        1,
        &[MSG_A],
    );
    // The end-of-body flush completes one last message event.
    let w = wires(&[(OPEN_TS, MSG_A), (OPEN_TS, MSG_B)]);
    let flushed = format!("{}{}", w[0], w[1].replace("\n\n", "\n\r"));
    let out = run(
        &[(0, flushed.len(), 0)],
        flushed.as_bytes(),
        config(&[OPEN_TS, OPEN_TS, OPEN_TS]),
        None,
    );
    assert_eq!(
        out,
        Outcome {
            messages: vec![MSG_A.to_string(), MSG_B.to_string()],
            terminal: Some(Truncated),
            frames: 2
        }
    );
    // The flush completes the end frame itself: a clean ended body.
    let w = wires(&[(OPEN_TS, MSG_A), (OPEN_TS, "")]);
    let flushed = format!("{}{}", w[0], w[1].replace("\n\n", "\n\r"));
    let out = run(
        &[(0, flushed.len(), 0)],
        flushed.as_bytes(),
        config(&[OPEN_TS, OPEN_TS, OPEN_TS]),
        None,
    );
    assert_eq!(
        out,
        Outcome {
            messages: vec![MSG_A.to_string()],
            terminal: None,
            frames: 2
        }
    );
}

#[test]
fn finish_without_a_open_header_is_truncated_and_sticky() {
    let mut verifier = StreamVerifier::new(config(&[OPEN_TS]));
    let first = verifier.finish(None);
    assert_eq!(first.terminal, Some(StreamFailure::new(Truncated, 0)));
    assert_eq!(first.messages, Vec::<String>::new());
    let second = verifier.finish(None);
    assert_eq!(second, first);
}

#[test]
fn idle_rules() {
    // A gap of exactly streamIdleMs between verified frames stays alive.
    let w = wires(&[(OPEN_TS, MSG_A), (OPEN_TS + 90, MSG_B), (OPEN_TS + 180, "")]);
    let arrivals = [0i64, 90_000, 180_000];
    let samples = [OPEN_TS, OPEN_TS, OPEN_TS + 90, OPEN_TS + 180];
    let (body, chunks) = chunked(&w, &arrivals);
    let out = run(&chunks, &body, config(&samples), None);
    assert_eq!(
        out,
        Outcome {
            messages: vec![MSG_A.to_string(), MSG_B.to_string()],
            terminal: None,
            frames: 3
        }
    );
    // One millisecond past the deadline: the late frame is not verified.
    let arrivals = [0i64, 90_001, 180_000];
    let (body, chunks) = chunked(&w, &arrivals);
    let out = run(&chunks, &body, config(&samples), None);
    assert_eq!(
        out,
        Outcome {
            messages: vec![MSG_A.to_string()],
            terminal: Some(Idle),
            frames: 1
        }
    );
    // Heartbeats reset the timer: 160 s alive with no 90 s gap.
    let hb = r#"{"jsonrpc":"2.0","method":"notifications/events/heartbeat","params":{}}"#;
    let w = wires(&[
        (OPEN_TS, hb),
        (OPEN_TS + 80, hb),
        (OPEN_TS + 160, hb),
        (OPEN_TS + 160, ""),
    ]);
    let arrivals = [0i64, 80_000, 160_000, 160_000];
    let samples = [OPEN_TS, OPEN_TS, OPEN_TS + 80, OPEN_TS + 160, OPEN_TS + 160];
    let (body, chunks) = chunked(&w, &arrivals);
    let out = run(&chunks, &body, config(&samples), None);
    assert_eq!(
        out,
        Outcome {
            messages: vec![hb.to_string(); 3],
            terminal: None,
            frames: 4
        }
    );
    // Valid opener, no bytes, more than streamIdleMs of silence.
    let out = run(&[], b"", config(&[OPEN_TS]), Some(90_001));
    assert_eq!(
        out,
        Outcome {
            messages: vec![],
            terminal: Some(Idle),
            frames: 0
        }
    );
    // Exactly streamIdleMs is a live connection, not a terminal.
    let out = run(&[], b"", config(&[OPEN_TS]), Some(90_000));
    assert_eq!(
        out,
        Outcome {
            messages: vec![],
            terminal: None,
            frames: 0
        }
    );
    // A comment resets nothing: 80 s + 20 s of silence is idle.
    let w = wires(&[(OPEN_TS, MSG_A)]);
    let mut body = w[0].clone().into_bytes();
    let cut = body.len();
    body.extend_from_slice(b": keepalive\n");
    let chunks = [(0, cut, 0i64), (cut, body.len(), 80_000)];
    let out = run(&chunks, &body, config(&[OPEN_TS, OPEN_TS]), Some(20_000));
    assert_eq!(
        out,
        Outcome {
            messages: vec![MSG_A.to_string()],
            terminal: Some(Idle),
            frames: 1
        }
    );
    // A late final newline still completes frame 0 after the deadline.
    let w = wires(&[(OPEN_TS, MSG_A), (OPEN_TS, "")]);
    for bom in [false, true] {
        let mut body = Vec::new();
        if bom {
            body.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        }
        body.extend_from_slice(&w[0].as_bytes()[..w[0].len() - 1]);
        let cut = body.len();
        body.push(b'\n');
        body.extend_from_slice(w[1].as_bytes());
        let chunks = [(0, cut, 0i64), (cut, body.len(), 90_001)];
        let out = run(&chunks, &body, config(&[OPEN_TS]), None);
        assert_eq!(
            out,
            Outcome {
                messages: vec![],
                terminal: Some(Idle),
                frames: 0
            }
        );
    }
}

fn chunked(wires: &[String], arrivals: &[i64]) -> (Vec<u8>, Vec<(usize, usize, i64)>) {
    let mut body = Vec::new();
    let mut chunks = Vec::new();
    for (wire, arrived) in wires.iter().zip(arrivals) {
        let start = body.len();
        body.extend_from_slice(wire.as_bytes());
        chunks.push((start, body.len(), *arrived));
    }
    (body, chunks)
}

#[test]
fn stdio_consumer_rules() {
    let stdio = |samples: Vec<i64>| {
        move || {
            let mut config = config(&samples);
            config.consumer = StreamConsumer::Stdio;
            config
        }
    };
    let input = [(OPEN_TS, MSG_A), (OPEN_TS, MSG_B), (OPEN_TS, "")];
    check_with(
        &body_of(&input),
        &stdio(samples_of(&input)),
        None,
        3,
        &[MSG_A, MSG_B],
    );
    // A raw LF in a verified value aborts after the frame counted.
    let input = [(OPEN_TS, "one\ntwo"), (OPEN_TS, "")];
    check_with(
        &body_of(&input),
        &stdio(samples_of(&input)),
        Some(BadFrame),
        1,
        &[],
    );
    // A raw CR byte is an SSE line terminator, so it can never reach the
    // consumer inside one value. The wire splits into `data: one` and an
    // ignored `two` field, and the signature over `one` still verifies.
    let mut w = wires(&[(OPEN_TS, "one"), (OPEN_TS, "")]);
    w[0] = w[0].replacen("data: one\n", "data: one\rtwo\n", 1);
    let samples = samples_of(&[(OPEN_TS, ""), (OPEN_TS, "")]);
    check_with(&body(&w), &stdio(samples), None, 2, &["one"]);
}

#[test]
fn close_lookalikes_are_ordinary_messages() {
    let lookalikes = [
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
        r#"{"id":1,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
        r#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
    ];
    for lookalike in lookalikes {
        let input = [(OPEN_TS, lookalike), (OPEN_TS, "")];
        check(&body_of(&input), &samples_of(&input), None, 2, &[lookalike]);
    }
}

#[test]
fn truncated_body_without_end_never_completes() {
    let final_response = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}"#;
    let input = [(OPEN_TS, MSG_A), (OPEN_TS + 1, final_response)];
    check(
        &body_of(&input),
        &samples_of(&input),
        Some(Truncated),
        2,
        &[MSG_A, final_response],
    );
}
