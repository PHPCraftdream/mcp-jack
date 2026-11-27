use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mcp_jack::client::RotationResponseKey;
use mcp_jack::encoding::{decode_b64url, encode_b64url};
use mcp_jack::stream::{
    StaticStreamSigner, StreamBuilder, StreamConsumer, StreamVerifier, StreamVerifierConfig,
};
use mcp_jack::user_key::ServerSigningKey;
use serde_json::Value;

const CLIENT_CASES: usize = 80;
const BUILD_CASES: usize = 8;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures")
}

fn load(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn int(value: &Value, name: &str) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("{name} must be an integer: {value}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{name} must be a string: {value}"))
}

fn as_bytes(body_parts: &[Value], fill: Option<&Value>) -> (Vec<u8>, Vec<usize>) {
    let mut body = Vec::new();
    let mut spans = Vec::new();
    for part in body_parts {
        if part.as_str() == Some("@data_fill@") {
            let spec = fill.expect("@data_fill@ marker without data_fill spec");
            let byte = text(&spec["byte"], "data_fill.byte").as_bytes();
            assert_eq!(byte.len(), 1, "data_fill byte must be one UTF-8 byte");
            let count = spec["count"].as_u64().expect("data_fill.count") as usize;
            let bytes = vec![byte[0]; count];
            spans.push(bytes.len());
            body.extend(bytes);
        } else {
            let bytes =
                decode_b64url(text(part, "stream_b64u chunk")).expect("canonical stream chunk");
            spans.push(bytes.len());
            body.extend(bytes);
        }
    }
    (body, spans)
}

fn is_rpc_response(message: &str, request_id: &Value) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(message) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && !object.contains_key("method")
        && object.get("id") == Some(request_id)
        && object.contains_key("result") != object.contains_key("error")
}

fn check_outcome(
    case: &Value,
    messages: &[String],
    terminal: Option<mcp_jack::stream::StreamFailure>,
) {
    let expect = &case["expect"];
    let wanted: Vec<String> = expect["messages"]
        .as_array()
        .expect("expect.messages")
        .iter()
        .map(|v| match v {
            Value::String(message) => message.clone(),
            marker => {
                let spec = &marker["data_fill"];
                let byte = text(&spec["byte"], "expected data_fill.byte").as_bytes();
                assert_eq!(
                    byte.len(),
                    1,
                    "expected data_fill byte must be one UTF-8 byte"
                );
                assert!(byte[0].is_ascii(), "expected data_fill byte must be ASCII");
                let count = spec["count"].as_u64().expect("expected data_fill.count") as usize;
                String::from_utf8(vec![byte[0]; count]).expect("ASCII data_fill byte")
            }
        })
        .collect();
    assert_eq!(messages, wanted, "{} messages", case["id"]);
    let state = text(&expect["terminal"]["state"], "terminal.state");
    if state == "ok" {
        assert!(
            terminal.is_none(),
            "{} unexpected terminal: {terminal:?}",
            case["id"]
        );
    } else {
        let failure = terminal.unwrap_or_else(|| panic!("{} expected error terminal", case["id"]));
        assert_eq!(
            failure.code.as_str(),
            text(&expect["terminal"]["code"], "terminal.code"),
            "{} code",
            case["id"]
        );
        assert_eq!(
            failure.frames_verified,
            expect["terminal"]["frames_verified"].as_u64().unwrap() as usize,
            "{} frame count",
            case["id"]
        );
    }
    if let Some(expected) = expect.get("mcp_complete") {
        let last = messages.last();
        let actual = state == "ok"
            && case.get("silent_after_ms").is_none_or(Value::is_null)
            && last.is_some_and(|message| is_rpc_response(message, &case["state"]["request_id"]));
        assert_eq!(
            expected.as_bool(),
            Some(actual),
            "{} mcp_complete",
            case["id"]
        );
    }
}

fn run_variant(
    case: &Value,
    body: &[u8],
    spans: &[usize],
    mode: usize,
) -> (Vec<String>, Option<mcp_jack::stream::StreamFailure>, usize) {
    let state = &case["state"];
    let response = &case["response"];
    let expected_key = decode_b64url(text(
        &state["pinned_server_public_key"],
        "pinned public key",
    ))
    .expect("key");
    let public_key: [u8; 32] = expected_key.try_into().expect("32-byte pinned key");
    let kid = text(&state["pinned_server_kid"], "pinned kid").to_owned();
    let mut keys = BTreeMap::new();
    keys.insert(
        kid,
        RotationResponseKey {
            public_key,
            not_before: 0,
            known_cutoff: state["successor_activation"].as_i64(),
        },
    );
    let samples: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let open_now = int(&state["now"], "state.now");
    let nows: Vec<i64> = state
        .get("frame_nows")
        .map(|values| {
            values
                .as_array()
                .expect("state.frame_nows must be an array")
                .iter()
                .map(|value| int(value, "frame_now"))
                .collect()
        })
        .unwrap_or_default();
    let sample_copy = Arc::clone(&samples);
    let mut config = StreamVerifierConfig::new(keys, text(&state["request_sig"], "request_sig"));
    config.window_seconds = int(&state["window_seconds"], "window_seconds");
    config.frame_max_bytes = state["frame_max_bytes"].as_u64().expect("frame_max_bytes") as usize;
    config.stream_idle_ms = state
        .get("stream_idle_ms")
        .and_then(Value::as_i64)
        .unwrap_or(90_000);
    config.consumer = match case
        .get("consumer")
        .and_then(Value::as_str)
        .unwrap_or("mcp")
    {
        "mcp" => StreamConsumer::Message,
        "stdio" => StreamConsumer::Stdio,
        consumer => panic!("unknown consumer: {consumer}"),
    };
    config.now = Arc::new(move || {
        let mut samples = sample_copy.lock().unwrap();
        let index = samples.len();
        let value = if index == 0 {
            open_now
        } else {
            nows.get(index - 1)
                .copied()
                .or_else(|| nows.last().copied())
                .unwrap_or(open_now)
        };
        samples.push(value);
        value
    });
    let mut verifier = StreamVerifier::new(config);
    let headers: Vec<(String, String)> = response["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .map(|pair| {
            (
                text(&pair[0], "header name").to_owned(),
                text(&pair[1], "header value").to_owned(),
            )
        })
        .collect();
    let mut messages = Vec::new();
    let mut terminal = verifier
        .open(
            response["status"].as_u64().expect("status") as u16,
            &headers,
        )
        .err();

    let arrival = case.get("arrival_ms").map(|value| {
        value
            .as_array()
            .expect("arrival_ms must be an array")
            .iter()
            .map(|time| int(time, "arrival_ms entry"))
            .collect::<Vec<_>>()
    });
    if let Some(times) = &arrival {
        assert_eq!(times.len(), spans.len(), "{} arrival_ms length", case["id"]);
    }
    let time_for = |offset: usize| -> i64 {
        let Some(times) = &arrival else {
            return 0;
        };
        let mut end = 0usize;
        for (i, length) in spans.iter().enumerate() {
            end += length;
            if offset < end {
                return times[i];
            }
        }
        0
    };
    if terminal.is_none() {
        let chunks: Vec<(usize, usize)> = match mode {
            0 => {
                if body.is_empty() {
                    vec![]
                } else {
                    vec![(0, body.len())]
                }
            }
            1 => (0..body.len()).map(|i| (i, i + 1)).collect(),
            _ => {
                let mut boundaries = vec![0];
                let mut i = 0;
                let mut previous_terminator_end = None;
                while i < body.len() {
                    let terminator_end = match body[i] {
                        b'\r' if body.get(i + 1) == Some(&b'\n') => i + 2,
                        b'\r' | b'\n' => i + 1,
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    if previous_terminator_end == Some(i) {
                        boundaries.push(terminator_end);
                    }
                    previous_terminator_end = Some(terminator_end);
                    i = terminator_end;
                }
                if boundaries.last().copied() != Some(body.len()) {
                    boundaries.push(body.len());
                }
                boundaries
                    .windows(2)
                    .filter(|w| w[1] > w[0])
                    .map(|w| (w[0], w[1]))
                    .collect()
            }
        };
        // A chunk never straddles two arrival times: split it at the span edges.
        let chunks: Vec<(usize, usize)> = if arrival.is_some() {
            let mut cuts = Vec::new();
            let mut edge = 0usize;
            for length in spans {
                edge += length;
                cuts.push(edge);
            }
            let mut split = Vec::new();
            for (start, end) in chunks {
                let mut from = start;
                for cut in &cuts {
                    if *cut > from && *cut < end {
                        split.push((from, *cut));
                        from = *cut;
                    }
                }
                split.push((from, end));
            }
            split
        } else {
            chunks
        };
        for (start, end) in chunks {
            let time = time_for(end - 1);
            let step = verifier.push(&body[start..end], time);
            messages.extend(step.messages);
            if step.terminal.is_some() {
                terminal = step.terminal;
                break;
            }
        }
        if terminal.is_none() {
            let silent = case
                .get("silent_after_ms")
                .filter(|value| !value.is_null())
                .map(|value| int(value, "silent_after_ms"));
            let step = verifier.finish(silent);
            messages.extend(step.messages);
            terminal = step.terminal;
        }
    }
    check_outcome(case, &messages, terminal);
    (messages, terminal, verifier.frames_verified())
}

fn run_client_corpus() {
    let path = fixture_dir().join("modern/stream-vectors.json");
    let cases = load(&path)["cases"]
        .as_array()
        .expect("client cases")
        .clone();
    assert_eq!(cases.len(), CLIENT_CASES, "client corpus case count");
    for case in &cases {
        let (body, spans) = as_bytes(
            case["response"]["stream_b64u"]
                .as_array()
                .expect("stream chunks"),
            case.get("data_fill"),
        );
        let mut baseline = None;
        for mode in 0..3 {
            let outcome = run_variant(case, &body, &spans, mode);
            if let Some(expected) = &baseline {
                assert_eq!(
                    &outcome, expected,
                    "{} chunking mode {mode} differs from whole-body outcome",
                    case["id"]
                );
            } else {
                baseline = Some(outcome);
            }
        }
    }
    println!("VECTOR-SUMMARY corpus=stream sdk=rust pass=80 excluded=0 deviation=0");
}

fn seed_from_hex(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert_eq!(bytes.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(std::str::from_utf8(&bytes[2 * i..2 * i + 2]).unwrap(), 16).unwrap();
    }
    out
}

fn run_build_corpus() {
    let fixture_root = fixture_dir();
    let keys = load(&fixture_root.join("keys.json"));
    let svc = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["name"] == "svc")
        .expect("svc seed");
    let signer = StaticStreamSigner::new(
        ServerSigningKey::from_bytes(&seed_from_hex(text(&svc["seed_hex"], "svc seed_hex"))),
        None,
    );
    let cases = load(&fixture_root.join("modern/stream-build-vectors.json"))["cases"]
        .as_array()
        .expect("build cases")
        .clone();
    assert_eq!(cases.len(), BUILD_CASES, "build corpus case count");
    for case in &cases {
        let input = &case["input"];
        let (mut builder, open) = StreamBuilder::open(
            input["status"].as_u64().unwrap() as u16,
            text(&input["request_sig"], "request_sig"),
            text(&input["kid"], "kid"),
            int(&input["open_ts"], "open_ts"),
            text(&input["sid"], "sid"),
            &signer,
        )
        .expect("open signature");
        let expected = &case["expect"];
        assert_eq!(
            open.jack_auth,
            text(&expected["jack_auth"], "expected jack_auth"),
            "{} open",
            case["id"]
        );
        assert_eq!(
            open.signing_string,
            text(
                &expected["open_signing_string"],
                "expected open signing string"
            ),
            "{} signing string",
            case["id"]
        );
        let mut stream = Vec::new();
        let expected_frames = expected["frames"].as_array().expect("expected frames");
        let input_frames = input["frames"].as_array().expect("input frames");
        assert_eq!(input_frames.len(), expected_frames.len());
        for (frame_input, frame_expect) in input_frames.iter().zip(expected_frames) {
            let (frame, wire) = builder
                .frame(
                    int(&frame_input["ts"], "frame ts"),
                    text(&frame_input["data"], "frame data"),
                    &signer,
                )
                .expect("frame signature");
            assert_eq!(
                frame.seq,
                frame_expect["seq"].as_u64().unwrap(),
                "{} seq",
                case["id"]
            );
            assert_eq!(
                frame.ts,
                frame_expect["ts"].as_i64().unwrap(),
                "{} ts",
                case["id"]
            );
            assert_eq!(
                frame.prev,
                text(&frame_expect["prev"], "prev"),
                "{} prev",
                case["id"]
            );
            assert_eq!(
                frame.data_hash,
                text(&frame_expect["data_hash"], "data_hash"),
                "{} data_hash",
                case["id"]
            );
            assert_eq!(
                frame.signing_string,
                text(&frame_expect["signing_string"], "frame signing_string"),
                "{} frame signing_string",
                case["id"]
            );
            assert_eq!(
                frame.sig,
                text(&frame_expect["sig"], "frame sig"),
                "{} frame sig",
                case["id"]
            );
            stream.extend_from_slice(wire.as_bytes());
        }
        assert_eq!(
            encode_b64url(&stream),
            text(&expected["stream_b64u"], "stream_b64u"),
            "{} stream bytes",
            case["id"]
        );
    }
    println!("VECTOR-SUMMARY corpus=stream-build sdk=rust pass=8 excluded=0 deviation=0");
}

#[test]
fn client_verification_vectors() {
    run_client_corpus();
}

#[test]
fn server_build_vectors() {
    run_build_corpus();
}
