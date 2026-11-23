//! Header and frame grammar tests: the exact codes of spec 05 sections 4.2
//! steps 1-3, the signing strings of the build vectors, the 2.18 signal
//! template, the frame field rules of 2.6-2.13, `Jack-Accept` (1.1) and the
//! routing rule (1.4).

use crate::encoding::encode_b64url;
use crate::stream::{
    accepts_s1, data_hash, format_open_auth, frame_signing_string, is_event_stream,
    open_signing_string, parse_frame, parse_jack_accept, parse_open_auth, parse_signal,
    serialize_frame, signal_data, FrameKind, JackAccept, JackFrame, OpenAuth, SseField, StreamCode,
    StreamFailure,
};

// Values of spec/fixtures/modern/stream-build-vectors.json "build-open" and
// "build-only-end", copied by hand.
const REQUEST_SIG: &str =
    "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw";
const FIXTURE_KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";
const FIXTURE_SID: &str = "q9nUNYuH-Xf_cgJBVu4_Dg";
const FIXTURE_OPEN_SIG: &str =
    "LTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ";
const EMPTY_HASH: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

// "build-open": expect.open_signing_string, exactly.
const OPEN_SIGNING_STRING: &str = "mcp-jack/stream1/open\n200\nOsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw\nwltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88\n1767225600\nq9nUNYuH-Xf_cgJBVu4_Dg";

// "build-only-end": expect.frames[0].signing_string, exactly.
const END_FRAME_SIGNING_STRING: &str = "mcp-jack/stream1/frame\nq9nUNYuH-Xf_cgJBVu4_Dg\n0\n1767225601\nLTE8doFNPgqOVb_LI-8rW-i295JexxTPR85x5XRzOLCTtIOlz8r4uuZZ1lr2QZeLdk15masENOU9rZScH8TBAQ\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

// "build-multiline": input.frames[0].data and expect.frames[0].
const MULTILINE_DATA: &str = "{\n  \"jsonrpc\": \"2.0\",\n  \"method\": \"notifications/message\",\n  \"params\": {\"data\": \"multi\"}\n}";
const MULTILINE_HASH: &str = "3aJZU1bGVyEDwSO4HdFAUup9rWlDPQBV-Egh0bF9Uls";
const MULTILINE_SIG: &str =
    "YFBaZCE7EFvha3zpGFC0CGfoSiJHrAOfCv2abn4SMS1lx_LbbLnmpXTIpAK5Lgd0oOmFKnzwXAACKsw3lWBmBQ";
const MULTILINE_WIRE: &str = "event: message\ndata: {\ndata:   \"jsonrpc\": \"2.0\",\ndata:   \"method\": \"notifications/message\",\ndata:   \"params\": {\"data\": \"multi\"}\ndata: }\njack: seq=0,ts=1767225600,sig=YFBaZCE7EFvha3zpGFC0CGfoSiJHrAOfCv2abn4SMS1lx_LbbLnmpXTIpAK5Lgd0oOmFKnzwXAACKsw3lWBmBQ\n\n";

// Specification of the 2.18 signal template up to the limit digits.
const SIGNAL_HEAD: &str = r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":"#;

fn kid() -> String {
    encode_b64url(&[1u8; 32])
}

fn sid() -> String {
    encode_b64url(&[2u8; 16])
}

fn sig() -> String {
    encode_b64url(&[3u8; 64])
}

fn open_value(kid: &str, ts: &str, sid: &str, sig: &str) -> String {
    format!("s1 kid={kid},ts={ts},sid={sid},sig={sig}")
}

fn canonical() -> String {
    open_value(&kid(), "1", &sid(), &sig())
}

fn expect_open_err(values: &[&str], code: StreamCode) {
    assert_eq!(
        parse_open_auth(values),
        Err(code),
        "parse_open_auth({values:?})"
    );
}

fn signal_text(limit: &str) -> String {
    let mut out = String::from(SIGNAL_HEAD);
    out.push_str(limit);
    out.push_str("}}");
    out
}

fn field(name: &str, value: &str) -> SseField {
    SseField {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    }
}

fn jack_field(extra: &str) -> SseField {
    field("jack", &format!("seq=0,ts=1767225600,sig={}{extra}", sig()))
}

fn message_echo() -> Vec<SseField> {
    vec![
        field("event", "message"),
        field("data", "{}"),
        jack_field(""),
    ]
}

#[test]
fn code_vocabulary() {
    // Spec 05 section 4.6, in order.
    let want = [
        "stream_missing_auth",
        "stream_malformed_auth",
        "stream_unsupported_version",
        "stream_unknown_server_key",
        "stream_out_of_window",
        "stream_bad_signature",
        "stream_bad_frame",
        "stream_out_of_order",
        "stream_stale_frame",
        "stream_truncated",
        "stream_idle",
        "stream_frame_too_large",
        "stream_after_cutoff",
    ];
    assert_eq!(StreamCode::ALL.len(), want.len());
    for (code, wire) in StreamCode::ALL.into_iter().zip(want) {
        assert_eq!(code.as_str(), wire);
        assert_eq!(code.to_string(), wire);
        assert_eq!(StreamCode::from_code(wire), Some(code));
    }
    assert_eq!(StreamCode::from_code("stream_errors"), None);
    assert_eq!(StreamCode::from_code(""), None);
    assert_eq!(StreamCode::from_code("STREAM_BAD_FRAME"), None);
}

#[test]
fn failure_display() {
    let failure = StreamFailure::new(StreamCode::BadFrame, 3);
    assert_eq!(failure.code, StreamCode::BadFrame);
    assert_eq!(failure.frames_verified, 3);
    assert_eq!(
        failure.to_string(),
        "jack: stream stream_bad_frame after 3 frames"
    );
}

#[test]
fn open_missing_and_duplicate() {
    expect_open_err(&[], StreamCode::MissingAuth);
    let value = canonical();
    expect_open_err(&[value.as_str(), value.as_str()], StreamCode::MalformedAuth);
}

#[test]
fn open_accepts_canonical() {
    let want = OpenAuth {
        kid: kid(),
        ts: 1,
        sid: sid(),
        sig: sig(),
    };
    let value = format_open_auth(&want);
    assert_eq!(value, canonical());
    assert_eq!(parse_open_auth(&[value.as_str()]), Ok(want.clone()));
    assert_eq!(format_open_auth(&want), value);
    // Parameter order is free within 2.2.
    let reordered = format!("s1 sig={},ts=1,kid={},sid={}", sig(), kid(), sid());
    assert_eq!(parse_open_auth(&[reordered.as_str()]), Ok(want));
}

#[test]
fn open_scheme_precedence() {
    let value = canonical();
    for scheme in ["s2", "v1", "s10", "v9"] {
        let replaced = value.replacen("s1 ", &format!("{scheme} "), 1);
        expect_open_err(&[replaced.as_str()], StreamCode::UnsupportedVersion);
    }
    // The scheme wins over broken parameters (2.3).
    expect_open_err(&["s2 garbage"], StreamCode::UnsupportedVersion);
    expect_open_err(&["v1"], StreamCode::UnsupportedVersion);
    for scheme in ["x1", "S1", "s", "sx", "s1x", " v1", "v"] {
        let replaced = value.replacen("s1 ", &format!("{scheme} "), 1);
        expect_open_err(&[replaced.as_str()], StreamCode::MalformedAuth);
    }
    expect_open_err(&["s1"], StreamCode::MalformedAuth);
    expect_open_err(&[""], StreamCode::MalformedAuth);
}

#[test]
fn open_parameters() {
    let value = canonical();
    // Extra parameter.
    expect_open_err(
        &[format!("{value},x=1").as_str()],
        StreamCode::MalformedAuth,
    );
    // Repeated parameter.
    expect_open_err(
        &[value.replacen("ts=1,", "ts=1,ts=1,", 1).as_str()],
        StreamCode::MalformedAuth,
    );
    // Missing parameter.
    let no_sid = format!("s1 kid={},ts=1,sig={}", kid(), sig());
    expect_open_err(&[no_sid.as_str()], StreamCode::MalformedAuth);
    // Empty parameter member, no '=', space inside the value.
    expect_open_err(&[format!("{value},").as_str()], StreamCode::MalformedAuth);
    expect_open_err(
        &[format!("{value},kid").as_str()],
        StreamCode::MalformedAuth,
    );
    expect_open_err(
        &[value.replacen("sid=", "sid=a b", 1).as_str()],
        StreamCode::MalformedAuth,
    );
    // Two spaces before the parameters.
    expect_open_err(
        &[value.replacen("s1 ", "s1  ", 1).as_str()],
        StreamCode::MalformedAuth,
    );
}

#[test]
fn open_ts_rules() {
    let value = canonical();
    for ts in ["01", "1234567890123", "-1", "+1", "1.0", "", "1e3", "0x10"] {
        let replaced = value.replacen("ts=1,", &format!("ts={ts},"), 1);
        expect_open_err(&[replaced.as_str()], StreamCode::MalformedAuth);
    }
    let zero = value.replacen("ts=1,", "ts=0,", 1);
    let parsed = parse_open_auth(&[zero.as_str()]).expect("ts=0 must parse");
    assert_eq!(parsed.ts, 0);
    let max = value.replacen("ts=1,", "ts=999999999999,", 1);
    let parsed = parse_open_auth(&[max.as_str()]).expect("12 digits must parse");
    assert_eq!(parsed.ts, 999_999_999_999);
}

#[test]
fn open_encodings() {
    let value = canonical();
    // A 15-byte sid encodes to 20 characters, not 22.
    let short_sid = encode_b64url(&[2u8; 15]);
    assert_eq!(short_sid.len(), 20);
    let bad_sid = value.replacen(&sid(), &short_sid, 1);
    expect_open_err(&[bad_sid.as_str()], StreamCode::MalformedAuth);
    // A 31-byte kid.
    let short_kid = encode_b64url(&[1u8; 31]);
    let bad_kid = value.replacen(&kid(), &short_kid, 1);
    expect_open_err(&[bad_kid.as_str()], StreamCode::MalformedAuth);
    // A 63-byte sig.
    let short_sig = encode_b64url(&[3u8; 63]);
    let bad_sig = value.replacen(&sig(), &short_sig, 1);
    expect_open_err(&[bad_sig.as_str()], StreamCode::MalformedAuth);
    // Padding is not canonical unpadded base64url.
    expect_open_err(
        &[value.replacen(&sig(), &format!("{}=", sig()), 1).as_str()],
        StreamCode::MalformedAuth,
    );
    // Foreign characters.
    let foreign_kid = format!("+{}", &kid()[1..]);
    expect_open_err(
        &[value.replacen(&kid(), &foreign_kid, 1).as_str()],
        StreamCode::MalformedAuth,
    );
}

#[test]
fn signing_strings_match_build_vectors() {
    assert_eq!(
        open_signing_string(200, REQUEST_SIG, FIXTURE_KID, 1767225600, FIXTURE_SID),
        OPEN_SIGNING_STRING
    );
    assert_eq!(
        frame_signing_string(FIXTURE_SID, 0, 1767225601, FIXTURE_OPEN_SIG, &data_hash("")),
        END_FRAME_SIGNING_STRING
    );
    assert_eq!(data_hash(""), EMPTY_HASH);
    assert_eq!(data_hash(""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    // "build-multiline" frame 0.
    assert_eq!(data_hash(MULTILINE_DATA), MULTILINE_HASH);
    assert_eq!(
        frame_signing_string(FIXTURE_SID, 0, 1767225600, FIXTURE_OPEN_SIG, MULTILINE_HASH),
        format!(
            "mcp-jack/stream1/frame\n{FIXTURE_SID}\n0\n1767225600\n{FIXTURE_OPEN_SIG}\n{MULTILINE_HASH}"
        )
    );
    // The signing strings are six LF-joined lines with no trailing LF.
    for string in [OPEN_SIGNING_STRING, END_FRAME_SIGNING_STRING] {
        assert_eq!(string.split('\n').count(), 6);
        assert!(!string.ends_with('\n'));
    }
}

#[test]
fn signal_accepts_canonical_template() {
    for limit in ["0", "1", "1024", "1048576", "9007199254740991"] {
        assert_eq!(
            parse_signal(&signal_text(limit)),
            Some(StreamCode::FrameTooLarge),
            "limit {limit}"
        );
    }
    // The build vector's oversize signal.
    assert_eq!(
        parse_signal(
            r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1024}}"#
        ),
        Some(StreamCode::FrameTooLarge)
    );
}

#[test]
fn signal_rejects_non_canonical_limits() {
    for limit in [
        "01",
        "+1000",
        "-1",
        "1e3",
        "1000.0",
        "01000",
        "9007199254740992",
        "99999999999999999999999999",
        "",
        " 1000",
        "1000 ",
    ] {
        assert_eq!(parse_signal(&signal_text(limit)), None, "limit {limit:?}");
    }
}

#[test]
fn signal_rejects_lookalikes() {
    // Every lookalike of spec/tests/modern/CASES.md
    // `stream-ok-signal-lookalike-*`, byte for byte from the vectors.
    let lookalikes = [
        // method "stream_errors"
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_errors","params":{"code":"stream_frame_too_large","limit":1048576}}"#,
        // an extra params member
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1048576,"extra":1}}"#,
        // code "stream_idle" is outside the signalled set
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_idle","limit":1048576}}"#,
        // a numeric code
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":5,"limit":1000}}"#,
        // a string limit
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":"1048576"}}"#,
        // limit 1e3
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1e3}}"#,
        // limit 1000.0
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1000.0}}"#,
        // limit 01000
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":01000}}"#,
        // one extra space
        r#"{"jsonrpc":"2.0", "method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large","limit":1000}}"#,
        // a missing member
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"code":"stream_frame_too_large"}}"#,
        // reordered members
        r#"{"jsonrpc":"2.0","method":"notifications/jack/stream_error","params":{"limit":1000,"code":"stream_frame_too_large"}}"#,
    ];
    for data in lookalikes {
        assert_eq!(parse_signal(data), None, "lookalike {data:?}");
    }
    // A trailing byte keeps it a message as well.
    let padded = format!("{} ", signal_text("1000"));
    assert_eq!(parse_signal(&padded), None);
}

#[test]
fn signal_data_builds_the_template() {
    assert_eq!(
        signal_data(StreamCode::FrameTooLarge, 1024),
        Some(signal_text("1024"))
    );
    assert_eq!(
        signal_data(StreamCode::FrameTooLarge, 0),
        Some(signal_text("0"))
    );
    // Only the signalled set may be written.
    for code in StreamCode::ALL {
        if code != StreamCode::FrameTooLarge {
            assert_eq!(signal_data(code, 1024), None, "{code}");
        }
    }
    // Whatever signal_data writes parses back to the same code.
    let data = signal_data(StreamCode::FrameTooLarge, 1048576).expect("signalled");
    assert_eq!(parse_signal(&data), Some(StreamCode::FrameTooLarge));
}

#[test]
fn serialize_message_with_lfs() {
    let wire = serialize_frame(
        FrameKind::Message,
        MULTILINE_DATA,
        0,
        1767225600,
        MULTILINE_SIG,
    );
    assert_eq!(wire, MULTILINE_WIRE);
    // Empty pieces inside the data become bare `data:` lines.
    let wire = serialize_frame(FrameKind::Message, "a\n\nb", 7, 8, "s");
    assert_eq!(
        wire,
        "event: message\ndata: a\ndata:\ndata: b\njack: seq=7,ts=8,sig=s\n\n"
    );
}

#[test]
fn serialize_end_frame() {
    let wire = serialize_frame(FrameKind::End, "", 1, 1767225601, FIXTURE_OPEN_SIG);
    assert_eq!(
        wire,
        format!("event: jack-end\ndata:\njack: seq=1,ts=1767225601,sig={FIXTURE_OPEN_SIG}\n\n")
    );
    assert_eq!(wire.matches("\ndata:").count(), 1);
    assert!(wire.ends_with("\n\n"));
    assert!(!wire.contains('\r'));
}

#[test]
fn parse_frame_accepts() {
    let want = JackFrame {
        kind: FrameKind::Message,
        data: "{}".to_string(),
        seq: 0,
        ts: 1767225600,
        sig: sig(),
    };
    assert_eq!(parse_frame(&message_echo()), Ok(want.clone()));
    // 2.6: a missing event line means the default event type.
    let no_event = vec![field("data", "{}"), jack_field("")];
    assert_eq!(parse_frame(&no_event), Ok(want.clone()));
    // 2.13: unknown fields carry nothing and are ignored.
    let unknown = vec![
        field("event", "message"),
        field("x-unknown", "v"),
        field("data", "{}"),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&unknown), Ok(want.clone()));
    // The end frame has empty data (2.16).
    let end = vec![field("event", "jack-end"), jack_field("")];
    assert_eq!(
        parse_frame(&end),
        Ok(JackFrame {
            kind: FrameKind::End,
            data: String::new(),
            seq: 0,
            ts: 1767225600,
            sig: sig(),
        })
    );
    assert_eq!(FrameKind::Message.event_name(), "message");
    assert_eq!(FrameKind::End.event_name(), "jack-end");
}

#[test]
fn parse_frame_joins_data_with_lf() {
    // 2.10: `data: {"a":` plus `data: 1}` gives `{"a":\n1}`.
    let lines = vec![
        field("data", "{\"a\":"),
        field("data", "1}"),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&lines).expect("must parse").data, "{\"a\":\n1}");
}

#[test]
fn parse_frame_rejections() {
    let bad = Err(StreamCode::BadFrame);
    // Two jack lines (2.7).
    let two_jack = vec![
        field("event", "message"),
        field("data", "{}"),
        jack_field(""),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&two_jack), bad);
    // No jack line (2.7).
    let no_jack = vec![field("event", "message"), field("data", "{}")];
    assert_eq!(parse_frame(&no_jack), bad);
    // The id and retry fields must not appear (2.11).
    for forbidden in ["id", "retry"] {
        let with_field = vec![
            field("event", "message"),
            field("data", "{}"),
            field(forbidden, "1"),
            jack_field(""),
        ];
        assert_eq!(parse_frame(&with_field), bad, "{forbidden}");
    }
    // Any other event value (2.8).
    let unknown_event = vec![field("event", "jack-end!"), jack_field("")];
    assert_eq!(parse_frame(&unknown_event), bad);
    // Two event lines (2.8).
    let double_event = vec![
        field("event", "message"),
        field("event", "jack-end"),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&double_event), bad);
    // An end frame with data (2.9).
    let end_with_data = vec![
        field("event", "jack-end"),
        field("data", "x"),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&end_with_data), bad);
    // A message frame with empty data (2.9).
    let empty_message = vec![field("event", "message"), field("data", ""), jack_field("")];
    assert_eq!(parse_frame(&empty_message), bad);
    let no_data = vec![field("event", "message"), jack_field("")];
    assert_eq!(parse_frame(&no_data), bad);
    // An extra jack parameter (2.7).
    let extra_param = vec![
        field("event", "message"),
        field("data", "{}"),
        jack_field(",kid=x"),
    ];
    assert_eq!(parse_frame(&extra_param), bad);
    // A repeated jack parameter.
    let repeated = vec![
        field("event", "message"),
        field("data", "{}"),
        field(
            "jack",
            &format!("seq=0,ts=1767225600,ts=1767225600,sig={}", sig()),
        ),
    ];
    assert_eq!(parse_frame(&repeated), bad);
    // A bare `jack` line has an empty value and fails 2.7 (2.13).
    let bare_jack = vec![
        field("event", "message"),
        field("data", "{}"),
        field("jack", ""),
    ];
    assert_eq!(parse_frame(&bare_jack), bad);
    // Non-canonical seq and ts, and a short sig.
    for value in [
        format!("seq=01,ts=1767225600,sig={}", sig()),
        format!("seq=0,ts=01,sig={}", sig()),
        format!("seq=0,ts=1767225600,sig={}", encode_b64url(&[3u8; 63])),
        format!("seq=-1,ts=1767225600,sig={}", sig()),
        format!("seq=0,ts=1767225600,sig=+{}", &sig()[1..]),
    ] {
        let lines = vec![
            field("event", "message"),
            field("data", "{}"),
            field("jack", &value),
        ];
        assert_eq!(parse_frame(&lines), bad, "{value}");
    }
    // A seq over 15 digits.
    let long_seq = vec![
        field("event", "message"),
        field("data", "{}"),
        field(
            "jack",
            &format!("seq=1234567890123456,ts=1767225600,sig={}", sig()),
        ),
    ];
    assert_eq!(parse_frame(&long_seq), bad);
}

#[test]
fn parse_frame_rejects_invalid_utf8() {
    let bad = Err(StreamCode::BadFrame);
    // 2.10: an invalid UTF-8 data value.
    let invalid_data = vec![
        field("event", "message"),
        SseField {
            name: b"data".to_vec(),
            value: vec![0xff, 0xfe],
        },
        jack_field(""),
    ];
    assert_eq!(parse_frame(&invalid_data), bad);
    // 2.10: an overlong encoding does not round-trip as UTF-8.
    let overlong = vec![
        field("event", "message"),
        SseField {
            name: b"data".to_vec(),
            value: vec![0xc0, 0xaf],
        },
        jack_field(""),
    ];
    assert_eq!(parse_frame(&overlong), bad);
    // An unknown field's value is decoded too.
    let invalid_unknown = vec![
        field("event", "message"),
        SseField {
            name: b"x-unknown".to_vec(),
            value: vec![0x80],
        },
        field("data", "{}"),
        jack_field(""),
    ];
    assert_eq!(parse_frame(&invalid_unknown), bad);
}

#[test]
fn jack_accept_tokens() {
    assert!(accepts_s1(&["s1"]));
    assert_eq!(parse_jack_accept(&["s1"]), JackAccept { s1: true });
    // Spaces before the first token and around the comma are OWS.
    assert!(accepts_s1(&[" s1 , s2"]));
    assert!(accepts_s1(&["s1,s2"]));
    assert!(accepts_s1(&["s1 ,s2"]));
    // 1.1 admits no OWS after the last token, so a trailing run of SP makes
    // the line invalid and it contributes no token at all.
    assert!(!accepts_s1(&["s1 "]));
    assert!(!accepts_s1(&["s1   "]));
    assert!(!accepts_s1(&[" s1 , s2 "]));
    // A line rejected for its trailing SP enables nothing, but the other
    // lines still count.
    assert!(accepts_s1(&["s1 ", " s1"]));
    // Case-sensitive: S1 is not s1.
    assert!(!accepts_s1(&["S1"]));
    // A trailing comma leaves an empty member.
    assert!(!accepts_s1(&["s1,"]));
    // HTAB is not OWS.
    assert!(!accepts_s1(&["s1\t"]));
    // A space between tokens without a comma.
    assert!(!accepts_s1(&["s1 s2"]));
    // Tokens with characters outside the token alphabet.
    assert!(!accepts_s1(&["s_1"]));
    assert!(!accepts_s1(&["s1.0"]));
    // All lines are combined.
    assert!(accepts_s1(&["s2", "s1"]));
    // A line the grammar rejects contributes no token, so the other line
    // alone decides.
    assert!(accepts_s1(&["s1,", " s1"]));
    assert!(!accepts_s1(&["s1!", "s2"]));
    assert!(!accepts_s1(&[]));
    assert!(!accepts_s1(&[""]));
    assert_eq!(JackAccept::default(), JackAccept { s1: false });
    // Other registered tokens are ignored.
    assert!(!accepts_s1(&["s2", "v1", "-"]));
    assert!(accepts_s1(&["-", "s1"]));
}

#[test]
fn event_stream_media_type() {
    let header = |name: &str, value: &str| (name.to_string(), value.to_string());
    assert!(is_event_stream(&[header(
        "Content-Type",
        "text/event-stream"
    )]));
    assert!(is_event_stream(&[header(
        "content-type",
        " Text/Event-Stream ; charset=utf-8"
    )]));
    assert!(is_event_stream(&[header(
        "content-type",
        "\ttext/event-stream\t"
    )]));
    assert!(is_event_stream(&[
        header("X-Accel-Buffering", "no"),
        header("CONTENT-TYPE", "text/event-stream"),
    ]));
    assert!(!is_event_stream(&[header(
        "content-type",
        "application/json"
    )]));
    assert!(!is_event_stream(&[header(
        "content-type",
        "text/event-stream-x"
    )]));
    assert!(!is_event_stream(&[header(
        "x-content-type",
        "text/event-stream"
    )]));
    assert!(!is_event_stream(&[header(
        "content-type",
        "text/event-streams; charset=utf-8"
    )]));
    assert!(!is_event_stream(&[]));
}
