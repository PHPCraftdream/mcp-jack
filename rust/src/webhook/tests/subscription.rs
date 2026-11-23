//! Subscription lifecycle unit tests (spec 06 R8.1-R8.9).
//!
//! The pinned values are copied verbatim from
//! `spec/fixtures/modern/webhook-subscription-vectors.json`; nothing here
//! reads a file at run time and everything is pure.

use serde_json::Value;

use crate::webhook::subscription::{
    canonical_json, cursor_ok, gap_body, subscription_id_ok, subscription_key, terminated_body,
    terminated_envelope, timestamp_ok, ttl_grant, webhook_id_ok, TtlGrant, TtlInput,
    CURSOR_MAX_CHARS,
};

/// The clock of the subscription vectors, in unix seconds.
const NOW: i64 = 1_767_225_600;

/// Parses one literal JSON text; a failure is a bug in the test.
fn json_of(text: &str) -> Value {
    match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => panic!("{text} is not JSON: {error}"),
    }
}

/// Returns the canonical JSON of one literal JSON text.
fn canonical_of(text: &str) -> String {
    match canonical_json(&json_of(text)) {
        Ok(canonical) => canonical,
        Err(error) => panic!("{text} was rejected: {error}"),
    }
}

/// Returns the grant of one `ttlMs` input (spec 06 R8.5).
fn grant_of(ttl: TtlInput, now: i64) -> TtlGrant {
    match ttl_grant(ttl, now) {
        Ok(grant) => grant,
        Err(error) => panic!("ttl {ttl:?} was rejected: {error}"),
    }
}

/// Returns the `terminated` body of one literal envelope input.
fn terminated_of(text: &str) -> String {
    match terminated_envelope(&json_of(text)) {
        Ok(body) => body,
        Err(error) => panic!("{text} was rejected: {error}"),
    }
}

#[test]
fn canonical_json_has_no_whitespace() {
    assert_eq!(canonical_of("{\"a\":1}"), "{\"a\":1}");
    assert_eq!(canonical_of("[ 1 , 2 ]"), "[1,2]");
}

#[test]
fn canonical_json_sorts_keys_by_utf16_code_units() {
    // Code-point order and UTF-16 code-unit order agree here.
    assert_eq!(canonical_of("{\"b\":1,\"a\":2}"), "{\"a\":2,\"b\":1}");
    // U+1F600 is the surrogate pair D83D DE00, so it sorts before U+FF61 in
    // UTF-16 order even though its code point is larger.
    assert_eq!(
        canonical_of("{\"\u{ff61}\":1,\"\u{1f600}\":2}"),
        "{\"\u{1f600}\":2,\"\u{ff61}\":1}"
    );
}

#[test]
fn canonical_json_uses_run_ecmascript_numbers() {
    assert_eq!(canonical_of("-0"), "0");
    assert_eq!(canonical_of("0"), "0");
    assert_eq!(canonical_of("1e3"), "1000");
    assert_eq!(canonical_of("1e21"), "1e+21");
    assert_eq!(canonical_of("0.1"), "0.1");
    assert_eq!(canonical_of("1.0"), "1");
    assert_eq!(canonical_of("-42"), "-42");
    assert_eq!(canonical_of("1e-7"), "1e-7");
}

#[test]
fn canonical_json_escapes_controls_and_keeps_non_ascii_raw() {
    let value = Value::String("\u{1}\u{8}\t\n\u{c}\r\"\\é—世界\u{1f600}\u{7f}".to_string());
    match canonical_json(&value) {
        Ok(canonical) => assert_eq!(
            canonical,
            "\"\\u0001\\b\\t\\n\\f\\r\\\"\\\\é—世界\u{1f600}\u{7f}\""
        ),
        Err(error) => panic!("the control string was rejected: {error}"),
    }
}

#[test]
fn subscription_key_derives_the_first_worked_example() {
    let arguments = json_of("{\"severity\":\"P1\"}");
    let key = match subscription_key(
        "alice",
        "https://hooks.example.test/hooks/alice",
        "incident.created",
        Some(&arguments),
    ) {
        Ok(key) => key,
        Err(error) => panic!("the worked example was rejected: {error}"),
    };
    assert_eq!(key.id, "sub_10dd9b3f501b751f");
    assert_eq!(key.canonical_url, "https://hooks.example.test/hooks/alice");
    assert_eq!(key.canonical_arguments, "{\"severity\":\"P1\"}");
    assert_eq!(
        key.jcs_input,
        "[\"mcp-jack/webhook1/subscription\",\"alice\",\"https://hooks.example.test/hooks/alice\",\"incident.created\",{\"severity\":\"P1\"}]"
    );
}

#[test]
fn subscription_key_derives_the_second_worked_example() {
    let key = match subscription_key(
        "alice",
        "https://hooks.example.test:8443/hooks/alice?tenant=1",
        "email.received",
        None,
    ) {
        Ok(key) => key,
        Err(error) => panic!("the worked example was rejected: {error}"),
    };
    assert_eq!(key.id, "sub_ce48aa2e898723ea");
    assert_eq!(
        key.canonical_url,
        "https://hooks.example.test:8443/hooks/alice?tenant=1"
    );
    assert_eq!(key.canonical_arguments, "null");
    assert_eq!(
        key.jcs_input,
        "[\"mcp-jack/webhook1/subscription\",\"alice\",\"https://hooks.example.test:8443/hooks/alice?tenant=1\",\"email.received\",null]"
    );
}

#[test]
fn ttl_grant_clamps_into_the_one_minute_and_one_day_bounds() {
    let cases: [(TtlInput, Option<i64>, Option<&str>); 4] = [
        (
            TtlInput::Absent,
            Some(3_600_000),
            Some("2026-01-01T01:00:00Z"),
        ),
        (
            TtlInput::Milliseconds(30_000),
            Some(60_000),
            Some("2026-01-01T00:01:00Z"),
        ),
        (
            TtlInput::Milliseconds(172_800_000),
            Some(86_400_000),
            Some("2026-01-02T00:00:00Z"),
        ),
        (TtlInput::Null, None, None),
    ];
    for (input, grant, refresh) in cases {
        let granted = grant_of(input, NOW);
        assert_eq!(granted.grant_ms, grant, "ttl {input:?}");
        assert_eq!(granted.refresh_before.as_deref(), refresh, "ttl {input:?}");
    }
}

#[test]
fn refresh_before_is_iso_utc_with_second_precision() {
    let at_epoch = grant_of(TtlInput::Milliseconds(60_000), 0);
    assert_eq!(
        at_epoch.refresh_before.as_deref(),
        Some("1970-01-01T00:01:00Z")
    );
    let later = grant_of(TtlInput::Absent, NOW + 17);
    assert_eq!(
        later.refresh_before.as_deref(),
        Some("2026-01-01T01:00:17Z")
    );
}

#[test]
fn a_negative_ttl_is_invalid_arguments() {
    let error = match ttl_grant(TtlInput::Milliseconds(-1), NOW) {
        Ok(grant) => panic!("a negative ttl was granted: {grant:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code, "invalid_arguments");
    assert_eq!(error.reason(), Some("ttl"));
    assert_eq!(error.http_status, 400);
}

#[test]
fn cursor_ok_is_printable_ascii_of_at_most_512_characters() {
    let longest = "c".repeat(CURSOR_MAX_CHARS);
    let too_long = "c".repeat(CURSOR_MAX_CHARS + 1);
    let cases: [(Option<&str>, bool); 12] = [
        (Some("cursor_7f3a"), true),
        (None, true),
        (Some("!"), true),
        (Some("~"), true),
        (Some(longest.as_str()), true),
        (Some(""), false),
        (Some("cursor 7f3a"), false),
        (Some("cursor\t7f3a"), false),
        (Some("cursor\u{7f}"), false),
        (Some("café"), false),
        (Some("cursor\n"), false),
        (Some(too_long.as_str()), false),
    ];
    for (value, expected) in cases {
        assert_eq!(cursor_ok(value), expected, "cursor {value:?}");
    }
}

#[test]
fn webhook_id_ok_matches_the_pinned_grammar() {
    let longest = "a".repeat(128);
    let too_long = "a".repeat(129);
    let cases: [(&str, bool); 9] = [
        ("msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f", true),
        ("abcdefgh", true),
        ("a_b-c_9Z", true),
        (longest.as_str(), true),
        ("abcdefg", false),
        (too_long.as_str(), false),
        ("abcdefg!", false),
        ("abc defg", false),
        ("", false),
    ];
    for (value, expected) in cases {
        assert_eq!(webhook_id_ok(value), expected, "webhook id {value:?}");
    }
}

#[test]
fn timestamp_ok_matches_the_pinned_grammar() {
    let cases: [(&str, bool); 11] = [
        ("0", true),
        ("1", true),
        ("1767225600", true),
        ("999999999999", true),
        ("", false),
        ("00", false),
        ("01", false),
        ("1234567890123", false),
        ("-1", false),
        ("1a", false),
        (" 1", false),
    ];
    for (value, expected) in cases {
        assert_eq!(timestamp_ok(value), expected, "timestamp {value:?}");
    }
}

#[test]
fn subscription_id_ok_matches_the_pinned_grammar() {
    let cases: [(&str, bool); 9] = [
        ("sub_a3f1c8e2b0d49f7e", true),
        ("sub_0000000000000000", true),
        ("sub_0123456789abcdef", true),
        ("sub_A3F1C8E2B0D49F7E", false),
        ("sub_a3f1c8e2b0d49f7", false),
        ("sub_a3f1c8e2b0d49f7e0", false),
        ("sub_a3f1c8e2b0d49g7e", false),
        ("SUB_a3f1c8e2b0d49f7e", false),
        ("", false),
    ];
    for (value, expected) in cases {
        assert_eq!(subscription_id_ok(value), expected, "id {value:?}");
    }
}

#[test]
fn gap_body_is_exactly_the_pinned_object() {
    assert_eq!(
        gap_body(Some("cursor_7f3a")),
        "{\"type\":\"gap\",\"cursor\":\"cursor_7f3a\"}"
    );
    assert_eq!(gap_body(None), "{\"type\":\"gap\",\"cursor\":null}");
    assert_eq!(
        gap_body(Some("a\"b")),
        "{\"type\":\"gap\",\"cursor\":\"a\\\"b\"}"
    );
    assert_eq!(
        gap_body(Some("a\nb")),
        "{\"type\":\"gap\",\"cursor\":\"a\\nb\"}"
    );
}

#[test]
fn terminated_envelope_is_exactly_the_pinned_object() {
    assert_eq!(
        terminated_of("{\"code\":-32024,\"message\":\"Forbidden\"}"),
        "{\"type\":\"terminated\",\"error\":{\"code\":-32024,\"message\":\"Forbidden\"}}"
    );
    assert_eq!(
        terminated_of("{\"code\":1,\"message\":\"m\",\"data\":{\"b\":1,\"a\":2}}"),
        "{\"type\":\"terminated\",\"error\":{\"code\":1,\"message\":\"m\",\"data\":{\"a\":2,\"b\":1}}}"
    );
}

#[test]
fn terminated_envelope_keeps_the_optional_data_last() {
    assert_eq!(
        terminated_of(
            "{\"code\":-32024,\"message\":\"Forbidden\",\"data\":{\"reason\":\"Access revoked\"}}"
        ),
        "{\"type\":\"terminated\",\"error\":{\"code\":-32024,\"message\":\"Forbidden\",\"data\":{\"reason\":\"Access revoked\"}}}"
    );
}

#[test]
fn terminated_envelope_rejects_every_shape_violation() {
    let cases = [
        "{\"code\":\"-32024\",\"message\":\"Forbidden\"}",
        "{\"code\":-32024.5,\"message\":\"Forbidden\"}",
        "{\"code\":-32024}",
        "{\"code\":-32024,\"message\":403}",
        "{\"code\":-32024,\"message\":\"Forbidden\",\"data\":null}",
        "{\"code\":-32024,\"message\":\"Forbidden\",\"data\":[\"Access revoked\"]}",
    ];
    for input in cases {
        let error = match terminated_envelope(&json_of(input)) {
            Ok(body) => panic!("{input} was accepted as {body}"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_envelope", "{input}");
        assert_eq!(error.http_status, 400, "{input}");
    }
}

#[test]
fn terminated_body_requires_an_integer_code_and_object_data() {
    let body = match terminated_body(&json_of("-32024"), "Forbidden", None) {
        Ok(body) => body,
        Err(error) => panic!("an integer code was rejected: {error}"),
    };
    assert_eq!(
        body,
        "{\"type\":\"terminated\",\"error\":{\"code\":-32024,\"message\":\"Forbidden\"}}"
    );
    for code in [json_of("\"-32024\""), json_of("-32024.5")] {
        let error = match terminated_body(&code, "Forbidden", None) {
            Ok(body) => panic!("code {code} was accepted as {body}"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_envelope");
    }
    let error = match terminated_body(&json_of("-32024"), "Forbidden", Some(&json_of("null"))) {
        Ok(body) => panic!("a null data member was accepted as {body}"),
        Err(error) => error,
    };
    assert_eq!(error.code, "invalid_envelope");
}
