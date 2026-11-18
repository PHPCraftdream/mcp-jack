// Strict id contract for decode_result: the numeric id answer must be the canonical
// JSON text of the expected id value, as JSON.stringify in TS. The same shapes
// are covered by the differential corpus; these tests pin the decoder's behavior.
use mcp_jack::rotation;

const ANCHOR_KID: &str = "YEb2j3Ks5XXZPu7oUyVoxSIBhIuRINlokvOy8KgcpNY";
const ANCHOR_PUBLIC_KEY: &str = "3joxjujavkVLc5Z17IVP_ZDmZDyqHPDLJ7Ye13e09Ug";

fn payload() -> String {
    format!(
        r#"{{"current":{{"kid":"{ANCHOR_KID}","public_key":"{ANCHOR_PUBLIC_KEY}"}},"records":[],"head":{{"ordinal":0,"hash":"-"}},"complete":true}}"#
    )
}

fn envelope(id: &str, payload: &str) -> Vec<u8> {
    let quoted = serde_json::to_string(payload).expect("text JSON encoding");
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":{quoted}}}],"structuredContent":{payload},"isError":false}}}}"#
    )
    .into_bytes()
}

fn rejected_code(body: &[u8], expected: &[u8]) -> &'static str {
    rotation::decode_result(body, expected)
        .expect_err("invalid id accepted")
        .code
}

#[test]
fn numeric_response_id_must_be_the_canonical_json_text_of_the_expected_value() {
    let payload = payload();
    assert!(rotation::decode_result(&envelope("7", &payload), b"7").is_ok());
    for lexeme in ["7.0", "7e0", "7E0", "+7", "07", "-0", "7."] {
        let body = envelope(lexeme, &payload);
        assert_eq!(
            rejected_code(&body, b"7"),
            "rotation_result_invalid",
            "lexeme={lexeme}"
        );
    }
    assert_eq!(
        rejected_code(&envelope(r#""7""#, &payload), b"7"),
        "rotation_result_invalid",
        "string response for numeric expected id"
    );
    assert_eq!(
        rejected_code(&envelope("7", &payload), br#""7""#),
        "rotation_result_invalid",
        "numeric response for string expected id"
    );
}

#[test]
fn exact_decimal_above_safe_integer_and_overflow_gate() {
    let payload = payload();
    // Exact canonization: 9007199254740993 is not exactly representable in float64,
    // but the canonical text matches byte-for-byte.
    let body = envelope("9007199254740993", &payload);
    assert!(rotation::decode_result(&body, b"9007199254740993").is_ok());
    for lexeme in [
        "9007199254740992",
        "9007199254740993.0",
        "9.007199254740993e15",
    ] {
        assert_eq!(
            rejected_code(&envelope(lexeme, &payload), b"9007199254740993"),
            "rotation_result_invalid",
            "lexeme={lexeme}"
        );
    }
    // 1e999 beyond the |value| < 2^1024 gate: Number() in TS yields Infinity — reject.
    assert_eq!(
        rejected_code(&envelope("1", &payload), b"1e999"),
        "rotation_result_invalid"
    );
    assert_eq!(
        rejected_code(&envelope("1e999", &payload), b"1"),
        "rotation_result_invalid"
    );
    // -0 canonizes to "0": expecting -0 accepts the answer 0.
    assert!(rotation::decode_result(&envelope("0", &payload), b"-0").is_ok());
}

#[test]
fn canonical_response_matches_non_canonical_expected_numeric_lexeme() {
    let payload = payload();
    // 7e0 denotes the same number 7: the canonical answer must decode.
    assert!(rotation::decode_result(&envelope("7", &payload), b"7e0").is_ok());
    // The same non-canonical lexeme on both sides is rejected.
    assert_eq!(
        rejected_code(&envelope("7e0", &payload), b"7e0"),
        "rotation_result_invalid"
    );
    // -0 canonizes to "0".
    assert!(rotation::decode_result(&envelope("0", &payload), b"-0").is_ok());
    assert_eq!(
        rejected_code(&envelope("-0", &payload), b"-0"),
        "rotation_result_invalid"
    );
}
