// Строгий id-контракт decode_result: числовой ответ id обязан быть каноническим
// JSON текстом значения ожидаемого id, как JSON.stringify в TS. Те же формы
// покрывает дифференциальный corpus; эти тесты фиксируют поведение у decoder.
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

fn rejected_code(body: &[u8], expected: &[u8]) -> String {
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
fn canonical_response_matches_non_canonical_expected_numeric_lexeme() {
    let payload = payload();
    // 7e0 обозначает то же число 7: канонический ответ обязан декодироваться.
    assert!(rotation::decode_result(&envelope("7", &payload), b"7e0").is_ok());
    // Один и тот же non-canonical lexeme с обеих сторон отклоняется.
    assert_eq!(
        rejected_code(&envelope("7e0", &payload), b"7e0"),
        "rotation_result_invalid"
    );
    // -0 канонизируется в "0".
    assert!(rotation::decode_result(&envelope("0", &payload), b"-0").is_ok());
    assert_eq!(
        rejected_code(&envelope("-0", &payload), b"-0"),
        "rotation_result_invalid"
    );
}
