//! Close tests: the 6.3 final-response lookalikes and the exact
//! `events/stream` result.

use crate::server::stream::{events_stream_result, is_final_response};

#[test]
fn final_response_positives() {
    assert!(is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "1"
    ));
    assert!(is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}"#,
        "1"
    ));
    assert!(is_final_response(
        r#"{"jsonrpc":"2.0","id":"a","result":null}"#,
        "\"a\""
    ));
    // Extra members are not forbidden by 6.3.
    assert!(is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{},"extra":true}"#,
        "1"
    ));
}

#[test]
fn wrong_id_lexemes_are_not_final() {
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
        "1"
    ));
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1.0,"result":{}}"#,
        "1"
    ));
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "1.0"
    ));
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "01"
    ));
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":null,"result":{}}"#,
        "null"
    ));
}

#[test]
fn string_id_is_not_the_numeric_lexeme() {
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
        "1"
    ));
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "\"1\""
    ));
}

#[test]
fn every_other_lookalike_is_not_final() {
    // No jsonrpc.
    assert!(!is_final_response(r#"{"id":1,"result":{}}"#, "1"));
    // Wrong jsonrpc.
    assert!(!is_final_response(
        r#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
        "1"
    ));
    // Both result and error.
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
        "1"
    ));
    // Both members present with null values.
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":null,"error":null}"#,
        "1"
    ));
    // Neither result nor error.
    assert!(!is_final_response(r#"{"jsonrpc":"2.0","id":1}"#, "1"));
    // A method member.
    assert!(!is_final_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{},"method":"x"}"#,
        "1"
    ));
    // Non-objects.
    assert!(!is_final_response(
        r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        "1"
    ));
    // A JSON array of the struct's fields is still not an object.
    assert!(!is_final_response(r#"["2.0",1,{}]"#, "1"));
    assert!(!is_final_response("1", "1"));
    assert!(!is_final_response("\"x\"", "1"));
    assert!(!is_final_response("not json", "1"));
}

#[test]
fn events_stream_result_is_exact() {
    assert_eq!(
        events_stream_result("1"),
        r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":1}}}"#
    );
}
