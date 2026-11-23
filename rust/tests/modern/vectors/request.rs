//! Runner for `spec/fixtures/modern/modern-request-vectors.json`: the 98
//! request-classification cases of spec 04 section 5, plus the single
//! by-reference entry, driven through `classify_request`.

use serde_json::Value;

use mcp_jack::server::modern::{
    classify_request, HeaderField, ModernOutcome, ModernRequest, Profile, Refusal,
};

use super::fixtures::*;

/// The case count stated in `spec/tests/modern/CASES.md`.
const EXPECTED_CASES: usize = 98;

/// The deployment profile of one case.
fn profile_of(case: &Value) -> Profile {
    match text(case, &["profile"]) {
        "legacy" => Profile::Legacy,
        "modern" => Profile::Modern,
        "both" => Profile::Both,
        other => panic!("case {}: unknown profile `{}`", case_id(case), other),
    }
}

/// The expected era of one case (`"legacy"` or `"modern"`).
fn era_of(case: &Value) -> &str {
    text(case, &["expect", "era"])
}

/// A `[[name, value], ...]` list at `path` as owned header fields.
fn headers_of(case: &Value, path: &[&str]) -> Vec<HeaderField> {
    header_pairs(case, at(case, path))
        .into_iter()
        .map(|(name, value)| HeaderField::new(name, value))
        .collect()
}

/// Classifies the request of one case through the SDK rules.
fn classify(case: &Value) -> ModernOutcome {
    let headers = headers_of(case, &["request", "headers"]);
    let request = ModernRequest {
        method: text(case, &["request", "method"]),
        target: text(case, &["request", "target"]),
        headers: &headers,
        body: body_of(case).as_bytes(),
    };
    classify_request(profile_of(case), &request)
}

/// The verified body bytes of one case: the `body_text`, or empty when the
/// case carries none.
fn body_of(case: &Value) -> &str {
    opt_text(case, &["request", "body_text"]).unwrap_or("")
}

/// The raw JSON text of `expect.id`: `None` for `null`, otherwise the JSON
/// literal (`"\"x\""` for a string, `"1"` for an integer).
fn expected_id(expect: &Value) -> Option<String> {
    let id = expect
        .get("id")
        .unwrap_or_else(|| panic!("refuse case without `expect.id`"));
    (!id.is_null()).then(|| id.to_string())
}

/// `expect.outcome == "forward"`: era, exact header list and request line.
fn check_forward(case: &Value, outcome: &ModernOutcome) -> Result<(), String> {
    let ModernOutcome::Forward { era, headers } = outcome else {
        return Err(format!("expected Forward, got {:?}", outcome));
    };
    if era.as_str() != era_of(case) {
        return Err(format!(
            "era `{}` != expected `{}`",
            era.as_str(),
            era_of(case)
        ));
    }
    let expected_headers = headers_of(case, &["expect", "forward", "headers"]);
    if *headers != expected_headers {
        return Err(format!(
            "forward headers {:?} != expected {:?}",
            headers, expected_headers
        ));
    }
    if text(case, &["expect", "forward", "method"]) != text(case, &["request", "method"]) {
        return Err(format!(
            "forward method `{}` != request method `{}`",
            text(case, &["expect", "forward", "method"]),
            text(case, &["request", "method"])
        ));
    }
    if text(case, &["expect", "forward", "target"]) != text(case, &["request", "target"]) {
        return Err(format!(
            "forward target `{}` != request target `{}`",
            text(case, &["expect", "forward", "target"]),
            text(case, &["request", "target"])
        ));
    }
    Ok(())
}

/// `expect.outcome == "refuse"`: the signed error fields and the echoed id.
fn check_refuse(case: &Value, outcome: &ModernOutcome) -> Result<(), String> {
    let ModernOutcome::Refuse(Refusal { reason, id }) = outcome else {
        return Err(format!("expected Refuse, got {:?}", outcome));
    };
    let expect = at(case, &["expect"]);
    let status = at(case, &["expect", "http_status"])
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "case {}: `expect.http_status` is not an integer",
                case_id(case)
            )
        });
    if u64::from(reason.http_status()) != status {
        return Err(format!(
            "http_status {} != expected {}",
            reason.http_status(),
            status
        ));
    }
    let code = at(case, &["expect", "error", "code"])
        .as_i64()
        .unwrap_or_else(|| {
            panic!(
                "case {}: `expect.error.code` is not an integer",
                case_id(case)
            )
        });
    if reason.code() != code {
        return Err(format!("error code {} != expected {}", reason.code(), code));
    }
    let message = text(case, &["expect", "error", "message"]);
    if reason.message() != message {
        return Err(format!(
            "error message `{}` != expected `{}`",
            reason.message(),
            message
        ));
    }
    let expected = expected_id(expect);
    if id != &expected {
        return Err(format!("refusal id {:?} != expected {:?}", id, expected));
    }
    if expect.get("signed").and_then(Value::as_bool) != Some(true) {
        return Err("vector does not carry signed == true".to_owned());
    }
    if expect.get("content_type").and_then(Value::as_str) != Some("application/json") {
        return Err("vector does not carry content_type == \"application/json\"".to_owned());
    }
    if expect.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("vector does not carry jsonrpc == \"2.0\"".to_owned());
    }
    if expect.get("consumes_nonce").and_then(Value::as_bool) != Some(true) {
        return Err("vector does not carry consumes_nonce == true".to_owned());
    }
    Ok(())
}

/// `expect.outcome == "refuse_invalid_request"`: the era-neutral
/// classification refusal, which carries no `jsonrpc` and no `id`.
fn check_classification_refusal(case: &Value, outcome: &ModernOutcome) -> Result<(), String> {
    let ModernOutcome::ClassificationRefusal { message } = outcome else {
        return Err(format!("expected ClassificationRefusal, got {:?}", outcome));
    };
    let expected = text(case, &["expect", "error", "message"]);
    if *message != expected {
        return Err(format!(
            "classification message `{}` != expected `{}`",
            message, expected
        ));
    }
    if text(case, &["expect", "error", "code"]) != "invalid_request" {
        return Err(format!(
            "error code `{}` != `invalid_request`",
            text(case, &["expect", "error", "code"])
        ));
    }
    let expect = at(case, &["expect"]);
    if expect.get("http_status").and_then(Value::as_u64) != Some(400) {
        return Err("vector does not carry http_status == 400".to_owned());
    }
    if expect.get("era").is_some_and(|era| !era.is_null()) {
        return Err("classification refusal carries a non-null era".to_owned());
    }
    if expect.get("jsonrpc").is_some() {
        return Err("classification refusal vector carries `jsonrpc`".to_owned());
    }
    if expect.get("id").is_some() {
        return Err("classification refusal vector carries `id`".to_owned());
    }
    Ok(())
}

/// Runs every assertion of one case, returning the first failure.
fn check_case(case: &Value) -> Result<(), String> {
    let outcome = classify(case);
    match text(case, &["expect", "outcome"]) {
        "forward" => check_forward(case, &outcome),
        "refuse" => check_refuse(case, &outcome),
        "refuse_invalid_request" => check_classification_refusal(case, &outcome),
        other => Err(format!("unknown `expect.outcome` `{}`", other)),
    }
}

/// The single `by_reference` entry: the cached response must be rejected as
/// the answer to a different request.
fn check_by_reference(document: &Value) {
    let entries = document
        .get("by_reference")
        .and_then(Value::as_array)
        .expect("modern-request-vectors.json: `by_reference` is not an array");
    assert_eq!(entries.len(), 1, "by_reference must hold exactly 1 entry");
    let entry = &entries[0];
    assert_eq!(
        entry.get("id").and_then(Value::as_str),
        Some("cache-replay"),
        "by_reference[0].id"
    );
    assert_eq!(
        entry.get("rule").and_then(Value::as_str),
        Some("C8"),
        "by_reference[0].rule"
    );
    assert_eq!(
        entry.get("file").and_then(Value::as_str),
        Some("fixtures/response-vectors.json"),
        "by_reference[0].file"
    );
    let vectors: Vec<&str> = entry
        .get("vectors")
        .and_then(Value::as_array)
        .expect("by_reference[0].vectors is not an array")
        .iter()
        .map(|vector| {
            vector
                .as_str()
                .expect("by_reference[0].vectors holds a non-string")
        })
        .collect();
    assert_eq!(
        vectors,
        ["res-wrong-request-binding", "res-accept"],
        "by_reference[0].vectors"
    );
    let path = modern_dir().join("../response-vectors.json");
    assert!(
        path.is_file(),
        "referenced corpus {} does not exist",
        path.display()
    );
}

#[test]
fn modern_request_vectors() {
    let document = load_modern_request_vectors();
    let listed = cases(&document);
    assert_eq!(
        listed.len(),
        EXPECTED_CASES,
        "Request classification (`fixtures/modern/modern-request-vectors.json`, 98 cases)"
    );

    let mut failures: Vec<(String, String)> = Vec::new();
    let mut pass = 0usize;
    for case in listed {
        match check_case(case) {
            Ok(()) => pass += 1,
            Err(message) => failures.push((case_id(case).to_owned(), message)),
        }
    }

    check_by_reference(&document);

    if pass != EXPECTED_CASES {
        let listing: Vec<String> = failures
            .iter()
            .map(|(id, message)| format!("  {}: {}", id, message))
            .collect();
        panic!(
            "modern request vectors: {}/{} passed; failures:\n{}",
            pass,
            EXPECTED_CASES,
            listing.join("\n")
        );
    }
    println!(
        "VECTOR-SUMMARY corpus=modern-request sdk=rust pass={} excluded=0 deviation=0",
        pass
    );
}
