//! Runner for `spec/fixtures/modern/modern-request-vectors.json`: the 98
//! request-classification cases of spec 04 section 5, plus the single
//! by-reference entry, driven through `classify_request`. The by-reference
//! entry runs the referenced response cases through the real
//! `mcp_jack::signing::verify_response`.

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

/// `expect.outcome == "forward"`: the engine's era and the exact header list
/// it hands the handler, compared with the fixture's `expect.forward`.
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
    Ok(())
}

/// The signed JSON-RPC envelope of one refusal (spec 04 `S10`):
/// `{"jsonrpc":"2.0","id":<id>,"error":{"code":<code>,"message":<message>}}`.
///
/// The renderer itself (`mcp_jack::server::http`) sits behind the `http`
/// feature, which this test binary does not enable, so the envelope is
/// rebuilt here from the fixture-independent pieces of the outcome type:
/// `RefusalReason::code`/`message` and `Refusal::id`. A non-`null` id stays
/// the raw JSON text (`1` for an integer, `"x"` for a string).
fn refusal_envelope(refusal: &Refusal) -> Value {
    let id = match refusal.id.as_deref() {
        None => Value::Null,
        Some(raw) => serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("refusal id `{}` is not a JSON value: {}", raw, e)),
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": refusal.reason.code(),
            "message": refusal.reason.message(),
        },
    })
}

/// The `Content-Type` of every refusal rendering (spec 04 `S10`), repeated
/// from the renderer because `mcp_jack::server::http` is behind the `http`
/// feature.
const REFUSAL_CONTENT_TYPE: &str = "application/json";

/// `expect.outcome == "refuse"`: the rendered envelope, the HTTP status and
/// the properties every `Refuse` outcome carries by construction.
fn check_refuse(case: &Value, outcome: &ModernOutcome) -> Result<(), String> {
    let ModernOutcome::Refuse(refusal) = outcome else {
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
    if u64::from(refusal.reason.http_status()) != status {
        return Err(format!(
            "http_status {} != expected {}",
            refusal.reason.http_status(),
            status
        ));
    }
    // The envelope is built from the real outcome, so the id, the code and
    // the message below are compared against it, never against the fixture's
    // own copy of the same request fields.
    let envelope = refusal_envelope(refusal);
    if expect.get("error") != envelope.get("error") {
        return Err(format!(
            "refusal error {:?} != rendered {:?}",
            expect.get("error"),
            envelope.get("error")
        ));
    }
    if expect.get("id") != envelope.get("id") {
        return Err(format!(
            "refusal id {:?} != rendered {:?}",
            expect.get("id"),
            envelope.get("id")
        ));
    }
    if expect.get("jsonrpc") != envelope.get("jsonrpc") {
        return Err(format!(
            "refusal jsonrpc {:?} != rendered {:?}",
            expect.get("jsonrpc"),
            envelope.get("jsonrpc")
        ));
    }
    if expect.get("content_type").and_then(Value::as_str) != Some(REFUSAL_CONTENT_TYPE) {
        return Err(format!(
            "refusal content type {:?} != renderer `{}`",
            expect.get("content_type"),
            REFUSAL_CONTENT_TYPE
        ));
    }
    // A `Refuse` outcome is produced by rules that run strictly after
    // authentication (spec 01 section 4 step 8 recorded the nonce) and every
    // response of that path is signed (spec 01 section 5), so the vector must
    // carry both properties; neither is read from the fixture as a truth.
    if expect.get("consumes_nonce").and_then(Value::as_bool) != Some(true) {
        return Err(
            "a Refuse outcome only exists after the nonce was recorded, so the vector must \
             carry consumes_nonce == true"
                .to_owned(),
        );
    }
    if expect.get("signed").and_then(Value::as_bool) != Some(true) {
        return Err(
            "a Refuse outcome is rendered signed, so the vector must carry signed == true"
                .to_owned(),
        );
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
    // The entry is by reference, so the referenced cases must actually RUN:
    // `res-accept` verifies and `res-wrong-request-binding` fails, both
    // through the real response verifier (spec 01 section 5), mirroring
    // `tests/conformance/responses.rs`.
    let responses = load_response_vectors();
    check_response_vector(&responses, "res-accept", true);
    check_response_vector(&responses, "res-wrong-request-binding", false);
}

/// Runs one case of `response-vectors.json` through
/// `mcp_jack::signing::verify_response`: `must_verify` says whether the
/// response has to verify or to fail verification.
fn check_response_vector(document: &Value, id: &str, must_verify: bool) {
    let case = cases(document)
        .iter()
        .find(|case| case.get("id").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("response-vectors.json: case `{}` is missing", id));
    // Header names are case-insensitive per the runner contract.
    let values: Vec<String> = header_pairs(case, at(case, &["response", "headers"]))
        .into_iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Jack-Auth"))
        .map(|(_, value)| value)
        .collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    let key_vec = mcp_jack::encoding::decode_b64url_fixed(
        text(case, &["state", "pinned_server_public_key"]),
        32,
    )
    .unwrap_or_else(|e| panic!("case {}: bad pinned key b64u: {:?}", id, e));
    let key: [u8; 32] = key_vec
        .try_into()
        .unwrap_or_else(|_| panic!("case {}: pinned key is not 32 bytes", id));
    let body = mcp_jack::encoding::decode_b64url(text(case, &["response", "body_b64u"]))
        .unwrap_or_else(|e| panic!("case {}: bad body b64u: {:?}", id, e));
    let integer = |path: &[&str]| {
        at(case, path)
            .as_i64()
            .unwrap_or_else(|| panic!("case {}: `{}` is not an integer", id, path.join(".")))
    };
    let result = mcp_jack::signing::verify_response(
        &key,
        integer(&["response", "status"]),
        &values,
        text(case, &["state", "request_sig"]),
        &body,
        integer(&["state", "now"]),
        integer(&["state", "window_seconds"]),
    );
    if must_verify {
        assert!(
            result.is_ok(),
            "case {}: expected the response to verify, got {:?}",
            id,
            result
        );
    } else {
        assert!(
            result.is_err(),
            "case {}: expected the response to fail verification",
            id
        );
    }
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
