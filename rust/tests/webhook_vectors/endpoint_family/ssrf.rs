//! Runner for `spec/fixtures/modern/ssrf-vectors.json`
//! (spec 06 section 6, R6.1-R6.11).
//!
//! Kinds: `url` (the scheme, authority and R8.2 canonical form), `host` (the
//! three host forms of R6.3), `address` (the two IANA special-purpose tables
//! and the R6.7 translation chains), `delivery` (the one delivery decision of
//! R6.8-R6.11) and `cidr` (the operator override ranges of R6.11).

use mcp_jack::webhook::ssrf::cidr::{cidr_contains, parse_cidr, CidrFamily};
use mcp_jack::webhook::ssrf::delivery::{
    classify_address, delivery_decision, DeliveryDecision, DeliveryInput,
};
use mcp_jack::webhook::ssrf::host::parse_host;
use mcp_jack::webhook::ssrf::tables::Decision;
use mcp_jack::webhook::ssrf::url::check_url;
use mcp_jack::webhook::WebhookError;
use serde_json::{json, Value};

use crate::common::{assert_case, cases, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 120;

#[test]
fn ssrf_vectors() {
    let corpus = cases("ssrf-vectors.json");
    assert_eq!(corpus.len(), CASE_COUNT, "ssrf-vectors.json cases");
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("ssrf", pass, CASE_COUNT);
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "url" => url_case(case),
        "host" => host_case(case),
        "address" => address_case(case),
        "delivery" => delivery_case(case),
        "cidr" => cidr_case(case),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R6.1-R6.3: the validated url parts and its canonical form.
fn url_case(case: &Value) -> Value {
    match check_url(&text_of(&case["input"]["url"])) {
        Ok(parts) => json!({
            "result": "accept",
            "canonical": parts.canonical,
            "host": parts.host,
            "port": parts.port,
            "path": parts.path,
            "query": parts.query,
        }),
        Err(error) => refusal(&error),
    }
}

/// R6.3: the normalized host and its form, or the rejection reason.
fn host_case(case: &Value) -> Value {
    match parse_host(&text_of(&case["input"]["host"])) {
        Ok(host) => json!({
            "result": "accept",
            "kind": host.kind.as_str(),
            "normalized": host.normalized,
        }),
        Err(error) => json!({
            "result": "reject",
            "reason": error.reason.as_deref().unwrap_or_default(),
        }),
    }
}

/// R6.4-R6.7: the decision, the reason (row name or chain), the family and
/// the canonical spelling of the literal.
fn address_case(case: &Value) -> Value {
    let verdict = classify_address(&text_of(&case["input"]["address"]));
    let result = match verdict.decision {
        Decision::Allow => "accept",
        Decision::Reject => "reject",
    };
    json!({
        "result": result,
        "family": verdict.family.map(CidrFamily::as_str),
        "reason": verdict.reason,
        "address": verdict.address,
    })
}

/// R6.8-R6.11: the connect target, or the refusal and its reason.
fn delivery_case(case: &Value) -> Value {
    let input = &case["input"];
    let id = id_of(case);
    let url = text_of(&input["url"]);
    let answers = strings_of(input.get("answers"));
    let recheck = strings_of(input.get("recheck"));
    let allowed_ranges = strings_of(input.get("allowedRanges"));
    let redirect_status = match input.get("redirect") {
        Some(Value::Null) | None => None,
        Some(value) => {
            let status = value
                .as_u64()
                .unwrap_or_else(|| panic!("{id}: redirect is not a status integer"));
            Some(
                u16::try_from(status).unwrap_or_else(|_| panic!("{id}: redirect is outside a u16")),
            )
        }
    };
    let decision = delivery_decision(&DeliveryInput {
        url: &url,
        answers: &answers,
        recheck: &recheck,
        allowed_ranges: &allowed_ranges,
        redirect_status,
    });
    match decision {
        DeliveryDecision::Allow { connect, reason } => json!({
            "result": "accept",
            "address": connect.address,
            "reason": reason,
            "host_header": connect.host_header,
            "sni": connect.sni,
        }),
        DeliveryDecision::Reject { code, reason } => json!({
            "result": "reject",
            "code": code,
            "reason": reason,
        }),
    }
}

/// R6.11: the parsed range and the containment of the address in it.
fn cidr_case(case: &Value) -> Value {
    match parse_cidr(&text_of(&case["input"]["cidr"])) {
        Some(range) => json!({
            "result": "accept",
            "contains": cidr_contains(&range, &text_of(&case["input"]["address"])),
        }),
        None => json!({"result": "reject"}),
    }
}

/// Renders a rejected url with its code and optional fixed-literal reason.
fn refusal(error: &WebhookError) -> Value {
    match error.reason.as_deref() {
        Some(reason) => json!({"result": "reject", "code": error.code, "reason": reason}),
        None => json!({"result": "reject", "code": error.code}),
    }
}

/// Returns the strings of a JSON array member; an absent or `null` member is
/// an empty list.
fn strings_of(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().map(text_of).collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => panic!("expected a JSON array of strings, got {other}"),
    }
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
