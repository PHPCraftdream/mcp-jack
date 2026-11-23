//! Runner for `spec/fixtures/modern/webhook-endpoint-verification-vectors.json`
//! (spec 06 section 5, R5.1-R5.12).
//!
//! Kinds: `gate` (the delivery gate of R5.1), `route` (the fixed route order
//! of R5.2, R5.5, R5.8-R5.10), `nonce`, `accept-echo`, `echo` (the challenge
//! of R5.3, R5.4), `allowlist-entry` and `allowlist` (R5.7), `doc`, `ttl`,
//! `wellknown-url`, `covers` and `doc-fetch` (the well-known document of
//! R5.9, R5.10, R5.12), `url-check` (the R5.11 dot segment) and
//! `verification-post` (the hardened delivery path of R5.12).
//!
//! Every kind is driven through the public API of
//! `mcp_jack::webhook::verification` and `mcp_jack::webhook::ssrf`, exactly as
//! `spec/tools/modern/webhooks/vectors/endpoint.mjs` builds its expectation:
//! the route and allowlist evidence of a `route` case is judged against the
//! fixed callback url of that generator, and a well-known document only
//! counts as evidence once its hardened fetch (`document_request`, R5.9,
//! R5.12) accepts it.

use mcp_jack::webhook::ssrf::delivery::{delivery_decision, DeliveryDecision, DeliveryInput};
use mcp_jack::webhook::ssrf::url::check_url;
use mcp_jack::webhook::verification::{
    accept_echo, allowlist_matches, challenge_echo, check_document_fetch, covers_path,
    document_cache_ttl, document_covers, document_request, gate, nonce_ok, parse_allowlist_entry,
    parse_receiver_doc, verification_route, well_known_url, DocumentRequestInput, EchoAttempt,
    EchoVerdict, RouteInput, VerificationRoute, NONCE_TTL_SECONDS,
};
use mcp_jack::webhook::{MessageKind, WebhookError};
use serde_json::{json, Value};

use crate::common::{assert_case, cases, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 93;

/// The fixed callback url the `route` evidence is judged against: the
/// `HOOK` of `vectors/endpoint.mjs`, used when a route case names no url.
const EVIDENCE_URL: &str = "https://hooks.example.test/hooks/alice";

/// The well-known url of the document the `route` evidence fetches when the
/// case names none (`DOC_FETCH_DEFAULT` of `vectors/endpoint.mjs`).
const DEFAULT_WELL_KNOWN_URL: &str =
    "https://hooks.example.test/.well-known/mcp-webhook-receiver.json";

/// The resolver answer of a document fetched without named answers
/// (`DOC_FETCH_DEFAULT` of `vectors/endpoint.mjs`).
const DEFAULT_DOCUMENT_ANSWER: &str = "93.184.216.34";

#[test]
fn webhook_endpoint_verification_vectors() {
    let corpus = cases("webhook-endpoint-verification-vectors.json");
    assert_eq!(
        corpus.len(),
        CASE_COUNT,
        "webhook-endpoint-verification-vectors.json cases"
    );
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("webhook-endpoint-verification", pass, CASE_COUNT);
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "gate" => gate_case(case),
        "route" => route_case(case),
        "nonce" => nonce_case(case),
        "accept-echo" => accept_echo_case(case),
        "echo" => echo_case(case),
        "allowlist-entry" => allowlist_entry_case(case),
        "allowlist" => allowlist_case(case),
        "doc" => doc_case(case),
        "ttl" => ttl_case(case),
        "wellknown-url" => wellknown_url_case(case),
        "covers" => covers_case(case),
        "url-check" => url_check_case(case),
        "verification-post" => verification_post_case(case),
        "doc-fetch" => doc_fetch_case(case),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R5.1: what the sender does with a message of the named kind for a pair
/// whose verification status is known.
fn gate_case(case: &Value) -> Value {
    let input = &case["input"];
    let verified = input["verified"]
        .as_bool()
        .unwrap_or_else(|| panic!("{}: verified is not a boolean", id_of(case)));
    json!({"action": gate(message_kind(&text_of(&input["message"])), verified).as_str()})
}

/// R5.2, R5.5, R5.8-R5.10: the first successful route or the fixed-literal
/// failure reason.
fn route_case(case: &Value) -> Value {
    let input = &case["input"];
    let cache = input["cache"].as_bool().unwrap_or(false);
    let allowlist_matched = match input.get("allowlist") {
        Some(Value::Null) | None => false,
        Some(allowlist) => {
            allowlist_matches(&strings_of(&allowlist["entries"]), EVIDENCE_URL).is_some()
        }
    };
    let hook = match input.get("hook") {
        Some(Value::Null) | None => None,
        Some(value) => Some(
            value
                .as_bool()
                .unwrap_or_else(|| panic!("{}: hook is not a boolean", id_of(case))),
        ),
    };
    let document_covers = match input.get("doc") {
        Some(Value::Null) | None => None,
        Some(doc) => Some(document_evidence(doc)),
    };
    let challenge = match input.get("challenge") {
        Some(Value::Null) | None => None,
        Some(challenge) => Some(challenge_echo(
            status_of(&challenge["status"]),
            &text_of(&challenge["bodyText"]),
            &text_of(&challenge["nonce"]),
        )),
    };
    let verdict = verification_route(&RouteInput {
        cache,
        allowlist_matched,
        hook,
        document_covers,
        challenge: challenge.as_ref(),
    });
    json!({
        "result": if verdict.verified { "accept" } else { "reject" },
        "route": verdict.route.map(VerificationRoute::as_str),
        "reason": verdict.reason,
    })
}

/// R5.3, R5.4: exactly 22 base64url characters.
fn nonce_case(case: &Value) -> Value {
    let accepted = nonce_ok(&text_of(&case["input"]["value"]));
    json!({"result": if accepted { "accept" } else { "reject" }})
}

/// R5.3: the value, freshness, single use and pairing of one echo.
fn accept_echo_case(case: &Value) -> Value {
    let input = &case["input"];
    let verdict = accept_echo(&EchoAttempt {
        nonce: input.get("nonce").and_then(Value::as_str),
        expected: input.get("expected").and_then(Value::as_str),
        issued_at: integer_of(&input["issuedAt"]),
        now: integer_of(&input["now"]),
        ttl: match input.get("ttl") {
            Some(value) => integer_of(value),
            None => NONCE_TTL_SECONDS,
        },
        consumed: input
            .get("consumed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        pair: input.get("pair"),
        expected_pair: input.get("expectedPair"),
    });
    echo_json(&verdict)
}

/// R5.4: the `2xx` JSON echo of the nonce.
fn echo_case(case: &Value) -> Value {
    let input = &case["input"];
    let verdict = challenge_echo(
        status_of(&input["status"]),
        &text_of(&input["bodyText"]),
        &text_of(&input["nonce"]),
    );
    echo_json(&verdict)
}

/// R5.7: one operator allowlist entry.
fn allowlist_entry_case(case: &Value) -> Value {
    match parse_allowlist_entry(&text_of(&case["input"]["entry"])) {
        Some(entry) => json!({
            "result": "accept",
            "host_pattern": entry.host_pattern,
            "port": entry.port,
            "path": entry.path,
        }),
        None => json!({"result": "reject"}),
    }
}

/// R5.7: the first entry that matches the case url.
fn allowlist_case(case: &Value) -> Value {
    let input = &case["input"];
    let entries = strings_of(&input["entries"]);
    match allowlist_matches(&entries, &text_of(&input["url"])) {
        Some(entry) => json!({
            "result": "accept",
            "host_pattern": entry.host_pattern,
            "port": entry.port,
            "path": entry.path,
        }),
        None => json!({"result": "reject"}),
    }
}

/// R5.9: the document shape, or the first offending `invalid_document`
/// reason.
fn doc_case(case: &Value) -> Value {
    match parse_receiver_doc(&text_of(&case["input"]["text"])) {
        Ok(document) => json!({"result": "accept", "receivers": document.receivers}),
        Err(error) => rejection(&error),
    }
}

/// R5.9: the per-origin cache lifetime, capped at 300 s.
fn ttl_case(case: &Value) -> Value {
    let max_age = case["input"].get("maxAge").map(integer_of);
    json!({"result": "accept", "ttl": document_cache_ttl(max_age)})
}

/// R5.9: the `/.well-known/mcp-webhook-receiver.json` url of the origin.
fn wellknown_url_case(case: &Value) -> Value {
    match well_known_url(&text_of(&case["input"]["url"])) {
        Some(url) => json!({"result": "accept", "url": url}),
        None => json!({"result": "reject"}),
    }
}

/// R5.10: the first receivers entry that covers the path at a segment
/// boundary, or no cover at all.
fn covers_case(case: &Value) -> Value {
    let input = &case["input"];
    let entry = parse_receiver_doc(&text_of(&input["text"]))
        .ok()
        .and_then(|document| {
            let path = text_of(&input["path"]);
            document
                .receivers
                .iter()
                .find(|entry| covers_path(entry.as_str(), &path))
                .cloned()
        });
    json!({"covered": entry.is_some(), "entry": entry})
}

/// R5.11: the callback url check, including the dot-segment rule.
fn url_check_case(case: &Value) -> Value {
    match check_url(&text_of(&case["input"]["url"])) {
        Ok(parts) => json!({"result": "accept", "canonical": parts.canonical}),
        Err(error) => rejection(&error),
    }
}

/// R5.12: the hardened delivery decision of the verification POST.
fn verification_post_case(case: &Value) -> Value {
    let input = &case["input"];
    let url = text_of(&input["url"]);
    let answers = strings_of(&input["answers"]);
    let allowed_ranges = optional_strings(input.get("allowedRanges"));
    let recheck = optional_strings(input.get("recheck"));
    let redirect_status = redirect_of(input.get("redirect"));
    match delivery_decision(&DeliveryInput {
        url: &url,
        answers: &answers,
        recheck: &recheck,
        allowed_ranges: &allowed_ranges,
        redirect_status,
    }) {
        DeliveryDecision::Allow { connect, .. } => {
            json!({"result": "accept", "address": connect.address})
        }
        DeliveryDecision::Reject { code, reason } => {
            json!({"result": "reject", "code": code, "reason": reason})
        }
    }
}

/// R5.9, R5.12: one well-known document fetch, judged on its own or behind
/// the hardened delivery path when the case names a url.
fn doc_fetch_case(case: &Value) -> Value {
    let input = &case["input"];
    let status = status_of(&input["status"]);
    let body_text = text_of(&input["bodyText"]);
    let verdict = match input.get("url") {
        Some(value) => {
            let url = text_of(value);
            let answers = strings_of(&input["answers"]);
            let allowed_ranges = optional_strings(input.get("allowedRanges"));
            let recheck = optional_strings(input.get("recheck"));
            let redirect_status = redirect_of(input.get("redirect"));
            document_request(&DocumentRequestInput {
                url: &url,
                answers: &answers,
                allowed_ranges: &allowed_ranges,
                recheck: &recheck,
                redirect_status,
                status,
                body_text: &body_text,
            })
        }
        None => check_document_fetch(status, &body_text),
    };
    match verdict {
        Ok(document) => json!({"result": "accept", "receivers": document.receivers}),
        Err(error) => rejection(&error),
    }
}

/// Returns true when the well-known document of a `route` case is route
/// evidence (spec 06 R5.9, R5.10, R5.12).
///
/// The hardened fetch is the precondition: `document_request` runs the
/// delivery decision of section 6 and then the fetch verdict, so a refused
/// address, a non-200 status or a body over 8192 bytes contributes nothing.
/// A document that passes is judged by `parse_receiver_doc` (inside the fetch
/// verdict) and then by `document_covers` on its path.
fn document_evidence(doc: &Value) -> bool {
    let url = doc
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_WELL_KNOWN_URL);
    let answers = match doc.get("answers") {
        Some(value) => strings_of(value),
        None => vec![DEFAULT_DOCUMENT_ANSWER.to_string()],
    };
    let allowed_ranges = optional_strings(doc.get("allowedRanges"));
    let recheck = optional_strings(doc.get("recheck"));
    let redirect_status = redirect_of(doc.get("redirect"));
    let body_text = text_of(&doc["bodyText"]);
    let verdict = document_request(&DocumentRequestInput {
        url,
        answers: &answers,
        allowed_ranges: &allowed_ranges,
        recheck: &recheck,
        redirect_status,
        status: status_of(&doc["status"]),
        body_text: &body_text,
    });
    verdict.is_ok_and(|document| document_covers(&document, &text_of(&doc["path"])).is_some())
}

/// Renders one challenge verdict as the case members `result`, `code` and
/// `reason`.
fn echo_json(verdict: &EchoVerdict) -> Value {
    json!({
        "result": if verdict.ok { "accept" } else { "reject" },
        "code": verdict.code,
        "reason": verdict.reason,
    })
}

/// Renders a rejected result with its wire code and optional fixed-literal
/// reason.
fn rejection(error: &WebhookError) -> Value {
    json!({"result": "reject", "code": error.code, "reason": error.reason})
}

/// Returns the message kind of the case-member spelling.
fn message_kind(name: &str) -> MessageKind {
    match name {
        "event" => MessageKind::Event,
        "gap" => MessageKind::Gap,
        "terminated" => MessageKind::Terminated,
        "verification" => MessageKind::Verification,
        other => panic!("unknown message kind {other}"),
    }
}

/// Returns the JSON strings of an array; an absent or `null` member is an
/// empty list.
fn strings_of(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().map(text_of).collect(),
        Value::Null => Vec::new(),
        other => panic!("expected a JSON array of strings, got {other}"),
    }
}

/// Returns the strings of an optional JSON array member; an absent or `null`
/// member is an empty list.
fn optional_strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(value) => strings_of(value),
        None => Vec::new(),
    }
}

/// Reads a JSON integer.
fn integer_of(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("expected a JSON integer, got {value}"))
}

/// Reads a JSON HTTP status.
fn status_of(value: &Value) -> u16 {
    let status = value
        .as_u64()
        .unwrap_or_else(|| panic!("expected a JSON status integer, got {value}"));
    u16::try_from(status).unwrap_or_else(|_| panic!("status {status} is outside a u16"))
}

/// Returns the `3xx` status of an optional `redirect` member: any value here
/// is a `3xx` and is never followed (spec 06 R6.10).
fn redirect_of(value: Option<&Value>) -> Option<u16> {
    match value {
        Some(Value::Null) | None => None,
        Some(value) => Some(status_of(value)),
    }
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
