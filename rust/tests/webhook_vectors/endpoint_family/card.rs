//! Runner for `spec/fixtures/modern/server-card-keys-vectors.json`
//! (spec 06 section 7, R7.1-R7.6).
//!
//! Kinds: `info` (the selected remote and its `webhooks` object of R7.1),
//! `remote` (the R7.1 remote selection), `fetch` (the one R7.2 fetch decision
//! with its R7.3 key set and R7.5 egress ranges), `jwk-set` (the R7.3 JWK
//! validator and set rules), `kid` (the R7.4 accepted-set lookup), `cidr-list`
//! (the R7.5 advisory ranges), `webhook-key-check` (the R7.6 cross-check) and
//! `webhook-key-discovery` (R7.2 discovery followed by the R7.6 check).

use mcp_jack::webhook::card::{
    accept_jwk_set, card_key_for_kid, cross_check_webhook_key_jwks, fetch_decision,
    parse_cidr_list, published_jwks, select_remote, webhook_info, CardFetchInput, KeyRejection,
    WebhookKeyRecord,
};
use mcp_jack::webhook::{codes, WebhookError};
use serde_json::{json, Value};

use crate::common::{assert_case, cases, jwk_for, key_record, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 43;

#[test]
fn server_card_keys_vectors() {
    let corpus = cases("server-card-keys-vectors.json");
    assert_eq!(
        corpus.len(),
        CASE_COUNT,
        "server-card-keys-vectors.json cases"
    );
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("server-card-keys", pass, CASE_COUNT);
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "info" => info_case(case),
        "remote" => remote_case(case),
        "fetch" => fetch_case(case),
        "jwk-set" => jwk_set_case(case),
        "kid" => kid_case(case),
        "cidr-list" => cidr_case(case),
        "webhook-key-check" => check_case(case),
        "webhook-key-discovery" => discovery_case(case),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R7.1: the events webhooks object, or the rejection code.
fn info_case(case: &Value) -> Value {
    let input = &case["input"];
    match webhook_info(&input["card"], &text_of(&input["mcpUrl"])) {
        Ok(info) => json!({
            "result": "accept",
            "signing_keys": info.signing_keys,
            "egress": info.egress_ip_ranges,
            "remote_url": info.remote_url,
        }),
        Err(error) => refusal(&error),
    }
}

/// R7.1: the selected remote url, or the rejection code.
fn remote_case(case: &Value) -> Value {
    let input = &case["input"];
    match select_remote(&input["card"], &text_of(&input["mcpUrl"])) {
        Ok(remote) => json!({"result": "accept", "url": text_of(&remote["url"])}),
        Err(error) => refusal(&error),
    }
}

/// R7.2-R7.5: the fetch decision, or the rejection code.
fn fetch_case(case: &Value) -> Value {
    let input = &case["input"];
    let response = &input["response"];
    let mcp_url = text_of(&input["mcpUrl"]);
    let card_url = text_of(&input["cardUrl"]);
    let body = response_body(response);
    let cache_control = response["headers"]["cache-control"].as_str();
    match fetch_decision(&CardFetchInput {
        mcp_url: &mcp_url,
        card_url: &card_url,
        status: status_of(response, case),
        redirect: response.get("redirect_to").is_some(),
        body: &body,
        overflow: false,
        elapsed_ms: input["elapsed_ms"].as_i64(),
        cache_control,
        mcp_server_kid: input["mcp_server_kid"].as_str(),
        mcp_server_public_key: input["mcp_server_public_key"].as_str(),
    }) {
        Ok(card) => json!({
            "result": "accept",
            "keys": card
                .keys
                .iter()
                .map(|key| key.kid.clone())
                .collect::<Vec<_>>(),
            "egress": card.egress_ip_ranges,
            "rejected": rejections(&card.rejected_keys),
            "cache_ttl": card.cache_ttl_seconds,
        }),
        Err(error) => refusal(&error),
    }
}

/// R7.3: the accepted kids and the rejected records of one JWK set.
///
/// The case publishes the set as a bare `keys` array, so it is wrapped as the
/// JWK set object `{"keys":[...]}` the validator reads; the configured MCP
/// server key members are threaded through the same R7.3 step.
fn jwk_set_case(case: &Value) -> Value {
    let input = &case["input"];
    let signing_keys = json!({"keys": input["signing_keys"].clone()});
    let verdict = accept_jwk_set(
        Some(&signing_keys),
        input["mcp_server_kid"].as_str(),
        input["mcp_server_public_key"].as_str(),
    );
    json!({
        "accepted": verdict
            .accepted
            .iter()
            .map(|key| key.kid.clone())
            .collect::<Vec<_>>(),
        "rejected": rejections(&verdict.rejected),
    })
}

/// R7.4: the accepted-set lookup of one kid.
fn kid_case(case: &Value) -> Value {
    let keys = named_keys(case);
    let kid = text_of(&case["input"]["kid"]);
    match card_key_for_kid(&keys, &kid) {
        Some(_) => json!({"result": "accept"}),
        None => json!({"result": "reject", "code": codes::UNKNOWN_WEBHOOK_KEY}),
    }
}

/// R7.5: the accepted ranges and the malformed ones of one list.
fn cidr_case(case: &Value) -> Value {
    let values = strings_of(&case["input"]["values"], id_of(case));
    let list = parse_cidr_list(&values);
    json!({
        "accepted": list
            .accepted
            .iter()
            .map(|range| json!({
                "cidr": range.cidr,
                "family": range.family,
                "prefix": range.prefix,
            }))
            .collect::<Vec<_>>(),
        "rejected": list
            .rejected
            .iter()
            .map(|entry| json!({"value": entry.value, "reason": entry.reason}))
            .collect::<Vec<_>>(),
    })
}

/// R7.6: the required or optional cross-check of the case's card-side JWKs.
fn check_case(case: &Value) -> Value {
    let input = &case["input"];
    let require = input["require"]
        .as_bool()
        .unwrap_or_else(|| panic!("{}: require is not a boolean", id_of(case)));
    let card_keys = card_keys(case);
    match cross_check_webhook_key_jwks(&card_keys, tool_result(input), require) {
        Ok(()) => json!({"result": "accept"}),
        Err(error) => refusal(&error),
    }
}

/// R7.2, R7.6: the card fetch, then the required cross-check of the raw
/// published JWKs the fetched card carries.
fn discovery_case(case: &Value) -> Value {
    let input = &case["input"];
    let response = &input["response"];
    let mcp_url = text_of(&input["mcpUrl"]);
    let card_url = text_of(&input["cardUrl"]);
    let body = response_body(response);
    if let Err(error) = fetch_decision(&CardFetchInput {
        mcp_url: &mcp_url,
        card_url: &card_url,
        status: status_of(response, case),
        redirect: false,
        body: &body,
        overflow: false,
        elapsed_ms: None,
        cache_control: None,
        mcp_server_kid: None,
        mcp_server_public_key: None,
    }) {
        return refusal(&error);
    }
    let card: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|error| panic!("{}: the fetched card is not JSON: {error}", id_of(case)));
    let published = match published_jwks(&card, &mcp_url) {
        Ok(published) => published,
        Err(error) => return refusal(&error),
    };
    match cross_check_webhook_key_jwks(&published, tool_result(input), true) {
        Ok(()) => json!({"result": "accept"}),
        Err(error) => refusal(&error),
    }
}

/// Returns the raw card-side JWKs of a `webhook-key-check` case: the
/// `card_keys` the case publishes verbatim, else the JWKs of the fixture
/// identities it names (spec 06 R7.3, R7.6).
fn card_keys(case: &Value) -> Vec<Value> {
    match case["input"].get("card_keys") {
        Some(Value::Array(keys)) => keys.clone(),
        Some(other) => panic!("{}: card_keys is not an array: {other}", id_of(case)),
        None => {
            let mut keys = Vec::new();
            for name in strings_of(&case["input"]["keys"], id_of(case)) {
                keys.push(jwk_for(&name));
            }
            keys
        }
    }
}

/// Returns the body bytes of a case response (spec 06 R7.2).
///
/// The fixture encodes the body as a `card` object, as a `raw` string or as
/// `pad` ASCII spaces; a response without any of them has an empty body.
fn response_body(response: &Value) -> Vec<u8> {
    if let Some(card) = response.get("card") {
        return serde_json::to_vec(card)
            .unwrap_or_else(|error| panic!("the case card does not serialize: {error}"));
    }
    if let Some(raw) = response.get("raw").and_then(Value::as_str) {
        return raw.as_bytes().to_vec();
    }
    if let Some(pad) = response.get("pad").and_then(Value::as_u64) {
        let len = usize::try_from(pad).unwrap_or_else(|_| panic!("{pad} does not fit in usize"));
        return vec![0u8; len];
    }
    Vec::new()
}

/// Returns the HTTP status of a case response (spec 06 R7.2).
fn status_of(response: &Value, case: &Value) -> Option<u16> {
    let id = id_of(case);
    let status = response
        .get("status")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{id}: status is not a non-negative integer"));
    Some(u16::try_from(status).unwrap_or_else(|_| panic!("{id}: status is outside a u16")))
}

/// Returns the accepted key records of the identity names a case lists, in
/// the order given (spec 06 R7.4, R7.6).
fn named_keys(case: &Value) -> Vec<WebhookKeyRecord> {
    strings_of(&case["input"]["keys"], id_of(case))
        .iter()
        .map(|name| key_record(name))
        .collect()
}

/// Returns the `jack.server.webhook_key` tool result, `None` for a null or
/// absent member (spec 06 R7.6).
fn tool_result(input: &Value) -> Option<&Value> {
    match input.get("toolResult") {
        Some(Value::Null) | None => None,
        Some(value) => Some(value),
    }
}

/// Renders the rejected key records as the corpus expects them, with a JSON
/// null `kid` when the JWK carried none (spec 06 R7.3).
fn rejections(rejected: &[KeyRejection]) -> Vec<Value> {
    rejected
        .iter()
        .map(|entry| json!({"kid": entry.kid, "reason": entry.reason}))
        .collect()
}

/// Renders a rejection with its fixed-literal code (spec 06 R7.2).
fn refusal(error: &WebhookError) -> Value {
    json!({"result": "reject", "code": error.code})
}

/// Returns the strings of a JSON array, panicking on any other value.
fn strings_of(value: &Value, id: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{id}: expected a JSON array of strings"))
        .iter()
        .map(text_of)
        .collect()
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
