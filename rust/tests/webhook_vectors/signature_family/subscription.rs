//! Runner for `spec/fixtures/modern/webhook-subscription-vectors.json`
//! (spec 06 section 8, R8.1-R8.9).
//!
//! Kinds: `sub-id` (key derivation, canonical url and canonical arguments),
//! `ttl` (grant and refresh deadline, absent vs explicit `null`), `secrets`
//! (rotation grace), `envelope` (the exact `gap` and `terminated` bodies) and
//! `cursor` (the R8.9 cursor rule).

use mcp_jack::webhook::encoding::WebhookSecret;
use mcp_jack::webhook::subscription::{
    active_secrets, cursor_ok, gap_body, subscription_key, terminated_body, ttl_grant, TtlInput,
};
use mcp_jack::webhook::WebhookError;
use serde_json::{json, Value};

use crate::common::{assert_case, cases, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 49;

#[test]
fn webhook_subscription_vectors() {
    let corpus = cases("webhook-subscription-vectors.json");
    assert_eq!(
        corpus.len(),
        CASE_COUNT,
        "webhook-subscription-vectors.json cases"
    );
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("webhook-subscription", pass, corpus.len());
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "sub-id" => sub_id(case),
        "ttl" => ttl(case),
        "secrets" => secrets(case),
        "envelope" => envelope(case),
        "cursor" => cursor(case),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R8.1-R8.4: the derived id and the three canonical strings.
fn sub_id(case: &Value) -> Value {
    let input = &case["input"];
    let principal = text_of(&input["principal"]);
    let url = text_of(&input["url"]);
    let name = text_of(&input["name"]);
    let arguments = match input.get("arguments_text") {
        Some(Value::String(text)) => Some(serde_json::from_str(text).unwrap_or_else(|error| {
            panic!("{}: arguments_text is not JSON: {error}", id_of(case))
        })),
        Some(Value::Null) | None => None,
        Some(other) => panic!(
            "{}: arguments_text is not a string or null: {other}",
            id_of(case)
        ),
    };
    match subscription_key(&principal, &url, &name, arguments.as_ref()) {
        Ok(key) => json!({
            "result": "accept",
            "id": key.id,
            "canonical_url": key.canonical_url,
            "canonical_arguments": key.canonical_arguments,
            "jcs_input": key.jcs_input,
        }),
        Err(error) => rejection(&error),
    }
}

/// R8.5: the grant and its refresh deadline; absent and explicit `null` are
/// different inputs.
fn ttl(case: &Value) -> Value {
    let input = &case["input"];
    let id = id_of(case);
    let now = integer_of(&input["now"]);
    let requested = match input.get("ttlMs") {
        None => TtlInput::Absent,
        Some(Value::Null) => TtlInput::Null,
        Some(value) => match value.as_i64() {
            Some(milliseconds) => TtlInput::Milliseconds(milliseconds),
            None => panic!(
                "{id}: the SDK cannot pass this case: R8.5 answers `invalid_arguments` with reason \
                 `ttl` for a fractional ttlMs, but `TtlInput` only has `Absent`, `Null` and \
                 `Milliseconds(i64)`, so a non-integer request value has no public entry point and \
                 the rejection is unreachable. Report as an SDK bug."
            ),
        },
    };
    match ttl_grant(requested, now) {
        Ok(grant) => json!({
            "result": "accept",
            "grantMs": grant.grant_ms,
            "refreshBefore": grant.refresh_before,
        }),
        Err(error) => rejection(&error),
    }
}

/// R8.6: the active secrets, current first, inside the exclusive grace.
fn secrets(case: &Value) -> Value {
    let input = &case["input"];
    let current = fixture_secret(&input["current"], id_of(case));
    let previous = match input.get("previous") {
        Some(Value::Null) | None => None,
        Some(_) => Some(fixture_secret(&input["previous"], id_of(case))),
    };
    let grace_ends_at = integer_of(&input["graceEndsAt"]);
    let now = integer_of(&input["now"]);
    let active = active_secrets(&current, previous.as_ref(), grace_ends_at, now);
    let order: Vec<&str> = active
        .iter()
        .enumerate()
        .map(|(index, _)| if index == 0 { "current" } else { "previous" })
        .collect();
    json!({"result": "accept", "order": order})
}

/// R8.7, R8.8: the exact `gap` and `terminated` bodies.
fn envelope(case: &Value) -> Value {
    let input = &case["input"];
    let id = id_of(case);
    let kind = text_of(&input["kind"]);
    if kind == "gap" {
        let cursor = optional_text(&input["cursor"]);
        return json!({
            "result": "accept",
            "body_text": gap_body(cursor.as_deref()),
        });
    }
    assert_eq!(kind, "terminated", "{id}: unknown envelope kind");
    let code = input.get("code").cloned().unwrap_or(Value::Null);
    let message = match input.get("message") {
        Some(Value::String(text)) => text.clone(),
        Some(other) => panic!(
            "{id}: the SDK cannot pass this case: R8.8 rejects a non-string message with \
             `invalid_envelope`, but `terminated_body` takes the message as `&str`, and the \
             JSON-shape check that would reject {other} is the private `fields_ok` of \
             `webhook::receiver::state`, so no public entry point reaches this row. \
             Report as an SDK bug."
        ),
        None => panic!(
            "{id}: the SDK cannot pass this case: R8.8 rejects a missing message with \
             `invalid_envelope`, but `terminated_body` requires a `&str` message, and the \
             JSON-shape check that would reject its absence is the private `fields_ok` of \
             `webhook::receiver::state`, so no public entry point reaches this row. \
             Report as an SDK bug."
        ),
    };
    match terminated_body(&code, &message, input.get("data")) {
        Ok(body) => json!({"result": "accept", "body_text": body}),
        Err(error) => rejection(&error),
    }
}

/// R8.9: the cursor rule; `null` is the absent cursor.
fn cursor(case: &Value) -> Value {
    let value = optional_text(&case["input"]["value"]);
    if cursor_ok(value.as_deref()) {
        json!({"result": "accept"})
    } else {
        json!({"result": "reject"})
    }
}

/// Parses one fixture `whsec_` value.
fn fixture_secret(value: &Value, case_id: &str) -> WebhookSecret {
    WebhookSecret::parse(&text_of(value))
        .unwrap_or_else(|error| panic!("{case_id}: the case secret is rejected ({error})"))
}

/// Returns the text of a JSON string member, `None` for an absent member or
/// an explicit JSON `null`.
fn optional_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Null => None,
        other => panic!("expected a JSON string or null, got {other}"),
    }
}

/// Reads a JSON integer.
fn integer_of(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("expected a JSON integer, got {value}"))
}

/// Renders a rejected case with its code and optional fixed-literal reason.
fn rejection(error: &WebhookError) -> Value {
    match error.reason() {
        Some(reason) => json!({"result": "reject", "code": error.code(), "reason": reason}),
        None => json!({"result": "reject", "code": error.code()}),
    }
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
