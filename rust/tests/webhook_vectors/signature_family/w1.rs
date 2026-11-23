//! Runner for `spec/fixtures/modern/webhook-w1-vectors.json` (spec 06
//! section 4, R4.1-R4.6).
//!
//! `kat-w1` renders the seven-line signing string and the exact
//! `Jack-Webhook-Auth` value; `verify-w1` drives the receiver-side check with
//! the case's own `now`, `window`, accepted keys, parts and server key id.

use mcp_jack::encoding::encode_b64url;
use mcp_jack::webhook::card::WebhookKeyRecord;
use mcp_jack::webhook::w1::{self, JackSigningParts};
use mcp_jack::webhook::WebhookError;
use serde_json::{json, Value};

use crate::common::{assert_case, body_of, cases, identity, key_record, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 25;

#[test]
fn webhook_w1_vectors() {
    let corpus = cases("webhook-w1-vectors.json");
    assert_eq!(corpus.len(), CASE_COUNT, "webhook-w1-vectors.json cases");
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("webhook-w1", pass, corpus.len());
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "kat-w1" => kat(case),
        "verify-w1" => verify(case),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R4.2: the signing string and its Ed25519 signature.
fn kat(case: &Value) -> Value {
    let input = &case["input"];
    let (kid, _, key) = identity(&text_of(&input["key"]));
    let claim = Claim::of(input);
    let parts = claim.parts();
    json!({
        "result": "accept",
        "header": w1::sign(&key, &kid, &parts),
        "signing_string_b64u": encode_b64url(w1::signing_string(&parts).as_bytes()),
    })
}

/// R4.1, R4.3-R4.6: the receiver-side `w1` check.
fn verify(case: &Value) -> Value {
    let input = &case["input"];
    let claim = Claim::of(&input["parts"]);
    let parts = claim.parts();
    let keys: Vec<WebhookKeyRecord> = input["keys"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: keys is not an array", id_of(case)))
        .iter()
        .map(|name| key_record(&text_of(name)))
        .collect();
    let now = integer_of(&input["now"]);
    let window = integer_of(&input["window"]);
    let header = input["header"].as_str();
    let server_kid = input["mcp_server_kid"].as_str();
    match w1::verify(header, &parts, &keys, now, window, server_kid) {
        Ok(_kid) => json!({"result": "accept"}),
        Err(error) => rejection(&error),
    }
}

/// The fields a `w1` signature covers, owned so the borrow lives long enough
/// for `JackSigningParts`.
struct Claim {
    aud: String,
    subscription_id: String,
    webhook_id: String,
    timestamp: String,
    callback_url: String,
    body: Vec<u8>,
}

impl Claim {
    /// Reads a claim from a case input or from its `parts` object.
    fn of(value: &Value) -> Self {
        Self {
            aud: text_of(&value["aud"]),
            subscription_id: text_of(&value["subscription_id"]),
            webhook_id: text_of(&value["webhook_id"]),
            timestamp: decimal_of(&value["webhook_timestamp"]),
            callback_url: text_of(&value["callback_url"]),
            body: body_of(value),
        }
    }

    /// Borrows the claim as the SDK signing parts (spec 06 R4.2, R4.3).
    fn parts(&self) -> JackSigningParts<'_> {
        JackSigningParts {
            aud: &self.aud,
            subscription_id: &self.subscription_id,
            webhook_id: &self.webhook_id,
            timestamp: &self.timestamp,
            callback_url: &self.callback_url,
            body: &self.body,
        }
    }
}

/// Renders a JSON number or string as its decimal text (a timestamp).
fn decimal_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
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
