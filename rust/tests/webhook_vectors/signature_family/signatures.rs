//! Runner for `spec/fixtures/modern/webhook-signature-vectors.json`
//! (spec 06 section 2 with the section 3 steps R3.9 and R3.11-R3.14).
//!
//! Every kind is driven through the public `mcp_jack::webhook` API:
//! `secret`, `kat-v1`, `kat-v1a`, `kat-v2a`, `upstream-v2a`,
//! `upstream-combined`, `verify` and `emission`. The `verify` kind composes
//! the SDK steps in the order of the section 3 table, because the SDK has no
//! single receiver pipeline: grammar, schemes, decoding, HMAC, freshness and
//! the asymmetric step.

use ed25519_dalek::SigningKey;
use mcp_jack::encoding::encode_b64url;
use mcp_jack::webhook::card::WebhookKeyRecord;
use mcp_jack::webhook::codes;
use mcp_jack::webhook::encoding::{decode_b64_std_strict, encode_b64_std, WebhookSecret};
use mcp_jack::webhook::signatures::{
    asymmetric_verify, check_schemes, decode_signatures, emission_header, parse_signature_header,
    v1_sign, v1_verify, v1a_sign, v2a_digest, v2a_sign, EmissionKey, EmissionSecret,
    SignatureContent,
};
use mcp_jack::webhook::WebhookError;
use serde_json::{json, Value};

use crate::common::{assert_case, body_of, cases, identity, key_record, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 45;

#[test]
fn webhook_signature_vectors() {
    let corpus = cases("webhook-signature-vectors.json");
    assert_eq!(
        corpus.len(),
        CASE_COUNT,
        "webhook-signature-vectors.json cases"
    );
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("webhook-signature", pass, corpus.len());
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    let input = &case["input"];
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "secret" => secret(input),
        "kat-v1" => kat_v1(input),
        "kat-v1a" => kat_v1a(input),
        "kat-v2a" => kat_v2a(input),
        "upstream-v2a" => upstream_v2a(case),
        "upstream-combined" => upstream_combined(case),
        "verify" => verify(case),
        "emission" => emission(input),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R2.1: parses a `whsec_` value and compares the decoded key.
fn secret(input: &Value) -> Value {
    match WebhookSecret::parse(&text_of(&input["value"])) {
        Ok(secret) => json!({
            "result": "accept",
            "key_b64u": encode_b64url(secret.as_bytes()),
        }),
        Err(error) => rejection(&error),
    }
}

/// R2.2: the v1 header entry and the signed content.
fn kat_v1(input: &Value) -> Value {
    let secret = fixture_secret(&input["secret"]);
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);
    json!({
        "result": "accept",
        "signature": v1_sign(&secret, &content),
        "content_b64u": encode_b64url(&content.to_bytes()),
    })
}

/// R2.5: the v1a entry signs the raw content.
fn kat_v1a(input: &Value) -> Value {
    let (_, key) = fixture_key(&input["key"]);
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);
    json!({
        "result": "accept",
        "signature": v1a_sign(&key, &content),
        "content_b64u": encode_b64url(&content.to_bytes()),
    })
}

/// R2.6: the v2a entry signs the SHA-256 digest of endpoint id, id,
/// timestamp and body; `content_b64u` is that digest.
fn kat_v2a(input: &Value) -> Value {
    let (_, key) = fixture_key(&input["key"]);
    let endpoint_id = text_of(&input["endpoint_id"]);
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);
    json!({
        "result": "accept",
        "signature": v2a_sign(&key, &endpoint_id, &content),
        "content_b64u": encode_b64url(&v2a_digest(&endpoint_id, &content)),
    })
}

/// R2.6: the published Standard Webhooks example, reproduced byte for byte
/// from its `whsk_` seed.
fn upstream_v2a(case: &Value) -> Value {
    let id = id_of(case);
    let input = &case["input"];
    let key = seed_key(&input["private_key"], id);
    let endpoint_id = text_of(&input["endpoint_id"]);
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);
    let upstream = &case["upstream"];

    let published = text_of(&upstream["public_key"]);
    let published = published
        .strip_prefix("whpk_")
        .unwrap_or_else(|| panic!("{id}: upstream.public_key has no whpk_ prefix"));
    let published_bytes = decode_b64_std_strict(published)
        .unwrap_or_else(|| panic!("{id}: upstream.public_key is not standard base64"));
    assert_eq!(
        encode_b64url(&published_bytes),
        encode_b64url(key.verifying_key().as_bytes()),
        "{id}: upstream.public_key"
    );
    assert_eq!(
        encode_b64_std(&v2a_digest(&endpoint_id, &content)),
        text_of(&upstream["sha256_base64"]),
        "{id}: upstream.sha256_base64"
    );
    assert_eq!(
        v2a_sign(&key, &endpoint_id, &content),
        text_of(&upstream["signature"]),
        "{id}: upstream.signature"
    );
    json!({"result": "accept"})
}

/// R2.4: the published combined header; its v1 entry is a literal, its v2a
/// entry is reproduced from the `whsk_` seed.
fn upstream_combined(case: &Value) -> Value {
    let id = id_of(case);
    let input = &case["input"];
    let key = seed_key(&input["private_key"], id);
    let endpoint_id = text_of(&input["endpoint_id"]);
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);

    let header = text_of(&case["upstream"]["header"]);
    let mut entries = header.split(' ');
    let v1_literal = entries
        .next()
        .unwrap_or_else(|| panic!("{id}: upstream.header has no v1 entry"))
        .to_owned();
    let published_v2a = entries
        .next()
        .unwrap_or_else(|| panic!("{id}: upstream.header has no v2a entry"));
    let v2a = v2a_sign(&key, &endpoint_id, &content);
    assert_eq!(v2a, published_v2a, "{id}: upstream.header v2a entry");
    json!({"result": "accept", "v1_literal": v1_literal, "v2a": v2a})
}

/// R2.4, R3.9, R3.11-R3.14: the receiver pipeline, step by step.
fn verify(case: &Value) -> Value {
    let input = &case["input"];
    let envelope = &input["envelope"];
    let (webhook_id, timestamp, body) = parts_of(envelope);
    let content = content_of(&webhook_id, &timestamp, &body);

    let entries = match parse_signature_header(&text_of(&envelope["signature_header"])) {
        Ok(entries) => entries,
        Err(error) => return rejection(&error),
    };
    if let Err(error) = check_schemes(&entries) {
        return rejection(&error);
    }
    let decoded = match decode_signatures(&entries) {
        Ok(decoded) => decoded,
        Err(error) => return rejection(&error),
    };

    let secrets: Vec<WebhookSecret> = input["secrets"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: secrets is not an array", id_of(case)))
        .iter()
        .map(fixture_secret)
        .collect();
    if !secrets
        .iter()
        .any(|secret| v1_verify(&decoded, secret, &content))
    {
        return reject_code(codes::BAD_SIGNATURE);
    }

    let now = integer_of(&input["now"]);
    let window = integer_of(&input["window"]);
    let sent = integer_of(&envelope["webhook_timestamp"]);
    if now - sent > window {
        return reject_code(codes::STALE_TIMESTAMP);
    }
    if sent - now > window {
        return reject_code(codes::FUTURE_TIMESTAMP);
    }

    if text_of(&input["enforce"]) != "none" {
        let names = input["keys"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: keys is not an array", id_of(case)));
        if names.is_empty() {
            return reject_code(codes::NO_SERVER_KEYS);
        }
        let keys: Vec<WebhookKeyRecord> = names
            .iter()
            .map(|name| key_record(&text_of(name)))
            .collect();
        let endpoint_id = text_of(&envelope["endpoint_id"]);
        if asymmetric_verify(&decoded, &endpoint_id, &content, &keys).is_none() {
            return reject_code(codes::BAD_SERVER_SIGNATURE);
        }
    }
    json!({"result": "accept"})
}

/// R2.8: the emission set and its order, as the whole header value.
fn emission(input: &Value) -> Value {
    let (webhook_id, timestamp, body) = parts_of(input);
    let content = content_of(&webhook_id, &timestamp, &body);
    let endpoint_id = text_of(&input["endpoint_id"]);

    let secret_values: Vec<(WebhookSecret, bool)> = input["secrets"]
        .as_array()
        .expect("emission secrets")
        .iter()
        .map(|entry| {
            (
                fixture_secret(&entry["secret"]),
                entry["current"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    let secrets: Vec<EmissionSecret<'_>> = secret_values
        .iter()
        .map(|(secret, current)| EmissionSecret {
            secret,
            current: *current,
        })
        .collect();

    let key_values: Vec<(String, SigningKey, bool)> = input["keys"]
        .as_array()
        .expect("emission keys")
        .iter()
        .map(|entry| {
            let (kid, signing_key) = fixture_key(&entry["key"]);
            (
                kid,
                signing_key,
                entry["current"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    let keys: Vec<EmissionKey<'_>> = key_values
        .iter()
        .map(|(kid, signing_key, current)| EmissionKey {
            kid,
            signing_key,
            current: *current,
        })
        .collect();

    let header = emission_header(&secrets, &keys, &endpoint_id, &content);
    let schemes: Vec<String> = parse_signature_header(&header)
        .expect("an emitted header parses as a signature header")
        .into_iter()
        .map(|entry| entry.scheme)
        .collect();
    json!({"result": "accept", "header": header, "schemes": schemes})
}

/// Returns the webhook id, the decimal timestamp and the raw body of a case
/// input or of its envelope.
fn parts_of(value: &Value) -> (String, String, Vec<u8>) {
    (
        text_of(&value["webhook_id"]),
        decimal_of(&value["webhook_timestamp"]),
        body_of(value),
    )
}

/// Borrows the signed content of one delivery.
fn content_of<'a>(webhook_id: &'a str, timestamp: &'a str, body: &'a [u8]) -> SignatureContent<'a> {
    SignatureContent {
        webhook_id,
        timestamp,
        body,
    }
}

/// Parses one fixture `whsec_` value.
fn fixture_secret(value: &Value) -> WebhookSecret {
    WebhookSecret::parse(&text_of(value))
        .unwrap_or_else(|_| panic!("the case carries a secret the profile rejects"))
}

/// Returns the kid and the signing key of one fixture identity name.
fn fixture_key(value: &Value) -> (String, SigningKey) {
    let (kid, _, key) = identity(&text_of(value));
    (kid, key)
}

/// Builds a signing key from a `whsk_` value: the standard base64 of the
/// 32-byte Ed25519 seed (spec 06 R2.6 upstream example).
fn seed_key(value: &Value, case_id: &str) -> SigningKey {
    let text = text_of(value);
    let body = text
        .strip_prefix("whsk_")
        .unwrap_or_else(|| panic!("{case_id}: private_key has no whsk_ prefix"));
    let bytes = decode_b64_std_strict(body)
        .unwrap_or_else(|| panic!("{case_id}: private_key is not standard base64"));
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("{case_id}: private_key does not decode to a 32-byte seed"));
    SigningKey::from_bytes(&seed)
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

/// Renders a rejected case with its code and, when the SDK carries one, its
/// fixed-literal reason.
fn rejection(error: &WebhookError) -> Value {
    match error.reason() {
        Some(reason) => json!({"result": "reject", "code": error.code(), "reason": reason}),
        None => reject_code(error.code()),
    }
}

/// Renders a rejected case with a code of the section 3 table.
fn reject_code(code: &str) -> Value {
    json!({"result": "reject", "code": code})
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
