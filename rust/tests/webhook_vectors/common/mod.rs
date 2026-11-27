//! Helpers every webhook corpus runner uses: fixture loading, the fixture
//! identities of `spec/fixtures/keys.json`, body decoding, the field-by-field
//! expectation check and the `VECTOR-SUMMARY` line.

use std::path::{Path, PathBuf};

use mcp_jack::user_key::ServerSigningKey;
use mcp_jack::webhook::card::WebhookKeyRecord;
use serde_json::Value;

/// Returns `spec/fixtures`, next to the `rust/` package root.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures")
}

/// Returns `spec/fixtures/modern`, where the webhook corpora live.
pub fn modern_dir() -> PathBuf {
    fixture_dir().join("modern")
}

/// Reads and parses one JSON fixture.
///
/// Panics with the path when the file is absent or not JSON, so a moved
/// fixture never turns into a silently empty corpus.
pub fn load(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

/// Returns the `cases` array of one modern vector file.
///
/// Panics with `file` when the document carries no `cases` array.
pub fn cases(file: &str) -> Vec<Value> {
    let document = load(&modern_dir().join(file));
    match document.get("cases").and_then(Value::as_array) {
        Some(entries) => entries.clone(),
        None => panic!("{file}: the fixture has no `cases` array"),
    }
}

/// Returns the parsed `keys.json` fixture.
pub fn identities() -> Value {
    load(&fixture_dir().join("keys.json"))
}

/// Returns the kid, the base64url public key and the Ed25519 signing key of
/// the fixture identity `name` (`spec/fixtures/keys.json`).
///
/// The signing key is rebuilt from the `seed_hex` member, so a runner signs
/// with exactly the key the other SDKs sign with.
pub fn identity(name: &str) -> (String, String, ServerSigningKey) {
    let all = identities();
    let entry = all["keys"]
        .as_array()
        .unwrap_or_else(|| panic!("keys.json has no `keys` array"))
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("keys.json has no identity named {name}"));
    let kid = text_of(&entry["kid"]);
    let public_key = text_of(&entry["public_key"]);
    let seed = seed_bytes(&text_of(&entry["seed_hex"]));
    (kid, public_key, ServerSigningKey::from_bytes(&seed))
}

/// Returns the public JWK of `name` (spec 06 R7.3).
pub fn jwk_for(name: &str) -> Value {
    let (kid, public_key, _) = identity(name);
    serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": public_key, "kid": kid})
}

/// Returns the accepted card key record of `name` (spec 06 R7.3).
pub fn key_record(name: &str) -> WebhookKeyRecord {
    let jwk = jwk_for(name);
    WebhookKeyRecord {
        kid: text_of(&jwk["kid"]),
        kty: text_of(&jwk["kty"]),
        crv: text_of(&jwk["crv"]),
        x: text_of(&jwk["x"]),
        public_key: text_of(&jwk["x"]),
    }
}

/// Decodes the `body_b64u` member of a case (or of one of its nested
/// objects) as unpadded base64url; a case without the member has an empty
/// body.
pub fn body_of(case: &Value) -> Vec<u8> {
    match find_string(case, "body_b64u") {
        Some(encoded) => mcp_jack::encoding::decode_b64url(&encoded)
            .unwrap_or_else(|_| panic!("body_b64u is not canonical base64url")),
        None => Vec::new(),
    }
}

/// Returns the text of a JSON string, panicking on any other JSON value.
pub fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => panic!("expected a JSON string, got {other}"),
    }
}

/// Compares `actual` with the `expect` object of `case` field by field.
///
/// Panics with the case id, the whole expected JSON and the whole actual
/// JSON, so a mismatch names the vector without any further lookup.
pub fn assert_case(case: &Value, actual: &Value) {
    let id = case
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed case>");
    let expected = case
        .get("expect")
        .unwrap_or_else(|| panic!("{id}: the case has no `expect` object"));
    let members = expected
        .as_object()
        .unwrap_or_else(|| panic!("{id}: `expect` is not a JSON object"));
    for (field, expected_value) in members {
        assert_eq!(
            actual.get(field),
            Some(expected_value),
            "{id}: expect.{field}\n  expected: {expected}\n  actual:   {actual}"
        );
    }
}

/// Prints the corpus verdict after asserting that every case passed.
pub fn summary(corpus: &str, pass: usize, expected: usize) {
    assert_eq!(pass, expected, "{corpus}: every case must pass");
    println!("VECTOR-SUMMARY corpus={corpus} sdk=rust pass={pass} excluded=0 deviation=0");
}

/// Returns the first JSON string stored under `key` in `value`, depth first.
fn find_string(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(members) => {
            if let Some(found) = members.get(key).and_then(Value::as_str) {
                return Some(found.to_owned());
            }
            members.values().find_map(|nested| find_string(nested, key))
        }
        Value::Array(items) => items.iter().find_map(|item| find_string(item, key)),
        _ => None,
    }
}

/// Decodes a 32-byte hex seed (`seed_hex` of `keys.json`).
fn seed_bytes(text: &str) -> [u8; 32] {
    let digits = text.as_bytes();
    assert_eq!(digits.len(), 64, "seed_hex must be 32 bytes of hex");
    let mut seed = [0u8; 32];
    for (index, slot) in seed.iter_mut().enumerate() {
        let high = hex_digit(digits[index * 2]);
        let low = hex_digit(digits[index * 2 + 1]);
        *slot = (high << 4) | low;
    }
    seed
}

/// Returns the value of one lowercase or uppercase hex digit.
fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("seed_hex contains a byte outside the hex alphabet"),
    }
}
