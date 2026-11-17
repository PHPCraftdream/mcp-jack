#![forbid(unsafe_code)]

//! Bounded JSON stdin/stdout probe for the public user-key transfer SDK.
use std::io::{self, Read, Write};

use mcp_jack::client::signer::Signer;
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url};
use mcp_jack::user_key::{self, ClientSigningKey, ExpectedIdentity, UserKeyError};
use serde_json::{json, Map, Value};

const MAX_IPC_BYTES: usize = 2 * 1024 * 1024;
const MAX_OPERATIONS: usize = 1024;
const MAX_MESSAGES: usize = 16;
const MAX_MESSAGE_BYTES: usize = 4096;

fn fail() -> ! {
    let _ = writeln!(
        io::stderr(),
        "interop-transfer: invalid request or SDK failure"
    );
    std::process::exit(1)
}

fn exact_fields(value: &Map<String, Value>, allowed: &[&str]) -> bool {
    value.keys().all(|key| allowed.contains(&key.as_str()))
}

fn required_string<'a>(value: &'a Map<String, Value>, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail())
}

fn decode(value: &str) -> Vec<u8> {
    decode_b64url(value).unwrap_or_else(|_| fail())
}

fn expected(value: Option<&Value>) -> ExpectedIdentity {
    let object = value.and_then(Value::as_object);
    ExpectedIdentity {
        url: object
            .and_then(|m| m.get("url"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        aud: object
            .and_then(|m| m.get("aud"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        server_public_key: object
            .and_then(|m| m.get("server_public_key"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        server_kid: object
            .and_then(|m| m.get("server_kid"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

fn messages(value: &Map<String, Value>) -> Vec<Vec<u8>> {
    let list = value
        .get("messages_b64u")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail());
    if list.len() > MAX_MESSAGES {
        fail();
    }
    list.iter()
        .map(|item| {
            let encoded = item.as_str().unwrap_or_else(|| fail());
            let message = decode(encoded);
            if message.len() > MAX_MESSAGE_BYTES {
                fail();
            }
            message
        })
        .collect()
}

fn signer_result(
    id: &Value,
    signer: &dyn Signer,
    messages: &[Vec<u8>],
    connection: Option<&user_key::ConnectionData>,
) -> Value {
    let public_key = signer.public_key();
    let envelope = match user_key::client::export_public_envelope(signer) {
        Ok(envelope) => envelope,
        Err(error) => return fail_result(id, error),
    };
    let signatures: Vec<String> = messages
        .iter()
        .map(|message| {
            signer
                .sign(message)
                .map(|signature| encode_b64url(&signature))
                .unwrap_or_else(|_| fail())
        })
        .collect();
    let mut result = json!({
        "id": id,
        "ok": true,
        "public_key": encode_b64url(&public_key),
        "kid": signer.kid(),
        "public_envelope_b64u": encode_b64url(&envelope),
        "signatures_b64u": signatures,
    });
    if let Some(connection) = connection {
        result["connection"] = json!({
            "url": connection.url(),
            "aud": connection.aud(),
            "server_public_key": connection.server_public_key(),
            "server_kid": connection.server_kid(),
        });
    }
    result
}

fn fail_result(id: &Value, error: UserKeyError) -> Value {
    match error.class() {
        Some(
            "malformed_json"
            | "wrong_root_type"
            | "oversized_envelope"
            | "unknown_version"
            | "unknown_type"
            | "bad_member_set"
            | "wrong_field_type"
            | "bad_encoding"
            | "bad_url"
            | "invalid_public_key"
            | "seed_pub_mismatch"
            | "kid_mismatch"
            | "non_canonical_bytes"
            | "wrong_envelope_type"
            | "private_material_rejected"
            | "not_private"
            | "server_identity_mismatch",
        ) => {}
        _ => fail(),
    }
    match error.class() {
        Some(class) => json!({"id": id, "ok": false, "class": class}),
        None => fail(),
    }
}

fn operation(input: &Value) -> Value {
    let value = input.as_object().unwrap_or_else(|| fail());
    let id = value.get("id").unwrap_or_else(|| fail());
    let name = required_string(value, "op");
    let allowed: &[&str] = match name {
        "issue" => &["id", "op", "seed_b64u", "expected"],
        "generate" | "from-seed" => &["id", "op", "seed_b64u", "messages_b64u"],
        "import-private" => &["id", "op", "document_b64u", "messages_b64u"],
        "import-credential" => &["id", "op", "document_b64u", "expected", "messages_b64u"],
        "import-public" => &["id", "op", "document_b64u", "role", "verifications"],
        "validate-credential" => &["id", "op", "document_b64u", "expected"],
        _ => fail(),
    };
    if !exact_fields(value, allowed) {
        fail();
    }

    match name {
        "issue" => {
            let seed = decode_b64url_fixed(required_string(value, "seed_b64u"), 32)
                .unwrap_or_else(|_| fail());
            let configured = expected(value.get("expected"));
            let connection = match user_key::ConnectionData::new(
                configured.url.clone(),
                configured.aud.clone(),
                configured.server_public_key.clone(),
                configured.server_kid.clone(),
            ) {
                Ok(connection) => connection,
                Err(error) => return fail_result(id, error),
            };
            let issued =
                match user_key::server::issue_user_key(&connection, &mut |_len| Ok(seed.clone())) {
                    Ok(issued) => issued,
                    Err(error) => return fail_result(id, error),
                };
            let issued_public = issued.public_identity();
            if issued_public.public_key.is_empty() || issued_public.kid.is_empty() {
                fail();
            }
            let mut first = issued.credential_bytes();
            let original = first.clone();
            let second = issued.credential_bytes();
            let public_before = issued.public_identity();
            let imported = match user_key::client::import_credential(&original, &configured) {
                Ok(imported) => imported,
                Err(error) => return fail_result(id, error),
            };
            let imported_public = imported.signer.public_key();
            let imported_kid = imported.signer.kid().to_owned();
            let signature_before = Signer::sign(&imported.signer, &[]).unwrap_or_else(|_| fail());
            first.fill(0);
            let third = issued.credential_bytes();
            let public_after = issued.public_identity();
            let signature_after = Signer::sign(&imported.signer, &[]).unwrap_or_else(|_| fail());
            let public_key_b64u = encode_b64url(&imported_public);
            let fresh = !original.is_empty()
                && first.as_ptr() != second.as_ptr()
                && second.as_ptr() != third.as_ptr()
                && original == second
                && original == third
                && signature_before == signature_after
                && imported.signer.public_key() == imported_public
                && imported.signer.kid() == imported_kid
                && public_before == public_after
                && public_before.public_key == public_key_b64u
                && public_before.kid == imported_kid;
            if !fresh {
                fail();
            }
            json!({
                "id": id,
                "ok": true,
                "credential_b64u": encode_b64url(&third),
                "public_key": public_key_b64u,
                "kid": imported_kid,
                "export_fresh": fresh,
            })
        }
        "generate" | "from-seed" | "import-private" | "import-credential" => {
            let messages = messages(value);
            match name {
                "generate" => {
                    let signer = ClientSigningKey::generate().unwrap_or_else(|_| fail());
                    signer_result(id, &signer, &messages, None)
                }
                "from-seed" => {
                    let seed = decode_b64url_fixed(required_string(value, "seed_b64u"), 32)
                        .unwrap_or_else(|_| fail());
                    let signer = ClientSigningKey::from_seed(&seed).unwrap_or_else(|_| fail());
                    signer_result(id, &signer, &messages, None)
                }
                "import-private" => {
                    let document = decode(required_string(value, "document_b64u"));
                    let signer = match user_key::client::import_private_envelope(&document) {
                        Ok(signer) => signer,
                        Err(error) => return fail_result(id, error),
                    };
                    signer_result(id, &signer, &messages, None)
                }
                "import-credential" => {
                    let document = decode(required_string(value, "document_b64u"));
                    let before = document.clone();
                    let configured = expected(value.get("expected"));
                    let configured_before = configured.clone();
                    let imported = user_key::client::import_credential(&document, &configured);
                    if document != before || configured != configured_before {
                        fail();
                    }
                    let imported = match imported {
                        Ok(imported) => imported,
                        Err(error) => return fail_result(id, error),
                    };
                    signer_result(id, &imported.signer, &messages, Some(&imported.connection))
                }
                _ => fail(),
            }
        }
        "import-public" => {
            let document = decode(required_string(value, "document_b64u"));
            let role = required_string(value, "role");
            if role != "client" && role != "server" {
                fail();
            }
            let pairs = match value.get("verifications") {
                None => &[][..],
                Some(Value::Array(items)) if items.len() <= MAX_MESSAGES => items.as_slice(),
                _ => fail(),
            };
            let mut decoded = Vec::with_capacity(pairs.len());
            for pair in pairs {
                let pair = pair.as_object().unwrap_or_else(|| fail());
                if !exact_fields(pair, &["message_b64u", "signature_b64u"]) {
                    fail();
                }
                let message = decode(required_string(pair, "message_b64u"));
                let signature = decode(required_string(pair, "signature_b64u"));
                if message.len() > MAX_MESSAGE_BYTES || signature.len() > MAX_MESSAGE_BYTES {
                    fail();
                }
                decoded.push((message, signature));
            }
            if role == "client" {
                let identity = match user_key::client::import_public_envelope(&document) {
                    Ok(identity) => identity,
                    Err(error) => return fail_result(id, error),
                };
                let probe = identity.sign(&[]);
                match probe {
                    Err(error) if error.class() == Some("not_private") => {}
                    _ => fail(),
                }
                let public_key = identity.public_key();
                let kid = identity.kid().to_owned();
                json!({
                    "id": id,
                    "ok": true,
                    "public_key": encode_b64url(&public_key),
                    "kid": kid,
                    "public_only": true,
                    "verification_results": decoded.iter().map(|(message, signature)| identity.verify(message, signature)).collect::<Vec<_>>(),
                })
            } else {
                let identity = match user_key::server::import_public_envelope(&document) {
                    Ok(identity) => identity,
                    Err(error) => return fail_result(id, error),
                };
                let public_key = identity.public_key();
                let kid = identity.kid().to_owned();
                json!({
                    "id": id,
                    "ok": true,
                    "public_key": encode_b64url(&public_key),
                    "kid": kid,
                    "public_only": true,
                    "verification_results": decoded.iter().map(|(message, signature)| identity.verify(message, signature)).collect::<Vec<_>>(),
                })
            }
        }
        "validate-credential" => {
            let document = decode(required_string(value, "document_b64u"));
            let configured = expected(value.get("expected"));
            match user_key::server::validate_issued_credential(&document, &configured) {
                Ok(()) => json!({"id": id, "ok": true}),
                Err(error) => fail_result(id, error),
            }
        }
        _ => fail(),
    }
}

fn main() {
    let mut input = Vec::new();
    let mut limited = io::stdin().take((MAX_IPC_BYTES + 1) as u64);
    if limited.read_to_end(&mut input).is_err() || input.len() > MAX_IPC_BYTES {
        fail();
    }
    let request: Value = serde_json::from_slice(&input).unwrap_or_else(|_| fail());
    let object = request.as_object().unwrap_or_else(|| fail());
    if !exact_fields(object, &["operations"]) {
        fail();
    }
    let operations = object
        .get("operations")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail());
    if operations.len() > MAX_OPERATIONS {
        fail();
    }
    let results: Vec<Value> = operations.iter().map(operation).collect();
    let output = serde_json::to_vec(&json!({"results": results})).unwrap_or_else(|_| fail());
    if output.len().saturating_add(1) > MAX_IPC_BYTES {
        fail();
    }
    let mut output = output;
    output.push(b'\n');
    if io::stdout().write_all(&output).is_err() {
        fail();
    }
}
