//! User-key transfer conformance tests (docs/design/user-keys.md sections
//! 11 and 12.2): all 66 cases of the shared table
//! `spec/fixtures/user-key-transfer.json` are loaded from ../spec/fixtures
//! via std::fs — the fixture file is the arbiter for exact bytes and
//! classes; pinned constants appear only as backup oracles. Deterministic
//! throughout: no wall-clock, no network, no new dependencies. Every test
//! is an independent #[test] fn (no ordering assumptions).

use std::fs;

use crate::common::fixtures::{fixture_path, load_key_vectors, load_keys};
use mcp_jack::client::error::ClientError;
use mcp_jack::client::signer::Signer;
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::user_key::client::{
    export_public_envelope, import_credential, import_private_envelope, import_public_envelope,
};
use mcp_jack::user_key::server::{issue_user_key, validate_issued_credential};
use mcp_jack::user_key::{
    ClientSigningKey, ConnectionData, ExpectedIdentity, ServerPublicKey, UserKeyError,
};

// ---------------------------------------------------------------------------
// Fixture loading and helpers
// ---------------------------------------------------------------------------

/// The shared transfer table, read in place (never copied).
fn transfer_table() -> serde_json::Value {
    let path = fixture_path("user-key-transfer.json");
    let text = fs::read_to_string(&path).expect("read user-key-transfer.json");
    serde_json::from_str(&text).expect("parse user-key-transfer.json")
}

/// One pinned identity from spec/fixtures/keys.json (the independent oracle).
struct OracleKey {
    seed_hex: String,
    public_key: String,
    kid: String,
}

fn oracle_key(name: &str) -> OracleKey {
    let keys = load_keys().expect("load keys.json");
    let found = keys
        .keys
        .iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("keys.json has no key named {name}"));
    OracleKey {
        seed_hex: found.seed_hex.clone(),
        public_key: found.public_key.clone(),
        kid: found.kid.clone(),
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let valid = pair.len() == 2 && pair.iter().all(|b| b.is_ascii_hexdigit());
            assert!(valid, "hex pair");
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex is UTF-8"), 16)
                .expect("hex digit")
        })
        .collect()
}

fn seed32(hex: &str) -> [u8; 32] {
    match hex_bytes(hex).try_into() {
        Ok(seed) => seed,
        Err(_) => panic!("keys.json seeds are 32 bytes"),
    }
}

/// The independently trusted server identity (keys.json vector `svc`; the
/// fixture provenance names it as the server stand-in; a credential never
/// carries server private material).
fn svc_expected() -> ExpectedIdentity {
    let svc = oracle_key("svc");
    ExpectedIdentity {
        url: "https://svc.example.test".to_owned(),
        aud: "https://svc.example.test".to_owned(),
        server_public_key: svc.public_key,
        server_kid: svc.kid,
    }
}

fn svc_connection() -> ConnectionData {
    let expected = svc_expected();
    ConnectionData::new(
        expected.url,
        expected.aud,
        expected.server_public_key,
        expected.server_kid,
    )
    .expect("svc tuple is a valid connection config")
}

/// Canonical JSON string spelling (same emitter the production serializer
/// uses): short control escapes, lowercase \u00xx, literal UTF-8 otherwise.
fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a Rust string is infallible")
}

/// Test-side canonical credential composition (the `client_credential`
/// template: members in exact lexicographic order, v as the integer 1).
fn compose_credential(
    aud: &str,
    client_key_envelope: &str,
    server_public_key: &str,
    server_kid: &str,
    url: &str,
) -> String {
    format!(
        "{{\"aud\":{},\"client_key\":{},\"server_kid\":{},\"server_public_key\":{},\"type\":\"user-key/credential/client\",\"url\":{},\"v\":1}}",
        quote(aud),
        quote(client_key_envelope),
        quote(server_kid),
        quote(server_public_key),
        quote(url),
    )
}

/// Test-side canonical private envelope (the `private_envelope` template).
fn compose_private_envelope(seed: &[u8; 32], public_key: &[u8; 32]) -> String {
    format!(
        "{{\"crv\":\"Ed25519\",\"d\":{},\"kid\":{},\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":{}}}",
        quote(&encode_b64url(seed)),
        quote(&key_id(public_key)),
        quote(&encode_b64url(public_key)),
    )
}

/// Test-side canonical public envelope (the `public_envelope` template).
fn compose_public_envelope(public_key: &[u8; 32]) -> String {
    format!(
        "{{\"crv\":\"Ed25519\",\"kid\":{},\"kty\":\"OKP\",\"type\":\"user-key/public\",\"v\":1,\"x\":{}}}",
        quote(&key_id(public_key)),
        quote(&encode_b64url(public_key)),
    )
}

/// Builds `aud` from an `aud_codepoints` array: each integer is a Unicode
/// scalar, each single-character string is exactly that character,
/// concatenated in listed order (section 11 composition recipe).
fn aud_from_codepoints(codepoints: &serde_json::Value) -> String {
    let mut aud = String::new();
    for element in codepoints.as_array().expect("aud_codepoints array") {
        if let Some(scalar) = element.as_u64() {
            aud.push(char::from_u32(scalar as u32).expect("valid scalar"));
        } else {
            let text = element.as_str().expect("single-character string");
            assert_eq!(text.chars().count(), 1, "single-character string");
            aud.push_str(text);
        }
    }
    aud
}

/// Finds a positive/negative/context case by id.
fn find_case<'a>(table: &'a serde_json::Value, array: &str, id: &str) -> &'a serde_json::Value {
    table[array]
        .as_array()
        .expect("case array")
        .iter()
        .find(|c| c["id"] == *id)
        .unwrap_or_else(|| panic!("{array} has no case {id}"))
}

fn envelope_of(case: &serde_json::Value) -> Vec<u8> {
    case["envelope"]
        .as_str()
        .expect("envelope string")
        .as_bytes()
        .to_vec()
}

/// Replaces the JSON string content between the aud quotes of a credential
/// document with the given RAW text (an escape recipe inserts literal
/// characters, it does not parse or repair anything).
fn replace_aud_raw(document: &[u8], raw_replacement: &str) -> Vec<u8> {
    let open = b"\"aud\":\"";
    let start = document
        .windows(open.len())
        .position(|w| w == open)
        .expect("credential has an aud string");
    let content_start = start + open.len();
    let content_end = content_start
        + document[content_start..]
            .iter()
            .position(|&b| b == b'"')
            .expect("aud string closing quote");
    let mut out = Vec::with_capacity(document.len());
    out.extend_from_slice(&document[..content_start]);
    out.extend_from_slice(raw_replacement.as_bytes());
    out.extend_from_slice(&document[content_end..]);
    out
}

/// Replaces the JSON string content of client_key with the canonical quoting
/// of `replacement` (the `client_key_replacement` recipe quotes the referenced
/// negative-document string with the canonical string emitter).
fn rebuild_credential_with_client_key(document: &[u8], replacement: &str) -> Vec<u8> {
    let parsed: serde_json::Value =
        serde_json::from_slice(document).expect("base credential parses");
    compose_credential(
        parsed["aud"].as_str().expect("aud"),
        replacement,
        parsed["server_public_key"].as_str().expect("server pub"),
        parsed["server_kid"].as_str().expect("server kid"),
        parsed["url"].as_str().expect("url"),
    )
    .into_bytes()
}

/// Resolves a compose reference of the form "the exact <id> envelope string".
fn referenced_envelope(table: &serde_json::Value, reference: &str) -> Vec<u8> {
    let id = reference
        .strip_prefix("the exact ")
        .and_then(|r| r.strip_suffix(" envelope string"))
        .expect("exact-envelope reference");
    for array in ["positives", "negatives"] {
        let case = table[array]
            .as_array()
            .expect("array")
            .iter()
            .find(|c| c["id"] == id);
        if let Some(case) = case {
            return envelope_of(case);
        }
    }
    panic!("no case named {id}");
}

/// The public-key bytes of a key-vectors.json reject case (by name).
fn key_vector_hex(name: &str) -> Vec<u8> {
    let vectors = load_key_vectors().expect("load key-vectors.json");
    let case = vectors
        .cases
        .iter()
        .find(|c| c.id == name)
        .unwrap_or_else(|| panic!("key-vectors.json has no case {name}"));
    hex_bytes(&case.public_key_hex)
}

/// Materializes a negative case: literal envelope bytes, or the documented
/// composition recipe. Returns (bytes, expected_class).
fn materialize_negative(table: &serde_json::Value, case: &serde_json::Value) -> (Vec<u8>, String) {
    let id = case["id"].as_str().expect("id");
    let expect_class = case["expect_class"]
        .as_str()
        .expect("expect_class")
        .to_owned();
    let priv_alice = envelope_of(find_case(table, "positives", "priv-alice"));
    let cred_alice = envelope_of(find_case(table, "positives", "cred-alice"));

    if let Some(envelope) = case["envelope"].as_str() {
        return (envelope.as_bytes().to_vec(), expect_class);
    }
    let compose = &case["compose"];
    let bytes = match id {
        "priv-rfc8032-test1" => unreachable!("composed positive, not a negative"),
        "neg-invalid-pub-noncanonical-y"
        | "neg-invalid-pub-identity"
        | "neg-invalid-pub-small-order"
        | "neg-invalid-pub-off-curve" => {
            let name = compose["x_from_key_vector"].as_str().expect("vector name");
            let x: [u8; 32] = key_vector_hex(name).try_into().expect("32-byte vector");
            compose_public_envelope(&x).into_bytes()
        }
        "neg-cred-invalid-server-pub" => {
            let x: [u8; 32] = key_vector_hex(
                compose["server_public_key_from_key_vector"]
                    .as_str()
                    .expect("vector name"),
            )
            .try_into()
            .expect("32-byte vector");
            let client_key =
                referenced_envelope(table, compose["client_key"].as_str().expect("ref"));
            compose_credential(
                compose["aud"].as_str().expect("aud"),
                std::str::from_utf8(&client_key).expect("envelope is UTF-8"),
                &encode_b64url(&x),
                &key_id(&x),
                compose["url"].as_str().expect("url"),
            )
            .into_bytes()
        }
        "neg-size-boundary-4096" | "neg-size-boundary-4097" => {
            let total: usize = compose["total_input_bytes"]
                .as_str()
                .and_then(|t| t.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .or_else(|| compose["total_input_bytes"].as_u64().map(|n| n as usize))
                .unwrap_or_else(|| panic!("{id} total_input_bytes"));
            let mut bytes = priv_alice.clone();
            // ASCII 0x20 appended until the total byte length is exact.
            while bytes.len() < total {
                bytes.push(0x20);
            }
            assert_eq!(bytes.len(), total, "size recipe reaches the exact length");
            bytes
        }
        "neg-invalid-utf8" => {
            let mut bytes = priv_alice;
            let last = bytes.len() - 1;
            assert_eq!(bytes[last], 0x7D, "final byte is the closing brace");
            bytes[last] = 0xFF;
            bytes
        }
        "neg-cred-aud-lone-surrogate-escape" => replace_aud_raw(&cred_alice, "\\ud800"),
        "neg-cred-aud-lone-low-surrogate-escape" => replace_aud_raw(&cred_alice, "\\udc00"),
        "neg-cred-aud-escaped-surrogate-pair" => replace_aud_raw(&cred_alice, "\\ud83d\\ude00"),
        "neg-cred-dup-inner-member" => {
            let inner = referenced_envelope(
                table,
                compose["client_key_replacement"].as_str().expect("ref"),
            );
            rebuild_credential_with_client_key(
                &cred_alice,
                std::str::from_utf8(&inner).expect("envelope is UTF-8"),
            )
        }
        other => panic!("unmaterialized composed case {other}"),
    };
    (bytes, expect_class)
}

/// Materializes the composed credential positives (aud_codepoints recipes).
fn materialize_positive(table: &serde_json::Value, case: &serde_json::Value) -> Vec<u8> {
    let id = case["id"].as_str().expect("id");
    if let Some(envelope) = case["envelope"].as_str() {
        return envelope.as_bytes().to_vec();
    }
    let compose = &case["compose"];
    if id == "priv-rfc8032-test1" {
        let seed = seed32(compose["seed_b64u_of_hex"].as_str().expect("seed hex"));
        let pub_bytes: [u8; 32] =
            hex_bytes(compose["public_key_b64u_of_hex"].as_str().expect("pub hex"))
                .try_into()
                .expect("32-byte public key");
        return compose_private_envelope(&seed, &pub_bytes).into_bytes();
    }
    let client_key = referenced_envelope(table, compose["client_key"].as_str().expect("ref"));
    let aud = match compose.get("aud_codepoints") {
        Some(codepoints) => aud_from_codepoints(codepoints),
        None => compose["aud"].as_str().expect("aud").to_owned(),
    };
    compose_credential(
        &aud,
        std::str::from_utf8(&client_key).expect("envelope is UTF-8"),
        compose["server_public_key"].as_str().expect("server pub"),
        compose["server_kid"].as_str().expect("server kid"),
        compose["url"].as_str().expect("url"),
    )
    .into_bytes()
}

/// The sink a negative targets: credential documents run through
/// import_credential with the trusted svc tuple; envelope cases run through
/// the client public or private sink. Routing is EXPLICIT (a fixed list
/// cross-checked against the fixture document shape below), because one
/// credential document (neg-escaped-url-slash) lacks the neg-cred- prefix.
fn is_credential_negative(id: &str) -> bool {
    id.starts_with("neg-cred-") || id == "neg-escaped-url-slash"
}

fn assert_negative_on_sink(case: &serde_json::Value, bytes: &[u8], expect_class: &str) {
    let id = case["id"].as_str().expect("id");
    if is_credential_negative(id) {
        // Routing is by case MEANING (the fixture id), never by demanding a
        // mutated field stay valid: neg-cred-unknown-type deliberately
        // carries "user-key/credential/server", so no discriminator or
        // aud-membership pre-assertion is allowed here. Straight to the
        // importer with the trusted tuple.
        let err =
            import_credential(bytes, &svc_expected()).expect_err("credential negative must fail");
        assert_eq!(err.class(), Some(expect_class), "{id}: wrong class");
        assert_no_input_bytes_in_diagnostic(&err);
        return;
    }
    const PRIVATE_SINK_IDS: [&str; 17] = [
        "neg-unknown-version",
        "neg-unknown-type",
        "neg-bad-kty",
        "neg-bad-crv",
        "neg-empty-d",
        "neg-seed-pub-mismatch",
        "neg-kid-mismatch",
        "neg-dup-member",
        "neg-dup-member-last-mismatched",
        "neg-dup-member-escaped",
        "neg-noncanonical-ws",
        "neg-key-reorder",
        "neg-truncated",
        "neg-oversized-envelope",
        "neg-v-float",
        "neg-size-boundary-4096",
        "neg-size-boundary-4097",
    ];
    let err = if PRIVATE_SINK_IDS.contains(&id) || id == "neg-invalid-utf8" {
        import_private_envelope(bytes).expect_err("negative must fail")
    } else {
        import_public_envelope(bytes).expect_err("negative must fail")
    };
    assert_eq!(err.class(), Some(expect_class), "{id}: wrong class");
    assert_no_input_bytes_in_diagnostic(&err);
}

/// Transfer failure diagnostics carry ONLY class/member/lengths: never the
/// input document or any secret bytes. The leak oracles are derived from
/// the PINNED keys.json / fixture data, not from generic substrings:
/// - the alice seed's base64url text (appears only inside envelope `d`
///   VALUES, and only if a seed leaked),
/// - the alice public key text (appears only inside envelope `x` VALUES),
/// - the literal canonical document fragment `{"crv":` (appears only inside
///   serialized document text; bare member names like `crv` are legitimate
///   diagnostic metadata — production reports `member=crv` for neg-bad-crv
///   — and are explicitly permitted, as are class names and lengths).
///
/// Fixed labels only: no surface interpolation, so a leaking surface can
/// never put its own bytes into the failure message.
fn assert_no_input_bytes_in_diagnostic(err: &UserKeyError) {
    let display = err.to_string();
    let debug = format!("{err:?}");
    let alice_seed_b64u = encode_b64url(&seed32(&oracle_key("alice").seed_hex));
    let alice_pub_b64u = oracle_key("alice").public_key;
    for surface in [&display, &debug] {
        assert!(
            !surface.contains(&alice_seed_b64u),
            "seed bytes leaked to a surface"
        );
        assert!(
            !surface.contains(&alice_pub_b64u),
            "envelope value leaked to a surface"
        );
        assert!(
            !surface.contains("{\"crv\":"),
            "document text leaked to a surface"
        );
    }
}

// ---------------------------------------------------------------------------
// Fixture shape checks (design section 11) — independent #[test] fns
// ---------------------------------------------------------------------------

const FIXED_RANDOM: [u8; 32] = [0x42; 32];

fn deterministic_random() -> impl FnMut(usize) -> Result<Vec<u8>, UserKeyError> {
    move |_length| Ok(FIXED_RANDOM.to_vec())
}

/// The independent recipe aud constant for an aud-control positive (the
/// documented compose recipe value, pinned in code — never parsed out of the
/// credential under test).
fn recipe_aud(id: &str) -> &'static str {
    match id {
        "cred-aud-html-sensitive" => "a<b>&c",
        "cred-aud-codepoints" => "\u{e9}\u{1f600}",
        "cred-aud-control" => "a\u{1}z",
        "cred-aud-separators" => "a\u{2028}b\u{2029}",
        "cred-aud-replacement-char" => "a\u{fffd}b",
        other => panic!("no recipe aud for {other}"),
    }
}

/// The total, document-INDEPENDENT pinned trust tuple for a credential
/// positive: the pinned svc identity (keys.json `svc` + svc url/aud) for
/// every id; the aud-control positives carry their independent recipe aud
/// constant instead of the svc aud. No field is taken from the parsed
/// document — the tuple is fully pinned by fixture identity + recipe
/// constants + svc identity.
fn pinned_expected_tuple(id: &str) -> ExpectedIdentity {
    let mut expected = svc_expected();
    if id != "cred-alice" && id != "cred-bob" {
        expected.aud = recipe_aud(id).to_owned();
    }
    expected
}

/// Cross-check: the DOCUMENT the fixture composes carries exactly the pinned
/// tuple's aud (fixture-vs-recipe consistency, checked against the fixture,
/// never feeding the tuple). This is the only place the document is read,
/// and its result never enters the tuple.
fn assert_document_aud_matches_pin(id: &str, aud_in_document: &str) {
    assert_eq!(
        aud_in_document,
        pinned_expected_tuple(id).aud,
        "{id}: fixture document aud equals the pinned recipe"
    );
}

mod exact_tuple_and_boundaries;
mod import_export;
mod negative_prerequisites;
