//! User-key transfer conformance tests (docs/design/user-keys.md sections
//! 11 and 12.2): all 66 cases of the shared table
//! `spec/fixtures/user-key-transfer.json` are loaded from ../spec/fixtures
//! via std::fs — the fixture file is the arbiter for exact bytes and
//! classes; pinned constants appear only as backup oracles. Deterministic
//! throughout: no wall-clock, no network, no new dependencies. Every test
//! is an independent #[test] fn (no ordering assumptions).

mod common;

use std::fs;

use common::fixtures::{fixture_path, load_key_vectors, load_keys};
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

#[test]
fn transfer_fixture_shape_and_counts() {
    let table = transfer_table();
    let positives = table["positives"].as_array().expect("positives");
    let negatives = table["negatives"].as_array().expect("negatives");
    let context = table["context_cases"].as_array().expect("context_cases");
    assert_eq!(positives.len(), 14, "14 shared positives");
    assert_eq!(negatives.len(), 51, "51 shared negatives");
    assert_eq!(context.len(), 1, "one context case");
    let total = positives.len() + negatives.len() + context.len();
    assert_eq!(total, 66, "66 shared cases");
    for array in ["positives", "negatives", "context_cases"] {
        let ids: Vec<_> = table[array]
            .as_array()
            .expect("array")
            .iter()
            .map(|c| c["id"].as_str().expect("id").to_owned())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "unique ids in {array}");
    }
}

#[test]
fn section11_positives_parse_and_are_canonical() {
    let table = transfer_table();
    for case in table["positives"].as_array().expect("positives") {
        let id = case["id"].as_str().expect("id");
        let bytes = materialize_positive(&table, case);
        let kind = case["kind"].as_str().expect("kind");
        match kind {
            "public_envelope" => {
                let identity = import_public_envelope(&bytes)
                    .unwrap_or_else(|e| panic!("{id} must parse: {e}"));
                // Byte-equal canonical serialization: re-export reproduces
                // the fixture string exactly.
                assert_eq!(
                    identity.export_public_envelope(),
                    bytes,
                    "{id}: canonical bytes must equal the fixture string"
                );
                if let (Some(x), Some(kid)) =
                    (case["expect_x"].as_str(), case["expect_kid"].as_str())
                {
                    assert_eq!(&encode_b64url(&identity.public_key()), x, "{id} x");
                    assert_eq!(identity.kid(), kid, "{id} kid");
                }
            }
            "private_envelope" => {
                let signer = import_private_envelope(&bytes)
                    .unwrap_or_else(|e| panic!("{id} must parse: {e}"));
                // kid is independently recomputed from the public key.
                let pub_bytes = signer.public_key();
                assert_eq!(signer.kid(), key_id(&pub_bytes), "{id} kid");
                // The test-side canonical template must equal the fixture
                // bytes (the private canonical serializer is not part of the
                // public API; template composition is the documented test-side
                // recipe). keys.json carries the seed oracle for the fixture
                // identities; priv-rfc8032-test1 is anchored by the RFC test
                // below instead.
                if id != "priv-rfc8032-test1" {
                    let seed = seed32(&oracle_key(client_name(id)).seed_hex);
                    // Secret-safe: compare via a boolean operand; the
                    // canonical private template embeds the seed.
                    let matches = compose_private_envelope(&seed, &pub_bytes).into_bytes() == bytes;
                    assert!(
                        matches,
                        "{id}: canonical bytes must equal the fixture string"
                    );
                }
            }
            "client_credential" => {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("positive credential is canonical JSON");
                // The trusted tuple is fully pinned by the case id alone;
                // the document aud is only cross-checked against the pin.
                let aud = parsed["aud"].as_str().expect("aud").to_owned();
                assert_document_aud_matches_pin(id, &aud);
                let exact = pinned_expected_tuple(id);
                let imported = import_credential(&bytes, &exact)
                    .unwrap_or_else(|e| panic!("{id} must parse with its exact tuple: {e}"));
                // Canonical bytes: recompose from the validated members.
                let recomposed = compose_credential(
                    parsed["aud"].as_str().expect("aud"),
                    parsed["client_key"].as_str().expect("client_key"),
                    parsed["server_public_key"].as_str().expect("server pub"),
                    parsed["server_kid"].as_str().expect("server kid"),
                    parsed["url"].as_str().expect("url"),
                );
                // Secret-safe: the credential embeds the private envelope, so
                // compare via a boolean operand.
                let matches = recomposed.into_bytes() == bytes;
                assert!(
                    matches,
                    "{id}: canonical bytes must equal the fixture string"
                );
                // The aud the credential carries is the exact aud of the
                // trusted tuple used.
                assert_eq!(
                    imported.connection.aud(),
                    parsed["aud"].as_str().expect("aud")
                );
            }
            other => panic!("unknown positive kind {other}"),
        }
    }
}

/// Maps a fixture positive id to its keys.json identity name (public and
/// private envelope positives of the same identity share the mapping).
fn client_name(id: &str) -> &'static str {
    match id {
        "pub-alice" | "priv-alice" | "cred-alice" => "alice",
        "pub-bob" | "priv-bob" | "cred-bob" => "bob",
        "pub-carol" | "priv-carol" => "carol",
        "priv-rfc8032-test1" => "rfc8032-test1",
        other => panic!("no keys.json mapping for {other}"),
    }
}

#[test]
fn section11_decoded_d_matches_keys_json_and_x_kid_are_pinned() {
    let table = transfer_table();
    for id in [
        "priv-alice",
        "priv-bob",
        "priv-carol",
        "pub-alice",
        "pub-bob",
        "pub-carol",
    ] {
        let case = find_case(&table, "positives", id);
        let parsed: serde_json::Value =
            serde_json::from_slice(&envelope_of(case)).expect("canonical JSON");
        let identity = oracle_key(client_name(id));
        let pub_bytes = decode_b64url_fixed(parsed["x"].as_str().expect("x"), 32)
            .expect("x decodes to 32 bytes");
        // CI obligation: compare decoded d RAW BYTES with keys.json seed_hex,
        // and independently pin x/kid.
        if let Some(d) = parsed["d"].as_str() {
            let seed = decode_b64url(d).expect("d decodes");
            // Secret-safe: compare via a boolean operand with a fixed label.
            let matches = seed == hex_bytes(&identity.seed_hex);
            assert!(matches, "{id}: d bytes == seed_hex (bytes withheld)");
        }
        // keys.json public_key is BASE64URL text, not hex: decode it as such.
        let oracle_pub = decode_b64url_fixed(&identity.public_key, 32)
            .expect("keys.json public_key is canonical base64url");
        assert_eq!(
            pub_bytes, oracle_pub,
            "{id}: x bytes == keys.json public_key"
        );
        assert_eq!(
            key_id(&pub_bytes),
            identity.kid,
            "{id}: key_id(x) == keys.json kid"
        );
        assert_eq!(
            parsed["kid"].as_str().expect("kid"),
            identity.kid,
            "{id} kid member"
        );
    }
}

#[test]
fn section11_embedded_client_key_strict_imports() {
    let table = transfer_table();
    let priv_alice = envelope_of(find_case(&table, "positives", "priv-alice"));
    let priv_bob = envelope_of(find_case(&table, "positives", "priv-bob"));
    for id in ["cred-alice", "cred-bob"] {
        let case = find_case(&table, "positives", id);
        let bytes = envelope_of(case);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("canonical JSON");
        let client_key = parsed["client_key"].as_str().expect("client_key");
        // Embedded client_key equals its referenced positive exactly...
        let referenced = if id == "cred-alice" {
            &priv_alice
        } else {
            &priv_bob
        };
        // ...and its bytes equal the referenced positive exactly. Secret-safe
        // boolean comparison (the private envelope embeds the seed).
        let matches = client_key.as_bytes() == referenced.as_slice();
        assert!(matches, "{id} inner == positive");
        // ...and strict-imports on the credential sink.
        import_credential(&bytes, &svc_expected())
            .unwrap_or_else(|e| panic!("{id} must import: {e}"));
    }
}

#[test]
fn section11_rfc8032_composition_matches_rfc_oracles() {
    let table = transfer_table();
    let case = find_case(&table, "positives", "priv-rfc8032-test1");
    // RFC 8032 section 7.1 TEST 1 seed/public; RFC 8037 A.1 gives the same
    // key as a JWK: d nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A,
    // x 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo.
    let rfc_d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    let rfc_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    let compose = &case["compose"];
    let seed = seed32(compose["seed_b64u_of_hex"].as_str().expect("seed hex"));
    let pub_bytes: [u8; 32] =
        hex_bytes(compose["public_key_b64u_of_hex"].as_str().expect("pub hex"))
            .try_into()
            .expect("32-byte public key");
    // The runner's own base64url encodings MUST equal the RFC strings.
    // Secret-safe: encode_b64url(&seed) IS the seed text, so compare via a
    // boolean operand with a fixed label.
    let seed_matches = encode_b64url(&seed) == rfc_d;
    assert!(seed_matches, "seed b64url == RFC 8037 d (text withheld)");
    assert_eq!(
        encode_b64url(&pub_bytes),
        rfc_x,
        "public b64url == RFC 8037 x"
    );
    // kid via the SDK key-id function.
    let kid = key_id(&pub_bytes);
    let envelope = compose_private_envelope(&seed, &pub_bytes).into_bytes();
    let signer = import_private_envelope(&envelope).expect("composed RFC envelope imports");
    assert_eq!(signer.public_key(), pub_bytes);
    assert_eq!(signer.kid(), kid);
    assert_eq!(
        signer.kid(),
        mcp_jack::encoding::key_id(&signer.public_key())
    );
}

#[test]
fn section11_context_cred_wrong_server_pipeline_vs_trust() {
    let table = transfer_table();
    let case = find_case(&table, "context_cases", "cred-wrong-server");
    assert_eq!(
        case["structural_outcome"].as_str().expect("structural"),
        "accepted_by_import_pipeline"
    );
    assert_eq!(
        case["trust_outcome"].as_str().expect("trust"),
        "server_identity_mismatch"
    );
    let compose = &case["compose"];
    let client_key = referenced_envelope(&table, compose["client_key"].as_str().expect("ref"));
    let document = compose_credential(
        compose["aud"].as_str().expect("aud"),
        std::str::from_utf8(&client_key).expect("envelope is UTF-8"),
        compose["server_public_key"].as_str().expect("server pub"),
        compose["server_kid"].as_str().expect("server kid"),
        compose["url"].as_str().expect("url"),
    )
    .into_bytes();

    // Structural acceptance (pipeline): with the WRONG-SERVER tuple the
    // document carries (internally consistent alice identity), import
    // succeeds — proof that the document itself is valid.
    let wrong_server = ExpectedIdentity {
        url: compose["url"].as_str().expect("url").to_owned(),
        aud: compose["aud"].as_str().expect("aud").to_owned(),
        server_public_key: compose["server_public_key"]
            .as_str()
            .expect("pub")
            .to_owned(),
        server_kid: compose["server_kid"].as_str().expect("kid").to_owned(),
    };
    import_credential(&document, &wrong_server)
        .expect("structurally valid document passes the pipeline");

    // Trust with the independently trusted svc tuple must fail closed with
    // exactly server_identity_mismatch.
    let err =
        import_credential(&document, &svc_expected()).expect_err("wrong server must be refused");
    assert_eq!(err.class(), Some("server_identity_mismatch"));
    assert_no_input_bytes_in_diagnostic(&err);

    // The server-side validator follows the same split.
    validate_issued_credential(&document, &wrong_server).expect("structural pass");
    let err = validate_issued_credential(&document, &svc_expected())
        .expect_err("server trust must refuse the wrong identity");
    assert_eq!(err.class(), Some("server_identity_mismatch"));
}

// ---------------------------------------------------------------------------
// Row 1: generate + export matches the canonical template; kid == key_id
// ---------------------------------------------------------------------------

#[test]
fn row1_generate_export_matches_canonical_template() {
    let key = ClientSigningKey::generate().expect("os randomness");
    assert_eq!(key.kid(), key_id(&key.public_key()), "kid == key_id");
    let envelope = export_public_envelope(&key).expect("public export");
    let pub_bytes = key.public_key();
    assert_eq!(
        envelope,
        compose_public_envelope(&pub_bytes).into_bytes(),
        "exported bytes equal the canonical template"
    );
    let identity = import_public_envelope(&envelope).expect("round trips");
    assert_eq!(identity.public_key(), pub_bytes);
    assert_eq!(identity.kid(), key.kid());
}

// ---------------------------------------------------------------------------
// Row 2: private imports match oracles; signatures are RFC-deterministic
// ---------------------------------------------------------------------------

#[test]
fn row2_private_imports_match_oracles_and_sign_deterministically() {
    let table = transfer_table();
    let message = b"mcp-jack transfer row2 determinism";
    for id in ["priv-alice", "priv-bob", "priv-carol"] {
        let case = find_case(&table, "positives", id);
        let bytes = envelope_of(case);
        let oracle = oracle_key(client_name(id));
        let imported = import_private_envelope(&bytes).expect("strict import");
        let pub_bytes = decode_b64url_fixed(&oracle.public_key, 32).expect("oracle pub");
        assert_eq!(
            imported.public_key().as_slice(),
            pub_bytes.as_slice(),
            "{id} pub"
        );
        assert_eq!(imported.kid(), oracle.kid, "{id} kid");
        // RFC 8032 determinism: the imported signer's signature equals the
        // independently imported pinned seed's signature, byte for byte,
        // and verifies.
        let pinned = ClientSigningKey::from_seed(&seed32(&oracle.seed_hex)).expect("32 bytes");
        assert_eq!(imported.sign(message), pinned.sign(message), "{id} sig");
        assert!(mcp_jack::ed25519::verify(
            &pub_bytes,
            message,
            &imported.sign(message)
        ));
    }
    // RFC 8032 TEST 1: the empty-message signature is pinned.
    let rfc_case = find_case(&table, "positives", "priv-rfc8032-test1");
    let seed = seed32(
        rfc_case["compose"]["seed_b64u_of_hex"]
            .as_str()
            .expect("seed hex"),
    );
    let signer = import_private_envelope(
        &compose_private_envelope(
            &seed,
            &hex_bytes(
                rfc_case["compose"]["public_key_b64u_of_hex"]
                    .as_str()
                    .expect("pub hex"),
            )
            .try_into()
            .expect("32 bytes"),
        )
        .into_bytes(),
    )
    .expect("RFC envelope imports");
    const RFC_SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(
        signer.sign(b"").to_vec(),
        hex_bytes(RFC_SIG_HEX),
        "RFC 8032 TEST 1 empty-message signature"
    );
}

// ---------------------------------------------------------------------------
// Row 3: deterministic issuance, redaction, independent copies
// ---------------------------------------------------------------------------

const FIXED_RANDOM: [u8; 32] = [0x42; 32];

fn deterministic_random() -> impl FnMut(usize) -> Result<Vec<u8>, UserKeyError> {
    move |_length| Ok(FIXED_RANDOM.to_vec())
}

#[test]
fn row3_issue_user_key_deterministic_template_and_redaction() {
    let connection = svc_connection();

    // The derived seed is the fixed random; its canonical private envelope
    // and the composed credential template are computed test-side.
    let derived = ClientSigningKey::from_seed(&FIXED_RANDOM).expect("32 bytes");
    let inner = compose_private_envelope(&FIXED_RANDOM, &derived.public_key());
    let svc = oracle_key("svc");
    let template = compose_credential(
        "https://svc.example.test",
        &inner,
        &svc.public_key,
        &svc.kid,
        "https://svc.example.test",
    );

    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");
    // Credential bytes equal the composed template for the same inputs.
    // Secret-safe: the credential embeds the private envelope, so the
    // comparison runs through a boolean operand with a fixed label.
    let matches = issued.credential_bytes() == template.into_bytes();
    assert!(matches, "issued credential equals the composed template");
    // public_identity matches the derived key.
    assert_eq!(
        issued.public_identity().public_key,
        derived.public_part().public_key
    );
    assert_eq!(issued.public_identity().kid, derived.public_part().kid);
    // Second call with the same injected random gives identical bytes.
    let mut random = deterministic_random();
    let again = issue_user_key(&connection, &mut random).expect("issuance");
    let stable = issued.credential_bytes() == again.credential_bytes();
    assert!(stable, "second issuance with the same random is identical");

    // Debug/Display expose the kid only — no credential bytes, no seed.
    let seed_b64u = encode_b64url(&FIXED_RANDOM);
    let rendered = format!("{issued:?}");
    assert!(rendered.contains(derived.kid()));
    assert!(!rendered.contains(&seed_b64u));
    assert!(!rendered.contains("FZSU"));
    assert!(!rendered.contains("server_private_key"));
    assert!(!rendered.contains("user-key/credential"));
    let display = issued.to_string();
    assert!(!display.contains(&seed_b64u));
    assert!(!display.contains("crv"));

    // Default JSON serialization of the public identity carries EXACTLY the
    // public UserKeyPublic member set and nothing else.
    let json =
        serde_json::to_string(&issued.public_identity()).expect("public identity serializes");
    let expected_json = format!(
        r#"{{"public_key":"{}","kid":"{}"}}"#,
        encode_b64url(&derived.public_key()),
        derived.kid()
    );
    assert_eq!(json, expected_json);

    // Repeated credential_bytes calls return equal, INDEPENDENT copies.
    // Secret-safe boolean comparisons: credential bytes embed the seed.
    let first = issued.credential_bytes();
    let second = issued.credential_bytes();
    let equal = first == second;
    assert!(equal, "first == second");
    let mut mutated = issued.credential_bytes();
    for byte in mutated.iter_mut() {
        *byte = !*byte;
    }
    let diverged = mutated != second;
    assert!(diverged, "mutating the first copy changes nothing else");
    let third = issued.credential_bytes();
    let intact = third == second;
    assert!(intact, "a third copy still equals the original");
    assert_eq!(
        issued.public_identity().kid,
        derived.kid(),
        "public identity unchanged"
    );
    let still_imports = import_credential(&third, &svc_expected()).expect("original imports");
    let signature = still_imports.signer.sign(b"stateless");
    assert_eq!(signature.len(), 64, "retained signer produces signatures");
    assert!(
        mcp_jack::ed25519::verify(&still_imports.signer.public_key(), b"stateless", &signature),
        "retained signer's signature verifies against its public key"
    );
    // Honest scope note: the absence of Serialize/Deserialize on the secret
    // types (ClientSigningKey, IssuedClientKey) is a COMPILE-TIME property
    // and cannot be runtime-asserted here; the compile_fail doc tests on the
    // types plus the consumer examples in rust/README.md carry that proof.
}

// ---------------------------------------------------------------------------
// Row 4: issuance handoff imports on the client role
// ---------------------------------------------------------------------------

#[test]
fn row4_issued_credential_imports_and_signs() {
    let connection = svc_connection();
    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");

    let imported = import_credential(&issued.credential_bytes(), &svc_expected())
        .expect("issued credential imports with the trusted tuple");
    // The signer works and matches the issued public identity.
    let message = b"mcp-jack transfer row4 handoff";
    let signature = imported.signer.sign(message);
    assert_eq!(imported.signer.public_part(), issued.public_identity());
    assert!(
        mcp_jack::ed25519::verify(&imported.signer.public_key(), message, &signature),
        "imported signer verifies"
    );
    // Connection data matches the trusted tuple.
    assert_eq!(imported.connection.url(), "https://svc.example.test");
    assert_eq!(imported.connection.aud(), "https://svc.example.test");
    // The public identity admits through the existing public-only path.
    let record = ServerPublicKey::from_public_part(&issued.public_identity())
        .expect("public identity is a valid server record");
    assert_eq!(record.kid(), issued.public_identity().kid);
    assert!(record.verify(message, &signature));
}

// ---------------------------------------------------------------------------
// Row 5: public envelope import; secret operations refuse not_private
// ---------------------------------------------------------------------------

#[test]
fn row5_public_imports_match_oracles_and_refuse_signing() {
    let table = transfer_table();
    for id in ["pub-alice", "pub-bob", "pub-carol"] {
        let case = find_case(&table, "positives", id);
        let bytes = envelope_of(case);
        let oracle = oracle_key(client_name(id));
        let identity = import_public_envelope(&bytes).expect("strict public import");
        assert_eq!(
            identity.public_key().as_slice(),
            decode_b64url_fixed(&oracle.public_key, 32)
                .expect("oracle pub")
                .as_slice(),
            "{id} pub"
        );
        assert_eq!(identity.kid(), oracle.kid, "{id} kid");
        let err = identity
            .sign(b"no private material")
            .expect_err("must refuse");
        assert_eq!(err.class(), Some("not_private"), "{id}");
    }
}

// ---------------------------------------------------------------------------
// Row 6: every negative fails with exactly expect_class on its sink
// ---------------------------------------------------------------------------

#[test]
fn row6_every_envelope_negative_exact_class() {
    let table = transfer_table();
    for case in table["negatives"].as_array().expect("negatives") {
        let id = case["id"].as_str().expect("id");
        if is_credential_negative(id) {
            continue;
        }
        let (bytes, expect_class) = materialize_negative(&table, case);
        assert_negative_on_sink(case, &bytes, &expect_class);
    }
}

#[test]
fn row6_every_credential_negative_exact_class() {
    let table = transfer_table();
    for case in table["negatives"].as_array().expect("negatives") {
        let id = case["id"].as_str().expect("id");
        if !is_credential_negative(id) {
            continue;
        }
        let (bytes, expect_class) = materialize_negative(&table, case);
        assert_negative_on_sink(case, &bytes, &expect_class);
    }
}

#[test]
fn row6_float_v_reaches_the_canonical_gate_not_early_rejection() {
    let table = transfer_table();
    let case = find_case(&table, "negatives", "neg-v-float");
    let (bytes, expect_class) = materialize_negative(&table, case);
    assert_eq!(expect_class, "non_canonical_bytes");
    // The float 1.0 parses equal to 1 everywhere, so the version check must
    // PASS and the failure must be the final canonical-bytes gate — the
    // serde_json 1-vs-1.0 distinction of design section 16.
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("float v parses");
    assert_eq!(parsed["v"].as_f64(), Some(1.0), "v is the float spelling");
    let err = import_private_envelope(&bytes).expect_err("float v is non-canonical");
    assert_eq!(
        err.class(),
        Some("non_canonical_bytes"),
        "final gate, not early rejection"
    );
    assert_eq!(err.member(), None);
    assert_eq!(err.lengths(), None);
}

#[test]
fn row6_escape_spellings_fail_with_exact_classes() {
    let table = transfer_table();
    // Escaped member name: parses to the same object, so the failure is the
    // canonical-bytes gate, not a member-set error.
    let (bytes, class) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-escaped-member-name"),
    );
    assert_eq!(class, "non_canonical_bytes");
    let err = import_public_envelope(&bytes).expect_err("escaped member name");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
    // Escaped URL solidus: same value after parsing; canonical gate.
    let (bytes, class) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-escaped-url-slash"),
    );
    assert_eq!(class, "non_canonical_bytes");
    let err = import_credential(&bytes, &svc_expected()).expect_err("escaped url");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
}

#[test]
fn row6_duplicate_member_classes_are_ordered() {
    let table = transfer_table();
    // Same-value duplicate: parsing keeps the last occurrence, the document
    // is semantically consistent but the bytes are not canonical.
    let (dup, _) = materialize_negative(&table, find_case(&table, "negatives", "neg-dup-member"));
    let err = import_private_envelope(&dup).expect_err("duplicate member");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
    // Mismatched last value: parsing keeps bob's kid, so the ordered
    // pipeline hits the kid gate BEFORE canonicality.
    let (mismatched, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-dup-member-last-mismatched"),
    );
    let err = import_private_envelope(&mismatched).expect_err("mismatched last value");
    assert_eq!(err.class(), Some("kid_mismatch"));
    assert_eq!(err.member(), Some("kid"));
    // Escaped duplicate member name: distinct raw key, duplicate kept, and
    // the canonical gate fires (non_canonical_bytes, not kid_mismatch).
    let (escaped, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-dup-member-escaped"),
    );
    let err = import_private_envelope(&escaped).expect_err("escaped duplicate");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
    // Credential with a duplicated inner member: the inner envelope's
    // duplicate is non_canonical_bytes propagated through the credential.
    let (inner_dup, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-dup-inner-member"),
    );
    let err = import_credential(&inner_dup, &svc_expected()).expect_err("inner duplicate");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
}

#[test]
fn row6_wrong_sink_envelope_types() {
    let table = transfer_table();
    let priv_alice = envelope_of(find_case(&table, "positives", "priv-alice"));
    let pub_alice = envelope_of(find_case(&table, "positives", "pub-alice"));
    // Client private sink fed public material.
    let err = import_private_envelope(&pub_alice).expect_err("public in private sink");
    assert_eq!(err.class(), Some("wrong_envelope_type"));
    assert_eq!(err.member(), Some("type"));
    // Client public sink fed private material.
    let err = import_public_envelope(&priv_alice).expect_err("private in public sink");
    assert_eq!(err.class(), Some("wrong_envelope_type"));
    // Server sink fed private or credential material.
    let err = mcp_jack::user_key::server::import_public_envelope(&priv_alice)
        .expect_err("private in server sink");
    assert_eq!(err.class(), Some("private_material_rejected"));
    let cred_alice = envelope_of(find_case(&table, "positives", "cred-alice"));
    let err = mcp_jack::user_key::server::import_public_envelope(&cred_alice)
        .expect_err("credential in server sink");
    assert_eq!(err.class(), Some("private_material_rejected"));
    // Credential carrying a public client_key (neg-cred-client-key-public).
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-client-key-public"),
    );
    let err = import_credential(&bytes, &svc_expected()).expect_err("public client_key");
    assert_eq!(err.class(), Some("wrong_envelope_type"));
    // Non-canonical inner envelope propagates non_canonical_bytes.
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-client-key-noncanonical"),
    );
    let err = import_credential(&bytes, &svc_expected()).expect_err("non-canonical client_key");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
}

// ---------------------------------------------------------------------------
// Row 7: secret absence
// ---------------------------------------------------------------------------

#[test]
fn row7_public_export_contains_no_private_material() {
    let table = transfer_table();
    let seed_b64u = encode_b64url(&seed32(&oracle_key("alice").seed_hex));
    for id in ["pub-alice", "pub-bob", "pub-carol"] {
        let bytes = envelope_of(find_case(&table, "positives", id));
        let identity = import_public_envelope(&bytes).expect("public import");
        let exported = identity.export_public_envelope();
        let exported_text = std::str::from_utf8(&exported).expect("UTF-8");
        // Full 3-byte token substring search (a windows(2) window can never
        // match a 3-byte needle, which made the original check vacuous).
        assert!(!exported_text.contains("\"d\""), "{id}: no d member");
        assert!(!std::str::from_utf8(&exported)
            .expect("UTF-8")
            .contains(&seed_b64u));
        let text = std::str::from_utf8(&exported).expect("UTF-8");
        assert!(text.contains("user-key/public"));
    }
    // Even a PRIVATE export path is absent: the only public export of a
    // signer is via export_public_envelope, which by construction serializes
    // the public template (row1 checks byte equality with that template).
    let alice = import_private_envelope(&envelope_of(find_case(&table, "positives", "priv-alice")))
        .expect("import");
    let exported = export_public_envelope(&alice).expect("public export");
    assert!(!std::str::from_utf8(&exported)
        .expect("UTF-8")
        .contains(&seed_b64u));
}

#[test]
fn row7_credentials_carry_no_server_private_key_member() {
    let table = transfer_table();
    for id in ["cred-alice", "cred-bob", "cred-aud-html-sensitive"] {
        let bytes = envelope_of(find_case(&table, "positives", id));
        assert!(
            !bytes
                .windows(b"server_private_key".len())
                .any(|w| w == b"server_private_key"),
            "{id}: no server_private_key member (byte test)"
        );
    }
    // The smuggle attempt itself is a member-set error.
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-extra-server-private-key"),
    );
    let err = import_credential(&bytes, &svc_expected()).expect_err("smuggled member");
    assert_eq!(err.class(), Some("bad_member_set"));
    // Issuance output redacts by default (row3 checks Debug/Display/JSON);
    // here: the issued credential bytes are ONLY returned through the
    // explicit credential_bytes accessor, never through Debug/Display.
    let connection = svc_connection();
    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");
    let rendered = format!("{issued:?}{issued}");
    assert!(!rendered.contains("server_private_key"));
    assert!(!rendered.contains("client_key"));
}

// ---------------------------------------------------------------------------
// Row 8: mutation isolation (design section 9)
// ---------------------------------------------------------------------------

#[test]
fn row8_mutation_isolation_for_exports_imports_issuance() {
    let table = transfer_table();
    let message = b"mcp-jack transfer row8 isolation";
    // (a) exports: mutating returned envelope bytes changes nothing.
    let priv_alice = envelope_of(find_case(&table, "positives", "priv-alice"));
    let signer = import_private_envelope(&priv_alice).expect("import");
    let exported = export_public_envelope(&signer).expect("export");
    let mut copy = exported.clone();
    copy[10] ^= 0xff;
    assert_ne!(copy, exported);
    assert_eq!(
        export_public_envelope(&signer).expect("fresh export"),
        exported,
        "second export is fresh and unchanged"
    );
    // (b) imports: mutating the INPUT envelope slice after import changes
    // nothing (the signer is already built from copied bytes).
    let mut input = priv_alice.clone();
    let signer2 = import_private_envelope(&input).expect("import");
    input[10] ^= 0xff;
    assert_eq!(signer2.sign(message), signer.sign(message));
    // (c) public_part / connection accessors return independent owned data.
    let imported = import_credential(
        &envelope_of(find_case(&table, "positives", "cred-alice")),
        &svc_expected(),
    )
    .expect("credential import");
    let mut part = imported.signer.public_part();
    part.kid.push('x');
    assert_ne!(part.kid, imported.signer.kid());
    // (d) issuance outputs: independent copies (row3's full check repeated
    // compactly here for the row-8 obligation).
    let connection = svc_connection();
    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");
    let original = issued.credential_bytes();
    let mut mutated = issued.credential_bytes();
    mutated[0] ^= 0xff;
    // Secret-safe boolean comparison (credential bytes embed the seed).
    let diverged = mutated != original;
    assert!(diverged, "mutating a copy leaves the issuer untouched");
    let intact = issued.credential_bytes() == original;
    assert!(intact, "issuer re-emits the original bytes");
}

// ---------------------------------------------------------------------------
// Row 9: redaction (debug_hides_seed style, per surface)
// ---------------------------------------------------------------------------

#[test]
fn row9_debug_hides_seed_for_signer_import_and_issuance() {
    let table = transfer_table();
    // Imported credential: Debug and Display carry kid/public only.
    let imported = import_credential(
        &envelope_of(find_case(&table, "positives", "cred-alice")),
        &svc_expected(),
    )
    .expect("import");
    let seed_b64u = encode_b64url(&seed32(&oracle_key("alice").seed_hex));
    for surface in [
        format!("{:?}", imported.signer),
        imported.signer.to_string(),
    ] {
        assert!(!surface.contains(&seed_b64u), "seed leaked to a surface");
        assert!(!surface.contains("FZSU"), "seed prefix leaked to a surface");
        assert!(surface.contains(imported.signer.kid()));
    }
    for surface in [format!("{imported:?}"), imported.to_string()] {
        assert!(!surface.contains(&seed_b64u));
        assert!(!surface.contains("client_key"));
    }
    // Issuance result: Debug and Display hide the seed and credential.
    let connection = svc_connection();
    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");
    let fixed_seed_b64u = encode_b64url(&FIXED_RANDOM);
    for surface in [format!("{issued:?}"), issued.to_string()] {
        assert!(!surface.contains(&fixed_seed_b64u));
        assert!(!surface.contains("crv"));
        assert!(!surface.contains("user-key/credential"));
    }
    // Error surfaces of transfer failures print only class/member/lengths.
    let bad = envelope_of(find_case(&table, "negatives", "neg-kid-mismatch"));
    let err = import_private_envelope(&bad).expect_err("kid mismatch");
    let display = err.to_string();
    assert!(display.starts_with("jack: user key: kid_mismatch"));
    assert!(!display.contains(&seed_b64u));
    assert!(!display.contains("crv"));
}

// ---------------------------------------------------------------------------
// Row 10: non-extractable signer compatibility
// ---------------------------------------------------------------------------

/// A test-only signer implementing ONLY the SDK signer trait (no inherent
/// methods beyond the trait; no seed accessor). It wraps a software key
/// internally, exactly like an OS key store would wrap its own material.
struct NonExtractableSigner {
    inner: ClientSigningKey,
}

impl Signer for NonExtractableSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        Ok(self.inner.sign(message).to_vec())
    }
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    fn kid(&self) -> &str {
        self.inner.kid()
    }
}

#[test]
fn row10_nonextractable_signer_works_through_dyn_trait() {
    let table = transfer_table();
    let signer = NonExtractableSigner {
        inner: import_private_envelope(&envelope_of(find_case(&table, "positives", "priv-alice")))
            .expect("import"),
    };
    let message = b"mcp-jack transfer row10 non-extractable";
    let dynamic: &dyn Signer = &signer;
    let envelope = export_public_envelope(dynamic).expect("public export through &dyn Signer");
    // The export equals the canonical template for the wrapped identity.
    let pub_bytes = dynamic.public_key();
    assert_eq!(envelope, compose_public_envelope(&pub_bytes).into_bytes());
    // Signing still works through the trait handle.
    let signature = dynamic
        .sign(message)
        .expect("software signing is infallible");
    assert!(mcp_jack::ed25519::verify(&pub_bytes, message, &signature));
    // The trait exposes sign/public_key/kid only — no seed accessor — so a
    // non-extractable implementation reveals nothing (capability absence is
    // additionally guarded by the compile_fail doc tests in rust/src/user_key.rs).
}

// ---------------------------------------------------------------------------
// Row 12: trust matrix
// ---------------------------------------------------------------------------

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

#[test]
fn row12_valid_credential_needs_exact_trusted_tuple() {
    let table = transfer_table();
    let svc = svc_expected();
    // Each credential positive succeeds ONLY with an independently supplied
    // tuple (pinned svc identity; for aud-control positives the recipe aud
    // constant) — never with a tuple copied from the credential.
    for case in table["positives"].as_array().expect("positives") {
        let id = case["id"].as_str().expect("id");
        if case["kind"].as_str() != Some("client_credential") {
            continue;
        }
        let bytes = materialize_positive(&table, case);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("canonical JSON");
        let aud = parsed["aud"].as_str().expect("aud").to_owned();
        // The tuple is pinned by the id alone; the document aud is only a
        // fixture-vs-recipe cross-check and never feeds the tuple.
        assert_document_aud_matches_pin(id, &aud);
        let exact = pinned_expected_tuple(id);
        import_credential(&bytes, &exact)
            .unwrap_or_else(|e| panic!("{id} must import with its exact aud tuple: {e}"));

        // Any differing expected identity refuses with the trust class.
        let differing = ExpectedIdentity {
            aud: "https://other.example.test".to_owned(),
            url: exact.url.clone(),
            server_public_key: exact.server_public_key.clone(),
            server_kid: exact.server_kid.clone(),
        };
        let err = import_credential(&bytes, &differing).expect_err("aud mismatch");
        assert_eq!(err.class(), Some("server_identity_mismatch"), "{id}");
        // Wrong url.
        let wrong_url = ExpectedIdentity {
            aud: exact.aud.clone(),
            url: "https://other.example.test".to_owned(),
            server_public_key: exact.server_public_key.clone(),
            server_kid: exact.server_kid.clone(),
        };
        let err = import_credential(&bytes, &wrong_url).expect_err("url mismatch");
        assert_eq!(err.class(), Some("server_identity_mismatch"));
        // Wrong server public key (a consistent bob tuple).
        let bob = oracle_key("bob");
        let wrong_key = ExpectedIdentity {
            aud: exact.aud.clone(),
            url: exact.url.clone(),
            server_public_key: bob.public_key.clone(),
            server_kid: bob.kid.clone(),
        };
        let err = import_credential(&bytes, &wrong_key).expect_err("server key mismatch");
        assert_eq!(err.class(), Some("server_identity_mismatch"));
        // Wrong server kid (inconsistent with its public key).
        let wrong_kid = ExpectedIdentity {
            aud: exact.aud.clone(),
            url: exact.url.clone(),
            server_public_key: exact.server_public_key.clone(),
            server_kid: bob.kid.clone(),
        };
        let err = import_credential(&bytes, &wrong_kid).expect_err("server kid mismatch");
        assert_eq!(err.class(), Some("server_identity_mismatch"));
    }

    // cred-wrong-server: structurally valid, wrong server identity.
    let case = find_case(&table, "context_cases", "cred-wrong-server");
    let compose = &case["compose"];
    let client_key = referenced_envelope(&table, compose["client_key"].as_str().expect("ref"));
    let document = compose_credential(
        compose["aud"].as_str().expect("aud"),
        std::str::from_utf8(&client_key).expect("envelope is UTF-8"),
        compose["server_public_key"].as_str().expect("pub"),
        compose["server_kid"].as_str().expect("kid"),
        compose["url"].as_str().expect("url"),
    )
    .into_bytes();
    let err = import_credential(&document, &svc).expect_err("wrong server refused");
    assert_eq!(err.class(), Some("server_identity_mismatch"));

    // Pin conflict: a consistently computed but different server tuple.
    let bob = oracle_key("bob");
    let conflict = ExpectedIdentity {
        url: svc.url.clone(),
        aud: svc.aud.clone(),
        server_public_key: bob.public_key.clone(),
        server_kid: bob.kid.clone(),
    };
    let cred_alice = envelope_of(find_case(&table, "positives", "cred-alice"));
    let err = import_credential(&cred_alice, &conflict).expect_err("pin conflict");
    assert_eq!(err.class(), Some("server_identity_mismatch"));
}

#[test]
fn row12_invalid_expected_tuple_refuses_after_document_validation() {
    let table = transfer_table();
    let cred_alice = envelope_of(find_case(&table, "positives", "cred-alice"));
    let base = svc_expected();
    let incomplete_tuples = [
        (
            "missing url",
            ExpectedIdentity {
                url: String::new(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: base.server_kid.clone(),
            },
        ),
        (
            "empty aud",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: String::new(),
                server_public_key: base.server_public_key.clone(),
                server_kid: base.server_kid.clone(),
            },
        ),
        (
            "invalid server public key spelling",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: "not-base64url!!".to_owned(),
                server_kid: base.server_kid.clone(),
            },
        ),
        (
            "kid conflicting with its public key",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: oracle_key("bob").kid.clone(),
            },
        ),
        (
            "malformed server kid spelling",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: "not-base64url!!".to_owned(),
            },
        ),
        (
            "empty server kid",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: String::new(),
            },
        ),
        (
            "padded server kid",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: format!("{}=", base.server_kid),
            },
        ),
        (
            "server kid with a nonzero unused bit (same 32 bytes)",
            // The 43-char unpadded encoding of 32 bytes uses 4 bits of the
            // final character: '8' (0b111100) and '9' (0b111101) share the
            // same top 4 bits, so both decode to the identical kid bytes
            // while '9' carries a nonzero padding bit — canonical base64url
            // forbids it.
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: format!("{}9", &base.server_kid[..base.server_kid.len() - 1]),
            },
        ),
        (
            "truncated server kid",
            ExpectedIdentity {
                url: base.url.clone(),
                aud: base.aud.clone(),
                server_public_key: base.server_public_key.clone(),
                server_kid: base.server_kid[..base.server_kid.len() - 1].to_owned(),
            },
        ),
    ];
    for (label, tuple) in incomplete_tuples {
        let err =
            import_credential(&cred_alice, &tuple).expect_err("incomplete/invalid tuple refuses");
        assert_eq!(err.class(), Some("server_identity_mismatch"), "{label}");
        // The SAME tuple controls apply to the server-side validator: the
        // shared helper maps every malformed expected kid to the trust class.
        let err = validate_issued_credential(&cred_alice, &tuple)
            .expect_err("server validator refuses the same invalid tuples");
        assert_eq!(err.class(), Some("server_identity_mismatch"), "{label}");
        // A valid signer/configuration is never returned alongside the
        // refusal (the Result is Err; nothing else escapes).
    }
    // Invalid DOCUMENTS keep their earlier pipeline classes even against a
    // valid trusted tuple...
    let earlier = [
        ("neg-cred-server-kid-mismatch", "kid_mismatch"),
        ("neg-cred-bad-url", "bad_url"),
        ("neg-cred-empty-aud", "wrong_field_type"),
    ];
    for (id, class) in earlier {
        let (bytes, _) = materialize_negative(&table, find_case(&table, "negatives", id));
        let err = import_credential(&bytes, &svc_expected()).expect_err(id);
        assert_eq!(err.class(), Some(class), "{id}");
    }
    // ...including the composed invalid-server-pub case.
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-invalid-server-pub"),
    );
    let err = import_credential(&bytes, &svc_expected()).expect_err("invalid server pub");
    assert_eq!(err.class(), Some("invalid_public_key"));
    // ...and even against an INVALID tuple the document class still wins.
    let bogus = ExpectedIdentity {
        url: String::new(),
        aud: String::new(),
        server_public_key: "!!!".to_owned(),
        server_kid: "???".to_owned(),
    };
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-server-kid-mismatch"),
    );
    let err = import_credential(&bytes, &bogus).expect_err("document class first");
    assert_eq!(err.class(), Some("kid_mismatch"));

    // Server-side validation uses the same pipeline before comparing its
    // own identity.
    let good = svc_expected();
    validate_issued_credential(&cred_alice, &good).expect("server validates its own credential");
    let other = ExpectedIdentity {
        url: good.url.clone(),
        aud: good.aud.clone(),
        server_public_key: oracle_key("bob").public_key.clone(),
        server_kid: oracle_key("bob").kid.clone(),
    };
    let err = validate_issued_credential(&cred_alice, &other).expect_err("identity differs");
    assert_eq!(err.class(), Some("server_identity_mismatch"));
    let (bytes, _) =
        materialize_negative(&table, find_case(&table, "negatives", "neg-cred-bad-url"));
    let err = validate_issued_credential(&bytes, &good).expect_err("bad url keeps its class");
    assert_eq!(err.class(), Some("bad_url"));
}

// ---------------------------------------------------------------------------
// Row 13: representation and boundary controls
// ---------------------------------------------------------------------------

#[test]
fn row13_boundary_negatives_exact_classes() {
    let table = transfer_table();
    let cases = [
        ("neg-b64-trailing-bits", "bad_encoding", "client"),
        ("neg-escaped-member-name", "non_canonical_bytes", "client"),
        ("neg-escaped-url-slash", "non_canonical_bytes", "credential"),
        ("neg-size-boundary-4096", "non_canonical_bytes", "client"),
        ("neg-size-boundary-4097", "oversized_envelope", "client"),
        ("neg-invalid-utf8", "malformed_json", "client"),
    ];
    for (id, class, _sink) in cases {
        let (bytes, expect_class) =
            materialize_negative(&table, find_case(&table, "negatives", id));
        assert_eq!(expect_class, class, "{id} fixture class");
        assert_negative_on_sink(find_case(&table, "negatives", id), &bytes, class);
    }
    // Length diagnostics: the oversized gate reports observed/expected.
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-size-boundary-4097"),
    );
    let err = import_public_envelope(&bytes).expect_err("4097 bytes");
    assert_eq!(err.lengths(), Some((4097, 4096)));
    // The 4096-boundary document parses fine and reaches the canonical gate.
    let (bytes, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-size-boundary-4096"),
    );
    let err = import_private_envelope(&bytes).expect_err("4096 padded document");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
    assert_eq!(err.lengths(), None);
}

#[test]
fn row13_public_import_export_round_trips_byte_identical() {
    let table = transfer_table();
    for id in ["pub-alice", "pub-bob", "pub-carol"] {
        let fixture_bytes = envelope_of(find_case(&table, "positives", id));
        let identity = import_public_envelope(&fixture_bytes).expect("import");
        assert_eq!(
            identity.export_public_envelope(),
            fixture_bytes,
            "{id}: import -> export is byte-identical to the fixture string"
        );
    }
}

// ---------------------------------------------------------------------------
// Row 14: credential aud/JCS controls
// ---------------------------------------------------------------------------

#[test]
fn row14_all_five_cred_aud_positives_import_with_exact_aud() {
    let table = transfer_table();
    for id in [
        "cred-aud-html-sensitive",
        "cred-aud-codepoints",
        "cred-aud-control",
        "cred-aud-separators",
        "cred-aud-replacement-char",
    ] {
        let case = find_case(&table, "positives", id);
        let bytes = materialize_positive(&table, case);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("canonical JSON");
        let aud = parsed["aud"].as_str().expect("aud").to_owned();
        // Independent tuple: pinned entirely by the case id (svc identity +
        // the recipe aud constant) — never copied out of the credential
        // under test; the document aud is only a cross-check.
        assert_document_aud_matches_pin(id, &aud);
        let tuple = pinned_expected_tuple(id);
        import_credential(&bytes, &tuple)
            .unwrap_or_else(|e| panic!("{id} must import with its exact aud tuple: {e}"));
        // Recipe spot checks: the aud strings are exactly the pinned
        // recipe constants.
        assert_eq!(aud, recipe_aud(id), "{id} aud == recipe constant");
    }
}

#[test]
fn row14_surrogate_spellings_have_exact_classes() {
    let table = transfer_table();
    for (id, class) in [
        ("neg-cred-aud-lone-surrogate-escape", "malformed_json"),
        ("neg-cred-aud-lone-low-surrogate-escape", "malformed_json"),
        ("neg-cred-aud-escaped-surrogate-pair", "non_canonical_bytes"),
    ] {
        let (bytes, fixture_class) =
            materialize_negative(&table, find_case(&table, "negatives", id));
        assert_eq!(fixture_class, class, "{id} fixture class");
        let err = import_credential(&bytes, &svc_expected()).expect_err(id);
        assert_eq!(err.class(), Some(class), "{id}");
    }
}

#[test]
fn row14_escaped_equivalent_and_inner_dup_errors_follow_section5() {
    let table = transfer_table();
    // Covered in depth by row6_duplicate_member_classes_are_ordered; the
    // row-14 obligation restates the two credential-relevant cases.
    let (escaped, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-dup-member-escaped"),
    );
    let err = import_private_envelope(&escaped).expect_err("escaped duplicate");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
    let (inner, _) = materialize_negative(
        &table,
        find_case(&table, "negatives", "neg-cred-dup-inner-member"),
    );
    let err = import_credential(&inner, &svc_expected()).expect_err("inner duplicate");
    assert_eq!(err.class(), Some("non_canonical_bytes"));
}

#[test]
fn row14_repeated_exports_are_fresh_and_identical() {
    let table = transfer_table();
    let message = b"mcp-jack transfer row14 ownership";
    // (a) Public exports: first == second; fully mutate the first; the
    // second is unchanged; a third export equals the original. Public
    // envelope bytes carry no secret, so direct comparison is fine.
    let signer =
        import_private_envelope(&envelope_of(find_case(&table, "positives", "priv-alice")))
            .expect("import");
    let mut first = export_public_envelope(&signer).expect("export");
    let second = export_public_envelope(&signer).expect("export");
    let equal = first == second;
    assert!(equal, "repeated export freshness");
    // Public envelope bytes carry no secret: mutate the ACTUAL first output
    // (not a clone) and compare directly.
    for byte in first.iter_mut() {
        *byte = !*byte;
    }
    let diverged = first != second;
    assert!(diverged, "mutating the first export changes nothing else");
    let third = export_public_envelope(&signer).expect("export");
    let intact = third == second;
    assert!(intact, "a third export still equals the original");
    // (b) Issuer ownership: the credential export stays intact AND the
    // retained signer is used after the mutation — it is imported from the
    // ORIGINAL issued credential before any mutation, snapshot BEFORE any
    // export is taken, then re-checked against its pre-mutation signature
    // and identity after a returned credential copy is fully overwritten.
    // The issuer's full public identity is snapshotted before and rechecked
    // after. A fresh re-import from the unchanged third export still signs
    // identically. Signatures are public; credential bytes are secret-safe
    // compared via boolean operands.
    let connection = svc_connection();
    let mut random = deterministic_random();
    let issued = issue_user_key(&connection, &mut random).expect("issuance");
    let original = issued.credential_bytes();
    let imported0 = import_credential(&original, &svc_expected()).expect("import");
    // PRE-mutation snapshots: retained-signer signature/identity and the
    // issuer's full public identity.
    let pre_sig = imported0.signer.sign(message);
    let pre_kid = imported0.signer.kid().to_owned();
    let pre_signer_part = imported0.signer.public_part();
    let pre_issued_identity = issued.public_identity();
    let mut first = issued.credential_bytes();
    let second = issued.credential_bytes();
    let snapshot = second.clone();
    // Fully overwrite the actual first output (not a clone of it).
    for byte in first.iter_mut() {
        *byte = !*byte;
    }
    // The SECOND export, taken before the mutation, is still intact: it
    // equals its independently cloned snapshot.
    let second_intact = second == snapshot;
    assert!(second_intact, "the pre-mutation second export is unchanged");
    let diverged = first != snapshot;
    assert!(diverged, "mutating the first export changes nothing else");
    // A third export still equals the ORIGINAL bytes.
    let third = issued.credential_bytes();
    let intact = third == original;
    assert!(intact, "a third export still equals the ORIGINAL bytes");
    // The RETAINED signer (imported from the ORIGINAL credential before the
    // mutation) is unchanged: same signature and identity as pre-mutation.
    let sig_stable = imported0.signer.sign(message) == pre_sig;
    assert!(sig_stable, "the retained signer still signs identically");
    assert_eq!(
        imported0.signer.kid(),
        pre_kid,
        "retained signer kid unchanged"
    );
    assert_eq!(
        imported0.signer.public_part(),
        pre_signer_part,
        "retained signer identity unchanged"
    );
    assert!(
        mcp_jack::ed25519::verify(&imported0.signer.public_key(), message, &pre_sig),
        "retained-signer signature verifies"
    );
    // The issuer's full public identity is retained unchanged.
    assert_eq!(
        issued.public_identity(),
        pre_issued_identity,
        "issued public identity unchanged"
    );
    // A signer freshly imported from the unchanged third export is the SAME
    // key: identical signature and public identity.
    let imported1 = import_credential(&third, &svc_expected()).expect("re-import");
    let reimported_sig_stable = imported1.signer.sign(message) == pre_sig;
    assert!(
        reimported_sig_stable,
        "the signer imported from the unchanged third export signs identically"
    );
    assert_eq!(
        imported1.signer.kid(),
        pre_kid,
        "re-imported signer kid unchanged"
    );
}

// ---------------------------------------------------------------------------
// Section 11 negative prerequisites: for EVERY one of the 51 negatives the
// intended mutation must exist in the bytes and the non-mutated baseline
// fields must be intact — WITHOUT demanding the mutated field stay valid
// (routing/canonicity requirements never apply to deliberately mutated
// fields). Byte-level checks only: no importer execution here. All
// envelope/seed/credential comparisons run through secret-safe booleans;
// public kid/pubkey strings, counts and class names may be asserted
// directly.
// ---------------------------------------------------------------------------

/// Counts non-overlapping byte occurrences of a needle.
fn occurrences(bytes: &[u8], needle: &str) -> usize {
    bytes
        .windows(needle.len())
        .filter(|w| *w == needle.as_bytes())
        .count()
}

#[test]
fn row6_negative_prerequisites_hold_for_all_51_cases() {
    let table = transfer_table();
    let negatives = table["negatives"].as_array().expect("negatives");
    let priv_alice = envelope_of(find_case(&table, "positives", "priv-alice"));
    let cred_alice = envelope_of(find_case(&table, "positives", "cred-alice"));
    let canonical_priv: serde_json::Value =
        serde_json::from_slice(&priv_alice).expect("canonical private parses");
    let canonical_pub: serde_json::Value = {
        let pub_alice = envelope_of(find_case(&table, "positives", "pub-alice"));
        serde_json::from_slice(&pub_alice).expect("canonical public parses")
    };
    let canonical_cred: serde_json::Value =
        serde_json::from_slice(&cred_alice).expect("canonical credential parses");
    let alice = oracle_key("alice");
    let bob = oracle_key("bob");
    let svc = svc_expected();
    let alice_seed_b64u = encode_b64url(&seed32(&alice.seed_hex));

    let mut covered = 0usize;
    for case in negatives {
        let id = case["id"].as_str().expect("id").to_owned();
        let (bytes, _) = materialize_negative(&table, case);
        covered += 1;
        // Helper views (parsed lazily; malformed documents skip parsing).
        let parsed = || -> serde_json::Value {
            serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{id} must parse: {e}"))
        };
        match id.as_str() {
            // --- envelope member-set / field mutations -------------------
            "neg-unknown-version" => {
                let mut v = parsed();
                assert_eq!(v["v"], 2, "{id}: mutated v present");
                v["v"] = serde_json::json!(1);
                let matches = v == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            "neg-unknown-type" => {
                let mut v = parsed();
                assert_eq!(v["type"], "user-key/secret", "{id}: mutated type");
                v["type"] = serde_json::json!("user-key/private");
                let matches = v == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            "neg-bad-kty" => {
                let mut v = parsed();
                assert_eq!(v["kty"], "EC", "{id}: mutated kty");
                v["kty"] = serde_json::json!("OKP");
                let matches = v == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            "neg-bad-crv" => {
                let mut v = parsed();
                assert_eq!(v["crv"], "Ed448", "{id}: mutated crv");
                v["crv"] = serde_json::json!("Ed25519");
                let matches = v == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            "neg-unknown-field" => {
                let mut v = parsed();
                assert!(v.get("comment").is_some(), "{id}: extra member present");
                v.as_object_mut().expect("object").remove("comment");
                let matches = v == canonical_pub;
                assert!(matches, "{id}: other members intact");
            }
            "neg-missing-kid" => {
                let mut v = parsed();
                assert!(v.get("kid").is_none(), "{id}: kid absent");
                v["kid"] = serde_json::json!(alice.kid);
                let matches = v == canonical_pub;
                assert!(matches, "{id}: other members intact");
            }
            "neg-wrong-field-type" => {
                let mut v = parsed();
                assert!(v["kid"].is_number(), "{id}: kid is a number");
                v["kid"] = serde_json::json!(alice.kid);
                let matches = v == canonical_pub;
                assert!(matches, "{id}: other members intact");
            }
            "neg-null-field" => {
                let mut v = parsed();
                assert!(v["x"].is_null(), "{id}: x is null");
                v["x"] = serde_json::json!(alice.public_key);
                let matches = v == canonical_pub;
                assert!(matches, "{id}: other members intact");
            }
            "neg-empty-d" => {
                let mut v = parsed();
                let d_is_empty = v["d"] == serde_json::json!("");
                assert!(d_is_empty, "{id}: d is empty");
                v["d"] = canonical_priv["d"].clone();
                let matches = v == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            // --- encoding spellings --------------------------------------
            "neg-b64-padding" => {
                let v = parsed();
                let x = v["x"].as_str().expect("x string");
                assert!(x.ends_with('='), "{id}: padded spelling present");
                assert_eq!(x.trim_end_matches('='), alice.public_key, "{id} baseline x");
                let mut intact = v;
                intact["x"] = canonical_pub["x"].clone();
                let matches = intact == canonical_pub;
                assert!(matches, "{id}: nonmutated baseline intact");
            }
            "neg-b64-char" => {
                let v = parsed();
                let kid = v["kid"].as_str().expect("kid string");
                let pos = kid.find('+').expect("{id}: '+' spelling present");
                assert!(kid[pos + 1..].find('+').is_none(), "{id}: exactly one '+");
                // Restore the EXACT pinned character at the mutated position — the
                // fixture substituted '+' for it; no base64 alphabet conversion applies.
                let pinned_char = alice.kid[pos..].chars().next().expect("pinned kid char");
                let restored = kid.replacen('+', &pinned_char.to_string(), 1);
                assert_eq!(restored, alice.kid, "{id} baseline kid");
                let mut intact = v;
                intact["kid"] = canonical_pub["kid"].clone();
                let matches = intact == canonical_pub;
                assert!(matches, "{id}: nonmutated baseline intact");
            }
            "neg-len-short" => {
                let v = parsed();
                let x = v["x"].as_str().expect("x string");
                assert_eq!(x.len(), 42, "{id}: short x length");
                assert_eq!(&x[..42], &alice.public_key[..42], "{id} baseline prefix");
                let mut intact = v;
                intact["x"] = canonical_pub["x"].clone();
                let matches = intact == canonical_pub;
                assert!(matches, "{id}: nonmutated baseline intact");
            }
            "neg-len-long" => {
                let v = parsed();
                let kid = v["kid"].as_str().expect("kid string");
                assert_eq!(kid.len(), 44, "{id}: long kid length");
                assert!(
                    kid.starts_with(alice.kid.as_str()),
                    "{id} baseline kid prefix"
                );
                assert_eq!(&kid[43..], "A", "{id}: appended spelling");
                let mut intact = v;
                intact["kid"] = canonical_pub["kid"].clone();
                let matches = intact == canonical_pub;
                assert!(matches, "{id}: nonmutated baseline intact");
            }
            "neg-b64-trailing-bits" => {
                let v = parsed();
                let x = v["x"].as_str().expect("x string");
                assert_eq!(x.len(), 43, "{id}: canonical length");
                assert_eq!(
                    &x[..42],
                    &alice.public_key[..42],
                    "{id}: differs from canonical alice x only in the last char"
                );
                assert!(
                    alice.public_key.ends_with('E') && x.ends_with('F'),
                    "{id}: exact unused-bit mutation E to F"
                );
                let mut intact = v;
                intact["x"] = canonical_pub["x"].clone();
                let matches = intact == canonical_pub;
                assert!(matches, "{id}: nonmutated baseline intact");
            }
            "neg-escaped-member-name" => {
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("\\u0063rv"),
                    "{id}: escaped member spelling present"
                );
                let v = parsed();
                let keys: Vec<&String> = v.as_object().expect("object").keys().collect();
                assert_eq!(keys.len(), 6, "{id}: same member count");
                let matches = v == canonical_pub;
                assert!(matches, "{id}: parsed document is the canonical baseline");
            }
            // --- identity relationships ----------------------------------
            "neg-seed-pub-mismatch" => {
                let v = parsed();
                let d_is_alice_seed = v["d"] == serde_json::json!(alice_seed_b64u);
                assert!(
                    d_is_alice_seed,
                    "{id}: d is the alice seed (bytes withheld)"
                );
                assert_eq!(
                    v["x"],
                    serde_json::json!(bob.public_key),
                    "{id}: x is bob pub"
                );
                assert_eq!(
                    v["kid"],
                    serde_json::json!(bob.kid),
                    "{id}: kid matches bob x"
                );
                let bob_priv: serde_json::Value = serde_json::from_slice(&envelope_of(find_case(
                    &table,
                    "positives",
                    "priv-bob",
                )))
                .expect("canonical priv-bob parses");
                let mut intact = v;
                intact["d"] = bob_priv["d"].clone();
                let matches = intact == bob_priv;
                assert!(matches, "{id}: rest of document is bob's baseline");
            }
            "neg-kid-mismatch" => {
                let v = parsed();
                assert_eq!(
                    v["x"],
                    serde_json::json!(alice.public_key),
                    "{id}: x intact"
                );
                assert_eq!(v["kid"], serde_json::json!(bob.kid), "{id}: kid is bob kid");
                let mut intact = v;
                intact["kid"] = canonical_priv["kid"].clone();
                let matches = intact == canonical_priv;
                assert!(matches, "{id}: rest of document intact");
            }
            // --- duplicate members ---------------------------------------
            "neg-dup-member" => {
                assert_eq!(
                    occurrences(&bytes, "\"kid\":"),
                    2,
                    "{id}: kid appears twice"
                );
                let v = parsed();
                assert_eq!(v["kid"], serde_json::json!(alice.kid), "{id}: same value");
                let matches = v == canonical_priv;
                assert!(matches, "{id}: parsed last-wins is the alice baseline");
                for member in [
                    "\"crv\":",
                    "\"d\":",
                    "\"kty\":",
                    "\"type\":",
                    "\"v\":",
                    "\"x\":",
                ] {
                    assert_eq!(
                        occurrences(&bytes, member),
                        1,
                        "{id}: {member} appears once"
                    );
                }
            }
            "neg-dup-member-last-mismatched" => {
                assert_eq!(
                    occurrences(&bytes, "\"kid\":"),
                    2,
                    "{id}: kid appears twice"
                );
                let text = std::str::from_utf8(&bytes).expect("UTF-8");
                let last = text.rsplit_once("\"kid\":").expect("kid occurrences").1;
                let last_value: String = last
                    .trim_start_matches('"')
                    .chars()
                    .take_while(|&c| c != '"')
                    .collect();
                assert_eq!(last_value, bob.kid, "{id}: LAST kid is bob kid");
                let first = text.split("\"kid\":").nth(1).expect("first kid");
                let first_value: String = first
                    .trim_start_matches('"')
                    .chars()
                    .take_while(|&c| c != '"')
                    .collect();
                assert_eq!(first_value, alice.kid, "{id}: first kid intact");
                let v = parsed();
                let mut intact = v;
                intact["kid"] = canonical_priv["kid"].clone();
                let matches = intact == canonical_priv;
                assert!(matches, "{id}: rest of document intact");
            }
            "neg-dup-member-escaped" => {
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("\\u006b\\u0069\\u0064"),
                    "{id}: escaped kid spelling present"
                );
                assert_eq!(
                    occurrences(&bytes, "\"kid\":"),
                    1,
                    "{id}: plain kid appears once"
                );
                let v = parsed();
                let matches = v == canonical_priv;
                assert!(matches, "{id}: parsed document is the canonical baseline");
            }
            // --- byte-level structure ------------------------------------
            "neg-noncanonical-ws" => {
                assert_eq!(
                    bytes.len(),
                    priv_alice.len() + 1,
                    "{id}: adds exactly one byte"
                );
                assert_eq!(&bytes[..2], b"{ ", "{id}: leading space present");
                let rest_intact = bytes[2..] == priv_alice[1..];
                assert!(rest_intact, "{id}: remaining bytes intact");
                let v = parsed();
                let matches = v == canonical_priv;
                assert!(matches, "{id}: parsed document is the canonical baseline");
            }
            "neg-key-reorder" => {
                let reordered = parsed();
                let same = reordered == canonical_priv;
                assert!(same, "{id}: reorder is semantically the document");
                let bytes_differ = bytes != priv_alice;
                assert!(bytes_differ, "{id}: reorder bytes differ");
                assert!(
                    bytes.starts_with(b"{\"type\""),
                    "{id}: non-canonical member first"
                );
            }
            "neg-truncated" => {
                assert!(bytes.len() < priv_alice.len(), "{id}: strictly shorter");
                assert!(
                    priv_alice.starts_with(&bytes),
                    "{id}: canonical prefix intact"
                );
            }
            "neg-size-boundary-4096" | "neg-size-boundary-4097" => {
                let total = if id == "neg-size-boundary-4096" {
                    4096
                } else {
                    4097
                };
                assert_eq!(bytes.len(), total, "{id}: exact boundary length");
                assert!(
                    bytes.starts_with(&priv_alice),
                    "{id}: canonical prefix intact"
                );
                assert!(
                    bytes[priv_alice.len()..].iter().all(|&b| b == 0x20),
                    "{id}: padding is spaces"
                );
            }
            "neg-invalid-utf8" => {
                assert_eq!(bytes.len(), priv_alice.len(), "{id}: same length");
                let prefix_intact = bytes[..bytes.len() - 1] == priv_alice[..priv_alice.len() - 1];
                assert!(prefix_intact, "{id}: prefix intact");
                assert_eq!(bytes[bytes.len() - 1], 0xFF, "{id}: final byte replaced");
                assert_eq!(
                    priv_alice[priv_alice.len() - 1],
                    0x7D,
                    "{id}: was closing brace"
                );
            }
            "neg-oversized-envelope" => {
                assert!(bytes.len() > 4096, "{id}: oversized");
                assert!(
                    bytes.starts_with(&priv_alice),
                    "{id}: canonical prefix intact"
                );
                assert!(
                    bytes[priv_alice.len()..].iter().all(|&b| b == 0x20),
                    "{id}: trailing spaces only"
                );
            }
            "neg-root-array" => assert_eq!(bytes, b"[]", "{id}: root is an array"),
            "neg-root-string" => assert!(
                std::str::from_utf8(&bytes)
                    .expect("UTF-8")
                    .contains("user-key/private"),
                "{id}: root is a document string"
            ),
            "neg-empty-input" => assert!(bytes.is_empty(), "{id}: zero bytes"),
            "neg-null-input" => assert_eq!(bytes, b"null", "{id}: root is null"),
            "neg-v-float" => {
                let v = parsed();
                assert!(
                    v["v"].is_f64() && !v["v"].is_u64(),
                    "{id}: v is the float spelling"
                );
                assert_eq!(v["v"].as_f64(), Some(1.0), "{id}: float value 1.0");
                let mut intact = v;
                intact["v"] = canonical_priv["v"].clone();
                let matches = intact == canonical_priv;
                assert!(matches, "{id}: other members intact");
            }
            // --- invalid public keys -------------------------------------
            "neg-invalid-pub-noncanonical-y"
            | "neg-invalid-pub-identity"
            | "neg-invalid-pub-small-order"
            | "neg-invalid-pub-off-curve" => {
                let name = case["compose"]["x_from_key_vector"]
                    .as_str()
                    .expect("vector name");
                let x_bytes = key_vector_hex(name);
                let x: [u8; 32] = x_bytes.clone().try_into().expect("32-byte vector");
                let v = parsed();
                assert_eq!(
                    v["x"],
                    serde_json::json!(encode_b64url(&x)),
                    "{id}: x comes from the key vector"
                );
                assert_eq!(
                    v["kid"],
                    serde_json::json!(key_id(&x)),
                    "{id}: kid matches that x"
                );
                assert_eq!(v["crv"], canonical_pub["crv"], "{id}: crv intact");
                assert_eq!(v["kty"], canonical_pub["kty"], "{id}: kty intact");
                assert_eq!(v["type"], canonical_pub["type"], "{id}: type intact");
                assert_eq!(v["v"], canonical_pub["v"], "{id}: v intact");
            }
            // --- credential negatives ------------------------------------
            "neg-cred-unknown-version" => {
                let mut v = parsed();
                assert_eq!(v["v"], 2, "{id}: mutated v present");
                v["v"] = serde_json::json!(1);
                let matches = v == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-unknown-type" => {
                let mut v = parsed();
                assert_eq!(
                    v["type"], "user-key/credential/server",
                    "{id}: mutated type present (deliberately NOT client)"
                );
                v["type"] = serde_json::json!("user-key/credential/client");
                let matches = v == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-missing-server-kid" => {
                let mut v = parsed();
                assert!(v.get("server_kid").is_none(), "{id}: server_kid absent");
                v["server_kid"] = serde_json::json!(svc.server_kid);
                let matches = v == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-extra-server-private-key" => {
                let mut v = parsed();
                assert!(
                    v.get("server_private_key").is_some(),
                    "{id}: smuggled member present"
                );
                v.as_object_mut()
                    .expect("object")
                    .remove("server_private_key");
                let matches = v == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-server-kid-mismatch" => {
                let v = parsed();
                assert_eq!(
                    v["server_kid"],
                    serde_json::json!(alice.kid),
                    "{id}: kid is alice kid"
                );
                assert_eq!(
                    v["server_public_key"],
                    serde_json::json!(svc.server_public_key),
                    "{id}: server public key intact"
                );
                let mut intact = v;
                intact["server_kid"] = canonical_cred["server_kid"].clone();
                let matches = intact == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-bad-url" => {
                let v = parsed();
                let url = v["url"].as_str().expect("url string");
                assert!(url.starts_with("http://"), "{id}: http spelling present");
                let mut intact = v;
                intact["url"] = canonical_cred["url"].clone();
                let matches = intact == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-empty-aud" => {
                let v = parsed();
                assert_eq!(v["aud"], "", "{id}: aud is empty");
                let mut intact = v;
                intact["aud"] = canonical_cred["aud"].clone();
                let matches = intact == canonical_cred;
                assert!(matches, "{id}: other members intact");
            }
            "neg-cred-aud-lone-surrogate-escape" => {
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("\\ud800"),
                    "{id}: lone high surrogate spelling present"
                );
                let restored =
                    replace_aud_raw(&bytes, canonical_cred["aud"].as_str().expect("aud"));
                let matches = restored == cred_alice;
                assert!(matches, "{id}: raw mutation is aud-only");
            }
            "neg-cred-aud-lone-low-surrogate-escape" => {
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("\\udc00"),
                    "{id}: lone low surrogate spelling present"
                );
                let restored =
                    replace_aud_raw(&bytes, canonical_cred["aud"].as_str().expect("aud"));
                let matches = restored == cred_alice;
                assert!(matches, "{id}: raw mutation is aud-only");
            }
            "neg-cred-aud-escaped-surrogate-pair" => {
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("\\ud83d\\ude00"),
                    "{id}: escaped surrogate-pair spelling present"
                );
                let restored =
                    replace_aud_raw(&bytes, canonical_cred["aud"].as_str().expect("aud"));
                let matches = restored == cred_alice;
                assert!(matches, "{id}: raw mutation is aud-only");
            }
            "neg-cred-dup-inner-member" => {
                let (dup, _) =
                    materialize_negative(&table, find_case(&table, "negatives", "neg-dup-member"));
                let v = parsed();
                let inner = v["client_key"].as_str().expect("client_key string");
                let same = inner.as_bytes() == dup.as_slice();
                assert!(same, "{id}: inner == neg-dup-member bytes");
                let mut intact = v;
                intact["client_key"] = canonical_cred["client_key"].clone();
                let matches = intact == canonical_cred;
                assert!(matches, "{id}: outer baseline intact");
            }
            "neg-cred-invalid-server-pub" => {
                let name = case["compose"]["server_public_key_from_key_vector"]
                    .as_str()
                    .expect("vector name");
                let x_bytes = key_vector_hex(name);
                let x: [u8; 32] = x_bytes.try_into().expect("32-byte vector");
                let v = parsed();
                assert_eq!(
                    v["server_public_key"],
                    serde_json::json!(encode_b64url(&x)),
                    "{id}: server pub comes from the key vector"
                );
                assert_eq!(
                    v["server_kid"],
                    serde_json::json!(key_id(&x)),
                    "{id}: server kid matches that pub"
                );
                assert_eq!(v["aud"], canonical_cred["aud"], "{id}: aud intact");
                assert_eq!(v["url"], canonical_cred["url"], "{id}: url intact");
                assert_eq!(v["type"], canonical_cred["type"], "{id}: type intact");
                assert_eq!(v["v"], canonical_cred["v"], "{id}: v intact");
                let inner_intact = v["client_key"].as_str().expect("client_key").as_bytes()
                    == priv_alice.as_slice();
                assert!(inner_intact, "{id}: client_key intact (bytes withheld)");
            }
            "neg-escaped-url-slash" => {
                assert!(
                    bytes.windows(2).any(|w| w == b"\\/"),
                    "{id}: escaped solidus spelling present"
                );
                assert!(
                    std::str::from_utf8(&bytes)
                        .expect("UTF-8")
                        .contains("user-key/credential/client"),
                    "{id}: credential document"
                );
                let v = parsed();
                let matches = v == canonical_cred;
                assert!(matches, "{id}: parsed document is the canonical baseline");
            }
            "neg-cred-client-key-noncanonical" => {
                let v = parsed();
                let inner = v["client_key"].as_str().expect("client_key string");
                assert!(
                    inner.starts_with("{ "),
                    "{id}: non-canonical inner whitespace"
                );
                assert!(
                    inner.replacen("{ ", "{", 1).as_bytes() == priv_alice.as_slice(),
                    "{id}: whitespace is the only inner private-envelope mutation"
                );
                for member in ["aud", "server_kid", "server_public_key", "type", "url", "v"] {
                    assert_eq!(
                        v[member], canonical_cred[member],
                        "{id}: outer {member} intact"
                    );
                }
            }
            "neg-cred-client-key-public" => {
                let v = parsed();
                let inner: serde_json::Value =
                    serde_json::from_str(v["client_key"].as_str().expect("client_key"))
                        .expect("inner parses");
                assert_eq!(
                    inner["type"], "user-key/public",
                    "{id}: inner is a PUBLIC envelope"
                );
                assert!(inner.get("d").is_none(), "{id}: no d member inside");
                assert!(
                    v["client_key"].as_str().expect("client_key").as_bytes()
                        == envelope_of(find_case(&table, "positives", "pub-alice")).as_slice(),
                    "{id}: inner public envelope exactly matches the pinned fixture"
                );
                for member in ["aud", "server_kid", "server_public_key", "type", "url", "v"] {
                    assert_eq!(
                        v[member], canonical_cred[member],
                        "{id}: outer {member} intact"
                    );
                }
            }
            other => panic!("negative case without a prerequisite check: {other}"),
        }
    }
    assert_eq!(covered, 51, "all 51 negatives carry prerequisites");
}

// ---------------------------------------------------------------------------
// Row 14 extension: deterministic issuance for EVERY aud-control fixture.
// ---------------------------------------------------------------------------

#[test]
fn row14_deterministic_issuance_reproduces_committed_fixture_bytes() {
    let table = transfer_table();
    let svc = oracle_key("svc");
    let url = "https://svc.example.test";
    // The pinned oracle: the client seed comes from the COMMITTED fixture
    // priv-alice / priv-bob envelopes (their exact `d` strings), decoded —
    // not from FIXED_RANDOM self-derived templates.
    let committed_seed = |positive: &str| -> Vec<u8> {
        let envelope = envelope_of(find_case(&table, "positives", positive));
        let parsed: serde_json::Value = serde_json::from_slice(&envelope).expect("canonical JSON");
        decode_b64url(parsed["d"].as_str().expect("d string")).expect("seed decodes")
    };
    // Covers exactly these seven positives: cred-alice, cred-bob and all
    // five cred-aud-* recipes. NOT the envelope positives (priv/pub-*) or
    // the RFC case.
    let cases: [(&str, &str, &str); 7] = [
        ("cred-alice", "priv-alice", url),
        ("cred-bob", "priv-bob", url),
        (
            "cred-aud-html-sensitive",
            "priv-alice",
            recipe_aud("cred-aud-html-sensitive"),
        ),
        (
            "cred-aud-codepoints",
            "priv-alice",
            recipe_aud("cred-aud-codepoints"),
        ),
        (
            "cred-aud-control",
            "priv-alice",
            recipe_aud("cred-aud-control"),
        ),
        (
            "cred-aud-separators",
            "priv-alice",
            recipe_aud("cred-aud-separators"),
        ),
        (
            "cred-aud-replacement-char",
            "priv-alice",
            recipe_aud("cred-aud-replacement-char"),
        ),
    ];
    for (id, seed_source, aud) in cases {
        let seed = committed_seed(seed_source);
        // Fixture-vs-recipe cross-check (read from the fixture, never fed
        // into issuance).
        let case = find_case(&table, "positives", id);
        let committed_bytes = materialize_positive(&table, case);
        let parsed: serde_json::Value =
            serde_json::from_slice(&committed_bytes).expect("canonical JSON");
        assert_eq!(
            parsed["aud"].as_str().expect("aud"),
            aud,
            "{id}: pinned aud"
        );
        // Issue with an injected random source returning EXACTLY the
        // decoded committed client seed.
        let connection = ConnectionData::new(
            url.to_owned(),
            aud.to_owned(),
            svc.public_key.clone(),
            svc.kid.clone(),
        )
        .expect("valid connection config");
        let mut random = move |_length: usize| Ok(seed.clone());
        let issued = issue_user_key(&connection, &mut random).expect("issuance");
        // The issued bytes equal the COMMITTED fixture envelope bytes
        // (secret-safe boolean comparison).
        let reproduces = issued.credential_bytes() == committed_bytes;
        assert!(
            reproduces,
            "{id}: issuance with the committed seed reproduces the committed bytes"
        );
        // The same bytes import with the independently pinned tuple.
        import_credential(&issued.credential_bytes(), &pinned_expected_tuple(id))
            .unwrap_or_else(|e| panic!("{id} must import: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Row 15: consumer bridge — the imported signer drives the existing Client
// through the fake transport (real signer interoperability end to end).
// ---------------------------------------------------------------------------

#[test]
fn row15_imported_signer_drives_existing_client_round_trip() {
    use std::sync::Arc;

    use common::harness::{
        fixed_clock, queued_nonce, rpc_result_body, TestServer, FIXTURE_AUD, FIXTURE_NOW, TEST_URL,
    };
    use mcp_jack::client::rpc::Client;
    use mcp_jack::client::transport::Transport;

    let table = transfer_table();
    let srv = TestServer::new();
    // The pinned expected tuple is the fake server's OWN key — supplied
    // independently of the credential (never parsed from it).
    let expected = ExpectedIdentity {
        url: TEST_URL.to_owned(),
        aud: FIXTURE_AUD.to_owned(),
        server_public_key: encode_b64url(&srv.pub_key),
        server_kid: srv.kid.clone(),
    };
    // Compose a credential for the pinned keys.json alice seed: the client
    // signer becomes alice, whose kid registers in the fake server's
    // client_keys (all keys.json kids are accepted).
    let priv_alice = envelope_of(find_case(&table, "positives", "priv-alice"));
    let document = compose_credential(
        FIXTURE_AUD,
        std::str::from_utf8(&priv_alice).expect("envelope is UTF-8"),
        &expected.server_public_key,
        &expected.server_kid,
        TEST_URL,
    )
    .into_bytes();
    let imported = import_credential(&document, &expected)
        .expect("credential imports with the independently pinned tuple");
    let signer_kid = imported.signer.kid().to_owned();
    assert_eq!(signer_kid, oracle_key("alice").kid, "signer is alice");
    assert!(
        srv.client_keys.contains_key(&signer_kid),
        "kid registers at the fake server"
    );

    // Bridge through the existing client: the connection data becomes the
    // Config, the imported signer is the signer, the fake transport rides
    // along; deterministic clock and queued nonce as in client_tools.rs.
    let transport: Arc<dyn Transport> = Arc::clone(&srv) as Arc<dyn Transport>;
    let mut config = imported
        .connection
        .client_config(Arc::new(imported.signer), transport);
    config.now = Some(fixed_clock(FIXTURE_NOW));
    let nonce = "AAAAAAAAAAAAAAAAAAAAAA";
    config.nonce = Some(queued_nonce(&[nonce, nonce]));
    config.window_seconds = 30;
    let client = Client::new(config).expect("valid client");

    let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&captured);
    srv.set_handler(Box::new(move |srv, _method, _target, auth, _body| {
        *slot.lock().expect("mutex") = Some(auth.kid.clone());
        srv.write_signed_json(
            auth,
            200,
            &rpc_result_body(&serde_json::json!({"tools": []})),
        )
    }));
    let result = client
        .call_tool_raw("tools/list", None)
        .expect("signed round trip succeeds through the imported signer");
    assert_eq!(result, serde_json::json!({"tools": []}));
    let seen_kid = captured
        .lock()
        .expect("mutex")
        .clone()
        .expect("request captured");
    assert_eq!(
        seen_kid, signer_kid,
        "captured request kid == imported signer kid"
    );
}
