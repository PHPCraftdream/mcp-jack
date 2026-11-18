use super::*;

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
