use super::*;

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

    use crate::common::harness::{
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
