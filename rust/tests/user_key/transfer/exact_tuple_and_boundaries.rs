use super::*;

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
