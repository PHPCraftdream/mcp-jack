use super::*;

#[test]
fn scheme_checked_before_parameters() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));

    let mut req = get(&key, &entry.kid, NOW, &nonce(1));
    req.auth_values = vec!["v2 kid=xx".to_owned()];
    let res = v.verify(&req);
    // Path ends at step 3: the scheme is examined before any parameter
    // grammar, so the malformed kid/nonce are never checked.
    assert_eq!(res.http_status, 401);
    assert_eq!(res.code, codes::UNSUPPORTED_VERSION);
    assert!(!res.nonce_recorded);

    // Step 3: unsupported_version.
    req.auth_values = vec!["v2".to_owned()];
    assert_eq!(v.verify(&req).code, codes::UNSUPPORTED_VERSION);

    // "V1" is not a v+digits scheme: malformed_auth, not
    // unsupported_version. Path ends at step 2.
    req.auth_values = vec![format!(
        "V1 kid={},ts={NOW},nonce={},sig={}",
        entry.kid,
        nonce(1),
        "A".repeat(86)
    )];
    assert_eq!(v.verify(&req).code, codes::MALFORMED_AUTH);
}

#[test]
fn unknown_key_vs_enrollment_exception() {
    let (alice_key, alice) = test_key("alice");
    let (mallory_key, mallory) = test_key("mallory");
    let state = seeded_state(&[&alice]);
    add_invite(&state, NOW + 60);
    let v = verifier(config(NOW, Arc::clone(&state), None));

    // (a) Unregistered kid, plain call: ends at step 4 unknown_key.
    let req = post_call("svc.status", None, &mallory_key, &mallory.kid, &nonce(1));
    let res = v.verify(&req);
    assert_eq!(res.http_status, 401);
    assert_eq!(res.code, codes::UNKNOWN_KEY);
    assert!(!res.nonce_recorded);

    // (b) Enrollment whose submitted key does not hash to kid: ends at
    // step 4 unknown_key (enrollment shape matches, the submitted key is
    // valid, but key_id(submitted) != kid).
    let body = call_body(TOOL_ENROLL, Some(&enroll_args(&alice.public_key)));
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &mallory_key,
        &mallory.kid,
        NOW,
        &nonce(2),
    );
    assert_eq!(v.verify(&req).code, codes::UNKNOWN_KEY);

    // (c) Small-order key: 400 key_rejected even though its hash != kid.
    // Ends at spec 03 section 3.2 step 3: validity precedes the hash
    // comparison.
    let bad_pub = encode_b64url(&[1u8; 32]);
    let body = call_body(TOOL_ENROLL, Some(&enroll_args(&bad_pub)));
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &mallory_key,
        &mallory.kid,
        NOW,
        &nonce(3),
    );
    let res = v.verify(&req);
    assert_eq!(res.http_status, 400);
    assert_eq!(res.code, codes::KEY_REJECTED);

    // (d) Valid enrollment, no handler: steps 4 (exception ok), 5
    // skipped, 6, 7, 8 pass; ends at step 9 native dispatch: 403
    // operation_denied, nonce consumed, no audit event.
    let (carol_key, carol) = test_key("carol");
    let state = seeded_state(&[&alice]);
    add_invite(&state, NOW + 60);
    let v = verifier(config(NOW, state, None));
    let body = call_body(TOOL_ENROLL, Some(&enroll_args(&carol.public_key)));
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &carol_key,
        &carol.kid,
        NOW,
        &nonce(4),
    );
    let res = v.verify(&req);
    assert_eq!(res.http_status, 403);
    assert_eq!(res.code, codes::OPERATION_DENIED);
    assert!(res.native);
    assert!(res.nonce_recorded);
    assert!(res.audit.is_none());

    // (e) Same with a handler: accepted, audit success.
    let state = seeded_state(&[&alice]);
    add_invite(&state, NOW + 60);
    let v = verifier(config(NOW, state, Some(stub())));
    let body = call_body(TOOL_ENROLL, Some(&enroll_args(&carol.public_key)));
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &carol_key,
        &carol.kid,
        NOW,
        &nonce(5),
    );
    let res = v.verify(&req);
    assert!(res.accepted);
    assert_eq!(res.structured, Some(serde_json::Value::Null));
    assert!(res.nonce_recorded);
    let event = res.audit.expect("enroll is audited");
    assert_eq!(event.tool, TOOL_ENROLL);
    assert_eq!(event.outcome, AUDIT_SUCCESS);
    assert_eq!(event.actor_kid, carol.kid);
    assert_eq!(event.actor_name, "");
    assert_eq!(event.target, carol.kid);

    // (f) Registered kid enrolling again: step 4 takes the normal
    // (registered) path through steps 6-8; ends at step 9 with the
    // handler rejection 409, audit failure.
    let v = verifier(config(NOW, seeded_state(&[&alice]), Some(stub())));
    let req = post_call(
        TOOL_ENROLL,
        Some(&format!(r#"{{"public_key":"{}"}}"#, alice.public_key)),
        &alice_key,
        &alice.kid,
        &nonce(6),
    );
    let res = v.verify(&req);
    assert_eq!(res.http_status, 409);
    assert_eq!(res.code, codes::KEY_EXISTS);
    let event = res.audit.expect("enroll is audited");
    assert_eq!(event.outcome, AUDIT_FAILURE);
    assert_eq!(event.code, codes::KEY_EXISTS);

    // (g) Unknown kid, an out-of-range number in a member the exception
    // never reads: the raw-member decode must not fail on it, so the
    // request passes step 4 (Go/TS continue to the invite check) and
    // ends at step 9 like (d); without the raw decode this is 401
    // unknown_key.
    let body = call_body(
        TOOL_ENROLL,
        Some(&format!(
            r#"{{"code":"{}","public_key":"{}","x":1e999}}"#,
            invite_code(),
            carol.public_key
        )),
    );
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &carol_key,
        &carol.kid,
        NOW,
        &nonce(7),
    );
    let state = seeded_state(&[&alice]);
    add_invite(&state, NOW + 60);
    let v = verifier(config(NOW, state, None));
    let res = v.verify(&req);
    assert_eq!(res.http_status, 403);
    assert_eq!(res.code, codes::OPERATION_DENIED);
    assert!(res.nonce_recorded);
    assert!(res.audit.is_none());
}

#[test]
fn enrollment_exception_requires_live_invite() {
    let (_, carol) = test_key("carol");
    let bad_code = format!("{}=", invite_code());
    let cases: [(&str, Option<i64>, String); 5] = [
        ("no invite in state", None, enroll_args(&carol.public_key)),
        ("expired at now", Some(NOW), enroll_args(&carol.public_key)),
        (
            "non-canonical code",
            Some(NOW + 60),
            format!(
                r#"{{"code":"{bad_code}","public_key":"{}"}}"#,
                carol.public_key
            ),
        ),
        (
            "code is not a string",
            Some(NOW + 60),
            format!(r#"{{"code":7,"public_key":"{}"}}"#, carol.public_key),
        ),
        (
            "code absent",
            Some(NOW + 60),
            format!(r#"{{"public_key":"{}"}}"#, carol.public_key),
        ),
    ];
    for (label, expires_at, args) in cases {
        let state = seeded_state(&[]);
        if let Some(expires_at) = expires_at {
            add_invite(&state, expires_at);
        }
        let nonces_store = Arc::new(NonceStore::new());
        let cfg = config_with_nonces(NOW, state, Some(stub()), nonces_store.clone());
        let (req, _) = enroll_request(&args, 1);
        let res = verifier(cfg).verify(&req);
        assert_eq!(res.http_status, 401, "{label}");
        assert_eq!(res.code, codes::UNKNOWN_KEY, "{label}");
        assert!(!res.nonce_recorded, "{label}");
        assert!(res.audit.is_none(), "{label}");
        // The nonce is still unused: the rejection never touched the store.
        let (kid, n) = (test_key("carol").1.kid, nonce(1));
        assert!(
            !nonces_store.check_and_record(&kid, &n, NOW, NOW + 60),
            "{label}"
        );
    }
}

#[test]
fn enrollment_exception_accepts_live_invite() {
    let state = seeded_state(&[]);
    add_invite(&state, NOW + 1);
    let v = verifier(config(NOW, state, Some(stub())));
    let (_, carol) = test_key("carol");
    let (req, _) = enroll_request(&enroll_args(&carol.public_key), 1);
    let res = v.verify(&req);
    assert!(res.accepted, "code: {}", res.code);
    assert!(res.nonce_recorded);
}

#[test]
fn enrollment_with_duplicate_members_is_unknown_key() {
    let state = seeded_state(&[]);
    add_invite(&state, NOW + 60);
    let v = verifier(config(NOW, state, Some(stub())));
    let (_, carol) = test_key("carol");
    let args = format!(
        r#"{{"code":"{}","public_key":"{}","public_key":"{}"}}"#,
        invite_code(),
        carol.public_key,
        carol.public_key
    );
    let (req, _) = enroll_request(&args, 1);
    let res = v.verify(&req);
    assert_eq!(res.http_status, 401);
    assert_eq!(res.code, codes::UNKNOWN_KEY);
    assert!(!res.nonce_recorded);
}
