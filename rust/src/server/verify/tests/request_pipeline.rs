use super::*;

#[test]
fn replay_only_after_signature() {
    let (key, entry) = test_key("alice");
    let state = seeded_state(&[&entry]);
    let nonces = Arc::new(NonceStore::new());
    let cfg = config_with_nonces(NOW, state, None, nonces.clone());
    nonces.check_and_record(&entry.kid, &nonce(1), 0, NOW + 10);

    // (a) Valid signature but replayed nonce. The reuse here IS the
    // subject — a replay. Steps 1-7 pass; ends at step 8.
    let v = verifier(cfg);
    let req = post_call("svc.status", None, &key, &entry.kid, &nonce(1));
    let res = v.verify(&req);
    assert_eq!(res.code, codes::REPLAYED_NONCE);
    assert!(!res.nonce_recorded);
    assert_eq!(nonces.len(), 1);
    drop(v);

    // (b) Bad signature with a replayed nonce: bad_signature wins, and
    // nothing was inserted. Step 6 passes (|NOW-NOW| = 0); ends at step 7.
    let state = seeded_state(&[&entry]);
    let nonces = Arc::new(NonceStore::new());
    let cfg = config_with_nonces(NOW, state, None, nonces.clone());
    nonces.check_and_record(&entry.kid, &nonce(2), 0, NOW + 10);
    let v = verifier(cfg);
    let mut req = get(&key, &entry.kid, NOW, &nonce(2));
    req.auth_values[0] = format!(
        "v1 kid={},ts={NOW},nonce={},sig={}",
        entry.kid,
        nonce(2),
        "A".repeat(86)
    );
    req.method = "POST".to_owned();
    req.body = PING.as_bytes().to_vec();
    let res = v.verify(&req);
    assert_eq!(res.code, codes::BAD_SIGNATURE);
    assert_eq!(nonces.len(), 1);
    drop(v);

    // (c) A failed attempt does not consume the nonce for the later
    // valid request reusing it. Fresh store, no preseed.
    let state = seeded_state(&[&entry]);
    let cfg = config(NOW, state, None);
    let v = verifier(cfg);
    let mut bad = get(&key, &entry.kid, NOW, &nonce(3));
    bad.method = "POST".to_owned();
    bad.body = PING.as_bytes().to_vec();
    bad.auth_values[0] = format!(
        "v1 kid={},ts={NOW},nonce={},sig={}",
        entry.kid,
        nonce(3),
        "A".repeat(86)
    );
    assert_eq!(v.verify(&bad).code, codes::BAD_SIGNATURE);
    // Deliberate reuse: proving the failed attempt did not record.
    let good = post_call("svc.status", None, &key, &entry.kid, &nonce(3));
    let res = v.verify(&good);
    assert!(res.accepted);
    assert!(res.nonce_recorded);
}

#[test]
fn invalid_utf8_checked_before_json() {
    let (key, entry) = test_key("alice");
    let body: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"p\xffng\"}";
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));

    // Steps 1-8 pass; ends at step 9 classify failure.
    let req = signed("POST", "/mcp", body, &key, &entry.kid, NOW, &nonce(4));
    let res = v.verify(&req);
    assert_eq!(res.http_status, 400);
    assert_eq!(res.code, codes::INVALID_REQUEST);
    assert!(res.nonce_recorded);

    // Step 4 precedes step 9: an unknown kid still gets unknown_key.
    let (mallory_key, mallory) = test_key("mallory");
    let req = signed(
        "POST",
        "/mcp",
        body,
        &mallory_key,
        &mallory.kid,
        NOW,
        &nonce(5),
    );
    assert_eq!(v.verify(&req).code, codes::UNKNOWN_KEY);
}

#[test]
fn empty_post_rejected() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));
    // Steps 1-8 pass; ends at step 9: 400 invalid_request.
    let req = signed("POST", "/mcp", b"", &key, &entry.kid, NOW, &nonce(6));
    let res = v.verify(&req);
    assert_eq!(res.http_status, 400);
    assert_eq!(res.code, codes::INVALID_REQUEST);
    assert!(res.nonce_recorded);
    assert!(!res.accepted);
    assert_eq!(res.rpc_id, None);
}

#[test]
fn window_checked_before_signature() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));

    // Ends at step 6 timestamp_out_of_window.
    let req = signed(
        "POST",
        "/mcp",
        PING.as_bytes(),
        &key,
        &entry.kid,
        NOW - 31,
        &nonce(7),
    );
    assert_eq!(v.verify(&req).code, codes::TIMESTAMP_OUT_OF_WINDOW);

    // Step 6 passes (|30| is not > 30); ends at step 7 bad_signature.
    let mut req = signed(
        "POST",
        "/mcp",
        PING.as_bytes(),
        &key,
        &entry.kid,
        NOW - 30,
        &nonce(8),
    );
    req.auth_values[0] = format!(
        "v1 kid={},ts={},nonce={},sig={}",
        entry.kid,
        NOW - 30,
        nonce(8),
        "A".repeat(86)
    );
    assert_eq!(v.verify(&req).code, codes::BAD_SIGNATURE);
}

#[test]
fn default_window_when_unset() {
    let (key, entry) = test_key("alice");
    let mut cfg = config(NOW, seeded_state(&[&entry]), None);
    cfg.window_seconds = 0;
    let v = verifier(cfg);

    // Steps 1-8 + GET accept.
    assert!(
        v.verify(&get(&key, &entry.kid, NOW - 30, &nonce(9)))
            .accepted
    );
    // Ends at step 6.
    assert_eq!(
        v.verify(&get(&key, &entry.kid, NOW - 31, &nonce(10))).code,
        codes::TIMESTAMP_OUT_OF_WINDOW
    );
}

#[test]
fn get_and_unknown_key() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));

    // Steps 1-8 + GET accept.
    let res = v.verify(&get(&key, &entry.kid, NOW, &nonce(11)));
    assert!(res.accepted);
    assert_eq!(res.kid, entry.kid);
    assert!(res.nonce_recorded);
    assert_eq!(res.tool, "");
    assert!(!res.native);
    assert_eq!(res.rpc_id, None);

    // Ends at step 4.
    let (mallory_key, mallory) = test_key("mallory");
    assert_eq!(
        v.verify(&get(&mallory_key, &mallory.kid, NOW, &nonce(12)))
            .code,
        codes::UNKNOWN_KEY
    );
}

#[test]
fn forwarded_for_any_authenticated_caller() {
    // Spec 02 section 2 pass-through: ordinary MCP traffic is forwarded
    // unchanged for ANY authenticated caller, whatever the method or tool
    // name, with the identity snapshot set (spec 02 section 3).
    let (alice_key, alice) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&alice]), None));

    // A tools/call of a non-native tool: accepted with identity.
    let req = post_call("svc.restart", None, &alice_key, &alice.kid, &nonce(13));
    let res = v.verify(&req);
    assert!(res.accepted, "code: {}", res.code);
    assert!(res.nonce_recorded);
    let identity = res.identity.expect("forwarded accept carries identity");
    assert_eq!(identity.kid(), alice.kid);
    assert_eq!(identity.name(), "alice");
    assert!(!identity.admin());

    // A non-tools/call method is forwarded too.
    let req = signed(
        "POST",
        "/mcp",
        br#"{"jsonrpc":"2.0","id":1,"method":"resources/read"}"#,
        &alice_key,
        &alice.kid,
        NOW,
        &nonce(14),
    );
    let res = v.verify(&req);
    assert!(res.accepted);
    assert!(res.identity.is_some());
}

#[test]
fn rpc_id_and_response_shapes() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));

    let check = |body: &str, n: u64| {
        v.verify(&signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &key,
            &entry.kid,
            NOW,
            &nonce(n),
        ))
    };

    let res = check(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#, 17);
    assert!(res.accepted);
    assert_eq!(res.rpc_id, Some("7".to_owned()));

    // A null result still counts as present.
    let res = check(r#"{"jsonrpc":"2.0","id":7,"result":null}"#, 18);
    assert!(res.accepted);
    assert_eq!(res.rpc_id, Some("7".to_owned()));

    // The raw id text keeps the quotes.
    let res = check(
        r#"{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"x"}}"#,
        19,
    );
    assert!(res.accepted);
    assert_eq!(res.rpc_id, Some("\"a\"".to_owned()));

    let res = check(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        20,
    );
    assert!(res.accepted);
    assert_eq!(res.rpc_id, None);

    // result AND error together is not a valid shape.
    assert_eq!(
        check(
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
            21
        )
        .code,
        codes::INVALID_REQUEST
    );
    // A response needs an id.
    assert_eq!(
        check(r#"{"jsonrpc":"2.0","result":{}}"#, 22).code,
        codes::INVALID_REQUEST
    );
    assert_eq!(
        check(r#"{"jsonrpc":"1.0","method":"ping"}"#, 23).code,
        codes::INVALID_REQUEST
    );
    // A null method is NOT a response shape.
    assert_eq!(
        check(r#"{"jsonrpc":"2.0","method":null,"id":1,"result":{}}"#, 24).code,
        codes::INVALID_REQUEST
    );
}

#[test]
fn native_denied_without_handler() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));
    // Ends at step 9: 403 operation_denied, no audit event.
    let req = post_call(TOOL_WHOAMI, None, &key, &entry.kid, &nonce(25));
    let res = v.verify(&req);
    assert_eq!(res.http_status, 403);
    assert_eq!(res.code, codes::OPERATION_DENIED);
    assert!(res.native);
    assert!(res.audit.is_none());
    assert!(res.nonce_recorded);

    // Unknown jack.* tool: denied even with a handler, no audit event.
    // Ends at step 9 (is_native_tool false).
    let v = verifier(config(NOW, seeded_state(&[&entry]), Some(stub())));
    let req = post_call("jack.nope", None, &key, &entry.kid, &nonce(26));
    let res = v.verify(&req);
    assert_eq!(res.code, codes::OPERATION_DENIED);
    assert!(res.native);
    assert!(res.audit.is_none());
}
