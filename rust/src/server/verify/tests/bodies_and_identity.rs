use super::*;

#[test]
fn classify_body_table() {
    let kind_of = |body: &str| classify_body(body.as_bytes()).map(|m| m.kind);
    let none = |body: &str| assert!(classify_body(body.as_bytes()).is_none(), "body: {body}");

    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
        Some(MessageKind::Request)
    );
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        Some(MessageKind::Request)
    );
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
        Some(MessageKind::Response)
    );
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}"#),
        Some(MessageKind::Response)
    );
    // A null id is still a present id.
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
        Some(MessageKind::Response)
    );

    none("");
    none("null");
    none(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
    none(r#"{"JSONRPC":"2.0","method":"ping"}"#);
    none(r#"{"jsonrpc":"1.0","method":"ping"}"#);
    none(r#"{"jsonrpc":2.0,"method":"ping"}"#);
    none(r#"{"jsonrpc":"2.0","method":null}"#);
    none(r#"{"jsonrpc":"2.0","method":7}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#);
    none(r#"{"jsonrpc":"2.0","result":{}}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}"#);
    assert!(
        classify_body(b"{\"jsonrpc\":\"2.0\",\"method\":\"p\xffng\"}").is_none(),
        "invalid UTF-8 must be rejected before parsing"
    );

    let call = classify_body(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status"}}"#
            .as_bytes(),
    )
    .expect("valid call");
    assert_eq!(call.tool.as_deref(), Some("svc.status"));
    assert!(call.arguments.is_none());

    let call = classify_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"k":"v"}}}"#.as_bytes()).expect("valid call");
    assert_eq!(
        call.arguments.map(|a| a.get().to_owned()),
        Some(r#"{"k":"v"}"#.to_owned())
    );

    let req = classify_body(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#.as_bytes())
        .expect("valid request");
    assert_eq!(req.id, Some("null".to_owned()));

    none(r#"["2.0","ping"]"#);
    none("[]");
    none(r#"[{"jsonrpc":"2.0","method":"ping"}]"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["name"]}"#);
    none("5");
    none(r#""hi""#);

    // Duplicate member names make the body unacceptable, compared after
    // unescaping and at any depth.
    none(r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"resources/read"}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"meth\u006fd":"ping","method":"ping"}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[{"a":1,"a":2}]}}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":{"a":{"b":1,"b":1}}}}"#);
    // Same name in different objects, case differences and a value equal
    // to a name are fine.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"A":2,"b":{"a":"a"},"c":[{"a":1},{"a":2}]}}"#;
    assert!(classify_body(body.as_bytes()).is_some());
}

// spec 02 section 4 step 2: lone surrogate escapes and over-deep nesting
// are rejected before parsing; valid pairs and escaped backslashes are not.
#[test]
fn body_text_rules() {
    let none = |body: &str| assert!(classify_body(body.as_bytes()).is_none(), "body: {body}");
    let kind_of = |body: &str| classify_body(body.as_bytes()).map(|m| m.kind);

    none(r#"{"jsonrpc":"2.0","id":1,"method":"pi\ud800ng"}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"m\ud800":1,"method":"ping"}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stat\udc00us"}}"#);
    none(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\ud83d\ude00\ud800"}}"#);
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\ud83d\ude00"}}"#),
        Some(MessageKind::Request)
    );
    assert_eq!(
        kind_of(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"a\\ud800b"}}"#),
        Some(MessageKind::Request)
    );
    let deep = |levels: usize| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"x":{}{}}}}}"#,
            "[".repeat(levels),
            "]".repeat(levels)
        )
    };
    assert_eq!(kind_of(deep(126).as_str()), Some(MessageKind::Request));
    none(deep(127).as_str());
    // Brackets inside string values never count toward depth.
    let in_string = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"x":"{}{}"}}}}"#,
        "[[".repeat(200),
        "]]".repeat(200)
    );
    assert_eq!(kind_of(in_string.as_str()), Some(MessageKind::Request));
}

// spec 02 section 4: "the body MUST be a single UTF-8 JSON-RPC 2.0 object"
// -> 400 invalid_request for arrays (positional or batch), scalars and null.
#[test]
fn object_bodies_only() {
    let (key, entry) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&entry]), None));
    let bodies = [
        r#"["2.0","ping"]"#,
        "[]",
        r#"[{"jsonrpc":"2.0","method":"ping"}]"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["name"]}"#,
        "5",
        r#""hi""#,
        "null",
    ];
    for (i, body) in bodies.iter().enumerate() {
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &key,
            &entry.kid,
            NOW,
            &nonce((i + 27) as u64),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 400, "body: {body}");
        assert_eq!(res.code, codes::INVALID_REQUEST, "body: {body}");
        assert!(res.nonce_recorded, "body: {body}");
    }
}

#[test]
fn audit_target_set_on_failed_native_calls() {
    let (root_key, root) = admin_key("root");
    let native: Arc<dyn NativeTools> = Arc::new(Native::new(NativeOptions::default()));
    let v = verifier(config(
        NOW,
        seeded_state(&[&root]),
        Some(Arc::clone(&native)),
    ));

    // (a) user.create: valid name, small-order public key -> the failure
    //     is key_rejected and the audit target is already the name (spec
    //     03 section 8). Both failure paths exit before new_invite_code,
    //     so the default (OS) random source is never reached.
    let bad_pub = encode_b64url(&[1u8; 32]);
    let args = format!(r#"{{"name":"dave","public_key":"{bad_pub}"}}"#);
    let req = post_call(
        TOOL_ADMIN_USER_CREATE,
        Some(&args),
        &root_key,
        &root.kid,
        &nonce(50),
    );
    let res = v.verify(&req);
    assert_eq!(res.http_status, 400);
    let event = res.audit.expect("user.create is audited");
    assert_eq!(event.outcome, AUDIT_FAILURE);
    assert_eq!(event.code, codes::KEY_REJECTED);
    assert_eq!(event.target, "dave");

    // (b) user.set_admin: well-formed kid, admin mistyped (number) ->
    //     the failure is invalid_params and the audit target is the kid.
    let (_, alice) = test_key("alice");
    let args = format!(r#"{{"kid":"{}","admin":1}}"#, alice.kid);
    let req = post_call(
        TOOL_ADMIN_USER_SET_ADMIN,
        Some(&args),
        &root_key,
        &root.kid,
        &nonce(51),
    );
    let res = v.verify(&req);
    assert_eq!(res.http_status, 400);
    let event = res.audit.expect("user.set_admin is audited");
    assert_eq!(event.outcome, AUDIT_FAILURE);
    assert_eq!(event.code, codes::INVALID_PARAMS);
    assert_eq!(event.target, alice.kid);

    // (c) A SUCCESSFUL user.create still targets the name.
    let (_, dave) = test_key("dave");
    let args = format!(r#"{{"name":"dave","public_key":"{}"}}"#, dave.public_key);
    let req = post_call(
        TOOL_ADMIN_USER_CREATE,
        Some(&args),
        &root_key,
        &root.kid,
        &nonce(52),
    );
    let res = v.verify(&req);
    assert!(res.accepted, "code: {}", res.code);
    let event = res.audit.expect("user.create is audited");
    assert_eq!(event.outcome, AUDIT_SUCCESS);
    assert_eq!(event.target, "dave");
}

#[test]
fn duplicate_members_rejected_after_authentication() {
    let (alice_key, alice) = test_key("alice");
    let state = seeded_state(&[&alice]);
    let v = verifier(config(NOW, Arc::clone(&state), Some(stub())));

    let bodies = [
        // Nested in params.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","name":"jack.nope"}}"#,
        // Top level, escaped spelling of the same name.
        r#"{"jsonrpc":"2.0","id":1,"meth\u006fd":"ping","method":"ping"}"#,
        // Object inside an array.
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[{"a":1,"a":2}]}}"#,
        // Free-form tool arguments.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"k":1,"k":2}}}"#,
    ];
    for (i, body) in bodies.iter().enumerate() {
        let req = signed(
            "POST",
            "/mcp",
            body.as_bytes(),
            &alice_key,
            &alice.kid,
            NOW,
            &nonce(34 + i as u64),
        );
        let res = v.verify(&req);
        assert_eq!(res.http_status, 400, "body: {body}");
        assert_eq!(res.code, codes::INVALID_REQUEST, "body: {body}");
        assert!(res.nonce_recorded, "body: {body}");
    }
}

#[test]
fn same_member_name_in_different_objects_is_accepted() {
    let (alice_key, alice) = test_key("alice");
    let v = verifier(config(NOW, seeded_state(&[&alice]), Some(stub())));
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"id":1,"x":[{"id":2},{"id":3}],"y":{"id":4}}}}"#;
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &alice_key,
        &alice.kid,
        NOW,
        &nonce(40),
    );
    let res = v.verify(&req);
    assert!(res.accepted, "code: {}", res.code);
}

#[test]
fn identity_snapshot_lifecycle() {
    // (a) Native jack.whoami accept carries identity=None while
    //     `structured` is set (native calls never reach the handler).
    let (key, entry) = admin_key("root");
    let native: Arc<dyn NativeTools> = Arc::new(Native::new(NativeOptions::default()));
    let state = seeded_state(&[&entry]);
    let v = verifier(config(NOW, Arc::clone(&state), Some(native)));
    let req = post_call(TOOL_WHOAMI, None, &key, &entry.kid, &nonce(60));
    let res = v.verify(&req);
    assert!(res.accepted, "code: {}", res.code);
    assert!(res.native);
    assert!(res.structured.is_some());
    assert!(res.identity.is_none());

    // (c) A rejection carries identity=None.
    let req = post_call("jack.nope", None, &key, &entry.kid, &nonce(61));
    let res = v.verify(&req);
    assert!(!res.accepted);
    assert!(res.identity.is_none());

    // (d) Snapshot lifecycle: the second verification reflects the NEW
    //     registry (subsequent requests see registry changes), while the
    //     first result keeps its old snapshot.
    let (alice_key, alice) = test_key("alice");
    let state = seeded_state(&[&alice]);
    let v = verifier(config(NOW, Arc::clone(&state), None));
    let first = v.verify(&get(&alice_key, &alice.kid, NOW, &nonce(62)));
    assert!(first.accepted);
    let first_identity = first.identity.clone().expect("forwarded accept");
    assert!(!first_identity.admin());
    // set_admin-style change of the caller's admin flag.
    let mut promoted = alice.clone();
    promoted.admin = true;
    state
        .update(&mut |e| {
            e.put_key(promoted.clone());
            Ok(())
        })
        .unwrap();
    let second = v.verify(&get(&alice_key, &alice.kid, NOW, &nonce(63)));
    assert!(second.accepted);
    let second_identity = second.identity.expect("forwarded accept");
    assert!(second_identity.admin());
    assert_eq!(second_identity.kid(), alice.kid);
    // The in-flight first snapshot is unchanged.
    assert!(!first_identity.admin());

    state
        .update(&mut |e| {
            e.put_key(alice.clone());
            Ok(())
        })
        .unwrap();

    // (e) Unspoofable: remote bytes cannot influence the snapshot. The
    //     body carries a fabricated identity but the signed, non-admin
    //     entry decides what is handed on.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.x","arguments":{"identity":{"kid":"evil","name":"evil","admin":true}}}}"#;
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &alice_key,
        &alice.kid,
        NOW,
        &nonce(64),
    );
    let res = v.verify(&req);
    assert!(res.accepted);
    let identity = res.identity.expect("forwarded accept");
    assert_eq!(identity.kid(), alice.kid);
    assert_eq!(identity.name(), "alice");
    assert!(!identity.admin());
}

#[test]
fn forwarded_accept_identity_admin_flag() {
    // (a) both admin true and false entries carry their registry admin
    //     flag in the identity snapshot.
    let (admin_signing, admin) = admin_key("boss");
    let (plain_signing, plain) = test_key("pleb");
    let v = verifier(config(NOW, seeded_state(&[&admin, &plain]), None));

    let res = v.verify(&get(&admin_signing, &admin.kid, NOW, &nonce(65)));
    let identity = res.identity.expect("GET accept carries identity");
    assert_eq!(identity.kid(), admin.kid);
    assert_eq!(identity.name(), "boss");
    assert!(identity.admin());

    let res = v.verify(&get(&plain_signing, &plain.kid, NOW, &nonce(66)));
    let identity = res.identity.expect("GET accept carries identity");
    assert!(!identity.admin());
}
