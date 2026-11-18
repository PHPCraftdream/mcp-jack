use super::*;

/// Go TestMiddlewareForwardsAndSigns: an authorized alice tool call reaches
/// the inner service and the answer is signed.
///
/// Pipeline: verification steps pass -> accept. There is no policy step:
/// ANY authenticated key's ordinary tool call (svc.* included) forwards.
#[tokio::test]
async fn forwards_and_signs() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp?x=1", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp?x=1", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_bodies(), vec![STATUS_BODY.to_vec()]);
    assert_eq!(h.inner.seen_targets(), vec!["/mcp?x=1".to_string()]);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
}

/// Go TestMiddlewareUnauthenticatedIsRejectedUnsigned: no Jack-Auth header.
///
/// Pipeline: stops at step 1 (missing_auth) before the key lookup; the nonce
/// is never recorded, so the 401 is unsigned and carries WWW-Authenticate.
#[tokio::test]
async fn unauthenticated_rejected_unsigned() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let got = inspect(
        send(
            &h.service,
            build_unsigned_request("POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "missing_auth");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "unsigned 401 has no Jack-Auth"
    );
    assert_eq!(
        got.www_authenticate.as_deref(),
        Some("Jack-Auth"),
        "401 carries WWW-Authenticate (Go parity)"
    );
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_eq!(h.inner.calls(), 0);
}

/// A v2 scheme with obs-text parameters is unsupported_version: the scheme is
/// examined on the raw bytes before the value is converted to UTF-8 (spec 01
/// section 3).
///
/// Pipeline: stops before the UTF-8 conversion gate; the nonce is never
/// recorded, so the 401 is unsigned and carries WWW-Authenticate.
#[tokio::test]
async fn v2_scheme_with_obs_text_is_unsupported_version() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let mut raw = b"v2 ".to_vec();
    raw.extend_from_slice(&[0xC3, 0xA9, 0x80]); // obs-text parameters
    let value = http::HeaderValue::from_bytes(&raw).expect("obs-text is a valid header value");
    let req = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", value)
        .body(Full::new(Bytes::copy_from_slice(STATUS_BODY)))
        .expect("static request parts");
    let got = inspect(send(&h.service, req).await.expect("no inner error")).await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "unsupported_version");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "unsigned 401 has no Jack-Auth"
    );
    assert_eq!(
        got.www_authenticate.as_deref(),
        Some("Jack-Auth"),
        "401 carries WWW-Authenticate (Go parity)"
    );
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_eq!(h.inner.calls(), 0);
}

/// A non-version scheme with obs-text is still malformed_auth (unchanged): the
/// rejection happens at the UTF-8 conversion gate, not the scheme check.
#[tokio::test]
async fn obs_text_with_plain_scheme_is_malformed_auth() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let mut raw = b"Bearer ".to_vec();
    raw.extend_from_slice(&[0xC3, 0xA9]); // obs-text parameters
    let value = http::HeaderValue::from_bytes(&raw).expect("obs-text is a valid header value");
    let req = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", value)
        .body(Full::new(Bytes::copy_from_slice(STATUS_BODY)))
        .expect("static request parts");
    let got = inspect(send(&h.service, req).await.expect("no inner error")).await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "malformed_auth");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "unsigned 401 has no Jack-Auth"
    );
    assert_eq!(
        got.www_authenticate.as_deref(),
        Some("Jack-Auth"),
        "401 carries WWW-Authenticate (Go parity)"
    );
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
    assert_eq!(h.inner.calls(), 0);
}

/// Go TestMiddlewareSignsAuthorizationRejection, reworked for the
/// admin-only wrapper: the admin flag gates only jack.admin.*, so alice's
/// svc.restart call is now ACCEPTED and forwarded; the answer is signed and
/// no WWW-Authenticate is ever attached to a signed (post-nonce) response.
#[tokio::test]
async fn lifecycle_tool_forwards_and_signs() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", RESTART_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", RESTART_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    // len==1 proves the response is signed; the 401-only WWW-Authenticate
    // claim is carried by the next assert.
    assert_eq!(got.jack_auth.len(), 1);
    assert!(
        got.www_authenticate.is_none(),
        "signed answers never carry WWW-Authenticate"
    );
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_bodies(), vec![RESTART_BODY.to_vec()]);
}

/// The admin gate (spec 02 section 4): alice (non-admin) calling a
/// jack.admin.* tool gets a signed 403 admin_required via HTTP; the inner
/// service is never called and the audit sink records the failure.
///
/// Counterfactual: revert to deny-by-default or any scope-check scheme and
/// this test fails — ordinary tools forward (see
/// lifecycle_tool_forwards_and_signs), so a 403 here can only come from the
/// admin flag gate.
#[tokio::test]
async fn admin_tool_denied_for_non_admin() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", LIST_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 403);
    assert_eq!(error_code(&got.body), "admin_required");
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the nonce was recorded, so the 403 is signed"
    );
    assert!(
        got.www_authenticate.is_none(),
        "403s never carry WWW-Authenticate"
    );
    assert_eq!(h.inner.calls(), 0, "the inner service is never called");

    let events = h.sink.events();
    assert_eq!(events.len(), 1, "exactly one audit event");
    assert_eq!(events[0].tool, "jack.admin.user.list");
    assert_eq!(events[0].outcome, "failure");
    assert_eq!(events[0].code, "admin_required");
    assert_eq!(events[0].actor_name, "alice");
    assert_eq!(events[0].actor_kid, alice_kid);
    assert_eq!(events[0].time, FIXTURE_NOW);
}

/// Go TestMiddlewareRefusesStreams: GET forwarding succeeds but an SSE answer
/// cannot be signed, so the layer refuses it.
///
/// Pipeline: GET skips body classification, verification passes and the
/// request forwards; the inner 200 text/event-stream hits the layer's stream
/// guard -> 501 streaming_unsupported, signed.
#[tokio::test]
async fn refuses_streams() {
    let h = new_harness(
        0,
        InnerResponse {
            status: 200,
            content_type: "text/event-stream",
            body: b"data: x\n\n".to_vec(),
            extra_headers: Vec::new(),
        },
    );
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 501);
    assert_eq!(error_code(&got.body), "streaming_unsupported");
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
}

/// Go TestMiddlewareBodyLimit: an oversized body is refused before
/// authentication.
///
/// Pipeline: the method gate passes but the body-limit read (Go
/// io.ReadAll(MaxBytesReader), before verify step 1) fails -> 413
/// invalid_request, unsigned.
#[tokio::test]
async fn body_limit_rejects_oversized() {
    let h = new_harness(64, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(200)
    )
    .into_bytes();
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", &body);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 413);
    assert_eq!(error_code(&got.body), "invalid_request");
    assert_eq!(error_message(&got.body), "request body is too large");
    assert_eq!(h.inner.calls(), 0);
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "pre-auth 413 is unsigned"
    );
    assert!(got.www_authenticate.is_none(), "413 is not a 401");
    assert_eq!(got.content_type.as_deref(), Some("application/json"));
}

/// Exactly-limit bodies pass Go's http.MaxBytesReader; the port must too.
///
/// Pipeline: same as body_limit_rejects_oversized but the buffered length
/// equals the limit, so verification passes and the request forwards -> 200,
/// signed.
#[tokio::test]
async fn body_limit_exact_boundary_passes() {
    let h = new_harness(64, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let base = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"\"}}";
    let pad = 64 - base.len();
    assert!(pad > 0, "base ping body must leave room for padding");
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(pad)
    )
    .into_bytes();
    assert_eq!(body.len(), 64);
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "POST", "/mcp", &body);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_bodies();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].len(), 64);
    assert_eq!(seen[0], body);
}

/// Go TestMiddlewareMethodNotAllowed: PUT never enters verification.
///
/// Pipeline: stops at the method gate before verify step 1 -> 405
/// method_not_allowed, unsigned.
#[tokio::test]
async fn method_not_allowed() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "PUT", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "PUT", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 405);
    assert_eq!(error_code(&got.body), "method_not_allowed");
    assert_eq!(got.jack_auth, Vec::<String>::new());
    assert!(got.www_authenticate.is_none(), "405 is not a 401");
    assert_eq!(h.inner.calls(), 0);
}

/// Go TestMiddlewareAnswersNativeToolsItself: the real Native answers
/// jack.admin.user.list and the layer signs its JSON-RPC result.
///
/// Pipeline: verification passes (root holds admin), the jack.* tool is
/// dispatched natively -> 200, signed, the inner service never sees the
/// request.
#[tokio::test]
async fn answers_native_tools_itself() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let svc = h.service;
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    // Derived from keys.json, not from the response.
    let alice_kid = harness::signer_by_name("alice").kid().to_string();
    let signed = signed_request(&root, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(&svc, build_request(&signed, "POST", "/mcp", LIST_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 0);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(got.content_type.as_deref(), Some("application/json"));

    let v: serde_json::Value = serde_json::from_slice(&got.body).expect("body is JSON");
    assert_eq!(v["id"], 1, "id echoes the request id");
    assert_eq!(v["result"]["isError"], false);
    let content = v["result"]["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1, "exactly one content item");
    assert_eq!(content[0]["type"], "text");
    let structured = &v["result"]["structuredContent"];
    let text = content[0]["text"].as_str().expect("text is a string");
    assert_eq!(
        text,
        serde_json::to_string(structured).expect("structured serializes"),
        "the text item is the marshaled structured content (Go parity)"
    );
    let users = structured["users"].as_array().expect("users array");
    let alice_entry = users
        .iter()
        .find(|u| u["name"] == "alice")
        .expect("alice is listed");
    assert_eq!(alice_entry["kid"], serde_json::Value::String(alice_kid));

    let events = h.sink.events();
    assert_eq!(events.len(), 1, "exactly one audit event");
    assert_eq!(events[0].tool, "jack.admin.user.list");
    assert_eq!(events[0].outcome, "success");
    assert_eq!(events[0].actor_name, "root");
    assert_eq!(events[0].actor_kid, root_kid);
    assert_eq!(events[0].time, FIXTURE_NOW);
    assert_eq!(events[0].target, "", "user.list sets no audit target");
}

/// No Go analogue (ServeHTTP cannot error): inner failures propagate
/// unchanged.
///
/// Pipeline: never reached — the inner service itself returns Err, which the
/// layer must pass through as-is.
#[tokio::test]
async fn inner_service_error_propagates() {
    let state = MemoryState::new();
    seed_registry(&state);
    let layer = JackLayer::new(HandlerConfig {
        verifier: build_verifier(state, None),
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    let svc = layer.layer(tower::service_fn(
        |_req: http::Request<Full<Bytes>>| async move {
            Err::<http::Response<Full<Bytes>>, _>("boom".to_string())
        },
    ));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let err = svc
        .oneshot(build_request(&signed, "GET", "/mcp", b""))
        .await
        .expect_err("inner error must propagate");
    assert_eq!(err, "boom");
}

/// Go parity for "never normalize": the target is signed and forwarded
/// exactly as received.
///
/// Pipeline: verification passes (the signature binds the raw target string)
/// and the GET forwards; a normalizing layer would break the signature
/// first, so this test fails the moment normalization is introduced.
#[tokio::test]
async fn request_target_not_normalized() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let target = "/mcp?x=%7e&y=a%2Fb";
    let signed = signed_request(&alice, "GET", target, b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", target, b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_signed(&got, &signed.request_sig, &h.server_pub);
    assert_eq!(h.inner.calls(), 1);
    assert_eq!(h.inner.seen_targets(), vec![target.to_string()]);
}

/// Non-origin-form targets are refused 400 invalid_request, unsigned, before
/// verification: the request carries a valid signature over "/mcp", so any
/// verifier involvement would answer 200 or 401 instead.
#[tokio::test]
async fn non_origin_form_targets_refused_before_verification() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    for target in ["http://svc.example.test/mcp", "*", "svc.example.test:443"] {
        let got = inspect(
            send(&h.service, build_request(&signed, "GET", target, b""))
                .await
                .expect("no inner error"),
        )
        .await;
        assert_eq!(got.status, 400, "target {target:?}");
        assert_eq!(
            error_code(&got.body),
            "invalid_request",
            "target {target:?}"
        );
        assert!(got.jack_auth.is_empty(), "unsigned: {target:?}");
        assert!(got.www_authenticate.is_none(), "not a 401: {target:?}");
    }
    assert_eq!(h.inner.calls(), 0);
    assert!(h.sink.events().is_empty());

    // The same signature is still good for the origin-form target: the nonce
    // was never consumed by the refusals.
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
}

/// A non-ASCII percent-encoded target is signed and verified over the exact
/// received bytes (no decoding).
#[tokio::test]
async fn percent_encoded_non_ascii_target_verified_exactly() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let target = "/mcp?q=%C3%A9";
    let signed = signed_request(&alice, "GET", target, b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", target, b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.seen_targets(), vec![target.to_string()]);
}
