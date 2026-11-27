use super::*;

/// Go TestNativeServerKeyExplicitDispatchStrictArgumentsAndImmutablePage,
/// page half: the selected signer signs exactly one committed record and the
/// candidate is never forwarded.
#[tokio::test]
async fn native_page_is_signed_by_selected_signer() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let exchange = h.candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#).await;
    let got = &exchange.got;
    assert_eq!(got.status, 200, "a valid native request must be answered");
    assert_eq!(got.jack_auth.len(), 1, "the candidate page is signed");
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        h.keys[0].kid(),
        "the SELECTED (anchor) signer signs the page"
    );
    assert_eq!(response.ts, NOW, "the signing timestamp is the store clock");
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &exchange.sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&h.keys[0].public_key(), message.as_bytes(), &sig),
        "native page signature does not verify under the anchor key"
    );

    let page = decode_result(&got.body, b"1").expect("the page envelope decodes");
    assert_eq!(page.current_kid, h.keys[0].kid(), "current is the anchor");
    assert_eq!(
        page.records,
        vec![first.wire],
        "exactly one exact committed snapshot record"
    );
    assert_eq!(page.head_ordinal, 1);
    assert!(page.complete, "one record page is complete");
    assert_eq!(
        h.inner_calls.load(Ordering::SeqCst),
        0,
        "the candidate is never forwarded"
    );
}

/// Go page half, head cursor: the cursor anchored at the head yields an empty
/// but complete page.
#[tokio::test]
async fn head_cursor_yields_empty_complete_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{}"}}"#, first.hash);
    let got = h.candidate(&arguments).await.got;
    assert_eq!(got.status, 200, "the head cursor is valid");
    let page = decode_result(&got.body, b"1").expect("the page envelope decodes");
    assert!(
        page.records.is_empty(),
        "the head cursor must yield an empty page"
    );
    assert!(page.complete, "the empty head page is complete");
}

/// Go strict-arguments half: every undecodable arguments form is a signed 400
/// invalid_params (the nonce was consumed), including a tools/call whose
/// params lack the `arguments` member entirely. A duplicate member name makes
/// the whole body unacceptable (spec 02 section 2): a signed 400 invalid_request.
#[tokio::test]
async fn strict_argument_refusals_are_signed_400() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let strict = [
        "null",
        "{}",
        r#"{"after_ordinal":0,"after_hash":"-","extra":true}"#,
    ];
    for arguments in strict {
        let got = h.candidate(arguments).await.got;
        assert_eq!(got.status, 400, "arguments {arguments} must be refused");
        assert_eq!(
            got.jack_auth.len(),
            1,
            "the nonce was consumed, so the refusal is signed"
        );
        assert_eq!(error_code(&got.body), "invalid_params");
    }
    let duplicates = [
        r#"{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}"#,
        r#"{"after_ordinal":0,"after_hash":"-","after_hash":"-"}"#,
    ];
    for arguments in duplicates {
        let got = h.candidate(arguments).await.got;
        assert_eq!(got.status, 400, "arguments {arguments} must be refused");
        assert_eq!(
            got.jack_auth.len(),
            1,
            "the nonce was consumed, so the refusal is signed"
        );
        assert_eq!(error_code(&got.body), "invalid_request");
    }
    // A tools/call WITHOUT the arguments member is invalid_params too
    // (Go: server decodes a missing member the same way).
    let body = server_key_body_without_arguments();
    let signed = signed_request(&h.caller, "POST", "/mcp", &body);
    let got = inspect(
        send(&h.service, build_request(&signed, "POST", "/mcp", &body))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 400, "absent arguments must be refused");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the absent-arguments call still consumed its nonce"
    );
    assert_eq!(error_code(&got.body), "invalid_params");
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "the candidate route must not reach the ordinary native implementation"
    );
}

/// Go unavailable-cursor half: a well-formed cursor whose hash anchors
/// nothing is a signed 409.
#[tokio::test]
async fn unavailable_cursor_is_signed_409() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let arguments = format!(r#"{{"after_ordinal":1,"after_hash":"{}"}}"#, "A".repeat(43));
    let got = h.candidate(&arguments).await.got;
    assert_eq!(got.status, 409, "an unanchored cursor is unavailable");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the unavailable-cursor refusal is signed"
    );
    assert_eq!(error_code(&got.body), "rotation_checkpoint_unavailable");
}

/// Go TestNativeServerKeyExplicitDispatch... closed half: without
/// `with_server_keys` the candidate route is enabled by NEITHER the ordinary
/// native implementation NOR its absence — signed 403 operation_denied, and
/// nothing is forwarded or dispatched.
#[tokio::test]
async fn candidate_route_requires_server_keys() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: false,
            mutation: None,
        },
    });
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 403, "the route must stay closed");
    assert_eq!(error_code(&got.body), "operation_denied");
    assert_eq!(
        got.jack_auth.len(),
        1,
        "the nonce was consumed, so the denial is signed"
    );
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "ordinary Native must not enable the candidate route"
    );
    assert_eq!(
        h.inner_calls.load(Ordering::SeqCst),
        0,
        "nothing is forwarded"
    );
}

/// Go TestConcreteProviderThroughMiddlewareFinalBeforeWireAndConsumedReplay,
/// success branch: a forwarded ping answer is preserved byte for byte and
/// signed by the anchor; the replayed identical request is refused unsigned;
/// the middleware releases its serving lease (clean close).
#[tokio::test]
async fn forwarded_answer_is_signed_and_replay_is_unsigned() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        // Count-only hook (Go signs++ without the late store): makes the
        // sign-count assertions non-vacuous.
        anchor_hook: Some(Arc::new(|_: &AtomicU64| {})),
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "a verified ping forwards");
    assert_eq!(
        got.body.as_ref(),
        APPLICATION_BODY,
        "the application answer is preserved byte for byte"
    );
    assert_eq!(
        got.x_private_app.as_deref(),
        Some("not-on-refusal"),
        "inner headers survive a signed forward"
    );
    assert_eq!(got.jack_auth.len(), 1);
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        h.keys[0].kid(),
        "the pinned wire identity is the anchor kid"
    );
    assert_eq!(response.ts, NOW, "the pinned wire time is 1000");
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&h.keys[0].public_key(), message.as_bytes(), &sig),
        "wire response signature invalid"
    );
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "exactly one sign");
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1, "one dispatch");
    assert_eq!(h.nonces.len(), 1, "exactly one nonce reservation");

    // Replay the IDENTICAL request bytes: consumed, refused, unsigned.
    let replay = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(
        replay.status, 401,
        "a consumed request must not be redelivered"
    );
    assert_eq!(error_code(&replay.body), "replayed_nonce");
    assert_eq!(
        replay.jack_auth,
        Vec::<String>::new(),
        "the replay answer is unsigned"
    );
    assert_eq!(
        h.inner_calls.load(Ordering::SeqCst),
        1,
        "no second dispatch"
    );
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "no second sign");

    // The middleware released its serving lease on every path.
    h.lock_store()
        .close()
        .expect("middleware leaked serving lease");
    // Go provider test parity: a closed owner never serves again.
    let dead = ResponseKeyRequest {
        status: 404,
        tool: "not-a-key-authority",
        request_signature: "",
        body: b"untrusted selector",
    };
    assert!(
        matches!(
            h.provider.authorize_response(&dead),
            Err(RotationError {
                code: "rotation_state_unavailable"
            })
        ),
        "closed owner served"
    );
}

/// Go success branch's twin, late-final: the anchor's on-sign hook moves the
/// store clock past the freshness window EXACTLY when write_authorized signs,
/// so the computed signature is discarded and the UNSIGNED 503 refusal leaks
/// neither the application body nor its headers.
#[tokio::test]
async fn late_final_gate_discards_signature() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        anchor_hook: Some(Arc::new(|clock: &AtomicU64| {
            clock.store(1031, Ordering::SeqCst);
        })),
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: None,
        },
    });
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(
        got.status, 503,
        "the late final gate must fail the response"
    );
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the refusal is unsigned: no Jack-Auth"
    );
    assert_eq!(error_code(&got.body), "rotation_state_unavailable");
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        !body.contains("exact application body"),
        "the application body leaked into the refusal: {body}"
    );
    assert_eq!(
        got.x_private_app, None,
        "inner headers are discarded on refusal"
    );
    assert_eq!(
        h.now.load(Ordering::SeqCst),
        1031,
        "the hook moved the clock"
    );
    assert_eq!(
        h.signs.load(Ordering::SeqCst),
        1,
        "the signature was computed once"
    );
    assert_eq!(
        h.inner_calls.load(Ordering::SeqCst),
        1,
        "the forward already happened"
    );

    // Go shared tail: the replay is a consumed nonce, and the refusal path
    // released the lease, so the store closes cleanly.
    let replay = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(
        replay.status, 401,
        "a consumed request must not be redelivered"
    );
    assert_eq!(h.signs.load(Ordering::SeqCst), 1, "no second sign");
    assert_eq!(
        h.inner_calls.load(Ordering::SeqCst),
        1,
        "no second dispatch"
    );
    h.lock_store()
        .close()
        .expect("middleware leaked serving lease");
}

/// Go TestNativeServerKeySigningTimeRejectsChangedHeadOrCurrent, head variant:
/// the committed head moves AFTER the page was assembled but BEFORE signing;
/// the response parity gate discards the stale page (never exposed).
#[tokio::test]
async fn signing_time_head_change_discards_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: Some(Mutation::Head),
        },
    });
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 503, "a mixed signing-time snapshot must refuse");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the stale page is never signed"
    );
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        body.contains("rotation_state_unavailable"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains("structuredContent"),
        "the stale page leaked into the refusal: {body}"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "never forwarded");
    assert_eq!(
        h.ordinary_native_calls.load(Ordering::SeqCst),
        0,
        "the wrapper must not reach the ordinary native implementation"
    );
}

/// Go current variant: the store clock moves to the announced record's
/// activation time AFTER the page was assembled, so the anchor retires
/// strictly there and another key is current at signing time; the stale page
/// is discarded unsigned.
#[tokio::test]
async fn signing_time_current_change_discards_page() {
    let h = new_harness(FixtureOptions {
        announce_next: true,
        anchor_hook: None,
        profile: Profile::Rotating {
            with_server_keys: true,
            mutation: Some(Mutation::Current),
        },
    });
    let first = h.first_record.clone().expect("announce happened");
    let got = h
        .candidate(r#"{"after_ordinal":0,"after_hash":"-"}"#)
        .await
        .got;
    assert_eq!(got.status, 503, "a changed current must refuse the page");
    assert_eq!(
        got.jack_auth,
        Vec::<String>::new(),
        "the stale page is never signed"
    );
    let body = String::from_utf8_lossy(&got.body).into_owned();
    assert!(
        body.contains("rotation_state_unavailable"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains("structuredContent"),
        "the stale page leaked into the refusal: {body}"
    );
    assert_eq!(
        h.now.load(Ordering::SeqCst),
        first.activates_at,
        "the mutation moved the store clock to the cutoff"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 0, "never forwarded");
}

/// Pin that the static response-signing profile is untouched by the rotating
/// work: the same fixture behind `JackLayer::new` still signs with its own
/// static key.
#[tokio::test]
async fn static_profile_still_signs_with_static_key() {
    let h = new_harness(FixtureOptions {
        announce_next: false,
        anchor_hook: None,
        profile: Profile::Static,
    });
    let static_pub = ServerSigningKey::from_bytes(&STATIC_SEED).public_key();
    let sent = signed_request(&h.caller, "POST", "/mcp", PING_BODY);
    let got = inspect(
        send(&h.service, build_request(&sent, "POST", "/mcp", PING_BODY))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200, "the static profile still forwards");
    assert_eq!(got.body.as_ref(), APPLICATION_BODY);
    assert_eq!(got.jack_auth.len(), 1, "the static profile still signs");
    let values: Vec<&str> = got.jack_auth.iter().map(String::as_str).collect();
    let response = parse_response_auth(&values).expect("Jack-Auth parses");
    assert_eq!(
        response.kid,
        key_id(&static_pub),
        "the static key signs, not a rotation key"
    );
    assert_eq!(
        response.ts, NOW,
        "the static profile signs at the verifier clock"
    );
    let sig = decode_b64url_fixed(&response.sig, 64).expect("sig decodes to 64 bytes");
    let message = response_signing_string(
        200,
        &sent.request_sig,
        &response.kid,
        response.ts,
        &got.body,
    );
    assert!(
        verify(&static_pub, message.as_bytes(), &sig),
        "static profile signature invalid"
    );
    assert_eq!(h.inner_calls.load(Ordering::SeqCst), 1);
}
