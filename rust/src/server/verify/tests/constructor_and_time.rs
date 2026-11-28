use super::*;

#[test]
fn new_rejects_control_characters_in_aud() {
    // The signing string is LF-joined lines including the audience, so an
    // aud with control characters would make it ambiguous (Go:
    // audHasControl in NewVerifier).
    for bad in ["a\nb", "a\rb", "a\0b", "a\tb", "a\u{7f}b"] {
        let err = match VerifierBuilder::new(bad, Arc::new(MemoryState::new())).try_build() {
            Err(err) => err,
            Ok(_) => panic!("control-character aud must be rejected: {bad:?}"),
        };
        assert_eq!(
            err,
            VerifierConfigError::AudienceControlCharacter,
            "aud {bad:?}"
        );
        assert_eq!(
            err.to_string(),
            "server: Config.Aud must not contain control characters",
            "aud {bad:?}"
        );
    }
    let error = match VerifierBuilder::new("", Arc::new(MemoryState::new())).try_build() {
        Err(error) => error,
        Ok(_) => panic!("empty audience must be rejected"),
    };
    assert_eq!(error, VerifierConfigError::EmptyAudience);
    assert_eq!(error.to_string(), "server: Config.Aud must be non-empty");

    // An ordinary value is still accepted.
    VerifierBuilder::new("https://svc.example.test", Arc::new(MemoryState::new()))
        .try_build()
        .expect("ordinary aud must be accepted");
}

#[test]
fn clock_step_back_cannot_revive_a_nonce() {
    let (key, entry) = test_key("alice");
    let clock = Arc::new(AtomicI64::new(NOW + 1000));
    let v = verifier(stepping_config(&clock, seeded_state(&[&entry])));

    let req = get(&key, &entry.kid, NOW + 1000, &nonce(1));
    assert!(v.verify(&req).accepted);

    // Wall clock steps back to NOW: the replay is still a live nonce.
    clock.store(NOW, Ordering::SeqCst);
    let res = v.verify(&req);
    assert_eq!(res.http_status, 401);
    assert_eq!(res.code, codes::REPLAYED_NONCE);

    // A request stamped at the stepped-back time is outside the window
    // measured from the high-water mark (window is 30 s).
    let stale = get(&key, &entry.kid, NOW, &nonce(2));
    let res = v.verify(&stale);
    assert_eq!(res.http_status, 401);
    assert_eq!(res.code, codes::TIMESTAMP_OUT_OF_WINDOW);
    // The response clock stays raw.
    assert_eq!(v.now(), NOW);
}

#[test]
fn rollback_cannot_reactivate_an_expired_key() {
    let (key, mut entry) = test_key("alice");
    entry.not_after = Some(NOW + 750);
    let clock = Arc::new(AtomicI64::new(NOW + 1000));
    let v = verifier(stepping_config(&clock, seeded_state(&[&entry])));

    // high sample must be expired while the stepped-back sample is active;
    // spec 01 §4 step 5 / Go Verify requires the interval check to use
    // effectiveNow, so rollback cannot revive this key.
    // Both signatures use the high-water timestamp so freshness passes
    // even on the stepped-back raw clock; this isolates key activity.
    let high = v.verify(&get(&key, &entry.kid, NOW + 1000, &nonce(21)));
    assert_eq!(high.code, codes::KEY_INACTIVE);

    clock.store(NOW + 500, Ordering::SeqCst);
    let rolled_back = v.verify(&get(&key, &entry.kid, NOW + 1000, &nonce(22)));
    assert_eq!(rolled_back.http_status, 401);
    assert_eq!(rolled_back.code, codes::KEY_INACTIVE);
    assert!(!rolled_back.nonce_recorded);
}

#[test]
fn rollback_cannot_revive_an_expired_enrollment_invite() {
    let (key, carol) = test_key("carol");
    let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    add_invite(&state, NOW + 30);
    let clock = Arc::new(AtomicI64::new(NOW + 40));
    let nonces = Arc::new(NonceStore::new());
    let mut cfg = stepping_config(&clock, Arc::clone(&state));
    let audit = Arc::new(MemoryAuditSink::new());
    cfg = Config {
        nonces: nonces.clone(),
        audit: Some(audit.clone()),
        native: Some(stub()),
        ..cfg
    };
    let v = verifier(cfg);
    let body = call_body(TOOL_ENROLL, Some(&enroll_args(&carol.public_key)));
    let req_high = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &key,
        &carol.kid,
        NOW + 40,
        &nonce(23),
    );
    assert_eq!(v.verify(&req_high).code, codes::UNKNOWN_KEY);

    clock.store(NOW + 20, Ordering::SeqCst);
    let req_after_rollback = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &key,
        &carol.kid,
        NOW + 40,
        &nonce(24),
    );
    let result = v.verify(&req_after_rollback);
    // spec 01 §4 step 4 enrollment exception: the expired invite remains
    // indistinguishable from an unknown kid; no nonce or audit is emitted.
    assert_eq!(result.http_status, 401);
    assert_eq!(result.code, codes::UNKNOWN_KEY);
    assert!(!result.nonce_recorded);
    assert!(result.audit.is_none());
    assert!(audit.events().is_empty());
    assert!(state
        .lookup_invite(&invite_id_of(&INVITE_CODE_RAW))
        .is_some());
    assert!(nonces.is_empty());
}

#[test]
fn rollback_uses_effective_time_for_native_calls_and_audit() {
    let (key, entry) = admin_key("alice");
    let high_now = NOW + 1000;
    let clock = Arc::new(AtomicI64::new(high_now));
    let mut cfg = stepping_config(&clock, seeded_state(&[&entry]));
    let native_now = Arc::new(AtomicI64::new(i64::MIN));
    let audit = Arc::new(MemoryAuditSink::new());
    cfg.native = Some(Arc::new(TimeRecordingNative(Arc::clone(&native_now))));
    cfg.audit = Some(audit.clone());
    let v = verifier(cfg);
    assert!(
        v.verify(&get(&key, &entry.kid, high_now, &nonce(25)))
            .accepted
    );

    clock.store(NOW + 500, Ordering::SeqCst);
    let body = call_body(TOOL_ADMIN_INVITE_LIST, None);
    let req = signed(
        "POST",
        "/mcp",
        body.as_bytes(),
        &key,
        &entry.kid,
        high_now,
        &nonce(26),
    );
    let result = v.verify(&req);
    assert!(result.accepted, "code: {}", result.code);
    // spec 01 §4 request-time rule: native handler and audit share
    // effectiveNow; only response signing keeps the raw clock sample.
    assert_eq!(native_now.load(Ordering::SeqCst), high_now);
    assert_eq!(v.now(), NOW + 500, "the response clock remains raw");
    let event = result.audit.expect("admin call is audited");
    assert_eq!(event.time, high_now);
    assert_eq!(audit.events(), vec![event]);
}

#[cfg(target_os = "linux")]
#[test]
fn durable_builder_keeps_window_validation() {
    let (_sandbox, store) = durable_test_store();
    let result = VerifierBuilder::new(AUD, Arc::new(MemoryState::new()))
        .window_seconds(121)
        .with_durable_nonces(Arc::clone(&store))
        .try_build();
    assert_eq!(result.err(), Some(VerifierConfigError::InvalidWindow));
    store.close().expect("close durable test store");
}

#[test]
fn constructor_validates_window_and_accepts_boundaries() {
    for invalid in [-1, 121] {
        let error = match VerifierBuilder::new(AUD, Arc::new(MemoryState::new()))
            .window_seconds(invalid)
            .try_build()
        {
            Err(error) => error,
            Ok(_) => panic!("invalid window {invalid} must be rejected"),
        };
        assert_eq!(error, VerifierConfigError::InvalidWindow);
        assert_eq!(
            error.to_string(),
            "server: window must be 0 (default 30) or an integer between 1 and 120 seconds"
        );
    }

    assert_eq!(
        VerifierBuilder::new(AUD, Arc::new(MemoryState::new()))
            .try_build()
            .expect("zero selects default")
            .window(),
        30
    );

    for window in [1, 120] {
        let (key, entry) = test_key("alice");
        let mut cfg = config(NOW, seeded_state(&[&entry]), None);
        cfg.window_seconds = window;
        let v = verifier(cfg);
        // spec 01 §4 step 6: the inclusive ±window boundary passes, and
        // one second beyond it is rejected (including the maximum 120 s).
        let accepted = v.verify(&get(&key, &entry.kid, NOW - window, &nonce(28)));
        assert!(accepted.accepted, "window {window}: {}", accepted.code);
        let accepted_past = v.verify(&get(&key, &entry.kid, NOW + window, &nonce(30)));
        assert!(
            accepted_past.accepted,
            "window {window}: {}",
            accepted_past.code
        );
        let rejected_past = v.verify(&get(&key, &entry.kid, NOW + window + 1, &nonce(31)));
        assert_eq!(
            rejected_past.code,
            codes::TIMESTAMP_OUT_OF_WINDOW,
            "window {window}"
        );
        let rejected = v.verify(&get(&key, &entry.kid, NOW - window - 1, &nonce(29)));
        assert_eq!(
            rejected.code,
            codes::TIMESTAMP_OUT_OF_WINDOW,
            "window {window}"
        );
    }
}

#[test]
fn freshness_is_judged_against_the_high_water_mark() {
    let (key, entry) = test_key("alice");
    let clock = Arc::new(AtomicI64::new(NOW + 1000));
    let v = verifier(stepping_config(&clock, seeded_state(&[&entry])));
    let first = v.verify(&get(&key, &entry.kid, NOW + 1000, &nonce(1)));
    assert!(first.accepted);

    // Raw time NOW alone would reject ts NOW + 1000 (1000 s > window).
    clock.store(NOW, Ordering::SeqCst);
    let res = v.verify(&get(&key, &entry.kid, NOW + 1000, &nonce(2)));
    assert!(res.accepted, "got {} {}", res.http_status, res.code);

    // Normal forward movement keeps working.
    clock.store(NOW + 1010, Ordering::SeqCst);
    let res = v.verify(&get(&key, &entry.kid, NOW + 1010, &nonce(3)));
    assert!(res.accepted, "got {} {}", res.http_status, res.code);
}
