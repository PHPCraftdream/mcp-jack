use super::*;

#[test]
fn bootstrap_then_enroll() {
    // One store shared by bootstrap and both enroll calls: the invite must
    // be visible to the tool calls.
    let state = Arc::new(MemoryState::new());
    let opts = || NativeOptions {
        random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
    };
    // TTL bounds (Go TestBootstrapAdminThenEnroll).
    assert_eq!(
        bootstrap_admin(state.as_ref(), NOW, 0, opts())
            .unwrap_err()
            .code,
        "internal_error"
    );
    let err = bootstrap_admin(state.as_ref(), NOW, MAX_INVITE_TTL + 1, opts())
        .expect_err("TTL above maximum must be rejected");
    assert_eq!(err.http_status, 0);
    assert_eq!(err.code, "internal_error");

    let code = bootstrap_admin(state.as_ref(), NOW, 600, opts()).unwrap();
    let view = state.view();
    assert_eq!(view.invites.len(), 1);
    assert!(view.invites[0].admin);
    assert_eq!(view.invites[0].created_by, "bootstrap");
    assert_eq!(view.invites[0].expires_at, NOW + 600);

    // First enrollment succeeds; the entry carries the invite's grants.
    let first = test_key("enroll-1", "first");
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(&format!(
            r#"{{"code":"{code}","name":"first","public_key":"{}"}}"#,
            first.public_key
        )),
        None,
        &first.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let res = native.call(&mut call).unwrap();
    assert_eq!(res.structured["kid"], first.kid.as_str());
    assert_eq!(res.structured["name"], "first");
    assert_eq!(res.structured["admin"], true);
    // Stored entry: admin from the invite, kid from the submitted key.
    let view = state.view();
    assert_eq!(view.keys.len(), 1);
    assert_eq!(view.keys[0].kid, first.kid);
    assert_eq!(view.keys[0].name, "first");
    assert!(view.keys[0].admin);
    assert_eq!(view.keys[0].not_after, None);
    // Single-use: the invite was consumed, a second use is invalid.
    assert!(state.view().invites.is_empty());
    let second = test_key("enroll-2", "second");
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(&format!(
            r#"{{"code":"{code}","name":"second","public_key":"{}"}}"#,
            second.public_key
        )),
        None,
        &second.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 403);
    assert_eq!(err.code, codes::INVALID_INVITE);
}

#[test]
fn enroll_default_invite_is_not_admin() {
    // An invite without the admin member enrolls admin=false (spec 03
    // sections 3.3 and 3.2: absent admin defaults to false).
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("admin", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ADMIN_INVITE_CREATE,
        raw_args("{}"),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    native.call(&mut call).unwrap();
    let invite = &state.view().invites[0];
    assert!(!invite.admin);
    let fresh = test_key("fresh", "newcomer");
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(&format!(
            r#"{{"code":"{}","name":"newcomer","public_key":"{}"}}"#,
            encode_b64url(&[0xA5; 32]),
            fresh.public_key
        )),
        None,
        &fresh.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let res = native.call(&mut call).unwrap();
    assert_eq!(res.structured["admin"], false);
    assert!(!state.lookup(&fresh.kid).unwrap().admin);
}

#[test]
fn rotate_preserves_admin() {
    // Rotation keeps the entry's admin and validity interval (spec 03
    // section 3.1: rotate only replaces kid and public_key).
    let state = Arc::new(MemoryState::new());
    let mut caller = admin_key("root", "root");
    caller.not_before = Some(NOW - 60);
    caller.not_after = Some(NOW + 3600);
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let before = state.view();
    let native = deterministic_native();
    let old_signing = test_signing("root");
    let new_signing = test_signing("newroot");
    let new_pub_key = test_key("newroot", "root");
    let proof_string = rotate_proof_string(AUD, &caller.kid, &new_pub_key.kid, NOW);
    let old_key_proof = encode_b64url(&old_signing.sign(proof_string.as_bytes()));

    let mut invalid_call = make_call(
        TOOL_ROTATE_KEY,
        raw_args(&format!(
            r#"{{"public_key":"{}","proof":"{old_key_proof}"}}"#,
            new_pub_key.public_key
        )),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut invalid_call).unwrap_err();
    assert_eq!(err.code, codes::INVALID_PROOF);
    assert_eq!(
        state.view(),
        before,
        "invalid proof must leave state unchanged"
    );

    // The new key signs the exact same rotate proof bytes; that proof is
    // valid for possession of the submitted replacement key.
    let new_key_proof = encode_b64url(&new_signing.sign(proof_string.as_bytes()));
    let mut valid_call = make_call(
        TOOL_ROTATE_KEY,
        raw_args(&format!(
            r#"{{"public_key":"{}","proof":"{new_key_proof}"}}"#,
            new_pub_key.public_key
        )),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    native.call(&mut valid_call).unwrap();

    let rotated = state.lookup(&new_pub_key.kid).expect("rotated entry");
    assert!(rotated.admin);
    assert_eq!(rotated.name, "root");
    assert_eq!(rotated.not_before, caller.not_before);
    assert_eq!(rotated.not_after, caller.not_after);
    assert!(
        state.lookup(&caller.kid).is_none(),
        "old kid must be removed"
    );
}

#[test]
fn invite_code_is_never_stored() {
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("admin", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ADMIN_INVITE_CREATE,
        raw_args("{}"),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let res = native.call(&mut call).unwrap();
    let code = res.structured["code"].as_str().unwrap();
    assert_eq!(code.len(), 43);
    let dumped = format!("{:?}", (state.view().keys, state.view().invites));
    assert!(!dumped.contains(code), "invite code leaked into the store");
    // The stored invite id (its hash) may appear.
    assert!(dumped.contains(res.structured["invite_id"].as_str().unwrap()));
}

#[test]
fn admin_requires_admin_before_arguments() {
    let state = Arc::new(MemoryState::new());
    let caller = test_key("plain", "plain");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = Native::new(NativeOptions::default());
    let mut call = make_call(
        TOOL_ADMIN_USER_LIST,
        raw_args("7"),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 403);
    assert_eq!(err.code, codes::ADMIN_REQUIRED);
}

#[test]
fn last_admin_survives_concurrent_revokes() {
    let native = Native::new(NativeOptions::default());
    for _ in 0..50 {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let a = admin_key("admin-a", "admin-a");
        let b = admin_key("admin-b", "admin-b");
        seed(&[a.clone(), b.clone()], &[], state.as_ref());
        let successes = AtomicUsize::new(0);
        std::thread::scope(|s| {
            let native = &native;
            let state = &state;
            let successes = &successes;
            let a = &a;
            let b = &b;
            s.spawn(move || {
                let store: Arc<dyn StateStore> = Arc::clone(state);
                let mut call = make_call(
                    TOOL_ADMIN_USER_REVOKE,
                    raw_args(&format!(r#"{{"kid":"{}"}}"#, b.kid)),
                    Some(a),
                    &a.kid,
                    store,
                );
                if native.call(&mut call).is_ok() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            });
            s.spawn(move || {
                let store: Arc<dyn StateStore> = Arc::clone(state);
                let mut call = make_call(
                    TOOL_ADMIN_USER_REVOKE,
                    raw_args(&format!(r#"{{"kid":"{}"}}"#, a.kid)),
                    Some(b),
                    &b.kid,
                    store,
                );
                if native.call(&mut call).is_ok() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            });
        });
        // Exactly one transaction can win: the first removes one admin,
        // so the second caller is then gone (401) or its target is gone
        // (404).
        assert_eq!(successes.load(Ordering::SeqCst), 1);
        assert!(active_admins(&state.view().keys, NOW) >= 1);
    }
}

#[test]
fn last_admin_survives_many_concurrent_demotes_and_revokes() {
    let native = Native::new(NativeOptions::default());
    let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let a = admin_key("admin-a", "admin-a");
    let b = admin_key("admin-b", "admin-b");
    seed(&[a.clone(), b.clone()], &[], state.as_ref());
    let successes = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        let native = &native;
        let successes = &successes;
        let a = &a;
        let b = &b;
        for i in 0..24 {
            let store: Arc<dyn StateStore> = Arc::clone(&state);
            s.spawn(move || {
                let (caller, target) = if i % 2 == 0 { (a, a) } else { (b, b) };
                let revoke = i % 4 < 2;
                let arguments = if revoke {
                    raw_args(&format!(r#"{{"kid":"{}"}}"#, target.kid))
                } else {
                    // Demote arm: set_admin admin=false.
                    raw_args(&format!(r#"{{"kid":"{}","admin":false}}"#, target.kid))
                };
                let tool = if revoke {
                    TOOL_ADMIN_USER_REVOKE
                } else {
                    TOOL_ADMIN_USER_SET_ADMIN
                };
                let mut call = make_call(tool, arguments, Some(caller), &caller.kid, store);
                if let Ok(res) = native.call(&mut call) {
                    successes
                        .lock()
                        .unwrap()
                        .push(res.structured["kid"].as_str().unwrap().to_owned());
                }
            });
        }
    });
    let wins = successes.into_inner().unwrap();
    // The first serialized operation always succeeds: both admins are
    // active, so removing or demoting either leaves the other.
    assert!(!wins.is_empty());
    assert!(active_admins(&state.view().keys, NOW) >= 1);
    // Two successes on DISTINCT targets are impossible: each success
    // leaves only one active admin, and a change to the OTHER one then
    // evaluates the last-admin rule against a post-change registry of
    // zero admins (or the demoted caller fails current_admin).
    assert!(
        wins.iter().all(|k| k == &wins[0]),
        "distinct targets succeeded: {wins:?}"
    );
}
