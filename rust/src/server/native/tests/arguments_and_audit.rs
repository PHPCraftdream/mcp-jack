use super::*;

#[test]
fn int_arg_is_lexical() {
    // -0 is the integer 0 (spec 03 section 3), in and out of range.
    assert_eq!(int_arg(&args_of(r#"{"v":-0}"#), "v", 0, 100), Some(0));
    assert_eq!(
        int_arg(&args_of(r#"{"v":-0}"#), "v", 1, MAX_INVITE_TTL),
        None
    );
    // Texts that are not valid JSON cannot reach int_arg (the verifier only
    // hands over parsed JSON), so the lexical rule is checked directly.
    for text in ["01", "-01", "+1", "-", "", "--1", "1_0", " 1"] {
        assert_eq!(json_int(text), None, "text {text:?}");
    }
    // Fraction, exponent and non-numbers (valid JSON) all fail.
    for text in ["1.0", "1e3", "1E3", "\"5\"", "true", "null"] {
        assert_eq!(
            int_arg(
                &args_of(&format!(r#"{{"v":{text}}}"#)),
                "v",
                i64::MIN,
                i64::MAX
            ),
            None,
            "text {text}"
        );
    }
    assert_eq!(int_arg(&args_of(r#"{"v":-1}"#), "v", -5, 5), Some(-1));
    assert_eq!(int_arg(&args_of(r#"{"v":-1}"#), "v", 0, 5), None);
    // No f64 rounding: 2^53+1 stays exact.
    assert_eq!(
        int_arg(&args_of(r#"{"v":9007199254740993}"#), "v", 0, i64::MAX),
        Some(9_007_199_254_740_993)
    );
    assert_eq!(
        int_arg(
            &args_of(r#"{"v":9007199254740993}"#),
            "v",
            0,
            999_999_999_999
        ),
        None
    );
    // A 20-digit magnitude parses in i128 and fails the range check.
    assert_eq!(
        int_arg(&args_of(r#"{"v":99999999999999999999}"#), "v", 0, i64::MAX),
        None
    );
}

#[test]
fn time_arg_table() {
    assert_eq!(time_arg(&args_of(r#"{"v":-0}"#), "v"), Some(Some(0)));
    assert_eq!(time_arg(&args_of(r#"{"v":null}"#), "v"), Some(None));
    assert_eq!(time_arg(&args_of("{}"), "v"), Some(None));
    assert_eq!(time_arg(&args_of(r#"{"v":1.5}"#), "v"), None);
}

#[test]
fn user_create_accepts_negative_zero_not_after() {
    // Mirrors the fixture admin-create-not-after-negative-zero; spec 03
    // section 3: `-0` is the integer 0.
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("admin", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = deterministic_native();
    let dave = test_key("dave", "dave");
    let mut call = make_call(
        TOOL_ADMIN_USER_CREATE,
        raw_args(&format!(
            r#"{{"name":"dave","public_key":"{}","not_after":-0}}"#,
            dave.public_key
        )),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    native.call(&mut call).unwrap();
    let stored = state.lookup(&dave.kid).unwrap();
    assert_eq!(stored.not_after, Some(0));
    assert_eq!(stored.name, "dave");
    assert!(!stored.admin);
}

#[test]
fn set_admin_argument_strictness() {
    // admin is REQUIRED and strict boolean: absent, null, number and
    // string are all invalid_params; the target entry (already admin) is
    // left untouched (spec 03 section 4).
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("root", "root");
    let target = admin_key("admin-b", "admin-b");
    seed(&[caller.clone(), target.clone()], &[], state.as_ref());
    let native = Native::new(NativeOptions::default());
    for admin in ["", ":null", ":1", ":\"yes\""] {
        let args = if admin.is_empty() {
            format!(r#"{{"kid":"{}"}}"#, target.kid)
        } else {
            format!(r#"{{"kid":"{}","admin"{}}}"#, target.kid, admin)
        };
        let mut call = make_call(
            TOOL_ADMIN_USER_SET_ADMIN,
            raw_args(&args),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.http_status, 400, "args: {args}");
        assert_eq!(err.code, codes::INVALID_PARAMS, "args: {args}");
    }
    assert!(state.lookup(&target.kid).unwrap().admin, "nothing mutated");
}

#[test]
fn admin_create_admin_mistyped_is_invalid_params() {
    // Mirrors the fixture admin-create-admin-mistyped: "true" (a string)
    // is not a JSON boolean -> invalid_params (spec 03 section 4).
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("root", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = Native::new(NativeOptions::default());
    let dave = test_key("dave", "dave");
    let mut call = make_call(
        TOOL_ADMIN_USER_CREATE,
        raw_args(&format!(
            r#"{{"name":"dave","public_key":"{}","admin":"true"}}"#,
            dave.public_key
        )),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 400);
    assert_eq!(err.code, codes::INVALID_PARAMS);
    assert!(state.lookup(&dave.kid).is_none());
}

#[test]
fn invite_create_admin_mistyped_is_invalid_params() {
    // Same rule as user_create: a present mistyped admin (string "true")
    // is not a JSON boolean -> invalid_params (spec 03 section 3).
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("root", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ADMIN_INVITE_CREATE,
        raw_args(r#"{"admin":"true"}"#),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 400);
    assert_eq!(err.code, codes::INVALID_PARAMS);
    assert!(state.view().invites.is_empty(), "nothing mutated");
}

#[test]
fn invite_ttl_member_decoys_are_invalid_params() {
    // String, boolean and fractional ttl_seconds are all invalid_params
    // (spec 03 section 3: integer only, judged on the JSON text).
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("root", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = deterministic_native();
    for ttl in ["\"60\"", "true", "1.5"] {
        let mut call = make_call(
            TOOL_ADMIN_INVITE_CREATE,
            raw_args(&format!(r#"{{"ttl_seconds":{ttl}}}"#)),
            Some(&caller),
            &caller.kid,
            Arc::clone(&state) as Arc<dyn StateStore>,
        );
        let err = native.call(&mut call).unwrap_err();
        assert_eq!(err.http_status, 400, "ttl {ttl}");
        assert_eq!(err.code, codes::INVALID_PARAMS, "ttl {ttl}");
    }
    // Duplicate member names keep the LAST value (parse_args map decode).
    let mut call = make_call(
        TOOL_ADMIN_INVITE_CREATE,
        raw_args(r#"{"ttl_seconds":1,"ttl_seconds":2}"#),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let res = native.call(&mut call).unwrap();
    assert_eq!(res.structured["expires_at"], NOW + 2);
}

#[test]
fn audit_target_names_target_on_failures() {
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("root", "root");
    seed(std::slice::from_ref(&caller), &[], state.as_ref());
    let native = Native::new(NativeOptions::default());

    // (a) user.create: valid name, small-order public key -> key_rejected,
    //     and the target is already the name (spec 03 section 8).
    let bad_pub = encode_b64url(&[1u8; 32]);
    let mut call = make_call(
        TOOL_ADMIN_USER_CREATE,
        raw_args(&format!(r#"{{"name":"dave","public_key":"{bad_pub}"}}"#)),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.code, codes::KEY_REJECTED);
    assert_eq!(call.target, "dave");

    // (b) user.set_admin: well-formed kid, admin mistyped (number) ->
    //     invalid_params, and the target is already the kid.
    let alice = test_key("alice", "alice");
    seed(std::slice::from_ref(&alice), &[], state.as_ref());
    let mut call = make_call(
        TOOL_ADMIN_USER_SET_ADMIN,
        raw_args(&format!(r#"{{"kid":"{}","admin":1}}"#, alice.kid)),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.code, codes::INVALID_PARAMS);
    assert_eq!(call.target, alice.kid);
}

#[test]
fn enroll_audit_target_follows_name_validation() {
    // An invalid name must leave the audit target empty: Go and TypeScript
    // assign the target only after ValidName passes (review L-7).
    let state = Arc::new(MemoryState::new());
    let entry = test_key("enroll-aud", "enroll-aud");
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(r#"{"code":"AAA","name":"bad name!","public_key":"x"}"#),
        None,
        &entry.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.code, codes::INVALID_PARAMS);
    assert!(
        call.target.is_empty(),
        "invalid name must not become the audit target, got {:?}",
        call.target
    );

    // A valid enrollment carries the requested name as the target.
    let code = bootstrap_admin(
        state.as_ref(),
        NOW,
        600,
        NativeOptions {
            random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
        },
    )
    .unwrap();
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(&format!(
            r#"{{"code":"{code}","name":"first","public_key":"{}"}}"#,
            entry.public_key
        )),
        None,
        &entry.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    native.call(&mut call).unwrap();
    assert_eq!(call.target, "first");
}

#[test]
fn failed_tool_calls_mutate_nothing() {
    // Tool-specific checks still precede each tool's OWN mutation (enroll:
    // put_key/remove_invite after the invite+name+kid checks; rotate:
    // remove/put after key_exists; user.create: put after
    // current_admin+name+kid; set_admin: put after
    // current_admin+target+last_admin; revoke: remove after current_admin
    // +target+last_admin; invite.create: put after current_admin;
    // invite.revoke: remove after found+expiry; bootstrap: put after the
    // ttl check). The one shared mutation that runs BEFORE those checks is
    // purge_expired_invites in the invite-editing tools; any later failure
    // rolls it back with the whole edit. This pins the tool-level half; the
    // store-level commit-only-on-Ok property (a closure that DOES mutate
    // then fail rolls back) is pinned by state.rs::rollback_on_error.
    let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let root = admin_key("root", "root");
    let bob_signing = test_signing("bob");
    let alice = test_key("alice", "alice");
    let bob = test_key("bob", "bob");
    let expired = InviteRecord {
        invite_id: "expired".into(),
        created_by: "root".into(),
        created_at: NOW - 1,
        expires_at: NOW,
        ..Default::default()
    };
    seed(
        &[root.clone(), alice.clone(), bob.clone()],
        &[expired],
        state.as_ref(),
    );
    let native = deterministic_native();
    let call = |tool: &'static str,
                args: String,
                caller: Option<&RegistryEntry>,
                kid: &str|
     -> Result<NativeResult, JackError> {
        let mut c = make_call(tool, raw_args(&args), caller, kid, Arc::clone(&state));
        native.call(&mut c)
    };

    // 1. enroll: valid seeded invite, name taken -> 409 name_taken AFTER
    //    the invite check but BEFORE put_key/remove_invite; the failure
    //    does not consume the invite (spec 03 section 3.2 step 7).
    let code = bootstrap_admin(
        state.as_ref(),
        NOW,
        600,
        NativeOptions {
            random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
        },
    )
    .unwrap();
    let before: crate::server::state::StateView = state.view();
    let fresh = test_key("fresh", "root");
    let err = call(
        TOOL_ENROLL,
        format!(
            r#"{{"code":"{code}","name":"root","public_key":"{}"}}"#,
            fresh.public_key
        ),
        None,
        &fresh.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 409);
    assert_eq!(err.code, codes::NAME_TAKEN);
    assert_eq!(before, state.view());
    // bootstrap_admin purged the seeded expired invite in its own edit, so
    // only the bootstrap invite is stored (the failed enroll rolled back).
    assert_eq!(state.view().invites.len(), 1);
    assert!(state.lookup(&fresh.kid).is_none());

    // 2. rotate: valid proof but the new kid is already registered ->
    //    mid-closure key_exists BEFORE remove_key/put_key (spec 03
    //    section 3.1 order: arguments, new key, proof, existence).
    let proof = encode_b64url(
        &bob_signing.sign(rotate_proof_string(AUD, &alice.kid, &bob.kid, NOW).as_bytes()),
    );
    let before = state.view();
    let err = call(
        TOOL_ROTATE_KEY,
        format!(r#"{{"public_key":"{}","proof":"{proof}"}}"#, bob.public_key),
        Some(&alice),
        &alice.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 409);
    assert_eq!(err.code, codes::KEY_EXISTS);
    assert_eq!(before, state.view());

    // 3. rotate with an invalid proof fails before the closure.
    let bad_proof = encode_b64url(&[0u8; 64]);
    let err = call(
        TOOL_ROTATE_KEY,
        format!(
            r#"{{"public_key":"{}","proof":"{bad_proof}"}}"#,
            bob.public_key
        ),
        Some(&alice),
        &alice.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 400);
    assert_eq!(err.code, codes::INVALID_PROOF);
    assert_eq!(before, state.view());

    // 4. user.create with stale members: `scopes`/`kind` are inert
    //    (lookup by exact member name), so this mirrors the fixture
    //    admin-create-stale-members-inert and SUCCEEDS, creating the
    //    entry with admin=false (spec 03 section 3).
    let esc = test_key("esc", "esc");
    let res = call(
        TOOL_ADMIN_USER_CREATE,
        format!(
            r#"{{"name":"esc","public_key":"{}","scopes":["read","admin"],"kind":"agent"}}"#,
            esc.public_key
        ),
        Some(&root),
        &root.kid,
    )
    .unwrap();
    assert_eq!(res.structured["kid"], esc.kid.as_str());
    let stored = state.lookup(&esc.kid).expect("entry created");
    assert!(!stored.admin);
    let after_create = state.view();

    // 5. user.set_admin: the sole admin demotes itself -> mid-closure
    //    last_admin AFTER current_admin+target, BEFORE put_key (spec 03
    //    section 4 rule 4), unchanged.
    let err = call(
        TOOL_ADMIN_USER_SET_ADMIN,
        format!(r#"{{"kid":"{}","admin":false}}"#, root.kid),
        Some(&root),
        &root.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 409);
    assert_eq!(err.code, codes::LAST_ADMIN);
    assert_eq!(after_create, state.view());

    // 6. user.revoke: the sole admin revokes itself -> mid-closure
    //    last_admin BEFORE remove_key, unchanged.
    let err = call(
        TOOL_ADMIN_USER_REVOKE,
        format!(r#"{{"kid":"{}"}}"#, root.kid),
        Some(&root),
        &root.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 409);
    assert_eq!(err.code, codes::LAST_ADMIN);
    assert_eq!(after_create, state.view());

    // 7. invite.create: a mistyped ttl is invalid_params before the
    //    transaction, unchanged.
    let err = call(
        TOOL_ADMIN_INVITE_CREATE,
        r#"{"ttl_seconds":"60"}"#.to_owned(),
        Some(&root),
        &root.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 400);
    assert_eq!(err.code, codes::INVALID_PARAMS);
    assert_eq!(after_create, state.view());

    // 8. invite.revoke: the invite expired at NOW -> 404 unknown_target
    //    BEFORE remove_invite, unchanged.
    let err = call(
        TOOL_ADMIN_INVITE_REVOKE,
        r#"{"invite_id":"expired"}"#.to_owned(),
        Some(&root),
        &root.kid,
    )
    .unwrap_err();
    assert_eq!(err.http_status, 404);
    assert_eq!(err.code, codes::UNKNOWN_TARGET);
    assert_eq!(after_create, state.view());

    // 9. bootstrap_admin: ttl 0 -> Err before any update, unchanged.
    let err = bootstrap_admin(
        state.as_ref(),
        NOW,
        0,
        NativeOptions {
            random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
        },
    )
    .expect_err("zero bootstrap TTL must be rejected");
    assert_eq!(err.http_status, 0);
    assert_eq!(err.code, "internal_error");
    assert_eq!(after_create, state.view());
}

#[test]
fn enroll_key_ttl_overflow_fails_closed() {
    let state = Arc::new(MemoryState::new());
    let invite = InviteRecord {
        invite_id: invite_id_of(&[0xA5; 32]),
        created_by: "root".to_owned(),
        created_at: NOW,
        expires_at: NOW + 600,
        // An attacker-crafted (or corrupted) store could hold this; the
        // TTL math must fail closed, not wrap into an immortal key.
        key_ttl_seconds: Some(i64::MAX),
        ..Default::default()
    };
    seed(&[], &[invite], state.as_ref());
    let before: crate::server::state::StateView = state.view();
    let fresh = test_key("fresh", "newcomer");
    let native = deterministic_native();
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
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 500);
    assert_eq!(err.code, "internal_error");
    // The invite was NOT consumed and no key was added.
    assert_eq!(before, state.view());
}

#[test]
fn invite_create_purges_expired_and_keeps_live() {
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("admin", "root");
    let expired = InviteRecord {
        invite_id: "expired".into(),
        created_by: caller.kid.clone(),
        created_at: NOW - 100,
        expires_at: NOW - 1,
        ..Default::default()
    };
    let live = InviteRecord {
        invite_id: "live".into(),
        created_by: caller.kid.clone(),
        created_at: NOW,
        expires_at: NOW + 100,
        ..Default::default()
    };
    seed(
        std::slice::from_ref(&caller),
        &[expired, live],
        state.as_ref(),
    );
    let native = deterministic_native();
    let mut call = make_call(
        TOOL_ADMIN_INVITE_CREATE,
        raw_args("{}"),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    // Advance the verifier clock past the seeded expiry.
    call.now = NOW + 1;
    native.call(&mut call).unwrap();
    let invites = state.view().invites;
    assert_eq!(
        invites.len(),
        2,
        "the live seed and the new invite must stay"
    );
    let ids: Vec<&str> = invites.iter().map(|i| i.invite_id.as_str()).collect();
    assert!(
        !ids.contains(&"expired"),
        "the expired invite must be purged"
    );
    assert!(ids.contains(&"live"), "a live invite is never purged");
}

#[test]
fn failed_invite_edits_keep_expired_invites() {
    let state = Arc::new(MemoryState::new());
    let caller = admin_key("admin", "root");
    let raw = [0x42u8; 32];
    let code = encode_b64url(&raw);
    let expired = InviteRecord {
        invite_id: invite_id_of(&raw),
        created_by: caller.kid.clone(),
        created_at: NOW - 200,
        expires_at: NOW - 1,
        ..Default::default()
    };
    seed(std::slice::from_ref(&caller), &[expired], state.as_ref());
    let native = deterministic_native();
    // An expired invite still answers invalid_invite on enroll ...
    let fresh = test_key("fresh", "fresh");
    let mut call = make_call(
        TOOL_ENROLL,
        raw_args(&format!(
            r#"{{"code":"{code}","name":"fresh","public_key":"{}"}}"#,
            fresh.public_key
        )),
        None,
        &fresh.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 403);
    assert_eq!(err.code, codes::INVALID_INVITE);
    // ... and unknown_target on revoke. Both updates failed, so the whole
    // atomic edit (purge included) rolled back: the record stays stored.
    let mut call = make_call(
        TOOL_ADMIN_INVITE_REVOKE,
        raw_args(&format!(r#"{{"invite_id":"{}"}}"#, invite_id_of(&raw))),
        Some(&caller),
        &caller.kid,
        Arc::clone(&state) as Arc<dyn StateStore>,
    );
    let err = native.call(&mut call).unwrap_err();
    assert_eq!(err.http_status, 404);
    assert_eq!(err.code, codes::UNKNOWN_TARGET);
    let invites = state.view().invites;
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].invite_id, invite_id_of(&raw));
}

#[test]
fn bootstrap_admin_purges_expired_invites() {
    let state = Arc::new(MemoryState::new());
    let expired = InviteRecord {
        invite_id: "expired".into(),
        created_by: "old".into(),
        created_at: 0,
        expires_at: 1,
        ..Default::default()
    };
    seed(&[], &[expired], state.as_ref());
    bootstrap_admin(state.as_ref(), NOW, 600, NativeOptions::default()).unwrap();
    let invites = state.view().invites;
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].created_by, "bootstrap");
}
