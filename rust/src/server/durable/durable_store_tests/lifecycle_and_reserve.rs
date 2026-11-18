use super::*;

#[test]
fn owner_exclusivity_clean_close_and_reopen() {
    // Spec §2 requires exactly one lifetime store owner.
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    // Missing input is unavailable, never an implicit empty store (Go: durable/store.go:167-170; spec §3).
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), clock(&[100])),
        Err(DurableStoreError::Unavailable)
    ));
    assert!(!path.with_file_name("nonce-store.owner").exists());
    DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])).unwrap();
    // Existing store data is not replaced (Go: durable/store.go:109-123; spec §2).
    assert!(matches!(
        DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])),
        Err(DurableStoreError::Unavailable)
    ));
    assert_eq!(owner_generation(&sandbox), 1);
    let store = DurableNonceStore::open(&path, &options(), clock(&[100])).unwrap();
    // The held lifetime-owner marker refuses a second owner (Go: durable/store.go:167-170; spec §2).
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), clock(&[100])),
        Err(DurableStoreError::Unavailable)
    ));
    assert!(path.with_file_name("nonce-store.owner").exists());
    assert_eq!(owner_generation(&sandbox), 2);
    store.close().unwrap();
    store.close().unwrap();
    assert!(!path.with_file_name("nonce-store.owner").exists());
    let reopened = DurableNonceStore::open(&path, &options(), clock(&[100])).unwrap();
    assert_eq!(owner_generation(&sandbox), 3);
    reopened.close().unwrap();
}

#[test]
fn crash_left_owner_marker_fails_closed() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    let marker = path.with_file_name("nonce-store.owner");
    fs::write(&marker, b"stale").unwrap();
    // Existing owner marker blocks both paths; exactly one owner is allowed (spec §2).
    assert!(matches!(
        DurableNonceStore::open(&path, &options(), clock(&[100])),
        Err(DurableStoreError::Unavailable)
    ));
    assert!(matches!(
        DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])),
        Err(DurableStoreError::Unavailable)
    ));
    assert!(marker.exists());
}

#[test]
fn wrong_deployment_or_window_is_refused() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    store.close().unwrap();
    let mut wrong = options();
    wrong.deployment_id = "other-deployment".into();
    // Persisted deployment and window must match (durable_store.rs:780-784; Go: durable/snapshot.go:42-43; spec §3).
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &wrong, clock(&[100])),
        Err(DurableStoreError::InvalidStore)
    ));
    let mut wrong = options();
    wrong.window = 60;
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &wrong, clock(&[100])),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn reserve_commit_receipt_fields_and_replay() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let (kid, nonce) = pair(1);
    let (receipt, lease) = store.reserve(&admission(&kid, &nonce, 100)).unwrap();
    assert!(lease.valid());
    assert_eq!(receipt.version, FORMAT_VERSION);
    assert_eq!(receipt.deployment, "candidate-test-deployment");
    assert_eq!(receipt.timestamp, 100);
    assert_eq!(receipt.retain_until, 130);
    assert_eq!(receipt.high_water, 100);
    let metadata = store.snapshot_metadata();
    let mut key = [0; 48];
    key[..32].copy_from_slice(&decode_b64url(&kid).unwrap());
    key[32..].copy_from_slice(&decode_b64url(&nonce).unwrap());
    let expected = intent_id(
        &metadata,
        &key,
        &decode_b64url(&receipt.signature).unwrap(),
        &decode_b64url(&receipt.request_hash).unwrap(),
        &receipt.operation_id,
    );
    assert_eq!(receipt.intent_id, expected);
    let state = decoded(&sandbox);
    assert_eq!(state.live.len(), 1);
    assert_eq!(state.intents.len(), 0);
    // A replay is a pure 401: no write, no fence, no retention extension.
    let committed_bytes = sandbox.bytes();
    let error = store.reserve(&admission(&kid, &nonce, 110)).unwrap_err();
    assert_eq!(error.status, 401);
    assert_eq!(error.code, "replayed_nonce");
    assert_eq!(sandbox.bytes(), committed_bytes);
    let state = decoded(&sandbox);
    assert_eq!(state.live.values().next().unwrap().retain_until, 130);
    // A different body/request id cannot reuse a committed pair.
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.code, "replayed_nonce");
    assert_eq!(decoded(&sandbox).live.len(), 1);
    // The lease must be released before close, which drains serving leases.
    drop(lease);
    store.close().unwrap();
}

#[test]
fn different_kid_same_nonce_is_not_a_replay() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let (kid_a, nonce) = pair(1);
    let (kid_b, _) = pair(2);
    drop(store.reserve(&admission(&kid_a, &nonce, 100)).unwrap());
    drop(store.reserve(&admission(&kid_b, &nonce, 100)).unwrap());
    assert_eq!(decoded(&sandbox).live.len(), 2);
    store.close().unwrap();
}

#[test]
fn expiry_equality_is_live_reuse_needs_h_advance() {
    let sandbox = Sandbox::new();
    // Open 100; the first commit samples 100,100,100; the replay at ts=130
    // takes one entry sample (no H advance for a live duplicate); the second
    // commit samples 131,131,131.
    let store = initialized(&sandbox, &[100, 100, 100, 100, 130, 131]);
    let (kid, nonce) = pair(1);
    drop(store.reserve(&admission(&kid, &nonce, 100)).unwrap());
    // now == retainUntil stays live; H does not advance for a pure replay.
    let error = store.reserve(&admission(&kid, &nonce, 130)).unwrap_err();
    assert_eq!(error.code, "replayed_nonce");
    let state = decoded(&sandbox);
    assert_eq!(state.metadata.high_water.get(), 100);
    assert_eq!(state.live.len(), 1);
    // At 131 the H advance expires the row and the fresh pair is admitted.
    let (receipt, _) = store.reserve(&admission(&kid, &nonce, 131)).unwrap();
    assert_eq!(receipt.high_water, 131);
    let state = decoded(&sandbox);
    assert_eq!(state.metadata.high_water.get(), 131);
    assert_eq!(state.live.len(), 1);
    assert_eq!(state.live.values().next().unwrap().timestamp, 131);
    store.close().unwrap();
}

#[test]
fn delayed_intent_sample_freshness_refuses_without_commit() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100, 131]);
    let (kid, nonce) = pair(1);
    let before = sandbox.bytes();
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.status, 401);
    assert_eq!(error.code, "timestamp_out_of_window");
    let state = decoded(&sandbox);
    assert!(state.live.is_empty());
    assert!(state.intents.is_empty());
    assert_eq!(sandbox.bytes(), before);
    store.close().unwrap();
}

#[test]
fn delayed_final_sample_cleans_intent_and_refuses() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100, 100, 131]);
    let (kid, nonce) = pair(1);
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.status, 401);
    assert_eq!(error.code, "timestamp_out_of_window");
    let state = decoded(&sandbox);
    assert!(state.live.is_empty());
    assert!(
        state.intents.is_empty(),
        "the exact intent slot must be cleaned"
    );
    assert!(state.operations.is_empty());
    store.close().unwrap();
}

#[test]
fn changed_snapshot_between_intent_and_final_refuses() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100, 100, 100]);
    let (kid, nonce) = pair(1);
    let mut request = admission(&kid, &nonce, 100);
    request.snapshot_valid = |_now| false;
    let error = store.reserve(&request).unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "state_changed");
    assert!(decoded(&sandbox).intents.is_empty());
    // A definite refusal leaves the store serving: the intent was cleaned up,
    // so the close clears the dirty epoch.
    store.close().unwrap();
}

#[test]
fn out_of_domain_timestamp_is_client_error_not_clock_unsafe() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let (kid, nonce) = pair(1);
    let error = store
        .reserve(&admission(&kid, &nonce, 999_999_999_999))
        .unwrap_err();
    assert_eq!(error.status, 401);
    assert_eq!(error.code, "timestamp_out_of_window");
    assert!(decoded(&sandbox).live.is_empty());
    store.close().unwrap();
}
