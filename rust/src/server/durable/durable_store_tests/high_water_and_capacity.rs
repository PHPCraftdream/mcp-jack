use super::*;

#[test]
fn high_water_latch_refuses_to_lower() {
    let mut high_water = HighWater::new(200);
    assert!(high_water.raise(250));
    assert_eq!(high_water.get(), 250);
    assert!(!high_water.raise(150));
    assert_eq!(high_water.get(), 250, "a stale sample must never lower H");
    assert!(!high_water.raise(250));
}

#[test]
fn sample_below_high_water_latches_clock_unsafe_and_persists() {
    let sandbox = Sandbox::new();
    // Samples: open 200, three 200s for the first commit, then 150 on the
    // next entry sample.
    let store = initialized(&sandbox, &[200, 200, 200, 200, 150]);
    let (kid, nonce) = pair(1);
    drop(store.reserve(&admission(&kid, &nonce, 200)).unwrap());
    // Entry sample 150 is below H=200: latch first, then clock_unsafe.
    let error = store
        .reserve(&admission(&b64(2, 32), &b64(3, 16), 150))
        .unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "clock_unsafe");
    // Any later admission is refused: the store is fenced.
    let error = store
        .reserve(&admission(&b64(4, 32), &b64(5, 16), 200))
        .unwrap_err();
    assert_eq!(error.code, "durability_unavailable");
    // A fenced store preserves recovery-required status on close (durable_store.rs:861-869; Go: durable/store.go:219-227).
    assert_eq!(store.close(), Err(DurableStoreError::RecoveryRequired));
    // The latch persists: reopen fails closed; inspect shows the latch.
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[201])),
        Err(DurableStoreError::RecoveryRequired)
    ));
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert!(snapshot.unsafe_latched);
    assert!(snapshot.dirty);
    assert_eq!(snapshot.high_water, 200);
}

#[test]
fn out_of_domain_clock_sample_latches_unsafe() {
    let sandbox = Sandbox::new();
    DurableNonceStore::initialize_unused(&sandbox.file(), &options(), clock(&[100])).unwrap();
    // Open sample 100 and entry sample 100 are in domain; the intent sample
    // -1 is out of domain.
    let store =
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100, 100, -1])).unwrap();
    let (kid, nonce) = pair(1);
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "clock_unsafe");
    // The store is fenced after an unsafe latch.
    let error = store
        .reserve(&admission(&b64(3, 32), &b64(4, 16), 100))
        .unwrap_err();
    assert_eq!(error.code, "durability_unavailable");
    assert_eq!(
        store.close().unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
}

#[test]
fn reopen_below_high_water_fails_closed_before_absence() {
    // Purge at H=216 then restart at 215: fail closed (spec section 7).
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[216]);
    let (kid, nonce) = pair(1);
    drop(store.reserve(&admission(&kid, &nonce, 186)).unwrap());
    store.close().unwrap();
    // Startup below H latches rollback and requires recovery (Go: durable/store.go:191-196; spec §3).
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[215])),
        Err(DurableStoreError::RecoveryRequired)
    ));
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert!(snapshot.unsafe_latched);
    assert_eq!(
        snapshot.live.len(),
        1,
        "no expiry-based absence may precede H"
    );
}

#[test]
fn reconcile_moves_exact_row_to_terminal_tombstone() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let metadata = store.snapshot_metadata();
    let (kid, nonce) = pair(1);
    let receipt = receipt_for(&metadata, &kid, &nonce, [7; 16], 100, 100);
    store
        .seed_records(&[record_of(
            &metadata,
            RecordKind::Intent,
            &kid,
            &nonce,
            [7; 16],
            100,
            100,
        )])
        .unwrap();
    // An outstanding intent keeps the dirty epoch; close is fenced.
    assert_eq!(
        store.close().unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert!(snapshot.dirty);
    assert_eq!(snapshot.intents.len(), 1);
    assert_eq!(snapshot.intents[0], receipt);
    let hash = snapshot.hash.clone();
    // Wrong expected hash is refused without any change.
    let wrong_hash = "wrong-hash-wrong-hash-wrong-hash-wrong-";
    assert_eq!(
        reconcile_unknown(&sandbox.file(), &options(), wrong_hash, &receipt).unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
    assert_eq!(
        inspect_recovery(&sandbox.file(), &options()).unwrap().hash,
        hash
    );
    reconcile_unknown(&sandbox.file(), &options(), &hash, &receipt).unwrap();
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert_eq!(snapshot.tombstones.len(), 1);
    assert_eq!(snapshot.intents.len(), 0);
    // Already terminal: idempotent. A missing record is not proof of abort.
    reconcile_unknown(&sandbox.file(), &options(), &snapshot.hash, &receipt).unwrap();
    let missing_metadata = snapshot_metadata_helper(&sandbox);
    let missing = receipt_for(
        &missing_metadata,
        &b64(3, 32),
        &b64(4, 16),
        [8; 16],
        100,
        100,
    );
    assert_eq!(
        reconcile_unknown(&sandbox.file(), &options(), &snapshot.hash, &missing).unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
    // Reconciliation leaves the dirty epoch closed until recovery (Go: durable/snapshot.go:45-46; spec §4).
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])),
        Err(DurableStoreError::RecoveryRequired)
    ));
}

#[test]
fn clean_store_refuses_reconcile() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    store.close().unwrap();
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert!(!snapshot.dirty);
    let metadata = DurableMetadata {
        deployment: options().deployment_id,
        store_id: [0; 16],
        generation: 1,
        owner: 1,
        window: WINDOW,
        high_water: HighWater::new(100),
        live: 0,
        intents: 0,
        tombstones: 0,
        dirty: false,
        unsafe_latched: false,
    };
    let (kid, nonce) = pair(1);
    let receipt = receipt_for(&metadata, &kid, &nonce, [7; 16], 100, 100);
    assert_eq!(
        reconcile_unknown(&sandbox.file(), &options(), &snapshot.hash, &receipt).unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
}

#[test]
fn tombstones_never_expire_and_block_redelivery() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100, 1000]);
    let metadata = store.snapshot_metadata();
    let (kid, nonce) = pair(1);
    let tombstone = record_of(
        &metadata,
        RecordKind::Tombstone,
        &kid,
        &nonce,
        [7; 16],
        70,
        100,
    );
    store.seed_records(&[tombstone]).unwrap();
    // Far past retainUntil=100 the tombstone is still present and still
    // conflicts; ordinary reservations expire normally.
    let (receipt, _) = store
        .reserve(&admission(&b64(5, 32), &b64(6, 16), 1000))
        .unwrap();
    assert_eq!(receipt.retain_until, 1030);
    let error = store.reserve(&admission(&kid, &nonce, 1000)).unwrap_err();
    assert_eq!(error.code, "durability_unavailable");
    let state = decoded(&sandbox);
    assert_eq!(state.tombstones.len(), 1);
    assert_eq!(state.live.len(), 1);
    // The 503 conflicting-tombstone outcome fenced the store.
    assert_eq!(
        store.close().unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
}

#[test]
fn capacity_4096_refuses_without_eviction() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let metadata = store.snapshot_metadata();
    let records = seeded_live(&metadata, 4095, RecordKind::Live, 100, 100);
    store.seed_records(&records).unwrap();
    // The 4096th slot is taken by a real intent + final conversion.
    let (kid, nonce) = pair(1);
    drop(store.reserve(&admission(&kid, &nonce, 100)).unwrap());
    let state = decoded(&sandbox);
    assert_eq!(state.live.len(), 4096);
    // The next admission is refused atomically, with no live row evicted.
    let before = sandbox.bytes();
    let error = store
        .reserve(&admission(&b64(6, 32), &b64(7, 16), 100))
        .unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "capacity_exhausted");
    assert_eq!(sandbox.bytes(), before);
    assert_eq!(decoded(&sandbox).live.len(), 4096);
    // capacity_exhausted is definite: no fence, so the close is clean.
    store.close().unwrap();
}

#[test]
fn tombstone_capacity_64_refuses() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let metadata = store.snapshot_metadata();
    let records = seeded_live(&metadata, 64, RecordKind::Tombstone, 70, 100);
    store.seed_records(&records).unwrap();
    let error = store
        .reserve(&admission(&b64(6, 32), &b64(7, 16), 100))
        .unwrap_err();
    assert_eq!(error.code, "capacity_exhausted");
    assert_eq!(decoded(&sandbox).tombstones.len(), 64);
    // The close refuses because the tombstone cap needs recovery, not because
    // the refusal fenced the store.
    assert_eq!(
        store.close().unwrap_err(),
        DurableStoreError::RecoveryRequired
    );
}

#[test]
fn purge_is_bounded_to_128_removals_per_transaction() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100, 131]);
    let metadata = store.snapshot_metadata();
    let records = seeded_live(&metadata, 200, RecordKind::Live, 90, 100);
    store.seed_records(&records).unwrap();
    assert_eq!(decoded(&sandbox).live.len(), 200);
    // First admission at 131 advances H and removes at most 128 expired rows.
    drop(
        store
            .reserve(&admission(&b64(6, 32), &b64(7, 16), 131))
            .unwrap(),
    );
    let state = decoded(&sandbox);
    assert_eq!(state.metadata.high_water.get(), 131);
    assert_eq!(
        state.live.len(),
        73,
        "128 expired rows removed plus the new one"
    );
    // The next transaction removes the remaining 72.
    drop(
        store
            .reserve(&admission(&b64(8, 32), &b64(9, 16), 131))
            .unwrap(),
    );
    // The two new rows are live (retain_until 161); every expired row is gone.
    let state = decoded(&sandbox);
    assert_eq!(state.live.len(), 2);
    assert_eq!(state.expiry.len(), 2);
    store.close().unwrap();
}
