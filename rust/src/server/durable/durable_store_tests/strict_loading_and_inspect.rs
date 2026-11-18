use super::*;

#[test]
fn strict_loader_rejects_trailing_bytes_and_corruption() {
    // Strict encoded-file rejection (durable_format.rs:615-699; spec §3).
    let (bytes, _, _, _) = valid_fixture();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        decode_state(&trailing),
        Err(DurableStoreError::InvalidStore)
    ));
    let mut flipped = bytes.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0xff;
    assert!(matches!(
        decode_state(&flipped),
        Err(DurableStoreError::InvalidStore)
    ));
    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(matches!(
        decode_state(&truncated),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn strict_loader_rejects_counter_and_cap_violations() {
    // Go: durable/metadata.go:118-125; spec §3 and §6 require exact counts and caps.
    let (_, metadata, key, receipt) = valid_fixture();
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let payload = strip_seal(&metadata_sealed).to_vec();
    // Metadata claims one more live row than the file contains.
    let mut wrong_count = payload.clone();
    let live_offset = wrong_count.len() - 13;
    wrong_count[live_offset..live_offset + 4].copy_from_slice(&1u32.to_be_bytes());
    let file = build_file(&seal_payload(&wrong_count), &[], &[], &[], &[], &[]);
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // A row present under a zeroed metadata counter is the mirror rejection.
    let record = record_of(
        &metadata,
        RecordKind::Live,
        &receipt.kid,
        &receipt.nonce,
        receipt.operation_id,
        100,
        100,
    );
    let mut row = key.to_vec();
    row.extend_from_slice(&seal_payload(&payload_of_record(&record)));
    let mut zeroed = metadata.clone();
    zeroed.live = 0;
    let zero_sealed = encode_metadata(&zeroed).unwrap();
    let file = build_file(
        &zero_sealed,
        &[row],
        &[],
        &[],
        &[expiry_key(130, &key)],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // Aggregate cap: 65 tombstones above the 64 cap is rejected at load.
    let mut over_cap = payload.clone();
    let tombstone_offset = over_cap.len() - 9;
    over_cap[tombstone_offset..tombstone_offset + 4].copy_from_slice(&65u32.to_be_bytes());
    let file = build_file(&seal_payload(&over_cap), &[], &[], &[], &[], &[]);
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn strict_loader_rejects_duplicate_and_inconsistent_indexes() {
    // Go: durable/layout.go:16-94; spec §3 requires exact primary/index agreement.
    let (_, metadata, key, receipt) = valid_fixture();
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let record = record_of(
        &metadata,
        RecordKind::Live,
        &receipt.kid,
        &receipt.nonce,
        receipt.operation_id,
        100,
        100,
    );
    let mut row = key.to_vec();
    row.extend_from_slice(&seal_payload(&payload_of_record(&record)));
    let ops = [(receipt.operation_id, key)];
    let index = expiry_key(130, &key);
    // The same encoded key twice in one section, with a counter admitting both.
    let mut doubled = metadata.clone();
    doubled.live = 2;
    let doubled_sealed = encode_metadata(&doubled).unwrap();
    let file = build_file(
        &doubled_sealed,
        &[row.clone(), row.clone()],
        &[],
        &[],
        &[index],
        &ops,
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // Missing expiry index entry for a live row.
    let file = build_file(&metadata_sealed, &[row.clone()], &[], &[], &[], &ops);
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // Duplicate expiry index entries.
    let file = build_file(
        &metadata_sealed,
        &[row.clone()],
        &[],
        &[],
        &[index, index],
        &ops,
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // Expiry entry that no live row produced.
    let file = build_file(
        &metadata_sealed,
        &[row.clone()],
        &[],
        &[],
        &[expiry_key(131, &key)],
        &ops,
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // The same operation identity stored twice in the operation index.
    let other = record_of(
        &metadata,
        RecordKind::Intent,
        &b64(3, 32),
        &b64(4, 16),
        receipt.operation_id,
        100,
        100,
    );
    let mut other_key = [0; 48];
    other_key[..32].copy_from_slice(&decode_b64url(&b64(3, 32)).unwrap());
    other_key[32..].copy_from_slice(&decode_b64url(&b64(4, 16)).unwrap());
    let mut other_row = other_key.to_vec();
    other_row.extend_from_slice(&seal_payload(&payload_of_record(&other)));
    let mut mixed = metadata.clone();
    mixed.intents = 1;
    let mixed_sealed = encode_metadata(&mixed).unwrap();
    let file = build_file(
        &mixed_sealed,
        &[row],
        &[other_row],
        &[],
        &[index],
        &[
            (receipt.operation_id, key),
            (receipt.operation_id, other_key),
        ],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn strict_loader_rejects_wrong_typed_and_inconsistent_records() {
    // Go: durable/record.go:42-72; spec §3 requires typed records and ts/W/expiry consistency.
    let (_, metadata, key, receipt) = valid_fixture();
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let build = |receipt: DurableReceipt, kind_value: Option<u8>| {
        let record = DurableRecord {
            kind: RecordKind::Live,
            key,
            store_id: metadata.store_id,
            receipt,
        };
        let mut payload = payload_of_record(&record);
        if let Some(kind_value) = kind_value {
            payload[1] = kind_value; // unsupported record kind byte
        }
        let mut row = key.to_vec();
        row.extend_from_slice(&seal_payload(&payload));
        row
    };
    // A record kind byte outside the version-1 domain.
    let row = build(receipt.clone(), Some(9));
    let file = build_file(
        &metadata_sealed,
        &[row],
        &[],
        &[],
        &[expiry_key(130, &key)],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // ts/retainUntil inconsistency.
    let mut inconsistent = receipt.clone();
    inconsistent.retain_until = 131;
    let row = build(inconsistent, None);
    let file = build_file(
        &metadata_sealed,
        &[row],
        &[],
        &[],
        &[expiry_key(131, &key)],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    // A receipt whose intent_id does not recompute is rejected.
    let mut wrong_intent = receipt.clone();
    wrong_intent.intent_id = b64(11, 32);
    let row = build(wrong_intent, None);
    let file = build_file(
        &metadata_sealed,
        &[row],
        &[],
        &[],
        &[expiry_key(130, &key)],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn strict_loader_rejects_wrong_store_binding() {
    // Go: durable/record.go:42-48; spec §3 binds every row to its store identity.
    let (_, metadata, key, receipt) = valid_fixture();
    let mut foreign = metadata.clone();
    foreign.store_id = [1; 16];
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let record = record_of(
        &foreign,
        RecordKind::Live,
        &receipt.kid,
        &receipt.nonce,
        receipt.operation_id,
        100,
        100,
    );
    let mut row = key.to_vec();
    row.extend_from_slice(&seal_payload(&payload_of_record(&record)));
    let file = build_file(
        &metadata_sealed,
        &[row],
        &[],
        &[],
        &[expiry_key(130, &key)],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
}

#[test]
fn inspect_reports_fields_and_sensitive_hash_changes_with_state() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let (kid, nonce) = pair(1);
    drop(store.reserve(&admission(&kid, &nonce, 100)).unwrap());
    store.close().unwrap();
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert_eq!(snapshot.deployment_id, "candidate-test-deployment");
    assert_eq!(snapshot.window, WINDOW);
    assert_eq!(snapshot.high_water, 100);
    assert!(!snapshot.dirty);
    assert_eq!(snapshot.live.len(), 1);
    assert!(!snapshot.store_id.is_empty());
    let hash = snapshot.hash.clone();
    // Any state change binds a different full-graph hash.
    let store = DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])).unwrap();
    let metadata = store.snapshot_metadata();
    store
        .seed_records(&[record_of(
            &metadata,
            RecordKind::Live,
            &b64(3, 32),
            &b64(4, 16),
            [7; 16],
            100,
            100,
        )])
        .unwrap();
    store.close().unwrap();
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert_ne!(snapshot.hash, hash);
    assert_eq!(snapshot.live.len(), 2);
    // A store held open by a live owner cannot be inspected concurrently.
    let store = DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])).unwrap();
    // The Linux owner marker excludes concurrent inspection (Go: durable/recovery_inspect.go:33-38).
    assert!(matches!(
        inspect_recovery(&sandbox.file(), &options()),
        Err(DurableStoreError::Unavailable)
    ));
    store.close().unwrap();
}

#[test]
fn oversized_logical_file_is_rejected() {
    // The format cap is 16 MiB (spec §3/§6); decode_state returns InvalidStore above MAX_FILE_BYTES.
    let (_, metadata, key, receipt) = valid_fixture();
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let record = record_of(
        &metadata,
        RecordKind::Live,
        &receipt.kid,
        &receipt.nonce,
        receipt.operation_id,
        100,
        100,
    );
    let mut row = key.to_vec();
    row.extend_from_slice(&seal_payload(&payload_of_record(&record)));
    // 16 MiB + 1 of padding inside an oversized padded row section: the
    // framing parser must reject it long before any cap arithmetic.
    row.resize(MAX_FILE_BYTES + 1, 0);
    let file = build_file(
        &metadata_sealed,
        &[row],
        &[],
        &[],
        &[],
        &[(receipt.operation_id, key)],
    );
    assert!(matches!(
        decode_state(&file),
        Err(DurableStoreError::InvalidStore)
    ));
    assert!(file.len() > MAX_FILE_BYTES);
}

#[test]
fn close_drains_leases_and_refuses_reserve_while_closing() {
    let sandbox = Sandbox::new();
    let current = Arc::new(AtomicI64::new(100));
    DurableNonceStore::initialize_unused(&sandbox.file(), &options(), {
        let current = Arc::clone(&current);
        move || current.load(Ordering::SeqCst)
    })
    .unwrap();
    let store = Arc::new(
        DurableNonceStore::open(
            &sandbox.file(),
            &options(),
            atomic_clock(Arc::clone(&current)),
        )
        .unwrap(),
    );
    let (kid, nonce) = pair(1);
    let (_receipt, lease) = store.reserve(&admission(&kid, &nonce, 100)).unwrap();
    let (close_tx, close_rx) = std::sync::mpsc::channel();
    {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let _ = close_tx.send(store.close());
        });
    }
    // The close is now draining while the lease is still held.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let (probe_tx, probe_rx) = std::sync::mpsc::channel();
    {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let _ = probe_tx.send(store.reserve(&admission(&b64(4, 32), &b64(5, 16), 100)));
        });
    }
    let probe = probe_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("reserve during closing must return promptly");
    let error = probe.unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "durability_unavailable");
    // Releasing the lease lets the drain finish; a closing refusal must not
    // have fenced the store.
    drop(lease);
    let closed = close_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("close must finish after the lease is dropped");
    closed.unwrap();
    assert!(!sandbox.file().with_file_name("nonce-store.owner").exists());
}

#[test]
fn open_refuses_clean_file_with_unresolved_intents() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    store.close().unwrap();
    let mut metadata = snapshot_metadata_helper(&sandbox);
    assert!(!metadata.dirty);
    let (kid, nonce) = pair(1);
    let record = record_of(
        &metadata,
        RecordKind::Intent,
        &kid,
        &nonce,
        [7; 16],
        100,
        100,
    );
    let mut row = record.key.to_vec();
    row.extend_from_slice(&seal_payload(&payload_of_record(&record)));
    metadata.intents = 1;
    let file = build_file(
        &encode_metadata(&metadata).unwrap(),
        &[],
        &[row],
        &[],
        &[],
        &[(record.receipt.operation_id, record.key)],
    );
    fs::write(sandbox.file(), &file).unwrap();
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])),
        Err(DurableStoreError::RecoveryRequired)
    ));
    // Recovery inspection still loads the same file.
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert_eq!(snapshot.intents.len(), 1);
    assert!(!snapshot.dirty);
}

#[test]
fn open_refuses_clean_file_at_tombstone_cap() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    store.close().unwrap();
    let mut metadata = snapshot_metadata_helper(&sandbox);
    assert!(!metadata.dirty);
    let template = seeded_live(&metadata, 64, RecordKind::Tombstone, 70, 100);
    let mut rows = Vec::new();
    let mut operations = Vec::new();
    for record in &template {
        let mut row = record.key.to_vec();
        row.extend_from_slice(&seal_payload(&payload_of_record(record)));
        rows.push(row);
        operations.push((record.receipt.operation_id, record.key));
    }
    metadata.tombstones = 64;
    let file = build_file(
        &encode_metadata(&metadata).unwrap(),
        &[],
        &[],
        &rows,
        &[],
        &operations,
    );
    fs::write(sandbox.file(), &file).unwrap();
    assert!(matches!(
        DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])),
        Err(DurableStoreError::RecoveryRequired)
    ));
    assert!(inspect_recovery(&sandbox.file(), &options()).is_ok());
}

#[test]
fn capacity_refusal_rolls_back_high_water_raise() {
    let sandbox = Sandbox::new();
    // Samples: open 100; reserve at 120 (entry, intent) hits the combined-row
    // cap after the staged intent sample raised H; then two 110 samples prove
    // that a smaller clock sample still lands in domain.
    let store = initialized(&sandbox, &[100, 120, 120, 110, 110]);
    let metadata = store.snapshot_metadata();
    // 4096 live rows, none expired at now=120 (retained until 130): nothing is
    // purged and the cap is exhausted.
    let records = seeded_live(&metadata, 4096, RecordKind::Live, 100, 100);
    store.seed_records(&records).unwrap();
    let error = store
        .reserve(&admission(&b64(6, 32), &b64(7, 16), 120))
        .unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "capacity_exhausted");
    // The staged high-water raise is discarded: memory and disk both keep H=100
    // and all 4096 rows.
    assert_eq!(store.snapshot_metadata().high_water.get(), 100);
    assert_eq!(decoded(&sandbox).metadata.high_water.get(), 100);
    assert_eq!(decoded(&sandbox).live.len(), 4096);
    // A smaller clock sample is still >= the durable H: the store keeps
    // serving with the same definite, non-fencing refusal (no clock_unsafe).
    let error = store
        .reserve(&admission(&b64(8, 32), &b64(9, 16), 110))
        .unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "capacity_exhausted");
    assert_eq!(store.snapshot_metadata().high_water.get(), 100);
    store.close().unwrap();
}

#[test]
fn poisoned_lock_fences_the_store() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    // A panic while the lock is held poisons it.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.poison_for_test();
    }));
    let Err(payload) = outcome else {
        panic!("poisoning panic did not propagate");
    };
    assert!(
        payload
            .downcast_ref::<&str>()
            .is_some_and(|message| *message == "poison the session lock")
            || payload
                .downcast_ref::<String>()
                .is_some_and(|message| message == "poison the session lock"),
        "unexpected poisoning panic payload"
    );
    // The poisoned lock fences: the next admission is refused, not resumed.
    let (kid, nonce) = pair(1);
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "durability_unavailable");
    // A fenced store preserves recovery-required status on close (durable_store.rs:861-869; Go: durable/store.go:219-227).
    assert_eq!(store.close(), Err(DurableStoreError::RecoveryRequired));
}
