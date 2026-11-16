//! Linux-gated tests for the durable nonce store: strict loading, intent and
//! final transactions, the high-water latch, tombstones, capacity limits,
//! bounded purge work, recovery inspect/reconcile, and owner exclusivity.
//! All clocks are injected; no real time is read.

use crate::encoding::{decode_b64url, encode_b64url};
use crate::server::durable_format::{
    decode_state, encode_metadata, expiry_key, intent_id, seal_payload, DurableMetadata,
    DurableReceipt, DurableRecord, DurableStoreError, HighWater, RecordKind, FORMAT_VERSION,
    MAX_FILE_BYTES,
};
use crate::server::durable_recovery::{inspect_recovery, reconcile_unknown};
use crate::server::durable_store::{DurableAdmission, DurableNonceStore, DurableStoreOptions};
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

const WINDOW: i64 = 30;

fn ok_snapshot(_now: i64) -> bool {
    true
}

fn options() -> DurableStoreOptions {
    DurableStoreOptions {
        deployment_id: "candidate-test-deployment".into(),
        window: WINDOW,
    }
}

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "jack-rust-durable-nonce-{}",
            encode_b64url(&random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("nonce-store")
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.file()).unwrap()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Scripted clock: returns the samples in order, then repeats the last one.
/// The sample semantics must match the store's real cadence (Go: Reserve):
/// one sample on open, then entry, intent, and final per reserve.
fn clock(samples: &[i64]) -> impl FnMut() -> i64 {
    let queue = Rc::new(RefCell::new(samples.to_vec()));
    move || {
        let mut queue = queue.borrow_mut();
        let sample = queue[0];
        if queue.len() > 1 {
            queue.remove(0);
        }
        sample
    }
}

fn b64(seed: u8, size: usize) -> String {
    let bytes: Vec<u8> = (0..size)
        .map(|i| seed.wrapping_add((i as u8).wrapping_mul(7)))
        .collect();
    encode_b64url(&bytes)
}

fn pair(seed: u8) -> (String, String) {
    (b64(seed, 32), b64(seed.wrapping_add(1), 16))
}

fn receipt_for(
    metadata: &DurableMetadata,
    kid: &str,
    nonce: &str,
    operation: [u8; 16],
    ts: i64,
    hw: i64,
) -> DurableReceipt {
    let mut key = [0; 48];
    key[..32].copy_from_slice(&decode_b64url(kid).unwrap());
    key[32..].copy_from_slice(&decode_b64url(nonce).unwrap());
    DurableReceipt {
        version: FORMAT_VERSION,
        deployment: metadata.deployment.clone(),
        store_generation: metadata.generation,
        owner_generation: metadata.owner,
        intent_id: intent_id(
            metadata,
            &key,
            &decode_b64url(&b64(9, 64)).unwrap(),
            &decode_b64url(&b64(10, 32)).unwrap(),
            &operation,
        ),
        operation_id: operation,
        kid: kid.to_owned(),
        nonce: nonce.to_owned(),
        signature: b64(9, 64),
        request_hash: b64(10, 32),
        timestamp: ts,
        retain_until: ts + metadata.window,
        high_water: hw,
    }
}

fn record_of(
    metadata: &DurableMetadata,
    kind: RecordKind,
    kid: &str,
    nonce: &str,
    operation: [u8; 16],
    ts: i64,
    hw: i64,
) -> DurableRecord {
    let mut key = [0; 48];
    key[..32].copy_from_slice(&decode_b64url(kid).unwrap());
    key[32..].copy_from_slice(&decode_b64url(nonce).unwrap());
    DurableRecord {
        kind,
        key,
        store_id: metadata.store_id,
        receipt: receipt_for(metadata, kid, nonce, operation, ts, hw),
    }
}

fn admission<'a>(kid: &'a str, nonce: &'a str, ts: i64) -> DurableAdmission<'a> {
    // The signature must outlive the helper; leak it (test-only, bounded by
    // the number of admissions constructed in this file).
    let signature: &'static str = Box::leak(b64(9, 64).into_boxed_str());
    DurableAdmission {
        kid,
        nonce,
        signature,
        signing_bytes: b"mcp-jack/v1/request\nfixed-signing-bytes",
        timestamp: ts,
        window: WINDOW,
        snapshot_valid: ok_snapshot,
    }
}

/// Unique, length-valid raw key material for seeded rows: the counter lives in
/// the leading bytes so every (kid, nonce) pair differs across the loop.
fn seeded_live(
    metadata: &DurableMetadata,
    count: u32,
    kind: RecordKind,
    ts: i64,
    hw: i64,
) -> Vec<DurableRecord> {
    (0..count)
        .map(|i| {
            let mut kid = [0; 32];
            kid[..4].copy_from_slice(&i.to_be_bytes());
            let mut nonce = [0; 16];
            nonce[..4].copy_from_slice(&i.wrapping_mul(3).to_be_bytes());
            let mut operation = [0; 16];
            operation[..4].copy_from_slice(&i.to_be_bytes());
            record_of(
                metadata,
                kind,
                &encode_b64url(&kid),
                &encode_b64url(&nonce),
                operation,
                ts,
                hw,
            )
        })
        .collect()
}

fn initialized(sandbox: &Sandbox, samples: &[i64]) -> DurableNonceStore<impl FnMut() -> i64> {
    DurableNonceStore::initialize_unused(&sandbox.file(), &options(), clock(&[100])).unwrap();
    DurableNonceStore::open(&sandbox.file(), &options(), clock(samples)).unwrap()
}

fn decoded(sandbox: &Sandbox) -> crate::server::durable_format::DurableState {
    decode_state(&sandbox.bytes()).unwrap()
}

fn owner_generation(sandbox: &Sandbox) -> u64 {
    decoded(sandbox).metadata.owner
}

// ---------------------------------------------------------------- lifecycle

#[test]
fn owner_exclusivity_clean_close_and_reopen() {
    let sandbox = Sandbox::new();
    let path = sandbox.file();
    // Opening an absent store is refused; it is never reinterpreted as empty.
    assert!(DurableNonceStore::open(&path, &options(), clock(&[100])).is_err());
    assert!(!path.with_file_name("nonce-store.owner").exists());
    DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])).unwrap();
    assert!(DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])).is_err());
    assert_eq!(owner_generation(&sandbox), 1);
    let store = DurableNonceStore::open(&path, &options(), clock(&[100])).unwrap();
    assert!(DurableNonceStore::open(&path, &options(), clock(&[100])).is_err());
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
    assert!(DurableNonceStore::open(&path, &options(), clock(&[100])).is_err());
    assert!(DurableNonceStore::initialize_unused(&path, &options(), clock(&[100])).is_err());
    assert!(marker.exists());
}

#[test]
fn wrong_deployment_or_window_is_refused() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    store.close().unwrap();
    let mut wrong = options();
    wrong.deployment_id = "other-deployment".into();
    assert!(DurableNonceStore::open(&sandbox.file(), &wrong, clock(&[100])).is_err());
    let mut wrong = options();
    wrong.window = 60;
    assert!(DurableNonceStore::open(&sandbox.file(), &wrong, clock(&[100])).is_err());
}

// ----------------------------------------------------------- reserve basics

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

// ------------------------------------------------------- freshness failures

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

// ------------------------------------------------------------ high-water H

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
    assert!(store.close().is_err());
    // The latch persists: reopen fails closed; inspect shows the latch.
    assert!(DurableNonceStore::open(&sandbox.file(), &options(), clock(&[201])).is_err());
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
    assert!(DurableNonceStore::open(&sandbox.file(), &options(), clock(&[215])).is_err());
    let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
    assert!(snapshot.unsafe_latched);
    assert_eq!(
        snapshot.live.len(),
        1,
        "no expiry-based absence may precede H"
    );
}

// --------------------------------------------------------------- tombstones

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
    // The fence stays: unknown terminal state never reopens automatically.
    assert!(DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])).is_err());
}

fn snapshot_metadata_helper(sandbox: &Sandbox) -> DurableMetadata {
    decode_state(&sandbox.bytes()).unwrap().metadata
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

// ------------------------------------------------------------ capacity caps

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

// ---------------------------------------------------------- bounded purge

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

// --------------------------------------------------------- strict loading

/// Rebuilds a store file from raw parts so structural reject rules can be
/// exercised without depending on incidental corruption.
fn build_file(
    metadata_sealed: &[u8],
    live: &[Vec<u8>],
    intents: &[Vec<u8>],
    tombstones: &[Vec<u8>],
    expiry: &[[u8; 56]],
    operations: &[([u8; 16], [u8; 48])],
) -> Vec<u8> {
    const FILE_MAGIC: &[u8] = b"mcp-jack/nonce-store/file/v1\n";
    let mut out = Vec::new();
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&(metadata_sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(metadata_sealed);
    for rows in [live, intents, tombstones] {
        out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
        for row in rows {
            out.extend_from_slice(row);
        }
    }
    out.extend_from_slice(&(expiry.len() as u32).to_be_bytes());
    for index in expiry {
        out.extend_from_slice(index);
    }
    out.extend_from_slice(&(operations.len() as u32).to_be_bytes());
    for (operation, key) in operations {
        out.extend_from_slice(operation);
        out.extend_from_slice(key);
    }
    out
}

fn strip_seal(sealed: &[u8]) -> &[u8] {
    &sealed[..sealed.len() - 32]
}

fn valid_fixture() -> (Vec<u8>, DurableMetadata, [u8; 48], DurableReceipt) {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    let metadata = store.snapshot_metadata();
    let (kid, nonce) = pair(1);
    let (receipt, _) = store.reserve(&admission(&kid, &nonce, 100)).unwrap();
    store.close().unwrap();
    let mut key = [0; 48];
    key[..32].copy_from_slice(&decode_b64url(&kid).unwrap());
    key[32..].copy_from_slice(&decode_b64url(&nonce).unwrap());
    (sandbox.bytes(), metadata, key, receipt)
}

#[test]
fn strict_loader_rejects_trailing_bytes_and_corruption() {
    let (bytes, _, _, _) = valid_fixture();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        decode_state(&trailing).is_err(),
        "trailing bytes must be rejected"
    );
    let mut flipped = bytes.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0xff;
    assert!(
        decode_state(&flipped).is_err(),
        "checksum corruption must be rejected"
    );
    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(decode_state(&truncated).is_err());
}

#[test]
fn strict_loader_rejects_counter_and_cap_violations() {
    let (_, metadata, key, receipt) = valid_fixture();
    let metadata_sealed = encode_metadata(&metadata).unwrap();
    let payload = strip_seal(&metadata_sealed).to_vec();
    // Metadata claims one more live row than the file contains.
    let mut wrong_count = payload.clone();
    let live_offset = wrong_count.len() - 13;
    wrong_count[live_offset..live_offset + 4].copy_from_slice(&1u32.to_be_bytes());
    let file = build_file(&seal_payload(&wrong_count), &[], &[], &[], &[], &[]);
    assert!(
        decode_state(&file).is_err(),
        "counter mismatch must be rejected"
    );
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
    assert!(
        decode_state(&file).is_err(),
        "row without counter must be rejected"
    );
    // Aggregate cap: 65 tombstones above the 64 cap is rejected at load.
    let mut over_cap = payload.clone();
    let tombstone_offset = over_cap.len() - 9;
    over_cap[tombstone_offset..tombstone_offset + 4].copy_from_slice(&65u32.to_be_bytes());
    let file = build_file(&seal_payload(&over_cap), &[], &[], &[], &[], &[]);
    assert!(
        decode_state(&file).is_err(),
        "65 tombstones must be rejected"
    );
}

#[test]
fn strict_loader_rejects_duplicate_and_inconsistent_indexes() {
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
    assert!(
        decode_state(&file).is_err(),
        "duplicate keys must be rejected"
    );
    // Missing expiry index entry for a live row.
    let file = build_file(&metadata_sealed, &[row.clone()], &[], &[], &[], &ops);
    assert!(
        decode_state(&file).is_err(),
        "missing expiry entry must be rejected"
    );
    // Duplicate expiry index entries.
    let file = build_file(
        &metadata_sealed,
        &[row.clone()],
        &[],
        &[],
        &[index, index],
        &ops,
    );
    assert!(
        decode_state(&file).is_err(),
        "duplicate expiry entries must be rejected"
    );
    // Expiry entry that no live row produced.
    let file = build_file(
        &metadata_sealed,
        &[row.clone()],
        &[],
        &[],
        &[expiry_key(131, &key)],
        &ops,
    );
    assert!(
        decode_state(&file).is_err(),
        "inconsistent expiry entry must be rejected"
    );
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
    assert!(
        decode_state(&file).is_err(),
        "duplicate operation identity must be rejected"
    );
}

#[test]
fn strict_loader_rejects_wrong_typed_and_inconsistent_records() {
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
    assert!(
        decode_state(&file).is_err(),
        "unsupported record kind must be rejected"
    );
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
    assert!(
        decode_state(&file).is_err(),
        "retainUntil != ts+W must be rejected"
    );
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
    assert!(
        decode_state(&file).is_err(),
        "non-recomputing intent_id must be rejected"
    );
}

#[test]
fn strict_loader_rejects_wrong_store_binding() {
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
    assert!(
        decode_state(&file).is_err(),
        "wrong store identity must be rejected"
    );
}

/// Builds the fixed-position version-1 record payload for crafted fixtures.
fn payload_of_record(record: &DurableRecord) -> Vec<u8> {
    let receipt = &record.receipt;
    let mut out = Vec::new();
    out.push(FORMAT_VERSION);
    out.push(record.kind.value());
    out.extend_from_slice(&record.store_id);
    out.extend_from_slice(&record.key);
    out.extend_from_slice(&receipt.store_generation.to_be_bytes());
    out.extend_from_slice(&receipt.owner_generation.to_be_bytes());
    out.extend_from_slice(&receipt.operation_id);
    out.extend_from_slice(&decode_b64url(&receipt.intent_id).unwrap());
    out.extend_from_slice(&decode_b64url(&receipt.signature).unwrap());
    out.extend_from_slice(&decode_b64url(&receipt.request_hash).unwrap());
    out.extend_from_slice(&(receipt.timestamp as u64).to_be_bytes());
    out.extend_from_slice(&(receipt.retain_until as u64).to_be_bytes());
    out.extend_from_slice(&(receipt.high_water as u64).to_be_bytes());
    out
}

// -------------------------------------------------------------- inspection

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
    assert!(inspect_recovery(&sandbox.file(), &options()).is_err());
    store.close().unwrap();
}

#[test]
fn oversized_logical_file_is_rejected() {
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
    assert!(decode_state(&file).is_err());
    assert!(file.len() > MAX_FILE_BYTES);
}

// ------------------------------------------------------------------ R2 close

/// A Send/Sync wall clock for cross-thread tests; the sample never changes.
fn atomic_clock(value: Arc<AtomicI64>) -> impl FnMut() -> i64 + Send {
    move || value.load(Ordering::SeqCst)
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

// ------------------------------------------------------------------ R3 open

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

// ------------------------------------------------------------------ R5 update

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

// ------------------------------------------------------------------ R7 poison

#[test]
fn poisoned_lock_fences_the_store() {
    let sandbox = Sandbox::new();
    let store = initialized(&sandbox, &[100]);
    // A panic while the lock is held poisons it.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.poison_for_test();
    }));
    assert!(outcome.is_err(), "the poisoning panic must propagate");
    // The poisoned lock fences: the next admission is refused, not resumed.
    let (kid, nonce) = pair(1);
    let error = store.reserve(&admission(&kid, &nonce, 100)).unwrap_err();
    assert_eq!(error.status, 503);
    assert_eq!(error.code, "durability_unavailable");
    assert!(store.close().is_err());
}
