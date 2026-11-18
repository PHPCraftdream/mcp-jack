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

// ----------------------------------------------------------- reserve basics

// ------------------------------------------------------- freshness failures

// ------------------------------------------------------------ high-water H

// --------------------------------------------------------------- tombstones

fn snapshot_metadata_helper(sandbox: &Sandbox) -> DurableMetadata {
    decode_state(&sandbox.bytes()).unwrap().metadata
}

// ------------------------------------------------------------ capacity caps

// ---------------------------------------------------------- bounded purge

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

// ------------------------------------------------------------------ R2 close

/// A Send/Sync wall clock for cross-thread tests; the sample never changes.
fn atomic_clock(value: Arc<AtomicI64>) -> impl FnMut() -> i64 + Send {
    move || value.load(Ordering::SeqCst)
}

// ------------------------------------------------------------------ R3 open

// ------------------------------------------------------------------ R5 update

// ------------------------------------------------------------------ R7 poison

mod high_water_and_capacity;

mod lifecycle_and_reserve;

mod strict_loading_and_inspect;
