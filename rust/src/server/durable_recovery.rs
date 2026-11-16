//! Explicit out-of-band recovery for a fenced/dirty durable nonce store
//! (Go: recovery_snapshot.go, recovery_inspect.go, recovery_reconcile.go).
//!
//! Inspection never creates a store, never samples the clock, and never
//! changes metadata or history. Reconciliation moves one exact snapshot to a
//! terminal no-redelivery tombstone; a missing record is not proof of abort
//! and never clears the startup fence.

use super::durable_format::{
    counter_to_usize, decode_state, encode_state, expiry_key, DurableReceipt, DurableState,
    DurableStoreError, RecordKind, MAX_TOMBSTONES,
};
use super::durable_store::{
    normalized_options, read_state_bytes, snapshot_hash, write_state_bytes, DurableStoreOptions,
    OwnerFile,
};
use crate::encoding::decode_b64url_fixed;
use std::path::Path;

/// Owned diagnostic snapshot of the full logical state; it is not an
/// admission receipt and not permission to reopen.
#[derive(Debug, Clone)]
pub struct DurableRecoverySnapshot {
    pub deployment_id: String,
    pub store_id: String,
    pub store_generation: u64,
    pub owner_generation: u64,
    pub window: i64,
    pub high_water: i64,
    pub dirty: bool,
    pub unsafe_latched: bool,
    pub hash: String,
    pub live: Vec<DurableReceipt>,
    pub intents: Vec<DurableReceipt>,
    pub tombstones: Vec<DurableReceipt>,
}

/// Acquires the lifetime-exclusive marker (so a live owner cannot be racing),
/// loads and strictly validates the whole logical graph, and releases the
/// marker without changing anything.
pub fn inspect_recovery(
    path: &Path,
    options: &DurableStoreOptions,
) -> Result<DurableRecoverySnapshot, DurableStoreError> {
    normalized_options(options)?;
    let owner = OwnerFile::acquire(path)?;
    let inspected = (|| {
        let bytes = read_state_bytes(&owner)?;
        let state = decode_state(&bytes)?;
        if state.metadata.deployment != options.deployment_id
            || state.metadata.window != options.window
        {
            return Err(DurableStoreError::InvalidStore);
        }
        let hash = snapshot_hash(&state)?;
        Ok(snapshot_of(&state, hash))
    })();
    let released = owner.release();
    match (inspected, released) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Ok(_), Err(_)) => Err(DurableStoreError::Unavailable),
        (Err(error), _) => Err(error),
    }
}

fn snapshot_of(state: &DurableState, hash: String) -> DurableRecoverySnapshot {
    let metadata = &state.metadata;
    DurableRecoverySnapshot {
        deployment_id: metadata.deployment.clone(),
        store_id: crate::encoding::encode_b64url(&metadata.store_id),
        store_generation: metadata.generation,
        owner_generation: metadata.owner,
        window: metadata.window,
        high_water: metadata.high_water.get(),
        dirty: metadata.dirty,
        unsafe_latched: metadata.unsafe_latched,
        hash,
        live: state.live.values().cloned().collect(),
        intents: state.intents.values().cloned().collect(),
        tombstones: state.tombstones.values().cloned().collect(),
    }
}

/// Explicit operator reconciliation of one unknown outcome (Go:
/// ReconcileUnknown): the exact persisted row matching `receipt` moves to a
/// terminal no-redelivery tombstone. Requires the dirty epoch and the exact
/// expected snapshot hash; a missing record is refused, not treated as abort.
pub fn reconcile_unknown(
    path: &Path,
    options: &DurableStoreOptions,
    expected_hash: &str,
    receipt: &DurableReceipt,
) -> Result<(), DurableStoreError> {
    normalized_options(options)?;
    if decode_b64url_fixed(expected_hash, 32).is_err() {
        return Err(DurableStoreError::RecoveryRequired);
    }
    let kid =
        decode_b64url_fixed(&receipt.kid, 32).map_err(|_| DurableStoreError::RecoveryRequired)?;
    let nonce =
        decode_b64url_fixed(&receipt.nonce, 16).map_err(|_| DurableStoreError::RecoveryRequired)?;
    let mut key = [0; 48];
    key[..32].copy_from_slice(&kid);
    key[32..].copy_from_slice(&nonce);
    let owner = OwnerFile::acquire(path)?;
    let reconciled = (|| {
        let bytes = read_state_bytes(&owner)?;
        let mut state = decode_state(&bytes)?;
        // Deployment and window mismatch is ErrInvalidStore for both inspect
        // and reconcile (Go: readStoreSnapshot via loadRecoverySnapshot).
        if state.metadata.deployment != options.deployment_id
            || state.metadata.window != options.window
        {
            return Err(DurableStoreError::InvalidStore);
        }
        if !state.metadata.dirty || snapshot_hash(&state)? != expected_hash {
            return Err(DurableStoreError::RecoveryRequired);
        }
        move_row_to_tombstone(&mut state, &key, receipt)?;
        write_state_bytes(&owner, &encode_state(&state)?)?;
        Ok(())
    })();
    let released = owner.release();
    match (reconciled, released) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(_)) => Err(DurableStoreError::Unavailable),
        (Err(error), _) => Err(error),
    }
}

fn move_row_to_tombstone(
    state: &mut DurableState,
    key: &[u8; 48],
    receipt: &DurableReceipt,
) -> Result<(), DurableStoreError> {
    if let Some(stored) = state.tombstones.get(key) {
        // Already terminal: an identical tombstone needs no further change.
        if stored == receipt {
            return Ok(());
        }
        return Err(DurableStoreError::RecoveryRequired);
    }
    let kind = if state.live.contains_key(key) {
        RecordKind::Live
    } else if state.intents.contains_key(key) {
        RecordKind::Intent
    } else {
        // A missing record is not proof of abort: refuse and keep the fence.
        return Err(DurableStoreError::RecoveryRequired);
    };
    let stored = if kind == RecordKind::Live {
        state.live.get(key)
    } else {
        state.intents.get(key)
    };
    if stored != Some(receipt) {
        return Err(DurableStoreError::RecoveryRequired);
    }
    if counter_to_usize(state.metadata.tombstones) >= MAX_TOMBSTONES {
        return Err(DurableStoreError::RecoveryRequired);
    }
    state.tombstones.insert(*key, receipt.clone());
    if kind == RecordKind::Live {
        let retain = receipt.retain_until;
        state.live.remove(key);
        state.expiry.remove(&expiry_key(retain, key));
        state.metadata.live -= 1;
    } else {
        state.intents.remove(key);
        state.metadata.intents -= 1;
    }
    state.metadata.tombstones += 1;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{inspect_recovery, reconcile_unknown};
    use crate::encoding::{decode_b64url_fixed, encode_b64url};
    use crate::server::durable_format::{
        intent_id, DurableMetadata, DurableReceipt, DurableRecord, DurableStoreError, RecordKind,
        FORMAT_VERSION,
    };
    use crate::server::durable_store::{DurableNonceStore, DurableStoreOptions};
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;

    const WINDOW: i64 = 30;

    fn b64(seed: u8, size: usize) -> String {
        let bytes: Vec<u8> = (0..size)
            .map(|i| seed.wrapping_add((i as u8).wrapping_mul(7)))
            .collect();
        encode_b64url(&bytes)
    }

    fn options() -> DurableStoreOptions {
        DurableStoreOptions {
            deployment_id: "reconcile-guard-deployment".into(),
            window: WINDOW,
        }
    }

    fn clock(samples: &[i64]) -> impl FnMut() -> i64 {
        let queue = std::cell::RefCell::new(samples.to_vec());
        move || {
            let mut queue = queue.borrow_mut();
            let sample = queue[0];
            if queue.len() > 1 {
                queue.remove(0);
            }
            sample
        }
    }

    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "jack-rust-durable-recovery-{}",
                encode_b64url(&random)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("nonce-store")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn receipt(metadata: &DurableMetadata, ts: i64) -> DurableReceipt {
        let kid = b64(3, 32);
        let nonce = b64(4, 16);
        let mut key = [0; 48];
        key[..32].copy_from_slice(&decode_b64url_fixed(&kid, 32).unwrap());
        key[32..].copy_from_slice(&decode_b64url_fixed(&nonce, 16).unwrap());
        let signature = decode_b64url_fixed(&b64(9, 64), 64).unwrap();
        let request_hash = decode_b64url_fixed(&b64(10, 32), 32).unwrap();
        DurableReceipt {
            version: FORMAT_VERSION,
            deployment: metadata.deployment.clone(),
            store_generation: metadata.generation,
            owner_generation: metadata.owner,
            intent_id: intent_id(metadata, &key, &signature, &request_hash, &[7; 16]),
            operation_id: [7; 16],
            kid,
            nonce,
            signature: b64(9, 64),
            request_hash: b64(10, 32),
            timestamp: ts,
            retain_until: ts + metadata.window,
            high_water: ts,
        }
    }

    /// Builds a dirty store holding one unresolved intent; reconcile is the
    /// only way back (mirrors the Go ReconcileUnknown test setup).
    fn dirty_intent_store(sandbox: &Sandbox) -> (String, DurableReceipt) {
        DurableNonceStore::initialize_unused(&sandbox.file(), &options(), clock(&[100])).unwrap();
        let store = DurableNonceStore::open(&sandbox.file(), &options(), clock(&[100])).unwrap();
        let metadata = store.snapshot_metadata();
        let claim = receipt(&metadata, 100);
        store
            .seed_records(&[DurableRecord {
                kind: RecordKind::Intent,
                key: {
                    let mut key = [0; 48];
                    key[..32].copy_from_slice(&decode_b64url_fixed(&claim.kid, 32).unwrap());
                    key[32..].copy_from_slice(&decode_b64url_fixed(&claim.nonce, 16).unwrap());
                    key
                },
                store_id: metadata.store_id,
                receipt: claim.clone(),
            }])
            .unwrap();
        // The outstanding intent keeps the dirty epoch: close is fenced.
        assert_eq!(
            store.close().unwrap_err(),
            DurableStoreError::RecoveryRequired
        );
        let snapshot = inspect_recovery(&sandbox.file(), &options()).unwrap();
        assert_eq!(snapshot.intents.len(), 1);
        (snapshot.hash, claim)
    }

    #[test]
    fn reconcile_refuses_deployment_or_window_mismatch() {
        let sandbox = Sandbox::new();
        let (hash, claim) = dirty_intent_store(&sandbox);

        // Deployment mismatch: ErrInvalidStore (Go: readStoreSnapshot), not a
        // silent reconcile under foreign identity options.
        let mut wrong = options();
        wrong.deployment_id = "other-deployment".into();
        assert_eq!(
            reconcile_unknown(&sandbox.file(), &wrong, &hash, &claim).unwrap_err(),
            DurableStoreError::InvalidStore
        );

        // Window mismatch: same ErrInvalidStore refusal.
        let mut wrong = options();
        wrong.window = 60;
        assert_eq!(
            reconcile_unknown(&sandbox.file(), &wrong, &hash, &claim).unwrap_err(),
            DurableStoreError::InvalidStore
        );

        // Matching options still reconcile the exact row to a tombstone.
        reconcile_unknown(&sandbox.file(), &options(), &hash, &claim).unwrap();
        let after = inspect_recovery(&sandbox.file(), &options()).unwrap();
        assert_eq!(after.tombstones.len(), 1);
        assert!(after.intents.is_empty() && after.live.is_empty());
    }
}
