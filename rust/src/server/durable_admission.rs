//! Verifier-side durable admission seam (Go: server/admission.go) plus the
//! documented candidate vector-runner support surface. Linux-gated together
//! with the durable store (see mod.rs).
//!
//! Order of operations (spec section 2): the admission is reserved only after
//! signature verification and before any authorization, state change, or
//! dispatch; the volatile nonce store is not used when the durable store is
//! configured. Every refusal maps to the exact candidate status and code
//! (spec section 5). The lease is finished by the HTTP adapter after the
//! response is produced; direct Verify callers finish it themselves.

use std::cell::RefCell;

use super::durable_format::{counter_to_usize, DurableStoreError, MAX_TIMESTAMP};
use super::durable_store::{
    DurableAdmission, DurableAdmissionError, DurableLease, DurableNonceStore,
};
use super::verify::{Clock, VerifyResult};
use crate::auth_header::RequestAuth;

/// Concrete store type accepted by the verifier: the store's injected clock
/// is boxed so the verifier needs no generic parameter.
pub type BoxedDurableClock = Box<dyn FnMut() -> i64 + Send>;
pub type SharedDurableNonceStore = DurableNonceStore<BoxedDurableClock>;

/// Holds the dirty-serving lease of one committed reservation until the
/// response is produced (Go: admissionLease + Result.Done). Dropping it also
/// releases the lease, so a forgotten finish degrades safely.
#[derive(Default)]
pub struct AdmissionFinish(Option<DurableLease>);

impl std::fmt::Debug for AdmissionFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdmissionFinish")
            .field(&self.0.is_some())
            .finish()
    }
}

impl AdmissionFinish {
    fn hold(lease: DurableLease) -> Self {
        Self(Some(lease))
    }

    /// True while the serving epoch is still held and the store not fenced.
    pub fn valid(&self) -> bool {
        self.0.as_ref().is_none_or(DurableLease::valid)
    }

    /// Finishes the admission: releases the lease (Go: Result.Done). The
    /// HTTP adapter calls this after the response is produced; Drop is
    /// equivalent for direct callers.
    pub fn finish(&mut self) {
        self.0 = None;
    }
}

/// The captured active-key/enrollment snapshot as an inclusive validity
/// window, revalidated at every fresh raw sample the store takes. Rust's
/// `snapshot_valid` field is a plain function pointer, so the captured
/// window is bridged through a thread-local set only for the duration of
/// the reservation (no capture escapes the call).
#[derive(Clone, Copy)]
pub(crate) struct SnapshotWindow {
    not_before: i64,
    not_after: i64,
}

impl SnapshotWindow {
    /// Enrollment-exception snapshot: the submitted key was fully validated
    /// before admission, and it has no registry validity window.
    pub(crate) fn unbounded() -> Self {
        Self {
            not_before: i64::MIN,
            not_after: i64::MAX,
        }
    }

    /// Registered-caller snapshot: the entry's active interval (spec 02
    /// section 1), captured before the reservation.
    pub(crate) fn of_entry(not_before: Option<i64>, not_after: Option<i64>) -> Self {
        Self {
            not_before: not_before.unwrap_or(i64::MIN),
            not_after: not_after.unwrap_or(i64::MAX),
        }
    }
}

thread_local! {
    static SNAPSHOT: RefCell<SnapshotWindow> = RefCell::new(SnapshotWindow::unbounded());
}

/// Runs `f` with `window` installed as the snapshot revalidated by
/// `snapshot_window_valid`; the previous window is always restored.
pub(crate) fn with_snapshot_window<T>(window: SnapshotWindow, f: impl FnOnce() -> T) -> T {
    let previous = SNAPSHOT.with(|slot| slot.replace(window));
    let result = f();
    SNAPSHOT.with(|slot| slot.replace(previous));
    result
}

/// Snapshot revalidation at a fresh raw sample (Go: NonceAdmission.Validate):
/// in-domain sample inside the captured active-key/enrollment window.
pub(crate) fn snapshot_window_valid(now: i64) -> bool {
    SNAPSHOT.with(|slot| {
        let window = *slot.borrow();
        (0..=MAX_TIMESTAMP).contains(&now) && now >= window.not_before && now < window.not_after
    })
}

/// Outcome of one durable admission: the verifier result (carrying the lease
/// on committed admissions, including post-commit refusals that keep the
/// reservation) and, when the request may proceed to authorization, the
/// post-commit freshness sample (Go: finalNow).
pub(crate) struct DurableAdmissionOutcome {
    pub result: VerifyResult,
    pub final_now: Option<i64>,
}

fn fail(mut res: VerifyResult, status: u16, code: &str, message: &str) -> VerifyResult {
    res.http_status = status;
    res.code = code.to_owned();
    res.message = message.to_owned();
    res.identity = None;
    res
}

/// Maps a store refusal to the exact spec section 5 status and code
/// (Go: storageRejection); anything else is the generic unknown refusal.
fn storage_rejection(error: DurableAdmissionError) -> VerifyResult {
    if error.status == 401
        && (error.code == "replayed_nonce" || error.code == "timestamp_out_of_window")
    {
        return fail(
            VerifyResult::default(),
            401,
            error.code,
            "request was not admitted",
        );
    }
    if error.status == 503
        && matches!(
            error.code,
            "durability_unavailable" | "state_changed" | "clock_unsafe" | "capacity_exhausted"
        )
    {
        return fail(
            VerifyResult::default(),
            503,
            error.code,
            "durable admission is unavailable",
        );
    }
    fail(
        VerifyResult::default(),
        503,
        "durability_unavailable",
        "durable admission is unavailable",
    )
}

/// Byte-exact binding of the receipt to the admitted request
/// (Go: receiptMatches).
fn receipt_matches(
    receipt: &super::durable_format::DurableReceipt,
    auth: &RequestAuth,
    window: i64,
) -> bool {
    let high_water_ok = receipt.high_water >= 0
        && receipt.high_water <= MAX_TIMESTAMP
        && receipt.high_water - receipt.timestamp <= window
        && receipt.timestamp - receipt.high_water <= window;
    receipt.version == super::durable_format::FORMAT_VERSION
        && receipt.kid == auth.kid
        && receipt.nonce == auth.nonce
        && receipt.signature == auth.sig
        && receipt.timestamp == auth.ts
        && receipt.retain_until == auth.ts.checked_add(window).unwrap_or(i64::MAX)
        && high_water_ok
}

/// One durable admission (Go: Verifier.reserveDurable): reserve after
/// signature verification, take the post-commit freshness sample, and map
/// every refusal to its spec section 5 status and code. A committed
/// reservation is kept on post-commit refusals; a consumed nonce is never
/// released.
pub(crate) fn reserve_durable(
    store: &SharedDurableNonceStore,
    auth: &RequestAuth,
    signing: &str,
    window: i64,
    snapshot: SnapshotWindow,
    now_fn: &Clock,
) -> DurableAdmissionOutcome {
    with_snapshot_window(snapshot, || {
        let mut res = VerifyResult {
            kid: auth.kid.clone(),
            request_sig: auth.sig.clone(),
            ..Default::default()
        };
        if auth.ts < 0 || auth.ts > MAX_TIMESTAMP.saturating_sub(window) {
            return DurableAdmissionOutcome {
                result: fail(
                    res,
                    401,
                    "timestamp_out_of_window",
                    "timestamp is outside the acceptance window",
                ),
                final_now: None,
            };
        }
        let admission = DurableAdmission {
            kid: &auth.kid,
            nonce: &auth.nonce,
            signature: &auth.sig,
            signing_bytes: signing.as_bytes(),
            timestamp: auth.ts,
            window,
            snapshot_valid: snapshot_window_valid,
        };
        let (receipt, lease) = match store.reserve(&admission) {
            Ok(ok) => ok,
            Err(error) => {
                return DurableAdmissionOutcome {
                    result: storage_rejection(error),
                    final_now: None,
                };
            }
        };
        if !receipt_matches(&receipt, auth, window) {
            store.fence();
            drop(lease);
            return DurableAdmissionOutcome {
                result: fail(
                    VerifyResult::default(),
                    503,
                    "durability_unavailable",
                    "durable admission is unavailable",
                ),
                final_now: None,
            };
        }
        res.nonce_recorded = true;
        let lease_valid = lease.valid();
        res.admission = AdmissionFinish::hold(lease);
        // Post-commit freshness sample (spec section 2): one further raw
        // sample after the final reservation committed, before dispatch.
        let final_now = (now_fn)();
        if !(0..=MAX_TIMESTAMP).contains(&final_now) || final_now < receipt.high_water {
            store.fence();
            return DurableAdmissionOutcome {
                result: fail(
                    res,
                    503,
                    "durability_unavailable",
                    "durable admission is unavailable",
                ),
                final_now: None,
            };
        }
        if !lease_valid || !snapshot_window_valid(final_now) {
            return DurableAdmissionOutcome {
                result: fail(res, 503, "state_changed", "verification state changed"),
                final_now: None,
            };
        }
        let difference = final_now - auth.ts;
        if difference > window || -difference > window {
            return DurableAdmissionOutcome {
                result: fail(
                    res,
                    401,
                    "timestamp_out_of_window",
                    "timestamp is outside the acceptance window",
                ),
                final_now: None,
            };
        }
        DurableAdmissionOutcome {
            result: res,
            final_now: Some(final_now),
        }
    })
}

// -------------------------------------------------------------------------
// Candidate vector-runner support. Doc-hidden test/recovery surface over the
// crate-internal seeding path; deliberately not part of the stable API.
// -------------------------------------------------------------------------

/// Read-only view of the store metadata used by the vector runner
/// assertions; not an admission receipt.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct NonceStoreInfo {
    pub high_water: i64,
    pub generation: u64,
    pub owner: u64,
    pub window: i64,
    pub live: usize,
    pub intents: usize,
    pub tombstones: usize,
    pub dirty: bool,
    pub unsafe_latched: bool,
}

#[doc(hidden)]
pub fn nonce_store_info<C: FnMut() -> i64>(store: &DurableNonceStore<C>) -> NonceStoreInfo {
    let metadata = store.snapshot_metadata();
    NonceStoreInfo {
        high_water: metadata.high_water.get(),
        generation: metadata.generation,
        owner: metadata.owner,
        window: metadata.window,
        live: counter_to_usize(metadata.live),
        intents: counter_to_usize(metadata.intents),
        tombstones: counter_to_usize(metadata.tombstones),
        dirty: metadata.dirty,
        unsafe_latched: metadata.unsafe_latched,
    }
}

/// Kind of a seeded row (Go: liveRecord/intentRecord/tombstoneRecord).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedKind {
    Intent,
    Live,
    Tombstone,
}

/// One strictly validated abstract row to seed through the store's own
/// record path (Go: vectorSeedRowRecord). Identities follow the candidate
/// vector derivation in the runner.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SeedRow {
    pub kind: SeedKind,
    pub kid: String,
    pub nonce: String,
    pub signature: String,
    pub request_hash: String,
    pub operation_id: [u8; 16],
    pub ts: i64,
    pub retain_until: i64,
    pub high_water: i64,
}

#[doc(hidden)]
pub fn seed_nonce_rows<C: FnMut() -> i64>(
    store: &DurableNonceStore<C>,
    rows: &[SeedRow],
) -> Result<(), DurableStoreError> {
    use super::durable_format::{intent_id, DurableReceipt, DurableRecord, RecordKind};
    use crate::encoding::decode_b64url_fixed;
    let metadata = store.snapshot_metadata();
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let kid = decode_b64url_fixed(&row.kid, 32).map_err(|_| DurableStoreError::InvalidStore)?;
        let nonce =
            decode_b64url_fixed(&row.nonce, 16).map_err(|_| DurableStoreError::InvalidStore)?;
        let signature =
            decode_b64url_fixed(&row.signature, 64).map_err(|_| DurableStoreError::InvalidStore)?;
        let request_hash = decode_b64url_fixed(&row.request_hash, 32)
            .map_err(|_| DurableStoreError::InvalidStore)?;
        let mut key = [0; 48];
        key[..32].copy_from_slice(&kid);
        key[32..].copy_from_slice(&nonce);
        let intent = intent_id(
            &metadata,
            &key,
            &signature,
            &request_hash,
            &row.operation_id,
        );
        records.push(DurableRecord {
            kind: match row.kind {
                SeedKind::Intent => RecordKind::Intent,
                SeedKind::Live => RecordKind::Live,
                SeedKind::Tombstone => RecordKind::Tombstone,
            },
            key,
            store_id: metadata.store_id,
            receipt: DurableReceipt {
                version: super::durable_format::FORMAT_VERSION,
                deployment: metadata.deployment.clone(),
                store_generation: metadata.generation,
                owner_generation: metadata.owner,
                intent_id: intent,
                operation_id: row.operation_id,
                kid: row.kid.clone(),
                nonce: row.nonce.clone(),
                signature: row.signature.clone(),
                request_hash: row.request_hash.clone(),
                timestamp: row.ts,
                retain_until: row.retain_until,
                high_water: row.high_water,
            },
        });
    }
    store.seed_records(&records)
}
