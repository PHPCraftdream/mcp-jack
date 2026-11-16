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
use std::sync::Arc;

use super::durable_format::{
    counter_to_usize, intent_id, DurableMetadata, DurableReceipt, DurableStoreError,
    FORMAT_VERSION, MAX_TIMESTAMP,
};
use super::durable_store::{
    admission_error, DurableAdmission, DurableAdmissionError, DurableLease, DurableNonceStore,
};
use super::state::{RegistryEntry, StateStore};
use super::verify::{entry_active, Clock, VerifyResult};
use crate::auth_header::RequestAuth;
use crate::encoding::{body_hash, decode_b64url_fixed};

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

/// The captured registry snapshot (Go: caller + known), revalidated
/// FIELD-BY-FIELD against the LIVE registry at reservation time and at every
/// fresh raw sample (Go: state.WithAdmission + sameEntry/currentKnown).
#[derive(Clone)]
pub(crate) struct CallerSnapshot {
    known: bool,
    kid: String,
    entry: Option<RegistryEntry>,
}

impl CallerSnapshot {
    /// Enrollment exception: the kid must still be unregistered when the
    /// reservation commits, and the submitted key has no registry validity
    /// window (Go: known=false, Validate skips entryActive).
    pub(crate) fn enrolled(kid: String) -> Self {
        Self {
            known: false,
            kid,
            entry: None,
        }
    }

    /// Registered-caller snapshot, captured at the verifier's lookup.
    pub(crate) fn registered(entry: RegistryEntry) -> Self {
        Self {
            known: true,
            kid: entry.kid.clone(),
            entry: Some(entry),
        }
    }
}

/// Registry plus snapshot installed for the duration of one reservation.
/// The store's `snapshot_valid` field is a plain function pointer, so the
/// gate is bridged through a thread-local (no capture escapes the call).
struct ReservationGate {
    snapshot: CallerSnapshot,
    state: Arc<dyn StateStore>,
}

thread_local! {
    static GATE: RefCell<Option<ReservationGate>> = const { RefCell::new(None) };
}

/// Runs `f` with `snapshot`/`state` installed as the registry gate
/// revalidated by [`snapshot_window_valid`]; the previous gate is restored.
pub(crate) fn with_caller_snapshot<T>(
    snapshot: CallerSnapshot,
    state: Arc<dyn StateStore>,
    f: impl FnOnce() -> T,
) -> T {
    let previous = GATE.with(|slot| slot.replace(Some(ReservationGate { snapshot, state })));
    let result = f();
    GATE.with(|slot| slot.replace(previous));
    result
}

/// Reports whether the live registry still matches the captured snapshot in
/// every field (Go: currentKnown == known && (!known || sameEntry)).
fn live_registry_matches(gate: &ReservationGate) -> bool {
    let current = gate.state.lookup(&gate.snapshot.kid);
    match (gate.snapshot.known, current) {
        (true, Some(entry)) => Some(entry) == gate.snapshot.entry,
        (false, None) => true,
        _ => false,
    }
}

/// Reservation-time registry revalidation (Go: the WithAdmission callback's
/// first check, taken without any clock sample). False outside a gate.
fn registry_matches_snapshot() -> bool {
    GATE.with(|slot| slot.borrow().as_ref().is_some_and(live_registry_matches))
}

/// Snapshot revalidation at a fresh raw sample (Go: NonceAdmission.Validate):
/// in-domain sample, the captured entry still active, and the live registry
/// still matching the snapshot in every field.
pub(crate) fn snapshot_window_valid(now: i64) -> bool {
    (0..=MAX_TIMESTAMP).contains(&now)
        && GATE.with(|slot| {
            let gate = slot.borrow();
            let Some(gate) = gate.as_ref() else {
                return false;
            };
            if let Some(entry) = &gate.snapshot.entry {
                if !entry_active(entry, now) {
                    return false;
                }
            }
            live_registry_matches(gate)
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

/// Recomputes the intent id from the receipt's deployment identity and the
/// exact request binding (Go: NonceIntentID); None when a field does not
/// decode, which must fence like any other mismatch.
fn expected_intent_id(
    metadata: &DurableMetadata,
    receipt: &DurableReceipt,
    auth: &RequestAuth,
    request_hash: &str,
) -> Option<String> {
    let kid = decode_b64url_fixed(&auth.kid, 32).ok()?;
    let nonce = decode_b64url_fixed(&auth.nonce, 16).ok()?;
    let signature = decode_b64url_fixed(&receipt.signature, 64).ok()?;
    let request_hash_raw = decode_b64url_fixed(request_hash, 32).ok()?;
    let mut key = [0; 48];
    key[..32].copy_from_slice(&kid);
    key[32..].copy_from_slice(&nonce);
    Some(intent_id(
        metadata,
        &key,
        &signature,
        &request_hash_raw,
        &receipt.operation_id,
    ))
}

/// Byte-exact binding of the receipt to the admitted request
/// (Go: receiptMatches): recomputed intent id, request hash, format version,
/// store/owner generations and high-water bounds.
fn receipt_matches(
    receipt: &DurableReceipt,
    auth: &RequestAuth,
    signing: &str,
    window: i64,
    metadata: &DurableMetadata,
) -> bool {
    let request_hash = body_hash(signing.as_bytes());
    let high_water_ok = receipt.high_water >= 0
        && receipt.high_water <= MAX_TIMESTAMP
        && receipt.high_water - receipt.timestamp <= window
        && receipt.timestamp - receipt.high_water <= window;
    let intent_ok = expected_intent_id(metadata, receipt, auth, &request_hash)
        .is_some_and(|intent| receipt.intent_id == intent);
    receipt.version == FORMAT_VERSION
        && receipt.store_generation > 0
        && receipt.owner_generation > 0
        && intent_ok
        && receipt.kid == auth.kid
        && receipt.nonce == auth.nonce
        && receipt.signature == auth.sig
        && receipt.request_hash == request_hash
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
    snapshot: CallerSnapshot,
    state: Arc<dyn StateStore>,
    now_fn: &Clock,
) -> DurableAdmissionOutcome {
    with_caller_snapshot(snapshot, state, || {
        let mut res = VerifyResult {
            kid: auth.kid.clone(),
            request_sig: auth.sig.clone(),
            ..Default::default()
        };
        // Reservation-time registry revalidation FIRST (Go: the
        // WithAdmission callback's first check): the caller entry or the
        // enrollment state changed since the verifier's lookup. Nothing is
        // consumed, the store is not fenced (503 state_changed is definite).
        if !registry_matches_snapshot() {
            return DurableAdmissionOutcome {
                result: storage_rejection(admission_error(503, "state_changed")),
                final_now: None,
            };
        }
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
        // Recompute the receipt binding from the RECEIPT's deployment
        // identity (Go: receiptMatches uses receipt.DeploymentID).
        let mut metadata = store.snapshot_metadata();
        metadata.deployment = receipt.deployment.clone();
        if !receipt_matches(&receipt, auth, signing, window, &metadata) {
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

#[cfg(test)]
mod tests {
    use super::super::durable_format::HighWater;
    use super::*;
    use crate::encoding::encode_b64url;
    use sha2::{Digest, Sha256};

    /// A committed receipt and the exact request it binds (window 30).
    fn fixture() -> (DurableReceipt, RequestAuth, String, i64, DurableMetadata) {
        let kid_raw: [u8; 32] = Sha256::digest(b"kid").into();
        let mut nonce_raw = [0; 16];
        nonce_raw.copy_from_slice(&Sha256::digest(b"nonce")[..16]);
        let mut signature_raw = [0; 64];
        let digest64 = Sha256::digest(b"sig");
        signature_raw[..32].copy_from_slice(&digest64);
        signature_raw[32..].copy_from_slice(&digest64);
        let request_hash_raw: [u8; 32] = Sha256::digest(b"signing").into();
        let metadata = DurableMetadata {
            deployment: "dep".to_owned(),
            store_id: [7; 16],
            generation: 1,
            owner: 1,
            window: 30,
            high_water: HighWater::new(0),
            live: 0,
            intents: 0,
            tombstones: 0,
            dirty: false,
            unsafe_latched: false,
        };
        let auth = RequestAuth {
            kid: encode_b64url(&kid_raw),
            ts: 100,
            nonce: encode_b64url(&nonce_raw),
            sig: encode_b64url(&signature_raw),
        };
        let mut key = [0; 48];
        key[..32].copy_from_slice(&kid_raw);
        key[32..].copy_from_slice(&nonce_raw);
        let receipt = DurableReceipt {
            version: FORMAT_VERSION,
            deployment: "dep".to_owned(),
            store_generation: 1,
            owner_generation: 1,
            intent_id: intent_id(&metadata, &key, &signature_raw, &request_hash_raw, &[9; 16]),
            operation_id: [9; 16],
            kid: auth.kid.clone(),
            nonce: auth.nonce.clone(),
            signature: auth.sig.clone(),
            request_hash: encode_b64url(&request_hash_raw),
            timestamp: 100,
            retain_until: 130,
            high_water: 100,
        };
        (receipt, auth, "signing".to_owned(), 30, metadata)
    }

    #[test]
    fn receipt_matches_the_exact_request() {
        let (receipt, auth, signing, window, metadata) = fixture();
        assert!(receipt_matches(
            &receipt, &auth, &signing, window, &metadata
        ));
    }

    #[test]
    fn receipt_request_hash_is_bound() {
        let (mut receipt, auth, signing, window, metadata) = fixture();
        let other: [u8; 32] = Sha256::digest(b"other").into();
        receipt.request_hash = encode_b64url(&other);
        assert!(!receipt_matches(
            &receipt, &auth, &signing, window, &metadata
        ));
    }

    #[test]
    fn receipt_intent_id_is_recomputed_from_the_receipt_deployment() {
        let (receipt, auth, signing, window, metadata) = fixture();
        // A receipt whose deployment identity differs must not match.
        let mut other = metadata.clone();
        other.deployment = "other".to_owned();
        assert!(!receipt_matches(&receipt, &auth, &signing, window, &other));
        let (mut receipt, auth, signing, window, metadata) = fixture();
        receipt.intent_id = encode_b64url(&Sha256::digest(b"tampered"));
        assert!(!receipt_matches(
            &receipt, &auth, &signing, window, &metadata
        ));
    }

    #[test]
    fn receipt_generations_must_be_positive() {
        let (mut receipt, auth, signing, window, metadata) = fixture();
        receipt.store_generation = 0;
        assert!(!receipt_matches(
            &receipt, &auth, &signing, window, &metadata
        ));
        let (mut receipt, auth, signing, window, metadata) = fixture();
        receipt.owner_generation = 0;
        assert!(!receipt_matches(
            &receipt, &auth, &signing, window, &metadata
        ));
    }
}
