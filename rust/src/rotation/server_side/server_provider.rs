use super::{
    create_record, decode_result, invalid, Binding, Checkpoint, ClockTuple, DecodedResult, Record,
    ResultCursor, RotationError, RotationServerStore, ServerSnapshot, SignerReference, TrustKey,
    GRACE_SECONDS, MAX_ORDINAL, MAX_RESULT_BODY_BYTES, MAX_RETAINED_KEYS,
    MAX_SIGNER_REFERENCE_BYTES, MAX_TIMESTAMP,
};
use crate::client::Signer;
use crate::ed25519::validate_public_key;
use crate::encoding::key_id;
use crate::server::response_keys::{
    FinalGate, Release, ResponseKeyAuthorization, ResponseKeyRequest, ResponseKeys, ResponseSigner,
};
use crate::server::verify::TOOL_SERVER_KEY;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

// TS/Go reference limits (Go hardcoded 128/1024): an anomalous number of pending/retained handles refuses.
const MAX_PENDING: usize = 128;
pub(crate) const MAX_RETIRED: usize = 1024;
// Every key but the newest eventually retires and serving (select_pinned) refuses more than
// MAX_RETIRED retired keys, so an announce must leave at most MAX_RETIRED + 1 keys in the ring.
pub(crate) const MAX_ANNOUNCE_RING_KEYS: usize = MAX_RETIRED + 1;

fn unavailable() -> RotationError {
    invalid("rotation_state_unavailable")
}

/// Resets the publication flag on any exit, including `?`; Go: `defer publication.Store(false)`.
/// Bound to `&AtomicBool` so the guard does not own the flag and lives exactly until announce ends.
struct PublicationReset<'a>(&'a AtomicBool);

impl Drop for PublicationReset<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Pre-configured signer handle: the reference does not replace public key verification.
pub struct RotationServerKey {
    pub reference: String,
    pub signer: Arc<dyn Signer>,
}

/// Pinned signer identity: the public key is copied once and does not change together with the callback.
#[derive(Clone)]
pub struct PinnedRotationSigner {
    public: [u8; 32],
    signer: Arc<dyn Signer>,
}

impl AsRef<dyn Signer> for PinnedRotationSigner {
    fn as_ref(&self) -> &(dyn Signer + 'static) {
        self.signer.as_ref()
    }
}

impl ResponseSigner for PinnedRotationSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RotationError> {
        // Raw signature bytes: length/verify stay at the HTTP layer (Go responseSignature).
        self.signer.sign(message).map_err(|_| unavailable())
    }
}

/// Only after exact durable ACK; this is not HTTP delivery.
pub struct RotationPublication {
    pub record: Record,
    pub revision: u64,
}

/// Binds a concrete server store with a pre-configured signer inventory: signer selection,
/// explicit publication of a single next key, and response-signing authorization. The inventory is given
/// only out-of-band; custody and lifecycle of signer handles belong to the caller. Signer callbacks must
/// be bounded and non-reentrant; the store lock is never held during callbacks.
pub struct RotationServerProvider<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    store: Arc<Mutex<RotationServerStore<C>>>,
    keys: HashMap<(String, String), PinnedRotationSigner>,
    publishing: AtomicBool,
    announce_ring_keys: usize,
}

/// Copies the public identity ONCE; the kid is derived from the copy, so later callback
/// changes cannot substitute the pinned identity. A Rust String is always valid UTF-8, so
/// the utf8 checks of TS pin()/Go pinKey are not needed here.
fn pin(key: &RotationServerKey) -> Result<PinnedRotationSigner, RotationError> {
    let reference = key.reference.as_str();
    let public = key.signer.public_key();
    if reference.is_empty()
        || reference.len() > MAX_SIGNER_REFERENCE_BYTES
        || validate_public_key(&public).is_err()
    {
        return Err(unavailable());
    }
    Ok(PinnedRotationSigner {
        public,
        signer: Arc::clone(&key.signer),
    })
}

/// Pure selection of a pinned signer without store or lock: requires all pending handles and the current
/// signer; retired handles are optional. The greatest eligible ordinal wins implicitly (later index —
/// larger ordinal); there is no fallback. The snapshot is already fully validated; after a fresh clock
/// sample only interval arithmetic remains.
fn select_pinned(
    keys: &HashMap<(String, String), PinnedRotationSigner>,
    snapshot: &ServerSnapshot,
    clock: &ClockTuple,
) -> Result<PinnedRotationSigner, RotationError> {
    let mut selected: Option<&PinnedRotationSigner> = None;
    let mut pending = 0usize;
    let mut retired = 0usize;
    for (index, key) in snapshot.public.keys.iter().enumerate() {
        let eligible = key.not_before <= clock.high_water
            && key
                .known_cutoff
                .is_none_or(|cutoff| clock.high_water < cutoff);
        let is_pending = key.not_before > clock.high_water;
        if is_pending {
            pending += 1;
        }
        if key
            .known_cutoff
            .is_some_and(|cutoff| cutoff <= clock.high_water)
        {
            retired += 1;
        }
        if pending > MAX_PENDING || retired > MAX_RETIRED {
            return Err(unavailable());
        }
        // Retired handles are optional: they are skipped before the reference lookup.
        if !eligible && !is_pending {
            continue;
        }
        // Validated snapshots guarantee equal lengths; defensive refuse on a mismatch.
        let reference = snapshot
            .signer_references
            .get(index)
            .ok_or_else(unavailable)?;
        let signer = keys
            .get(&(reference.reference.clone(), key.kid.clone()))
            .ok_or_else(unavailable)?;
        // Identity theft guard: the pinned public key must match the committed key.
        if signer.public != key.public_key {
            return Err(unavailable());
        }
        if eligible {
            selected = Some(signer);
        }
    }
    selected.cloned().ok_or_else(unavailable)
}

fn snapshot_signer_kid(snapshot: &ServerSnapshot, public: &[u8; 32]) -> String {
    snapshot
        .public
        .keys
        .iter()
        .find(|key| &key.public_key == public)
        .map(|key| key.kid.clone())
        .unwrap_or_default()
}

/// Go matchesNativeResponse: the page must exactly continue the committed ring, otherwise refusal.
fn matches_page(
    page: &DecodedResult,
    snapshot: &ServerSnapshot,
    signer: &PinnedRotationSigner,
) -> bool {
    if page.current_public_key != signer.public
        || page.current_kid != snapshot_signer_kid(snapshot, &signer.public)
        || page.head_ordinal != snapshot.public.head.ordinal
        || page.head_hash != snapshot.public.head.hash
    {
        return false;
    }
    if page.records.is_empty() {
        return page.complete;
    }
    // The first matching start is fixed as in Go; later ones are not tried.
    let Some(start) = snapshot
        .public
        .records
        .iter()
        .position(|wire| wire == &page.records[0])
    else {
        return false;
    };
    let end = start + page.records.len();
    if end > snapshot.public.records.len()
        || page.complete != (end == snapshot.public.records.len())
    {
        return false;
    }
    snapshot.public.records[start..end] == page.records[..]
}

// Map-only schema: plain derive tolerates unknown members like Go partial unmarshal;
// a missing id breaks parsing — the same outcome as Go's nil-id path.
#[derive(Deserialize)]
struct EnvelopeId {
    id: Box<RawValue>,
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> RotationServerProvider<C> {
    /// Does not create state and does not authorize publication; refuses if the ring is not ready for serving.
    /// The input inventory is copied: later caller mutations do not change the pinned identity.
    pub fn new(
        store: Arc<Mutex<RotationServerStore<C>>>,
        keys: Vec<RotationServerKey>,
    ) -> Result<Self, RotationError> {
        if keys.is_empty() || keys.len() > MAX_RETAINED_KEYS {
            return Err(unavailable());
        }
        let mut pinned: HashMap<(String, String), PinnedRotationSigner> =
            HashMap::with_capacity(keys.len());
        for key in keys {
            let signer = pin(&key)?;
            // Rust equivalent of TS identity(reference, kid): a composite key instead of a JSON string.
            let identity = (key.reference.clone(), key_id(&signer.public));
            if pinned.contains_key(&identity) {
                return Err(unavailable());
            }
            pinned.insert(identity, signer);
        }
        let provider = Self {
            store,
            keys: pinned,
            publishing: AtomicBool::new(false),
            announce_ring_keys: MAX_ANNOUNCE_RING_KEYS,
        };
        provider.ready()?;
        Ok(provider)
    }

    /// Test only: lowers the announce bound so a test need not build a real 1025-key ring.
    #[cfg(test)]
    pub(crate) fn set_announce_ring_keys_for_tests(&mut self, bound: usize) {
        self.announce_ring_keys = bound;
    }

    /// Readiness: committed ring, fresh ClockGuard, and all pending/current handles available.
    pub fn ready(&self) -> Result<(), RotationError> {
        let mut store = self.lock_store();
        let _lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        let (snapshot, _) = store.snapshot()?;
        let clock = store.check_snapshot_clock(&snapshot)?;
        let _ = self.select_signer(&snapshot, &clock)?;
        Ok(())
    }

    /// Requires handles of all pending keys and the current signer; retired handles are optional.
    /// No fallback: greatest eligible ordinal or refusal. Pure function without store access.
    pub fn select_signer(
        &self,
        snapshot: &ServerSnapshot,
        clock: &ClockTuple,
    ) -> Result<PinnedRotationSigner, RotationError> {
        select_pinned(&self.keys, snapshot, clock)
    }

    /// One explicit authorization for a pre-configured next handle. P is fixed by a single
    /// fresh sample; refusal, conflict, or unknown is not retried automatically.
    pub fn announce(
        &self,
        reference: &str,
        kid: &str,
    ) -> Result<RotationPublication, RotationError> {
        // Reentrancy gate: nested publication from a signer callback refuses immediately.
        if self
            .publishing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(unavailable());
        }
        let _reset = PublicationReset(&self.publishing);
        // Unknown inventory entry refuses before the store and before the first clock sample.
        let next = self
            .keys
            .get(&(reference.to_owned(), kid.to_owned()))
            .ok_or_else(unavailable)?;
        let mut store = self.lock_store();
        let _lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        let (snapshot, _) = store.snapshot()?;
        if snapshot.public.head.ordinal == MAX_ORDINAL
            || snapshot.public.revision == MAX_ORDINAL
            || snapshot.public.keys.len() >= self.announce_ring_keys
            || snapshot.public.keys.len() >= MAX_RETAINED_KEYS
        {
            return Err(unavailable());
        }
        if snapshot
            .public
            .keys
            .iter()
            .any(|key| key.kid == kid || key.public_key == next.public)
        {
            return Err(unavailable());
        }
        let last = snapshot.public.keys.last().ok_or_else(unavailable)?;
        let tail = snapshot.signer_references.last().ok_or_else(unavailable)?;
        let old = self
            .keys
            .get(&(tail.reference.clone(), last.kid.clone()))
            .ok_or_else(unavailable)?;
        if old.public != last.public_key {
            return Err(unavailable());
        }
        // A matching checkpoint is taken as is; otherwise previous is derived from the last key.
        let previous = if last.ordinal == snapshot.public.checkpoint.ordinal {
            snapshot.public.checkpoint.clone()
        } else {
            Checkpoint {
                ordinal: last.ordinal,
                hash: snapshot.public.head.hash.clone(),
                kid: last.kid.clone(),
                public_key: last.public_key,
                // Go subtracts explicitly; validation makes the subtraction exact — checked against a corrupt store.
                published_at: last
                    .not_before
                    .checked_sub(GRACE_SECONDS)
                    .ok_or_else(unavailable)?,
            }
        };
        let clock = store.check_snapshot_clock(&snapshot)?;
        // Signer callbacks run WITHOUT the store lock: the hook may itself advance the committed clock.
        drop(store);
        if clock.high_water > MAX_TIMESTAMP - GRACE_SECONDS {
            return Err(unavailable());
        }
        self.select_signer(&snapshot, &clock)?;
        if snapshot
            .public
            .keys
            .iter()
            .filter(|key| key.not_before > clock.high_water)
            .count()
            >= MAX_PENDING
        {
            return Err(unavailable());
        }
        // Any CreateRecord error is mapped to unavailable; Go createPublication does recover.
        // Callback panics are deliberately not caught (crate-wide policy, unlike Go recover).
        let record = create_record(
            Binding {
                endpoint: &snapshot.public.binding.endpoint,
                aud: &snapshot.public.binding.aud,
            },
            &previous,
            old.as_ref(),
            next.as_ref(),
            clock.high_water,
        )
        .map_err(|_| unavailable())?;
        let mut public = snapshot.public.clone();
        let mut signer_references = snapshot.signer_references.clone();
        public.records.push(record.wire.clone());
        if let Some(retained) = public.keys.last_mut() {
            retained.known_cutoff = Some(record.activates_at);
        }
        public.keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        public.head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
        };
        // The MAX check above guarantees increment precision.
        public.revision += 1;
        public.clock = clock.clone();
        signer_references.push(SignerReference {
            kid: kid.to_owned(),
            reference: reference.to_owned(),
        });
        let desired = ServerSnapshot {
            format_version: snapshot.format_version,
            public,
            signer_references,
        };
        let mut store = self.lock_store();
        // Raw store error: rotation_state_changed must pass through verbatim and does not fence the owner.
        store.compare_and_swap(&snapshot, &desired, &clock)?;
        Ok(RotationPublication {
            record,
            revision: desired.public.revision,
        })
    }

    /// A poisoned lock does not panic: fail closed via the store's own state.
    fn lock_store(&self) -> MutexGuard<'_, RotationServerStore<C>> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Full envelope parse before the signing-time clock; no page for non-key-authority responses.
    fn response_page(
        &self,
        input: &ResponseKeyRequest,
    ) -> Result<Option<DecodedResult>, RotationError> {
        if input.tool != TOOL_SERVER_KEY || input.status != 200 {
            return Ok(None);
        }
        if input.body.len() > MAX_RESULT_BODY_BYTES {
            return Err(unavailable());
        }
        let envelope: EnvelopeId = serde_json::from_slice(input.body).map_err(|_| unavailable())?;
        decode_result(input.body, envelope.id.get().as_bytes())
            .map(Some)
            .map_err(|_| unavailable())
    }
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> ResponseKeys
    for RotationServerProvider<C>
{
    /// Does not trust body/tool when selecting the identity and does not fall back. Final is one-shot
    /// (Box<dyn FnOnce> is consumed by the call — Go's finalized CAS is not needed); Release is required
    /// after the physical write, also on any error.
    fn authorize_response(
        &self,
        input: &ResponseKeyRequest,
    ) -> Result<ResponseKeyAuthorization, RotationError> {
        let page = self.response_page(input)?;
        let mut store = self.lock_store();
        let lease = store.acquire_serving_lease().map_err(|_| unavailable())?;
        // Unlike announce, store errors here are sanitized into unavailable (Go parity).
        let (snapshot, _) = store.snapshot().map_err(|_| unavailable())?;
        let clock = store
            .check_snapshot_clock(&snapshot)
            .map_err(|_| unavailable())?;
        let signer = self
            .select_signer(&snapshot, &clock)
            .map_err(|_| unavailable())?;
        if let Some(page) = &page {
            if !matches_page(page, &snapshot, &signer) {
                return Err(unavailable());
            }
        }
        drop(store);
        let released = Arc::new(AtomicBool::new(false));
        let release_flag = Arc::clone(&released);
        let release: Release = Box::new(move || {
            // CAS mirrors Go: release is logically one-shot; the lease in the box also fails on drop without a call.
            if release_flag
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                drop(lease);
            }
        });
        let signer_public = signer.public;
        let high_water = clock.high_water;
        let window = snapshot.public.window;
        // select_signer reads only the pinned inventory: a copy is equivalent to Go's captured provider.
        let keys = self.keys.clone();
        let gate_store = Arc::clone(&self.store);
        let gate_released = Arc::clone(&released);
        let final_gate: FinalGate = Box::new(move || {
            if gate_released.load(Ordering::SeqCst) {
                return Err(unavailable());
            }
            let mut store = gate_store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let fresh = store
                .check_snapshot_clock(&snapshot)
                .map_err(|_| unavailable())?;
            // Window freshness is strictly upward and no further than window; the subtraction is guarded by the first branch.
            if fresh.high_water < high_water || fresh.high_water - high_water > window {
                return Err(unavailable());
            }
            let current = select_pinned(&keys, &snapshot, &fresh).map_err(|_| unavailable())?;
            if current.public != signer_public || gate_released.load(Ordering::SeqCst) {
                return Err(unavailable());
            }
            Ok(())
        });
        Ok(ResponseKeyAuthorization {
            signer: Arc::new(signer),
            timestamp: high_water,
            final_gate,
            release,
        })
    }

    /// The committed ring is read under the same serving lease as `authorize_response`: a
    /// store error or an unknown/uncut `kid` is `None`, never a guess (spec 05 5.1).
    fn successor_activation(&self, kid: &str) -> Option<i64> {
        let mut store = self.lock_store();
        let _lease = store.acquire_serving_lease().ok()?;
        let (snapshot, _) = store.snapshot().ok()?;
        snapshot
            .public
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .and_then(|key| key.known_cutoff)
            .and_then(|cutoff| i64::try_from(cutoff).ok())
    }
}
