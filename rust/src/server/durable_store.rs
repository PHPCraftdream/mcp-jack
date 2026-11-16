//! Durable authenticated nonce store: exclusive lifetime owner, intent and
//! final transactions, monotone clock high-water, bounded purge (Go:
//! durable/store.go, admit.go, transaction.go, private_linux.go).
//!
//! Every transaction is one atomic whole-file snapshot replacement (temp file,
//! fsync, rename, directory fsync). An uncertain persist fences the store and
//! reports `durability_unavailable`; nothing is retried or repaired.

use super::durable_format::{
    counter_to_usize, decode_state, encode_state, expiry_key, intent_id, validate_record,
    DurableReceipt, DurableRecord, DurableState, DurableStoreError, RecordKind, FORMAT_VERSION,
    MAX_COMBINED_ROWS, MAX_DEPLOYMENT_BYTES, MAX_FILE_BYTES, MAX_PURGE_REMOVALS, MAX_TIMESTAMP,
    MAX_TOMBSTONES,
};
use crate::encoding::{body_hash, decode_b64url_fixed, encode_b64url};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Admission refusal with the exact candidate HTTP status and code
/// (spec sections 2 and 5); deliberately generic, no backend detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableAdmissionError {
    pub status: u16,
    pub code: &'static str,
}

pub(crate) fn admission_error(status: u16, code: &'static str) -> DurableAdmissionError {
    DurableAdmissionError { status, code }
}

pub(crate) fn unavailable() -> DurableAdmissionError {
    admission_error(503, "durability_unavailable")
}

/// Deployment identity plus the immutable window W for one store generation.
#[derive(Debug, Clone)]
pub struct DurableStoreOptions {
    pub deployment_id: String,
    pub window: i64,
}

pub(crate) fn normalized_options(options: &DurableStoreOptions) -> Result<(), DurableStoreError> {
    if options.deployment_id.is_empty()
        || options.deployment_id.len() > MAX_DEPLOYMENT_BYTES
        || options.window < 1
        || options.window > 120
    {
        return Err(DurableStoreError::InvalidStore);
    }
    Ok(())
}

/// One authenticated, already-signed request admitted to durable storage.
/// `snapshot_valid` revalidates the captured active-key/enrollment snapshot at
/// a fresh raw sample; false means `state_changed` with no retry.
pub struct DurableAdmission<'a> {
    pub kid: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
    pub signing_bytes: &'a [u8],
    pub timestamp: i64,
    pub window: i64,
    pub snapshot_valid: fn(i64) -> bool,
}

/// Dirty-serving lease over one committed reservation; dropping it releases
/// the store's drain counter. Validity is re-checked after every await point.
#[must_use = "a dropped lease no longer holds the dirty serving epoch"]
pub struct DurableLease {
    shared: Arc<StoreShared>,
}

impl DurableLease {
    /// False once the store fenced, began closing, or closed.
    pub fn valid(&self) -> bool {
        !self.shared.fenced.load(Ordering::SeqCst)
            && !self.shared.closing.load(Ordering::SeqCst)
            && !self.shared.closed.load(Ordering::SeqCst)
    }
}

impl Drop for DurableLease {
    fn drop(&mut self) {
        self.shared.leases.fetch_sub(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for DurableLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableLease")
            .field("valid", &self.valid())
            .field("leases", &self.shared.leases.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct StoreShared {
    fenced: AtomicBool,
    closing: AtomicBool,
    closed: AtomicBool,
    leases: AtomicUsize,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], DurableStoreError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| DurableStoreError::Unavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(DurableStoreError::Unavailable);
    }
    Ok(bytes)
}

/// Lifetime-exclusive owner via a create-exclusive marker file beside the
/// store (owner-marker lease pattern of the rotation private-file store).
/// Drop does NOT remove the marker: a crash leaves the store fail-closed.
pub(crate) struct OwnerFile {
    parent: File,
    parent_path: PathBuf,
    name: OsString,
    marker_name: OsString,
    marker: Vec<u8>,
}

fn unavailable_store() -> DurableStoreError {
    DurableStoreError::Unavailable
}

/// Only explicitly listed local filesystems are accepted; this is not
/// power-loss certification (same gate as the rotation private-file store).
fn directory(path: &Path) -> Result<File, DurableStoreError> {
    let uid = rustix::process::geteuid().as_raw();
    if uid != rustix::process::getuid().as_raw()
        || !path.is_absolute()
        || path.as_os_str().as_bytes().len() > 4096
    {
        return Err(unavailable_store());
    }
    let mut normalized = PathBuf::from("/");
    let mut current = File::from(
        fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| unavailable_store())?,
    );
    let validate = |file: &File, leaf: bool| -> Result<(), DurableStoreError> {
        let metadata = file.metadata().map_err(|_| unavailable_store())?;
        let mode = metadata.mode();
        if !metadata.is_dir()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0))
            || (leaf && (metadata.uid() != uid || mode & 0o7777 != 0o700))
        {
            return Err(unavailable_store());
        }
        Ok(())
    };
    validate(&current, false)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = File::from(
                    fs::openat(
                        &current,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| unavailable_store())?,
                );
                normalized.push(name);
            }
            _ => return Err(unavailable_store()),
        }
    }
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
        return Err(unavailable_store());
    }
    validate(&current, true)?;
    let kind = fs::fstatfs(&current)
        .map_err(|_| unavailable_store())?
        .f_type;
    if ![0xef53, 0x58465342, 0x9123683e].contains(&(i128::from(kind) & 0xffff_ffff)) {
        return Err(unavailable_store());
    }
    Ok(current)
}

impl OwnerFile {
    /// Creates the marker exclusively; a second owner (or a crash-left
    /// marker) is refused.
    pub(crate) fn acquire(path: &Path) -> Result<Self, DurableStoreError> {
        let parent_path = path.parent().ok_or_else(unavailable_store)?.to_path_buf();
        let name = path
            .file_name()
            .ok_or_else(unavailable_store)?
            .to_os_string();
        let mut canonical = parent_path.clone();
        canonical.push(&name);
        if canonical.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
            return Err(unavailable_store());
        }
        let parent = directory(&parent_path)?;
        let mut marker_name = name.clone();
        marker_name.push(".owner");
        let marker = format!(
            "mcp-jack/durable-nonce-owner/v1\n{}\n",
            encode_b64url(&random_bytes::<32>()?)
        )
        .into_bytes();
        let file = fs::openat(
            &parent,
            marker_name.as_os_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| unavailable_store())?;
        let written = (|| {
            let mut file = File::from(file);
            file.write_all(&marker).map_err(|_| unavailable_store())?;
            file.sync_all().map_err(|_| unavailable_store())
        })();
        if written.is_err() || parent.sync_all().is_err() {
            return Err(unavailable_store());
        }
        Ok(Self {
            parent,
            parent_path,
            name,
            marker_name,
            marker,
        })
    }

    /// Revalidates the parent identity and that our marker still exists.
    fn ensure(&self) -> Result<(), DurableStoreError> {
        let current = directory(&self.parent_path)?;
        let left = current.metadata().map_err(|_| unavailable_store())?;
        let right = self.parent.metadata().map_err(|_| unavailable_store())?;
        if left.dev() != right.dev()
            || left.ino() != right.ino()
            || read_at(&self.parent, self.marker_name.as_os_str(), 128)? != self.marker
        {
            return Err(unavailable_store());
        }
        Ok(())
    }

    /// Explicit clean release: unlinks the marker; an error leaves it in place
    /// so reopening stays fenced.
    pub(crate) fn release(&self) -> Result<(), DurableStoreError> {
        self.ensure()?;
        if fs::unlinkat(&self.parent, self.marker_name.as_os_str(), AtFlags::empty()).is_err()
            || self.parent.sync_all().is_err()
        {
            return Err(unavailable_store());
        }
        Ok(())
    }
}

fn read_at(parent: &File, name: &OsStr, maximum: usize) -> Result<Vec<u8>, DurableStoreError> {
    let mut file = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| unavailable_store())?,
    );
    let metadata = file.metadata().map_err(|_| unavailable_store())?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() < 32
        || metadata.len() > u64::try_from(maximum).map_err(|_| unavailable_store())?
    {
        return Err(DurableStoreError::InvalidStore);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| unavailable_store())?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| unavailable_store())?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(|_| unavailable_store())? != 0 {
        return Err(unavailable_store());
    }
    Ok(bytes)
}

/// Atomic snapshot replacement: temp file, fsync, rename, directory fsync.
pub(crate) fn write_state_bytes(owner: &OwnerFile, bytes: &[u8]) -> Result<(), DurableStoreError> {
    write_snapshot(owner, bytes)
}

/// Bounded, strictly validated full-file read (crate-internal).
pub(crate) fn read_state_bytes(owner: &OwnerFile) -> Result<Vec<u8>, DurableStoreError> {
    read_at(&owner.parent, owner.name.as_os_str(), MAX_FILE_BYTES)
}

/// Atomic snapshot replacement: temp file, fsync, rename, directory fsync.
fn write_snapshot(owner: &OwnerFile, bytes: &[u8]) -> Result<(), DurableStoreError> {
    let temporary = OsString::from(format!(
        ".mcp-jack-nonce-{}.tmp",
        encode_b64url(&random_bytes::<16>()?)
    ));
    let file = fs::openat(
        &owner.parent,
        temporary.as_os_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| unavailable_store())?;
    let result = (|| {
        let mut file = File::from(file);
        file.write_all(bytes).map_err(|_| unavailable_store())?;
        file.sync_all().map_err(|_| unavailable_store())?;
        owner.ensure()?;
        fs::renameat(
            &owner.parent,
            temporary.as_os_str(),
            &owner.parent,
            owner.name.as_os_str(),
        )
        .map_err(|_| unavailable_store())?;
        owner.parent.sync_all().map_err(|_| unavailable_store())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&owner.parent, temporary.as_os_str(), AtFlags::empty());
    }
    result
}

/// One open owner's full session; all mutation happens under the store mutex.
struct Session<C: FnMut() -> i64> {
    owner: OwnerFile,
    state: DurableState,
    now: C,
    shared: Arc<StoreShared>,
}

impl<C: FnMut() -> i64> Session<C> {
    fn blocked(&self) -> bool {
        self.shared.fenced.load(Ordering::SeqCst)
            || self.shared.closing.load(Ordering::SeqCst)
            || self.shared.closed.load(Ordering::SeqCst)
    }

    fn fence(&self) {
        self.shared.fenced.store(true, Ordering::SeqCst);
    }

    /// Refusal that fences: the store cannot prove a safe continuing state.
    fn fence_unavailable(&self) -> DurableAdmissionError {
        self.fence();
        unavailable()
    }

    fn persist(&self, state: &DurableState) -> Result<(), DurableStoreError> {
        let bytes = encode_state(state)?;
        write_snapshot(&self.owner, &bytes)
    }

    /// One durable transaction: apply to a staged copy and replace the
    /// in-memory state only after a successful persist (Go: transaction.go
    /// rolls the tx back and keeps `s.meta` untouched on refusal). A definite
    /// callback refusal therefore never leaks a purge or high-water raise that
    /// disk does not hold; an uncertain persist fences the store.
    fn update(
        &mut self,
        apply: impl FnOnce(&mut DurableState) -> Result<(), DurableAdmissionError>,
    ) -> Result<(), DurableAdmissionError> {
        if self.blocked() {
            return Err(unavailable());
        }
        let mut staged = self.state.clone();
        match apply(&mut staged) {
            Err(error) => Err(error),
            Ok(()) => match self.persist(&staged) {
                Ok(()) => {
                    self.state = staged;
                    Ok(())
                }
                Err(_) => Err(self.fence_unavailable()),
            },
        }
    }

    /// Clock-sample gate (Go: checkSample). Out-of-domain or below-H samples
    /// durably latch the unsafe fence before `clock_unsafe` is returned;
    /// uncertain latch writes remain unknown `durability_unavailable`.
    fn check_sample(
        &mut self,
        request: &DurableAdmission<'_>,
        now: i64,
        prepared: Option<&DurableRecord>,
    ) -> Result<(), DurableAdmissionError> {
        if self.blocked() {
            return Err(unavailable());
        }
        if !(0..=MAX_TIMESTAMP).contains(&now) || now < self.state.metadata.high_water.get() {
            let latched = self.update(|state| {
                if let Some(row) = prepared {
                    remove_exact_intent(state, row)?;
                }
                state.metadata.unsafe_latched = true;
                Ok(())
            });
            return match latched {
                Ok(()) => {
                    // The latch is durable: the store must stay fenced.
                    self.fence();
                    Err(admission_error(503, "clock_unsafe"))
                }
                Err(_) => Err(unavailable()),
            };
        }
        let rejection = if !(request.snapshot_valid)(now) {
            Some(admission_error(503, "state_changed"))
        } else {
            let difference = now - request.timestamp;
            if difference > request.window || -difference > request.window {
                Some(admission_error(401, "timestamp_out_of_window"))
            } else {
                None
            }
        };
        if let Some(error) = rejection {
            if let Some(row) = prepared {
                self.update(|state| remove_exact_intent(state, row))?;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Authoritative replay/intent lookup (Go: replayLookup). A live row is a
    /// replay while `now <= retainUntil`; unresolved intents/tombstones are
    /// conflicting unresolved state, never an absence proof.
    fn replay_lookup(&self, key: [u8; 48], now: i64) -> Result<(), DurableAdmissionError> {
        if let Some(row) = self.state.live.get(&key) {
            if now <= row.retain_until {
                return Err(admission_error(401, "replayed_nonce"));
            }
        }
        if self.state.intents.contains_key(&key) || self.state.tombstones.contains_key(&key) {
            return Err(unavailable());
        }
        Ok(())
    }

    fn reserve_locked(
        &mut self,
        request: &DurableAdmission<'_>,
    ) -> Result<(DurableReceipt, DurableLease), DurableAdmissionError> {
        if self.blocked() {
            return Err(unavailable());
        }
        if request.window != self.state.metadata.window {
            return Err(admission_error(503, "state_changed"));
        }
        if request.timestamp < 0 || request.timestamp > MAX_TIMESTAMP - request.window {
            return Err(admission_error(401, "timestamp_out_of_window"));
        }
        let kid = match decode_b64url_fixed(request.kid, 32) {
            Ok(kid) => kid,
            Err(_) => return Err(self.fence_unavailable()),
        };
        let nonce = match decode_b64url_fixed(request.nonce, 16) {
            Ok(nonce) => nonce,
            Err(_) => return Err(self.fence_unavailable()),
        };
        if decode_b64url_fixed(request.signature, 64).is_err() {
            return Err(self.fence_unavailable());
        }
        let mut key = [0; 48];
        key[..32].copy_from_slice(&kid);
        key[32..].copy_from_slice(&nonce);
        let entry_now = (self.now)();
        self.check_sample(request, entry_now, None)?;
        self.replay_lookup(key, entry_now)?;
        // Unique operation id within the deployment; one retry, then refuse.
        let mut operation = random_bytes::<16>().map_err(|_| self.fence_unavailable())?;
        let mut unique = false;
        for _ in 0..2 {
            if self.state.operations.contains_key(&operation) {
                operation = random_bytes::<16>().map_err(|_| self.fence_unavailable())?;
            } else {
                unique = true;
                break;
            }
        }
        if !unique || self.state.operations.contains_key(&operation) {
            return Err(self.fence_unavailable());
        }
        let signature =
            decode_b64url_fixed(request.signature, 64).map_err(|_| self.fence_unavailable())?;
        let request_hash = body_hash(request.signing_bytes);
        let request_hash_raw =
            decode_b64url_fixed(&request_hash, 32).map_err(|_| self.fence_unavailable())?;
        let intent_now = (self.now)();
        self.check_sample(request, intent_now, None)?;
        let intent_id = intent_id(
            &self.state.metadata,
            &key,
            &signature,
            &request_hash_raw,
            &operation,
        );
        let mut prepared = DurableRecord {
            kind: RecordKind::Intent,
            key,
            store_id: self.state.metadata.store_id,
            receipt: DurableReceipt {
                version: FORMAT_VERSION,
                deployment: self.state.metadata.deployment.clone(),
                store_generation: self.state.metadata.generation,
                owner_generation: self.state.metadata.owner,
                intent_id,
                operation_id: operation,
                kid: request.kid.to_owned(),
                nonce: request.nonce.to_owned(),
                signature: request.signature.to_owned(),
                request_hash,
                timestamp: request.timestamp,
                retain_until: request
                    .timestamp
                    .checked_add(request.window)
                    .ok_or_else(|| self.fence_unavailable())?,
                high_water: intent_now,
            },
        };
        // Intent transaction: fresh sample, revalidated replay, bounded purge,
        // atomic capacity check counting intents, unique operation id.
        self.update(|state| {
            replay_lookup_state(state, key, intent_now)?;
            purge_expired(state, intent_now, key)?;
            if counter_to_usize(state.metadata.live) + counter_to_usize(state.metadata.intents)
                >= MAX_COMBINED_ROWS
                || counter_to_usize(state.metadata.tombstones) >= MAX_TOMBSTONES
            {
                return Err(admission_error(503, "capacity_exhausted"));
            }
            if state.operations.contains_key(&operation) {
                return Err(unavailable());
            }
            state.intents.insert(key, prepared.receipt.clone());
            state.operations.insert(operation, key);
            state.metadata.intents = state
                .metadata
                .intents
                .checked_add(1)
                .ok_or_else(unavailable)?;
            Ok(())
        })?;
        // Final transaction: fresh sample and full revalidation, then the
        // exact intent slot is replaced by the live reservation.
        let final_now = (self.now)();
        self.check_sample(request, final_now, Some(&prepared))?;
        let intent_receipt = prepared.receipt.clone();
        prepared.kind = RecordKind::Live;
        prepared.receipt.high_water = final_now;
        let committed = prepared.receipt.clone();
        self.update(|state| {
            if state.intents.get(&key) != Some(&intent_receipt)
                || state.operations.get(&operation) != Some(&key)
            {
                return Err(unavailable());
            }
            if state.metadata.intents == 0
                || counter_to_usize(state.metadata.live) >= MAX_COMBINED_ROWS
            {
                return Err(unavailable());
            }
            state.metadata.high_water.raise(final_now);
            // The operation index keeps its entry: the live row carries the same operation id.
            state.intents.remove(&key);
            state.live.insert(key, committed.clone());
            state
                .expiry
                .insert(expiry_key(committed.retain_until, &key));
            state.metadata.intents -= 1;
            state.metadata.live = state.metadata.live.checked_add(1).ok_or_else(unavailable)?;
            Ok(())
        })?;
        self.shared.leases.fetch_add(1, Ordering::SeqCst);
        Ok((
            committed,
            DurableLease {
                shared: Arc::clone(&self.shared),
            },
        ))
    }
}

fn replay_lookup_state(
    state: &DurableState,
    key: [u8; 48],
    now: i64,
) -> Result<(), DurableAdmissionError> {
    if let Some(row) = state.live.get(&key) {
        if now <= row.retain_until {
            return Err(admission_error(401, "replayed_nonce"));
        }
    }
    if state.intents.contains_key(&key) || state.tombstones.contains_key(&key) {
        return Err(unavailable());
    }
    Ok(())
}

/// Removes exactly the prepared intent slot; any mismatch is store-invalid.
fn remove_exact_intent(
    state: &mut DurableState,
    prepared: &DurableRecord,
) -> Result<(), DurableAdmissionError> {
    if state.intents.get(&prepared.key) != Some(&prepared.receipt)
        || state.operations.get(&prepared.receipt.operation_id) != Some(&prepared.key)
    {
        return Err(unavailable());
    }
    state.intents.remove(&prepared.key);
    state.operations.remove(&prepared.receipt.operation_id);
    state.metadata.intents = state
        .metadata
        .intents
        .checked_sub(1)
        .ok_or_else(unavailable)?;
    Ok(())
}

/// Bounded purge (Go: purgeExpired): advances H first — no absence decision
/// may precede the H receipt — then removes at most 128 expired entries in
/// this transaction, always including the exact pair when it is expired.
fn purge_expired(
    state: &mut DurableState,
    now: i64,
    exact: [u8; 48],
) -> Result<(), DurableAdmissionError> {
    if now < state.metadata.high_water.get() {
        return Err(unavailable());
    }
    state.metadata.high_water.raise(now);
    let mut batch: Vec<[u8; 56]> = Vec::new();
    if let Some(row) = state.live.get(&exact) {
        if row.retain_until < now {
            batch.push(expiry_key(row.retain_until, &exact));
        }
    }
    for index in &state.expiry {
        if batch.len() >= MAX_PURGE_REMOVALS {
            break;
        }
        let raw = u64::from_be_bytes(index[..8].try_into().map_err(|_| unavailable())?);
        // Entries are ordered by retainUntil; the first live entry ends the scan.
        if raw > MAX_TIMESTAMP as u64 || (raw as i64) >= now {
            break;
        }
        if !batch.contains(index) {
            batch.push(*index);
        }
    }
    for index in batch {
        let mut key = [0; 48];
        key.copy_from_slice(&index[8..]);
        let row = state.live.get(&key).ok_or_else(unavailable)?;
        if expiry_key(row.retain_until, &key) != index || row.retain_until >= now {
            return Err(unavailable());
        }
        let operation_id = row.operation_id;
        if state.operations.get(&operation_id) != Some(&key) {
            return Err(unavailable());
        }
        state.live.remove(&key);
        state.expiry.remove(&index);
        state.operations.remove(&operation_id);
        state.metadata.live = state.metadata.live.checked_sub(1).ok_or_else(unavailable)?;
    }
    Ok(())
}

/// Lifetime-exclusive durable nonce store (Go: durable.Store). All admission
/// is serialized under one mutex that is never held across crypto or handler
/// execution: `reserve` returns after the final commit, before dispatch.
pub struct DurableNonceStore<C: FnMut() -> i64> {
    session: Mutex<Session<C>>,
    shared: Arc<StoreShared>,
}

impl<C: FnMut() -> i64> DurableNonceStore<C> {
    fn lock(&self) -> MutexGuard<'_, Session<C>> {
        // A panic while holding the lock can only come from allocation inside
        // BTreeMap operations; the lock is then poisoned and the store must
        // fence rather than continue (Go fences on any panic: admit.go).
        self.session.lock().unwrap_or_else(|poisoned| {
            self.shared.fenced.store(true, Ordering::SeqCst);
            poisoned.into_inner()
        })
    }

    /// Explicit out-of-band initialization for a proven never-used deployment
    /// (Go: InitializeUnused). Never overwrites an existing store and never
    /// migrates volatile history; on uncertain writes the artifact is kept
    /// fail-closed, not deleted or recreated.
    pub fn initialize_unused(
        path: &Path,
        options: &DurableStoreOptions,
        mut now: C,
    ) -> Result<(), DurableStoreError> {
        normalized_options(options)?;
        let owner = OwnerFile::acquire(path)?;
        let result = (|| {
            let sample = now();
            if !(0..=MAX_TIMESTAMP).contains(&sample) {
                return Err(DurableStoreError::InvalidStore);
            }
            let store_id = random_bytes::<16>()?;
            if store_id == [0; 16] {
                return Err(DurableStoreError::Unavailable);
            }
            // Claim the data file create-only before the first snapshot write.
            let claim = fs::openat(
                &owner.parent,
                owner.name.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| unavailable_store())?;
            drop(File::from(claim));
            let mut state = DurableState::fresh(
                options.deployment_id.clone(),
                store_id,
                1,
                1,
                options.window,
                sample,
            );
            write_snapshot(&owner, &encode_state(&state)?)?;
            // Dirty epoch confirmed first; only then is the store marked clean.
            state.metadata.dirty = false;
            write_snapshot(&owner, &encode_state(&state)?)?;
            owner.parent.sync_all().map_err(|_| unavailable_store())
        })();
        if result.is_err() {
            // Keep every store artifact for recovery; never reset the store.
            // The owner marker itself is released so a clean retry is possible;
            // any partially written data file still fails closed on open.
            let _ = owner.release();
            return result;
        }
        owner.release()
    }

    /// Opens only an existing initialized store; dirty/unsafe state always
    /// fails closed until explicit recovery (Go: Open). A new owner
    /// generation is established before the startup clock is observed.
    pub fn open(
        path: &Path,
        options: &DurableStoreOptions,
        mut now: C,
    ) -> Result<Self, DurableStoreError> {
        normalized_options(options)?;
        let owner = OwnerFile::acquire(path)?;
        let loaded = (|| {
            let bytes = read_at(&owner.parent, owner.name.as_os_str(), MAX_FILE_BYTES)?;
            let state = decode_state(&bytes)?;
            if state.metadata.deployment != options.deployment_id
                || state.metadata.window != options.window
            {
                return Err(DurableStoreError::InvalidStore);
            }
            if state.metadata.dirty || state.metadata.unsafe_latched {
                return Err(DurableStoreError::RecoveryRequired);
            }
            // A clean marker never proves a quiet store: unresolved intents or
            // a tombstone cap at the recovery boundary still fail closed
            // (Go: snapshot.go requireReady checks).
            if state.metadata.intents != 0
                || counter_to_usize(state.metadata.tombstones) >= MAX_TOMBSTONES
            {
                return Err(DurableStoreError::RecoveryRequired);
            }
            Ok(state)
        })();
        let mut state = match loaded {
            Ok(state) => state,
            Err(error) => {
                let _ = owner.release();
                return Err(error);
            }
        };
        let shared = Arc::new(StoreShared::default());
        let opened = (|| {
            state.metadata.owner += 1;
            state.metadata.dirty = true;
            write_snapshot(&owner, &encode_state(&state)?)?;
            // First confirm the dirty marker, then observe the startup clock.
            let sample = now();
            if !(0..=MAX_TIMESTAMP).contains(&sample) || sample < state.metadata.high_water.get() {
                state.metadata.unsafe_latched = true;
                let _ = write_snapshot(&owner, &encode_state(&state)?);
                return Err(DurableStoreError::RecoveryRequired);
            }
            state.metadata.high_water.raise(sample);
            write_snapshot(&owner, &encode_state(&state)?)
        })();
        if let Err(error) = opened {
            let _ = owner.release();
            return Err(error);
        }
        Ok(Self {
            session: Mutex::new(Session {
                owner,
                state,
                now,
                shared: Arc::clone(&shared),
            }),
            shared,
        })
    }

    /// Fences the store: admission refuses until the process exits; the
    /// persisted dirty epoch keeps the next startup closed.
    pub fn fence(&self) {
        self.shared.fenced.store(true, Ordering::SeqCst);
    }

    /// Stops admission, waits for leases, and clears the dirty epoch only
    /// when not fenced (Go: Close). The owner marker is released either way;
    /// a fenced close still leaves the persisted state fail-closed.
    pub fn close(&self) -> Result<(), DurableStoreError> {
        {
            let session = self.lock();
            if session.shared.closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            session.shared.closing.store(true, Ordering::SeqCst);
        }
        // Drain leases outside the lock (Go: Close sets `closing` under the
        // lock and waits via the lease WaitGroup outside it): a lease holder
        // may need the mutex and the runtime to finish. Short sleeps keep the
        // drain from burning a core.
        while self.shared.leases.load(Ordering::SeqCst) != 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut session = self.lock();
        let mut result = Ok(());
        if session.shared.fenced.load(Ordering::SeqCst) {
            result = Err(DurableStoreError::RecoveryRequired);
        } else if session.state.metadata.intents != 0
            || counter_to_usize(session.state.metadata.tombstones) >= MAX_TOMBSTONES
            || session.state.metadata.unsafe_latched
        {
            session.fence();
            result = Err(DurableStoreError::RecoveryRequired);
        }
        if !session.shared.fenced.load(Ordering::SeqCst) {
            session.state.metadata.dirty = false;
            if session.persist(&session.state).is_err() {
                session.fence();
                result = Err(DurableStoreError::Unavailable);
            }
        }
        if session.owner.release().is_err() && result.is_ok() {
            session.fence();
            result = Err(DurableStoreError::Unavailable);
        }
        session.shared.closed.store(true, Ordering::SeqCst);
        result
    }

    /// Coordinated durable admission: entry sample, intent transaction, final
    /// sample, final transaction (Go: Reserve). Confirmed intent is not
    /// dispatch permission; only the confirmed receipt is.
    pub fn reserve(
        &self,
        request: &DurableAdmission<'_>,
    ) -> Result<(DurableReceipt, DurableLease), DurableAdmissionError> {
        let result = self.lock().reserve_locked(request);
        // Only a non-definite outcome fences (Go definiteStorageRefusal): a 401, a
        // state_changed or a capacity_exhausted refusal leaves the store serving.
        if let Err(error) = &result {
            // A refusal caused by closing/closed is not an uncertainty
            // (Go: reserveLocked returns plain unavailable while closing).
            let definite = self.shared.closing.load(Ordering::SeqCst)
                || self.shared.closed.load(Ordering::SeqCst)
                || error.status != 503
                || matches!(error.code, "state_changed" | "capacity_exhausted");
            if !definite {
                self.shared.fenced.store(true, Ordering::SeqCst);
            }
        }
        result
    }

    /// Crate-internal metadata view for recovery and test seeding.
    pub(crate) fn snapshot_metadata(&self) -> super::durable_format::DurableMetadata {
        self.lock().state.metadata.clone()
    }

    /// Test-only: panics while holding the session lock, which poisons it. Kept
    /// out of the admission path so the unwind leaves no ghost in its coverage counters.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _session = self.lock();
        panic!("poison the session lock");
    }

    /// Test/recovery seeding: strictly validated rows inserted through the
    /// normal validation and persistence path (crate-internal only).
    pub(crate) fn seed_records(&self, records: &[DurableRecord]) -> Result<(), DurableStoreError> {
        let mut session = self.lock();
        if session.blocked() {
            return Err(DurableStoreError::Unavailable);
        }
        for record in records {
            let metadata = &session.state.metadata;
            let kind = record.kind;
            let key = record.key;
            let receipt = record.receipt.clone();
            if validate_record(record, metadata).is_err() {
                return Err(DurableStoreError::InvalidStore);
            }
            let target = match kind {
                RecordKind::Live => &mut session.state.live,
                RecordKind::Intent => &mut session.state.intents,
                RecordKind::Tombstone => &mut session.state.tombstones,
            };
            if target.insert(key, receipt).is_some() {
                return Err(DurableStoreError::InvalidStore);
            }
            if kind == RecordKind::Live {
                session
                    .state
                    .expiry
                    .insert(expiry_key(record.receipt.retain_until, &key));
            }
            session
                .state
                .operations
                .insert(record.receipt.operation_id, key);
            match kind {
                RecordKind::Live => session.state.metadata.live += 1,
                RecordKind::Intent => session.state.metadata.intents += 1,
                RecordKind::Tombstone => session.state.metadata.tombstones += 1,
            }
        }
        session.persist(&session.state)
    }
}

/// Recovery-snapshot hash: base64url(SHA-256) over the canonical whole-file
/// encoding; binds the full logical graph, not proof of absence of rollback.
pub(crate) fn snapshot_hash(state: &DurableState) -> Result<String, DurableStoreError> {
    let bytes = encode_state(state)?;
    Ok(encode_b64url(&Sha256::digest(&bytes)))
}
