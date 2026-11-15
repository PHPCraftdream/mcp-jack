//! Strict version-1 on-disk format for the durable authenticated nonce store
//! (Go: durable/metadata.go, record.go, layout.go).
//!
//! On-disk design: one whole-file snapshot, atomically replaced per
//! transaction with a temp file + fsync + rename + directory fsync, exactly
//! like the rotation stores. Every load enforces the exact version-1 schema
//! and every reject rule of spec section 3; nothing is truncated, repaired,
//! or evicted.

use crate::encoding::{decode_b64url_fixed, encode_b64url};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const MAX_TIMESTAMP: i64 = 999_999_999_999;
pub(crate) const MAX_DEPLOYMENT_BYTES: usize = 1024;
/// Combined live reservations plus outstanding intents (spec section 6).
pub(crate) const MAX_COMBINED_ROWS: usize = 4096;
pub(crate) const MAX_TOMBSTONES: usize = 64;
/// Expiry-index removals per purge transaction (spec section 6).
pub(crate) const MAX_PURGE_REMOVALS: usize = 128;
pub(crate) const MAX_FILE_BYTES: usize = 16 << 20;

const METADATA_MAGIC: &[u8] = b"mcp-jack/nonce-store/v1\n";
const FILE_MAGIC: &[u8] = b"mcp-jack/nonce-store/file/v1\n";
const MAX_METADATA_BYTES: usize = 2048;
const CHECKSUM_BYTES: usize = 32;

/// Store-level failures; admission refusals use `DurableAdmissionError` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStoreError {
    /// The store or its environment is currently unusable.
    Unavailable,
    /// The persisted state violates the version-1 contract.
    InvalidStore,
    /// Explicit out-of-band recovery is required before any reopen.
    RecoveryRequired,
}

/// Monotone clock high-water latch. Refuses to lower without any `unsafe`:
/// the only mutation is `raise`, so a stale sample can never turn the fence off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HighWater(i64);

impl HighWater {
    /// Builds a latch value; negative inputs saturate to zero so every
    /// persisted high-water stays a valid timestamp-like value.
    #[cfg(test)]
    pub(crate) fn new(value: i64) -> Self {
        Self(value.max(0))
    }

    pub(crate) fn get(self) -> i64 {
        self.0
    }

    /// Raises H to `sample` when strictly greater; returns true when raised.
    pub(crate) fn raise(&mut self, sample: i64) -> bool {
        if sample > self.0 {
            self.0 = sample;
            true
        } else {
            false
        }
    }
}

/// Converts a validated u32 counter; saturates instead of panicking.
pub(crate) fn counter_to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Exact committed receipt (spec section 1 tuple). `format_version` and the
/// deployment identity are part of every persisted record and receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReceipt {
    pub version: u8,
    pub deployment: String,
    pub store_generation: u64,
    pub owner_generation: u64,
    pub intent_id: String,
    pub operation_id: [u8; 16],
    pub kid: String,
    pub nonce: String,
    pub signature: String,
    pub request_hash: String,
    pub timestamp: i64,
    pub retain_until: i64,
    pub high_water: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Intent,
    Live,
    Tombstone,
}

impl RecordKind {
    pub(crate) fn value(self) -> u8 {
        match self {
            RecordKind::Intent => 1,
            RecordKind::Live => 2,
            RecordKind::Tombstone => 3,
        }
    }

    pub(crate) fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(RecordKind::Intent),
            2 => Some(RecordKind::Live),
            3 => Some(RecordKind::Tombstone),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableRecord {
    pub kind: RecordKind,
    pub key: [u8; 48],
    pub store_id: [u8; 16],
    pub receipt: DurableReceipt,
}

/// Exact version-1 store metadata (spec section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableMetadata {
    pub deployment: String,
    pub store_id: [u8; 16],
    pub generation: u64,
    pub owner: u64,
    pub window: i64,
    pub high_water: HighWater,
    pub live: u32,
    pub intents: u32,
    pub tombstones: u32,
    pub dirty: bool,
    pub unsafe_latched: bool,
}

pub(crate) type RowMap = BTreeMap<[u8; 48], DurableReceipt>;

/// The whole logical database: primary rows plus the explicit expiry and
/// operation indexes, whose agreement is enforced exactly at load and write.
#[derive(Debug, Clone)]
pub(crate) struct DurableState {
    pub metadata: DurableMetadata,
    pub live: RowMap,
    pub intents: RowMap,
    pub tombstones: RowMap,
    pub expiry: BTreeSet<[u8; 56]>,
    pub operations: BTreeMap<[u8; 16], [u8; 48]>,
}

impl DurableState {
    /// A fresh initialized store; it always starts in the dirty-serving epoch.
    pub(crate) fn fresh(
        deployment: String,
        store_id: [u8; 16],
        generation: u64,
        owner: u64,
        window: i64,
        high_water: i64,
    ) -> Self {
        Self {
            metadata: DurableMetadata {
                deployment,
                store_id,
                generation,
                owner,
                window,
                high_water: HighWater(high_water),
                live: 0,
                intents: 0,
                tombstones: 0,
                dirty: true,
                unsafe_latched: false,
            },
            live: RowMap::new(),
            intents: RowMap::new(),
            tombstones: RowMap::new(),
            expiry: BTreeSet::new(),
            operations: BTreeMap::new(),
        }
    }
}

/// Local intent identity: SHA-256 over the spec section 1 domain, the exact
/// deployment, raw key/signature/request-hash bytes, and the operation id.
pub(crate) fn intent_id(
    metadata: &DurableMetadata,
    key: &[u8; 48],
    signature: &[u8],
    request_hash: &[u8],
    operation: &[u8; 16],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mcp-jack/durable-nonce/intent/v1\n");
    hash.update(
        u16::try_from(metadata.deployment.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    hash.update(metadata.deployment.as_bytes());
    hash.update(key);
    hash.update(signature);
    hash.update(request_hash);
    hash.update(operation);
    encode_b64url(&hash.finalize())
}

/// Expiry index key: exactly `uint64be(retainUntil) || kid_raw || nonce_raw`.
pub(crate) fn expiry_key(retain_until: i64, key: &[u8; 48]) -> [u8; 56] {
    let mut index = [0; 56];
    index[..8].copy_from_slice(&(retain_until as u64).to_be_bytes());
    index[8..].copy_from_slice(key);
    index
}

/// Checksum detects accidental corruption, not malicious-host tampering or
/// backup rollback (Go: sealPayload).
pub(crate) fn seal_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    out.extend_from_slice(&Sha256::digest(payload));
    out
}

fn checked_payload(data: &[u8]) -> Result<&[u8], DurableStoreError> {
    if data.len() < CHECKSUM_BYTES {
        return Err(DurableStoreError::InvalidStore);
    }
    let (payload, checksum) = data.split_at(data.len() - CHECKSUM_BYTES);
    if Sha256::digest(payload).as_slice() != checksum {
        return Err(DurableStoreError::InvalidStore);
    }
    Ok(payload)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    put_u64(out, value as u64);
}

/// Minimal cursor over a fixed byte buffer; every overrun is a reject.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], DurableStoreError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DurableStoreError::InvalidStore)?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DurableStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DurableStoreError> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes(
            raw.try_into()
                .map_err(|_| DurableStoreError::InvalidStore)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, DurableStoreError> {
        let raw = self.take(4)?;
        Ok(u32::from_be_bytes(
            raw.try_into()
                .map_err(|_| DurableStoreError::InvalidStore)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DurableStoreError> {
        let raw = self.take(8)?;
        Ok(u64::from_be_bytes(
            raw.try_into()
                .map_err(|_| DurableStoreError::InvalidStore)?,
        ))
    }

    fn i64(&mut self) -> Result<i64, DurableStoreError> {
        let raw = self.u64()?;
        if raw > MAX_TIMESTAMP as u64 {
            return Err(DurableStoreError::InvalidStore);
        }
        Ok(raw as i64)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DurableStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DurableStoreError::InvalidStore)
    }

    fn done(&self) -> Result<(), DurableStoreError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(DurableStoreError::InvalidStore)
        }
    }
}

fn timestamp_domain(metadata: &DurableMetadata) -> Result<(), DurableStoreError> {
    if metadata.window < 1 || metadata.window > 120 {
        return Err(DurableStoreError::InvalidStore);
    }
    Ok(())
}

/// Strict metadata load: exact fields, canonical deployment, checked caps.
pub(crate) fn encode_metadata(metadata: &DurableMetadata) -> Result<Vec<u8>, DurableStoreError> {
    timestamp_domain(metadata)?;
    if metadata.deployment.is_empty()
        || metadata.deployment.len() > MAX_DEPLOYMENT_BYTES
        || metadata.generation == 0
        || metadata.owner == 0
        || metadata.deployment.len() > u16::MAX as usize
    {
        return Err(DurableStoreError::InvalidStore);
    }
    if metadata.high_water.get() < 0 || metadata.high_water.get() > MAX_TIMESTAMP {
        return Err(DurableStoreError::InvalidStore);
    }
    let mut out = Vec::new();
    out.extend_from_slice(METADATA_MAGIC);
    out.push(FORMAT_VERSION);
    put_u16(&mut out, metadata.deployment.len() as u16);
    out.extend_from_slice(metadata.deployment.as_bytes());
    out.extend_from_slice(&metadata.store_id);
    put_u64(&mut out, metadata.generation);
    put_u64(&mut out, metadata.owner);
    put_i64(&mut out, metadata.window);
    put_i64(&mut out, metadata.high_water.get());
    put_u32(&mut out, metadata.live);
    put_u32(&mut out, metadata.intents);
    put_u32(&mut out, metadata.tombstones);
    let mut flags = 0;
    if metadata.dirty {
        flags |= 1;
    }
    if metadata.unsafe_latched {
        flags |= 2;
    }
    out.push(flags);
    Ok(seal_payload(&out))
}

pub(crate) fn decode_metadata(data: &[u8]) -> Result<DurableMetadata, DurableStoreError> {
    if data.len() > MAX_METADATA_BYTES {
        return Err(DurableStoreError::InvalidStore);
    }
    let payload = checked_payload(data)?;
    if !payload.starts_with(METADATA_MAGIC) {
        return Err(DurableStoreError::InvalidStore);
    }
    let mut reader = Reader::new(&payload[METADATA_MAGIC.len()..]);
    if reader.u8()? != FORMAT_VERSION {
        return Err(DurableStoreError::InvalidStore);
    }
    let length = reader.u16()?;
    if length == 0 || length as usize > MAX_DEPLOYMENT_BYTES {
        return Err(DurableStoreError::InvalidStore);
    }
    let deployment = reader.take(length as usize)?;
    let deployment =
        std::str::from_utf8(deployment).map_err(|_| DurableStoreError::InvalidStore)?;
    let store_id = reader.fixed::<16>()?;
    if store_id == [0; 16] {
        return Err(DurableStoreError::InvalidStore);
    }
    let generation = reader.u64()?;
    let owner = reader.u64()?;
    if generation == 0 || owner == 0 {
        return Err(DurableStoreError::InvalidStore);
    }
    let window = reader.i64()?;
    let high_water = reader.i64()?;
    let live = reader.u32()?;
    let intents = reader.u32()?;
    let tombstones = reader.u32()?;
    let flags = reader.u8()?;
    reader.done()?;
    if flags > 3 {
        return Err(DurableStoreError::InvalidStore);
    }
    if counter_to_usize(live) + counter_to_usize(intents) > MAX_COMBINED_ROWS
        || counter_to_usize(tombstones) > MAX_TOMBSTONES
    {
        return Err(DurableStoreError::InvalidStore);
    }
    let metadata = DurableMetadata {
        deployment: deployment.to_owned(),
        store_id,
        generation,
        owner,
        window,
        high_water: HighWater(high_water),
        live,
        intents,
        tombstones,
        dirty: flags & 1 != 0,
        unsafe_latched: flags & 2 != 0,
    };
    timestamp_domain(&metadata)?;
    Ok(metadata)
}

/// Validates every per-record rule of spec section 3 against store metadata.
pub(crate) fn validate_record(
    record: &DurableRecord,
    metadata: &DurableMetadata,
) -> Result<(), DurableStoreError> {
    timestamp_domain(metadata)?;
    let receipt = &record.receipt;
    if receipt.version != FORMAT_VERSION
        || receipt.deployment != metadata.deployment
        || record.store_id != metadata.store_id
        || receipt.store_generation != metadata.generation
        || receipt.owner_generation == 0
        || receipt.owner_generation > metadata.owner
    {
        return Err(DurableStoreError::InvalidStore);
    }
    let kid = decode_b64url_fixed(&receipt.kid, 32).map_err(|_| DurableStoreError::InvalidStore)?;
    let nonce =
        decode_b64url_fixed(&receipt.nonce, 16).map_err(|_| DurableStoreError::InvalidStore)?;
    let signature =
        decode_b64url_fixed(&receipt.signature, 64).map_err(|_| DurableStoreError::InvalidStore)?;
    let request_hash = decode_b64url_fixed(&receipt.request_hash, 32)
        .map_err(|_| DurableStoreError::InvalidStore)?;
    if kid[..] != record.key[..32] || nonce[..] != record.key[32..] {
        return Err(DurableStoreError::InvalidStore);
    }
    let expected = intent_id(
        metadata,
        &record.key,
        &signature,
        &request_hash,
        &receipt.operation_id,
    );
    if receipt.intent_id != expected {
        return Err(DurableStoreError::InvalidStore);
    }
    if receipt.timestamp < 0
        || receipt.timestamp > MAX_TIMESTAMP - metadata.window
        || receipt.retain_until != receipt.timestamp + metadata.window
        || receipt.high_water < 0
        || receipt.high_water > MAX_TIMESTAMP
        || receipt.high_water > metadata.high_water.get()
    {
        return Err(DurableStoreError::InvalidStore);
    }
    let difference = receipt.high_water - receipt.timestamp;
    if difference > metadata.window || -difference > metadata.window {
        return Err(DurableStoreError::InvalidStore);
    }
    Ok(())
}

const RECORD_PAYLOAD_BYTES: usize = 250;
pub(crate) const RECORD_BYTES: usize = RECORD_PAYLOAD_BYTES + CHECKSUM_BYTES;

/// Fixed typed encoding of one record; every field has an exact position.
pub(crate) fn encode_record(
    record: &DurableRecord,
    metadata: &DurableMetadata,
) -> Result<Vec<u8>, DurableStoreError> {
    validate_record(record, metadata)?;
    let receipt = &record.receipt;
    let signature =
        decode_b64url_fixed(&receipt.signature, 64).map_err(|_| DurableStoreError::InvalidStore)?;
    let request_hash = decode_b64url_fixed(&receipt.request_hash, 32)
        .map_err(|_| DurableStoreError::InvalidStore)?;
    let intent =
        decode_b64url_fixed(&receipt.intent_id, 32).map_err(|_| DurableStoreError::InvalidStore)?;
    let mut out = Vec::with_capacity(RECORD_PAYLOAD_BYTES);
    out.push(FORMAT_VERSION);
    out.push(record.kind.value());
    out.extend_from_slice(&record.store_id);
    out.extend_from_slice(&record.key);
    put_u64(&mut out, receipt.store_generation);
    put_u64(&mut out, receipt.owner_generation);
    out.extend_from_slice(&receipt.operation_id);
    out.extend_from_slice(&intent);
    out.extend_from_slice(&signature);
    out.extend_from_slice(&request_hash);
    put_i64(&mut out, receipt.timestamp);
    put_i64(&mut out, receipt.retain_until);
    put_i64(&mut out, receipt.high_water);
    debug_assert_eq!(out.len(), RECORD_PAYLOAD_BYTES);
    Ok(seal_payload(&out))
}

/// Strict record load: exact length, sealed payload, all section-3 rules.
pub(crate) fn decode_record(
    data: &[u8],
    metadata: &DurableMetadata,
) -> Result<DurableRecord, DurableStoreError> {
    if data.len() != RECORD_BYTES {
        return Err(DurableStoreError::InvalidStore);
    }
    let payload = checked_payload(data)?;
    let mut reader = Reader::new(payload);
    if reader.u8()? != FORMAT_VERSION {
        return Err(DurableStoreError::InvalidStore);
    }
    let kind = RecordKind::from_value(reader.u8()?).ok_or(DurableStoreError::InvalidStore)?;
    let store_id = reader.fixed::<16>()?;
    let key = reader.fixed::<48>()?;
    let store_generation = reader.u64()?;
    let owner_generation = reader.u64()?;
    let operation_id = reader.fixed::<16>()?;
    let intent_raw = reader.take(32)?;
    let signature_raw = reader.take(64)?;
    let request_raw = reader.take(32)?;
    let timestamp = reader.i64()?;
    let retain_until = reader.i64()?;
    let high_water = reader.i64()?;
    reader.done()?;
    let record = DurableRecord {
        kind,
        key,
        store_id,
        receipt: DurableReceipt {
            version: FORMAT_VERSION,
            deployment: metadata.deployment.clone(),
            store_generation,
            owner_generation,
            intent_id: encode_b64url(intent_raw),
            operation_id,
            kid: encode_b64url(&key[..32]),
            nonce: encode_b64url(&key[32..]),
            signature: encode_b64url(signature_raw),
            request_hash: encode_b64url(request_raw),
            timestamp,
            retain_until,
            high_water,
        },
    };
    validate_record(&record, metadata)?;
    Ok(record)
}

/// Canonical whole-file encoding; enforces the logical 16 MiB budget.
pub(crate) fn encode_state(state: &DurableState) -> Result<Vec<u8>, DurableStoreError> {
    let metadata_bytes = encode_metadata(&state.metadata)?;
    let mut out = Vec::new();
    out.extend_from_slice(FILE_MAGIC);
    put_u16(
        &mut out,
        u16::try_from(metadata_bytes.len()).map_err(|_| DurableStoreError::InvalidStore)?,
    );
    out.extend_from_slice(&metadata_bytes);
    for (rows, kind) in [
        (&state.live, RecordKind::Live),
        (&state.intents, RecordKind::Intent),
        (&state.tombstones, RecordKind::Tombstone),
    ] {
        put_u32(&mut out, rows.len() as u32);
        for (key, receipt) in rows {
            let record = DurableRecord {
                kind,
                key: *key,
                store_id: state.metadata.store_id,
                receipt: receipt.clone(),
            };
            out.extend_from_slice(&record.key);
            out.extend_from_slice(&encode_record(&record, &state.metadata)?);
        }
    }
    put_u32(&mut out, state.expiry.len() as u32);
    for index in &state.expiry {
        out.extend_from_slice(index);
    }
    put_u32(&mut out, state.operations.len() as u32);
    for (operation, key) in &state.operations {
        out.extend_from_slice(operation);
        out.extend_from_slice(key);
    }
    if out.len() > MAX_FILE_BYTES {
        return Err(DurableStoreError::InvalidStore);
    }
    Ok(out)
}

/// Strict whole-file load enforcing every section-3 reject rule: no trailing
/// bytes, no duplicate keys/operations/index entries, exact index agreement,
/// exact counter agreement, no missing metadata, no aggregate cap overflow.
pub(crate) fn decode_state(bytes: &[u8]) -> Result<DurableState, DurableStoreError> {
    if bytes.len() > MAX_FILE_BYTES || !bytes.starts_with(FILE_MAGIC) {
        return Err(DurableStoreError::InvalidStore);
    }
    let mut reader = Reader::new(bytes);
    reader.take(FILE_MAGIC.len())?;
    let metadata_length = reader.u16()? as usize;
    let metadata = decode_metadata(reader.take(metadata_length)?)?;
    let mut state = DurableState {
        metadata: metadata.clone(),
        live: RowMap::new(),
        intents: RowMap::new(),
        tombstones: RowMap::new(),
        expiry: BTreeSet::new(),
        operations: BTreeMap::new(),
    };
    let mut seen_keys = BTreeSet::new();
    for (rows, kind, counter) in [
        (&mut state.live, RecordKind::Live, metadata.live),
        (&mut state.intents, RecordKind::Intent, metadata.intents),
        (
            &mut state.tombstones,
            RecordKind::Tombstone,
            metadata.tombstones,
        ),
    ] {
        let count = reader.u32()?;
        if counter_to_usize(count) != counter_to_usize(counter) {
            return Err(DurableStoreError::InvalidStore);
        }
        for _ in 0..count {
            let key = reader.fixed::<48>()?;
            let record = decode_record(reader.take(RECORD_BYTES)?, &metadata)?;
            if record.kind != kind || record.key != key || !seen_keys.insert(key) {
                return Err(DurableStoreError::InvalidStore);
            }
            if rows.insert(key, record.receipt).is_some() {
                return Err(DurableStoreError::InvalidStore);
            }
        }
    }
    let expiry_count = reader.u32()?;
    for _ in 0..expiry_count {
        let index = reader.fixed::<56>()?;
        if !state.expiry.insert(index) {
            return Err(DurableStoreError::InvalidStore);
        }
    }
    let operation_count = reader.u32()?;
    for _ in 0..operation_count {
        let operation = reader.fixed::<16>()?;
        let key = reader.fixed::<48>()?;
        if state.operations.insert(operation, key).is_some() {
            return Err(DurableStoreError::InvalidStore);
        }
    }
    reader.done()?;
    // Index agreement: the expiry index is exactly the derived live index.
    let derived: BTreeSet<[u8; 56]> = state
        .live
        .iter()
        .map(|(key, row)| expiry_key(row.retain_until, key))
        .collect();
    if state.expiry != derived {
        return Err(DurableStoreError::InvalidStore);
    }
    // Operation index: one unique entry per row, pointing at its exact key.
    let total = state.live.len() + state.intents.len() + state.tombstones.len();
    if state.operations.len() != total {
        return Err(DurableStoreError::InvalidStore);
    }
    for rows in [&state.live, &state.intents, &state.tombstones] {
        for (key, row) in rows {
            if state.operations.get(&row.operation_id) != Some(key) {
                return Err(DurableStoreError::InvalidStore);
            }
        }
    }
    Ok(state)
}
