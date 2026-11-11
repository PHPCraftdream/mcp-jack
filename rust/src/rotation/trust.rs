use super::{
    invalid, verify_chain, Binding, Checkpoint, ResultCursor, RotationError, GRACE_SECONDS,
    MAX_ORDINAL, MAX_RECORD_BYTES, MAX_RETAINED_KEYS, MAX_TIMESTAMP,
};
use std::collections::BTreeMap;

/// Owned binding для whole-state values; fixed v1 DTO, без caller borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBinding {
    pub endpoint: String,
    pub aud: String,
}

/// Copied CAS dependency, не самостоятельная time authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockTuple {
    pub binding: OwnedBinding,
    pub window: u64,
    pub high_water: u64,
    pub revision: u64,
    pub unsafe_clock: bool,
}

/// Только публичные key metadata; cutoff остаётся optional, не zero sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustKey {
    pub ordinal: u64,
    pub kid: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub known_cutoff: Option<u64>,
}

/// Целый fixed v1 value для будущего store; validation не подтверждает persistence.
#[derive(Debug, Clone)]
pub struct TrustSnapshot {
    pub format_version: u32,
    pub binding: OwnedBinding,
    pub window: u64,
    pub checkpoint: Checkpoint,
    pub head: ResultCursor,
    pub records: Vec<String>,
    pub keys: Vec<TrustKey>,
    pub revision: u64,
    pub fenced: bool,
    pub clock: ClockTuple,
}

fn valid_binding(binding: &OwnedBinding) -> bool {
    !binding.endpoint.is_empty()
        && binding.endpoint.len() <= 2048
        && !binding.aud.is_empty()
        && binding.aud.len() <= 1024
}

fn valid_clock(clock: &ClockTuple, binding: &OwnedBinding, window: u64) -> bool {
    clock.binding == *binding
        && clock.window == window
        && clock.high_water <= MAX_TIMESTAMP
        && clock.revision <= MAX_ORDINAL
}

fn same_checkpoint(left: &Checkpoint, right: &Checkpoint) -> bool {
    left.ordinal == right.ordinal
        && left.hash == right.hash
        && left.kid == right.kid
        && left.public_key == right.public_key
        && left.published_at == right.published_at
}

/// Reference: Go rotation/trust.go и docs/design/minimal-server-rotation.md §5.
/// Возвращает owned copy после полной chain/proof проверки, без clock/store/ACK.
pub fn validate_trust_snapshot(
    input: &TrustSnapshot,
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<TrustSnapshot, RotationError> {
    let refuse = || invalid("rotation_state_unknown");
    if input.format_version != 1
        || !valid_binding(&input.binding)
        || input.binding.endpoint != binding.endpoint
        || input.binding.aud != binding.aud
        || !(1..=120).contains(&window)
        || input.window != window
        || !same_checkpoint(&input.checkpoint, checkpoint)
        || input.revision == 0
        || input.revision > MAX_ORDINAL
        || !valid_clock(&input.clock, &input.binding, window)
        || checkpoint.published_at > MAX_TIMESTAMP - GRACE_SECONDS
        || (checkpoint.ordinal == 0 && checkpoint.published_at != 0)
        || input.records.len() >= MAX_RETAINED_KEYS
        || input.keys.len() != input.records.len() + 1
    {
        return Err(refuse());
    }
    let mut wires = Vec::with_capacity(input.records.len());
    for wire in &input.records {
        if wire.is_empty() || wire.len() > MAX_RECORD_BYTES {
            return Err(refuse());
        }
        wires.push(wire.as_bytes());
    }
    let records =
        verify_chain(&wires, binding, checkpoint, &BTreeMap::new()).map_err(|_| refuse())?;
    let mut head = ResultCursor {
        ordinal: checkpoint.ordinal,
        hash: checkpoint.hash.clone(),
    };
    let not_before = if checkpoint.ordinal == 0 {
        0
    } else {
        checkpoint
            .published_at
            .checked_add(GRACE_SECONDS)
            .ok_or_else(refuse)?
    };
    let mut keys = Vec::with_capacity(input.keys.len());
    keys.push(TrustKey {
        ordinal: checkpoint.ordinal,
        kid: checkpoint.kid.clone(),
        public_key: checkpoint.public_key,
        not_before,
        known_cutoff: None,
    });
    for record in records {
        let previous = keys.last_mut().ok_or_else(refuse)?;
        previous.known_cutoff = Some(record.activates_at);
        keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid,
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash,
        };
    }
    if input.head != head || input.keys != keys {
        return Err(refuse());
    }
    let mut pending = 0;
    let mut retired = 0;
    for key in &keys {
        if key.not_before > input.clock.high_water {
            pending += 1;
        } else if key
            .known_cutoff
            .is_some_and(|cutoff| cutoff <= input.clock.high_water)
        {
            retired += 1;
        }
    }
    if pending > 128 || retired > 1024 {
        return Err(refuse());
    }
    Ok(TrustSnapshot {
        format_version: input.format_version,
        binding: input.binding.clone(),
        window: input.window,
        checkpoint: input.checkpoint.clone(),
        head,
        records: input.records.clone(),
        keys,
        revision: input.revision,
        fenced: input.fenced,
        clock: input.clock.clone(),
    })
}

/// Требует validated snapshot; tuple compatibility не fresh clock/readiness/ACK.
pub fn trust_clock_compatible(snapshot: &TrustSnapshot, clock: &ClockTuple) -> bool {
    snapshot.format_version == 1
        && !snapshot.fenced
        && !snapshot.clock.unsafe_clock
        && !clock.unsafe_clock
        && valid_binding(&snapshot.binding)
        && (1..=120).contains(&snapshot.window)
        && valid_clock(&snapshot.clock, &snapshot.binding, snapshot.window)
        && valid_clock(clock, &snapshot.binding, snapshot.window)
        && snapshot.clock.high_water <= clock.high_water
        && snapshot.clock.revision <= clock.revision
}
