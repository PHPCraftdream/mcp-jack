use super::{
    invalid, trust_clock_compatible, validate_trust_snapshot, Binding, Checkpoint, RotationError,
    TrustSnapshot, GRACE_SECONDS, MAX_ORDINAL,
};

pub const MAX_SIGNER_REFERENCE_BYTES: usize = 1024;

/// Opaque server-local signer handle; not a private-key encoding and not key authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerReference {
    pub kid: String,
    pub reference: String,
}

/// Stored only in the protected server store; never enters the delivery payload.
#[derive(Debug, Clone)]
pub struct ServerSnapshot {
    pub format_version: u32,
    pub public: TrustSnapshot,
    pub signer_references: Vec<SignerReference>,
}

/// Whole trust plus exactly one opaque reference per retained key; owned copy.
pub fn validate_server_snapshot(
    input: &ServerSnapshot,
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<ServerSnapshot, RotationError> {
    let refuse = || invalid("rotation_state_unavailable");
    if input.format_version != 1 {
        return Err(refuse());
    }
    let public = validate_trust_snapshot(&input.public, binding, window, checkpoint)
        .map_err(|_| refuse())?;
    if input.signer_references.len() != public.keys.len() {
        return Err(refuse());
    }
    for (entry, key) in input.signer_references.iter().zip(&public.keys) {
        if entry.kid != key.kid
            || entry.reference.is_empty()
            || entry.reference.len() > MAX_SIGNER_REFERENCE_BYTES
        {
            return Err(refuse());
        }
    }
    Ok(ServerSnapshot {
        format_version: 1,
        public,
        signer_references: input.signer_references.clone(),
    })
}

/// Validates one fixed-P transition; this is not durable authorization and not persistence.
pub fn validate_server_publication(
    expected: &ServerSnapshot,
    desired: &ServerSnapshot,
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<ServerSnapshot, RotationError> {
    let refuse = || invalid("rotation_state_unavailable");
    let previous = validate_server_snapshot(expected, binding, window, checkpoint)?;
    let next = validate_server_snapshot(desired, binding, window, checkpoint)?;
    let (before, after) = (&previous.public, &next.public);
    if before.revision == MAX_ORDINAL
        || after.revision != before.revision + 1
        || after.records.len() != before.records.len() + 1
        || before.fenced
        || after.fenced
        || !trust_clock_compatible(before, &after.clock)
        || !after.records.starts_with(&before.records)
        || !next
            .signer_references
            .starts_with(&previous.signer_references)
    {
        return Err(refuse());
    }
    // P is already fixed in clock.high_water; A = P + 48h is derived only from it.
    let last = after.keys.last().ok_or_else(refuse)?;
    if last.not_before.checked_sub(GRACE_SECONDS) != Some(after.clock.high_water) {
        return Err(refuse());
    }
    Ok(next)
}
