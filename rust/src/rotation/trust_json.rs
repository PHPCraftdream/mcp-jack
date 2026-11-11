use super::trust_json_wire::{
    BindingDocument, BoundedVec, CheckpointDocument, ClockDocument, Cutoff, HeadDocument,
    KeyDocument, Object, TrustDocument, Unsigned,
};
use super::{
    invalid, validate_trust_snapshot, Binding, Checkpoint, ClockTuple, OwnedBinding, ResultCursor,
    RotationError, TrustKey, TrustSnapshot,
};
use crate::encoding::{decode_b64url_fixed, encode_b64url};

pub const MAX_TRUST_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

fn public_key(text: &str) -> Result<[u8; 32], RotationError> {
    decode_b64url_fixed(text, 32)
        .map_err(|_| invalid("rotation_state_unknown"))?
        .try_into()
        .map_err(|_| invalid("rotation_state_unknown"))
}

fn read_binding(value: Object<BindingDocument>) -> OwnedBinding {
    OwnedBinding {
        endpoint: value.0.endpoint,
        aud: value.0.aud,
    }
}

fn write_binding(value: OwnedBinding) -> Object<BindingDocument> {
    Object(BindingDocument {
        endpoint: value.endpoint,
        aud: value.aud,
    })
}

/// Strict local schema из Go rotation/trust_json.go; не HTTP carrier decoder/ACK.
/// Все objects — map-only; serde проверяет duplicate/unknown/missing fields.
pub fn decode_trust_snapshot(
    bytes: &[u8],
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<TrustSnapshot, RotationError> {
    let refuse = || invalid("rotation_state_unknown");
    if bytes.is_empty() || bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
        return Err(refuse());
    }
    let Object(wire): Object<TrustDocument> =
        serde_json::from_slice(bytes).map_err(|_| refuse())?;
    let root = wire.checkpoint.0;
    let clock = wire.clock.0;
    let mut keys = Vec::with_capacity(wire.keys.0.len());
    for Object(key) in wire.keys.0 {
        keys.push(TrustKey {
            ordinal: key.ordinal.0,
            kid: key.kid,
            public_key: public_key(&key.public_key)?,
            not_before: key.not_before.0,
            known_cutoff: key.known_cutoff.0,
        });
    }
    let input = TrustSnapshot {
        format_version: u32::try_from(wire.format_version.0).map_err(|_| refuse())?,
        binding: read_binding(wire.binding),
        window: wire.window.0,
        checkpoint: Checkpoint {
            ordinal: root.ordinal.0,
            hash: root.hash,
            kid: root.kid,
            public_key: public_key(&root.public_key)?,
            published_at: root.published_at.0,
        },
        head: ResultCursor {
            ordinal: wire.head.0.ordinal.0,
            hash: wire.head.0.hash,
        },
        records: wire.records.0,
        keys,
        revision: wire.trust_revision.0,
        fenced: wire.fenced,
        clock: ClockTuple {
            binding: read_binding(clock.binding),
            window: clock.window.0,
            high_water: clock.high_water.0,
            revision: clock.clock_revision.0,
            unsafe_clock: clock.unsafe_clock,
        },
    };
    validate_trust_snapshot(&input, binding, window, checkpoint)
}

/// Детерминированный public-only encode после полной validation; без store/clock.
pub fn encode_trust_snapshot(
    input: &TrustSnapshot,
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<Vec<u8>, RotationError> {
    let value = validate_trust_snapshot(input, binding, window, checkpoint)?;
    let root = value.checkpoint;
    let clock = value.clock;
    let wire = TrustDocument {
        format_version: Unsigned(u64::from(value.format_version)),
        binding: write_binding(value.binding),
        window: Unsigned(value.window),
        checkpoint: Object(CheckpointDocument {
            ordinal: Unsigned(root.ordinal),
            hash: root.hash,
            kid: root.kid,
            public_key: encode_b64url(&root.public_key),
            published_at: Unsigned(root.published_at),
        }),
        head: Object(HeadDocument {
            ordinal: Unsigned(value.head.ordinal),
            hash: value.head.hash,
        }),
        records: BoundedVec(value.records),
        keys: BoundedVec(
            value
                .keys
                .into_iter()
                .map(|key| {
                    Object(KeyDocument {
                        ordinal: Unsigned(key.ordinal),
                        kid: key.kid,
                        public_key: encode_b64url(&key.public_key),
                        not_before: Unsigned(key.not_before),
                        known_cutoff: Cutoff(key.known_cutoff),
                    })
                })
                .collect(),
        ),
        trust_revision: Unsigned(value.revision),
        fenced: value.fenced,
        clock: Object(ClockDocument {
            binding: write_binding(clock.binding),
            window: Unsigned(clock.window),
            high_water: Unsigned(clock.high_water),
            clock_revision: Unsigned(clock.revision),
            unsafe_clock: clock.unsafe_clock,
        }),
    };
    let encoded = serde_json::to_vec(&wire).map_err(|_| invalid("rotation_state_unknown"))?;
    if encoded.len() > MAX_TRUST_SNAPSHOT_BYTES {
        return Err(invalid("rotation_state_unknown"));
    }
    Ok(encoded)
}
