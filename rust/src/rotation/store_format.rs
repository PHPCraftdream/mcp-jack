use super::json_object::Object;
use super::trust_json_wire::{BindingDocument, ClockDocument, Unsigned};
use super::{
    decode_trust_snapshot, encode_trust_snapshot, invalid, trust_clock_compatible,
    validate_trust_snapshot, Binding, Checkpoint, ClockTuple, OwnedBinding, ResultCursor,
    RotationError, TrustKey, TrustSnapshot, GRACE_SECONDS, MAX_ORDINAL, MAX_TIMESTAMP,
    MAX_TRUST_SNAPSHOT_BYTES,
};
use crate::encoding::{body_hash, decode_b64url_fixed};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct RotationStoreOptions {
    pub binding: OwnedBinding,
    pub window: u64,
    pub checkpoint: Checkpoint,
}

impl RotationStoreOptions {
    pub(super) fn binding(&self) -> Binding<'_> {
        Binding {
            endpoint: &self.binding.endpoint,
            aud: &self.binding.aud,
        }
    }

    pub(super) fn anchor(&self) -> Result<TrustSnapshot, RotationError> {
        let root = &self.checkpoint;
        let not_before = if root.ordinal == 0 {
            0
        } else {
            root.published_at
                .checked_add(GRACE_SECONDS)
                .ok_or_else(refuse)?
        };
        let snapshot = TrustSnapshot {
            format_version: 1,
            binding: self.binding.clone(),
            window: self.window,
            checkpoint: root.clone(),
            head: ResultCursor {
                ordinal: root.ordinal,
                hash: root.hash.clone(),
            },
            records: Vec::new(),
            keys: vec![TrustKey {
                ordinal: root.ordinal,
                kid: root.kid.clone(),
                public_key: root.public_key,
                not_before,
                known_cutoff: None,
            }],
            revision: 1,
            fenced: false,
            clock: ClockTuple {
                binding: self.binding.clone(),
                window: self.window,
                high_water: 0,
                revision: 0,
                unsafe_clock: false,
            },
        };
        validate_trust_snapshot(&snapshot, self.binding(), self.window, root)
    }

    pub(super) fn encode(&self, value: &TrustSnapshot) -> Result<String, RotationError> {
        String::from_utf8(encode_trust_snapshot(
            value,
            self.binding(),
            self.window,
            &self.checkpoint,
        )?)
        .map_err(|_| refuse())
    }
}

fn refuse() -> RotationError {
    invalid("rotation_state_unavailable")
}

pub(super) fn clock_bytes(clock: &ClockTuple) -> Result<String, RotationError> {
    serde_json::to_string(&ClockDocument {
        binding: Object(BindingDocument {
            endpoint: clock.binding.endpoint.clone(),
            aud: clock.binding.aud.clone(),
        }),
        window: Unsigned(clock.window),
        high_water: Unsigned(clock.high_water),
        clock_revision: Unsigned(clock.revision),
        unsafe_clock: clock.unsafe_clock,
    })
    .map_err(|_| refuse())
}

pub(super) fn read_clock(
    bytes: &str,
    options: &RotationStoreOptions,
) -> Result<ClockTuple, RotationError> {
    let Object(wire): Object<ClockDocument> = serde_json::from_str(bytes).map_err(|_| refuse())?;
    let binding = OwnedBinding {
        endpoint: wire.binding.0.endpoint,
        aud: wire.binding.0.aud,
    };
    if binding != options.binding
        || wire.window.0 != options.window
        || wire.high_water.0 > MAX_TIMESTAMP
    {
        return Err(refuse());
    }
    Ok(ClockTuple {
        binding,
        window: wire.window.0,
        high_water: wire.high_water.0,
        revision: wire.clock_revision.0,
        unsafe_clock: wire.unsafe_clock,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    payload: String,
    checksum: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    domain: String,
    format_version: Unsigned,
    pub store_id: String,
    pub profile: String,
    pub owner: Unsigned,
    pub dirty: bool,
    pub fenced: bool,
    pub clock: String,
    pub snapshot: String,
}

/// Domain разделяет client/server private files: один не открывается как другой.
pub(super) const CLIENT_DOMAIN: &str = "mcp-jack/client-trust/private-file/v1";

impl Bundle {
    /// Client trust profile; clock/snapshot берутся из anchor.
    pub(super) fn new(
        store_id: String,
        profile: String,
        anchor: &TrustSnapshot,
        options: &RotationStoreOptions,
    ) -> Result<Self, RotationError> {
        Ok(Self::sealed(
            CLIENT_DOMAIN,
            store_id,
            profile,
            clock_bytes(&anchor.clock)?,
            options.encode(anchor)?,
        ))
    }

    pub(super) fn sealed(
        domain: &str,
        store_id: String,
        profile: String,
        clock: String,
        snapshot: String,
    ) -> Self {
        Self {
            domain: domain.into(),
            format_version: Unsigned(1),
            store_id,
            profile,
            owner: Unsigned(1),
            dirty: true,
            fenced: false,
            clock,
            snapshot,
        }
    }

    /// Checksum обнаруживает случайную порчу; это не MAC или backup rollback oracle.
    pub(super) fn pack(&self) -> Result<Vec<u8>, RotationError> {
        let payload = serde_json::to_string(self).map_err(|_| refuse())?;
        let checksum = body_hash(payload.as_bytes());
        let bytes = serde_json::to_vec(&Seal { payload, checksum }).map_err(|_| refuse())?;
        if bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
            return Err(refuse());
        }
        Ok(bytes)
    }
}

/// Envelope без snapshot decode: caller проверяет snapshot своего типа против clock.
pub(super) struct Sealed {
    pub bytes: Vec<u8>,
    pub bundle: Bundle,
    pub clock: ClockTuple,
}

pub(super) fn unpack_envelope(
    bytes: Vec<u8>,
    options: &RotationStoreOptions,
    profile: &str,
    domain: &str,
) -> Result<Sealed, RotationError> {
    if bytes.is_empty() || bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
        return Err(refuse());
    }
    let Object(seal): Object<Seal> = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if body_hash(seal.payload.as_bytes()) != seal.checksum {
        return Err(refuse());
    }
    let Object(bundle): Object<Bundle> =
        serde_json::from_str(&seal.payload).map_err(|_| refuse())?;
    let id = decode_b64url_fixed(&bundle.store_id, 16).map_err(|_| refuse())?;
    if bundle.domain != domain
        || bundle.format_version.0 != 1
        || id.iter().all(|byte| *byte == 0)
        || bundle.profile != profile
        || bundle.owner.0 == 0
        || bundle.owner.0 > MAX_ORDINAL
    {
        return Err(refuse());
    }
    let clock = read_clock(&bundle.clock, options)?;
    Ok(Sealed {
        bytes,
        bundle,
        clock,
    })
}

pub(super) struct Loaded {
    pub bytes: Vec<u8>,
    pub bundle: Bundle,
    pub snapshot: TrustSnapshot,
    pub clock: ClockTuple,
}

pub(super) fn unpack(
    bytes: Vec<u8>,
    options: &RotationStoreOptions,
    profile: &str,
) -> Result<Loaded, RotationError> {
    let Sealed {
        bytes,
        bundle,
        clock,
    } = unpack_envelope(bytes, options, profile, CLIENT_DOMAIN)?;
    let snapshot = decode_trust_snapshot(
        bundle.snapshot.as_bytes(),
        options.binding(),
        options.window,
        &options.checkpoint,
    )?;
    if snapshot.clock.high_water > clock.high_water || snapshot.clock.revision > clock.revision {
        return Err(refuse());
    }
    Ok(Loaded {
        bytes,
        bundle,
        snapshot,
        clock,
    })
}

pub(super) fn compatible(state: &Loaded) -> Result<(), RotationError> {
    if !trust_clock_compatible(&state.snapshot, &state.clock) {
        return Err(refuse());
    }
    Ok(())
}
