use super::store_format::{unpack_envelope, Bundle, RotationStoreOptions, Sealed};
use super::{
    decode_server_snapshot, encode_server_snapshot, invalid, trust_clock_compatible,
    validate_server_snapshot, Checkpoint, ClockTuple, OwnedBinding, RotationError, ServerSnapshot,
    SignerReference,
};

/// Domain отделяет server ring от client trust: файлы не взаимозаменяемы.
pub(super) const SERVER_DOMAIN: &str = "mcp-jack/server-ring/private-file/v1";

/// Независимый OOB profile плюс opaque handle подписанта anchor key; handle не key authority.
#[derive(Clone)]
pub struct RotationServerStoreOptions {
    pub binding: OwnedBinding,
    pub window: u64,
    pub checkpoint: Checkpoint,
    pub anchor_reference: String,
}

fn refuse() -> RotationError {
    invalid("rotation_state_unavailable")
}

impl RotationServerStoreOptions {
    pub(super) fn base(&self) -> RotationStoreOptions {
        RotationStoreOptions {
            binding: self.binding.clone(),
            window: self.window,
            checkpoint: self.checkpoint.clone(),
        }
    }

    /// Anchor ring: один checkpoint key с его opaque reference, revision 1, clock ещё не sampled.
    pub(super) fn anchor(&self) -> Result<ServerSnapshot, RotationError> {
        let base = self.base();
        let public = base.anchor().map_err(|_| refuse())?;
        let signer_references = vec![SignerReference {
            kid: public.checkpoint.kid.clone(),
            reference: self.anchor_reference.clone(),
        }];
        validate_server_snapshot(
            &ServerSnapshot {
                format_version: 1,
                public,
                signer_references,
            },
            base.binding(),
            base.window,
            &base.checkpoint,
        )
    }
}

pub(super) fn encode(
    base: &RotationStoreOptions,
    value: &ServerSnapshot,
) -> Result<String, RotationError> {
    let bytes = encode_server_snapshot(value, base.binding(), base.window, &base.checkpoint)?;
    String::from_utf8(bytes).map_err(|_| refuse())
}

pub(super) struct ServerLoaded {
    pub bytes: Vec<u8>,
    pub bundle: Bundle,
    pub snapshot: ServerSnapshot,
    pub clock: ClockTuple,
}

pub(super) fn unpack_server(
    bytes: Vec<u8>,
    base: &RotationStoreOptions,
    profile: &str,
) -> Result<ServerLoaded, RotationError> {
    let Sealed {
        bytes,
        bundle,
        clock,
    } = unpack_envelope(bytes, base, profile, SERVER_DOMAIN)?;
    let snapshot = decode_server_snapshot(
        bundle.snapshot.as_bytes(),
        base.binding(),
        base.window,
        &base.checkpoint,
    )?;
    // Copied clock внутри snapshot не опережает authoritative guard.
    if snapshot.public.clock.high_water > clock.high_water
        || snapshot.public.clock.revision > clock.revision
    {
        return Err(refuse());
    }
    Ok(ServerLoaded {
        bytes,
        bundle,
        snapshot,
        clock,
    })
}

pub(super) fn compatible_server(state: &ServerLoaded) -> Result<(), RotationError> {
    if !trust_clock_compatible(&state.snapshot.public, &state.clock) {
        return Err(refuse());
    }
    Ok(())
}
