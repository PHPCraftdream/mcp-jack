use super::json_object::Object;
use super::trust_json::{read_trust_document, write_trust_document};
use super::trust_json_wire::{BoundedVec, TrustDocument, Unsigned};
use super::{
    invalid, validate_server_snapshot, Binding, Checkpoint, RotationError, ServerSnapshot,
    SignerReference, MAX_RETAINED_KEYS, MAX_TRUST_SNAPSHOT_BYTES,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerReferenceDocument {
    kid: String,
    reference: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerDocument {
    format_version: Unsigned,
    public: Object<TrustDocument>,
    signer_refs: BoundedVec<Object<SignerReferenceDocument>, MAX_RETAINED_KEYS>,
}

/// Private local format Go rotation/server_state.go; caller не передаёт его клиентам.
pub fn encode_server_snapshot(
    input: &ServerSnapshot,
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<Vec<u8>, RotationError> {
    let refuse = || invalid("rotation_state_unavailable");
    let value = validate_server_snapshot(input, binding, window, checkpoint)?;
    let wire = ServerDocument {
        format_version: Unsigned(u64::from(value.format_version)),
        public: Object(write_trust_document(value.public)),
        signer_refs: BoundedVec(
            value
                .signer_references
                .into_iter()
                .map(|entry| {
                    Object(SignerReferenceDocument {
                        kid: entry.kid,
                        reference: entry.reference,
                    })
                })
                .collect(),
        ),
    };
    let encoded = serde_json::to_vec(&wire).map_err(|_| refuse())?;
    if encoded.len() > MAX_TRUST_SNAPSHOT_BYTES {
        return Err(refuse());
    }
    Ok(encoded)
}

/// Strict map-only parse сохраняет fences/unsafe; успешный decode не является serving readiness.
pub fn decode_server_snapshot(
    bytes: &[u8],
    binding: Binding<'_>,
    window: u64,
    checkpoint: &Checkpoint,
) -> Result<ServerSnapshot, RotationError> {
    let refuse = || invalid("rotation_state_unavailable");
    if bytes.is_empty() || bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
        return Err(refuse());
    }
    let Object(wire): Object<ServerDocument> =
        serde_json::from_slice(bytes).map_err(|_| refuse())?;
    let public = read_trust_document(wire.public.0).map_err(|_| refuse())?;
    let signer_references = wire
        .signer_refs
        .0
        .into_iter()
        .map(|Object(entry)| SignerReference {
            kid: entry.kid,
            reference: entry.reference,
        })
        .collect();
    let format_version = u32::try_from(wire.format_version.0).map_err(|_| refuse())?;
    validate_server_snapshot(
        &ServerSnapshot {
            format_version,
            public,
            signer_references,
        },
        binding,
        window,
        checkpoint,
    )
}
