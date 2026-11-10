use super::{
    invalid, parse_record, Binding, Checkpoint, Record, RotationError, DOMAIN, GRACE_SECONDS,
    MAX_ORDINAL, MAX_TIMESTAMP,
};
use crate::client::Signer;
use crate::ed25519::{validate_public_key, verify};
use crate::encoding::{decode_b64url_fixed, encode_b64url, key_id};
use std::collections::BTreeMap;

/// Использует существующий dyn-compatible Signer, не требует private export.
/// Только создание record: не publication, persistence, trust mutation или retry.
pub fn create_record(
    binding: Binding<'_>,
    previous: &Checkpoint,
    old: &dyn Signer,
    next: &dyn Signer,
    published_at: u64,
) -> Result<Record, RotationError> {
    if binding.endpoint.is_empty()
        || binding.endpoint.len() > 2048
        || binding.aud.is_empty()
        || binding.aud.len() > 1024
    {
        return Err(invalid("binding_size"));
    }
    if previous.ordinal >= MAX_ORDINAL {
        return Err(invalid("ordinal"));
    }
    let activates_at = published_at
        .checked_add(GRACE_SECONDS)
        .filter(|value| *value <= MAX_TIMESTAMP)
        .ok_or_else(|| invalid("timestamp"))?;
    if previous.published_at > MAX_TIMESTAMP || published_at < previous.published_at {
        return Err(invalid("publication_order"));
    }
    if previous.ordinal == 0 {
        if previous.hash != "-" {
            return Err(invalid("previous_hash"));
        }
    } else {
        decode_b64url_fixed(&previous.hash, 32).map_err(|_| invalid("previous_hash"))?;
    }
    let old_public = old.public_key();
    let next_public = next.public_key();
    validate_public_key(&old_public).map_err(|_| invalid("signer_key"))?;
    validate_public_key(&next_public).map_err(|_| invalid("signer_key"))?;
    let old_kid = key_id(&old_public);
    let next_kid = key_id(&next_public);
    if old_public != previous.public_key || old_kid != previous.kid {
        return Err(invalid("anchor_key_id"));
    }
    if old_kid == next_kid {
        return Err(invalid("key_reuse"));
    }
    let ordinal = previous
        .ordinal
        .checked_add(1)
        .ok_or_else(|| invalid("ordinal"))?;
    let body = [
        DOMAIN.to_owned(),
        encode_b64url(binding.endpoint.as_bytes()),
        encode_b64url(binding.aud.as_bytes()),
        ordinal.to_string(),
        previous.hash.clone(),
        old_kid.clone(),
        next_kid,
        encode_b64url(&next_public),
        published_at.to_string(),
        activates_at.to_string(),
    ]
    .join("\n");
    let next_message = format!("{DOMAIN}/next-proof\n{body}");
    let next_proof = next
        .sign(next_message.as_bytes())
        .map_err(|_| invalid("signer"))?;
    if !verify(&next_public, next_message.as_bytes(), &next_proof) {
        return Err(invalid("new_proof"));
    }
    let next_proof_text = encode_b64url(&next_proof);
    // OLD вызывается только после подтверждённого NEXT proof; retries отсутствуют.
    let old_message = format!("{DOMAIN}/authorize\n{body}\n{next_proof_text}");
    let old_proof = old
        .sign(old_message.as_bytes())
        .map_err(|_| invalid("signer"))?;
    if !verify(&old_public, old_message.as_bytes(), &old_proof) {
        return Err(invalid("old_authorization"));
    }
    let wire = format!("{body}\n{next_proof_text}\n{}", encode_b64url(&old_proof));
    parse_record(
        wire.as_bytes(),
        binding,
        &BTreeMap::from([(old_kid, old_public)]),
    )
}
