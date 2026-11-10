use super::{invalid, Binding, Record, RotationError, DOMAIN, GRACE_SECONDS, MAX_ORDINAL, MAX_RECORD_BYTES, MAX_TIMESTAMP};
use crate::ed25519::{validate_public_key, verify};
use crate::encoding::{body_hash, decode_b64url, decode_b64url_fixed, key_id};
use std::collections::BTreeMap;

fn decimal(text: &str, maximum: u64, code: &'static str) -> Result<u64, RotationError> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(code));
    }
    let value = text.parse::<u64>().map_err(|_| invalid(code))?;
    if value > maximum {
        return Err(invalid(code));
    }
    Ok(value)
}

/// Только codec/proof verification; не fetch, persistence, ACK или admission carrier.
pub fn parse_record(wire: &[u8], binding: Binding<'_>, authorizers: &BTreeMap<String, [u8; 32]>) -> Result<Record, RotationError> {
    if wire.is_empty() || wire.len() > MAX_RECORD_BYTES {
        return Err(invalid("record_size"));
    }
    if !wire.is_ascii() {
        return Err(invalid("non_ascii"));
    }
    let text = std::str::from_utf8(wire).map_err(|_| invalid("utf8"))?;
    if text.ends_with('\n') {
        return Err(invalid("trailing_lf"));
    }
    let lines: [&str; 12] = text.split('\n').collect::<Vec<_>>().try_into().map_err(|_| invalid("line_count"))?;
    if lines[0] != DOMAIN {
        return Err(invalid("domain"));
    }
    let ordinal = decimal(lines[3], MAX_ORDINAL, "ordinal")?;
    if ordinal == 0 {
        return Err(invalid("ordinal"));
    }
    let published_at = decimal(lines[8], MAX_TIMESTAMP, "timestamp")?;
    let activates_at = decimal(lines[9], MAX_TIMESTAMP, "timestamp")?;
    if binding.endpoint.is_empty() || binding.endpoint.len() > 2048 || binding.aud.is_empty() || binding.aud.len() > 1024 {
        return Err(invalid("binding_size"));
    }
    let endpoint = decode_b64url(lines[1]).map_err(|_| invalid("binding_encoding"))?;
    let aud = decode_b64url(lines[2]).map_err(|_| invalid("binding_encoding"))?;
    if endpoint.is_empty() || endpoint.len() > 2048 || aud.is_empty() || aud.len() > 1024 {
        return Err(invalid("binding_encoding"));
    }
    let endpoint = std::str::from_utf8(&endpoint).map_err(|_| invalid("utf8"))?;
    let aud = std::str::from_utf8(&aud).map_err(|_| invalid("utf8"))?;
    if endpoint != binding.endpoint || aud != binding.aud {
        return Err(invalid("binding"));
    }
    decode_b64url_fixed(lines[5], 32).map_err(|_| invalid("key_id"))?;
    decode_b64url_fixed(lines[6], 32).map_err(|_| invalid("key_id"))?;
    if lines[7].len() != 43 {
        return Err(invalid("base64url"));
    }
    let public_key: [u8; 32] = decode_b64url_fixed(lines[7], 32).map_err(|_| invalid("new_key"))?.try_into().map_err(|_| invalid("new_key"))?;
    validate_public_key(&public_key).map_err(|_| invalid("new_key"))?;
    if key_id(&public_key) != lines[6] {
        return Err(invalid("new_key_id"));
    }
    let next_proof = decode_b64url_fixed(lines[10], 64).map_err(|_| invalid("proof_encoding"))?;
    let old_proof = decode_b64url_fixed(lines[11], 64).map_err(|_| invalid("proof_encoding"))?;
    if published_at.checked_add(GRACE_SECONDS).filter(|value| *value <= MAX_TIMESTAMP) != Some(activates_at) {
        return Err(invalid("activation"));
    }
    let old_public = authorizers.get(lines[5]).ok_or_else(|| invalid("unknown_authorizer"))?;
    if key_id(old_public) != lines[5] || validate_public_key(old_public).is_err() {
        return Err(invalid("unknown_authorizer"));
    }
    // Array length12 проверена выше; B — exact первые10 строк без final LF.
    let body = lines[..10].join("\n");
    if !verify(&public_key, format!("{DOMAIN}/next-proof\n{body}").as_bytes(), &next_proof) {
        return Err(invalid("new_proof"));
    }
    if !verify(old_public, format!("{DOMAIN}/authorize\n{body}\n{}", lines[10]).as_bytes(), &old_proof) {
        return Err(invalid("old_authorization"));
    }
    Ok(Record {
        ordinal, previous_hash: lines[4].to_owned(), old_kid: lines[5].to_owned(), new_kid: lines[6].to_owned(),
        public_key, published_at, activates_at, wire: text.to_owned(), hash: body_hash(wire),
    })
}
