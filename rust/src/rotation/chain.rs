use super::{invalid, parse_record, Binding, Record, RotationError, MAX_ORDINAL, MAX_TIMESTAMP};
use crate::ed25519::validate_public_key;
use crate::encoding::{decode_b64url_fixed, key_id};
use std::collections::BTreeMap;

pub const MAX_RETAINED_KEYS: usize = 1024 + 128 + 1;

/// Только independently trusted или ранее ACKed checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub ordinal: u64,
    pub hash: String,
    pub kid: String,
    pub public_key: [u8; 32],
    pub published_at: u64,
}

/// Возвращает owned contiguous extension, без изменения caller trust/persistence.
pub fn verify_chain(
    wires: &[&[u8]],
    binding: Binding<'_>,
    checkpoint: &Checkpoint,
    retained: &BTreeMap<String, [u8; 32]>,
) -> Result<Vec<Record>, RotationError> {
    if wires.len() > MAX_RETAINED_KEYS || retained.len() > MAX_RETAINED_KEYS {
        return Err(invalid("capacity"));
    }
    if checkpoint.ordinal > MAX_ORDINAL
        || checkpoint.published_at > MAX_TIMESTAMP
        || validate_public_key(&checkpoint.public_key).is_err()
        || key_id(&checkpoint.public_key) != checkpoint.kid
    {
        return Err(invalid("anchor_key_id"));
    }
    if checkpoint.ordinal == 0 {
        if checkpoint.hash != "-" {
            return Err(invalid("previous_hash"));
        }
    } else {
        decode_b64url_fixed(&checkpoint.hash, 32).map_err(|_| invalid("previous_hash"))?;
    }
    if !retained.contains_key(&checkpoint.kid) && retained.len() == MAX_RETAINED_KEYS {
        return Err(invalid("capacity"));
    }
    let mut keys = retained.clone();
    for (kid, public) in &keys {
        if validate_public_key(public).is_err() || key_id(public) != *kid {
            return Err(invalid("anchor_key_id"));
        }
    }
    keys.insert(checkpoint.kid.clone(), checkpoint.public_key);
    let mut previous = checkpoint.clone();
    let mut records = Vec::with_capacity(wires.len());
    for wire in wires {
        let record = parse_record(wire, binding, &keys)?;
        if previous.ordinal == MAX_ORDINAL
            || previous.ordinal.checked_add(1) != Some(record.ordinal)
        {
            return Err(invalid("ordinal_sequence"));
        }
        if record.previous_hash != previous.hash {
            return Err(invalid("previous_hash"));
        }
        if record.old_kid != previous.kid {
            return Err(invalid("adjacency"));
        }
        if record.published_at < previous.published_at {
            return Err(invalid("publication_order"));
        }
        if keys.contains_key(&record.new_kid) {
            return Err(invalid("key_reuse"));
        }
        if keys.len() >= MAX_RETAINED_KEYS {
            return Err(invalid("capacity"));
        }
        keys.insert(record.new_kid.clone(), record.public_key);
        previous = Checkpoint {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            published_at: record.published_at,
        };
        records.push(record);
    }
    Ok(records)
}

/// Records уже должны быть проверены; greatest eligible ordinal разрешает ties.
pub fn selected_ordinal(records: &[Record], now: u64) -> Result<u64, RotationError> {
    if now > MAX_TIMESTAMP {
        return Err(invalid("timestamp"));
    }
    Ok(records
        .iter()
        .filter(|record| record.activates_at <= now)
        .map(|record| record.ordinal)
        .max()
        .unwrap_or(0))
}

/// Проверяет lower ts bound и strict known cutoff по ts и final_now.
pub fn assignment_valid(records: &[Record], ordinal: u64, ts: u64, final_now: u64) -> bool {
    if ordinal > MAX_ORDINAL || ts > MAX_TIMESTAMP || final_now > MAX_TIMESTAMP {
        return false;
    }
    let mut found = ordinal == 0;
    for record in records {
        if record.ordinal == ordinal {
            found = true;
            if ts < record.activates_at {
                return false;
            }
        }
        if ordinal.checked_add(1) == Some(record.ordinal)
            && (ts >= record.activates_at || final_now >= record.activates_at)
        {
            return false;
        }
    }
    found
}
