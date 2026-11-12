use super::{
    invalid, parse_record, validate_page_framing, verify_chain, Binding, Checkpoint, ClockTuple,
    DecodedResult, PageFraming, Record, ResultCursor, RotationError, TrustKey, TrustSnapshot,
    GRACE_SECONDS, MAX_ORDINAL, MAX_RETAINED_KEYS,
};
use crate::encoding::body_hash;
use std::collections::BTreeMap;

fn record_error(error: RotationError) -> RotationError {
    let gap = matches!(
        error.code,
        "unknown_authorizer"
            | "adjacency"
            | "previous_hash"
            | "ordinal_sequence"
            | "publication_order"
    );
    invalid(if gap {
        "rotation_gap"
    } else {
        "rotation_record_invalid"
    })
}

/// Pre-authority validation; framing/decoded values не являются trust ACK.
pub(super) fn prepare(
    snapshot: &TrustSnapshot,
    page: &DecodedResult,
    cursor: &ResultCursor,
    carrier_timestamp: u64,
) -> Result<(PageFraming, Vec<Record>), RotationError> {
    if *cursor != snapshot.head || page.head_ordinal < cursor.ordinal {
        return Err(invalid("rotation_gap"));
    }
    let binding = Binding {
        endpoint: &snapshot.binding.endpoint,
        aud: &snapshot.binding.aud,
    };
    let mut authorizers: BTreeMap<_, _> = snapshot
        .keys
        .iter()
        .map(|key| (key.kid.clone(), key.public_key))
        .collect();
    let mut hashes = BTreeMap::from([(
        snapshot.checkpoint.ordinal,
        snapshot.checkpoint.hash.clone(),
    )]);
    for (index, wire) in snapshot.records.iter().enumerate() {
        let ordinal = snapshot
            .checkpoint
            .ordinal
            .checked_add(u64::try_from(index).map_err(|_| invalid("rotation_gap"))? + 1)
            .ok_or_else(|| invalid("rotation_gap"))?;
        hashes.insert(ordinal, body_hash(wire.as_bytes()));
    }
    let mut records = Vec::with_capacity(page.records.len());
    for wire in &page.records {
        let record = parse_record(wire.as_bytes(), binding, &authorizers).map_err(record_error)?;
        if record.published_at > carrier_timestamp {
            return Err(invalid("rotation_record_invalid"));
        }
        authorizers.insert(record.new_kid.clone(), record.public_key);
        records.push(record);
    }
    let framing = validate_page_framing(page, cursor, &records, &hashes)?;
    let extension = records.split_off(framing.extension_start);
    if !extension.is_empty() {
        let tail = snapshot
            .keys
            .last()
            .ok_or_else(|| invalid("rotation_state_unknown"))?;
        if snapshot.revision == MAX_ORDINAL
            || snapshot.keys.len() + extension.len() > MAX_RETAINED_KEYS
        {
            return Err(invalid("rotation_state_changed"));
        }
        let previous = if snapshot.records.is_empty() {
            snapshot.checkpoint.clone()
        } else {
            Checkpoint {
                ordinal: snapshot.head.ordinal,
                hash: snapshot.head.hash.clone(),
                kid: tail.kid.clone(),
                public_key: tail.public_key,
                published_at: tail
                    .not_before
                    .checked_sub(GRACE_SECONDS)
                    .ok_or_else(|| invalid("rotation_state_unknown"))?,
            }
        };
        let retained = snapshot
            .keys
            .iter()
            .map(|key| (key.kid.clone(), key.public_key))
            .collect();
        let wires: Vec<&[u8]> = extension
            .iter()
            .map(|record| record.wire.as_bytes())
            .collect();
        verify_chain(&wires, binding, &previous, &retained).map_err(record_error)?;
    }
    Ok((framing, extension))
}

/// Bounded desired value; store выполняет whole-state validation и exact CAS.
pub(super) fn extended(
    snapshot: &TrustSnapshot,
    extension: Vec<Record>,
    clock: ClockTuple,
) -> Result<TrustSnapshot, RotationError> {
    if extension.is_empty()
        || snapshot.revision >= MAX_ORDINAL
        || snapshot.keys.len() + extension.len() > MAX_RETAINED_KEYS
    {
        return Err(invalid("rotation_state_changed"));
    }
    let mut desired = snapshot.clone();
    for record in extension {
        desired
            .keys
            .last_mut()
            .ok_or_else(|| invalid("rotation_state_unknown"))?
            .known_cutoff = Some(record.activates_at);
        desired.keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid,
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        desired.records.push(record.wire);
        desired.head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash,
        };
    }
    let mut pending = 0;
    let mut retired = 0;
    for key in &desired.keys {
        if key.not_before > clock.high_water {
            pending += 1;
        } else if key
            .known_cutoff
            .is_some_and(|cutoff| cutoff <= clock.high_water)
        {
            retired += 1;
        }
    }
    if pending > 128 || retired > 1024 {
        return Err(invalid("rotation_state_changed"));
    }
    desired.revision += 1;
    desired.clock = clock;
    Ok(desired)
}
