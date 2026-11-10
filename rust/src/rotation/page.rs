use super::{invalid, DecodedResult, Record, RotationError, MAX_ORDINAL, MAX_PAGE_RECORDS};
use crate::encoding::{body_hash, decode_b64url_fixed};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultCursor {
    pub ordinal: u64,
    pub hash: String,
}

/// Owned framing metadata, не автоматическое продвижение ACKed cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageFraming {
    pub extension_start: usize,
    pub terminal: ResultCursor,
    pub head: ResultCursor,
    pub complete: bool,
}

fn valid_cursor(cursor: &ResultCursor) -> bool {
    if cursor.ordinal > MAX_ORDINAL {
        return false;
    }
    if cursor.ordinal == 0 {
        return cursor.hash == "-";
    }
    decode_b64url_fixed(&cursor.hash, 32).is_ok()
}

/// Caller уже проверил outer/ClockGuard/schema и intrinsic record proofs.
/// Только cursor/prefix/link/head framing; authorizer/P/reuse/current/bridge/CAS —
/// отдельные controller/chain gates. Нет ACK, persistence, retry или fetch.
pub fn validate_page_framing(
    result: &DecodedResult,
    cursor: &ResultCursor,
    records: &[Record],
    acknowledged_hashes: &BTreeMap<u64, String>,
) -> Result<PageFraming, RotationError> {
    let head = ResultCursor {
        ordinal: result.head_ordinal,
        hash: result.head_hash.clone(),
    };
    if !valid_cursor(cursor) || !valid_cursor(&head) {
        return Err(invalid("rotation_gap"));
    }
    if records.len() != result.records.len() || records.len() > MAX_PAGE_RECORDS {
        return Err(invalid("rotation_result_invalid"));
    }
    if acknowledged_hashes
        .get(&cursor.ordinal)
        .is_some_and(|saved| *saved != cursor.hash)
    {
        return Err(invalid("rotation_conflict"));
    }
    let mut previous: Option<ResultCursor> = None;
    let mut extension_start = records.len();
    let mut extension = false;
    for (index, record) in records.iter().enumerate() {
        if record.wire != result.records[index] || body_hash(record.wire.as_bytes()) != record.hash
        {
            return Err(invalid("rotation_record_invalid"));
        }
        if record.ordinal == 0 || record.ordinal > MAX_ORDINAL {
            return Err(invalid("rotation_gap"));
        }
        if let Some(prior) = &previous {
            if prior.ordinal == MAX_ORDINAL
                || prior.ordinal.checked_add(1) != Some(record.ordinal)
                || record.previous_hash != prior.hash
            {
                return Err(invalid("rotation_gap"));
            }
        }
        if record.ordinal <= cursor.ordinal {
            if extension {
                return Err(invalid("rotation_gap"));
            }
            let saved = if record.ordinal == cursor.ordinal {
                Some(&cursor.hash)
            } else {
                acknowledged_hashes.get(&record.ordinal)
            };
            match saved {
                None => return Err(invalid("rotation_gap")),
                Some(hash) if *hash != record.hash => return Err(invalid("rotation_conflict")),
                Some(_) => {}
            }
        } else if !extension {
            if cursor.ordinal == MAX_ORDINAL
                || cursor.ordinal.checked_add(1) != Some(record.ordinal)
                || record.previous_hash != cursor.hash
                || previous
                    .as_ref()
                    .is_some_and(|prior| prior.ordinal != cursor.ordinal)
            {
                return Err(invalid("rotation_gap"));
            }
            extension_start = index;
            extension = true;
        }
        previous = Some(ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
        });
    }
    if !extension
        && previous
            .as_ref()
            .is_some_and(|prior| prior.ordinal != cursor.ordinal)
    {
        return Err(invalid("rotation_gap"));
    }
    let terminal = previous.unwrap_or_else(|| cursor.clone());
    if result.complete {
        if head != terminal {
            return Err(invalid("rotation_gap"));
        }
    } else if records.is_empty() || head.ordinal <= terminal.ordinal {
        return Err(invalid("rotation_gap"));
    }
    Ok(PageFraming {
        extension_start,
        terminal,
        head,
        complete: result.complete,
    })
}
