use super::json_object::Object;
use super::trust_json_wire::Unsigned;
use super::{invalid, DecodedResult, ResultCursor, RotationError, ServerSnapshot, MAX_PAGE_RECORDS};
use crate::encoding::{body_hash, decode_b64url_fixed};
use serde::{de, Deserialize, Deserializer};
use serde_json::value::RawValue;

// Literal `-0` — JSON-целое ноль (Go reference parity); остальные формы canonical Unsigned.
struct CursorOrdinal(u64);

impl<'de> Deserialize<'de> for CursorOrdinal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        if raw.get() == "-0" {
            return Ok(Self(0));
        }
        serde_json::from_str::<Unsigned>(raw.get())
            .map(|Unsigned(value)| Self(value))
            .map_err(<D::Error as de::Error>::custom)
    }
}

// Map-only schema: serde отвергает duplicate/unknown/missing члены и positional sequence.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    after_ordinal: CursorOrdinal,
    after_hash: String,
}

/// Candidate-strict `params.arguments` для `jack.server.key`: ровно after_ordinal и after_hash.
/// Результат — только cursor запроса, не checkpoint authority. Любой отказ — invalid_params.
pub fn decode_server_key_arguments(text: &[u8]) -> Result<ResultCursor, RotationError> {
    let refuse = || invalid("invalid_params");
    let Object(wire): Object<Arguments> = serde_json::from_slice(text).map_err(|_| refuse())?;
    let ordinal = wire.after_ordinal.0;
    if ordinal == 0 {
        if wire.after_hash != "-" {
            return Err(refuse());
        }
    } else if decode_b64url_fixed(&wire.after_hash, 32).is_err() {
        return Err(refuse());
    }
    Ok(ResultCursor {
        ordinal,
        hash: wire.after_hash,
    })
}

/// Строит страницу из уже validated snapshot и выбранного response-signer; повторных чтений нет.
/// Caller обязан выполнить authoritative clock check и signer-eligibility до вызова и final
/// guard после него. Cursor вне ring или с неверным hash — rotation_checkpoint_unavailable;
/// signer вне ring — rotation_state_unavailable.
pub fn server_key_page(
    snapshot: &ServerSnapshot,
    cursor: &ResultCursor,
    signer_public_key: &[u8; 32],
) -> Result<DecodedResult, RotationError> {
    let trust = &snapshot.public;
    let unavailable = || invalid("rotation_checkpoint_unavailable");
    if cursor.ordinal < trust.checkpoint.ordinal || cursor.ordinal > trust.head.ordinal {
        return Err(unavailable());
    }
    let offset = usize::try_from(cursor.ordinal - trust.checkpoint.ordinal)
        .map_err(|_| unavailable())?;
    let expected = match offset.checked_sub(1) {
        None => trust.checkpoint.hash.clone(),
        Some(index) => {
            let wire = trust.records.get(index).ok_or_else(unavailable)?;
            body_hash(wire.as_bytes())
        }
    };
    if cursor.hash != expected {
        return Err(unavailable());
    }
    let signer = trust
        .keys
        .iter()
        .find(|key| key.public_key == *signer_public_key)
        .ok_or_else(|| invalid("rotation_state_unavailable"))?;
    let end = trust.records.len().min(offset + MAX_PAGE_RECORDS);
    Ok(DecodedResult {
        current_kid: signer.kid.clone(),
        current_public_key: signer.public_key,
        records: trust
            .records
            .get(offset..end)
            .ok_or_else(unavailable)?
            .to_vec(),
        head_ordinal: trust.head.ordinal,
        head_hash: trust.head.hash.clone(),
        complete: end == trust.records.len(),
    })
}
