use super::json_object::Object;
use super::{invalid, RotationError, MAX_ORDINAL};
use crate::ed25519::validate_public_key;
use crate::encoding::{decode_b64url_fixed, key_id};
use serde::Deserialize;
use serde_json::value::RawValue;

pub const MAX_RESULT_BODY_BYTES: usize = 256 * 1024;
pub const MAX_PAGE_RECORDS: usize = 16;

/// Owned публичные данные, не carrier authentication или ACKed trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedResult {
    pub current_kid: String,
    pub current_public_key: [u8; 32],
    pub records: Vec<String>,
    pub head_ordinal: u64,
    pub head_hash: String,
    pub complete: bool,
}

// Map-only schema как в TS rotation-result.ts; не serde positional structs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    jsonrpc: String,
    id: Box<RawValue>,
    result: Object<NativeResult>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeResult {
    content: Vec<Object<Content>>,
    #[serde(rename = "structuredContent")]
    structured: Box<RawValue>,
    #[serde(rename = "isError")]
    is_error: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    current: Object<Current>,
    records: Vec<String>,
    head: Object<Head>,
    complete: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    kid: String,
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    ordinal: Box<RawValue>,
    hash: String,
}

fn source(value: &RawValue) -> &str {
    value
        .get()
        .trim_matches(|character: char| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

fn id_matches(actual: &RawValue, expected: &RawValue) -> bool {
    let actual = source(actual);
    let expected = source(expected);
    if actual.starts_with('"') && expected.starts_with('"') {
        return match (
            serde_json::from_str::<String>(actual),
            serde_json::from_str::<String>(expected),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        };
    }
    let numeric = |text: &str| {
        text.as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'-')
    };
    numeric(actual) && numeric(expected) && actual == expected
}

fn payload(text: &str) -> Result<DecodedResult, RotationError> {
    let Object(wire): Object<Payload> =
        serde_json::from_str(text).map_err(|_| invalid("rotation_result_invalid"))?;
    if wire.records.len() > MAX_PAGE_RECORDS {
        return Err(invalid("rotation_result_invalid"));
    }
    let current = wire.current.0;
    let head = wire.head.0;
    let public_key: [u8; 32] = decode_b64url_fixed(&current.public_key, 32)
        .map_err(|_| invalid("rotation_result_invalid"))?
        .try_into()
        .map_err(|_| invalid("rotation_result_invalid"))?;
    if validate_public_key(&public_key).is_err() || key_id(&public_key) != current.kid {
        return Err(invalid("rotation_result_invalid"));
    }
    let ordinal_text = source(&head.ordinal);
    if ordinal_text.is_empty()
        || (ordinal_text.len() > 1 && ordinal_text.starts_with('0'))
        || !ordinal_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("rotation_result_invalid"));
    }
    let ordinal = ordinal_text
        .parse::<u64>()
        .map_err(|_| invalid("rotation_result_invalid"))?;
    if ordinal > MAX_ORDINAL {
        return Err(invalid("rotation_result_invalid"));
    }
    if ordinal == 0 {
        if head.hash != "-" {
            return Err(invalid("rotation_result_invalid"));
        }
    } else {
        decode_b64url_fixed(&head.hash, 32).map_err(|_| invalid("rotation_result_invalid"))?;
    }
    Ok(DecodedResult {
        current_kid: current.kid,
        current_public_key: public_key,
        records: wire.records,
        head_ordinal: ordinal,
        head_hash: head.hash,
        complete: wire.complete,
    })
}

/// Только schema/parity/limits. Caller сначала выполняет outer authentication,
/// known interval и ClockGuard; затем отдельно proofs/cursor/current binding/bridge/CAS.
/// Нет ACK, persistence, fetch или refresh; signed errors обрабатывает caller.
pub fn decode_result(body: &[u8], expected_id: &[u8]) -> Result<DecodedResult, RotationError> {
    if body.is_empty() || body.len() > MAX_RESULT_BODY_BYTES {
        return Err(invalid("rotation_result_invalid"));
    }
    let text = std::str::from_utf8(body).map_err(|_| invalid("rotation_result_invalid"))?;
    let Object(wire): Object<Envelope> =
        serde_json::from_str(text).map_err(|_| invalid("rotation_result_invalid"))?;
    let expected_text =
        std::str::from_utf8(expected_id).map_err(|_| invalid("rotation_result_invalid"))?;
    let expected: Box<RawValue> =
        serde_json::from_str(expected_text).map_err(|_| invalid("rotation_result_invalid"))?;
    let result = wire.result.0;
    if wire.jsonrpc != "2.0"
        || !id_matches(&wire.id, &expected)
        || result.is_error
        || result.content.len() != 1
    {
        return Err(invalid("rotation_result_invalid"));
    }
    // Length1 проверена выше; content и payload types запрещают duplicate/extra fields.
    let item = &result.content[0].0;
    if item.kind != "text" {
        return Err(invalid("rotation_result_invalid"));
    }
    let structured = payload(result.structured.get())?;
    let mirror = payload(&item.text)?;
    // Единственное numeric payload поле — canonical head ordinal: его lexeme уникален.
    if structured != mirror {
        return Err(invalid("rotation_result_invalid"));
    }
    Ok(structured)
}

#[cfg(test)]
mod tests {
    use super::{Envelope, Object};

    #[test]
    fn raw_struct_sequence_control_demonstrates_why_map_gate_is_required() {
        let sequence = r#"["2.0",7,{"content":[],"structuredContent":null,"isError":false}]"#;
        assert!(serde_json::from_str::<Envelope>(sequence).is_ok());
        assert!(serde_json::from_str::<Object<Envelope>>(sequence).is_err());
    }
}
