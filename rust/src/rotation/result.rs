use super::json_object::Object;
use super::{invalid, RotationError, MAX_ORDINAL};
use crate::ed25519::validate_public_key;
use crate::encoding::{decode_b64url_fixed, key_id};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::cmp::Ordering;

pub const MAX_RESULT_BODY_BYTES: usize = 256 * 1024;
pub const MAX_PAGE_RECORDS: usize = 16;

/// Owned public data, not carrier authentication or ACKed trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedResult {
    pub current_kid: String,
    pub current_public_key: [u8; 32],
    pub records: Vec<String>,
    pub head_ordinal: u64,
    pub head_hash: String,
    pub complete: bool,
}

// Map-only schema as in TS rotation-result.ts; not serde positional structs.
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
    // Numeric id: the response must be the byte-for-byte canonical JSON text
    // of the expected id value: shortest decimal form without exponent, exact
    // arithmetic without float; -0 is canonicalized to "0".
    canonical_id(expected).is_some_and(|canonical| actual == canonical)
}

fn canonical_id(text: &str) -> Option<String> {
    let (negative, digits, exponent) = parse_number_lexeme(text)?;
    if !within_float_range(&digits, exponent) {
        return None;
    }
    Some(canonical_decimal(negative, &digits, exponent))
}

// JSON number grammar: -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?;
// splits the lexeme into sign, int+frac digits and E = exp - len(frac).
fn parse_number_lexeme(text: &str) -> Option<(bool, String, i64)> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (mantissa, exp_text) = match rest.split_once(['e', 'E']) {
        Some((mantissa, exp_text)) => (mantissa, Some(exp_text)),
        None => (rest, None),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((int_part, frac_part)) => (int_part, Some(frac_part)),
        None => (mantissa, None),
    };
    if int_part.is_empty()
        || !int_part.bytes().all(|byte| byte.is_ascii_digit())
        || (int_part.len() > 1 && int_part.starts_with('0'))
    {
        return None;
    }
    if let Some(frac_part) = frac_part {
        if frac_part.is_empty() || !frac_part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
    }
    let mut digits = String::from(int_part);
    let mut exponent: i64 = 0;
    if let Some(frac_part) = frac_part {
        digits.push_str(frac_part);
        exponent -= frac_part.len() as i64;
    }
    if let Some(exp_text) = exp_text {
        let (sign, digits_text) = match exp_text.strip_prefix('-') {
            Some(rest) => (-1i64, rest),
            None => (1i64, exp_text.strip_prefix('+').unwrap_or(exp_text)),
        };
        if digits_text.is_empty() || !digits_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        // A giant exponent is cut off by the overflow gate anyway: rejecting at parse is correct.
        let parsed: i64 = digits_text.parse().ok()?;
        exponent += sign * parsed;
    }
    Some((negative, digits, exponent))
}

// Decimal digits of 2^exponent (most significant first): repeated doubling with carry,
// no float and no big-int crate.
fn power_of_two_decimal(exponent: u32) -> Vec<u8> {
    let mut digits: Vec<u8> = vec![1];
    for _ in 0..exponent {
        let mut carry = 0u8;
        for digit in digits.iter_mut() {
            let value = *digit * 2 + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    digits.reverse();
    digits
}

// Exact gate |value| < 2^1024: compares the digit string of value = D·10^E against
// 2^1024. Length comparison first, to avoid building giant runs of zeros.
fn within_float_range(digits: &str, exponent: i64) -> bool {
    // Outside the f64 range the gate can be closed immediately: 10^309 > 2^1024;
    // E < -MAX_RESULT_BODY_BYTES ⇒ the canonical text is longer than the body limit
    // and cannot match byte-for-byte the lexeme in the accepted response.
    if exponent > 308 {
        return false;
    }
    if -exponent > MAX_RESULT_BODY_BYTES as i64 {
        return false;
    }
    let stripped = digits.trim_start_matches('0');
    if stripped.is_empty() {
        return true;
    }
    let limit = power_of_two_decimal(1024);
    let (left_len, right_len) = if exponent >= 0 {
        (stripped.len() as i64 + exponent, limit.len() as i64)
    } else {
        (stripped.len() as i64, limit.len() as i64 - exponent)
    };
    match left_len.cmp(&right_len) {
        Ordering::Less => true,
        Ordering::Greater => false,
        // Equal lengths => runs of zeros are bounded: E >= 0 — at most
        // 308 zeros; E < 0 — bounded by the memory guard plus the input digit length.
        Ordering::Equal => {
            let left = if exponent >= 0 {
                format!("{stripped}{}", "0".repeat(exponent as usize))
            } else {
                stripped.to_string()
            };
            let mut right: String = limit.iter().map(|digit| char::from(b'0' + digit)).collect();
            if exponent < 0 {
                right.push_str(&"0".repeat((-exponent) as usize));
            }
            left < right
        }
    }
}

// Shortest decimal form without exponent; leading/trailing zeros are removed,
// -0 → "0", minus sign only on a nonzero value.
fn canonical_decimal(negative: bool, digits: &str, exponent: i64) -> String {
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut text = if exponent >= 0 {
        format!("{digits}{}", "0".repeat(exponent as usize))
    } else {
        let split = (-exponent) as usize;
        let (int_part, frac_part) = if digits.len() > split {
            let (int_part, frac_part) = digits.split_at(digits.len() - split);
            (int_part.to_string(), frac_part.to_string())
        } else {
            (
                "0".to_string(),
                format!("{}{digits}", "0".repeat(split - digits.len())),
            )
        };
        let frac_part = frac_part.trim_end_matches('0');
        if frac_part.is_empty() {
            int_part
        } else {
            format!("{int_part}.{frac_part}")
        }
    };
    if negative {
        text.insert(0, '-');
    }
    text
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

/// Only schema/parity/limits. Caller first performs outer authentication,
/// known interval and ClockGuard; then separately proofs/cursor/current binding/bridge/CAS.
/// No ACK, persistence, fetch or refresh; signed errors are handled by the caller.
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
    // Length1 checked above; content and payload types reject duplicate/extra fields.
    let item = &result.content[0].0;
    if item.kind != "text" {
        return Err(invalid("rotation_result_invalid"));
    }
    let structured = payload(result.structured.get())?;
    let mirror = payload(&item.text)?;
    // The only numeric payload field is the canonical head ordinal: its lexeme is unique.
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
