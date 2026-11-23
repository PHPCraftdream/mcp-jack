//! Subscription lifecycle of spec 06 section 8 (R8.1-R8.9): the canonical JSON
//! of `arguments`, the canonical callback url of R8.2, the derived `sub_` id,
//! the TTL grant with its `refreshBefore` deadline, secret rotation, and the
//! exact `gap` and `terminated` bodies.
//!
//! Everything here is pure: `now` is an argument, the only entropy is the
//! slice a caller supplies (or `getrandom` for [`random_webhook_id`]), and no
//! function performs I/O or logs a secret. Canonicalization mirrors
//! `spec/tools/modern/webhooks/ref/subscription.mjs` exactly, so an id derived
//! here equals the one the other SDKs derive from the same key.

use core::cmp::Ordering;
use core::fmt::Write as _;

use serde_json::{Map, Number, Value};

use crate::webhook::encoding::{sha256, WebhookSecret};
use crate::webhook::ssrf::url::{check_url, UrlParts};
use crate::webhook::{MessageKind, WebhookError};

/// The domain-separation string prefixed to the key of R8.4
/// (spec 06 R8.4).
pub const SUBSCRIPTION_DOMAIN: &str = "mcp-jack/webhook1/subscription";

/// The TTL granted when the request carries no `ttlMs`, in milliseconds
/// (spec 06 R8.5).
pub const DEFAULT_TTL_MS: i64 = 3_600_000;

/// The shortest TTL a suggestion is clamped up to, in milliseconds
/// (spec 06 R8.5).
pub const MIN_TTL_MS: i64 = 60_000;

/// The longest TTL a suggestion is clamped down to, in milliseconds
/// (spec 06 R8.5).
pub const MAX_TTL_MS: i64 = 86_400_000;

/// How long a rotated-out secret keeps signing deliveries, in seconds
/// (spec 06 R8.6).
pub const SECRET_GRACE_SECONDS: i64 = 300;

/// The longest accepted `cursor`, in characters (spec 06 R8.9).
pub const CURSOR_MAX_CHARS: usize = 512;

/// The largest integer magnitude an IEEE-754 double represents exactly
/// (spec 06 R8.3).
const MAX_EXACT_INTEGER: u64 = 1 << 53;

/// The prefix of every derived subscription id (spec 06 R8.4).
const ID_PREFIX: &str = "sub_";

/// The number of hex characters kept from the digest of the key
/// (spec 06 R8.4).
const ID_HEX_LEN: usize = 16;

/// The `invalid_arguments` wire code of R8.1, R8.3 and R8.5.
const INVALID_ARGUMENTS: &str = "invalid_arguments";

/// The `invalid_envelope` code of a `terminated` body outside the R8.8 shape.
const INVALID_ENVELOPE: &str = "invalid_envelope";

/// The fixed `invalid_arguments` message; it never names an input byte
/// (spec 06 R8.1, R8.3).
const ARGUMENTS_MESSAGE: &str = "the arguments are not acceptable";

/// The fixed `invalid_envelope` message (spec 06 R8.8).
const ENVELOPE_MESSAGE: &str = "the envelope is not acceptable";

/// The invalid-input status the profile uses for a rejected client value; the
/// spec assigns these codes no separate HTTP status (spec 06 section 3).
const BAD_REQUEST: u16 = 400;

/// The shortest and longest `webhook-id`, in characters (spec 06 R1.4).
const WEBHOOK_ID_MIN_CHARS: usize = 8;

/// The longest `webhook-id`, in characters (spec 06 R1.4).
const WEBHOOK_ID_MAX_CHARS: usize = 128;

/// The number of `[A-Za-z0-9]` characters after the `msg_` prefix of a
/// `webhook-id` (spec 06 R1.4).
const WEBHOOK_ID_SUFFIX_CHARS: usize = 32;

/// The alphabet of the `webhook-id` suffix, `[A-Za-z0-9]` in this order
/// (spec 06 R1.4).
const WEBHOOK_ID_ALPHABET: [u8; 62] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The largest multiple of 62 that fits a byte plus one: a byte at or above
/// it is rejected so every symbol is equally likely (spec 06 R1.4).
const WEBHOOK_ID_ACCEPT_BELOW: u8 = 248;

/// How often [`random_webhook_id`] refills its entropy before giving up.
const ENTROPY_ROUNDS: usize = 8;

/// The four-component subscription key and the three derived strings
/// (spec 06 R8.1-R8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionKey {
    /// The derived routing handle, `sub_` plus 16 lowercase hex characters
    /// (spec 06 R8.4).
    pub id: String,
    /// `delivery.url` in the R8.2 canonical form (spec 06 R8.2).
    pub canonical_url: String,
    /// The canonical JSON of `arguments`, `null` when absent
    /// (spec 06 R8.3).
    pub canonical_arguments: String,
    /// The canonical JSON array the id is hashed from (spec 06 R8.4).
    pub jcs_input: String,
}

/// The `ttlMs` member of a subscribe or refresh request (spec 06 R8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlInput {
    /// The member is absent: the server default applies (spec 06 R8.5).
    Absent,
    /// The member is `null`: no expiry (spec 06 R8.5).
    Null,
    /// The member is an integer number of milliseconds (spec 06 R8.5).
    Milliseconds(i64),
}

/// The authoritative TTL grant and its refresh deadline (spec 06 R8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlGrant {
    /// The granted lifetime in milliseconds, `None` for no expiry
    /// (spec 06 R8.5).
    pub grant_ms: Option<i64>,
    /// The grant as `YYYY-MM-DDTHH:MM:SSZ`, `None` for no expiry
    /// (spec 06 R8.5).
    pub refresh_before: Option<String>,
}

/// Builds the `invalid_arguments` rejection with a fixed-literal reason
/// (spec 06 R8.1, R8.3, R8.5).
fn invalid_arguments(reason: &'static str) -> WebhookError {
    WebhookError::with_reason(BAD_REQUEST, INVALID_ARGUMENTS, reason, ARGUMENTS_MESSAGE)
}

/// Builds the `invalid_envelope` rejection of R8.8.
fn invalid_envelope() -> WebhookError {
    WebhookError::new(BAD_REQUEST, INVALID_ENVELOPE, ENVELOPE_MESSAGE)
}

/// Returns the RFC 8785 canonical JSON of `value` (spec 06 R8.3).
///
/// Object members are sorted by the UTF-16 code-unit order of their keys, no
/// whitespace is emitted, only `"`, `\` and the control characters below
/// `U+0020` are escaped (with the `JSON.stringify` spellings), non-ASCII is
/// kept raw, and numbers use the ECMAScript `Number::toString` form: integers
/// as their decimal text, other values as their shortest round-trip digits.
/// A non-finite number is `invalid_arguments` with reason `arguments`
/// (spec 06 R8.3).
pub fn canonical_json(value: &Value) -> Result<String, WebhookError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

/// Returns the R8.2 canonical form of a callback url (spec 06 R8.2).
///
/// Delegates to the section 6 parser, so the same rejections apply; only the
/// canonical string is used by the key (spec 06 R8.2).
pub fn canonical_url(url: &str) -> Result<UrlParts, WebhookError> {
    check_url(url)
}

/// Derives the subscription key of `(principal, url, name, arguments)`
/// (spec 06 R8.1-R8.4).
///
/// The id is `sub_` plus the first 16 lowercase hex characters of SHA-256 over
/// the UTF-8 bytes of
/// `[SUBSCRIPTION_DOMAIN, principal, canonical_url, name, arguments]` in
/// canonical JSON. Absent arguments and JSON `null` are the same key, and a
/// non-object value is canonicalized like any other (spec 06 R8.3, R8.4).
pub fn subscription_key(
    principal: &str,
    url: &str,
    name: &str,
    arguments: Option<&Value>,
) -> Result<SubscriptionKey, WebhookError> {
    let target = canonical_url(url)?;
    let arguments = arguments.cloned().unwrap_or(Value::Null);
    let canonical_arguments = canonical_json(&arguments)?;
    let input = Value::Array(vec![
        Value::String(SUBSCRIPTION_DOMAIN.to_string()),
        Value::String(principal.to_string()),
        Value::String(target.canonical.clone()),
        Value::String(name.to_string()),
        arguments,
    ]);
    let jcs_input = canonical_json(&input)?;
    let digest = sha256(jcs_input.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(SubscriptionKey {
        id: format!("{ID_PREFIX}{}", &hex[..ID_HEX_LEN]),
        canonical_url: target.canonical,
        canonical_arguments,
        jcs_input,
    })
}

/// Computes the TTL grant and its refresh deadline (spec 06 R8.5).
///
/// `Absent` takes [`DEFAULT_TTL_MS`], `Null` grants no expiry, and an integer
/// is clamped into `[MIN_TTL_MS, MAX_TTL_MS]`; a negative integer is
/// `invalid_arguments` with reason `ttl`. `refresh_before` is
/// `now + grant / 1000` as `YYYY-MM-DDTHH:MM:SSZ` (spec 06 R8.5).
pub fn ttl_grant(ttl: TtlInput, now: i64) -> Result<TtlGrant, WebhookError> {
    let grant_ms = match ttl {
        TtlInput::Null => {
            return Ok(TtlGrant {
                grant_ms: None,
                refresh_before: None,
            })
        }
        TtlInput::Absent => DEFAULT_TTL_MS,
        TtlInput::Milliseconds(milliseconds) => {
            if milliseconds < 0 {
                return Err(invalid_arguments("ttl"));
            }
            milliseconds.clamp(MIN_TTL_MS, MAX_TTL_MS)
        }
    };
    let deadline = now.saturating_add(grant_ms / 1000);
    Ok(TtlGrant {
        grant_ms: Some(grant_ms),
        refresh_before: Some(iso_seconds(deadline)),
    })
}

/// Maps the JSON `ttlMs` member of a subscribe or refresh request onto the
/// grant of [`ttl_grant`] (spec 06 R8.5).
///
/// `None` is the absent member and takes [`DEFAULT_TTL_MS`],
/// `Some(Value::Null)` grants no expiry, and `Some(number)` must be a
/// non-negative integer JSON number under the reference's JavaScript number
/// semantics, so `1e3` is the integer 1000: a fraction and every non-number
/// value are `invalid_arguments` with reason `ttl`. The accepted
/// integer is then clamped into `[MIN_TTL_MS, MAX_TTL_MS]` and its
/// `refresh_before` rendered exactly as [`ttl_grant`] does it, so the grant
/// rule itself lives in one place (spec 06 R8.5).
pub fn ttl_grant_from_json(
    ttl: Option<&serde_json::Value>,
    now: i64,
) -> Result<TtlGrant, WebhookError> {
    let input = match ttl {
        None => TtlInput::Absent,
        Some(Value::Null) => TtlInput::Null,
        Some(value) => {
            let Some(milliseconds) = integer_number(value) else {
                return Err(invalid_arguments("ttl"));
            };
            TtlInput::Milliseconds(milliseconds)
        }
    };
    ttl_grant(input, now)
}

/// Returns `value` as a JSON integer number of milliseconds (spec 06 R8.5).
///
/// Follows the reference's JavaScript number semantics: the value is accepted
/// whenever JavaScript's `Number.isInteger` accepts it, so `1000` and `1e3`
/// are both `Some(1000)` while `1.5` is `None`. An integer above `i64::MAX`
/// saturates, and a float outside the `i64` range is refused, leaving the
/// grant to the clamp of [`ttl_grant`] (spec 06 R8.5).
fn integer_number(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    if let Some(number) = value.as_u64() {
        return Some(i64::try_from(number).unwrap_or(i64::MAX));
    }
    let number = value.as_f64()?;
    // An integral float such as `1e3` is an integer, so it is truncated to its
    // `i64` value; a fraction, a non-finite value and a magnitude no `i64`
    // holds are all refused (spec 06 R8.5).
    const I64_MIN_F64: f64 = -9_223_372_036_854_775_808.0;
    const I64_MAX_EXCLUSIVE_F64: f64 = 9_223_372_036_854_775_808.0;
    if !number.is_finite() || number.fract() != 0.0 {
        return None;
    }
    if !(I64_MIN_F64..I64_MAX_EXCLUSIVE_F64).contains(&number) {
        return None;
    }
    Some(number as i64)
}

/// Returns the secrets that may sign right now, current first (spec 06 R8.6).
///
/// The previous secret is active only while `now < grace_ends_at`, so the
/// grace window is exclusive; a caller without a previous secret passes
/// `None` and gets one entry (spec 06 R8.6).
pub fn active_secrets<'a>(
    current: &'a WebhookSecret,
    previous: Option<&'a WebhookSecret>,
    grace_ends_at: i64,
    now: i64,
) -> Vec<&'a WebhookSecret> {
    let mut secrets = vec![current];
    if let Some(previous) = previous {
        if now < grace_ends_at {
            secrets.push(previous);
        }
    }
    secrets
}

/// Returns the exact `{"type":"gap","cursor":...}` body (spec 06 R8.7).
///
/// The `cursor` member is the string itself or `null`, in that member order,
/// with no other member (spec 06 R8.7).
pub fn gap_body(cursor: Option<&str>) -> String {
    let mut body = String::from("{\"type\":\"gap\",\"cursor\":");
    match cursor {
        Some(cursor) => write_json_string(cursor, &mut body),
        None => body.push_str("null"),
    }
    body.push('}');
    body
}

/// Returns the exact `{"type":"terminated",...}` body (spec 06 R8.8).
///
/// `code` must be a JSON integer and `data`, when present, a JSON object;
/// anything else is `invalid_envelope`. The emitted member order is `type`,
/// `error.code`, `error.message` and, only when supplied, `error.data`
/// (spec 06 R8.8).
pub fn terminated_body(
    code: &Value,
    message: &str,
    data: Option<&Value>,
) -> Result<String, WebhookError> {
    let Some(code) = code.as_i64() else {
        return Err(invalid_envelope());
    };
    let mut body = String::from("{\"type\":\"terminated\",\"error\":{\"code\":");
    body.push_str(&code.to_string());
    body.push_str(",\"message\":");
    write_json_string(message, &mut body);
    if let Some(data) = data {
        if !data.is_object() {
            return Err(invalid_envelope());
        }
        body.push_str(",\"data\":");
        body.push_str(&canonical_json(data).map_err(|_| invalid_envelope())?);
    }
    body.push_str("}}");
    Ok(body)
}

/// Returns the R8.8 `terminated` body for a JSON envelope input
/// (spec 06 R8.8).
///
/// `input` must be an object whose `code` is an integer JSON number, whose
/// `message` is a string, and whose optional `data` member, when present, is
/// an object: `null`, an array and a scalar are all `invalid_envelope`. The
/// body text itself comes from [`terminated_body`], so there is one
/// serializer (spec 06 R8.8).
pub fn terminated_envelope(input: &Value) -> Result<String, WebhookError> {
    let Some(members) = input.as_object() else {
        return Err(invalid_envelope());
    };
    let Some(code) = members.get("code") else {
        return Err(invalid_envelope());
    };
    if code.as_i64().is_none() {
        return Err(invalid_envelope());
    }
    let Some(message) = members.get("message").and_then(Value::as_str) else {
        return Err(invalid_envelope());
    };
    let data = members.get("data");
    if data.is_some_and(|data| !data.is_object()) {
        return Err(invalid_envelope());
    }
    terminated_body(code, message, data)
}

/// Reports whether `value` is an acceptable `cursor` (spec 06 R8.9).
///
/// `None` is the `null` cursor and is accepted; otherwise the value is 1 to
/// [`CURSOR_MAX_CHARS`] characters of printable ASCII `0x21..=0x7e`
/// (spec 06 R8.9).
pub fn cursor_ok(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= CURSOR_MAX_CHARS
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

/// Reports whether `value` matches `^[A-Za-z0-9_-]{8,128}$` (spec 06 R1.4).
pub fn webhook_id_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    (WEBHOOK_ID_MIN_CHARS..=WEBHOOK_ID_MAX_CHARS).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

/// Reports whether `value` matches `^(0|[1-9][0-9]{0,11})$` (spec 06 R1.5).
///
/// The accepted form is a single `0` or one to twelve decimal digits with no
/// leading zero, so the value always fits an `i64` (spec 06 R1.5).
pub fn timestamp_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes == b"0" {
        return true;
    }
    !bytes.is_empty()
        && bytes.len() <= 12
        && bytes[0] != b'0'
        && bytes.iter().all(u8::is_ascii_digit)
}

/// Reports whether `value` matches `^sub_[0-9a-f]{16}$` (spec 06 R3.5,
/// R8.4).
pub fn subscription_id_ok(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(ID_PREFIX) else {
        return false;
    };
    hex.len() == ID_HEX_LEN
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Derives a `webhook-id` of `kind` from caller-supplied entropy
/// (spec 06 R1.4).
///
/// The value is `msg_` followed by 32 characters of `[A-Za-z0-9]` for an
/// event, and `msg_<type>_` followed by the same 32 characters for a control
/// envelope. Each byte below `248` contributes one symbol, so the 32 symbols
/// are uniform and carry at least 120 bits; a slice with too few acceptable
/// bytes yields `None` (spec 06 R1.4).
pub fn new_webhook_id(kind: MessageKind, entropy: &[u8]) -> Option<String> {
    let mut suffix = String::with_capacity(WEBHOOK_ID_SUFFIX_CHARS);
    for byte in entropy {
        if *byte >= WEBHOOK_ID_ACCEPT_BELOW {
            continue;
        }
        let index = usize::from(*byte) % WEBHOOK_ID_ALPHABET.len();
        suffix.push(char::from(WEBHOOK_ID_ALPHABET[index]));
        if suffix.len() == WEBHOOK_ID_SUFFIX_CHARS {
            break;
        }
    }
    if suffix.len() < WEBHOOK_ID_SUFFIX_CHARS {
        return None;
    }
    Some(match kind {
        MessageKind::Event => format!("msg_{suffix}"),
        other => format!("msg_{}_{suffix}", other.as_str()),
    })
}

/// Derives a fresh `webhook-id` of `kind` from the OS entropy source
/// (spec 06 R1.4).
///
/// The value is never derived from an `eventId` and is reused unchanged
/// across the retries of one message (spec 06 R1.4). A failure of the entropy
/// source is the internal error of the profile.
pub fn random_webhook_id(kind: MessageKind) -> Result<String, WebhookError> {
    let mut entropy = [0u8; 64];
    for _ in 0..ENTROPY_ROUNDS {
        getrandom::fill(&mut entropy)
            .map_err(|_| WebhookError::new(500, "internal_error", "internal error"))?;
        if let Some(id) = new_webhook_id(kind, &entropy) {
            return Ok(id);
        }
    }
    Err(WebhookError::new(500, "internal_error", "internal error"))
}

/// Appends the RFC 8785 form of `value` to `out` (spec 06 R8.3).
fn write_canonical(value: &Value, out: &mut String) -> Result<(), WebhookError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&canonical_number(number)?),
        Value::String(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => write_canonical_object(members, out)?,
    }
    Ok(())
}

/// Appends one canonical JSON object to `out` (spec 06 R8.3).
fn write_canonical_object(
    members: &Map<String, Value>,
    out: &mut String,
) -> Result<(), WebhookError> {
    let mut keys: Vec<&String> = members.keys().collect();
    keys.sort_by(|left, right| utf16_order(left, right));
    out.push('{');
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_json_string(key, out);
        out.push(':');
        write_canonical(&members[*key], out)?;
    }
    out.push('}');
    Ok(())
}

/// Compares two strings by UTF-16 code-unit order (spec 06 R8.3).
fn utf16_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Appends the `JSON.stringify` form of one JSON string to `out`
/// (spec 06 R8.3).
///
/// Only `"`, `\` and the control characters below `U+0020` are escaped:
/// `\b`, `\t`, `\n`, `\f` and `\r` get their names and every other control
/// character becomes a lowercase `\u00xx`; non-ASCII is kept raw
/// (spec 06 R8.3).
fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            literal => out.push(literal),
        }
    }
    out.push('"');
}

/// Returns the ECMAScript `Number::toString` form of one JSON number
/// (spec 06 R8.3).
///
/// Follows the reference's JavaScript number semantics, where `jcs` renders a
/// value that came through `JSON.parse`, so every number is an IEEE-754
/// double: an integer member of magnitude at most `2^53` is emitted as its
/// exact decimal text, an integer beyond that range is converted to `f64`
/// first, and a float is rendered by [`ecma_number`] (spec 06 R8.3).
fn canonical_number(number: &Number) -> Result<String, WebhookError> {
    if let Some(value) = number.as_i64() {
        if value.unsigned_abs() <= MAX_EXACT_INTEGER {
            return Ok(value.to_string());
        }
    } else if let Some(value) = number.as_u64() {
        if value <= MAX_EXACT_INTEGER {
            return Ok(value.to_string());
        }
    }
    let Some(value) = number.as_f64() else {
        return Err(invalid_arguments("arguments"));
    };
    if !value.is_finite() {
        return Err(invalid_arguments("arguments"));
    }
    Ok(ecma_number(value))
}

/// Formats one finite `f64` as ECMAScript 7.1.12.1 renders it
/// (spec 06 R8.3).
///
/// The shortest round-trip digits come from Rust's `{:e}` form; the ECMAScript
/// algorithm then chooses plain decimal while the decimal point stays within
/// 21 places and the exponential form otherwise (`1e21` is `1e+21`, `1e3` is
/// `1000`, `0.1` is `0.1`, and either zero is `0`).
fn ecma_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let scientific = format!("{:e}", value.abs());
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return format!("{sign}{scientific}");
    };
    let digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let Ok(exponent) = exponent.parse::<i32>() else {
        return format!("{sign}{scientific}");
    };
    let count = digits.len() as i32;
    // `n` is the position of the decimal point: digits before it when positive.
    let point = exponent + 1;
    let body = if count <= point && point <= 21 {
        format!("{digits}{}", "0".repeat((point - count) as usize))
    } else if 0 < point && point <= 21 {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    } else if -6 < point && point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        let magnitude = (point - 1).abs();
        let marker = if point > 0 { '+' } else { '-' };
        if count == 1 {
            format!("{digits}e{marker}{magnitude}")
        } else {
            format!("{}.{}e{marker}{magnitude}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// Renders `seconds` as an ISO 8601 UTC timestamp with second precision
/// (spec 06 R8.5).
///
/// The calendar fields are computed by hand, so no date library is needed: the
/// days-since-epoch are converted by the proleptic Gregorian algorithm and the
/// second-of-day is taken with Euclidean remainder, which keeps instants
/// before the epoch correct (spec 06 R8.5).
fn iso_seconds(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let within_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = within_day / 3_600;
    let minute = (within_day % 3_600) / 60;
    let second = within_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts days since the Unix epoch to a proleptic Gregorian year, month
/// and day (spec 06 R8.5).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
