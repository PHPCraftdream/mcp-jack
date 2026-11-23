//! Value grammars and the base64 sentinel codec of the modern profile
//! (spec 04 sections 2 and 4): the `version` grammar, the RFC 9110
//! field-value and token grammars, and the `C3` encoder / `C4` decoder.
//!
//! Every check works on bytes of the UTF-8 encoding, so a non-ASCII byte
//! (and therefore every multi-byte character) fails the grammars that only
//! admit ASCII. No regex engine and no extra dependency is involved.

use std::cmp::Ordering;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::MODERN_MIN;

/// Length in bytes of a well-formed protocol version (`YYYY-MM-DD`).
const VERSION_LEN: usize = 10;

/// Opening marker of the base64 sentinel (spec 04 section 4, `C3`/`C4`).
const SENTINEL_PREFIX: &str = "=?base64?";

/// Closing marker of the base64 sentinel (spec 04 section 4, `C3`/`C4`).
const SENTINEL_SUFFIX: &str = "?=";

/// Shortest byte length that can hold both markers without overlap.
const SENTINEL_MIN_LEN: usize = SENTINEL_PREFIX.len() + SENTINEL_SUFFIX.len();

/// Why a header value could not be decoded as a base64 sentinel (C4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeHeaderValueError {
    /// The sentinel's inner text is not canonical standard base64 or not UTF-8.
    BadEncoding,
}

impl fmt::Display for DecodeHeaderValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jack: header value is not a decodable base64 sentinel")
    }
}

impl std::error::Error for DecodeHeaderValueError {}

/// Reports whether `value` is a well-formed protocol version: exactly 10
/// bytes, four ASCII digits, `-`, two ASCII digits, `-`, two ASCII digits
/// (spec 04 section 2).
pub fn is_version(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == VERSION_LEN
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

/// Compares two protocol versions byte-wise. For well-formed values this is
/// chronological order because the grammar is zero-padded `YYYY-MM-DD`.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Reports whether `value` is a modern-era version: well-formed and at least
/// `MODERN_MIN`.
pub fn is_modern_version(value: &str) -> bool {
    is_version(value) && compare_versions(value, MODERN_MIN) >= Ordering::Equal
}

/// Reports whether every byte of `value` is HTAB (0x09) or visible ASCII
/// (0x20..=0x7E), the RFC 9110 field-value grammar (spec 04 section 2).
/// NUL, LF, CR, DEL, every non-ASCII byte and therefore every non-ASCII
/// character make it false.
pub fn is_field_value(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|&b| b == b'\t' || (0x20..=0x7E).contains(&b))
}

/// Reports whether `value` is a non-empty RFC 9110 token (`1*tchar`), used
/// for header names and other bare words (spec 04 section 2).
pub fn is_token(value: &str) -> bool {
    !value.is_empty() && value.as_bytes().iter().all(|&b| is_tchar(b))
}

/// Reports whether `b` is an RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Reports whether `text` must be sent as a base64 sentinel: it is non-empty
/// and contains a character outside 0x20..=0x7E, starts or ends with SP, or
/// is itself sentinel-shaped (spec 04 section 4, `C3`).
fn needs_sentinel(text: &str) -> bool {
    !text.is_empty()
        && (text.chars().any(|c| !(' '..='~').contains(&c))
            || text.starts_with(' ')
            || text.ends_with(' ')
            || (text.starts_with(SENTINEL_PREFIX) && text.ends_with(SENTINEL_SUFFIX)))
}

/// Encodes `text` for a header value: unchanged when plain, otherwise
/// `=?base64?` + padded RFC 4648 section 4 standard base64 of the UTF-8
/// bytes + `?=` (spec 04 section 4, `C3`).
pub fn encode_header_value(text: &str) -> String {
    if !needs_sentinel(text) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(
        SENTINEL_PREFIX.len() + text.len().div_ceil(3) * 4 + SENTINEL_SUFFIX.len(),
    );
    out.push_str(SENTINEL_PREFIX);
    out.push_str(&STANDARD.encode(text.as_bytes()));
    out.push_str(SENTINEL_SUFFIX);
    out
}

/// Reports whether `text` is canonical padded standard base64 (RFC 4648
/// section 4): a non-empty multiple of four bytes, at most two trailing `=`
/// in the correct positions and only alphabet symbols before them.
fn is_canonical_base64(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return false;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return false;
    }
    let body = &bytes[..bytes.len() - pad];
    body.iter().all(|&b| {
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'+'
            || b == b'/'
    })
}

/// Decodes a header value: a `=?base64?…?=` sentinel becomes the UTF-8 text
/// it carries, every other value is returned unchanged (spec 04 section 4,
/// `C4`). Marker case is significant.
pub fn decode_header_value(text: &str) -> Result<String, DecodeHeaderValueError> {
    if !(text.starts_with(SENTINEL_PREFIX)
        && text.ends_with(SENTINEL_SUFFIX)
        && text.len() >= SENTINEL_MIN_LEN)
    {
        return Ok(text.to_owned());
    }
    let inner = &text[SENTINEL_PREFIX.len()..text.len() - SENTINEL_SUFFIX.len()];
    if inner.is_empty() {
        return Ok(String::new());
    }
    // Explicit canonical-form check: the engine's own rejection of foreign
    // bytes and stray padding must not be assumed.
    if !is_canonical_base64(inner) {
        return Err(DecodeHeaderValueError::BadEncoding);
    }
    let decoded = STANDARD
        .decode(inner)
        .map_err(|_| DecodeHeaderValueError::BadEncoding)?;
    // Re-encoding rejects non-zero unused trailing bits (for example "YR==").
    if STANDARD.encode(&decoded) != inner {
        return Err(DecodeHeaderValueError::BadEncoding);
    }
    String::from_utf8(decoded).map_err(|_| DecodeHeaderValueError::BadEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_header_value_vectors() {
        let cases: &[(&str, &str)] = &[
            ("us-west1", "us-west1"),
            ("Seattle WA", "Seattle WA"),
            ("", ""),
            ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
            (" padded ", "=?base64?IHBhZGRlZCA=?="),
            ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
            ("a\rb", "=?base64?YQ1i?="),
            ("a\u{0}b", "=?base64?YQBi?="),
            ("a\u{7f}b", "=?base64?YX9i?="),
            ("a\tb", "=?base64?YQli?="),
            ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
            ("=?base64?abc", "=?base64?abc"),
            ("abc?=", "abc?="),
            ("=?Base64?SGVsbG8=?=", "=?Base64?SGVsbG8=?="),
            ("🚀", "=?base64?8J+agA==?="),
        ];
        for (input, want) in cases {
            assert_eq!(encode_header_value(input), *want, "encode {input:?}");
        }
    }

    #[test]
    fn decode_round_trips() {
        for text in [
            "us-west1",
            "Seattle WA",
            "",
            "Hello, 世界",
            " padded ",
            "line1\nline2",
            "a\rb",
            "a\u{0}b",
            "a\u{7f}b",
            "a\tb",
            "=?base64?literal?=",
            "=?base64?abc",
            "abc?=",
            "=?Base64?SGVsbG8=?=",
            "🚀",
        ] {
            let encoded = encode_header_value(text);
            assert_eq!(
                decode_header_value(&encoded),
                Ok(text.to_owned()),
                "round trip {text:?} via {encoded:?}"
            );
        }
    }

    #[test]
    fn decode_plain_values_unchanged() {
        for text in ["us-west1", "Hello, 世界", "=?BASE64?SGVsbG8=?="] {
            assert_eq!(decode_header_value(text), Ok(text.to_owned()));
        }
    }

    #[test]
    fn decode_empty_sentinel_is_empty() {
        assert_eq!(decode_header_value("=?base64??="), Ok(String::new()));
    }

    #[test]
    fn decode_rejects_bad_sentinels() {
        for text in [
            "=?base64?YQ?=",    // missing padding
            "=?base64?YR==?=",  // non-zero unused trailing bits
            "=?base64?Y Q==?=", // space inside
            "=?base64?____?=",  // base64url alphabet
            "=?base64?/w==?=",  // byte 0xFF is not UTF-8
        ] {
            assert_eq!(
                decode_header_value(text),
                Err(DecodeHeaderValueError::BadEncoding),
                "decode {text:?}"
            );
        }
    }

    #[test]
    fn is_field_value_table() {
        for ok in ["", "a b", "a\tb"] {
            assert!(is_field_value(ok), "is_field_value({ok:?})");
        }
        for bad in ["a\nb", "a\rb", "a\0b", "a\u{7f}b", "é"] {
            assert!(!is_field_value(bad), "is_field_value({bad:?})");
        }
    }

    #[test]
    fn is_version_table() {
        assert!(is_version("2026-07-28"));
        assert!(is_version("2026-07-27"));
        assert!(is_version("2025-11-25"));
        for bad in [
            "2026-7-28",
            "2026-07-28-draft",
            "DRAFT-2026",
            "2026/07/28",
            "",
        ] {
            assert!(!is_version(bad), "is_version({bad:?})");
        }
    }

    #[test]
    fn compare_and_modern_versions() {
        assert!(is_modern_version("2026-07-28"));
        assert!(!is_modern_version("2026-07-27"));
        assert!(!is_modern_version("2025-11-25"));
        assert!(!is_modern_version("2026-7-28"));
        assert!(!is_modern_version("2026-07-28-draft"));
        assert!(!is_modern_version("DRAFT-2026"));
        assert!(!is_modern_version(""));

        assert_eq!(
            compare_versions("2026-07-28", "2026-07-27"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("2025-11-25", "2026-07-28"), Ordering::Less);
        assert_eq!(
            compare_versions("2026-07-28", "2026-07-28"),
            Ordering::Equal
        );
    }

    #[test]
    fn is_token_table() {
        for ok in ["Region", "x-mcp_header-1", "!#$%&'*+-.^_`|~"] {
            assert!(is_token(ok), "is_token({ok:?})");
        }
        for bad in ["", "a b", "a:b", "a@b", "a\"b", "é"] {
            assert!(!is_token(bad), "is_token({bad:?})");
        }
    }
}
