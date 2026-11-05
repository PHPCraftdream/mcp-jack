//! Strict canonical unpadded base64url encoding/decoding plus two SHA-256
//! based helpers (Go: base64.go). Spec 01 section 2 requires rejecting
//! padding, foreign characters, and encodings whose unused trailing bits are
//! not zero.

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, engine::DecodePaddingMode, Engine as _};
use sha2::{Digest, Sha256};
use std::{fmt, sync::LazyLock};

/// Sentinel error for a string that is not canonical unpadded base64url
/// (Go: ErrBadBase64URL). Callers map it to the context-appropriate
/// protocol code (malformed_auth, invalid_invite, ...), so encoding stays
/// decoupled from the error table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadBase64Url;

impl fmt::Display for BadBase64Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jack: invalid base64url")
    }
}

impl std::error::Error for BadBase64Url {}

// Strict engine: every setting is load-bearing.
// - `with_encode_padding(false)`: canonical form is unpadded (RFC 4648 section 5 raw).
// - `with_decode_padding_mode(RequireNone)`: `=` must be rejected on decode (spec 01 section 2).
// - `with_decode_allow_trailing_bits(false)`: a final symbol with non-zero unused
//   bits (e.g. "ab", "aa_") is non-canonical and must be rejected; with this
//   enabled the decoder would silently accept it.
static STRICT_B64: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    // The unpadded RFC 4648 section 5 url-safe alphabet.
    let alphabet =
        alphabet::Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            .expect("literal alphabet is valid");
    GeneralPurpose::new(
        &alphabet,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(false),
    )
});

/// Reports whether every byte of `s` is in the RFC 4648 section 5 url-safe
/// alphabet. Needed because the engine alone would not flag whitespace or
/// other foreign bytes in every position (Go: b64URLAlphabetOK).
fn b64url_alphabet_ok(s: &str) -> bool {
    s.bytes().all(|c| {
        c.is_ascii_uppercase()
            || c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == b'-'
            || c == b'_'
    })
}

/// Returns the canonical unpadded base64url encoding of `data`
/// (RFC 4648 section 5, no padding).
pub fn encode_b64url(data: &[u8]) -> String {
    STRICT_B64.encode(data)
}
/// Strictly decodes an unpadded, canonical base64url string (spec 01 section 2).
/// The empty string decodes to an empty Vec.
pub fn decode_b64url(s: &str) -> Result<Vec<u8>, BadBase64Url> {
    if !b64url_alphabet_ok(s) {
        return Err(BadBase64Url);
    }
    // The engine rejects padding, invalid lengths and non-zero unused trailing
    // bits, so any error maps to the single sentinel.
    STRICT_B64.decode(s).map_err(|_| BadBase64Url)
}

/// `decode_b64url` plus a required exact decoded length of `size` bytes.
pub fn decode_b64url_fixed(s: &str, size: usize) -> Result<Vec<u8>, BadBase64Url> {
    let decoded = decode_b64url(s)?;
    if decoded.len() != size {
        return Err(BadBase64Url);
    }
    Ok(decoded)
}

/// Returns base64url(SHA-256(public_key)) (spec 01 section 2).
pub fn key_id(public_key: &[u8]) -> String {
    encode_b64url(&Sha256::digest(public_key))
}

/// Returns base64url(SHA-256(body)) over the exact bytes; an empty body
/// is hashed as an empty byte string, so the result is never empty (spec 01
/// section 3.1).
pub fn body_hash(body: &[u8]) -> String {
    encode_b64url(&Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_rfc4648_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, want) in vectors {
            assert_eq!(&encode_b64url(bytes), want);
            assert_eq!(decode_b64url(want).as_deref(), Ok(*bytes));
        }
    }

    #[test]
    fn round_trip_lengths() {
        for n in [0usize, 1, 2, 3, 16, 32, 64] {
            let b: Vec<u8> = (0..n).map(|i| ((i * 7 + 1) & 0xff) as u8).collect();
            assert_eq!(
                decode_b64url(&encode_b64url(&b)).as_deref(),
                Ok(b.as_slice())
            );
        }
    }

    #[test]
    fn decode_rejects_malformed() {
        for s in [
            "ab=", "ab==", "a b", "ab\n", "?", "a", "aa_", "ab", "+", "/", "abé",
        ] {
            assert!(
                decode_b64url(s).is_err(),
                "decode_b64url({s:?}) should fail"
            );
        }
    }

    #[test]
    fn decode_accepts_zero_trailing_bits() {
        let cases: &[(&str, &[u8])] = &[
            ("aw", &[0x6B]),        // 011010 110000: unused bits are zero
            ("aag", &[0x69, 0xA8]), // 011010 011010 100000
            ("aa8", &[0x69, 0xAF]), // 011010 011010 111100
        ];
        for (input, want) in cases {
            let decoded = decode_b64url(input).unwrap_or_else(|e| panic!("decode {input:?}: {e}"));
            assert_eq!(decoded.as_slice(), *want);
            assert_eq!(encode_b64url(&decoded), *input);
        }
    }

    #[test]
    fn decode_fixed_size() {
        assert_eq!(decode_b64url_fixed("aw", 1).as_deref(), Ok(&[0x6B][..]));
        assert!(decode_b64url_fixed("aw", 2).is_err());
        assert!(decode_b64url_fixed("aw", 0).is_err());
        assert!(decode_b64url_fixed("a", 1).is_err());
    }

    #[test]
    fn key_id_and_body_hash() {
        let pub_key: Vec<u8> = (0..32).map(|i| ((i * 7 + 1) & 0xff) as u8).collect();
        assert_eq!(key_id(&pub_key), key_id(&pub_key));
        assert_eq!(key_id(&pub_key).len(), 43);

        assert_eq!(body_hash(b"payload"), body_hash(b"payload"));
        assert_eq!(body_hash(b"payload").len(), 43);

        assert_eq!(key_id(&[]), key_id(&[]));
        assert_eq!(key_id(&[]).len(), 43);
        assert!(!body_hash(&[]).is_empty());

        let other: Vec<u8> = (0..32).map(|i| ((i * 11 + 3) & 0xff) as u8).collect();
        assert_ne!(key_id(&pub_key), key_id(&other));
    }
}
