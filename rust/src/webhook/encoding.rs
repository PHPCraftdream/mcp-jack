//! Canonical standard base64, SHA-256, HMAC-SHA-256, constant-time comparison
//! and the Standard Webhooks delivery secret (spec 06 section 2).
//!
//! Standard Webhooks signs with base64 (RFC 4648 section 4, *padded*, `+`/`/`
//! alphabet) — unlike the Jack wire profile, which is base64url. Every
//! rejection here is expressed as a fixed literal: a secret is never printed
//! and never copied into an error or a log line (spec 06 section 3).

use core::fmt;

use hmac::digest::crypto_common::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::webhook::{codes, WebhookError};

/// The RFC 4648 section 4 standard base64 alphabet (`A-Za-z0-9+/`).
const STD_ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The literal Standard Webhooks secret prefix (spec 06 R2.1).
const SECRET_PREFIX: &str = "whsec_";

/// Smallest accepted decoded secret length in bytes (spec 06 R2.1).
const SECRET_MIN_LEN: usize = 24;

/// Largest accepted decoded secret length in bytes (spec 06 R2.1).
const SECRET_MAX_LEN: usize = 64;

/// The single fixed message for every `invalid_secret` rejection
/// (spec 06 section 3); it never names an input byte.
const INVALID_SECRET_MESSAGE: &str = "the delivery secret is not acceptable";

/// HMAC instantiated with SHA-256 (spec 06 R2.2).
type HmacSha256 = Hmac<Sha256>;

/// Returns the canonical *padded* standard base64 encoding of `bytes`
/// (RFC 4648 section 4: `A-Za-z0-9+/`, `=` padding to a multiple of four).
///
/// This is the encoding Standard Webhooks uses for a secret and a signature
/// value (spec 06 R2.1, R2.2).
pub fn encode_b64_std(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut triple = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            triple |= u32::from(*byte) << (16 - 8 * index);
        }
        out.push(char::from(STD_ALPHABET[(triple >> 18) as usize & 0x3f]));
        out.push(char::from(STD_ALPHABET[(triple >> 12) as usize & 0x3f]));
        if chunk.len() > 1 {
            out.push(char::from(STD_ALPHABET[(triple >> 6) as usize & 0x3f]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(STD_ALPHABET[triple as usize & 0x3f]));
        } else {
            out.push('=');
        }
    }
    out
}

/// Why `text` is not canonical padded standard base64 (spec 06 R2.1).
///
/// The variants are the fixed-literal reasons of the `invalid_secret` code,
/// in the priority order the spec assigns them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum B64Reject {
    /// A character outside `A-Za-z0-9+/` (spec 06 R2.1, reason `alphabet`).
    Alphabet,
    /// A `=` that is not the last one or two characters, or a length that is
    /// not a multiple of four (spec 06 R2.1, reason `padding`).
    Padding,
    /// Non-zero unused trailing bits, or a re-encoding mismatch
    /// (spec 06 R2.1, reason `canonical`).
    Canonical,
}

/// Returns the six-bit value of one standard base64 symbol, or `None` for a
/// byte outside `A-Za-z0-9+/` (RFC 4648 section 4).
fn b64_symbol(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes padded standard base64, reporting which rule rejected the input.
///
/// Accepts exactly the strings `encode_b64_std` produces, classifying every
/// other string by the first rule it violates: alphabet, then padding, then
/// canonical form (spec 06 R2.1).
fn decode_b64_std_classified(text: &str) -> Result<Vec<u8>, B64Reject> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    // The alphabet rule comes first: every byte must be a symbol of
    // `A-Za-z0-9+/`, `=` being judged by its position alone.
    for byte in bytes {
        if *byte != b'=' && b64_symbol(*byte).is_none() {
            return Err(B64Reject::Alphabet);
        }
    }
    // `=` may only be the last one or two characters; a `=` anywhere else is
    // a padding failure, not an alphabet one (spec 06 R2.1).
    let pad = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if pad > 2 {
        return Err(B64Reject::Padding);
    }
    let data = &bytes[..len - pad];
    if data.contains(&b'=') {
        return Err(B64Reject::Padding);
    }
    if !len.is_multiple_of(4) {
        return Err(B64Reject::Padding);
    }

    let mut out = Vec::with_capacity(len / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in data {
        let value = match b64_symbol(*byte) {
            Some(value) => value,
            None => return Err(B64Reject::Alphabet),
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    // With a length that is a multiple of four, `bits` is 0, 2 or 4; the
    // unused low bits of the last symbol must be zero, otherwise the encoding
    // is not canonical (spec 01 section 2, applied to the standard alphabet).
    if bits > 0 && (accumulator & ((1u32 << bits) - 1)) != 0 {
        return Err(B64Reject::Canonical);
    }
    // The strongest check: only the one encoding of these bytes is accepted
    // (spec 06 R2.1, reason `canonical`).
    if encode_b64_std(&out) != text {
        return Err(B64Reject::Canonical);
    }
    Ok(out)
}

/// Strictly decodes canonical *padded* standard base64 (spec 06 R2.1, R2.2).
///
/// Returns `Some` only when every character is in `A-Za-z0-9+/`, a `=` appears
/// solely as the last one or two characters, the length is a multiple of four,
/// the unused trailing bits are zero, and re-encoding the decoded bytes
/// reproduces `text` exactly. The empty string decodes to an empty `Vec`.
pub fn decode_b64_std_strict(text: &str) -> Option<Vec<u8>> {
    decode_b64_std_classified(text).ok()
}

/// Returns SHA-256 of exactly `bytes` (spec 06 R2.2: the signature is an
/// HMAC-SHA-256, and hashing is never done over a decoded or re-encoded form).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Returns HMAC-SHA-256 of `message` under `key` (spec 06 R2.2).
///
/// The key is first brought to the SHA-256 block size exactly as RFC 2104
/// prescribes, so a key of any length — including one longer than 64 bytes —
/// yields the standard result without any fallible call.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        let hashed = sha256(key);
        block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut mac = <HmacSha256 as KeyInit>::new(&block.into());
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Compares two byte strings in time that depends only on their lengths
/// (spec 06 R2.2, step 15 of section 3).
///
/// Returns `false` immediately on a length mismatch, then folds every byte
/// pair into one accumulator, so no byte position short-circuits the loop on
/// content.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// A Standard Webhooks delivery secret: the `whsec_` prefix plus the canonical
/// padded standard base64 of 24 to 64 bytes (spec 06 R2.1).
///
/// The value is compared and copied by the signature layer; it is never
/// rendered by `Debug` and never placed in an error (spec 06 section 3).
pub struct WebhookSecret {
    /// The decoded secret bytes, 24 to 64 of them (spec 06 R2.1).
    bytes: Vec<u8>,
}

impl WebhookSecret {
    /// Parses a `delivery.secret` value (spec 06 R2.1).
    ///
    /// The value must start with the literal `whsec_`, the remainder must be
    /// canonical padded standard base64 (the one encoding of its bytes) and
    /// must decode to 24 to 64 bytes. Every failure is
    /// `invalid_secret` with HTTP status 400 and the fixed reason of the rule
    /// that rejected it: `prefix`, `alphabet`, `padding`, `canonical` or
    /// `length`, checked in that order. No input byte reaches the error.
    pub fn parse(value: &str) -> Result<Self, WebhookError> {
        let remainder = match value.strip_prefix(SECRET_PREFIX) {
            Some(remainder) => remainder,
            None => return Err(invalid_secret("prefix")),
        };
        let bytes = match decode_b64_std_classified(remainder) {
            Ok(bytes) => bytes,
            Err(B64Reject::Alphabet) => return Err(invalid_secret("alphabet")),
            Err(B64Reject::Padding) => return Err(invalid_secret("padding")),
            Err(B64Reject::Canonical) => return Err(invalid_secret("canonical")),
        };
        if !(SECRET_MIN_LEN..=SECRET_MAX_LEN).contains(&bytes.len()) {
            return Err(invalid_secret("length"));
        }
        Ok(Self { bytes })
    }

    /// Wraps already-decoded secret bytes (spec 06 R2.1).
    ///
    /// The length rule belongs to `parse`; this constructor is for callers
    /// that own the bytes directly and performs no check.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the decoded secret bytes, never the `whsec_` text form
    /// (spec 06 R2.1).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Clones a secret; `Clone` is deliberate rather than derived so the type can
/// never be compared or ordered by accident (spec 06 R2.1).
impl Clone for WebhookSecret {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

impl fmt::Debug for WebhookSecret {
    /// Prints `WebhookSecret(<redacted>)` and never a secret byte
    /// (spec 06 section 3: no secret in any log line).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// Builds the `invalid_secret` rejection with a fixed-literal reason
/// (spec 06 R2.1).
fn invalid_secret(reason: &'static str) -> WebhookError {
    WebhookError::with_reason(400, codes::INVALID_SECRET, reason, INVALID_SECRET_MESSAGE)
}
