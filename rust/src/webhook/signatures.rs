//! The Standard Webhooks signing content and signature header of spec 06
//! section 2: `v1`, `v1a` and `v2a` (R2.2, R2.5, R2.6), the
//! `webhook-signature` grammar (R2.4) and the scheme and length checks the
//! receiver applies before verifying (R3.11, R3.12).
//!
//! Everything here is pure: no clock, no I/O, no logging. A rejection carries
//! the spec-assigned status and code, and its message is a fixed literal, so
//! neither a secret nor a header byte can reach an error (spec 06 section 3,
//! R2.3).

use ed25519_dalek::{Signer, SigningKey};

use crate::webhook::encoding::{
    constant_time_eq, decode_b64_std_strict, encode_b64_std, hmac_sha256, sha256, WebhookSecret,
};
use crate::webhook::{codes, WebhookError};

/// The single SP that separates header entries (spec 06 R2.4).
const SP: char = ' ';

/// The decoded length of a `v1` HMAC-SHA-256 value (spec 06 R2.2).
const V1_LEN: usize = 32;

/// The decoded length of a `v1a` or `v2a` Ed25519 value (spec 06 R2.5, R2.6).
const ASYM_LEN: usize = 64;

/// The fixed `malformed_signature_header` message (spec 06 R2.4, section 3).
const MALFORMED_HEADER_MESSAGE: &str = "the webhook-signature header is malformed";

/// The fixed `unsupported_signature_scheme` message (spec 06 R3.11).
const UNSUPPORTED_SCHEME_MESSAGE: &str = "a signature scheme is not v1, v1a or v2a";

/// The fixed `malformed_signature` message (spec 06 R3.12).
const MALFORMED_SIGNATURE_MESSAGE: &str =
    "a signature value is not canonical standard base64 of the expected length";

/// The bytes a signature covers, borrowed from the request (spec 06 R2.3).
///
/// The body is kept as raw bytes: it is never parsed, re-serialized or
/// normalized, so the signed content is exactly what was received
/// (spec 06 R2.3).
#[derive(Debug, Clone, Copy)]
pub struct SignatureContent<'a> {
    /// The `webhook-id` header value, verbatim (spec 06 R2.2).
    pub webhook_id: &'a str,
    /// The `webhook-timestamp` header value, verbatim (spec 06 R2.2).
    pub timestamp: &'a str,
    /// The raw request body bytes, unmodified (spec 06 R2.3).
    pub body: &'a [u8],
}

impl SignatureContent<'_> {
    /// Returns the signed content `webhook-id "." timestamp "." body` as UTF-8
    /// bytes with the raw body appended (spec 06 R2.2, R2.3).
    ///
    /// Both header values are copied byte for byte and the body follows the
    /// second dot unchanged, so the same function produces the content of
    /// `v1` and of `v1a` (spec 06 R2.2, R2.5).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.webhook_id.len() + 1 + self.timestamp.len() + 1 + self.body.len(),
        );
        out.extend_from_slice(self.webhook_id.as_bytes());
        out.push(b'.');
        out.extend_from_slice(self.timestamp.as_bytes());
        out.push(b'.');
        out.extend_from_slice(self.body);
        out
    }
}

/// Returns `HMAC-SHA256(secret, content)` over the decoded secret bytes
/// (spec 06 R2.2).
///
/// The MAC is 32 bytes; a receiver compares it in constant time, which is the
/// caller's job (`encoding::constant_time_eq`, spec 06 R2.2).
pub fn v1_mac(secret: &WebhookSecret, content: &SignatureContent<'_>) -> [u8; 32] {
    hmac_sha256(secret.as_bytes(), &content.to_bytes())
}

/// Returns `SHA-256("endpoint_id." + content)` (spec 06 R2.6).
///
/// The endpoint id is the subscription id of section 8; it and the two header
/// values are joined by dots and hashed once together with the raw body, and
/// `v2a` signs the resulting 32-byte digest.
pub fn v2a_digest(endpoint_id: &str, content: &SignatureContent<'_>) -> [u8; 32] {
    let inner = content.to_bytes();
    let mut bytes = Vec::with_capacity(endpoint_id.len() + 1 + inner.len());
    bytes.extend_from_slice(endpoint_id.as_bytes());
    bytes.push(b'.');
    bytes.extend_from_slice(&inner);
    sha256(&bytes)
}

/// Renders the `v1,<value>` header entry of spec 06 R2.2.
///
/// The value is the canonical *padded* standard base64 of the 32-byte MAC, so
/// it always renders as 44 characters ending `=` (spec 06 R2.2).
pub fn v1_sign(secret: &WebhookSecret, content: &SignatureContent<'_>) -> String {
    format!("v1,{}", encode_b64_std(&v1_mac(secret, content)))
}

/// Renders the `v1a,<value>` header entry of spec 06 R2.5.
///
/// Ed25519 signs the raw content — no hash and no endpoint id — and the
/// 64-byte signature is rendered as canonical padded standard base64
/// (spec 06 R2.5).
pub fn v1a_sign(key: &SigningKey, content: &SignatureContent<'_>) -> String {
    let signature = key.sign(&content.to_bytes());
    format!("v1a,{}", encode_b64_std(&signature.to_bytes()))
}

/// Renders the `v2a,<value>` header entry of spec 06 R2.6.
///
/// Ed25519 signs the SHA-256 digest of `v2a_digest`, i.e.
/// `endpoint_id "." webhook-id "." timestamp "." body`, and the 64-byte
/// signature is rendered as canonical padded standard base64 (spec 06 R2.6).
pub fn v2a_sign(key: &SigningKey, endpoint_id: &str, content: &SignatureContent<'_>) -> String {
    let signature = key.sign(&v2a_digest(endpoint_id, content));
    format!("v2a,{}", encode_b64_std(&signature.to_bytes()))
}

/// The signature schemes of spec 06 section 2 (R2.2, R2.5, R2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Symmetric `v1`, HMAC-SHA-256 under the delivery secret (spec 06 R2.2).
    V1,
    /// Deprecated upstream `v1a`, Ed25519 over the raw content (spec 06 R2.5).
    V1a,
    /// `v2a`, Ed25519 over the SHA-256 digest with the endpoint id
    /// (spec 06 R2.6).
    V2a,
}

impl Scheme {
    /// Returns the header spelling of the scheme, exactly `v1`, `v1a` or
    /// `v2a` and case-sensitive (spec 06 R2.4, R2.2, R2.5, R2.6).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V1a => "v1a",
            Self::V2a => "v2a",
        }
    }

    /// Maps a parsed scheme name to its scheme; anything else is not a scheme
    /// the receiver supports (spec 06 R3.11).
    fn of(name: &str) -> Option<Self> {
        match name {
            "v1" => Some(Self::V1),
            "v1a" => Some(Self::V1a),
            "v2a" => Some(Self::V2a),
            _ => None,
        }
    }
}

/// One `<scheme>,<value>` pair of a `webhook-signature` header (spec 06 R2.4).
///
/// The value stays encoded: grammar parsing never decodes, so an unknown
/// scheme is preserved for the scheme check instead of being dropped
/// (spec 06 R2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    /// The scheme name, matched against `[A-Za-z0-9]+` and case-sensitive
    /// (spec 06 R2.4).
    pub scheme: String,
    /// The encoded signature value, with no comma and no whitespace
    /// (spec 06 R2.4).
    pub value: String,
}

/// Splits a `webhook-signature` header into its entries (spec 06 R2.4,
/// step 9 of the section 3 order table).
///
/// Accepts one or more `<scheme>,<value>` entries separated by exactly one
/// SP, with no leading or trailing space, no empty entry, a scheme matching
/// `[A-Za-z0-9]+`, and a value free of commas and whitespace. Anything else
/// is `400 malformed_signature_header`, with no header byte in the error.
pub fn parse_signature_header(value: &str) -> Result<Vec<SignatureEntry>, WebhookError> {
    if value.is_empty() {
        return Err(malformed_header());
    }
    if value.starts_with(SP) || value.ends_with(SP) {
        return Err(malformed_header());
    }
    let mut entries = Vec::new();
    for part in value.split(SP) {
        if part.is_empty() || part.chars().any(char::is_whitespace) {
            return Err(malformed_header());
        }
        let comma = match part.find(',') {
            Some(comma) if comma > 0 && comma < part.len() - 1 => comma,
            _ => return Err(malformed_header()),
        };
        let scheme = &part[..comma];
        let entry = &part[comma + 1..];
        if !scheme.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(malformed_header());
        }
        if entry.contains(',') || entry.chars().any(char::is_whitespace) {
            return Err(malformed_header());
        }
        entries.push(SignatureEntry {
            scheme: scheme.to_owned(),
            value: entry.to_owned(),
        });
    }
    Ok(entries)
}

/// Requires every scheme to be `v1`, `v1a` or `v2a` (spec 06 R3.11, step 10
/// of the section 3 order table).
///
/// An unknown scheme is `400 unsupported_signature_scheme`; the check runs
/// before any value is decoded, so its code wins over `malformed_signature`.
pub fn check_schemes(entries: &[SignatureEntry]) -> Result<(), WebhookError> {
    if entries
        .iter()
        .all(|entry| Scheme::of(&entry.scheme).is_some())
    {
        Ok(())
    } else {
        Err(WebhookError::new(
            400,
            codes::UNSUPPORTED_SIGNATURE_SCHEME,
            UNSUPPORTED_SCHEME_MESSAGE,
        ))
    }
}

/// One signature value after the length-carrying decode of spec 06 R3.12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSignature {
    /// The scheme the value belongs to (spec 06 R2.4, R3.11).
    pub scheme: Scheme,
    /// The decoded signature bytes: 32 for `v1`, 64 for `v1a` and `v2a`
    /// (spec 06 R3.12).
    pub bytes: Vec<u8>,
}

/// Decodes every entry's value, enforcing the per-scheme length
/// (spec 06 R3.12, step 11 of the section 3 order table).
///
/// Each value must be the canonical *padded* standard base64 of exactly 32
/// bytes for `v1` or 64 bytes for `v1a` and `v2a`; a non-canonical encoding or
/// a wrong length is `400 malformed_signature`. An unknown scheme is
/// `400 unsupported_signature_scheme`, the same code `check_schemes` gives it
/// (spec 06 R3.11), so calling this without the scheme check stays correct.
pub fn decode_signatures(
    entries: &[SignatureEntry],
) -> Result<Vec<DecodedSignature>, WebhookError> {
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let scheme = match Scheme::of(&entry.scheme) {
            Some(scheme) => scheme,
            None => {
                return Err(WebhookError::new(
                    400,
                    codes::UNSUPPORTED_SIGNATURE_SCHEME,
                    UNSUPPORTED_SCHEME_MESSAGE,
                ))
            }
        };
        let bytes = match decode_b64_std_strict(&entry.value) {
            Some(bytes) => bytes,
            None => return Err(malformed_signature()),
        };
        let expected = match scheme {
            Scheme::V1 => V1_LEN,
            Scheme::V1a | Scheme::V2a => ASYM_LEN,
        };
        if bytes.len() != expected {
            return Err(malformed_signature());
        }
        decoded.push(DecodedSignature { scheme, bytes });
    }
    Ok(decoded)
}

/// Reports whether any `v1` entry carries the MAC of `secret` over `content`
/// (spec 06 R2.7).
///
/// Several `v1` entries may be present for one header, and the scheme is
/// accepted when any of them verifies, so this returns `true` as soon as one
/// decoded `v1` value equals `v1_mac` byte for byte. The comparison uses
/// `constant_time_eq` so a mismatching MAC is not revealed by timing
/// (spec 06 R2.7, R2.2).
pub fn v1_verify(
    decoded: &[DecodedSignature],
    secret: &WebhookSecret,
    content: &SignatureContent<'_>,
) -> bool {
    let mac = v1_mac(secret, content);
    decoded.iter().any(|entry| {
        entry.scheme == Scheme::V1 && constant_time_eq(entry.bytes.as_slice(), mac.as_slice())
    })
}

/// An accepted Server Card public key the receiver may verify `v1a` or `v2a`
/// entries with (spec 06 R2.7, section 7).
///
/// The key id is reported back on success and the verification primitive is
/// left to the implementation, so a caller that stores keys in another form
/// can still be tried key by key.
pub trait ServerKey {
    /// Returns the key id of this key, reported by `asymmetric_verify`
    /// (spec 06 R2.7).
    fn kid(&self) -> &str;

    /// Returns whether `signature` is a valid signature of `message` under
    /// this key (spec 06 R2.5, R2.6, R2.7).
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

/// Returns the kid of the first accepted key that verifies any `v1a` or `v2a`
/// entry (spec 06 R2.7).
///
/// The keys are tried in the given order and, for each key, every `v1a` and
/// `v2a` entry of the header, which is exactly the order of the reference
/// receiver. A `v1a` entry signs `content.to_bytes()` and a `v2a` entry signs
/// `v2a_digest(endpoint_id, content)` (spec 06 R2.5, R2.6). `None` means the
/// header has no asymmetric entry at all or none of them verifies; `v1`
/// entries are ignored either way.
pub fn asymmetric_verify<K: ServerKey>(
    decoded: &[DecodedSignature],
    endpoint_id: &str,
    content: &SignatureContent<'_>,
    keys: &[K],
) -> Option<String> {
    if !decoded
        .iter()
        .any(|entry| matches!(entry.scheme, Scheme::V1a | Scheme::V2a))
    {
        return None;
    }
    let v1a_message = content.to_bytes();
    let v2a_message = v2a_digest(endpoint_id, content);
    for key in keys {
        for entry in decoded {
            let message = match entry.scheme {
                Scheme::V1a => v1a_message.as_slice(),
                Scheme::V2a => v2a_message.as_slice(),
                Scheme::V1 => continue,
            };
            if key.verify(message, &entry.bytes) {
                return Some(key.kid().to_owned());
            }
        }
    }
    None
}

/// One candidate delivery secret of an outgoing header, flagged as the
/// current one or the previous one (spec 06 R2.8).
#[derive(Debug, Clone, Copy)]
pub struct EmissionSecret<'a> {
    /// The delivery secret to sign the content with (spec 06 R2.2, R2.8).
    pub secret: &'a WebhookSecret,
    /// `true` for the current secret, `false` for the previous secret still
    /// inside the rotation grace of section 8 (spec 06 R2.8).
    pub current: bool,
}

/// One candidate signing key of an outgoing header, flagged as the current
/// one or the previous one (spec 06 R2.8).
#[derive(Debug, Clone, Copy)]
pub struct EmissionKey<'a> {
    /// The key id paired with the signing key that signs `v1a` and `v2a`
    /// (spec 06 R2.6, R2.8).
    pub kid: &'a str,
    /// The Ed25519 signing key that signs `v1a` and `v2a` (spec 06 R2.5, R2.6).
    pub signing_key: &'a ed25519_dalek::SigningKey,
    /// `true` for the current signing key, `false` for the previous one still
    /// published by the rotation of section 8 (spec 06 R2.8).
    pub current: bool,
}

/// Builds the emission set of an outgoing header, current first
/// (spec 06 R2.8).
///
/// The order is the one the receiver expects: the current secret's `v1`, then
/// the previous secret's `v1`, then the current key's `v1a` and `v2a`, then
/// the previous key's `v1a` and `v2a`. The first secret (and key) flagged
/// current and the first flagged non-current are the ones emitted, and any
/// missing position is skipped, so an HMAC-only delivery yields just its
/// `v1` entries and no empty entry is ever produced (spec 06 R2.8).
pub fn emission_entries(
    secrets: &[EmissionSecret<'_>],
    keys: &[EmissionKey<'_>],
    endpoint_id: &str,
    content: &SignatureContent<'_>,
) -> Vec<String> {
    let mut entries = Vec::new();
    let current_secret = secrets.iter().find(|entry| entry.current);
    let previous_secret = secrets.iter().find(|entry| !entry.current);
    let current_key = keys.iter().find(|entry| entry.current);
    let previous_key = keys.iter().find(|entry| !entry.current);
    if let Some(secret) = current_secret {
        push_non_empty(&mut entries, v1_sign(secret.secret, content));
    }
    if let Some(secret) = previous_secret {
        push_non_empty(&mut entries, v1_sign(secret.secret, content));
    }
    if let Some(key) = current_key {
        push_non_empty(&mut entries, v1a_sign(key.signing_key, content));
        push_non_empty(
            &mut entries,
            v2a_sign(key.signing_key, endpoint_id, content),
        );
    }
    if let Some(key) = previous_key {
        push_non_empty(&mut entries, v1a_sign(key.signing_key, content));
        push_non_empty(
            &mut entries,
            v2a_sign(key.signing_key, endpoint_id, content),
        );
    }
    entries
}

/// Renders the emission set of an outgoing header as one space-delimited
/// value (spec 06 R2.8).
///
/// The entries are joined with the single SP the grammar of R2.4 requires,
/// with no leading or trailing space, and an empty emission set renders as
/// the empty string rather than a lone space (spec 06 R2.4, R2.8).
pub fn emission_header(
    secrets: &[EmissionSecret<'_>],
    keys: &[EmissionKey<'_>],
    endpoint_id: &str,
    content: &SignatureContent<'_>,
) -> String {
    emission_entries(secrets, keys, endpoint_id, content).join(&SP.to_string())
}

/// Appends `entry` unless it is empty (spec 06 R2.8).
fn push_non_empty(entries: &mut Vec<String>, entry: String) {
    if !entry.is_empty() {
        entries.push(entry);
    }
}

/// Builds the `malformed_signature_header` rejection with a fixed literal
/// message (spec 06 R2.4, section 3).
fn malformed_header() -> WebhookError {
    WebhookError::new(
        400,
        codes::MALFORMED_SIGNATURE_HEADER,
        MALFORMED_HEADER_MESSAGE,
    )
}

/// Builds the `malformed_signature` rejection with a fixed literal message
/// (spec 06 R3.12).
fn malformed_signature() -> WebhookError {
    WebhookError::new(400, codes::MALFORMED_SIGNATURE, MALFORMED_SIGNATURE_MESSAGE)
}
