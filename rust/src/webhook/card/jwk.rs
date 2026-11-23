//! Server Card signing keys of spec 06 section 7 (R7.1, R7.3): the JWK
//! validator of the R7.3 member table, the per-key acceptance rules with the
//! configured MCP server key moved out, the duplicate-`kid` rule and the
//! accepted key record a receiver verifies `v1a` and `v2a` entries with.
//!
//! Everything here is pure: no I/O, no clock, no logging. A rejection reason
//! is a fixed literal of the R7.3 order, so no card byte can reach an error.

use std::collections::HashMap;

use serde_json::Value;

use crate::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url, key_id};
use crate::webhook::signatures::ServerKey;

/// The extension key the Events webhooks object lives under (spec 06 R7.1).
pub const EVENTS_EXTENSION: &str = "io.modelcontextprotocol/events";

/// The decoded length of a card `x` member, i.e. of an Ed25519 public key
/// (spec 06 R7.3).
const PUBLIC_KEY_BYTES: usize = 32;

/// The one `kty` a card key may carry (spec 06 R7.3).
const KEY_TYPE: &str = "OKP";

/// The one `crv` a card key may carry (spec 06 R7.3).
const CURVE: &str = "Ed25519";

/// The one `alg` a card key may name, when the member is present
/// (spec 06 R7.3).
const ALGORITHM: &str = "EdDSA";

/// The one `use` a card key may name, when the member is present
/// (spec 06 R7.3).
const USE: &str = "sig";

/// The rejection reason of a key equal to the configured MCP server key
/// (spec 06 R7.3, R4.5).
const MCP_SERVER_KEY: &str = "mcp_server_key";

/// The rejection reason of every key of a duplicated `kid`
/// (spec 06 R7.3).
const DUPLICATE_KID: &str = "duplicate_kid";

/// One accepted card signing key (spec 06 R7.3).
///
/// `x` and `public_key` are both the canonical unpadded base64url of the same
/// 32 raw bytes, so the R7.6 comparison has the same members whichever source
/// produced the key (spec 06 R7.3). A record exists only after `validate_jwk`
/// accepted the JWK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookKeyRecord {
    /// The key id, equal to `base64url(SHA-256(x))` (spec 06 R7.3).
    pub kid: String,
    /// The key type, always `OKP` (spec 06 R7.3).
    pub kty: String,
    /// The curve, always `Ed25519` (spec 06 R7.3).
    pub crv: String,
    /// The canonical unpadded base64url of the 32 raw public-key bytes
    /// (spec 06 R7.3).
    pub x: String,
    /// The canonical unpadded base64url of the same 32 raw public-key bytes
    /// (spec 06 R7.3).
    pub public_key: String,
}

impl WebhookKeyRecord {
    /// Returns the decoded 32 raw public-key bytes of the record
    /// (spec 06 R7.3).
    ///
    /// A record built by `validate_jwk` always decodes; a hand-built record
    /// with a malformed `public_key` yields an empty vector instead of
    /// panicking, and such a key then simply verifies nothing.
    pub fn raw(&self) -> Vec<u8> {
        decode_b64url_fixed(&self.public_key, PUBLIC_KEY_BYTES).unwrap_or_default()
    }
}

impl ServerKey for WebhookKeyRecord {
    /// Returns the card `kid` of the key (spec 06 R7.3).
    fn kid(&self) -> &str {
        &self.kid
    }

    /// Verifies a `v1a` or `v2a` signature under the record's public key
    /// (spec 06 R7.3, R2.5, R2.6).
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        crate::ed25519::verify(&self.raw(), message, signature)
    }
}

/// One rejected card key: the `kid` the JWK carried, when it was a string,
/// and the fixed-literal reason (spec 06 R7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRejection {
    /// The `kid` member of the rejected JWK, or `None` when it was absent,
    /// empty or not a string (spec 06 R7.3).
    pub kid: Option<String>,
    /// One of the R7.3 reasons in their fixed order: `kty`, `crv`,
    /// `x_encoding`, `x_length`, `x_key`, `kid_missing`, `kid_mismatch`,
    /// `alg`, `use`, plus the set-level `mcp_server_key` and
    /// `duplicate_kid` (spec 06 R7.3).
    pub reason: String,
}

/// Builds the rejection of one JWK with a fixed-literal reason and the `kid`
/// the JWK carried, when it is a string (spec 06 R7.3).
fn rejection(jwk: &Value, reason: &'static str) -> KeyRejection {
    KeyRejection {
        kid: jwk.get("kid").and_then(Value::as_str).map(str::to_owned),
        reason: reason.to_owned(),
    }
}

/// Validates one card JWK (spec 06 R7.3).
///
/// The checks run in the spec order and the first failure wins: `kty` is
/// `OKP`; `crv` is `Ed25519`; `x` is canonical unpadded base64url
/// (`x_encoding`); it decodes to exactly 32 bytes (`x_length`); it is a
/// strict Ed25519 public key (`x_key`); `kid` is present and non-empty
/// (`kid_missing`); it equals `base64url(SHA-256(x))` (`kid_mismatch`);
/// `alg` is absent or `EdDSA`; `use` is absent or `sig`. Unknown members are
/// ignored (spec 06 R7.3).
pub fn validate_jwk(jwk: &Value) -> Result<WebhookKeyRecord, KeyRejection> {
    if !jwk.is_object() || jwk.get("kty").and_then(Value::as_str) != Some(KEY_TYPE) {
        return Err(rejection(jwk, "kty"));
    }
    if jwk.get("crv").and_then(Value::as_str) != Some(CURVE) {
        return Err(rejection(jwk, "crv"));
    }
    let Some(x) = jwk.get("x").and_then(Value::as_str) else {
        return Err(rejection(jwk, "x_encoding"));
    };
    let Ok(public_key) = decode_b64url(x) else {
        return Err(rejection(jwk, "x_encoding"));
    };
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(rejection(jwk, "x_length"));
    }
    if crate::ed25519::validate_public_key(&public_key).is_err() {
        return Err(rejection(jwk, "x_key"));
    }
    let kid = match jwk.get("kid").and_then(Value::as_str) {
        Some(kid) if !kid.is_empty() => kid,
        _ => return Err(rejection(jwk, "kid_missing")),
    };
    let expected = key_id(&public_key);
    if kid != expected.as_str() {
        return Err(rejection(jwk, "kid_mismatch"));
    }
    if jwk
        .get("alg")
        .is_some_and(|alg| alg.as_str() != Some(ALGORITHM))
    {
        return Err(rejection(jwk, "alg"));
    }
    if jwk
        .get("use")
        .is_some_and(|value| value.as_str() != Some(USE))
    {
        return Err(rejection(jwk, "use"));
    }
    let encoded = encode_b64url(&public_key);
    Ok(WebhookKeyRecord {
        kid: kid.to_owned(),
        kty: KEY_TYPE.to_owned(),
        crv: CURVE.to_owned(),
        x: encoded.clone(),
        public_key: encoded,
    })
}

/// Returns true when the accepted key equals the configured MCP server key,
/// by `kid` or by raw public key (spec 06 R7.3, R4.5).
fn is_server_key(
    key: &WebhookKeyRecord,
    mcp_server_kid: Option<&str>,
    mcp_server_public_key: Option<&str>,
) -> bool {
    mcp_server_kid.is_some_and(|kid| key.kid == kid)
        || mcp_server_public_key.is_some_and(|public_key| key.public_key == public_key)
}

/// The accepted card keys and the rejected ones, each with its reason
/// (spec 06 R7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedKeys {
    /// The accepted records, in card order, with a unique `kid` each
    /// (spec 06 R7.3).
    pub accepted: Vec<WebhookKeyRecord>,
    /// Every rejection in the order the checks produced it: the per-key
    /// R7.3 reasons, then `mcp_server_key`, then `duplicate_kid`
    /// (spec 06 R7.3).
    pub rejected: Vec<KeyRejection>,
}

/// Validates a card JWK set, moves the configured MCP server key out and
/// drops every key of a duplicated `kid` (spec 06 R7.3).
///
/// Each JWK is validated on its own and an invalid one is recorded and never
/// accepted. Then a key equal to the configured `mcp_server_kid` or to the
/// configured raw `mcp_server_public_key` is rejected as `mcp_server_key`, so
/// a card that publishes the server key yields no accepted key from that
/// member. Finally, on a repeated `kid` every key with that `kid` is rejected
/// as `duplicate_kid`. A missing or non-array `keys` member yields no keys
/// and no rejection (spec 06 R7.3).
pub fn accept_jwk_set(
    signing_keys: Option<&Value>,
    mcp_server_kid: Option<&str>,
    mcp_server_public_key: Option<&str>,
) -> AcceptedKeys {
    let entries = signing_keys
        .and_then(|value| value.get("keys"))
        .and_then(Value::as_array);
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    if let Some(entries) = entries {
        for jwk in entries {
            match validate_jwk(jwk) {
                Ok(key) => accepted.push(key),
                Err(reason) => rejected.push(reason),
            }
        }
    }
    let mut surviving = Vec::new();
    for key in accepted {
        if is_server_key(&key, mcp_server_kid, mcp_server_public_key) {
            rejected.push(KeyRejection {
                kid: Some(key.kid),
                reason: MCP_SERVER_KEY.to_owned(),
            });
        } else {
            surviving.push(key);
        }
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for key in &surviving {
        *counts.entry(key.kid.clone()).or_insert(0) += 1;
    }
    let mut kept = Vec::new();
    for key in surviving {
        if counts.get(&key.kid).copied().unwrap_or(0) > 1 {
            rejected.push(KeyRejection {
                kid: Some(key.kid),
                reason: DUPLICATE_KID.to_owned(),
            });
        } else {
            kept.push(key);
        }
    }
    AcceptedKeys {
        accepted: kept,
        rejected,
    }
}

/// Looks up one accepted card key by its exact `kid` (spec 06 R7.2, R7.3).
///
/// Only the accepted set is searched, so a rejected key never verifies
/// anything and a `kid` no accepted key carries is `unknown_webhook_key` at
/// the `w1` step (spec 06 R4.5, R7.3).
pub fn card_key_for_kid<'a>(
    keys: &'a [WebhookKeyRecord],
    kid: &str,
) -> Option<&'a WebhookKeyRecord> {
    if kid.is_empty() {
        return None;
    }
    keys.iter().find(|key| key.kid == kid)
}
