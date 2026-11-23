//! The optional `jack.server.webhook_key` cross-check of spec 06 R7.6: the
//! card-derived key set and the tool result are both validated with the R7.3
//! validator before their `{kty, crv, x, kid}` records are compared as
//! canonical JSON sorted by `kid`.
//!
//! Everything here is pure: no I/O, no clock. A mismatch never names a key.

use serde_json::Value;

use crate::webhook::card::jwk::{validate_jwk, WebhookKeyRecord};
use crate::webhook::card::keys::record_jwk;
use crate::webhook::{codes, WebhookError};

/// The status the R7.6 cross-check answers with (spec 06 R7.6, section 3).
const CHECK_STATUS: u16 = 401;

/// The fixed-literal message of a required check without a tool result
/// (spec 06 R7.6).
const MISSING_MESSAGE: &str = "the required jack.server.webhook_key result is absent";

/// The fixed-literal message of a required check that disagrees
/// (spec 06 R7.6).
const MISMATCH_MESSAGE: &str = "the jack.server.webhook_key result disagrees with the card";

/// Validates every JWK of one side with the R7.3 validator; a single failure
/// fails the whole side (spec 06 R7.6).
fn validated_key_set<'a>(
    entries: impl Iterator<Item = &'a Value>,
) -> Option<Vec<WebhookKeyRecord>> {
    let mut keys = Vec::new();
    for entry in entries {
        keys.push(validate_jwk(entry).ok()?);
    }
    Some(keys)
}

/// Returns the canonical `{kty, crv, x, kid}` records sorted by `kid`
/// (spec 06 R7.6).
fn canonical_records(keys: &[WebhookKeyRecord]) -> Vec<(&str, &str, &str, &str)> {
    let mut records: Vec<(&str, &str, &str, &str)> = keys
        .iter()
        .map(|key| {
            (
                key.kty.as_str(),
                key.crv.as_str(),
                key.x.as_str(),
                key.kid.as_str(),
            )
        })
        .collect();
    records.sort_by(|left, right| left.3.cmp(right.3));
    records
}

/// Runs the required `jack.server.webhook_key` cross-check over raw JWKs
/// (spec 06 R7.6).
///
/// `require = false` always succeeds and ignores the tool result entirely.
/// A required check with no tool result — because the server predates the
/// tool — is `401 webhook_key_missing`. Otherwise BOTH sides are validated
/// with the R7.3 validator, so a key that fails it on either side, for
/// example an `alg` other than `EdDSA` or a `use` other than `sig`, is
/// `401 webhook_key_mismatch`; then the `{kty, crv, x, kid}` records are
/// compared as canonical JSON sorted by `kid` and any difference is
/// `401 webhook_key_mismatch` (spec 06 R7.6).
///
/// `published` holds the raw card JWKs, not the accepted records, so a card
/// member the R7.3 validator refuses still fails the required check rather
/// than silently disappearing from the comparison (spec 06 R7.3, R7.6).
pub fn cross_check_webhook_key_jwks(
    published: &[Value],
    tool_result: Option<&Value>,
    require: bool,
) -> Result<(), WebhookError> {
    if !require {
        return Ok(());
    }
    let Some(tool_keys) = tool_result
        .and_then(|value| value.get("webhook_key"))
        .and_then(|value| value.get("signing_keys"))
        .and_then(|value| value.get("keys"))
        .and_then(Value::as_array)
    else {
        return Err(WebhookError::new(
            CHECK_STATUS,
            codes::WEBHOOK_KEY_MISSING,
            MISSING_MESSAGE,
        ));
    };
    let Some(card) = validated_key_set(published.iter()) else {
        return Err(mismatch());
    };
    let Some(tool) = validated_key_set(tool_keys.iter()) else {
        return Err(mismatch());
    };
    if canonical_records(&card) != canonical_records(&tool) {
        return Err(mismatch());
    }
    Ok(())
}

/// Runs the required `jack.server.webhook_key` cross-check (spec 06 R7.6).
///
/// `require = false` always succeeds and ignores the tool result entirely.
/// A required check with no tool result — because the server predates the
/// tool — is `401 webhook_key_missing`. Otherwise the accepted records are
/// rendered as the JWKs they came from and both sides are validated with the
/// R7.3 validator, so a key that fails it on either side, for example an
/// `alg` other than `EdDSA` or a `use` other than `sig`, is
/// `401 webhook_key_mismatch`; then the `{kty, crv, x, kid}` records are
/// compared as canonical JSON sorted by `kid` and any difference is
/// `401 webhook_key_mismatch` (spec 06 R7.6).
pub fn cross_check_webhook_key(
    keys: &[WebhookKeyRecord],
    tool_result: Option<&Value>,
    require: bool,
) -> Result<(), WebhookError> {
    if !require {
        return Ok(());
    }
    let published: Vec<Value> = keys.iter().map(record_jwk).collect();
    cross_check_webhook_key_jwks(&published, tool_result, require)
}

/// Builds the `webhook_key_mismatch` rejection of R7.6 (spec 06 R7.6).
fn mismatch() -> WebhookError {
    WebhookError::new(CHECK_STATUS, codes::WEBHOOK_KEY_MISMATCH, MISMATCH_MESSAGE)
}
