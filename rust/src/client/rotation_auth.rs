use crate::auth_header::parse_response_auth;
use crate::ed25519::validate_public_key;
use crate::encoding::key_id;
use crate::error::{codes, JackError};
use crate::rotation::MAX_TIMESTAMP;
use crate::signing::verify_response;
use std::collections::BTreeMap;

/// Только independently trusted/ACKed snapshot, не response payload.
#[derive(Debug, Clone)]
pub struct RotationResponseKey {
    pub public_key: [u8; 32],
    pub not_before: i64,
    pub known_cutoff: Option<i64>,
}

/// Crypto/interval metadata, не ClockGuard readiness или trust ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationCarrier {
    pub kid: String,
    pub timestamp: i64,
}

/// Unknown kid → freshness → signature → interval; exact body не парсится.
/// Transport ограничивает/удерживает bytes. Caller затем выполняет durable
/// ClockGuard до decode и final interval/bridge/revision/full-state CAS.
/// Нет key discovery, credential mutation, retry или fetch.
pub fn verify_rotation_carrier(known: &BTreeMap<String, RotationResponseKey>, status: i64, headers: &[&str], request_sig: &str, body: &[u8], now: i64, window_seconds: i64) -> Result<RotationCarrier, JackError> {
    let refuse = |code| JackError::new(0, code, "rotation response verification refused");
    if !(1..=120).contains(&window_seconds) {
        return Err(refuse("rotation_state_unknown"));
    }
    let auth = parse_response_auth(headers).map_err(|mut error| { error.http_status = 0; error })?;
    let key = known.get(&auth.kid).ok_or_else(|| refuse(codes::UNKNOWN_SERVER_KEY))?;
    if validate_public_key(&key.public_key).is_err() || key_id(&key.public_key) != auth.kid || key.not_before < 0 || key.not_before.unsigned_abs() > MAX_TIMESTAMP {
        return Err(refuse("rotation_state_unknown"));
    }
    if key.known_cutoff.is_some_and(|cutoff| cutoff < key.not_before || cutoff.unsigned_abs() > MAX_TIMESTAMP) {
        return Err(refuse("rotation_state_unknown"));
    }
    verify_response(&key.public_key, status, headers, request_sig, body, now, window_seconds)?;
    if auth.ts < key.not_before || key.known_cutoff.is_some_and(|cutoff| auth.ts >= cutoff || now >= cutoff) {
        return Err(refuse("rotation_key_interval"));
    }
    Ok(RotationCarrier { kid: auth.kid, timestamp: auth.ts })
}
