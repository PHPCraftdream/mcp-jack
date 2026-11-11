use super::{
    ClockTuple, RotationError, RotationTrustStore, TrustSnapshot, MAX_ORDINAL,
    MAX_RETAINED_KEYS, MAX_TIMESTAMP,
};
use crate::auth_header::parse_response_auth;
use crate::client::rotation_auth::{
    verify_rotation_carrier, RotationCarrier, RotationResponseKey,
};
use crate::error::{codes, JackError};
use std::collections::BTreeMap;

/// Caller передаёт actual status, raw auth value и signature конкретного request.
/// Transport отвечает за TLS/destination/redirect/deadline/header/body bounds.
pub struct RotationResponse {
    pub status: i64,
    pub headers: Vec<String>,
    pub request_signature: String,
    pub body: Vec<u8>,
}

fn refuse(code: &str) -> JackError {
    JackError::new(0, code, "rotation response refused")
}

fn store_error(error: RotationError) -> JackError {
    refuse(error.code)
}

fn signed_time(value: u64) -> Result<i64, JackError> {
    i64::try_from(value).map_err(|_| refuse("rotation_clock_unavailable"))
}

fn known_keys(snapshot: &TrustSnapshot) -> Result<BTreeMap<String, RotationResponseKey>, JackError> {
    snapshot.keys.iter().map(|key| {
        Ok((key.kid.clone(), RotationResponseKey {
            public_key: key.public_key,
            not_before: signed_time(key.not_before)?,
            known_cutoff: key.known_cutoff.map(signed_time).transpose()?,
        }))
    }).collect()
}

/// Только bounded scalar/interval/capacity checks после authoritative sample.
fn time_valid(snapshot: &TrustSnapshot, carrier: &RotationCarrier, clock: &ClockTuple) -> Result<(), JackError> {
    let now = clock.high_water;
    if now > MAX_TIMESTAMP { return Err(refuse("rotation_clock_unavailable")); }
    let timestamp = u64::try_from(carrier.timestamp)
        .map_err(|_| refuse(codes::TIMESTAMP_OUT_OF_WINDOW))?;
    if timestamp > MAX_TIMESTAMP || now.abs_diff(timestamp) > snapshot.window {
        return Err(refuse(codes::TIMESTAMP_OUT_OF_WINDOW));
    }
    let key = snapshot.keys.iter().find(|key| key.kid == carrier.kid)
        .ok_or_else(|| refuse(codes::UNKNOWN_SERVER_KEY))?;
    if timestamp < key.not_before || key.known_cutoff.is_some_and(|cutoff| timestamp >= cutoff || now >= cutoff) {
        return Err(refuse("rotation_key_interval"));
    }
    if snapshot.revision == 0 || snapshot.revision > MAX_ORDINAL || snapshot.keys.len() > MAX_RETAINED_KEYS {
        return Err(refuse("rotation_state_changed"));
    }
    let mut pending = 0;
    let mut retired = 0;
    for key in &snapshot.keys {
        if key.not_before > now { pending += 1; }
        else if key.known_cutoff.is_some_and(|cutoff| cutoff <= now) { retired += 1; }
    }
    if pending > 128 || retired > 1024 { return Err(refuse("rotation_state_changed")); }
    Ok(())
}

/// Store остаётся caller-owned; mutable borrow сериализует safe operations.
/// Нет fetch, retry, implicit refresh или изменения static credentials.
pub struct RotationController<'a, C: FnMut() -> Result<u64, RotationError>> {
    store: &'a mut RotationTrustStore<C>,
}

impl<'a, C: FnMut() -> Result<u64, RotationError>> RotationController<'a, C> {
    pub fn new(store: &'a mut RotationTrustStore<C>) -> Result<Self, JackError> {
        let (snapshot, _) = store.snapshot().map_err(store_error)?;
        store.check_snapshot_clock(&snapshot).map_err(store_error)?;
        Ok(Self { store })
    }

    /// Owned exact opaque body выдаётся только после final gate; это не refresh ACK.
    pub fn verify_response(&mut self, response: RotationResponse) -> Result<Vec<u8>, JackError> {
        let (snapshot, _) = self.store.snapshot().map_err(store_error)?;
        let headers = match response.headers.as_slice() {
            [single] => [single.as_str()],
            [] => return Err(refuse(codes::MISSING_AUTH)),
            _ => return Err(refuse(codes::MALFORMED_AUTH)),
        };
        let auth = parse_response_auth(&headers).map_err(|error| refuse(&error.code))?;
        let known = known_keys(&snapshot)?;
        if !known.contains_key(&auth.kid) { return Err(refuse(codes::UNKNOWN_SERVER_KEY)); }
        if response.body.len() > 1024 * 1024 { return Err(refuse("rotation_result_invalid")); }
        let raw = self.store.raw_clock().map_err(store_error)?;
        let carrier = verify_rotation_carrier(
            &known, response.status, &headers, &response.request_signature,
            &response.body, signed_time(raw)?, signed_time(snapshot.window)?,
        ).map_err(|error| refuse(&error.code))?;
        let clock = self.store.check_snapshot_clock(&snapshot).map_err(store_error)?;
        time_valid(&snapshot, &carrier, &clock)?;
        let final_clock = self.store.check_snapshot_clock(&snapshot).map_err(store_error)?;
        time_valid(&snapshot, &carrier, &final_clock)?;
        Ok(response.body)
    }
}
