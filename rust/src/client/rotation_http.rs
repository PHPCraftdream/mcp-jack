//! Candidate rotation HTTP client: one explicit signed `jack.server.key`
//! page POST per call (Go: client/rotation/http.go; TS: rotation-http.ts +
//! rotation-http-wire.ts). Same URL policy, TLS policy and no-follow rules as
//! the shared HttpTransport; no proxy, retry, pagination or hidden refresh.

use crate::client::auth::{random_nonce, sign_request};
use crate::client::http_transport::HttpTransport;
use crate::client::signer::Signer;
use crate::client::transport::{HttpRequest, Transport, TransportError};
use crate::client::url::{request_target, validate_base_url};
use crate::error::JackError;
use crate::rotation::{
    Checkpoint, OwnedBinding, ResultCursor, RotationController, RotationError,
    RotationRefreshResult, RotationResponse, RotationTrustStore, TrustSnapshot, MAX_ORDINAL,
    MAX_RESULT_BODY_BYTES, MAX_RETAINED_KEYS,
};
use std::sync::Arc;
use std::time::Duration;

/// Request-side sanity bound (Go: exchange refuses len(body) > 1<<20).
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Конструктор принимает только deadline 1..=30 секунд (Go: NewHTTP).
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

fn refuse(code: &'static str) -> RotationError {
    RotationError { code }
}

/// RotationError -> sanitized JackError, как controller store_error.
fn gate(error: RotationError) -> JackError {
    JackError::new(0, error.code, "rotation response refused")
}

fn signed_time(value: u64) -> Result<i64, RotationError> {
    i64::try_from(value).map_err(|_| refuse("rotation_clock_unavailable"))
}

/// Pre-send bounded state check (Go: capacityValid); controller повторяет её
/// после ответа на fresh guard.
fn capacity_valid(snapshot: &TrustSnapshot, now: u64) -> bool {
    if snapshot.revision == 0
        || snapshot.revision > MAX_ORDINAL
        || snapshot.keys.len() > MAX_RETAINED_KEYS
    {
        return false;
    }
    let mut pending = 0;
    let mut retired = 0;
    for key in &snapshot.keys {
        if key.not_before > now {
            pending += 1;
        } else if key.known_cutoff.is_some_and(|cutoff| cutoff <= now) {
            retired += 1;
        }
    }
    pending <= 128 && retired <= 1024
}

/// Fixed JSON-RPC envelope; id = 1, expected response id "1" (Go/TS parity).
fn refresh_body(after_ordinal: u64, after_hash: &str) -> Vec<u8> {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "jack.server.key",
            "arguments": {
                "after_ordinal": after_ordinal,
                "after_hash": after_hash,
            },
        },
    })
    .to_string()
    .into_bytes()
}

/// Caller-pinned profile (те же независимые значения, что у RotationStoreOptions),
/// signer и bounded deadline. Store остаётся caller-owned: каждый вызов берёт
/// `&mut store` и не держит borrow между вызовами.
pub struct RotationHttpClient {
    binding: OwnedBinding,
    window: u64,
    checkpoint: Checkpoint,
    /// Origin-form target, байт-в-байт как настроено (path?query, без fragment).
    target: String,
    signer: Arc<dyn Signer>,
    transport: HttpTransport,
}

impl RotationHttpClient {
    /// Pins profile and builds the shared-policy HttpTransport; no store access.
    pub fn new(
        binding: OwnedBinding,
        window: u64,
        checkpoint: Checkpoint,
        signer: Arc<dyn Signer>,
        timeout: Duration,
    ) -> Result<Self, RotationError> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(refuse("rotation_state_unknown"));
        }
        if !(1..=120).contains(&window) {
            return Err(refuse("rotation_state_unknown"));
        }
        if validate_base_url(&binding.endpoint).is_err() {
            return Err(refuse("rotation_state_unknown"));
        }
        let target = match request_target(&binding.endpoint) {
            Ok(target) => target,
            Err(_) => return Err(refuse("rotation_state_unknown")),
        };
        let transport = match HttpTransport::builder().timeout(timeout).build() {
            Ok(transport) => transport,
            Err(_) => return Err(refuse("rotation_state_unknown")),
        };
        Ok(Self {
            binding,
            window,
            checkpoint,
            target,
            signer,
            transport,
        })
    }

    /// Transport failures never look like a trust outcome (Go:
    /// ErrRequestUnavailable); a stream cannot be fully read, hence cannot be
    /// verified.
    fn wire_error(error: TransportError) -> JackError {
        match error {
            TransportError::Streaming => {
                JackError::new(0, "rotation_result_invalid", "rotation response refused")
            }
            _ => JackError::new(
                0,
                "rotation_request_unavailable",
                "rotation response refused",
            ),
        }
    }

    fn exchange<C: FnMut() -> Result<u64, RotationError>>(
        &self,
        store: &mut RotationTrustStore<C>,
        snapshot: &TrustSnapshot,
        body: &[u8],
        limit: usize,
    ) -> Result<RotationResponse, JackError> {
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(gate(refuse("rotation_result_invalid")));
        }
        // Fresh durable guard sample; Go signs with its HighWater.
        let clock = store.check_snapshot_clock(snapshot).map_err(gate)?;
        if !capacity_valid(snapshot, clock.high_water) {
            return Err(gate(refuse("rotation_state_changed")));
        }
        let ts = signed_time(clock.high_water).map_err(gate)?;
        let nonce = random_nonce()
            .map_err(|_| refuse("rotation_state_unknown"))
            .map_err(gate)?;
        let signed = sign_request(
            self.signer.as_ref(),
            &self.binding.aud,
            "POST",
            &self.target,
            body,
            &nonce,
            ts,
        )
        .map_err(|_| gate(refuse("rotation_state_unknown")))?;
        // TS dispatch re-check (rotation-http.ts send()): signer callback must
        // not send a request after store lifetime loss.
        let dispatch = store.check_snapshot_clock(snapshot).map_err(gate)?;
        if !capacity_valid(snapshot, dispatch.high_water) {
            return Err(gate(refuse("rotation_state_changed")));
        }
        let dispatch_now = signed_time(dispatch.high_water).map_err(gate)?;
        if dispatch_now.abs_diff(ts) > snapshot.window {
            return Err(gate(refuse("timestamp_out_of_window")));
        }
        let request = HttpRequest {
            method: "POST".to_owned(),
            url: self.binding.endpoint.clone(),
            headers: vec![
                ("Connection".to_owned(), "close".to_owned()),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                (
                    "Accept".to_owned(),
                    "application/json, text/event-stream".to_owned(),
                ),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Jack-Auth".to_owned(), signed.header_value.clone()),
                ("MCP-Protocol-Version".to_owned(), "2025-11-25".to_owned()),
            ],
            body: body.to_vec(),
        };
        let response = self
            .transport
            .round_trip(request)
            .map_err(Self::wire_error)?;
        // Strict status/header handling (rotation-http-wire.ts exchange()).
        // HttpTransport never follows redirects; the whole 3xx range is
        // refused (Go: ErrRedirectRefused).
        if (300..400).contains(&response.status) {
            return Err(gate(refuse("rotation_redirect_refused")));
        }
        if response.header("Content-Encoding").is_some() {
            return Err(gate(refuse("rotation_result_invalid")));
        }
        // HttpTransport already buffers/caps at 1 MiB internally; the per-call
        // limit is checked here.
        if response.body.len() > limit {
            return Err(gate(refuse("rotation_result_invalid")));
        }
        Ok(RotationResponse {
            status: i64::from(response.status),
            headers: response
                .header_values("Jack-Auth")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            request_signature: signed.auth.sig,
            body: response.body,
        })
    }

    fn refresh_wire<C: FnMut() -> Result<u64, RotationError>>(
        &self,
        store: &mut RotationTrustStore<C>,
    ) -> Result<(RotationResponse, ResultCursor), JackError> {
        let (snapshot, _) = store.snapshot().map_err(gate)?;
        // Pinned-profile drift check (Go: state()). Checkpoint has no
        // PartialEq, so the five fields are compared manually.
        if snapshot.binding != self.binding
            || snapshot.window != self.window
            || snapshot.checkpoint.ordinal != self.checkpoint.ordinal
            || snapshot.checkpoint.hash != self.checkpoint.hash
            || snapshot.checkpoint.kid != self.checkpoint.kid
            || snapshot.checkpoint.public_key != self.checkpoint.public_key
            || snapshot.checkpoint.published_at != self.checkpoint.published_at
        {
            return Err(gate(refuse("rotation_state_unknown")));
        }
        let body = refresh_body(snapshot.head.ordinal, &snapshot.head.hash);
        let response = self.exchange(store, &snapshot, &body, MAX_RESULT_BODY_BYTES)?;
        Ok((response, snapshot.head))
    }

    /// Ровно один signed `jack.server.key` POST для текущего ACKed cursor и
    /// controller accept_refresh. Без retry/pagination/reset; ответ никогда
    /// не расширяет trust сам. Ошибка не откатывает уже подтверждённый ACK.
    pub fn refresh<C: FnMut() -> Result<u64, RotationError>>(
        &self,
        store: &mut RotationTrustStore<C>,
    ) -> Result<RotationRefreshResult, JackError> {
        let (response, cursor) = self.refresh_wire(store)?;
        let mut controller = RotationController::new(store)?;
        controller.accept_refresh(response, b"1", &cursor)
    }

    /// Только wire-половина: один POST и сырой RotationResponse (status,
    /// значения Jack-Auth, request signature, body) плюс запрошенный cursor —
    /// для caller-owned controller обработки.
    pub fn refresh_response<C: FnMut() -> Result<u64, RotationError>>(
        &self,
        store: &mut RotationTrustStore<C>,
    ) -> Result<(RotationResponse, ResultCursor), JackError> {
        self.refresh_wire(store)
    }
}
