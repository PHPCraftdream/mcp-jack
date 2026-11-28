//! Candidate native tool `jack.server.key`: one published page of the server
//! key ring (Go: server/rotation/native.go `Provider.Call`; TS:
//! server/server-key-tool.ts). Read-only candidate route: NOT part of the
//! closed set of 11 current-v1 native tools (`is_native_tool` stays false;
//! through `VerifierBuilder::server_keys`), and it NEVER
//! forwards a request. Refusal classes, in check order: 403 operation_denied
//! (wrong route or no caller), 400 invalid_params (undecodable arguments), 503
//! rotation_state_unavailable (serving lease, snapshot, audience, fresh
//! ClockGuard, signer selection or page assembly), 409
//! rotation_checkpoint_unavailable (cursor outside the committed ring or not
//! anchored by its hash). Storage and signer details never leak: every such
//! failure collapses into the same refusal message.

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::json;

use crate::encoding::{body_hash, encode_b64url};
use crate::error::{codes, JackError};
use crate::rotation::{
    decode_server_key_arguments, server_key_page, ResultCursor, RotationError,
    RotationServerProvider, RotationServerStore, ServerSnapshot,
};
use crate::server::response_keys::ResponseSigner;
use crate::server::verify::{NativeCall, NativeResult, NativeTools, TOOL_SERVER_KEY};

/// Message of every refusal this tool produces (Go: nativeError).
const REFUSAL_MESSAGE: &str = "server key request unavailable";

/// Builds the single refusal shape of the tool (TS: refusal(status, code)).
fn refusal(http_status: u16, code: &str) -> JackError {
    JackError::new(http_status, code, REFUSAL_MESSAGE)
}

/// The state exists but cannot serve this request right now.
fn state_unavailable() -> JackError {
    refusal(503, "rotation_state_unavailable")
}

/// The cursor is outside the committed ring or not anchored by its hash.
fn checkpoint_unavailable() -> JackError {
    refusal(409, "rotation_checkpoint_unavailable")
}

/// Serves only the explicit candidate route `jack.server.key` and never
/// forwards (TS: ServerKeyTool). One committed snapshot, one fresh server
/// ClockGuard and one selected signer; page fields are never mixed across
/// snapshots. The store handle is shared with the provider, so both sides see
/// the same committed ring.
pub struct ServerKeyTool<C: FnMut() -> Result<u64, RotationError> + Send + 'static> {
    store: Arc<Mutex<RotationServerStore<C>>>,
    provider: Arc<RotationServerProvider<C>>,
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> ServerKeyTool<C> {
    /// Keeps the two handles; no state is created and the ring is not read
    /// (readiness stays the provider's `ready` check).
    pub fn new(
        store: Arc<Mutex<RotationServerStore<C>>>,
        provider: Arc<RotationServerProvider<C>>,
    ) -> Self {
        Self { store, provider }
    }
}

impl<C: FnMut() -> Result<u64, RotationError> + Send + 'static> NativeTools for ServerKeyTool<C> {
    fn call(&self, c: &mut NativeCall) -> Result<NativeResult, JackError> {
        if c.tool != TOOL_SERVER_KEY || c.caller.is_none() {
            return Err(refusal(403, codes::OPERATION_DENIED));
        }
        // An absent `params.arguments` is invalid_params like any undecodable
        // payload (TS decodes `undefined` the same way).
        let Some(arguments) = c.arguments.as_ref() else {
            return Err(refusal(400, codes::INVALID_PARAMS));
        };
        let cursor = decode_server_key_arguments(arguments.get().as_bytes())
            .map_err(|_| refusal(400, codes::INVALID_PARAMS))?;
        // Poisoned lock fails closed instead of panicking (crate-wide policy).
        let mut store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        // Lease lives until the end of the call (Go: defer release()); drop releases the dirty epoch.
        let _lease = store
            .acquire_serving_lease()
            .map_err(|_| state_unavailable())?;
        let (snapshot, _) = store.snapshot().map_err(|_| state_unavailable())?;
        if c.aud != snapshot.public.binding.aud {
            return Err(state_unavailable());
        }
        // All proof/hash operations are finished before the authoritative sample (Go: same comment).
        validate_cursor(&snapshot, &cursor)?;
        let clock = store
            .check_snapshot_clock(&snapshot)
            .map_err(|_| state_unavailable())?;
        let signer = self
            .provider
            .select_signer(&snapshot, &clock)
            .map_err(|_| state_unavailable())?;
        // Re-validates the cursor internally; after `validate_cursor` its
        // checkpoint branch is unreachable, so any error here is a fault state.
        let page = server_key_page(&snapshot, &cursor, &signer.public_key())
            .map_err(|_| state_unavailable())?;
        let structured = json!({
            "current": {
                "kid": page.current_kid,
                "public_key": encode_b64url(&page.current_public_key),
            },
            "records": page.records,
            "head": {
                "ordinal": page.head_ordinal,
                "hash": page.head_hash,
            },
            "complete": page.complete,
        });
        Ok(NativeResult { structured })
    }
}

/// Checks the cursor against the retained ring (Go `Call` lines 49-64; TS:
/// `validateRotationServerKeyCursor`): the ordinal must sit between the
/// checkpoint and the head, the offset must fit the retained records, and the
/// hash must anchor the previous record or the checkpoint itself. Returns the
/// 409 refusal directly: `RotationError` has no public constructor, and the
/// caller maps every OTHER store failure to the 503 refusal.
fn validate_cursor(snapshot: &ServerSnapshot, cursor: &ResultCursor) -> Result<(), JackError> {
    let trust = &snapshot.public;
    if cursor.ordinal < trust.checkpoint.ordinal || cursor.ordinal > trust.head.ordinal {
        return Err(checkpoint_unavailable());
    }
    // The subtraction is guarded by the previous branch: ordinal >= checkpoint.ordinal.
    let offset = cursor.ordinal - trust.checkpoint.ordinal;
    // Comparison in u64: usize -> u64 widens losslessly; the reverse cast would truncate.
    if offset > trust.records.len() as u64 {
        return Err(checkpoint_unavailable());
    }
    let expected = match offset.checked_sub(1) {
        // offset == 0: the cursor anchors to the checkpoint itself.
        None => trust.checkpoint.hash.clone(),
        Some(index) => match usize::try_from(index)
            .ok()
            .and_then(|index| trust.records.get(index))
        {
            // Unreachable under the effective offset limit; refusal instead of panic.
            Some(wire) => body_hash(wire.as_bytes()),
            None => return Err(checkpoint_unavailable()),
        },
    };
    if cursor.hash != expected {
        return Err(checkpoint_unavailable());
    }
    Ok(())
}
