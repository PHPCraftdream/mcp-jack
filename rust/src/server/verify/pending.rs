//! The pending half of the two-phase verification (spec 01 section 4, spec 02
//! section 2): the [`Authentication`] outcome of [`super::Verifier::authenticate`]
//! and the single-use [`PendingRequest`] token that [`super::Verifier::dispatch`]
//! consumes.

use serde_json::value::RawValue;

use crate::server::state::RegistryEntry;

use super::VerifyResult;

/// Outcome of the authentication phase of [`super::Verifier::authenticate`].
// The size gap is deliberate: boxing either half would obscure the two shapes
// this split exists to separate, and one value is alive per request.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Authentication {
    /// The request was rejected by steps 1-8 or by the body classification of
    /// spec 02 section 2; no native tool ran and no audit event was written.
    Refused(VerifyResult),
    /// The request is authenticated and classified but nothing was dispatched
    /// yet: [`super::Verifier::dispatch`] executes it, dropping it executes
    /// nothing.
    Pending(PendingRequest),
}

/// An authenticated and classified request that has NOT been dispatched.
///
/// It carries the verified state [`super::Verifier::dispatch`] needs, and it is
/// the single-use token of one request:
/// - `dispatch` consumes it by value, so a request is dispatched at most once;
/// - dropping it without dispatch performs no native effect at all and no
///   audit event, and finishes the durable nonce lease it holds exactly like
///   dropping [`VerifyResult::admission`] does;
/// - it is bound to the verifier that issued it, so another verifier's
///   `dispatch` fails closed with the signed 500 `internal_error`.
///
/// It has no public constructor and is deliberately not `Clone`.
#[derive(Debug)]
pub struct PendingRequest {
    /// Issuer id of the verifier that authenticated the request.
    pub(super) issuer: u64,
    /// The verified state; None only once it was consumed.
    pub(super) state: Option<PendingState>,
}

/// The verified state of one [`PendingRequest`].
#[derive(Debug)]
pub(super) struct PendingState {
    /// Authenticated result: kid, nonce_recorded, request sig, rpc id, tool
    /// name and, on Linux, the committed durable admission lease.
    pub(super) res: VerifyResult,
    /// Authenticated key id (the Jack-Auth kid).
    pub(super) kid: String,
    /// ts parameter of the Jack-Auth header (rotate proofs bind it).
    pub(super) ts: i64,
    /// Authorization time of the native tool and its audit event.
    pub(super) now: i64,
    /// Server audience the request was verified against.
    pub(super) aud: String,
    /// Registry entry of the authenticated key; None for the enrollment
    /// exception, which is always a native call.
    pub(super) caller: Option<RegistryEntry>,
    /// What dispatch must do with the request.
    pub(super) action: PendingAction,
}

/// The one dispatch operation a [`PendingRequest`] may need.
#[derive(Debug)]
pub(super) enum PendingAction {
    /// Ordinary MCP traffic, a client answer, or a non-`POST` request: accept
    /// and forward with the verified identity.
    Forward,
    /// A protocol-native `jack.*` call: tool name and its raw arguments.
    Native {
        tool: String,
        arguments: Option<Box<RawValue>>,
    },
}

impl PendingRequest {
    /// The authenticated result of a pending request that is answered WITHOUT
    /// dispatching (e.g. a modern-profile refusal of spec 04 `S1`-`S12`): it
    /// carries the kid, request signature, nonce flag and rpc id that a signed
    /// answer needs, and it has had no dispatch effect. Consuming `self` is
    /// what guarantees the request cannot be dispatched afterwards.
    pub fn into_refusal_base(mut self) -> VerifyResult {
        match self.state.take() {
            Some(state) => state.res,
            // Unreachable: only dispatch and this method empty a pending
            // request, and both consume the value.
            None => VerifyResult::default(),
        }
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        // A pending request that is never dispatched finishes its durable
        // admission lease here, exactly as `drop(res.admission)` does in the
        // one-shot path: the committed reservation is never held past the
        // request, and no native tool runs.
        #[cfg(target_os = "linux")]
        if let Some(state) = self.state.as_mut() {
            state.res.admission.finish();
        }
    }
}
