//! Response-signing authorization profile (Go: server/response_keys.go). The
//! rotating profile selects the signer BEFORE the signature is computed and
//! re-confirms eligibility at a fresh final gate; the SDK never falls back to
//! another key.

use std::sync::Arc;

use crate::rotation::RotationError;

/// Response signer handle: fixed public identity plus bounded signing
/// capability; the provider pins the identity at construction (Go:
/// ResponseSigner). 64-byte Ed25519 signatures; length and verification are
/// enforced by the HTTP adapter (Go: responseSignature).
pub trait ResponseSigner: Send + Sync {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RotationError>;
}

/// What one authorized response hands to the signer selection (Go:
/// ResponseKeyRequest). A borrowed, read-only view of the exact bytes that
/// will be signed; the provider must not trust `tool` or `body` for the
/// identity choice (Go: the handler hands the provider an owned copy of the
/// payload for exactly this reason).
pub struct ResponseKeyRequest<'a> {
    /// HTTP status the response will carry.
    pub status: u16,
    /// Tool name of the call the response answers ("" when there is none).
    pub tool: &'a str,
    /// sig of the request; the response signature is bound to it.
    pub request_signature: &'a str,
    /// The exact response body bytes.
    pub body: &'a [u8],
}

/// The single-use final gate, run once AFTER the signature is computed (Go:
/// Final).
pub type FinalGate = Box<dyn FnOnce() -> Result<(), RotationError> + Send>;
/// The lease release; idempotent from the caller's view because the HTTP
/// adapter wraps it in `ReleaseGuard` (Go: Release).
pub type Release = Box<dyn FnOnce() + Send>;

/// Authorization for ONE response: the pinned signer, the authoritative
/// signing timestamp, the final gate to run after the signature is computed,
/// and the lease release (Go: ResponseKeyAuthorization). The HTTP adapter
/// MUST run `release` on every path (success and failure) — wrap it in
/// `ReleaseGuard`.
pub struct ResponseKeyAuthorization {
    /// Signer selected by the provider; its public key pins the response
    /// identity.
    pub signer: Arc<dyn ResponseSigner>,
    /// Fresh clock high-water mark the signer was selected at (Go:
    /// Timestamp).
    pub timestamp: u64,
    /// Re-confirms eligibility at a fresh clock AFTER the signature is
    /// computed (Go: Final).
    pub final_gate: FinalGate,
    /// Releases the serving lease; runs exactly once on every path (Go:
    /// Release).
    pub release: Release,
}

/// Runs the wrapped release exactly once, also on unwind (Go: `defer
/// releaseResponseAuthorization`).
pub struct ReleaseGuard(Option<Release>);

impl ReleaseGuard {
    /// Wraps a release so that dropping the guard runs it (Go: the deferred
    /// call in writeAuthorized).
    pub fn new(release: Release) -> Self {
        Self(Some(release))
    }
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// Selects the response signer and builds the authorization (Go:
/// ResponseKeyProvider). Implementations must never fall back to another key
/// and must not hold a state lock across signer callbacks (Go:
/// Provider.AuthorizeResponse).
pub trait ResponseKeys: Send + Sync {
    fn authorize_response(
        &self,
        input: &ResponseKeyRequest,
    ) -> Result<ResponseKeyAuthorization, RotationError>;
}
