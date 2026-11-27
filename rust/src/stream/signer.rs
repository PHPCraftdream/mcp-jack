//! Raw signing of an `s1` stream (spec 05 section 3.1): the capability the
//! open header and every frame are signed with.
//!
//! Frames carry no `kid` (2.15), so the key is the one that opened the stream.
//! The known successor activation `A_next` of 5.1 is carried by
//! [`StaticStreamSigner`] so a caller can read it, but it is the caller that
//! enforces it: a signature is produced before anyone can inspect it, and
//! refusing inside [`StaticStreamSigner::sign`] would hide the cutoff from the
//! code that chooses the timestamp.

use std::sync::Arc;

use crate::user_key::ServerSigningKey;

/// Raw signing capability of the stream key (3.1). Frames carry no kid; the key is the one
/// that opened the stream.
pub trait StreamSigner: Send + Sync {
    /// Signs the exact UTF-8 signing-string bytes; None when the key may no longer sign
    /// (rotation cutoff reached), never a fallback to another key.
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>>;
}

/// Static Ed25519 stream key plus the known successor activation of spec 05 section 5.1.
///
/// [`StreamSigner::sign`] signs unconditionally, cutoff or not: the caller
/// decides whether a timestamp may still be signed (the cutoff is reachable
/// through [`StaticStreamSigner::cutoff`]). An implementation for an external
/// key store may instead return `None` once the key is retired.
pub struct StaticStreamSigner {
    key: Arc<ServerSigningKey>,
    kid: String,
    cutoff: Option<i64>,
}

impl StaticStreamSigner {
    /// Wraps `key`; `kid` is derived from the public key (spec 01 section 2).
    /// `cutoff` is the successor activation `A_next` for this key (5.1), kept
    /// for the caller that enforces it.
    pub fn new(key: ServerSigningKey, cutoff: Option<i64>) -> Self {
        Self::from_shared(Arc::new(key), cutoff)
    }

    /// Wraps a shared key without copying signing material.
    pub fn from_shared(key: Arc<ServerSigningKey>, cutoff: Option<i64>) -> Self {
        let kid = key.kid().to_owned();
        StaticStreamSigner { key, kid, cutoff }
    }

    /// The key id written in the open header.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The 32-byte raw Ed25519 public key (public data).
    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// The successor activation of 5.1, when the rotation is already known.
    pub fn cutoff(&self) -> Option<i64> {
        self.cutoff
    }
}

impl StreamSigner for StaticStreamSigner {
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        Some(self.key.sign(message).to_vec())
    }
}
