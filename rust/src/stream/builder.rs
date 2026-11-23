//! Server-side signing of an `s1` stream (spec 05 sections 2.1, 2.5, 2.6,
//! 2.15, 2.16 and the section 9 build fields): the open header, then the
//! frame chain rooted in the open signature.
//!
//! Every timestamp is supplied by the caller, so the bytes are deterministic
//! and match `spec/fixtures/modern/stream-build-vectors.json` exactly. The
//! frame kind is not an input: it follows the emptiness of `data` (2.9).

use super::grammar::{
    data_hash, format_open_auth, frame_signing_string, open_signing_string, serialize_frame,
    FrameKind, OpenAuth,
};
use super::signer::StreamSigner;
use crate::encoding::encode_b64url;

/// One signed frame and every input of its signature (spec 05 section 2.15, the section 9
/// build fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFrame {
    pub seq: u64,
    pub ts: i64,
    pub prev: String,
    pub data_hash: String,
    pub signing_string: String,
    pub sig: String,
}

/// The signed open header (2.1, 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOpen {
    pub signing_string: String,
    pub sig: String,
    pub jack_auth: String,
}

/// Builds the signed open header and then frames chained over it. Every timestamp is given by
/// the caller, so the bytes are deterministic; the frame kind follows the emptiness of `data`.
#[derive(Debug, Clone)]
pub struct StreamBuilder {
    sid: String,
    seq: u64,
    prev: String,
}

impl StreamBuilder {
    /// Signs `mcp-jack/stream1/open` and returns the builder plus the open values. None when
    /// the signer refused.
    pub fn open(
        status: u16,
        request_sig: &str,
        kid: &str,
        ts: i64,
        sid: &str,
        signer: &dyn StreamSigner,
    ) -> Option<(Self, SignedOpen)> {
        let signing_string = open_signing_string(status, request_sig, kid, ts, sid);
        let sig = encode_b64url(&signer.sign(signing_string.as_bytes())?);
        let jack_auth = format_open_auth(&OpenAuth {
            kid: kid.to_string(),
            ts,
            sid: sid.to_string(),
            sig: sig.clone(),
        });
        let builder = StreamBuilder {
            sid: sid.to_string(),
            seq: 0,
            prev: sig.clone(),
        };
        Some((
            builder,
            SignedOpen {
                signing_string,
                sig,
                jack_auth,
            },
        ))
    }

    /// Continues a stream whose open header was signed elsewhere (the HTTP adapter signs the open
    /// header); `open_sig` is the chain root and the next frame carries seq 0.
    pub fn resume(sid: &str, open_sig: &str) -> Self {
        Self {
            sid: sid.to_string(),
            seq: 0,
            prev: open_sig.to_string(),
        }
    }

    /// Signs one frame at `seq` over the chained `prev`; empty `data` writes the end frame
    /// (`FrameKind::End`). Returns the signed fields and the exact wire bytes (2.6).
    /// None when the signer refused.
    pub fn frame(
        &mut self,
        ts: i64,
        data: &str,
        signer: &dyn StreamSigner,
    ) -> Option<(SignedFrame, String)> {
        // 2.9: the kind is a function of the signed data.
        let kind = if data.is_empty() {
            FrameKind::End
        } else {
            FrameKind::Message
        };
        let data_hash = data_hash(data);
        let signing_string = frame_signing_string(&self.sid, self.seq, ts, &self.prev, &data_hash);
        // A refused signature must not advance the chain.
        let sig = encode_b64url(&signer.sign(signing_string.as_bytes())?);
        let wire = serialize_frame(kind, data, self.seq, ts, &sig);
        let frame = SignedFrame {
            seq: self.seq,
            ts,
            prev: self.prev.clone(),
            data_hash,
            signing_string,
            sig: sig.clone(),
        };
        self.seq += 1;
        self.prev = sig;
        Some((frame, wire))
    }

    /// Convenience for the end frame: `frame(ts, "")`.
    pub fn end(&mut self, ts: i64, signer: &dyn StreamSigner) -> Option<(SignedFrame, String)> {
        self.frame(ts, "", signer)
    }

    /// The seq the next frame will carry.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The signature the next frame chains over.
    pub fn prev(&self) -> &str {
        &self.prev
    }
}
