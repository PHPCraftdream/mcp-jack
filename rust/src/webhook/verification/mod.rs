//! Endpoint verification of spec 06 section 5 (R5.1-R5.12): the fixed route
//! order, its cache, the operator allowlist, the well-known receiver
//! document and the challenge handshake (R5.2-R5.10), plus the delivery gate
//! of R5.1.
//!
//! Everything here is pure: `now` is an argument, the only entropy is the
//! slice a caller supplies (or `getrandom` for [`random_nonce`]), and every
//! verdict carries only fixed-literal codes and reasons, never an endpoint
//! body, header or status line (spec 06 R5.4). The modules mirror
//! `spec/tools/modern/webhooks/ref/verification.mjs` exactly.

pub mod allowlist;
pub mod cache;
pub mod document;
pub mod nonce;
pub mod route;

pub use allowlist::{allowlist_matches, parse_allowlist_entry, AllowlistEntry};
pub use cache::VerificationCache;
pub use document::{
    check_document_fetch, covers_path, document_cache_ttl, document_covers, document_request,
    parse_receiver_doc, well_known_url, DocumentRequestInput, ReceiverDocument,
};
pub use nonce::{
    accept_echo, challenge_echo, new_nonce, nonce_ok, pair_key, random_nonce, EchoAttempt,
    EchoVerdict, NONCE_TTL_SECONDS,
};
pub use route::{
    gate, verification_route, GateAction, RouteInput, RouteVerdict, VerificationRoute,
};
