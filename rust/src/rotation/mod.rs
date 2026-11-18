//! Candidate rotation primitives; static credentials and runtime trust are not changed.

#[cfg(target_os = "linux")]
mod server_side;
mod snapshot;
#[cfg(target_os = "linux")]
mod trust_client;
#[cfg(target_os = "linux")]
mod trust_store;
mod wire;

#[cfg(target_os = "linux")]
use server_side::{server_provider, server_store, server_store_format};
#[cfg(target_os = "linux")]
use snapshot::trust_json_wire;
use snapshot::{server_key, server_state, server_state_json, trust, trust_json};
#[cfg(target_os = "linux")]
use trust_client::controller;
#[cfg(all(test, target_os = "linux"))]
use trust_client::refresh_tests;
#[cfg(all(test, target_os = "linux"))]
use trust_store::store_tests;
#[cfg(target_os = "linux")]
use trust_store::{private_file, store, store_format};
use wire::{chain, json_object, page, record, result, sign};

#[cfg(target_os = "linux")]
pub use controller::{RotationController, RotationRefreshResult, RotationResponse};
#[cfg(target_os = "linux")]
pub use server_provider::{
    PinnedRotationSigner, RotationPublication, RotationServerKey, RotationServerProvider,
};
#[cfg(target_os = "linux")]
pub use server_store::{RotationServerStore, ServingLease};
#[cfg(target_os = "linux")]
pub use server_store_format::RotationServerStoreOptions;
#[cfg(target_os = "linux")]
pub use store::RotationTrustStore;
#[cfg(target_os = "linux")]
pub use store_format::RotationStoreOptions;

pub use chain::{assignment_valid, selected_ordinal, verify_chain, Checkpoint, MAX_RETAINED_KEYS};
pub use page::{validate_page_framing, PageFraming, ResultCursor};
pub use record::parse_record;
pub use result::{decode_result, DecodedResult, MAX_PAGE_RECORDS, MAX_RESULT_BODY_BYTES};
pub use server_key::{decode_server_key_arguments, server_key_page};
pub use server_state::{
    validate_server_publication, validate_server_snapshot, ServerSnapshot, SignerReference,
    MAX_SIGNER_REFERENCE_BYTES,
};
pub use server_state_json::{decode_server_snapshot, encode_server_snapshot};
pub use sign::create_record;
pub use trust::{
    trust_clock_compatible, validate_trust_snapshot, ClockTuple, OwnedBinding, TrustKey,
    TrustSnapshot,
};
pub use trust_json::{decode_trust_snapshot, encode_trust_snapshot, MAX_TRUST_SNAPSHOT_BYTES};

use std::fmt;

pub const DOMAIN: &str = "mcp-jack/server-key-rotation/min1";
pub const GRACE_SECONDS: u64 = 172_800;
pub const MAX_TIMESTAMP: u64 = 999_999_999_999;
pub const MAX_ORDINAL: u64 = 9_007_199_254_740_991;
pub const MAX_RECORD_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub endpoint: &'a str,
    pub aud: &'a str,
}

/// Owned public data; the input wire/key buffers are not retained by reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub ordinal: u64,
    pub previous_hash: String,
    pub old_kid: String,
    pub new_kid: String,
    pub public_key: [u8; 32],
    pub published_at: u64,
    pub activates_at: u64,
    pub wire: String,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationError {
    pub code: &'static str,
}

impl fmt::Display for RotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jack: candidate rotation {}", self.code)
    }
}

impl std::error::Error for RotationError {}

fn invalid(code: &'static str) -> RotationError {
    RotationError { code }
}
