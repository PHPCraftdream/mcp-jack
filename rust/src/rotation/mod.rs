//! Candidate rotation primitives; static credentials и runtime trust не меняются.

mod chain;
#[cfg(target_os = "linux")]
mod controller;
#[cfg(all(test, target_os = "linux"))]
mod controller_tests;
mod json_object;
mod page;
#[cfg(target_os = "linux")]
mod private_file;
mod record;
mod result;
mod sign;
#[cfg(target_os = "linux")]
mod store;
#[cfg(target_os = "linux")]
mod store_format;
#[cfg(all(test, target_os = "linux"))]
mod store_tests;
mod trust;
mod trust_json;
mod trust_json_wire;

#[cfg(target_os = "linux")]
pub use controller::{RotationController, RotationResponse};
#[cfg(target_os = "linux")]
pub use store::RotationTrustStore;
#[cfg(target_os = "linux")]
pub use store_format::RotationStoreOptions;

pub use chain::{assignment_valid, selected_ordinal, verify_chain, Checkpoint, MAX_RETAINED_KEYS};
pub use page::{validate_page_framing, PageFraming, ResultCursor};
pub use record::parse_record;
pub use result::{decode_result, DecodedResult, MAX_PAGE_RECORDS, MAX_RESULT_BODY_BYTES};
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

/// Owned публичные данные; входные wire/key buffers не сохраняются по ссылке.
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
