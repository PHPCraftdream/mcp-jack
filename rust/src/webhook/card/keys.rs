//! Server Card signing key snapshots of spec 06 section 7 (R7.1-R7.4): the
//! accepted keys and the raw published JWKs one key source reports at a
//! moment, plus the fixed in-memory source.
//!
//! Everything here is pure: `now` is an argument and no source performs I/O.
//! The published JWKs stay raw, so the R7.6 cross-check validates them itself
//! instead of trusting the accepted set (spec 06 R7.3, R7.6).

use serde_json::{json, Value};

use crate::webhook::card::jwk::{KeyRejection, WebhookKeyRecord};

/// The keys one source reports at one moment (spec 06 R7.1-R7.4).
///
/// `accepted` and `rejected` are the R7.3 outcome, and `published` holds the
/// raw JWKs the card or tool published, including members the validator
/// rejects, so a later R7.6 cross-check can apply the R7.3 validator to them
/// itself (spec 06 R7.3, R7.6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySnapshot {
    /// The accepted records, in source order, with a unique `kid` each
    /// (spec 06 R7.3).
    pub accepted: Vec<WebhookKeyRecord>,
    /// Every rejection, with its fixed-literal reason (spec 06 R7.3).
    pub rejected: Vec<KeyRejection>,
    /// The raw published JWKs valid at the snapshot time
    /// (spec 06 R7.1, R7.3).
    pub published: Vec<Value>,
}

impl KeySnapshot {
    /// Returns a snapshot with no accepted key, no rejection and no published
    /// JWK (spec 06 R7.1, R7.3).
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Reports the keys of one origin at a moment (spec 06 R7.1-R7.4).
///
/// A source that fetches the card performs the fetch outside this trait's
/// contract; the trait itself only reports what is valid at `now`, which is
/// how rotation (R7.4) reaches the caller without re-delivery.
pub trait KeySource: Send + Sync {
    /// Returns the accepted keys and the raw published JWKs valid at `now`
    /// (R7.1-R7.4).
    ///
    /// A source whose fetched key set is no longer trusted at `now` — the
    /// R7.2 cache lifetime of a [`crate::webhook::card::source::CardSource`]
    /// passed without a successful refresh — reports no accepted key, so the
    /// receiver answers the fixed `no_server_keys` refusal (spec 06 R7.3).
    fn snapshot(&self, now: i64) -> KeySnapshot;
}

/// A key source over a fixed accepted key set (spec 06 R7.1, R7.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StaticKeys {
    /// The accepted records handed to [`StaticKeys::new`]
    /// (spec 06 R7.3).
    keys: Vec<WebhookKeyRecord>,
}

impl StaticKeys {
    /// Builds a source that reports `keys` forever (spec 06 R7.1, R7.3).
    pub fn new(keys: Vec<WebhookKeyRecord>) -> Self {
        Self { keys }
    }
}

impl KeySource for StaticKeys {
    /// Returns the fixed records as accepted keys, no rejection, and each
    /// record rendered as the JWK it came from (spec 06 R7.1-R7.3).
    fn snapshot(&self, _now: i64) -> KeySnapshot {
        KeySnapshot {
            accepted: self.keys.clone(),
            rejected: Vec::new(),
            published: self.keys.iter().map(record_jwk).collect(),
        }
    }
}

/// Renders one accepted record as the `{kty, crv, x, kid}` JWK the R7.3
/// validator reads (spec 06 R7.3, R7.6).
///
/// Both sides of the R7.6 comparison pass through this renderer, so the
/// records compare as canonical JSON whichever source produced the key
/// (spec 06 R7.3).
pub(crate) fn record_jwk(record: &WebhookKeyRecord) -> Value {
    json!({
        "kty": record.kty,
        "crv": record.crv,
        "x": record.x,
        "kid": record.kid,
    })
}
