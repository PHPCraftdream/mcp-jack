//! The verification cache route of spec 06 section 5 (R5.2): a prior success
//! for one `(principal, canonical_url)` pair, held for the grant TTL.
//!
//! The cache is in-memory soft state: it is never keyed by subscription,
//! name or arguments, one principal's verification never waives another's,
//! and a restart simply redoes the verification (spec 06 R5.2).
//!
//! Every instant and lifetime here is in MILLISECONDS of Unix time
//! (spec 06 R5.2).

use std::collections::HashMap;

/// An in-memory verification cache keyed on `(principal, canonical_url)`
/// (spec 06 R5.2).
///
/// An entry lives as long as the subscription's TTL; a record with no TTL
/// never expires while the process lives, and a server that persists
/// no-expiry subscriptions must persist that status itself (spec 06 R5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationCache {
    /// The expiry of every recorded pair, in Unix MILLISECONDS, the unit of
    /// the `now_ms` argument of [`VerificationCache::record`]; `None` never
    /// expires (spec 06 R5.2).
    entries: HashMap<(String, String), Option<i64>>,
}

impl VerificationCache {
    /// Returns an empty cache (spec 06 R5.2).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when the pair was recorded and its grant has not
    /// expired at `now_ms`, in Unix MILLISECONDS (spec 06 R5.2).
    ///
    /// An entry expires when `now_ms >= expires_at`, so a zero or negative
    /// TTL leaves it already expired. A cached verification does not expire
    /// because of delivery failures; only its TTL expires it
    /// (spec 06 R5.2, R5.12).
    pub fn is_verified(&self, principal: &str, canonical_url: &str, now_ms: i64) -> bool {
        let Some(expiry) = self
            .entries
            .get(&(principal.to_string(), canonical_url.to_string()))
        else {
            return false;
        };
        match expiry {
            Some(expires_at) => now_ms < *expires_at,
            None => true,
        }
    }

    /// Records a successful verification of the pair for the grant TTL
    /// (spec 06 R5.2).
    ///
    /// `now_ms` is Unix milliseconds and `ttl_ms` is the grant TTL in the same
    /// unit; `None` records a verification that never expires (spec 06 R5.2).
    pub fn record(
        &mut self,
        principal: &str,
        canonical_url: &str,
        now_ms: i64,
        ttl_ms: Option<i64>,
    ) {
        let expires_at = ttl_ms.map(|ttl| now_ms.saturating_add(ttl));
        self.entries.insert(
            (principal.to_string(), canonical_url.to_string()),
            expires_at,
        );
    }

    /// Returns the number of recorded pairs, expired ones included
    /// (spec 06 R5.2).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no pair was ever recorded (spec 06 R5.2).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
