//! (kid, nonce) replay cache (Go: server/nonce.go).
//!
//! The store remembers `(kid, nonce)` pairs for a caller-supplied retention
//! window so a repeated pair is detected atomically under one mutex hold.
//! The store NEVER reads a clock: all times are caller-injected Unix seconds,
//! which keeps tests deterministic (spec 01 section 4).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// Replay protection: remembers `(kid, nonce)` pairs until their retention
/// expires so a repeated live pair is detected as a replay.
pub struct NonceStore {
    data: Mutex<NonceData>,
}

struct NonceData {
    /// `(kid, nonce) -> retain_until`. Keyed by the tuple rather than Go's
    /// NUL-joined string: same partitioning, no separator ambiguity at all.
    seen: HashMap<(String, String), i64>,
    /// `now` of the last full purge; bounds the scan to once per second.
    last_purge: i64,
}

impl NonceStore {
    /// Returns an empty nonce store.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(NonceData {
                seen: HashMap::new(),
                last_purge: 0,
            }),
        }
    }

    /// Atomically checks whether `(kid, nonce)` was already seen and records
    /// it if not. Callers derive `retain_until` as `ts + window`: an entry is
    /// live while `now <= retain_until`. Returns true on replay.
    ///
    /// Returns `true` when the pair was already recorded and still live — a
    /// REPLAY, which the caller must reject with `replayed_nonce` — and
    /// `false` when the pair was just recorded.
    ///
    /// A replay does NOT extend retention (the branch returns before the
    /// insert), and the lazy purge is gated on `now > last_purge` because a
    /// full scan per request would be quadratic while expired entries are
    /// never consulted (the liveness test below is explicit).
    pub fn check_and_record(&self, kid: &str, nonce: &str, now: i64, retain_until: i64) -> bool {
        let mut data = Self::lock(&self.data);

        if now > data.last_purge {
            data.seen.retain(|_, until| *until >= now);
            data.last_purge = now;
        }

        if let Some(&until) = data.seen.get(&(kid.to_owned(), nonce.to_owned())) {
            if now <= until {
                return true;
            }
        }
        data.seen
            .insert((kid.to_owned(), nonce.to_owned()), retain_until);
        false
    }

    /// Deletes every entry whose retention has expired (`retain_until < now`,
    /// strictly less: `until == now` is still live) and returns the count.
    pub fn purge(&self, now: i64) -> usize {
        let mut data = Self::lock(&self.data);
        let before = data.seen.len();
        data.seen.retain(|_, until| *until >= now);
        before - data.seen.len()
    }

    /// How many entries are currently held, including expired ones not yet
    /// purged.
    pub fn len(&self) -> usize {
        Self::lock(&self.data).seen.len()
    }

    /// True when no entries are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A panic while holding this lock can only come from a HashMap operation
    /// (allocation failure); entries are plain `(kid, nonce) -> i64` values
    /// with no cross-invariant, so recovering cannot expose broken state —
    /// and replay protection must not die because a thread panicked.
    fn lock(data: &Mutex<NonceData>) -> MutexGuard<'_, NonceData> {
        data.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn same_nonce_wins_exactly_once() {
        let store = NonceStore::new();
        let wins = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..64 {
                s.spawn(|| {
                    if !store.check_and_record("kidA", "nonceX", 100, 130) {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn distinct_nonces_each_win_once() {
        let store = NonceStore::new();
        let wins = AtomicUsize::new(0);
        std::thread::scope(|s| {
            let store = &store;
            let wins = &wins;
            for i in 0..64 {
                s.spawn(move || {
                    if !store.check_and_record("kidA", &format!("nonce-{i}"), 100, 130) {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 64);
    }

    #[test]
    fn retention_boundary() {
        let store = NonceStore::new();
        assert!(!store.check_and_record("kidA", "n1", 100, 130));
        // Live while now <= retain_until; the boundary is inclusive.
        assert!(store.check_and_record("kidA", "n1", 130, 500));
    }

    #[test]
    fn past_retention() {
        let store = NonceStore::new();
        store.check_and_record("kidA", "n1", 100, 130);
        // 131 > 130: the entry is expired and no longer blocks.
        assert!(!store.check_and_record("kidA", "n1", 131, 500));
    }

    #[test]
    fn replay_does_not_extend_retention() {
        let store = NonceStore::new();
        assert!(!store.check_and_record("kidA", "n1", 100, 130));
        // Rejected replay offering a far-future retention must not update it.
        assert!(store.check_and_record("kidA", "n1", 110, 1000));
        // Retention is still 130, so at now=131 the pair is usable again.
        assert!(!store.check_and_record("kidA", "n1", 131, 999));
    }

    #[test]
    fn per_kid_scoping() {
        let store = NonceStore::new();
        assert!(!store.check_and_record("kidA", "shared-nonce", 100, 130));
        assert!(!store.check_and_record("kidB", "shared-nonce", 100, 130));
        assert!(store.check_and_record("kidA", "shared-nonce", 110, 130));
        assert!(store.check_and_record("kidB", "shared-nonce", 110, 130));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn purge_removes_expired() {
        let store = NonceStore::new();
        for i in 0..500 {
            store.check_and_record(&format!("kid-{i}"), &format!("nonce-{i}"), 100, 100);
        }
        assert_eq!(store.len(), 500);
        // 100 < 101: every entry is expired.
        assert_eq!(store.purge(101), 500);
        assert_eq!(store.len(), 0);
        assert!(!store.check_and_record("kidA", "nonceX", 200, 300));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn lazy_purge_on_record() {
        let store = NonceStore::new();
        for i in 0..10 {
            store.check_and_record(&format!("kid-{i}"), &format!("nonce-{i}"), 10, 50);
        }
        // Gate 60 > last_purge 0 fires the scan, removing all ten at 50 < 60,
        // before recording the new pair.
        assert!(!store.check_and_record("kidNew", "nonceNew", 60, 120));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn polarity_true_means_replay() {
        // Pinned explicitly because the verifier maps this boolean to
        // accept/reject: true == live pair already recorded (replay),
        // false == pair was just recorded (fresh, request may proceed).
        let store = NonceStore::new();
        assert!(!store.check_and_record("kidA", "n1", 100, 130)); // fresh: recorded
        assert!(store.check_and_record("kidA", "n1", 110, 130)); // live pair: replay
        assert!(!store.check_and_record("kidA", "n2", 110, 130)); // other nonce: fresh
    }
}
