//! The concurrency state of one [`super::Receiver`]: one mutex over routing,
//! termination, secrets, accepted ids and the in-flight set, plus the
//! condition variable a concurrent delivery of the same `webhook-id` waits on
//! (spec 06 R1.10, R3.16, R3.17).
//!
//! # Locking order (spec 06 R1.10, R3.16)
//!
//! There is exactly one lock in a receiver: the mutex of [`Dispatch`]. A
//! caller takes it to read the routing, termination, secret and dedup state,
//! takes it again to reserve a `webhook-id` for delivery, and takes it a last
//! time to record the enqueue outcome. A reservation is released, with the
//! condition variable signalled, on every path that does not record the id, so
//! a waiting delivery never observes a reservation that cannot finish.
//!
//! The durable `enqueue` callback, the key source snapshot and the challenge
//! echo of a verification envelope all run with no lock held, and no other
//! lock is ever taken while this mutex is held. A poisoned mutex is recovered
//! with [`PoisonError::into_inner`], never by panicking: a delivery that
//! panicked must not break every later delivery.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use crate::webhook::encoding::WebhookSecret;

/// One configured delivery secret with the state the receiver keeps for it
/// (spec 06 R3.7, R5.6).
pub(crate) struct SecretEntry {
    /// The decoded `whsec_` secret, never rendered (spec 06 R2.1).
    pub(crate) secret: WebhookSecret,
    /// The subscription id, `None` while the entry is pending (spec 06 R5.6).
    pub(crate) subscription_id: Option<String>,
    /// The callback url the pending entry expects its challenge under
    /// (spec 06 R5.6).
    pub(crate) callback_url: Option<String>,
}

/// The mutable state one mutex guards (spec 06 R3.7-R3.17, R5.6).
#[derive(Default)]
pub(crate) struct ReceiverState {
    /// The registered and pending secrets in configuration order
    /// (spec 06 R3.7, R5.6).
    pub(crate) entries: Vec<SecretEntry>,
    /// The subscription ids the receiver routes (spec 06 R3.8).
    pub(crate) routed: BTreeSet<String>,
    /// The subscription ids marked terminated (spec 06 R3.17).
    pub(crate) terminated: BTreeSet<String>,
    /// The accepted `webhook-id` values and the clock time each was recorded
    /// with (spec 06 R3.16).
    pub(crate) accepted: BTreeMap<String, i64>,
    /// The `webhook-id` values a delivery currently owns, so a concurrent
    /// delivery of the same id waits instead of enqueueing twice
    /// (spec 06 R1.10, R3.16).
    pub(crate) in_flight: BTreeSet<String>,
}

/// The outcome of reserving one `webhook-id` before its enqueue
/// (spec 06 R1.10, R3.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reservation {
    /// The id was already recorded within the retention window, so the
    /// delivery is answered `duplicate` and never enqueues (spec 06 R3.16).
    Duplicate,
    /// This delivery owns the id: it must either record it after a successful
    /// enqueue or release it after a failure (spec 06 R1.10).
    Owner,
}

/// The one mutex and condition variable of a receiver (spec 06 R1.10).
pub(crate) struct Dispatch {
    /// The routing, termination, secret, dedup and in-flight state
    /// (spec 06 R3.7-R3.17).
    state: Mutex<ReceiverState>,
    /// Signalled whenever an in-flight id is settled, so a waiting delivery
    /// of that id re-checks and either answers `duplicate` or becomes the new
    /// owner (spec 06 R1.10, R3.16).
    settled: Condvar,
}

impl Dispatch {
    /// Builds the dispatch state of a receiver from its initial state
    /// (spec 06 R3.7, R3.8).
    pub(crate) fn new(state: ReceiverState) -> Self {
        Self {
            state: Mutex::new(state),
            settled: Condvar::new(),
        }
    }

    /// Takes the one lock, recovering a poisoned mutex instead of panicking
    /// (spec 06 section 3: a delivery never breaks the receiver).
    pub(crate) fn lock(&self) -> MutexGuard<'_, ReceiverState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `read` against the state under the lock and releases it again
    /// (spec 06 R3.7-R3.17).
    ///
    /// `read` is pure: it must not call the enqueue callback, the key source
    /// or any other code that could take a lock, because the state mutex is
    /// held for its whole duration.
    pub(crate) fn with_state<T>(&self, read: impl FnOnce(&ReceiverState) -> T) -> T {
        let guard = self.lock();
        read(&guard)
    }

    /// Waits for a settled in-flight id, releasing the lock while waiting
    /// (spec 06 R1.10).
    fn wait<'a>(&self, guard: MutexGuard<'a, ReceiverState>) -> MutexGuard<'a, ReceiverState> {
        self.settled
            .wait(guard)
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserves `id` for one delivery and returns the guard and the outcome
    /// (spec 06 R1.10, R3.16).
    ///
    /// A recorded id within `retention` seconds is [`Reservation::Duplicate`]
    /// and is answered without enqueueing. An id another delivery owns is
    /// waited for, and the loop then re-checks: the first attempt's success
    /// makes this one a duplicate, and its failure makes this delivery the new
    /// owner, so the retry is processed exactly once (spec 06 R1.10).
    pub(crate) fn reserve(
        &self,
        id: &str,
        now: i64,
        retention: i64,
    ) -> (MutexGuard<'_, ReceiverState>, Reservation) {
        let mut guard = self.lock();
        loop {
            if let Some(&seen_at) = guard.accepted.get(id) {
                if now.saturating_sub(seen_at) <= retention {
                    return (guard, Reservation::Duplicate);
                }
            }
            if !guard.in_flight.contains(id) {
                guard.in_flight.insert(id.to_owned());
                return (guard, Reservation::Owner);
            }
            guard = self.wait(guard);
        }
    }

    /// Releases one reservation without recording the id
    /// (spec 06 R1.10, R3.16).
    ///
    /// Every path that answers without a `2xx` calls this, so the next
    /// delivery of the id is processed from the start and a concurrent waiter
    /// becomes the new owner.
    pub(crate) fn abandon(&self, guard: &mut ReceiverState, id: &str) {
        guard.in_flight.remove(id);
        self.settled.notify_all();
    }

    /// Records one id as answered with a `2xx` and releases its reservation
    /// (spec 06 R1.10, R3.16).
    pub(crate) fn record(&self, guard: &mut ReceiverState, id: &str, now: i64) {
        guard.in_flight.remove(id);
        guard.accepted.insert(id.to_owned(), now);
        self.settled.notify_all();
    }
}
