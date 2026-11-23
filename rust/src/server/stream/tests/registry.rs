//! Registry tests: the 3.3 per-identity limit, the counters and the slot
//! release on every path.

use std::sync::Arc;

use crate::server::stream::StreamRegistry;
use crate::stream::DEFAULT_MAX_CONCURRENT_STREAMS;

fn registry() -> Arc<StreamRegistry> {
    Arc::new(StreamRegistry::new())
}

#[test]
fn limit_is_per_identity() {
    let registry = registry();
    let alice = registry.try_acquire("alice", 1).expect("alice has a slot");
    let bob = registry.try_acquire("bob", 1).expect("bob has his own");
    assert_eq!(alice.identity(), "alice");
    assert_eq!(bob.identity(), "bob");
    assert_eq!(registry.active("alice"), 1);
    assert_eq!(registry.active("bob"), 1);
    assert_eq!(registry.total(), 2);
}

#[test]
fn none_at_the_limit_reserves_nothing() {
    let registry = registry();
    let _slot = registry.try_acquire("alice", 1).expect("first slot");
    assert!(registry.try_acquire("alice", 1).is_none());
    assert_eq!(registry.active("alice"), 1);
    assert_eq!(registry.total(), 1);
}

#[test]
fn zero_limit_means_the_default() {
    let registry = registry();
    let slots: Vec<_> = (0..DEFAULT_MAX_CONCURRENT_STREAMS)
        .map(|_| registry.try_acquire("alice", 0).expect("a default slot"))
        .collect();
    assert_eq!(registry.active("alice"), DEFAULT_MAX_CONCURRENT_STREAMS);
    assert!(registry.try_acquire("alice", 0).is_none());
    drop(slots);
    assert_eq!(registry.total(), 0);
}

#[test]
fn dropping_a_slot_releases_it_and_leaves_no_zero_entry() {
    let registry = registry();
    let slot = registry.try_acquire("alice", 1).expect("a slot");
    drop(slot);
    assert_eq!(registry.active("alice"), 0);
    assert_eq!(registry.total(), 0);
    // A stale zero entry would reject this re-acquire at limit 1.
    let again = registry.try_acquire("alice", 1).expect("released");
    assert_eq!(registry.active("alice"), 1);
    drop(again);
    assert_eq!(registry.total(), 0);
}

#[test]
fn arc_clones_share_the_same_registry() {
    let registry = registry();
    let clone = Arc::clone(&registry);
    let slot = clone.try_acquire("alice", 2).expect("a slot");
    assert_eq!(registry.active("alice"), 1);
    assert_eq!(registry.total(), 1);
    drop(slot);
    assert_eq!(registry.active("alice"), 0);
    assert_eq!(clone.total(), 0);
}

#[test]
fn independent_arc_clones_enforce_one_limit() {
    let registry = registry();
    let clone = Arc::clone(&registry);
    let _slot = registry.try_acquire("alice", 1).expect("the only slot");
    assert!(clone.try_acquire("alice", 1).is_none());
    assert_eq!(clone.total(), 1);
}
