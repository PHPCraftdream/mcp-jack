//! Per-identity concurrent stream admission (spec 05 section 3.3).
//!
//! One counter per authenticated identity's stable `name`; a slot is released
//! by dropping [`StreamSlot`], so every path (end frame, handler return,
//! client disconnect, error) frees it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::stream::DEFAULT_MAX_CONCURRENT_STREAMS;

/// 3.3 per-identity concurrent stream admission. Cheap to clone? No: construct
/// once in an [`Arc`].
#[derive(Debug, Default)]
pub struct StreamRegistry {
    active: Mutex<HashMap<String, usize>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        StreamRegistry::default()
    }

    /// 3.3: reserves one slot for the authenticated identity (its stable
    /// `name`), per identity. A `limit` of 0 means
    /// `DEFAULT_MAX_CONCURRENT_STREAMS`. `None` at the limit; nothing is
    /// reserved then.
    pub fn try_acquire(self: &Arc<Self>, identity: &str, limit: usize) -> Option<StreamSlot> {
        let limit = if limit == 0 {
            DEFAULT_MAX_CONCURRENT_STREAMS
        } else {
            limit
        };
        let mut active = self.lock();
        let count = active.get(identity).copied().unwrap_or(0);
        if count >= limit {
            return None;
        }
        active.insert(identity.to_string(), count + 1);
        drop(active);
        Some(StreamSlot {
            registry: Arc::clone(self),
            identity: identity.to_string(),
        })
    }

    /// Number of slots currently held by `identity`.
    pub fn active(&self, identity: &str) -> usize {
        self.lock().get(identity).copied().unwrap_or(0)
    }

    /// Number of slots currently held by every identity.
    pub fn total(&self) -> usize {
        self.lock().values().sum()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, usize>> {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One reserved slot; dropping it releases the slot on every path (3.3).
pub struct StreamSlot {
    registry: Arc<StreamRegistry>,
    identity: String,
}

impl StreamSlot {
    /// The identity this slot was reserved for.
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut active = self.registry.lock();
        let remove = match active.get_mut(&self.identity) {
            Some(count) => {
                *count -= 1;
                *count == 0
            }
            None => false,
        };
        // 3.3: no zero entry survives its last slot.
        if remove {
            active.remove(&self.identity);
        }
    }
}
