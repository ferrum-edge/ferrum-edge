//! Compact ownership-generation → value maps for `proxy_alerts` lifecycle rows.
//!
//! Per-proxy lifecycle state is almost always a single live generation. A
//! pool-sharded `DashMap` for that dimension would cost many KB per essentially
//! one-entry row. This module stores generations in a small
//! poison-recovering `Mutex<HashMap<…>>` instead.
//!
//! Reads never take that mutex. Every mutation republishes an immutable
//! snapshot through an [`ArcSwap`] before the writer's guard drops, so the
//! per-sample hot path (an established window lookup, a recovery-state read,
//! an existing cooldown atomic) is one `ArcSwap::load()` plus a tiny `HashMap`
//! probe. Writers — first insert of a generation, lifecycle transitions,
//! retention/eviction sweeps — are rare and serialize on the mutex.
//!
//! Outer `rule` / `proxy` (and cooldown `channel`) dimensions remain pool-sharded
//! `DashMap`s. Callers that store `Arc` values look up through the snapshot,
//! then perform lock-free atomic work on the shared value.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;

/// Concurrent map from admission ownership generation → value.
pub(crate) struct GenerationMap<V> {
    /// Authoritative map. Writers serialize here.
    inner: Mutex<HashMap<u64, V>>,
    /// Immutable read snapshot of `inner`, republished by every mutation while
    /// the writer still holds `inner`, so snapshots are published in mutation
    /// order and a reader that runs after a writer released the guard always
    /// observes that write.
    published: ArcSwap<HashMap<u64, V>>,
}

impl<V: Clone> GenerationMap<V> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            published: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, V>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Republish the read snapshot. Must be called while holding `inner`.
    fn publish(&self, map: &HashMap<u64, V>) {
        self.published.store(Arc::new(map.clone()));
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.published.load().is_empty()
    }

    pub(crate) fn contains_key(&self, generation: &u64) -> bool {
        self.published.load().contains_key(generation)
    }

    pub(crate) fn get_cloned(&self, generation: &u64) -> Option<V> {
        self.published.load().get(generation).cloned()
    }

    pub(crate) fn get_copied(&self, generation: &u64) -> Option<V>
    where
        V: Copy,
    {
        self.published.load().get(generation).copied()
    }

    /// Every `(generation, value)` pair in the current snapshot. Cold path only
    /// (background lifecycle re-evaluation); allocates.
    pub(crate) fn entries(&self) -> Vec<(u64, V)> {
        self.published
            .load()
            .iter()
            .map(|(generation, value)| (*generation, value.clone()))
            .collect()
    }

    /// Return a clone of the value for `generation`, inserting with `init` on miss.
    ///
    /// Established hits are served from the lock-free snapshot and allocate
    /// nothing beyond the `V: Clone` cost (typically an `Arc` bump). Only a
    /// miss takes the mutex, re-checks, inserts, and republishes.
    pub(crate) fn get_or_insert_with(&self, generation: u64, init: impl FnOnce() -> V) -> V {
        if let Some(existing) = self.published.load().get(&generation) {
            return existing.clone();
        }
        let mut guard = self.lock();
        if let Some(existing) = guard.get(&generation) {
            return existing.clone();
        }
        let value = init();
        guard.insert(generation, value.clone());
        self.publish(&guard);
        value
    }

    /// Mutate the value for `generation`, inserting with `init` on miss.
    pub(crate) fn with_mut<R>(
        &self,
        generation: u64,
        init: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> R,
    ) -> R {
        let mut guard = self.lock();
        let value = guard.entry(generation).or_insert_with(init);
        let result = f(value);
        self.publish(&guard);
        result
    }

    /// Keep only entries for which `f` returns `true`. The predicate observes
    /// values read-only, so the snapshot is republished only when an entry was
    /// actually removed.
    pub(crate) fn retain(&self, mut f: impl FnMut(&u64, &V) -> bool) {
        let mut guard = self.lock();
        let before = guard.len();
        guard.retain(|generation, value| f(generation, value));
        if guard.len() != before {
            self.publish(&guard);
        }
    }

    /// Run `f` while holding the writer mutex. Test-only: proves established
    /// reads are served from the snapshot and never wait on a writer.
    #[allow(dead_code)] // Reached only through external-test hooks.
    pub(crate) fn with_writer_lock_held<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.lock();
        f()
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for GenerationMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.published.load();
        f.debug_map().entries(snapshot.iter()).finish()
    }
}
