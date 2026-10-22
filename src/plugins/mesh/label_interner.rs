//! Bounded mesh-label interning and a worker-local cache of admitted values.
//!
//! The front cache stores exact text, never request keys or identity decisions.
//! Only globally interned values may enter it: per-call overflow allocations
//! must remain uncached, preserving the process interner's cardinality bound.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

pub(super) const FRONT_CACHE_SLOTS: usize = 64;
pub(super) const FRONT_CACHE_MAX_LABEL_BYTES: usize = 256;

pub(super) enum LabelLookup {
    Interned(Arc<str>),
    Uncached(Arc<str>),
}

impl LabelLookup {
    #[inline]
    pub(super) fn into_arc(self) -> Arc<str> {
        match self {
            Self::Interned(value) | Self::Uncached(value) => value,
        }
    }
}

/// The existing reservation-before-insert cap, shared by every worker.
/// Entries never change or evict, so front-cache text needs no reload epoch.
pub(super) struct LabelInterner<const CAP: usize> {
    entries: DashMap<Box<str>, Arc<str>>,
    count: AtomicUsize,
}

impl<const CAP: usize> LabelInterner<CAP> {
    pub(super) fn new(shards: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shards),
            count: AtomicUsize::new(0),
        }
    }

    pub(super) fn intern(&self, value: &str) -> LabelLookup {
        if let Some(existing) = self.entries.get(value) {
            return LabelLookup::Interned(Arc::clone(existing.value()));
        }
        if self
            .count
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < CAP).then_some(count + 1)
            })
            .is_err()
        {
            return LabelLookup::Uncached(Arc::from(value));
        }

        match self.entries.entry(Box::from(value)) {
            Entry::Occupied(entry) => {
                self.count.fetch_sub(1, Ordering::Relaxed);
                LabelLookup::Interned(Arc::clone(entry.get()))
            }
            Entry::Vacant(entry) => {
                let interned = Arc::from(value);
                entry.insert(Arc::clone(&interned));
                LabelLookup::Interned(interned)
            }
        }
    }
}

/// Fixed-size, direct-mapped cache. A collision replaces one admitted Arc;
/// equality always checks the complete text before a cached value is used.
/// Long values bypass this cache without truncation or changed interning.
pub(super) struct LabelFrontCache {
    slots: [Option<Arc<str>>; FRONT_CACHE_SLOTS],
}

impl LabelFrontCache {
    pub(super) const fn new() -> Self {
        Self {
            slots: [const { None }; FRONT_CACHE_SLOTS],
        }
    }

    #[inline]
    pub(super) fn intern_with(
        &mut self,
        value: &str,
        resolve: impl FnOnce(&str) -> LabelLookup,
    ) -> Arc<str> {
        if value.len() > FRONT_CACHE_MAX_LABEL_BYTES {
            return resolve(value).into_arc();
        }
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        let slot = hasher.finish() as usize % FRONT_CACHE_SLOTS;
        if let Some(existing) = &self.slots[slot]
            && existing.as_ref() == value
        {
            return Arc::clone(existing);
        }
        match resolve(value) {
            LabelLookup::Interned(interned) => {
                self.slots[slot] = Some(Arc::clone(&interned));
                interned
            }
            LabelLookup::Uncached(uncached) => uncached,
        }
    }
}
