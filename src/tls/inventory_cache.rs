//! Cached, non-secret TLS inventory snapshot for the metrics scrape path.
//!
//! Issue #2410: authenticated `/metrics` used to rebuild the full TLS inventory
//! inline, including private keys and provider-backed sources. Scrapes now only
//! read the snapshot published here, without source I/O or waiting on a provider.
//!
//! - [`TlsInventoryCache::snapshot`] is a lock-free `ArcSwap` load.
//! - [`TlsInventoryCache::schedule_refresh_if_due`] moves collection to a bounded
//!   background `spawn_blocking` task: single-flight per cache and rate-limited
//!   by `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS`.
//! - [`mark_stale`] lets validated rotation/reload outcomes from
//!   [`crate::tls::events`] invalidate the production process cache immediately.
//! - The collector uses the metrics-safe scope
//!   ([`super::inventory::TlsInventory::collect_public_metadata`]), so private-key
//!   bytes are never materialized to produce certificate-expiry metrics.
//!
//! Production uses [`process_cache`], preserving process-wide single-flight and
//! TLS-event invalidation. An in-process fixture can instead own a cache, its
//! collector, and its invalidations (issue #5544). Background work retains that
//! exact cache; replacing or dropping another fixture cannot affect it.
//!
//! Freshness is explicit: `/metrics` exports the collection timestamp as
//! `ferrum_tls_inventory_snapshot_timestamp_seconds` alongside the configured
//! bound `ferrum_tls_inventory_snapshot_max_age_seconds`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use tracing::debug;

use super::inventory::TlsInventory;

/// Default maximum snapshot age before a scrape schedules a background refresh.
pub const DEFAULT_SNAPSHOT_TTL_SECONDS: u64 = 300;

/// Blocking producer of metrics-safe TLS inventory. Runs only on a background
/// refresh task, never on a request path.
pub trait TlsInventoryCollector: Send + Sync + 'static {
    fn collect_public_metadata(&self) -> TlsInventory;

    /// Stable identity for listeners that share one admin serving cycle.
    /// `None` conservatively replaces the collector on every registration.
    fn serving_cycle_key(&self) -> Option<usize> {
        None
    }
}

/// A published, non-secret inventory snapshot.
#[derive(Debug)]
pub struct TlsInventorySnapshot {
    pub inventory: Arc<TlsInventory>,
    /// Wall-clock collection time, exported as the freshness gauge.
    pub collected_at: DateTime<Utc>,
    /// Monotonic publication counter for diagnostics and cache owners.
    pub generation: u64,
    /// Monotonic collection instant: wall-clock jumps cannot pin or expire it.
    collected_at_instant: Instant,
    /// A snapshot from a replaced collector is never exposed to the new cycle.
    collector_generation: u64,
}

impl TlsInventorySnapshot {
    pub fn age(&self) -> Duration {
        self.collected_at_instant.elapsed()
    }
}

/// Ownable snapshot, collector registration, TTL, and single-flight state.
/// Share one `Arc` across listeners and config publishers belonging to an owner.
pub struct TlsInventoryCache {
    snapshot: ArcSwap<Option<Arc<TlsInventorySnapshot>>>,
    /// Publish collector and generation together so a racing replacement cannot
    /// pair the old collector with the new generation.
    collector: ArcSwap<Option<Arc<CollectorRegistration>>>,
    refresh_in_flight: AtomicBool,
    stale_requested: AtomicBool,
    generation: AtomicU64,
    next_collector_generation: AtomicU64,
    collector_pinned: bool,
    /// Cold-path registration only. Scrapes with a collector never take this lock.
    collector_registration: Mutex<()>,
}

struct CollectorRegistration {
    collector: Arc<dyn TlsInventoryCollector>,
    generation: u64,
}

static CACHE: LazyLock<Arc<TlsInventoryCache>> =
    LazyLock::new(|| Arc::new(TlsInventoryCache::default()));

/// Production cache shared with the process-wide TLS event producers.
pub fn process_cache() -> &'static Arc<TlsInventoryCache> {
    &CACHE
}

/// Invalidate the production snapshot after a validated TLS rotation/reload outcome.
pub fn mark_stale() {
    process_cache().mark_stale();
}

impl Default for TlsInventoryCache {
    fn default() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(None),
            collector: ArcSwap::from_pointee(None),
            refresh_in_flight: AtomicBool::new(false),
            stale_requested: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            next_collector_generation: AtomicU64::new(0),
            collector_pinned: false,
            collector_registration: Mutex::new(()),
        }
    }
}

impl TlsInventoryCache {
    /// Create an independent cache with an owner-supplied collector. Listener
    /// startup cannot replace it. This never pins or mutates the process cache.
    pub fn with_collector(collector: Arc<dyn TlsInventoryCollector>) -> Self {
        let cache = Self {
            collector_pinned: true,
            ..Self::default()
        };
        cache
            .collector
            .store(Arc::new(Some(cache.new_collector_registration(collector))));
        cache
    }

    fn new_collector_registration(
        &self,
        collector: Arc<dyn TlsInventoryCollector>,
    ) -> Arc<CollectorRegistration> {
        Arc::new(CollectorRegistration {
            collector,
            generation: self
                .next_collector_generation
                .fetch_add(1, Ordering::Relaxed)
                + 1,
        })
    }

    /// Idempotent fallback for direct handler callers. First installation wins.
    pub fn install_collector(&self, collector: Arc<dyn TlsInventoryCollector>) -> bool {
        let _registration = self
            .collector_registration
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.collector_pinned || self.collector_installed() {
            return false;
        }
        self.collector
            .store(Arc::new(Some(self.new_collector_registration(collector))));
        true
    }

    /// Replace the collector and invalidate its snapshot for a new serving cycle.
    /// Plaintext/HTTPS listeners sharing a cycle key reuse the current collector.
    /// Old in-flight results remain generation-fenced; fixed collectors stay owned
    /// by the cache's creator.
    pub fn replace_collector_for_serving_cycle(
        &self,
        collector: Arc<dyn TlsInventoryCollector>,
    ) -> bool {
        let _registration = self
            .collector_registration
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.collector_pinned {
            return false;
        }
        let serving_cycle_key = collector.serving_cycle_key();
        if serving_cycle_key.is_some()
            && self
                .collector
                .load()
                .as_ref()
                .as_ref()
                .is_some_and(|registration| {
                    registration.collector.serving_cycle_key() == serving_cycle_key
                })
        {
            return false;
        }
        self.collector
            .store(Arc::new(Some(self.new_collector_registration(collector))));
        self.snapshot.store(Arc::new(None));
        self.mark_stale();
        true
    }

    pub fn collector_installed(&self) -> bool {
        self.collector.load().as_ref().is_some()
    }

    /// Lock-free read of this owner's published snapshot. Never performs source I/O.
    pub fn snapshot(&self) -> Option<Arc<TlsInventorySnapshot>> {
        loop {
            let collector_before = self.collector.load_full();
            let snapshot = self.snapshot.load().as_ref().clone();
            let collector_after = self.collector.load_full();
            if Arc::ptr_eq(&collector_before, &collector_after) {
                let collector_generation = collector_after.as_ref().as_ref()?.generation;
                return snapshot
                    .filter(|snapshot| snapshot.collector_generation == collector_generation);
            }
        }
    }

    /// Ask the next due check to refresh regardless of remaining TTL.
    pub fn mark_stale(&self) {
        self.stale_requested.store(true, Ordering::Relaxed);
    }

    pub fn refresh_is_due(&self, ttl: Duration) -> bool {
        if self.stale_requested.load(Ordering::Relaxed) {
            return true;
        }
        match self.snapshot() {
            None => true,
            Some(snapshot) => snapshot.age() >= ttl,
        }
    }

    /// Schedule a bounded refresh without waiting for collection. Dropping the
    /// returned task handle detaches it (the scrape path); cache owners can join
    /// it to observe publication and single-flight release without timing guesses.
    pub fn schedule_refresh_if_due(
        self: &Arc<Self>,
        ttl: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !self.refresh_is_due(ttl) {
            return None;
        }
        let registration = self.collector.load().as_ref().clone()?;
        let guard = RefreshGuard::try_acquire(self)?;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            debug!("No Tokio runtime available to refresh the TLS inventory snapshot");
            return None;
        };
        // Consume staleness before collecting: invalidation during collection
        // must re-arm the next refresh, rather than being swallowed by this one.
        self.stale_requested.store(false, Ordering::Relaxed);
        Some(handle.spawn_blocking(move || {
            guard.cache.publish(
                registration.collector.collect_public_metadata(),
                registration.generation,
            );
            drop(guard);
        }))
    }

    fn publish(&self, inventory: TlsInventory, collector_generation: u64) {
        let snapshot = Arc::new(TlsInventorySnapshot {
            inventory: Arc::new(inventory),
            collected_at: Utc::now(),
            generation: self.generation.fetch_add(1, Ordering::Relaxed) + 1,
            collected_at_instant: Instant::now(),
            collector_generation,
        });
        debug!(
            generation = snapshot.generation,
            collector_generation,
            entries = snapshot.inventory.entries.len(),
            "Published cached TLS inventory snapshot"
        );
        self.snapshot.store(Arc::new(Some(snapshot)));
    }
}

/// Retains the exact cache until collection finishes, including on panic.
struct RefreshGuard {
    cache: Arc<TlsInventoryCache>,
}

impl RefreshGuard {
    fn try_acquire(cache: &Arc<TlsInventoryCache>) -> Option<Self> {
        cache
            .refresh_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self {
                cache: Arc::clone(cache),
            })
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.cache.refresh_in_flight.store(false, Ordering::Release);
    }
}
