//! Cached, non-secret TLS inventory snapshot for the metrics scrape path.
//!
//! Issue #2410: authenticated `/metrics` used to rebuild the full TLS inventory
//! inline, which loaded every configured certificate, CA bundle, CRL **and
//! private key** from its source on every scrape. Provider-backed and Kubernetes
//! sources were re-fetched per scrape, per replica, and each provider load
//! spawns an OS thread with its own current-thread runtime, so a slow secret
//! manager held an admin worker for the fetch timeout per source.
//!
//! The scrape path now only reads the snapshot published here:
//!
//! - [`snapshot`] is a lock-free `ArcSwap` load. It performs zero filesystem,
//!   Kubernetes, HSM, or cloud-secret I/O and never blocks on a provider.
//! - [`schedule_refresh_if_due`] moves collection to a bounded background
//!   `spawn_blocking` task: single-flight (one refresh in flight process-wide)
//!   and rate-limited by the configured snapshot TTL
//!   (`FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS`). A scrape at most *schedules*
//!   a refresh; it never waits for one.
//! - [`mark_stale`] lets validated rotation/reload outcomes
//!   ([`crate::tls::events`]) make the next scrape schedule a refresh
//!   immediately instead of waiting out the TTL.
//! - The collector itself ([`TlsInventoryCollector`]) uses the metrics-safe
//!   scope ([`crate::tls::inventory::TlsInventory::collect_public_metadata`]),
//!   so private-key bytes are never materialized to produce certificate-expiry
//!   metrics.
//!
//! Freshness is explicit rather than implied: the snapshot carries its
//! collection timestamp, and `/metrics` exports it as
//! `ferrum_tls_inventory_snapshot_timestamp_seconds` alongside the configured
//! bound `ferrum_tls_inventory_snapshot_max_age_seconds`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use tracing::debug;

use super::inventory::TlsInventory;

/// Default maximum age of the cached snapshot before a scrape schedules a
/// background refresh.
pub const DEFAULT_SNAPSHOT_TTL_SECONDS: u64 = 300;

/// Blocking producer of the metrics-safe TLS inventory.
///
/// Implemented in production by the admin state (which owns the resolved
/// `EnvConfig` and the live gateway-config `ArcSwap`) and in tests by counting
/// fakes. Runs only on the background refresh task, never on a request path.
pub trait TlsInventoryCollector: Send + Sync + 'static {
    fn collect_public_metadata(&self) -> TlsInventory;

    /// Stable identity for listeners that belong to one admin serving cycle.
    ///
    /// Plaintext and HTTPS listeners start independently but share an
    /// `AdminState`; returning the same key lets their collector registration
    /// stay idempotent. `None` keeps the conservative replace-on-every-call
    /// behavior for collectors that cannot prove shared ownership.
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
    /// Monotonic publication counter. Tests and diagnostics use it to tell two
    /// snapshots apart without comparing wall-clock timestamps.
    pub generation: u64,
    /// Monotonic collection instant used for TTL math (wall-clock jumps must not
    /// pin or expire the snapshot).
    collected_at_instant: Instant,
    /// Serving-cycle collector generation that produced this snapshot. A
    /// snapshot from a replaced collector is never exposed to the new cycle.
    collector_generation: u64,
}

impl TlsInventorySnapshot {
    /// Age of this snapshot on the monotonic clock.
    pub fn age(&self) -> Duration {
        self.collected_at_instant.elapsed()
    }
}

struct InventoryCache {
    snapshot: ArcSwap<Option<Arc<TlsInventorySnapshot>>>,
    /// Collector and its serving-cycle generation are published together.
    /// Loading them separately would allow a refresh racing replacement to
    /// pair the prior cycle's collector with the new cycle's generation.
    collector: ArcSwap<Option<Arc<CollectorRegistration>>>,
    refresh_in_flight: AtomicBool,
    stale_requested: AtomicBool,
    generation: AtomicU64,
    next_collector_generation: AtomicU64,
    collector_pinned: AtomicBool,
    /// Registration is cold-path only (admin serving-cycle startup and test
    /// setup). Serialize install/replace/pin so a pinned test collector cannot
    /// be overwritten by a racing fallback or serving-cycle registration.
    collector_registration: Mutex<()>,
}

struct CollectorRegistration {
    collector: Arc<dyn TlsInventoryCollector>,
    generation: u64,
}

static CACHE: LazyLock<InventoryCache> = LazyLock::new(|| InventoryCache {
    snapshot: ArcSwap::from_pointee(None),
    collector: ArcSwap::from_pointee(None),
    refresh_in_flight: AtomicBool::new(false),
    stale_requested: AtomicBool::new(false),
    generation: AtomicU64::new(0),
    next_collector_generation: AtomicU64::new(0),
    collector_pinned: AtomicBool::new(false),
    collector_registration: Mutex::new(()),
});

fn new_collector_registration(
    collector: Arc<dyn TlsInventoryCollector>,
) -> Arc<CollectorRegistration> {
    Arc::new(CollectorRegistration {
        collector,
        generation: CACHE
            .next_collector_generation
            .fetch_add(1, Ordering::Relaxed)
            + 1,
    })
}

/// Install the process-wide collector. First installation wins.
///
/// The metrics handler uses this as an idempotent fallback when no admin
/// serving path installed a collector. A test harness that pinned a counting
/// fake with [`pin_collector`] stays in control of what the background refresh
/// calls.
///
/// Returns `true` when this call installed the collector.
pub fn install_collector(collector: Arc<dyn TlsInventoryCollector>) -> bool {
    let _registration = CACHE
        .collector_registration
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if CACHE.collector_pinned.load(Ordering::Acquire) {
        return false;
    }
    if CACHE.collector.load().as_ref().is_some() {
        return false;
    }
    // Racing installers converge on one collector: both produce the same
    // metrics-safe inventory, so a lost race is not a correctness problem.
    CACHE
        .collector
        .store(Arc::new(Some(new_collector_registration(collector))));
    true
}

/// Replace the process-wide collector for a new admin serving cycle.
///
/// Sequential in-process serving cycles can own different `AdminState` /
/// `ProxyState` values. Keeping the first collector forever would leave later
/// cycles refreshing from the previous cycle's config. A serving-cycle install
/// therefore replaces the collector, advances its generation, and invalidates
/// the current snapshot; the next bounded refresh publishes metadata from the
/// new owner. Plaintext and HTTPS listeners from the same serving cycle are
/// deduplicated by [`TlsInventoryCollector::serving_cycle_key`] so the second
/// listener cannot invalidate the first listener's warmup. An old in-flight
/// refresh from a genuinely replaced cycle may finish, but its generation-bound
/// snapshot is ignored. Pinned test collectors remain authoritative.
///
/// Returns `true` when this call replaced the collector.
pub fn replace_collector_for_serving_cycle(collector: Arc<dyn TlsInventoryCollector>) -> bool {
    let _registration = CACHE
        .collector_registration
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if CACHE.collector_pinned.load(Ordering::Acquire) {
        return false;
    }
    let serving_cycle_key = collector.serving_cycle_key();
    if serving_cycle_key.is_some()
        && CACHE
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
    CACHE
        .collector
        .store(Arc::new(Some(new_collector_registration(collector))));
    CACHE.snapshot.store(Arc::new(None));
    mark_stale();
    true
}

/// Install a collector and refuse every later install or serving-cycle
/// replacement.
///
/// Endpoint-level test harnesses pin a counting fake so the process-wide
/// serving paths cannot replace it — or win an install race against it — while
/// the harness measures how many source fetches a scrape causes. Production
/// never pins.
#[allow(dead_code)] // Used by the external endpoint tests, not by the binary.
pub fn pin_collector(collector: Arc<dyn TlsInventoryCollector>) {
    let _registration = CACHE
        .collector_registration
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    CACHE.collector_pinned.store(true, Ordering::Release);
    CACHE
        .collector
        .store(Arc::new(Some(new_collector_registration(collector))));
    CACHE.snapshot.store(Arc::new(None));
    mark_stale();
}

/// Whether a collector has been installed.
pub fn collector_installed() -> bool {
    CACHE.collector.load().as_ref().is_some()
}

/// Lock-free read of the published snapshot. Never performs source I/O.
pub fn snapshot() -> Option<Arc<TlsInventorySnapshot>> {
    loop {
        let collector_before = CACHE.collector.load_full();
        let snapshot = CACHE.snapshot.load().as_ref().clone();
        let collector_after = CACHE.collector.load_full();
        if Arc::ptr_eq(&collector_before, &collector_after) {
            let collector_generation = collector_after.as_ref().as_ref()?.generation;
            return snapshot
                .filter(|snapshot| snapshot.collector_generation == collector_generation);
        }
    }
}

/// Ask the next due check to refresh regardless of remaining TTL.
///
/// Called from validated rotation/reload outcomes so a rotated certificate is
/// reflected on the next scrape rather than at the end of the TTL window.
pub fn mark_stale() {
    CACHE.stale_requested.store(true, Ordering::Relaxed);
}

/// Whether a refresh is due: no snapshot yet, an explicit staleness request, or
/// a snapshot older than `ttl`.
pub fn refresh_is_due(ttl: Duration) -> bool {
    if CACHE.stale_requested.load(Ordering::Relaxed) {
        return true;
    }
    match snapshot() {
        None => true,
        Some(snapshot) => snapshot.age() >= ttl,
    }
}

/// Schedule a bounded background refresh when one is due.
///
/// Returns `true` when a refresh task was spawned. Never blocks: the caller
/// keeps serving from the current snapshot (which may be absent on the very
/// first scrape, in which case certificate gauges appear from the next scrape).
pub fn schedule_refresh_if_due(ttl: Duration) -> bool {
    if !refresh_is_due(ttl) {
        return false;
    }
    let Some(registration) = CACHE.collector.load().as_ref().clone() else {
        return false;
    };
    let Some(guard) = RefreshGuard::try_acquire() else {
        return false;
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        debug!("No Tokio runtime available to refresh the TLS inventory snapshot");
        return false;
    };
    // The staleness request is consumed by the refresh that honors it. Cleared
    // before collection starts so a rotation landing mid-collection re-arms the
    // next refresh instead of being swallowed by this one.
    CACHE.stale_requested.store(false, Ordering::Relaxed);
    handle.spawn_blocking(move || {
        let _guard = guard;
        publish(
            registration.collector.collect_public_metadata(),
            registration.generation,
        );
    });
    true
}

fn publish(inventory: TlsInventory, collector_generation: u64) {
    let snapshot = Arc::new(TlsInventorySnapshot {
        inventory: Arc::new(inventory),
        collected_at: Utc::now(),
        generation: CACHE.generation.fetch_add(1, Ordering::Relaxed) + 1,
        collected_at_instant: Instant::now(),
        collector_generation,
    });
    debug!(
        generation = snapshot.generation,
        collector_generation,
        entries = snapshot.inventory.entries.len(),
        "Published cached TLS inventory snapshot"
    );
    CACHE.snapshot.store(Arc::new(Some(snapshot)));
}

/// Single-flight token. `Drop` releases the flag so a panicking collector cannot
/// wedge refreshes for the process lifetime.
struct RefreshGuard;

impl RefreshGuard {
    fn try_acquire() -> Option<Self> {
        CACHE
            .refresh_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        CACHE.refresh_in_flight.store(false, Ordering::Release);
    }
}
