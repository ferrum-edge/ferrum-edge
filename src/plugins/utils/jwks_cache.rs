//! Global JWKS key store cache shared across plugin instances.
//!
//! When multiple proxies (or multiple providers within one proxy) reference
//! the same JWKS URI, they share a single [`JwksKeyStore`] — avoiding
//! redundant HTTP fetches and duplicate background refresh tasks.
//!
//! The cache is keyed by the resolved `jwks_uri` string. It is lazily
//! initialized on first access and lives for the process lifetime.
//!
//! On config reload, [`retain_active_uris`] removes entries for JWKS URIs
//! that are no longer referenced by any active JWKS consumer, aborting their
//! background refresh tasks after any retired in-flight consumers finish.

use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::{
    JwksFailureClass, JwksKeyStore, JwksTrustState, redacted_jwks_uri, register_trust_change_hook,
};

/// Effective requirements contributed by one active shared-store consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JwksRefreshRequirement {
    pub refresh_interval: Duration,
    pub max_stale: Duration,
}

impl JwksRefreshRequirement {
    pub const fn new(refresh_interval: Duration, max_stale: Duration) -> Self {
        Self {
            refresh_interval,
            max_stale,
        }
    }

    pub fn strictest(self, other: Self) -> Self {
        Self {
            refresh_interval: self.refresh_interval.min(other.refresh_interval),
            max_stale: self.max_stale.min(other.max_stale),
        }
    }
}

/// A cached JWKS entry: the key store plus its background refresh task handle.
struct JwksCacheEntry {
    store: Arc<JwksKeyStore>,
    refresh_handle: JoinHandle<()>,
    requirement: JwksRefreshRequirement,
    refresh_generation: u64,
    retirement_epoch: Arc<AtomicU64>,
    active: AtomicBool,
    reaper_generation: AtomicU64,
}

const RETIRED_STORE_REAP_INTERVAL: Duration = Duration::from_millis(100);

/// Fixed-cardinality, redacted aggregate of active remote JWKS trust stores.
///
/// Counts never include inline key material. Endpoints, credentials, `kid`
/// values, tokens, claims, and key bytes never appear here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JwksTrustHealthAggregate {
    pub fresh: u64,
    pub grace: u64,
    pub expired: u64,
    pub max_age_seconds_fresh: u64,
    pub max_age_seconds_grace: u64,
    pub max_age_seconds_expired: u64,
    /// Earliest monotonic expiry among currently non-expired active remotes.
    /// Readiness flips when `Instant::now() >= deadline` even before the
    /// background republish task runs.
    next_expiry_at: Option<Instant>,
    /// Earliest monotonic grace transition among currently fresh active remotes.
    next_grace_at: Option<Instant>,
}

impl JwksTrustHealthAggregate {
    /// True when no active remote store is expired (or past its expiry deadline).
    pub fn ready(&self, now: Instant) -> bool {
        self.expired == 0 && self.next_expiry_at.is_none_or(|deadline| now < deadline)
    }

    /// True when any active remote is in grace, expired, or past a transition
    /// deadline that leaves the fleet less than fully fresh.
    pub fn degraded(&self, now: Instant) -> bool {
        self.grace > 0
            || self.expired > 0
            || self.next_grace_at.is_some_and(|deadline| now >= deadline)
            || self.next_expiry_at.is_some_and(|deadline| now >= deadline)
    }

    pub fn store_count_for(&self, state: JwksTrustState) -> u64 {
        match state {
            JwksTrustState::Fresh => self.fresh,
            JwksTrustState::Grace => self.grace,
            JwksTrustState::Expired => self.expired,
        }
    }

    pub fn max_age_seconds_for(&self, state: JwksTrustState) -> u64 {
        match state {
            JwksTrustState::Fresh => self.max_age_seconds_fresh,
            JwksTrustState::Grace => self.max_age_seconds_grace,
            JwksTrustState::Expired => self.max_age_seconds_expired,
        }
    }
}

/// Global, process-wide cache of JWKS key stores keyed by `jwks_uri`.
static JWKS_CACHE: OnceLock<Arc<DashMap<String, JwksCacheEntry>>> = OnceLock::new();
/// Last successfully resolved JWKS URI for each OIDC discovery URL. This map
/// stores only URI strings; key material remains owned by `JWKS_CACHE` and its
/// generation-aware reaper.
static DISCOVERED_JWKS_URIS: OnceLock<DashMap<String, String>> = OnceLock::new();
/// Precomputed active-remote trust aggregate for O(1) `/health` and `/status`.
static TRUST_HEALTH: OnceLock<arc_swap::ArcSwap<JwksTrustHealthAggregate>> = OnceLock::new();
/// Generation for the deadline-watcher task; bumping cancels a stale sleeper.
static TRUST_HEALTH_WATCH_GENERATION: AtomicU64 = AtomicU64::new(0);

fn trust_health_slot() -> &'static arc_swap::ArcSwap<JwksTrustHealthAggregate> {
    TRUST_HEALTH
        .get_or_init(|| arc_swap::ArcSwap::from_pointee(JwksTrustHealthAggregate::default()))
}

fn ensure_trust_health_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        register_trust_change_hook(republish_trust_health);
    });
}

fn global_cache() -> &'static Arc<DashMap<String, JwksCacheEntry>> {
    ensure_trust_health_hook();
    JWKS_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

fn discovered_jwks_uris() -> &'static DashMap<String, String> {
    DISCOVERED_JWKS_URIS.get_or_init(DashMap::new)
}

/// O(1) snapshot of active remote JWKS trust health for `/health` and `/status`.
///
/// Readiness and degraded flags incorporate monotonic deadlines so expiry makes
/// the gateway not-ready even if the background republish task has not yet run.
pub fn trust_health_snapshot() -> JwksTrustHealthAggregate {
    ensure_trust_health_hook();
    **trust_health_slot().load()
}

/// Rebuild the precomputed active-remote trust aggregate and arm the next
/// deadline watcher. Never inspects URLs for output — only closed-set counts.
pub fn republish_trust_health() {
    ensure_trust_health_hook();
    let now = Instant::now();
    let mut aggregate = JwksTrustHealthAggregate::default();
    let mut next_watch: Option<Instant> = None;

    if let Some(cache) = JWKS_CACHE.get() {
        for entry in cache.iter() {
            if !entry.value().active.load(Ordering::Acquire) {
                continue;
            }
            let store = &entry.value().store;
            if !store.is_refreshable() {
                continue;
            }
            let health = store.health_snapshot();
            match health.trust_state {
                JwksTrustState::Fresh => {
                    aggregate.fresh = aggregate.fresh.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_seconds_fresh =
                            aggregate.max_age_seconds_fresh.max(age.as_secs());
                    }
                }
                JwksTrustState::Grace => {
                    aggregate.grace = aggregate.grace.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_seconds_grace =
                            aggregate.max_age_seconds_grace.max(age.as_secs());
                    }
                }
                JwksTrustState::Expired => {
                    aggregate.expired = aggregate.expired.saturating_add(1);
                    if let Some(age) = health.last_success_age {
                        aggregate.max_age_seconds_expired =
                            aggregate.max_age_seconds_expired.max(age.as_secs());
                    }
                }
            }
            if health.trust_state != JwksTrustState::Expired
                && let Some(deadline) = store.expiry_deadline()
            {
                aggregate.next_expiry_at = Some(
                    aggregate
                        .next_expiry_at
                        .map_or(deadline, |current| current.min(deadline)),
                );
                if deadline > now {
                    next_watch = Some(next_watch.map_or(deadline, |current| current.min(deadline)));
                }
            }
            if health.trust_state == JwksTrustState::Fresh
                && let Some(deadline) = store.grace_deadline()
            {
                aggregate.next_grace_at = Some(
                    aggregate
                        .next_grace_at
                        .map_or(deadline, |current| current.min(deadline)),
                );
                if deadline > now {
                    next_watch = Some(next_watch.map_or(deadline, |current| current.min(deadline)));
                }
            }
        }
    }

    trust_health_slot().store(Arc::new(aggregate));
    schedule_trust_health_watch(next_watch);
}

fn schedule_trust_health_watch(next_watch: Option<Instant>) {
    let Some(deadline) = next_watch else {
        TRUST_HEALTH_WATCH_GENERATION.fetch_add(1, Ordering::AcqRel);
        return;
    };
    let generation = TRUST_HEALTH_WATCH_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        if TRUST_HEALTH_WATCH_GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        republish_trust_health();
    });
}

/// Get or create a shared [`JwksKeyStore`] for the given JWKS URI.
///
/// If a store already exists for this URI (created by another plugin instance
/// or another provider), the existing store is returned — no duplicate fetch
/// or background refresh task is spawned.
///
/// On first creation the store starts a single shared background refresh task.
/// That task performs the initial fetch and then continues periodic refreshes.
pub fn get_or_create_jwks_store(
    jwks_uri: &str,
    http_client: &PluginHttpClient,
    refresh_interval: Duration,
    max_stale: Duration,
) -> Arc<JwksKeyStore> {
    let cache = global_cache();
    let requested = JwksRefreshRequirement::new(refresh_interval, max_stale);

    // Fast path: store already exists. A newly observed stricter interval or
    // maximum-stale requirement takes effect immediately; relaxation is
    // applied only when the committed generation is reconciled, because
    // another active consumer may still require the stricter policy.
    if let Some(mut entry) = cache.get_mut(jwks_uri) {
        // A new consumer revives an entry that may have been marked retired by
        // a concurrent plugin-cache publication. Bumping the epoch invalidates
        // any pending last-owner reaper before cloning the store.
        entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
        let strictest = entry.requirement.strictest(requested);
        if strictest != entry.requirement {
            reconfigure_refresh_policy(jwks_uri, entry.value_mut(), strictest);
        }
        return Arc::clone(&entry.value().store);
    }

    // Slow path: create new store (DashMap entry API handles races)
    let mut entry = cache.entry(jwks_uri.to_string()).or_insert_with(|| {
        info!(
            "JWKS cache: creating shared store for {}",
            redacted_jwks_uri(jwks_uri)
        );
        let store = JwksKeyStore::new(jwks_uri.to_string(), http_client.clone());
        store.configure_trust_policy(refresh_interval, max_stale);
        let refresh_handle = store.start_background_refresh(refresh_interval);
        JwksCacheEntry {
            store: Arc::new(store),
            refresh_handle,
            requirement: requested,
            refresh_generation: 1,
            retirement_epoch: Arc::new(AtomicU64::new(0)),
            active: AtomicBool::new(false),
            reaper_generation: AtomicU64::new(0),
        }
    });
    entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
    let strictest = entry.requirement.strictest(requested);
    if strictest != entry.requirement {
        reconfigure_refresh_policy(jwks_uri, entry.value_mut(), strictest);
    }
    entry.value().store.clone()
}

fn reconfigure_refresh_policy(
    jwks_uri: &str,
    entry: &mut JwksCacheEntry,
    requirement: JwksRefreshRequirement,
) {
    if entry.requirement == requirement {
        return;
    }
    let previous = entry.requirement;
    entry
        .store
        .configure_trust_policy(requirement.refresh_interval, requirement.max_stale);
    entry.refresh_handle.abort();
    entry.refresh_handle = entry
        .store
        .start_background_refresh_after_policy_change(requirement.refresh_interval);
    entry.requirement = requirement;
    entry.refresh_generation = entry.refresh_generation.wrapping_add(1);
    info!(
        "JWKS cache: policy for {} changed from refresh={:?}/max-stale={:?} to refresh={:?}/max-stale={:?}",
        redacted_jwks_uri(jwks_uri),
        previous.refresh_interval,
        previous.max_stale,
        requirement.refresh_interval,
        requirement.max_stale
    );
    // configure_trust_policy already republishes; keep an explicit republish so
    // active-bit transitions that share this path stay coherent.
    republish_trust_health();
}

/// Reconcile the shared cache against the exact strictest requirement of the
/// newly committed plugin generation, then retire unreferenced stores.
pub fn retain_active_requirements(active_requirements: &HashMap<String, JwksRefreshRequirement>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if let Some(requirement) = active_requirements.get(uri) {
            entry.active.store(true, Ordering::Release);
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            reconfigure_refresh_policy(uri, entry, *requirement);
            true
        } else {
            entry.active.store(false, Ordering::Release);
            retain_retired_entry(uri, entry)
        }
    });
    republish_trust_health();
}

/// Remove JWKS cache entries whose URIs are not in `active_uris`.
///
/// Aborts the background refresh task for each removed entry so leaked tokio
/// tasks don't accumulate across config reloads. Stores still owned by a
/// retired plugin generation are reaped after their final external owner
/// drops. External unit tests use this lower-level helper to exercise
/// retirement independently from refresh-interval reconciliation.
#[allow(dead_code)] // exercised by external unit tests
pub fn retain_active_uris(active_uris: &HashSet<String>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if active_uris.contains(uri) {
            // Cancel a reaper scheduled by an older publication if this URI is
            // active again in the newly committed plugin generation.
            entry.active.store(true, Ordering::Release);
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            true
        } else {
            entry.active.store(false, Ordering::Release);
            retain_retired_entry(uri, entry)
        }
    });
    republish_trust_health();
}

fn retain_retired_entry(uri: &str, entry: &JwksCacheEntry) -> bool {
    if Arc::strong_count(&entry.store) > 1 {
        // Keep refreshes alive while an old plugin generation, an in-flight
        // request, or an asynchronously publishing discovery worker still
        // owns the store. The epoch-bound reaper removes it promptly after
        // the cache becomes the final owner, without requiring another
        // configuration reload.
        schedule_retired_store_reaper(uri.to_string(), entry);
        true
    } else {
        info!(
            "JWKS cache: removing stale store for {}",
            redacted_jwks_uri(uri)
        );
        entry.refresh_handle.abort();
        forget_discovered_jwks_uri(uri);
        false
    }
}

fn schedule_retired_store_reaper(uri: String, entry: &JwksCacheEntry) {
    let retirement_epoch = Arc::clone(&entry.retirement_epoch);
    let epoch = retirement_epoch
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    entry.reaper_generation.fetch_add(1, Ordering::AcqRel);
    let store = Arc::downgrade(&entry.store);
    let cache = Arc::clone(global_cache());

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RETIRED_STORE_REAP_INTERVAL).await;
            if retirement_epoch.load(Ordering::Acquire) != epoch {
                return;
            }
            if store.strong_count() > 1 {
                continue;
            }

            if let Some((_, stale)) = cache.remove_if(&uri, |_, current| {
                Arc::ptr_eq(&current.retirement_epoch, &retirement_epoch)
                    && retirement_epoch.load(Ordering::Acquire) == epoch
                    && !current.active.load(Ordering::Acquire)
                    && Arc::strong_count(&current.store) == 1
            }) {
                info!(
                    "JWKS cache: removing retired store for {}",
                    redacted_jwks_uri(&uri)
                );
                stale.refresh_handle.abort();
                forget_discovered_jwks_uri(&uri);
                republish_trust_health();
            }
            return;
        }
    });
}

/// A provisional discovery acquisition. Dropping it before the caller has
/// published or explicitly retired the candidate releases its store reference
/// first, then retires a cache entry that has no committed owner. This makes
/// task cancellation safe at every await point after acquisition.
pub(crate) struct DiscoveryStoreCandidate {
    jwks_uri: String,
    store: Option<Arc<JwksKeyStore>>,
}

impl DiscoveryStoreCandidate {
    pub(crate) fn acquire(
        jwks_uri: &str,
        http_client: &PluginHttpClient,
        refresh_interval: Duration,
        max_stale: Duration,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.to_string(),
            store: Some(get_or_create_jwks_store(
                jwks_uri,
                http_client,
                refresh_interval,
                max_stale,
            )),
        }
    }

    pub(crate) fn store(&self) -> Option<&Arc<JwksKeyStore>> {
        self.store.as_ref()
    }

    pub(crate) fn publish(&mut self) {
        drop(self.store.take());
    }
}

impl Drop for DiscoveryStoreCandidate {
    fn drop(&mut self) {
        let store = self.store.take();
        if store.is_none() {
            return;
        }
        drop(store);
        retire_jwks_store_if_unreferenced(&self.jwks_uri);
    }
}

/// Record a validated discovery result so an equivalent replacement plugin
/// generation can acquire the last-good store synchronously before rediscovery.
pub fn remember_discovered_jwks_uri(discovery_url: &str, jwks_uri: &str) {
    discovered_jwks_uris().insert(discovery_url.to_string(), jwks_uri.to_string());
}

/// Return the last validated JWKS URI for a discovery endpoint.
pub fn last_discovered_jwks_uri(discovery_url: &str) -> Option<String> {
    discovered_jwks_uris()
        .get(discovery_url)
        .map(|entry| entry.value().clone())
}

fn forget_discovered_jwks_uri(jwks_uri: &str) {
    if let Some(discoveries) = DISCOVERED_JWKS_URIS.get() {
        discoveries.retain(|_, resolved_uri| resolved_uri != jwks_uri);
    }
}

/// Retire a superseded or rejected discovery store. A sole-owner cache entry
/// is removed immediately; transient owners keep it alive until the epoch-bound
/// reaper can remove it safely. A URI retained by the committed plugin
/// generation is marked active and never gets a retirement reaper; transient
/// owners keep the reaper alive until their last reference drops.
pub fn retire_jwks_store_if_unreferenced(jwks_uri: &str) {
    let cache = global_cache();
    if let Some(entry) = cache.get(jwks_uri) {
        if entry.active.load(Ordering::Acquire) {
            return;
        }
        if Arc::strong_count(&entry.store) > 1 {
            // A prior plugin generation or in-flight authentication still owns
            // this superseded store. Reuse the epoch-bound reaper so its refresh
            // task stops as soon as those transient owners finish; a concurrent
            // active consumer revives the epoch and cancels this retirement.
            schedule_retired_store_reaper(jwks_uri.to_string(), entry.value());
            return;
        }
    }
    if let Some((_, stale)) = cache.remove_if(jwks_uri, |_, entry| {
        !entry.active.load(Ordering::Acquire) && Arc::strong_count(&entry.store) == 1
    }) {
        info!(
            "JWKS cache: removing superseded discovery store for {}",
            redacted_jwks_uri(jwks_uri)
        );
        stale.refresh_handle.abort();
        forget_discovered_jwks_uri(jwks_uri);
        republish_trust_health();
    }
}

/// Return the current interval and task generation for diagnostics and tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_refresh_state(jwks_uri: &str) -> Option<(Duration, u64)> {
    global_cache().get(jwks_uri).map(|entry| {
        (
            entry.value().requirement.refresh_interval,
            entry.value().refresh_generation,
        )
    })
}

/// Return the current strict shared-store policy for diagnostics and tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_requirement(jwks_uri: &str) -> Option<JwksRefreshRequirement> {
    global_cache()
        .get(jwks_uri)
        .map(|entry| entry.value().requirement)
}

/// Render fixed-cardinality JWKS trust and refresh observability.
///
/// Stores are aggregated by closed state/failure enums; endpoint URLs, key
/// identifiers, tokens, claims, and key material never enter this surface.
pub fn render_prometheus() -> String {
    // Keep metrics aligned with the readiness aggregate (active remotes only).
    republish_trust_health();
    let health = trust_health_snapshot();
    let mut max_consecutive_failures = [0u64; 6];

    if let Some(cache) = JWKS_CACHE.get() {
        for entry in cache.iter() {
            if !entry.value().active.load(Ordering::Acquire) {
                continue;
            }
            let snapshot = entry.value().store.health_snapshot();
            if let Some(class) = snapshot.last_failure {
                let class_index = class.index();
                max_consecutive_failures[class_index] = max_consecutive_failures[class_index]
                    .max(u64::from(snapshot.consecutive_failures));
            }
        }
    }

    let mut output = String::new();
    output.push_str(
        "# HELP ferrum_jwks_trust_stores Active remote JWKS stores by bounded trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_stores gauge\n");
    output.push_str(
        "# HELP ferrum_jwks_trust_age_seconds Maximum age of the last validated non-empty JWKS among active remote stores in each trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_age_seconds gauge\n");
    for state in JwksTrustState::ALL {
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_stores{{state=\"{}\"}} {}",
            state.as_str(),
            health.store_count_for(state)
        );
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_age_seconds{{state=\"{}\"}} {}",
            state.as_str(),
            health.max_age_seconds_for(state)
        );
    }

    output.push_str(
        "# HELP ferrum_jwks_refresh_failures_total Remote JWKS refresh failures by fixed failure class.\n",
    );
    output.push_str("# TYPE ferrum_jwks_refresh_failures_total counter\n");
    output.push_str(
        "# HELP ferrum_jwks_consecutive_failures Maximum current consecutive failures among active remote stores by fixed failure class.\n",
    );
    output.push_str("# TYPE ferrum_jwks_consecutive_failures gauge\n");
    let failure_counts = JwksKeyStore::refresh_failure_counts();
    for (index, class) in JwksFailureClass::ALL.iter().enumerate() {
        let _ = writeln!(
            output,
            "ferrum_jwks_refresh_failures_total{{class=\"{}\"}} {}",
            class.as_str(),
            failure_counts[index]
        );
        let _ = writeln!(
            output,
            "ferrum_jwks_consecutive_failures{{class=\"{}\"}} {}",
            class.as_str(),
            max_consecutive_failures[index]
        );
    }
    output
}

/// Return reaper-scheduling state for lifecycle tests.
#[doc(hidden)]
#[allow(dead_code)] // exercised by external unit tests
pub fn cached_reaper_generation(jwks_uri: &str) -> Option<u64> {
    global_cache()
        .get(jwks_uri)
        .map(|entry| entry.value().reaper_generation.load(Ordering::Acquire))
}

/// Clear the global JWKS cache. Used in tests to isolate state between runs.
#[allow(dead_code)]
pub fn clear_jwks_cache() {
    if let Some(cache) = JWKS_CACHE.get() {
        // Abort all background refresh tasks before clearing
        for entry in cache.iter() {
            entry.value().refresh_handle.abort();
        }
        cache.clear();
    }
    if let Some(discoveries) = DISCOVERED_JWKS_URIS.get() {
        discoveries.clear();
    }
    republish_trust_health();
}
