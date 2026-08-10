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
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::{JwksFailureClass, JwksKeyStore, JwksTrustState, redacted_jwks_uri};

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

/// Global, process-wide cache of JWKS key stores keyed by `jwks_uri`.
static JWKS_CACHE: OnceLock<Arc<DashMap<String, JwksCacheEntry>>> = OnceLock::new();
/// Last successfully resolved JWKS URI for each OIDC discovery URL. This map
/// stores only URI strings; key material remains owned by `JWKS_CACHE` and its
/// generation-aware reaper.
static DISCOVERED_JWKS_URIS: OnceLock<DashMap<String, String>> = OnceLock::new();

fn global_cache() -> &'static Arc<DashMap<String, JwksCacheEntry>> {
    JWKS_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

fn discovered_jwks_uris() -> &'static DashMap<String, String> {
    DISCOVERED_JWKS_URIS.get_or_init(DashMap::new)
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
        .start_background_refresh(requirement.refresh_interval);
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
    let mut store_counts = [0u64; 3];
    let mut max_trust_age_seconds = [0u64; 3];
    let mut max_consecutive_failures = [0u64; 6];

    for entry in global_cache().iter() {
        let health = entry.value().store.health_snapshot();
        let state_index = health.trust_state.index();
        store_counts[state_index] = store_counts[state_index].saturating_add(1);
        if let Some(age) = health.last_success_age {
            max_trust_age_seconds[state_index] =
                max_trust_age_seconds[state_index].max(age.as_secs());
        }
        if let Some(class) = health.last_failure {
            let class_index = class.index();
            max_consecutive_failures[class_index] =
                max_consecutive_failures[class_index].max(u64::from(health.consecutive_failures));
        }
    }

    let mut output = String::new();
    output.push_str(
        "# HELP ferrum_jwks_trust_stores Shared remote JWKS stores by bounded trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_stores gauge\n");
    output.push_str(
        "# HELP ferrum_jwks_trust_age_seconds Maximum age of the last validated non-empty JWKS among stores in each trust state.\n",
    );
    output.push_str("# TYPE ferrum_jwks_trust_age_seconds gauge\n");
    for state in JwksTrustState::ALL {
        let index = state.index();
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_stores{{state=\"{}\"}} {}",
            state.as_str(),
            store_counts[index]
        );
        let _ = writeln!(
            output,
            "ferrum_jwks_trust_age_seconds{{state=\"{}\"}} {}",
            state.as_str(),
            max_trust_age_seconds[index]
        );
    }

    output.push_str(
        "# HELP ferrum_jwks_refresh_failures_total Remote JWKS refresh failures by fixed failure class.\n",
    );
    output.push_str("# TYPE ferrum_jwks_refresh_failures_total counter\n");
    output.push_str(
        "# HELP ferrum_jwks_consecutive_failures Maximum current consecutive failures among shared stores by fixed failure class.\n",
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
}
