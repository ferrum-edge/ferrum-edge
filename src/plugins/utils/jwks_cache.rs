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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::{JwksKeyStore, redacted_jwks_uri};

/// A cached JWKS entry: the key store plus its background refresh task handle.
struct JwksCacheEntry {
    store: Arc<JwksKeyStore>,
    refresh_handle: JoinHandle<()>,
    refresh_interval: Duration,
    refresh_generation: u64,
    retirement_epoch: Arc<AtomicU64>,
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
) -> Arc<JwksKeyStore> {
    let cache = global_cache();

    // Fast path: store already exists. A newly observed shorter interval must
    // take effect immediately; longer intervals are applied only when the
    // committed plugin generation is reconciled, because another active
    // consumer may still require the shorter cadence.
    if let Some(mut entry) = cache.get_mut(jwks_uri) {
        // A new consumer revives an entry that may have been marked retired by
        // a concurrent plugin-cache publication. Bumping the epoch invalidates
        // any pending last-owner reaper before cloning the store.
        entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
        if refresh_interval < entry.refresh_interval {
            reconfigure_refresh_task(jwks_uri, entry.value_mut(), refresh_interval);
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
        let refresh_handle = store.start_background_refresh(refresh_interval);
        JwksCacheEntry {
            store: Arc::new(store),
            refresh_handle,
            refresh_interval,
            refresh_generation: 1,
            retirement_epoch: Arc::new(AtomicU64::new(0)),
        }
    });
    entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
    if refresh_interval < entry.refresh_interval {
        reconfigure_refresh_task(jwks_uri, entry.value_mut(), refresh_interval);
    }
    entry.value().store.clone()
}

fn reconfigure_refresh_task(
    jwks_uri: &str,
    entry: &mut JwksCacheEntry,
    refresh_interval: Duration,
) {
    if entry.refresh_interval == refresh_interval {
        return;
    }
    let previous = entry.refresh_interval;
    entry.refresh_handle.abort();
    entry.refresh_handle = entry.store.start_background_refresh(refresh_interval);
    entry.refresh_interval = refresh_interval;
    entry.refresh_generation = entry.refresh_generation.wrapping_add(1);
    info!(
        "JWKS cache: refresh interval for {} changed from {:?} to {:?}",
        redacted_jwks_uri(jwks_uri),
        previous,
        refresh_interval
    );
}

/// Reconcile the shared cache against the exact minimum interval required by
/// the newly committed plugin generation, then retire unreferenced stores.
pub fn retain_active_requirements(active_requirements: &HashMap<String, Duration>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if let Some(refresh_interval) = active_requirements.get(uri) {
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            reconfigure_refresh_task(uri, entry, *refresh_interval);
            true
        } else {
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
            entry.retirement_epoch.fetch_add(1, Ordering::AcqRel);
            true
        } else {
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
/// is removed immediately; transient or shared owners keep it alive until the
/// epoch-bound reaper can remove it safely. A committed active consumer revives
/// the epoch during publication reconciliation.
pub fn retire_jwks_store_if_unreferenced(jwks_uri: &str) {
    let cache = global_cache();
    if let Some(entry) = cache.get(jwks_uri)
        && Arc::strong_count(&entry.store) > 1
    {
        // A prior plugin generation or in-flight authentication still owns
        // this superseded store. Reuse the epoch-bound reaper so its refresh
        // task stops as soon as those transient owners finish; a concurrent
        // active consumer revives the epoch and cancels this retirement.
        schedule_retired_store_reaper(jwks_uri.to_string(), entry.value());
        return;
    }
    if let Some((_, stale)) =
        cache.remove_if(jwks_uri, |_, entry| Arc::strong_count(&entry.store) == 1)
    {
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
            entry.value().refresh_interval,
            entry.value().refresh_generation,
        )
    })
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
