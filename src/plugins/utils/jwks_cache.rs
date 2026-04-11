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
//! that are no longer referenced by any active `jwks_auth` plugin instance,
//! aborting their background refresh tasks to prevent leaked tokio tasks.

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use super::PluginHttpClient;
use super::jwks_store::JwksKeyStore;

/// A cached JWKS entry: the key store plus its background refresh task handle.
struct JwksCacheEntry {
    store: Arc<JwksKeyStore>,
    refresh_handle: JoinHandle<()>,
}

/// Global, process-wide cache of JWKS key stores keyed by `jwks_uri`.
static JWKS_CACHE: OnceLock<Arc<DashMap<String, JwksCacheEntry>>> = OnceLock::new();

fn global_cache() -> &'static Arc<DashMap<String, JwksCacheEntry>> {
    JWKS_CACHE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Get or create a shared [`JwksKeyStore`] for the given JWKS URI.
///
/// If a store already exists for this URI (created by another plugin instance
/// or another provider), the existing store is returned — no duplicate fetch
/// or background refresh task is spawned.
///
/// On first creation the store is constructed but keys are **not** fetched
/// eagerly here; the caller should call [`JwksKeyStore::fetch_keys`] or
/// rely on the background refresh task.
pub fn get_or_create_jwks_store(
    jwks_uri: &str,
    http_client: &PluginHttpClient,
    refresh_interval: Duration,
) -> Arc<JwksKeyStore> {
    let cache = global_cache();

    // Fast path: store already exists
    if let Some(entry) = cache.get(jwks_uri) {
        return Arc::clone(&entry.value().store);
    }

    // Slow path: create new store (DashMap entry API handles races)
    cache
        .entry(jwks_uri.to_string())
        .or_insert_with(|| {
            info!("JWKS cache: creating shared store for {}", jwks_uri);
            let store = JwksKeyStore::new(jwks_uri.to_string(), http_client.clone());
            let refresh_handle = store.start_background_refresh(refresh_interval);
            JwksCacheEntry {
                store: Arc::new(store),
                refresh_handle,
            }
        })
        .value()
        .store
        .clone()
}

/// Remove JWKS cache entries whose URIs are not in `active_uris`.
///
/// Aborts the background refresh task for each removed entry so leaked
/// tokio tasks don't accumulate across config reloads. Called by
/// `PluginCache::rebuild()` and `PluginCache::apply_delta()` after the
/// new plugin set is constructed.
pub fn retain_active_uris(active_uris: &HashSet<String>) {
    let cache = global_cache();
    cache.retain(|uri, entry| {
        if active_uris.contains(uri) {
            true
        } else {
            info!("JWKS cache: removing stale store for {}", uri);
            entry.refresh_handle.abort();
            false
        }
    });
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
}
