//! Router cache for high-performance proxy route lookups.
//!
//! Pre-sorts routes by listen_path length (longest first) at config load time,
//! and caches path→proxy lookups in a bounded DashMap for O(1) repeated hits.
//! Route table rebuilds happen atomically via ArcSwap when config changes —
//! never on the hot request path.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::debug;

use crate::config::types::{GatewayConfig, Proxy};

/// A pre-sorted route entry for longest-prefix matching.
struct RouteEntry {
    listen_path: String,
    proxy: Arc<Proxy>,
}

/// High-performance router cache with pre-sorted route table and path lookup cache.
///
/// The route table is rebuilt atomically (via ArcSwap) whenever configuration changes,
/// keeping the rebuild off the hot request path. Repeated path lookups hit a DashMap
/// cache for O(1) performance.
pub struct RouterCache {
    /// Pre-sorted route entries (longest listen_path first) for early-exit prefix scan.
    route_table: ArcSwap<Vec<RouteEntry>>,
    /// Bounded cache: request path → matched proxy for O(1) repeated lookups.
    path_cache: DashMap<String, Arc<Proxy>>,
    /// Maximum entries in path_cache before clearing to bound memory.
    max_cache_entries: usize,
}

impl RouterCache {
    /// Build a new RouterCache from the given config.
    ///
    /// Routes are pre-sorted by listen_path length descending so the first
    /// `starts_with` match is always the longest prefix match.
    pub fn new(config: &GatewayConfig, max_cache_entries: usize) -> Self {
        let table = Self::build_route_table(config);
        Self {
            route_table: ArcSwap::new(Arc::new(table)),
            path_cache: DashMap::new(),
            max_cache_entries,
        }
    }

    /// Atomically rebuild the route table from new config and clear the path cache.
    ///
    /// Called by `ProxyState::update_config()` when database polling or SIGHUP
    /// delivers a new configuration. Lock-free for readers — in-flight requests
    /// continue using the previous table until they complete.
    pub fn rebuild(&self, config: &GatewayConfig) {
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));
        self.path_cache.clear();
        debug!(
            "Router cache rebuilt: {} routes, path cache cleared",
            config.proxies.len()
        );
    }

    /// Find the matching proxy for a request path.
    ///
    /// 1. O(1) DashMap cache lookup for repeated paths
    /// 2. Falls back to pre-sorted route table scan (first match = longest prefix)
    /// 3. Caches the result for future O(1) hits
    pub fn find_proxy(&self, path: &str) -> Option<Arc<Proxy>> {
        // Fast path: check the path cache
        if let Some(entry) = self.path_cache.get(path) {
            return Some(Arc::clone(entry.value()));
        }

        // Slow path: scan pre-sorted route table (longest listen_path first)
        let table = self.route_table.load();
        let result = table
            .iter()
            .find(|entry| path.starts_with(&entry.listen_path))
            .map(|entry| Arc::clone(&entry.proxy));

        // Cache the result (including None → we skip caching misses to avoid
        // unbounded growth from random paths / scanners)
        if let Some(ref proxy) = result {
            // Bound memory: if cache is too large, clear it.
            // This is rare in practice and cheaper than LRU bookkeeping.
            if self.path_cache.len() >= self.max_cache_entries {
                self.path_cache.clear();
                debug!(
                    "Router path cache cleared (exceeded {} entries)",
                    self.max_cache_entries
                );
            }
            self.path_cache.insert(path.to_string(), Arc::clone(proxy));
        }

        result
    }

    /// Number of entries currently in the path lookup cache (for testing).
    #[allow(dead_code)]
    pub fn cache_len(&self) -> usize {
        self.path_cache.len()
    }

    /// Number of routes in the pre-sorted route table (for testing).
    #[allow(dead_code)]
    pub fn route_count(&self) -> usize {
        self.route_table.load().len()
    }

    /// Build a pre-sorted route table from config.
    /// Sorted by listen_path length descending so the first starts_with match
    /// is the longest prefix match.
    fn build_route_table(config: &GatewayConfig) -> Vec<RouteEntry> {
        let mut entries: Vec<RouteEntry> = config
            .proxies
            .iter()
            .map(|p| RouteEntry {
                listen_path: p.listen_path.clone(),
                proxy: Arc::new(p.clone()),
            })
            .collect();

        // Sort by listen_path length descending (longest first)
        entries.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        entries
    }
}
