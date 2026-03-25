//! Router cache for high-performance proxy route lookups.
//!
//! Pre-sorts routes by listen_path length (longest first) at config load time,
//! and caches path→proxy lookups in a bounded DashMap for O(1) repeated hits.
//! Route table rebuilds happen atomically via ArcSwap when config changes —
//! never on the hot request path.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// cache for O(1) performance. Negative lookups (no route matched) are also cached
/// to prevent O(n) rescans from scanner traffic.
pub struct RouterCache {
    /// Pre-sorted route entries (longest listen_path first) for early-exit prefix scan.
    route_table: ArcSwap<Vec<RouteEntry>>,
    /// Bounded cache: request path → matched proxy for O(1) repeated lookups.
    /// `None` entries represent negative cache (no route matched this path),
    /// preventing O(n) rescans from scanner/bot traffic.
    path_cache: DashMap<String, Option<Arc<Proxy>>>,
    /// Maximum entries in path_cache before eviction.
    max_cache_entries: usize,
    /// Monotonic counter used for random-sample eviction (avoids clearing entire cache).
    eviction_counter: AtomicU64,
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
            path_cache: DashMap::with_capacity(max_cache_entries),
            max_cache_entries,
            eviction_counter: AtomicU64::new(0),
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
    /// 1. O(1) DashMap cache lookup for repeated paths (including negative cache)
    /// 2. Falls back to pre-sorted route table scan (first match = longest prefix)
    /// 3. Caches the result (including misses) for future O(1) hits
    pub fn find_proxy(&self, path: &str) -> Option<Arc<Proxy>> {
        // Fast path: check the path cache (includes negative entries)
        if let Some(entry) = self.path_cache.get(path) {
            return entry.value().clone();
        }

        // Slow path: scan pre-sorted route table (longest listen_path first)
        let table = self.route_table.load();
        let result = table
            .iter()
            .find(|entry| {
                // Path must match the listen_path exactly or the listen_path must
                // be followed by '/' or '?' to respect path boundaries.
                // This prevents "/api" from matching "/api-internal".
                if path == entry.listen_path {
                    true
                } else if path.starts_with(&entry.listen_path) {
                    entry.listen_path.ends_with('/')
                        || path.as_bytes().get(entry.listen_path.len()) == Some(&b'/')
                        || path.as_bytes().get(entry.listen_path.len()) == Some(&b'?')
                } else {
                    false
                }
            })
            .map(|entry| Arc::clone(&entry.proxy));

        // Cache both hits AND misses. Negative cache entries (None) prevent
        // O(n) rescans for repeated scanner/bot traffic hitting non-existent
        // paths. Bounded by max_cache_entries with eviction.
        if self.path_cache.len() >= self.max_cache_entries {
            self.evict_sample();
        }
        self.path_cache
            .insert(path.to_string(), result.as_ref().map(Arc::clone));

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

    /// Evict ~25% of cache entries using counter-based pseudo-random sampling.
    /// Much better than clearing the entire cache because the remaining 75%
    /// of hot entries continue to serve O(1) hits, avoiding a thundering herd
    /// of O(routes) scans.
    fn evict_sample(&self) {
        let target_removals = self.max_cache_entries / 4;
        let seed = self.eviction_counter.fetch_add(1, Ordering::Relaxed);
        let mut removed = 0;

        // DashMap shards provide pseudo-random iteration order; we just
        // remove the first `target_removals` entries we encounter.
        // Use retain for efficient bulk removal.
        let mut keep_count = 0u64;
        self.path_cache.retain(|_, _| {
            if removed >= target_removals {
                return true;
            }
            // Use a simple hash of the counter to decide which entries to evict.
            // This provides a roughly uniform eviction pattern.
            keep_count += 1;
            if (keep_count.wrapping_mul(seed.wrapping_add(7))).is_multiple_of(4) {
                removed += 1;
                false
            } else {
                true
            }
        });

        debug!(
            "Router path cache evicted {} entries (was at capacity {})",
            removed, self.max_cache_entries
        );
    }

    /// Incrementally update the route table and surgically invalidate only
    /// the path cache entries affected by changed routes.
    ///
    /// The route table itself is rebuilt (cheap O(n log n) sort) because
    /// insertion order matters for longest-prefix matching. But the path
    /// cache — which is the expensive thing to lose — is preserved for all
    /// unaffected routes. Only paths that `starts_with` a changed
    /// listen_path are evicted, so the hot 99% of cache entries survive.
    pub fn apply_delta(&self, config: &GatewayConfig, affected_listen_paths: &[String]) {
        // Rebuild the sorted route table (cheap, O(n log n))
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));

        if affected_listen_paths.is_empty() {
            return;
        }

        // Surgically invalidate only path cache entries that could be
        // affected by the changed routes. A cached path "/api/v2/users"
        // is invalidated if any affected listen_path (e.g. "/api/v2") is
        // a prefix of it, OR if the cached path is a prefix of an affected
        // listen_path (handles the case where a new longer route takes
        // priority over a shorter cached match).
        let before = self.path_cache.len();
        self.path_cache.retain(|cached_path, _| {
            // Evict both positive and negative cache entries affected by changed routes.
            // A cached path "/api/v2/users" is invalidated if any affected listen_path
            // (e.g. "/api/v2") is a prefix of it, OR vice versa. This correctly
            // invalidates negative cache entries too (a new route could match a
            // previously unmatched path).
            !affected_listen_paths.iter().any(|lp| {
                cached_path.starts_with(lp.as_str()) || lp.starts_with(cached_path.as_str())
            })
        });
        let evicted = before - self.path_cache.len();
        if evicted > 0 {
            debug!(
                "Router cache: route table rebuilt ({} routes), surgically evicted {} of {} path cache entries",
                config.proxies.len(),
                evicted,
                before
            );
        }
    }

    /// Build a pre-sorted route table from config.
    /// Sorted by listen_path length descending so the first starts_with match
    /// is the longest prefix match.
    fn build_route_table(config: &GatewayConfig) -> Vec<RouteEntry> {
        let mut entries: Vec<RouteEntry> = config
            .proxies
            .iter()
            .filter(|p| !p.backend_protocol.is_stream_proxy())
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
