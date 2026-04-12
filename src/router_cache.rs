//! Router cache for high-performance proxy route lookups.
//!
//! Pre-sorts routes by listen_path length (longest first) at config load time,
//! with two-tier host+path matching: exact host → wildcard host → catch-all.
//! Within each host tier, prefix routes are checked first, then regex routes.
//!
//! Caches (host, path) → proxy lookups in a bounded DashMap for O(1) repeated hits.
//! Regex route matches use a separate cache partition to prevent high-cardinality
//! regex paths (e.g., UUID segments) from evicting prefix route cache entries.
//! Route table rebuilds happen atomically via ArcSwap when config changes —
//! never on the hot request path.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use regex::{Regex, RegexSet};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use tracing::{debug, warn};

use crate::config::types::{GatewayConfig, Proxy, wildcard_matches};

thread_local! {
    /// Thread-local buffer for router cache key construction.
    /// Reused across requests on the same tokio worker thread to avoid
    /// per-lookup String allocation on cache hits (the 99%+ fast path).
    static CACHE_KEY_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(128));
}

/// Result of a route match, containing the matched proxy and any extracted path parameters.
#[derive(Clone, Debug)]
pub struct RouteMatch {
    pub proxy: Arc<Proxy>,
    /// Extracted named path parameters from regex routes. Empty for prefix routes.
    pub path_params: Vec<(String, String)>,
    /// Length of the path prefix consumed by the match (for `strip_listen_path`).
    /// For prefix routes: `listen_path.len()`. For regex routes: regex match length.
    pub matched_prefix_len: usize,
}

/// A pre-sorted route entry for longest-prefix matching.
struct RouteEntry {
    listen_path: String,
    proxy: Arc<Proxy>,
}

/// A collection of prefix routes with both sorted Vec (for fallback) and
/// HashMap index (for O(path_depth) lookup instead of O(n_routes) linear scan).
///
/// The HashMap maps each listen_path to its proxy, enabling rapid longest-prefix
/// matching by walking the request path backwards through segment boundaries.
/// This is the key optimization for scaling to thousands of proxies — without it,
/// every cache miss triggers a linear scan of ALL routes in the tier.
struct IndexedPrefixRoutes {
    /// Sorted by listen_path length descending (longest first).
    /// Used as fallback and for the apply_delta retain scan.
    sorted: Vec<RouteEntry>,
    /// Maps listen_path → Arc<Proxy> for O(1) exact-match and O(depth) prefix lookups.
    path_index: HashMap<String, Arc<Proxy>>,
}

/// A pre-compiled regex route entry.
struct RegexRouteEntry {
    pattern: Regex,
    /// Named capture group names, pre-extracted for O(1) iteration.
    capture_names: Vec<String>,
    proxy: Arc<Proxy>,
}

/// A collection of regex routes with a `RegexSet` for O(1) multi-pattern matching.
///
/// Instead of testing each regex pattern sequentially (O(n_patterns) per cache miss),
/// `RegexSet` compiles all patterns into a single DFA and evaluates them in one pass.
/// When a match is found, only the winning pattern's `Regex` runs `captures()` to
/// extract named groups. This turns the regex hot path from O(n) to O(1) matching
/// + O(1) capture extraction.
struct IndexedRegexRoutes {
    /// Individual route entries (in config order) for capture extraction after RegexSet match.
    entries: Vec<RegexRouteEntry>,
    /// All patterns compiled into a single DFA for O(1) multi-pattern matching.
    /// Index correspondence: `regex_set` pattern at index i matches `entries[i]`.
    regex_set: RegexSet,
}

impl IndexedRegexRoutes {
    /// Build from a list of regex route entries.
    /// The RegexSet is compiled from the same anchored patterns used by individual entries.
    fn new(entries: Vec<RegexRouteEntry>) -> Self {
        let patterns: Vec<&str> = entries.iter().map(|e| e.pattern.as_str()).collect();
        // RegexSet::new cannot fail here because all patterns were already individually
        // compiled as Regex (invalid patterns were skipped with a warning during build_route_table).
        let regex_set = RegexSet::new(&patterns).unwrap_or_else(|e| {
            warn!(error = %e, "RegexSet compilation failed — falling back to empty set");
            RegexSet::empty()
        });
        Self { entries, regex_set }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Pre-computed host-based route index.
///
/// Routes are partitioned into three tiers searched in priority order:
/// 1. Exact host match (HashMap O(1) lookup)
/// 2. Wildcard host match (linear scan of wildcard patterns — typically very few)
/// 3. Catch-all (proxies with empty `hosts` — today's behavior)
///
/// Within each tier, prefix routes are checked first (longest-prefix matching),
/// then regex routes (first match in config order).
struct HostRouteTable {
    /// Exact host → indexed prefix route entries (longest listen_path first + HashMap index).
    exact_hosts: HashMap<String, IndexedPrefixRoutes>,
    /// Wildcard suffix entries, e.g., ("*.example.com", routes).
    /// Sorted by pattern length descending so more-specific wildcards match first.
    wildcard_hosts: Vec<(String, IndexedPrefixRoutes)>,
    /// Catch-all prefix routes (proxies with empty `hosts`) with HashMap index.
    catch_all: IndexedPrefixRoutes,
    /// Exact host → indexed regex route entries (RegexSet + individual patterns).
    exact_hosts_regex: HashMap<String, IndexedRegexRoutes>,
    /// Wildcard host → indexed regex route entries.
    wildcard_hosts_regex: Vec<(String, IndexedRegexRoutes)>,
    /// Catch-all regex routes with RegexSet index.
    catch_all_regex: IndexedRegexRoutes,
    /// Pre-computed flag: true if any regex routes exist (skip regex path entirely when false).
    has_regex_routes: bool,
}

/// Cached regex match result (stored in regex_cache).
#[derive(Clone)]
struct RegexCacheEntry {
    proxy: Arc<Proxy>,
    path_params: Vec<(String, String)>,
    matched_len: usize,
}

/// Cache-line aligned counter row for the Count-Min Sketch.
///
/// Wrapping the `Vec<AtomicU8>` in a cache-line aligned struct ensures that
/// `row0` and `row1` start on different cache lines, preventing false sharing
/// between cores that increment counters in different rows concurrently.
/// Without this, the tail of `row0` and head of `row1` could share a 64-byte
/// cache line, causing unnecessary invalidation traffic.
#[repr(align(64))]
struct AlignedCounterRow(Vec<AtomicU8>);

/// Lightweight Count-Min Sketch for frequency estimation.
///
/// Uses two rows of `AtomicU8` counters with FNV-1a hashing (two different seeds)
/// to estimate access frequency for cache keys. The sketch supports periodic aging
/// (right-shift all counters by 1) to adapt to changing workloads.
///
/// Memory: `2 * width` bytes + 64-byte alignment padding. With the default width
/// of 8192, that is ~16 KiB + padding.
struct CountMinSketch {
    row0: AlignedCounterRow,
    row1: AlignedCounterRow,
    width_mask: usize,
    /// Total increments across all keys, for triggering periodic aging.
    total_increments: AtomicU64,
    /// Age (halve all counters) after this many increments.
    age_threshold: u64,
}

impl CountMinSketch {
    /// Create a new sketch with the given width (rounded up to a power of two).
    /// `age_threshold` controls how often counters are halved (typically `cache_capacity * 4`).
    fn new(width: usize, age_threshold: u64) -> Self {
        let width = width.next_power_of_two();
        let row0 = AlignedCounterRow((0..width).map(|_| AtomicU8::new(0)).collect());
        let row1 = AlignedCounterRow((0..width).map(|_| AtomicU8::new(0)).collect());
        Self {
            row0,
            row1,
            width_mask: width - 1,
            total_increments: AtomicU64::new(0),
            age_threshold,
        }
    }

    /// Hash a key using FNV-1a with the given seed.
    #[inline]
    fn fnv1a(key: &str, seed: u64) -> u64 {
        // FNV-1a with a seed-mixed offset basis for two independent hash functions
        let mut hash: u64 = 0xcbf29ce484222325u64 ^ seed;
        for byte in key.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3u64);
        }
        hash
    }

    /// Increment the frequency count for a key and return the estimated count.
    /// Triggers aging if the total increment count crosses the threshold.
    #[inline]
    fn increment(&self, key: &str) -> u8 {
        let h0 = Self::fnv1a(key, 0) as usize & self.width_mask;
        let h1 = Self::fnv1a(key, 0x9e3779b97f4a7c15) as usize & self.width_mask;

        // Saturating increment: cap at 255 to avoid wrap-around
        let v0 = self.row0.0[h0]
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v < 255 { Some(v + 1) } else { None }
            })
            .unwrap_or(255);
        let v1 = self.row1.0[h1]
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v < 255 { Some(v + 1) } else { None }
            })
            .unwrap_or(255);

        // Check if we need to age
        let total = self.total_increments.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_multiple_of(self.age_threshold) {
            self.age();
        }

        // Return post-increment min (the fetched value is pre-increment, so add 1)
        let c0 = if v0 < 255 { v0 + 1 } else { 255 };
        let c1 = if v1 < 255 { v1 + 1 } else { 255 };
        c0.min(c1)
    }

    /// Estimate the frequency of a key without incrementing.
    #[inline]
    fn estimate(&self, key: &str) -> u8 {
        let h0 = Self::fnv1a(key, 0) as usize & self.width_mask;
        let h1 = Self::fnv1a(key, 0x9e3779b97f4a7c15) as usize & self.width_mask;
        let v0 = self.row0.0[h0].load(Ordering::Relaxed);
        let v1 = self.row1.0[h1].load(Ordering::Relaxed);
        v0.min(v1)
    }

    /// Age all counters by right-shifting by 1 (halves all frequencies).
    /// This prevents long-running hot entries from permanently dominating.
    fn age(&self) {
        for cell in &self.row0.0 {
            let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v >> 1));
        }
        for cell in &self.row1.0 {
            let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v >> 1));
        }
    }

    /// Reset all counters to zero (used on full cache rebuild).
    fn reset(&self) {
        for cell in &self.row0.0 {
            cell.store(0, Ordering::Relaxed);
        }
        for cell in &self.row1.0 {
            cell.store(0, Ordering::Relaxed);
        }
        self.total_increments.store(0, Ordering::Relaxed);
    }
}

/// High-performance router cache with pre-sorted route table and partitioned lookup caches.
///
/// The route table is rebuilt atomically (via ArcSwap) whenever configuration changes,
/// keeping the rebuild off the hot request path. Repeated lookups hit DashMap
/// caches for O(1) performance. Negative lookups (no route matched) are also cached
/// to prevent O(n) rescans from scanner traffic.
///
/// Prefix routes and regex routes use separate cache partitions so that
/// high-cardinality regex paths (e.g., `/users/{uuid}/...`) cannot evict
/// frequently-hit prefix route cache entries.
pub struct RouterCache {
    /// Pre-computed host-based route index.
    route_table: ArcSwap<HostRouteTable>,
    /// Bounded cache for prefix route lookups: "host\0path" → matched proxy.
    /// `None` entries represent negative cache (no route matched from any tier).
    prefix_cache: DashMap<String, Option<Arc<Proxy>>>,
    /// Bounded cache for regex route lookups: "host\0path" → match result.
    /// Separate partition prevents high-cardinality regex paths from evicting
    /// prefix cache entries. `None` entries are NOT stored here — a regex miss
    /// combined with a prefix miss produces a `None` in `prefix_cache`.
    regex_cache: DashMap<String, RegexCacheEntry>,
    /// Maximum entries in each cache partition before eviction.
    max_cache_entries: usize,
    /// Monotonic counters for eviction tracking per partition.
    prefix_eviction_counter: AtomicU64,
    regex_eviction_counter: AtomicU64,
    /// Frequency sketch shared by both cache partitions.
    /// Tracks access frequency for frequency-aware eviction (least-frequent-of-sample).
    frequency_sketch: CountMinSketch,
}

impl RouterCache {
    /// Build a new RouterCache from the given config.
    ///
    /// Routes are partitioned by host tier and pre-sorted by listen_path length
    /// descending so the first `starts_with` match is always the longest prefix match.
    /// Regex routes are compiled at build time, not per-request.
    pub fn new(config: &GatewayConfig, max_cache_entries: usize) -> Self {
        let table = Self::build_route_table(config);
        // Sketch width: 2x cache capacity, clamped to [1024, 65536], power of two.
        let sketch_width = (max_cache_entries * 2).clamp(1024, 65536);
        // Age after cache_capacity * 4 increments to adapt to workload changes.
        let age_threshold = (max_cache_entries as u64).saturating_mul(4).max(1);
        Self {
            route_table: ArcSwap::new(Arc::new(table)),
            prefix_cache: DashMap::with_capacity(max_cache_entries),
            regex_cache: DashMap::with_capacity(max_cache_entries / 4 + 1),
            max_cache_entries,
            prefix_eviction_counter: AtomicU64::new(0),
            regex_eviction_counter: AtomicU64::new(0),
            frequency_sketch: CountMinSketch::new(sketch_width, age_threshold),
        }
    }

    /// Atomically rebuild the route table from new config and clear all caches.
    ///
    /// Called by `ProxyState::update_config()` when database polling or SIGHUP
    /// delivers a new configuration. Lock-free for readers — in-flight requests
    /// continue using the previous table until they complete.
    pub fn rebuild(&self, config: &GatewayConfig) {
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));
        self.prefix_cache.clear();
        self.regex_cache.clear();
        self.frequency_sketch.reset();
        debug!(
            "Router cache rebuilt: {} routes, caches cleared",
            config.proxies.len()
        );
    }

    /// Find the matching proxy for a request host and path.
    ///
    /// Priority order (within each host tier):
    /// 1. Prefix route: longest path prefix match
    /// 2. Regex route: first pattern match (in config order)
    ///
    /// Host tiers are searched: exact host → wildcard host → catch-all.
    ///
    /// Results are cached (including misses) for O(1) repeated lookups.
    /// Prefix and regex matches use separate cache partitions.
    pub fn find_proxy(&self, host: Option<&str>, path: &str) -> Option<RouteMatch> {
        // Fast path: use thread-local buffer for cache lookup to avoid String
        // allocation on cache hits (99%+ of requests). Only allocate on misses.
        let hit = CACHE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            write_cache_key(&mut buf, host, path);

            // Fast path 1: check prefix cache (includes negative entries for total misses)
            if let Some(entry) = self.prefix_cache.get(buf.as_str()) {
                self.frequency_sketch.increment(&buf);
                return Some(entry.value().as_ref().map(|proxy| RouteMatch {
                    proxy: Arc::clone(proxy),
                    path_params: Vec::new(),
                    matched_prefix_len: proxy.listen_path.len(),
                }));
            }

            // Fast path 2: check regex cache (only contains positive matches)
            if let Some(entry) = self.regex_cache.get(buf.as_str()) {
                self.frequency_sketch.increment(&buf);
                let cached = entry.value();
                return Some(Some(RouteMatch {
                    proxy: Arc::clone(&cached.proxy),
                    path_params: cached.path_params.clone(),
                    matched_prefix_len: cached.matched_len,
                }));
            }

            None // Cache miss — need slow path
        });

        // Unwrap the Option<Option<RouteMatch>>: Some(inner) = cache hit
        if let Some(result) = hit {
            return result;
        }

        // Slow path: search the host route table (cache miss)
        let table = self.route_table.load();
        let result = Self::search_route_table(&table, host, path);

        // Allocate the cache key String only on the cold path (cache miss + insert).
        let cache_key = make_cache_key(host, path);

        // Cache the result in the appropriate partition.
        // Increment sketch on insert so the new entry starts with a frequency of 1.
        match &result {
            Some(route_match)
                if !route_match.path_params.is_empty() || is_regex_proxy(&route_match.proxy) =>
            {
                // Regex match → regex cache
                if self.regex_cache.len() >= self.max_cache_entries {
                    self.evict_regex_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.regex_cache.insert(
                    cache_key,
                    RegexCacheEntry {
                        proxy: Arc::clone(&route_match.proxy),
                        path_params: route_match.path_params.clone(),
                        matched_len: route_match.matched_prefix_len,
                    },
                );
            }
            Some(route_match) => {
                // Prefix match → prefix cache
                if self.prefix_cache.len() >= self.max_cache_entries {
                    self.evict_prefix_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.prefix_cache
                    .insert(cache_key, Some(Arc::clone(&route_match.proxy)));
            }
            None => {
                // Negative entry → prefix cache (both tiers missed)
                if self.prefix_cache.len() >= self.max_cache_entries {
                    self.evict_prefix_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.prefix_cache.insert(cache_key, None);
            }
        }

        result
    }

    /// Search the route table for a matching proxy.
    ///
    /// Within each host tier: prefix routes first, then regex routes.
    fn search_route_table(
        table: &HostRouteTable,
        host: Option<&str>,
        path: &str,
    ) -> Option<RouteMatch> {
        if let Some(host) = host {
            // 1. Exact host match — prefix then regex
            if let Some(routes) = table.exact_hosts.get(host)
                && let Some(route_match) = find_prefix_match_indexed(routes, path)
            {
                return Some(route_match);
            }
            if table.has_regex_routes
                && let Some(routes) = table.exact_hosts_regex.get(host)
                && let Some(route_match) = find_regex_match_indexed(routes, path)
            {
                return Some(route_match);
            }

            // 2. Wildcard host match — prefix then regex
            for (pattern, routes) in &table.wildcard_hosts {
                if wildcard_matches(pattern, host)
                    && let Some(route_match) = find_prefix_match_indexed(routes, path)
                {
                    return Some(route_match);
                }
            }
            if table.has_regex_routes {
                for (pattern, routes) in &table.wildcard_hosts_regex {
                    if wildcard_matches(pattern, host)
                        && let Some(route_match) = find_regex_match_indexed(routes, path)
                    {
                        return Some(route_match);
                    }
                }
            }
        }

        // 3. Catch-all — prefix then regex
        if let Some(route_match) = find_prefix_match_indexed(&table.catch_all, path) {
            return Some(route_match);
        }
        if table.has_regex_routes
            && let Some(route_match) = find_regex_match_indexed(&table.catch_all_regex, path)
        {
            return Some(route_match);
        }

        None
    }

    /// Cache statistics for metrics: (prefix_entries, regex_entries, prefix_evictions, regex_evictions, max_entries).
    pub fn cache_stats(&self) -> (usize, usize, u64, u64, usize) {
        (
            self.prefix_cache.len(),
            self.regex_cache.len(),
            self.prefix_eviction_counter.load(Ordering::Relaxed),
            self.regex_eviction_counter.load(Ordering::Relaxed),
            self.max_cache_entries,
        )
    }

    /// Number of entries currently in the prefix cache (for testing).
    #[allow(dead_code)]
    pub fn cache_len(&self) -> usize {
        self.prefix_cache.len()
    }

    /// Number of entries currently in the regex cache (for testing).
    #[allow(dead_code)]
    pub fn regex_cache_len(&self) -> usize {
        self.regex_cache.len()
    }

    /// Number of routes in the pre-sorted route table (for testing).
    #[allow(dead_code)]
    pub fn route_count(&self) -> usize {
        let table = self.route_table.load();
        let exact_count: usize = table.exact_hosts.values().map(|v| v.sorted.len()).sum();
        let wildcard_count: usize = table
            .wildcard_hosts
            .iter()
            .map(|(_, v)| v.sorted.len())
            .sum();
        let exact_regex: usize = table
            .exact_hosts_regex
            .values()
            .map(|v| v.entries.len())
            .sum();
        let wildcard_regex: usize = table
            .wildcard_hosts_regex
            .iter()
            .map(|(_, v)| v.entries.len())
            .sum();
        exact_count
            + wildcard_count
            + table.catch_all.sorted.len()
            + exact_regex
            + wildcard_regex
            + table.catch_all_regex.entries.len()
    }

    /// Evict low-frequency entries from the prefix cache using frequency-guided sampling.
    ///
    /// Samples up to `8 * target_removals` entries from the DashMap, estimates each
    /// entry's access frequency via the Count-Min Sketch, and removes the least
    /// frequent entries. This protects hot cache entries from eviction while keeping
    /// the eviction cost proportional to the sample size, not the cache size.
    fn evict_prefix_sample(&self) {
        let removed = frequency_aware_evict(
            &self.prefix_cache,
            &self.frequency_sketch,
            self.max_cache_entries,
        );
        self.prefix_eviction_counter
            .fetch_add(removed as u64, Ordering::Relaxed);
        debug!(
            "Router prefix cache evicted {} entries (was at capacity {})",
            removed, self.max_cache_entries
        );
    }

    /// Evict low-frequency entries from the regex cache using frequency-guided sampling.
    fn evict_regex_sample(&self) {
        let removed = frequency_aware_evict(
            &self.regex_cache,
            &self.frequency_sketch,
            self.max_cache_entries,
        );
        self.regex_eviction_counter
            .fetch_add(removed as u64, Ordering::Relaxed);
        debug!(
            "Router regex cache evicted {} entries (was at capacity {})",
            removed, self.max_cache_entries
        );
    }

    /// Incrementally update the route table and surgically invalidate only
    /// the path cache entries affected by changed routes.
    ///
    /// The route table itself is rebuilt (cheap O(n log n) sort) because
    /// insertion order matters for longest-prefix matching. But the caches
    /// — which are the expensive things to lose — are preserved for all
    /// unaffected routes. Only paths related to changed listen_paths are evicted.
    pub fn apply_delta(&self, config: &GatewayConfig, affected_listen_paths: &[String]) {
        // Rebuild the sorted route table (cheap, O(n log n))
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));

        if affected_listen_paths.is_empty() {
            return;
        }

        // Separate affected paths into prefix patterns and regex patterns
        let (regex_patterns, prefix_patterns): (Vec<&String>, Vec<&String>) = affected_listen_paths
            .iter()
            .partition(|lp| lp.starts_with('~'));

        // Surgically invalidate prefix cache entries affected by changed routes.
        if !prefix_patterns.is_empty() {
            let before = self.prefix_cache.len();
            self.prefix_cache.retain(|cached_key, _| {
                let cached_path = cached_key
                    .find('\0')
                    .map(|i| &cached_key[i + 1..])
                    .unwrap_or(cached_key.as_str());
                !prefix_patterns
                    .iter()
                    .any(|lp| cached_path.starts_with(lp.as_str()) || lp.starts_with(cached_path))
            });
            let evicted = before - self.prefix_cache.len();
            if evicted > 0 {
                debug!(
                    "Router cache: surgically evicted {} prefix cache entries",
                    evicted
                );
            }
        }

        // For regex route changes, clear the entire regex cache (regex patterns
        // can match arbitrary paths, so surgical invalidation isn't reliable).
        if !regex_patterns.is_empty() {
            let before = self.regex_cache.len();
            self.regex_cache.clear();
            if before > 0 {
                debug!(
                    "Router cache: cleared {} regex cache entries due to regex route change",
                    before
                );
            }
        }

        debug!(
            "Router cache: route table rebuilt ({} routes)",
            config.proxies.len()
        );
    }

    /// Build a pre-computed host route table from config.
    ///
    /// Partitions proxies into prefix/regex and by host tier.
    /// Prefix routes are sorted by listen_path length descending within each tier
    /// and indexed in a HashMap for O(path_depth) lookup instead of O(n) linear scan.
    /// Regex patterns are pre-compiled at build time.
    fn build_route_table(config: &GatewayConfig) -> HostRouteTable {
        let mut exact_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut catch_all: Vec<RouteEntry> = Vec::new();
        let mut exact_hosts_regex: HashMap<String, Vec<RegexRouteEntry>> = HashMap::new();
        let mut wildcard_hosts_regex: HashMap<String, Vec<RegexRouteEntry>> = HashMap::new();
        let mut catch_all_regex: Vec<RegexRouteEntry> = Vec::new();

        for proxy in config
            .proxies
            .iter()
            .filter(|p| !p.backend_protocol.is_stream_proxy())
        {
            let arc_proxy = Arc::new(proxy.clone());

            if proxy.listen_path.starts_with('~') {
                // Regex route: compile the pattern
                let pattern_str = &proxy.listen_path[1..];
                // Auto-anchor for full-path matching (^pattern$)
                let anchored = crate::config::types::anchor_regex_pattern(pattern_str);
                let compiled = match Regex::new(&anchored) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            proxy_id = %proxy.id,
                            pattern = %pattern_str,
                            error = %e,
                            "Skipping proxy with invalid regex listen_path"
                        );
                        continue;
                    }
                };
                let capture_names: Vec<String> = compiled
                    .capture_names()
                    .flatten()
                    .map(String::from)
                    .collect();

                let add_regex = |target: &mut Vec<RegexRouteEntry>, proxy: &Arc<Proxy>| {
                    target.push(RegexRouteEntry {
                        pattern: compiled.clone(),
                        capture_names: capture_names.clone(),
                        proxy: Arc::clone(proxy),
                    });
                };

                if proxy.hosts.is_empty() {
                    add_regex(&mut catch_all_regex, &arc_proxy);
                } else {
                    for host in &proxy.hosts {
                        if host.starts_with("*.") {
                            wildcard_hosts_regex.entry(host.clone()).or_default().push(
                                RegexRouteEntry {
                                    pattern: compiled.clone(),
                                    capture_names: capture_names.clone(),
                                    proxy: Arc::clone(&arc_proxy),
                                },
                            );
                        } else {
                            exact_hosts_regex.entry(host.clone()).or_default().push(
                                RegexRouteEntry {
                                    pattern: compiled.clone(),
                                    capture_names: capture_names.clone(),
                                    proxy: Arc::clone(&arc_proxy),
                                },
                            );
                        }
                    }
                }
            } else {
                // Prefix route (existing behavior)
                if proxy.hosts.is_empty() {
                    catch_all.push(RouteEntry {
                        listen_path: proxy.listen_path.clone(),
                        proxy: Arc::clone(&arc_proxy),
                    });
                } else {
                    for host in &proxy.hosts {
                        let entry = RouteEntry {
                            listen_path: proxy.listen_path.clone(),
                            proxy: Arc::clone(&arc_proxy),
                        };
                        if host.starts_with("*.") {
                            wildcard_hosts.entry(host.clone()).or_default().push(entry);
                        } else {
                            exact_hosts.entry(host.clone()).or_default().push(entry);
                        }
                    }
                }
            }
        }

        // Sort prefix route lists by listen_path length descending (longest first)
        // and build HashMap indexes for O(path_depth) lookups
        for routes in exact_hosts.values_mut() {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        let exact_hosts_indexed: HashMap<String, IndexedPrefixRoutes> = exact_hosts
            .into_iter()
            .map(|(host, routes)| (host, IndexedPrefixRoutes::from_sorted(routes)))
            .collect();

        let mut wildcard_vec: Vec<(String, Vec<RouteEntry>)> = wildcard_hosts.into_iter().collect();
        for (_, routes) in &mut wildcard_vec {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        // Sort wildcard patterns by length descending (more-specific wildcards first)
        wildcard_vec.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let wildcard_indexed: Vec<(String, IndexedPrefixRoutes)> = wildcard_vec
            .into_iter()
            .map(|(pattern, routes)| (pattern, IndexedPrefixRoutes::from_sorted(routes)))
            .collect();

        catch_all.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        let catch_all_indexed = IndexedPrefixRoutes::from_sorted(catch_all);

        // Build RegexSet indexes for O(1) multi-pattern matching
        let exact_hosts_regex_indexed: HashMap<String, IndexedRegexRoutes> = exact_hosts_regex
            .into_iter()
            .map(|(host, entries)| (host, IndexedRegexRoutes::new(entries)))
            .collect();

        // Sort wildcard regex hosts by pattern length descending (same ordering as prefix)
        let mut wildcard_regex_vec: Vec<(String, Vec<RegexRouteEntry>)> =
            wildcard_hosts_regex.into_iter().collect();
        wildcard_regex_vec.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let wildcard_regex_indexed: Vec<(String, IndexedRegexRoutes)> = wildcard_regex_vec
            .into_iter()
            .map(|(pattern, entries)| (pattern, IndexedRegexRoutes::new(entries)))
            .collect();

        let catch_all_regex_indexed = IndexedRegexRoutes::new(catch_all_regex);

        let has_regex_routes = !exact_hosts_regex_indexed.is_empty()
            || !wildcard_regex_indexed.is_empty()
            || !catch_all_regex_indexed.is_empty();

        HostRouteTable {
            exact_hosts: exact_hosts_indexed,
            wildcard_hosts: wildcard_indexed,
            catch_all: catch_all_indexed,
            exact_hosts_regex: exact_hosts_regex_indexed,
            wildcard_hosts_regex: wildcard_regex_indexed,
            catch_all_regex: catch_all_regex_indexed,
            has_regex_routes,
        }
    }
}

impl IndexedPrefixRoutes {
    /// Build from a pre-sorted Vec<RouteEntry> (must already be sorted by length descending).
    fn from_sorted(sorted: Vec<RouteEntry>) -> Self {
        let path_index: HashMap<String, Arc<Proxy>> = sorted
            .iter()
            .map(|entry| (entry.listen_path.clone(), Arc::clone(&entry.proxy)))
            .collect();
        Self { sorted, path_index }
    }
}

/// Find the longest-prefix-matching route using the HashMap index.
///
/// Instead of scanning all N routes linearly (O(n)), this walks the request path
/// backwards through "/" segment boundaries, doing O(1) HashMap lookups at each step.
/// Total cost: O(path_depth) which is typically 2-5, independent of proxy count.
///
/// This is the key optimization that prevents throughput degradation as proxy count
/// scales from tens to tens of thousands.
fn find_prefix_match_indexed(routes: &IndexedPrefixRoutes, path: &str) -> Option<RouteMatch> {
    if routes.path_index.is_empty() {
        return None;
    }

    // Strip query string — listen_paths never contain query parameters
    let match_path = match path.find('?') {
        Some(pos) => &path[..pos],
        None => path,
    };

    // 1. Exact match (most common case for the scale test pattern)
    if let Some(proxy) = routes.path_index.get(match_path) {
        return Some(RouteMatch {
            proxy: Arc::clone(proxy),
            path_params: Vec::new(),
            matched_prefix_len: match_path.len(),
        });
    }

    // 2. Walk backwards through "/" boundaries for longest-prefix match.
    //    At each "/" position, try both "with slash" (for listen_paths ending in "/")
    //    and "without slash" (for listen_paths like "/api" matching "/api/users").
    let bytes = match_path.as_bytes();
    let mut search_end = match_path.len();
    loop {
        match match_path[..search_end].rfind('/') {
            Some(0) => {
                // Try "/" as a listen_path
                if let Some(proxy) = routes.path_index.get("/") {
                    return Some(RouteMatch {
                        proxy: Arc::clone(proxy),
                        path_params: Vec::new(),
                        matched_prefix_len: 1,
                    });
                }
                break;
            }
            Some(slash_pos) => {
                // Try with trailing slash: "/api/" matching "/api/users"
                // (listen_paths ending in "/" pass the boundary check because
                // the slash IS the boundary)
                let with_slash = &match_path[..=slash_pos];
                if let Some(proxy) = routes.path_index.get(with_slash) {
                    return Some(RouteMatch {
                        proxy: Arc::clone(proxy),
                        path_params: Vec::new(),
                        matched_prefix_len: with_slash.len(),
                    });
                }

                // Try without trailing slash: "/api" matching "/api/users"
                // The char at listen_path.len() must be '/' or '?' (boundary check)
                let without_slash = &match_path[..slash_pos];
                if let Some(proxy) = routes.path_index.get(without_slash) {
                    // Verify boundary: char after the prefix must be '/'
                    // (we know it is because we found the slash at slash_pos)
                    if bytes[slash_pos] == b'/' {
                        return Some(RouteMatch {
                            proxy: Arc::clone(proxy),
                            path_params: Vec::new(),
                            matched_prefix_len: without_slash.len(),
                        });
                    }
                }

                search_end = slash_pos;
            }
            None => break,
        }
    }

    // 3. Check if original path (with query string) has a "?" boundary match.
    //    E.g., listen_path "/api" matching "/api?foo=bar"
    if match_path.len() < path.len() {
        // There was a query string; match_path is the path before "?"
        if let Some(proxy) = routes.path_index.get(match_path) {
            return Some(RouteMatch {
                proxy: Arc::clone(proxy),
                path_params: Vec::new(),
                matched_prefix_len: match_path.len(),
            });
        }
    }

    None
}

/// Find the first prefix-matching route in a pre-sorted route list (linear scan fallback).
#[allow(dead_code)]
fn find_prefix_match(routes: &[RouteEntry], path: &str) -> Option<RouteMatch> {
    routes
        .iter()
        .find(|entry| {
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
        .map(|entry| RouteMatch {
            proxy: Arc::clone(&entry.proxy),
            path_params: Vec::new(),
            matched_prefix_len: entry.listen_path.len(),
        })
}

/// Find the first regex-matching route using the RegexSet index.
///
/// Instead of testing each regex pattern sequentially (O(n_patterns) per cache miss),
/// `RegexSet::matches()` evaluates all patterns in a single DFA pass (O(path_length),
/// independent of pattern count). When multiple patterns match, the lowest index wins
/// (preserving config-order / first-match-wins semantics). Only the winning pattern's
/// individual `Regex` runs `captures()` to extract named groups.
fn find_regex_match_indexed(routes: &IndexedRegexRoutes, path: &str) -> Option<RouteMatch> {
    if routes.is_empty() {
        return None;
    }

    // O(1) amortized: single DFA pass tests all patterns simultaneously
    let matches = routes.regex_set.matches(path);
    // First matching index preserves config-order semantics (first-match-wins)
    let winner_idx = matches.iter().next()?;

    let entry = &routes.entries[winner_idx];
    // Only run captures() on the single winning pattern
    let captures = entry.pattern.captures(path)?;
    let matched_len = captures.get(0).map(|m| m.end()).unwrap_or(0);

    let path_params: Vec<(String, String)> = entry
        .capture_names
        .iter()
        .filter_map(|name| {
            captures
                .name(name)
                .map(|m| (name.clone(), m.as_str().to_string()))
        })
        .collect();

    Some(RouteMatch {
        proxy: Arc::clone(&entry.proxy),
        path_params,
        matched_prefix_len: matched_len,
    })
}

/// Find the first regex-matching route in a list of regex route entries (linear scan fallback).
#[allow(dead_code)]
fn find_regex_match(routes: &[RegexRouteEntry], path: &str) -> Option<RouteMatch> {
    for entry in routes {
        if let Some(captures) = entry.pattern.captures(path) {
            let matched_len = captures.get(0).map(|m| m.end()).unwrap_or(0);

            let path_params: Vec<(String, String)> = entry
                .capture_names
                .iter()
                .filter_map(|name| {
                    captures
                        .name(name)
                        .map(|m| (name.clone(), m.as_str().to_string()))
                })
                .collect();

            return Some(RouteMatch {
                proxy: Arc::clone(&entry.proxy),
                path_params,
                matched_prefix_len: matched_len,
            });
        }
    }
    None
}

/// Check if a proxy uses a regex listen_path.
fn is_regex_proxy(proxy: &Proxy) -> bool {
    proxy.listen_path.starts_with('~')
}

/// Evict entries from a DashMap using frequency-guided sampling.
///
/// Samples a bounded number of entries, estimates each entry's access frequency
/// via the Count-Min Sketch, then removes the least frequent entries from the sample.
/// This approach is O(sample_size), not O(cache_size), and protects frequently
/// accessed entries from eviction (similar to Redis LFU and TinyUFO).
///
/// Returns the number of entries actually removed.
fn frequency_aware_evict<V>(
    map: &DashMap<String, V>,
    sketch: &CountMinSketch,
    max_entries: usize,
) -> usize {
    let target_removals = max_entries / 4;
    if target_removals == 0 {
        return 0;
    }
    let sample_size = target_removals * 8;

    // Collect a sample of (key, frequency) pairs by iterating the DashMap.
    // DashMap::iter() yields entries in shard order (pseudo-random relative to
    // insertion order), so taking the first N entries is effectively a random sample.
    let mut sample: Vec<(String, u8)> = Vec::with_capacity(sample_size);
    for entry in map.iter() {
        if sample.len() >= sample_size {
            break;
        }
        let freq = sketch.estimate(entry.key());
        sample.push((entry.key().clone(), freq));
    }

    if sample.is_empty() {
        return 0;
    }

    // Partition so the lowest-frequency entries are in sample[..to_remove].
    // select_nth_unstable is O(n) average vs O(n log n) for a full sort.
    let to_remove = sample.len().min(target_removals);
    if to_remove > 0 && to_remove < sample.len() {
        sample.select_nth_unstable_by_key(to_remove - 1, |&(_, freq)| freq);
    }
    let mut removed = 0;
    for (key, _) in &sample[..to_remove] {
        if map.remove(key).is_some() {
            removed += 1;
        }
    }

    removed
}

/// Build a cache key from host and path with exact-capacity pre-allocation.
///
/// Uses NUL separator which cannot appear in hostnames or URL paths.
/// Uses `String::with_capacity` + `push_str` instead of `format!()` to
/// avoid format-machinery overhead and produce an exact-size allocation.
/// Write the cache key into an existing buffer (zero-allocation on cache hits).
/// Used by the thread-local fast path in `find_proxy()`.
#[inline]
fn write_cache_key(buf: &mut String, host: Option<&str>, path: &str) {
    buf.clear();
    if let Some(h) = host {
        buf.push_str(h);
    }
    buf.push('\0');
    buf.push_str(path);
}

/// Allocate a new String for the cache key (used only on cache misses for DashMap insertion).
fn make_cache_key(host: Option<&str>, path: &str) -> String {
    match host {
        Some(h) => {
            let mut key = String::with_capacity(h.len() + 1 + path.len());
            key.push_str(h);
            key.push('\0');
            key.push_str(path);
            key
        }
        None => {
            let mut key = String::with_capacity(1 + path.len());
            key.push('\0');
            key.push_str(path);
            key
        }
    }
}
