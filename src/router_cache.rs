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
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

use crate::config::types::{GatewayConfig, Proxy, wildcard_matches};

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

/// A pre-compiled regex route entry.
struct RegexRouteEntry {
    pattern: Regex,
    /// Named capture group names, pre-extracted for O(1) iteration.
    capture_names: Vec<String>,
    proxy: Arc<Proxy>,
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
    /// Exact host → sorted prefix route entries (longest listen_path first).
    exact_hosts: HashMap<String, Vec<RouteEntry>>,
    /// Wildcard suffix entries, e.g., ("*.example.com", routes).
    /// Sorted by pattern length descending so more-specific wildcards match first.
    wildcard_hosts: Vec<(String, Vec<RouteEntry>)>,
    /// Catch-all prefix routes (proxies with empty `hosts`).
    catch_all: Vec<RouteEntry>,
    /// Exact host → regex route entries (in config order).
    exact_hosts_regex: HashMap<String, Vec<RegexRouteEntry>>,
    /// Wildcard host → regex route entries.
    wildcard_hosts_regex: Vec<(String, Vec<RegexRouteEntry>)>,
    /// Catch-all regex routes.
    catch_all_regex: Vec<RegexRouteEntry>,
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
    /// Monotonic counters for random-sample eviction per partition.
    prefix_eviction_counter: AtomicU64,
    regex_eviction_counter: AtomicU64,
}

impl RouterCache {
    /// Build a new RouterCache from the given config.
    ///
    /// Routes are partitioned by host tier and pre-sorted by listen_path length
    /// descending so the first `starts_with` match is always the longest prefix match.
    /// Regex routes are compiled at build time, not per-request.
    pub fn new(config: &GatewayConfig, max_cache_entries: usize) -> Self {
        let table = Self::build_route_table(config);
        Self {
            route_table: ArcSwap::new(Arc::new(table)),
            prefix_cache: DashMap::with_capacity(max_cache_entries),
            regex_cache: DashMap::with_capacity(max_cache_entries / 4 + 1),
            max_cache_entries,
            prefix_eviction_counter: AtomicU64::new(0),
            regex_eviction_counter: AtomicU64::new(0),
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
        let cache_key = make_cache_key(host, path);

        // Fast path 1: check prefix cache (includes negative entries for total misses)
        if let Some(entry) = self.prefix_cache.get(&cache_key) {
            return entry.value().as_ref().map(|proxy| RouteMatch {
                proxy: Arc::clone(proxy),
                path_params: Vec::new(),
                matched_prefix_len: proxy.listen_path.len(),
            });
        }

        // Fast path 2: check regex cache (only contains positive matches)
        if let Some(entry) = self.regex_cache.get(&cache_key) {
            let cached = entry.value();
            return Some(RouteMatch {
                proxy: Arc::clone(&cached.proxy),
                path_params: cached.path_params.clone(),
                matched_prefix_len: cached.matched_len,
            });
        }

        // Slow path: search the host route table
        let table = self.route_table.load();
        let result = Self::search_route_table(&table, host, path);

        // Cache the result in the appropriate partition
        match &result {
            Some(route_match)
                if !route_match.path_params.is_empty() || is_regex_proxy(&route_match.proxy) =>
            {
                // Regex match → regex cache
                if self.regex_cache.len() >= self.max_cache_entries {
                    self.evict_regex_sample();
                }
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
                self.prefix_cache
                    .insert(cache_key, Some(Arc::clone(&route_match.proxy)));
            }
            None => {
                // Negative entry → prefix cache (both tiers missed)
                if self.prefix_cache.len() >= self.max_cache_entries {
                    self.evict_prefix_sample();
                }
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
                && let Some(route_match) = find_prefix_match(routes, path)
            {
                return Some(route_match);
            }
            if table.has_regex_routes
                && let Some(routes) = table.exact_hosts_regex.get(host)
                && let Some(route_match) = find_regex_match(routes, path)
            {
                return Some(route_match);
            }

            // 2. Wildcard host match — prefix then regex
            for (pattern, routes) in &table.wildcard_hosts {
                if wildcard_matches(pattern, host)
                    && let Some(route_match) = find_prefix_match(routes, path)
                {
                    return Some(route_match);
                }
            }
            if table.has_regex_routes {
                for (pattern, routes) in &table.wildcard_hosts_regex {
                    if wildcard_matches(pattern, host)
                        && let Some(route_match) = find_regex_match(routes, path)
                    {
                        return Some(route_match);
                    }
                }
            }
        }

        // 3. Catch-all — prefix then regex
        if let Some(route_match) = find_prefix_match(&table.catch_all, path) {
            return Some(route_match);
        }
        if table.has_regex_routes
            && let Some(route_match) = find_regex_match(&table.catch_all_regex, path)
        {
            return Some(route_match);
        }

        None
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
        let exact_count: usize = table.exact_hosts.values().map(|v| v.len()).sum();
        let wildcard_count: usize = table.wildcard_hosts.iter().map(|(_, v)| v.len()).sum();
        let exact_regex: usize = table.exact_hosts_regex.values().map(|v| v.len()).sum();
        let wildcard_regex: usize = table
            .wildcard_hosts_regex
            .iter()
            .map(|(_, v)| v.len())
            .sum();
        exact_count
            + wildcard_count
            + table.catch_all.len()
            + exact_regex
            + wildcard_regex
            + table.catch_all_regex.len()
    }

    /// Evict ~25% of prefix cache entries using counter-based pseudo-random sampling.
    fn evict_prefix_sample(&self) {
        evict_dashmap_sample(
            &self.prefix_cache,
            self.max_cache_entries,
            &self.prefix_eviction_counter,
            "prefix",
        );
    }

    /// Evict ~25% of regex cache entries using counter-based pseudo-random sampling.
    fn evict_regex_sample(&self) {
        evict_dashmap_sample(
            &self.regex_cache,
            self.max_cache_entries,
            &self.regex_eviction_counter,
            "regex",
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
    /// Prefix routes are sorted by listen_path length descending within each tier.
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
                // Auto-anchor to start of path if not already anchored
                let anchored = if pattern_str.starts_with('^') {
                    pattern_str.to_string()
                } else {
                    format!("^{}", pattern_str)
                };
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
        for routes in exact_hosts.values_mut() {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        let mut wildcard_vec: Vec<(String, Vec<RouteEntry>)> = wildcard_hosts.into_iter().collect();
        for (_, routes) in &mut wildcard_vec {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        // Sort wildcard patterns by length descending (more-specific wildcards first)
        wildcard_vec.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        catch_all.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));

        // Sort wildcard regex hosts by pattern length descending (same ordering as prefix)
        let mut wildcard_regex_vec: Vec<(String, Vec<RegexRouteEntry>)> =
            wildcard_hosts_regex.into_iter().collect();
        wildcard_regex_vec.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let has_regex_routes = !exact_hosts_regex.is_empty()
            || !wildcard_regex_vec.is_empty()
            || !catch_all_regex.is_empty();

        HostRouteTable {
            exact_hosts,
            wildcard_hosts: wildcard_vec,
            catch_all,
            exact_hosts_regex,
            wildcard_hosts_regex: wildcard_regex_vec,
            catch_all_regex,
            has_regex_routes,
        }
    }
}

/// Find the first prefix-matching route in a pre-sorted route list.
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

/// Find the first regex-matching route in a list of regex route entries.
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

/// Evict ~25% of entries from a DashMap using counter-based pseudo-random sampling.
fn evict_dashmap_sample<V>(
    map: &DashMap<String, V>,
    max_entries: usize,
    counter: &AtomicU64,
    label: &str,
) {
    let target_removals = max_entries / 4;
    let seed = counter.fetch_add(1, Ordering::Relaxed);
    let mut removed = 0;

    let mut keep_count = 0u64;
    map.retain(|_, _| {
        if removed >= target_removals {
            return true;
        }
        keep_count += 1;
        if (keep_count.wrapping_mul(seed.wrapping_add(7))).is_multiple_of(4) {
            removed += 1;
            false
        } else {
            true
        }
    });

    debug!(
        "Router {} cache evicted {} entries (was at capacity {})",
        label, removed, max_entries
    );
}

/// Build a cache key from host and path.
/// Uses NUL separator which cannot appear in hostnames or URL paths.
fn make_cache_key(host: Option<&str>, path: &str) -> String {
    match host {
        Some(h) => format!("{}\0{}", h, path),
        None => format!("\0{}", path),
    }
}
