//! Router cache for high-performance proxy route lookups.
//!
//! Pre-sorts routes by listen_path length (longest first) at config load time,
//! with two-tier host+path matching: exact host → wildcard host → catch-all.
//! Within each host tier, literal exact-path routes are checked first, then
//! prefix routes, then regex routes.
//!
//! Caches (host, path) → proxy lookups in a bounded DashMap for O(1) repeated hits.
//! Regex route matches use a separate cache partition to prevent high-cardinality
//! regex paths (e.g., UUID segments) from evicting prefix route cache entries.
//! Route table rebuilds happen atomically via ArcSwap when config changes —
//! never on the hot request path.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use regex::{Regex, RegexSet};
use std::borrow::Cow;
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

/// How [`RouterCache::search_route_table`] treats direction-scoped materialized
/// mesh routes (`__mesh-inbound-*` / `__mesh-outbound-*`). The inbound and
/// outbound capture listeners share one route table, so the slow path filters by
/// the request's listener direction.
#[derive(Clone, Copy)]
enum MeshRouteDirectionFilter {
    /// Admit all routes regardless of direction — the cached fast path. The
    /// request handler re-resolves with `MatchingDirection` only if the cached
    /// winner turns out to be a wrong-direction mesh route.
    Unfiltered,
    /// Admit non-mesh routes plus mesh routes whose direction equals this
    /// request's listener direction (`None` ⇒ a non-mesh listener, which admits
    /// no direction-scoped mesh route).
    MatchingDirection(Option<crate::modes::mesh::MeshTrafficDirection>),
}

/// Result of a route match, containing the matched proxy and any extracted path parameters.
#[derive(Clone, Debug)]
pub struct RouteMatch {
    pub proxy: Arc<Proxy>,
    /// Extracted named path parameters from regex routes. Empty for prefix routes.
    pub path_params: Vec<(String, String)>,
    /// Length of the path prefix consumed by the match (for `strip_listen_path`).
    /// For prefix routes: `listen_path.len()`. For exact/regex routes: matched path length.
    pub matched_prefix_len: usize,
}

/// A pre-sorted route entry for longest-prefix matching.
struct RouteEntry {
    listen_path: String,
    proxy: Arc<Proxy>,
}

/// Literal exact-path routes with O(1) lookup.
struct IndexedExactPathRoutes {
    path_index: HashMap<String, Arc<Proxy>>,
}

/// A collection of prefix routes with both sorted Vec (for fallback) and
/// HashMap index (for O(path_depth) lookup instead of O(n_routes) linear scan).
///
/// The HashMap maps each listen_path to its proxy, enabling rapid longest-prefix
/// matching by walking the request path backwards through segment boundaries.
/// This is the key optimization for scaling to thousands of proxies — without it,
/// every cache miss triggers a linear scan of ALL routes in the tier.
struct IndexedPrefixRoutes {
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
    regex_set: Option<RegexSet>,
}

impl IndexedRegexRoutes {
    /// Build from a list of regex route entries.
    /// The RegexSet is compiled from the same anchored patterns used by individual entries.
    fn new(entries: Vec<RegexRouteEntry>) -> Self {
        let patterns: Vec<&str> = entries.iter().map(|e| e.pattern.as_str()).collect();
        let regex_set = match RegexSet::new(&patterns) {
            Ok(set) => Some(set),
            Err(e) => {
                warn!(
                    error = %e,
                    "RegexSet compilation failed — falling back to linear regex matching"
                );
                None
            }
        };
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
/// 3. Catch-all (proxies with empty `hosts`)
///
/// Within each tier the order is:
/// a. Literal exact-path routes (`Exact` Kubernetes translations)
/// b. Prefix listen_path routes (longest-prefix matching)
/// c. Regex listen_path routes (first match in config order)
/// d. Host-only routes (`listen_path.is_none()`) — fallback catch-all for the host
///
/// Host-only routes never exist in the catch-all tier: a proxy with both
/// `hosts.is_empty()` and `listen_path.is_none()` is rejected at config validation.
pub(crate) struct HostRouteTable {
    /// Exact host → literal exact-path route entries.
    exact_hosts_exact_paths: HashMap<String, IndexedExactPathRoutes>,
    /// Exact host → indexed prefix route entries (longest listen_path first + HashMap index).
    exact_hosts: HashMap<String, IndexedPrefixRoutes>,
    /// Wildcard host → literal exact-path route entries.
    wildcard_hosts_exact_paths: Vec<(String, IndexedExactPathRoutes)>,
    /// Wildcard suffix entries, e.g., ("*.example.com", routes).
    /// Sorted by pattern length descending so more-specific wildcards match first.
    wildcard_hosts: Vec<(String, IndexedPrefixRoutes)>,
    /// Catch-all literal exact-path routes (proxies with empty `hosts`).
    catch_all_exact_paths: IndexedExactPathRoutes,
    /// Catch-all prefix routes (proxies with empty `hosts`) with HashMap index.
    catch_all: IndexedPrefixRoutes,
    /// Exact host → indexed regex route entries (RegexSet + individual patterns).
    exact_hosts_regex: HashMap<String, IndexedRegexRoutes>,
    /// Wildcard host → indexed regex route entries.
    wildcard_hosts_regex: Vec<(String, IndexedRegexRoutes)>,
    /// Catch-all regex routes with RegexSet index.
    catch_all_regex: IndexedRegexRoutes,
    /// Exact host → host-only proxy (`listen_path.is_none()`). Fallback when
    /// no prefix or regex route matches the request path under `host`.
    exact_hosts_host_only: HashMap<String, Arc<Proxy>>,
    /// Wildcard host → host-only proxy. Sorted by pattern length descending.
    wildcard_hosts_host_only: Vec<(String, Arc<Proxy>)>,
    /// Pre-computed flag: true if any exact-path routes exist.
    has_exact_path_routes: bool,
    /// Pre-computed flag: true if any regex routes exist (skip regex path entirely when false).
    has_regex_routes: bool,
    /// Pre-computed flag: true if any host-only routes exist (skip host-only path entirely when false).
    has_host_only_routes: bool,
    /// Mesh outbound per-port sibling groups, keyed by the **representative**
    /// proxy id (the lowest-port sibling — the only one inserted into the
    /// host/path tiers, since they are (host, path)-keyed and every sibling
    /// shares its service's hosts + `/`). After a representative matches on
    /// the outbound capture listener,
    /// [`HostRouteTable::select_mesh_outbound_port_route`] swaps in the
    /// sibling whose service port equals the connection's captured original
    /// destination port. Built at route-table construction; empty outside
    /// mesh mode.
    mesh_outbound_ports: HashMap<String, Arc<MeshOutboundPortGroup>>,
    /// Mesh sidecar INBOUND per-port sibling groups, keyed by the
    /// representative proxy id — the inbound mirror of `mesh_outbound_ports`.
    /// After a representative matches on the inbound listener,
    /// [`HostRouteTable::select_mesh_inbound_port_route`] swaps in the sibling
    /// matching the connection's captured original destination port (container
    /// port; REDIRECT-captured plain inbound) or the request's pre-strip
    /// authority port (service port; peer-sidecar dials). Built at route-table
    /// construction; empty outside mesh mode.
    mesh_inbound_ports: HashMap<String, Arc<MeshInboundPortGroup>>,
    /// Raw-TCP mesh egress lookup: strict `(service VIP, service port)` →
    /// relay entry, consulted by the outbound capture accept loop BEFORE the
    /// stream is handed to hyper. Built forward from the prepared `mesh`
    /// block (stream-family ports × `cluster_ips`); empty outside mesh mode.
    mesh_tcp_egress: HashMap<(std::net::IpAddr, u16), MeshTcpEgressDecision>,
}

/// One routable raw-TCP egress destination: the per-port upstream to
/// LB-select a workload from, and the synthesized relay proxy whose fields
/// drive the HBONE pool's per-proxy config, the connect budget, the copy-loop
/// timeouts, and the capability-registry key (shared with probe enrollment —
/// see `mesh_outbound_tcp_relay_proxy`).
pub(crate) struct MeshTcpEgressEntry {
    pub(crate) upstream_id: String,
    pub(crate) relay_proxy: Arc<Proxy>,
    /// The service FQDN (the upstream's DR-matchable name) for logging.
    pub(crate) service_fqdn: String,
}

/// Outcome of a raw-TCP egress lookup for a captured original destination
/// that matched a declared `(VIP, stream-family port)` pair. A captured
/// destination matching NO pair is not represented here — it falls through
/// to the HTTP path unchanged (it may be an HTTP service port on the same
/// VIP, or non-mesh traffic that was never routable before).
#[derive(Clone)]
pub(crate) enum MeshTcpEgressDecision {
    /// Relay the raw stream over HBONE to a workload of this entry.
    Relay(Arc<MeshTcpEgressEntry>),
    /// The pair is DECLARED by the slice but not routable (no upstream
    /// materialized: no reachable local-cluster workloads, unresolved named
    /// targetPort, or a topology without raw-TCP egress). Close the
    /// connection — the destination is mesh-owned, so letting it fall
    /// through to hyper would just fail confusingly later, and guessing a
    /// different port/service is forbidden.
    CloseNotRoutable,
}

/// Per-service group of mesh outbound per-port sibling routes
/// (`__mesh-outbound-{ns}-{name}-{port}`), derived from the prepared config's
/// `mesh` block by `crate::modes::mesh::mesh_outbound_service_groups`.
pub(crate) struct MeshOutboundPortGroup {
    /// HTTP-family ports the service DECLARES — may exceed `ports.len()` when
    /// a port materialized no sibling (unresolved named `targetPort`, no
    /// reachable targets). Orig-dst-less requests fail closed whenever this
    /// is > 1, even for a partially materialized group: without the captured
    /// port, traffic meant for a skipped port is indistinguishable from the
    /// surviving one.
    declared_http_ports: usize,
    /// `(service_port, route)` pairs sorted by port ascending; entry 0 is the
    /// representative present in the route tiers.
    ports: Vec<(u16, Arc<Proxy>)>,
}

/// Per-service group of mesh sidecar INBOUND per-port sibling routes
/// (`__mesh-inbound-{ns}-{name}-{port}`), derived from the prepared config's
/// `mesh` block by `crate::modes::mesh::mesh_inbound_service_groups` (the
/// local-inbound service view). Each sibling routes one SERVICE port to the
/// local app's resolved CONTAINER (target) port — `proxy.backend_port` — so
/// selection matches captured original destinations against the container
/// port and authority ports against the service port.
pub(crate) struct MeshInboundPortGroup {
    /// HTTP-family ports the local service DECLARES — may exceed `ports.len()`
    /// when a port materialized no sibling (unresolved named `targetPort`).
    /// Signal-less requests fail closed whenever this is > 1, even for a
    /// partially materialized group: without a port signal, traffic meant for
    /// a skipped port is indistinguishable from the surviving one.
    declared_http_ports: usize,
    /// `(service_port, route)` pairs sorted by service port ascending; entry 0
    /// is the representative present in the route tiers.
    ports: Vec<(u16, Arc<Proxy>)>,
}

/// Why [`HostRouteTable::select_mesh_inbound_port_route`] refused to pick a
/// per-port sibling. Both cases fail closed at the request handler — inbound
/// traffic is never forwarded to a port the client did not address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeshInboundPortSelectError {
    /// The matched local service DECLARES multiple HTTP-family ports but the
    /// request carries neither a captured original destination (the dial was
    /// direct, e.g. a peer sidecar's `:15006` connection) nor an explicit
    /// `Host`/`:authority` port — the addressed port cannot be determined and
    /// must never be guessed. Applies even when only one sibling
    /// materialized (partially materialized multi-port service).
    PortSignalUnavailable,
    /// A port signal was present but matches none of the service's
    /// materialized HTTP-family siblings (orig-dst port matched no sibling's
    /// container port, or the authority port matched no sibling's service
    /// port). Forwarding it to a different port's backend would be a
    /// misroute, so it is rejected — a present-but-unmatched orig-dst never
    /// falls through to the authority port (the dialed truth outranks app
    /// baggage).
    PortNotMaterialized,
}

/// Why [`HostRouteTable::select_mesh_outbound_port_route`] refused to pick a
/// per-port sibling. Both cases fail closed at the request handler — captured
/// traffic is never forwarded to a port the client did not dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeshOutboundPortSelectError {
    /// The matched service DECLARES multiple HTTP-family ports but the
    /// connection carries no captured original destination (non-Linux, direct
    /// dial, getsockopt failure) — the dialed port cannot be determined and
    /// must never be guessed. Applies even when only one sibling
    /// materialized (partially materialized multi-port service).
    OrigDstUnavailable,
    /// The captured original destination's port is not one of the matched
    /// service's materialized HTTP-family ports.
    PortNotMaterialized,
}

impl HostRouteTable {
    /// Swap a matched mesh outbound representative route for the sibling
    /// matching the connection's captured original-destination port.
    ///
    /// Behavior matrix (see [`MeshOutboundPortGroup`]):
    /// - route not grouped (an outbound-prefixed proxy no mesh service
    ///   claims) → keep `current`;
    /// - no orig-dst and the service DECLARES exactly one HTTP-family port →
    ///   keep `current` (back-compat: single-port services never needed
    ///   orig-dst);
    /// - no orig-dst and the service declares multiple HTTP-family ports →
    ///   [`MeshOutboundPortSelectError::OrigDstUnavailable`] — even when only
    ///   one sibling materialized (a partially materialized multi-port
    ///   service must not silently absorb the skipped port's traffic);
    /// - orig-dst port matches a sibling → that sibling (same `path_params`
    ///   / `matched_prefix_len`: every sibling is the same `/` prefix route);
    /// - orig-dst port matches no sibling → [`MeshOutboundPortSelectError::PortNotMaterialized`],
    ///   even for single-port groups — the client dialed a port the mesh does
    ///   not route, and forwarding it to a different port's backend would be a
    ///   misroute.
    pub(crate) fn select_mesh_outbound_port_route(
        &self,
        current: RouteMatch,
        orig_dst_port: Option<u16>,
    ) -> Result<RouteMatch, MeshOutboundPortSelectError> {
        let Some(group) = self.mesh_outbound_ports.get(&current.proxy.id) else {
            return Ok(current);
        };
        match orig_dst_port {
            None if group.declared_http_ports == 1 => Ok(current),
            None => Err(MeshOutboundPortSelectError::OrigDstUnavailable),
            Some(port) => match group.ports.iter().find(|(p, _)| *p == port) {
                Some((_, proxy)) => Ok(RouteMatch {
                    proxy: Arc::clone(proxy),
                    path_params: current.path_params,
                    matched_prefix_len: current.matched_prefix_len,
                }),
                None => Err(MeshOutboundPortSelectError::PortNotMaterialized),
            },
        }
    }

    /// Swap a matched mesh sidecar INBOUND representative route for the
    /// sibling matching the request's port signal.
    ///
    /// Signals, in priority order (the first PRESENT signal decides — a
    /// present-but-unmatched higher-priority signal fails closed rather than
    /// falling through to a lower one):
    /// 1. `orig_dst_port` — the captured original destination of a
    ///    REDIRECT-captured plain inbound connection (a sidecar-less client
    ///    dialed the app port directly and iptables redirected it to
    ///    `:15006`). Matches the sibling's CONTAINER port
    ///    (`proxy.backend_port`); it is the dialed truth, so it outranks the
    ///    authority. Peer-sidecar dials are direct (never NATed) and carry
    ///    `None`.
    /// 2. `authority_port` — the request's pre-strip `Host`/`:authority`
    ///    port. Matches the sibling's SERVICE port; a peer sidecar's
    ///    multi-port egress rewrites the authority to carry it.
    ///
    /// Behavior matrix (see [`MeshInboundPortGroup`]):
    /// - route not grouped → keep `current`;
    /// - the service DECLARES exactly one HTTP-family port → keep `current`
    ///   unconditionally (back-compat: single-port services accept bare-Host
    ///   clients, older peers, and any explicit port today — selection adds
    ///   no new requirement to them);
    /// - multi-port with no signal at all →
    ///   [`MeshInboundPortSelectError::PortSignalUnavailable`];
    /// - multi-port with a present-but-unmatched signal →
    ///   [`MeshInboundPortSelectError::PortNotMaterialized`].
    pub(crate) fn select_mesh_inbound_port_route(
        &self,
        current: RouteMatch,
        orig_dst_port: Option<u16>,
        authority_port: Option<u16>,
    ) -> Result<RouteMatch, MeshInboundPortSelectError> {
        let Some(group) = self.mesh_inbound_ports.get(&current.proxy.id) else {
            return Ok(current);
        };
        if group.declared_http_ports == 1 {
            return Ok(current);
        }
        let selected = if let Some(container_port) = orig_dst_port {
            group
                .ports
                .iter()
                .find(|(_, proxy)| proxy.backend_port == container_port)
        } else if let Some(service_port) = authority_port {
            group.ports.iter().find(|(p, _)| *p == service_port)
        } else {
            return Err(MeshInboundPortSelectError::PortSignalUnavailable);
        };
        match selected {
            Some((_, proxy)) => Ok(RouteMatch {
                proxy: Arc::clone(proxy),
                path_params: current.path_params,
                matched_prefix_len: current.matched_prefix_len,
            }),
            None => Err(MeshInboundPortSelectError::PortNotMaterialized),
        }
    }

    /// Raw-TCP egress lookup for a captured connection's pre-NAT original
    /// destination. `None` ⇒ not a declared `(service VIP, stream-family
    /// port)` pair: fall through to the HTTP handling path unchanged.
    pub(crate) fn mesh_tcp_egress_decision(
        &self,
        orig_dst: std::net::SocketAddr,
    ) -> Option<&MeshTcpEgressDecision> {
        if self.mesh_tcp_egress.is_empty() {
            return None;
        }
        // Canonicalized so an IPv4-mapped IPv6 capture address
        // (`::ffff:a.b.c.d`) still matches the IPv4 VIP the slice declared.
        self.mesh_tcp_egress
            .get(&(orig_dst.ip().to_canonical(), orig_dst.port()))
    }
}

/// Cached regex match result (stored in regex_cache).
#[derive(Clone)]
struct RegexCacheEntry {
    proxy: Arc<Proxy>,
    path_params: Vec<(String, String)>,
    matched_len: usize,
    route_generation: u64,
}

/// Cached prefix or host-only match result.
#[derive(Clone)]
struct PrefixCacheEntry {
    proxy: Option<Arc<Proxy>>,
    route_generation: u64,
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
    /// `proxy: None` entries represent negative cache (no route matched from any tier).
    prefix_cache: DashMap<String, PrefixCacheEntry>,
    /// Bounded cache for regex route lookups: "host\0path" → match result.
    /// Separate partition prevents high-cardinality regex paths from evicting
    /// prefix cache entries. `None` entries are NOT stored here — a regex miss
    /// combined with a prefix miss produces a `None` in `prefix_cache`.
    regex_cache: DashMap<String, RegexCacheEntry>,
    /// Maximum entries in each cache partition before eviction.
    max_cache_entries: usize,
    /// Resolved DashMap shard count used by the lookup caches.
    #[cfg(test)]
    cache_shard_amount: usize,
    /// Monotonic counters for eviction tracking per partition.
    prefix_eviction_counter: AtomicU64,
    regex_eviction_counter: AtomicU64,
    /// Frequency sketch shared by both cache partitions.
    /// Tracks access frequency for frequency-aware eviction (least-frequent-of-sample).
    frequency_sketch: CountMinSketch,
    /// Route-table generation for standalone wrapper users. RequestEpoch hot
    /// paths pass their own route_generation into lookup so LB-only epochs do
    /// not invalidate route cache entries.
    route_generation: AtomicU64,
}

impl RouterCache {
    /// Build a new RouterCache from the given config.
    ///
    /// Routes are partitioned by host tier and pre-sorted by listen_path length
    /// descending so the first `starts_with` match is always the longest prefix match.
    /// Regex routes are compiled at build time, not per-request.
    ///
    /// `max_cache_entries == 0` is the documented "auto" sentinel
    /// (`FERRUM_ROUTER_CACHE_MAX_ENTRIES=0`) and is resolved here to the
    /// same bounded auto value as `ProxyState::new`: `proxies.len() * 3`
    /// clamped to `[10_000, 1_000_000]`. That keeps direct callers aligned
    /// with production env-var resolution while still getting a usable cache.
    /// Without this,
    /// `frequency_aware_evict`'s `max_entries / 4 == 0` short-circuit would leave
    /// the cache unbounded under load.
    #[allow(dead_code)]
    pub fn new(config: &GatewayConfig, max_cache_entries: usize) -> Self {
        Self::with_shard_amount(config, max_cache_entries, 0)
    }

    /// Build a new RouterCache with an explicit pool/cache shard amount.
    ///
    /// `pool_shard_amount == 0` keeps the documented auto sentinel. Non-zero
    /// values are normalized by `pool_shard_amount()` so direct callers get the
    /// same power-of-two clamping as production env config.
    pub fn with_shard_amount(
        config: &GatewayConfig,
        max_cache_entries: usize,
        pool_shard_amount: usize,
    ) -> Self {
        let max_cache_entries = if max_cache_entries == 0 {
            let resolved = resolve_auto_router_cache_entries(config.proxies.len());
            debug!(
                "Router cache max_entries=0 resolved to auto value {} (proxies={})",
                resolved,
                config.proxies.len()
            );
            resolved
        } else {
            max_cache_entries
        };
        let table = Self::build_route_table(config);
        // Sketch width: 2x cache capacity, clamped to [1024, 65536], power of two.
        let sketch_width = (max_cache_entries * 2).clamp(1024, 65536);
        // Age after cache_capacity * 4 increments to adapt to workload changes.
        let age_threshold = (max_cache_entries as u64).saturating_mul(4).max(1);
        // Pre-size the DashMap shard count alongside the per-entry capacity.
        // The router caches sit on the request hot path with high cardinality
        // (one entry per distinct host+path) and concurrent writers (each
        // tokio worker can race to insert a freshly resolved match), so the
        // dashmap default of `4 * num_cpus` shards starves on inserts at
        // scale. The helper resolves to `next_power_of_two(max(64,
        // num_cpus * 16))` — see `crate::util::sharding`.
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_amount);
        Self {
            route_table: ArcSwap::new(Arc::new(table)),
            prefix_cache: DashMap::with_capacity_and_shard_amount(max_cache_entries, shards),
            regex_cache: DashMap::with_capacity_and_shard_amount(max_cache_entries / 4 + 1, shards),
            max_cache_entries,
            #[cfg(test)]
            cache_shard_amount: shards,
            prefix_eviction_counter: AtomicU64::new(0),
            regex_eviction_counter: AtomicU64::new(0),
            frequency_sketch: CountMinSketch::new(sketch_width, age_threshold),
            route_generation: AtomicU64::new(1),
        }
    }

    pub(crate) fn build_route_table_snapshot(config: &GatewayConfig) -> Arc<HostRouteTable> {
        Arc::new(Self::build_route_table(config))
    }

    pub(crate) fn store_route_table_snapshot(
        &self,
        table: Arc<HostRouteTable>,
        route_generation: u64,
    ) {
        self.route_table.store(table);
        self.route_generation
            .store(route_generation, Ordering::Release);
    }

    pub(crate) fn clear_lookup_caches(&self) {
        self.prefix_cache.clear();
        self.regex_cache.clear();
        self.frequency_sketch.reset();
    }

    /// Find the matching proxy for a request host and path.
    ///
    /// Priority order (within each host tier):
    /// 1. Literal exact-path route
    /// 2. Prefix route: longest path prefix match
    /// 3. Regex route: first pattern match (in config order)
    ///
    /// Host tiers are searched: exact host → wildcard host → catch-all.
    ///
    /// Results are cached (including misses) for O(1) repeated lookups.
    /// Prefix and regex matches use separate cache partitions.
    #[allow(dead_code)] // Library/test API; request hot paths use find_proxy_in_snapshot().
    pub fn find_proxy(&self, host: Option<&str>, path: &str) -> Option<RouteMatch> {
        let generation = self.route_generation.load(Ordering::Acquire);
        let table = self.route_table.load();
        self.find_proxy_in_snapshot(&table, generation, host, path)
    }

    pub(crate) fn find_proxy_in_snapshot(
        &self,
        table: &HostRouteTable,
        route_generation: u64,
        host: Option<&str>,
        path: &str,
    ) -> Option<RouteMatch> {
        let normalized = normalize_encoded_slashes(path);
        let path: &str = &normalized;

        // Fast path: use thread-local buffer for cache lookup to avoid String
        // allocation on cache hits (99%+ of requests). Only allocate on misses.
        let hit = CACHE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            write_cache_key(&mut buf, host, path);

            // Fast path 1: check prefix cache (includes negative entries for total misses)
            if let Some(entry) = self.prefix_cache.get(buf.as_str()) {
                let cached = entry.value();
                if cached.route_generation == route_generation {
                    self.frequency_sketch.increment(&buf);
                    return Some(cached.proxy.as_ref().map(|proxy| RouteMatch {
                        // Host-only proxies (listen_path == None) match any path and
                        // strip nothing; `matched_prefix_len` is 0. Otherwise, use
                        // the listen_path length as before.
                        matched_prefix_len: proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
                        proxy: Arc::clone(proxy),
                        path_params: Vec::new(),
                    }));
                }
            }

            // Fast path 2: check regex cache (only contains positive matches)
            if let Some(entry) = self.regex_cache.get(buf.as_str()) {
                let cached = entry.value();
                if cached.route_generation == route_generation {
                    self.frequency_sketch.increment(&buf);
                    return Some(Some(RouteMatch {
                        proxy: Arc::clone(&cached.proxy),
                        path_params: cached.path_params.clone(),
                        matched_prefix_len: cached.matched_len,
                    }));
                }
            }

            None // Cache miss — need slow path
        });

        // Unwrap the Option<Option<RouteMatch>>: Some(inner) = cache hit
        if let Some(result) = hit {
            return result;
        }

        // Slow path: search the host route table (cache miss). The normal lookup
        // never filters by direction; direction scoping is handled by the request
        // handlers via `resolve_route_excluding_wrong_direction` when the cached
        // winner turns out to be a wrong-direction mesh route.
        let result =
            Self::search_route_table(table, host, path, MeshRouteDirectionFilter::Unfiltered);

        // Allocate the cache key String only on the cold path (cache miss + insert).
        let cache_key = make_cache_key(host, path);

        // Cache the result in the appropriate partition.
        // Increment sketch on insert so the new entry starts with a frequency of 1.
        match &result {
            Some(route_match)
                if !route_match.path_params.is_empty()
                    || is_regex_proxy(&route_match.proxy)
                    || is_exact_path_proxy(&route_match.proxy) =>
            {
                // Regex/exact match → regex cache (stores matched length).
                if self.regex_cache.len() >= self.max_cache_entries
                    && !self.regex_cache.contains_key(&cache_key)
                {
                    self.evict_regex_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.regex_cache.insert(
                    cache_key,
                    RegexCacheEntry {
                        proxy: Arc::clone(&route_match.proxy),
                        path_params: route_match.path_params.clone(),
                        matched_len: route_match.matched_prefix_len,
                        route_generation,
                    },
                );
            }
            Some(route_match) => {
                // Prefix match → prefix cache
                if self.prefix_cache.len() >= self.max_cache_entries
                    && !self.prefix_cache.contains_key(&cache_key)
                {
                    self.evict_prefix_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.prefix_cache.insert(
                    cache_key,
                    PrefixCacheEntry {
                        proxy: Some(Arc::clone(&route_match.proxy)),
                        route_generation,
                    },
                );
            }
            None => {
                // Negative entry → prefix cache (both tiers missed)
                if self.prefix_cache.len() >= self.max_cache_entries
                    && !self.prefix_cache.contains_key(&cache_key)
                {
                    self.evict_prefix_sample();
                }
                self.frequency_sketch.increment(&cache_key);
                self.prefix_cache.insert(
                    cache_key,
                    PrefixCacheEntry {
                        proxy: None,
                        route_generation,
                    },
                );
            }
        }

        result
    }

    /// Search the route table for a matching proxy.
    ///
    /// Within each host tier, matching order is:
    ///   exact-path routes → prefix routes → regex routes → host-only fallback.
    /// Host tiers are searched exact → wildcard → catch-all. Catch-all has no
    /// host-only tier (validation forbids empty-hosts + no-listen-path).
    fn search_route_table(
        table: &HostRouteTable,
        host: Option<&str>,
        path: &str,
        direction_filter: MeshRouteDirectionFilter,
    ) -> Option<RouteMatch> {
        // Admit a tier's match unless it is a direction-scoped materialized mesh
        // route (`__mesh-inbound-*` / `__mesh-outbound-*`) excluded by this lookup
        // because the request's listener direction does not match the route's
        // direction. Dropping the match here lets the tiered search fall through
        // to a lower-priority valid route instead of returning a wrong-direction
        // route. A no-op (and zero-cost via short-circuit) on the normal
        // `Unfiltered` lookup path.
        let admit = |rm: &RouteMatch| match direction_filter {
            MeshRouteDirectionFilter::Unfiltered => true,
            MeshRouteDirectionFilter::MatchingDirection(req_dir) => {
                match crate::modes::mesh::mesh_route_direction(&rm.proxy.id) {
                    None => true,
                    Some(route_dir) => req_dir == Some(route_dir),
                }
            }
        };
        if let Some(host) = host {
            // 1. Exact host match — exact path, prefix, regex, then host-only
            if table.has_exact_path_routes
                && let Some(routes) = table.exact_hosts_exact_paths.get(host)
                && let Some(route_match) =
                    find_exact_path_match_indexed(routes, path).filter(|rm| admit(rm))
            {
                return Some(route_match);
            }
            if let Some(routes) = table.exact_hosts.get(host)
                && let Some(route_match) =
                    find_prefix_match_indexed(routes, path).filter(|rm| admit(rm))
            {
                return Some(route_match);
            }
            if table.has_regex_routes
                && let Some(routes) = table.exact_hosts_regex.get(host)
                && let Some(route_match) =
                    find_regex_match_indexed(routes, path).filter(|rm| admit(rm))
            {
                return Some(route_match);
            }
            if table.has_host_only_routes
                && let Some(proxy) = table.exact_hosts_host_only.get(host)
            {
                return Some(RouteMatch {
                    proxy: Arc::clone(proxy),
                    path_params: Vec::new(),
                    matched_prefix_len: 0,
                });
            }

            // 2. Wildcard host match — exact path, prefix, regex, then host-only
            if table.has_exact_path_routes {
                for (pattern, routes) in &table.wildcard_hosts_exact_paths {
                    if wildcard_matches(pattern, host)
                        && let Some(route_match) =
                            find_exact_path_match_indexed(routes, path).filter(|rm| admit(rm))
                    {
                        return Some(route_match);
                    }
                }
            }
            for (pattern, routes) in &table.wildcard_hosts {
                if wildcard_matches(pattern, host)
                    && let Some(route_match) =
                        find_prefix_match_indexed(routes, path).filter(|rm| admit(rm))
                {
                    return Some(route_match);
                }
            }
            if table.has_regex_routes {
                for (pattern, routes) in &table.wildcard_hosts_regex {
                    if wildcard_matches(pattern, host)
                        && let Some(route_match) =
                            find_regex_match_indexed(routes, path).filter(|rm| admit(rm))
                    {
                        return Some(route_match);
                    }
                }
            }
            if table.has_host_only_routes {
                for (pattern, proxy) in &table.wildcard_hosts_host_only {
                    if wildcard_matches(pattern, host) {
                        return Some(RouteMatch {
                            proxy: Arc::clone(proxy),
                            path_params: Vec::new(),
                            matched_prefix_len: 0,
                        });
                    }
                }
            }
        }

        // 3. Catch-all — exact path, prefix, then regex (no host-only tier: validation
        //    forbids empty-hosts + no-listen-path).
        if table.has_exact_path_routes
            && let Some(route_match) =
                find_exact_path_match_indexed(&table.catch_all_exact_paths, path)
                    .filter(|rm| admit(rm))
        {
            return Some(route_match);
        }
        if let Some(route_match) =
            find_prefix_match_indexed(&table.catch_all, path).filter(|rm| admit(rm))
        {
            return Some(route_match);
        }
        if table.has_regex_routes
            && let Some(route_match) =
                find_regex_match_indexed(&table.catch_all_regex, path).filter(|rm| admit(rm))
        {
            return Some(route_match);
        }

        None
    }

    /// Resolve a route while keeping only mesh routes whose direction matches the
    /// request's listener direction (`req_direction`); non-mesh routes are always
    /// admitted. Uncached slow-path lookup used by the request handlers only when
    /// the cached winner is a direction-scoped mesh route (`__mesh-inbound-*` /
    /// `__mesh-outbound-*`) that does NOT match the current listener direction:
    /// it re-resolves so a valid lower-priority route is found instead of serving
    /// a wrong-direction route or 404ing. The inbound and outbound capture
    /// listeners share one route table, so this keeps each listener serving only
    /// its own direction's materialized routes. `req_direction == None` (a
    /// non-mesh listener) excludes every direction-scoped mesh route.
    pub(crate) fn resolve_route_excluding_wrong_direction(
        &self,
        table: &HostRouteTable,
        host: Option<&str>,
        path: &str,
        req_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    ) -> Option<RouteMatch> {
        let normalized = normalize_encoded_slashes(path);
        Self::search_route_table(
            table,
            host,
            &normalized,
            MeshRouteDirectionFilter::MatchingDirection(req_direction),
        )
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
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn cache_len(&self) -> usize {
        self.prefix_cache.len()
    }

    /// Number of entries currently in the regex cache (for testing).
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn regex_cache_len(&self) -> usize {
        self.regex_cache.len()
    }

    /// Resolved DashMap shard count used by `prefix_cache` and `regex_cache`.
    #[cfg(test)]
    pub fn cache_shard_amount(&self) -> usize {
        self.cache_shard_amount
    }

    /// Number of routes in the pre-sorted route table (for testing).
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn route_count(&self) -> usize {
        let table = self.route_table.load();
        let exact_count: usize = table.exact_hosts.values().map(|v| v.path_index.len()).sum();
        let exact_path_count: usize = table
            .exact_hosts_exact_paths
            .values()
            .map(|v| v.path_index.len())
            .sum();
        let wildcard_count: usize = table
            .wildcard_hosts
            .iter()
            .map(|(_, v)| v.path_index.len())
            .sum();
        let wildcard_exact_path_count: usize = table
            .wildcard_hosts_exact_paths
            .iter()
            .map(|(_, v)| v.path_index.len())
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
            + exact_path_count
            + wildcard_count
            + wildcard_exact_path_count
            + table.catch_all_exact_paths.path_index.len()
            + table.catch_all.path_index.len()
            + exact_regex
            + wildcard_regex
            + table.catch_all_regex.entries.len()
            + table.exact_hosts_host_only.len()
            + table.wildcard_hosts_host_only.len()
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

    /// Build a pre-computed host route table from config.
    ///
    /// Partitions proxies into prefix / regex / host-only and by host tier.
    /// Prefix routes are sorted by listen_path length descending within each tier
    /// and indexed in a HashMap for O(path_depth) lookup instead of O(n) linear scan.
    /// Regex patterns are pre-compiled at build time. Host-only routes (no
    /// listen_path) are stored as the fallback tier per host.
    fn build_route_table(config: &GatewayConfig) -> HostRouteTable {
        let mut exact_hosts_exact_paths: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut exact_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard_hosts_exact_paths: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut catch_all_exact_paths: Vec<RouteEntry> = Vec::new();
        let mut catch_all: Vec<RouteEntry> = Vec::new();
        let mut exact_hosts_regex: HashMap<String, Vec<RegexRouteEntry>> = HashMap::new();
        let mut wildcard_hosts_regex: HashMap<String, Vec<RegexRouteEntry>> = HashMap::new();
        let mut catch_all_regex: Vec<RegexRouteEntry> = Vec::new();
        let mut exact_hosts_host_only: HashMap<String, Arc<Proxy>> = HashMap::new();
        let mut wildcard_hosts_host_only: HashMap<String, Arc<Proxy>> = HashMap::new();

        // ── Mesh outbound per-port sibling groups ──────────────────────────
        // The route tiers are (host, path)-keyed, so per-port outbound
        // siblings (same hosts, same `/`) would silently clobber each other.
        // Groups are derived FORWARD from the prepared config's `mesh` block
        // (`mesh_outbound_service_groups` computes each service's expected
        // sibling ids and its DECLARED HTTP-port count) — never by parsing
        // ids backwards, which is lossy across the `{ns}-{name}` join and
        // could conflate distinct services. Only the lowest-port materialized
        // representative enters the tiers; the full group is registered for
        // post-match selection by captured original-destination port. An
        // outbound-prefixed proxy no mesh service claims (operator-crafted
        // edge) stays ungrouped and inserts normally. Empty outside mesh
        // mode (`config.mesh` is `None`).
        let mut mesh_outbound_ports: HashMap<String, Arc<MeshOutboundPortGroup>> = HashMap::new();
        let mut mesh_inbound_ports: HashMap<String, Arc<MeshInboundPortGroup>> = HashMap::new();
        // Non-representative siblings of BOTH directions: reachable only via
        // post-match port selection, never via the tiers.
        let mut mesh_sibling_skip_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        if let Some(mesh) = config.mesh.as_deref() {
            let group_members = |siblings: &[(u16, String)],
                                 proxies: &HashMap<&str, &Proxy>|
             -> Vec<(u16, Arc<Proxy>)> {
                let mut members: Vec<(u16, Arc<Proxy>)> = siblings
                    .iter()
                    .filter_map(|(port, id)| {
                        proxies
                            .get(id.as_str())
                            .map(|p| (*port, Arc::new((*p).clone())))
                    })
                    .collect();
                members.sort_by_key(|(port, _)| *port);
                members
            };
            let outbound_proxies: HashMap<&str, &Proxy> = config
                .proxies
                .iter()
                .filter(|p| {
                    !p.dispatch_kind.is_stream()
                        && crate::modes::mesh::is_mesh_outbound_route_id(&p.id)
                })
                .map(|p| (p.id.as_str(), p))
                .collect();
            for group in crate::modes::mesh::mesh_outbound_service_groups(mesh) {
                let members = group_members(&group.siblings, &outbound_proxies);
                if members.is_empty() {
                    continue;
                }
                let representative_id = members[0].1.id.clone();
                for (_, sibling) in members.iter().skip(1) {
                    mesh_sibling_skip_ids.insert(sibling.id.clone());
                }
                mesh_outbound_ports.insert(
                    representative_id,
                    Arc::new(MeshOutboundPortGroup {
                        declared_http_ports: group.declared_http_ports,
                        ports: members,
                    }),
                );
            }
            // Inbound mirror: same forward derivation, reading the
            // local-inbound service view (`mesh_inbound_service_groups`). The
            // synthesized HBONE relay proxy never appears in `config.proxies`,
            // so it can never be grouped here despite sharing the id prefix.
            let inbound_proxies: HashMap<&str, &Proxy> = config
                .proxies
                .iter()
                .filter(|p| {
                    !p.dispatch_kind.is_stream()
                        && crate::modes::mesh::is_mesh_inbound_route_id(&p.id)
                })
                .map(|p| (p.id.as_str(), p))
                .collect();
            for group in crate::modes::mesh::mesh_inbound_service_groups(mesh) {
                let members = group_members(&group.siblings, &inbound_proxies);
                if members.is_empty() {
                    continue;
                }
                let representative_id = members[0].1.id.clone();
                for (_, sibling) in members.iter().skip(1) {
                    mesh_sibling_skip_ids.insert(sibling.id.clone());
                }
                mesh_inbound_ports.insert(
                    representative_id,
                    Arc::new(MeshInboundPortGroup {
                        declared_http_ports: group.declared_http_ports,
                        ports: members,
                    }),
                );
            }
        }

        // ── Raw-TCP egress (VIP, port) lookup ──────────────────────────────
        // Forward-derived from the prepared `mesh` block: every declared
        // stream-family service port × every declared service VIP. Routable
        // when its per-port upstream materialized; otherwise the pair is
        // mesh-owned but unroutable and the accept loop closes it (never
        // guesses). VIPs are canonicalized so mapped-IPv6 captures match.
        let mut mesh_tcp_egress: HashMap<(std::net::IpAddr, u16), MeshTcpEgressDecision> =
            HashMap::new();
        if let Some(mesh) = config.mesh.as_deref() {
            let upstream_ids: std::collections::HashSet<&str> =
                config.upstreams.iter().map(|u| u.id.as_str()).collect();
            for service in &mesh.services {
                let tcp_ports = crate::modes::mesh::service_tcp_stream_ports(service);
                if tcp_ports.is_empty() || service.cluster_ips.is_empty() {
                    continue;
                }
                for sp in tcp_ports {
                    let upstream_id = crate::modes::mesh::mesh_outbound_tcp_upstream_id(
                        &service.namespace,
                        &service.name,
                        sp.port,
                    );
                    let decision = if upstream_ids.contains(upstream_id.as_str()) {
                        let relay_proxy =
                            Arc::new(crate::modes::mesh::mesh_outbound_tcp_relay_proxy(
                                &service.namespace,
                                &service.name,
                                sp.port,
                                &upstream_id,
                            ));
                        let service_fqdn = config
                            .upstreams
                            .iter()
                            .find(|u| u.id == upstream_id)
                            .and_then(|u| u.name.clone())
                            .unwrap_or_else(|| format!("{}.{}", service.name, service.namespace));
                        MeshTcpEgressDecision::Relay(Arc::new(MeshTcpEgressEntry {
                            upstream_id,
                            relay_proxy,
                            service_fqdn,
                        }))
                    } else {
                        MeshTcpEgressDecision::CloseNotRoutable
                    };
                    for vip in &service.cluster_ips {
                        let Ok(ip) = vip.parse::<std::net::IpAddr>() else {
                            // Config validation rejects unparseable VIPs for
                            // operator-authored slices; skip defensively.
                            continue;
                        };
                        mesh_tcp_egress
                            .entry((ip.to_canonical(), sp.port))
                            .or_insert_with(|| decision.clone());
                    }
                }
            }
        }

        for proxy in config
            .proxies
            .iter()
            .filter(|p| !p.dispatch_kind.is_stream())
        {
            // Non-representative mesh per-port siblings (both directions) are
            // reachable only via post-match port selection, never via the tiers.
            if mesh_sibling_skip_ids.contains(proxy.id.as_str()) {
                continue;
            }
            let arc_proxy = Arc::new(proxy.clone());

            let Some(listen_path) = proxy.listen_path.as_deref() else {
                // Host-only proxy: matches any path under its hosts.
                // A proxy with empty hosts AND no listen_path is rejected at
                // validation, so `proxy.hosts` is guaranteed non-empty here.
                if proxy.hosts.is_empty() {
                    warn!(
                        proxy_id = %proxy.id,
                        "Host-only proxy with empty hosts should have been rejected at validation; skipping"
                    );
                    continue;
                }
                for host in &proxy.hosts {
                    let target = if host.starts_with("*.") {
                        &mut wildcard_hosts_host_only
                    } else {
                        &mut exact_hosts_host_only
                    };
                    // `validate_unique_listen_paths` already rejects overlapping
                    // host-only proxies, so duplicate keys here shouldn't occur;
                    // if they do, first-wins matches prefix-route semantics.
                    target
                        .entry(host.clone())
                        .or_insert_with(|| Arc::clone(&arc_proxy));
                }
                continue;
            };

            if let Some(pattern_str) = listen_path.strip_prefix('~') {
                // Regex route: compile the pattern
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
            } else if let Some(exact_path) = listen_path.strip_prefix('=') {
                let add_exact_path = |target: &mut Vec<RouteEntry>, proxy: &Arc<Proxy>| {
                    target.push(RouteEntry {
                        listen_path: exact_path.to_string(),
                        proxy: Arc::clone(proxy),
                    });
                };

                if proxy.hosts.is_empty() {
                    add_exact_path(&mut catch_all_exact_paths, &arc_proxy);
                } else {
                    for host in &proxy.hosts {
                        let entry = RouteEntry {
                            listen_path: exact_path.to_string(),
                            proxy: Arc::clone(&arc_proxy),
                        };
                        if host.starts_with("*.") {
                            wildcard_hosts_exact_paths
                                .entry(host.clone())
                                .or_default()
                                .push(entry);
                        } else {
                            exact_hosts_exact_paths
                                .entry(host.clone())
                                .or_default()
                                .push(entry);
                        }
                    }
                }
            } else {
                // Prefix route (existing behavior)
                if proxy.hosts.is_empty() {
                    catch_all.push(RouteEntry {
                        listen_path: listen_path.to_string(),
                        proxy: Arc::clone(&arc_proxy),
                    });
                } else {
                    for host in &proxy.hosts {
                        let entry = RouteEntry {
                            listen_path: listen_path.to_string(),
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
            routes.sort_by_key(|b| std::cmp::Reverse(b.listen_path.len()));
        }
        let exact_hosts_indexed: HashMap<String, IndexedPrefixRoutes> = exact_hosts
            .into_iter()
            .map(|(host, routes)| (host, IndexedPrefixRoutes::from_sorted(routes)))
            .collect();
        let exact_hosts_exact_path_indexed: HashMap<String, IndexedExactPathRoutes> =
            exact_hosts_exact_paths
                .into_iter()
                .map(|(host, routes)| (host, IndexedExactPathRoutes::from_entries(routes)))
                .collect();

        let mut wildcard_vec: Vec<(String, Vec<RouteEntry>)> = wildcard_hosts.into_iter().collect();
        for (_, routes) in &mut wildcard_vec {
            routes.sort_by_key(|b| std::cmp::Reverse(b.listen_path.len()));
        }
        // Sort wildcard patterns by length descending (more-specific wildcards first)
        wildcard_vec.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
        let wildcard_indexed: Vec<(String, IndexedPrefixRoutes)> = wildcard_vec
            .into_iter()
            .map(|(pattern, routes)| (pattern, IndexedPrefixRoutes::from_sorted(routes)))
            .collect();
        let mut wildcard_exact_path_vec: Vec<(String, Vec<RouteEntry>)> =
            wildcard_hosts_exact_paths.into_iter().collect();
        wildcard_exact_path_vec.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
        let wildcard_exact_path_indexed: Vec<(String, IndexedExactPathRoutes)> =
            wildcard_exact_path_vec
                .into_iter()
                .map(|(pattern, routes)| (pattern, IndexedExactPathRoutes::from_entries(routes)))
                .collect();

        catch_all.sort_by_key(|b| std::cmp::Reverse(b.listen_path.len()));
        let catch_all_indexed = IndexedPrefixRoutes::from_sorted(catch_all);
        let catch_all_exact_path_indexed =
            IndexedExactPathRoutes::from_entries(catch_all_exact_paths);

        // Build RegexSet indexes for O(1) multi-pattern matching
        let exact_hosts_regex_indexed: HashMap<String, IndexedRegexRoutes> = exact_hosts_regex
            .into_iter()
            .map(|(host, entries)| (host, IndexedRegexRoutes::new(entries)))
            .collect();

        // Sort wildcard regex hosts by pattern length descending (same ordering as prefix)
        let mut wildcard_regex_vec: Vec<(String, Vec<RegexRouteEntry>)> =
            wildcard_hosts_regex.into_iter().collect();
        wildcard_regex_vec.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
        let wildcard_regex_indexed: Vec<(String, IndexedRegexRoutes)> = wildcard_regex_vec
            .into_iter()
            .map(|(pattern, entries)| (pattern, IndexedRegexRoutes::new(entries)))
            .collect();

        let catch_all_regex_indexed = IndexedRegexRoutes::new(catch_all_regex);

        let has_regex_routes = !exact_hosts_regex_indexed.is_empty()
            || !wildcard_regex_indexed.is_empty()
            || !catch_all_regex_indexed.is_empty();
        let has_exact_path_routes = !exact_hosts_exact_path_indexed.is_empty()
            || !wildcard_exact_path_indexed.is_empty()
            || !catch_all_exact_path_indexed.is_empty();

        // Sort wildcard host-only entries by pattern length descending so
        // more-specific wildcards match first (same ordering as wildcard_hosts).
        let mut wildcard_host_only_vec: Vec<(String, Arc<Proxy>)> =
            wildcard_hosts_host_only.into_iter().collect();
        wildcard_host_only_vec.sort_by_key(|(host, _)| std::cmp::Reverse(host.len()));

        let has_host_only_routes =
            !exact_hosts_host_only.is_empty() || !wildcard_host_only_vec.is_empty();

        HostRouteTable {
            exact_hosts_exact_paths: exact_hosts_exact_path_indexed,
            exact_hosts: exact_hosts_indexed,
            wildcard_hosts_exact_paths: wildcard_exact_path_indexed,
            wildcard_hosts: wildcard_indexed,
            catch_all_exact_paths: catch_all_exact_path_indexed,
            catch_all: catch_all_indexed,
            exact_hosts_regex: exact_hosts_regex_indexed,
            wildcard_hosts_regex: wildcard_regex_indexed,
            catch_all_regex: catch_all_regex_indexed,
            exact_hosts_host_only,
            wildcard_hosts_host_only: wildcard_host_only_vec,
            has_exact_path_routes,
            has_regex_routes,
            has_host_only_routes,
            mesh_outbound_ports,
            mesh_inbound_ports,
            mesh_tcp_egress,
        }
    }
}

impl IndexedExactPathRoutes {
    fn from_entries(entries: Vec<RouteEntry>) -> Self {
        let path_index = entries
            .iter()
            .map(|entry| (entry.listen_path.clone(), Arc::clone(&entry.proxy)))
            .collect();
        Self { path_index }
    }

    fn is_empty(&self) -> bool {
        self.path_index.is_empty()
    }
}

impl IndexedPrefixRoutes {
    /// Build from a pre-sorted Vec<RouteEntry> (must already be sorted by length descending).
    fn from_sorted(sorted: Vec<RouteEntry>) -> Self {
        let path_index: HashMap<String, Arc<Proxy>> = sorted
            .iter()
            .map(|entry| (entry.listen_path.clone(), Arc::clone(&entry.proxy)))
            .collect();
        Self { path_index }
    }
}

fn find_exact_path_match_indexed(
    routes: &IndexedExactPathRoutes,
    path: &str,
) -> Option<RouteMatch> {
    if routes.path_index.is_empty() {
        return None;
    }

    let match_path = match path.find('?') {
        Some(pos) => &path[..pos],
        None => path,
    };
    routes.path_index.get(match_path).map(|proxy| RouteMatch {
        proxy: Arc::clone(proxy),
        path_params: Vec::new(),
        matched_prefix_len: match_path.len(),
    })
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

    None
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

    let (entry, captures) = if let Some(regex_set) = &routes.regex_set {
        // O(1) amortized: single DFA pass tests all patterns simultaneously
        let matches = regex_set.matches(path);
        // First matching index preserves config-order semantics (first-match-wins)
        let winner_idx = matches.iter().next()?;
        let entry = &routes.entries[winner_idx];
        // Only run captures() on the single winning pattern
        let captures = entry.pattern.captures(path)?;
        (entry, captures)
    } else {
        // Fallback preserves route behavior when aggregate RegexSet compilation fails.
        let (entry, captures) = routes
            .entries
            .iter()
            .find_map(|entry| entry.pattern.captures(path).map(|caps| (entry, caps)))?;
        (entry, captures)
    };

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

/// Check if a proxy uses a regex listen_path.
fn is_regex_proxy(proxy: &Proxy) -> bool {
    proxy
        .listen_path
        .as_deref()
        .is_some_and(|p| p.starts_with('~'))
}

fn is_exact_path_proxy(proxy: &Proxy) -> bool {
    proxy
        .listen_path
        .as_deref()
        .is_some_and(|p| p.starts_with('='))
}

fn resolve_auto_router_cache_entries(proxy_count: usize) -> usize {
    proxy_count.saturating_mul(3).clamp(10_000, 1_000_000)
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

/// Normalizes percent-encoded slashes in a URL path for route matching.
///
/// Converts `%2F`/`%2f` (single-encoded) and `%252F`/`%252f` (double-encoded)
/// to literal `/` so that encoded slashes cannot bypass prefix-based route
/// matching and auth policies. Returns the input unchanged (zero allocation)
/// when no encoded slashes are present.
///
/// Paired with `contains_encoded_slash` in `src/config/types.rs`, which
/// rejects the same encodings in configured `listen_path` values so that
/// admission and runtime lookup share the same canonical alphabet. The two
/// functions must be extended together if additional encodings are added.
///
/// Also used by the backend-URL builders (`build_backend_url_with_target` /
/// `build_websocket_backend_url_with_target`) to strip the listen-path prefix
/// in the SAME coordinate system the router used to compute the offset, so the
/// slice can never land mid-codepoint or desync routing from forwarding.
pub(crate) fn normalize_encoded_slashes(path: &str) -> Cow<'_, str> {
    if !path.as_bytes().contains(&b'%') {
        return Cow::Borrowed(path);
    }

    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut modified = false;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Double-encoded slash: %252F / %252f (5 bytes)
            if i + 4 < bytes.len()
                && bytes[i + 1] == b'2'
                && bytes[i + 2] == b'5'
                && bytes[i + 3] == b'2'
                && matches!(bytes[i + 4], b'F' | b'f')
            {
                out.push(b'/');
                i += 5;
                modified = true;
                continue;
            }
            // Single-encoded slash: %2F / %2f (3 bytes)
            if i + 2 < bytes.len() && bytes[i + 1] == b'2' && matches!(bytes[i + 2], b'F' | b'f') {
                out.push(b'/');
                i += 3;
                modified = true;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    if modified {
        // Input was valid UTF-8 and we only replaced ASCII percent-sequences
        // with ASCII '/'; the result is guaranteed valid UTF-8.
        match String::from_utf8(out) {
            Ok(s) => Cow::Owned(s),
            Err(_) => Cow::Borrowed(path),
        }
    } else {
        Cow::Borrowed(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CountMinSketch tests ────────────────────────────────────────────

    #[test]
    fn cms_new_starts_at_zero() {
        let cms = CountMinSketch::new(64, 1000);
        assert_eq!(cms.estimate("any-key"), 0);
        assert_eq!(cms.total_increments.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cms_increment_returns_post_increment_count() {
        let cms = CountMinSketch::new(64, 1000);
        assert_eq!(cms.increment("key-a"), 1);
        assert_eq!(cms.increment("key-a"), 2);
        assert_eq!(cms.increment("key-a"), 3);
    }

    #[test]
    fn cms_estimate_matches_increment() {
        let cms = CountMinSketch::new(64, 1000);
        cms.increment("key-a");
        cms.increment("key-a");
        cms.increment("key-a");
        assert_eq!(cms.estimate("key-a"), 3);
    }

    #[test]
    fn cms_different_keys_independent() {
        let cms = CountMinSketch::new(1024, 100_000);
        for _ in 0..10 {
            cms.increment("hot-key");
        }
        cms.increment("cold-key");

        assert_eq!(cms.estimate("hot-key"), 10);
        assert_eq!(cms.estimate("cold-key"), 1);
    }

    #[test]
    fn cms_saturates_at_255() {
        let cms = CountMinSketch::new(64, 100_000);
        for _ in 0..300 {
            cms.increment("saturate");
        }
        assert_eq!(cms.estimate("saturate"), 255);
        // Further increments stay at 255
        assert_eq!(cms.increment("saturate"), 255);
    }

    #[test]
    fn cms_age_halves_counters() {
        let cms = CountMinSketch::new(64, 100_000);
        for _ in 0..20 {
            cms.increment("key-a");
        }
        assert_eq!(cms.estimate("key-a"), 20);

        cms.age();
        assert_eq!(cms.estimate("key-a"), 10);

        cms.age();
        assert_eq!(cms.estimate("key-a"), 5);
    }

    #[test]
    fn cms_age_triggered_by_threshold() {
        // Set age_threshold = 10 so aging happens every 10 increments
        let cms = CountMinSketch::new(1024, 10);
        // Increment a single key 10 times — on the 10th, aging triggers
        for _ in 0..9 {
            cms.increment("key-a");
        }
        assert_eq!(cms.estimate("key-a"), 9);

        // The 10th increment: row goes 9→10, then age() halves it to 5.
        // increment() returns the PRE-age post-increment value (10).
        let val = cms.increment("key-a");
        assert_eq!(val, 10, "Return value is pre-age post-increment");

        // But estimate() now sees the aged value
        assert_eq!(
            cms.estimate("key-a"),
            5,
            "Post-age estimate should be halved"
        );
    }

    #[test]
    fn cms_reset_clears_all() {
        let cms = CountMinSketch::new(64, 1000);
        for _ in 0..50 {
            cms.increment("key-a");
        }
        assert!(cms.estimate("key-a") > 0);
        assert!(cms.total_increments.load(Ordering::Relaxed) > 0);

        cms.reset();
        assert_eq!(cms.estimate("key-a"), 0);
        assert_eq!(cms.total_increments.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cms_width_rounds_to_power_of_two() {
        let cms = CountMinSketch::new(100, 1000);
        // 100 rounds up to 128, so width_mask = 127
        assert_eq!(cms.width_mask, 127);
    }

    // ── frequency_aware_evict tests ─────────────────────────────────────

    #[test]
    fn evict_removes_low_frequency_entries() {
        let sketch = CountMinSketch::new(1024, 100_000);
        let map: DashMap<String, ()> = DashMap::new();

        // Insert entries with varying frequencies
        for i in 0..100 {
            let key = format!("key-{}", i);
            map.insert(key.clone(), ());
            // Keys 0-49 get 1 hit, keys 50-99 get 20 hits
            if i >= 50 {
                for _ in 0..20 {
                    sketch.increment(&key);
                }
            } else {
                sketch.increment(&key);
            }
        }

        let removed = frequency_aware_evict(&map, &sketch, 100);
        assert!(removed > 0, "Should have evicted some entries");
        assert!(map.len() < 100, "Map should be smaller after eviction");

        // High-frequency keys should be more likely to survive
        let mut high_freq_surviving = 0;
        for i in 50..100 {
            if map.contains_key(&format!("key-{}", i)) {
                high_freq_surviving += 1;
            }
        }
        let mut low_freq_surviving = 0;
        for i in 0..50 {
            if map.contains_key(&format!("key-{}", i)) {
                low_freq_surviving += 1;
            }
        }
        assert!(
            high_freq_surviving > low_freq_surviving,
            "High-freq keys ({}) should survive more than low-freq keys ({})",
            high_freq_surviving,
            low_freq_surviving
        );
    }

    #[test]
    fn evict_empty_map_is_noop() {
        let sketch = CountMinSketch::new(64, 1000);
        let map: DashMap<String, ()> = DashMap::new();
        let removed = frequency_aware_evict(&map, &sketch, 100);
        assert_eq!(removed, 0);
    }

    #[test]
    fn evict_very_small_capacity_is_noop() {
        // target_removals = max_entries / 4 = 3 / 4 = 0
        let sketch = CountMinSketch::new(64, 1000);
        let map: DashMap<String, ()> = DashMap::new();
        map.insert("a".into(), ());
        let removed = frequency_aware_evict(&map, &sketch, 3);
        assert_eq!(removed, 0);
    }

    // ── RouterCache::new auto-resolution tests ──────────────────────────
    //
    // FERRUM_ROUTER_CACHE_MAX_ENTRIES=0 is the documented "auto" sentinel.
    // Harden `new` itself so direct callers (tests, future refactors) can't
    // end up with an effectively unbounded cache — `frequency_aware_evict`
    // returns 0 when `max_entries / 4 == 0`.

    fn minimal_proxy_for_routing(id: &str, listen_path: &str) -> Proxy {
        use crate::config::types::{
            AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResponseBodyMode,
        };
        let now = chrono::Utc::now();
        Proxy {
            id: id.to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some(listen_path.to_string()),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "backend.test".to_string(),
            backend_port: 80,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5_000,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            pool_max_requests_per_connection: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn config_with_n_proxies(n: usize) -> GatewayConfig {
        let proxies = (0..n)
            .map(|i| minimal_proxy_for_routing(&format!("p{i}"), &format!("/p{i}")))
            .collect();
        GatewayConfig {
            proxies,
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn resolve_route_excluding_wrong_direction_scopes_mesh_routes_by_listener() {
        use crate::modes::mesh::MeshTrafficDirection;
        // A materialized mesh route is served ONLY on its own direction's
        // listener. The inbound and outbound capture listeners share one route
        // table; the slow-path resolver drops a route whose direction does not
        // match the request's listener direction (and a non-mesh `None` listener
        // — e.g. the H3 frontend — drops every direction-scoped mesh route),
        // falling through to whatever lower-priority route remains (here, none).
        let mut outbound = minimal_proxy_for_routing("__mesh-outbound-default-ratings-8080", "/");
        outbound.hosts = vec!["ratings".to_string()];
        let config = GatewayConfig {
            proxies: vec![outbound],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        // Outbound listener: the outbound route is served.
        let outb = cache
            .resolve_route_excluding_wrong_direction(
                &table,
                Some("ratings"),
                "/",
                Some(MeshTrafficDirection::Outbound),
            )
            .expect("outbound listener serves the outbound route");
        assert_eq!(outb.proxy.id, "__mesh-outbound-default-ratings-8080");
        // Inbound listener and non-mesh (H3) listener: wrong direction → dropped.
        assert!(
            cache
                .resolve_route_excluding_wrong_direction(
                    &table,
                    Some("ratings"),
                    "/",
                    Some(MeshTrafficDirection::Inbound),
                )
                .is_none(),
            "an outbound route must not serve on the inbound listener"
        );
        assert!(
            cache
                .resolve_route_excluding_wrong_direction(&table, Some("ratings"), "/", None)
                .is_none(),
            "a non-mesh listener serves no direction-scoped mesh route"
        );

        // The inbound prefix is the mirror image: served on the inbound listener,
        // dropped on the outbound listener.
        let mut inbound = minimal_proxy_for_routing("__mesh-inbound-default-reviews-8080", "/");
        inbound.hosts = vec!["reviews".to_string()];
        let config = GatewayConfig {
            proxies: vec![inbound],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();
        assert_eq!(
            cache
                .resolve_route_excluding_wrong_direction(
                    &table,
                    Some("reviews"),
                    "/",
                    Some(MeshTrafficDirection::Inbound),
                )
                .expect("inbound listener serves the inbound route")
                .proxy
                .id,
            "__mesh-inbound-default-reviews-8080"
        );
        assert!(
            cache
                .resolve_route_excluding_wrong_direction(
                    &table,
                    Some("reviews"),
                    "/",
                    Some(MeshTrafficDirection::Outbound),
                )
                .is_none(),
            "an inbound route must not serve on the outbound listener"
        );
    }

    /// Build the mesh block the router derives sibling groups from: one
    /// service per entry, `(namespace, name, declared HTTP ports)`.
    fn mesh_block(
        services: &[(&str, &str, &[u16])],
    ) -> Option<Box<crate::modes::mesh::config::MeshConfig>> {
        use crate::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
        Some(Box::new(MeshConfig {
            services: services
                .iter()
                .map(|(namespace, name, ports)| MeshService {
                    cluster_ips: Vec::new(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    ports: ports
                        .iter()
                        .map(|port| ServicePort {
                            port: *port,
                            protocol: AppProtocol::Http,
                            name: None,
                            target_port: None,
                        })
                        .collect(),
                    workloads: Vec::new(),
                    protocol_overrides: std::collections::HashMap::new(),
                })
                .collect(),
            ..MeshConfig::default()
        }))
    }

    /// Multi-port outbound siblings: one lowest-port representative in the
    /// tiers, the rest reachable only via orig-dst-port selection. Groups are
    /// derived from the config's `mesh` block, not from id parsing.
    #[test]
    fn mesh_outbound_port_group_selects_sibling_by_orig_dst_port() {
        let mut proxies = Vec::new();
        for port in [8080u16, 80, 90] {
            let mut p =
                minimal_proxy_for_routing(&format!("__mesh-outbound-default-reviews-{port}"), "/");
            p.hosts = vec!["reviews".to_string()];
            proxies.push(p);
        }
        let config = GatewayConfig {
            proxies,
            mesh: mesh_block(&[("default", "reviews", &[80, 90, 8080])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        // The tiers hold exactly the lowest-port representative — including on
        // a cached second lookup (selection is post-cache, per request).
        for _ in 0..2 {
            let rm = cache
                .find_proxy(Some("reviews"), "/")
                .expect("representative route matches by host");
            assert_eq!(rm.proxy.id, "__mesh-outbound-default-reviews-80");
        }

        // Orig-dst port picks each sibling (including the representative).
        for port in [80u16, 90, 8080] {
            let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
            let selected = table
                .select_mesh_outbound_port_route(rm, Some(port))
                .expect("materialized port selects its sibling");
            assert_eq!(
                selected.proxy.id,
                format!("__mesh-outbound-default-reviews-{port}")
            );
        }

        // A captured port the slice does not materialize fails closed.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_outbound_port_route(rm, Some(7777)),
            Err(MeshOutboundPortSelectError::PortNotMaterialized)
        ));

        // No orig-dst on a multi-port group: the dialed port is unknowable —
        // fail closed, never guess a port.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_outbound_port_route(rm, None),
            Err(MeshOutboundPortSelectError::OrigDstUnavailable)
        ));
    }

    /// Single-port services keep their orig-dst-free behavior (direct dials,
    /// non-Linux), but a present orig-dst port still must match.
    #[test]
    fn mesh_outbound_single_port_group_without_orig_dst_keeps_route() {
        let mut p = minimal_proxy_for_routing("__mesh-outbound-default-ratings-8080", "/");
        p.hosts = vec!["ratings".to_string()];
        let config = GatewayConfig {
            proxies: vec![p],
            mesh: mesh_block(&[("default", "ratings", &[8080])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
        let kept = table
            .select_mesh_outbound_port_route(rm, None)
            .expect("single-port group needs no orig-dst");
        assert_eq!(kept.proxy.id, "__mesh-outbound-default-ratings-8080");

        let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
        assert!(
            table
                .select_mesh_outbound_port_route(rm, Some(8080))
                .is_ok(),
            "matching orig-dst port keeps the route"
        );

        let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_outbound_port_route(rm, Some(99)),
                Err(MeshOutboundPortSelectError::PortNotMaterialized)
            ),
            "a captured dial to a non-materialized port must not be forwarded \
             to a different port's backend"
        );
    }

    /// A partially materialized multi-port service (one declared HTTP port
    /// produced no sibling — unresolved named targetPort / no targets) must
    /// STILL require orig-dst: without the captured port, traffic meant for
    /// the skipped port is indistinguishable from the surviving one.
    #[test]
    fn mesh_outbound_partially_materialized_multi_port_requires_orig_dst() {
        // The service declares HTTP ports 80 + 90, but only 80 materialized.
        let mut p = minimal_proxy_for_routing("__mesh-outbound-default-reviews-80", "/");
        p.hosts = vec!["reviews".to_string()];
        let config = GatewayConfig {
            proxies: vec![p],
            mesh: mesh_block(&[("default", "reviews", &[80, 90])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_outbound_port_route(rm, None),
                Err(MeshOutboundPortSelectError::OrigDstUnavailable)
            ),
            "a declared-multi-port service with one materialized sibling must not \
             absorb orig-dst-less traffic"
        );

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            table.select_mesh_outbound_port_route(rm, Some(80)).is_ok(),
            "the surviving port still routes with a captured orig-dst"
        );

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_outbound_port_route(rm, Some(90)),
                Err(MeshOutboundPortSelectError::PortNotMaterialized)
            ),
            "the skipped declared port fails closed instead of misrouting to port 80"
        );
    }

    /// An outbound-prefixed proxy no mesh service claims (operator-crafted
    /// edge, or no mesh block at all) is not grouped: it inserts normally and
    /// selection is a no-op on it.
    #[test]
    fn mesh_outbound_unclaimed_reserved_prefix_is_not_grouped() {
        let mut p = minimal_proxy_for_routing("__mesh-outbound-oddball", "/");
        p.hosts = vec!["oddball".to_string()];
        let config = GatewayConfig {
            proxies: vec![p],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let rm = cache.find_proxy(Some("oddball"), "/").expect("route");
        let kept = table
            .select_mesh_outbound_port_route(rm, Some(12345))
            .expect("unclaimed reserved-prefix route passes through selection");
        assert_eq!(kept.proxy.id, "__mesh-outbound-oddball");
    }

    /// Sibling groups must not leak across services — including the lossy
    /// `{ns}-{name}` join collision (ns `a` / svc `b-c` vs ns `a-b` / svc
    /// `c`): forward derivation from the mesh block keeps both services
    /// independently routable instead of conflating them into one group.
    #[test]
    fn mesh_outbound_port_groups_are_per_service() {
        let mut a80 = minimal_proxy_for_routing("__mesh-outbound-default-reviews-80", "/");
        a80.hosts = vec!["reviews".to_string()];
        let mut a90 = minimal_proxy_for_routing("__mesh-outbound-default-reviews-90", "/");
        a90.hosts = vec!["reviews".to_string()];
        let mut b = minimal_proxy_for_routing("__mesh-outbound-default-ratings-9080", "/");
        b.hosts = vec!["ratings".to_string()];
        // Lossy-join collision pair: their ids share the joined `{ns}-{name}`
        // text, but they are distinct services with distinct hosts.
        let mut c1 = minimal_proxy_for_routing("__mesh-outbound-a-b-c-80", "/");
        c1.hosts = vec!["b-c.a.svc.cluster.local".to_string()];
        let mut c2 = minimal_proxy_for_routing("__mesh-outbound-a-b-c-90", "/");
        c2.hosts = vec!["c.a-b.svc.cluster.local".to_string()];
        let config = GatewayConfig {
            proxies: vec![a80, a90, b, c1, c2],
            mesh: mesh_block(&[
                ("default", "reviews", &[80, 90]),
                ("default", "ratings", &[9080]),
                ("a", "b-c", &[80]),
                ("a-b", "c", &[90]),
            ]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_outbound_port_route(rm, Some(80)),
                Err(MeshOutboundPortSelectError::PortNotMaterialized)
            ),
            "another service's port must not select into this service's group"
        );
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let selected = table
            .select_mesh_outbound_port_route(rm, Some(90))
            .expect("own port selects");
        assert_eq!(selected.proxy.id, "__mesh-outbound-default-reviews-90");

        // Both collision-pair services stay routable under their own hosts —
        // a backwards id parse would have grouped them and dropped one from
        // the tiers entirely.
        let rm = cache
            .find_proxy(Some("b-c.a.svc.cluster.local"), "/")
            .expect("first collision-pair service routes");
        assert_eq!(
            table
                .select_mesh_outbound_port_route(rm, Some(80))
                .expect("own port selects")
                .proxy
                .id,
            "__mesh-outbound-a-b-c-80"
        );
        let rm = cache
            .find_proxy(Some("c.a-b.svc.cluster.local"), "/")
            .expect("second collision-pair service routes");
        assert_eq!(
            table
                .select_mesh_outbound_port_route(rm, Some(90))
                .expect("own port selects")
                .proxy
                .id,
            "__mesh-outbound-a-b-c-90"
        );
    }

    #[test]
    fn k8s_exact_path_route_precedes_prefix_catch_all() {
        let config = GatewayConfig {
            proxies: vec![
                minimal_proxy_for_routing("root-prefix", "/"),
                minimal_proxy_for_routing("exact", "=/api.v1"),
            ],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);

        let exact = cache
            .find_proxy(None, "/api.v1")
            .expect("exact path should match");
        assert_eq!(exact.proxy.id, "exact");

        let exact_with_query = cache
            .find_proxy(None, "/api.v1?debug=true")
            .expect("exact path should ignore query string");
        assert_eq!(exact_with_query.proxy.id, "exact");

        let child = cache
            .find_proxy(None, "/api.v1/users")
            .expect("child path should fall back to prefix");
        assert_eq!(child.proxy.id, "root-prefix");
    }

    #[test]
    fn noncapturing_group_regex_routes_stay_in_regex_tier() {
        let config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("regex", "~(?:/api|/admin)")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);

        let api = cache
            .find_proxy(None, "/api")
            .expect("non-capturing group regex should match /api");
        assert_eq!(api.proxy.id, "regex");

        let admin = cache
            .find_proxy(None, "/admin")
            .expect("non-capturing group regex should match /admin");
        assert_eq!(admin.proxy.id, "regex");
    }

    #[test]
    fn replacing_stale_prefix_entry_does_not_evict_unrelated_cache_entries() {
        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old", "/api")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&old_config, 4);

        for path in ["/api/a", "/api/b", "/api/c", "/api/d"] {
            let matched = cache
                .find_proxy(None, path)
                .expect("old route should match");
            assert_eq!(matched.proxy.id, "old");
        }
        let before = cache.cache_stats();
        assert_eq!(before.0, 4);
        assert_eq!(before.2, 0);

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new", "/api")],
            ..GatewayConfig::default()
        };
        let new_table = RouterCache::build_route_table_snapshot(&new_config);
        let matched = cache
            .find_proxy_in_snapshot(&new_table, 2, None, "/api/a")
            .expect("new route should match");
        assert_eq!(matched.proxy.id, "new");

        let after = cache.cache_stats();
        assert_eq!(after.0, 4);
        assert_eq!(
            after.2, before.2,
            "replacing the same stale prefix key should not evict another entry"
        );
    }

    #[test]
    fn replacing_stale_regex_entry_does_not_evict_unrelated_cache_entries() {
        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old-regex", "~/item/[0-9]+")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&old_config, 4);

        for path in ["/item/1", "/item/2", "/item/3", "/item/4"] {
            let matched = cache
                .find_proxy(None, path)
                .expect("old regex should match");
            assert_eq!(matched.proxy.id, "old-regex");
        }
        let before = cache.cache_stats();
        assert_eq!(before.1, 4);
        assert_eq!(before.3, 0);

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new-regex", "~/item/[0-9]+")],
            ..GatewayConfig::default()
        };
        let new_table = RouterCache::build_route_table_snapshot(&new_config);
        let matched = cache
            .find_proxy_in_snapshot(&new_table, 2, None, "/item/1")
            .expect("new regex should match");
        assert_eq!(matched.proxy.id, "new-regex");

        let after = cache.cache_stats();
        assert_eq!(after.1, 4);
        assert_eq!(
            after.3, before.3,
            "replacing the same stale regex key should not evict another entry"
        );
    }

    #[test]
    fn new_resolves_zero_max_entries_to_auto_floor() {
        // 5 proxies × 3 = 15, well below the 10_000 floor — must clamp up.
        let config = config_with_n_proxies(5);
        let cache = RouterCache::new(&config, 0);
        let max_entries = cache.cache_stats().4;
        assert!(
            max_entries >= 10_000,
            "max_entries should be at least 10_000 when caller passes 0, got {}",
            max_entries
        );
    }

    #[test]
    fn new_resolves_zero_max_entries_scales_with_proxies() {
        // 5_000 proxies × 3 = 15_000, exceeds the 10_000 floor.
        let config = config_with_n_proxies(5_000);
        let cache = RouterCache::new(&config, 0);
        let max_entries = cache.cache_stats().4;
        assert_eq!(
            max_entries, 15_000,
            "max_entries should be max(10_000, proxies*3) = 15_000"
        );
    }

    #[test]
    fn auto_max_entries_caps_at_production_ceiling() {
        assert_eq!(resolve_auto_router_cache_entries(333_334), 1_000_000);
        assert_eq!(resolve_auto_router_cache_entries(usize::MAX), 1_000_000);
    }

    #[test]
    fn new_keeps_explicit_nonzero_max_entries() {
        // Explicit values must NOT be overridden by auto-resolution, even when
        // they are well below the auto floor.
        let config = config_with_n_proxies(5);
        let cache = RouterCache::new(&config, 5_000);
        assert_eq!(cache.cache_stats().4, 5_000);
    }

    #[test]
    fn new_defaults_cache_shards_to_auto_value() {
        let config = config_with_n_proxies(5);
        let cache = RouterCache::new(&config, 5_000);
        assert_eq!(
            cache.cache_shard_amount(),
            crate::util::sharding::pool_shard_amount(0)
        );
    }

    #[test]
    fn with_shard_amount_uses_configured_cache_shards() {
        let config = config_with_n_proxies(5);
        let cache = RouterCache::with_shard_amount(&config, 5_000, 256);
        assert_eq!(cache.cache_shard_amount(), 256);
    }

    #[test]
    fn with_shard_amount_normalizes_cache_shards() {
        let config = config_with_n_proxies(5);
        let cache = RouterCache::with_shard_amount(&config, 5_000, 3);
        assert_eq!(cache.cache_shard_amount(), 4);
    }

    // ── normalize_encoded_slashes tests ─────────────────────────────────

    #[test]
    fn encoded_slash_no_percent_unchanged() {
        let result = normalize_encoded_slashes("/api/admin");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "/api/admin");
    }

    #[test]
    fn encoded_slash_single_lower() {
        assert_eq!(normalize_encoded_slashes("/api%2fadmin"), "/api/admin");
    }

    #[test]
    fn encoded_slash_single_upper() {
        assert_eq!(normalize_encoded_slashes("/api%2Fadmin"), "/api/admin");
    }

    #[test]
    fn encoded_slash_double_lower() {
        assert_eq!(normalize_encoded_slashes("/api%252fadmin"), "/api/admin");
    }

    #[test]
    fn encoded_slash_double_upper() {
        assert_eq!(normalize_encoded_slashes("/api%252Fadmin"), "/api/admin");
    }

    #[test]
    fn encoded_slash_multiple() {
        assert_eq!(normalize_encoded_slashes("/a%2Fb%2fc%252Fd"), "/a/b/c/d");
    }

    #[test]
    fn encoded_slash_other_percent_unchanged() {
        let result = normalize_encoded_slashes("/api%20name");
        assert_eq!(result, "/api%20name");
    }

    #[test]
    fn encoded_slash_trailing_percent_safe() {
        assert_eq!(normalize_encoded_slashes("/api%"), "/api%");
        assert_eq!(normalize_encoded_slashes("/api%2"), "/api%2");
    }

    #[test]
    fn encoded_slash_empty_path() {
        assert_eq!(normalize_encoded_slashes(""), "");
    }

    /// Multi-port INBOUND siblings: representative in the tiers, post-match
    /// selection by inbound orig-dst (container port) with the authority
    /// port (service port) as the fallback signal — and a present-but-
    /// unmatched higher-priority signal failing closed, never falling
    /// through.
    #[test]
    fn mesh_inbound_port_group_selects_sibling_by_signals() {
        let mut proxies = Vec::new();
        for (service_port, container_port) in [(80u16, 8080u16), (90, 9090)] {
            let mut p = minimal_proxy_for_routing(
                &format!("__mesh-inbound-default-reviews-{service_port}"),
                "/",
            );
            p.hosts = vec!["reviews".to_string()];
            p.backend_port = container_port;
            proxies.push(p);
        }
        let config = GatewayConfig {
            proxies,
            mesh: mesh_block(&[("default", "reviews", &[80, 90])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        // Tiers hold exactly the lowest-service-port representative.
        let rm = cache
            .find_proxy(Some("reviews"), "/")
            .expect("representative route matches by host");
        assert_eq!(rm.proxy.id, "__mesh-inbound-default-reviews-80");

        // Inbound orig-dst (container port) picks each sibling.
        for (service_port, container_port) in [(80u16, 8080u16), (90, 9090)] {
            let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
            let selected = table
                .select_mesh_inbound_port_route(rm, Some(container_port), None)
                .expect("captured container port selects its sibling");
            assert_eq!(
                selected.proxy.id,
                format!("__mesh-inbound-default-reviews-{service_port}")
            );
        }

        // Authority port (service port) picks each sibling when orig-dst is
        // absent (the peer-sidecar direct-dial case).
        for service_port in [80u16, 90] {
            let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
            let selected = table
                .select_mesh_inbound_port_route(rm, None, Some(service_port))
                .expect("authority service port selects its sibling");
            assert_eq!(
                selected.proxy.id,
                format!("__mesh-inbound-default-reviews-{service_port}")
            );
        }

        // A present-but-unmatched orig-dst fails closed even when the
        // authority would have matched: the dialed truth outranks app
        // baggage and is never second-guessed.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, Some(7777), Some(80)),
            Err(MeshInboundPortSelectError::PortNotMaterialized)
        ));

        // An unmatched authority with no orig-dst fails closed.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, None, Some(7777)),
            Err(MeshInboundPortSelectError::PortNotMaterialized)
        ));

        // No signal at all on a multi-port group fails closed.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, None, None),
            Err(MeshInboundPortSelectError::PortSignalUnavailable)
        ));
    }

    /// Single-declared-port local services keep today's behavior
    /// unconditionally: bare-Host clients, older peers, and any explicit
    /// port all keep routing (selection adds no new requirement to them).
    #[test]
    fn mesh_inbound_single_port_group_keeps_route_unconditionally() {
        let mut p = minimal_proxy_for_routing("__mesh-inbound-default-ratings-8080", "/");
        p.hosts = vec!["ratings".to_string()];
        p.backend_port = 8081;
        let config = GatewayConfig {
            proxies: vec![p],
            mesh: mesh_block(&[("default", "ratings", &[8080])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        for (orig_dst, authority) in [(None, None), (None, Some(9999u16)), (Some(9999u16), None)] {
            let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
            let kept = table
                .select_mesh_inbound_port_route(rm, orig_dst, authority)
                .expect("single-port group never demands a signal");
            assert_eq!(kept.proxy.id, "__mesh-inbound-default-ratings-8080");
        }
    }

    /// A partially materialized multi-port group (one sibling skipped) still
    /// demands a signal and never absorbs the skipped port's traffic.
    #[test]
    fn mesh_inbound_partial_group_still_demands_signal() {
        let mut p = minimal_proxy_for_routing("__mesh-inbound-default-reviews-80", "/");
        p.hosts = vec!["reviews".to_string()];
        p.backend_port = 8080;
        let config = GatewayConfig {
            proxies: vec![p],
            // The service DECLARES two HTTP ports; only one materialized.
            mesh: mesh_block(&[("default", "reviews", &[80, 90])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, None, None),
            Err(MeshInboundPortSelectError::PortSignalUnavailable)
        ));

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            table
                .select_mesh_inbound_port_route(rm, None, Some(80))
                .is_ok(),
            "the surviving sibling stays addressable by its service port"
        );

        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_inbound_port_route(rm, None, Some(90)),
                Err(MeshInboundPortSelectError::PortNotMaterialized)
            ),
            "traffic for the skipped port must not be absorbed by the survivor"
        );
    }

    /// Raw-TCP egress lookup: strict (VIP, port) matching, mapped-IPv6
    /// canonicalization, fail-closed for declared-but-unroutable pairs, and
    /// fallthrough (`None`) for everything else.
    #[test]
    fn mesh_tcp_egress_table_routes_by_vip_and_port() {
        use crate::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
        let service = MeshService {
            name: "redis".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 6379,
                protocol: AppProtocol::Redis,
                name: Some("redis".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: std::collections::HashMap::new(),
            cluster_ips: vec!["10.96.0.1".to_string()],
        };
        let upstream: crate::config::types::Upstream = serde_json::from_value(serde_json::json!({
            "id": "__mesh-out-tcp-upstream-default-redis-6379",
            "name": "redis.default.svc.cluster.local",
            "targets": [{"host": "10.0.0.5", "port": 6379}],
        }))
        .expect("upstream deserializes");
        let config = GatewayConfig {
            upstreams: vec![upstream],
            mesh: Some(Box::new(MeshConfig {
                services: vec![service.clone()],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();

        let decision =
            |addr: &str| table.mesh_tcp_egress_decision(addr.parse().expect("socket addr"));

        // Exact (VIP, port) match relays through the per-port upstream.
        match decision("10.96.0.1:6379") {
            Some(MeshTcpEgressDecision::Relay(entry)) => {
                assert_eq!(
                    entry.upstream_id,
                    "__mesh-out-tcp-upstream-default-redis-6379"
                );
                assert_eq!(entry.service_fqdn, "redis.default.svc.cluster.local");
                assert_eq!(
                    entry.relay_proxy.upstream_id.as_deref(),
                    Some("__mesh-out-tcp-upstream-default-redis-6379")
                );
            }
            _ => panic!("expected Relay decision for an exact (VIP, port) match"),
        }

        // A mapped-IPv6 capture of the same IPv4 VIP still matches.
        assert!(matches!(
            decision("[::ffff:10.96.0.1]:6379"),
            Some(MeshTcpEgressDecision::Relay(_))
        ));

        // Same VIP, undeclared port: fall through to the HTTP path (it may be
        // an HTTP service port on the same VIP).
        assert!(decision("10.96.0.1:9999").is_none());
        // Same port, different IP: never matched by port number alone.
        assert!(decision("10.96.0.2:6379").is_none());

        // Declared pair whose upstream did NOT materialize: mesh-owned but
        // unroutable — close, never guess.
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![service],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table.load();
        assert!(matches!(
            table.mesh_tcp_egress_decision("10.96.0.1:6379".parse().expect("addr")),
            Some(MeshTcpEgressDecision::CloseNotRoutable)
        ));
    }
}
