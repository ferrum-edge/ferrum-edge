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
//! Route table rebuilds publish the table and its cache-validation generation as
//! one ArcSwap snapshot when config changes — never on the hot request path.

use arc_swap::ArcSwap;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use regex::{Regex, RegexSet};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use tracing::{debug, warn};

use crate::config::types::{GatewayConfig, Proxy, wildcard_matches};

thread_local! {
    /// Thread-local buffer for router cache key construction.
    /// Reused across requests on the same tokio worker thread to avoid
    /// per-lookup String allocation on cache hits (the 99%+ fast path).
    static CACHE_KEY_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(128));
}

const ROUTER_CACHE_EVICTION_SAMPLE_LIMIT: usize = 256;
const ROUTER_CACHE_EVICTION_MAX_REMOVALS: usize = 64;
/// One in every `HEAD_BLEND_PERIOD` eviction passes mixes a small rotating slice
/// of resident keys into the reservoir sample (see `frequency_aware_evict`) so
/// that entries which fell out of the recency reservoir without ever being
/// sampled can still become eviction candidates. Kept infrequent so the
/// reservoir stays the dominant candidate source and the extra bounded head walk
/// only runs occasionally. Must be non-zero (it is a modulus divisor).
const HEAD_BLEND_PERIOD: u64 = 8;
/// Capacity of each partition's eviction sample reservoir (a lock-free MPMC
/// ring). Eviction samples candidate keys by draining this ring instead of
/// walking a shard-ordered prefix of the DashMap, so per-pass work is bounded by
/// `ROUTER_CACHE_EVICTION_SAMPLE_LIMIT` regardless of `max_cache_entries` and
/// every inserted key — including cold, high-cardinality keys that land deep in
/// the map — is eventually an eviction candidate. Sized to several sample
/// windows so a single pass can fill its budget with headroom for concurrent
/// cold inserts arriving between passes. Must stay non-zero: `ArrayQueue::new`
/// panics on a zero capacity (a fixed compile-time constant, so this is an
/// invariant, never a runtime input).
const ROUTER_CACHE_EVICTION_RING_CAPACITY: usize = 4096;
/// Maximum number of Count-Min Sketch cells halved per `increment` call.
///
/// Aging used to sweep both rows inline when `age_threshold` was crossed
/// (~65k–131k atomic RMWs on one unlucky route lookup). Work is now amortized:
/// each increment past an armed aging cycle processes at most this many cells.
/// Must stay well below typical sketch width (default ≥1024 → ≥2048 cells) so
/// no single lookup completes a full-row sweep. Exposed for unit tests.
const CMS_AGE_CHUNK: usize = 256;

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
    /// [`HostRouteTable::select_mesh_outbound_port_route_with_authz_port`] swaps in the
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
    /// Direct-pod-IP / headless raw-TCP mesh egress lookup (F3 §3.4): strict
    /// `(backing workload IP, resolved target port)` → relay entry, consulted
    /// AFTER `mesh_tcp_egress` misses (a client that resolved a headless
    /// service itself and dialed a POD IP directly bypasses the VIP table).
    /// Built forward from the prepared `mesh` block (stream-family ports ×
    /// backing workload addresses, canonicalized the SAME way as the VIP keys);
    /// empty outside mesh mode.
    mesh_tcp_egress_by_workload: HashMap<(std::net::IpAddr, u16), MeshTcpEgressDecision>,
    /// Direct-pod-IP HTTP-family mesh egress lookup: strict
    /// `(backing workload IP, resolved target port)` → hidden outbound route,
    /// selected inside the HTTP request path before Host routing. Duplicate
    /// claims or missing materialized route/upstream entries become
    /// `CloseNotRoutable`, so a captured direct Pod-IP request is never
    /// attributed to an arbitrary service by its Host header.
    mesh_http_egress_by_workload:
        HashMap<(std::net::IpAddr, u16), MeshHttpEgressByWorkloadDecision>,
    /// Local Sidecar raw-TCP inbound lookup: captured original-destination app
    /// port → loopback relay entry. Consulted by the inbound accept loop before
    /// Hyper parses the connection, so Redis/MySQL/etc. bytes never enter the
    /// HTTP parser. Built from runtime-only mesh preparation state; empty
    /// outside Sidecar mesh mode or when no local stream-family service port
    /// resolved.
    mesh_tcp_inbound: HashMap<u16, Arc<MeshTcpInboundEntry>>,
    /// UDP mesh egress lookup (F3 §3.3 Stage 4): strict `(service VIP, UDP
    /// service port)` → relay entry, consulted by the UDP capture listener for
    /// each captured datagram's recovered original destination BEFORE any
    /// forwarding. Built forward from the prepared `mesh` block (UDP ports ×
    /// `cluster_ips`); Ambient-only relay (the materializer skips non-Ambient
    /// topologies, so non-Ambient entries are always `CloseNotRoutable`). Empty
    /// outside mesh mode.
    //
    // Consumed by the mesh UDP capture listener, which is Linux-only
    // (`IP_TRANSPARENT` + recvmsg cmsg). The field is still built on every
    // platform (the route table is platform-agnostic), so silence the dead-code
    // warning where the only consumer is `#[cfg(not(linux))]`-compiled out.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    mesh_udp_egress: HashMap<(std::net::IpAddr, u16), MeshTcpEgressDecision>,
}

pub(crate) struct RouteSnapshot {
    table: Arc<HostRouteTable>,
    generation: u64,
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

/// One local raw-TCP Sidecar inbound destination: the synthesized relay proxy
/// and loopback backend selected by captured original-destination app port.
pub(crate) struct MeshTcpInboundEntry {
    pub(crate) relay_proxy: Arc<Proxy>,
    pub(crate) backend_addr: std::net::SocketAddr,
    /// The local service FQDN for logging.
    pub(crate) service_fqdn: String,
    /// `true` only for opaque-TLS app ports: the inbound relay peeks the
    /// ClientHello SNI before the stream plugin chain. Carried from
    /// [`crate::modes::mesh::config::MeshInboundTcpRoute::tls_inspect`].
    pub(crate) tls_inspect: bool,
    /// `true` only when mesh has an explicit client-first signal. `false` for
    /// ambiguous/server-first raw-TCP protocols (Tcp/Redis/Mongo/MySQL/
    /// Postgres), where peeking would block the relay on the handshake clock
    /// before the backend greeting can arrive.
    pub(crate) first_bytes_inspect: bool,
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

#[derive(Clone)]
pub(crate) enum MeshHttpEgressByWorkloadDecision {
    Route {
        proxy: Arc<Proxy>,
        service_port: u16,
    },
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
    /// Per-sibling selection keys, sorted by `authority_port` ascending; entry 0
    /// is the representative present in the route tiers.
    ports: Vec<MeshInboundSibling>,
    /// `true` for a Sidecar `ingress[]` group (`__mesh-ingress-*`), `false` for
    /// a service-port default inbound group (`__mesh-inbound-*`). Drives the
    /// authorization destination port: an ingress listener authorizes on the
    /// declared LISTENER port (`authority_port`, e.g. `8443`), NOT the
    /// `defaultEndpoint` backend port — so an `AuthorizationPolicy` ALLOW/DENY
    /// scoped to the listener port matches (a DENY on the listener port must be
    /// enforced; routing it through the backend port would fail a DENY OPEN). A
    /// service-port default inbound group authorizes on the container/backend
    /// port, matching Istio's inbound authz, so this stays `false` there.
    is_ingress: bool,
}

/// One inbound per-port sibling's selection keys. The authority port and the
/// captured-original-destination match port are stored separately because they
/// DIFFER for Sidecar `ingress[]` listeners: a service-port default inbound
/// sibling matches orig-dst against the resolved CONTAINER (target) port
/// (`backend_port`) and the request authority against the SERVICE port, while
/// an `ingress[]` listener matches BOTH signals against the declared LISTENER
/// port (the dialed port) and forwards to a separate `defaultEndpoint` backend.
pub(crate) struct MeshInboundSibling {
    /// Port the request's pre-strip `Host`/`:authority` must carry to select
    /// this sibling — the SERVICE port (default inbound) or the LISTENER port
    /// (`ingress[]`).
    authority_port: u16,
    /// Port the connection's captured original destination must equal to select
    /// this sibling — the CONTAINER port (default inbound) or the LISTENER port
    /// (`ingress[]`).
    orig_dst_match_port: u16,
    route: Arc<Proxy>,
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

/// Why [`HostRouteTable::select_mesh_outbound_port_route_with_authz_port`] refused to pick a
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
    #[cfg(test)]
    pub(crate) fn select_mesh_outbound_port_route(
        &self,
        current: RouteMatch,
        orig_dst_port: Option<u16>,
    ) -> Result<RouteMatch, MeshOutboundPortSelectError> {
        self.select_mesh_outbound_port_route_with_authz_port(current, orig_dst_port)
            .map(|(route_match, _)| route_match)
    }

    /// Swap a matched mesh outbound representative route for the sibling
    /// matching the connection's captured original-destination port, plus the
    /// service port that authorization policy should see as
    /// `destination.port` when the selected route belongs to a mesh outbound
    /// service group.
    pub(crate) fn select_mesh_outbound_port_route_with_authz_port(
        &self,
        current: RouteMatch,
        orig_dst_port: Option<u16>,
    ) -> Result<(RouteMatch, Option<u16>), MeshOutboundPortSelectError> {
        let Some(group) = self.mesh_outbound_ports.get(&current.proxy.id) else {
            return Ok((current, None));
        };
        match orig_dst_port {
            None if group.declared_http_ports == 1 => {
                Ok((current, group.ports.first().map(|(port, _)| *port)))
            }
            None => Err(MeshOutboundPortSelectError::OrigDstUnavailable),
            Some(port) => match group.ports.iter().find(|(p, _)| *p == port) {
                Some((selected_port, proxy)) => Ok((
                    RouteMatch {
                        proxy: Arc::clone(proxy),
                        path_params: current.path_params,
                        matched_prefix_len: current.matched_prefix_len,
                    },
                    Some(*selected_port),
                )),
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
    /// - a single-port SERVICE-default group (`is_ingress == false`) → keep
    ///   `current` unconditionally (back-compat: single-port services accept
    ///   bare-Host clients, older peers, and any explicit port today — selection
    ///   adds no new requirement to them);
    /// - a single-listener INGRESS group (`is_ingress == true`) → a present port
    ///   signal MUST equal the declared listener port (else
    ///   [`MeshInboundPortSelectError::PortNotMaterialized`]); a request with no
    ///   port signal falls through to the sole listener. An ingress listener
    ///   binds a specific port and must not absorb traffic to an undeclared one;
    /// - multi-port with no signal at all →
    ///   [`MeshInboundPortSelectError::PortSignalUnavailable`];
    /// - multi-port with a present-but-unmatched signal →
    ///   [`MeshInboundPortSelectError::PortNotMaterialized`].
    ///
    /// Returns the selected `RouteMatch` plus the **authorization listener
    /// port** for a Sidecar `ingress[]` route: `Some(listener_port)` when the
    /// matched group is an ingress group, else `None`. The request handler
    /// stamps this onto `RequestContext` so `mesh_authz` authorizes an ingress
    /// listener on its DECLARED port (e.g. `8443`), not the `defaultEndpoint`
    /// backend port — see [`MeshInboundPortGroup::is_ingress`]. The port is the
    /// selected sibling's `authority_port` (which equals its `orig_dst_match_port`
    /// for ingress), so it is correct for both the multi-listener and the
    /// single-listener (no-signal fall-through) paths.
    pub(crate) fn select_mesh_inbound_port_route(
        &self,
        current: RouteMatch,
        orig_dst_port: Option<u16>,
        authority_port: Option<u16>,
    ) -> Result<(RouteMatch, Option<u16>), MeshInboundPortSelectError> {
        let Some(group) = self.mesh_inbound_ports.get(&current.proxy.id) else {
            return Ok((current, None));
        };
        if group.declared_http_ports == 1 {
            if group.is_ingress {
                // A Sidecar `ingress[]` group binds a SPECIFIC declared listener
                // port (e.g. `8443`); unlike a single-port service it must NOT
                // absorb traffic to any other port. A request that names a port
                // (captured orig-dst or explicit authority) is accepted only when
                // that port matches the sole listener; a present-but-unmatched
                // signal fails closed (a single-port service-default group keeps
                // the back-compat passthrough below). With NO port signal the
                // request falls through to the sole listener — there is no other
                // inbound destination to confuse it with.
                let listener_port = group.ports.first().map(|s| s.authority_port);
                let signal = orig_dst_port.or(authority_port);
                if let Some(port) = signal
                    && listener_port != Some(port)
                {
                    return Err(MeshInboundPortSelectError::PortNotMaterialized);
                }
                return Ok((current, listener_port));
            }
            // Single declared SERVICE port (non-ingress): keep the representative
            // unconditionally (back-compat — single-port services accept bare-Host
            // clients and any explicit port). Not an ingress group, so no authz
            // listener port to stamp.
            return Ok((current, None));
        }
        let selected = if let Some(container_port) = orig_dst_port {
            group
                .ports
                .iter()
                .find(|sibling| sibling.orig_dst_match_port == container_port)
        } else if let Some(service_port) = authority_port {
            group
                .ports
                .iter()
                .find(|sibling| sibling.authority_port == service_port)
        } else {
            return Err(MeshInboundPortSelectError::PortSignalUnavailable);
        };
        match selected {
            Some(sibling) => Ok((
                RouteMatch {
                    proxy: Arc::clone(&sibling.route),
                    path_params: current.path_params,
                    matched_prefix_len: current.matched_prefix_len,
                },
                // The authz listener port for an ingress group is the SELECTED
                // sibling's listener port (its `authority_port`).
                group.is_ingress.then_some(sibling.authority_port),
            )),
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

    /// Direct-pod-IP / headless raw-TCP egress lookup (F3 §3.4) for a captured
    /// connection's pre-NAT original destination, consulted by the accept loop
    /// only AFTER [`HostRouteTable::mesh_tcp_egress_decision`] (the VIP table)
    /// misses. `None` ⇒ the `(IP, port)` matches neither a service VIP nor a
    /// declared backing workload address: fall through to the HTTP handling path
    /// unchanged. Strict exact match, fail closed — a declared-but-unroutable
    /// workload pair is `CloseNotRoutable`, never guessed.
    pub(crate) fn mesh_tcp_egress_by_workload_decision(
        &self,
        orig_dst: std::net::SocketAddr,
    ) -> Option<&MeshTcpEgressDecision> {
        if self.mesh_tcp_egress_by_workload.is_empty() {
            return None;
        }
        self.mesh_tcp_egress_by_workload
            .get(&(orig_dst.ip().to_canonical(), orig_dst.port()))
    }

    /// Direct-pod-IP HTTP-family egress lookup for captured outbound requests,
    /// consulted before Host routing. `None` means the original destination is
    /// not a declared workload HTTP target and the regular Host route may
    /// proceed. A declared-but-unroutable or ambiguous pair returns
    /// `CloseNotRoutable` and the request path fails closed.
    pub(crate) fn mesh_http_egress_by_workload_decision(
        &self,
        orig_dst: std::net::SocketAddr,
    ) -> Option<&MeshHttpEgressByWorkloadDecision> {
        if self.mesh_http_egress_by_workload.is_empty() {
            return None;
        }
        self.mesh_http_egress_by_workload
            .get(&(orig_dst.ip().to_canonical(), orig_dst.port()))
    }

    /// Local Sidecar raw-TCP inbound lookup for a captured connection's
    /// original destination. The inbound REDIRECT path preserves the local app
    /// port in `orig_dst.port()`, which selects the loopback relay target.
    /// `None` means no prepared stream-family local service port matched.
    pub(crate) fn mesh_tcp_inbound_entry(
        &self,
        orig_dst: std::net::SocketAddr,
    ) -> Option<Arc<MeshTcpInboundEntry>> {
        if self.mesh_tcp_inbound.is_empty() {
            return None;
        }
        self.mesh_tcp_inbound.get(&orig_dst.port()).cloned()
    }

    /// UDP mesh egress lookup (F3 §3.3 Stage 4) for a captured datagram's
    /// recovered original destination. `None` ⇒ not a declared `(service VIP,
    /// UDP service port)` pair: the datagram is NOT mesh-routable and is dropped
    /// by the capture listener (UDP has no fall-through HTTP path). A declared
    /// but unroutable pair is `CloseNotRoutable` — fail closed, never guessed.
    //
    // Linux-only consumer (the UDP capture listener); see the field comment.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn mesh_udp_egress_decision(
        &self,
        orig_dst: std::net::SocketAddr,
    ) -> Option<&MeshTcpEgressDecision> {
        if self.mesh_udp_egress.is_empty() {
            return None;
        }
        // Canonicalized so an IPv4-mapped IPv6 capture address still matches the
        // IPv4 VIP the slice declared.
        self.mesh_udp_egress
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
/// Aging is incremental: crossing `age_threshold` arms a pass that halves every
/// cell across both rows, but each `increment` only processes up to
/// [`CMS_AGE_CHUNK`] cells. That keeps route-lookup latency bounded even while
/// the thread-local `CACHE_KEY_BUF` borrow is held on the hit path.
///
/// Chunk mutation is single-owner and non-blocking: `age_step` first loads the
/// idle signals (`age_remaining` / `age_pending`) with relaxed reads and returns
/// without touching `age_owner` when both are idle — the common route-lookup
/// path. Only when work may be owed does it CAS `age_owner`; losers return
/// immediately. The owner halves a chunk, then publishes the reduced
/// `age_remaining` cursor — so `age_remaining == 0` is never visible until that
/// chunk's cell RMWs have finished. That prevents a concurrent re-arm from
/// starting the next generation while the prior pass is still mutating cells
/// (overlapping generations / double-halving).
///
/// Cold-path [`Self::reset`] (cache reload) joins the same protocol: it
/// bounded-spins until it exclusively owns `age_owner`, then clears cells /
/// cursor / pending state, then releases. It must never blindly
/// `store(false)` on `age_owner` while another thread still owns a chunk —
/// that would let a second owner acquire and allow the original owner to
/// publish a stale nonzero `age_remaining` after the clear.
///
/// If a threshold fires while a pass is already draining, `age_pending` records
/// that another full pass is owed and re-arms as soon as the cursor returns to
/// idle — without double-halving any cell mid-pass or exceeding the per-lookup
/// chunk budget.
///
/// Memory: `2 * width` bytes + 64-byte alignment padding plus `CachePadded`
/// atomics for the increment counter, aging cursor, pending-pass flag, and
/// single-owner bit (no extra heap allocation for aging).
struct CountMinSketch {
    row0: AlignedCounterRow,
    row1: AlignedCounterRow,
    width_mask: usize,
    /// Total increments across all keys, for triggering periodic aging.
    total_increments: CachePadded<AtomicU64>,
    /// Age (halve all counters) after this many increments. Always ≥ 1.
    age_threshold: u64,
    /// Cells left to halve in the current aging pass (`0` = idle).
    /// High-water index into the flat `[row0||row1]` layout: an owned step of
    /// `n` cells ages `[remaining - n, remaining)` and only then stores
    /// `remaining - n`. Idle (`0`) is therefore published only after the last
    /// chunk's cell updates complete.
    age_remaining: CachePadded<AtomicUsize>,
    /// Set when a threshold crosses while a pass is already in progress.
    /// Consumed to re-arm exactly one follow-up pass after the cursor drains.
    age_pending: CachePadded<AtomicBool>,
    /// Exclusive non-blocking owner for one `age_step` chunk. Contended
    /// callers leave aging to the owner and return without blocking.
    /// Cold-path `reset` acquires this with a bounded spin/yield instead.
    age_owner: CachePadded<AtomicBool>,
    /// Test-only: CAS attempts inside [`Self::acquire_age_owner_blocking`], so
    /// concurrency tests can observe a blocked reset without sleeping.
    #[cfg(test)]
    age_owner_acquire_spins: AtomicUsize,
    /// Test-only: `age_owner` CAS attempts from [`Self::age_step`] (not reset).
    /// Idle fast-path returns must leave this at zero.
    #[cfg(test)]
    age_step_owner_cas_attempts: AtomicUsize,
}

impl CountMinSketch {
    /// Maximum cells aged per `increment` (see [`CMS_AGE_CHUNK`]).
    #[cfg(test)]
    const AGE_CHUNK: usize = CMS_AGE_CHUNK;

    /// Create a new sketch with the given width (rounded up to a power of two).
    /// `age_threshold` controls how often counters are halved (typically
    /// `cache_capacity * 4`). A zero threshold is raised to 1 so
    /// `is_multiple_of` never panics on the hot path.
    fn new(width: usize, age_threshold: u64) -> Self {
        let width = width.next_power_of_two();
        let row0 = AlignedCounterRow((0..width).map(|_| AtomicU8::new(0)).collect());
        let row1 = AlignedCounterRow((0..width).map(|_| AtomicU8::new(0)).collect());
        Self {
            row0,
            row1,
            width_mask: width - 1,
            total_increments: CachePadded::new(AtomicU64::new(0)),
            age_threshold: age_threshold.max(1),
            age_remaining: CachePadded::new(AtomicUsize::new(0)),
            age_pending: CachePadded::new(AtomicBool::new(false)),
            age_owner: CachePadded::new(AtomicBool::new(false)),
            #[cfg(test)]
            age_owner_acquire_spins: AtomicUsize::new(0),
            #[cfg(test)]
            age_step_owner_cas_attempts: AtomicUsize::new(0),
        }
    }

    /// Non-blocking attempt to become the sole `age_step` / reset owner.
    #[inline]
    fn try_acquire_age_owner(&self) -> bool {
        self.age_owner
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release exclusive ownership. Only the current owner may call this.
    #[inline]
    fn release_age_owner(&self) {
        self.age_owner.store(false, Ordering::Release);
    }

    /// Cold-path: spin/yield until this thread exclusively owns `age_owner`.
    ///
    /// Used by [`Self::reset`] (cache reload). Hot-path [`Self::age_step`] must
    /// keep using [`Self::try_acquire_age_owner`] and return immediately on loss.
    fn acquire_age_owner_blocking(&self) {
        while !self.try_acquire_age_owner() {
            #[cfg(test)]
            self.age_owner_acquire_spins.fetch_add(1, Ordering::Relaxed);
            std::hint::spin_loop();
            std::thread::yield_now();
        }
    }

    /// Width of each row (power of two).
    #[inline]
    fn width(&self) -> usize {
        self.width_mask + 1
    }

    /// Total cells across both rows.
    #[inline]
    fn total_cells(&self) -> usize {
        self.width() * 2
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

    /// Arm a full aging pass if one is not already in progress.
    ///
    /// Concurrent callers racing at the threshold: at most one wins the CAS and
    /// starts the pass. A threshold that fires while a pass is already running
    /// (including while an owner still holds the last chunk before publishing
    /// idle) sets [`Self::age_pending`] so a follow-up pass is re-armed after
    /// the cursor drains (multiple mid-pass hits collapse to one owed pass).
    #[inline]
    fn arm_aging(&self) {
        if self
            .age_remaining
            .compare_exchange(0, self.total_cells(), Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            self.age_pending.store(true, Ordering::Relaxed);
        }
    }

    /// Halve at most [`CMS_AGE_CHUNK`] cells of an in-progress aging pass.
    ///
    /// Non-blocking single-owner protocol: only one thread mutates cells at a
    /// time. When both the cursor and pending flag are idle, returns after two
    /// relaxed loads without writing `age_owner` (route-lookup idle fast path).
    /// A concurrent arm that races after those loads is picked up on a later
    /// call. Contended callers that observe owed work fail the `age_owner` CAS
    /// and return immediately (no mutex, spawn, or allocation). The owner
    /// halves up to one chunk, then publishes the reduced cursor — so a new
    /// generation cannot observe idle and re-arm until every claimed chunk from
    /// the prior generation has finished its cell RMWs. Per-call work stays ≤
    /// `CMS_AGE_CHUNK` regardless of sketch width. When the cursor is idle and
    /// a pass is pending, re-arms and ages the first follow-up chunk in the
    /// same call (still within budget).
    #[inline]
    fn age_step(&self) {
        // Idle fast path: shared loads only. Do not CAS `age_owner` when no
        // aging work is armed or pending — otherwise every route-cache lookup
        // would contend on a single written cache line.
        if self.age_remaining.load(Ordering::Relaxed) == 0
            && !self.age_pending.load(Ordering::Relaxed)
        {
            return;
        }

        #[cfg(test)]
        self.age_step_owner_cas_attempts
            .fetch_add(1, Ordering::Relaxed);
        if !self.try_acquire_age_owner() {
            return;
        }

        let mut remaining = self.age_remaining.load(Ordering::Relaxed);
        if remaining == 0 {
            if !self.age_pending.swap(false, Ordering::Relaxed) {
                self.release_age_owner();
                return;
            }
            // Re-arm an owed follow-up pass. `arm_aging` may already have won
            // the CAS; either way the cursor is non-zero before we mutate.
            let _ = self.age_remaining.compare_exchange(
                0,
                self.total_cells(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            remaining = self.age_remaining.load(Ordering::Relaxed);
            if remaining == 0 {
                self.release_age_owner();
                return;
            }
        }

        let n = remaining.min(CMS_AGE_CHUNK);
        self.age_cells_in_range(remaining - n, remaining);
        // Publish the cursor only after cell updates complete. Publishing idle
        // before the RMWs finish would let a concurrent caller consume
        // `age_pending`, re-arm, and overlap generations (double-halving).
        self.age_remaining.store(remaining - n, Ordering::Relaxed);
        self.release_age_owner();
    }

    /// Right-shift cells in the flat `[row0 || row1]` index range `[start, end)`.
    #[inline]
    fn age_cells_in_range(&self, start: usize, end: usize) {
        let width = self.width();
        for flat in start..end {
            let cell = if flat < width {
                &self.row0.0[flat]
            } else {
                &self.row1.0[flat - width]
            };
            let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v >> 1));
        }
    }

    /// Increment the frequency count for a key and return the estimated count.
    ///
    /// Crossing `age_threshold` arms an incremental aging pass; each call then
    /// performs at most [`CMS_AGE_CHUNK`] cell halvings. The returned estimate is
    /// always the post-increment, pre-aging value for this key (same as before
    /// incremental aging).
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

        // Return value is post-increment / pre-aging (fetched value is pre-increment).
        let c0 = if v0 < 255 { v0 + 1 } else { 255 };
        let c1 = if v1 < 255 { v1 + 1 } else { 255 };
        let result = c0.min(c1);

        // Arm a new aging cycle on the threshold, then advance at most one chunk.
        // Ordering matters: arm before step so the threshold-crossing call does
        // bounded work immediately when it wins ownership. Mid-cycle threshold
        // hits set `age_pending` instead of resetting the cursor (follow-up
        // re-arms only after the owned cursor drains to idle). Contended
        // `age_step` losers return without blocking; the owner performs the RMWs.
        let total = self.total_increments.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_multiple_of(self.age_threshold) {
            self.arm_aging();
        }
        self.age_step();

        result
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
    ///
    /// Completes any in-progress incremental pass first, then runs a fresh full
    /// pass via the same chunked helper used on the hot path. Not used by
    /// production `increment` (which only arms + steps); kept for tests and any
    /// explicit full-refresh callers. Spins on `age_step` until the single
    /// owner publishes an idle cursor (non-blocking for the hot path; this
    /// helper is off the route-lookup path).
    #[cfg(test)]
    fn age(&self) {
        // Ignore owed follow-up passes: this helper forces exactly one full
        // refresh after draining the current cursor.
        self.age_pending.store(false, Ordering::Relaxed);
        while self.age_remaining.load(Ordering::Relaxed) > 0
            || self.age_owner.load(Ordering::Acquire)
        {
            self.age_step();
        }
        self.age_remaining
            .store(self.total_cells(), Ordering::Relaxed);
        while self.age_remaining.load(Ordering::Relaxed) > 0
            || self.age_owner.load(Ordering::Acquire)
        {
            self.age_step();
        }
        self.age_pending.store(false, Ordering::Relaxed);
    }

    /// Reset all counters to zero (used on full cache rebuild).
    ///
    /// Synchronizes with the single-owner aging protocol before clearing:
    /// bounded-spins until this thread exclusively owns `age_owner`, then
    /// zeroes cells / totals / cursor / pending, then releases ownership.
    /// Never clears another thread's ownership flag. Request-path
    /// [`Self::age_step`] losers stay immediate/non-blocking; increments that
    /// race a reload keep best-effort frequency semantics (no hot-path lock).
    fn reset(&self) {
        // Cold reload path: wait for any in-flight `age_step` owner to finish
        // publishing its cursor and releasing, then take exclusive ownership
        // so we cannot free the flag under that owner (which would let a second
        // thread acquire and let the original owner republish a stale cursor).
        self.acquire_age_owner_blocking();

        for cell in &self.row0.0 {
            cell.store(0, Ordering::Relaxed);
        }
        for cell in &self.row1.0 {
            cell.store(0, Ordering::Relaxed);
        }
        self.total_increments.store(0, Ordering::Relaxed);
        self.age_remaining.store(0, Ordering::Relaxed);
        self.age_pending.store(false, Ordering::Relaxed);
        self.release_age_owner();
    }

    /// Test helper: acquire ownership of an armed pass, pause at `acquired` /
    /// `release_hold` barriers, then publish the reduced cursor and release.
    ///
    /// Mirrors the owned body of [`Self::age_step`] so concurrency tests can
    /// hold the single-owner bit mid-chunk without sleeps or timing races.
    #[cfg(test)]
    fn age_step_with_hold_gates(
        &self,
        acquired: &std::sync::Barrier,
        release_hold: &std::sync::Barrier,
    ) {
        assert!(
            self.try_acquire_age_owner(),
            "test helper expects an uncontended age_owner acquire"
        );
        let remaining = self.age_remaining.load(Ordering::Relaxed);
        assert!(
            remaining > 0,
            "test helper expects an already-armed aging pass"
        );
        // Hold ownership before any cursor publish so a concurrent `reset` must
        // either wait (correct) or blindly clear our flag (the race under test).
        acquired.wait();
        release_hold.wait();

        let n = remaining.min(CMS_AGE_CHUNK);
        self.age_cells_in_range(remaining - n, remaining);
        self.age_remaining.store(remaining - n, Ordering::Relaxed);
        self.release_age_owner();
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
    /// Pre-computed host-based route index and its cache-validation generation.
    route_snapshot: ArcSwap<RouteSnapshot>,
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
    /// Approximate prefix cache entries maintained on insert/remove so cold
    /// inserts do not scan all DashMap shards through `len()`.
    prefix_cache_entries: AtomicUsize,
    /// Approximate regex cache entries maintained on insert/remove so cold
    /// inserts do not scan all DashMap shards through `len()`.
    regex_cache_entries: AtomicUsize,
    /// Resolved DashMap shard count used by the lookup caches.
    #[cfg(test)]
    cache_shard_amount: usize,
    /// Monotonic counters for eviction tracking per partition (entries removed).
    prefix_eviction_counter: AtomicU64,
    regex_eviction_counter: AtomicU64,
    /// Monotonic counters of eviction *attempts* (passes) per partition. They
    /// advance by one per eviction pass regardless of how many entries were
    /// removed, and exist purely as telemetry / a test signal that passes fired.
    /// They no longer drive sample selection: candidates are drawn from the
    /// per-partition eviction reservoir below, not from a rotating DashMap window.
    prefix_eviction_attempts: AtomicU64,
    regex_eviction_attempts: AtomicU64,
    /// Bounded lock-free reservoirs of recently inserted cache keys, one per
    /// partition. Every cold-path miss insert pushes its key here; eviction
    /// drains candidates from the reservoir instead of walking a shard-ordered
    /// DashMap prefix. This keeps each eviction pass O(sample_size) (independent
    /// of `max_cache_entries`) while letting the whole keyspace — including cold,
    /// high-cardinality entries that land deep in the map — become eviction
    /// candidates as they are inserted, rather than only the first few thousand
    /// shard-ordered entries. `force_push` overwrites the oldest queued key when
    /// full, so the reservoir is a moving window over recent inserts.
    prefix_eviction_reservoir: ArrayQueue<String>,
    regex_eviction_reservoir: ArrayQueue<String>,
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
    ///
    /// `max_cache_entries == 0` is the documented "auto" sentinel
    /// (`FERRUM_ROUTER_CACHE_MAX_ENTRIES=0`) and is resolved here to the
    /// same bounded auto value as `ProxyState::new`: `proxies.len() * 3`
    /// clamped to `[10_000, 1_000_000]`. That keeps direct callers aligned
    /// with production env-var resolution while still getting a usable cache.
    /// Without this,
    /// the tiny-cache eviction short-circuit would leave the cache unbounded
    /// under load.
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
        let table = Arc::new(Self::build_route_table(config));
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
            route_snapshot: ArcSwap::new(Arc::new(RouteSnapshot {
                table,
                generation: 1,
            })),
            prefix_cache: DashMap::with_capacity_and_shard_amount(max_cache_entries, shards),
            regex_cache: DashMap::with_capacity_and_shard_amount(max_cache_entries / 4 + 1, shards),
            max_cache_entries,
            prefix_cache_entries: AtomicUsize::new(0),
            regex_cache_entries: AtomicUsize::new(0),
            #[cfg(test)]
            cache_shard_amount: shards,
            prefix_eviction_counter: AtomicU64::new(0),
            regex_eviction_counter: AtomicU64::new(0),
            prefix_eviction_attempts: AtomicU64::new(0),
            regex_eviction_attempts: AtomicU64::new(0),
            // ROUTER_CACHE_EVICTION_RING_CAPACITY is a non-zero compile-time
            // constant, so `ArrayQueue::new` cannot panic here.
            prefix_eviction_reservoir: ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY),
            regex_eviction_reservoir: ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY),
            frequency_sketch: CountMinSketch::new(sketch_width, age_threshold),
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
        let previous_generation = self.route_snapshot.load().generation;
        self.route_snapshot.store(Arc::new(RouteSnapshot {
            table,
            generation: route_generation,
        }));
        if previous_generation != route_generation {
            self.clear_lookup_caches();
        }
    }

    pub(crate) fn clear_lookup_caches(&self) {
        // Eviction is driven by the atomic entry counters, so the clear and the
        // counter reset must stay coherent even while request threads keep
        // inserting cache misses concurrently (a reload runs alongside live
        // traffic). Neither a blind `store(0)` nor a `store(len())` is safe:
        //
        //   * `store(0)` and `store(self.prefix_cache.len())` both *overwrite*
        //     the counter, so any insert whose `fetch_add(1)` lands between the
        //     value being computed and the store has its increment clobbered.
        //     With `store(len())` the racing insert's entry may not yet be
        //     visible to the `len()` read, so the store can leave the counter
        //     *below* the real entry count — under-reporting admin stats and
        //     delaying future eviction until later inserts make up the lost
        //     increment.
        //
        // Instead subtract a snapshot of the counter taken just before each
        // `clear()`, *floored at the live map length* (see
        // `reconcile_cache_entries_after_clear`). `fetch_sub` is an atomic RMW
        // that composes additively with concurrent `fetch_add(1)`s, so no
        // increment is ever lost. Correctness sketch: every entry resident
        // *after* the clear was inserted after the `clear()` call, so its
        // `fetch_add` (which always follows its map insert) ran after the
        // snapshot load and is therefore not part of the subtracted snapshot —
        // resident entries stay counted. The `max(map.len())` floor closes the
        // one remaining under-count window: if an eviction pass races the clear
        // and `fetch_sub`s its own removals *after* this snapshot is loaded, the
        // snapshot still includes those entries, so subtracting it bare would
        // double-count the evictor's removals and could leave the counter below
        // the live set; flooring at `len()` (a valid lower bound on resident
        // entries) makes that impossible. This is the load-bearing invariant:
        // under-counting would delay eviction and let the cache grow unbounded,
        // so we only ever err toward over-count.
        //
        // The residual imprecision is a bounded *over*-count: an entry inserted
        // in the window `[snapshot load, clear()]` whose `fetch_add` runs after
        // the subtract is removed by `clear()` yet still counted (its +1 is not
        // in the subtracted snapshot). Note this over-count does NOT self-correct
        // through eviction — an eviction subtracts equal amounts from the counter
        // and the live set, preserving the offset — so it persists until the next
        // clear. It is nonetheless harmless and self-limiting: (1) it only feeds
        // the eviction-trigger comparison and admin telemetry, never a
        // correctness/security decision, and erring high just makes eviction fire
        // marginally early; (2) it is bounded by the inserts that race a single
        // clear (a `clear()` is microseconds), not the whole map; and (3) it
        // cannot accumulate across reloads — the *next* clear snapshots the
        // entire current counter (leftover offset included) and subtracts it,
        // re-deriving the counter from that reload's race window. Eliminating
        // even this bounded skew would require making the clear and the counter
        // reset atomic per entry, which DashMap does not offer without a global
        // lock on the proxy hot path; the bounded over-count is the deliberate
        // trade. Each partition snapshots, clears, and subtracts together so the
        // per-partition window is as small as possible (the regex partition no
        // longer sits between the prefix snapshot and the prefix subtract).
        let prefix_cleared = self.prefix_cache_entries.load(Ordering::Relaxed);
        self.prefix_cache.clear();
        reconcile_cache_entries_after_clear(
            &self.prefix_cache_entries,
            &self.prefix_cache,
            prefix_cleared,
        );
        let regex_cleared = self.regex_cache_entries.load(Ordering::Relaxed);
        self.regex_cache.clear();
        reconcile_cache_entries_after_clear(
            &self.regex_cache_entries,
            &self.regex_cache,
            regex_cleared,
        );
        // Drain the reservoirs *after* clearing the maps. A race-insert that lands
        // after `clear()` but before this drain can have its candidate key popped
        // here, so its still-resident entry temporarily holds no reservoir slot.
        // That is an accepted eviction-*quality* residual, not a correctness gap:
        // the entry stays resident and counted, so the capacity bound is still
        // enforced — it simply re-enters the candidate pool via the periodic
        // resident-key blend / underfilled-sample top-up in `frequency_aware_evict`
        // (the very mechanism added for "resident keys that aged out of the
        // reservoir"), or via its next access re-inserting it as a miss. Draining
        // *before* clearing would NOT help — inserts race the clear regardless of
        // order — and would reintroduce the unbounded-spin hazard the
        // capacity-bounded `drain_reservoir` exists to avoid (a sustained insert
        // storm could keep a drain-until-empty loop from ever terminating). So the
        // ordering here is deliberate.
        drain_reservoir(&self.prefix_eviction_reservoir);
        drain_reservoir(&self.regex_eviction_reservoir);
        self.frequency_sketch.reset();
    }

    fn insert_prefix_cache_entry(&self, cache_key: String, entry: PrefixCacheEntry) {
        // Record this key as an eviction candidate only *after* the map insert
        // lands, then trip eviction. If we enqueued before the insert, a
        // concurrent eviction pass (the cache may already be over capacity) could
        // pop this key, find `map.contains_key` still false, and drop it as
        // stale — leaving the freshly inserted entry with no reservoir candidate,
        // so under sustained traffic where the reservoir never empties cold
        // entries stay outside the eviction sample and bias eviction toward later
        // inserts. Enqueuing after the insert guarantees a popped candidate is
        // live. `force_push` is O(1) and lock-free; it overwrites the oldest
        // queued key when the reservoir is full, and any key it drops is simply a
        // candidate we chose not to consider. This runs only on the cold miss
        // path, never on the cache-hit fast path. The clone is required because
        // the map insert consumes the key.
        let reservoir_key = cache_key.clone();
        let is_new = self.prefix_cache.insert(cache_key, entry).is_none();
        // Entry is now resident either way; enqueue the candidate so any concurrent
        // evictor that later pops it sees a live entry. On an overwrite this just
        // refreshes recency (membership unchanged).
        let _ = self.prefix_eviction_reservoir.force_push(reservoir_key);
        if is_new {
            let entries = self.prefix_cache_entries.fetch_add(1, Ordering::Relaxed) + 1;
            if entries > self.max_cache_entries {
                self.evict_prefix_sample();
            }
        }
    }

    fn insert_regex_cache_entry(&self, cache_key: String, entry: RegexCacheEntry) {
        // See `insert_prefix_cache_entry`: enqueue the eviction candidate only
        // after the map insert lands so a concurrent evictor never pops it while
        // it is not yet resident. Cold miss path only.
        let reservoir_key = cache_key.clone();
        let is_new = self.regex_cache.insert(cache_key, entry).is_none();
        let _ = self.regex_eviction_reservoir.force_push(reservoir_key);
        if is_new {
            let entries = self.regex_cache_entries.fetch_add(1, Ordering::Relaxed) + 1;
            if entries > self.max_cache_entries {
                self.evict_regex_sample();
            }
        }
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
        let snapshot = self.route_snapshot.load();
        self.find_proxy_in_snapshot(&snapshot.table, snapshot.generation, host, path)
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
                self.frequency_sketch.increment(&cache_key);
                self.insert_regex_cache_entry(
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
                self.frequency_sketch.increment(&cache_key);
                self.insert_prefix_cache_entry(
                    cache_key,
                    PrefixCacheEntry {
                        proxy: Some(Arc::clone(&route_match.proxy)),
                        route_generation,
                    },
                );
            }
            None => {
                // Negative entry → prefix cache (both tiers missed)
                self.frequency_sketch.increment(&cache_key);
                self.insert_prefix_cache_entry(
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
            self.prefix_cache_entries.load(Ordering::Relaxed),
            self.regex_cache_entries.load(Ordering::Relaxed),
            self.prefix_eviction_counter.load(Ordering::Relaxed),
            self.regex_eviction_counter.load(Ordering::Relaxed),
            self.max_cache_entries,
        )
    }

    /// Number of entries currently in the prefix cache (for testing).
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn cache_len(&self) -> usize {
        self.prefix_cache_entries.load(Ordering::Relaxed)
    }

    /// Number of entries currently in the regex cache (for testing).
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn regex_cache_len(&self) -> usize {
        self.regex_cache_entries.load(Ordering::Relaxed)
    }

    /// Resolved DashMap shard count used by `prefix_cache` and `regex_cache`.
    #[cfg(test)]
    pub fn cache_shard_amount(&self) -> usize {
        self.cache_shard_amount
    }

    #[cfg(test)]
    fn route_table_for_tests(&self) -> Arc<HostRouteTable> {
        let snapshot = self.route_snapshot.load();
        Arc::clone(&snapshot.table)
    }

    #[cfg(test)]
    fn route_snapshot_for_tests(&self) -> Arc<RouteSnapshot> {
        self.route_snapshot.load_full()
    }

    #[cfg(test)]
    fn publish_route_snapshot_without_clearing_for_tests(
        &self,
        table: Arc<HostRouteTable>,
        generation: u64,
    ) {
        self.route_snapshot
            .store(Arc::new(RouteSnapshot { table, generation }));
    }

    /// Number of routes in the pre-sorted route table (for testing).
    #[allow(dead_code)] // Library integration tests exercise this API; the binary target does not.
    pub fn route_count(&self) -> usize {
        let snapshot = self.route_snapshot.load();
        let table = &snapshot.table;
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
    /// Samples a small bounded set of candidate keys from the eviction reservoir,
    /// estimates each entry's access frequency via the Count-Min Sketch, and
    /// removes the least frequent entries. This protects hot cache entries from
    /// eviction while keeping the eviction cost bounded by constants, not cache
    /// capacity, and — because every inserted key passes through the reservoir —
    /// lets cold entries anywhere in the map become eviction candidates.
    fn evict_prefix_sample(&self) {
        // Bump the pass counter for telemetry and reuse it as the head-blend
        // rotation seed so successive passes periodically sample resident keys
        // from a rotating window (see `frequency_aware_evict`).
        let pass = self
            .prefix_eviction_attempts
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let removed = frequency_aware_evict(
            &self.prefix_cache,
            &self.prefix_eviction_reservoir,
            &self.frequency_sketch,
            self.max_cache_entries,
            pass,
        );
        if removed > 0 {
            subtract_cache_entries(&self.prefix_cache_entries, removed);
            self.prefix_eviction_counter
                .fetch_add(removed as u64, Ordering::Relaxed);
            debug!(
                "Router prefix cache evicted {} entries (was at capacity {})",
                removed, self.max_cache_entries
            );
        }
    }

    /// Evict low-frequency entries from the regex cache using frequency-guided sampling.
    fn evict_regex_sample(&self) {
        // Bump the pass counter for telemetry and reuse it as the head-blend
        // rotation seed (see `evict_prefix_sample` / `frequency_aware_evict`).
        let pass = self.regex_eviction_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        let removed = frequency_aware_evict(
            &self.regex_cache,
            &self.regex_eviction_reservoir,
            &self.frequency_sketch,
            self.max_cache_entries,
            pass,
        );
        if removed > 0 {
            subtract_cache_entries(&self.regex_cache_entries, removed);
            self.regex_eviction_counter
                .fetch_add(removed as u64, Ordering::Relaxed);
            debug!(
                "Router regex cache evicted {} entries (was at capacity {})",
                removed, self.max_cache_entries
            );
        }
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
            // A service-port default inbound sibling matches the captured
            // original destination against its resolved CONTAINER port
            // (`backend_port`) and the request authority against its SERVICE
            // port (the group key).
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
                let mut members: Vec<MeshInboundSibling> = group
                    .siblings
                    .iter()
                    .filter_map(|(service_port, id)| {
                        inbound_proxies.get(id.as_str()).map(|p| {
                            let route = Arc::new((*p).clone());
                            MeshInboundSibling {
                                authority_port: *service_port,
                                orig_dst_match_port: route.backend_port,
                                route,
                            }
                        })
                    })
                    .collect();
                members.sort_by_key(|sibling| sibling.authority_port);
                if members.is_empty() {
                    continue;
                }
                let representative_id = members[0].route.id.clone();
                for sibling in members.iter().skip(1) {
                    mesh_sibling_skip_ids.insert(sibling.route.id.clone());
                }
                mesh_inbound_ports.insert(
                    representative_id,
                    Arc::new(MeshInboundPortGroup {
                        declared_http_ports: group.declared_http_ports,
                        ports: members,
                        // Service-port default inbound: authorize on the
                        // container/backend port (Istio inbound authz).
                        is_ingress: false,
                    }),
                );
            }
            // F6 §6.2: Sidecar ingress[] custom-listener siblings. Forward-derived
            // from the resolved listeners (`mesh_ingress_listener_groups`), keyed
            // by the declared LISTENER port for BOTH the captured original
            // destination AND the request authority (the dialed port is the
            // listener port on the shared :15006 inbound listener), forwarding to
            // a separate `defaultEndpoint` backend. Folded into the same
            // `mesh_inbound_ports` map so the request path's existing inbound
            // arm (`select_mesh_inbound_port_route`) disambiguates them with no
            // fork. Ingress and service-port defaults never coexist for one
            // workload (ingress replaces defaults at materialization).
            let ingress_proxies: HashMap<&str, &Proxy> = config
                .proxies
                .iter()
                .filter(|p| {
                    !p.dispatch_kind.is_stream()
                        && crate::modes::mesh::is_mesh_ingress_route_id(&p.id)
                })
                .map(|p| (p.id.as_str(), p))
                .collect();
            for group in crate::modes::mesh::mesh_ingress_listener_groups(mesh) {
                let mut members: Vec<MeshInboundSibling> = group
                    .siblings
                    .iter()
                    .filter_map(|(listener_port, id)| {
                        ingress_proxies
                            .get(id.as_str())
                            .map(|p| MeshInboundSibling {
                                authority_port: *listener_port,
                                orig_dst_match_port: *listener_port,
                                route: Arc::new((*p).clone()),
                            })
                    })
                    .collect();
                members.sort_by_key(|sibling| sibling.authority_port);
                if members.is_empty() {
                    continue;
                }
                let representative_id = members[0].route.id.clone();
                for sibling in members.iter().skip(1) {
                    mesh_sibling_skip_ids.insert(sibling.route.id.clone());
                }
                mesh_inbound_ports.insert(
                    representative_id,
                    Arc::new(MeshInboundPortGroup {
                        declared_http_ports: group.declared_http_ports,
                        ports: members,
                        // Sidecar ingress[]: authorize on the declared LISTENER
                        // port (`authority_port`), not the `defaultEndpoint`
                        // backend port — see `MeshInboundPortGroup::is_ingress`.
                        is_ingress: true,
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
                        let mut relay_proxy = crate::modes::mesh::mesh_outbound_tcp_relay_proxy(
                            &service.namespace,
                            &service.name,
                            sp.port,
                            &upstream_id,
                        );
                        // Project per-port DestinationRule overrides onto the
                        // synthesized relay proxy (mirrors the UDP table): the
                        // stream selection path gates the per-port LB lane on
                        // `Proxy.dispatch_port_overrides`, which the relay
                        // builders leave unset.
                        relay_proxy.dispatch_port_overrides =
                            dispatch_port_overrides_for_upstream(config, &upstream_id);
                        let relay_proxy = Arc::new(relay_proxy);
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

        // ── Direct-pod-IP / headless raw-TCP egress (F3 §3.4) ───────────────
        // Strict `(backing workload IP, resolved target port)` → relay entry,
        // consulted only AFTER the VIP table above misses. Forward-derived from
        // the SAME `mesh_outbound_tcp_bywl_upstreams` source the materializer
        // used (keys + ids + capability keys agree by construction); routable
        // when its per-workload upstream materialized, otherwise the declared
        // pair is mesh-owned but unroutable and the accept loop closes it (never
        // guesses). IPs are canonicalized so mapped-IPv6 captures match.
        let mut mesh_tcp_egress_by_workload: HashMap<
            (std::net::IpAddr, u16),
            MeshTcpEgressDecision,
        > = HashMap::new();
        if let Some(mesh) = config.mesh.as_deref() {
            let upstream_ids: std::collections::HashSet<&str> =
                config.upstreams.iter().map(|u| u.id.as_str()).collect();
            for spec in crate::modes::mesh::mesh_outbound_tcp_bywl_upstreams(
                &mesh.services,
                &mesh.workloads,
                mesh.multi_cluster.as_ref(),
            ) {
                let decision = if upstream_ids.contains(spec.upstream_id.as_str()) {
                    let mut relay_proxy = crate::modes::mesh::mesh_outbound_tcp_bywl_relay_proxy(
                        &spec.service.namespace,
                        &spec.service.name,
                        spec.service_port.port,
                        spec.canonical_ip,
                        &spec.upstream_id,
                    );
                    // Same per-port DR override projection as the VIP table.
                    relay_proxy.dispatch_port_overrides =
                        dispatch_port_overrides_for_upstream(config, &spec.upstream_id);
                    let relay_proxy = Arc::new(relay_proxy);
                    let service_fqdn = config
                        .upstreams
                        .iter()
                        .find(|u| u.id == spec.upstream_id)
                        .and_then(|u| u.name.clone())
                        .unwrap_or_else(|| {
                            format!("{}.{}", spec.service.name, spec.service.namespace)
                        });
                    MeshTcpEgressDecision::Relay(Arc::new(MeshTcpEgressEntry {
                        upstream_id: spec.upstream_id,
                        relay_proxy,
                        service_fqdn,
                    }))
                } else {
                    MeshTcpEgressDecision::CloseNotRoutable
                };
                // First-wins on a `(IP, port)` collision, matching the spec's
                // first-wins de-dupe and the VIP table's `or_insert`.
                mesh_tcp_egress_by_workload
                    .entry((spec.canonical_ip, spec.target_port))
                    .or_insert(decision);
            }
        }

        // ── Direct-pod-IP HTTP-family egress ──────────────────────────────
        // Strict `(backing workload IP, resolved target port)` → hidden
        // outbound proxy. The HTTP request path checks this before Host routing
        // so a direct Pod-IP request cannot be attributed to whichever service
        // the client chose to put in the Host header. Missing materialized
        // proxy/upstream entries and duplicate claims fail closed.
        let mut mesh_http_egress_by_workload: HashMap<
            (std::net::IpAddr, u16),
            MeshHttpEgressByWorkloadDecision,
        > = HashMap::new();
        if let Some(mesh) = config.mesh.as_deref() {
            let upstream_ids: std::collections::HashSet<&str> =
                config.upstreams.iter().map(|u| u.id.as_str()).collect();
            let proxy_by_id: HashMap<&str, &Proxy> = config
                .proxies
                .iter()
                .filter(|p| crate::modes::mesh::is_mesh_outbound_http_bywl_route_id(&p.id))
                .map(|p| (p.id.as_str(), p))
                .collect();
            for spec in crate::modes::mesh::mesh_outbound_http_bywl_upstreams(
                &mesh.services,
                &mesh.workloads,
                mesh.multi_cluster.as_ref(),
            ) {
                let decision = match (
                    upstream_ids.contains(spec.upstream_id.as_str()),
                    proxy_by_id.get(spec.proxy_id.as_str()),
                ) {
                    (true, Some(proxy)) => MeshHttpEgressByWorkloadDecision::Route {
                        proxy: Arc::new((**proxy).clone()),
                        service_port: spec.service_port.port,
                    },
                    _ => MeshHttpEgressByWorkloadDecision::CloseNotRoutable,
                };
                let key = (spec.canonical_ip, spec.target_port);
                match mesh_http_egress_by_workload.entry(key) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(decision);
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        let collision = match (entry.get(), &decision) {
                            (
                                MeshHttpEgressByWorkloadDecision::Route {
                                    proxy: existing_proxy,
                                    service_port: existing_port,
                                },
                                MeshHttpEgressByWorkloadDecision::Route {
                                    proxy: new_proxy,
                                    service_port: new_port,
                                },
                            ) => existing_proxy.id != new_proxy.id || existing_port != new_port,
                            (
                                MeshHttpEgressByWorkloadDecision::CloseNotRoutable,
                                MeshHttpEgressByWorkloadDecision::CloseNotRoutable,
                            ) => false,
                            _ => true,
                        };
                        if collision {
                            entry.insert(MeshHttpEgressByWorkloadDecision::CloseNotRoutable);
                        }
                    }
                }
            }
        }

        // ── Local raw-TCP Sidecar inbound lookup ──────────────────────────
        // Forward-derived during mesh preparation from the same local
        // workload/service view that HTTP inbound materialization consumes.
        // Keyed by the captured original-destination app/container port.
        let mut mesh_tcp_inbound: HashMap<u16, Arc<MeshTcpInboundEntry>> = HashMap::new();
        if let Some(mesh) = config.mesh.as_deref() {
            for route in &mesh.local_inbound_tcp_routes {
                if route.match_port == 0 || route.backend_addr.port() == 0 {
                    continue;
                }
                let relay_proxy = Arc::new(crate::modes::mesh::mesh_inbound_tcp_relay_proxy(route));
                mesh_tcp_inbound.entry(route.match_port).or_insert_with(|| {
                    Arc::new(MeshTcpInboundEntry {
                        relay_proxy,
                        backend_addr: route.backend_addr,
                        service_fqdn: route.service_fqdn.clone(),
                        tls_inspect: route.tls_inspect,
                        first_bytes_inspect: route.first_bytes_inspect,
                    })
                });
            }
        }

        // ── UDP egress (VIP, UDP port) lookup (F3 §3.3 Stage 4) ─────────────
        // Forward-derived from the prepared `mesh` block: every declared UDP
        // service port × every declared service VIP. Routable when its per-port
        // UDP upstream materialized (Ambient-only — the materializer skips
        // non-Ambient topologies, so those pairs resolve to CloseNotRoutable);
        // otherwise the pair is mesh-owned but unroutable and the capture
        // listener drops it (never guesses). VIPs are canonicalized so
        // mapped-IPv6 captures match. Mirrors the raw-TCP VIP table above.
        let mut mesh_udp_egress: HashMap<(std::net::IpAddr, u16), MeshTcpEgressDecision> =
            HashMap::new();
        if let Some(mesh) = config.mesh.as_deref() {
            let upstream_ids: std::collections::HashSet<&str> =
                config.upstreams.iter().map(|u| u.id.as_str()).collect();
            for service in &mesh.services {
                let udp_ports = crate::modes::mesh::service_udp_stream_ports(service);
                if udp_ports.is_empty() || service.cluster_ips.is_empty() {
                    continue;
                }
                for sp in udp_ports {
                    let upstream_id = crate::modes::mesh::mesh_outbound_udp_upstream_id(
                        &service.namespace,
                        &service.name,
                        sp.port,
                    );
                    let decision = if upstream_ids.contains(upstream_id.as_str()) {
                        let mut relay_proxy = crate::modes::mesh::mesh_outbound_udp_relay_proxy(
                            &service.namespace,
                            &service.name,
                            sp.port,
                            &upstream_id,
                        );
                        // Project the UDP upstream's DestinationRule per-port
                        // overrides (`portLevelSettings`: connectTimeout,
                        // tcpKeepalive, ...) onto the synthesized relay proxy's
                        // `dispatch_port_overrides`. `resolve_dispatch_port_overrides`
                        // only populates configured `config.proxies`, not these
                        // router-synthesized egress relay proxies, so without this
                        // the UDP egress dial (`hbone_pool::get_datagram_tunnel`,
                        // which reads `dispatch_port_overrides`) would ignore the
                        // DR (codex r5 P2).
                        relay_proxy.dispatch_port_overrides =
                            dispatch_port_overrides_for_upstream(config, &upstream_id);
                        let relay_proxy = Arc::new(relay_proxy);
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
                            continue;
                        };
                        mesh_udp_egress
                            .entry((ip.to_canonical(), sp.port))
                            .or_insert_with(|| decision.clone());
                    }
                }
            }
        }

        for proxy in &config.proxies {
            if crate::modes::mesh::is_mesh_outbound_http_bywl_route_id(&proxy.id) {
                mesh_sibling_skip_ids.insert(proxy.id.clone());
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
            mesh_tcp_egress_by_workload,
            mesh_http_egress_by_workload,
            mesh_tcp_inbound,
            mesh_udp_egress,
        }
    }
}

/// Project an upstream's DestinationRule per-port overrides (`port_overrides`)
/// into the `dispatch_port_overrides` shape carried on a `Proxy`. Mirrors
/// `GatewayConfig::resolve_dispatch_port_overrides` for a single upstream, used
/// to populate router-synthesized mesh egress relay proxies (which are NOT in
/// `config.proxies`, so the GatewayConfig-level pass never touches them).
/// Returns `None` when the upstream is absent or declares no port overrides.
fn dispatch_port_overrides_for_upstream(
    config: &GatewayConfig,
    upstream_id: &str,
) -> Option<std::collections::HashMap<u16, crate::config::types::ResolvedPortOverride>> {
    let upstream = config.upstreams.iter().find(|u| u.id == upstream_id)?;
    if upstream.port_overrides.is_empty() {
        return None;
    }
    let resolved: std::collections::HashMap<u16, crate::config::types::ResolvedPortOverride> =
        upstream
            .port_overrides
            .iter()
            .filter_map(|(port, ovr)| {
                crate::config::types::ResolvedPortOverride::from_upstream_override(ovr)
                    .map(|resolved| (*port, resolved))
            })
            .collect();
    (!resolved.is_empty()).then_some(resolved)
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
                // `without_slash` is built directly from `slash_pos`, so the
                // next byte is the segment boundary that made this candidate.
                let without_slash = &match_path[..slash_pos];
                if let Some(proxy) = routes.path_index.get(without_slash) {
                    return Some(RouteMatch {
                        proxy: Arc::clone(proxy),
                        path_params: Vec::new(),
                        matched_prefix_len: without_slash.len(),
                    });
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

fn subtract_cache_entries(counter: &AtomicUsize, removed: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |entries| {
        Some(entries.saturating_sub(removed))
    });
}

/// Reconcile a per-partition entry counter after its map has just been
/// `clear()`ed, subtracting `removed` (a pre-clear snapshot of the counter) while
/// flooring the result at the live map length so the counter can never drop
/// *below* the resident set.
///
/// A plain `subtract_cache_entries(snapshot)` is unsafe here because a config
/// reload runs concurrently with both live request inserts *and* an in-flight
/// eviction pass. If an evictor `map.remove`s `r` entries and `fetch_sub(r)`s the
/// counter after this snapshot was loaded, those `r` entries are still part of
/// the snapshot (they were counted when inserted, before the load), so
/// subtracting the snapshot double-counts the evictor's `r` and can leave the
/// counter `r` below the live map size. Under-count is the dangerous direction:
/// inserts only trigger eviction from this counter (`entries > max_cache_entries`
/// in `insert_*_cache_entry`), so an under-count delays eviction and lets the
/// cache overshoot its configured bound until later inserts refill the deficit.
///
/// `DashMap::len()` read *inside* the `fetch_update` closure is a valid lower
/// bound on the resident set at that instant (it sums shard lengths; an entry is
/// counted iff its insert has landed, and every entry's counter `fetch_add`
/// follows its map insert). Flooring at `len()` therefore guarantees the
/// post-clear counter is `>= live`, preserving the load-bearing `counter >= live`
/// invariant. The benign bounded *over*-count documented in `clear_lookup_caches`
/// (an insert in the `[snapshot load, clear()]` window whose entry is removed by
/// `clear()` yet still counted) is unaffected — `len()` only ever raises the
/// floor, never lowers the value below it. `len()` is O(shards) and runs only on
/// the cold reload path, never the proxy hot path; CAS retries re-read it, which
/// is correct.
fn reconcile_cache_entries_after_clear<V>(
    counter: &AtomicUsize,
    map: &DashMap<String, V>,
    removed: usize,
) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |entries| {
        Some(entries.saturating_sub(removed).max(map.len()))
    });
}

/// Drop queued keys from an eviction reservoir on a config-driven cache clear.
///
/// Used so a rebuild does not leave stale candidate keys queued. `pop` is O(1)
/// and lock-free; stale keys are otherwise harmless (they self-skip on the
/// live-entry check in `frequency_aware_evict`), but draining keeps the
/// reservoir coherent with the cleared map.
///
/// The drain is bounded to the reservoir's fixed capacity rather than looping
/// until empty. A reload runs concurrently with request threads still inserting
/// cache misses (each `force_push`es a key here), so an unbounded
/// `while pop().is_some()` could be kept non-empty by a sustained
/// high-cardinality insert storm and make the reload spin for an unbounded
/// time. Popping at most `capacity` times still removes every key that was
/// queued when the clear began (the queue cannot hold more than `capacity`);
/// any keys pushed by races after that point are fresh candidates for the
/// rebuilt cache, and the few that may be stale self-skip on the next pass.
fn drain_reservoir(reservoir: &ArrayQueue<String>) {
    for _ in 0..reservoir.capacity() {
        if reservoir.pop().is_none() {
            break;
        }
    }
}

/// Append up to `budget` resident DashMap keys (not already in `seen`) to the
/// eviction `sample`, starting from a rotated, bounded shard-order offset.
///
/// Shared by the periodic resident-key blend and the underfilled-sample top-up
/// in `frequency_aware_evict`. The offset is `rotation.wrapping_mul(budget)`
/// taken modulo `sample_size + 1`, so the `skip` walks at most `sample_size`
/// extra positions and the whole step stays O(`sample_size`), never an O(n) map
/// scan. `rotation` advances the window across map positions over successive
/// calls so different resident keys are sampled over time. Frequencies come from
/// the Count-Min Sketch so the blended keys compete on the same footing as
/// reservoir candidates.
fn blend_resident_keys<V>(
    map: &DashMap<String, V>,
    sketch: &CountMinSketch,
    sample: &mut Vec<(String, u8)>,
    seen: &mut HashSet<String>,
    rotation: usize,
    budget: usize,
    sample_size: usize,
) {
    if budget == 0 {
        return;
    }
    let offset = rotation
        .wrapping_mul(budget)
        .checked_rem(sample_size + 1)
        .unwrap_or(0);
    for entry in map.iter().skip(offset).take(budget) {
        if !seen.insert(entry.key().clone()) {
            continue; // already sampled this pass
        }
        let freq = sketch.estimate(entry.key());
        sample.push((entry.key().clone(), freq));
    }
}

/// Evict entries from a DashMap using frequency-guided sampling.
///
/// Builds a bounded sample of candidate keys by draining the per-partition
/// eviction reservoir (the keys most recently inserted as cache misses),
/// estimates each entry's access frequency via the Count-Min Sketch, then
/// removes the least frequent entries from the sample. Sampling from the
/// reservoir rather than walking a shard-ordered DashMap prefix keeps each pass
/// O(`sample_size`) regardless of `max_entries` and lets cold entries anywhere
/// in the map become eviction candidates (every inserted key passed through the
/// reservoir), so hot entries near the front of shard iteration are no longer
/// the only ones at risk. Frequently accessed entries are still protected
/// (similar to Redis LFU and TinyUFO).
///
/// `blend_rotation` periodically mixes a small bounded slice of *resident* keys
/// into the sample so that entries which aged out of the reservoir before any
/// eviction fired — e.g. the earliest inserts under the default >=10k cap, which
/// fill the map before the first eviction and then fall out of the 4096-slot
/// reservoir — can still become eviction candidates instead of becoming
/// immortal. Production passes the per-partition eviction-attempts counter so
/// the blend rotates its window across map positions over successive passes and
/// only fires every `HEAD_BLEND_PERIOD` passes (the reservoir remains the
/// dominant source). On a blend pass the reservoir drain is capped so a fixed
/// slice of the sample budget (`<= sample_size / 4`) is *reserved* for resident
/// keys; without that reservation a sustained high-cardinality stream keeps the
/// reservoir full, the blend never gets spare budget, and the cold-resident
/// rescue silently stops contributing. Passing `0` disables the blend (used by
/// unit tests that assert pure-reservoir behavior). The rotated offset is capped
/// at `sample_size`, so the head walk stays O(`sample_size`) and never becomes an
/// O(n) scan.
///
/// The sample is also topped up from resident keys whenever it comes back
/// *underfilled* — shorter than twice the removal target — not only when it is
/// fully empty. A reload racing with inserts can leave the reservoir full of
/// stale/duplicate keys so the bounded pop loop yields only a handful of live
/// candidates; evicting that tiny sample wholesale would drop hot entries
/// regardless of frequency while cold entries remain resident. Topping up from a
/// bounded resident-key walk keeps eviction from being starved into removing its
/// entire sample. (This also subsumes the transient-empty case right after a
/// clear, so the cache still cannot overshoot capacity unbounded.) The top-up
/// walk is bounded by `sample_size`.
///
/// Residual (deliberate, not an oversight): the rotated blend offset is taken
/// modulo `sample_size + 1`, so `map.iter().skip(offset)` walks at most
/// `sample_size` positions and the blend sweeps only the first `~2 * sample_size`
/// shard-ordered positions, not the whole map. This cap is load-bearing: the
/// hot-path contract is that an eviction pass is O(`sample_size`) regardless of
/// `max_cache_entries`, and `skip(offset)` is O(`offset`). Rotating the offset
/// across the whole map (`% map.len()`) would make a blend pass O(`map.len()`) —
/// a per-eviction O(n) scan on the proxy path under the default >=10k (up to 1M)
/// cap — which is exactly what the reservoir design exists to avoid. Resident
/// keys deeper than the swept window therefore still rely on re-entering the
/// reservoir (a later access re-inserts them as a miss after a generation bump,
/// or a survivor requeue keeps them) to become candidates. Uniform coverage of
/// arbitrarily-deep stale residents would need shard-indexed sampling (a
/// DashMap-internal `shards()` walk that visits a bounded slice of each shard in
/// O(`sample_size`)); that is deferred as a heavier rework rather than paying an
/// O(n) blend scan here.
fn frequency_aware_evict<V>(
    map: &DashMap<String, V>,
    reservoir: &ArrayQueue<String>,
    sketch: &CountMinSketch,
    max_entries: usize,
    blend_rotation: u64,
) -> usize {
    let sample_size = max_entries.min(ROUTER_CACHE_EVICTION_SAMPLE_LIMIT);
    if sample_size < 4 {
        return 0;
    }

    let target_removals = (sample_size / 4).clamp(1, ROUTER_CACHE_EVICTION_MAX_REMOVALS);

    // Decide up front whether this is a periodic resident-key blend pass. On a
    // blend pass we *reserve* part of the sample budget for resident keys so the
    // blend always contributes, even when the reservoir alone could fill the
    // whole sample. Without reserving room, a sustained high-cardinality stream
    // keeps the reservoir full, the old `sample.len() < sample_size` guard never
    // fires, and the resident-key walk that is meant to rescue entries which aged
    // out of the reservoir before the first eviction (e.g. the earliest inserts
    // under the default >=10k cap) never runs — pinning those cold residents
    // permanently and shrinking effective capacity. Reserving caps the reservoir
    // drain so the blend has guaranteed headroom on its period.
    let blend_active = blend_rotation != 0 && blend_rotation.is_multiple_of(HEAD_BLEND_PERIOD);
    let head_reserve = if blend_active {
        (sample_size / 4).max(1)
    } else {
        0
    };
    let reservoir_budget = sample_size - head_reserve;

    // Drain up to `reservoir_budget` distinct, still-live candidate keys from the
    // reservoir. Bounded by `2 * sample_size` pops (O(1) each); stale keys
    // (already evicted) and duplicates are dropped so the sample reflects distinct
    // live entries. Popping past `reservoir_budget` makes headway through stale
    // entries without ever turning the drain into an unbounded loop, and leaves
    // `head_reserve` slots free for the blend below.
    let mut sample: Vec<(String, u8)> = Vec::with_capacity(sample_size);
    let mut seen: HashSet<String> = HashSet::with_capacity(sample_size);
    let max_pops = sample_size.saturating_mul(2);
    for _ in 0..max_pops {
        if sample.len() >= reservoir_budget {
            break;
        }
        let Some(key) = reservoir.pop() else {
            break;
        };
        if !map.contains_key(&key) {
            continue; // stale candidate; self-cleans from the reservoir
        }
        if !seen.insert(key.clone()) {
            continue; // duplicate within this pass
        }
        let freq = sketch.estimate(&key);
        sample.push((key, freq));
    }

    // Periodic resident-key blend: mix a small, rotating slice of resident keys
    // into the sample so older entries that fell out of the reservoir can still be
    // evicted. Runs only every `HEAD_BLEND_PERIOD` passes; the reserved budget
    // above guarantees it has room even when the reservoir is full, so the blend
    // actually contributes rather than only consuming spare budget. The reservoir
    // remains the dominant source (it gets `sample_size - head_reserve` of the
    // budget). `head_reserve` is at most `sample_size / 4`, so the walk stays
    // O(`sample_size`).
    if blend_active {
        let head_budget = head_reserve.min(sample_size - sample.len());
        let rotation_steps = (blend_rotation / HEAD_BLEND_PERIOD) as usize;
        blend_resident_keys(
            map,
            sketch,
            &mut sample,
            &mut seen,
            rotation_steps,
            head_budget,
            sample_size,
        );
    }

    // Top up an underfilled sample from resident keys before choosing victims.
    // The reservoir sample can come up short of the removal target even when the
    // reservoir is non-empty — e.g. after a reload races with inserts the queue
    // fills with stale/duplicate keys, so the bounded pop loop yields only a few
    // live candidates. The old code only topped up when the sample was *empty*,
    // so a tiny non-empty sample would have every member evicted regardless of
    // frequency (`to_remove == sample.len()`), evicting hot entries while many
    // cold entries remained resident. Treat any sample shorter than the removal
    // target like the empty case and supplement it with a bounded resident-key
    // walk so eviction is never starved into removing its whole sample. This walk
    // is also bounded by `sample_size`, so the pass stays O(`sample_size`).
    if sample.len() < target_removals * 2 {
        // Walk from the head (offset 0) rather than a rotated window: the top-up
        // is a rare recovery path (it only fires when the reservoir under-delivers)
        // and wants maximal coverage of accessible residents to fill the sample,
        // not the rotation the periodic blend uses to sweep over time. This also
        // exactly reproduces the previous empty-sample fallback's `take(sample_size)`
        // from the head when the reservoir yielded nothing.
        let topup_budget = sample_size - sample.len();
        blend_resident_keys(
            map,
            sketch,
            &mut sample,
            &mut seen,
            0,
            topup_budget,
            sample_size,
        );
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

    // Requeue the sampled survivors (everything not removed) so they remain
    // eviction candidates on a later pass. Without this, draining the reservoir
    // permanently dropped these still-live keys: in a saturated cache an old
    // cold-but-not-coldest entry would get a single chance to be removed and
    // then become effectively immortal, while subsequent passes could only
    // sample freshly inserted keys. `force_push` is O(1) and lock-free, and the
    // survivor count is bounded by `sample_size`, so requeueing keeps the pass
    // O(`sample_size`) and the reservoir a moving window over still-resident
    // recent inserts rather than a one-shot queue. Survivors came from the head
    // of the reservoir; pushing them back puts them behind newer inserts, which
    // is the intended recency ordering. Stale survivors (none here — every
    // sample entry was live when popped) would self-skip on the next pass.
    for (key, _) in sample.drain(to_remove..) {
        let _ = reservoir.force_push(key);
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
        // Width 1024 → 2048 cells; AGE_CHUNK is 256, so one threshold-crossing
        // increment cannot finish the pass.
        let cms = CountMinSketch::new(1024, 10);
        for _ in 0..9 {
            cms.increment("key-a");
        }
        assert_eq!(cms.estimate("key-a"), 9);
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);

        // The 10th increment: row goes 9→10, return is pre-aging, and aging arms
        // with a single bounded chunk — not a full-row sweep.
        let val = cms.increment("key-a");
        assert_eq!(val, 10, "Return value is pre-age post-increment");
        let remaining_after_arm = cms.age_remaining.load(Ordering::Relaxed);
        let total_cells = cms.total_cells();
        assert!(
            remaining_after_arm > 0,
            "aging cycle must still be in progress after one increment"
        );
        assert!(
            remaining_after_arm < total_cells,
            "threshold-crossing increment must age some cells"
        );
        let aged = total_cells - remaining_after_arm;
        assert_eq!(
            aged,
            CountMinSketch::AGE_CHUNK,
            "first aging step must process exactly AGE_CHUNK cells"
        );

        // Drain the rest of the cycle via age_step (no further key increments) so
        // the halved estimate is deterministic.
        let mut steps = 1usize; // already did one chunk in increment()
        while cms.age_remaining.load(Ordering::Relaxed) > 0 {
            let before = cms.age_remaining.load(Ordering::Relaxed);
            cms.age_step();
            let after = cms.age_remaining.load(Ordering::Relaxed);
            assert!(
                before - after <= CountMinSketch::AGE_CHUNK,
                "each age_step must be ≤ AGE_CHUNK"
            );
            steps += 1;
            assert!(steps <= total_cells.div_ceil(CountMinSketch::AGE_CHUNK));
        }
        assert_eq!(steps, total_cells.div_ceil(CountMinSketch::AGE_CHUNK));

        assert_eq!(
            cms.estimate("key-a"),
            5,
            "after a full incremental cycle, seeded counter must be halved"
        );
    }

    #[test]
    fn cms_incremental_aging_completes_without_full_row_sweep() {
        // Require a sketch large enough that one chunk cannot cover both rows.
        let width = 1024;
        let total_cells = width * 2;
        assert!(
            total_cells > CountMinSketch::AGE_CHUNK,
            "test setup must make a full-row sweep impossible in one step"
        );

        // High threshold so seeding and the observed cycle are not interleaved
        // with automatic re-arming.
        let cms = CountMinSketch::new(width, u64::MAX);
        for _ in 0..20 {
            cms.increment("hot");
        }
        assert_eq!(cms.estimate("hot"), 20);
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);

        // Pick a driver whose CMS cells do not overlap "hot", so the post-cycle
        // estimate stays deterministic under concurrent increments + aging.
        let hot0 = CountMinSketch::fnv1a("hot", 0) as usize & cms.width_mask;
        let hot1 = CountMinSketch::fnv1a("hot", 0x9e3779b97f4a7c15) as usize & cms.width_mask;
        let driver = (0..10_000)
            .map(|i| format!("cycle-driver-{i}"))
            .find(|k| {
                let d0 = CountMinSketch::fnv1a(k, 0) as usize & cms.width_mask;
                let d1 = CountMinSketch::fnv1a(k, 0x9e3779b97f4a7c15) as usize & cms.width_mask;
                d0 != hot0 && d0 != hot1 && d1 != hot0 && d1 != hot1
            })
            .expect("non-colliding driver key");

        // Arm a pass the same way the threshold path does, then drive completion
        // only through increment()'s age_step. Threshold is u64::MAX so increment
        // never re-arms mid-cycle.
        cms.arm_aging();
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), total_cells);

        let expected_steps = total_cells.div_ceil(CountMinSketch::AGE_CHUNK);
        let mut prev = total_cells;
        let mut increments = 0usize;
        while cms.age_remaining.load(Ordering::Relaxed) > 0 {
            cms.increment(&driver);
            let now = cms.age_remaining.load(Ordering::Relaxed);
            let aged = prev - now;
            assert!(
                aged > 0 && aged <= CountMinSketch::AGE_CHUNK,
                "expected 1..=AGE_CHUNK cells aged, got {aged} (prev={prev}, now={now})"
            );
            assert!(
                aged < total_cells,
                "a single increment must not sweep the full sketch"
            );
            prev = now;
            increments += 1;
            assert!(increments <= expected_steps);
        }

        assert_eq!(
            increments, expected_steps,
            "cycle must take cells/chunk increments, not one full sweep"
        );
        assert_eq!(cms.estimate("hot"), 10);
    }

    #[test]
    fn cms_age_chunk_constant_is_explicit() {
        assert_eq!(CountMinSketch::AGE_CHUNK, 256);
        assert_eq!(CMS_AGE_CHUNK, 256);
    }

    #[test]
    fn cms_idle_age_step_skips_owner_cas() {
        // Idle increments must not CAS `age_owner` (shared loads only). Armed
        // and pending cycles must still attempt ownership and make progress.
        let cms = CountMinSketch::new(1024, u64::MAX);
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);
        assert!(!cms.age_pending.load(Ordering::Relaxed));

        cms.age_step_owner_cas_attempts.store(0, Ordering::Relaxed);
        for _ in 0..8 {
            cms.age_step();
            let _ = cms.increment("idle-driver");
        }
        assert_eq!(
            cms.age_step_owner_cas_attempts.load(Ordering::Relaxed),
            0,
            "idle age_step / increment must not attempt age_owner acquisition"
        );
        assert!(!cms.age_owner.load(Ordering::Relaxed));
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);

        // Armed pass: must CAS and age one chunk.
        cms.arm_aging();
        let total_cells = cms.total_cells();
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), total_cells);
        cms.age_step_owner_cas_attempts.store(0, Ordering::Relaxed);
        cms.age_step();
        assert!(
            cms.age_step_owner_cas_attempts.load(Ordering::Relaxed) >= 1,
            "armed age_step must attempt age_owner acquisition"
        );
        assert_eq!(
            cms.age_remaining.load(Ordering::Relaxed),
            total_cells - CountMinSketch::AGE_CHUNK,
            "armed owner must age exactly one chunk"
        );
        assert!(!cms.age_owner.load(Ordering::Relaxed));

        // Pending re-arm with idle cursor: must CAS, consume pending, and start
        // a follow-up pass with bounded first-chunk work.
        cms.age_remaining.store(0, Ordering::Relaxed);
        cms.age_pending.store(true, Ordering::Relaxed);
        cms.age_step_owner_cas_attempts.store(0, Ordering::Relaxed);
        cms.age_step();
        assert!(
            cms.age_step_owner_cas_attempts.load(Ordering::Relaxed) >= 1,
            "pending age_step must attempt age_owner acquisition"
        );
        assert!(
            !cms.age_pending.load(Ordering::Relaxed),
            "pending bit consumed when the follow-up pass arms"
        );
        assert_eq!(
            cms.age_remaining.load(Ordering::Relaxed),
            total_cells - CountMinSketch::AGE_CHUNK,
            "pending re-arm must age the first follow-up chunk"
        );
        assert!(!cms.age_owner.load(Ordering::Relaxed));
    }

    #[test]
    fn cms_overlapping_threshold_rearms_without_double_halving() {
        // Production minimum width: one chunk cannot finish a pass.
        let width: usize = 1024;
        let total_cells = width * 2;
        let steps_per_pass = total_cells.div_ceil(CountMinSketch::AGE_CHUNK);
        assert!(steps_per_pass > 2);

        // High threshold so seeding and explicit arm/pending control the cycle.
        let cms = CountMinSketch::new(width, u64::MAX);
        for _ in 0..20 {
            cms.increment("hot");
        }
        assert_eq!(cms.estimate("hot"), 20);

        let hot0 = CountMinSketch::fnv1a("hot", 0) as usize & cms.width_mask;
        let hot1 = CountMinSketch::fnv1a("hot", 0x9e3779b97f4a7c15) as usize & cms.width_mask;
        let driver = (0..10_000)
            .map(|i| format!("overlap-driver-{i}"))
            .find(|k| {
                let d0 = CountMinSketch::fnv1a(k, 0) as usize & cms.width_mask;
                let d1 = CountMinSketch::fnv1a(k, 0x9e3779b97f4a7c15) as usize & cms.width_mask;
                d0 != hot0 && d0 != hot1 && d1 != hot0 && d1 != hot1
            })
            .expect("non-colliding driver key");

        cms.arm_aging();
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), total_cells);

        // Progress one chunk, then simulate a mid-pass threshold hit.
        cms.increment(&driver);
        assert!(cms.age_remaining.load(Ordering::Relaxed) > 0);
        cms.arm_aging();
        assert!(
            cms.age_pending.load(Ordering::Relaxed),
            "mid-pass arm must record an owed follow-up pass"
        );

        // Drain the first pass via increment; every step stays ≤ AGE_CHUNK.
        let mut guard = 0usize;
        while cms.age_remaining.load(Ordering::Relaxed) > 0 {
            let before = cms.age_remaining.load(Ordering::Relaxed);
            cms.increment(&driver);
            let after = cms.age_remaining.load(Ordering::Relaxed);
            let aged = before.saturating_sub(after);
            assert!(
                aged > 0 && aged <= CountMinSketch::AGE_CHUNK,
                "expected 1..=AGE_CHUNK cells aged, got {aged}"
            );
            guard += 1;
            assert!(guard <= steps_per_pass);
        }
        assert!(
            cms.age_pending.load(Ordering::Relaxed),
            "finishing the first pass must leave the owed follow-up pending"
        );
        assert_eq!(cms.estimate("hot"), 10, "exactly one full pass so far");

        // Next increment re-arms from pending and ages the first follow-up chunk.
        let before = cms.age_remaining.load(Ordering::Relaxed);
        assert_eq!(before, 0);
        cms.increment(&driver);
        let after = cms.age_remaining.load(Ordering::Relaxed);
        assert!(
            !cms.age_pending.load(Ordering::Relaxed),
            "pending bit consumed when the follow-up pass arms"
        );
        assert_eq!(
            after,
            total_cells - CountMinSketch::AGE_CHUNK,
            "re-arm must start a fresh full pass and age one chunk"
        );
        assert_eq!(
            before + (total_cells - after),
            CountMinSketch::AGE_CHUNK,
            "re-arm + first chunk must stay within AGE_CHUNK"
        );

        // Finish the follow-up pass.
        while cms.age_remaining.load(Ordering::Relaxed) > 0
            || cms.age_pending.load(Ordering::Relaxed)
        {
            cms.age_step();
            guard += 1;
            assert!(guard <= steps_per_pass * 3);
        }

        // Two complete passes: 20 → 10 → 5. No mid-pass double-halving.
        assert_eq!(cms.estimate("hot"), 5);
        assert!(!cms.age_pending.load(Ordering::Relaxed));
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cms_zero_age_threshold_is_raised_to_one() {
        let cms = CountMinSketch::new(1024, 0);
        assert_eq!(cms.age_threshold, 1);
        // Must not panic on is_multiple_of(0); first increment arms + steps.
        let _ = cms.increment("k");
        assert_eq!(cms.total_increments.load(Ordering::Relaxed), 1);
        assert_eq!(
            cms.age_remaining.load(Ordering::Relaxed),
            cms.total_cells() - CountMinSketch::AGE_CHUNK,
            "threshold=1 must arm on the first increment with bounded work"
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
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);
        assert!(!cms.age_pending.load(Ordering::Relaxed));
        assert!(!cms.age_owner.load(Ordering::Relaxed));
    }

    #[test]
    fn cms_reset_does_not_steal_age_owner_or_allow_stale_cursor() {
        // Regression for blind `age_owner.store(false)` in `reset`: if reset
        // clears the ownership flag while another thread still owns a mid-chunk
        // `age_step`, that owner can later publish a stale nonzero
        // `age_remaining` after the clear — violating single-owner and letting
        // post-reload aging overlap. Correct reset waits to own `age_owner`
        // before clearing, so the active owner's publish happens before the
        // clear (or is finished under ownership) and the final cursor is 0.
        use std::sync::{Arc, Barrier};

        let width = 1024;
        let total_cells = width * 2;
        assert!(total_cells > CountMinSketch::AGE_CHUNK);

        let cms = Arc::new(CountMinSketch::new(width, u64::MAX));
        for cell in cms.row0.0.iter().chain(cms.row1.0.iter()) {
            cell.store(8, Ordering::Relaxed);
        }
        cms.age_remaining.store(total_cells, Ordering::Relaxed);
        cms.age_owner_acquire_spins.store(0, Ordering::Relaxed);

        // 3-way ready: owner holds mid-chunk, reset + main are about to run.
        let ready = Arc::new(Barrier::new(3));
        // Owner stays mid-hold until main confirms reset has engaged.
        let release_hold = Arc::new(Barrier::new(2));

        let cms_owner = Arc::clone(&cms);
        let ready_owner = Arc::clone(&ready);
        let release_owner = Arc::clone(&release_hold);
        let owner = std::thread::spawn(move || {
            cms_owner.age_step_with_hold_gates(&ready_owner, &release_owner);
        });

        let cms_reset = Arc::clone(&cms);
        let ready_reset = Arc::clone(&ready);
        let reset = std::thread::spawn(move || {
            ready_reset.wait();
            cms_reset.reset();
        });

        ready.wait();
        // Owner holds `age_owner` and has not published yet. Wait until reset
        // either steals the flag / clears state (buggy blind store) or is
        // observed spinning in `acquire_age_owner_blocking` (correct wait).
        loop {
            if !cms.age_owner.load(Ordering::Acquire) {
                // Buggy reset released ownership under the active owner.
                break;
            }
            if cms.age_owner_acquire_spins.load(Ordering::Relaxed) > 0 {
                // Correct reset is blocked waiting for exclusive ownership.
                assert!(
                    cms.age_owner.load(Ordering::Acquire),
                    "reset must not clear another thread's age_owner while spinning"
                );
                assert_eq!(
                    cms.age_remaining.load(Ordering::Relaxed),
                    total_cells,
                    "reset must not clear the cursor until it owns age_owner"
                );
                break;
            }
            std::hint::spin_loop();
            std::thread::yield_now();
        }

        release_hold.wait();
        owner.join().expect("owner thread");
        reset.join().expect("reset thread");

        // If reset cleared ownership under the owner, the owner's post-hold
        // publish leaves a stale nonzero cursor here. Correct reset clears only
        // after owning, so the cursor ends idle.
        assert_eq!(
            cms.age_remaining.load(Ordering::Relaxed),
            0,
            "reset must leave age_remaining idle; a nonzero cursor after join \
             means an owner republished a stale remaining after a stolen flag"
        );
        assert!(!cms.age_owner.load(Ordering::Relaxed));
        assert!(!cms.age_pending.load(Ordering::Relaxed));
        assert_eq!(cms.total_increments.load(Ordering::Relaxed), 0);
        for cell in cms.row0.0.iter().chain(cms.row1.0.iter()) {
            assert_eq!(
                cell.load(Ordering::Relaxed),
                0,
                "reset must zero every cell once it exclusively owns aging"
            );
        }
    }

    #[test]
    fn cms_concurrent_aging_generations_do_not_overlap() {
        // Regression for the claim-before-mutate race: publishing
        // `age_remaining == 0` before the last chunk's cell RMWs finish lets a
        // concurrent caller consume `age_pending`, re-arm, and double-halve.
        // Seed every cell to 8, arm one pass with an owed follow-up, then hammer
        // `age_step` from many threads. Exactly two completed generations must
        // leave every cell at 2 (8 >> 2); overlapping gens would push some ≤ 1.
        use std::sync::{Arc, Barrier};

        let width: usize = 1024;
        let total_cells = width * 2;
        let steps_per_pass = total_cells.div_ceil(CountMinSketch::AGE_CHUNK);
        assert!(steps_per_pass > 2);

        let cms = Arc::new(CountMinSketch::new(width, u64::MAX));
        for cell in cms.row0.0.iter().chain(cms.row1.0.iter()) {
            cell.store(8, Ordering::Relaxed);
        }

        cms.arm_aging();
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), total_cells);
        // Owed follow-up so the idle→re-arm race is on the critical path the
        // moment the first pass's last chunk completes.
        cms.age_pending.store(true, Ordering::Relaxed);

        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));
        // Each thread runs enough steps to cover both passes several times over
        // even if most CAS attempts lose ownership.
        let steps_per_thread = steps_per_pass * 4;
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let cms = Arc::clone(&cms);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..steps_per_thread {
                    cms.age_step();
                }
            }));
        }
        for handle in handles {
            handle.join().expect("aging worker thread");
        }

        // Finish any leftover owned chunk / pending re-arm on this thread.
        let mut guard = 0usize;
        while cms.age_remaining.load(Ordering::Relaxed) > 0
            || cms.age_pending.load(Ordering::Relaxed)
            || cms.age_owner.load(Ordering::Acquire)
        {
            cms.age_step();
            guard += 1;
            assert!(
                guard <= steps_per_pass * 4,
                "drain must complete within a bounded number of steps"
            );
        }

        assert!(!cms.age_pending.load(Ordering::Relaxed));
        assert_eq!(cms.age_remaining.load(Ordering::Relaxed), 0);
        assert!(!cms.age_owner.load(Ordering::Relaxed));

        for cell in cms.row0.0.iter().chain(cms.row1.0.iter()) {
            assert_eq!(
                cell.load(Ordering::Relaxed),
                2,
                "each cell must be halved exactly twice (8→4→2); \
                 a smaller value means overlapping generations double-halved"
            );
        }
    }

    #[test]
    fn cms_width_rounds_to_power_of_two() {
        let cms = CountMinSketch::new(100, 1000);
        // 100 rounds up to 128, so width_mask = 127
        assert_eq!(cms.width_mask, 127);
    }

    // ── frequency_aware_evict tests ─────────────────────────────────────

    /// Build an eviction reservoir holding every key currently in `map`.
    /// Eviction now samples candidates from the reservoir, so the unit tests
    /// must enqueue the keys they expect to be eligible.
    fn reservoir_with_map_keys<V>(map: &DashMap<String, V>) -> ArrayQueue<String> {
        let reservoir = ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY);
        for entry in map.iter() {
            let _ = reservoir.force_push(entry.key().clone());
        }
        reservoir
    }

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

        let reservoir = reservoir_with_map_keys(&map);
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 100, 0);
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
        let reservoir = reservoir_with_map_keys(&map);
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 100, 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn evict_very_small_capacity_is_noop() {
        // Tiny capacities skip sampling because there is no meaningful LFU set.
        let sketch = CountMinSketch::new(64, 1000);
        let map: DashMap<String, ()> = DashMap::new();
        map.insert("a".into(), ());
        let reservoir = reservoir_with_map_keys(&map);
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 3, 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn evict_large_capacity_uses_bounded_sample() {
        let sketch = CountMinSketch::new(65_536, 1_000_000);
        let map: DashMap<String, ()> = DashMap::new();

        for i in 0..1_000 {
            let key = format!("key-{i}");
            map.insert(key.clone(), ());
            sketch.increment(&key);
        }

        let reservoir = reservoir_with_map_keys(&map);
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 10_000, 0);
        assert!(
            removed <= ROUTER_CACHE_EVICTION_MAX_REMOVALS,
            "eviction removed {removed} entries despite bounded sample"
        );
        assert!(
            map.len() >= 1_000 - ROUTER_CACHE_EVICTION_MAX_REMOVALS,
            "eviction should not scan and remove the whole map"
        );
    }

    #[test]
    fn evict_falls_back_to_head_when_reservoir_empty() {
        // If the reservoir is empty (e.g. right after a clear) eviction must
        // still make progress via the bounded head sample so the cache cannot
        // grow without bound.
        let sketch = CountMinSketch::new(1024, 100_000);
        let map: DashMap<String, ()> = DashMap::new();
        for i in 0..200 {
            map.insert(format!("key-{i}"), ());
        }
        let empty = ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY);
        let removed = frequency_aware_evict(&map, &empty, &sketch, 200, 0);
        assert!(removed > 0, "empty reservoir must fall back to head sample");
        assert!(removed <= ROUTER_CACHE_EVICTION_MAX_REMOVALS);
    }

    #[test]
    fn evict_skips_stale_reservoir_keys() {
        // Keys queued in the reservoir but no longer in the map (already evicted
        // or cleared) must be skipped, not counted, and must not cause spurious
        // removals.
        let sketch = CountMinSketch::new(1024, 100_000);
        let map: DashMap<String, ()> = DashMap::new();
        for i in 0..50 {
            map.insert(format!("live-{i}"), ());
        }
        let reservoir = ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY);
        // Queue stale keys first, then a couple of live ones.
        for i in 0..100 {
            let _ = reservoir.force_push(format!("stale-{i}"));
        }
        for i in 0..50 {
            let _ = reservoir.force_push(format!("live-{i}"));
        }
        let before = map.len();
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 50, 0);
        // Only live keys can be removed; stale candidates never touch the map.
        assert_eq!(map.len() + removed, before);
        for i in 0..100 {
            assert!(!map.contains_key(&format!("stale-{i}")));
        }
    }

    #[test]
    fn evict_requeues_sampled_survivors() {
        // Survivors of a sample (live keys popped but not in the removed
        // bottom quartile) must be pushed back into the reservoir so a later
        // pass can reconsider them. Otherwise a single pass would permanently
        // drop them and they could become immortal once resident.
        let sketch = CountMinSketch::new(1024, 100_000);
        let map: DashMap<String, ()> = DashMap::new();
        for i in 0..50 {
            map.insert(format!("key-{i}"), ());
            // Uniform-ish frequency so removals come from a small quartile and
            // most sampled keys survive the pass.
            sketch.increment(&format!("key-{i}"));
        }
        let reservoir = reservoir_with_map_keys(&map);

        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 50, 0);
        assert!(removed > 0, "expected at least one removal");
        // Survivors were requeued: the reservoir holds the sampled-but-kept
        // keys (sample_size - removed), not zero.
        let surviving_candidates = reservoir.len();
        assert!(
            surviving_candidates > 0,
            "sampled survivors must be requeued, reservoir is empty"
        );
        // Every requeued key is still live in the map (no stale survivors).
        let mut drained = Vec::new();
        while let Some(k) = reservoir.pop() {
            assert!(
                map.contains_key(&k),
                "requeued survivor {k} is not a live map entry"
            );
            drained.push(k);
        }
        assert_eq!(drained.len(), surviving_candidates);
    }

    #[test]
    fn blend_resident_keys_appends_within_bounds() {
        // Direct unit test of the shared resident-key walk: it appends up to
        // `budget` not-yet-seen resident keys, dedups against `seen`, and the
        // rotated offset is taken modulo `sample_size + 1` so it never panics or
        // walks more than `budget` positions.
        let sketch = CountMinSketch::new(1024, 100_000);
        let map: DashMap<String, ()> = DashMap::new();
        for i in 0..100 {
            map.insert(format!("k-{i}"), ());
        }
        let mut sample: Vec<(String, u8)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // budget 0 is a no-op.
        blend_resident_keys(&map, &sketch, &mut sample, &mut seen, 3, 0, 64);
        assert!(sample.is_empty());

        // A normal call appends exactly `budget` distinct keys.
        blend_resident_keys(&map, &sketch, &mut sample, &mut seen, 1, 8, 64);
        assert_eq!(sample.len(), 8);
        assert_eq!(seen.len(), 8);

        // Keys already in `seen` are skipped (no duplicates appended).
        let before = sample.len();
        let dup_key = sample[0].0.clone();
        let mut seen_with_dup = seen.clone();
        // Force the walk to encounter an already-seen key by seeding `seen` with
        // everything; the next call must add nothing.
        for entry in map.iter() {
            seen_with_dup.insert(entry.key().clone());
        }
        blend_resident_keys(&map, &sketch, &mut sample, &mut seen_with_dup, 2, 8, 64);
        assert_eq!(sample.len(), before, "all-seen walk must append nothing");
        assert!(seen_with_dup.contains(&dup_key));

        // A large rotation must not panic (offset is reduced modulo sample_size+1).
        blend_resident_keys(&map, &sketch, &mut sample, &mut seen, usize::MAX, 4, 64);
    }

    #[test]
    fn evict_blend_reserves_budget_on_blend_pass() {
        // Regression for the reserved-budget fix (F2): on a blend pass the
        // reservoir drain is capped (`reservoir_budget = sample_size - head_reserve`)
        // so the resident-key blend always has room, even when the reservoir alone
        // could fill the whole sample. Without the reservation a saturated
        // reservoir filled the sample, the old `sample.len() < sample_size` guard
        // never fired, and cold residents that aged out of the reservoir could
        // never be evicted.
        //
        // Sizing is chosen so coverage is deterministic, not shard-order-luck:
        // sample_size = 40 -> head_reserve = 10, reservoir_budget = 30. The map
        // holds 40 HOT keys (saturating the reservoir past reservoir_budget) plus
        // 20 COLD keys absent from the reservoir (60 entries total). The blend
        // walk covers a rotating `[offset, offset+10)` window with offsets
        // sweeping 0..40 over rotations, so its union covers map positions 0..49;
        // at most 10 of the 20 cold keys can sit in positions 50..59, so >=10 cold
        // keys are guaranteed inside the covered window and become candidates.
        let sketch = CountMinSketch::new(8192, 1_000_000);
        let map: DashMap<String, ()> = DashMap::new();
        for i in 0..20 {
            let cold = format!("cold-{i}");
            map.insert(cold.clone(), ());
            sketch.increment(&cold); // freq 1
        }
        for i in 0..40 {
            let hot = format!("hot-{i}");
            map.insert(hot.clone(), ());
            for _ in 0..100 {
                sketch.increment(&hot); // hot
            }
        }
        let reservoir = ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY);

        // Run blend passes across rotations, re-saturating the reservoir with hot,
        // live keys before each pass (mimics sustained hot traffic keeping it full
        // so the reservoir would otherwise monopolize the sample). The F2 guarantee
        // is that cold residents *become candidates*: a cold key (freq 1) sorts
        // below every co-sampled hot key (freq 100), so as soon as the rotating
        // blend window covers a cold position it is evicted. Coverage of map
        // positions 0..49 is guaranteed (see sizing note), and >=10 cold keys must
        // lie there, so at least one cold key is deterministically evicted within
        // the sweep — impossible if the blend never ran for lack of reserved room.
        let mut cold_evicted = false;
        for r in 1..=32u64 {
            for i in 0..40 {
                let _ = reservoir.force_push(format!("hot-{i}"));
            }
            let pass = r * HEAD_BLEND_PERIOD; // always a blend pass
            let _ = frequency_aware_evict(&map, &reservoir, &sketch, 40, pass);
            let cold_remaining = (0..20)
                .filter(|i| map.contains_key(&format!("cold-{i}")))
                .count();
            if cold_remaining < 20 {
                cold_evicted = true;
                break;
            }
        }
        assert!(
            cold_evicted,
            "reserved blend budget must let cold residents (absent from a full \
             reservoir) become eviction candidates; none were evicted across the \
             rotation sweep (the blend never ran for lack of reserved room)"
        );
    }

    #[test]
    fn evict_tops_up_underfilled_sample_instead_of_clearing_it() {
        // Regression for the top-up fix (F3): a reservoir polluted with stale
        // keys can yield only a couple of live candidates. The old code only
        // topped up when the live sample was *empty*, so a tiny non-empty sample
        // had every member evicted regardless of frequency. Here the only live
        // reservoir candidates are HOT; without the top-up they would all be
        // removed even though many cold residents exist. With the top-up, cold
        // residents are pulled in so the hot candidates survive.
        let sketch = CountMinSketch::new(4096, 100_000);
        let map: DashMap<String, ()> = DashMap::new();
        // Cold residents not in the reservoir (occupy the head of the map for the
        // top-up walk's `skip(0)` offset on rotation 1).
        for i in 0..256 {
            let key = format!("cold-{i}");
            map.insert(key.clone(), ());
            sketch.increment(&key); // freq 1
        }
        // Two hot live keys, plus a flood of stale keys, in the reservoir.
        let reservoir = ArrayQueue::new(ROUTER_CACHE_EVICTION_RING_CAPACITY);
        for i in 0..2 {
            let key = format!("hot-{i}");
            map.insert(key.clone(), ());
            for _ in 0..200 {
                sketch.increment(&key);
            }
        }
        // Stale keys first so the bounded pop loop burns its budget on them and
        // the live sample comes up short (only the 2 hot keys are live).
        for i in 0..400 {
            let _ = reservoir.force_push(format!("stale-{i}"));
        }
        for i in 0..2 {
            let _ = reservoir.force_push(format!("hot-{i}"));
        }

        // Non-blend pass (rotation not divisible by HEAD_BLEND_PERIOD) so only the
        // shortfall top-up can supply extra candidates. `to_remove` is
        // target_removals (sample_size/4 = 64), so without the top-up the 2-key
        // sample would lose both hot keys; with it, 64 cold residents absorb the
        // removal.
        let removed = frequency_aware_evict(&map, &reservoir, &sketch, 257, 1);
        assert!(removed > 0, "underfilled sample must still evict");
        assert!(
            map.contains_key("hot-0") && map.contains_key("hot-1"),
            "hot live candidates must not be wholesale-evicted from a tiny sample"
        );
        let cold_remaining = (0..256)
            .filter(|i| map.contains_key(&format!("cold-{i}")))
            .count();
        assert!(
            cold_remaining < 256,
            "top-up should let cold residents absorb the eviction (cold_remaining={cold_remaining})"
        );
    }

    #[test]
    fn successive_evictions_stay_bounded_and_fire_passes() {
        // Drive several real eviction passes through `evict_prefix_sample` and
        // assert the cache stays bounded near capacity and the pass counter
        // advances (eviction is actually firing on cold inserts).
        let config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("p", "/")],
            ..GatewayConfig::default()
        };
        // Tiny capacity so each cache-miss insert trips eviction quickly.
        let cache = RouterCache::new(&config, 8);

        // Generate enough distinct paths to force multiple eviction passes.
        for i in 0..200 {
            let _ = cache.find_proxy(None, &format!("/p/{i}"));
        }

        let attempts = cache.prefix_eviction_attempts.load(Ordering::Relaxed);
        assert!(
            attempts >= 2,
            "expected multiple eviction passes, got {attempts}"
        );
        // Cache stays bounded near capacity even under sustained cold-insert
        // churn (the reservoir-driven sample keeps eviction bounded per pass).
        assert!(
            cache.cache_len() <= cache.max_cache_entries + ROUTER_CACHE_EVICTION_MAX_REMOVALS,
            "cache should stay bounded, len={}",
            cache.cache_len()
        );
    }

    #[test]
    fn eviction_covers_cold_entries_and_protects_hot_ones() {
        // Regression for the bounded-prefix eviction bug: under high-cardinality
        // churn, cold entries that land deep in the shard-ordered map must still
        // become eviction candidates (via the insert-time reservoir), while hot
        // entries that are repeatedly accessed must survive. The old rotation
        // only ever sampled the first ~4096 iterator positions, so deep cold
        // entries were immortal and hot entries in the covered windows churned.
        let config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("p", "/")],
            ..GatewayConfig::default()
        };
        // Capacity well below the number of distinct cold paths so eviction runs
        // continuously, but the reservoir (4096) dwarfs it so candidates are
        // drawn from the recent-insert stream, not a shard prefix.
        let cache = RouterCache::new(&config, 256);

        // A small set of hot paths, hammered repeatedly so their frequency stays
        // high across the run.
        let hot: Vec<String> = (0..8).map(|i| format!("/p/hot-{i}")).collect();
        for _ in 0..50 {
            for h in &hot {
                let _ = cache.find_proxy(None, h);
            }
        }

        // Drive a large stream of distinct cold paths interleaved with hot hits.
        // Far more than capacity, so the cache is continuously evicting.
        for i in 0..5_000 {
            let _ = cache.find_proxy(None, &format!("/p/cold-{i}"));
            if i % 4 == 0 {
                for h in &hot {
                    let _ = cache.find_proxy(None, h);
                }
            }
        }

        // The cache stayed bounded despite 5k distinct cold inserts — proof the
        // deep cold entries were reachable as eviction candidates (otherwise the
        // counter-driven cap could not have held).
        assert!(
            cache.cache_len() <= cache.max_cache_entries + ROUTER_CACHE_EVICTION_MAX_REMOVALS,
            "cache should stay bounded under high-cardinality churn, len={}",
            cache.cache_len()
        );

        // Hot entries must have *survived* eviction on their own frequency, so
        // inspect cache residency directly rather than calling `find_proxy`
        // (which would repopulate a missing entry from the route table and mask
        // an eviction). The hot keys were accumulating frequency throughout the
        // run (50 warm-up hits + ~1250 interleaved hits each), so they should be
        // far above the cold keys (frequency 1) the sampler removes. The old
        // prefix-only sampler would have evicted hot entries sitting in the
        // covered shard windows; this asserts the reservoir+sketch keeps them.
        let surviving_hot = hot
            .iter()
            .filter(|h| cache.prefix_cache.contains_key(&make_cache_key(None, h)))
            .count();
        assert_eq!(
            surviving_hot,
            hot.len(),
            "all hot entries should still be resident in the cache (not repopulated): \
             survived {surviving_hot}/{}",
            hot.len()
        );
    }

    #[test]
    fn clear_lookup_caches_keeps_counter_coherent() {
        // After a clear, the entry counter must equal the live map length so the
        // counter-driven eviction cap is not desynced below the real count.
        let config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("p", "/")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 10_000);
        for i in 0..500 {
            let _ = cache.find_proxy(None, &format!("/p/{i}"));
        }
        assert!(cache.cache_len() > 0);
        cache.clear_lookup_caches();
        assert_eq!(
            cache.cache_len(),
            cache.prefix_cache.len(),
            "prefix counter must match the live map length after clear"
        );
        assert_eq!(
            cache.regex_cache_len(),
            cache.regex_cache.len(),
            "regex counter must match the live map length after clear"
        );
        // The reservoir is drained so no stale candidates linger.
        assert!(cache.prefix_eviction_reservoir.is_empty());
        assert!(cache.regex_eviction_reservoir.is_empty());
    }

    #[test]
    fn reconcile_after_clear_never_undercounts_live_entries() {
        // Models the clear-vs-evict race: a pre-clear counter snapshot can
        // over-cover the live set when an in-flight eviction pass subtracts its
        // own removals after the snapshot was taken. Subtracting the bare
        // snapshot would drive the counter below the resident map; the
        // `max(map.len())` floor must prevent that (under-count is the dangerous
        // direction — it delays eviction and lets the cache overshoot its cap).
        let map: DashMap<String, u8> = DashMap::new();
        // Resident set survives the "clear" (these stand in for race-inserts that
        // landed after clear() but are still live and counted).
        for i in 0..40 {
            map.insert(format!("live-{i}"), 1);
        }
        let counter = AtomicUsize::new(40);
        // A racing evictor already subtracted 25 of these 40 from the counter,
        // but the stale snapshot still reflects the full 40 (those 25 were
        // counted before the snapshot load).
        counter.fetch_sub(25, Ordering::Relaxed);
        let stale_snapshot = 40usize;
        reconcile_cache_entries_after_clear(&counter, &map, stale_snapshot);
        // Bare subtract would have saturated to 0 (15 - 40); the floor keeps the
        // counter at >= the 40 live entries, so the cap can never be under-driven.
        assert_eq!(
            counter.load(Ordering::Relaxed),
            map.len(),
            "counter must be floored at the live map length, never below it"
        );
        assert!(counter.load(Ordering::Relaxed) >= map.len());
    }

    #[test]
    fn reconcile_after_clear_subtracts_when_above_live_floor() {
        // When no race is in play the helper behaves like the plain subtract:
        // snapshot fully removed, counter lands at the (empty) live length.
        let map: DashMap<String, u8> = DashMap::new();
        let counter = AtomicUsize::new(500);
        reconcile_cache_entries_after_clear(&counter, &map, 500);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // With residents present and a snapshot that does not over-cover them,
        // the subtract still applies and floors at the live length.
        for i in 0..10 {
            map.insert(format!("k-{i}"), 1);
        }
        let counter = AtomicUsize::new(310);
        reconcile_cache_entries_after_clear(&counter, &map, 300);
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    // ── RouterCache::new auto-resolution tests ──────────────────────────
    //
    // FERRUM_ROUTER_CACHE_MAX_ENTRIES=0 is the documented "auto" sentinel.
    // Harden `new` itself so direct callers (tests, future refactors) can't
    // end up with an effectively unbounded cache under tiny explicit capacities.

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
            dispatch_port_override_fallback: None,
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
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
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
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
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
        let table = cache.route_table_for_tests();

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
        let table = cache.route_table_for_tests();
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
        let table = cache.route_table_for_tests();

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
        let table = cache.route_table_for_tests();

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
        let table = cache.route_table_for_tests();

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
        let table = cache.route_table_for_tests();

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
        let table = cache.route_table_for_tests();

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
    fn store_route_table_snapshot_clears_lookup_caches_on_generation_change() {
        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old", "/api")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&old_config, 100);

        let old = cache
            .find_proxy(None, "/api/resource")
            .expect("old route should match");
        assert_eq!(old.proxy.id, "old");
        assert_eq!(cache.cache_len(), 1);

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new", "/api")],
            ..GatewayConfig::default()
        };
        cache.store_route_table_snapshot(RouterCache::build_route_table_snapshot(&new_config), 2);

        let (prefix, regex, _, _, _) = cache.cache_stats();
        assert_eq!(prefix, 0, "prefix cache should clear on route reload");
        assert_eq!(regex, 0, "regex cache should clear on route reload");

        let new = cache
            .find_proxy(None, "/api/resource")
            .expect("new route should match");
        assert_eq!(new.proxy.id, "new");
        assert_eq!(cache.cache_len(), 1);
    }

    #[test]
    fn standalone_route_snapshot_publishes_table_and_generation_together() {
        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old", "/api")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&old_config, 100);

        let old = cache
            .find_proxy(None, "/api/resource")
            .expect("old route should match");
        assert_eq!(old.proxy.id, "old");
        assert_eq!(cache.route_snapshot_for_tests().generation, 1);

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new", "/api")],
            ..GatewayConfig::default()
        };
        cache.store_route_table_snapshot(RouterCache::build_route_table_snapshot(&new_config), 2);

        let snapshot = cache.route_snapshot_for_tests();
        assert_eq!(snapshot.generation, 2);
        let new = cache
            .find_proxy_in_snapshot(&snapshot.table, snapshot.generation, None, "/api/resource")
            .expect("new route should match through the published snapshot");
        assert_eq!(new.proxy.id, "new");
    }

    #[test]
    fn standalone_lookup_rejects_stale_cache_after_snapshot_publication() {
        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old", "/api")],
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&old_config, 100);

        let old = cache
            .find_proxy(None, "/api/resource")
            .expect("old route should match");
        assert_eq!(old.proxy.id, "old");
        assert_eq!(cache.cache_len(), 1);

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new", "/api")],
            ..GatewayConfig::default()
        };
        cache.publish_route_snapshot_without_clearing_for_tests(
            RouterCache::build_route_table_snapshot(&new_config),
            2,
        );
        assert_eq!(
            cache.cache_len(),
            1,
            "old generation cache entry should still be resident before reload clearing"
        );

        let new = cache
            .find_proxy(None, "/api/resource")
            .expect("new route should match despite stale resident cache entry");
        assert_eq!(new.proxy.id, "new");
        let snapshot = cache.route_snapshot_for_tests();
        assert_eq!(snapshot.generation, 2);
    }

    #[test]
    fn standalone_lookup_during_reload_observes_one_complete_route_snapshot() {
        use std::sync::{Barrier, mpsc};

        let old_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("old", "/api")],
            ..GatewayConfig::default()
        };
        let cache = Arc::new(RouterCache::new(&old_config, 100));
        let old = cache
            .find_proxy(None, "/api/resource")
            .expect("old route should match before reload");
        assert_eq!(old.proxy.id, "old");

        let new_config = GatewayConfig {
            proxies: vec![minimal_proxy_for_routing("new", "/api")],
            ..GatewayConfig::default()
        };
        let new_table = RouterCache::build_route_table_snapshot(&new_config);

        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        let reader_cache = Arc::clone(&cache);
        let reader_barrier = Arc::clone(&barrier);
        let reader = std::thread::spawn(move || {
            reader_barrier.wait();
            let observed = reader_cache
                .find_proxy(None, "/api/resource")
                .map(|route_match| route_match.proxy.id.clone());
            tx.send(observed).expect("send observed route");
        });

        barrier.wait();
        cache.store_route_table_snapshot(new_table, 2);
        let observed = rx.recv().expect("receive observed route");
        reader.join().expect("reader thread should not panic");

        assert!(
            matches!(observed.as_deref(), Some("old") | Some("new")),
            "lookup must observe either the complete old snapshot or the complete new snapshot, got {observed:?}"
        );
        let after = cache
            .find_proxy(None, "/api/resource")
            .expect("route should match after reload");
        assert_eq!(after.proxy.id, "new");
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
        let table = cache.route_table_for_tests();

        // Tiers hold exactly the lowest-service-port representative.
        let rm = cache
            .find_proxy(Some("reviews"), "/")
            .expect("representative route matches by host");
        assert_eq!(rm.proxy.id, "__mesh-inbound-default-reviews-80");

        // Inbound orig-dst (container port) picks each sibling. A service-port
        // default inbound group is NOT ingress, so the authz listener port is
        // `None` (authz uses the backend port).
        for (service_port, container_port) in [(80u16, 8080u16), (90, 9090)] {
            let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
            let (selected, ingress_authz_port) = table
                .select_mesh_inbound_port_route(rm, Some(container_port), None)
                .expect("captured container port selects its sibling");
            assert_eq!(
                selected.proxy.id,
                format!("__mesh-inbound-default-reviews-{service_port}")
            );
            assert_eq!(ingress_authz_port, None);
        }

        // Authority port (service port) picks each sibling when orig-dst is
        // absent (the peer-sidecar direct-dial case).
        for service_port in [80u16, 90] {
            let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
            let (selected, ingress_authz_port) = table
                .select_mesh_inbound_port_route(rm, None, Some(service_port))
                .expect("authority service port selects its sibling");
            assert_eq!(
                selected.proxy.id,
                format!("__mesh-inbound-default-reviews-{service_port}")
            );
            assert_eq!(ingress_authz_port, None);
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
        let table = cache.route_table_for_tests();

        for (orig_dst, authority) in [(None, None), (None, Some(9999u16)), (Some(9999u16), None)] {
            let rm = cache.find_proxy(Some("ratings"), "/").expect("route");
            let (kept, ingress_authz_port) = table
                .select_mesh_inbound_port_route(rm, orig_dst, authority)
                .expect("single-port group never demands a signal");
            assert_eq!(kept.proxy.id, "__mesh-inbound-default-ratings-8080");
            assert_eq!(
                ingress_authz_port, None,
                "service-port group is not ingress"
            );
        }
    }

    /// Sidecar `ingress[]` custom-listener siblings (F6 §6.2) disambiguate by
    /// the declared LISTENER port for BOTH the captured original destination
    /// AND the request authority — NOT by the backend (`defaultEndpoint`) port,
    /// which is distinct. Folded into the same `mesh_inbound_ports` map, so the
    /// shared `select_mesh_inbound_port_route` resolves them with no fork.
    #[test]
    fn mesh_ingress_port_group_selects_sibling_by_listener_port() {
        use crate::modes::mesh::config::{MeshConfig, ResolvedIngressListener};
        // Two ingress listeners: listener 8080 → backend 5000, listener 8443 →
        // backend 6000. The backend ports deliberately do NOT equal the listener
        // ports, proving orig-dst matches the LISTENER port.
        let mut proxies = Vec::new();
        for (listener_port, backend_port) in [(8080u16, 5000u16), (8443, 6000)] {
            let mut p = minimal_proxy_for_routing(
                &format!("__mesh-ingress-default-reviews-{listener_port}"),
                "/",
            );
            p.hosts = vec!["reviews".to_string()];
            p.backend_port = backend_port;
            proxies.push(p);
        }
        let config = GatewayConfig {
            proxies,
            mesh: Some(Box::new(MeshConfig {
                local_ingress_listeners: vec![
                    ResolvedIngressListener {
                        port: 8080,
                        endpoint_host: "127.0.0.1".to_string(),
                        endpoint_port: 5000,
                        owner_namespace: "default".to_string(),
                        owner_service: "reviews".to_string(),
                    },
                    ResolvedIngressListener {
                        port: 8443,
                        endpoint_host: "127.0.0.1".to_string(),
                        endpoint_port: 6000,
                        owner_namespace: "default".to_string(),
                        owner_service: "reviews".to_string(),
                    },
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        // Lowest listener port is the tier representative.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert_eq!(rm.proxy.id, "__mesh-ingress-default-reviews-8080");

        // orig-dst = LISTENER port selects the matching sibling (by listener
        // port, NOT backend port — 6000 as orig-dst must NOT match). The authz
        // listener port returned is the DECLARED listener port (8443), NOT the
        // backend port (6000) — this is what `mesh_authz` enforces on (F6 §6.2).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (by_orig, authz_port) = table
            .select_mesh_inbound_port_route(rm, Some(8443), None)
            .expect("orig-dst = listener port 8443 selects its sibling");
        assert_eq!(by_orig.proxy.backend_port, 6000);
        assert_eq!(
            authz_port,
            Some(8443),
            "ingress authz must use the declared listener port, not the backend port"
        );

        // authority = LISTENER port also selects, and stamps the listener port.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (by_auth, authz_port) = table
            .select_mesh_inbound_port_route(rm, None, Some(8080))
            .expect("authority = listener port 8080 selects its sibling");
        assert_eq!(by_auth.proxy.backend_port, 5000);
        assert_eq!(authz_port, Some(8080));

        // A backend port presented as orig-dst must NOT match a listener — fail
        // closed (5000/6000 are backends, not dialed listener ports).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, Some(6000), None),
            Err(MeshInboundPortSelectError::PortNotMaterialized)
        ));
    }

    /// A SINGLE ingress listener still surfaces its declared listener port for
    /// authz — so a peer dial with no orig-dst / authority port authorizes on the
    /// listener port, never the backend port (F6 §6.2 security, single-listener
    /// path). A PRESENT port signal must MATCH the declared listener port; an
    /// undeclared port fails closed (codex round-2 P1: a single ingress listener
    /// must not absorb traffic addressed to a different port).
    #[test]
    fn mesh_ingress_single_listener_surfaces_listener_authz_port() {
        use crate::modes::mesh::config::{MeshConfig, ResolvedIngressListener};
        let mut p = minimal_proxy_for_routing("__mesh-ingress-default-reviews-8443", "/");
        p.hosts = vec!["reviews".to_string()];
        p.backend_port = 8080; // backend != listener
        let config = GatewayConfig {
            proxies: vec![p],
            mesh: Some(Box::new(MeshConfig {
                local_ingress_listeners: vec![ResolvedIngressListener {
                    port: 8443,
                    endpoint_host: "127.0.0.1".to_string(),
                    endpoint_port: 8080,
                    owner_namespace: "default".to_string(),
                    owner_service: "reviews".to_string(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        // No port signal at all: falls through to the sole listener AND stamps
        // the declared listener port for authz.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (kept, authz_port) = table
            .select_mesh_inbound_port_route(rm, None, None)
            .expect("single ingress listener keeps the route when no port signal is present");
        assert_eq!(kept.proxy.backend_port, 8080);
        assert_eq!(
            authz_port,
            Some(8443),
            "single ingress listener must authorize on its declared listener port"
        );

        // A MATCHING orig-dst (the dialed listener port) is accepted and stamps
        // the listener port.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (kept, authz_port) = table
            .select_mesh_inbound_port_route(rm, Some(8443), None)
            .expect("orig-dst = the declared listener port selects the sole listener");
        assert_eq!(kept.proxy.backend_port, 8080);
        assert_eq!(authz_port, Some(8443));

        // A MATCHING authority port (a peer dial carrying the listener port) is
        // accepted.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            table
                .select_mesh_inbound_port_route(rm, None, Some(8443))
                .is_ok(),
            "authority = the declared listener port selects the sole listener"
        );

        // A MISMATCHED orig-dst (a port the listener did not declare — e.g. the
        // backend port 8080, or any other port) must FAIL CLOSED, not be absorbed
        // onto the sole listener (codex round-2 P1).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_inbound_port_route(rm, Some(8080), None),
                Err(MeshInboundPortSelectError::PortNotMaterialized)
            ),
            "an orig-dst to an undeclared port must not be accepted onto the single ingress listener"
        );
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(matches!(
            table.select_mesh_inbound_port_route(rm, Some(9999), None),
            Err(MeshInboundPortSelectError::PortNotMaterialized)
        ));

        // A MISMATCHED authority port likewise fails closed (orig-dst absent).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_inbound_port_route(rm, None, Some(9999)),
                Err(MeshInboundPortSelectError::PortNotMaterialized)
            ),
            "an authority to an undeclared port must not be accepted onto the single ingress listener"
        );
    }

    /// Codex round-4 P2: a Sidecar that DECLARES two HTTP-family ingress[]
    /// listeners but where only ONE resolved (the other had an omitted / `unix://`
    /// / off-box `defaultEndpoint`) must NOT collapse to the single-listener
    /// no-signal pass-through. `MeshConfig.declared_ingress_http_ports` (2) carries
    /// the DECLARED count past the resolved set (1), so `mesh_ingress_listener_groups`
    /// reports `declared_http_ports == 2`, keeping the group AMBIGUOUS: an
    /// orig-dst-less request fails closed (`PortSignalUnavailable`) instead of being
    /// routed to the surviving sibling and absorbing the skipped listener's traffic.
    #[test]
    fn mesh_ingress_partial_materialization_fails_closed_without_signal() {
        use crate::modes::mesh::config::{MeshConfig, ResolvedIngressListener};
        // Only listener 8080 resolved; listener 8443 was declared HTTP-family but
        // its endpoint was unroutable, so it is absent from local_ingress_listeners
        // yet counted in declared_ingress_http_ports.
        let mut p = minimal_proxy_for_routing("__mesh-ingress-default-reviews-8080", "/");
        p.hosts = vec!["reviews".to_string()];
        p.backend_port = 5000;
        let config = GatewayConfig {
            proxies: vec![p],
            mesh: Some(Box::new(MeshConfig {
                local_ingress_listeners: vec![ResolvedIngressListener {
                    port: 8080,
                    endpoint_host: "127.0.0.1".to_string(),
                    endpoint_port: 5000,
                    owner_namespace: "default".to_string(),
                    owner_service: "reviews".to_string(),
                }],
                // Operator declared TWO HTTP-family ingress ports; only one
                // resolved. The declared count must drive the router.
                declared_ingress_http_ports: 2,
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        // No port signal: with two DECLARED listeners and one resolved, the group
        // is ambiguous → fail closed (NOT a fall-through to the survivor).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_inbound_port_route(rm, None, None),
                Err(MeshInboundPortSelectError::PortSignalUnavailable)
            ),
            "a partially materialized ingress group must fail closed without a port signal, \
             not route the skipped port's traffic to the surviving listener"
        );

        // A signal for the RESOLVED listener port still routes correctly.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (kept, authz_port) = table
            .select_mesh_inbound_port_route(rm, Some(8080), None)
            .expect("orig-dst = the resolved listener port selects its sibling");
        assert_eq!(kept.proxy.backend_port, 5000);
        assert_eq!(authz_port, Some(8080));

        // A signal for the SKIPPED (declared-but-unresolved) listener port has no
        // materialized sibling → fail closed, never absorbed by the survivor.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            matches!(
                table.select_mesh_inbound_port_route(rm, Some(8443), None),
                Err(MeshInboundPortSelectError::PortNotMaterialized)
            ),
            "a signal to the skipped declared listener port must fail closed"
        );
    }

    /// Counterpart to the ingress fail-closed check: a SINGLE-port SERVICE-default
    /// inbound group (`is_ingress == false`) keeps the back-compat passthrough —
    /// it accepts any explicit port and a bare-Host dial onto the sole sibling, so
    /// the round-2 ingress tightening does NOT regress single-port services.
    #[test]
    fn mesh_inbound_single_service_port_keeps_backcompat_passthrough() {
        let mut p = minimal_proxy_for_routing("__mesh-inbound-default-reviews-80", "/");
        p.hosts = vec!["reviews".to_string()];
        p.backend_port = 8080;
        let config = GatewayConfig {
            proxies: vec![p],
            // The service declares exactly one HTTP port.
            mesh: mesh_block(&[("default", "reviews", &[80])]),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        // No signal → keep (back-compat), and NO ingress authz port (service
        // default authorizes on the backend port).
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        let (kept, authz_port) = table
            .select_mesh_inbound_port_route(rm, None, None)
            .expect("single service port keeps the route unconditionally");
        assert_eq!(kept.proxy.backend_port, 8080);
        assert_eq!(authz_port, None);

        // An explicit (even unrelated) authority/orig-dst port is still accepted
        // for a single-port service — unchanged from round-1.
        let rm = cache.find_proxy(Some("reviews"), "/").expect("route");
        assert!(
            table
                .select_mesh_inbound_port_route(rm, Some(12345), None)
                .is_ok(),
            "a single-port service must keep accepting any explicit port (back-compat)"
        );
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
        let table = cache.route_table_for_tests();

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
            "port_overrides": {
                "6379": { "algorithm": "round_robin" }
            },
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
        let table = cache.route_table_for_tests();

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
                // Per-port DR overrides project onto the synthesized relay
                // proxy (mirrors the UDP table); the stream selection path
                // gates the per-port LB lane on `dispatch_port_overrides`.
                assert!(
                    entry
                        .relay_proxy
                        .dispatch_port_overrides
                        .as_ref()
                        .is_some_and(|o| o.contains_key(&6379)),
                    "TCP relay proxy must carry the upstream's per-port overrides"
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
        let table = cache.route_table_for_tests();
        assert!(matches!(
            table.mesh_tcp_egress_decision("10.96.0.1:6379".parse().expect("addr")),
            Some(MeshTcpEgressDecision::CloseNotRoutable)
        ));
    }

    #[test]
    fn mesh_tcp_inbound_table_routes_by_captured_app_port() {
        use crate::config::types::BackendScheme;
        use crate::modes::mesh::config::{MeshConfig, MeshInboundTcpRoute};

        let redis_route = MeshInboundTcpRoute {
            match_port: 6380,
            backend_addr: "127.0.0.1:6380".parse().unwrap(),
            namespace: "default".to_string(),
            service_name: "redis".to_string(),
            service_fqdn: "redis.default.svc.cluster.local".to_string(),
            // Redis is not opaque TLS: the relay must NOT peek SNI for this port.
            tls_inspect: false,
            // Redis is server-first: the relay must not block before dialing loopback.
            first_bytes_inspect: false,
        };
        let tcp_route = MeshInboundTcpRoute {
            match_port: 7000,
            backend_addr: "127.0.0.1:7000".parse().unwrap(),
            namespace: "default".to_string(),
            service_name: "tcpapp".to_string(),
            service_fqdn: "tcpapp.default.svc.cluster.local".to_string(),
            tls_inspect: false,
            // Generic TCP is ambiguous and must not pre-dial peek by default.
            first_bytes_inspect: false,
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                local_inbound_tcp_routes: vec![redis_route, tcp_route],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        let entry = table
            .mesh_tcp_inbound_entry("10.0.0.7:6380".parse().unwrap())
            .expect("captured app port should route");
        assert_eq!(entry.backend_addr, "127.0.0.1:6380".parse().unwrap());
        assert_eq!(entry.service_fqdn, "redis.default.svc.cluster.local");
        assert!(
            !entry.tls_inspect,
            "non-TLS raw-TCP inbound entries must not SNI-peek"
        );
        assert!(
            !entry.first_bytes_inspect,
            "Redis inbound entries are server-first and must not pre-dial peek first bytes"
        );
        assert_eq!(entry.relay_proxy.backend_scheme, Some(BackendScheme::Tcp));
        assert_eq!(
            entry.relay_proxy.id,
            "__mesh-in-tcp-relay-default-redis-6380"
        );

        let tcp_entry = table
            .mesh_tcp_inbound_entry("10.0.0.7:7000".parse().unwrap())
            .expect("captured generic TCP app port should route");
        assert_eq!(tcp_entry.backend_addr, "127.0.0.1:7000".parse().unwrap());
        assert!(
            !tcp_entry.first_bytes_inspect,
            "generic TCP inbound entries are ambiguous and must not pre-dial peek first bytes"
        );

        assert!(
            table
                .mesh_tcp_inbound_entry("10.0.0.7:6381".parse().unwrap())
                .is_none(),
            "raw-TCP inbound never routes by IP or nearby port alone"
        );
    }

    #[test]
    fn mesh_udp_egress_table_routes_by_vip_and_port() {
        // F3 §3.3 Stage 4: a UDP service port × VIP routes through the per-port
        // UDP upstream; an undeclared port / different IP misses; a declared pair
        // whose upstream did not materialize is CloseNotRoutable (fail closed).
        use crate::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
        let service = MeshService {
            name: "dns".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 53,
                protocol: AppProtocol::Udp,
                name: Some("dns".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: std::collections::HashMap::new(),
            cluster_ips: vec!["10.96.0.10".to_string()],
        };
        let upstream: crate::config::types::Upstream = serde_json::from_value(serde_json::json!({
            "id": "__mesh-out-udp-upstream-default-dns-53",
            "name": "dns.default.svc.cluster.local",
            "targets": [{"host": "10.0.0.9", "port": 53}],
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
        let table = cache.route_table_for_tests();
        let decision =
            |addr: &str| table.mesh_udp_egress_decision(addr.parse().expect("socket addr"));

        match decision("10.96.0.10:53") {
            Some(MeshTcpEgressDecision::Relay(entry)) => {
                assert_eq!(entry.upstream_id, "__mesh-out-udp-upstream-default-dns-53");
                assert_eq!(entry.service_fqdn, "dns.default.svc.cluster.local");
            }
            _ => panic!("expected Relay decision for an exact (VIP, UDP port) match"),
        }
        // Mapped-IPv6 capture of the same IPv4 VIP still matches.
        assert!(matches!(
            decision("[::ffff:10.96.0.10]:53"),
            Some(MeshTcpEgressDecision::Relay(_))
        ));
        // Undeclared port / different IP miss (not mesh UDP destinations).
        assert!(decision("10.96.0.10:54").is_none());
        assert!(decision("10.96.0.11:53").is_none());

        // Declared pair whose upstream did NOT materialize: CloseNotRoutable.
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![service],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();
        assert!(matches!(
            table.mesh_udp_egress_decision("10.96.0.10:53".parse().expect("addr")),
            Some(MeshTcpEgressDecision::CloseNotRoutable)
        ));
    }

    #[test]
    fn mesh_tcp_egress_by_workload_routes_direct_pod_ip_dials() {
        // F3 §3.4: a HEADLESS service (no cluster_ips) backed by a workload whose
        // pod IP a client dials directly routes via the by-workload index, keyed
        // by `(workload IP, resolved target port)`, NOT the VIP table.
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            AppProtocol, MeshConfig, MeshService, ServicePort, ServiceTargetPort, Workload,
            WorkloadPort, WorkloadRef, WorkloadSelector,
        };

        let spiffe = "spiffe://cluster.local/ns/default/sa/redis";
        let service = MeshService {
            name: "redis".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 6379,
                protocol: AppProtocol::Redis,
                name: Some("redis".to_string()),
                // targetPort 6380: the index is keyed by the RESOLVED target
                // port, not the service port — a direct pod-IP dial hits :6380.
                target_port: Some(ServiceTargetPort::Number(6380)),
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: SpiffeId::new(spiffe).unwrap(),
            }],
            protocol_overrides: std::collections::HashMap::new(),
            // Headless: no VIP at all — the whole point of the by-workload path.
            cluster_ips: Vec::new(),
        };
        let workload = Workload {
            spiffe_id: SpiffeId::new(spiffe).unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "redis".to_string(),
            addresses: vec!["10.0.0.7".to_string()],
            ports: vec![WorkloadPort {
                port: 6380,
                protocol: AppProtocol::Redis,
                name: Some("redis".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").unwrap(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        };

        // The single-target per-workload upstream the materializer would emit,
        // keyed by the canonical workload IP. Built here with the deterministic
        // id helper (forward-derived, never parsed) + the resolved target port.
        let bywl_id = crate::modes::mesh::mesh_outbound_tcp_bywl_upstream_id(
            "default",
            "redis",
            6379,
            "10.0.0.7".parse().unwrap(),
        );
        let upstream: crate::config::types::Upstream = serde_json::from_value(serde_json::json!({
            "id": bywl_id,
            "name": "redis.default.svc.cluster.local",
            "targets": [{"host": "10.0.0.7", "port": 6380}],
        }))
        .expect("upstream deserializes");
        let config = GatewayConfig {
            upstreams: vec![upstream],
            mesh: Some(Box::new(MeshConfig {
                services: vec![service.clone()],
                workloads: vec![workload.clone()],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        let bywl = |addr: &str| {
            table.mesh_tcp_egress_by_workload_decision(addr.parse().expect("socket addr"))
        };

        // Exact (workload IP, target port) routes to the pinned single-target
        // upstream. The dial is to the RESOLVED targetPort (6380), not 6379.
        match bywl("10.0.0.7:6380") {
            Some(MeshTcpEgressDecision::Relay(entry)) => {
                assert_eq!(entry.upstream_id, bywl_id);
                assert_eq!(
                    entry.relay_proxy.upstream_id.as_deref(),
                    Some(bywl_id.as_str())
                );
            }
            _ => panic!("expected a by-workload Relay for the pod IP + target port"),
        }
        // Mapped-IPv6 capture of the same pod IP still matches (canonicalized).
        assert!(matches!(
            bywl("[::ffff:10.0.0.7]:6380"),
            Some(MeshTcpEgressDecision::Relay(_))
        ));
        // The SERVICE port (6379) is not a workload target port → no by-workload
        // route (only the resolved targetPort 6380 is indexed).
        assert!(bywl("10.0.0.7:6379").is_none());
        // A different (undeclared) pod IP is never matched.
        assert!(bywl("10.0.0.8:6380").is_none());
        // The VIP table is empty (headless), so it never matches either.
        assert!(
            table
                .mesh_tcp_egress_decision("10.0.0.7:6380".parse().unwrap())
                .is_none()
        );

        // Declared backing workload whose per-workload upstream did NOT
        // materialize: mesh-owned but unroutable — close, never guess.
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![service],
                workloads: vec![workload],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();
        assert!(matches!(
            table.mesh_tcp_egress_by_workload_decision("10.0.0.7:6380".parse().unwrap()),
            Some(MeshTcpEgressDecision::CloseNotRoutable)
        ));
    }

    #[test]
    fn mesh_http_egress_by_workload_routes_direct_pod_ip_dials() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            AppProtocol, MeshConfig, MeshService, ServicePort, ServiceTargetPort, Workload,
            WorkloadPort, WorkloadRef, WorkloadSelector,
        };

        let spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
        let service = MeshService {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: Some(ServiceTargetPort::Number(18080)),
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: SpiffeId::new(spiffe).unwrap(),
            }],
            protocol_overrides: std::collections::HashMap::new(),
            cluster_ips: Vec::new(),
        };
        let workload = Workload {
            spiffe_id: SpiffeId::new(spiffe).unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "reviews".to_string(),
            addresses: vec!["10.0.0.7".to_string()],
            ports: vec![WorkloadPort {
                port: 18080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").unwrap(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        };
        let canonical_ip = "10.0.0.7".parse().unwrap();
        let upstream_id = crate::modes::mesh::mesh_outbound_http_bywl_upstream_id(
            "default",
            "reviews",
            8080,
            canonical_ip,
        );
        let proxy_id = crate::modes::mesh::mesh_outbound_http_bywl_proxy_id(
            "default",
            "reviews",
            8080,
            canonical_ip,
        );
        let mut proxy = minimal_proxy_for_routing(&proxy_id, "/");
        proxy.hosts = vec!["bywl-default-reviews-8080-10-0-0-7.mesh.internal".to_string()];
        proxy.upstream_id = Some(upstream_id.clone());
        proxy.preserve_host_header = false;
        let upstream: crate::config::types::Upstream = serde_json::from_value(serde_json::json!({
            "id": upstream_id,
            "name": "reviews.default.svc.cluster.local",
            "targets": [{"host": "10.0.0.7", "port": 18080}],
        }))
        .expect("upstream deserializes");
        let config = GatewayConfig {
            proxies: vec![proxy],
            upstreams: vec![upstream],
            mesh: Some(Box::new(MeshConfig {
                services: vec![service],
                workloads: vec![workload],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();

        match table.mesh_http_egress_by_workload_decision("10.0.0.7:18080".parse().unwrap()) {
            Some(MeshHttpEgressByWorkloadDecision::Route {
                proxy,
                service_port,
            }) => {
                assert_eq!(proxy.id, proxy_id);
                assert_eq!(*service_port, 8080);
            }
            _ => panic!("expected direct-pod HTTP route"),
        }
        assert!(matches!(
            table.mesh_http_egress_by_workload_decision("[::ffff:10.0.0.7]:18080".parse().unwrap()),
            Some(MeshHttpEgressByWorkloadDecision::Route { .. })
        ));
        assert!(
            cache
                .find_proxy(
                    Some("bywl-default-reviews-8080-10-0-0-7.mesh.internal"),
                    "/"
                )
                .is_none(),
            "hidden direct-pod proxies must not enter normal Host routing"
        );
        assert!(
            table
                .mesh_http_egress_by_workload_decision("10.0.0.7:8080".parse().unwrap())
                .is_none(),
            "index is keyed by resolved targetPort, not service port"
        );
    }

    #[test]
    fn mesh_http_egress_by_workload_closes_ambiguous_direct_pod_ip_dials() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::config::{
            AppProtocol, MeshConfig, MeshService, ServicePort, ServiceTargetPort, Workload,
            WorkloadPort, WorkloadRef, WorkloadSelector,
        };

        let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
        let workload = Workload {
            spiffe_id: SpiffeId::new(spiffe).unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "shared".to_string(),
            addresses: vec!["10.0.0.7".to_string()],
            ports: vec![WorkloadPort {
                port: 18080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").unwrap(),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        };
        let service = |name: &str, port: u16| MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: Some(ServiceTargetPort::Number(18080)),
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: SpiffeId::new(spiffe).unwrap(),
            }],
            protocol_overrides: std::collections::HashMap::new(),
            cluster_ips: Vec::new(),
        };

        let canonical_ip = "10.0.0.7".parse().unwrap();
        let mut proxies = Vec::new();
        let mut upstreams = Vec::new();
        for (name, port) in [("reviews", 8080u16), ("ratings", 9090u16)] {
            let upstream_id = crate::modes::mesh::mesh_outbound_http_bywl_upstream_id(
                "default",
                name,
                port,
                canonical_ip,
            );
            let proxy_id = crate::modes::mesh::mesh_outbound_http_bywl_proxy_id(
                "default",
                name,
                port,
                canonical_ip,
            );
            let mut proxy = minimal_proxy_for_routing(&proxy_id, "/");
            proxy.hosts = vec![format!("bywl-default-{name}-{port}-10-0-0-7.mesh.internal")];
            proxy.upstream_id = Some(upstream_id.clone());
            proxies.push(proxy);
            upstreams.push(
                serde_json::from_value(serde_json::json!({
                    "id": upstream_id,
                    "name": format!("{name}.default.svc.cluster.local"),
                    "targets": [{"host": "10.0.0.7", "port": 18080}],
                }))
                .expect("upstream deserializes"),
            );
        }

        let config = GatewayConfig {
            proxies,
            upstreams,
            mesh: Some(Box::new(MeshConfig {
                services: vec![service("reviews", 8080), service("ratings", 9090)],
                workloads: vec![workload],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let cache = RouterCache::new(&config, 100);
        let table = cache.route_table_for_tests();
        assert!(matches!(
            table.mesh_http_egress_by_workload_decision("10.0.0.7:18080".parse().unwrap()),
            Some(MeshHttpEgressByWorkloadDecision::CloseNotRoutable)
        ));
    }
}
