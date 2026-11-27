//! ServiceWaypoint L7 bound-Service targets and per-bound-Service route
//! partitions (issue #7500).
//!
//! A `ServiceWaypoint` is the L7 terminator for the Services bound to it. The
//! data plane materializes, for every HTTP-family port of a bound Service:
//!
//! * a default L7 Service upstream (`__mesh-sw-upstream-{ns}-{svc}-{port}`)
//!   holding the Service's local-cluster backing workloads over the mesh
//!   transport, and
//! * a default L7 Service route (`__mesh-sw-service-{ns}-{svc}-{port}`) that
//!   serves the Service when no carried VirtualService route matches.
//!
//! The VirtualService `http[]` routes the slice carries for the bound Services
//! are rebound onto those upstreams by the shared carried-route binding.
//!
//! This module holds what the HBONE `:15008` L7 termination (issue #7501)
//! consults, built once per configuration generation (inside the router's
//! per-epoch `HostRouteTable`), never per request:
//!
//! * [`ServiceWaypointL7TargetIndex`] classifies an outer `CONNECT` authority
//!   (`<ClusterIP>:<port>`, a Service host variant with its port, or a backing
//!   pod `<podIP>:<targetPort>`) to exactly one bound Service HTTP port, an
//!   ambiguous match, or "not an L7 target".
//! * [`ServiceWaypointL7RoutePartition`] is the route table of one bound
//!   Service port: its admitted host set, the carried routes bound to that
//!   Service, and its default route.
//!
//! The HBONE `:15008` L7 termination (issue #7501,
//! `crate::proxy::service_waypoint_l7_proxy`) classifies an outer `CONNECT`
//! through the index, serves the upgraded stream with an inner HTTP/1.1 and
//! HTTP/2 server, and resolves every inner request ONLY through the bound
//! Service's partition ([`ServiceWaypointL7RoutePartition::resolve`]), after
//! the inner `Host` / `:authority` passed
//! [`ServiceWaypointL7RoutePartition::admits_request_host`]. The shared route
//! lookup never serves these routes: the default L7 routes are kept out of the
//! shared route tiers entirely (`RouterCache::build_route_table`), and
//! [`super::mesh_route_admitted_for_direction`] refuses both them and every
//! carried `istio-vs-*` route on every inbound listener, so a direct request
//! on `:15008` (outside an admitted tunnel), the Sidecar `:15006` and the
//! NodeWaypoint `:15008` listeners never reach them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::types::{GatewayConfig, Proxy};

/// Reserved id prefix of a ServiceWaypoint default L7 Service route.
pub const SERVICE_WAYPOINT_L7_ROUTE_ID_PREFIX: &str = "__mesh-sw-service-";

/// Reserved id prefix of a ServiceWaypoint default L7 Service upstream. Not a
/// prefix of [`SERVICE_WAYPOINT_L7_ROUTE_ID_PREFIX`] (or the reverse), so an
/// upstream id is never classified as a route.
pub const SERVICE_WAYPOINT_L7_UPSTREAM_ID_PREFIX: &str = "__mesh-sw-upstream-";

/// Id of the default L7 route for one bound Service port. Sanitized of `/` and
/// `.` like every other materialized mesh route id. Never parsed back into
/// namespace/name: the [`ServiceWaypointL7Binding`] records carry the identity
/// forward.
pub fn service_waypoint_l7_route_id(namespace: &str, name: &str, port: u16) -> String {
    format!("{SERVICE_WAYPOINT_L7_ROUTE_ID_PREFIX}{namespace}-{name}-{port}")
        .replace(['/', '.'], "-")
}

/// Id of the default L7 upstream for one bound Service port.
pub fn service_waypoint_l7_upstream_id(namespace: &str, name: &str, port: u16) -> String {
    format!("{SERVICE_WAYPOINT_L7_UPSTREAM_ID_PREFIX}{namespace}-{name}-{port}")
        .replace(['/', '.'], "-")
}

/// Whether a proxy id names a ServiceWaypoint default L7 Service route.
/// Operator ids cannot start with `_` (resource-id validation), so only the
/// mesh materializer creates one.
pub fn is_service_waypoint_l7_route_id(id: &str) -> bool {
    id.starts_with(SERVICE_WAYPOINT_L7_ROUTE_ID_PREFIX)
}

/// One HTTP-family port of a Service bound to this ServiceWaypoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceWaypointL7Target {
    pub namespace: String,
    pub service: String,
    pub service_port: u16,
}

/// The unforgeable, runtime-only provenance of one inner HTTP request served
/// inside an L7-terminated ServiceWaypoint HBONE tunnel (issue #7501).
///
/// Built ONCE per admitted outer `CONNECT`, from facts the outer tunnel
/// verified, and carried on every inner `RequestContext`
/// (`RequestContext::service_waypoint_l7`). No outer listener sets it, it is
/// never serialized, and nothing an inner request carries can change it:
///
/// * `target` pins the inner request to its bound Service's route partition;
/// * `outer_baggage` is the folded `baggage` value of the OUTER `CONNECT`, the
///   only input `mesh_authz` and `workload_metrics` evaluate a trusted HBONE
///   `source.principal` assertion from for the inner requests (an inner
///   request's own `baggage` header is application data, never an HBONE
///   identity assertion).
///
/// The verified outer peer identity itself rides the inner context as its
/// certificate principal (the outer connection's client certificate), so the
/// ordinary `spiffe_identity` / `mesh_authz` resolution applies to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWaypointL7Context {
    pub target: ServiceWaypointL7Target,
    pub outer_baggage: Option<String>,
}

impl ServiceWaypointL7Context {
    /// The bound Service's namespace.
    pub fn bound_service_namespace(&self) -> &str {
        &self.target.namespace
    }

    /// The bound Service's name.
    pub fn bound_service_name(&self) -> &str {
        &self.target.service
    }

    /// The bound Service port the outer `CONNECT` named (the trusted
    /// `destination.port` of every inner request).
    pub fn bound_service_port(&self) -> u16 {
        self.target.service_port
    }
}

/// The materialized L7 surface of one bound Service HTTP port, back-projected
/// onto the prepared `MeshConfig` (`service_waypoint_l7_bindings`) on every
/// ServiceWaypoint apply and EMPTY on every other topology.
///
/// Built only from explicit binding evidence
/// (`MeshSlice::service_waypoint_bound_services`, this runtime's exact
/// waypoint identity) and only for ports that materialized at least one
/// reachable backing workload, so the L7 target index can never widen the
/// inbound relay inventory: a target here is always a bound Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWaypointL7Binding {
    pub target: ServiceWaypointL7Target,
    /// Id of the default L7 route ([`service_waypoint_l7_route_id`]).
    pub route_id: String,
    /// Id of the default L7 upstream ([`service_waypoint_l7_upstream_id`]).
    pub upstream_id: String,
    /// The Service's canonical host variants (ASCII-lowercase, no trailing
    /// dot): the short name, `<svc>.<ns>`, `<svc>.<ns>.svc` and the FQDN.
    pub hosts: Vec<String>,
    /// The Service's ClusterIP addresses (canonical form).
    pub service_addresses: Vec<IpAddr>,
    /// `(backing pod address, resolved target port)` pairs (canonical form).
    pub backing_endpoints: Vec<(IpAddr, u16)>,
}

/// What an outer HBONE `CONNECT` authority resolves to against the bound
/// Services' HTTP-family ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceWaypointConnectMode {
    /// Exactly one bound Service HTTP port: terminate HTTP inside the tunnel
    /// and dispatch through that port's route partition (issue #7501).
    TerminateL7(ServiceWaypointL7Target),
    /// The authority maps to more than one bound Service HTTP port (for
    /// example a backing pod `address:port` two bound Services share). Must
    /// be refused before any upgrade; never guessed.
    Ambiguous,
    /// Not an HTTP-family port of a bound Service: the existing L4 relay path
    /// (and its open-relay guard) decides, unchanged.
    NotL7Target,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IndexedTarget {
    Target(ServiceWaypointL7Target),
    Ambiguous,
}

impl IndexedTarget {
    fn mode(&self) -> ServiceWaypointConnectMode {
        match self {
            Self::Target(target) => ServiceWaypointConnectMode::TerminateL7(target.clone()),
            Self::Ambiguous => ServiceWaypointConnectMode::Ambiguous,
        }
    }

    fn merge(&mut self, target: &ServiceWaypointL7Target) {
        if let Self::Target(existing) = self
            && existing != target
        {
            *self = Self::Ambiguous;
        }
    }
}

fn insert_indexed<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, IndexedTarget>,
    key: K,
    target: &ServiceWaypointL7Target,
) {
    map.entry(key)
        .and_modify(|existing| existing.merge(target))
        .or_insert_with(|| IndexedTarget::Target(target.clone()));
}

/// Immutable classification of outer `CONNECT` authorities to bound Service
/// HTTP-family ports, built once per configuration generation from
/// [`ServiceWaypointL7Binding`]s. Lookups take no lock and allocate nothing
/// for a canonical host.
#[derive(Debug, Default)]
pub struct ServiceWaypointL7TargetIndex {
    by_service_address: HashMap<(IpAddr, u16), IndexedTarget>,
    by_backing_endpoint: HashMap<(IpAddr, u16), IndexedTarget>,
    by_service_host: HashMap<String, Vec<(u16, IndexedTarget)>>,
    live: BTreeSet<ServiceWaypointL7Target>,
}

impl ServiceWaypointL7TargetIndex {
    /// Build the index from the generation's back-projected bindings.
    pub fn from_bindings(bindings: &[ServiceWaypointL7Binding]) -> Self {
        let mut index = Self::default();
        for binding in bindings {
            let target = &binding.target;
            index.live.insert(target.clone());
            for address in &binding.service_addresses {
                insert_indexed(
                    &mut index.by_service_address,
                    (address.to_canonical(), target.service_port),
                    target,
                );
            }
            for (address, port) in &binding.backing_endpoints {
                insert_indexed(
                    &mut index.by_backing_endpoint,
                    (address.to_canonical(), *port),
                    target,
                );
            }
            for host in &binding.hosts {
                let ports = index.by_service_host.entry(host.clone()).or_default();
                match ports
                    .iter_mut()
                    .find(|(port, _)| *port == target.service_port)
                {
                    Some((_, existing)) => existing.merge(target),
                    None => {
                        ports.push((target.service_port, IndexedTarget::Target(target.clone())))
                    }
                }
            }
        }
        index
    }

    /// Classify an outer `CONNECT` authority `host:port`. `host` may be a
    /// bracketed or bare IP literal or a Service host; a host is compared
    /// ASCII-case-insensitively without a trailing dot.
    pub fn classify_authority(&self, host: &str, port: u16) -> ServiceWaypointConnectMode {
        let bare = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(address) = bare.parse::<IpAddr>() {
            let key = (address.to_canonical(), port);
            return self
                .by_service_address
                .get(&key)
                .or_else(|| self.by_backing_endpoint.get(&key))
                .map_or(ServiceWaypointConnectMode::NotL7Target, IndexedTarget::mode);
        }
        let trimmed = bare.strip_suffix('.').unwrap_or(bare);
        let lookup = |candidate: &str| {
            self.by_service_host.get(candidate).and_then(|ports| {
                ports
                    .iter()
                    .find(|(candidate_port, _)| *candidate_port == port)
                    .map(|(_, indexed)| indexed.mode())
            })
        };
        let found = if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
            lookup(&trimmed.to_ascii_lowercase())
        } else {
            lookup(trimmed)
        };
        found.unwrap_or(ServiceWaypointConnectMode::NotL7Target)
    }

    /// Whether `target` is still a bound Service HTTP port in this
    /// generation (the admission fence's bound-Service liveness check).
    pub fn contains(&self, target: &ServiceWaypointL7Target) -> bool {
        self.live.contains(target)
    }

    /// Every bound Service HTTP port this generation terminates, in order.
    pub fn targets(&self) -> impl Iterator<Item = &ServiceWaypointL7Target> {
        self.live.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// The carried-route router of one partition: a dedicated route table over the
/// partition's carried routes only, built once per generation, so an inner
/// request is matched with exactly the shared router's host-tier, prefix,
/// exact (`=`) and regex (`~`) semantics without ever consulting a route of
/// another bound Service.
#[derive(Clone)]
struct PartitionRouter(Arc<crate::router_cache::RouterCache>);

impl std::fmt::Debug for PartitionRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionRouter")
            .field("routes", &self.0.route_count())
            .finish()
    }
}

/// Route-cache capacity of one partition router: one partition carries at
/// most the routes of one Service, so a small bounded cache suffices.
const PARTITION_ROUTER_CACHE_ENTRIES: usize = 256;
/// Shard count of one partition router's caches (power of two, >= 2).
const PARTITION_ROUTER_SHARDS: usize = 2;

/// The route table of one bound Service HTTP port.
#[derive(Debug, Clone)]
pub struct ServiceWaypointL7RoutePartition {
    pub target: ServiceWaypointL7Target,
    /// Host names an inner request on this Service may carry (canonical): the
    /// Service's host variants plus every host a carried route bound to this
    /// Service declares, except a host that names ANOTHER bound Service (an
    /// inner `Host` for Service B inside a tunnel to Service A is a host
    /// mismatch, never a route to B).
    pub admitted_hosts: Vec<String>,
    /// Carried VirtualService routes bound to this Service (same namespace,
    /// a host naming the Service), in configuration order. They shadow the
    /// default route on the paths they match.
    pub carried_routes: Vec<Arc<Proxy>>,
    /// The default L7 Service route, used when no carried route matches.
    pub default_route: Arc<Proxy>,
    /// Router over `carried_routes` only; `None` when the partition carries
    /// none.
    carried_router: Option<PartitionRouter>,
}

impl ServiceWaypointL7RoutePartition {
    /// Whether an inner request host (port already stripped) belongs to this
    /// bound Service.
    pub fn admits_host(&self, host: &str) -> bool {
        let trimmed = host.strip_suffix('.').unwrap_or(host);
        self.admitted_hosts
            .iter()
            .any(|admitted| admitted.eq_ignore_ascii_case(trimmed))
    }

    /// Whether an inner request may be served by this bound Service at all
    /// (issue #7501 host pinning): its normalized `Host` / `:authority` host
    /// must be one this Service admits, and an explicit authority port must be
    /// the bound Service port the outer `CONNECT` named. A request with no
    /// host at all is refused (fail closed): it cannot be shown to address
    /// this Service.
    pub fn admits_request_host(&self, host: Option<&str>, authority_port: Option<u16>) -> bool {
        let Some(host) = host else {
            return false;
        };
        if authority_port.is_some_and(|port| port != self.target.service_port) {
            return false;
        }
        self.admits_host(host)
    }

    /// Resolve an admitted inner request to a route of THIS partition only:
    /// the carried VirtualService route matching `host` and `path` (shared
    /// router semantics), else the bound Service's default L7 route. Never a
    /// route of another bound Service, never a route of the shared table.
    pub fn resolve(&self, host: &str, path: &str) -> crate::router_cache::RouteMatch {
        if let Some(router) = self.carried_router.as_ref()
            && let Some(matched) = router.0.find_proxy(Some(host), path)
        {
            return matched;
        }
        crate::router_cache::RouteMatch {
            proxy: Arc::clone(&self.default_route),
            path_params: Vec::new(),
            matched_prefix_len: self
                .default_route
                .listen_path
                .as_deref()
                .map_or(0, str::len),
        }
    }

    /// Number of carried VirtualService routes bound to this Service port.
    pub fn virtual_service_route_count(&self) -> usize {
        self.carried_routes.len()
    }
}

/// Operator view of one bound Service across its HTTP-family ports, for
/// `GET /service-waypoint/services`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceWaypointL7ServiceSummary {
    /// HTTP-family ports with a materialized default L7 route, ascending.
    pub l7_http_ports: Vec<u16>,
    /// Distinct carried VirtualService routes bound to the Service.
    pub virtual_service_route_count: usize,
}

/// Everything the ServiceWaypoint L7 path needs from one configuration
/// generation: the target index and the per-bound-Service route partitions.
#[derive(Debug, Default)]
pub struct ServiceWaypointL7Routes {
    index: ServiceWaypointL7TargetIndex,
    partitions: BTreeMap<ServiceWaypointL7Target, ServiceWaypointL7RoutePartition>,
}

fn canonical_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl ServiceWaypointL7Routes {
    /// Build from a prepared configuration. Empty unless the configuration is
    /// a ServiceWaypoint generation with back-projected bindings. Cold path:
    /// runs once per route-table build.
    pub fn build(config: &GatewayConfig) -> Self {
        let Some(mesh) = config.mesh.as_deref() else {
            return Self::default();
        };
        let bindings = &mesh.service_waypoint_l7_bindings;
        if bindings.is_empty() {
            return Self::default();
        }
        let index = ServiceWaypointL7TargetIndex::from_bindings(bindings);
        // Every bound Service's host variants, keyed to the Service, so a
        // carried route host naming another bound Service is never admitted
        // on this one.
        let mut host_owner: HashMap<&str, (&str, &str)> = HashMap::new();
        for binding in bindings {
            for host in &binding.hosts {
                host_owner.insert(
                    host.as_str(),
                    (
                        binding.target.namespace.as_str(),
                        binding.target.service.as_str(),
                    ),
                );
            }
        }
        let mut partitions = BTreeMap::new();
        for binding in bindings {
            let target = &binding.target;
            let Some(default_route) = config
                .proxies
                .iter()
                .find(|proxy| proxy.namespace == target.namespace && proxy.id == binding.route_id)
            else {
                continue;
            };
            let names_service = |host: &str| {
                let host = canonical_host(host);
                binding.hosts.iter().any(|candidate| *candidate == host)
            };
            let carried_routes: Vec<Arc<Proxy>> = config
                .proxies
                .iter()
                .filter(|proxy| {
                    proxy.namespace == target.namespace
                        && super::config::is_virtual_service_http_route_proxy_id(&proxy.id)
                        && !proxy.dispatch_kind.is_stream()
                        && proxy.hosts.iter().any(|host| names_service(host))
                })
                .map(|proxy| Arc::new(proxy.clone()))
                .collect();
            let mut admitted_hosts: BTreeSet<String> = binding.hosts.iter().cloned().collect();
            for route in &carried_routes {
                for host in &route.hosts {
                    let host = canonical_host(host);
                    let other_bound_service =
                        host_owner
                            .get(host.as_str())
                            .is_some_and(|(namespace, service)| {
                                *namespace != target.namespace || *service != target.service
                            });
                    if !host.is_empty() && !other_bound_service {
                        admitted_hosts.insert(host);
                    }
                }
            }
            // A dedicated route table over the carried routes only. Built from
            // a configuration with no `mesh` block, so it can never build
            // partitions of its own.
            let carried_router = (!carried_routes.is_empty()).then(|| {
                let carried_config = GatewayConfig {
                    proxies: carried_routes
                        .iter()
                        .map(|route| route.as_ref().clone())
                        .collect(),
                    ..GatewayConfig::default()
                };
                PartitionRouter(Arc::new(
                    crate::router_cache::RouterCache::with_shard_amount(
                        &carried_config,
                        PARTITION_ROUTER_CACHE_ENTRIES,
                        PARTITION_ROUTER_SHARDS,
                    ),
                ))
            });
            partitions.insert(
                target.clone(),
                ServiceWaypointL7RoutePartition {
                    target: target.clone(),
                    admitted_hosts: admitted_hosts.into_iter().collect(),
                    carried_routes,
                    default_route: Arc::new(default_route.clone()),
                    carried_router,
                },
            );
        }
        Self { index, partitions }
    }

    /// The outer `CONNECT` target index.
    pub fn index(&self) -> &ServiceWaypointL7TargetIndex {
        &self.index
    }

    /// The route partition of one bound Service port.
    pub fn partition(
        &self,
        target: &ServiceWaypointL7Target,
    ) -> Option<&ServiceWaypointL7RoutePartition> {
        self.partitions.get(target)
    }

    /// Every route partition, ordered by target.
    pub fn partitions(&self) -> impl Iterator<Item = &ServiceWaypointL7RoutePartition> {
        self.partitions.values()
    }

    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty() && self.index.is_empty()
    }

    /// Operator summary of one bound Service: its L7 HTTP ports and the
    /// distinct carried VirtualService routes bound to it. A Service with no
    /// partition reports no L7 port and no route.
    pub fn service_summary(
        &self,
        namespace: &str,
        service: &str,
    ) -> ServiceWaypointL7ServiceSummary {
        let mut l7_http_ports = Vec::new();
        let mut routes: BTreeSet<&str> = BTreeSet::new();
        for partition in self.partitions.values().filter(|partition| {
            partition.target.namespace == namespace && partition.target.service == service
        }) {
            l7_http_ports.push(partition.target.service_port);
            routes.extend(
                partition
                    .carried_routes
                    .iter()
                    .map(|route| route.id.as_str()),
            );
        }
        l7_http_ports.sort_unstable();
        l7_http_ports.dedup();
        ServiceWaypointL7ServiceSummary {
            l7_http_ports,
            virtual_service_route_count: routes.len(),
        }
    }
}
