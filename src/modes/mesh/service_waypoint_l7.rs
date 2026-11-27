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
//! Until issue #7501 lands nothing on the request path terminates HTTP inside
//! an HBONE tunnel: the `:15008` listener keeps its L4 transparent relay, the
//! default L7 routes are kept out of the shared route tiers entirely
//! (`RouterCache::build_route_table`), and
//! [`super::mesh_route_admitted_for_direction`] refuses both them and every
//! carried `istio-vs-*` route on every inbound listener.

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

/// One Service bound to this ServiceWaypoint, reachable or not, with its
/// canonical host variants. Host ownership for every route partition is read
/// from this full inventory, so a bound Service with no reachable HTTP port
/// still owns its hosts (no other partition admits them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWaypointBoundService {
    pub namespace: String,
    pub service: String,
    /// Canonical host variants (ASCII-lowercase, no trailing dot).
    pub hosts: Vec<String>,
}

/// The control plane's admission of one carried route for one bound Service
/// (`MeshHttpRouteSet::service_waypoint_attachments`): the route's host names
/// the Service and the owner/`exportTo` rule admits the route for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceWaypointRouteAttachment {
    pub route_namespace: String,
    pub route_id: String,
    pub service_namespace: String,
    pub service_name: String,
}

/// The bound-Service inventory and the admitted route attachments of one
/// ServiceWaypoint generation, back-projected onto the prepared `MeshConfig`
/// (`service_waypoint_l7_inventory`) beside the L7 bindings. Empty outside a
/// ServiceWaypoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceWaypointL7Inventory {
    pub bound_services: Vec<ServiceWaypointBoundService>,
    pub route_attachments: Vec<ServiceWaypointRouteAttachment>,
}

/// What an outer HBONE `CONNECT` authority resolves to against the bound
/// Services' HTTP-family ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceWaypointConnectMode {
    /// Exactly one bound Service HTTP port: terminate HTTP inside the tunnel
    /// and dispatch through that port's route partition (issue #7501). The
    /// target is the generation's own shared record, so a classification
    /// allocates nothing.
    TerminateL7(Arc<ServiceWaypointL7Target>),
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
    Target(Arc<ServiceWaypointL7Target>),
    Ambiguous,
}

impl IndexedTarget {
    fn mode(&self) -> ServiceWaypointConnectMode {
        match self {
            Self::Target(target) => ServiceWaypointConnectMode::TerminateL7(Arc::clone(target)),
            Self::Ambiguous => ServiceWaypointConnectMode::Ambiguous,
        }
    }

    fn merge(&mut self, target: &Arc<ServiceWaypointL7Target>) {
        if let Self::Target(existing) = self
            && **existing != **target
        {
            *self = Self::Ambiguous;
        }
    }
}

fn insert_indexed<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, IndexedTarget>,
    key: K,
    target: &Arc<ServiceWaypointL7Target>,
) {
    map.entry(key)
        .and_modify(|existing| existing.merge(target))
        .or_insert_with(|| IndexedTarget::Target(Arc::clone(target)));
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
            let target = &Arc::new(binding.target.clone());
            index.live.insert(binding.target.clone());
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
                    None => ports.push((
                        target.service_port,
                        IndexedTarget::Target(Arc::clone(target)),
                    )),
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
    /// Carried VirtualService routes the control plane attached to this
    /// Service (`ServiceWaypointRouteAttachment`) that survived the data
    /// plane's binding, in configuration order. They shadow the default route
    /// on the paths they match.
    pub carried_routes: Vec<Arc<Proxy>>,
    /// The default L7 Service route, used when no carried route matches.
    pub default_route: Arc<Proxy>,
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
        let inventory = &mesh.service_waypoint_l7_inventory;
        // Every bound Service's host variants (reachable or not), keyed to
        // the Service, so a carried route host naming another bound Service
        // is never admitted on this one.
        let mut host_owner: HashMap<&str, (&str, &str)> = HashMap::new();
        for service in &inventory.bound_services {
            for host in &service.hosts {
                host_owner.insert(
                    host.as_str(),
                    (service.namespace.as_str(), service.service.as_str()),
                );
            }
        }
        for binding in bindings {
            for host in &binding.hosts {
                host_owner.entry(host.as_str()).or_insert((
                    binding.target.namespace.as_str(),
                    binding.target.service.as_str(),
                ));
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
            let attached: BTreeSet<(&str, &str)> = inventory
                .route_attachments
                .iter()
                .filter(|attachment| {
                    attachment.service_namespace == target.namespace
                        && attachment.service_name == target.service
                })
                .map(|attachment| {
                    (
                        attachment.route_namespace.as_str(),
                        attachment.route_id.as_str(),
                    )
                })
                .collect();
            let carried_routes: Vec<Arc<Proxy>> = config
                .proxies
                .iter()
                .filter(|proxy| {
                    attached.contains(&(proxy.namespace.as_str(), proxy.id.as_str()))
                        && super::config::is_virtual_service_http_route_proxy_id(&proxy.id)
                        && !proxy.dispatch_kind.is_stream()
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
            partitions.insert(
                target.clone(),
                ServiceWaypointL7RoutePartition {
                    target: target.clone(),
                    admitted_hosts: admitted_hosts.into_iter().collect(),
                    carried_routes,
                    default_route: Arc::new(default_route.clone()),
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
        let mut routes: BTreeSet<(&str, &str)> = BTreeSet::new();
        for partition in self.partitions.values().filter(|partition| {
            partition.target.namespace == namespace && partition.target.service == service
        }) {
            l7_http_ports.push(partition.target.service_port);
            routes.extend(
                partition
                    .carried_routes
                    .iter()
                    .map(|route| (route.namespace.as_str(), route.id.as_str())),
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
