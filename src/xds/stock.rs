//! Stock Envoy / third-party Istio xDS interoperability profile (issue #3317).
//!
//! This module is the **entire** trust boundary between a third-party ADS
//! control plane and Ferrum's typed mesh model. It is deliberately separate
//! from [`super::translator`] / [`super::carrier`], which implement the
//! **Ferrum-private** xDS profile (`FERRUM_MESH_CONFIG_PROTOCOL=xds`): that
//! profile keeps its name-only CDS/EDS/LDS/RDS resources and its
//! `ferrum.config.extension.v3.*` ECDS carriers, and nothing here changes it.
//!
//! ## What the stock profile consumes
//!
//! Standard v3 `Cluster` / `ClusterLoadAssignment` / `Listener` /
//! `RouteConfiguration` resources, decoded through the field-exact projections
//! in `proto/envoy/stock/v3/stock_xds.proto`, and mapped onto exactly two
//! slice inputs:
//!
//! * [`MeshService`] — namespace/name/ports/protocol/cluster VIPs, and
//! * [`Workload`] — endpoint addresses carrying the peer SPIFFE identity the
//!   control plane itself pins in the cluster's `UpstreamTlsContext`.
//!
//! Everything security-bearing (authorization, PeerAuthentication, JWT rules,
//! trust bundles, DestinationRules, Sidecar scope) comes from Ferrum's own
//! local mesh policy document, never from the stock control plane. A stock CP
//! is a *discovery* authority here, not a *policy* authority.
//!
//! ## Fail-closed rules
//!
//! Two distinct outcomes, and the difference is load-bearing:
//!
//! * **Structural error** (`Err`) — the bytes are not a well-formed resource
//!   of the announced type, a name is empty/duplicated, or a declared bound is
//!   exceeded. The caller NACKs the whole response and rolls its accumulator
//!   back, exactly like the Ferrum-private client.
//! * **Refusal** ([`StockRefusal`]) — the resource is well formed but uses a
//!   capability Ferrum does not model. The resource is dropped from the view
//!   with a field-specific diagnostic and never contributes a route, an
//!   endpoint, or an identity. The response is still ACKed, because a stock CP
//!   legitimately programs Envoy features Ferrum has no counterpart for and
//!   NACKing the stream would leave the data plane permanently unconverged.
//!
//! A refusal always *narrows*: a refused cluster contributes no service, a
//! refused listener contributes no protocol classification or VIP, a refused
//! route contributes no host alias. Refusing therefore cannot broaden reach or
//! trust — the worst case is that traffic is not routed.
//!
//! The **extension-escape closure** is the set of fields through which an
//! Envoy extension, a filesystem path, credential material, an enforcement
//! filter, or a second delivery channel could otherwise enter. Every member is
//! declared in the proto projection and refused here: cluster `cluster_type` /
//! `filters` / `load_balancing_policy` / `lb_subset_config` /
//! `typed_extension_protocol_options`, unknown transport sockets, inline TLS
//! certificates, listener `api_listener` / `filter_chain_matcher` / unknown
//! listener+network filters, HCM `scoped_routes` / non-allowlisted HTTP
//! filters, route `typed_per_filter_config` / regex matchers / cluster
//! specifier plugins, non-ADS `ConfigSource`s, and every SDS variant that
//! carries a private key.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use prost::Message;

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AppProtocol, MeshService, ServicePort, ServiceTargetPort, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};

use super::stock_proto as sp;
use super::translator::{CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL};

/// The exact xDS type URLs the stock profile subscribes to.
///
/// SDS is intentionally absent: Ferrum's workload identity and trust anchors
/// come from its own SPIFFE/SVID configuration, and it never ingests private
/// key material handed to it by a third-party control plane. ECDS and RTDS are
/// absent because they are the Ferrum-private carrier transport — accepting
/// them from a stock CP would let an unrelated control plane author Ferrum
/// security policy.
pub const STOCK_XDS_TYPE_URLS: [&str; 4] = [CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL];

/// Types that gate the first mesh slice.
///
/// CDS is unconditional. EDS is *conditional* on CDS having produced at least
/// one EDS-discovered cluster — a mesh whose clusters are all STATIC has
/// nothing to wait for, and blocking on an EDS response that will never come
/// would wedge startup. LDS/RDS only enrich the view (port protocol
/// classification and service VIPs), so they never gate. See
/// [`StockXdsAccumulator::ready`] for the live predicate.
pub const STOCK_REQUIRED_TYPE_URLS: [&str; 2] = [CDS_TYPE_URL, EDS_TYPE_URL];

const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const TCP_PROXY_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const UPSTREAM_TLS_CONTEXT_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
const RAW_BUFFER_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer";
const HTTP_PROTOCOL_OPTIONS_KEY: &str = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

/// The single terminal HTTP filter Ferrum accepts on a stock listener.
const HTTP_ROUTER_FILTER: &str = "envoy.filters.http.router";

/// HTTP filters that only observe traffic (telemetry, metadata exchange) or
/// only *shape* it (fault injection). Dropping them cannot admit a request the
/// control plane intended to reject, so they are ignored rather than refused.
///
/// Every ENFORCEMENT filter is deliberately absent — `envoy.filters.http.rbac`,
/// `jwt_authn`, `ext_authz`, `cors`, `local_ratelimit`, `ratelimit`,
/// `health_check`, `lua`, and `wasm` all refuse the listener. Silently reducing
/// an Istio listener that carries an RBAC or JWT filter to plain routing would
/// turn the control plane's DENY into an ALLOW.
const IGNORABLE_HTTP_FILTERS: [&str; 6] = [
    "istio.metadata_exchange",
    "istio.stats",
    "istio.alpn",
    "envoy.filters.http.grpc_stats",
    "envoy.filters.http.grpc_web",
    "envoy.filters.http.fault",
];

/// Network filters that carry no routing or enforcement decision.
const IGNORABLE_NETWORK_FILTERS: [&str; 3] = [
    "istio.metadata_exchange",
    "envoy.filters.network.metadata_exchange",
    "istio.stats",
];

/// Listener filters that only *inspect* the connection. `original_src` and
/// `proxy_protocol` are absent on purpose: both rewrite the observed source
/// address, which is an authorization input.
const IGNORABLE_LISTENER_FILTERS: [&str; 4] = [
    "envoy.filters.listener.original_dst",
    "envoy.filters.listener.tls_inspector",
    "envoy.filters.listener.http_inspector",
    "envoy.filters.listener.workload_metadata",
];

/// Envoy/Istio clusters that exist for the proxy's own plumbing and never name
/// a mesh service. Enumerated rather than pattern-matched so a service that
/// happens to be called `agent` is still refused with a parse diagnostic
/// instead of being silently swallowed.
const RESERVED_ENVOY_CLUSTERS: [&str; 9] = [
    "BlackHoleCluster",
    "BlackHoleTCPCluster",
    "PassthroughCluster",
    "InboundPassthroughCluster",
    "InboundPassthroughClusterIpv4",
    "InboundPassthroughClusterIpv6",
    "agent",
    "prometheus_stats",
    "sds-grpc",
];

// ── refusal vocabulary ───────────────────────────────────────────────────

/// Stable, operator-facing reason codes for a refused stock resource. These
/// appear verbatim in logs, so they are treated as a compatibility surface.
pub mod refusal {
    pub const CLUSTER_EXTENSION_ESCAPE: &str = "cluster_extension_escape";
    pub const UNSUPPORTED_DISCOVERY_TYPE: &str = "unsupported_cluster_discovery_type";
    pub const UNSUPPORTED_TRANSPORT_SOCKET: &str = "unsupported_transport_socket";
    pub const INLINE_CREDENTIAL_MATERIAL: &str = "inline_credential_material";
    pub const FILESYSTEM_DATA_SOURCE: &str = "filesystem_data_source";
    pub const UNSUPPORTED_PEER_IDENTITY_MATCHER: &str = "unsupported_peer_identity_matcher";
    pub const UNPARSABLE_CLUSTER_NAME: &str = "unparsable_cluster_name";
    pub const RESERVED_ENVOY_CLUSTER: &str = "reserved_envoy_cluster";
    pub const INBOUND_CLUSTER_NOT_MAPPED: &str = "inbound_cluster_not_mapped";
    pub const SUBSET_CLUSTER_UNSUPPORTED: &str = "subset_cluster_unsupported";
    pub const NON_KUBERNETES_SERVICE_HOST: &str = "non_kubernetes_service_host";
    pub const NON_ADS_CONFIG_SOURCE: &str = "non_ads_config_source";
    pub const ENDPOINT_ADDRESS_UNSUPPORTED: &str = "endpoint_address_unsupported";
    pub const ENDPOINT_LIMIT_EXCEEDED: &str = "endpoint_limit_exceeded";
    pub const LISTENER_EXTENSION_ESCAPE: &str = "listener_extension_escape";
    pub const UNSUPPORTED_LISTENER_FILTER: &str = "unsupported_listener_filter";
    pub const UNSUPPORTED_NETWORK_FILTER: &str = "unsupported_network_filter";
    pub const UNSUPPORTED_HTTP_FILTER: &str = "unsupported_http_filter";
    pub const UNSUPPORTED_CODEC: &str = "unsupported_codec";
    pub const MISSING_ROUTE_SOURCE: &str = "missing_route_source";
    pub const ROUTE_EXTENSION_ESCAPE: &str = "route_extension_escape";
    pub const UNSUPPORTED_ROUTE_MATCH: &str = "unsupported_route_match";
    pub const UNSUPPORTED_ROUTE_ACTION: &str = "unsupported_route_action";
    pub const AMBIGUOUS_VIRTUAL_HOST_TARGET: &str = "ambiguous_virtual_host_target";
    pub const AMBIGUOUS_PORT_PROTOCOL: &str = "ambiguous_port_protocol";
    pub const AMBIGUOUS_PEER_IDENTITY: &str = "ambiguous_peer_identity";
    pub const NO_PINNED_PEER_IDENTITY: &str = "no_pinned_peer_identity";
    pub const RESOURCE_LIMIT_EXCEEDED: &str = "resource_limit_exceeded";
    pub const SDS_SECRET_REFUSED: &str = "sds_secret_refused";
}

/// Render a control-plane-supplied value for a log line: control characters
/// stripped (no log-line forgery) and truncated.
///
/// A resource name, an extension key, and a filter name are all chosen by the
/// control plane and bounded only by [`StockXdsLimits::max_resource_bytes`] —
/// up to a mebibyte of arbitrary text per default bound. They are diagnostics,
/// never comparison keys, so bounding them here costs nothing: the accumulator
/// keeps every raw value it actually matches on.
pub fn diagnostic_value(value: &str) -> String {
    const MAX_CHARS: usize = 160;
    let mut rendered = String::with_capacity(value.len().min(MAX_CHARS) + 12);
    let mut truncated = false;
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_CHARS {
            truncated = true;
            break;
        }
        rendered.push(if ch.is_control() { '.' } else { ch });
    }
    if truncated {
        rendered.push_str("(truncated)");
    }
    rendered
}

/// One refused stock resource. Both string fields are rendered through
/// [`diagnostic_value`] at construction, so a refusal carries no payload bytes
/// and no unbounded or control-character-bearing control-plane value, and is
/// safe to log verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockRefusal {
    /// Short xDS type label (`cds` / `eds` / `lds` / `rds`).
    pub type_label: &'static str,
    /// The control-plane resource name that was refused.
    pub resource: String,
    /// Stable reason code from [`refusal`].
    pub reason: &'static str,
    /// Field-specific detail — a field path or extension name, never a value.
    pub detail: String,
}

impl StockRefusal {
    fn new(
        type_label: &'static str,
        resource: impl Into<String>,
        reason: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        let resource: String = resource.into();
        let detail: String = detail.into();
        Self {
            type_label,
            resource: diagnostic_value(&resource),
            reason,
            detail: diagnostic_value(&detail),
        }
    }
}

/// Bounds applied to every stock response before anything reaches the typed
/// mesh model. Exceeding a per-response bound is a structural error (NACK);
/// exceeding a per-resource bound refuses that one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockXdsLimits {
    pub max_resources_per_type: usize,
    pub max_resource_bytes: usize,
    pub max_endpoints_per_cluster: usize,
    pub max_filter_chains: usize,
    pub max_virtual_hosts: usize,
    pub max_routes_per_virtual_host: usize,
    pub max_domains_per_virtual_host: usize,
    pub max_peer_identities_per_cluster: usize,
}

impl Default for StockXdsLimits {
    fn default() -> Self {
        Self {
            max_resources_per_type: 10_000,
            max_resource_bytes: 1024 * 1024,
            max_endpoints_per_cluster: 4_096,
            max_filter_chains: 256,
            max_virtual_hosts: 4_096,
            max_routes_per_virtual_host: 1_024,
            max_domains_per_virtual_host: 256,
            max_peer_identities_per_cluster: 8,
        }
    }
}

// ── decoded shapes ───────────────────────────────────────────────────────

/// A stock cluster Ferrum accepted, already resolved to a mesh service port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockCluster {
    pub name: String,
    pub namespace: String,
    pub service: String,
    pub port: u16,
    /// EDS resource name to look up endpoints under (`service_name` when the
    /// CP set one, otherwise the cluster name). `None` for STATIC clusters,
    /// whose endpoints are inlined below.
    pub eds_resource: Option<String>,
    pub inline_endpoints: Vec<StockEndpoint>,
    /// SPIFFE identities the control plane pins as the expected peer for this
    /// cluster. Ferrum only synthesizes dialable workloads when exactly one is
    /// present, so an unverifiable peer is never given an endpoint.
    pub peer_identities: Vec<String>,
}

/// A single endpoint address from EDS (or an inlined STATIC assignment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockEndpoint {
    pub address: IpAddr,
    pub port: u16,
    pub weight: Option<u32>,
    pub locality: Option<String>,
}

/// Protocol classification derived from a listener's filter chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortClass {
    Http,
    Http2,
    Tcp,
    /// Two listeners classified the same bind/port differently.
    Ambiguous,
}

impl PortClass {
    fn merge(self, other: PortClass) -> PortClass {
        if self == other {
            self
        } else {
            PortClass::Ambiguous
        }
    }

    fn app_protocol(self) -> AppProtocol {
        match self {
            PortClass::Http => AppProtocol::Http,
            PortClass::Http2 => AppProtocol::Http2,
            PortClass::Tcp => AppProtocol::Tcp,
            PortClass::Ambiguous => AppProtocol::Unknown,
        }
    }
}

/// A stock listener Ferrum accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockListener {
    pub name: String,
    /// Concrete bind address, or `None` for a wildcard (`0.0.0.0` / `::`)
    /// listener. A concrete address on an outbound listener is the service VIP.
    pub bind_address: Option<IpAddr>,
    pub port: u16,
    /// `envoy.config.core.v3.TrafficDirection`: 0 unspecified, 1 inbound,
    /// 2 outbound.
    pub traffic_direction: i32,
    class: Option<PortClass>,
    /// RDS route configuration names referenced by this listener's HCM chains.
    pub route_config_names: Vec<String>,
    /// Cluster names referenced by this listener's TcpProxy chains.
    pub tcp_clusters: Vec<String>,
}

impl StockListener {
    /// Application protocol this listener's filter chains classify its port as.
    /// `Unknown` covers both "no classifiable chain" and "two chains disagreed"
    /// — in either case Ferrum refuses to guess a protocol for the port.
    pub fn app_protocol(&self) -> AppProtocol {
        self.class
            .map_or(AppProtocol::Unknown, PortClass::app_protocol)
    }
}

/// A virtual host Ferrum accepted, reduced to the two things it can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockVirtualHost {
    pub name: String,
    pub domains: Vec<String>,
    /// Distinct cluster names the accepted routes target.
    pub clusters: Vec<String>,
}

/// A stock route configuration Ferrum accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockRouteConfig {
    pub name: String,
    pub virtual_hosts: Vec<StockVirtualHost>,
}

/// The discovery output the stock profile folds into the local mesh policy
/// document before building a slice.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StockDiscovery {
    pub services: Vec<MeshService>,
    pub workloads: Vec<Workload>,
    pub refusals: Vec<StockRefusal>,
}

// ── accumulator ──────────────────────────────────────────────────────────

/// State-of-the-world accumulator for the stock profile.
///
/// CDS and LDS are the two types a SotW server must send as COMPLETE state, so
/// they are replaced wholesale — that is what makes deletion work: a cluster
/// absent from a new CDS response disappears from the next built slice, and its
/// endpoints become unreachable rather than stale. EDS and RDS are subscribed
/// by name and a response for them may carry only a subset of the subscription
/// (istiod pushes just the assignments a change touched), so those are MERGED
/// and pruned against the current subscription set instead — an omitted
/// assignment must never be read as "this service has no endpoints".
/// Per-type versions are tracked independently because a stock CP does
/// NOT share one `version_info` across types (unlike the Ferrum CP, whose
/// coherence gate protects its ECDS security carriers; there are no security
/// carriers here to skew against).
#[derive(Debug, Clone)]
pub struct StockXdsAccumulator {
    limits: StockXdsLimits,
    clusters: BTreeMap<String, StockCluster>,
    endpoints: BTreeMap<String, Vec<StockEndpoint>>,
    listeners: Vec<StockListener>,
    route_configs: BTreeMap<String, StockRouteConfig>,
    versions: BTreeMap<&'static str, String>,
    refusals: BTreeMap<&'static str, Vec<StockRefusal>>,
}

impl Default for StockXdsAccumulator {
    fn default() -> Self {
        Self::new(StockXdsLimits::default())
    }
}

impl StockXdsAccumulator {
    pub fn new(limits: StockXdsLimits) -> Self {
        Self {
            limits,
            clusters: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            listeners: Vec::new(),
            route_configs: BTreeMap::new(),
            versions: BTreeMap::new(),
            refusals: BTreeMap::new(),
        }
    }

    /// Apply one state-of-the-world response. CDS/LDS replace their complete
    /// type state; by-name EDS/RDS resources merge and are pruned when their
    /// complete-state parent stops subscribing to them.
    ///
    /// `Err` is a NACK-worthy structural error; the caller must roll back to a
    /// pre-call clone so a rejected response never partially lands.
    pub fn apply_sotw(
        &mut self,
        type_url: &str,
        resources: &[(String, Vec<u8>)],
        version: &str,
    ) -> Result<(), String> {
        let limits = self.limits;
        // Every diagnostic below is echoed back to the control plane in
        // `error_detail` AND logged locally, so the control-plane-supplied
        // halves go through `diagnostic_value` first.
        let safe_url = diagnostic_value(type_url);
        let label = stock_type_label(type_url)
            .ok_or_else(|| format!("unsupported xDS type_url '{safe_url}' on the stock profile"))?;
        if version.trim().is_empty() {
            return Err(format!(
                "xDS response for type_url '{safe_url}' has empty version_info"
            ));
        }
        if resources.len() > limits.max_resources_per_type {
            return Err(format!(
                "xDS response for type_url '{safe_url}' carries {} resources, over the \
                 configured stock-profile bound of {}",
                resources.len(),
                limits.max_resources_per_type
            ));
        }
        for (resource_type_url, bytes) in resources {
            if !resource_type_url.is_empty() && resource_type_url != type_url {
                return Err(format!(
                    "resource type_url '{}' does not match response type_url '{safe_url}'",
                    diagnostic_value(resource_type_url)
                ));
            }
            if bytes.len() > limits.max_resource_bytes {
                return Err(format!(
                    "xDS resource for type_url '{safe_url}' is {} bytes, over the configured \
                     stock-profile bound of {}",
                    bytes.len(),
                    limits.max_resource_bytes
                ));
            }
        }

        let mut refusals = Vec::new();
        match type_url {
            CDS_TYPE_URL => {
                let mut clusters = BTreeMap::new();
                let mut seen = BTreeSet::new();
                for (_, bytes) in resources {
                    let decoded = sp::Cluster::decode(bytes.as_slice())
                        .map_err(|e| format!("failed to decode Cluster resource: {e}"))?;
                    let name = non_empty_name(&decoded.name, "Cluster")?;
                    if !seen.insert(name.clone()) {
                        return Err(format!(
                            "duplicate Cluster resource name '{}'",
                            diagnostic_value(&name)
                        ));
                    }
                    match classify_cluster(&decoded, &name, &limits) {
                        Ok(Some((cluster, cluster_refusals))) => {
                            refusals.extend(cluster_refusals);
                            clusters.insert(name, cluster);
                        }
                        Ok(None) => {}
                        Err(refused) => refusals.push(refused),
                    }
                }
                self.clusters = clusters;
                // CDS *is* complete state, so it is what actually deletes an
                // endpoint assignment: an assignment no accepted cluster
                // references any more can never be reached again.
                self.prune_unsubscribed_endpoints();
            }
            EDS_TYPE_URL => {
                // Only CDS and LDS responses are complete state under SotW.
                // An EDS response may legitimately carry a SUBSET of the
                // subscribed assignments — istiod skips recomputing a cluster
                // its push did not touch — and an omitted assignment is NOT a
                // deletion. Replacing the map wholesale would blackhole every
                // service an ordinary endpoint update did not mention, so the
                // response is MERGED and deletion comes from the subscription
                // set instead (see `prune_unsubscribed_endpoints`).
                let mut endpoints = self.endpoints.clone();
                let mut seen = BTreeSet::new();
                for (_, bytes) in resources {
                    let decoded =
                        sp::ClusterLoadAssignment::decode(bytes.as_slice()).map_err(|e| {
                            format!("failed to decode ClusterLoadAssignment resource: {e}")
                        })?;
                    let name = non_empty_name(&decoded.cluster_name, "ClusterLoadAssignment")?;
                    if !seen.insert(name.clone()) {
                        return Err(format!(
                            "duplicate ClusterLoadAssignment resource name '{}'",
                            diagnostic_value(&name)
                        ));
                    }
                    match collect_endpoints(&decoded, &name, &limits, "eds") {
                        Ok(collected) => {
                            endpoints.insert(name, collected.endpoints);
                            refusals.extend(collected.refusals);
                        }
                        Err(refused) => {
                            // A refused assignment leaves the cluster with NO
                            // endpoints rather than its previous ones: stale
                            // endpoints would keep traffic flowing to a shape
                            // the CP has since rejected.
                            endpoints.insert(name, Vec::new());
                            refusals.push(refused);
                        }
                    }
                }
                self.endpoints = endpoints;
                self.prune_unsubscribed_endpoints();
            }
            LDS_TYPE_URL => {
                let mut listeners = Vec::new();
                let mut inline_routes = BTreeMap::new();
                let mut seen = BTreeSet::new();
                for (_, bytes) in resources {
                    let decoded = sp::Listener::decode(bytes.as_slice())
                        .map_err(|e| format!("failed to decode Listener resource: {e}"))?;
                    let name = non_empty_name(&decoded.name, "Listener")?;
                    if !seen.insert(name.clone()) {
                        return Err(format!(
                            "duplicate Listener resource name '{}'",
                            diagnostic_value(&name)
                        ));
                    }
                    match classify_listener(&decoded, &name, &limits) {
                        Ok(Some(accepted)) => {
                            for (route_name, route_config) in accepted.inline_route_configs {
                                inline_routes.insert(route_name, route_config);
                            }
                            refusals.extend(accepted.refusals);
                            listeners.push(accepted.listener);
                        }
                        Ok(None) => {}
                        Err(refused) => refusals.push(refused),
                    }
                }
                self.listeners = listeners;
                // Inline `route_config` blocks belong to the listener that
                // carried them, so they are rebuilt with LDS and must not
                // survive a listener's removal.
                self.route_configs
                    .retain(|name, _| !name.starts_with(INLINE_ROUTE_PREFIX));
                self.route_configs.extend(inline_routes);
                // LDS is complete state, so it is what deletes a CP-delivered
                // route configuration: one no accepted listener references any
                // more is unreachable.
                self.prune_unsubscribed_route_configs();
            }
            RDS_TYPE_URL => {
                // Same SotW rule as EDS: an RDS response may carry a SUBSET of
                // the subscribed route configurations, and an omitted one is
                // not a deletion. Merge into what is already held (inline,
                // listener-owned configs included — RDS never replaces those).
                let mut route_configs: BTreeMap<String, StockRouteConfig> =
                    self.route_configs.clone();
                let mut seen = BTreeSet::new();
                for (_, bytes) in resources {
                    let decoded =
                        sp::RouteConfiguration::decode(bytes.as_slice()).map_err(|e| {
                            format!("failed to decode RouteConfiguration resource: {e}")
                        })?;
                    let name = non_empty_name(&decoded.name, "RouteConfiguration")?;
                    if !seen.insert(name.clone()) {
                        return Err(format!(
                            "duplicate RouteConfiguration resource name '{}'",
                            diagnostic_value(&name)
                        ));
                    }
                    if name.starts_with(INLINE_ROUTE_PREFIX) {
                        return Err(format!(
                            "RouteConfiguration name '{}' uses the reserved inline-route \
                             prefix '{INLINE_ROUTE_PREFIX}'",
                            diagnostic_value(&name)
                        ));
                    }
                    match classify_route_configuration(&decoded, &name, &limits) {
                        Ok(accepted) => {
                            refusals.extend(accepted.refusals);
                            route_configs.insert(name, accepted.config);
                        }
                        Err(refused) => {
                            // Omitted RDS resources retain their last accepted state, but an
                            // explicitly present refusal must fail closed rather than leave the
                            // previously accepted configuration active.
                            route_configs.remove(&name);
                            refusals.push(refused);
                        }
                    }
                }
                self.route_configs = route_configs;
                self.prune_unsubscribed_route_configs();
            }
            other => {
                return Err(format!(
                    "unsupported xDS type_url '{}' on the stock profile",
                    diagnostic_value(other)
                ));
            }
        }

        // Versions are opaque protocol tokens. The stream state retains the
        // raw value needed for ACK/NACK, but the accumulator uses versions only
        // for diagnostics and slice observability, so never retain an
        // unbounded/control-character-bearing control-plane value here.
        self.versions.insert(label, diagnostic_value(version));
        self.refusals.insert(label, refusals);
        Ok(())
    }

    /// Drop endpoint assignments no accepted cluster references any more.
    ///
    /// This is what makes EDS deletion work now that responses are merged
    /// rather than replaced: the *subscription set* is authoritative for which
    /// assignments still matter, not the contents of the latest response.
    fn prune_unsubscribed_endpoints(&mut self) {
        let subscribed: BTreeSet<String> = self.eds_subscriptions().into_iter().collect();
        self.endpoints.retain(|name, _| subscribed.contains(name));
    }

    /// Drop CP-delivered route configurations no accepted listener references
    /// any more. Inline (listener-owned) configs are rebuilt by LDS itself and
    /// are exempt.
    fn prune_unsubscribed_route_configs(&mut self) {
        let subscribed: BTreeSet<String> = self.rds_subscriptions().into_iter().collect();
        self.route_configs
            .retain(|name, _| name.starts_with(INLINE_ROUTE_PREFIX) || subscribed.contains(name));
    }

    /// EDS resource names the accepted clusters depend on, deduplicated and
    /// sorted so the subscription request is stable across equivalent CDS
    /// responses. This is the *dependency-ordered* EDS subscription: Ferrum
    /// asks only for the assignments its clusters actually reference.
    pub fn eds_subscriptions(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .clusters
            .values()
            .filter_map(|cluster| cluster.eds_resource.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// RDS route-configuration names the accepted listeners depend on. Inline
    /// `route_config` blocks are excluded — they arrived with LDS and must not
    /// be requested from the control plane.
    pub fn rds_subscriptions(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .listeners
            .iter()
            .flat_map(|listener| listener.route_config_names.iter().cloned())
            .filter(|name| !name.starts_with(INLINE_ROUTE_PREFIX))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Dependency-ordered readiness: CDS has landed, and either no cluster
    /// needs EDS or EDS has landed too. There is deliberately no cross-type
    /// version-coherence gate — a stock CP versions each type independently,
    /// and there are no Ferrum security carriers here that a version skew
    /// could leave stale.
    pub fn ready(&self) -> bool {
        self.versions.contains_key("cds")
            && (self.eds_subscriptions().is_empty() || self.versions.contains_key("eds"))
    }

    /// Short labels of the gating types still awaiting an initial response.
    pub fn pending_types(&self) -> Vec<&'static str> {
        let mut pending = Vec::new();
        if !self.versions.contains_key("cds") {
            pending.push("cds");
        }
        if !self.eds_subscriptions().is_empty() && !self.versions.contains_key("eds") {
            pending.push("eds");
        }
        pending
    }

    /// Observability-only composite version. `MeshSlice::content_eq` ignores
    /// `version`, so this never participates in change detection.
    pub fn composite_version(&self) -> String {
        self.versions
            .iter()
            .map(|(label, version)| format!("{label}={version}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn per_type_versions(&self) -> BTreeMap<String, String> {
        self.versions
            .iter()
            .map(|(label, version)| ((*label).to_string(), version.clone()))
            .collect()
    }

    /// Every refusal currently held, ordered by type then discovery order.
    pub fn refusals(&self) -> Vec<StockRefusal> {
        self.refusals.values().flatten().cloned().collect()
    }

    pub fn clusters(&self) -> &BTreeMap<String, StockCluster> {
        &self.clusters
    }

    pub fn listeners(&self) -> &[StockListener] {
        &self.listeners
    }

    pub fn route_configs(&self) -> &BTreeMap<String, StockRouteConfig> {
        &self.route_configs
    }

    /// Project the accumulated stock resources onto Ferrum's typed mesh model.
    pub fn discovery(&self) -> StockDiscovery {
        build_discovery(self)
    }
}

const INLINE_ROUTE_PREFIX: &str = "ferrum-inline-route/";

fn stock_type_label(type_url: &str) -> Option<&'static str> {
    match type_url {
        CDS_TYPE_URL => Some("cds"),
        EDS_TYPE_URL => Some("eds"),
        LDS_TYPE_URL => Some("lds"),
        RDS_TYPE_URL => Some("rds"),
        _ => None,
    }
}

fn non_empty_name(name: &str, kind: &str) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err(format!("xDS {kind} resource has an empty name"));
    }
    Ok(name.to_string())
}

// ── cluster classification ───────────────────────────────────────────────

/// Parsed Istio cluster name: `<direction>|<port>|<subset>|<host>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IstioClusterName {
    pub direction: String,
    pub port: u16,
    pub subset: String,
    pub host: String,
}

/// Parse the Istio cluster-name grammar. Returns `None` for anything that is
/// not exactly four `|`-separated parts with a valid port.
pub fn parse_istio_cluster_name(name: &str) -> Option<IstioClusterName> {
    let parts: Vec<&str> = name.split('|').collect();
    if parts.len() != 4 {
        return None;
    }
    let port = parts[1].parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(IstioClusterName {
        direction: parts[0].to_string(),
        port,
        subset: parts[2].to_string(),
        host: parts[3].to_string(),
    })
}

/// Split a Kubernetes service FQDN (`<service>.<namespace>.svc.<domain>`) into
/// its service and namespace. Returns `None` for any other host shape,
/// including bare hostnames and external DNS names.
pub fn parse_kubernetes_service_host(host: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.');
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 4 || labels[2] != "svc" {
        return None;
    }
    let service = labels[0];
    let namespace = labels[1];
    if !is_dns_label(service) || !is_dns_label(namespace) {
        return None;
    }
    Some((service.to_string(), namespace.to_string()))
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// `Ok(Some((cluster, refusals)))` accepted (possibly with per-endpoint
/// refusals from an inlined STATIC assignment), `Ok(None)` deliberately ignored
/// (a reserved Envoy plumbing cluster), `Err(refusal)` refused with a
/// field-specific diagnostic.
#[allow(clippy::type_complexity)]
fn classify_cluster(
    cluster: &sp::Cluster,
    name: &str,
    limits: &StockXdsLimits,
) -> Result<Option<(StockCluster, Vec<StockRefusal>)>, StockRefusal> {
    let refuse =
        |reason: &'static str, detail: &str| StockRefusal::new("cds", name, reason, detail);

    // ── extension-escape closure ──
    for (field, present) in [
        ("cluster_type", !cluster.cluster_type.is_empty()),
        ("filters", !cluster.filters.is_empty()),
        (
            "load_balancing_policy",
            !cluster.load_balancing_policy.is_empty(),
        ),
        ("lb_subset_config", !cluster.lb_subset_config.is_empty()),
    ] {
        if present {
            return Err(refuse(refusal::CLUSTER_EXTENSION_ESCAPE, field));
        }
    }
    for key in cluster.typed_extension_protocol_options.keys() {
        if key != HTTP_PROTOCOL_OPTIONS_KEY {
            return Err(refuse(
                refusal::CLUSTER_EXTENSION_ESCAPE,
                format!("typed_extension_protocol_options[{key}]").as_str(),
            ));
        }
    }

    if RESERVED_ENVOY_CLUSTERS.contains(&name) {
        return Ok(None);
    }
    let Some(parsed) = parse_istio_cluster_name(name) else {
        return Err(refuse(
            refusal::UNPARSABLE_CLUSTER_NAME,
            "name (expected '<direction>|<port>|<subset>|<host>')",
        ));
    };
    if parsed.direction != "outbound" {
        // Ferrum materializes its own inbound listeners from the local policy
        // document; an Istio `inbound|...` cluster describes the *peer* proxy's
        // loopback wiring and must never become an outbound route here.
        return Err(refuse(
            refusal::INBOUND_CLUSTER_NOT_MAPPED,
            "name.direction",
        ));
    }
    if !parsed.subset.is_empty() {
        return Err(refuse(refusal::SUBSET_CLUSTER_UNSUPPORTED, "name.subset"));
    }
    let Some((service, namespace)) = parse_kubernetes_service_host(&parsed.host) else {
        return Err(refuse(refusal::NON_KUBERNETES_SERVICE_HOST, "name.host"));
    };

    // ── discovery type ──
    // DiscoveryType: STATIC = 0, STRICT_DNS = 1, LOGICAL_DNS = 2, EDS = 3,
    // ORIGINAL_DST = 4. DNS-resolved and original-destination clusters have no
    // endpoint inventory Ferrum can pin an identity to.
    let mut refusals = Vec::new();
    let (eds_resource, inline_endpoints) = match cluster.r#type {
        3 => {
            let eds_config = cluster
                .eds_cluster_config
                .as_ref()
                .ok_or_else(|| refuse(refusal::UNSUPPORTED_DISCOVERY_TYPE, "eds_cluster_config"))?;
            let source = eds_config.eds_config.as_ref().ok_or_else(|| {
                refuse(
                    refusal::NON_ADS_CONFIG_SOURCE,
                    "eds_cluster_config.eds_config",
                )
            })?;
            require_ads_config_source(source)
                .map_err(|field| refuse(refusal::NON_ADS_CONFIG_SOURCE, field.as_str()))?;
            let resource = if eds_config.service_name.is_empty() {
                name.to_string()
            } else {
                eds_config.service_name.clone()
            };
            (Some(resource), Vec::new())
        }
        0 => {
            let endpoints = match cluster.load_assignment.as_ref() {
                Some(assignment) => {
                    let collected = collect_endpoints(assignment, name, limits, "cds")?;
                    refusals.extend(collected.refusals);
                    collected.endpoints
                }
                None => Vec::new(),
            };
            (None, endpoints)
        }
        other => {
            return Err(refuse(
                refusal::UNSUPPORTED_DISCOVERY_TYPE,
                format!("type={other}").as_str(),
            ));
        }
    };

    let peer_identities = cluster_peer_identities(cluster, limits)
        .map_err(|(reason, detail)| refuse(reason, detail.as_str()))?;

    Ok(Some((
        StockCluster {
            name: name.to_string(),
            namespace,
            service,
            port: parsed.port,
            eds_resource,
            inline_endpoints,
            peer_identities,
        },
        refusals,
    )))
}

fn require_ads_config_source(source: &sp::ConfigSource) -> Result<(), String> {
    if source.ads.is_empty() {
        let which = if !source.path.is_empty() {
            "path"
        } else if !source.api_config_source.is_empty() {
            "api_config_source"
        } else if !source.self_.is_empty() {
            "self"
        } else if !source.path_config_source.is_empty() {
            "path_config_source"
        } else {
            "unset"
        };
        return Err(format!("config_source.{which}"));
    }
    Ok(())
}

/// Extract the peer SPIFFE identities the control plane pins for a cluster.
///
/// Istio programs these as URI SAN matchers on the cluster's
/// `UpstreamTlsContext`, which makes them the CP's own authoritative statement
/// of "who is allowed to answer for this cluster". Ferrum reuses that statement
/// verbatim rather than inventing an identity from endpoint metadata.
fn cluster_peer_identities(
    cluster: &sp::Cluster,
    limits: &StockXdsLimits,
) -> Result<Vec<String>, (&'static str, String)> {
    let mut sockets: Vec<(&str, &sp::TransportSocket)> = Vec::new();
    if let Some(socket) = cluster.transport_socket.as_ref() {
        sockets.push(("transport_socket", socket));
    }
    for entry in &cluster.transport_socket_matches {
        if let Some(socket) = entry.transport_socket.as_ref() {
            sockets.push(("transport_socket_matches", socket));
        }
    }

    let mut identities: BTreeSet<String> = BTreeSet::new();
    for (field, socket) in sockets {
        let Some(typed) = socket.typed_config.as_ref() else {
            return Err((
                refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                format!("{field}.typed_config (unset)"),
            ));
        };
        match typed.type_url.as_str() {
            RAW_BUFFER_TYPE_URL => continue,
            UPSTREAM_TLS_CONTEXT_TYPE_URL => {}
            other => {
                return Err((
                    refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                    format!("{field}.typed_config[{other}]"),
                ));
            }
        }
        let context = sp::UpstreamTlsContext::decode(typed.value.as_slice()).map_err(|_| {
            (
                refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                format!("{field}.typed_config (undecodable UpstreamTlsContext)"),
            )
        })?;
        let Some(common) = context.common_tls_context.as_ref() else {
            continue;
        };
        if !common.tls_certificates.is_empty() {
            return Err((
                refusal::INLINE_CREDENTIAL_MATERIAL,
                format!("{field}.common_tls_context.tls_certificates"),
            ));
        }
        if !common.custom_handshaker.is_empty() {
            return Err((
                refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                format!("{field}.common_tls_context.custom_handshaker"),
            ));
        }
        let mut contexts: Vec<&sp::CertificateValidationContext> = Vec::new();
        if let Some(validation) = common.validation_context.as_ref() {
            contexts.push(validation);
        }
        if let Some(combined) = common.combined_validation_context.as_ref()
            && let Some(default) = combined.default_validation_context.as_ref()
        {
            contexts.push(default);
        }
        for validation in contexts {
            if let Some(trusted_ca) = validation.trusted_ca.as_ref() {
                if !trusted_ca.filename.is_empty() {
                    return Err((
                        refusal::FILESYSTEM_DATA_SOURCE,
                        format!("{field}.validation_context.trusted_ca.filename"),
                    ));
                }
                if !trusted_ca.environment_variable.is_empty() {
                    return Err((
                        refusal::FILESYSTEM_DATA_SOURCE,
                        format!("{field}.validation_context.trusted_ca.environment_variable"),
                    ));
                }
            }
            if !validation.custom_validator_config.is_empty() {
                return Err((
                    refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                    format!("{field}.validation_context.custom_validator_config"),
                ));
            }
            for matcher in &validation.match_typed_subject_alt_names {
                // SanType URI = 3. Ferrum pins SPIFFE URIs only; a DNS or IP
                // SAN constraint is a different assertion and is skipped
                // rather than reinterpreted as an identity.
                if matcher.san_type != 3 {
                    continue;
                }
                let Some(string_matcher) = matcher.matcher.as_ref() else {
                    continue;
                };
                if !string_matcher.safe_regex.is_empty() || !string_matcher.custom.is_empty() {
                    return Err((
                        refusal::UNSUPPORTED_PEER_IDENTITY_MATCHER,
                        format!("{field}.match_typed_subject_alt_names[].matcher.safe_regex"),
                    ));
                }
                if string_matcher.exact.is_empty() {
                    return Err((
                        refusal::UNSUPPORTED_PEER_IDENTITY_MATCHER,
                        format!(
                            "{field}.match_typed_subject_alt_names[].matcher (only `exact` is \
                             accepted)"
                        ),
                    ));
                }
                if SpiffeId::new(string_matcher.exact.clone()).is_err() {
                    return Err((
                        refusal::UNSUPPORTED_PEER_IDENTITY_MATCHER,
                        format!(
                            "{field}.match_typed_subject_alt_names[].matcher.exact (not a valid \
                             SPIFFE ID)"
                        ),
                    ));
                }
                identities.insert(string_matcher.exact.clone());
                if identities.len() > limits.max_peer_identities_per_cluster {
                    return Err((
                        refusal::RESOURCE_LIMIT_EXCEEDED,
                        format!(
                            "{field}.match_typed_subject_alt_names (over {})",
                            limits.max_peer_identities_per_cluster
                        ),
                    ));
                }
            }
        }
    }
    Ok(identities.into_iter().collect())
}

// ── endpoint collection ──────────────────────────────────────────────────

struct CollectedEndpoints {
    endpoints: Vec<StockEndpoint>,
    refusals: Vec<StockRefusal>,
}

fn collect_endpoints(
    assignment: &sp::ClusterLoadAssignment,
    resource: &str,
    limits: &StockXdsLimits,
    type_label: &'static str,
) -> Result<CollectedEndpoints, StockRefusal> {
    let refuse = |reason: &'static str, detail: &str| {
        StockRefusal::new(type_label, resource, reason, detail)
    };
    let total: usize = assignment
        .endpoints
        .iter()
        .map(|locality| locality.lb_endpoints.len())
        .sum();
    if total > limits.max_endpoints_per_cluster {
        return Err(refuse(
            refusal::ENDPOINT_LIMIT_EXCEEDED,
            format!(
                "endpoints ({total} over the bound of {})",
                limits.max_endpoints_per_cluster
            )
            .as_str(),
        ));
    }

    let mut endpoints = Vec::new();
    let mut refusals = Vec::new();
    for locality in &assignment.endpoints {
        if !locality.leds_cluster_locality_config.is_empty() {
            return Err(refuse(
                refusal::NON_ADS_CONFIG_SOURCE,
                "endpoints[].leds_cluster_locality_config",
            ));
        }
        let locality_label = locality.locality.as_ref().and_then(|locality| {
            let label = format!(
                "{}/{}/{}",
                locality.region, locality.zone, locality.sub_zone
            );
            if label == "//" { None } else { Some(label) }
        });
        for lb_endpoint in &locality.lb_endpoints {
            if !lb_endpoint.endpoint_name.is_empty() {
                refusals.push(refuse(
                    refusal::ENDPOINT_ADDRESS_UNSUPPORTED,
                    "lb_endpoints[].endpoint_name",
                ));
                continue;
            }
            // HealthStatus: UNKNOWN = 0, HEALTHY = 1, UNHEALTHY = 2,
            // DRAINING = 3, TIMEOUT = 4, DEGRADED = 5. Excluding the
            // non-serving states is ordinary health signalling, not a
            // capability gap, so it produces no refusal record.
            if !matches!(lb_endpoint.health_status, 0 | 1 | 5) {
                continue;
            }
            let Some(endpoint) = lb_endpoint.endpoint.as_ref() else {
                refusals.push(refuse(
                    refusal::ENDPOINT_ADDRESS_UNSUPPORTED,
                    "lb_endpoints[].endpoint (unset)",
                ));
                continue;
            };
            if !endpoint.additional_addresses.is_empty() {
                refusals.push(refuse(
                    refusal::ENDPOINT_ADDRESS_UNSUPPORTED,
                    "lb_endpoints[].endpoint.additional_addresses",
                ));
                continue;
            }
            match endpoint_socket(endpoint) {
                Ok((address, port)) => endpoints.push(StockEndpoint {
                    address,
                    port,
                    weight: lb_endpoint
                        .load_balancing_weight
                        .as_ref()
                        .map(|weight| weight.value),
                    locality: locality_label.clone(),
                }),
                Err(detail) => {
                    refusals.push(refuse(
                        refusal::ENDPOINT_ADDRESS_UNSUPPORTED,
                        detail.as_str(),
                    ));
                }
            }
        }
    }
    Ok(CollectedEndpoints {
        endpoints,
        refusals,
    })
}

fn endpoint_socket(endpoint: &sp::Endpoint) -> Result<(IpAddr, u16), String> {
    let Some(address) = endpoint.address.as_ref() else {
        return Err("lb_endpoints[].endpoint.address (unset)".to_string());
    };
    if !address.pipe.is_empty() {
        return Err("lb_endpoints[].endpoint.address.pipe".to_string());
    }
    if !address.envoy_internal_address.is_empty() {
        return Err("lb_endpoints[].endpoint.address.envoy_internal_address".to_string());
    }
    let Some(socket) = address.socket_address.as_ref() else {
        return Err("lb_endpoints[].endpoint.address.socket_address (unset)".to_string());
    };
    if socket.protocol != 0 {
        return Err("lb_endpoints[].endpoint.address.socket_address.protocol".to_string());
    }
    if !socket.named_port.is_empty() {
        return Err("lb_endpoints[].endpoint.address.socket_address.named_port".to_string());
    }
    if !socket.resolver_name.is_empty() {
        return Err("lb_endpoints[].endpoint.address.socket_address.resolver_name".to_string());
    }
    let port = u16::try_from(socket.port_value).map_err(|_| {
        "lb_endpoints[].endpoint.address.socket_address.port_value (out of range)".to_string()
    })?;
    if port == 0 {
        return Err("lb_endpoints[].endpoint.address.socket_address.port_value (zero)".to_string());
    }
    let address: IpAddr = socket.address.parse().map_err(|_| {
        "lb_endpoints[].endpoint.address.socket_address.address (not an IP literal)".to_string()
    })?;
    Ok((address, port))
}

// ── listener classification ──────────────────────────────────────────────

struct AcceptedListener {
    listener: StockListener,
    inline_route_configs: Vec<(String, StockRouteConfig)>,
    refusals: Vec<StockRefusal>,
}

fn classify_listener(
    listener: &sp::Listener,
    name: &str,
    limits: &StockXdsLimits,
) -> Result<Option<AcceptedListener>, StockRefusal> {
    let refuse =
        |reason: &'static str, detail: &str| StockRefusal::new("lds", name, reason, detail);

    for (field, present) in [
        ("api_listener", !listener.api_listener.is_empty()),
        (
            "filter_chain_matcher",
            !listener.filter_chain_matcher.is_empty(),
        ),
        (
            "additional_addresses",
            !listener.additional_addresses.is_empty(),
        ),
    ] {
        if present {
            return Err(refuse(refusal::LISTENER_EXTENSION_ESCAPE, field));
        }
    }
    for filter in &listener.listener_filters {
        if !filter.config_discovery.is_empty() {
            return Err(refuse(
                refusal::UNSUPPORTED_LISTENER_FILTER,
                "listener_filters[].config_discovery",
            ));
        }
        if !IGNORABLE_LISTENER_FILTERS.contains(&filter.name.as_str()) {
            return Err(refuse(
                refusal::UNSUPPORTED_LISTENER_FILTER,
                format!("listener_filters[{}]", filter.name).as_str(),
            ));
        }
    }

    let Some(address) = listener.address.as_ref() else {
        // A listener with no address programs nothing Ferrum can classify.
        return Ok(None);
    };
    if !address.pipe.is_empty() || !address.envoy_internal_address.is_empty() {
        return Err(refuse(
            refusal::LISTENER_EXTENSION_ESCAPE,
            "address (pipe / envoy_internal_address)",
        ));
    }
    let Some(socket) = address.socket_address.as_ref() else {
        return Ok(None);
    };
    let port = u16::try_from(socket.port_value)
        .map_err(|_| refuse(refusal::LISTENER_EXTENSION_ESCAPE, "address.port_value"))?;
    if port == 0 || !socket.named_port.is_empty() {
        return Ok(None);
    }
    let bind_address = match socket.address.parse::<IpAddr>() {
        Ok(address) if address.is_unspecified() => None,
        Ok(address) => Some(address),
        // A non-literal bind address (a DNS name) is not a VIP Ferrum can key
        // a captured connection on; the listener still classifies its port.
        Err(_) => None,
    };

    let mut chains: Vec<&sp::FilterChain> = listener.filter_chains.iter().collect();
    if let Some(default_chain) = listener.default_filter_chain.as_ref() {
        chains.push(default_chain);
    }
    if chains.len() > limits.max_filter_chains {
        return Err(refuse(
            refusal::RESOURCE_LIMIT_EXCEEDED,
            format!(
                "filter_chains ({} over the bound of {})",
                chains.len(),
                limits.max_filter_chains
            )
            .as_str(),
        ));
    }

    let mut class: Option<PortClass> = None;
    let mut route_config_names = Vec::new();
    let mut tcp_clusters = Vec::new();
    let mut inline_route_configs = Vec::new();
    let mut refusals = Vec::new();

    for (index, chain) in chains.iter().enumerate() {
        if let Some(matcher) = chain.filter_chain_match.as_ref() {
            for (field, present) in [
                ("prefix_ranges", !matcher.prefix_ranges.is_empty()),
                ("address_suffix", !matcher.address_suffix.is_empty()),
                ("suffix_len", matcher.suffix_len.is_some()),
                (
                    "source_prefix_ranges",
                    !matcher.source_prefix_ranges.is_empty(),
                ),
                ("source_ports", !matcher.source_ports.is_empty()),
                ("destination_port", matcher.destination_port.is_some()),
                ("transport_protocol", !matcher.transport_protocol.is_empty()),
                (
                    "application_protocols",
                    !matcher.application_protocols.is_empty(),
                ),
                ("server_names", !matcher.server_names.is_empty()),
                ("source_type", matcher.source_type != 0),
                (
                    "direct_source_prefix_ranges",
                    !matcher.direct_source_prefix_ranges.is_empty(),
                ),
            ] {
                if present {
                    return Err(refuse(
                        refusal::LISTENER_EXTENSION_ESCAPE,
                        format!("filter_chains[].filter_chain_match.{field}").as_str(),
                    ));
                }
            }
        }
        if chain.transport_socket.is_some() {
            return Err(refuse(
                refusal::UNSUPPORTED_TRANSPORT_SOCKET,
                "filter_chains[].transport_socket",
            ));
        }
        for filter in &chain.filters {
            if !filter.config_discovery.is_empty() {
                return Err(refuse(
                    refusal::UNSUPPORTED_NETWORK_FILTER,
                    "filter_chains[].filters[].config_discovery",
                ));
            }
            let Some(typed) = filter.typed_config.as_ref() else {
                if IGNORABLE_NETWORK_FILTERS.contains(&filter.name.as_str()) {
                    continue;
                }
                return Err(refuse(
                    refusal::UNSUPPORTED_NETWORK_FILTER,
                    format!("filter_chains[].filters[{}] (no typed_config)", filter.name).as_str(),
                ));
            };
            match typed.type_url.as_str() {
                HCM_TYPE_URL => {
                    let hcm = sp::HttpConnectionManager::decode(typed.value.as_slice()).map_err(
                        |_| {
                            refuse(
                                refusal::UNSUPPORTED_NETWORK_FILTER,
                                "filter_chains[].filters[].typed_config (undecodable \
                                 HttpConnectionManager)",
                            )
                        },
                    )?;
                    let outcome = classify_http_connection_manager(
                        &hcm,
                        name,
                        index,
                        limits,
                        &mut inline_route_configs,
                        &mut refusals,
                    )?;
                    route_config_names.extend(outcome.route_config_names);
                    class =
                        Some(class.map_or(outcome.class, |current| current.merge(outcome.class)));
                }
                TCP_PROXY_TYPE_URL => {
                    let tcp = sp::TcpProxy::decode(typed.value.as_slice()).map_err(|_| {
                        refuse(
                            refusal::UNSUPPORTED_NETWORK_FILTER,
                            "filter_chains[].filters[].typed_config (undecodable TcpProxy)",
                        )
                    })?;
                    if !tcp.weighted_clusters.is_empty() {
                        return Err(refuse(
                            refusal::UNSUPPORTED_ROUTE_ACTION,
                            "tcp_proxy.weighted_clusters",
                        ));
                    }
                    if !tcp.tunneling_config.is_empty() {
                        return Err(refuse(
                            refusal::UNSUPPORTED_NETWORK_FILTER,
                            "tcp_proxy.tunneling_config",
                        ));
                    }
                    if !tcp.cluster.is_empty() {
                        tcp_clusters.push(tcp.cluster.clone());
                    }
                    class =
                        Some(class.map_or(PortClass::Tcp, |current| current.merge(PortClass::Tcp)));
                }
                other if IGNORABLE_NETWORK_FILTERS.contains(&filter.name.as_str()) => {
                    let _ = other;
                }
                other => {
                    return Err(refuse(
                        refusal::UNSUPPORTED_NETWORK_FILTER,
                        format!("filter_chains[].filters[{}] ({other})", filter.name).as_str(),
                    ));
                }
            }
        }
    }

    route_config_names.sort();
    route_config_names.dedup();
    tcp_clusters.sort();
    tcp_clusters.dedup();

    Ok(Some(AcceptedListener {
        listener: StockListener {
            name: name.to_string(),
            bind_address,
            port,
            traffic_direction: listener.traffic_direction,
            class,
            route_config_names,
            tcp_clusters,
        },
        inline_route_configs,
        refusals,
    }))
}

struct HcmOutcome {
    class: PortClass,
    route_config_names: Vec<String>,
}

fn classify_http_connection_manager(
    hcm: &sp::HttpConnectionManager,
    listener_name: &str,
    chain_index: usize,
    limits: &StockXdsLimits,
    inline_route_configs: &mut Vec<(String, StockRouteConfig)>,
    refusals: &mut Vec<StockRefusal>,
) -> Result<HcmOutcome, StockRefusal> {
    let refuse = |reason: &'static str, detail: &str| {
        StockRefusal::new("lds", listener_name, reason, detail)
    };

    if !hcm.scoped_routes.is_empty() {
        return Err(refuse(
            refusal::LISTENER_EXTENSION_ESCAPE,
            "http_connection_manager.scoped_routes",
        ));
    }
    // CodecType: AUTO = 0, HTTP1 = 1, HTTP2 = 2, HTTP3 = 3.
    let class = match hcm.codec_type {
        0 | 1 => PortClass::Http,
        2 => PortClass::Http2,
        other => {
            return Err(refuse(
                refusal::UNSUPPORTED_CODEC,
                format!("http_connection_manager.codec_type={other}").as_str(),
            ));
        }
    };

    let mut saw_router = false;
    for filter in &hcm.http_filters {
        if !filter.config_discovery.is_empty() {
            return Err(refuse(
                refusal::UNSUPPORTED_HTTP_FILTER,
                "http_filters[].config_discovery",
            ));
        }
        if filter.name == HTTP_ROUTER_FILTER {
            saw_router = true;
            continue;
        }
        if IGNORABLE_HTTP_FILTERS.contains(&filter.name.as_str()) {
            continue;
        }
        // Deliberately independent of `disabled` / `is_optional`: a disabled
        // enforcement filter can still be re-enabled per route, and Ferrum has
        // no way to honour either state.
        return Err(refuse(
            refusal::UNSUPPORTED_HTTP_FILTER,
            format!("http_filters[{}]", filter.name).as_str(),
        ));
    }
    if !saw_router && !hcm.http_filters.is_empty() {
        return Err(refuse(
            refusal::UNSUPPORTED_HTTP_FILTER,
            "http_filters (no terminal envoy.filters.http.router)",
        ));
    }

    let mut route_config_names = Vec::new();
    match (hcm.rds.as_ref(), hcm.route_config.as_ref()) {
        (Some(rds), None) => {
            let source = rds.config_source.as_ref().ok_or_else(|| {
                refuse(
                    refusal::NON_ADS_CONFIG_SOURCE,
                    "http_connection_manager.rds.config_source (unset)",
                )
            })?;
            require_ads_config_source(source).map_err(|field| {
                refuse(
                    refusal::NON_ADS_CONFIG_SOURCE,
                    format!("http_connection_manager.rds.{field}").as_str(),
                )
            })?;
            if rds.route_config_name.is_empty() {
                return Err(refuse(
                    refusal::MISSING_ROUTE_SOURCE,
                    "http_connection_manager.rds.route_config_name",
                ));
            }
            route_config_names.push(rds.route_config_name.clone());
        }
        (None, Some(inline)) => {
            let name = format!("{INLINE_ROUTE_PREFIX}{listener_name}/{chain_index}");
            match classify_route_configuration(inline, &name, limits) {
                Ok(accepted) => {
                    refusals.extend(accepted.refusals);
                    inline_route_configs.push((name.clone(), accepted.config));
                    route_config_names.push(name);
                }
                Err(refused) => refusals.push(refused),
            }
        }
        (Some(_), Some(_)) => {
            return Err(refuse(
                refusal::MISSING_ROUTE_SOURCE,
                "http_connection_manager (both rds and route_config set)",
            ));
        }
        (None, None) => {
            return Err(refuse(
                refusal::MISSING_ROUTE_SOURCE,
                "http_connection_manager (neither rds nor route_config set)",
            ));
        }
    }

    Ok(HcmOutcome {
        class,
        route_config_names,
    })
}

// ── route configuration classification ───────────────────────────────────

struct AcceptedRouteConfig {
    config: StockRouteConfig,
    refusals: Vec<StockRefusal>,
}

fn classify_route_configuration(
    config: &sp::RouteConfiguration,
    name: &str,
    limits: &StockXdsLimits,
) -> Result<AcceptedRouteConfig, StockRefusal> {
    let refuse =
        |reason: &'static str, detail: &str| StockRefusal::new("rds", name, reason, detail);

    for (field, present) in [
        ("vhds", !config.vhds.is_empty()),
        (
            "cluster_specifier_plugins",
            !config.cluster_specifier_plugins.is_empty(),
        ),
        (
            "typed_per_filter_config",
            !config.typed_per_filter_config.is_empty(),
        ),
    ] {
        if present {
            return Err(refuse(refusal::ROUTE_EXTENSION_ESCAPE, field));
        }
    }
    if config.virtual_hosts.len() > limits.max_virtual_hosts {
        return Err(refuse(
            refusal::RESOURCE_LIMIT_EXCEEDED,
            format!(
                "virtual_hosts ({} over the bound of {})",
                config.virtual_hosts.len(),
                limits.max_virtual_hosts
            )
            .as_str(),
        ));
    }

    let mut virtual_hosts = Vec::new();
    let mut refusals = Vec::new();
    for virtual_host in &config.virtual_hosts {
        match classify_virtual_host(virtual_host, name, limits) {
            Ok(accepted) => virtual_hosts.push(accepted),
            Err(refused) => refusals.push(refused),
        }
    }

    Ok(AcceptedRouteConfig {
        config: StockRouteConfig {
            name: name.to_string(),
            virtual_hosts,
        },
        refusals,
    })
}

fn classify_virtual_host(
    virtual_host: &sp::VirtualHost,
    config_name: &str,
    limits: &StockXdsLimits,
) -> Result<StockVirtualHost, StockRefusal> {
    let resource = format!("{config_name}/{}", virtual_host.name);
    let refuse = |reason: &'static str, detail: &str| {
        StockRefusal::new("rds", resource.clone(), reason, detail)
    };

    if !virtual_host.matcher.is_empty() {
        return Err(refuse(refusal::ROUTE_EXTENSION_ESCAPE, "matcher"));
    }
    if !virtual_host.typed_per_filter_config.is_empty() {
        return Err(refuse(
            refusal::ROUTE_EXTENSION_ESCAPE,
            "typed_per_filter_config",
        ));
    }
    // TlsRequirementType: NONE = 0. A non-zero requirement is an enforcement
    // decision Ferrum cannot express from a stock route, so it must not be
    // dropped into an unconditional allow.
    if virtual_host.require_tls != 0 {
        return Err(refuse(
            refusal::ROUTE_EXTENSION_ESCAPE,
            format!("require_tls={}", virtual_host.require_tls).as_str(),
        ));
    }
    if virtual_host.domains.len() > limits.max_domains_per_virtual_host {
        return Err(refuse(
            refusal::RESOURCE_LIMIT_EXCEEDED,
            format!(
                "domains ({} over the bound of {})",
                virtual_host.domains.len(),
                limits.max_domains_per_virtual_host
            )
            .as_str(),
        ));
    }
    if virtual_host.routes.len() > limits.max_routes_per_virtual_host {
        return Err(refuse(
            refusal::RESOURCE_LIMIT_EXCEEDED,
            format!(
                "routes ({} over the bound of {})",
                virtual_host.routes.len(),
                limits.max_routes_per_virtual_host
            )
            .as_str(),
        ));
    }

    let mut clusters = BTreeSet::new();
    for route in &virtual_host.routes {
        // A route Ferrum cannot represent refuses the WHOLE virtual host, not
        // just itself: keeping the surviving routes would silently widen the
        // remaining matches to traffic the refused route was meant to take.
        for (field, present) in [
            ("redirect", !route.redirect.is_empty()),
            ("direct_response", !route.direct_response.is_empty()),
            ("filter_action", !route.filter_action.is_empty()),
            (
                "non_forwarding_action",
                !route.non_forwarding_action.is_empty(),
            ),
            (
                "typed_per_filter_config",
                !route.typed_per_filter_config.is_empty(),
            ),
        ] {
            if present {
                return Err(refuse(
                    refusal::ROUTE_EXTENSION_ESCAPE,
                    format!("routes[].{field}").as_str(),
                ));
            }
        }
        if let Some(matcher) = route.r#match.as_ref() {
            for (field, present) in [
                ("path", !matcher.path.is_empty()),
                ("safe_regex", !matcher.safe_regex.is_empty()),
                ("connect_matcher", !matcher.connect_matcher.is_empty()),
                (
                    "path_separated_prefix",
                    !matcher.path_separated_prefix.is_empty(),
                ),
                ("path_match_policy", !matcher.path_match_policy.is_empty()),
                ("prefix", matcher.prefix != "/"),
                ("headers", !matcher.headers.is_empty()),
                ("query_parameters", !matcher.query_parameters.is_empty()),
                ("grpc", !matcher.grpc.is_empty()),
                ("runtime_fraction", !matcher.runtime_fraction.is_empty()),
                ("tls_context", !matcher.tls_context.is_empty()),
                ("dynamic_metadata", !matcher.dynamic_metadata.is_empty()),
            ] {
                if present {
                    return Err(refuse(
                        refusal::UNSUPPORTED_ROUTE_MATCH,
                        format!("routes[].match.{field}").as_str(),
                    ));
                }
            }
            if matcher
                .case_sensitive
                .as_ref()
                .is_some_and(|flag| !flag.value)
            {
                return Err(refuse(
                    refusal::UNSUPPORTED_ROUTE_MATCH,
                    "routes[].match.case_sensitive=false",
                ));
            }
        }
        let Some(action) = route.route.as_ref() else {
            return Err(refuse(
                refusal::UNSUPPORTED_ROUTE_ACTION,
                "routes[].route (unset)",
            ));
        };
        for (field, present) in [
            ("cluster_header", !action.cluster_header.is_empty()),
            ("weighted_clusters", !action.weighted_clusters.is_empty()),
            (
                "cluster_specifier_plugin",
                !action.cluster_specifier_plugin.is_empty(),
            ),
            (
                "inline_cluster_specifier_plugin",
                !action.inline_cluster_specifier_plugin.is_empty(),
            ),
        ] {
            if present {
                return Err(refuse(
                    refusal::UNSUPPORTED_ROUTE_ACTION,
                    format!("routes[].route.{field}").as_str(),
                ));
            }
        }
        if action.cluster.is_empty() {
            return Err(refuse(
                refusal::UNSUPPORTED_ROUTE_ACTION,
                "routes[].route.cluster (empty)",
            ));
        }
        clusters.insert(action.cluster.clone());
    }

    Ok(StockVirtualHost {
        name: virtual_host.name.clone(),
        domains: virtual_host.domains.clone(),
        clusters: clusters.into_iter().collect(),
    })
}

// ── projection onto the typed mesh model ─────────────────────────────────

#[derive(Debug, Default)]
struct ServiceBuild {
    ports: BTreeMap<u16, PortBuild>,
    cluster_ips: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct PortBuild {
    /// Endpoint container ports observed for this service port.
    target_ports: BTreeSet<u16>,
    endpoints: Vec<StockEndpoint>,
    identity: Option<SpiffeId>,
}

fn build_discovery(accumulator: &StockXdsAccumulator) -> StockDiscovery {
    let mut refusals = accumulator.refusals();
    let mut services: BTreeMap<(String, String), ServiceBuild> = BTreeMap::new();
    // Cluster name → the service it resolves to, used by LDS/RDS to attribute
    // a VIP or a protocol classification to a service.
    let mut service_by_cluster: BTreeMap<&str, (String, String)> = BTreeMap::new();

    for (name, cluster) in &accumulator.clusters {
        service_by_cluster.insert(
            name.as_str(),
            (cluster.namespace.clone(), cluster.service.clone()),
        );
        let entry = services
            .entry((cluster.namespace.clone(), cluster.service.clone()))
            .or_default();
        let port = entry.ports.entry(cluster.port).or_default();

        let endpoints: &[StockEndpoint] = match cluster.eds_resource.as_deref() {
            Some(resource) => accumulator
                .endpoints
                .get(resource)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            None => cluster.inline_endpoints.as_slice(),
        };

        match cluster.peer_identities.len() {
            1 => match SpiffeId::new(cluster.peer_identities[0].clone()) {
                Ok(spiffe) => port.identity = Some(spiffe),
                Err(_) => refusals.push(StockRefusal::new(
                    "cds",
                    cluster.name.clone(),
                    refusal::UNSUPPORTED_PEER_IDENTITY_MATCHER,
                    "match_typed_subject_alt_names[].matcher.exact",
                )),
            },
            0 => {
                if !endpoints.is_empty() {
                    // Endpoints exist but the CP pinned no peer identity, so
                    // Ferrum cannot verify who answers. Publish the service
                    // shape (ports/VIPs stay useful for policy and for the
                    // registry gate) without any dialable endpoint.
                    refusals.push(StockRefusal::new(
                        "cds",
                        cluster.name.clone(),
                        refusal::NO_PINNED_PEER_IDENTITY,
                        "transport_socket.common_tls_context.match_typed_subject_alt_names",
                    ));
                }
            }
            _ => refusals.push(StockRefusal::new(
                "cds",
                cluster.name.clone(),
                refusal::AMBIGUOUS_PEER_IDENTITY,
                "transport_socket.common_tls_context.match_typed_subject_alt_names",
            )),
        }

        if port.identity.is_some() {
            for endpoint in endpoints {
                port.target_ports.insert(endpoint.port);
                port.endpoints.push(endpoint.clone());
            }
        }
    }

    // ── VIPs and protocol classification from LDS/RDS ──
    let mut wildcard_class: BTreeMap<u16, PortClass> = BTreeMap::new();
    let mut vip_class: BTreeMap<(IpAddr, u16), PortClass> = BTreeMap::new();
    // Route config name → the single service its virtual hosts resolve to.
    let mut service_by_route_config: BTreeMap<&str, Option<(String, String)>> = BTreeMap::new();

    for (name, config) in &accumulator.route_configs {
        let mut resolved: BTreeSet<(String, String)> = BTreeSet::new();
        for virtual_host in &config.virtual_hosts {
            let mut host_services: BTreeSet<(String, String)> = BTreeSet::new();
            for cluster in &virtual_host.clusters {
                if let Some(service) = service_by_cluster.get(cluster.as_str()) {
                    host_services.insert(service.clone());
                }
            }
            if host_services.len() > 1 {
                refusals.push(StockRefusal::new(
                    "rds",
                    format!("{name}/{}", virtual_host.name),
                    refusal::AMBIGUOUS_VIRTUAL_HOST_TARGET,
                    "routes[].route.cluster",
                ));
                continue;
            }
            let Some(service_key) = host_services.into_iter().next() else {
                continue;
            };
            resolved.insert(service_key.clone());
            if let Some(entry) = services.get_mut(&service_key) {
                for domain in &virtual_host.domains {
                    if let Some(ip) = domain_ip_literal(domain) {
                        entry.cluster_ips.insert(ip);
                    }
                }
            }
        }
        let single = if resolved.len() == 1 {
            resolved.into_iter().next()
        } else {
            None
        };
        service_by_route_config.insert(name.as_str(), single);
    }

    for listener in &accumulator.listeners {
        if let Some(class) = listener.class {
            match listener.bind_address {
                Some(address) => {
                    vip_class
                        .entry((address, listener.port))
                        .and_modify(|current| *current = current.merge(class))
                        .or_insert(class);
                }
                None => {
                    wildcard_class
                        .entry(listener.port)
                        .and_modify(|current| *current = current.merge(class))
                        .or_insert(class);
                }
            }
        }
        // A concrete-bind listener names its service's VIP. Attribute it
        // through the listener's TcpProxy cluster or its route configuration.
        let Some(bind_address) = listener.bind_address else {
            continue;
        };
        let mut targets: BTreeSet<(String, String)> = BTreeSet::new();
        for cluster in &listener.tcp_clusters {
            if let Some(service) = service_by_cluster.get(cluster.as_str()) {
                targets.insert(service.clone());
            }
        }
        for route_config in &listener.route_config_names {
            if let Some(Some(service)) = service_by_route_config.get(route_config.as_str()) {
                targets.insert(service.clone());
            }
        }
        if targets.len() != 1 {
            continue;
        }
        if let Some(key) = targets.into_iter().next()
            && let Some(entry) = services.get_mut(&key)
        {
            entry.cluster_ips.insert(bind_address.to_string());
        }
    }

    // ── emit the typed model ──
    let mut workloads_by_key: BTreeMap<(String, String), Workload> = BTreeMap::new();
    let mut mesh_services = Vec::new();

    for ((namespace, name), build) in services {
        let mut ports = Vec::new();
        let mut refs: BTreeSet<String> = BTreeSet::new();
        let cluster_ips: Vec<String> = build.cluster_ips.iter().cloned().collect();

        for (port, port_build) in &build.ports {
            let class = resolve_port_class(*port, &cluster_ips, &wildcard_class, &vip_class);
            if class == Some(PortClass::Ambiguous) {
                refusals.push(StockRefusal::new(
                    "lds",
                    format!("{namespace}/{name}:{port}"),
                    refusal::AMBIGUOUS_PORT_PROTOCOL,
                    "filter_chains[].filters[]",
                ));
            }
            // A single distinct endpoint container port is the service's
            // `targetPort`; a heterogeneous set has no single remap and is
            // left to Ferrum's default (dial the service port).
            let target_port = if port_build.target_ports.len() == 1 {
                port_build
                    .target_ports
                    .iter()
                    .next()
                    .copied()
                    .filter(|container| container != port)
                    .map(ServiceTargetPort::Number)
            } else {
                None
            };
            ports.push(ServicePort {
                port: *port,
                protocol: class.map_or(AppProtocol::Unknown, PortClass::app_protocol),
                name: None,
                target_port,
            });

            let Some(identity) = port_build.identity.as_ref() else {
                continue;
            };
            for endpoint in &port_build.endpoints {
                let address = endpoint.address.to_string();
                let key = (identity.as_str().to_string(), address.clone());
                let workload = workloads_by_key.entry(key).or_insert_with(|| Workload {
                    spiffe_id: identity.clone(),
                    selector: WorkloadSelector::default(),
                    service_name: name.clone(),
                    service_namespace: identity
                        .namespace()
                        .filter(|identity_ns| *identity_ns != namespace)
                        .map(|_| namespace.clone()),
                    addresses: vec![address.clone()],
                    ports: Vec::new(),
                    trust_domain: identity.trust_domain().clone(),
                    namespace: identity
                        .namespace()
                        .map(str::to_string)
                        .unwrap_or_else(|| namespace.clone()),
                    network: None,
                    cluster: None,
                    weight: endpoint.weight,
                    locality: endpoint.locality.clone(),
                    service_account: identity.service_account().map(str::to_string),
                    pod_uid: None,
                    node_waypoint: None,
                    remote_provenance: false,
                });
                if !workload
                    .ports
                    .iter()
                    .any(|existing| existing.port == endpoint.port)
                {
                    workload.ports.push(WorkloadPort {
                        port: endpoint.port,
                        protocol: class.map_or(AppProtocol::Unknown, PortClass::app_protocol),
                        name: None,
                    });
                }
                refs.insert(identity.as_str().to_string());
            }
        }

        let workload_refs = refs
            .into_iter()
            .filter_map(|spiffe| SpiffeId::new(spiffe).ok())
            .map(|spiffe_id| WorkloadRef { spiffe_id })
            .collect();

        mesh_services.push(MeshService {
            name,
            namespace,
            ports,
            workloads: workload_refs,
            protocol_overrides: HashMap::new(),
            cluster_ips,
        });
    }

    let mut workloads: Vec<Workload> = workloads_by_key.into_values().collect();
    workloads.sort_by(|left, right| {
        left.spiffe_id
            .as_str()
            .cmp(right.spiffe_id.as_str())
            .then_with(|| left.addresses.cmp(&right.addresses))
    });

    StockDiscovery {
        services: mesh_services,
        workloads,
        refusals,
    }
}

fn resolve_port_class(
    port: u16,
    cluster_ips: &[String],
    wildcard_class: &BTreeMap<u16, PortClass>,
    vip_class: &BTreeMap<(IpAddr, u16), PortClass>,
) -> Option<PortClass> {
    for ip in cluster_ips {
        if let Ok(address) = ip.parse::<IpAddr>()
            && let Some(class) = vip_class.get(&(address, port))
        {
            return Some(*class);
        }
    }
    wildcard_class.get(&port).copied()
}

/// Extract the IP literal from an Envoy virtual-host domain. Istio programs
/// both `10.0.0.1` and `10.0.0.1:9080` forms; hostname domains yield `None`.
fn domain_ip_literal(domain: &str) -> Option<String> {
    if let Ok(address) = domain.parse::<IpAddr>() {
        return Some(address.to_string());
    }
    // `[::1]:8080` and `10.0.0.1:8080`.
    if let Some(rest) = domain.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return host.parse::<IpAddr>().ok().map(|ip| ip.to_string());
    }
    let (host, port) = domain.rsplit_once(':')?;
    if port.parse::<u16>().is_err() {
        return None;
    }
    host.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Classify an SDS `Secret` a stock control plane pushed unsolicited.
///
/// The stock profile never subscribes to SDS, so reaching this function means
/// the CP volunteered one. Every variant is refused; the key-bearing ones are
/// refused without decoding, so no private key material is ever parsed, held,
/// or logged.
pub fn refuse_stock_secret(bytes: &[u8]) -> StockRefusal {
    match sp::Secret::decode(bytes) {
        Ok(secret) => {
            let detail = if !secret.tls_certificate.is_empty() {
                "tls_certificate"
            } else if !secret.session_ticket_keys.is_empty() {
                "session_ticket_keys"
            } else if !secret.generic_secret.is_empty() {
                "generic_secret"
            } else if secret.validation_context.is_some() {
                "validation_context"
            } else {
                "secret"
            };
            StockRefusal::new("sds", secret.name, refusal::SDS_SECRET_REFUSED, detail)
        }
        Err(_) => StockRefusal::new(
            "sds",
            String::new(),
            refusal::SDS_SECRET_REFUSED,
            "secret (undecodable)",
        ),
    }
}
