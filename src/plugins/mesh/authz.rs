//! Mesh authorization plugin.
//!
//! Evaluates Layer 2 `MeshPolicy` rules against the SPIFFE identity extracted
//! by `spiffe_identity` or, for ambient HBONE streams, the identity carried in
//! the HBONE baggage metadata.
//!
//! ## PolicyScope enforcement
//!
//! Each [`crate::modes::mesh::config::MeshPolicy`] carries a [`crate::modes::mesh::config::PolicyScope`]
//! that determines which workloads it applies to. Applying every policy to
//! every workload is a security correctness gap — a namespace-scoped DENY in
//! namespace `A` would deny traffic for workloads in namespace `B`, and a
//! namespace-scoped ALLOW in `A` would raise the implicit-deny floor for
//! unrelated namespaces.
//!
//! In normal mesh topologies, the plugin pre-filters `slice.mesh_policies` at
//! construction time using
//! [`crate::modes::mesh::config::policy_scope_applies_to_workload`]. The hot
//! path ([`evaluate_mesh_authorization`]) then sees only the policies that
//! apply to **this** proxy's workload, so the per-request cost stays at the same
//! O(policies × rules) it was before — minus any policies the scope filter
//! discarded. Filtering is keyed on `(proxy_namespace, proxy_labels)` supplied
//! either by the embedded `mesh_slice` (mesh mode injection) or by explicit
//! `namespace` / `labels` config fields (direct-config / test).
//!
//! Node-waypoint mode is different because one proxy instance handles many
//! pods. When `per_pod_policy_scoping` is enabled, construction-time filtering
//! is skipped. The request path still uses the source pod's
//! `RequestContext::node_waypoint_policy_scope` as the liveness/scope-missing
//! fail-closed gate, but HTTP Service egress filters policy applicability by
//! the selected destination Service's backing workload scopes, matching Istio's
//! destination-scoped AuthorizationPolicy semantics. A missing source scope
//! means the pod's workload is no longer in the live slice (the resolver derives
//! a pod's scope from the same single generation that vouches its identity, so
//! it is not an enrollment race): both the HTTP/HBONE and stream paths then
//! **fail closed** (403) when any namespace/selector-scoped policy is
//! configured, and fall through to mesh-wide-only when the mesh carries only
//! mesh-wide policies.
//!
//! Service-waypoint mode also carries a full policy superset because its
//! inbound HBONE relay protects workloads that may not share the waypoint
//! pod's namespace or labels. Byte-stream and datagram CONNECTs resolve the
//! exact destination workload scope from the synthesized relay backend, fail
//! closed when that evidence is missing, and stamp the authorized destination
//! so later route dispatch cannot substitute a different backend.

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::config::types::Proxy;
use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::config::{
    MeshPolicy, PolicyAction, PolicyScope, is_mesh_condition_ip_key,
    is_supported_mesh_condition_key, mesh_condition_has_values,
    normalize_request_match_host_pattern, policy_scope_applies_to_workload, resolve_target_port,
    validate_mesh_condition_ip_block, workload_selector_matches,
};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::policy::{
    MeshAuthzAttribute, MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    evaluate_mesh_authorization_policies, istio_source_principal, mesh_policies_have_header_rules,
    normalize_mesh_policy_header_names,
};
use crate::modes::mesh::policy_deny_log::{self, PolicyDenyEvent};
use crate::modes::mesh::slice::MeshSlice;
use crate::plugins::{
    ALL_PROTOCOLS, JwtAuthAttributeValue, Plugin, PluginResult, ProxyProtocol, RequestContext,
    StreamConnectionContext, priority,
};

pub(crate) const IGNORED_UDP_SOURCE_SCOPE_METADATA: &str = "mesh_authz.ignored_udp_source_scope";

pub struct MeshAuthz {
    slice: MeshSlice,
    /// Unfiltered policy superset used for Ambient UDP CONNECTs carrying
    /// validated per-pod evidence and for ServiceWaypoint inbound relays whose
    /// destination workload differs from the waypoint identity. Ordinary
    /// Ambient/Sidecar traffic continues to use the construction-time workload
    /// filter in `slice.mesh_policies`.
    relay_policy_superset: Vec<MeshPolicy>,
    ambient_udp_source_scopes: HashMap<[u8; 16], crate::modes::mesh::runtime::PolicyScopeCache>,
    ambient_udp_source_scoping: bool,
    /// ServiceWaypoint relays terminate for workloads outside the waypoint's
    /// own namespace. Their destination policy scope must therefore be resolved
    /// from the CONNECT authority/backend, not from `slice.namespace` (the
    /// waypoint namespace). This applies to byte-stream and UDP CONNECTs alike.
    service_waypoint_destination_scope_required: bool,
    destination_policy_scopes_by_upstream:
        HashMap<String, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
    destination_policy_scopes_by_backend:
        HashMap<DestinationBackendKey, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
    destination_policy_scopes_by_namespaced_backend: HashMap<
        NamespacedDestinationBackendKey,
        Vec<crate::modes::mesh::runtime::PolicyScopeCache>,
    >,
    destination_backend_aliases_by_backend:
        HashMap<DestinationBackendKey, Vec<DestinationBackendKey>>,
    destination_backend_aliases_by_namespaced_backend:
        HashMap<NamespacedDestinationBackendKey, Vec<DestinationBackendKey>>,
    destination_same_namespace_backend_alias_by_backend:
        HashMap<NamespacedDestinationBackendKey, DestinationBackendKey>,
    destination_service_backend_hosts: HashSet<String>,
    destination_namespaced_service_backend_hosts: HashSet<NamespacedDestinationBackendHostKey>,
    destination_route_upstreams_requiring_scope: HashSet<String>,
    has_route_upstream_metadata: bool,
    has_header_rules: bool,
    relay_policy_superset_has_header_rules: bool,
    /// Additional SPIFFE trust domains accepted as equivalent to the peer
    /// cert's trust domain when authorising HBONE baggage `source.principal`.
    /// Default empty: strict same-trust-domain match.
    trust_domain_aliases: Vec<TrustDomain>,
    /// Identity-asserting infrastructure SVIDs that are trusted to rewrite the
    /// authz principal via HBONE baggage `source.principal`. Any
    /// authenticated HBONE peer outside this set has its baggage identity
    /// dropped and is authorised under its own peer SPIFFE ID. Default
    /// `["ztunnel", "waypoint"]` (Istio ambient convention). See the
    /// `TrustedAssertor` variants for matching semantics.
    trusted_hbone_assertors: Vec<TrustedAssertor>,
    /// When `true`, the construction-time slice-level scope filter is
    /// skipped and policies are filtered per-request using
    /// [`RequestContext::node_waypoint_policy_scope`] instead. Used in
    /// node-waypoint topology where one listener serves many pods and a
    /// single proxy-identity filter doesn't fit. Default `false`
    /// preserves the existing sidecar/ambient/east-west/egress-gateway
    /// behaviour (slice-level filter at construction).
    per_pod_policy_scoping: bool,
    /// Precomputed: whether any namespace/selector-scoped (non-mesh-wide)
    /// policy is loaded. The stream path uses this to fail closed when the
    /// per-pod scope is missing but scoped policies exist (they can't be
    /// evaluated without the scope), while letting mesh-wide-only meshes fall
    /// through to mesh-wide evaluation. Only meaningful when
    /// `per_pod_policy_scoping` is true.
    has_scoped_policies: bool,
    /// Precomputed set of Istio attribute keys referenced by `when:`
    /// conditions across the loaded policies. The request hot path only
    /// materializes attributes named here, so a policy set with no `when:`
    /// conditions pays nothing and the common cases (a handful of keys)
    /// avoid building the full attribute namespace per request.
    condition_keys: ConditionAttributeKeys,
    relay_policy_superset_condition_keys: ConditionAttributeKeys,
    /// Monotonic-ms of the last emitted `principal_pod_mismatch` warning, or
    /// `0` before the first. Gates a rate-limited operator warning when the
    /// node-agent-derived HBONE source SPIFFE fails to byte-match the CP-derived
    /// slice `Workload.spiffe_id` for the same pod UID, so per-pod Ambient UDP
    /// scoping silently degrades to mesh-wide. Lock-free (`&self` hot path);
    /// see [`Self::warn_udp_principal_pod_mismatch`].
    udp_principal_pod_mismatch_warn_last_ms: std::sync::atomic::AtomicU64,
}

/// Which Istio `when:` attribute keys the loaded policies actually reference.
///
/// Built once at construction from `slice.mesh_policies`. Categorised so the
/// request path can decide cheaply (a `bool` check) whether to touch a given
/// source — e.g. only parse the peer SPIFFE namespace when some condition asks
/// for `source.namespace`, only fetch headers/claims for the exact bracketed
/// keys requested. The dynamic-key sets (`request.headers[...]`,
/// `request.auth.claims[...]`) store the full bracketed key so lookup is a
/// direct map/contains check with no per-request parsing.
#[derive(Debug, Default, Clone)]
struct ConditionAttributeKeys {
    /// Any `when:` condition exists at all. When false the request path skips
    /// attribute materialization entirely.
    any: bool,
    source_principal: bool,
    source_namespace: bool,
    source_ip: bool,
    remote_ip: bool,
    request_auth_principal: bool,
    request_auth_presenter: bool,
    request_auth_audiences: bool,
    destination_port: bool,
    connection_sni: bool,
    /// Full `request.headers[<name>]` keys referenced.
    header_keys: std::collections::BTreeSet<String>,
    /// Full `request.auth.claims[<name>]` keys referenced.
    claim_keys: std::collections::BTreeSet<String>,
}

// A condition on an attribute key the gateway does not source (or sources only
// for one protocol, e.g. `request.headers[...]` on a stream) is intentionally
// left out of the materialized map. The evaluator then treats it as absent,
// which is the correct, fail-closed posture: a `values` condition on a missing
// attribute never matches, and a `not_values`-only condition on a missing
// attribute passes (Istio `not_rule` semantics). We never silently treat an
// unknown key as a positive match.

// ── Istio `when:` attribute key constants ────────────────────────────────
const ATTR_SOURCE_PRINCIPAL: &str = "source.principal";
const ATTR_SOURCE_NAMESPACE: &str = "source.namespace";
const ATTR_SOURCE_IP: &str = "source.ip";
const ATTR_REMOTE_IP: &str = "remote.ip";
const ATTR_REQUEST_AUTH_PRINCIPAL: &str = "request.auth.principal";
const ATTR_REQUEST_AUTH_PRESENTER: &str = "request.auth.presenter";
const ATTR_REQUEST_AUTH_AUDIENCES: &str = "request.auth.audiences";
const ATTR_DESTINATION_PORT: &str = "destination.port";
const ATTR_CONNECTION_SNI: &str = "connection.sni";
const ATTR_REQUEST_HEADERS_PREFIX: &str = "request.headers[";
const ATTR_REQUEST_AUTH_CLAIMS_PREFIX: &str = "request.auth.claims[";
pub(crate) const NODE_WAYPOINT_AUTHORIZED_UPSTREAM_ID_METADATA: &str =
    "mesh_authz.node_waypoint_authorized_upstream_id";
pub(crate) const NODE_WAYPOINT_AUTHORIZED_BACKEND_METADATA: &str =
    "mesh_authz.node_waypoint_authorized_backend";
pub(crate) const NODE_WAYPOINT_AUTHORIZED_BACKEND_ALIASES_METADATA: &str =
    "mesh_authz.node_waypoint_authorized_backend_aliases";
pub(crate) const NODE_WAYPOINT_SCOPED_AUTHZ_ACTIVE_METADATA: &str =
    "mesh_authz.node_waypoint_scoped_authz_active";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DestinationBackendKey {
    host: String,
    port: u16,
}

impl DestinationBackendKey {
    fn new(host: &str, port: u16) -> Option<Self> {
        if port == 0 {
            return None;
        }
        let host = normalize_destination_backend_host(host)?;
        Some(Self { host, port })
    }

    fn metadata_value(&self) -> String {
        format!("{}|{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NamespacedDestinationBackendKey {
    namespace: String,
    host: String,
    port: u16,
}

impl NamespacedDestinationBackendKey {
    fn new(namespace: &str, host: &str, port: u16) -> Option<Self> {
        if port == 0 {
            return None;
        }
        let namespace = normalize_destination_backend_host(namespace)?;
        let host = normalize_destination_backend_host(host)?;
        Some(Self {
            namespace,
            host,
            port,
        })
    }

    fn backend_key(&self) -> DestinationBackendKey {
        DestinationBackendKey {
            host: self.host.clone(),
            port: self.port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NamespacedDestinationBackendHostKey {
    namespace: String,
    host: String,
}

impl NamespacedDestinationBackendHostKey {
    fn new(namespace: &str, host: &str) -> Option<Self> {
        let namespace = normalize_destination_backend_host(namespace)?;
        let host = normalize_destination_backend_host(host)?;
        Some(Self { namespace, host })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServicePortKey {
    namespace: String,
    name: String,
    port: u16,
}

impl ServicePortKey {
    fn new(service: &crate::modes::mesh::config::MeshService, port: u16) -> Self {
        Self {
            namespace: service.namespace.clone(),
            name: service.name.clone(),
            port,
        }
    }

    fn from_parts(namespace: &str, name: &str, port: u16) -> Option<Self> {
        if port == 0 || namespace.trim().is_empty() || name.trim().is_empty() {
            return None;
        }
        Some(Self {
            namespace: namespace.trim().to_ascii_lowercase(),
            name: name.trim().to_ascii_lowercase(),
            port,
        })
    }
}

#[derive(Debug, Clone)]
enum NodeWaypointAuthorizedDestination {
    Upstream(String),
    Backend {
        key: DestinationBackendKey,
        aliases: Vec<DestinationBackendKey>,
    },
}

struct DestinationScopeMatch<'a> {
    authorized_destination: NodeWaypointAuthorizedDestination,
    scopes: &'a [crate::modes::mesh::runtime::PolicyScopeCache],
}

#[derive(Default)]
struct DestinationPolicyScopeIndex {
    by_upstream: HashMap<String, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
    by_backend: HashMap<DestinationBackendKey, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
    by_namespaced_backend: HashMap<
        NamespacedDestinationBackendKey,
        Vec<crate::modes::mesh::runtime::PolicyScopeCache>,
    >,
    backend_aliases_by_backend: HashMap<DestinationBackendKey, Vec<DestinationBackendKey>>,
    backend_aliases_by_namespaced_backend:
        HashMap<NamespacedDestinationBackendKey, Vec<DestinationBackendKey>>,
    same_namespace_backend_alias_by_backend:
        HashMap<NamespacedDestinationBackendKey, DestinationBackendKey>,
    service_backend_hosts: HashSet<String>,
    namespaced_service_backend_hosts: HashSet<NamespacedDestinationBackendHostKey>,
    route_upstreams_requiring_scope: HashSet<String>,
}

#[derive(Debug, Deserialize)]
struct NodeWaypointRouteUpstreamConfig {
    id: String,
    namespace: String,
    #[serde(default)]
    targets: Vec<NodeWaypointRouteTargetConfig>,
}

#[derive(Debug, Deserialize)]
struct NodeWaypointRouteTargetConfig {
    host: String,
    port: u16,
    #[serde(default)]
    service_namespace: Option<String>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    service_port: Option<u16>,
}

#[derive(Clone)]
struct ServicePortDestinationScopes {
    scopes: Vec<crate::modes::mesh::runtime::PolicyScopeCache>,
    endpoint_backends: HashSet<DestinationBackendKey>,
    endpoint_scopes:
        HashMap<DestinationBackendKey, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
}

impl ConditionAttributeKeys {
    fn from_policies(policies: &[MeshPolicy]) -> Self {
        let mut keys = ConditionAttributeKeys::default();
        for policy in policies {
            for rule in &policy.rules {
                for condition in &rule.when {
                    keys.note_key(&condition.key);
                }
            }
        }
        keys
    }

    fn note_key(&mut self, key: &str) {
        self.any = true;
        match key {
            ATTR_SOURCE_PRINCIPAL => self.source_principal = true,
            ATTR_SOURCE_NAMESPACE => self.source_namespace = true,
            ATTR_SOURCE_IP => self.source_ip = true,
            ATTR_REMOTE_IP => self.remote_ip = true,
            ATTR_REQUEST_AUTH_PRINCIPAL => self.request_auth_principal = true,
            ATTR_REQUEST_AUTH_PRESENTER => self.request_auth_presenter = true,
            ATTR_REQUEST_AUTH_AUDIENCES => self.request_auth_audiences = true,
            ATTR_DESTINATION_PORT => self.destination_port = true,
            ATTR_CONNECTION_SNI => self.connection_sni = true,
            _ => {
                if bracketed_attribute_name(key, ATTR_REQUEST_HEADERS_PREFIX).is_some() {
                    self.header_keys.insert(key.to_string());
                } else if bracketed_attribute_name(key, ATTR_REQUEST_AUTH_CLAIMS_PREFIX).is_some() {
                    self.claim_keys.insert(key.to_string());
                }
                // Other keys (unsourced or unknown) are deliberately not
                // tracked; the evaluator treats them as absent (see note on
                // `ConditionAttributeKeys`).
            }
        }
    }
}

/// Extract `<name>` from an Istio bracketed attribute key
/// (`request.headers[x-foo]` ⇒ `x-foo`). Returns `None` when `key` is not a
/// `prefix...]` form.
fn bracketed_attribute_name<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    key.strip_prefix(prefix)?.strip_suffix(']')
}

fn normalize_destination_backend_host(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn node_waypoint_generated_route_upstream_id(upstream_id: &str) -> bool {
    upstream_id.starts_with("istio-vs-upstream-")
        || upstream_id.starts_with("gwapi-route-upstream-")
}

fn normalized_cluster_domains(config: &Value) -> Vec<String> {
    fn push_domain(domains: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
        let domain = value.trim().trim_matches('.').to_ascii_lowercase();
        if !domain.is_empty() && seen.insert(domain.clone()) {
            domains.push(domain);
        }
    }

    let mut domains = Vec::new();
    let mut seen = HashSet::new();
    if let Some(domain) = config.get("cluster_domain").and_then(Value::as_str) {
        push_domain(&mut domains, &mut seen, domain);
    }
    if let Some(extra_domains) = config.get("cluster_domains").and_then(Value::as_array) {
        for domain in extra_domains.iter().filter_map(Value::as_str) {
            push_domain(&mut domains, &mut seen, domain);
        }
    }
    if domains.is_empty() {
        domains.push("cluster.local".to_string());
    }
    domains
}

fn service_qualified_host_aliases(
    service: &crate::modes::mesh::config::MeshService,
    cluster_domains: &[String],
) -> Vec<String> {
    let mut aliases = vec![
        format!("{}.{}", service.name, service.namespace),
        format!("{}.{}.svc", service.name, service.namespace),
    ];
    for cluster_domain in cluster_domains {
        let cluster_domain = cluster_domain.trim().trim_matches('.');
        if cluster_domain.is_empty() {
            continue;
        }
        aliases.push(format!(
            "{}.{}.svc.{}",
            service.name, service.namespace, cluster_domain
        ));
    }
    aliases
}

fn destination_policy_scopes_for_service_port(
    service: &crate::modes::mesh::config::MeshService,
    service_port: &crate::modes::mesh::config::ServicePort,
    workloads: &[crate::modes::mesh::config::Workload],
    multi_cluster: Option<&crate::modes::mesh::config::MultiClusterConfig>,
) -> ServicePortDestinationScopes {
    let mut scopes = Vec::new();
    let mut endpoint_backends = HashSet::new();
    let mut endpoint_scopes: HashMap<_, Vec<_>> = HashMap::new();
    for workload in
        crate::modes::mesh::matched_local_service_workloads(service, workloads, multi_cluster)
    {
        if workload.addresses.is_empty() {
            continue;
        }
        let app_port = match service_port.target_port.as_ref() {
            Some(_) => {
                match resolve_target_port(service_port.target_port.as_ref(), &workload.ports) {
                    Some(port) if port != 0 => port,
                    _ => continue,
                }
            }
            None => service_port.port,
        };
        if app_port == 0 {
            continue;
        }
        let workload_scope = crate::modes::mesh::runtime::PolicyScopeCache::from_workload(workload);
        scopes.push(workload_scope.clone());
        for address in &workload.addresses {
            if let Some(key) = DestinationBackendKey::new(address, app_port) {
                endpoint_backends.insert(key.clone());
                endpoint_scopes
                    .entry(key)
                    .or_default()
                    .push(workload_scope.clone());
            }
        }
    }
    ServicePortDestinationScopes {
        scopes,
        endpoint_backends,
        endpoint_scopes,
    }
}

fn parse_node_waypoint_route_upstreams(
    config: &Value,
) -> Result<(bool, Vec<NodeWaypointRouteUpstreamConfig>), String> {
    match config.get("node_waypoint_route_upstreams") {
        Some(value) => {
            serde_json::from_value::<Vec<NodeWaypointRouteUpstreamConfig>>(value.clone())
                .map(|upstreams| (true, upstreams))
                .map_err(|error| {
                    format!("mesh_authz: invalid node_waypoint_route_upstreams: {error}")
                })
        }
        None => Ok((false, Vec::new())),
    }
}

fn service_port_key_for_backend(
    host: &str,
    port: u16,
    default_namespace: &str,
    qualified_service_ports: &HashMap<DestinationBackendKey, ServicePortKey>,
    namespaced_service_ports: &HashMap<NamespacedDestinationBackendKey, ServicePortKey>,
) -> Option<ServicePortKey> {
    if let Some(key) = DestinationBackendKey::new(host, port)
        && let Some(service_key) = qualified_service_ports.get(&key)
    {
        return Some(service_key.clone());
    }
    let key = NamespacedDestinationBackendKey::new(default_namespace, host, port)?;
    namespaced_service_ports.get(&key).cloned()
}

fn service_port_key_for_route_target(
    target: &NodeWaypointRouteTargetConfig,
    default_namespace: &str,
    qualified_service_ports: &HashMap<DestinationBackendKey, ServicePortKey>,
    namespaced_service_ports: &HashMap<NamespacedDestinationBackendKey, ServicePortKey>,
) -> Option<ServicePortKey> {
    if let (Some(service_name), Some(service_port)) =
        (target.service_name.as_deref(), target.service_port)
    {
        let namespace = target
            .service_namespace
            .as_deref()
            .unwrap_or(default_namespace);
        return ServicePortKey::from_parts(namespace, service_name, service_port);
    }
    let service_port = target.service_port.unwrap_or(target.port);
    service_port_key_for_backend(
        &target.host,
        service_port,
        default_namespace,
        qualified_service_ports,
        namespaced_service_ports,
    )
}

fn route_target_uses_service_alias(
    target: &NodeWaypointRouteTargetConfig,
    service_key: &ServicePortKey,
    default_namespace: &str,
    qualified_service_ports: &HashMap<DestinationBackendKey, ServicePortKey>,
    namespaced_service_ports: &HashMap<NamespacedDestinationBackendKey, ServicePortKey>,
) -> bool {
    let service_port = target.service_port.unwrap_or(target.port);
    service_port_key_for_backend(
        &target.host,
        service_port,
        default_namespace,
        qualified_service_ports,
        namespaced_service_ports,
    )
    .is_some_and(|key| key == *service_key)
}

fn route_target_uses_modeled_endpoint(
    target: &NodeWaypointRouteTargetConfig,
    service_key: &ServicePortKey,
    service_port_endpoints: &HashMap<ServicePortKey, HashSet<DestinationBackendKey>>,
) -> bool {
    DestinationBackendKey::new(&target.host, target.port).is_some_and(|backend| {
        service_port_endpoints
            .get(service_key)
            .is_some_and(|endpoints| endpoints.contains(&backend))
    })
}

fn destination_backend_aliases_for_service_port(
    service: &crate::modes::mesh::config::MeshService,
    service_port: u16,
    qualified_aliases: &[String],
    include_short_name: bool,
) -> Vec<DestinationBackendKey> {
    let mut aliases = Vec::new();
    let mut seen = HashSet::new();
    for alias in qualified_aliases {
        if let Some(key) = DestinationBackendKey::new(alias, service_port)
            && seen.insert(key.clone())
        {
            aliases.push(key);
        }
    }
    if include_short_name
        && let Some(key) = DestinationBackendKey::new(&service.name, service_port)
        && seen.insert(key.clone())
    {
        aliases.push(key);
    }
    aliases
}

fn destination_policy_scope_index(
    slice: &MeshSlice,
    cluster_domains: &[String],
    route_upstreams: &[NodeWaypointRouteUpstreamConfig],
) -> DestinationPolicyScopeIndex {
    let mut index = DestinationPolicyScopeIndex::default();
    let mut service_port_scopes = HashMap::new();
    let mut service_port_endpoints = HashMap::new();
    let mut qualified_service_ports = HashMap::new();
    let mut namespaced_service_ports = HashMap::new();
    let mut workload_backend_hosts = HashSet::new();
    for workload in &slice.workloads {
        for address in &workload.addresses {
            if let Some(address) = normalize_destination_backend_host(address) {
                workload_backend_hosts.insert(address);
            }
        }
    }
    for service in &slice.services {
        let aliases = service_qualified_host_aliases(service, cluster_domains);
        for alias in &aliases {
            if let Some(host) = normalize_destination_backend_host(alias) {
                index.service_backend_hosts.insert(host);
            }
        }
        if let Some(host_key) =
            NamespacedDestinationBackendHostKey::new(&service.namespace, &service.name)
        {
            index.namespaced_service_backend_hosts.insert(host_key);
        }
        for service_port in &service.ports {
            let service_key = ServicePortKey::new(service, service_port.port);
            let qualified_backend_aliases = destination_backend_aliases_for_service_port(
                service,
                service_port.port,
                &aliases,
                false,
            );
            let short_backend_alias = DestinationBackendKey::new(&service.name, service_port.port);
            let namespaced_backend_aliases = destination_backend_aliases_for_service_port(
                service,
                service_port.port,
                &aliases,
                true,
            );
            for alias in &aliases {
                if let Some(key) = DestinationBackendKey::new(alias, service_port.port) {
                    qualified_service_ports.insert(key, service_key.clone());
                }
            }
            if let Some(key) = NamespacedDestinationBackendKey::new(
                &service.namespace,
                &service.name,
                service_port.port,
            ) {
                namespaced_service_ports.insert(key, service_key.clone());
            }
            let scopes = destination_policy_scopes_for_service_port(
                service,
                service_port,
                &slice.workloads,
                slice.multi_cluster.as_ref(),
            );
            if scopes.scopes.is_empty() {
                continue;
            }
            service_port_scopes.insert(service_key.clone(), scopes.scopes.clone());
            service_port_endpoints.insert(service_key.clone(), scopes.endpoint_backends.clone());
            index.by_upstream.insert(
                crate::modes::mesh::mesh_outbound_upstream_id(
                    &service.namespace,
                    &service.name,
                    service_port.port,
                ),
                scopes.scopes.clone(),
            );
            for alias in &aliases {
                if let Some(key) = DestinationBackendKey::new(alias, service_port.port) {
                    index.by_backend.insert(key, scopes.scopes.clone());
                }
            }
            for (endpoint, endpoint_scopes) in &scopes.endpoint_scopes {
                index
                    .by_backend
                    .insert(endpoint.clone(), endpoint_scopes.clone());
                index
                    .backend_aliases_by_backend
                    .insert(endpoint.clone(), vec![endpoint.clone()]);
            }
            for alias_key in &qualified_backend_aliases {
                index
                    .backend_aliases_by_backend
                    .insert(alias_key.clone(), qualified_backend_aliases.clone());
                if let (Some(namespaced_alias_key), Some(short_backend_alias)) = (
                    NamespacedDestinationBackendKey::new(
                        &service.namespace,
                        &alias_key.host,
                        alias_key.port,
                    ),
                    short_backend_alias.clone(),
                ) {
                    index
                        .same_namespace_backend_alias_by_backend
                        .insert(namespaced_alias_key, short_backend_alias);
                }
            }
            if let Some(key) = NamespacedDestinationBackendKey::new(
                &service.namespace,
                &service.name,
                service_port.port,
            ) {
                index
                    .by_namespaced_backend
                    .insert(key.clone(), scopes.scopes.clone());
                index
                    .backend_aliases_by_namespaced_backend
                    .insert(key, namespaced_backend_aliases);
            }
        }
    }
    for upstream in route_upstreams {
        let mut route_scopes = Vec::new();
        let mut requires_destination_scope = false;
        let mut unscoped_target_seen = false;
        let mut external_target_seen = false;
        let mut seen_service_ports = HashSet::new();
        for target in &upstream.targets {
            let Some(service_key) = service_port_key_for_route_target(
                target,
                &upstream.namespace,
                &qualified_service_ports,
                &namespaced_service_ports,
            ) else {
                let host = normalize_destination_backend_host(&target.host);
                if host.is_some_and(|host| workload_backend_hosts.contains(&host))
                    || target.service_name.is_some()
                    || target.service_port.is_some()
                {
                    requires_destination_scope = true;
                    unscoped_target_seen = true;
                } else {
                    external_target_seen = true;
                }
                continue;
            };
            requires_destination_scope = true;
            if !route_target_uses_service_alias(
                target,
                &service_key,
                &upstream.namespace,
                &qualified_service_ports,
                &namespaced_service_ports,
            ) && !route_target_uses_modeled_endpoint(
                target,
                &service_key,
                &service_port_endpoints,
            ) {
                unscoped_target_seen = true;
                continue;
            }
            if seen_service_ports.insert(service_key.clone()) {
                if let Some(scopes) = service_port_scopes.get(&service_key) {
                    route_scopes.extend(scopes.clone());
                } else {
                    unscoped_target_seen = true;
                }
            }
        }
        if requires_destination_scope {
            index
                .route_upstreams_requiring_scope
                .insert(upstream.id.clone());
        }
        if requires_destination_scope
            && !unscoped_target_seen
            && !external_target_seen
            && !route_scopes.is_empty()
        {
            index.by_upstream.insert(upstream.id.clone(), route_scopes);
        }
    }
    index
}

fn evaluate_destination_policy_scopes(
    policies: &[MeshPolicy],
    scopes: &[crate::modes::mesh::runtime::PolicyScopeCache],
    request: &MeshAuthzRequest,
) -> MeshAuthzDecision {
    let mut audit_policy = None;
    for scope in scopes {
        let decision = evaluate_mesh_authorization_policies(
            policies
                .iter()
                .filter(|policy| scope.policy_applies(policy)),
            request,
        );
        match decision {
            MeshAuthzDecision::Deny { policy } => {
                return MeshAuthzDecision::Deny { policy };
            }
            MeshAuthzDecision::Audit { policy } => {
                audit_policy.get_or_insert(policy);
            }
            MeshAuthzDecision::Allow => {}
        }
    }
    if let Some(policy) = audit_policy {
        MeshAuthzDecision::Audit { policy }
    } else {
        MeshAuthzDecision::Allow
    }
}

/// Resolve a `request.headers[<name>]` value. Reads the already-lowercased
/// materialized `headers` map when header rules forced materialization;
/// otherwise falls back to the raw header accessor so a `when:` header
/// condition still works on a policy set whose `to.headers` were empty.
/// Istio header names are matched case-insensitively, and the condition key
/// name is lowercased to match the stored convention.
fn http_header_attribute(
    ctx: &RequestContext,
    materialized_lowercased: &BTreeMap<String, String>,
    name: &str,
) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if let Some(value) = materialized_lowercased.get(&lower) {
        return Some(value.clone());
    }
    if let Some(value) = ctx.headers.get(&lower).or_else(|| ctx.headers.get(name)) {
        return Some(value.clone());
    }
    if RequestContext::is_reserved_gateway_assertion_header(&lower) {
        return None;
    }
    ctx.raw_header_get(&lower)
        .or_else(|| ctx.raw_header_get(name))
        .map(str::to_string)
}

/// Parse an IP string into an `IpAddr` for
/// Istio `source.ip` / `remote.ip` matching. Returns `None` for an
/// unparseable value so IP-block matchers fail closed.
fn parse_client_ip(client_ip: &str) -> Option<std::net::IpAddr> {
    client_ip.trim().parse().ok()
}

/// Destination port for mesh authorization (`to.operation.ports` /
/// `when: destination.port`).
///
/// For materialized sidecar **inbound** routes the authorized port depends on
/// which KIND of inbound route matched:
///
///   * **Service-port default inbound** (`__mesh-inbound-*`): the request is
///     delivered to the local app at the route's backend (workload/container)
///     port, which is the port Istio inbound authz matches on — so authorize on
///     `proxy.backend_port`.
///   * **Sidecar `ingress[]` custom listener** (`__mesh-ingress-*`, F6 §6.2):
///     the listener declares a port (e.g. `8443`) and forwards to a SEPARATE
///     `defaultEndpoint` backend port (e.g. `8080`). Istio scopes
///     `AuthorizationPolicy` `port` / `destination.port` to the **declared
///     listener port**, so authorize on `ingress_listener_authz_port` (stamped
///     by the request handler from port selection), NOT the backend port.
///     Authorizing on the backend port would let an ALLOW miss and — worse — a
///     DENY scoped to the listener port FAIL OPEN.
///
/// A host-routed inbound `Proxy` carries `listen_port == None`, so without this
/// the port would fall back to `frontend_listen_port` (the shared `:15006`
/// listener socket) and a port-scoped rule would never match.
///
/// For mesh **outbound** routes, `destination.port` is the captured original
/// destination port when present. Direct/non-Linux single-port routes fall
/// back to the router-stamped service port. They must never fall back to the
/// outbound capture listener port (`:15001`), because that makes port-scoped
/// ALLOWs over-deny and DENYs under-deny.
fn mesh_authz_destination_port(
    mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    matched_proxy: Option<&crate::config::types::Proxy>,
    ingress_listener_authz_port: Option<u16>,
    outbound_destination_authz_port: Option<u16>,
    orig_dst: Option<std::net::SocketAddr>,
    frontend_listen_port: Option<u16>,
) -> Option<u16> {
    if mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Outbound) {
        return orig_dst
            .map(|addr| addr.port())
            .or(outbound_destination_authz_port)
            .or_else(|| matched_proxy.and_then(|proxy| proxy.listen_port));
    }

    mesh_inbound_app_port(
        mesh_direction,
        matched_proxy.map(|proxy| (proxy.id.as_str(), proxy.backend_port)),
        ingress_listener_authz_port,
    )
    .or(frontend_listen_port)
    .or_else(|| matched_proxy.and_then(|proxy| proxy.listen_port))
}

fn mesh_authz_authorization_path(path: &str) -> String {
    crate::router_cache::normalize_encoded_slashes(path).into_owned()
}

/// The authorization destination port for a materialized sidecar inbound route,
/// when the matched route is one — else `None` so the caller falls back to the
/// listener-port derivation. For a Sidecar `ingress[]` route it is the declared
/// LISTENER port (`ingress_listener_authz_port`); for a service-port default
/// inbound route it is the route's backend (container) port. Pure over its
/// inputs for testability.
fn mesh_inbound_app_port(
    mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    matched: Option<(&str, u16)>,
    ingress_listener_authz_port: Option<u16>,
) -> Option<u16> {
    if mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Inbound)
        && let Some((id, backend_port)) = matched
        && crate::modes::mesh::is_mesh_inbound_route_id(id)
    {
        // Ingress listener routes authorize on the DECLARED listener port, not
        // the `defaultEndpoint` backend port the route forwards to (F6 §6.2
        // security). The handler stamps the listener port for ingress routes;
        // if it is somehow absent for an ingress id, fail closed by keeping the
        // backend port out of the authz decision (return `None` → fall back to
        // the listener-socket port) rather than authorizing on the wrong port.
        if crate::modes::mesh::is_mesh_ingress_route_id(id) {
            return ingress_listener_authz_port;
        }
        return Some(backend_port);
    }
    None
}

fn jwt_attribute_to_mesh_attribute(value: &JwtAuthAttributeValue) -> MeshAuthzAttribute {
    match value {
        JwtAuthAttributeValue::Scalar(value) => MeshAuthzAttribute::Scalar(value.clone()),
        JwtAuthAttributeValue::StringList(values) => MeshAuthzAttribute::StringList(values.clone()),
    }
}

fn jwt_scalar_attribute_to_mesh_attribute(
    value: &JwtAuthAttributeValue,
) -> Option<MeshAuthzAttribute> {
    match value {
        JwtAuthAttributeValue::Scalar(value) => Some(MeshAuthzAttribute::Scalar(value.clone())),
        JwtAuthAttributeValue::StringList(_) => None,
    }
}

/// Matching rule for the [`MeshAuthz::trusted_hbone_assertors`] allow-list.
///
/// Operators may supply either a bare service-account name (the Istio default
/// for ztunnel and waypoints), or a full SPIFFE ID to pin a specific
/// assertor identity, trust domain, and namespace.
#[derive(Debug, Clone)]
pub(crate) enum TrustedAssertor {
    /// Match any peer whose SPIFFE-ID path encodes this Kubernetes service
    /// account per the Istio convention `ns/<ns>/sa/<sa>`.
    ServiceAccount(String),
    /// Match a specific SPIFFE-ID exactly.
    Spiffe(SpiffeId),
}

impl TrustedAssertor {
    fn matches(&self, peer: &SpiffeId) -> bool {
        match self {
            Self::ServiceAccount(name) => peer.service_account() == Some(name.as_str()),
            Self::Spiffe(id) => id == peer,
        }
    }
}

/// Default trusted-assertor allow-list used when the plugin config does not
/// supply one. Matches Istio ambient's `ztunnel` and `waypoint` service
/// accounts. Operators with custom waypoint SA names (Gateway-managed
/// waypoints often use `<gateway-name>` or `<gateway-name>-istio`) must
/// override this list to add their names.
const DEFAULT_TRUSTED_HBONE_ASSERTOR_SA_NAMES: &[&str] = &["ztunnel", "waypoint"];

fn ambient_udp_source_scope_index(
    slice: &MeshSlice,
) -> HashMap<[u8; 16], crate::modes::mesh::runtime::PolicyScopeCache> {
    let mut scopes = HashMap::new();
    let mut ambiguous = HashSet::new();
    for workload in &slice.ambient_udp_source_workloads {
        let Some(raw_uid) = workload.pod_uid.as_deref() else {
            continue;
        };
        let Ok(uid) = crate::modes::mesh::node_waypoint::parse_pod_uid(raw_uid) else {
            continue;
        };
        if ambiguous.contains(&uid) {
            continue;
        }
        let candidate = crate::modes::mesh::runtime::PolicyScopeCache::from_workload(workload);
        match scopes.entry(uid) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(entry) if entry.get() == &candidate => {
                // Kubernetes may project one pod through multiple Services.
                // Identical attestations are one scope, not an ambiguity.
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                entry.remove();
                ambiguous.insert(uid);
            }
        }
    }
    scopes
}

fn normalize_authz_policies(policies: &mut [MeshPolicy]) {
    for policy in policies {
        normalize_mesh_policy_header_names(policy);
        for rule in &mut policy.rules {
            for request in &mut rule.to {
                for host in &mut request.hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for host in &mut request.not_hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
            }
        }
    }
}

impl MeshAuthz {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Whether the policies arrived via a `mesh_slice` (the slice-apply path
        // builds this — see `inject_mesh_authz_plugin`) vs. a flat
        // `mesh_policies` operator config with no slice context. This selects
        // how `validate_scope_filter_identity` treats a workload-selector policy
        // whose labels cannot be resolved against the proxy: the slice path
        // computed authoritative (possibly empty/ambiguous) labels and a
        // downstream consumer may re-filter, so it tolerates; a flat operator
        // config has no such recovery and must fail closed instead of silently
        // dropping the policy (which `evaluate_mesh_authorization_policies`
        // would then treat as allow-by-default).
        let from_slice = config.get("mesh_slice").is_some();
        let mut slice = if let Some(value) = config.get("mesh_slice") {
            serde_json::from_value::<MeshSlice>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid mesh_slice: {e}"))?
        } else if let Some(value) = config.get("mesh_policies") {
            let mesh_policies = serde_json::from_value::<Vec<MeshPolicy>>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid mesh_policies: {e}"))?;
            MeshSlice {
                mesh_policies,
                ..MeshSlice::default()
            }
        } else {
            MeshSlice::default()
        };
        let trust_domain_aliases = parse_trust_domain_aliases(config)?;
        let trusted_hbone_assertors = parse_trusted_hbone_assertors(config)?;

        // Allow explicit identity overrides on top of the slice-embedded
        // namespace/labels — useful when `mesh_policies` is supplied directly
        // (no slice context) or to override what the slice carried. These
        // fields drive the construction-time scope filter below; when
        // `per_pod_policy_scoping` is true (node-waypoint topology) the
        // filter is skipped and these writes are unused, but the parsing
        // still runs so the on-disk config shape is identical across
        // topologies and validation errors (bad type / malformed labels)
        // surface uniformly.
        if let Some(value) = config.get("namespace") {
            let namespace = value
                .as_str()
                .ok_or_else(|| "mesh_authz: namespace must be a string".to_string())?;
            slice.namespace = namespace.to_string();
        }
        if let Some(value) = config.get("labels") {
            let labels = serde_json::from_value::<BTreeMap<String, String>>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid labels: {e}"))?;
            slice.labels = labels;
            // An explicit `labels` override is the DP resolving its AUTHORITATIVE
            // identity (the documented way to pin a workload's labels — see
            // docs/mesh.md "The marker is cleared on the recovered slice once the
            // DP has resolved its authoritative labels"). Once provided, the
            // shared-SPIFFE `labels_ambiguous` intersection marker is stale: these
            // labels — not the slice's partial intersection — are this workload's
            // real set, so the cold-path `retain` can narrow the candidate-any
            // superset deterministically. Leaving the marker set would make the
            // ambiguous fail-closed branches in `validate_scope_filter_identity`
            // reject an otherwise-valid workload whose authoritative labels simply
            // do not match a candidate-only selector policy carried in the superset
            // (e.g. override `role=worker` while the slice also carried a
            // `role=api` policy). Clear it so the override governs scoping.
            slice.labels_ambiguous = false;
        }

        validate_policy_ip_inputs(&slice.mesh_policies)?;

        let per_pod_policy_scoping = config
            .get("per_pod_policy_scoping")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ambient_udp_source_scoping = config
            .get("ambient_udp_source_scoping")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut relay_policy_superset = if ambient_udp_source_scoping {
            slice.mesh_policies.clone()
        } else {
            Vec::new()
        };
        let ambient_udp_source_scopes = if ambient_udp_source_scoping {
            ambient_udp_source_scope_index(&slice)
        } else {
            HashMap::new()
        };

        if !per_pod_policy_scoping {
            validate_scope_filter_identity(&slice, from_slice)?;

            // Pre-filter the slice's mesh_policies down to those whose `scope`
            // applies to this proxy's workload identity. Done once at
            // construction (cold path); the request hot path then iterates a
            // smaller list. Skipped in node-waypoint mode because one listener
            // serves many pods — filtering happens per request using the
            // pod-scoped cache set on RequestContext.
            let proxy_namespace = slice.namespace.clone();
            let proxy_labels = slice.labels.clone();
            slice.mesh_policies.retain(|policy| {
                policy_scope_applies_to_workload(policy, &proxy_namespace, &proxy_labels)
            });
        }

        normalize_authz_policies(&mut slice.mesh_policies);
        normalize_authz_policies(&mut relay_policy_superset);
        let has_header_rules = mesh_policies_have_header_rules(&slice.mesh_policies);
        let condition_keys = ConditionAttributeKeys::from_policies(&slice.mesh_policies);
        let relay_policy_superset_has_header_rules =
            mesh_policies_have_header_rules(&relay_policy_superset);
        let relay_policy_superset_condition_keys =
            ConditionAttributeKeys::from_policies(&relay_policy_superset);
        // Whether any namespace/selector-scoped (non-mesh-wide) policy is loaded.
        // The stream path fails closed on a missing per-pod scope only when such
        // policies exist; otherwise mesh-wide-only evaluation is complete.
        let has_scoped_policies = per_pod_policy_scoping
            && slice.mesh_policies.iter().any(|policy| {
                // Only ENFORCING scoped policies justify failing closed on a
                // missing per-pod scope. A scoped `Audit` rule only records
                // `mesh_authz.audit_policy` and returns `Continue`, so an
                // audit-only scoped policy must not 403 the request — let it
                // fall through like any other non-enforcing case. Istio
                // empty-rule ALLOW (allow-nothing) is translated to a
                // never-matching `Allow` rule, so it is still counted here.
                !matches!(policy.scope, PolicyScope::MeshWide)
                    && policy
                        .rules
                        .iter()
                        .any(|rule| matches!(rule.action, PolicyAction::Allow | PolicyAction::Deny))
            });
        let service_waypoint_destination_scope_required =
            ambient_udp_source_scoping && slice.waypoint_name.is_some();
        let mut has_route_upstream_metadata = false;
        let destination_policy_scope_index =
            if per_pod_policy_scoping || service_waypoint_destination_scope_required {
                let cluster_domains = normalized_cluster_domains(config);
                let route_upstreams = if per_pod_policy_scoping {
                    let (route_metadata_present, route_upstreams) =
                        parse_node_waypoint_route_upstreams(config)?;
                    has_route_upstream_metadata = route_metadata_present;
                    route_upstreams
                } else {
                    Vec::new()
                };
                destination_policy_scope_index(&slice, &cluster_domains, &route_upstreams)
            } else {
                DestinationPolicyScopeIndex::default()
            };
        Ok(Self {
            slice,
            relay_policy_superset,
            ambient_udp_source_scopes,
            ambient_udp_source_scoping,
            service_waypoint_destination_scope_required,
            destination_policy_scopes_by_upstream: destination_policy_scope_index.by_upstream,
            destination_policy_scopes_by_backend: destination_policy_scope_index.by_backend,
            destination_policy_scopes_by_namespaced_backend: destination_policy_scope_index
                .by_namespaced_backend,
            destination_backend_aliases_by_backend: destination_policy_scope_index
                .backend_aliases_by_backend,
            destination_backend_aliases_by_namespaced_backend: destination_policy_scope_index
                .backend_aliases_by_namespaced_backend,
            destination_same_namespace_backend_alias_by_backend: destination_policy_scope_index
                .same_namespace_backend_alias_by_backend,
            destination_service_backend_hosts: destination_policy_scope_index.service_backend_hosts,
            destination_namespaced_service_backend_hosts: destination_policy_scope_index
                .namespaced_service_backend_hosts,
            destination_route_upstreams_requiring_scope: destination_policy_scope_index
                .route_upstreams_requiring_scope,
            has_route_upstream_metadata,
            has_header_rules,
            relay_policy_superset_has_header_rules,
            trust_domain_aliases,
            trusted_hbone_assertors,
            per_pod_policy_scoping,
            has_scoped_policies,
            condition_keys,
            relay_policy_superset_condition_keys,
            udp_principal_pod_mismatch_warn_last_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Emit a rate-limited (one per ~30s) structured warning when an Ambient
    /// UDP CONNECT's asserted `source.pod_uid` is present in the slice scope
    /// index but the honored `source.principal` does not byte-match the CP's
    /// `Workload.spiffe_id` for that pod. This is the observable signal for the
    /// otherwise-silent cross-component derivation divergence between the
    /// node-agent's published SPIFFE (`spiffe://<trust_domain>/ns/<ns>/sa/<sa>`,
    /// `node_agent.rs`) and the CP-derived slice identity: when they diverge,
    /// per-pod scoping fails closed to mesh-wide with no other trace. The
    /// fail-closed fallback itself is unchanged; this only makes it visible.
    fn warn_udp_principal_pod_mismatch(&self, asserted: Option<&str>, expected: &str) {
        use std::sync::atomic::Ordering;
        // ~30s window: divergence is a configuration/derivation fault, not a
        // per-request condition, so one line per window per proxy is enough to
        // surface it without pegging the log pipeline under a UDP flood.
        const WINDOW_MS: u64 = 30_000;
        let now = crate::socket_opts::monotonic_now_ms();
        let last = self
            .udp_principal_pod_mismatch_warn_last_ms
            .load(Ordering::Relaxed);
        // Emit on the first event (`last == 0`) or after a full window. A single
        // CAS claims the window; losers stay silent. `saturating_sub` guards a
        // coarse clock that does not advance between calls.
        if last != 0 && now.saturating_sub(last) < WINDOW_MS {
            return;
        }
        if self
            .udp_principal_pod_mismatch_warn_last_ms
            .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        tracing::warn!(
            asserted_source_principal = asserted.unwrap_or("<none>"),
            expected_slice_spiffe_id = %expected,
            "mesh_authz: Ambient UDP source pod UID matched the slice but its asserted \
             source.principal does not byte-match the CP-derived Workload.spiffe_id; per-pod \
             UDP policy scoping is degrading to mesh-wide for this workload. Verify the \
             node-agent FERRUM_MESH_TRUST_DOMAIN and service-account SPIFFE derivation match \
             the control plane's Workload identity"
        );
    }

    /// Build the Istio `when:` attribute map for an HTTP-family request,
    /// materializing only the keys referenced by some loaded policy (see
    /// [`ConditionAttributeKeys`]). Returns an empty map when no policy uses
    /// `when:` conditions so the no-condition hot path allocates nothing
    /// beyond the empty `BTreeMap` the request already needs.
    ///
    /// `source_principal` is the resolved authz principal (post-baggage
    /// rewrite) so `source.principal` / `source.namespace` reflect the
    /// identity the rule is actually evaluated against. `headers` are the
    /// already-lowercased request headers built by the caller when header
    /// rules exist; conditions on `request.headers[...]` reuse that map.
    fn build_http_condition_attributes(
        &self,
        keys: &ConditionAttributeKeys,
        ctx: &RequestContext,
        source_principal: Option<&SpiffeId>,
        port: Option<u16>,
        source_ips: (Option<std::net::IpAddr>, Option<std::net::IpAddr>),
        headers: &BTreeMap<String, String>,
    ) -> BTreeMap<String, MeshAuthzAttribute> {
        let mut attributes = BTreeMap::new();
        if !keys.any {
            return attributes;
        }
        let (source_ip, remote_ip) = source_ips;
        if keys.source_principal
            && let Some(principal) = source_principal
        {
            attributes.insert(
                ATTR_SOURCE_PRINCIPAL.to_string(),
                istio_source_principal(principal).to_string().into(),
            );
        }
        if keys.source_namespace
            && let Some(namespace) = source_principal.and_then(|principal| principal.namespace())
        {
            attributes.insert(
                ATTR_SOURCE_NAMESPACE.to_string(),
                namespace.to_string().into(),
            );
        }
        if keys.request_auth_principal
            && let Some(principal) = ctx.metadata.get("mesh.request_principal")
        {
            attributes.insert(
                ATTR_REQUEST_AUTH_PRINCIPAL.to_string(),
                principal.clone().into(),
            );
        }
        if keys.request_auth_presenter
            && let Some(presenter) = ctx.mesh_request_auth_claims.get("azp")
            && let Some(presenter) = jwt_scalar_attribute_to_mesh_attribute(presenter)
        {
            attributes.insert(ATTR_REQUEST_AUTH_PRESENTER.to_string(), presenter);
        }
        if keys.request_auth_audiences && !ctx.mesh_request_auth_audiences.is_empty() {
            attributes.insert(
                ATTR_REQUEST_AUTH_AUDIENCES.to_string(),
                MeshAuthzAttribute::StringList(ctx.mesh_request_auth_audiences.clone()),
            );
        }
        if keys.destination_port
            && let Some(port) = port
        {
            attributes.insert(ATTR_DESTINATION_PORT.to_string(), port.to_string().into());
        }
        if keys.connection_sni
            && let Some(sni) = ctx.frontend_sni_hostname.as_ref()
        {
            attributes.insert(ATTR_CONNECTION_SNI.to_string(), sni.clone().into());
        }
        // `source.ip` / `remote.ip` as string `when:` attributes. `source.ip`
        // is the direct downstream peer, while `remote.ip` is the trusted
        // forwarded/original client IP when one was resolved.
        if keys.source_ip
            && let Some(ip) = source_ip
        {
            attributes.insert(ATTR_SOURCE_IP.to_string(), ip.to_string().into());
        }
        if keys.remote_ip
            && let Some(ip) = remote_ip
        {
            attributes.insert(ATTR_REMOTE_IP.to_string(), ip.to_string().into());
        }
        for header_key in &keys.header_keys {
            if let Some(name) = bracketed_attribute_name(header_key, ATTR_REQUEST_HEADERS_PREFIX)
                && let Some(value) = http_header_attribute(ctx, headers, name)
            {
                attributes.insert(header_key.clone(), value.into());
            }
        }
        for claim_key in &keys.claim_keys {
            if let Some(name) = bracketed_attribute_name(claim_key, ATTR_REQUEST_AUTH_CLAIMS_PREFIX)
                && let Some(value) = ctx.mesh_request_auth_claims.get(name)
            {
                attributes.insert(claim_key.clone(), jwt_attribute_to_mesh_attribute(value));
            }
        }
        attributes
    }

    /// Build the Istio `when:` attribute map for a stream (TCP/UDP)
    /// connection. Only source identity, destination port, connection SNI,
    /// and IP attributes are available on a stream — HTTP headers and JWT
    /// claims are HTTP-only and are intentionally absent so a `when:`
    /// condition on them fails closed (Istio values-check requires presence).
    fn build_stream_condition_attributes(
        &self,
        ctx: &StreamConnectionContext,
        source_principal: Option<&SpiffeId>,
        source_ip: Option<std::net::IpAddr>,
        remote_ip: Option<std::net::IpAddr>,
    ) -> BTreeMap<String, MeshAuthzAttribute> {
        let mut attributes = BTreeMap::new();
        let keys = &self.condition_keys;
        if !keys.any {
            return attributes;
        }
        if keys.source_principal
            && let Some(principal) = source_principal
        {
            attributes.insert(
                ATTR_SOURCE_PRINCIPAL.to_string(),
                istio_source_principal(principal).to_string().into(),
            );
        }
        if keys.source_namespace
            && let Some(namespace) = source_principal.and_then(|principal| principal.namespace())
        {
            attributes.insert(
                ATTR_SOURCE_NAMESPACE.to_string(),
                namespace.to_string().into(),
            );
        }
        if keys.destination_port {
            attributes.insert(
                ATTR_DESTINATION_PORT.to_string(),
                ctx.listen_port.to_string().into(),
            );
        }
        if keys.connection_sni
            && let Some(sni) = ctx.sni_hostname.as_ref()
        {
            attributes.insert(ATTR_CONNECTION_SNI.to_string(), sni.clone().into());
        }
        // `source.ip` is the immediate downstream socket peer before any
        // PROXY-protocol rewriting; `remote.ip` is the resolved/forwarded
        // client IP after inbound PROXY protocol is applied.  These mirror
        // the HTTP-path split in `build_condition_attributes`.
        if keys.source_ip
            && let Some(ip) = source_ip
        {
            attributes.insert(ATTR_SOURCE_IP.to_string(), ip.to_string().into());
        }
        if keys.remote_ip
            && let Some(ip) = remote_ip
        {
            attributes.insert(ATTR_REMOTE_IP.to_string(), ip.to_string().into());
        }
        attributes
    }

    /// Predicate used by [`MeshAuthz::authorize`] /
    /// [`MeshAuthz::on_stream_connect`] to decide whether a configured policy
    /// applies to the request's source pod when per-pod policy scoping is
    /// enabled.
    ///
    /// With a resolved scope, only the policies that scope matches apply. A
    /// `None` scope reaches this predicate ONLY after the caller has already
    /// decided not to fail closed — i.e. no namespace/selector-scoped policies
    /// are configured (a mesh-wide-only mesh) — so it keeps just the mesh-wide
    /// policies. When scoped policies DO exist, a missing scope means the pod's
    /// workload left the live slice generation (not an enrollment race) and the
    /// caller rejects (403) before reaching here; see [`MeshAuthz::authorize`].
    fn policy_applies_to_pod(
        policy: &MeshPolicy,
        scope: Option<&crate::modes::mesh::runtime::PolicyScopeCache>,
    ) -> bool {
        match scope {
            Some(scope) => scope.policy_applies(policy),
            None => matches!(policy.scope, PolicyScope::MeshWide),
        }
    }

    fn destination_scope_match_for_proxy(
        &self,
        proxy: &Proxy,
    ) -> Option<DestinationScopeMatch<'_>> {
        if let Some(upstream_id) = proxy.upstream_id.as_deref() {
            if let Some(scopes) = self.destination_policy_scopes_by_upstream.get(upstream_id) {
                return Some(DestinationScopeMatch {
                    authorized_destination: NodeWaypointAuthorizedDestination::Upstream(
                        upstream_id.to_string(),
                    ),
                    scopes,
                });
            }
            return None;
        }
        let backend_key = DestinationBackendKey::new(&proxy.backend_host, proxy.backend_port)?;
        if let Some(scopes) = self.destination_policy_scopes_by_backend.get(&backend_key) {
            let mut aliases = self
                .destination_backend_aliases_by_backend
                .get(&backend_key)
                .cloned()
                .unwrap_or_else(|| vec![backend_key.clone()]);
            if let Some(namespaced_backend_key) = NamespacedDestinationBackendKey::new(
                &proxy.namespace,
                &backend_key.host,
                backend_key.port,
            ) && let Some(short_alias) = self
                .destination_same_namespace_backend_alias_by_backend
                .get(&namespaced_backend_key)
                && !aliases.contains(short_alias)
            {
                aliases.push(short_alias.clone());
            }
            return Some(DestinationScopeMatch {
                authorized_destination: NodeWaypointAuthorizedDestination::Backend {
                    key: backend_key,
                    aliases,
                },
                scopes,
            });
        }
        let namespaced_backend_key = NamespacedDestinationBackendKey::new(
            &proxy.namespace,
            &proxy.backend_host,
            proxy.backend_port,
        )?;
        self.destination_policy_scopes_by_namespaced_backend
            .get(&namespaced_backend_key)
            .map(|scopes| DestinationScopeMatch {
                authorized_destination: NodeWaypointAuthorizedDestination::Backend {
                    key: namespaced_backend_key.backend_key(),
                    aliases: self
                        .destination_backend_aliases_by_namespaced_backend
                        .get(&namespaced_backend_key)
                        .cloned()
                        .unwrap_or_else(|| vec![namespaced_backend_key.backend_key()]),
                },
                scopes,
            })
    }

    fn proxy_requires_destination_scope(&self, proxy: &Proxy) -> bool {
        if let Some(upstream_id) = proxy.upstream_id.as_deref() {
            if upstream_id.starts_with("__mesh-out-upstream-") {
                return true;
            }
            if node_waypoint_generated_route_upstream_id(upstream_id) {
                return !self.has_route_upstream_metadata
                    || self
                        .destination_route_upstreams_requiring_scope
                        .contains(upstream_id);
            }
            return false;
        }
        if DestinationBackendKey::new(&proxy.backend_host, proxy.backend_port)
            .is_some_and(|key| self.destination_service_backend_hosts.contains(&key.host))
        {
            return true;
        }
        NamespacedDestinationBackendHostKey::new(&proxy.namespace, &proxy.backend_host).is_some_and(
            |key| {
                self.destination_namespaced_service_backend_hosts
                    .contains(&key)
            },
        )
    }

    fn decision_to_result(
        &self,
        decision: MeshAuthzDecision,
        metadata: &mut HashMap<String, String>,
    ) -> PluginResult {
        match decision {
            MeshAuthzDecision::Allow => PluginResult::Continue,
            MeshAuthzDecision::Audit { policy } => {
                metadata.insert("mesh_authz.audit_policy".to_string(), policy);
                PluginResult::Continue
            }
            MeshAuthzDecision::Deny { policy } => {
                metadata.insert("mesh_authz.deny_policy".to_string(), policy);
                PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Mesh authorization denied"}"#.into(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    /// Push a deny record into the process-singleton policy-deny recorder
    /// consumed by `GET /mesh/policy-denies/recent`. Exception-path only —
    /// `mesh_authz` is called on every request, but this helper runs only
    /// when the decision was a reject. The recorder degrades to a cheap
    /// `Mutex::lock` + ring push; capacity `0` short-circuits inside the
    /// recorder so we don't hide a branch behind a feature flag here.
    fn record_policy_deny(
        &self,
        metadata: &HashMap<String, String>,
        source_principal: Option<&str>,
    ) {
        let rule = match metadata.get("mesh_authz.deny_policy") {
            Some(rule) => rule.clone(),
            // Defensive: if the deny metadata was stripped (custom plugin
            // chain) we still record under an unknown-rule bucket so the
            // operator can see the volume.
            None => "unknown".to_string(),
        };
        // Reason mirrors the rule name today because mesh_authz exposes only
        // the rule that fired. Keeping them as separate fields lets future
        // synthesised deny reasons (e.g. `trust_domain_mismatch`) round-trip
        // without forcing callers to munge `rule` strings. Today the
        // synthesised-reason rules already use the reason string as their
        // rule, so the two columns intentionally agree.
        policy_deny_log::record_global(PolicyDenyEvent {
            rule: rule.clone(),
            source: source_principal.map(str::to_string),
            destination: self.slice.workload_spiffe_id.clone(),
            reason: rule,
            at: Utc::now(),
        });
    }
}

/// Whether a policy carries at least one ENFORCING rule (`Allow` / `Deny`).
///
/// An `Audit`-only policy is non-enforcing per Istio semantics:
/// `evaluate_mesh_authorization_policies` records `mesh_authz.audit_policy`
/// metadata and returns `Continue`, so dropping an audit-only policy never
/// changes the allow/deny outcome (it is NOT the allow-by-default fail-open the
/// scope-resolution guards below protect against). The construction-time
/// fail-closed branches must therefore gate on this, exactly as the per-pod
/// missing-scope check in `MeshAuthz::new` (`has_scoped_policies`) already does
/// — an unscopable audit-only selector policy is skipped, not rejected.
fn policy_has_enforcing_rule(policy: &MeshPolicy) -> bool {
    policy
        .rules
        .iter()
        .any(|rule| matches!(rule.action, PolicyAction::Allow | PolicyAction::Deny))
}

fn validate_scope_filter_identity(slice: &MeshSlice, from_slice: bool) -> Result<(), String> {
    let has_proxy_namespace = !slice.namespace.trim().is_empty();
    let has_proxy_labels = !slice.labels.is_empty();

    for policy in &slice.mesh_policies {
        match &policy.scope {
            PolicyScope::MeshWide => {}
            PolicyScope::Namespace { .. } => {
                if !has_proxy_namespace {
                    return Err(format!(
                        "mesh_authz: policy '{}' uses namespace scope but no proxy namespace is configured; set mesh_slice.namespace or namespace",
                        policy.name
                    ));
                }
            }
            PolicyScope::WorkloadSelector { selector } => {
                if let Some(selector_namespace) = selector.namespace.as_ref() {
                    if !has_proxy_namespace {
                        return Err(format!(
                            "mesh_authz: policy '{}' uses workload selector namespace '{}' but no proxy namespace is configured; set mesh_slice.namespace or namespace",
                            policy.name, selector_namespace
                        ));
                    }
                    if selector_namespace != &slice.namespace {
                        continue;
                    }
                }

                if !selector.labels.is_empty() && !has_proxy_labels {
                    if !from_slice && policy_has_enforcing_rule(policy) {
                        // Operator-direct config (flat `mesh_policies`, no
                        // `mesh_slice` context): a workload-selector policy
                        // carries selector labels but the operator supplied no
                        // proxy `labels`, so the cold-path `retain` would drop
                        // it and `evaluate_mesh_authorization_policies` would
                        // then allow the request by default — a silent fail-open
                        // for a DENY/ALLOW the operator clearly intended to
                        // apply. There is no downstream consumer to recover the
                        // labels here (unlike the slice path), so fail closed at
                        // construction and make the operator supply the proxy's
                        // identity.
                        //
                        // Gated on an ENFORCING rule: an AUDIT-only operator
                        // selector policy is non-enforcing, so dropping it is a
                        // no-op, not a fail-open — it falls through to the
                        // warn-and-tolerate path below (the `!from_slice` audit
                        // exemption, consistent with the slice-path branches and
                        // the per-pod missing-scope `has_scoped_policies` check).
                        return Err(format!(
                            "mesh_authz: policy '{}' uses a workload selector with labels {:?} but \
                             no proxy labels are configured; set `labels` so the policy can be \
                             scoped to this workload",
                            policy.name, selector.labels
                        ));
                    }
                    // Slice-apply path with no resolved proxy labels.
                    if slice.labels_ambiguous && policy_has_enforcing_rule(policy) {
                        // The slice marked these labels as an ambiguous
                        // shared-SPIFFE intersection and shipped the selector
                        // policy as a candidate-any superset for a label-holding
                        // consumer to re-filter. Reaching mesh_authz `new()` with
                        // EMPTY `slice.labels` means that recovery already failed:
                        // the per-pod NodeWaypoint consumer skips this validation
                        // entirely (it re-filters per pod), so we are a
                        // Sidecar/Ambient/xDS DP whose labels are final, and the
                        // xDS reverse path only leaves `labels` empty when the DP
                        // also had no local `FERRUM_MESH_WORKLOAD_LABELS` to
                        // prefer. There is no further consumer; the cold-path
                        // `retain` would drop the policy and
                        // `evaluate_mesh_authorization_policies` would then allow
                        // by default — a silent fail-open for a selector DENY/ALLOW
                        // that demonstrably applies to a candidate workload. Fail
                        // closed and make the operator pin the proxy identity.
                        //
                        // Gated on an ENFORCING rule: an AUDIT-only selector policy
                        // is a non-enforcing no-op (it only records audit metadata
                        // and continues), so dropping it via the cold-path `retain`
                        // is NOT a fail-open — rejecting plugin construction for it
                        // would be a regression. It falls through to the
                        // warn-and-tolerate path below, mirroring the per-pod
                        // missing-scope `has_scoped_policies` audit exemption.
                        return Err(format!(
                            "mesh_authz: policy '{}' uses a workload selector with labels {:?} but \
                             the slice resolved no proxy labels for this ambiguous shared-SPIFFE \
                             workload; set mesh_slice.labels / FERRUM_MESH_WORKLOAD_LABELS so the \
                             policy can be scoped to this workload",
                            policy.name, selector.labels
                        ));
                    }
                    // Reached when the slice is NOT ambiguous (the slice is
                    // authoritative for THIS workload and a label-based selector
                    // simply does not apply — single-candidate or label-less
                    // workload), OR the slice IS ambiguous but the policy is
                    // AUDIT-only (non-enforcing — gated out of the fail-closed
                    // branch above). In both cases dropping the policy via the
                    // cold-path `retain` is correct, not a fail-open: a
                    // non-applicable authoritative selector or an audit-only no-op
                    // never opens an allow-by-default hole. Warn for visibility but
                    // tolerate construction (a hard error would reject the slice or
                    // drop authz entirely — issue #1708); set `mesh_slice.labels` /
                    // `FERRUM_MESH_WORKLOAD_LABELS` for deterministic selector
                    // scoping on Sidecar/Ambient.
                    //
                    // A current Ferrum CP cannot reach this branch with an
                    // ENFORCING genuinely-ambiguous slice: it sets
                    // `labels_ambiguous` on divergent shared-SPIFFE candidates
                    // (slice.rs), and the candidate-any projection only keeps a
                    // selector policy that matches SOME candidate — a single
                    // label-less candidate `{}` never matches a non-empty selector,
                    // so the policy is dropped at slice build and never rides in.
                    // The only way an unmarked empty-label slice carries an
                    // unsatisfiable enforcing selector policy is a cross-version
                    // slice from a CP predating the marker (serde defaults
                    // `labels_ambiguous = false`). Per the Build-Out Policy (no
                    // legacy shims for old wire/config shapes; CP and DP ship from
                    // one binary version), that case is out of scope and is not
                    // failed closed here — set the labels to pin identity.
                    tracing::warn!(
                        policy = %policy.name,
                        "mesh_authz: workload-selector policy has selector labels but the slice \
                         resolved no proxy labels for this workload; not enforced here — set \
                         mesh_slice.labels / FERRUM_MESH_WORKLOAD_LABELS for deterministic scoping"
                    );
                } else if slice.labels_ambiguous
                    && from_slice
                    && policy_has_enforcing_rule(policy)
                    && !workload_selector_matches(selector, &slice.namespace, &slice.labels)
                {
                    // Ambiguous shared-SPIFFE slice with a NON-EMPTY label
                    // intersection (e.g. candidates share `app=shared` but only
                    // one has `role=api`). `slice.labels` here is just that
                    // partial intersection, NOT this workload's authoritative
                    // labels, and the slice carried this candidate-only selector
                    // policy (`role=api`) as a superset. Because the selector is
                    // not satisfied by the partial intersection, the cold-path
                    // `retain` below would DROP it; if no other ALLOW remains
                    // `evaluate_mesh_authorization_policies` then allows by default
                    // — the non-empty-intersection fail-open. The marker reaching
                    // here unchanged (xDS preserves it when the DP had no local
                    // labels to make the intersection authoritative; native
                    // MeshSubscribe carries it verbatim) proves the labels are not
                    // final, so we cannot prove this DENY/ALLOW does not apply.
                    // Fail closed and make the operator pin the proxy identity so
                    // the candidate-any superset can be re-filtered deterministically.
                    //
                    // Gated on an ENFORCING rule: an AUDIT-only candidate-only
                    // selector policy is a non-enforcing no-op, so dropping it via
                    // the cold-path `retain` does not open an allow-by-default hole.
                    // Rejecting plugin construction for it would be a regression, so
                    // it is tolerated (the `retain` still drops it from evaluation),
                    // mirroring the per-pod missing-scope `has_scoped_policies` audit
                    // exemption.
                    return Err(format!(
                        "mesh_authz: policy '{}' uses a workload selector with labels {:?} that the \
                         ambiguous shared-SPIFFE slice's partial label intersection {:?} cannot \
                         resolve; set mesh_slice.labels / FERRUM_MESH_WORKLOAD_LABELS so the policy \
                         can be scoped to this workload",
                        policy.name, selector.labels, slice.labels
                    ));
                }
            }
        }
    }

    Ok(())
}

#[async_trait]
impl Plugin for MeshAuthz {
    fn name(&self) -> &str {
        "mesh_authz"
    }

    fn priority(&self) -> u16 {
        priority::MESH_AUTHZ
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let inbound_hbone_relay_request = ctx.mesh_direction
            == Some(crate::modes::mesh::MeshTrafficDirection::Inbound)
            && ctx.matched_proxy.as_ref().is_some_and(|proxy| {
                proxy.id == crate::modes::mesh::MESH_INBOUND_HBONE_RELAY_PROXY_ID
            });
        let ambient_udp_source_scope_request = self.ambient_udp_source_scoping
            && inbound_hbone_relay_request
            && ctx
                .metadata
                .get(crate::modes::mesh::hbone::HBONE_DATAGRAM_METADATA_KEY)
                .is_some_and(|value| value == "udp");
        let service_waypoint_destination_scope_request =
            self.service_waypoint_destination_scope_required && inbound_hbone_relay_request;
        let relay_policy_superset_request =
            ambient_udp_source_scope_request || service_waypoint_destination_scope_request;
        let unauthenticated_hbone_baggage = is_hbone_request(ctx)
            && has_baggage_header_from_request(ctx)
            && !is_authenticated_hbone_request(ctx);
        if unauthenticated_hbone_baggage {
            record_ignored_baggage_reason(&mut ctx.metadata, "unauthenticated_hbone");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.unauthenticated".to_string(),
                "true".to_string(),
            );
        }
        let (mut source_principal, baggage_outcome) = self.resolve_source_principal(ctx);
        let ambient_udp_source_scope =
            if ambient_udp_source_scope_request && baggage_outcome == BaggageOutcome::Honored {
                match self.ambient_udp_source_scope(ctx, source_principal.as_ref()) {
                    Ok(scope) => scope,
                    Err(reason) => {
                        ctx.metadata.insert(
                            IGNORED_UDP_SOURCE_SCOPE_METADATA.to_string(),
                            reason.to_string(),
                        );
                        // The asserted principal and pod UID are one evidence
                        // bundle. If the live slice cannot bind them exactly,
                        // discard both before mesh-wide evaluation and fall
                        // back to the authenticated attesting gateway SVID.
                        source_principal = ctx.peer_spiffe_id.clone();
                        None
                    }
                }
            } else {
                None
            };
        // Capture the final authz principal up front so the
        // /mesh/policy-denies/recent drilldown records the identity the rule
        // actually saw, including the HBONE baggage rewrite for trusted
        // assertors or the authenticated gateway fallback after invalid UDP
        // pod evidence. `source_principal` is moved into `MeshAuthzRequest`
        // below, so we own a separate `String` here.
        let source_for_log = source_principal.as_ref().map(|id| id.as_str().to_string());
        let trust_domain_mismatch = baggage_outcome == BaggageOutcome::TrustDomainMismatch;
        let untrusted_assertor = baggage_outcome == BaggageOutcome::UntrustedAssertor;
        if trust_domain_mismatch {
            record_ignored_baggage_reason(&mut ctx.metadata, "trust_domain_mismatch");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.trust_domain_mismatch".to_string(),
                "true".to_string(),
            );
        }
        if untrusted_assertor {
            record_ignored_baggage_reason(&mut ctx.metadata, "untrusted_assertor");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.untrusted_assertor".to_string(),
                "true".to_string(),
            );
        }
        let mut host = ctx
            .raw_header_get("host")
            .or_else(|| ctx.raw_header_get(":authority"))
            .map(str::to_string);
        let has_header_rules = if relay_policy_superset_request {
            self.relay_policy_superset_has_header_rules
        } else {
            self.has_header_rules
        };
        let headers = if has_header_rules {
            ctx.materialize_headers();
            if host.is_none() {
                host = ctx.headers.get("host").cloned();
            }
            ctx.headers
                .iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
                .collect()
        } else {
            if host.is_none() {
                host = ctx.headers.get("host").cloned();
            }
            BTreeMap::new()
        };
        let request_principal = ctx.metadata.get("mesh.request_principal").cloned();
        let port = mesh_authz_destination_port(
            ctx.mesh_direction,
            ctx.matched_proxy.as_deref(),
            ctx.mesh_inbound_listener_authz_port,
            ctx.mesh_outbound_destination_authz_port,
            ctx.orig_dst,
            ctx.frontend_listen_port,
        );
        // Istio source IP matchers. `source.ip` is the immediate downstream
        // socket peer captured before trusted-proxy rewriting; `remote.ip` is
        // the gateway-resolved client IP after XFF / real-IP resolution.
        let source_ip = parse_client_ip(&ctx.direct_client_ip);
        let remote_ip = parse_client_ip(&ctx.client_ip);
        // Istio `when:` attributes. Built from the resolved authz principal
        // (post-baggage rewrite) plus request metadata/headers, and only for
        // the keys some loaded policy references (`condition_keys`). Without
        // this, condition-gated DENY rules never fired and condition-gated
        // ALLOW rules never matched — a fail-open hole this closes.
        let condition_keys = if relay_policy_superset_request {
            &self.relay_policy_superset_condition_keys
        } else {
            &self.condition_keys
        };
        let attributes = self.build_http_condition_attributes(
            condition_keys,
            ctx,
            source_principal.as_ref(),
            port,
            (source_ip, remote_ip),
            &headers,
        );
        let request = MeshAuthzRequest {
            source_principal,
            request_principal,
            method: Some(ctx.method.clone()),
            path: Some(mesh_authz_authorization_path(&ctx.path)),
            host,
            port,
            headers,
            attributes,
            source_ip,
            remote_ip,
        };
        // GAP-2M.4: per-pod scoping for node-waypoint topology.
        //
        // When `per_pod_policy_scoping` is enabled, the construction-time
        // filter was skipped (`self.slice.mesh_policies` carries the full
        // unfiltered set). The source pod scope remains the fail-closed
        // liveness gate. For materialized NodeWaypoint HTTP Service egress, the
        // policy applicability filter must use the destination Service's backing
        // workload scopes (AuthorizationPolicy scopes select destination
        // workloads). Other per-pod paths keep source-pod filtering.
        //
        // Filtering is expressed as an iterator predicate so the hot path
        // never clones the full `MeshSlice` (which carries workloads,
        // services, destination_rules, etc. the authz engine never reads).
        let mut scope_missing = false;
        let mut authorized_destination = None;
        let decision = if relay_policy_superset_request {
            // Destination-aware inbound relay. ServiceWaypoint byte-stream and
            // UDP CONNECTs both resolve the exact destination workload scope;
            // plain Ambient enters this branch only for UDP source scoping.
            // Evaluate the UNION of:
            //
            //   1. DESTINATION-scoped policies. Plain Ambient uses
            //      `self.slice.mesh_policies`, retained at construction to the
            //      destination workload identity just like non-UDP inbound HBONE.
            //      ServiceWaypoint is different: `slice.namespace` is the
            //      WAYPOINT namespace, while the protected Service/backends may be
            //      elsewhere. For it, resolve the synthesized relay's exact
            //      CONNECT-authority backend through the precomputed destination
            //      scope index and test the full policy superset against those
            //      backing-workload scopes. Missing destination evidence fails
            //      closed; it never falls back to waypoint-namespace filtering.
            //
            //   2. for UDP only, the SOURCE-scoped policies applicable to the
            //      asserted source-pod scope from `relay_policy_superset` (the
            //      pre-retain full clone), or mesh-wide-only when the source
            //      evidence is absent/invalid. Byte-stream CONNECTs have no UDP
            //      source scope, so this arm contributes only mesh-wide policy.
            //      Absent/invalid source evidence therefore still fails closed to
            //      mesh-wide + destination policies (never broader than before).
            //
            // Both sets feed ONE `evaluate_mesh_authorization_policies` iterator so
            // the deny-first / "if any ALLOW is applicable at least one must match"
            // aggregation is computed once across the combined set. Combining two
            // separate decisions would break that aggregation (a destination-only
            // ALLOW plus a source-only ALLOW must not each independently deny).
            //
            // Dedup is predicate-only and allocation-free. Plain Ambient chains
            // the retained destination set with source-only entries from the full
            // superset. ServiceWaypoint filters the full superset once with
            // `destination_applies || source_applies`, so a policy applying to
            // both arms is yielded only once.
            let source_scope = ambient_udp_source_scope;
            if self.service_waypoint_destination_scope_required {
                let destination_scope_match = ctx
                    .matched_proxy
                    .as_ref()
                    .and_then(|proxy| self.destination_scope_match_for_proxy(proxy));
                let Some(destination_scope_match) = destination_scope_match else {
                    ctx.metadata.insert(
                        "mesh_authz.destination_scope_missing".to_string(),
                        "true".to_string(),
                    );
                    ctx.metadata.insert(
                        "mesh_authz.deny_policy".to_string(),
                        "destination_scope_missing".to_string(),
                    );
                    self.record_policy_deny(&ctx.metadata, source_for_log.as_deref());
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"Mesh authorization denied: missing destination policy scope"}"#
                            .into(),
                        headers: HashMap::new(),
                    };
                };
                // Authorization runs before `before_proxy`, where
                // `mesh_route_dispatch` may attempt to replace this relay's
                // destination. Stamp the exact destination that supplied the
                // scopes evaluated below; the route-dispatch guard then rejects
                // any different post-authz backend instead of letting either
                // relay handler dial a workload whose policies were never
                // evaluated.
                authorized_destination =
                    Some(destination_scope_match.authorized_destination.clone());
                let destination_scopes = destination_scope_match.scopes;
                evaluate_mesh_authorization_policies(
                    self.relay_policy_superset.iter().filter(|policy| {
                        let destination_applies = destination_scopes
                            .iter()
                            .any(|scope| scope.policy_applies(policy));
                        let source_applies = source_scope.map_or_else(
                            || matches!(policy.scope, PolicyScope::MeshWide),
                            |scope| scope.policy_applies(policy),
                        );
                        destination_applies || source_applies
                    }),
                    &request,
                )
            } else {
                evaluate_mesh_authorization_policies(
                    self.slice.mesh_policies.iter().chain(
                        self.relay_policy_superset.iter().filter(|policy| {
                            let source_applies = source_scope.map_or_else(
                                || matches!(policy.scope, PolicyScope::MeshWide),
                                |scope| scope.policy_applies(policy),
                            );
                            source_applies
                                && !policy_scope_applies_to_workload(
                                    policy,
                                    &self.slice.namespace,
                                    &self.slice.labels,
                                )
                        }),
                    ),
                    &request,
                )
            }
        } else if self.per_pod_policy_scoping {
            if self.has_scoped_policies {
                ctx.metadata.insert(
                    NODE_WAYPOINT_SCOPED_AUTHZ_ACTIVE_METADATA.to_string(),
                    "true".to_string(),
                );
            }
            let destination_scope_match = ctx
                .matched_proxy
                .as_ref()
                .and_then(|proxy| self.destination_scope_match_for_proxy(proxy));
            let can_use_destination_scope = ctx.node_waypoint_policy_scope.is_some()
                || can_use_inbound_relay_destination_scope_without_source_scope(
                    ctx,
                    baggage_outcome,
                );
            if can_use_destination_scope
                && let Some(destination_scope_match) = destination_scope_match
            {
                authorized_destination = Some(destination_scope_match.authorized_destination);
                evaluate_destination_policy_scopes(
                    &self.slice.mesh_policies,
                    destination_scope_match.scopes,
                    &request,
                )
            } else {
                scope_missing = ctx.node_waypoint_policy_scope.is_none();
                // Fail closed when scoped policies exist and this request's pod has
                // no current scope — matching the stream path (`on_stream_connect`).
                // The resolver derives a pod's scope from the SAME slice generation
                // that vouches its identity, and the accepting connection holds the
                // identity `Arc` (which the idle sweep's strong_count guard keeps
                // enrolled), so a missing scope here is NOT an enrollment race: it
                // means the workload's hash has left the live slice gate (the pod was
                // removed or re-keyed). A long-lived HTTP/2/HBONE connection from a
                // removed workload must therefore stop being served under scoped
                // authz rather than silently dropping to mesh-wide-only — the same
                // per-request gate the stream path enforces at accept. A mesh with
                // only mesh-wide policies stays fully evaluable and falls through.
                //
                // The exception above is the synthesized inbound HBONE relay with an
                // honored trusted source assertion: that destination-side request has
                // no captured source-pod scope, but authz can evaluate destination
                // policies against the asserted source workload. Source-side
                // HBONE-shaped traffic, untrusted relay baggage, and missing baggage
                // keep the existing removed-workload fail-closed behavior.
                if scope_missing && self.has_scoped_policies {
                    ctx.metadata
                        .insert("mesh_authz.scope_missing".to_string(), "true".to_string());
                    ctx.metadata.insert(
                        "mesh_authz.deny_policy".to_string(),
                        "scope_missing".to_string(),
                    );
                    self.record_policy_deny(&ctx.metadata, source_for_log.as_deref());
                    return PluginResult::Reject {
                        status_code: 403,
                        body:
                            r#"{"error":"Mesh authorization denied: missing per-pod policy scope"}"#
                                .into(),
                        headers: HashMap::new(),
                    };
                }
                if self.has_scoped_policies
                    && ctx
                        .matched_proxy
                        .as_ref()
                        .is_some_and(|proxy| self.proxy_requires_destination_scope(proxy))
                {
                    ctx.metadata.insert(
                        "mesh_authz.destination_scope_missing".to_string(),
                        "true".to_string(),
                    );
                    ctx.metadata.insert(
                        "mesh_authz.deny_policy".to_string(),
                        "destination_scope_missing".to_string(),
                    );
                    self.record_policy_deny(&ctx.metadata, source_for_log.as_deref());
                    return PluginResult::Reject {
                        status_code: 403,
                        body:
                            r#"{"error":"Mesh authorization denied: missing destination policy scope"}"#
                                .into(),
                        headers: HashMap::new(),
                    };
                }
                let scope = ctx.node_waypoint_policy_scope.as_deref();
                let policies = self
                    .slice
                    .mesh_policies
                    .iter()
                    .filter(|policy| Self::policy_applies_to_pod(policy, scope));
                evaluate_mesh_authorization_policies(policies, &request)
            }
        } else {
            evaluate_mesh_authorization(&self.slice, &request)
        };
        // Remaining scope-missing cases reach here only when no scoped policies
        // are configured (the mesh is fully evaluable mesh-wide), so surface the
        // fall-through for operator visibility. The fail-closed removed-workload
        // case returns above. Only emitted when per_pod_policy_scoping is on.
        if scope_missing {
            ctx.metadata
                .insert("mesh_authz.scope_missing".to_string(), "true".to_string());
        }
        let result = self.decision_to_result(decision, &mut ctx.metadata);
        // NodeWaypoint stamps destinations when scoped policy filtering is
        // active. ServiceWaypoint byte-stream and UDP relays must stamp as well:
        // their exact backend supplied the destination scopes above even though
        // per-pod scoping is disabled for that topology. In both cases, route
        // dispatch must remain bound to the destination whose policies were
        // authorized.
        if (self.has_scoped_policies || self.service_waypoint_destination_scope_required)
            && matches!(result, PluginResult::Continue)
            && let Some(destination) = authorized_destination
        {
            match destination {
                NodeWaypointAuthorizedDestination::Upstream(upstream_id) => {
                    ctx.metadata.insert(
                        NODE_WAYPOINT_AUTHORIZED_UPSTREAM_ID_METADATA.to_string(),
                        upstream_id,
                    );
                }
                NodeWaypointAuthorizedDestination::Backend { key, aliases } => {
                    ctx.metadata.insert(
                        NODE_WAYPOINT_AUTHORIZED_BACKEND_METADATA.to_string(),
                        key.metadata_value(),
                    );
                    if !aliases.is_empty() {
                        ctx.metadata.insert(
                            NODE_WAYPOINT_AUTHORIZED_BACKEND_ALIASES_METADATA.to_string(),
                            aliases
                                .iter()
                                .map(DestinationBackendKey::metadata_value)
                                .collect::<Vec<_>>()
                                .join(","),
                        );
                    }
                }
            }
        }
        if matches!(
            result,
            PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
        ) {
            if unauthenticated_hbone_baggage {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "unauthenticated_baggage".to_string(),
                );
            } else if trust_domain_mismatch {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "trust_domain_mismatch".to_string(),
                );
            } else if untrusted_assertor {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "untrusted_assertor".to_string(),
                );
            }
            // `source_for_log` was captured from the resolved authz
            // principal above (post-baggage-rewrite), so HBONE flows from
            // trusted assertors record the workload identity that authz
            // evaluated, not the ztunnel/waypoint peer cert. The
            // synthesised-deny branches (untrusted_assertor /
            // trust_domain_mismatch / unauthenticated_baggage) carry the
            // peer cert identity or `None`, matching the authz request.
            self.record_policy_deny(&ctx.metadata, source_for_log.as_deref());
        }
        result
    }

    fn is_authorize_plugin(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let mut metadata = ctx.metadata.clone().unwrap_or_default();
        let source_principal = metadata
            .get("peer_spiffe_id")
            .and_then(|value| SpiffeId::new(value).ok())
            .or_else(|| {
                ctx.authenticated_identity
                    .as_deref()
                    .and_then(|value| SpiffeId::new(value).ok())
            });
        let source_for_log = source_principal.as_ref().map(|id| id.as_str().to_string());
        // Istio `when:` attributes for stream (TCP/UDP) connections. No HTTP
        // headers or JWT here, but source identity, destination port,
        // connection SNI, and source/remote IP are all available.
        //
        // Istio source IP matchers. `source.ip` is the immediate downstream
        // socket peer captured at accept() before any PROXY-protocol rewriting
        // (`direct_client_ip`); `remote.ip` is the resolved client IP after
        // inbound PROXY protocol is applied (`client_ip`). When PROXY protocol
        // is not enabled these two are the same socket-peer value, matching
        // Envoy's un-fronted raw-TCP behavior. This mirrors the HTTP-path split
        // at `on_request_received` where `direct_client_ip` and `client_ip` are
        // similarly separated via XFF / real-IP resolution.
        let source_ip = parse_client_ip(&ctx.direct_client_ip);
        let remote_ip = parse_client_ip(&ctx.client_ip);
        let attributes = self.build_stream_condition_attributes(
            ctx,
            source_principal.as_ref(),
            source_ip,
            remote_ip,
        );
        let request = MeshAuthzRequest {
            source_principal,
            port: Some(ctx.listen_port),
            attributes,
            source_ip,
            remote_ip,
            ..MeshAuthzRequest::default()
        };
        let decision = if self.per_pod_policy_scoping {
            let scope = ctx.node_waypoint_policy_scope.as_deref();
            if scope.is_none() {
                metadata.insert("mesh_authz.scope_missing".to_string(), "true".to_string());
                // Fail closed ONLY when namespace/selector-scoped policies exist:
                // without the per-pod scope we cannot prove they don't apply, so
                // rejecting is the safe default. A mesh with only mesh-wide
                // policies is fully evaluable, so fall through to mesh-wide-only
                // evaluation (matching the HTTP path) instead of rejecting all
                // stream traffic. `Reject` is the variant the stream accept loops
                // honor; `RejectBinary` would be silently dropped by them.
                if self.has_scoped_policies {
                    metadata.insert(
                        "mesh_authz.deny_policy".to_string(),
                        "scope_missing".to_string(),
                    );
                    self.record_policy_deny(&metadata, source_for_log.as_deref());
                    ctx.metadata = (!metadata.is_empty()).then_some(metadata);
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"stream denied: missing per-pod policy scope"}"#.into(),
                        headers: HashMap::new(),
                    };
                }
            }
            let policies = self
                .slice
                .mesh_policies
                .iter()
                .filter(|policy| Self::policy_applies_to_pod(policy, scope));
            evaluate_mesh_authorization_policies(policies, &request)
        } else {
            evaluate_mesh_authorization(&self.slice, &request)
        };
        let result = self.decision_to_result(decision, &mut metadata);
        if matches!(
            result,
            PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
        ) {
            self.record_policy_deny(&metadata, source_for_log.as_deref());
        }
        ctx.metadata = (!metadata.is_empty()).then_some(metadata);
        result
    }
}

impl MeshAuthz {
    fn ambient_udp_source_scope(
        &self,
        ctx: &RequestContext,
        source_principal: Option<&SpiffeId>,
    ) -> Result<Option<&crate::modes::mesh::runtime::PolicyScopeCache>, &'static str> {
        let identity = HboneIdentity::from_baggage_values(
            ctx.raw_header_values(BAGGAGE_HEADER)
                .chain(ctx.headers.get(BAGGAGE_HEADER).map(String::as_str)),
        );
        let Some(pod_uid) = identity.source_pod_uid else {
            return Err("missing_or_invalid_pod_uid");
        };
        let Some(scope) = self.ambient_udp_source_scopes.get(&pod_uid) else {
            return Err("pod_not_in_slice");
        };
        if source_principal != Some(&scope.spiffe_id) {
            // The pod UID is in the slice but the asserted principal does not
            // byte-match the CP's Workload.spiffe_id — the cross-component
            // derivation divergence described on `warn_udp_principal_pod_mismatch`.
            // Surface it (rate-limited) so operators see why per-pod scoping is
            // not applying; the fail-closed mesh-wide fallback is unchanged.
            self.warn_udp_principal_pod_mismatch(
                source_principal.map(SpiffeId::as_str),
                scope.spiffe_id.as_str(),
            );
            return Err("principal_pod_mismatch");
        }
        Ok(Some(scope))
    }

    /// Resolve the SPIFFE identity used for authz, applying the HBONE baggage
    /// trust-assertor and trust-domain checks.
    ///
    /// Returns `(principal, BaggageOutcome)`. The outcome describes the
    /// disposition of any incoming HBONE `baggage: source.principal` so that
    /// the caller can stamp diagnostic metadata:
    ///
    /// - `Honored` — baggage parsed, the peer is a trusted assertor, and the
    ///   baggage identity's trust domain matched the peer cert's (or an
    ///   alias). The returned principal is the baggage identity.
    /// - `UntrustedAssertor` — the peer is not on
    ///   [`MeshAuthz::trusted_hbone_assertors`]. Baggage is dropped; the
    ///   returned principal is the peer cert identity.
    /// - `TrustDomainMismatch` — the peer is trusted but the baggage
    ///   identity's trust domain neither matched the peer cert's nor appeared
    ///   in [`MeshAuthz::trust_domain_aliases`]. Baggage is dropped; the
    ///   returned principal is the peer cert identity (typically the
    ///   ztunnel's own SPIFFE id).
    /// - `NoBaggageOrNonHbone` — non-HBONE request, no baggage, or no
    ///   authenticated peer to begin with. No diagnostic stamped.
    fn resolve_source_principal(&self, ctx: &RequestContext) -> (Option<SpiffeId>, BaggageOutcome) {
        if !is_authenticated_hbone_request(ctx) {
            return (
                ctx.peer_spiffe_id.clone(),
                BaggageOutcome::NoBaggageOrNonHbone,
            );
        }
        let Some(peer) = ctx.peer_spiffe_id.as_ref() else {
            return (None, BaggageOutcome::NoBaggageOrNonHbone);
        };
        let baggage_principal = HboneIdentity::from_baggage_values(
            ctx.raw_header_values(BAGGAGE_HEADER)
                .chain(ctx.headers.get(BAGGAGE_HEADER).map(String::as_str)),
        )
        .source_principal;
        if !is_trusted_hbone_assertor(&self.trusted_hbone_assertors, peer) {
            // Stamp `UntrustedAssertor` only when the request actually carried
            // a baggage source identity that we suppressed. Without that
            // signal there's nothing observable for operators to triage and
            // the metadata would just be noise on every non-assertor HBONE
            // flow.
            let outcome = if baggage_principal.is_some() {
                BaggageOutcome::UntrustedAssertor
            } else {
                BaggageOutcome::NoBaggageOrNonHbone
            };
            return (Some(peer.clone()), outcome);
        }
        match baggage_principal {
            Some(b) if self.trust_domain_allowed(peer.trust_domain(), b.trust_domain()) => {
                (Some(b), BaggageOutcome::Honored)
            }
            Some(_) => (Some(peer.clone()), BaggageOutcome::TrustDomainMismatch),
            None => (Some(peer.clone()), BaggageOutcome::NoBaggageOrNonHbone),
        }
    }

    fn trust_domain_allowed(&self, peer_td: &TrustDomain, baggage_td: &TrustDomain) -> bool {
        peer_td == baggage_td
            || self
                .trust_domain_aliases
                .iter()
                .any(|alias| alias == baggage_td)
    }
}

/// Whether `peer` is on the trusted-assertor allow-list.
///
/// Shared by `mesh_authz` and `workload_metrics` so the authorization decision
/// and the telemetry attribution always apply the SAME baggage trust gate — a
/// forked copy is exactly how a workload-to-workload baggage spoof could slip
/// into dashboards / the service graph while authz still correctly rejects it.
pub(crate) fn is_trusted_hbone_assertor(assertors: &[TrustedAssertor], peer: &SpiffeId) -> bool {
    assertors.iter().any(|entry| entry.matches(peer))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaggageOutcome {
    /// Baggage parsed and accepted; returned principal is the baggage identity.
    Honored,
    /// Peer is not a trusted assertor and baggage carried a source identity
    /// that we dropped; returned principal is the peer cert identity.
    UntrustedAssertor,
    /// Baggage's trust domain did not match the peer's or an alias; returned
    /// principal is the peer cert identity.
    TrustDomainMismatch,
    /// Nothing to surface — non-HBONE request, no baggage, or no authenticated
    /// peer.
    NoBaggageOrNonHbone,
}

fn validate_policy_ip_inputs(policies: &[MeshPolicy]) -> Result<(), String> {
    for policy in policies {
        for (rule_idx, rule) in policy.rules.iter().enumerate() {
            // Source negation IP blocks are pre-validated at ParsedCidr
            // parse/deserialization time. Only condition IP blocks (stored
            // as strings) need runtime validation here.
            for (condition_idx, condition) in rule.when.iter().enumerate() {
                if !is_supported_mesh_condition_key(&condition.key) {
                    return Err(format!(
                        "mesh_authz: unsupported condition key in policy '{}'/{} rule {} when {}: '{}'",
                        policy.namespace, policy.name, rule_idx, condition_idx, condition.key
                    ));
                }
                if !mesh_condition_has_values(condition) {
                    return Err(format!(
                        "mesh_authz: condition in policy '{}'/{} rule {} when {} key '{}' must set values or notValues",
                        policy.namespace, policy.name, rule_idx, condition_idx, condition.key
                    ));
                }
                if is_mesh_condition_ip_key(&condition.key) {
                    validate_condition_ip_blocks(
                        policy,
                        rule_idx,
                        condition_idx,
                        &condition.key,
                        "values",
                        &condition.values,
                    )?;
                    validate_condition_ip_blocks(
                        policy,
                        rule_idx,
                        condition_idx,
                        &condition.key,
                        "notValues",
                        &condition.not_values,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_condition_ip_blocks(
    policy: &MeshPolicy,
    rule_idx: usize,
    condition_idx: usize,
    key: &str,
    field: &str,
    blocks: &[String],
) -> Result<(), String> {
    for block in blocks {
        validate_mesh_condition_ip_block(block).map_err(|reason| {
            format!(
                "mesh_authz: invalid condition IP block in policy '{}'/{} rule {} when {} key '{}' field {}: '{}' is invalid: {}",
                policy.namespace, policy.name, rule_idx, condition_idx, key, field, block, reason
            )
        })?;
    }
    Ok(())
}

pub(crate) fn parse_trust_domain_aliases(config: &Value) -> Result<Vec<TrustDomain>, String> {
    match config.get("trust_domain_aliases") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let raw = item
                    .as_str()
                    .ok_or_else(|| "trust_domain_aliases entries must be strings".to_string())?;
                TrustDomain::new(raw)
                    .map_err(|e| format!("invalid trust_domain_aliases entry '{raw}': {e}"))
            })
            .collect(),
        Some(_) => Err("trust_domain_aliases must be an array of strings".to_string()),
    }
}

fn is_authenticated_hbone_request(ctx: &RequestContext) -> bool {
    ctx.peer_spiffe_id.is_some() && is_hbone_request(ctx)
}

fn can_use_inbound_relay_destination_scope_without_source_scope(
    ctx: &RequestContext,
    baggage_outcome: BaggageOutcome,
) -> bool {
    ctx.mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Inbound)
        && matches!(baggage_outcome, BaggageOutcome::Honored)
        && is_authenticated_hbone_request(ctx)
        && ctx
            .matched_proxy
            .as_ref()
            .is_some_and(|proxy| proxy.id == crate::modes::mesh::MESH_INBOUND_HBONE_RELAY_PROXY_ID)
}

fn is_hbone_request(ctx: &RequestContext) -> bool {
    ctx.metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
}

fn record_ignored_baggage_reason(metadata: &mut HashMap<String, String>, reason: &'static str) {
    metadata
        .entry("mesh_authz.ignored_baggage".to_string())
        .and_modify(|existing| {
            if !existing.split(',').any(|item| item == reason) {
                existing.push(',');
                existing.push_str(reason);
            }
        })
        .or_insert_with(|| reason.to_string());
}

fn has_baggage_header_from_request(ctx: &RequestContext) -> bool {
    ctx.raw_header_get(BAGGAGE_HEADER).is_some() || ctx.headers.contains_key(BAGGAGE_HEADER)
}

pub(crate) fn parse_trusted_hbone_assertors(
    config: &Value,
) -> Result<Vec<TrustedAssertor>, String> {
    let items = match config.get("trusted_hbone_assertors") {
        None | Some(Value::Null) => {
            return Ok(default_trusted_hbone_assertors());
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err("trusted_hbone_assertors must be an array of strings".to_string());
        }
    };

    // Empty array intentionally means "no peer can assert baggage"; default
    // assertors only apply when the key is absent or null. Operators can use
    // `[]` to lock down baggage-rewrite entirely while still leaving the
    // mesh_authz plugin active.
    items
        .iter()
        .map(|item| {
            let raw = item
                .as_str()
                .ok_or_else(|| "trusted_hbone_assertors entries must be strings".to_string())?;
            parse_trusted_hbone_assertor(raw)
        })
        .collect()
}

fn parse_trusted_hbone_assertor(raw: &str) -> Result<TrustedAssertor, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("trusted_hbone_assertors entries must not be empty".to_string());
    }
    if trimmed.starts_with("spiffe://") {
        SpiffeId::new(trimmed)
            .map(TrustedAssertor::Spiffe)
            .map_err(|e| format!("invalid trusted_hbone_assertors SPIFFE id '{trimmed}': {e}"))
    } else {
        // Reject anything that looks like an attempted URI but isn't a SPIFFE
        // id (e.g. typo'd scheme) instead of silently treating it as a
        // service-account name.
        if trimmed.contains("://") {
            return Err(format!(
                "trusted_hbone_assertors entry '{trimmed}' looks like a URI but is not a 'spiffe://' SPIFFE id"
            ));
        }
        Ok(TrustedAssertor::ServiceAccount(trimmed.to_string()))
    }
}

fn default_trusted_hbone_assertors() -> Vec<TrustedAssertor> {
    DEFAULT_TRUSTED_HBONE_ASSERTOR_SA_NAMES
        .iter()
        .map(|name| TrustedAssertor::ServiceAccount((*name).to_string()))
        .collect()
}

// Minimal inline module: `mesh_inbound_app_port` is private and cannot be
// reached from `tests/` without widening the API (see testing rules). It is the
// security-critical decision that surfaces a materialized inbound route's app
// port to authz instead of the shared mTLS listener port, so a port-scoped DENY
// no longer fails open.
#[cfg(test)]
mod tests {
    use super::{
        mesh_authz_authorization_path, mesh_authz_destination_port, mesh_inbound_app_port,
    };
    use crate::modes::mesh::{
        MESH_INBOUND_PROXY_ID_PREFIX, MESH_INGRESS_PROXY_ID_PREFIX, MeshTrafficDirection,
    };

    #[test]
    fn mesh_inbound_app_port_uses_backend_port_for_inbound_routes() {
        let id = format!("{MESH_INBOUND_PROXY_ID_PREFIX}default-reviews-80");
        assert_eq!(
            mesh_inbound_app_port(
                Some(MeshTrafficDirection::Inbound),
                Some((id.as_str(), 8080)),
                None,
            ),
            Some(8080),
            "a materialized service-port inbound route must authorize on the app/backend \
             port, not the mTLS listener port"
        );
    }

    #[test]
    fn mesh_inbound_app_port_uses_listener_port_for_ingress_routes() {
        // F6 §6.2 security: an ingress listener `8443 → 127.0.0.1:8080` must
        // authorize on the DECLARED listener port (8443), not the backend port
        // (8080) — otherwise a DENY scoped to 8443 fails open. The handler
        // stamps the listener port; the backend port is ignored for ingress.
        let id = format!("{MESH_INGRESS_PROXY_ID_PREFIX}default-reviews-8443");
        assert_eq!(
            mesh_inbound_app_port(
                Some(MeshTrafficDirection::Inbound),
                Some((id.as_str(), 8080)),
                Some(8443),
            ),
            Some(8443),
            "an ingress listener route must authorize on the declared listener port"
        );
    }

    #[test]
    fn mesh_inbound_app_port_ingress_without_stamped_port_fails_closed() {
        // If the listener port is somehow missing for an ingress id, do NOT fall
        // back to the backend port (which would silently let a listener-port DENY
        // miss). Return `None` → the caller falls back to the listener socket
        // port, never the backend port.
        let id = format!("{MESH_INGRESS_PROXY_ID_PREFIX}default-reviews-8443");
        assert_eq!(
            mesh_inbound_app_port(
                Some(MeshTrafficDirection::Inbound),
                Some((id.as_str(), 8080)),
                None,
            ),
            None,
            "ingress route with no stamped listener port must not authorize on the backend port"
        );
    }

    #[test]
    fn mesh_inbound_app_port_none_for_non_inbound_or_non_mesh() {
        let id = format!("{MESH_INBOUND_PROXY_ID_PREFIX}default-reviews-80");
        // Outbound direction, no direction, a non-mesh proxy id, and no matched
        // proxy all fall back to the listener-port derivation (None here).
        assert_eq!(
            mesh_inbound_app_port(
                Some(MeshTrafficDirection::Outbound),
                Some((id.as_str(), 8080)),
                None,
            ),
            None,
        );
        assert_eq!(
            mesh_inbound_app_port(None, Some((id.as_str(), 8080)), None),
            None
        );
        assert_eq!(
            mesh_inbound_app_port(
                Some(MeshTrafficDirection::Inbound),
                Some(("operator-route", 8080)),
                None,
            ),
            None,
        );
        assert_eq!(
            mesh_inbound_app_port(Some(MeshTrafficDirection::Inbound), None, None),
            None,
        );
    }

    #[test]
    fn mesh_authz_destination_port_uses_orig_dst_for_outbound() {
        let orig_dst = "10.0.0.10:9080".parse().expect("valid socket addr");
        assert_eq!(
            mesh_authz_destination_port(
                Some(MeshTrafficDirection::Outbound),
                None,
                None,
                Some(8080),
                Some(orig_dst),
                Some(15001),
            ),
            Some(9080),
            "outbound authz must prefer the real captured destination port over route/listener ports"
        );
    }

    #[test]
    fn mesh_authz_destination_port_uses_selected_outbound_service_port_without_orig_dst() {
        assert_eq!(
            mesh_authz_destination_port(
                Some(MeshTrafficDirection::Outbound),
                None,
                None,
                Some(8080),
                None,
                Some(15001),
            ),
            Some(8080),
            "single-port direct/non-Linux outbound routes use the router-selected service port"
        );
    }

    #[test]
    fn mesh_authz_destination_port_does_not_fall_back_to_capture_listener_for_outbound() {
        assert_eq!(
            mesh_authz_destination_port(
                Some(MeshTrafficDirection::Outbound),
                None,
                None,
                None,
                None,
                Some(15001),
            ),
            None,
            "outbound destination.port must not evaluate as the shared capture listener port"
        );
    }

    #[test]
    fn mesh_authz_authorization_path_normalizes_encoded_slashes() {
        assert_eq!(
            mesh_authz_authorization_path("/admin%2fsecret"),
            "/admin/secret"
        );
        assert_eq!(
            mesh_authz_authorization_path("/admin%252Fsecret"),
            "/admin/secret"
        );
        assert_eq!(mesh_authz_authorization_path("/api%20name"), "/api%20name");
    }
}
