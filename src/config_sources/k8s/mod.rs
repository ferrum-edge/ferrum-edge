//! Kubernetes config-source translation (Layer 4).
//!
//! This module accepts unstructured Kubernetes resources and translates the
//! supported Istio + Gateway API surface into Ferrum's canonical Layer 2 model.
//! Unsupported resources fail closed when silent translation would be unsafe.

mod core;
mod gateway_api;
mod istio;
mod mesh_config;

pub(crate) use core::secret_object_is_valid_tls_certificate;
pub(crate) use gateway_api::{
    allowed_route_namespaces as parse_gateway_listener_allowed_route_namespaces,
    namespace_selector_matches,
};
// Shared with the Istio status writer (`crate::k8s_controller::istio_status`) so
// the translator's "emit cors plugin vs. leave unprojected" decision and the
// status writer's deferred-field reporting use one predicate and never diverge.
pub(crate) use istio::cors_policy_translatable;
// Shared with the Istio status writer the same way: the Sidecar `ingress[]`
// HTTP-family classification used by resolution and by deferred-field reporting
// is one predicate, so an HTTPS (→ Unknown → HTTP-family) listener is never
// modeled by resolution yet reported as a deferred non-HTTP listener.
pub(crate) use istio::sidecar_ingress_protocol_is_http_family;
// Shared with the Istio status writer the same way: the ServiceEntry UDP-port
// classification used by translation/materialization (a `protocol: UDP` port is
// classified `AppProtocol::Udp` and its egress materialization is deferred/inert
// in F3 §3.3 stage 1) and by the status writer's deferred-field reporting is one
// predicate, so a UDP ServiceEntry is never reported as fully accepted while its
// egress lane is silently skipped.
pub(crate) use istio::service_entry_port_protocol_is_udp;

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::db_backend::NamespacedResourceId;
use crate::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    MAX_TARGET_WEIGHT, PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode,
    RetryConfig, UPSTREAM_TARGET_SERVICE_NAME_TAG, UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG,
    UPSTREAM_TARGET_SERVICE_PORT_TAG, Upstream, UpstreamTarget, default_namespace,
};
use crate::identity::spiffe::TrustDomain;
use crate::modes::mesh::config::{MeshConfig, WorkloadSelector};
use crate::plugins::utils::fault_roll::MAX_FAULT_DELAY_MS;

const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sMetadata {
    #[serde(default)]
    pub name: String,
    /// Kubernetes object UID (`metadata.uid`). Used to key node-waypoint
    /// per-pod policy scope by the pod's exact UID. Optional + default so
    /// old K8s payload JSON deserializes unchanged.
    #[serde(default)]
    pub uid: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    /// Object annotations. Required to read Istio waypoint bindings
    /// (`istio.io/use-waypoint`, `istio.io/waypoint-for`) and any other
    /// annotation-driven translation in the future. Optional + default so
    /// old K8s payload JSON deserializes unchanged.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(
        default,
        rename = "creationTimestamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_timestamp: Option<String>,
    #[serde(
        default,
        rename = "deletionTimestamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct K8sObject {
    #[serde(default, rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: K8sMetadata,
    #[serde(default)]
    pub spec: Value,
    #[serde(default, skip_serializing_if = "is_empty_object")]
    pub status: Value,
}

#[derive(Debug, Clone)]
pub struct K8sTranslationOptions {
    pub namespace: String,
    pub node_waypoint_namespace: String,
    pub trust_domain: TrustDomain,
    pub prefer_istio_on_overlap: bool,
    pub istio_root_namespace: String,
    pub cluster_domain: String,
    /// Opt-in core Kubernetes Pod/Service/EndpointSlice discovery. Default
    /// false for the first rollout so operators can enable it deliberately.
    pub pod_discovery_enabled: bool,
    /// Whether Sidecar `ingress[]` custom inbound listeners are actually
    /// MATERIALIZED on the data plane (F6 §6.2) — the effective enforcement gate
    /// `FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`,
    /// mirroring the slice builder's `sidecar_enforced && !sidecar_dry_run`
    /// ingress predicate. The Istio status writer reports `ingress_modeled > 0`
    /// only when this is true, so the `FerrumAccepted` status never claims a
    /// listener is modeled while the data plane is still serving the default
    /// inbound behavior (dry-run / default-off). Default false (matches the env
    /// default and the slice builder). Egress narrowing has its OWN, looser gate
    /// (`enforced || dry_run`) and is not affected by this.
    pub mesh_sidecar_ingress_enforced: bool,
    source_namespaces: Option<HashSet<String>>,
    pod_source_namespaces: Option<HashSet<String>>,
}

/// A stable, value-redacted validation error for a Gateway listener's
/// `allowedRoutes` namespace policy.
///
/// The field path identifies the invalid selector surface without echoing a
/// user-supplied label key, label value, or operator into status or logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayApiListenerValidationError {
    field: &'static str,
    message: &'static str,
}

impl GatewayApiListenerValidationError {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    pub const fn field(&self) -> &'static str {
        self.field
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for GatewayApiListenerValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for GatewayApiListenerValidationError {}

/// Validate the namespace attachment policy for one unstructured Gateway
/// listener.
///
/// Translation and status use the same underlying fallible parser so a
/// malformed AND selector cannot be weakened differently on either surface.
pub fn validate_gateway_listener_allowed_routes(
    listener: &Value,
) -> Result<(), GatewayApiListenerValidationError> {
    gateway_api::allowed_route_namespaces(listener).map(|_| ())
}

impl K8sTranslationOptions {
    pub fn new(namespace: String, trust_domain: TrustDomain) -> Self {
        let source_namespaces = HashSet::from([namespace.clone()]);
        let pod_source_namespaces = HashSet::from([namespace.clone()]);
        Self {
            node_waypoint_namespace: namespace.clone(),
            namespace,
            trust_domain,
            prefer_istio_on_overlap: true,
            istio_root_namespace: "istio-system".to_string(),
            cluster_domain: "cluster.local".to_string(),
            pod_discovery_enabled: false,
            mesh_sidecar_ingress_enforced: false,
            source_namespaces: Some(source_namespaces),
            pod_source_namespaces: Some(pod_source_namespaces),
        }
    }

    pub fn with_pod_discovery_enabled(mut self, enabled: bool) -> Self {
        self.pod_discovery_enabled = enabled;
        self
    }

    /// Set the effective Sidecar ingress enforcement gate
    /// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`).
    /// The Istio status writer reports `ingress_modeled` as materialized only
    /// when this is true, keeping the status in lock-step with what the slice
    /// builder actually materializes.
    pub fn with_mesh_sidecar_ingress_enforced(mut self, enforced: bool) -> Self {
        self.mesh_sidecar_ingress_enforced = enforced;
        self
    }

    pub fn with_istio_root_namespace(mut self, namespace: String) -> Self {
        if !namespace.trim().is_empty() {
            self.istio_root_namespace = namespace;
        }
        self
    }

    pub fn with_node_waypoint_namespace(mut self, namespace: String) -> Self {
        if !namespace.trim().is_empty() {
            self.node_waypoint_namespace = namespace;
        }
        self
    }

    pub fn with_cluster_domain(mut self, domain: String) -> Self {
        // Empty/whitespace falls back to the existing default (`cluster.local`)
        // rather than producing a translator that can never match a FQDN host.
        if !domain.trim().is_empty() {
            self.cluster_domain = domain;
        }
        self
    }

    pub fn with_source_namespaces(mut self, namespaces: Vec<String>) -> Self {
        let source_namespaces = if namespaces.is_empty() {
            None
        } else {
            Some(namespaces.into_iter().collect())
        };
        self.pod_source_namespaces = source_namespaces.clone();
        self.source_namespaces = source_namespaces;
        self
    }

    pub fn with_pod_source_namespaces(mut self, namespaces: Vec<String>) -> Self {
        self.pod_source_namespaces = if namespaces.is_empty() {
            None
        } else {
            Some(namespaces.into_iter().collect())
        };
        self
    }

    fn includes_namespace(&self, namespace: &str) -> bool {
        self.source_namespaces
            .as_ref()
            .is_none_or(|namespaces| namespaces.contains(namespace))
    }

    fn includes_pod_namespace(&self, namespace: &str) -> bool {
        self.pod_source_namespaces
            .as_ref()
            .is_none_or(|namespaces| namespaces.contains(namespace))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedK8sResource {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum K8sTranslateError {
    Unsupported(UnsupportedK8sResource),
    InvalidResource {
        kind: String,
        namespace: String,
        name: String,
        message: String,
    },
}

impl std::fmt::Display for K8sTranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(resource) => write!(
                f,
                "unsupported Kubernetes resource {}/{} {}: {}",
                resource.namespace, resource.name, resource.kind, resource.reason
            ),
            Self::InvalidResource {
                kind,
                namespace,
                name,
                message,
            } => write!(
                f,
                "invalid Kubernetes resource {}/{} {}: {}",
                namespace, name, kind, message
            ),
        }
    }
}

impl std::error::Error for K8sTranslateError {}

#[derive(Debug, Clone, Default)]
pub struct K8sTranslation {
    pub config: GatewayConfig,
    pub warnings: Vec<String>,
    /// Gateway API route conflicts computed over the routes that survived
    /// translator validation. Invalid routes are excluded so the status writer
    /// does not mark a valid (and materialized) route as `Conflicted=True`
    /// against an older sibling that the translator already dropped.
    pub route_conflicts: Vec<GatewayApiRouteConflict>,
    /// Route parentRefs that actually produced live route configuration.
    /// Status uses this per-parent set instead of route-wide proxy IDs so a
    /// route attached to one programmed parent and one fail-closed parent does
    /// not report both parents as Programmed.
    pub materialized_route_parents: HashSet<GatewayApiMaterializedRouteParent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Istio,
    GatewayApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct K8sResourceKey {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
}

impl K8sResourceKey {
    pub fn from_object(object: &K8sObject) -> Self {
        Self {
            api_version: object.api_version.clone(),
            kind: object.kind.clone(),
            namespace: object.metadata.namespace.clone(),
            name: object.metadata.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayApiRouteConflictKey {
    pub route_family: String,
    pub parent_ref: String,
    pub hostname: String,
    pub listen_path: String,
    pub match_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiRouteConflict {
    pub key: GatewayApiRouteConflictKey,
    pub winner: K8sResourceKey,
    pub loser: K8sResourceKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayApiMaterializedRouteParent {
    pub route: K8sResourceKey,
    pub parent_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct K8sServiceKey {
    pub namespace: String,
    pub name: String,
}

impl K8sServiceKey {
    pub(crate) fn new(namespace: impl Into<String>, name: impl Into<String>) -> Option<Self> {
        let namespace = namespace.into();
        let name = name.into();
        if namespace.trim().is_empty() || name.trim().is_empty() {
            return None;
        }
        Some(Self { namespace, name })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GatewayApiListenerKey {
    pub namespace: String,
    pub gateway: String,
    pub listener: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum GatewayApiAllowedRoutesNamespaces {
    #[default]
    Same,
    All,
    Selector(GatewayApiNamespaceSelector),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GatewayApiNamespaceSelector {
    pub match_labels: HashMap<String, String>,
    pub match_expressions: Vec<GatewayApiNamespaceSelectorExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayApiNamespaceSelectorExpression {
    pub key: String,
    pub operator: GatewayApiNamespaceSelectorOperator,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayApiNamespaceSelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct GatewayApiListenerPolicy {
    pub namespaces: GatewayApiAllowedRoutesNamespaces,
    pub validation_error: Option<GatewayApiListenerValidationError>,
    pub hostname: Option<String>,
    pub port: Option<u64>,
    pub route_kinds: HashSet<String>,
    pub materializable: bool,
    pub routes_materializable: bool,
    pub requires_frontend_tls: bool,
}

pub(crate) struct K8sAccumulator {
    pub options: K8sTranslationOptions,
    pub config: GatewayConfig,
    pub mesh: MeshConfig,
    pub warnings: Vec<String>,
    reference_grants: HashSet<ReferenceGrantPermission>,
    /// Ownership / precedence map keyed by Ferrum `(namespace, id)`.
    /// Bare IDs are only unique within a namespace, and generated K8s IDs are
    /// lossy across dashed namespace/name components, so a multi-namespace
    /// translation must never key ownership by bare id alone.
    proxy_sources: HashMap<NamespacedResourceId, SourceKind>,
    known_namespaces: HashSet<String>,
    /// Port-name → port-number index for collected `Service` objects, nested
    /// `namespace → service_name → port_name → port`. Built in the translator
    /// pre-pass so VirtualService destinations carrying `port.name` (not
    /// `port.number`) can be resolved against the workload's actual Service.
    /// The nested shape lets `lookup_service_port` borrow `&str` arguments
    /// directly — no per-lookup `.to_string()` allocations.
    service_port_names: HashMap<String, HashMap<String, HashMap<String, u16>>>,
    service_ports: HashMap<String, HashMap<String, HashSet<u16>>>,
    pub(crate) mesh_config_registry: mesh_config::MeshConfigProviderRegistry,
    core: core::CoreState,
    explicit_workload_services: HashSet<K8sServiceKey>,
    explicit_service_entries: HashSet<K8sServiceKey>,
    pub(crate) gateway_api_conflict_losers: HashMap<K8sResourceKey, Vec<GatewayApiRouteConflict>>,
    pub(crate) gateway_api_listener_policies:
        HashMap<GatewayApiListenerKey, GatewayApiListenerPolicy>,
    gateway_api_gateway_classes: HashMap<String, bool>,
    pub(crate) namespace_labels: HashMap<String, HashMap<String, String>>,
    /// Flat copy of the Gateway API route conflicts computed over the
    /// translator's filtered object set. Reused by the status writer so
    /// invalid routes (which the translator skips) cannot push a valid
    /// sibling into `Conflicted=True`.
    gateway_api_route_conflicts: Vec<GatewayApiRouteConflict>,
    gateway_api_materialized_route_parents: HashSet<GatewayApiMaterializedRouteParent>,
}

impl K8sAccumulator {
    fn new(options: K8sTranslationOptions) -> Self {
        let mesh = MeshConfig {
            istio_root_namespace: options.istio_root_namespace.clone(),
            ..MeshConfig::default()
        };
        Self {
            options,
            config: GatewayConfig::default(),
            mesh,
            warnings: Vec::new(),
            reference_grants: HashSet::new(),
            proxy_sources: HashMap::new(),
            known_namespaces: HashSet::new(),
            service_port_names: HashMap::new(),
            service_ports: HashMap::new(),
            mesh_config_registry: mesh_config::MeshConfigProviderRegistry::default(),
            core: core::CoreState::default(),
            explicit_workload_services: HashSet::new(),
            explicit_service_entries: HashSet::new(),
            gateway_api_conflict_losers: HashMap::new(),
            gateway_api_listener_policies: HashMap::new(),
            gateway_api_gateway_classes: HashMap::new(),
            namespace_labels: HashMap::new(),
            gateway_api_route_conflicts: Vec::new(),
            gateway_api_materialized_route_parents: HashSet::new(),
        }
    }

    /// Resolve a Service port name to its `port` value. Returns `None` when
    /// the service was never collected (cluster-external host, foreign
    /// namespace, etc.) or when the named port isn't on that service.
    pub(crate) fn lookup_service_port(
        &self,
        namespace: &str,
        service: &str,
        port_name: &str,
    ) -> Option<u16> {
        self.service_port_names
            .get(namespace)
            .and_then(|by_svc| by_svc.get(service))
            .and_then(|ports| ports.get(port_name))
            .copied()
    }

    pub(crate) fn service_exists(&self, namespace: &str, service: &str) -> bool {
        self.service_port_names
            .get(namespace)
            .is_some_and(|services| services.contains_key(service))
    }

    pub(crate) fn service_port_exists(&self, namespace: &str, service: &str, port: u16) -> bool {
        self.service_ports
            .get(namespace)
            .and_then(|services| services.get(service))
            .is_some_and(|ports| ports.contains(&port))
    }

    pub(crate) fn has_observed_services(&self) -> bool {
        !self.service_port_names.is_empty()
    }

    pub(crate) fn endpoint_route_backends_for_service(
        &self,
        namespace: &str,
        service: &str,
        service_port: u16,
        weight: u32,
    ) -> Vec<RouteBackend> {
        core::endpoint_route_backends_for_service(self, namespace, service, service_port, weight)
    }

    pub(crate) fn secret_is_valid_tls_certificate(&self, namespace: &str, name: &str) -> bool {
        core::secret_is_valid_tls_certificate(self, namespace, name)
    }

    pub(crate) fn secret_tls_material_digest(&self, namespace: &str, name: &str) -> Option<&str> {
        core::secret_tls_material_digest(self, namespace, name)
    }

    fn observe_namespace(&mut self, namespace: &str) {
        self.known_namespaces.insert(namespace.to_string());
    }

    pub(crate) fn record_namespace_labels(
        &mut self,
        namespace: String,
        labels: HashMap<String, String>,
    ) {
        self.namespace_labels.insert(namespace, labels);
    }

    pub(crate) fn record_gateway_class(&mut self, object: &K8sObject) {
        let managed = object.spec.get("controllerName").and_then(Value::as_str)
            == Some(FERRUM_GATEWAY_CONTROLLER_NAME);
        self.gateway_api_gateway_classes
            .insert(object.metadata.name.clone(), managed);
    }

    pub(crate) fn gateway_is_managed_by_ferrum(&self, object: &K8sObject) -> bool {
        let Some(class_name) = object.spec.get("gatewayClassName").and_then(Value::as_str) else {
            return false;
        };
        self.gateway_api_gateway_classes
            .get(class_name)
            .copied()
            .unwrap_or_else(|| class_name == "ferrum")
    }

    fn record_explicit_workload_service(&mut self, key: K8sServiceKey) {
        self.explicit_workload_services.insert(key);
    }

    fn record_explicit_service_entry(&mut self, key: K8sServiceKey) {
        self.explicit_service_entries.insert(key);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_reference_grant(
        &mut self,
        from_namespace: String,
        from_group: String,
        from_kind: String,
        to_namespace: String,
        to_group: String,
        to_kind: String,
        to_name: Option<String>,
    ) {
        self.reference_grants.insert(ReferenceGrantPermission {
            from_namespace,
            from_group,
            from_kind,
            to_namespace,
            to_group,
            to_kind,
            to_name,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reference_grant_allows(
        &self,
        from_namespace: &str,
        from_group: &str,
        from_kind: &str,
        to_namespace: &str,
        to_group: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> bool {
        self.reference_grants.iter().any(|grant| {
            grant.from_namespace == from_namespace
                && grant.from_group == from_group
                && grant.from_kind == from_kind
                && grant.to_namespace == to_namespace
                && grant.to_group == to_group
                && grant.to_kind == to_kind
                && grant
                    .to_name
                    .as_deref()
                    .is_none_or(|name| Some(name) == to_name)
        })
    }

    pub(crate) fn proxy_source(&self, namespace: &str, id: &str) -> Option<SourceKind> {
        let key = namespaced_resource_key(namespace, id)?;
        self.proxy_sources.get(&key).copied()
    }

    pub(crate) fn upsert_proxy(&mut self, proxy: Proxy, source: SourceKind) {
        let Some(key) = namespaced_resource_key(&proxy.namespace, &proxy.id) else {
            self.warnings.push(format!(
                "proxy with empty namespace or id was ignored (namespace='{}', id='{}')",
                proxy.namespace, proxy.id
            ));
            return;
        };
        if let Some(existing_source) = self.proxy_sources.get(&key).copied() {
            let istio_wins = self.options.prefer_istio_on_overlap
                && existing_source == SourceKind::GatewayApi
                && source == SourceKind::Istio;
            let gateway_loses = self.options.prefer_istio_on_overlap
                && existing_source == SourceKind::Istio
                && source == SourceKind::GatewayApi;

            if gateway_loses {
                self.warnings.push(format!(
                    "Gateway API proxy '{}/{}' ignored because Istio resource has precedence",
                    proxy.namespace, proxy.id
                ));
                return;
            }

            if let Some(existing) = self.config.proxies.iter_mut().find(|candidate| {
                candidate.namespace == proxy.namespace && candidate.id == proxy.id
            }) {
                if istio_wins || !self.options.prefer_istio_on_overlap {
                    *existing = proxy;
                    self.proxy_sources.insert(key, source);
                }
                return;
            }
        }

        self.proxy_sources.insert(key, source);
        self.config.proxies.push(proxy);
    }

    pub(crate) fn upsert_upstream(&mut self, upstream: Upstream) {
        if namespaced_resource_key(&upstream.namespace, &upstream.id).is_none() {
            self.warnings.push(format!(
                "upstream with empty namespace or id was ignored (namespace='{}', id='{}')",
                upstream.namespace, upstream.id
            ));
            return;
        }
        if let Some(existing) = self.config.upstreams.iter_mut().find(|candidate| {
            candidate.namespace == upstream.namespace && candidate.id == upstream.id
        }) {
            *existing = upstream;
        } else {
            self.config.upstreams.push(upstream);
        }
    }

    pub(crate) fn record_gateway_api_materialized_route_parent(
        &mut self,
        route: &K8sObject,
        parent_ref: String,
    ) {
        self.gateway_api_materialized_route_parents
            .insert(GatewayApiMaterializedRouteParent {
                route: K8sResourceKey::from_object(route),
                parent_ref,
            });
    }

    fn finish(mut self) -> K8sTranslation {
        gateway_api::finalize_dispatch_plugin_precedence(&mut self.config.plugin_configs);
        debug_assert!(
            !gateway_api::dispatch_rule_internal_metadata_present(&self.config.plugin_configs),
            "internal Gateway API dispatch precedence metadata must be stripped before translation output"
        );
        self.mesh.normalize();
        // Sort single-winner / additive mesh resources by (namespace, name) for
        // deterministic slice order. `peer_authentications` is sorted alongside
        // its siblings so the inbound-mTLS resolver sees a stable order (its
        // same-tier tiebreak in `resolve_effective_mtls_mode` is the
        // load-bearing guarantee; this keeps the translated slice itself
        // deterministic too).
        self.mesh.peer_authentications.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        self.mesh.request_authentications.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        self.mesh.telemetry_resources.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        self.mesh.proxy_configs.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        let empty_mesh = MeshConfig {
            istio_root_namespace: self.mesh.istio_root_namespace.clone(),
            ..MeshConfig::default()
        };
        if self.mesh != empty_mesh {
            self.config.mesh = Some(Box::new(self.mesh));
        }
        let mut known_namespaces: Vec<String> = self.known_namespaces.into_iter().collect();
        known_namespaces.sort();
        self.config.known_namespaces.extend(known_namespaces);
        self.config.normalize_fields();
        K8sTranslation {
            config: self.config,
            warnings: self.warnings,
            route_conflicts: self.gateway_api_route_conflicts,
            materialized_route_parents: self.gateway_api_materialized_route_parents,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReferenceGrantPermission {
    from_namespace: String,
    from_group: String,
    from_kind: String,
    to_namespace: String,
    to_group: String,
    to_kind: String,
    to_name: Option<String>,
}

pub fn translate_k8s_objects(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Result<K8sTranslation, K8sTranslateError> {
    translate_k8s_objects_with_filter(objects, options, |_| true)
}

pub fn gateway_api_route_conflicts(
    objects: &[K8sObject],
    options: &K8sTranslationOptions,
) -> Vec<GatewayApiRouteConflict> {
    let mut acc = K8sAccumulator::new(options.clone());
    collect_gateway_api_status_context(objects, &mut acc);
    gateway_api::route_conflicts(objects, options, Some(&acc))
}

pub fn gateway_api_route_conflict_keys(object: &K8sObject) -> Vec<GatewayApiRouteConflictKey> {
    gateway_api::route_conflict_keys(object)
}

pub fn gateway_api_route_conflict_keys_with_context(
    objects: &[K8sObject],
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Vec<GatewayApiRouteConflictKey> {
    let mut acc = K8sAccumulator::new(options.clone());
    collect_gateway_api_status_context(objects, &mut acc);
    gateway_api::route_conflict_keys_for_acc(object, Some(&acc))
}

fn collect_gateway_api_status_context(objects: &[K8sObject], acc: &mut K8sAccumulator) {
    for object in objects {
        if object.kind == "Namespace" {
            acc.record_namespace_labels(
                object.metadata.name.clone(),
                object.metadata.labels.clone(),
            );
        } else if object.kind == "GatewayClass" {
            acc.record_gateway_class(object);
        }
    }
    for object in objects {
        if !includes_object_namespace(&acc.options, object) {
            continue;
        }
        if object.kind == "ReferenceGrant" {
            let _ = gateway_api::collect_reference_grant(acc, object);
        } else if object.kind == "Secret" {
            let _ = core::collect(acc, object);
        }
    }
    for object in objects {
        if object.kind == "Gateway"
            && includes_object_namespace(&acc.options, object)
            && acc.gateway_is_managed_by_ferrum(object)
        {
            let _ = gateway_api::collect_gateway_listener_policy(acc, object);
        }
    }
}

pub(crate) fn translate_k8s_objects_with_filter<F>(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    include: F,
) -> Result<K8sTranslation, K8sTranslateError>
where
    F: Fn(&K8sObject) -> bool,
{
    // Performance follow-up: each K8sObject carries the entire `spec`/`status`
    // `serde_json::Value` (HTTPRoute/VirtualService specs can be tens of KB).
    // Cloning every included object once per reconcile is bounded by reconcile
    // cadence (~30s on the CP) but unnecessary — every downstream consumer
    // borrows immutably. Migrating this to `Vec<&K8sObject>` requires
    // `gateway_api::route_conflicts` (and any future `&[K8sObject]` consumers)
    // to take `&[&K8sObject]`; left as a follow-up to keep this slice focused.
    let included_objects: Vec<K8sObject> = objects
        .iter()
        .filter(|object| include(object))
        .cloned()
        .collect();
    let mut acc = K8sAccumulator::new(options);

    for object in &included_objects {
        if object.kind == "Namespace" {
            acc.record_namespace_labels(
                object.metadata.name.clone(),
                object.metadata.labels.clone(),
            );
        } else if object.kind == "GatewayClass" {
            acc.record_gateway_class(object);
        }
    }

    for object in &included_objects {
        if object.kind == "Namespace" || object.kind == "GatewayClass" {
            continue;
        }
        if !includes_object_namespace(&acc.options, object) {
            continue;
        }
        observe_object_namespace(&mut acc, object);
        if object.kind == "ReferenceGrant" {
            gateway_api::collect_reference_grant(&mut acc, object)?;
        } else if object.kind == "Service" {
            collect_service(&mut acc, object)?;
            if acc.options.pod_discovery_enabled {
                core::collect(&mut acc, object)?;
            }
        } else if object.kind == "Secret" {
            core::collect(&mut acc, object)?;
        } else if mesh_config::is_istio_mesh_config_map(&acc.options, object) {
            mesh_config::collect(&mut acc, object)?;
        } else if acc.options.pod_discovery_enabled && object.kind == "WorkloadEntry" {
            collect_explicit_workload_service(&mut acc, object);
        } else if acc.options.pod_discovery_enabled && object.kind == "ServiceEntry" {
            collect_explicit_service_entry_keys(&mut acc, object);
        } else if acc.options.pod_discovery_enabled && core::is_core_resource_kind(&object.kind) {
            core::collect(&mut acc, object)?;
        }
    }

    for object in &included_objects {
        if object.kind == "Gateway"
            && includes_object_namespace(&acc.options, object)
            && acc.gateway_is_managed_by_ferrum(object)
        {
            gateway_api::collect_gateway_listener_policy(&mut acc, object)?;
        }
    }

    let gateway_api_route_conflicts =
        gateway_api::route_conflicts(&included_objects, &acc.options, Some(&acc));
    for conflict in &gateway_api_route_conflicts {
        // GRPCRoute method / header predicates now carry their own conflict
        // signature (see `gateway_api::grpc_route_match_signature`), so two
        // gRPC routes only collide when they claim the *same* predicate on the
        // same parent, hostname, and listen path — exactly like HTTPRoute.
        //
        // A cross-kind (HTTPRoute vs GRPCRoute) collision is different in
        // kind, not degree: Gateway API v1.5.1 requires the whole losing Route
        // to be rejected on the shared listener, so every one of its matches is
        // suppressed rather than just the colliding one. Because the
        // materialized route is port-agnostic, the rejection covers the whole
        // parentRef claim — including any other listener that claim reaches.
        let skipped_reason = if conflict.loser.kind == conflict.winner.kind {
            "the conflicting match was skipped"
        } else {
            "the whole route was withdrawn from that parentRef claim because Gateway API forbids \
             merging HTTPRoute and GRPCRoute rules on a shared listener"
        };
        acc.warnings.push(format!(
            "Gateway API {} {}/{} conflicted on parent={} host={} path={} match={} and {}; winner is {}/{}",
            conflict.loser.kind,
            conflict.loser.namespace,
            conflict.loser.name,
            conflict.key.parent_ref,
            conflict.key.hostname,
            conflict.key.listen_path,
            conflict.key.match_signature,
            skipped_reason,
            conflict.winner.namespace,
            conflict.winner.name
        ));
        acc.gateway_api_conflict_losers
            .entry(conflict.loser.clone())
            .or_default()
            .push(conflict.clone());
    }
    acc.gateway_api_route_conflicts = gateway_api_route_conflicts;

    for object in &included_objects {
        if object.kind == "Namespace" || object.kind == "GatewayClass" {
            continue;
        }
        if !includes_object_namespace(&acc.options, object) {
            continue;
        }
        observe_object_namespace(&mut acc, object);

        if object.kind == "EnvoyFilter" {
            return Err(K8sTranslateError::Unsupported(UnsupportedK8sResource {
                kind: object.kind.clone(),
                namespace: object.metadata.namespace.clone(),
                name: object.metadata.name.clone(),
                reason: "EnvoyFilter is intentionally unsupported; file an issue with the required behavior instead of relying on opaque Envoy patches".to_string(),
            }));
        }

        // Service objects are consumed by the pre-pass for port-name resolution;
        // they do not produce Ferrum proxies/upstreams directly.
        if object.kind == "Service" {
            continue;
        }

        // The root-namespace `istio` ConfigMap feeds the translation-time
        // MeshConfig registry during the pre-pass. Other ConfigMaps watched
        // from that namespace are not Ferrum resources.
        if object.kind == "ConfigMap" {
            continue;
        }

        if core::is_core_resource_kind(&object.kind) {
            continue;
        }

        if istio::translate(&mut acc, object)? || gateway_api::translate(&mut acc, object)? {
            continue;
        }

        acc.warnings.push(format!(
            "Ignoring unsupported Kubernetes resource kind '{}' in {}/{}",
            object.kind, object.metadata.namespace, object.metadata.name
        ));
    }

    if acc.options.pod_discovery_enabled {
        core::finalize(&mut acc)?;
    }

    Ok(acc.finish())
}

fn includes_object_namespace(options: &K8sTranslationOptions, object: &K8sObject) -> bool {
    object_namespace_matches_source(options, object)
        || object.kind == "GatewayClass"
        || mesh_config::is_root_namespace_config_map(options, object)
        || (options.pod_discovery_enabled
            && core::trusted_node_waypoint_pod_object(options, object))
        || (options.pod_discovery_enabled
            && core::is_cluster_scoped_core_resource_kind(&object.kind))
}

fn observe_object_namespace(acc: &mut K8sAccumulator, object: &K8sObject) {
    if !core::is_cluster_scoped_core_resource_kind(&object.kind)
        && (object_namespace_matches_source(&acc.options, object)
            || mesh_config::is_root_namespace_config_map(&acc.options, object))
    {
        acc.observe_namespace(&object.metadata.namespace);
    }
}

fn object_namespace_matches_source(options: &K8sTranslationOptions, object: &K8sObject) -> bool {
    if options.pod_discovery_enabled && object.kind == "Pod" {
        options.includes_pod_namespace(&object.metadata.namespace)
    } else {
        options.includes_namespace(&object.metadata.namespace)
    }
}

/// Collect the `ports[].name → port` map from a core/v1 Service so later
/// translation passes can resolve Istio `destination.port.name` references.
/// Services with no named ports populate an empty entry — callers can still
/// distinguish "service exists, port name unknown" from "service unknown".
pub(crate) fn collect_service(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    let ports = object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .map(|arr| arr.as_slice())
        .unwrap_or(&[]);
    let mut port_names: HashMap<String, u16> = HashMap::new();
    let mut port_numbers: HashSet<u16> = HashSet::new();
    for port_entry in ports {
        let Some(raw) = port_entry.get("port").and_then(Value::as_u64) else {
            continue;
        };
        let port = port_from_u64(object, raw, "Service.spec.ports[].port")?;
        port_numbers.insert(port);
        if let Some(name) = string_field(port_entry, "name") {
            port_names.insert(name.to_string(), port);
        }
    }
    acc.service_port_names
        .entry(object.metadata.namespace.clone())
        .or_default()
        .insert(object.metadata.name.clone(), port_names);
    acc.service_ports
        .entry(object.metadata.namespace.clone())
        .or_default()
        .insert(object.metadata.name.clone(), port_numbers);

    // GAMMA Waypoint binding: a Service with the `istio.io/use-waypoint`
    // annotation routes through the named waypoint. We append the binding
    // to `acc.mesh.waypoint_bindings` so the slice builder can narrow
    // services per waypoint at projection time.
    gateway_api::add_service_waypoint_binding(acc, object);
    Ok(())
}

fn collect_explicit_workload_service(acc: &mut K8sAccumulator, object: &K8sObject) {
    let service = string_field(&object.spec, "service").unwrap_or(&object.metadata.name);
    if let Some(key) = service_key_from_host(
        service,
        &object.metadata.namespace,
        &acc.options.cluster_domain,
    )
    .filter(|key| key.namespace == object.metadata.namespace)
    {
        acc.record_explicit_workload_service(key);
    }
}

fn collect_explicit_service_entry_keys(acc: &mut K8sAccumulator, object: &K8sObject) {
    for host in string_array(&object.spec, "hosts") {
        if let Some(key) = service_key_from_host(
            &host,
            &object.metadata.namespace,
            &acc.options.cluster_domain,
        )
        .filter(|key| key.namespace == object.metadata.namespace)
        {
            acc.record_explicit_service_entry(key);
        }
    }
}

pub(crate) fn service_key_from_host(
    host: &str,
    default_namespace: &str,
    cluster_domain: &str,
) -> Option<K8sServiceKey> {
    let host = normalized_service_host(host)?;
    let parts: Vec<&str> = host.split('.').collect();
    match parts.as_slice() {
        [name] => K8sServiceKey::new(default_namespace.to_string(), (*name).to_string()),
        [name, namespace] if *namespace == default_namespace => {
            K8sServiceKey::new((*namespace).to_string(), (*name).to_string())
        }
        [_, _] => None,
        [name, namespace, "svc"] => {
            K8sServiceKey::new((*namespace).to_string(), (*name).to_string())
        }
        [name, namespace, "svc", rest @ ..] => {
            let suffix = rest.join(".");
            let cluster_domain = cluster_domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if suffix.eq_ignore_ascii_case(&cluster_domain) {
                K8sServiceKey::new((*namespace).to_string(), (*name).to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn workload_entry_service_key_from_host(
    host: &str,
    default_namespace: &str,
    cluster_domain: &str,
) -> Option<K8sServiceKey> {
    service_key_from_host(host, default_namespace, cluster_domain)
}

fn normalized_service_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.contains('*') {
        return None;
    }
    Some(host.to_string())
}

pub(crate) fn invalid_resource(
    object: &K8sObject,
    message: impl Into<String>,
) -> K8sTranslateError {
    K8sTranslateError::InvalidResource {
        kind: object.kind.clone(),
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
        message: message.into(),
    }
}

pub(crate) fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

pub(crate) fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn string_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
        .collect()
}

pub(crate) fn port_from_u64(
    object: &K8sObject,
    raw: u64,
    field: &str,
) -> Result<u16, K8sTranslateError> {
    if raw == 0 || raw > u16::MAX as u64 {
        return Err(invalid_resource(
            object,
            format!("{field} must be between 1 and 65535 (got {raw})"),
        ));
    }
    Ok(raw as u16)
}

pub(crate) fn optional_port_field(
    object: &K8sObject,
    value: Option<&Value>,
    field: &str,
) -> Result<Option<u16>, K8sTranslateError> {
    value
        .and_then(Value::as_u64)
        .map(|raw| port_from_u64(object, raw, field))
        .transpose()
}

pub(crate) fn optional_target_weight_field(
    object: &K8sObject,
    value: &Value,
    field: &str,
    default: u32,
) -> Result<u32, K8sTranslateError> {
    value
        .get("weight")
        .map(|weight| target_weight_from_value(object, weight, field))
        .unwrap_or(Ok(default))
}

pub(crate) fn target_weight_from_value(
    object: &K8sObject,
    value: &Value,
    field: &str,
) -> Result<u32, K8sTranslateError> {
    let Some(weight) = value.as_u64() else {
        return Err(invalid_resource(
            object,
            format!("{field} must be between 0 and {MAX_TARGET_WEIGHT} (got {value})"),
        ));
    };
    if weight > u64::from(MAX_TARGET_WEIGHT) {
        return Err(invalid_resource(
            object,
            format!("{field} must be between 0 and {MAX_TARGET_WEIGHT} (got {weight})"),
        ));
    }
    Ok(weight as u32)
}

pub(crate) fn selector_from_istio(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(|selector| selector.get("matchLabels"))
        .map(string_map)
        .unwrap_or_default()
}

/// Parse an Istio `selector` only when it contains at least one match label.
/// Istio classifies both JSON `null` and an explicit empty `matchLabels` map as
/// namespace/mesh scope; centralizing that rule keeps translation and status
/// reporting aligned.
pub(crate) fn workload_selector_from_istio(
    value: Option<&Value>,
    namespace: Option<String>,
) -> Option<WorkloadSelector> {
    let value = value.filter(|selector| !selector.is_null())?;
    let selector = WorkloadSelector {
        labels: selector_from_istio(Some(value)),
        namespace,
    };
    selector.has_labels().then_some(selector)
}

pub(crate) fn sidecar_selector_from_istio(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(|selector| {
            selector
                .get("labels")
                .or_else(|| selector.get("matchLabels"))
        })
        .map(string_map)
        .unwrap_or_default()
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_none_or(serde_json::Map::is_empty)
}

pub(crate) struct RouteProxySpec {
    pub id: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    pub listen_path: Option<String>,
    pub strip_listen_path: bool,
    pub preserve_host_header: bool,
    pub backend_host: String,
    pub backend_port: u16,
    pub upstream_id: Option<String>,
    pub backend_scheme: BackendScheme,
    pub listen_port: Option<u16>,
    pub retry: Option<RetryConfig>,
    pub backend_read_timeout_ms: Option<u64>,
}

pub(crate) fn proxy_for_route(spec: RouteProxySpec) -> Proxy {
    let now = Utc::now();
    Proxy {
        id: spec.id,
        name: None,
        namespace: spec.namespace,
        hosts: spec.hosts,
        listen_path: spec.listen_path,
        backend_scheme: Some(spec.backend_scheme),
        dispatch_kind: DispatchKind::default(),
        backend_host: spec.backend_host,
        backend_port: spec.backend_port,
        backend_path: None,
        strip_listen_path: spec.strip_listen_path,
        preserve_host_header: spec.preserve_host_header,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: spec.backend_read_timeout_ms.unwrap_or(30_000),
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
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
        // Derived-only: projected from DestinationRule port overrides at
        // dispatch time, never set by route translation.
        pool_http1_max_pending_requests: None,
        upstream_id: spec.upstream_id,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: spec.retry,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: spec.listen_port,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        tcp_idle_timeout_seconds: None,
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn attach_route_plugins_to_proxy(proxy: &mut Proxy, plugins: &[PluginConfig]) {
    proxy
        .plugins
        .extend(plugins.iter().map(|plugin| PluginAssociation {
            plugin_config_id: plugin.id.clone(),
        }));
}

/// Build a no-static-rules `request_transformer` whose only purpose is to
/// apply per-rule `mesh_route_dispatch` route-level transforms. Emitted by
/// the VirtualService translator on proxies that do not already carry a
/// `request_transformer` plugin so the per-context override channel
/// reaches a consumer. `apply_route_overrides: true` lets the plugin
/// accept the empty-rules config.
///
/// The id uses the translator-owned `istio-vs-req-xform-` prefix so it remains
/// recognizable and deterministic while satisfying the same resource-ID
/// grammar enforced on CP-delivered full snapshots. Namespace-qualified
/// ownership and the full proxy id keep distinct translated routes isolated.
pub(crate) fn route_request_transformer_plugin_for_proxy(
    proxy_id: &str,
    namespace: &str,
) -> PluginConfig {
    let now = Utc::now();
    PluginConfig {
        id: format!("istio-vs-req-xform-{proxy_id}"),
        plugin_name: "request_transformer".to_string(),
        namespace: namespace.to_string(),
        config: serde_json::json!({
            "rules": [],
            "apply_route_overrides": true,
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// Counterpart to [`route_request_transformer_plugin_for_proxy`] for response
/// header transforms. Same valid translator-owned prefix convention.
pub(crate) fn route_response_transformer_plugin_for_proxy(
    proxy_id: &str,
    namespace: &str,
) -> PluginConfig {
    let now = Utc::now();
    PluginConfig {
        id: format!("istio-vs-resp-xform-{proxy_id}"),
        plugin_name: "response_transformer".to_string(),
        namespace: namespace.to_string(),
        config: serde_json::json!({
            "rules": [],
            "apply_route_overrides": true,
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// Build a `request_termination` plugin config for a translated route that
/// cannot safely be represented by Ferrum's current routing dimensions.
pub(crate) fn request_termination_plugin_for_proxy(
    proxy_id: &str,
    namespace: &str,
    message: &str,
) -> PluginConfig {
    let now = Utc::now();
    PluginConfig {
        id: format!("istio-vs-rt-{proxy_id}"),
        plugin_name: "request_termination".to_string(),
        namespace: namespace.to_string(),
        config: serde_json::json!({
            "status_code": 404,
            "message": message,
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// Project an Istio `VirtualService.http[].fault` block into the per-rule
/// `FaultActionConfig` JSON shape consumed by `mesh_route_dispatch`.
/// Returns `None` when neither side (`delay` nor `abort`) yields a
/// representable action — for example, an `abort` block missing
/// `httpStatus`, or a `delay` block with an unparseable `fixedDelay`.
///
/// Used by the K8s translator to project the VS-level fault onto every
/// emitted dispatch rule (including the URI-only catch-all). Replaces the
/// historical proxy-scoped `fault_injection` plugin emission which could
/// not be collapsed with sibling routes — moving fault to the dispatch
/// rule eliminates the previous fail-closed escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteLocalFaultDelay {
    pub requested_ms: u64,
    pub applied_ms: u64,
}

impl RouteLocalFaultDelay {
    pub(crate) fn was_clamped(self) -> bool {
        self.requested_ms != self.applied_ms
    }
}

/// Resolve the effective delay for one route-local Istio fault. Istio accepts
/// durations above Ferrum's one-minute runtime cap, so those values are
/// clamped instead of silently dropping an otherwise valid fault action. The
/// translator and status writer share this predicate to keep warning/status
/// visibility in lockstep with the emitted rule.
pub(crate) fn route_local_fault_delay_for_rule(fault: &Value) -> Option<RouteLocalFaultDelay> {
    let delay_obj = fault.as_object()?.get("delay")?.as_object()?;
    let delay_str = delay_obj.get("fixedDelay")?.as_str()?;
    let requested_ms = parse_istio_duration_ms(delay_str)?;
    if requested_ms == 0 || istio_fault_percentage(delay_obj).is_none() {
        return None;
    }
    Some(RouteLocalFaultDelay {
        requested_ms,
        applied_ms: requested_ms.min(MAX_FAULT_DELAY_MS),
    })
}

pub(crate) fn route_local_fault_value_for_rule(fault: &Value) -> Option<Value> {
    let obj = fault.as_object()?;
    let mut config = serde_json::Map::new();

    if let Some(delay) = route_local_fault_delay_for_rule(fault)
        && let Some(delay_obj) = obj.get("delay").and_then(Value::as_object)
        && let Some(percentage) = istio_fault_percentage(delay_obj)
    {
        config.insert(
            "delay".to_string(),
            serde_json::json!({
                "duration_ms": delay.applied_ms,
                "percentage": percentage,
            }),
        );
    }

    if let Some(abort_obj) = obj.get("abort").and_then(Value::as_object)
        && let Some(percentage) = istio_fault_percentage(abort_obj)
    {
        let mut abort_value = serde_json::Map::new();
        abort_value.insert("percentage".to_string(), serde_json::json!(percentage));

        if let Some(status) = abort_obj.get("httpStatus").and_then(Value::as_u64)
            && (200..=599).contains(&status)
        {
            abort_value.insert("status_code".to_string(), serde_json::json!(status));
        }

        if let Some(grpc) = abort_obj
            .get("grpcStatus")
            .and_then(parse_istio_grpc_status)
        {
            abort_value.insert("grpc_status".to_string(), serde_json::json!(grpc));
        }

        // Per-rule abort requires status_code (the plugin's validator rejects
        // a status-less abort). Skip the abort sub-field if absent so a
        // standalone delay still projects.
        if abort_value.contains_key("status_code") {
            config.insert("abort".to_string(), Value::Object(abort_value));
        }
    }

    if config.is_empty() {
        return None;
    }
    Some(Value::Object(config))
}

#[derive(Clone, Copy)]
pub(crate) struct MeshRouteDispatchDestination<'a> {
    pub backend_host: &'a str,
    pub backend_port: u16,
    pub upstream_id: Option<&'a str>,
    pub requires_node_waypoint_authz: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct MeshRouteDispatchPolicy<'a> {
    pub timeout_ms: Option<u64>,
    pub timeout_disabled: bool,
    pub retry: Option<&'a RetryConfig>,
    pub retry_disabled: bool,
    /// Pre-shaped fault JSON to project onto every emitted dispatch rule.
    /// `None` when the source `http[]` entry has no `fault` block or when
    /// the fault block has nothing the per-rule action can represent
    /// (e.g., abort without `httpStatus`). Cloned per emitted rule via
    /// [`Value::clone`].
    pub fault: Option<&'a Value>,
    /// Pre-shaped `rewrite` JSON (Istio `http[].rewrite`) projected onto every
    /// emitted dispatch rule so a URI / authority rewrite follows the matched
    /// route through route-collapse. `None` when the `http[]` entry has no
    /// `rewrite` block. Cloned per emitted rule via [`Value::clone`].
    pub rewrite: Option<&'a Value>,
    /// Pre-shaped `redirect` JSON (Istio `http[].redirect`) projected onto
    /// every emitted dispatch rule so a redirecting route short-circuits at
    /// dispatch time. `None` when the `http[]` entry has no `redirect` block.
    /// Cloned per emitted rule via [`Value::clone`].
    pub redirect: Option<&'a Value>,
}

/// Translate a VirtualService `http[]` entry's `match[]` blocks into a
/// `mesh_route_dispatch` plugin instance for the route's proxy.
///
/// Each in-scope `match[]` entry becomes one rule. URI predicates are
/// already captured at the proxy level via `listen_path`, so this helper
/// extracts only the non-URI predicates (`method`, `headers`,
/// `queryParams`). If no in-scope match entry has non-URI predicates,
/// returns `None` — no plugin emitted.
///
/// `listen_path` scopes the in-scope entries to this proxy: a `match[]`
/// entry with a `uri` predicate only contributes to the proxy whose
/// `listen_path` was derived from that same URI. URI-less entries (Istio
/// "any URI with these predicates") apply to every proxy emitted from
/// this `http[]` rule. Without this scoping, a `[{uri:/a}, {uri:/b,
/// headers:...}]` `match[]` would bleed the `/b` header rule into the
/// `/a` proxy, and the second P1 below would also fire.
///
/// `reject_unmatched` is forced to `false` when any in-scope entry is
/// URI-only. Istio `match[]` entries are ORed: a URI-only entry is an
/// unconditional catch-all for its listen_path, so requests that miss
/// every other predicate must still be allowed to fall through to the
/// proxy's default backend. With `reject_unmatched: true` and a URI-only
/// sibling silently dropped, plain `/api` traffic on a `[{uri:/api},
/// {uri:/api, headers:...}]` `match[]` would 404. When every in-scope
/// entry carries non-URI predicates, `reject_unmatched: true` is kept so
/// e.g. a GET-only route does not silently serve POST traffic.
///
/// Entries carrying predicates we cannot represent in the rule
/// (`method.regex` / `.prefix`, `headers.X.regex` / `.prefix`,
/// `queryParams.X.regex`, or fully-unsupported keys like `scheme`, `port`,
/// `sourceLabels`, `gateways`, `withoutHeaders`) are skipped by the
/// dispatch-rule extractor — they do NOT collapse onto the URI-only
/// catch-all branch. The VirtualService translator emits a separate
/// proxy-scoped `request_termination` artifact for
/// unsupported-only route candidates so later broader routes do not silently
/// serve gated traffic. If unsupported entries collapsed here, a mixed
/// `match[]` with one supported exact rule plus one unsupported regex sibling
/// would disable `reject_unmatched` and silently forward exactly the requests
/// the operator gated. `authority` is supported as a first-class
/// `StringMatch` predicate (exact / prefix / regex), `sourceNamespace`
/// is supported as a first-class exact-string predicate (the request hot
/// path resolves the source workload namespace from `ctx.peer_spiffe_id`),
/// and `ignoreUriCase: true` is also first-class (T1-B.5) for exact/prefix
/// URI matches: the URI's listen_path is widened to a case-insensitive
/// regex and the dispatch rule carries the flag so the plugin re-evaluates
/// with ASCII case folding. Regex URI matches keep their operator-supplied
/// regex semantics; Istio documents `ignoreUriCase` as exact/prefix-only.
///
/// The rule's destination overrides to the route's own destination
/// (`backend_host`/`backend_port` or `upstream_id`). The destination is
/// effectively the proxy's default backend, so the override is a no-op for
/// the single-route case. The plugin is still emitted so:
///   1. Predicate config is captured and visible via the admin API.
///   2. Future enhancements (multi-destination canary routing collapsing
///      multiple `http[]` entries into one proxy + multi-rule plugin) reuse
///      the same plugin contract.
#[allow(dead_code)]
pub(crate) fn mesh_route_dispatch_plugin_for_proxy(
    proxy_id: &str,
    namespace: &str,
    http: &Value,
    listen_path: Option<&str>,
    destination: MeshRouteDispatchDestination<'_>,
    policy: MeshRouteDispatchPolicy<'_>,
    prepend_rules: &[Value],
) -> Option<PluginConfig> {
    let (mut rules, has_uri_only_match) =
        mesh_route_dispatch_rules_for_proxy(http, listen_path, destination, policy, false);
    if !prepend_rules.is_empty() {
        let mut combined = Vec::with_capacity(prepend_rules.len() + rules.len());
        combined.extend(prepend_rules.iter().cloned());
        combined.append(&mut rules);
        rules = combined;
    }
    if rules.is_empty() {
        return None;
    }

    let current_route_has_rules = rules.len() > prepend_rules.len();
    let reject_unmatched = current_route_has_rules && !has_uri_only_match;

    mesh_route_dispatch_plugin_from_rules(proxy_id, namespace, rules, reject_unmatched)
}

#[allow(dead_code)]
pub(crate) fn mesh_route_dispatch_uri_less_rules(
    http: &Value,
    destination: MeshRouteDispatchDestination<'_>,
    policy: MeshRouteDispatchPolicy<'_>,
) -> Vec<Value> {
    mesh_route_dispatch_rules_for_proxy(http, None, destination, policy, true).0
}

pub(crate) fn mesh_route_dispatch_rules_for_proxy(
    http: &Value,
    listen_path: Option<&str>,
    route_destination: MeshRouteDispatchDestination<'_>,
    route_policy: MeshRouteDispatchPolicy<'_>,
    uri_less_only: bool,
) -> (Vec<Value>, bool) {
    // VirtualService `headers.{request,response}.{set,add,remove}` is a
    // per-http[] (not per-match) block. Project it onto each emitted rule so
    // the same transforms fire regardless of which match-branch wins. The
    // mesh_route_dispatch plugin parses and validates these at construction
    // time; we only emit the JSON shape here.
    //
    // Extract transforms BEFORE the match-check early returns so that a
    // matchless http[] entry with header transforms still reaches the
    // `needs_catch_all` block below instead of being silently dropped.
    let route_request_transform = vs_route_header_transform_rules(http, "request");
    let route_response_transform = vs_route_header_transform_rules(http, "response");
    let has_route_actions = !route_request_transform.is_empty()
        || !route_response_transform.is_empty()
        || route_policy.fault.is_some()
        || route_policy.rewrite.is_some()
        || route_policy.redirect.is_some();

    let empty_matches = Vec::new();
    let matches = http
        .get("match")
        .and_then(Value::as_array)
        .unwrap_or(&empty_matches);
    if matches.is_empty() && !has_route_actions {
        return (Vec::new(), false);
    }

    let mut rules = Vec::new();
    let mut has_uri_only_match = matches.is_empty();
    for entry in matches {
        if uri_less_only && entry.get("uri").is_some() {
            continue;
        }

        // Scope to this proxy's listen_path. A match entry with a parseable
        // URI applies only to the proxy whose listen_path was built from
        // that URI; entries without a URI (or with an unsupported URI
        // shape, which never produces a proxy) apply to every listen_path
        // derived from this http[] rule and are not filtered out here.
        // `entry_listen_path` widens exact/prefix URI entries to the
        // case-insensitive regex form when `ignoreUriCase: true` is set,
        // matching the listen_path key `match_paths` produced for the proxy
        // (T1-B.5). Collapsed route-order cases may deliberately install a
        // case-sensitive sibling on that widened proxy too, so overlap is
        // accepted in addition to exact listen_path equality.
        let entry_path = istio::entry_listen_path(entry);
        let guard_uri_only_match = entry_path
            .as_deref()
            .zip(listen_path)
            .is_some_and(|(entry_path, listen_path)| entry_path != listen_path);
        if let (Some(entry_path), Some(listen_path)) = (entry_path.as_deref(), listen_path)
            && entry_path != listen_path
            && !istio::listen_paths_overlap_for_route_order(
                &Some(entry_path.to_string()),
                &Some(listen_path.to_string()),
            )
        {
            continue;
        }

        // `ignoreUriCase: true` on a source entry with an exact/prefix URI —
        // we propagate the URI predicate + flag onto the dispatch rule so the
        // plugin can re-evaluate case-folded matching. Istio documents the flag
        // as exact/prefix-only; regex URI entries therefore keep their raw regex
        // semantics and do not receive `ignore_uri_case`.
        let ignore_uri_case = entry
            .get("ignoreUriCase")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut match_criteria = serde_json::Map::new();
        // Track whether this entry carries any non-URI predicate that we
        // cannot represent in the mesh_route_dispatch rule. Keep this
        // classification in one helper so path materialization and plugin
        // rule emission agree: a URI-less entry that would be skipped here
        // must not create an unguarded catch-all proxy in `match_paths`.
        let had_unsupported_predicate = mesh_route_dispatch_has_unsupported_predicate(entry);

        // Istio `StringMatch` shape: exactly one of `exact` / `prefix` /
        // `regex` should be present on the `method` entry. `exact` emits as
        // the bare-string back-compat form so older binaries (and existing
        // wire snapshots) keep deserializing it as an `Exact` matcher;
        // `prefix` and `regex` emit as the tagged form so the plugin
        // compiles them as the matching predicate type at config-load time.
        // Entries without any of the three supported keys are skipped here
        // — the entry-level `had_unsupported_predicate` flag (computed
        // up-front) ensures such an entry is dropped wholesale below, never
        // partially.
        if let Some(method_obj) = entry.get("method").and_then(Value::as_object) {
            if let Some(exact) = method_obj.get("exact").and_then(Value::as_str) {
                match_criteria.insert("methods".to_string(), serde_json::json!([exact]));
            } else if let Some(prefix) = method_obj.get("prefix").and_then(Value::as_str) {
                match_criteria.insert(
                    "methods".to_string(),
                    serde_json::json!([{"prefix": prefix}]),
                );
            } else if let Some(regex) = method_obj.get("regex").and_then(Value::as_str) {
                match_criteria.insert("methods".to_string(), serde_json::json!([{"regex": regex}]));
            }
        }

        if let Some(headers_obj) = entry.get("headers").and_then(Value::as_object) {
            let mut headers = serde_json::Map::new();
            for (name, value) in headers_obj {
                // Istio `StringMatch` shape: exactly one of `exact` / `prefix`
                // / `regex` should be present on each header entry. `exact`
                // emits as the bare-string back-compat form so older binaries
                // (and existing wire snapshots) keep deserializing it as an
                // `Exact` matcher; `prefix` and `regex` emit as the tagged
                // form so the plugin compiles them as the matching predicate
                // type at config-load time. Entries without any of the three
                // supported keys are skipped here — the entry-level
                // `had_unsupported_predicate` flag (computed up-front)
                // ensures such an entry is dropped wholesale below, never
                // partially.
                if let Some(exact) = value.get("exact").and_then(Value::as_str) {
                    headers.insert(name.to_ascii_lowercase(), Value::String(exact.to_string()));
                } else if let Some(prefix) = value.get("prefix").and_then(Value::as_str) {
                    headers.insert(
                        name.to_ascii_lowercase(),
                        serde_json::json!({ "prefix": prefix }),
                    );
                } else if let Some(regex) = value.get("regex").and_then(Value::as_str) {
                    headers.insert(
                        name.to_ascii_lowercase(),
                        serde_json::json!({ "regex": regex }),
                    );
                }
            }
            if !headers.is_empty() {
                match_criteria.insert("headers".to_string(), Value::Object(headers));
            }
        }

        if let Some(qp_obj) = entry.get("queryParams").and_then(Value::as_object) {
            let mut params = serde_json::Map::new();
            for (name, value) in qp_obj {
                if let Some(exact) = value.get("exact").and_then(Value::as_str) {
                    params.insert(name.to_string(), Value::String(exact.to_string()));
                }
            }
            if !params.is_empty() {
                match_criteria.insert("query_params".to_string(), Value::Object(params));
            }
        }

        // Istio `HTTPMatchRequest.sourceNamespace` is an exact-only string
        // predicate (no `prefix`/`regex` arms in the spec) that matches the
        // source workload's Kubernetes namespace. The hot path resolves the
        // namespace from `ctx.peer_spiffe_id` via `SpiffeId::namespace`. A
        // non-string `sourceNamespace` (object, array, bool, etc.) does not
        // match the Istio CRD shape, and empty / whitespace-only strings
        // would be rejected by the plugin's `normalize_source_namespace` at
        // config-load time; both shapes are surfaced by
        // `mesh_route_dispatch_has_unsupported_predicate`, so the entry-level
        // `had_unsupported_predicate` flag catches them below and the entry
        // is dropped wholesale via `request_termination` rather than
        // partially extracted or silently dropped at plugin-cache rebuild.
        if let Some(source_namespace) = entry.get("sourceNamespace").and_then(Value::as_str) {
            match_criteria.insert(
                "source_namespace".to_string(),
                Value::String(source_namespace.to_string()),
            );
        }

        // Istio `HTTPMatchRequest.authority` is a single `StringMatch`
        // predicate per rule (exactly one of `exact` / `prefix` / `regex`).
        // `exact` emits as the bare-string back-compat form so older
        // binaries (and existing wire snapshots) keep deserializing it as
        // an `Exact` matcher; `prefix` and `regex` emit as the tagged form
        // so the plugin compiles them as the matching predicate type at
        // config-load time. An entry whose `authority` is missing any of
        // the three supported keys is treated as unsupported via the
        // entry-level `had_unsupported_predicate` flag and dropped wholesale
        // below — never partially extracted.
        if let Some(authority_obj) = entry.get("authority").and_then(Value::as_object) {
            if let Some(exact) = authority_obj.get("exact").and_then(Value::as_str) {
                match_criteria.insert("authority".to_string(), Value::String(exact.to_string()));
            } else if let Some(prefix) = authority_obj.get("prefix").and_then(Value::as_str) {
                match_criteria.insert(
                    "authority".to_string(),
                    serde_json::json!({ "prefix": prefix }),
                );
            } else if let Some(regex) = authority_obj.get("regex").and_then(Value::as_str) {
                match_criteria.insert(
                    "authority".to_string(),
                    serde_json::json!({ "regex": regex }),
                );
            }
        }

        // T1-B.5: project the URI predicate onto the dispatch rule when
        // `ignoreUriCase: true`. The widened (case-insensitive) listen_path
        // already routes both casings to this proxy; carrying the original
        // URI predicate + the case-fold flag here keeps the operator's
        // match precision intact for collapse cases (multiple URIs on one
        // proxy) and for admin-API observability of the resolved rule.
        // When `ignoreUriCase` is false or absent, the dispatch rule does
        // NOT carry the URI — the proxy's `listen_path` already enforces
        // it case-sensitively, and adding a redundant URI predicate would
        // both pay a per-request hash + compare and cloud the operator
        // view of the resolved rule (legacy wire shape: URI absent).
        if ignore_uri_case && let Some(uri_obj) = entry.get("uri").and_then(Value::as_object) {
            let mut uri_value = serde_json::Map::new();
            if let Some(exact) = uri_obj.get("exact").and_then(Value::as_str) {
                uri_value.insert("exact".to_string(), Value::String(exact.to_string()));
            } else if let Some(prefix) = uri_obj.get("prefix").and_then(Value::as_str) {
                uri_value.insert("prefix".to_string(), Value::String(prefix.to_string()));
            }
            if !uri_value.is_empty() {
                match_criteria.insert("uri".to_string(), Value::Object(uri_value));
                match_criteria.insert("ignore_uri_case".to_string(), Value::Bool(true));
            }
        }

        if had_unsupported_predicate {
            // Entry has predicates we can't represent. Emitting a partial
            // rule would widen traffic; classifying as URI-only would
            // disable reject_unmatched and forward gated traffic. Skip the
            // entry — with reject_unmatched: true, unmatched requests get
            // a 404, which is the fail-closed VirtualService semantic.
            continue;
        }

        if guard_uri_only_match
            && !match_criteria.contains_key("uri")
            && let Some(entry_path) = entry_path.as_deref()
        {
            let Some(uri_match) = uri_match_for_listen_path(entry_path) else {
                continue;
            };
            match_criteria.insert("uri".to_string(), uri_match);
        }

        if match_criteria.is_empty() {
            // In-scope entry with no non-URI predicate keys at all normally
            // means its URI already matched at proxy level, so this is an
            // unconditional catch-all branch for `listen_path`. Same-shape
            // collapse guards were inserted above before this check, so an
            // empty match here is a genuine URI-only catch-all.
            has_uri_only_match = true;
            continue;
        }

        let mut rule = serde_json::Map::new();
        rule.insert("match".to_string(), Value::Object(match_criteria));
        // A redirect-only route carries no backend (`backend_host` empty,
        // `upstream_id` none). Omit the destination so the plugin accepts the
        // redirect rule; every other rule carries the route's destination.
        if let Some(destination) = route_dispatch_destination_value(&route_destination) {
            rule.insert("destination".to_string(), Value::Object(destination));
        }
        if let Some(timeout_ms) = route_policy.timeout_ms {
            rule.insert("timeout_ms".to_string(), serde_json::json!(timeout_ms));
        } else if route_policy.timeout_disabled {
            rule.insert("timeout_disabled".to_string(), Value::Bool(true));
        }
        if let Some(retry) = route_policy.retry {
            rule.insert(
                "retry".to_string(),
                serde_json::to_value(retry).expect("RetryConfig serializes"),
            );
        } else if route_policy.retry_disabled {
            rule.insert("retry_disabled".to_string(), Value::Bool(true));
        }
        if !route_request_transform.is_empty() {
            rule.insert(
                "request_transform".to_string(),
                Value::Array(route_request_transform.clone()),
            );
        }
        if !route_response_transform.is_empty() {
            rule.insert(
                "response_transform".to_string(),
                Value::Array(route_response_transform.clone()),
            );
        }
        if let Some(fault) = route_policy.fault {
            rule.insert("fault".to_string(), fault.clone());
        }
        if let Some(rewrite) = route_policy.rewrite {
            rule.insert(
                "rewrite".to_string(),
                rewrite_value_with_match_prefix(rewrite, entry.get("uri")),
            );
        }
        if let Some(redirect) = route_policy.redirect {
            rule.insert("redirect".to_string(), redirect.clone());
        }
        rules.push(Value::Object(rule));
    }

    // URI-only catch-all carrying the http[]-level transforms. Without this,
    // a VirtualService whose `match` is purely URI-based (e.g. only
    // `{uri: {prefix: "/v1"}}`) would generate no `mesh_route_dispatch` rule
    // at all and the per-rule transform channel would have no carrier — the
    // header `set` / `add` / `remove` directives would be silently dropped.
    // The rule is emitted LAST so explicit-predicate rules (from this http[]
    // or stashed siblings) get first-match-wins evaluation; the empty match
    // is a "default" that catches every other request on this proxy. Per-rule
    // policy (timeout / retry) and destination are carried so the catch-all
    // behaves like the regular path. `route_destination` and `route_policy`
    // already describe the proxy's default backend, so the catch-all is a
    // semantic no-op for routing — its sole purpose is to publish the
    // transform Arcs onto `RequestContext`.
    let needs_catch_all = has_uri_only_match
        && (!route_request_transform.is_empty()
            || !route_response_transform.is_empty()
            || route_policy.fault.is_some()
            || route_policy.rewrite.is_some()
            || route_policy.redirect.is_some());
    if needs_catch_all {
        let mut rule = serde_json::Map::new();
        rule.insert("match".to_string(), Value::Object(serde_json::Map::new()));
        if let Some(destination) = route_dispatch_destination_value(&route_destination) {
            rule.insert("destination".to_string(), Value::Object(destination));
        }
        if let Some(timeout_ms) = route_policy.timeout_ms {
            rule.insert("timeout_ms".to_string(), serde_json::json!(timeout_ms));
        } else if route_policy.timeout_disabled {
            rule.insert("timeout_disabled".to_string(), Value::Bool(true));
        }
        if let Some(retry) = route_policy.retry {
            rule.insert(
                "retry".to_string(),
                serde_json::to_value(retry).expect("RetryConfig serializes"),
            );
        } else if route_policy.retry_disabled {
            rule.insert("retry_disabled".to_string(), Value::Bool(true));
        }
        if !route_request_transform.is_empty() {
            rule.insert(
                "request_transform".to_string(),
                Value::Array(route_request_transform),
            );
        }
        if !route_response_transform.is_empty() {
            rule.insert(
                "response_transform".to_string(),
                Value::Array(route_response_transform),
            );
        }
        if let Some(fault) = route_policy.fault {
            rule.insert("fault".to_string(), fault.clone());
        }
        if let Some(rewrite) = route_policy.rewrite {
            // The catch-all rule matches the proxy's whole `listen_path`. When
            // that listen_path is a literal prefix, Istio prefix-rewrite
            // semantics strip exactly that prefix; otherwise (exact / regex /
            // root) the whole path is replaced.
            rule.insert(
                "rewrite".to_string(),
                rewrite_value_with_match_prefix_from_listen_path(rewrite, listen_path),
            );
        }
        if let Some(redirect) = route_policy.redirect {
            rule.insert("redirect".to_string(), redirect.clone());
        }
        rules.push(Value::Object(rule));
    }

    (rules, has_uri_only_match)
}

/// Clone a `rewrite` template JSON and fill in `match_prefix` from the source
/// match entry's `uri.prefix`. Istio prefix-rewrite replaces only the matched
/// prefix; exact / regex / URI-less matches replace the whole path, so
/// `match_prefix` is omitted (the plugin replaces the full path).
fn rewrite_value_with_match_prefix(rewrite: &Value, uri_match: Option<&Value>) -> Value {
    let prefix = uri_match
        .and_then(Value::as_object)
        .and_then(|uri| uri.get("prefix"))
        .and_then(Value::as_str);
    rewrite_value_with_optional_prefix(rewrite, prefix)
}

/// Catch-all variant: derive the prefix from the proxy `listen_path`. Ferrum's
/// listen_path encoding uses `~` for regex and `=` for exact; a bare value is a
/// literal prefix. Only the literal-prefix form yields a `match_prefix`.
fn rewrite_value_with_match_prefix_from_listen_path(
    rewrite: &Value,
    listen_path: Option<&str>,
) -> Value {
    let prefix = listen_path
        .filter(|lp| !lp.starts_with('~') && !lp.starts_with('=') && !lp.is_empty() && *lp != "/");
    rewrite_value_with_optional_prefix(rewrite, prefix)
}

/// Build the `destination` JSON for a dispatch rule from the route's resolved
/// backend. Returns `None` for a redirect-only route (no upstream and an empty
/// backend host) so the emitted rule omits the destination — the plugin
/// accepts a destination-less rule only when it carries a redirect.
fn route_dispatch_destination_value(
    route_destination: &MeshRouteDispatchDestination<'_>,
) -> Option<serde_json::Map<String, Value>> {
    let mut destination = serde_json::Map::new();
    if let Some(uid) = route_destination.upstream_id {
        destination.insert("upstream_id".to_string(), Value::String(uid.to_string()));
    } else if !route_destination.backend_host.is_empty() {
        destination.insert(
            "backend_host".to_string(),
            Value::String(route_destination.backend_host.to_string()),
        );
        destination.insert(
            "backend_port".to_string(),
            serde_json::json!(route_destination.backend_port),
        );
    } else {
        return None;
    }
    if route_destination.requires_node_waypoint_authz {
        destination.insert(
            "requires_node_waypoint_authz".to_string(),
            Value::Bool(true),
        );
    }
    Some(destination)
}

fn rewrite_value_with_optional_prefix(rewrite: &Value, prefix: Option<&str>) -> Value {
    let mut value = rewrite.clone();
    if let (Some(prefix), Some(obj)) = (prefix, value.as_object_mut()) {
        obj.insert(
            "match_prefix".to_string(),
            Value::String(prefix.to_string()),
        );
    }
    value
}

fn uri_match_for_listen_path(listen_path: &str) -> Option<Value> {
    if let Some(path) = listen_path.strip_prefix('=') {
        return Some(serde_json::json!({ "exact": path }));
    }
    if listen_path.starts_with('~') {
        return None;
    }
    Some(serde_json::json!({ "prefix": listen_path }))
}

/// Extract `headers.{direction}.{set,add,remove}` from a VirtualService
/// `http[]` entry into the canonical transformer rule JSON shape (the same
/// shape the `request_transformer` / `response_transformer` plugins accept).
/// `direction` is `"request"` or `"response"`.
pub(crate) fn vs_route_header_transform_rules(http: &Value, direction: &str) -> Vec<Value> {
    let Some(headers) = http
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|h| h.get(direction))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let set = headers.get("set").and_then(Value::as_object);
    let add = headers.get("add").and_then(Value::as_object);

    // Warn (don't silently drop) when set/add contain non-string values.
    // Istio's CRD typing requires string values, but a hand-rolled
    // VirtualService JSON like `{"X-Count": 42}` will deserialize into a
    // serde_json::Number that the route-header parser cannot use. Surface
    // the loss instead of silently applying less than what the operator
    // wrote (CLAUDE.md "no silent behavior changes").
    if let Some(set_map) = set {
        for (key, value) in set_map {
            if !value.is_string() {
                tracing::warn!(
                    direction = direction,
                    header = %key,
                    value_kind = ?value,
                    "VirtualService headers.{}.set entry has non-string value; entry will be dropped",
                    direction,
                );
            }
        }
    }
    if let Some(add_map) = add {
        for (key, value) in add_map {
            if !value.is_string() {
                tracing::warn!(
                    direction = direction,
                    header = %key,
                    value_kind = ?value,
                    "VirtualService headers.{}.add entry has non-string value; entry will be dropped",
                    direction,
                );
            }
        }
    }

    let remove = headers.get("remove").and_then(Value::as_array).map(|arr| {
        let mut names = Vec::with_capacity(arr.len());
        for entry in arr {
            match entry.as_str() {
                Some(name) => names.push(name.to_string()),
                None => {
                    tracing::warn!(
                        direction = direction,
                        value_kind = ?entry,
                        "VirtualService headers.{}.remove entry is not a string; entry will be dropped",
                        direction,
                    );
                }
            }
        }
        names
    });
    crate::plugins::utils::route_header_transform::route_header_transform_rules_to_json(
        set,
        add,
        remove.as_deref(),
    )
}

pub(crate) fn mesh_route_dispatch_plugin_from_rules(
    proxy_id: &str,
    namespace: &str,
    rules: Vec<Value>,
    reject_unmatched: bool,
) -> Option<PluginConfig> {
    if rules.is_empty() {
        return None;
    }
    let now = Utc::now();
    Some(PluginConfig {
        id: format!("istio-vs-mrd-{proxy_id}"),
        plugin_name: "mesh_route_dispatch".to_string(),
        namespace: namespace.to_string(),
        // `reject_unmatched: true` enforces VirtualService match semantics:
        // a route whose `match[]` specifies `method`/`headers`/`queryParams`
        // must not serve requests that miss those predicates via the proxy's
        // default backend. Without this, e.g., a GET-only route would
        // silently forward POST traffic to the same upstream.
        //
        // It flips to `false` when any in-scope entry is URI-only -- that
        // entry is an unconditional ORed match for this listen_path, so
        // unmatched requests must fall through to the default backend
        // rather than 404. See the function docstring for the full
        // rationale and the regression scenarios this guards against.
        config: serde_json::json!({
            "rules": rules,
            "reject_unmatched": reject_unmatched,
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
}

/// Returns `true` if the `method` value object carries one of the predicate
/// operators that `mesh_route_dispatch` supports today. Method `StringMatch`
/// support tracks Istio: `exact`, `prefix`, `regex`.
fn method_value_has_supported_predicate(value: &Value) -> bool {
    string_match_has_exactly_one_supported_operator(value, &["exact", "prefix", "regex"])
}

/// Returns `true` if any header value object carries one of the predicate
/// operators that `mesh_route_dispatch` supports today. Header `StringMatch`
/// support tracks Istio: `exact`, `prefix`, `regex`.
fn header_value_has_supported_predicate(value: &Value) -> bool {
    string_match_has_exactly_one_supported_operator(value, &["exact", "prefix", "regex"])
}

/// Returns `true` if the `authority` value object carries one of the
/// predicate operators that `mesh_route_dispatch` supports today. Authority
/// `StringMatch` support tracks Istio: `exact`, `prefix`, `regex`. The Istio
/// CRD models `authority` as exactly one predicate per rule (NOT a list),
/// so this mirrors the single-field shape rather than the headers / query
/// params collection shape.
fn authority_value_has_supported_predicate(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != 1 {
        return false;
    }
    let Some((key, value)) = obj.iter().next() else {
        return false;
    };
    if !["exact", "prefix", "regex"].contains(&key.as_str()) {
        return false;
    }
    let Some(raw) = value.as_str() else {
        return false;
    };
    if raw.is_empty() {
        return false;
    }
    if key == "regex" && regex::Regex::new(raw).is_err() {
        return false;
    }
    true
}

fn query_param_value_has_supported_predicate(value: &Value) -> bool {
    string_match_has_exactly_one_supported_operator(value, &["exact"])
}

fn string_match_has_exactly_one_supported_operator(value: &Value, allowed: &[&str]) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != 1 {
        return false;
    }
    let Some((key, value)) = obj.iter().next() else {
        return false;
    };
    allowed.contains(&key.as_str()) && value.as_str().is_some()
}

pub(crate) fn mesh_route_dispatch_has_supported_non_uri_predicate(entry: &Value) -> bool {
    if let Some(method) = entry.get("method")
        && method_value_has_supported_predicate(method)
    {
        return true;
    }
    if let Some(headers) = entry.get("headers").and_then(Value::as_object)
        && headers.values().any(header_value_has_supported_predicate)
    {
        return true;
    }
    if let Some(qp) = entry.get("queryParams").and_then(Value::as_object)
        && qp.values().any(query_param_value_has_supported_predicate)
    {
        return true;
    }
    // `sourceNamespace` is a string-typed exact predicate in the Istio CRD;
    // when it's a non-empty, non-whitespace string we can carry it through to
    // the plugin. Empty / whitespace-only strings and non-string shapes fall
    // through to `mesh_route_dispatch_has_unsupported_predicate` and fail
    // closed via `request_termination`. Without that guard, the plugin's
    // construction-time validation in `normalize_source_namespace` would
    // reject the whole rule and the plugin would be silently dropped at
    // cache rebuild, defeating `reject_unmatched: true` and letting traffic
    // the operator intended to gate flow to the default backend.
    if entry
        .get("sourceNamespace")
        .and_then(Value::as_str)
        .is_some_and(|ns| !ns.is_empty() && !ns.chars().all(char::is_whitespace))
    {
        return true;
    }
    if let Some(authority) = entry.get("authority")
        && authority_value_has_supported_predicate(authority)
    {
        return true;
    }
    false
}

pub(crate) fn mesh_route_dispatch_has_unsupported_predicate(entry: &Value) -> bool {
    if let Some(ignore_uri_case) = entry.get("ignoreUriCase")
        && ignore_uri_case.as_bool().is_none()
    {
        // T1-B.5: `ignoreUriCase: true` is now first-class (handled by the
        // `mesh_route_dispatch` plugin via `match.uri` + `ignore_uri_case`).
        // A non-bool value (e.g. a typo `ignoreUriCase: "true"`) is still
        // an operator misconfiguration we fail closed on — the K8s CRD
        // schema would reject a non-bool, but defensive coding catches
        // unvalidated inputs from native MeshSubscribe.
        return true;
    }

    // Method `StringMatch` supports `exact` / `prefix` / `regex`. Any other
    // shape (missing op, unknown op, non-string value, non-object method
    // entry) is treated as an unsupported predicate so the route falls
    // closed via `request_termination` rather than silently widening
    // traffic.
    if let Some(method) = entry.get("method")
        && !method_value_has_supported_predicate(method)
    {
        return true;
    }

    if let Some(headers) = entry.get("headers") {
        let Some(headers) = headers.as_object() else {
            return true;
        };
        // Header `StringMatch` supports `exact` / `prefix` / `regex`. Any
        // other shape (missing op, unknown op, non-string value) is treated
        // as an unsupported predicate so the route falls closed via
        // `request_termination` rather than silently widening traffic.
        if headers
            .values()
            .any(|v| !header_value_has_supported_predicate(v))
        {
            return true;
        }
    }

    if let Some(qp) = entry.get("queryParams") {
        let Some(qp) = qp.as_object() else {
            return true;
        };
        if qp
            .values()
            .any(|v| !query_param_value_has_supported_predicate(v))
        {
            return true;
        }
    }

    // `sourceNamespace` is exact-only per the Istio CRD (a bare string). Any
    // other JSON shape (object with operator keys, array, bool, number) is
    // outside the CRD contract and treated as unsupported so the route falls
    // closed via `request_termination` rather than silently widening. The
    // same fail-closed treatment applies to empty / whitespace-only strings:
    // the plugin's construction-time validation in `normalize_source_namespace`
    // rejects those, and without classifying them as unsupported here the
    // plugin would be silently dropped at cache rebuild and `reject_unmatched`
    // would no longer fire.
    if let Some(source_ns) = entry.get("sourceNamespace") {
        match source_ns.as_str() {
            Some(ns) if !ns.is_empty() && !ns.chars().all(char::is_whitespace) => {}
            _ => return true,
        }
    }

    // Authority `StringMatch` supports `exact` / `prefix` / `regex`. Any other
    // shape (non-object, missing every supported op, unknown op only) is
    // treated as an unsupported predicate so the route falls closed via
    // `request_termination` rather than silently widening traffic.
    if let Some(authority) = entry.get("authority") {
        if !authority.is_object() {
            return true;
        }
        if !authority_value_has_supported_predicate(authority) {
            return true;
        }
    }

    entry.as_object().is_some_and(|obj| {
        obj.keys().any(|key| {
            matches!(
                key.as_str(),
                "scheme" | "port" | "sourceLabels" | "gateways" | "withoutHeaders"
            )
        })
    })
}

pub(crate) fn mesh_route_dispatch_can_emit_rule(entry: &Value) -> bool {
    mesh_route_dispatch_has_supported_non_uri_predicate(entry)
        && !mesh_route_dispatch_has_unsupported_predicate(entry)
}

/// Parse an Istio duration string to milliseconds. Supports the same suffix
/// set as Go's `time.ParseDuration` (`ns`, `us`, `ms`, `s`, `m`, `h`); Istio's
/// CRDs expose this format via `google.protobuf.Duration`'s string form
/// (e.g., `"5s"`, `"500ms"`, `"30m"`, `"1.5h"`). Positive sub-millisecond
/// inputs round up to 1 ms so duration-based policy fields do not disappear.
pub(crate) fn parse_istio_duration_ms(duration: &str) -> Option<u64> {
    let trimmed = duration.trim();
    // 2-char suffixes first so they aren't shadowed by the trailing `s` or `m`.
    if let Some(s) = trimmed.strip_suffix("ms") {
        return duration_component_ms(s, 1.0);
    }
    if let Some(s) = trimmed.strip_suffix("us") {
        return duration_component_ms(s, 0.001);
    }
    if let Some(s) = trimmed.strip_suffix("ns") {
        return duration_component_ms(s, 0.000_001);
    }
    if let Some(s) = trimmed.strip_suffix('s') {
        return duration_component_ms(s, 1000.0);
    }
    if let Some(s) = trimmed.strip_suffix('m') {
        return duration_component_ms(s, 60_000.0);
    }
    if let Some(s) = trimmed.strip_suffix('h') {
        return duration_component_ms(s, 3_600_000.0);
    }
    None
}

fn duration_component_ms(raw: &str, multiplier: f64) -> Option<u64> {
    let value: f64 = raw.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let ms = value * multiplier;
    if !ms.is_finite() || ms > u64::MAX as f64 {
        return None;
    }
    if ms > 0.0 && ms < 1.0 {
        Some(1)
    } else {
        Some(ms as u64)
    }
}

/// Extract an Istio fault percentage in the range (0.0, 100.0]. Accepts both
/// the nested `percentage.value` (Istio's `Percent` message) and the legacy
/// `percent` integer field. Returns `None` for omitted, zero, or out-of-range
/// values so the caller can skip emitting a sub-field that the
/// `fault_injection` plugin would reject (`parse_percentage` rejects 0.0 and
/// anything outside 0–100 inclusive).
fn istio_fault_percentage(obj: &serde_json::Map<String, Value>) -> Option<f64> {
    let raw = obj
        .get("percentage")
        .and_then(|p| p.get("value"))
        .and_then(Value::as_f64)
        .or_else(|| obj.get("percent").and_then(Value::as_f64));
    let pct = raw.unwrap_or(100.0);
    if pct.is_finite() && pct > 0.0 && pct <= 100.0 {
        Some(pct)
    } else {
        None
    }
}

/// Translate Istio's `grpcStatus` field (per
/// <https://github.com/grpc/grpc/blob/master/doc/statuscodes.md>) into the
/// numeric `0..=16` form expected by the `fault_injection` plugin. Accepts the
/// canonical string name (`"UNAVAILABLE"`), the same name with hyphens, or a
/// numeric literal. Returns `None` for unknown / out-of-range input rather
/// than emitting a plugin config the plugin constructor would reject.
fn parse_istio_grpc_status(value: &Value) -> Option<u32> {
    if let Some(code) = value.as_u64() {
        return u32::try_from(code).ok().filter(|c| *c <= 16);
    }
    let raw = value.as_str()?.trim();
    if let Ok(code) = raw.parse::<u32>() {
        return if code <= 16 { Some(code) } else { None };
    }
    let normalized = raw.replace('-', "_").to_ascii_uppercase();
    match normalized.as_str() {
        "OK" => Some(0),
        "CANCELLED" | "CANCELED" => Some(1),
        "UNKNOWN" => Some(2),
        "INVALID_ARGUMENT" => Some(3),
        "DEADLINE_EXCEEDED" => Some(4),
        "NOT_FOUND" => Some(5),
        "ALREADY_EXISTS" => Some(6),
        "PERMISSION_DENIED" => Some(7),
        "RESOURCE_EXHAUSTED" => Some(8),
        "FAILED_PRECONDITION" => Some(9),
        "ABORTED" => Some(10),
        "OUT_OF_RANGE" => Some(11),
        "UNIMPLEMENTED" => Some(12),
        "INTERNAL" => Some(13),
        "UNAVAILABLE" => Some(14),
        "DATA_LOSS" => Some(15),
        "UNAUTHENTICATED" => Some(16),
        _ => None,
    }
}

pub(crate) struct RouteBackend {
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub service_namespace: Option<String>,
    pub service_name: Option<String>,
    pub service_port: Option<u16>,
}

pub(crate) fn route_backends_require_node_waypoint_authz(backends: &[RouteBackend]) -> bool {
    backends.iter().any(|backend| {
        backend.service_namespace.is_some()
            && backend.service_name.is_some()
            && backend.service_port.is_some()
    })
}

pub(crate) fn upstream_for_route(
    id: String,
    namespace: String,
    backends: Vec<RouteBackend>,
) -> Upstream {
    let now = Utc::now();
    let first_weight = backends.first().map(|backend| backend.weight).unwrap_or(1);
    let has_weighted_target = backends
        .iter()
        .any(|backend| backend.weight != first_weight);
    Upstream {
        id: id.clone(),
        name: Some(id),
        namespace,
        targets: backends
            .into_iter()
            .map(|backend| {
                let mut tags = HashMap::new();
                if let (Some(namespace), Some(name), Some(port)) = (
                    backend.service_namespace.as_ref(),
                    backend.service_name.as_ref(),
                    backend.service_port,
                ) {
                    tags.insert(
                        UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG.to_string(),
                        namespace.clone(),
                    );
                    tags.insert(UPSTREAM_TARGET_SERVICE_NAME_TAG.to_string(), name.clone());
                    tags.insert(
                        UPSTREAM_TARGET_SERVICE_PORT_TAG.to_string(),
                        port.to_string(),
                    );
                }
                UpstreamTarget {
                    host: backend.host,
                    port: backend.port,
                    service_port_policy_key: backend.service_port,
                    weight: backend.weight,
                    tags,
                    locality: None,
                    path: None,
                }
            })
            .collect(),
        algorithm: if has_weighted_target {
            LoadBalancerAlgorithm::WeightedRoundRobin
        } else {
            LoadBalancerAlgorithm::RoundRobin
        },
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn service_dns_name(name: &str, namespace: &str, cluster_domain: &str) -> String {
    format!("{name}.{namespace}.svc.{cluster_domain}")
}

pub(crate) fn exact_path_listen_path(path: &str) -> String {
    format!("={path}")
}

pub(crate) fn resource_id(prefix: &str, namespace: &str, name: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        format!("{prefix}-{namespace}-{name}")
    } else {
        format!("{prefix}-{namespace}-{name}-{suffix}")
    }
    .replace(['/', '.'], "-")
}

/// Build a `(namespace, id)` ownership key, failing closed on empty components.
///
/// K8s-generated IDs are lossy across dashed namespace/name joins, and ordinary
/// IDs are only unique within a namespace, so ownership maps must never fall
/// back to a delimiter-encoded bare string.
pub(crate) fn namespaced_resource_key(namespace: &str, id: &str) -> Option<NamespacedResourceId> {
    if namespace.is_empty() || id.is_empty() {
        return None;
    }
    Some(NamespacedResourceId::new(namespace, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn options(namespace: &str) -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            namespace.to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    #[test]
    fn rejects_envoy_filter_fail_closed() {
        let err = translate_k8s_objects(
            &[object("EnvoyFilter", serde_json::json!({}))],
            options("default"),
        )
        .expect_err("EnvoyFilter must fail closed");

        assert!(
            err.to_string()
                .contains("EnvoyFilter is intentionally unsupported")
        );
    }

    #[test]
    fn filters_resources_by_namespace() {
        let ignored = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let result =
            translate_k8s_objects(&[ignored], options("prod")).expect("translation should succeed");

        assert!(result.config.mesh.is_none());
    }

    #[test]
    fn gateway_class_is_status_only_not_unsupported_translation_input() {
        let mut gateway_class = object(
            "GatewayClass",
            serde_json::json!({"controllerName": "ferrum.io/gateway-controller"}),
        );
        gateway_class.api_version = "gateway.networking.k8s.io/v1".to_string();
        gateway_class.metadata.namespace.clear();
        let options = options("default").with_source_namespaces(Vec::new());

        let result =
            translate_k8s_objects(&[gateway_class], options).expect("translation should succeed");

        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("GatewayClass"))
        );
    }

    #[test]
    fn controller_can_disable_source_namespace_filter() {
        let object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let options = options("ferrum").with_source_namespaces(Vec::new());

        let result = translate_k8s_objects(&[object], options).expect("translation should succeed");

        assert!(result.config.mesh.is_some());
    }

    #[test]
    fn translation_records_included_source_namespaces() {
        let mut default_object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        default_object.metadata.namespace = "default".to_string();
        let mut prod_object = default_object.clone();
        prod_object.metadata.namespace = "prod".to_string();
        let mut ignored_object = default_object.clone();
        ignored_object.metadata.namespace = "ignored".to_string();
        let options = options("ferrum")
            .with_source_namespaces(vec!["default".to_string(), "prod".to_string()]);

        let result = translate_k8s_objects(&[default_object, prod_object, ignored_object], options)
            .expect("translation should succeed");

        assert_eq!(
            result.config.known_namespaces,
            vec!["default".to_string(), "prod".to_string()]
        );
    }

    #[test]
    fn include_filter_excludes_gateway_api_conflict_candidates() {
        let mut skipped_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "skipped", "port": 8080}]
                }]
            }),
        );
        skipped_route.api_version = "gateway.networking.k8s.io/v1".to_string();
        skipped_route.metadata.name = "api-a-skipped".to_string();
        skipped_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut included_route = skipped_route.clone();
        included_route.metadata.name = "api-b-included".to_string();
        included_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());
        included_route.spec["rules"][0]["backendRefs"][0]["name"] = serde_json::json!("included");

        let result = translate_k8s_objects_with_filter(
            &[skipped_route, included_route],
            options("default"),
            |object| object.metadata.name == "api-b-included",
        )
        .expect("filtered translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(result.config.proxies[0].id.contains("api-b-included"));
        assert!(
            result.warnings.is_empty(),
            "skipped routes must not win conflicts: {:?}",
            result.warnings
        );
    }

    #[test]
    fn controller_source_namespace_filter_uses_watch_namespaces() {
        let object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let options = options("ferrum")
            .with_source_namespaces(vec!["default".to_string(), "prod".to_string()]);

        let result = translate_k8s_objects(&[object], options).expect("translation should succeed");

        assert!(result.config.mesh.is_some());
    }

    #[test]
    fn port_from_u64_enforces_kubernetes_port_boundaries() {
        let object = object("HTTPRoute", serde_json::json!({}));

        assert!(port_from_u64(&object, 0, "port").is_err());
        assert_eq!(port_from_u64(&object, 1, "port").unwrap(), 1);
        assert_eq!(port_from_u64(&object, 65_535, "port").unwrap(), 65_535);
        assert!(port_from_u64(&object, 65_536, "port").is_err());
        assert!(port_from_u64(&object, u64::MAX, "port").is_err());
    }

    #[test]
    fn service_key_from_host_accepts_unambiguous_kubernetes_service_forms() {
        assert_eq!(
            service_key_from_host("reviews", "default", "cluster.local"),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
        assert_eq!(
            service_key_from_host("reviews.default.svc", "ignored", "cluster.local"),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
        assert_eq!(
            service_key_from_host("reviews.default", "default", "cluster.local"),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
        assert_eq!(
            service_key_from_host(
                "reviews.default.svc.cluster.local.",
                "ignored",
                "cluster.local"
            ),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
        assert_eq!(
            service_key_from_host(
                "reviews.default.svc.Cluster.Local",
                "ignored",
                "cluster.local"
            ),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
    }

    #[test]
    fn service_key_from_host_preserves_service_and_namespace_case() {
        assert_eq!(
            service_key_from_host(
                "Reviews.Default.svc.cluster.local",
                "ignored",
                "cluster.local"
            ),
            Some(K8sServiceKey {
                namespace: "Default".to_string(),
                name: "Reviews".to_string(),
            })
        );
        assert_eq!(
            service_key_from_host("reviews.Default", "default", "cluster.local"),
            None
        );
    }

    #[test]
    fn service_key_from_host_rejects_ambiguous_two_label_hosts() {
        assert_eq!(
            service_key_from_host("example.com", "default", "cluster.local"),
            None
        );
        assert_eq!(
            service_key_from_host("reviews.default", "ignored", "cluster.local"),
            None
        );
        assert_eq!(
            service_key_from_host("reviews.prod", "default", "cluster.local"),
            None
        );
    }

    #[test]
    fn workload_entry_service_key_from_host_rejects_cross_namespace_two_label_refs() {
        assert_eq!(
            workload_entry_service_key_from_host("reviews.default", "default", "cluster.local",),
            Some(K8sServiceKey {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            })
        );
        assert_eq!(
            workload_entry_service_key_from_host("reviews.prod", "default", "cluster.local",),
            None
        );
        assert_eq!(
            workload_entry_service_key_from_host("reviews.prod.", "default", "cluster.local",),
            None
        );
        assert_eq!(
            workload_entry_service_key_from_host("reviews.Prod", "default", "cluster.local",),
            None
        );
    }

    #[test]
    fn workload_entry_service_key_from_host_preserves_unknown_two_label_dns_names() {
        assert_eq!(
            workload_entry_service_key_from_host("example.com", "default", "cluster.local",),
            None
        );
    }

    #[test]
    fn namespaced_resource_key_rejects_empty_components() {
        assert!(namespaced_resource_key("a", "id").is_some());
        assert!(namespaced_resource_key("", "id").is_none());
        assert!(namespaced_resource_key("a", "").is_none());
        assert!(namespaced_resource_key("", "").is_none());
    }

    #[test]
    fn upsert_proxy_keeps_same_bare_id_in_two_namespaces_and_scopes_precedence() {
        let mut acc = K8sAccumulator::new(options("ferrum").with_source_namespaces(Vec::new()));
        let shared_id = "lossy-shared-id";

        let gateway_a = proxy_for_route(RouteProxySpec {
            id: shared_id.to_string(),
            namespace: "tenant-a".to_string(),
            hosts: vec!["a.example.com".to_string()],
            listen_path: Some("/a".to_string()),
            strip_listen_path: false,
            preserve_host_header: false,
            backend_host: "a.svc".to_string(),
            backend_port: 8080,
            upstream_id: None,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
            retry: None,
            backend_read_timeout_ms: None,
        });
        let istio_b = proxy_for_route(RouteProxySpec {
            id: shared_id.to_string(),
            namespace: "tenant-b".to_string(),
            hosts: vec!["b.example.com".to_string()],
            listen_path: Some("/b".to_string()),
            strip_listen_path: false,
            preserve_host_header: false,
            backend_host: "b.svc".to_string(),
            backend_port: 8081,
            upstream_id: None,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
            retry: None,
            backend_read_timeout_ms: None,
        });
        let gateway_b = proxy_for_route(RouteProxySpec {
            id: shared_id.to_string(),
            namespace: "tenant-b".to_string(),
            hosts: vec!["b-gateway.example.com".to_string()],
            listen_path: Some("/b-gateway".to_string()),
            strip_listen_path: false,
            preserve_host_header: false,
            backend_host: "b-gateway.svc".to_string(),
            backend_port: 8082,
            upstream_id: None,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
            retry: None,
            backend_read_timeout_ms: None,
        });
        let istio_a = proxy_for_route(RouteProxySpec {
            id: shared_id.to_string(),
            namespace: "tenant-a".to_string(),
            hosts: vec!["a-istio.example.com".to_string()],
            listen_path: Some("/a-istio".to_string()),
            strip_listen_path: false,
            preserve_host_header: false,
            backend_host: "a-istio.svc".to_string(),
            backend_port: 8083,
            upstream_id: None,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
            retry: None,
            backend_read_timeout_ms: None,
        });

        acc.upsert_proxy(gateway_a, SourceKind::GatewayApi);
        acc.upsert_proxy(istio_b, SourceKind::Istio);
        // Same bare id in tenant-b: Gateway API must lose to Istio only inside tenant-b.
        acc.upsert_proxy(gateway_b, SourceKind::GatewayApi);
        // Same bare id in tenant-a: Istio replaces Gateway API only inside tenant-a.
        acc.upsert_proxy(istio_a, SourceKind::Istio);

        assert_eq!(acc.config.proxies.len(), 2);
        let proxy_a = acc
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "tenant-a")
            .expect("tenant-a proxy");
        let proxy_b = acc
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "tenant-b")
            .expect("tenant-b proxy");
        assert_eq!(proxy_a.id, shared_id);
        assert_eq!(proxy_b.id, shared_id);
        assert_eq!(proxy_a.backend_port, 8083);
        assert_eq!(proxy_b.backend_port, 8081);
        assert_eq!(
            acc.proxy_source("tenant-a", shared_id),
            Some(SourceKind::Istio)
        );
        assert_eq!(
            acc.proxy_source("tenant-b", shared_id),
            Some(SourceKind::Istio)
        );
        assert!(
            acc.warnings.iter().any(|warning| {
                warning.contains("tenant-b")
                    && warning.contains(shared_id)
                    && warning.contains("Istio resource has precedence")
            }),
            "Gateway API loss in tenant-b must be warned without touching tenant-a: {:?}",
            acc.warnings
        );
    }

    #[test]
    fn upsert_upstream_keeps_same_bare_id_in_two_namespaces() {
        let mut acc = K8sAccumulator::new(options("ferrum").with_source_namespaces(Vec::new()));
        let shared_id = "lossy-upstream-id";

        acc.upsert_upstream(upstream_for_route(
            shared_id.to_string(),
            "tenant-a".to_string(),
            vec![RouteBackend {
                host: "a.svc".to_string(),
                port: 8080,
                weight: 100,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }],
        ));
        acc.upsert_upstream(upstream_for_route(
            shared_id.to_string(),
            "tenant-b".to_string(),
            vec![RouteBackend {
                host: "b.svc".to_string(),
                port: 8081,
                weight: 100,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }],
        ));
        // Replace only tenant-a's upstream; tenant-b must survive.
        acc.upsert_upstream(upstream_for_route(
            shared_id.to_string(),
            "tenant-a".to_string(),
            vec![RouteBackend {
                host: "a-updated.svc".to_string(),
                port: 9090,
                weight: 100,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }],
        ));

        assert_eq!(acc.config.upstreams.len(), 2);
        let upstream_a = acc
            .config
            .upstreams
            .iter()
            .find(|upstream| upstream.namespace == "tenant-a")
            .expect("tenant-a upstream");
        let upstream_b = acc
            .config
            .upstreams
            .iter()
            .find(|upstream| upstream.namespace == "tenant-b")
            .expect("tenant-b upstream");
        assert_eq!(upstream_a.targets[0].host, "a-updated.svc");
        assert_eq!(upstream_a.targets[0].port, 9090);
        assert_eq!(upstream_b.targets[0].host, "b.svc");
        assert_eq!(upstream_b.targets[0].port, 8081);
    }

    #[test]
    fn upsert_proxy_and_upstream_fail_closed_on_empty_identity() {
        let mut acc = K8sAccumulator::new(options("ferrum").with_source_namespaces(Vec::new()));
        acc.upsert_proxy(
            proxy_for_route(RouteProxySpec {
                id: String::new(),
                namespace: "tenant-a".to_string(),
                hosts: vec!["a.example.com".to_string()],
                listen_path: Some("/a".to_string()),
                strip_listen_path: false,
                preserve_host_header: false,
                backend_host: "a.svc".to_string(),
                backend_port: 8080,
                upstream_id: None,
                backend_scheme: BackendScheme::Http,
                listen_port: None,
                retry: None,
                backend_read_timeout_ms: None,
            }),
            SourceKind::GatewayApi,
        );
        acc.upsert_upstream(upstream_for_route(
            "ok".to_string(),
            String::new(),
            vec![RouteBackend {
                host: "a.svc".to_string(),
                port: 8080,
                weight: 100,
                service_namespace: None,
                service_name: None,
                service_port: None,
            }],
        ));

        assert!(acc.config.proxies.is_empty());
        assert!(acc.config.upstreams.is_empty());
        assert!(
            acc.warnings
                .iter()
                .any(|warning| warning.contains("empty namespace or id")),
            "empty identities must warn and fail closed: {:?}",
            acc.warnings
        );
    }
}
