//! Internal mesh data model (Layer 2 of the mesh expansion).
//!
//! These types deliberately mirror Istio CRD vocabulary so the Phase B/C
//! translation layer can be near-1:1. Every type carries `#[serde(default)]`
//! on optional collections and `skip_serializing_if` on `Option`/`Vec` so
//! that a non-mesh `GatewayConfig` round-trips byte-identical (no extra
//! keys appear in the serialised JSON / YAML).
//!
//! All types are namespace-scoped (`namespace: String`) — same convention
//! as `Proxy`, `Consumer`, `Upstream` in [`crate::config::types`]. The
//! mesh subsystem will share the same `FERRUM_NAMESPACE` mechanism so a
//! single gateway instance only loads its own namespace's mesh resources.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{JwtAuthority as IdentityJwtAuthority, TrustBundle as IdentityTrustBundle};

/// Application-layer protocol classification for mesh ports.
///
/// Mirrors Istio's `appProtocol` field on `Service` ports + endpoints. Phase
/// A serialises lowercase ("http", "http2", "grpc", "tcp", "tls", "mongo",
/// "redis", "mysql", "postgres", "unknown").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppProtocol {
    Http,
    Http2,
    Grpc,
    Tcp,
    Tls,
    Mongo,
    Redis,
    Mysql,
    Postgres,
    #[default]
    Unknown,
}

// ── Workload ──────────────────────────────────────────────────────────────

/// A single workload registered with the mesh.
///
/// `Workload` is the unit of identity — every SVID is issued to one workload.
/// The `selector` describes how the workload is matched at attestation time
/// (K8s labels, VM tags, or static), the `service_name` is the logical
/// service it participates in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    pub spiffe_id: SpiffeId,
    pub selector: WorkloadSelector,
    pub service_name: String,
    /// Workload IPs or DNS names. Istio `WorkloadEntry.address` maps here;
    /// K8s pod IPs land here once the reconciler wires pod watching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<WorkloadPort>,
    pub trust_domain: TrustDomain,
    pub namespace: String,
    /// Istio network label for multi-network routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Cluster name for CP-to-CP exchange and VM workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Istio `WorkloadEntry.weight` — load-balancing weight for traffic
    /// splitting between multiple workloads of the same service. Absent
    /// here means "use the default" — equivalent to today's behavior. A
    /// value of `0` is accepted (Istio "no traffic" / drain). Capped at
    /// `MAX_TARGET_WEIGHT` (65_535) at translation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    /// Istio `WorkloadEntry.locality` — slash-delimited
    /// `region/zone/subzone` string consumed by locality-aware routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// Istio `WorkloadEntry.serviceAccount` — kept separately from
    /// `spiffe_id` so introspection and audit don't need to parse the
    /// SPIFFE path. None when the source omits it; the SPIFFE translation
    /// still falls back to `"default"` for SVID issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
}

/// A port advertised by a workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadPort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Selector for workload matching. Empty `labels` matches any workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSelector {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ── MeshService ───────────────────────────────────────────────────────────

/// A logical service. Workloads are referenced by SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshService {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<WorkloadRef>,
    /// Per-port overrides for service-level protocol classification.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub protocol_overrides: HashMap<u16, AppProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServicePort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadRef {
    pub spiffe_id: SpiffeId,
}

// ── MeshPolicy ────────────────────────────────────────────────────────────

/// Identity-based authorization policy. Mirrors Istio AuthorizationPolicy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshPolicy {
    pub name: String,
    pub namespace: String,
    pub scope: PolicyScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MeshRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyScope {
    WorkloadSelector {
        selector: WorkloadSelector,
    },
    Namespace {
        namespace: String,
    },
    #[default]
    MeshWide,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<PrincipalMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<RequestMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<ConditionMatch>,
    /// Glob patterns over JWT-derived request principals (`iss/sub`).
    ///
    /// Mirrors Istio AuthorizationPolicy `from[].source.requestPrincipals`.
    /// A request matches when its `request_principal` (set by `jwks_auth`
    /// from the validated JWT's `iss/sub`) matches any pattern in this list.
    /// An empty list means "any request principal" (no filter).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_principals: Vec<String>,
    /// Synthetic marker for rules that should affect policy accounting but
    /// never match traffic, e.g. Istio ALLOW-without-rules allow-nothing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub never_matches: bool,
    #[serde(default)]
    pub action: PolicyAction,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Allow,
    Deny,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalMatch {
    /// Glob pattern over SPIFFE IDs, e.g. `spiffe://prod/ns/foo/sa/*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id_pattern: Option<String>,
    /// Glob pattern over workload namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,
    /// Restrict matches to a specific trust domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Glob path patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Glob host patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Header name → glob value pattern.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Glob port patterns, used for Istio string-match ports such as "*".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_patterns: Vec<String>,
    /// Istio `notMethods` — conjunctive negative-match: when any value
    /// matches the request method, the rule fails. Empty means "no
    /// negative filter".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_methods: Vec<String>,
    /// Istio `notPaths` — conjunctive negative-match for the request path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_paths: Vec<String>,
    /// Istio `notHosts` — conjunctive negative-match for the request host.
    /// Normalised at config-load time identical to `hosts` so the hot path
    /// stays allocation-free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_hosts: Vec<String>,
    /// Istio `notPorts` — conjunctive negative-match for the request port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConditionMatch {
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_values: Vec<String>,
}

/// Abstraction over per-workload label maps.
///
/// `mesh_authz` carries labels in a `BTreeMap<String, String>` (the
/// canonical [`crate::modes::mesh::slice::MeshSlice`] form), the Kubernetes injector
/// keeps them in a `HashMap`, and tests freely build either. This trait lets
/// the scope-matching helpers below accept any of those without copying.
pub trait WorkloadLabels {
    fn lookup(&self, key: &str) -> Option<&str>;
}

impl<S: ::std::hash::BuildHasher> WorkloadLabels for HashMap<String, String, S> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl WorkloadLabels for ::std::collections::BTreeMap<String, String> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Returns `true` when `policy.scope` applies to a workload whose namespace is
/// `proxy_namespace` and whose labels are `proxy_labels`.
///
/// This is the **single canonical scope-matching helper** used by both the
/// xDS / native MeshSubscribe slice builder ([`crate::modes::mesh::slice::MeshSlice::from_gateway_config`])
/// and the `mesh_authz` plugin's per-policy filter so that scope semantics
/// stay byte-identical across the two surfaces.
///
/// Semantics:
/// - [`PolicyScope::MeshWide`] — applies to every workload.
/// - [`PolicyScope::Namespace`] — applies iff `proxy_namespace == policy.scope.namespace`.
/// - [`PolicyScope::WorkloadSelector`] — applies iff (a) the selector's
///   namespace is unset or equal to `proxy_namespace` AND (b) every
///   `(key, value)` in `selector.labels` is present in `proxy_labels` with the
///   same value (subset match — empty selector labels means "any workload in
///   the optional namespace").
pub fn policy_scope_applies_to_workload<L: WorkloadLabels + ?Sized>(
    policy: &MeshPolicy,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    match &policy.scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace {
            namespace: policy_namespace,
        } => policy_namespace == proxy_namespace,
        PolicyScope::WorkloadSelector { selector } => {
            workload_selector_matches(selector, proxy_namespace, proxy_labels)
        }
    }
}

/// Returns `true` when a [`PolicyScope`] applies to a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`.
///
/// Same semantics as [`policy_scope_applies_to_workload`] but accepts a
/// bare `PolicyScope` instead of a full `MeshPolicy`, making it reusable
/// for `MeshRequestAuthentication` scope filtering.
pub fn scope_applies_to_workload<L: WorkloadLabels + ?Sized>(
    scope: &PolicyScope,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    match scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace {
            namespace: policy_namespace,
        } => policy_namespace == proxy_namespace,
        PolicyScope::WorkloadSelector { selector } => {
            workload_selector_matches(selector, proxy_namespace, proxy_labels)
        }
    }
}

/// Returns `true` when a [`WorkloadSelector`] matches a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`. Same
/// shape as [`policy_scope_applies_to_workload`]; lifted so PeerAuthentication
/// selector matching shares the same predicate.
pub fn workload_selector_matches<L: WorkloadLabels + ?Sized>(
    selector: &WorkloadSelector,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    if let Some(selector_namespace) = selector.namespace.as_ref()
        && selector_namespace != proxy_namespace
    {
        return false;
    }
    labels_match_subset(&selector.labels, proxy_labels)
}

// ── RequestAuthentication ─────────────────────────────────────────────────

/// Represents an Istio `RequestAuthentication` resource translated into
/// Ferrum's model. Declares which JWTs are accepted for a workload.
///
/// Semantics mirror Istio: RequestAuthentication is **permissive** by
/// default — it only declares which JWTs are *valid*, not which are
/// *required*. A request with no JWT passes through. An invalid JWT is
/// rejected. A valid JWT has its claims extracted and identity propagated.
/// Enforcement (requiring a JWT) comes from `AuthorizationPolicy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshRequestAuthentication {
    pub name: String,
    pub namespace: String,
    pub scope: PolicyScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_rules: Vec<MeshJwtRule>,
}

/// A single JWT validation rule within a [`MeshRequestAuthentication`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshJwtRule {
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Inline JWKS JSON (alternative to `jwks_uri`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_headers: Vec<JwtHeader>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_params: Vec<String>,
    #[serde(default)]
    pub forward_original_token: bool,
}

/// A header location from which to extract a JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtHeader {
    pub name: String,
    /// Prefix stripped before validation (e.g., `"Bearer "`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

// ── Telemetry ─────────────────────────────────────────────────────────────

/// Raw Telemetry resource from Istio CRD translation (before workload merge).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshTelemetryResource {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub scope: PolicyScope,
    pub config: MeshTelemetryConfig,
}

/// Merged telemetry configuration for a workload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MeshTelemetryConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracing: Option<MeshTracingConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MeshMetricsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_logging: Option<MeshAccessLoggingConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshTracingConfig {
    /// Istio tracing mode selector — `Server`, `Client`, or `ClientAndServer`.
    /// `None` defers to the default (Istio treats unset as SERVER for sidecar
    /// inbound and CLIENT for sidecar outbound). The mesh plugin injection
    /// path turns this into a `direction_emit` field on the `workload_metrics`
    /// plugin instance so a single plugin handles both sides of a hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<TelemetryTracingMode>,
    /// Sampling percentage 0.0–100.0. `None` inherits from less-specific Telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_percentage: Option<f64>,
    /// Istio `disableSpanReporting`.
    #[serde(
        default,
        alias = "disableSpanReporting",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_span_reporting: Option<bool>,
    /// Literal/environment custom tags injected into every span / transaction metadata.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_tags: HashMap<String, String>,
    /// Custom tags resolved from request headers at runtime.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_header_tags: HashMap<String, String>,
    /// Provider-specific tracing backends (Zipkin / Datadog / Lightstep / OpenTelemetry).
    ///
    /// The legacy singular `provider` spelling deserializes into this vector
    /// for back-compat, but new slices serialize only `providers`.
    #[serde(
        default,
        alias = "provider",
        deserialize_with = "deserialize_tracing_providers",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub providers: Vec<TracingProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryTracingMode {
    Client,
    Server,
    ClientAndServer,
}

impl TelemetryTracingMode {
    /// Whether this mode covers server-side (inbound) span emission.
    pub fn emits_server(self) -> bool {
        matches!(self, Self::Server | Self::ClientAndServer)
    }

    /// Whether this mode covers client-side (outbound) span emission.
    pub fn emits_client(self) -> bool {
        matches!(self, Self::Client | Self::ClientAndServer)
    }
}

/// Tracing backend selection for a `MeshTracingConfig`.
///
/// Mirrors Istio's `Tracing.providers[]` provider definitions for the four
/// most common backends. Serialised with `kind` discriminator + `config`
/// payload so a future variant can be appended without an `unknown`-handling
/// shim on older DPs (serde will simply fail to deserialise an unknown
/// variant and the slice update is rejected at slice-apply time, consistent
/// with the rest of the mesh slice contract).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "config")]
pub enum TracingProvider {
    Zipkin {
        url: String,
    },
    Datadog {
        agent_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
    Lightstep {
        collector_url: String,
        #[serde(alias = "accessTokenEnv")]
        access_token_env: String,
    },
    #[serde(rename = "opentelemetry")]
    OpenTelemetry {
        endpoint: String,
    },
}

impl fmt::Debug for TracingProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zipkin { url } => f.debug_struct("Zipkin").field("url", url).finish(),
            Self::Datadog { agent_url, service } => f
                .debug_struct("Datadog")
                .field("agent_url", agent_url)
                .field("service", service)
                .finish(),
            Self::Lightstep {
                collector_url,
                access_token_env,
            } => f
                .debug_struct("Lightstep")
                .field("collector_url", collector_url)
                .field("access_token_env", access_token_env)
                .finish(),
            Self::OpenTelemetry { endpoint } => f
                .debug_struct("OpenTelemetry")
                .field("endpoint", endpoint)
                .finish(),
        }
    }
}

fn deserialize_tracing_providers<'de, D>(deserializer: D) -> Result<Vec<TracingProvider>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(Vec::new());
    }
    if value.is_array() {
        serde_json::from_value(value).map_err(serde::de::Error::custom)
    } else {
        serde_json::from_value(value)
            .map(|provider| vec![provider])
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshMetricsConfig {
    /// Tag overrides: rename, remove, or set custom values for metric tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_overrides: Vec<MetricTagOverride>,
    /// Specific metric names to disable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_metrics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricTagOverride {
    pub name: String,
    pub operation: TagOverrideOperation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TagOverrideOperation {
    Remove,
    Rename { new_name: String },
    Set { value: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshAccessLoggingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AccessLogFilter>,
}

fn default_true() -> bool {
    true
}

/// Simple access log filter operating on transaction summary fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogFilter {
    /// Only log responses with status code >= this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code_min: Option<u16>,
    /// Only log responses with status code <= this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code_max: Option<u16>,
    /// Only log requests with latency above this threshold (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_latency_ms: Option<u64>,
    /// Only log requests that resulted in an error.
    #[serde(default)]
    pub errors_only: bool,
}

// ── ProxyConfig ───────────────────────────────────────────────────────────

/// Represents an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) resource
/// translated into Ferrum's model.
///
/// ProxyConfig carries config-time, read-only settings for a workload's
/// data plane: `concurrency`, `image`, `environmentVariables`, and tracing
/// `sampling`. It has **no data-plane request-path impact** — values are
/// applied at slice-apply time (cold path) and surfaced to operator
/// tooling. Tracing `sampling` flows into the injected `workload_metrics`
/// plugin's `sampling_percentage` field.
///
/// Scope resolution mirrors the canonical [`PolicyScope`] used by
/// `PeerAuthentication`, `RequestAuthentication`, and `Telemetry`: a
/// resource in the Istio root namespace with no selector is `MeshWide`; a
/// resource in any other namespace with no selector is `Namespace`-scoped;
/// any resource with a selector is `WorkloadSelector`-scoped (with the
/// `namespace` set when not in the root namespace, mirroring the Istio
/// "root-namespace selectors apply mesh-wide" rule used by Telemetry / RA).
/// Most-specific match wins per workload (WorkloadSelector > Namespace >
/// MeshWide); same-specificity ties are broken by ASCII-ordered name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshProxyConfig {
    pub name: String,
    pub namespace: String,
    /// Resolved [`PolicyScope`] capturing Istio's root-namespace +
    /// selector semantics. See struct docs for the full table.
    #[serde(default)]
    pub scope: PolicyScope,
    /// `spec.concurrency` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    /// `spec.image.imageType` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// `spec.environmentVariables` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment: HashMap<String, String>,
    /// `spec.tracing.sampling` — percentage 0-100; merged into
    /// `workload_metrics.sampling_percentage` at slice-apply time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracing_sampling: Option<f64>,
}

/// Returns `true` when a [`MeshProxyConfig`] applies to a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`.
///
/// Delegates to the canonical [`scope_applies_to_workload`] helper so
/// ProxyConfig honors the same root-namespace + selector semantics as
/// every other Istio mesh resource (PeerAuthentication, Telemetry,
/// RequestAuthentication, AuthorizationPolicy).
pub fn proxy_config_applies_to_workload<L: WorkloadLabels + ?Sized>(
    config: &MeshProxyConfig,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    scope_applies_to_workload(&config.scope, proxy_namespace, proxy_labels)
}

/// Returns `true` when every `(key, value)` in `selector_labels` is present
/// in `proxy_labels` with the same value. Empty `selector_labels` always
/// matches (subset semantics). Shared by [`workload_selector_matches`].
#[inline]
fn labels_match_subset<L: WorkloadLabels + ?Sized>(
    selector_labels: &HashMap<String, String>,
    proxy_labels: &L,
) -> bool {
    selector_labels
        .iter()
        .all(|(key, value)| proxy_labels.lookup(key) == Some(value.as_str()))
}

/// Returns true when a ServiceEntry is visible to a workload namespace under
/// Ferrum's egress materialization rules. Empty `export_to` is intentionally
/// namespace-local to avoid cross-tenant exposure by omission. Istio
/// `workloadSelector` describes backing workloads/endpoints, not which clients
/// may consume the service, so it is deliberately not part of this visibility
/// check.
pub fn service_entry_exported_to_namespace(entry: &ServiceEntry, workload_namespace: &str) -> bool {
    if entry.export_to.is_empty() {
        return entry.namespace == workload_namespace;
    }

    entry.export_to.iter().any(|target| {
        target == "*"
            || target == workload_namespace
            || (target == "." && entry.namespace == workload_namespace)
    })
}

pub fn service_entry_applies_to_workload<L: WorkloadLabels + ?Sized>(
    entry: &ServiceEntry,
    workload_namespace: &str,
    _workload_labels: &L,
) -> bool {
    service_entry_exported_to_namespace(entry, workload_namespace)
}

// ── PeerAuthentication ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerAuthentication {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PolicyScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<WorkloadSelector>,
    #[serde(default)]
    pub mtls_mode: MtlsMode,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_overrides: HashMap<u16, MtlsMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtlsMode {
    // ── PeerAuthentication server-side modes ──
    Strict,
    #[default]
    Permissive,
    Disable,
    // ── DestinationRule client-side modes (Istio `ClientTLSSettings.mode`) ──
    /// SIMPLE: originate TLS to the backend, verify the server certificate.
    Simple,
    /// MUTUAL: originate mTLS with operator-provided client cert/key.
    Mutual,
    /// ISTIO_MUTUAL: originate mTLS using the workload's SPIFFE identity
    /// material (no explicit cert/key in the DR).
    IstioMutual,
}

// ── ServiceEntry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<MeshEndpoint>,
    #[serde(default)]
    pub resolution: Resolution,
    #[serde(default)]
    pub location: ServiceEntryLocation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
    /// Optional Istio-style visibility list. Empty means namespace-local for
    /// Ferrum's materialization path; `*` exports mesh-wide, `.` exports to
    /// this entry's namespace, and a namespace value exports there explicitly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_selector: Option<WorkloadSelector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Dns,
    Static,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEntryLocation {
    #[default]
    MeshExternal,
    MeshInternal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEndpoint {
    pub address: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ports: HashMap<String, u16>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── Trust bundles ─────────────────────────────────────────────────────────

/// Full trust-bundle set carried in `GatewayConfig`. Mirrors
/// [`crate::identity::TrustBundleSet`] in shape, but uses serialisable
/// representations so the config can be persisted to file/DB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundleSet {
    pub local: TrustBundle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federated: Vec<TrustBundle>,
}

/// Persistable trust bundle. `x509_authorities` is a list of base64-encoded
/// DER blobs; `jwt_authorities` is a flat list. Both are intentionally
/// serialisation-friendly (no `Vec<u8>` raw bytes) so YAML/JSON output
/// stays human-readable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    /// Base64-encoded DER certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_authorities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_authorities: Vec<JwtAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAuthority {
    pub key_id: String,
    pub public_key_pem: String,
}

impl TrustBundle {
    /// Decode the base64 authorities into raw DER, suitable for handing to
    /// the runtime [`crate::identity::TrustBundle`]. Returns the list of
    /// bytes or an error on the first malformed entry.
    pub fn decode_x509_authorities(&self) -> Result<Vec<Vec<u8>>, String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        self.x509_authorities
            .iter()
            .enumerate()
            .map(|(i, s)| {
                engine
                    .decode(s.as_bytes())
                    .map_err(|e| format!("x509_authorities[{}]: invalid base64: {}", i, e))
            })
            .collect()
    }

    /// Convert this serialisable bundle into a runtime
    /// [`crate::identity::TrustBundle`] (DER-decoded).
    pub fn to_runtime(&self) -> Result<IdentityTrustBundle, String> {
        Ok(IdentityTrustBundle {
            trust_domain: self.trust_domain.clone(),
            x509_authorities: self.decode_x509_authorities()?,
            jwt_authorities: self
                .jwt_authorities
                .iter()
                .map(|a| IdentityJwtAuthority {
                    key_id: a.key_id.clone(),
                    public_key_pem: a.public_key_pem.clone(),
                })
                .collect(),
            refresh_hint_seconds: self.refresh_hint_seconds,
        })
    }
}

impl TrustBundleSet {
    /// Convenience: build a runtime [`crate::identity::TrustBundleSet`].
    pub fn to_runtime(&self) -> Result<crate::identity::TrustBundleSet, String> {
        let local = self.local.to_runtime()?;
        let mut federated = std::collections::HashMap::new();
        for tb in &self.federated {
            let runtime = tb.to_runtime()?;
            federated.insert(runtime.trust_domain.clone(), runtime);
        }
        Ok(crate::identity::TrustBundleSet { local, federated })
    }
}

// ── Sidecar (Istio egress scoping) ───────────────────────────────────────

/// Istio `Sidecar` resource. Narrows which services / service-entries /
/// destination-rules a workload may reach via egress. Mirror of Istio's
/// `networking.istio.io/v1.Sidecar` for `egress` scoping; ingress listener
/// configuration is intentionally not modeled.
///
/// Resolution order at slice build time (most specific wins):
/// 1. Workload-scoped (non-empty `workload_selector` whose labels match)
/// 2. Namespace-default (empty / `None` `workload_selector`)
///
/// Behavior is gated by `FERRUM_MESH_SIDECAR_ENFORCED` (default `false`).
/// When the flag is unset, sidecars are accepted and persisted in
/// `MeshConfig` but slice narrowing is not applied (existing behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSidecar {
    pub name: String,
    pub namespace: String,
    /// Empty / `None` = namespace-default; non-empty = workload-scoped via labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_selector: Option<WorkloadSelector>,
    /// `true` when Kubernetes `spec.egress` was omitted and the Sidecar should
    /// inherit the namespace default outbound scope instead of treating the
    /// empty `egress` vector as an explicit block-all policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub egress_inherits_defaults: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<MeshSidecarEgress>,
}

/// A single egress listener entry under a [`MeshSidecar`]. Carries the
/// Istio scope-host syntax (`namespace/host`) plus an optional port narrowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSidecarEgress {
    /// Egress hosts in Istio scope-host syntax:
    ///   - `*/*`           — allow everything (effectively no narrowing)
    ///   - `*/host`        — `host` in any namespace
    ///   - `./host`        — `host` in the Sidecar's own namespace
    ///   - `namespace/host` — `host` in the specified namespace
    ///   - `namespace/*`   — anything in the specified namespace
    pub hosts: Vec<String>,
    /// Optional Istio Port object; when set, narrows MeshService and
    /// ServiceEntry port lists during Sidecar egress slice projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Parsed Istio scope-host pattern (`<namespace_part>/<host_part>`).
///
/// Returned by [`MeshSidecarEgress::parse_host_pattern`]; centralises the
/// pattern-form for downstream matchers in [`crate::modes::mesh::slice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarHostPattern<'a> {
    /// `*/*` — allow everything.
    AllowAll,
    /// `*/host` — `host` in any namespace.
    AnyNamespaceHost { host: &'a str },
    /// `./host` — `host` in the Sidecar's own namespace.
    SameNamespaceHost { host: &'a str },
    /// `namespace/*` — anything in the specified namespace.
    NamespaceWildcard { namespace: &'a str },
    /// `namespace/host` — exact namespace + host.
    NamespaceHost { namespace: &'a str, host: &'a str },
    /// Bare `host` (no `/`): treated as same-namespace, matching the
    /// Istio convention when the namespace prefix is omitted.
    SameNamespaceHostBare { host: &'a str },
}

impl MeshSidecarEgress {
    /// Parse one `egress.hosts` entry into a [`SidecarHostPattern`].
    pub fn parse_host_pattern(host: &str) -> SidecarHostPattern<'_> {
        let trimmed = host.trim().trim_end_matches('.');
        match trimmed.split_once('/') {
            Some(("*", "*")) => SidecarHostPattern::AllowAll,
            Some(("*", host)) if !host.is_empty() => SidecarHostPattern::AnyNamespaceHost { host },
            Some((".", host)) if !host.is_empty() => SidecarHostPattern::SameNamespaceHost { host },
            Some((namespace, "*")) if !namespace.is_empty() => {
                SidecarHostPattern::NamespaceWildcard { namespace }
            }
            Some((namespace, host)) if !namespace.is_empty() && !host.is_empty() => {
                SidecarHostPattern::NamespaceHost { namespace, host }
            }
            // Fallback: bare host — treat as same-namespace host.
            _ => SidecarHostPattern::SameNamespaceHostBare { host: trimmed },
        }
    }
}

// ── Multi-cluster ────────────────────────────────────────────────────────

/// Layer-10 multi-cluster mesh settings.
///
/// This is intentionally control-plane neutral. Istio CRDs, Gateway API,
/// native ConfigSync, xDS, file mode, and future CP-to-CP exchange all carry
/// the same canonical shape instead of talking past Layer 2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MultiClusterConfig {
    /// Operator-facing name for the local cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cluster: Option<String>,
    /// SPIFFE federation endpoint served by this control plane, when Ferrum
    /// is publishing bundles to remote clusters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
    /// Remote clusters whose services/workloads/bundles may be exchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_clusters: Vec<RemoteCluster>,
    /// SNI-routed east-west gateway backends. Mesh mode materializes these as
    /// passthrough TCP proxies only when topology is `east_west_gateway`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub east_west_gateways: Vec<EastWestGateway>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCluster {
    pub name: String,
    pub trust_domain: TrustDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EastWestGateway {
    pub name: String,
    pub namespace: String,
    /// Backend host to which the east-west gateway forwards matched SNI.
    pub host: String,
    /// Backend port on `host`.
    pub port: u16,
    /// TLS SNI hosts routed through this gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── DestinationRule ──────────────────────────────────────────────────────

/// Istio DestinationRule traffic policy mapped onto Ferrum primitives.
///
/// Each DestinationRule targets a service host and carries connection pool
/// settings, outlier detection, load balancer config, and optional subsets.
/// The mesh runtime applies these onto matching `Upstream` entries during
/// `prepare_gateway_config_for_mesh()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshDestinationRule {
    pub name: String,
    pub namespace: String,
    /// Target service host (e.g., `reviews.default.svc.cluster.local`).
    pub host: String,
    /// Top-level traffic policy applied to all targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<MeshTrafficPolicy>,
    /// Per-destination-port traffic policy overrides. Keyed by destination
    /// port number; values override the corresponding fields of
    /// `traffic_policy` for traffic landing on that port. Mirrors Istio's
    /// `trafficPolicy.portLevelSettings[]`.
    ///
    /// Default empty → old DPs reading new slices ignore the field; new DPs
    /// reading old slices see an empty map (same behaviour as today).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_level_settings: HashMap<u16, MeshTrafficPolicy>,
    /// Named subsets with per-subset label selectors and optional policy
    /// overrides. Proxies reference these via `upstream_subset`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subsets: Vec<MeshSubset>,
}

/// Traffic policy controlling connection pool, outlier detection, and LB.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshTrafficPolicy {
    /// Backend connect timeout in milliseconds
    /// (from `connectionPool.tcp.connectTimeout`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Outlier detection (maps to Ferrum PassiveHealthCheck).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outlier_detection: Option<MeshOutlierDetection>,
    /// Load balancer configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<MeshLoadBalancer>,
    /// Optional backend TLS override from `DestinationRule.trafficPolicy.tls`.
    ///
    /// When `None` (default) the workload's `PeerAuthentication`-derived
    /// mTLS posture continues to apply. When `Some(...)` the DR settings
    /// win at cold-path apply time: `apply_traffic_policy_to_upstream`
    /// projects them onto the matching `Upstream`'s `backend_tls_*` fields.
    /// Old DPs reading new slices see this as a no-op (serde defaults to
    /// `None`); new DPs reading old slices behave identically to today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<MeshTrafficPolicyTls>,
    /// Optional `DestinationRule.trafficPolicy.localityLbSetting`. When
    /// present, the mesh apply layer projects this onto the resolved
    /// `Upstream.locality_lb_setting`; the load balancer then honours
    /// `distribute` weights and `failover` region overrides on top of the
    /// existing priority-tier (exact/zone/region) preference. Old DPs
    /// reading new slices see this as a no-op via the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality_lb_setting: Option<MeshLocalityLbSetting>,
    /// Cap on inflight backend TCP connections per target, mapped from
    /// Istio `connectionPool.tcp.maxConnections`. Currently enforced only
    /// by stream-family backend dispatch (TCP / TCP+TLS proxies); HTTP-family
    /// dispatch ignores the field — that is tracked as a follow-on PR.
    /// Old DPs reading new slices see this as a no-op via the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// TCP keepalive overrides mapped from Istio
    /// `connectionPool.tcp.tcpKeepalive`. Each subfield is independently
    /// optional. Currently applied only by stream-family backend dispatch on
    /// the newly connected backend socket (HTTP-family dispatch is a
    /// follow-on PR). Old DPs reading new slices see this as a no-op via
    /// the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keepalive: Option<crate::config::types::TcpKeepaliveCfg>,
    /// Optional `DestinationRule.trafficPolicy.connectionPool.http` block.
    /// When present, the K8s translator has parsed at least one of the
    /// supported HTTP connection-pool knobs (`maxRequestsPerConnection`,
    /// `idleTimeout`, `http2MaxRequests`); the mesh apply layer projects
    /// these onto the matching upstream's `port_overrides[port]` slot
    /// (top-level fan-out applies to every target port; per-port
    /// `portLevelSettings` overrides per-port). Old DPs reading new slices
    /// see this as a no-op via the serde default. Currently-deferred
    /// Istio HTTP knobs (`http1MaxPendingRequests`, `maxRetries`,
    /// `h2UpgradePolicy`) are intentionally absent — the K8s translator
    /// emits a debug line when an operator sets them and otherwise drops
    /// them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_pool_http: Option<MeshConnectionPoolHttp>,
}

/// Subset of Istio `ConnectionPoolSettings.HTTPSettings` parsed and
/// projected by the gateway. Each field is independently optional so the
/// translator can express "operator set N of M fields"; the apply pass
/// only overlays fields that are `Some`. See
/// [`crate::config::types::UpstreamPortOverride`] for the corresponding
/// resolved slots and dispatch wiring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConnectionPoolHttp {
    /// Mapped from `maxRequestsPerConnection`. Wire-projected end-to-end
    /// (admitted, persisted on slice, and reaches dispatch via
    /// `Proxy.pool_max_requests_per_connection`) but hyper does not yet
    /// expose a close-after-N-requests builder knob, so the runtime
    /// effect is pending. Tracked as a follow-on; documented same as the
    /// proxy-level field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_connection: Option<u32>,
    /// Mapped from `idleTimeout` (parsed as an Istio duration, persisted
    /// as milliseconds). Translator rejects sub-second durations because
    /// the proxy-level `pool_idle_timeout_seconds` field is whole-second
    /// granular and silently rounding `500ms` would not match the
    /// operator's intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
    /// Mapped from `http2MaxRequests`. Projects to
    /// `Proxy.pool_http2_max_concurrent_streams` per port via
    /// `resolve_effective_proxy_for_target` and threads into the H2/gRPC
    /// builder knobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2_max_requests: Option<u32>,
}

/// `DestinationRule.trafficPolicy.tls` settings mapped from Istio's
/// `ClientTLSSettings` (`networking.istio.io/v1beta1`).
///
/// Carries the originating-client TLS mode plus optional SNI, CA, client
/// cert/key, SAN verification list, and an `insecureSkipVerify` escape
/// hatch. The cold-path apply at `apply_traffic_policy_to_upstream`
/// projects these onto the `Upstream` `backend_tls_*` fields when set.
///
/// `Default::default()` returns a `Simple`-mode block (matches Istio's
/// `ClientTLSSettings.mode` default and avoids the `MtlsMode::Permissive`
/// server-side default that the derived `Default` would otherwise produce —
/// a `MeshTrafficPolicyTls` with a server-side mode is treated as a
/// programming error by the cold-path apply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshTrafficPolicyTls {
    /// DR client-side TLS mode: `Disable` / `Simple` / `Mutual` / `IstioMutual`.
    ///
    /// Defaults to `Simple` when omitted, matching Istio's `ClientTLSSettings.mode`
    /// default and the `translate_client_tls_settings` translator behavior. Without
    /// this default, a hand-authored or partially-updated slice such as
    /// `{ "tls": { "sni": "..." } }` would fail to deserialize even though Istio
    /// defaulting semantics treat it as `SIMPLE`.
    #[serde(default = "default_client_tls_mode")]
    pub mode: MtlsMode,
    /// Optional Server Name Indication value for backend TLS origination.
    /// Cold-path DestinationRule application projects this onto
    /// `Upstream.backend_tls_sni` and then into `Proxy.resolved_tls` so the
    /// backend handshake layer can consume the cached value when wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Optional path to a PEM CA bundle for verifying the backend server's
    /// certificate (Istio `caCertificates`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    /// Optional path to a PEM client certificate for mTLS with the backend
    /// (Istio `clientCertificate`). Required when `mode == Mutual`; must be
    /// absent when `mode == IstioMutual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// Optional path to a PEM private key for mTLS with the backend
    /// (Istio `privateKey`). Required when `mode == Mutual`; must be
    /// absent when `mode == IstioMutual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Optional list of acceptable Subject Alternative Names for the
    /// backend's server certificate (Istio `subjectAltNames`). Cold-path
    /// DestinationRule application projects this onto
    /// `Upstream.backend_tls_san_allow_list` and then into
    /// `Proxy.resolved_tls` so certificate-verifier enforcement can consume
    /// the cached value when wired.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_alt_names: Vec<String>,
    /// When true, suppress server-cert verification on the backend handshake
    /// (Istio `insecureSkipVerify`). Maps to
    /// `Upstream.backend_tls_verify_server_cert = false`.
    #[serde(default = "default_insecure_skip_verify")]
    pub insecure_skip_verify: bool,
}

fn default_insecure_skip_verify() -> bool {
    false
}

fn default_client_tls_mode() -> MtlsMode {
    MtlsMode::Simple
}

impl Default for MeshTrafficPolicyTls {
    fn default() -> Self {
        // Use a client-side default (`Simple`) instead of the derived
        // `MtlsMode::default() == Permissive` so that `..Default::default()`
        // in callers / tests always produces a value that the cold-path
        // apply treats as a valid DR.tls mode. `Simple` also matches Istio's
        // own `ClientTLSSettings.mode` default when the block is present but
        // `mode` is omitted. Shares the `default_client_tls_mode` helper with
        // the serde field default so the two cannot drift.
        Self {
            mode: default_client_tls_mode(),
            sni: None,
            ca_certificates: None,
            client_certificate: None,
            private_key: None,
            subject_alt_names: Vec::new(),
            insecure_skip_verify: default_insecure_skip_verify(),
        }
    }
}

/// Outlier detection settings from Istio DestinationRule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshOutlierDetection {
    /// Number of consecutive errors before ejecting a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consecutive_errors: Option<u32>,
    /// Detection interval in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u64>,
    /// Base ejection duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ejection_seconds: Option<u64>,
    /// Maximum percentage of hosts that can be ejected (0-100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ejection_percent: Option<u8>,
}

/// Load balancer configuration from Istio DestinationRule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshLoadBalancer {
    /// Simple algorithm selection.
    Simple(MeshSimpleLb),
    /// Consistent hash configuration.
    ConsistentHash(MeshConsistentHash),
}

/// Simple LB algorithm names matching Istio's enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeshSimpleLb {
    RoundRobin,
    LeastRequest,
    Random,
    Passthrough,
}

/// Consistent hash key source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshConsistentHash {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_cookie_name: Option<String>,
    #[serde(default)]
    pub use_source_ip: bool,
}

/// Istio `DestinationRule.trafficPolicy.localityLbSetting` mapped onto
/// Ferrum primitives.
///
/// `enabled` defaults to `true` when the block is present (matches Istio
/// semantics — an explicit `enabled: false` disables locality-aware LB
/// entirely, including the priority-tier preference projected by
/// `Upstream.source_locality`). `distribute` and `failover` are mutually
/// exclusive at evaluation time: when a `distribute` entry matches the
/// source locality the load balancer uses per-locality weights and ignores
/// the priority-tier preference; otherwise `failover` (when configured)
/// adds a fourth tier consulted after `region` and before the unfiltered
/// fallback set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshLocalityLbSetting {
    /// When `false`, disables all locality preference (priority tier,
    /// distribute weighting, and failover override). Defaults to `true`.
    #[serde(default = "default_true_bool")]
    pub enabled: bool,
    /// Per-source-locality weighted distribution to target localities.
    /// Each entry's `to` map values are integer weights (Istio specifies
    /// 0-100 as a percentage). Targets in localities not named by any
    /// matching `to` map are excluded from selection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribute: Vec<MeshLocalityDistribute>,
    /// Per-source-region failover targets. Consulted when no healthy
    /// target exists in the source's exact/zone/region tiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failover: Vec<MeshLocalityFailover>,
}

fn default_true_bool() -> bool {
    true
}

impl Default for MeshLocalityLbSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            distribute: Vec::new(),
            failover: Vec::new(),
        }
    }
}

/// One `localityLbSetting.distribute[]` entry.
///
/// `from` is an Istio-style `region/zone/subzone` locality string. `to`
/// maps target localities (same syntax) to integer weights. Istio's API
/// treats the values as percentages summing to 100; we propagate the
/// integers verbatim and use them as ratios so non-summing operator
/// configurations still produce a deterministic ratio split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLocalityDistribute {
    pub from: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub to: std::collections::BTreeMap<String, u32>,
}

/// One `localityLbSetting.failover[]` entry. `from` and `to` are Istio
/// region names (the first `region/zone/subzone` segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLocalityFailover {
    pub from: String,
    pub to: String,
}

/// Named subset of targets with label selectors and optional policy override.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshSubset {
    pub name: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<MeshTrafficPolicy>,
}

// ── Top-level mesh config container ───────────────────────────────────────

/// All mesh-specific configuration, kept in a single container so the
/// core `GatewayConfig` struct stays lean for non-mesh deployments.
/// Stored as `Option<Box<MeshConfig>>` on `GatewayConfig` — `None` when
/// the operator has no mesh resources, zero cost in that case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Istio root namespace used for mesh-wide policy resources and
    /// cluster-wide Sidecar defaults. Native mesh YAML can override it;
    /// Kubernetes translation fills it from `K8sTranslationOptions`.
    #[serde(
        default = "default_istio_root_namespace",
        skip_serializing_if = "is_default_istio_root_namespace"
    )]
    pub istio_root_namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<Workload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_policies: Vec<MeshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_authentications: Vec<PeerAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<ServiceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_authentications: Vec<MeshRequestAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telemetry_resources: Vec<MeshTelemetryResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<MeshDestinationRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_configs: Vec<MeshProxyConfig>,
    /// Istio `Sidecar` egress-scoping resources. Used by the slice builder
    /// to narrow which services / service-entries / destination-rules a
    /// workload sees. Narrowing is gated by `FERRUM_MESH_SIDECAR_ENFORCED`
    /// (default `false`) — when disabled the field is parsed and persisted
    /// but slice narrowing is skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<MeshSidecar>,
    /// GAMMA Waypoint bindings: a list mapping waypoint names to the set
    /// of services routed through that waypoint. Populated by the K8s
    /// translator from `Gateway` resources whose `gatewayClassName` is
    /// `istio-waypoint` / `ferrum-waypoint` plus `Service` objects
    /// annotated with `istio.io/use-waypoint`. The slice builder consumes
    /// this map when `MeshSliceRequest.waypoint_name == Some(name)` to
    /// narrow `services` / `service_entries` / `destination_rules` /
    /// `workloads` to entries bound to the named waypoint. Empty default
    /// keeps non-mesh and non-waypoint deployments at zero overhead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waypoint_bindings: Vec<MeshWaypointBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<TrustBundleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<MultiClusterConfig>,
    /// Mirrors Istio `MeshConfig.outboundTrafficPolicy.mode`. `None` keeps
    /// the legacy `AllowAny` behavior (no gate). When set to `RegistryOnly`,
    /// the mesh outbound dispatcher rejects requests whose destination does
    /// not appear in the slice-derived known-destinations registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<OutboundTrafficPolicy>,
    /// Operator-defined ECDS resources served by the ADS translator as
    /// `envoy.config.core.v3.TypedExtensionConfig` payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_configs: Vec<crate::modes::mesh::slice::MeshExtensionConfig>,
}

pub fn default_istio_root_namespace() -> String {
    "istio-system".to_string()
}

fn is_default_istio_root_namespace(value: &str) -> bool {
    value == default_istio_root_namespace()
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            istio_root_namespace: default_istio_root_namespace(),
            workloads: Vec::new(),
            services: Vec::new(),
            mesh_policies: Vec::new(),
            peer_authentications: Vec::new(),
            service_entries: Vec::new(),
            request_authentications: Vec::new(),
            telemetry_resources: Vec::new(),
            destination_rules: Vec::new(),
            proxy_configs: Vec::new(),
            sidecars: Vec::new(),
            waypoint_bindings: Vec::new(),
            trust_bundles: None,
            multi_cluster: None,
            outbound_traffic_policy: None,
            extension_configs: Vec::new(),
        }
    }
}

/// One GAMMA Waypoint → services binding. Produced by the K8s translator
/// from Gateway resources with `gatewayClassName: istio-waypoint` /
/// `ferrum-waypoint` plus `Service` annotations
/// (`istio.io/use-waypoint: <name>`). `waypoint_for` mirrors Istio's
/// `istio.io/waypoint-for` annotation: `service` (default) means the
/// waypoint terminates traffic targeted at the listed services;
/// `workload` means it terminates traffic addressed directly to the
/// workload IPs; `all` means both. `none` opts out and yields no binding.
///
/// `services` is the list of `MeshService` references (namespace + name)
/// the operator has bound to this waypoint. The slice builder uses the
/// list as the authoritative narrowing key when
/// `MeshSliceRequest.waypoint_name == Some(name)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshWaypointBinding {
    /// Waypoint name. Matches the `metadata.name` of the Gateway resource
    /// in the K8s flow, and the `istio.io/use-waypoint` annotation value
    /// on bound Services.
    pub name: String,
    /// Namespace the waypoint is scoped to (the Gateway resource's
    /// namespace). Bound services normally live in the same namespace;
    /// `istio.io/use-waypoint-namespace` can override, in which case the
    /// translator emits the cross-namespace ref directly.
    pub namespace: String,
    /// `service` (default), `workload`, `all`, or `none`. Persisted as a
    /// string to keep the schema forward-compatible with future Istio
    /// enum values without requiring a Ferrum-side migration.
    #[serde(default = "default_waypoint_for")]
    pub waypoint_for: String,
    /// Bound services. Empty when the Gateway resource exists but no
    /// `Service` annotation references it; the slice builder treats an
    /// empty binding as "no services pass through this waypoint" and
    /// fails closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshWaypointServiceRef>,
}

fn default_waypoint_for() -> String {
    "service".to_string()
}

/// A `(namespace, service)` reference inside a `MeshWaypointBinding`.
/// Kept as plain strings rather than a `WorkloadRef`-style typed handle
/// so the binding survives slice round-trips through CP→DP gRPC and
/// xDS ECDS without needing a separate per-service lookup table at apply
/// time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshWaypointServiceRef {
    pub namespace: String,
    pub name: String,
}

/// Istio mesh-wide outbound traffic policy. Mirrors
/// `MeshConfig.outboundTrafficPolicy.mode` in the upstream API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundTrafficPolicy {
    /// Sidecar accepts traffic to any destination (no gate). Existing default.
    #[default]
    AllowAny,
    /// Sidecar only accepts traffic to destinations resolved in the mesh
    /// registry (services, service entries, workload addresses) plus their
    /// declared ports. Unknown destinations are rejected at the proxy entry
    /// point with a configurable 4xx/5xx status (default 502).
    ///
    /// HTTP-family only: the gate relies on the `Host` header, so raw TCP
    /// and UDP outbound traffic bypass this policy. The registry is built
    /// from the already-projected mesh slice, so future slice-filtering
    /// refinements naturally narrow the allowed destination set.
    RegistryOnly,
}

impl MeshConfig {
    pub fn validate(&self) -> Vec<String> {
        validate_mesh_config_internal(
            &self.workloads,
            &self.services,
            &self.mesh_policies,
            &self.peer_authentications,
            &self.service_entries,
            &self.request_authentications,
            self.trust_bundles.as_ref(),
            self.multi_cluster.as_ref(),
        )
    }

    pub fn normalize(&mut self) {
        let trimmed_root_namespace = self.istio_root_namespace.trim();
        if trimmed_root_namespace.is_empty() {
            self.istio_root_namespace = default_istio_root_namespace();
        } else if trimmed_root_namespace.len() != self.istio_root_namespace.len() {
            self.istio_root_namespace = trimmed_root_namespace.to_string();
        }
        normalize_mesh_fields_internal(
            &mut self.service_entries,
            &mut self.workloads,
            &mut self.mesh_policies,
            &mut self.destination_rules,
            &mut self.sidecars,
            self.multi_cluster.as_mut(),
        );
    }
}

// ── Validation ────────────────────────────────────────────────────────────

/// Validate the mesh portion of a [`crate::config::types::GatewayConfig`].
///
/// Errors are returned as a flat `Vec<String>` so the file/DB/DP modes can
/// dispatch them per their own error-handling policy (file = fatal, DB =
/// warn, DP = reject update).
pub fn validate_mesh_config(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    request_authentications: &[MeshRequestAuthentication],
    trust_bundles: Option<&TrustBundleSet>,
) -> Vec<String> {
    validate_mesh_config_internal(
        workloads,
        services,
        policies,
        peer_auths,
        service_entries,
        request_authentications,
        trust_bundles,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_mesh_config_internal(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    request_authentications: &[MeshRequestAuthentication],
    trust_bundles: Option<&TrustBundleSet>,
    multi_cluster: Option<&MultiClusterConfig>,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Workloads
    for wl in workloads {
        if wl.spiffe_id.trust_domain() != &wl.trust_domain {
            errors.push(format!(
                "Workload '{}': spiffe_id trust domain '{}' does not match \
                 workload's trust_domain '{}'",
                wl.spiffe_id,
                wl.spiffe_id.trust_domain(),
                wl.trust_domain
            ));
        }
        if wl.namespace.is_empty() {
            errors.push(format!(
                "Workload '{}': namespace must not be empty",
                wl.spiffe_id
            ));
        }
        if wl.service_name.is_empty() {
            errors.push(format!(
                "Workload '{}': service_name must not be empty",
                wl.spiffe_id
            ));
        }
        for (i, address) in wl.addresses.iter().enumerate() {
            if address.trim().is_empty() {
                errors.push(format!(
                    "Workload '{}'.addresses[{}]: address must not be empty",
                    wl.spiffe_id, i
                ));
            }
        }
        if wl
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': network must not be empty when set",
                wl.spiffe_id
            ));
        }
        if wl
            .cluster
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': cluster must not be empty when set",
                wl.spiffe_id
            ));
        }
    }

    // Services
    for svc in services {
        if svc.name.is_empty() {
            errors.push("MeshService: name must not be empty".to_string());
        }
        if svc.namespace.is_empty() {
            errors.push(format!(
                "MeshService '{}': namespace must not be empty",
                svc.name
            ));
        }
    }

    // Policies
    for policy in policies {
        if policy.name.is_empty() {
            errors.push("MeshPolicy: name must not be empty".to_string());
        }
        for (i, rule) in policy.rules.iter().enumerate() {
            for (j, principal) in rule.from.iter().enumerate() {
                if principal.spiffe_id_pattern.is_none()
                    && principal.namespace_pattern.is_none()
                    && principal.trust_domain.is_none()
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}]: at least one \
                         of spiffe_id_pattern/namespace_pattern/trust_domain \
                         must be set",
                        policy.name, i, j
                    ));
                }
                if let Some(pat) = principal.spiffe_id_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].spiffe_id_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
                if let Some(pat) = principal.namespace_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].namespace_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
            }
            for (j, request) in rule.to.iter().enumerate() {
                let any_method = !request.methods.is_empty();
                let any_path = !request.paths.is_empty();
                let any_host = !request.hosts.is_empty();
                let any_header = !request.headers.is_empty();
                let any_port = !request.ports.is_empty() || !request.port_patterns.is_empty();
                let any_not = !request.not_methods.is_empty()
                    || !request.not_paths.is_empty()
                    || !request.not_hosts.is_empty()
                    || !request.not_ports.is_empty();
                if !(any_method || any_path || any_host || any_header || any_port || any_not) {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].to[{}]: at least one of \
                         methods/paths/hosts/headers/ports or their negated \
                         counterparts must be non-empty",
                        policy.name, i, j
                    ));
                }
                for (k, host) in request.hosts.iter().enumerate() {
                    if !is_valid_request_match_host_pattern(host) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].hosts[{}] \
                             '{}' is not a valid host pattern \
                             (expected hostname, [ipv6], or host:port/host:* \
                             with u16 numeric or '*' port)",
                            policy.name, i, j, k, host
                        ));
                    }
                }
                for (k, host) in request.not_hosts.iter().enumerate() {
                    if !is_valid_request_match_host_pattern(host) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].not_hosts[{}] \
                             '{}' is not a valid host pattern \
                             (expected hostname, [ipv6], or host:port/host:* \
                             with u16 numeric or '*' port)",
                            policy.name, i, j, k, host
                        ));
                    }
                }
                for (k, pattern) in request.port_patterns.iter().enumerate() {
                    if !is_valid_request_match_port_pattern(pattern) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].port_patterns[{}] \
                             '{}' is not a valid port pattern \
                             (expected '*', '<digits>*', or '*<digits>')",
                            policy.name, i, j, k, pattern
                        ));
                    }
                }
            }
        }
    }

    // PeerAuthentications
    for pa in peer_auths {
        if pa.name.is_empty() {
            errors.push("PeerAuthentication: name must not be empty".to_string());
        }
        if pa.namespace.is_empty() {
            errors.push(format!(
                "PeerAuthentication '{}': namespace must not be empty",
                pa.name
            ));
        }
    }

    // RequestAuthentications
    for ra in request_authentications {
        if ra.name.is_empty() {
            errors.push("MeshRequestAuthentication: name must not be empty".to_string());
        }
        if ra.namespace.is_empty() {
            errors.push(format!(
                "MeshRequestAuthentication '{}': namespace must not be empty",
                ra.name
            ));
        }
        for (i, rule) in ra.jwt_rules.iter().enumerate() {
            if rule.issuer.trim().is_empty() {
                errors.push(format!(
                    "MeshRequestAuthentication '{}' jwt_rules[{}]: issuer must not be empty",
                    ra.name, i
                ));
            }
            if rule.jwks_uri.is_none() && rule.jwks.is_none() {
                errors.push(format!(
                    "MeshRequestAuthentication '{}' jwt_rules[{}]: one of jwks_uri or jwks is required",
                    ra.name, i
                ));
            }
        }
    }

    // ServiceEntries
    for se in service_entries {
        if se.name.is_empty() {
            errors.push("ServiceEntry: name must not be empty".to_string());
        }
        if se.hosts.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': hosts must not be empty",
                se.name
            ));
        }
        if se.resolution != Resolution::Static && !se.endpoints.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': endpoints are only valid when resolution=static",
                se.name
            ));
        }
    }

    // Trust bundles
    if let Some(tb_set) = trust_bundles {
        if tb_set.local.x509_authorities.is_empty() && tb_set.local.jwt_authorities.is_empty() {
            errors.push(format!(
                "TrustBundleSet.local for trust domain '{}' has no authorities",
                tb_set.local.trust_domain
            ));
        }
        if let Err(e) = tb_set.local.decode_x509_authorities() {
            errors.push(format!("TrustBundleSet.local: {e}"));
        }
        let mut seen_trust_domains = HashSet::from([tb_set.local.trust_domain.clone()]);
        for fed in &tb_set.federated {
            if !seen_trust_domains.insert(fed.trust_domain.clone()) {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: duplicate trust domain",
                    fed.trust_domain
                ));
            }
            if fed.x509_authorities.is_empty() && fed.jwt_authorities.is_empty() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: no authorities",
                    fed.trust_domain
                ));
            }
            if let Err(e) = fed.decode_x509_authorities() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: {e}",
                    fed.trust_domain
                ));
            }
        }
    }

    if let Some(multi_cluster) = multi_cluster {
        validate_multi_cluster(multi_cluster, trust_bundles, &mut errors);
    }

    errors
}

fn validate_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundles: Option<&TrustBundleSet>,
    errors: &mut Vec<String>,
) {
    if multi_cluster
        .local_cluster
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors.push("MultiClusterConfig.local_cluster must not be empty when set".to_string());
    }
    if multi_cluster
        .federation_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors
            .push("MultiClusterConfig.federation_endpoint must not be empty when set".to_string());
    }

    let mut seen_cluster_names = HashSet::new();
    for remote in &multi_cluster.remote_clusters {
        if remote.name.trim().is_empty() {
            errors.push("RemoteCluster: name must not be empty".to_string());
        } else if !seen_cluster_names.insert(remote.name.as_str()) {
            errors.push(format!("RemoteCluster '{}': duplicate name", remote.name));
        }
        if remote
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': network must not be empty when set",
                remote.name
            ));
        }
        if remote
            .control_plane_url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': control_plane_url must not be empty when set",
                remote.name
            ));
        }
        if remote
            .federation_endpoint
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': federation_endpoint must not be empty when set",
                remote.name
            ));
        }

        if let Some(tb_set) = trust_bundles
            && remote.trust_domain != tb_set.local.trust_domain
            && !tb_set
                .federated
                .iter()
                .any(|bundle| bundle.trust_domain == remote.trust_domain)
        {
            errors.push(format!(
                "RemoteCluster '{}': trust domain '{}' has no matching federated trust bundle",
                remote.name, remote.trust_domain
            ));
        }
    }

    let mut seen_sni_routes: HashSet<String> = HashSet::new();
    for gateway in &multi_cluster.east_west_gateways {
        if gateway.name.trim().is_empty() {
            errors.push("EastWestGateway: name must not be empty".to_string());
        }
        if gateway.namespace.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': namespace must not be empty",
                gateway.name
            ));
        }
        if gateway.host.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': host must not be empty",
                gateway.name
            ));
        }
        if gateway.port == 0 {
            errors.push(format!(
                "EastWestGateway '{}': port must be between 1 and 65535",
                gateway.name
            ));
        }
        if gateway.sni_hosts.is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': sni_hosts must not be empty",
                gateway.name
            ));
        }
        if gateway
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "EastWestGateway '{}': network must not be empty when set",
                gateway.name
            ));
        }
        for sni in &gateway.sni_hosts {
            if sni.trim().is_empty() {
                errors.push(format!(
                    "EastWestGateway '{}': sni_hosts must not contain empty entries",
                    gateway.name
                ));
                continue;
            }
            if !seen_sni_routes.insert(sni.to_ascii_lowercase()) {
                errors.push(format!(
                    "EastWestGateway '{}': duplicate SNI host '{}'",
                    gateway.name, sni
                ));
            }
        }
    }
}

/// Lower-case in-place hostname normalisation for mesh entries — matches
/// the existing `normalize_fields()` pattern used elsewhere in
/// [`crate::config::types`]. Idempotent.
pub fn normalize_mesh_fields(service_entries: &mut [ServiceEntry], workloads: &mut [Workload]) {
    normalize_mesh_fields_internal(service_entries, workloads, &mut [], &mut [], &mut [], None);
}

fn normalize_mesh_fields_internal(
    service_entries: &mut [ServiceEntry],
    workloads: &mut [Workload],
    policies: &mut [MeshPolicy],
    destination_rules: &mut [MeshDestinationRule],
    sidecars: &mut [MeshSidecar],
    multi_cluster: Option<&mut MultiClusterConfig>,
) {
    for se in service_entries {
        for host in &mut se.hosts {
            *host = normalize_mesh_hostname_like(host);
        }
        for ep in &mut se.endpoints {
            ep.address.make_ascii_lowercase();
        }
    }
    for workload in workloads {
        for address in &mut workload.addresses {
            address.make_ascii_lowercase();
        }
    }
    normalize_mesh_policy_fields(policies);
    for dr in destination_rules {
        dr.host = normalize_mesh_hostname_like(&dr.host);
    }
    for sidecar in sidecars {
        for egress in &mut sidecar.egress {
            for host in &mut egress.hosts {
                *host = normalize_mesh_hostname_like(host);
            }
        }
    }
    if let Some(multi_cluster) = multi_cluster {
        for gateway in &mut multi_cluster.east_west_gateways {
            gateway.host.make_ascii_lowercase();
            for sni in &mut gateway.sni_hosts {
                sni.make_ascii_lowercase();
            }
        }
    }
}

fn normalize_mesh_hostname_like(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_mesh_policy_fields(policies: &mut [MeshPolicy]) {
    for policy in policies {
        for rule in &mut policy.rules {
            for request in &mut rule.to {
                for host in &mut request.hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for host in &mut request.not_hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for pattern in &mut request.port_patterns {
                    let trimmed = pattern.trim();
                    if trimmed.len() != pattern.len() {
                        *pattern = trimmed.to_string();
                    }
                }
                normalize_mesh_policy_header_map(&mut request.headers);
            }
        }
    }
}

/// Normalise a `RequestMatch.hosts` glob pattern at config-load time so the
/// authorization hot path never re-normalises on every request.
///
/// Mirrors `normalize_match_host` for inbound request authorities so a pattern
/// `Example.COM:8443` and a request `example.com:8443` produce equal strings.
/// Lower-cases ASCII, strips a trailing dot from the host portion, and
/// preserves any explicit `:port` (or `:*`) suffix.
pub(crate) fn normalize_request_match_host_pattern(pattern: &str) -> String {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.starts_with('[') {
        return pattern;
    }
    if let Some((name, port)) = pattern.rsplit_once(':')
        && !name.contains(':')
    {
        let name = name.strip_suffix('.').unwrap_or(name);
        return format!("{name}:{port}");
    }
    pattern
        .strip_suffix('.')
        .map(ToOwned::to_owned)
        .unwrap_or(pattern)
}

/// True when `pattern` is one of the three Istio-allowed port wildcard forms:
/// `*`, `<digits>*`, or `*<digits>`. Mirrors `is_istio_port_pattern` in the
/// Istio translator so direct-config and translated configs validate
/// identically.
pub(crate) fn is_valid_request_match_port_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit());
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

/// True when `pattern` is a syntactically valid `RequestMatch.hosts` entry.
///
/// Accepts:
///   - bare hostname / glob (any chars except `:`, `@`)
///   - bracketed IPv6 literal `[...]`, optionally followed by `:port` or `:*`
///   - `host:port` or `host:*` where `host` has no other `:`
///
/// Rejects:
///   - empty / `@`-bearing values
///   - `host:abc` / `host:` (port is neither digits nor `*`)
///   - multiple `:` outside an IPv6 bracket
fn is_valid_request_match_host_pattern(pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.contains('@') {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        if close == 0 {
            return false;
        }
        let suffix = &rest[close + 1..];
        return suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(is_request_match_host_port_token);
    }
    match pattern.rsplit_once(':') {
        Some((name, port)) => {
            !name.is_empty() && !name.contains(':') && is_request_match_host_port_token(port)
        }
        None => true,
    }
}

fn is_request_match_host_port_token(token: &str) -> bool {
    if token == "*" {
        return true;
    }
    token.parse::<u16>().is_ok()
}

pub(crate) fn normalize_mesh_policy_header_map(headers: &mut HashMap<String, String>) {
    if headers
        .keys()
        .all(|key| key.bytes().all(|byte| !byte.is_ascii_uppercase()))
    {
        return;
    }

    let mut normalized = HashMap::with_capacity(headers.len());
    for (key, value) in headers.iter() {
        let lower = key.to_ascii_lowercase();
        if let Some(existing) = normalized.get(&lower)
            && existing != value
        {
            return;
        }
        normalized.insert(lower, value.clone());
    }

    *headers = normalized;
}

// ── MeshRuntimeOverlay (GAP-3E) ───────────────────────────────────────────

/// Mesh runtime knobs sourced from xDS RTDS (`envoy.service.runtime.v3.Runtime`)
/// layers.
///
/// The overlay is carried verbatim on
/// [`crate::modes::mesh::slice::MeshSlice`]; operators inspect it via
/// `GET /mesh/runtime-overlay`. Every slice install fans the overlay out to
/// three live consumers via
/// [`crate::modes::mesh::runtime_overlay_consumers::apply_overlay`]:
/// fault-injection percentages
/// ([`crate::plugins::fault_injection::runtime_overlay`]), request/response
/// transformer gates
/// ([`crate::plugins::request_transformer::runtime_overlay`],
/// [`crate::plugins::response_transformer::runtime_overlay`]), and the
/// gateway-wide tracing filter
/// ([`crate::logging::runtime_overlay`]). Adding a new consumer is a single
/// `apply_*` call from `runtime_overlay_consumers`.
///
/// Wire compatibility: the type is an optional field on `MeshSlice` with
/// `#[serde(default, skip_serializing_if = "MeshRuntimeOverlay::is_empty")]`,
/// so non-RTDS deployments round-trip byte-identical.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshRuntimeOverlay {
    /// Top-level keys flattened from the RTDS layer's `google.protobuf.Struct`
    /// payload. Keys are runtime feature names
    /// (e.g. `envoy.reloadable_features.allow_multiplexed_response`); values
    /// preserve the typed shape from the wire.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub fields: HashMap<String, RuntimeValue>,
}

impl MeshRuntimeOverlay {
    /// Cheap emptiness check used by both `skip_serializing_if` and runtime
    /// callers that want to elide overlay handling when no layer has shipped
    /// any fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Typed runtime value mapped from an RTDS layer field.
///
/// Mirrors the subset of `google.protobuf.Value` kinds that RTDS layers ship
/// in practice. `null` and list values are intentionally absent — Envoy / Istio
/// CPs do not emit them as runtime knob values today, and inventing a
/// placeholder semantics here would be a footgun once consumers land.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RuntimeValue {
    Number(f64),
    String(String),
    Bool(bool),
    FractionalPercent(RuntimeFractionalPercent),
}

/// Envoy `type.v3.FractionalPercent`-shaped runtime value. RTDS layers
/// encode it on the wire as a `google.protobuf.Struct` with two fields,
/// `numerator: number` and `denominator: string`, where the string is one of
/// the three named denominators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFractionalPercent {
    pub numerator: u32,
    pub denominator: FractionalPercentDenominator,
}

impl RuntimeFractionalPercent {
    /// Convert to a 0.0–100.0 percentage. Saturates at 100.0 if the operator
    /// supplied a numerator larger than the denominator. Used by RTDS
    /// consumers that work in `f64` percent space (e.g. fault injection).
    pub fn as_percent(&self) -> f64 {
        let denom = self.denominator.units_per_full();
        if denom == 0 {
            return 0.0;
        }
        let pct = (self.numerator as f64 / denom as f64) * 100.0;
        pct.clamp(0.0, 100.0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FractionalPercentDenominator {
    #[default]
    Hundred,
    TenThousand,
    Million,
}

impl FractionalPercentDenominator {
    /// The number of units the `numerator` is expressed against. `Hundred`
    /// → 100, `TenThousand` → 10_000, `Million` → 1_000_000.
    pub fn units_per_full(&self) -> u64 {
        match self {
            FractionalPercentDenominator::Hundred => 100,
            FractionalPercentDenominator::TenThousand => 10_000,
            FractionalPercentDenominator::Million => 1_000_000,
        }
    }
}

/// Extract a `0.0..=100.0` percentage from a [`RuntimeValue`] for consumers
/// that work in percent space. Accepts:
///
///   - `RuntimeValue::Number(n)` where `0.0 <= n <= 100.0`
///   - `RuntimeValue::FractionalPercent(fp)` (via `as_percent`)
///
/// Returns `None` for any other shape so RTDS consumers can fall back to
/// their static config without aborting the slice install.
pub fn runtime_value_as_percent(value: &RuntimeValue) -> Option<f64> {
    match value {
        RuntimeValue::Number(n) if n.is_finite() && (0.0..=100.0).contains(n) => Some(*n),
        RuntimeValue::FractionalPercent(fp) => Some(fp.as_percent()),
        _ => None,
    }
}
