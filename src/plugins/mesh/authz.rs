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

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::config::{
    MeshPolicy, PolicyAction, PolicyScope, is_mesh_condition_ip_key,
    is_supported_mesh_condition_key, mesh_condition_has_values,
    normalize_request_match_host_pattern, policy_scope_applies_to_workload,
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

pub struct MeshAuthz {
    slice: MeshSlice,
    destination_policy_scopes_by_upstream:
        HashMap<String, Vec<crate::modes::mesh::runtime::PolicyScopeCache>>,
    has_header_rules: bool,
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

fn destination_policy_scopes_by_upstream(
    slice: &MeshSlice,
) -> HashMap<String, Vec<crate::modes::mesh::runtime::PolicyScopeCache>> {
    let mut scopes_by_upstream = HashMap::new();
    for service in &slice.services {
        let scopes: Vec<_> = if service.workloads.is_empty() {
            slice
                .workloads
                .iter()
                .filter(|workload| {
                    workload.namespace == service.namespace && workload.service_name == service.name
                })
                .map(crate::modes::mesh::runtime::PolicyScopeCache::from_workload)
                .collect()
        } else {
            service
                .workloads
                .iter()
                .filter_map(|workload_ref| {
                    slice.workloads.iter().find(|workload| {
                        workload.spiffe_id == workload_ref.spiffe_id
                            && workload.namespace == service.namespace
                            && workload.service_name == service.name
                    })
                })
                .map(crate::modes::mesh::runtime::PolicyScopeCache::from_workload)
                .collect()
        };
        if scopes.is_empty() {
            continue;
        }
        for service_port in &service.ports {
            scopes_by_upstream.insert(
                crate::modes::mesh::mesh_outbound_upstream_id(
                    &service.namespace,
                    &service.name,
                    service_port.port,
                ),
                scopes.clone(),
            );
        }
    }
    scopes_by_upstream
}

fn policy_applies_to_any_scope<'a>(
    policy: &MeshPolicy,
    scopes: impl IntoIterator<Item = &'a crate::modes::mesh::runtime::PolicyScopeCache>,
) -> bool {
    scopes.into_iter().any(|scope| scope.policy_applies(policy))
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

        for policy in &mut slice.mesh_policies {
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
        let has_header_rules = mesh_policies_have_header_rules(&slice.mesh_policies);
        let condition_keys = ConditionAttributeKeys::from_policies(&slice.mesh_policies);
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
        let destination_policy_scopes_by_upstream = if per_pod_policy_scoping {
            destination_policy_scopes_by_upstream(&slice)
        } else {
            HashMap::new()
        };
        Ok(Self {
            slice,
            destination_policy_scopes_by_upstream,
            has_header_rules,
            trust_domain_aliases,
            trusted_hbone_assertors,
            per_pod_policy_scoping,
            has_scoped_policies,
            condition_keys,
        })
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
        ctx: &RequestContext,
        source_principal: Option<&SpiffeId>,
        port: Option<u16>,
        source_ip: Option<std::net::IpAddr>,
        remote_ip: Option<std::net::IpAddr>,
        headers: &BTreeMap<String, String>,
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
        resolved_ip: Option<std::net::IpAddr>,
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
        if keys.source_ip
            && let Some(ip) = resolved_ip
        {
            attributes.insert(ATTR_SOURCE_IP.to_string(), ip.to_string().into());
        }
        if keys.remote_ip
            && let Some(ip) = resolved_ip
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
        let (source_principal, baggage_outcome) = self.resolve_source_principal(ctx);
        // Capture the resolved authz principal up front so the
        // /mesh/policy-denies/recent drilldown records the identity the rule
        // actually saw, including the HBONE baggage rewrite for trusted
        // assertors. `source_principal` is moved into `MeshAuthzRequest`
        // below, so we own a separate `String` here. For the synthesised
        // deny paths (untrusted_assertor / trust_domain_mismatch /
        // unauthenticated_baggage) `resolve_source_principal` already
        // returns the peer cert identity (or `None`), so logging this value
        // is consistent across all branches.
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
        let headers = if self.has_header_rules {
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
        let attributes = self.build_http_condition_attributes(
            ctx,
            source_principal.as_ref(),
            port,
            source_ip,
            remote_ip,
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
        let decision = if self.per_pod_policy_scoping {
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
                    body: r#"{"error":"Mesh authorization denied: missing per-pod policy scope"}"#
                        .into(),
                    headers: HashMap::new(),
                };
            }
            let destination_scopes = ctx
                .matched_proxy
                .as_ref()
                .and_then(|proxy| proxy.upstream_id.as_deref())
                .and_then(|upstream_id| {
                    self.destination_policy_scopes_by_upstream
                        .get(upstream_id)
                        .map(Vec::as_slice)
                });
            let scope = ctx.node_waypoint_policy_scope.as_deref();
            let policies = self.slice.mesh_policies.iter().filter(|policy| {
                if let Some(destination_scopes) = destination_scopes {
                    policy_applies_to_any_scope(policy, destination_scopes.iter())
                } else {
                    Self::policy_applies_to_pod(policy, scope)
                }
            });
            evaluate_mesh_authorization_policies(policies, &request)
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
        let resolved_ip = parse_client_ip(&ctx.client_ip);
        let attributes =
            self.build_stream_condition_attributes(ctx, source_principal.as_ref(), resolved_ip);
        let request = MeshAuthzRequest {
            source_principal,
            port: Some(ctx.listen_port),
            attributes,
            source_ip: resolved_ip,
            remote_ip: resolved_ip,
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
