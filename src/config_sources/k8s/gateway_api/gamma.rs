//! Gateway API GAMMA routes: `HTTPRoute` and `GRPCRoute` objects whose
//! `parentRefs` name a core `Service` (issue #7538).
//!
//! A Service parent attaches a route to the Service's *frontend* (its name and
//! cluster IP) for mesh traffic, instead of to a Gateway listener. Every route
//! attached to one Service from one namespace is translated into ONE mesh route
//! — a `/` proxy for the Service's host (and IPv4 cluster IPs) whose single
//! `mesh_route_dispatch` instance carries every rule of every attached route,
//! each with an explicit path predicate, ordered by Gateway API precedence
//! across all of them and `reject_unmatched` — carried to the mesh data planes
//! that already apply carried routes (Sidecar and NodeWaypoint) through the
//! existing `mesh.virtual_service_http_routes` binding, `MeshSlice.http_routes`
//! and `HttpRoutesCarrier`, with no wire change:
//!
//! * the proxy is `istio-vs-gamma_service-…__<digest>`, inside the
//!   translator-owned `istio-vs-` space every data-plane ownership check and
//!   controller withdrawal list keys on (`_` never appears in a Kubernetes name,
//!   so no VirtualService id collides with one). The data plane admits a GAMMA
//!   proxy only on an OUTBOUND mesh listener
//!   (`modes::mesh::mesh_route_admitted_for_direction`), so the same snapshot on
//!   a gateway listener or an inbound mesh listener serves nothing for it;
//! * weighted backends ride an `istio-vs-upstream-gamma_<kind>-…` upstream whose
//!   targets are Service hosts, which the data plane rebinds onto its own mesh
//!   transport exactly as it does VirtualService split legs;
//! * rule actions come from the shared Gateway-bound builders
//!   (`gateway_api_dispatch_route_rule`, transformers), so filter, match,
//!   timeout and retry coverage and every `Accepted=False` refusal reason are
//!   the Gateway-bound route's;
//! * the binding is `gamma_<service namespace>_<service>` in the route
//!   namespace, `exportTo: ["*"]` for a producer route (route in the Service's
//!   namespace) and namespace-local for a consumer route.
//!
//! One dispatch instance per Service means a rule on a longer path never hides
//! a matching rule on a shorter path, a regex path, or another port: the first
//! rule (in precedence order) whose path, method, headers, query parameters
//! and port all match serves the request, and a request no rule matches is
//! rejected (404), as GAMMA requires.
//!
//! Precedence (decided in [`finalize`], over the complete snapshot):
//!
//! 1. A mesh-bound VirtualService whose `http[]` route names the Service (any
//!    exact alias of its host) and is visible in the route's namespace wins;
//!    every GAMMA route for that Service there is `Conflicted`, never applied.
//! 2. On one Service port, GRPCRoute wins over HTTPRoute (GEP-1294). An
//!    HTTPRoute keeps its other ports; a parentRef whose port is lost is
//!    `Conflicted`.
//! 3. Rules of every surviving route are ordered by Gateway API precedence:
//!    exact path, longest prefix, regex, method, header count, query count,
//!    oldest route, namespace/name, rule and match order. An identical match
//!    is therefore served by the oldest route.
//! 4. A `/` route slot already served by a non-GAMMA proxy for an overlapping
//!    host is never taken over; the GAMMA routes are `Conflicted`.
//!
//! A parentRef `port` (or `sectionName`, the Service port name) scopes the
//! route to that port: each of its rules carries the port predicate, and
//! HTTP-family ports of the Service no attached route covers get pass-through
//! rules to the Service on that port.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Map, Value, json};

use crate::config::types::{BackendScheme, Proxy, Upstream};
use crate::config_sources::k8s::backend_ref::{BackendKind, backend_target_missing};
use crate::config_sources::k8s::{
    GammaParentKey, GammaParentOutcome, K8sAccumulator, K8sObject, K8sResourceKey,
    K8sTranslateError, MeshRouteDispatchDestination, ProxyUpsert, RouteBackend, RouteProxySpec,
    SourceKind, attach_route_plugins_to_proxy, invalid_resource,
    mesh_route_dispatch_plugin_from_rules, optional_port_field, proxy_for_route,
    route_backends_require_node_waypoint_authz, route_request_transformer_plugin_for_proxy,
    route_response_transformer_plugin_for_proxy, service_dns_name, string_field,
    upstream_for_route,
};
use crate::modes::mesh::config::{
    MeshVirtualServiceHttpRoutes, virtual_service_http_routes_exported_to_namespace,
};
use crate::time_compat::UtcTimestamp;

use super::{
    BackendRefFaultReason, GATEWAY_API_DISPATCH_PRECEDENCE_KEY,
    GATEWAY_API_ROUTE_DERIVED_PLUGIN_ID_PREFIX_LEN, RouteBackendResolution,
    RouteMatchEntryDescriptor, RouteRuleActions, ZERO_WEIGHT_BACKEND_PORT,
    backend_ref_fault_percentage, backend_ref_fault_value_with_percentage,
    backend_ref_resolution_reason, checked_backend_namespace_with_grant_policy,
    compare_creation_timestamps, compare_dispatch_rule_precedence, dispatch_rule_precedence,
    dispatch_rules_carry_field, ensure_http_route_features, error_is_backend_ref_resolution,
    gateway_api_default_path_prefix_match, gateway_api_dispatch_route_rule,
    gateway_api_source_bound_id, gateway_backend_weight, gateway_request_header_modifier_rules,
    gateway_request_redirect_value, gateway_response_header_modifier_rules,
    gateway_route_rule_retry, gateway_route_rule_timeouts, gateway_url_rewrite_value,
    grpc_any_call_match, grpc_dispatch_match_criteria, grpc_dispatch_match_criteria_for,
    has_only_zero_weight_backend_refs, http_route_dispatch_match_criteria,
    normalize_backend_weights_to_target_limit, parse_k8s_timestamp,
    route_match_descriptor_for_entry, route_match_entry_descriptors,
};

/// Readable prefix of a group's one route proxy (inside
/// [`crate::modes::mesh::config::GAMMA_HTTP_ROUTE_PROXY_ID_PREFIX`]).
const GAMMA_SERVICE_PROXY_READABLE_PREFIX: &str = "istio-vs-gamma_service";
/// Prefix of the `mesh.virtual_service_http_routes` binding name a GAMMA route
/// group writes (`gamma_<service namespace>_<service>`). Kubernetes names never
/// contain `_`, so it never collides with a VirtualService binding.
pub(crate) const GAMMA_ROUTE_BINDING_NAME_PREFIX: &str = "gamma_";
use crate::modes::mesh::config::{GAMMA_NO_FORWARD_HOST, GAMMA_ROUTE_UPSTREAM_ID_PREFIX};
/// Internal path-precedence metadata on a GAMMA dispatch rule; stripped before
/// the rule leaves translation.
const GAMMA_PATH_PRECEDENCE_KEY: &str = "_ferrum_gamma_path_precedence";

/// Where a programmed GAMMA route is applied in this release, for status.
pub(crate) const GAMMA_ROUTE_PROGRAMMED_SCOPE_NOTE: &str = "applied by Sidecar and NodeWaypoint \
     mesh data planes to clients in the route's namespace; ServiceWaypoint data planes and \
     clients in other namespaces are not served yet (issue #7538)";

/// Whether `id` is a GAMMA route proxy id.
pub(crate) fn is_gamma_route_proxy_id(id: &str) -> bool {
    crate::modes::mesh::config::is_gamma_http_route_proxy_id(id)
}

/// Whether a route `parentRef` names a core `Service` (the GAMMA mesh
/// binding). The ParentReference defaults are `group:
/// gateway.networking.k8s.io` and `kind: Gateway`, so a Service parent spells
/// both out; the core group is `""` (upstream examples also write `core`).
pub(crate) fn parent_ref_is_service(parent_ref: &Value) -> bool {
    let group = string_field(parent_ref, "group").unwrap_or("gateway.networking.k8s.io");
    let kind = string_field(parent_ref, "kind").unwrap_or("Gateway");
    (group.is_empty() || group == "core") && kind == "Service"
}

/// Whether an `HTTPRoute` / `GRPCRoute` declares at least one Service parent.
pub(crate) fn route_has_service_parent_ref(object: &K8sObject) -> bool {
    matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute")
        && object
            .spec
            .get("parentRefs")
            .and_then(Value::as_array)
            .is_some_and(|parent_refs| parent_refs.iter().any(parent_ref_is_service))
}

/// The canonical key of one Service parentRef, shared by translation (which
/// records each parent's outcome under it) and the status writer (which looks
/// the outcome up). `""` and `core` spell the same group.
pub(crate) fn gamma_parent_ref_key(route_namespace: &str, parent_ref: &Value) -> String {
    let namespace = string_field(parent_ref, "namespace").unwrap_or(route_namespace);
    let name = string_field(parent_ref, "name").unwrap_or("*");
    let section = string_field(parent_ref, "sectionName").unwrap_or("*");
    let port = parent_ref
        .get("port")
        .and_then(Value::as_u64)
        .map_or_else(|| "*".to_string(), |port| port.to_string());
    format!("core/Service/{namespace}/{name}/{section}/{port}")
}

fn gamma_binding_name(service_namespace: &str, service_name: &str) -> String {
    format!("{GAMMA_ROUTE_BINDING_NAME_PREFIX}{service_namespace}_{service_name}")
}

/// One resolved Service parentRef: its status key and the Service port it
/// names (`None`: every port).
#[derive(Debug, Clone)]
struct GammaParent {
    key: String,
    port: Option<u16>,
}

/// One `(route, Service)` attachment admitted in the per-object pass, awaiting
/// snapshot-wide precedence in [`finalize`].
#[derive(Debug, Clone)]
pub(crate) struct GammaStagedRoute {
    object: K8sObject,
    route: K8sResourceKey,
    creation_timestamp: Option<UtcTimestamp>,
    service_namespace: String,
    service_name: String,
    /// HTTP-family Service ports the route attaches to; `None` is every port.
    ports: Option<BTreeSet<u16>>,
    parents: Vec<GammaParent>,
    /// A reason this attachment is accepted or refused without being carried.
    blocked: Option<GammaParentOutcome>,
}

#[derive(Default)]
struct GammaRouteResources {
    /// Dispatch rules, each with an explicit path predicate and internal
    /// precedence metadata ([`GATEWAY_API_DISPATCH_PRECEDENCE_KEY`],
    /// [`GAMMA_PATH_PRECEDENCE_KEY`]).
    rules: Vec<Value>,
    upstreams: Vec<Upstream>,
    blocked: Option<GammaParentOutcome>,
}

/// The Service ports mesh data planes route HTTP on (the same classification
/// the data plane's outbound materializer uses).
fn service_http_ports(acc: &K8sAccumulator, namespace: &str, name: &str) -> BTreeSet<u16> {
    acc.service_http_family_ports
        .get(&(namespace.to_string(), name.to_string()))
        .cloned()
        .unwrap_or_default()
}

fn record_parent(
    acc: &mut K8sAccumulator,
    staged: &GammaStagedRoute,
    parent: &GammaParent,
    outcome: &GammaParentOutcome,
) {
    acc.gamma_route_parents.insert(
        GammaParentKey {
            route: staged.route.clone(),
            parent_ref: parent.key.clone(),
        },
        outcome.clone(),
    );
}

fn record_outcome(
    acc: &mut K8sAccumulator,
    staged: &GammaStagedRoute,
    outcome: &GammaParentOutcome,
) {
    for parent in &staged.parents {
        record_parent(acc, staged, parent, outcome);
    }
}

/// Resolve one Service parentRef to `(namespace, name, port)`, or the
/// `NoMatchingParent` outcome that refuses it. Diagnostics quote supplied names
/// with Debug escaping and never echo a port number.
fn resolve_service_parent(
    acc: &K8sAccumulator,
    route_namespace: &str,
    parent_ref: &Value,
) -> Result<(String, String, Option<u16>), GammaParentOutcome> {
    let no_match = |message: String| GammaParentOutcome::NoMatchingParent { message };
    let namespace = string_field(parent_ref, "namespace").unwrap_or(route_namespace);
    let Some(name) = string_field(parent_ref, "name").filter(|name| !name.is_empty()) else {
        return Err(no_match(
            "the Service parentRef names no Service".to_string(),
        ));
    };
    if !acc.service_exists(namespace, name) {
        return Err(no_match(format!(
            "Service {namespace:?}/{name:?} was not found in the namespaces this control plane \
             watches"
        )));
    }
    if acc.service_is_external_name(namespace, name) {
        return Err(no_match(format!(
            "Service {namespace:?}/{name:?} is type ExternalName and has no Service frontend for \
             the mesh to route"
        )));
    }
    if acc.service_is_headless(namespace, name) {
        return Err(no_match(format!(
            "Service {namespace:?}/{name:?} is headless (clusterIP: None) and has no Service \
             frontend for the mesh to route"
        )));
    }
    let section_port = match string_field(parent_ref, "sectionName") {
        Some(section) => match acc.lookup_service_port(namespace, name, section) {
            Some(port) => Some(port),
            None => {
                return Err(no_match(format!(
                    "sectionName {section:?} does not name a port of Service {namespace:?}/{name:?}"
                )));
            }
        },
        None => None,
    };
    let port = match parent_ref.get("port") {
        Some(value) => {
            let Some(port) = value
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
            else {
                return Err(no_match(
                    "the Service parentRef port is not a valid port number".to_string(),
                ));
            };
            if !acc.service_port_exists(namespace, name, port) {
                return Err(no_match(format!(
                    "the parentRef port is not a port of Service {namespace:?}/{name:?}"
                )));
            }
            Some(port)
        }
        None => None,
    };
    if let (Some(section_port), Some(port)) = (section_port, port)
        && section_port != port
    {
        return Err(no_match(format!(
            "the parentRef sectionName and port name different ports of Service \
             {namespace:?}/{name:?}"
        )));
    }
    let port = port.or(section_port);
    let http_ports = service_http_ports(acc, namespace, name);
    if let Some(port) = port
        && !http_ports.contains(&port)
    {
        return Err(no_match(format!(
            "the parentRef selects a port of Service {namespace:?}/{name:?} that mesh data \
             planes do not route HTTP on (its protocol, name and appProtocol mark it as a \
             non-HTTP port)"
        )));
    }
    if http_ports.is_empty() {
        return Err(no_match(format!(
            "Service {namespace:?}/{name:?} has no port mesh data planes route HTTP on"
        )));
    }
    Ok((namespace.to_string(), name.to_string(), port))
}

/// Per-object pass: admit the Service parents of one `HTTPRoute` /
/// `GRPCRoute` and stage each `(route, Service)` attachment.
///
/// Route content is admitted exactly as for a Gateway-bound route
/// (`ensure_http_route_features`): an unsupported field, filter or value
/// refuses the whole route with the same `Accepted=False` reason, and the
/// reconciler retranslates without it. Each attachment is built once here so
/// any other malformed value is refused the same way, atomically. A parent that
/// does not resolve is recorded per parent and refuses nothing else.
pub(super) fn stage_service_parent_routes(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    if !route_has_service_parent_ref(object) {
        return Ok(());
    }
    ensure_http_route_features(object)?;
    let route = K8sResourceKey::from_object(object);
    let route_namespace = object.metadata.namespace.as_str();
    let mut services: BTreeMap<(String, String), Vec<GammaParent>> = BTreeMap::new();
    let parent_refs: Vec<&Value> = object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|parent_ref| parent_ref_is_service(parent_ref))
        .collect();
    for parent_ref in parent_refs {
        let key = gamma_parent_ref_key(route_namespace, parent_ref);
        match resolve_service_parent(acc, route_namespace, parent_ref) {
            Ok((namespace, name, port)) => {
                services
                    .entry((namespace, name))
                    .or_default()
                    .push(GammaParent { key, port });
            }
            Err(outcome) => {
                acc.gamma_route_parents.insert(
                    GammaParentKey {
                        route: route.clone(),
                        parent_ref: key,
                    },
                    outcome,
                );
            }
        }
    }
    let creation_timestamp = object
        .metadata
        .creation_timestamp
        .as_deref()
        .and_then(parse_k8s_timestamp);
    for ((service_namespace, service_name), parents) in services {
        // A parent with no port attaches to every port of the Service; an
        // explicit port list ALWAYS keeps its trusted `match.port` predicate
        // (even when it covers every HTTP-family port on the Service), because
        // the GAMMA proxy is host/path-scoped and would otherwise match
        // requests arriving on other ports of the Service host.
        let ports = if parents.iter().any(|parent| parent.port.is_none()) {
            None
        } else {
            let scoped: BTreeSet<u16> = parents.iter().filter_map(|parent| parent.port).collect();
            (!scoped.is_empty()).then_some(scoped)
        };
        let mut staged = GammaStagedRoute {
            object: object.clone(),
            route: route.clone(),
            creation_timestamp,
            service_namespace,
            service_name,
            ports,
            parents,
            blocked: None,
        };
        let resources = build_route_resources(acc, &staged)?;
        staged.blocked = resources.blocked;
        acc.gamma_staged_routes.push(staged);
    }
    Ok(())
}

/// The explicit dispatch path predicate for a Gateway API match listen path,
/// with its precedence class (`0` exact, `1` prefix, `2` regex) and length.
///
/// `PathPrefix` keeps Gateway API element-wise semantics (`/api` matches
/// `/api` and `/api/x`, never `/apix`; a trailing `/` is ignored), so it is a
/// full-match regex rather than the dispatcher's plain string prefix.
fn path_predicate(listen_path: &str) -> (Option<Value>, u64, u64) {
    if let Some(path) = listen_path.strip_prefix('=') {
        return (Some(json!({ "exact": path })), 0, path.len() as u64);
    }
    if let Some(pattern) = listen_path.strip_prefix('~') {
        return (Some(json!({ "regex": pattern })), 2, 0);
    }
    let base = listen_path.trim_end_matches('/');
    if base.is_empty() {
        return (Some(json!({ "prefix": "/" })), 1, 1);
    }
    (
        Some(json!({ "regex": format!("{}(/.*)?", regex::escape(base)) })),
        1,
        base.len() as u64,
    )
}

/// Whether a `URLRewrite` hostname is one a carried route may forward: Sidecar
/// data planes keep an authority rewrite only when it names the selected
/// destination Service (any alias, port-less only on a Service with one HTTP
/// port), so anything else would be removed on the data plane while status
/// reported it programmed.
fn rewrite_authority_is_carriable(
    acc: &K8sAccumulator,
    authority: &str,
    backends: &[RouteBackend],
) -> bool {
    let [backend] = backends else {
        return false;
    };
    let (Some(namespace), Some(name)) = (
        backend.service_namespace.as_deref(),
        backend.service_name.as_deref(),
    ) else {
        return false;
    };
    let authority = authority.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = acc
        .options
        .cluster_domain
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    let aliases = [
        name.to_string(),
        format!("{name}.{namespace}"),
        format!("{name}.{namespace}.svc"),
        format!("{name}.{namespace}.svc.{domain}"),
    ];
    aliases.contains(&authority) && service_http_ports(acc, namespace, name).len() == 1
}

/// Build the dispatch rules and upstreams of one staged attachment.
fn build_route_resources(
    acc: &mut K8sAccumulator,
    staged: &GammaStagedRoute,
) -> Result<GammaRouteResources, K8sTranslateError> {
    let object = &staged.object;
    let route_namespace = object.metadata.namespace.clone();
    let route_name = object.metadata.name.as_str();
    let kind_tag = object.kind.to_ascii_lowercase();
    let upstream_prefix = format!("{GAMMA_ROUTE_UPSTREAM_ID_PREFIX}{kind_tag}");
    // A producer route (in the Service's own namespace) applies to every
    // client of the Service, so a backendRef into another namespace needs that
    // namespace's ReferenceGrant; a consumer route only steers its own
    // namespace's traffic and needs none (upstream GAMMA, issue #7538).
    let producer = route_namespace == staged.service_namespace;
    // A redirect that changes neither scheme nor port keeps the port the client
    // addressed: the scoped Service port, or the Service's only HTTP port.
    let http_ports = service_http_ports(acc, &staged.service_namespace, &staged.service_name);
    let redirect_default_port = match staged.ports.as_ref() {
        Some(ports) if ports.len() == 1 => ports.iter().next().copied(),
        _ if http_ports.len() == 1 => http_ports.iter().next().copied(),
        _ => None,
    };

    let mut resources = GammaRouteResources::default();
    let no_rules = Vec::new();
    let rules = object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .unwrap_or(&no_rules);
    let default_entry = if object.kind == "GRPCRoute" {
        Value::Object(Map::new())
    } else {
        gateway_api_default_path_prefix_match()
    };
    for (rule_index, rule) in rules.iter().enumerate() {
        if rule.get("sessionPersistence").is_some() && resources.blocked.is_none() {
            resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                message: format!(
                    "rules[{rule_index}].sessionPersistence is not applied by mesh data planes yet \
                     (issue #7538)"
                ),
            });
        }
        // A match Ferrum cannot represent refuses the Service parent instead
        // of being dropped while a supported sibling keeps the route
        // programmed.
        let explicit_matches = rule
            .get("matches")
            .and_then(Value::as_array)
            .filter(|matches| !matches.is_empty());
        if let Some(matches) = explicit_matches {
            for (match_index, entry) in matches.iter().enumerate() {
                if route_match_descriptor_for_entry(object, entry).is_none()
                    && resources.blocked.is_none()
                {
                    resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                        message: format!(
                            "rules[{rule_index}].matches[{match_index}] uses a match predicate \
                             Ferrum cannot represent"
                        ),
                    });
                }
            }
        }
        let entry_descriptors: Vec<RouteMatchEntryDescriptor> =
            route_match_entry_descriptors(object, rule);
        if entry_descriptors.is_empty() {
            continue;
        }

        let request_transform = gateway_request_header_modifier_rules(rule);
        let response_transform = gateway_response_header_modifier_rules(rule);
        let redirect = gateway_request_redirect_value(object, rule, redirect_default_port)?;
        let rewrite = gateway_url_rewrite_value(rule);
        let timeouts = gateway_route_rule_timeouts(rule);
        let retry = gateway_route_rule_retry(rule);
        let mut backend_resolution =
            gamma_route_backends(object, rule, acc, &mut resources, producer)?;
        // A matching HTTP rule with no backend to forward to and no filter
        // that answers the request itself (`RequestRedirect`) returns a 500;
        // it never falls through to another route or the plain Service.
        if object.kind == "HTTPRoute"
            && backend_resolution.backends.is_empty()
            && backend_resolution.fault_reason.is_none()
            && redirect.is_none()
        {
            backend_resolution.fault_reason = Some(BackendRefFaultReason::NoServiceableBackend);
        }
        if let Some(authority) = rewrite
            .as_ref()
            .and_then(|rewrite| rewrite.get("authority"))
            .and_then(Value::as_str)
            && !rewrite_authority_is_carriable(acc, authority, &backend_resolution.backends)
            && resources.blocked.is_none()
        {
            resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                message: format!(
                    "rules[{rule_index}] URLRewrite hostname must name the rule's single backend \
                     Service (and that Service must have one HTTP port): mesh data planes forward \
                     no other rewritten authority"
                ),
            });
        }
        let backend_ref_fault = backend_resolution.fault_reason.map(|reason| {
            backend_ref_fault_value_with_percentage(
                reason,
                backend_ref_fault_percentage(
                    backend_resolution.valid_weight,
                    backend_resolution.invalid_weight,
                ),
            )
        });
        let actions = RouteRuleActions {
            request_transform: &request_transform,
            response_transform: &response_transform,
            redirect: redirect.as_ref(),
            rewrite: rewrite.as_ref(),
            fault: backend_ref_fault.as_ref(),
            timeouts,
            retry: retry.as_ref(),
        };
        let has_route_actions = !actions.is_empty();

        let (backend_host, backend_port, upstream_id, requires_node_waypoint_authz) =
            if backend_resolution.backends.is_empty() {
                if !has_only_zero_weight_backend_refs(rule) && !has_route_actions {
                    continue;
                }
                (
                    GAMMA_NO_FORWARD_HOST.to_string(),
                    ZERO_WEIGHT_BACKEND_PORT,
                    None,
                    false,
                )
            } else if backend_resolution.backends.len() == 1 {
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(&backend_resolution.backends);
                let Some(backend) = backend_resolution.backends.into_iter().next() else {
                    continue;
                };
                (
                    backend.host,
                    backend.port,
                    None,
                    requires_node_waypoint_authz,
                )
            } else {
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(&backend_resolution.backends);
                // `.` never appears in a namespace or Service name, so this
                // suffix is an unambiguous `(Service, rule)` key for the digest.
                let upstream_id = gateway_api_source_bound_id(
                    &upstream_prefix,
                    &object.kind,
                    &route_namespace,
                    route_name,
                    &format!(
                        "{}.{}.{rule_index}",
                        staged.service_namespace, staged.service_name
                    ),
                    0,
                );
                resources.upstreams.push(upstream_for_route(
                    upstream_id.clone(),
                    route_namespace.clone(),
                    backend_resolution.backends,
                ));
                (
                    String::new(),
                    0,
                    Some(upstream_id),
                    requires_node_waypoint_authz,
                )
            };
        let destination = MeshRouteDispatchDestination {
            backend_host: backend_host.as_str(),
            backend_port,
            upstream_id: upstream_id.as_deref(),
            requires_node_waypoint_authz,
        };

        for entry_descriptor in &entry_descriptors {
            let entry = explicit_matches
                .and_then(|matches| matches.get(entry_descriptor.match_index))
                .unwrap_or(&default_entry);
            let mut criteria = if object.kind == "GRPCRoute" {
                if explicit_matches.is_some() {
                    let Some(criteria) = grpc_dispatch_match_criteria(entry) else {
                        continue;
                    };
                    criteria
                } else {
                    grpc_dispatch_match_criteria_for(&grpc_any_call_match())
                }
            } else {
                http_route_dispatch_match_criteria(entry)
            };
            let (uri, path_class, path_length) =
                path_predicate(&entry_descriptor.descriptor.listen_path);
            if let Some(uri) = uri
                && !criteria.contains_key("uri")
            {
                criteria.insert("uri".to_string(), uri);
            }
            if let Some(reason) = invalid_gamma_match_regex(&criteria)
                && resources.blocked.is_none()
            {
                resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                    message: format!(
                        "rules[{rule_index}].matches[{}] {reason}",
                        entry_descriptor.match_index
                    ),
                });
            }
            let mut dispatch_rule = gateway_api_dispatch_route_rule(
                object,
                Value::Object(criteria),
                rule_index,
                entry_descriptor.match_index,
                destination,
                actions,
                entry,
            );
            if let Some(rule_object) = dispatch_rule.as_object_mut() {
                rule_object.insert(
                    GAMMA_PATH_PRECEDENCE_KEY.to_string(),
                    json!({"class": path_class, "length": path_length}),
                );
            }
            match staged.ports.as_ref() {
                None => resources.rules.push(dispatch_rule),
                Some(ports) => {
                    for port in ports {
                        let mut scoped = dispatch_rule.clone();
                        if let Some(criteria) =
                            scoped.get_mut("match").and_then(Value::as_object_mut)
                        {
                            criteria.insert("port".to_string(), json!(port));
                            resources.rules.push(scoped);
                        }
                    }
                }
            }
        }
    }
    Ok(resources)
}

/// Validate any regex matcher in a GAMMA dispatch rule's match criteria using
/// the dispatcher's own full-match compiler so an invalid or over-complex
/// regex is rejected on its own route attachment instead of poisoning the
/// receiving mesh slice.
fn invalid_gamma_match_regex(criteria: &serde_json::Map<String, Value>) -> Option<&'static str> {
    let check_regex = |pattern: &str| {
        !pattern.is_empty()
            && crate::plugins::mesh_route_dispatch::compile_full_match_regex(pattern).is_ok()
    };
    if let Some(pattern) = criteria
        .get("uri")
        .and_then(|uri| uri.get("regex"))
        .and_then(Value::as_str)
        && !check_regex(pattern)
    {
        return Some("path regular expression is invalid or too complex");
    }
    for (field, label) in [
        (
            "headers",
            "header regular expression is invalid or too complex",
        ),
        (
            "query_params",
            "query parameter regular expression is invalid or too complex",
        ),
    ] {
        if let Some(entries) = criteria.get(field).and_then(Value::as_object) {
            for matcher in entries.values() {
                if let Some(pattern) = matcher.get("regex").and_then(Value::as_str)
                    && !check_regex(pattern)
                {
                    return Some(label);
                }
            }
        }
    }
    None
}

/// Resolve one rule's `backendRefs` to mesh Service backends.
///
/// Each backend is the Service host (`<svc>.<ns>.svc.<cluster domain>`) on its
/// port, never an endpoint expansion: the data plane rebinds it onto the
/// Service port's mesh transport. Reference admission (ExternalName refusal,
/// EndpointSlice attribution) and the fail-closed fault for an unresolvable
/// share are exactly the Gateway-bound route's. A ReferenceGrant from the
/// backend's namespace is required for a `producer` route (it redirects every
/// client's traffic, other tenants' included) and not for a consumer route,
/// which only steers its own namespace's requests (upstream GAMMA; stricter
/// VirtualService `http[]` tenancy, #7499, always requires one).
fn gamma_route_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
    resources: &mut GammaRouteResources,
    producer: bool,
) -> Result<RouteBackendResolution, K8sTranslateError> {
    let mut backends = Vec::new();
    let mut fault_reason = None;
    let mut invalid_weight = 0u32;
    let mut valid_weight = 0u32;
    let mut skipped_zero = 0usize;
    let no_backend_refs = Vec::new();
    let backend_refs = rule
        .get("backendRefs")
        .and_then(Value::as_array)
        .unwrap_or(&no_backend_refs);
    for backend_ref in backend_refs {
        let weight = gateway_backend_weight(object, backend_ref)?;
        if weight == 0 {
            skipped_zero += 1;
            continue;
        }
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let (backend_kind, backend_namespace) = match checked_backend_namespace_with_grant_policy(
            object,
            backend_ref,
            acc,
            object.kind.as_str(),
            producer,
        ) {
            Ok(resolved) => resolved,
            Err(error) if error_is_backend_ref_resolution(&error) => {
                fault_reason.get_or_insert(backend_ref_resolution_reason(&error));
                invalid_weight = invalid_weight.saturating_add(weight);
                continue;
            }
            Err(error) => return Err(error),
        };
        if backend_kind != BackendKind::Service {
            if resources.blocked.is_none() {
                resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                    message: "a ServiceImport backendRef is not served by mesh data planes yet \
                              (issue #7538)"
                        .to_string(),
                });
            }
            fault_reason.get_or_insert(BackendRefFaultReason::InvalidKind);
            invalid_weight = invalid_weight.saturating_add(weight);
            continue;
        }
        let port = optional_port_field(object, backend_ref.get("port"), "backendRefs[].port")?
            .unwrap_or(if object.kind == "GRPCRoute" {
                50051
            } else {
                80
            });
        if backend_target_missing(acc, backend_kind, &backend_namespace, backend_name, port) {
            fault_reason.get_or_insert(BackendRefFaultReason::BackendNotFound);
            invalid_weight = invalid_weight.saturating_add(weight);
            continue;
        }
        if backend_namespace != object.metadata.namespace && resources.blocked.is_none() {
            resources.blocked = Some(GammaParentOutcome::Pending {
                message: "a backendRef names a Service in another namespace; cross-namespace \
                          GAMMA backends are unsupported in phase 1, so this route is not carried"
                    .to_string(),
            });
        }
        valid_weight = valid_weight.saturating_add(weight);
        backends.push(RouteBackend {
            host: service_dns_name(
                backend_name,
                &backend_namespace,
                &acc.options.cluster_domain,
            ),
            port,
            weight,
            service_namespace: Some(backend_namespace.clone()),
            service_name: Some(backend_name.to_string()),
            service_port: Some(port),
        });
    }
    normalize_backend_weights_to_target_limit(&mut backends);
    if skipped_zero > 0 && object.kind == "HTTPRoute" && has_only_zero_weight_backend_refs(rule) {
        fault_reason.get_or_insert(BackendRefFaultReason::NoServiceableBackend);
    }
    Ok(RouteBackendResolution {
        backends,
        fault_reason,
        invalid_weight,
        valid_weight,
    })
}

/// `(namespace, Service namespace, Service name)` → the mesh-bound
/// VirtualService `(namespace, name)` whose carried `http[]` route names that
/// Service there. Only a binding the namespace's own clients receive (its
/// `exportTo` admits its namespace) counts, and only exact Service host forms;
/// a wildcard host never names one Service.
fn virtual_service_service_claims(
    acc: &K8sAccumulator,
) -> HashMap<(String, String, String), (String, String)> {
    let proxies: HashMap<(&str, &str), &Proxy> = acc
        .config
        .proxies
        .iter()
        .map(|proxy| ((proxy.namespace.as_str(), proxy.id.as_str()), proxy))
        .collect();
    let cluster_domain = acc
        .options
        .cluster_domain
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    let mut claims = HashMap::new();
    for binding in &acc.mesh.virtual_service_http_routes {
        if binding.name.starts_with(GAMMA_ROUTE_BINDING_NAME_PREFIX)
            || !virtual_service_http_routes_exported_to_namespace(binding, &binding.namespace)
        {
            continue;
        }
        for id in &binding.proxy_ids {
            let Some(proxy) = proxies.get(&(binding.namespace.as_str(), id.as_str())) else {
                continue;
            };
            for host in &proxy.hosts {
                let host = host.trim().to_ascii_lowercase();
                if host.contains('*') {
                    continue;
                }
                let Some((service, namespace)) =
                    crate::config_sources::k8s::istio::service_host_components(
                        &host,
                        &binding.namespace,
                        &cluster_domain,
                    )
                else {
                    continue;
                };
                claims
                    .entry((
                        binding.namespace.clone(),
                        namespace.to_string(),
                        service.to_string(),
                    ))
                    .or_insert_with(|| (binding.namespace.clone(), binding.name.clone()));
            }
        }
    }
    claims
}

/// Snapshot-wide pass, run after every object translated: apply GAMMA
/// precedence per `(route namespace, Service)` group, materialize each group's
/// route, write the mesh bindings and record every parent's outcome.
pub(super) fn finalize(acc: &mut K8sAccumulator) {
    let staged = std::mem::take(&mut acc.gamma_staged_routes);
    if staged.is_empty() {
        return;
    }
    let virtual_service_claims = virtual_service_service_claims(acc);
    let mut groups: BTreeMap<(String, String, String), Vec<GammaStagedRoute>> = BTreeMap::new();
    for route in staged {
        groups
            .entry((
                route.object.metadata.namespace.clone(),
                route.service_namespace.clone(),
                route.service_name.clone(),
            ))
            .or_default()
            .push(route);
    }
    for (group, mut routes) in groups {
        routes.sort_by(|left, right| {
            compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp)
                .then_with(|| left.route.cmp(&right.route))
        });
        let virtual_service = virtual_service_claims.get(&group).cloned();
        finalize_group(acc, &group.0, &group.1, &group.2, routes, virtual_service);
    }
}

/// The route proxy's hosts: the Service FQDN (the data plane adds every
/// alias) and its IPv4 cluster IPs, so a client addressing the Service frontend
/// by its cluster IP is routed too.
fn service_frontend_hosts(acc: &K8sAccumulator, namespace: &str, name: &str) -> Vec<String> {
    let mut hosts = vec![service_dns_name(
        name,
        namespace,
        &acc.options.cluster_domain,
    )];
    if let Some(addresses) = acc
        .service_cluster_ipv4s
        .get(&(namespace.to_string(), name.to_string()))
    {
        hosts.extend(addresses.iter().cloned());
    }
    hosts
}

fn finalize_group(
    acc: &mut K8sAccumulator,
    route_namespace: &str,
    service_namespace: &str,
    service_name: &str,
    routes: Vec<GammaStagedRoute>,
    virtual_service: Option<(String, String)>,
) {
    if let Some((vs_namespace, vs_name)) = virtual_service {
        let outcome = GammaParentOutcome::Conflicted {
            message: format!(
                "mesh-bound VirtualService {vs_namespace:?}/{vs_name:?} routes Service \
                 {service_namespace:?}/{service_name:?} for this namespace; a VirtualService \
                 http[] route takes precedence over GAMMA routes for the same Service host, so \
                 this route is not applied"
            ),
        };
        for route in &routes {
            record_outcome(acc, route, &outcome);
        }
        return;
    }

    let mut eligible = Vec::with_capacity(routes.len());
    for route in routes {
        match route.blocked.clone() {
            Some(outcome) => record_outcome(acc, &route, &outcome),
            None => eligible.push(route),
        }
    }

    let http_ports = service_http_ports(acc, service_namespace, service_name);
    // GEP-1294: on one Service port, GRPCRoute wins over HTTPRoute.
    let mut grpc_ports: BTreeSet<u16> = BTreeSet::new();
    for route in eligible
        .iter()
        .filter(|route| route.object.kind == "GRPCRoute")
    {
        match route.ports.as_ref() {
            Some(ports) => grpc_ports.extend(ports.iter().copied()),
            None => grpc_ports.extend(http_ports.iter().copied()),
        }
    }

    let producer = route_namespace == service_namespace;
    let grpc_conflict = GammaParentOutcome::Conflicted {
        message: format!(
            "a GRPCRoute attached to this port of Service {service_namespace:?}/{service_name:?} \
             takes precedence over this HTTPRoute (GEP-1294 route type specificity)"
        ),
    };
    let mut rules: Vec<Value> = Vec::new();
    let mut upstreams: Vec<Upstream> = Vec::new();
    let mut programmed: Vec<(GammaStagedRoute, Vec<GammaParent>)> = Vec::new();
    let mut covered: Option<BTreeSet<u16>> = Some(BTreeSet::new());
    for mut route in eligible {
        let mut serving_parents = route.parents.clone();
        if route.object.kind == "HTTPRoute" && !grpc_ports.is_empty() {
            let attached = route.ports.clone().unwrap_or_else(|| http_ports.clone());
            let kept: BTreeSet<u16> = attached.difference(&grpc_ports).copied().collect();
            serving_parents.retain(|parent| match parent.port {
                Some(port) => !grpc_ports.contains(&port),
                None => !kept.is_empty(),
            });
            for parent in &route.parents {
                if !serving_parents.iter().any(|kept| kept.key == parent.key) {
                    record_parent(acc, &route, parent, &grpc_conflict);
                }
            }
            if kept.is_empty() || serving_parents.is_empty() {
                continue;
            }
            route.ports = (!http_ports.is_subset(&kept)).then_some(kept);
        }
        // Built once already in the per-object pass; this build only applies
        // the final port scope, so its warnings would be duplicates.
        let warnings_before = acc.warnings.len();
        let built = build_route_resources(acc, &route);
        acc.warnings.truncate(warnings_before);
        let resources = match built {
            Ok(resources) => resources,
            Err(error) => {
                let outcome = GammaParentOutcome::UnsupportedValue {
                    message: format!("Ferrum could not translate this route: {error}"),
                };
                for parent in &serving_parents {
                    record_parent(acc, &route, parent, &outcome);
                }
                continue;
            }
        };
        if resources.rules.is_empty() {
            for parent in &serving_parents {
                record_parent(acc, &route, parent, &GammaParentOutcome::NoRules);
            }
            continue;
        }
        covered = match (covered, route.ports.as_ref()) {
            (Some(mut covered), Some(ports)) => {
                covered.extend(ports.iter().copied());
                Some(covered)
            }
            _ => None,
        };
        rules.extend(resources.rules);
        upstreams.extend(resources.upstreams);
        programmed.push((route, serving_parents));
    }
    if programmed.is_empty() {
        return;
    }

    let hosts = service_frontend_hosts(acc, service_namespace, service_name);
    let record_serving_parents = |acc: &mut K8sAccumulator,
                                  programmed: &[(GammaStagedRoute, Vec<GammaParent>)],
                                  outcome: GammaParentOutcome| {
        for (route, parents) in programmed {
            for parent in parents {
                record_parent(acc, route, parent, &outcome);
            }
        }
    };

    // HTTP-family ports no attached route covers keep plain Service routing:
    // they pass through to the Service on that port.
    let uncovered: Vec<u16> = match covered.as_ref() {
        Some(covered) => http_ports.difference(covered).copied().collect(),
        None => Vec::new(),
    };
    if !uncovered.is_empty() && !producer {
        // The pass-through destination is the parent Service, in another
        // namespace, which mesh data planes do not carry yet.
        record_serving_parents(
            acc,
            &programmed,
            GammaParentOutcome::Pending {
                message: "a port-scoped consumer route passes the Service's other ports through \
                          to the Service in another namespace; mesh data planes refuse a carried \
                          route with a cross-namespace destination until issue #7499 lands, so \
                          this route is not carried"
                    .to_string(),
            },
        );
        return;
    }

    // Never take over a `/` slot another source serves for one of the hosts.
    let occupied = acc.config.proxies.iter().any(|existing| {
        existing.namespace == route_namespace
            && !is_gamma_route_proxy_id(&existing.id)
            && existing.listen_path.as_deref() == Some("/")
            && existing.listen_port.is_none()
            && existing.hosts.iter().any(|host| hosts.contains(host))
    });
    if occupied {
        record_serving_parents(
            acc,
            &programmed,
            GammaParentOutcome::Conflicted {
                message: format!(
                    "another route already serves `/` for Service {service_namespace:?}/\
                     {service_name:?} in this namespace; a GAMMA route never takes over a route \
                     slot it does not own"
                ),
            },
        );
        return;
    }

    sort_group_rules(&mut rules);
    let pass_through_host =
        service_dns_name(service_name, service_namespace, &acc.options.cluster_domain);
    rules.extend(
        uncovered
            .iter()
            .map(|port| pass_through_rule(&pass_through_host, *port)),
    );

    let proxy_id = gateway_api_source_bound_id(
        GAMMA_SERVICE_PROXY_READABLE_PREFIX,
        "Service",
        route_namespace,
        &format!("{service_namespace}.{service_name}"),
        "",
        GATEWAY_API_ROUTE_DERIVED_PLUGIN_ID_PREFIX_LEN,
    );
    let rules_have_request_transform = dispatch_rules_carry_field(&rules, "request_transform");
    let rules_have_response_transform = dispatch_rules_carry_field(&rules, "response_transform");
    let Some(dispatch) =
        mesh_route_dispatch_plugin_from_rules(&proxy_id, route_namespace, rules, true)
    else {
        return;
    };
    // The proxy's own destination is never dialled: every request either
    // matches a rule (with its own destination) or is rejected.
    let mut proxy = proxy_for_route(RouteProxySpec {
        id: proxy_id.clone(),
        namespace: route_namespace.to_string(),
        hosts,
        listen_path: Some("/".to_string()),
        strip_listen_path: false,
        preserve_host_header: false,
        backend_host: GAMMA_NO_FORWARD_HOST.to_string(),
        backend_port: ZERO_WEIGHT_BACKEND_PORT,
        upstream_id: None,
        backend_scheme: BackendScheme::Http,
        listen_port: None,
        retry: None,
        backend_read_timeout_ms: None,
    });
    let mut route_plugins = Vec::new();
    if rules_have_request_transform {
        route_plugins.push(route_request_transformer_plugin_for_proxy(
            &proxy_id,
            route_namespace,
        ));
    }
    if rules_have_response_transform {
        route_plugins.push(route_response_transformer_plugin_for_proxy(
            &proxy_id,
            route_namespace,
        ));
    }
    route_plugins.push(dispatch);
    attach_route_plugins_to_proxy(&mut proxy, &route_plugins);
    if matches!(
        acc.upsert_proxy(proxy, SourceKind::GatewayApi),
        ProxyUpsert::Ignored
    ) {
        return;
    }
    acc.config.plugin_configs.extend(route_plugins);
    for upstream in upstreams {
        acc.upsert_upstream(upstream);
    }
    acc.mesh
        .virtual_service_http_routes
        .push(MeshVirtualServiceHttpRoutes {
            name: gamma_binding_name(service_namespace, service_name),
            namespace: route_namespace.to_string(),
            // A producer route applies to every client of the Service; a
            // consumer route only to clients in its own namespace.
            export_to: if producer {
                vec!["*".to_string()]
            } else {
                Vec::new()
            },
            proxy_ids: vec![proxy_id],
            authorized_cross_namespace_targets: Vec::new(),
        });
    record_serving_parents(
        acc,
        &programmed,
        GammaParentOutcome::Programmed { producer },
    );
}

/// Order a group's rules by Gateway API precedence across every attached
/// route: exact path before prefix before regex, longer prefix first, then the
/// Gateway-bound rule precedence (method, header and query counts, oldest
/// route, namespace/name, rule and match order). The internal metadata is then
/// stripped so translation output never carries it.
fn sort_group_rules(rules: &mut [Value]) {
    let path_key = |rule: &Value| {
        let metadata = rule.get(GAMMA_PATH_PRECEDENCE_KEY);
        let class = metadata
            .and_then(|metadata| metadata.get("class"))
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let length = metadata
            .and_then(|metadata| metadata.get("length"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        (class, std::cmp::Reverse(length))
    };
    rules.sort_by(|left, right| {
        path_key(left).cmp(&path_key(right)).then_with(|| {
            compare_dispatch_rule_precedence(
                &dispatch_rule_precedence(left),
                &dispatch_rule_precedence(right),
            )
        })
    });
    for rule in rules.iter_mut() {
        if let Some(object) = rule.as_object_mut() {
            object.remove(GAMMA_PATH_PRECEDENCE_KEY);
            object.remove(GATEWAY_API_DISPATCH_PRECEDENCE_KEY);
        }
    }
}

/// A rule passing one Service port through to the Service on that port.
fn pass_through_rule(host: &str, port: u16) -> Value {
    json!({
        "match": {"port": port},
        "destination": {
            "backend_host": host,
            "backend_port": port,
            "requires_node_waypoint_authz": true,
        },
    })
}
