//! Gateway API GAMMA routes: `HTTPRoute` and `GRPCRoute` objects whose
//! `parentRefs` name a core `Service` (issue #7538).
//!
//! A Service parent attaches a route to the Service's *frontend* (its name and
//! cluster IP) for mesh traffic, instead of to a Gateway listener. Such a route
//! is translated into the same mesh route set a mesh-bound VirtualService
//! `http[]` route produces, so it reaches the mesh data planes that already
//! apply carried routes (Sidecar and NodeWaypoint) through the existing
//! `mesh.virtual_service_http_routes` binding, `MeshSlice.http_routes` and
//! `HttpRoutesCarrier`, with no wire change:
//!
//! * proxies are `istio-vs-gamma_<kind>-…__<digest>` (inside the translator-owned
//!   `istio-vs-` space every data-plane ownership check, inbound-listener
//!   exclusion and controller withdrawal list already keys on; the `_` can never
//!   appear in a Kubernetes name, so no VirtualService id collides with one, and
//!   the digest binds each id to its source route object);
//! * weighted backends ride an `istio-vs-upstream-gamma_<kind>-…` upstream whose
//!   targets are Service hosts, which the data plane rebinds onto its own mesh
//!   transport exactly as it does for VirtualService split legs;
//! * route plugins are the shared `mesh_route_dispatch` /
//!   `request_transformer` / `response_transformer` builders the Gateway-bound
//!   HTTPRoute translator uses, so filter, match, timeout and retry coverage and
//!   every `Accepted=False` refusal reason are identical to a Gateway-bound
//!   route;
//! * the binding is `gamma_<service namespace>_<service>` in the route
//!   namespace, `exportTo: ["*"]` for a producer route (route in the Service's
//!   namespace) and namespace-local for a consumer route.
//!
//! Precedence (decided in [`finalize`], over the complete snapshot):
//!
//! 1. A mesh-bound VirtualService whose `http[]` route names the Service (any
//!    exact alias of its host) in the same namespace wins; every GAMMA route
//!    for that Service there is refused (`Conflicted`) and never applied.
//! 2. Between kinds on one Service port, GRPCRoute wins over HTTPRoute
//!    (GEP-1294 route type specificity); the HTTPRoute is `Conflicted`.
//! 3. Within one kind, routes merge under the Gateway API route merging rules:
//!    the oldest route (`creationTimestamp`, then namespace/name) keeps an
//!    identical match; rules are ordered by Gateway API precedence.
//! 4. A route slot (host, path) already served by a non-GAMMA proxy is never
//!    taken over; the GAMMA route is `Conflicted`.
//!
//! Requests that match no rule of the attached routes are rejected (404), as
//! GAMMA requires. A parentRef `port` (or `sectionName`, the Service port name)
//! scopes the route to that port: every rule carries the port predicate, and
//! ports of the Service no attached route covers are passed through to the
//! plain Service.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::config::types::{BackendScheme, PluginConfig, Proxy, Upstream};
use crate::config_sources::k8s::backend_ref::{BackendKind, backend_target_missing};
use crate::config_sources::k8s::{
    GammaParentKey, GammaParentOutcome, K8sAccumulator, K8sObject, K8sResourceKey,
    K8sTranslateError, MeshRouteDispatchDestination, ProxyUpsert, RouteBackend, RouteProxySpec,
    SourceKind, attach_route_plugins_to_proxy, invalid_resource,
    mesh_route_dispatch_plugin_from_rules, namespaced_resource_key, optional_port_field,
    proxy_for_route, route_backends_require_node_waypoint_authz,
    route_request_transformer_plugin_for_proxy, route_response_transformer_plugin_for_proxy,
    service_dns_name, string_field, upstream_for_route,
};
use crate::modes::mesh::config::MeshVirtualServiceHttpRoutes;
use crate::time_compat::UtcTimestamp;

use super::{
    BackendRefFaultReason, GATEWAY_API_ROUTE_DERIVED_PLUGIN_ID_PREFIX_LEN, RouteBackendResolution,
    RouteMatchDescriptor, RouteMatchEntryDescriptor, RouteRuleActions, ZERO_WEIGHT_BACKEND_HOST,
    ZERO_WEIGHT_BACKEND_PORT, append_dispatch_rules, backend_ref_fault_percentage,
    backend_ref_fault_value_with_percentage, backend_ref_resolution_reason,
    checked_backend_namespace, compare_creation_timestamps, dedup_route_match_descriptors,
    dispatch_plugin_index, dispatch_rules_carry_field, ensure_http_route_features,
    error_is_backend_ref_resolution, gateway_api_default_path_prefix_match,
    gateway_api_dispatch_route_rule, gateway_api_source_bound_id, gateway_backend_weight,
    gateway_request_header_modifier_rules, gateway_request_redirect_value,
    gateway_response_header_modifier_rules, gateway_route_rule_retry, gateway_route_rule_timeouts,
    gateway_url_rewrite_value, has_only_zero_weight_backend_refs,
    http_route_dispatch_match_criteria, http_route_dispatch_rules_for_proxy,
    merge_http_route_proxy, normalize_backend_weights_to_target_limit, occupies_same_route_slot,
    parse_k8s_timestamp, route_match_entry_descriptors, sort_dispatch_rules,
};

/// Prefix of every GAMMA route proxy id. It sits inside the translator-owned
/// `istio-vs-` space (`is_virtual_service_http_route_proxy_id`), so carried
/// GAMMA routes pass the same data-plane ownership and inbound-exclusion checks
/// as VirtualService routes.
pub(crate) const GAMMA_ROUTE_PROXY_ID_PREFIX: &str = "istio-vs-gamma_";
/// Prefix of every GAMMA weighted-backend upstream id, inside the carried
/// `istio-vs-upstream-` space.
pub(crate) const GAMMA_ROUTE_UPSTREAM_ID_PREFIX: &str = "istio-vs-upstream-gamma_";
/// Readable prefix of the per-Service `/` catch-all that rejects requests no
/// attached route matches.
const GAMMA_UNMATCHED_PROXY_ID_PREFIX: &str = "istio-vs-gamma_unmatched";
/// Prefix of the `mesh.virtual_service_http_routes` binding name a GAMMA route
/// group writes (`gamma_<service namespace>_<service>`). Kubernetes names never
/// contain `_`, so it never collides with a VirtualService binding.
pub(crate) const GAMMA_ROUTE_BINDING_NAME_PREFIX: &str = "gamma_";

/// Where a programmed GAMMA route is applied in this release, for status.
pub(crate) const GAMMA_ROUTE_PROGRAMMED_SCOPE_NOTE: &str = "applied by Sidecar and NodeWaypoint \
     mesh data planes to clients in the route's namespace; ServiceWaypoint data planes and \
     clients in other namespaces are not served yet (issue #7538)";

/// Whether `id` is a GAMMA route proxy id.
pub(crate) fn is_gamma_route_proxy_id(id: &str) -> bool {
    id.starts_with(GAMMA_ROUTE_PROXY_ID_PREFIX)
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

/// One `(route, Service)` attachment admitted in the per-object pass, awaiting
/// snapshot-wide precedence in [`finalize`].
#[derive(Debug, Clone)]
pub(crate) struct GammaStagedRoute {
    object: K8sObject,
    route: K8sResourceKey,
    creation_timestamp: Option<UtcTimestamp>,
    service_namespace: String,
    service_name: String,
    /// Service ports the route attaches to; `None` is every port.
    ports: Option<BTreeSet<u16>>,
    /// Keys of the parentRefs that resolved to this Service.
    parent_keys: Vec<String>,
    /// A reason this attachment is accepted or refused without being carried.
    blocked: Option<GammaParentOutcome>,
}

#[derive(Default)]
struct GammaRouteResources {
    proxies: Vec<Proxy>,
    plugins: Vec<PluginConfig>,
    upstreams: Vec<Upstream>,
    blocked: Option<GammaParentOutcome>,
    /// Every match descriptor the route materialized, for oldest-wins
    /// arbitration against younger routes on the same Service.
    descriptors: Vec<RouteMatchDescriptor>,
    /// The route had matches but an older route claims every one of them.
    every_match_claimed: bool,
}

/// One route's attachment to one Service: the ports it attaches to (`None` is
/// every port) and the keys of the parentRefs that resolved to that Service.
type ServiceAttachment = (Option<BTreeSet<u16>>, Vec<String>);

/// Port scopes of the routes that already claimed one match descriptor.
type ClaimedDescriptors = HashMap<RouteMatchDescriptor, Vec<Option<BTreeSet<u16>>>>;

fn port_scopes_overlap(left: Option<&BTreeSet<u16>>, right: Option<&BTreeSet<u16>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => !left.is_disjoint(right),
        _ => true,
    }
}

fn descriptor_claimed(
    claimed: &ClaimedDescriptors,
    descriptor: &RouteMatchDescriptor,
    ports: Option<&BTreeSet<u16>>,
) -> bool {
    claimed.get(descriptor).is_some_and(|scopes| {
        scopes
            .iter()
            .any(|scope| port_scopes_overlap(scope.as_ref(), ports))
    })
}

fn service_port_numbers(acc: &K8sAccumulator, namespace: &str, name: &str) -> BTreeSet<u16> {
    acc.service_ports
        .get(namespace)
        .and_then(|services| services.get(name))
        .map(|ports| ports.iter().copied().collect())
        .unwrap_or_default()
}

fn record_outcome(
    acc: &mut K8sAccumulator,
    staged: &GammaStagedRoute,
    outcome: &GammaParentOutcome,
) {
    for parent_ref in &staged.parent_keys {
        acc.gamma_route_parents.insert(
            GammaParentKey {
                route: staged.route.clone(),
                parent_ref: parent_ref.clone(),
            },
            outcome.clone(),
        );
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
    Ok((
        namespace.to_string(),
        name.to_string(),
        port.or(section_port),
    ))
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
    // `http_route_resources` already admitted the content (and warned about
    // unrepresentable GRPCRoute matches) on the way here; re-checking keeps
    // this entry point safe on its own.
    ensure_http_route_features(object)?;
    let route = K8sResourceKey::from_object(object);
    let route_namespace = object.metadata.namespace.as_str();
    let mut services: BTreeMap<(String, String), ServiceAttachment> = BTreeMap::new();
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
                let entry = services
                    .entry((namespace, name))
                    .or_insert_with(|| (Some(BTreeSet::new()), Vec::new()));
                // No port is every port; otherwise the scoped ports union.
                match port {
                    None => entry.0 = None,
                    Some(port) => {
                        if let Some(ports) = entry.0.as_mut() {
                            ports.insert(port);
                        }
                    }
                }
                entry.1.push(key);
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
    for ((service_namespace, service_name), (ports, parent_keys)) in services {
        // A port scope that covers every port of the Service is no scope.
        let all_ports = service_port_numbers(acc, &service_namespace, &service_name);
        let ports = ports.filter(|ports| !all_ports.is_subset(ports));
        let mut staged = GammaStagedRoute {
            object: object.clone(),
            route: route.clone(),
            creation_timestamp,
            service_namespace,
            service_name,
            ports,
            parent_keys,
            blocked: None,
        };
        let resources = build_route_resources(acc, &staged, &ClaimedDescriptors::new())?;
        staged.blocked = resources.blocked;
        acc.gamma_staged_routes.push(staged);
    }
    Ok(())
}

/// Build the mesh route resources of one staged attachment, skipping every
/// match descriptor an older route on the same Service already claims.
fn build_route_resources(
    acc: &mut K8sAccumulator,
    staged: &GammaStagedRoute,
    claimed: &ClaimedDescriptors,
) -> Result<GammaRouteResources, K8sTranslateError> {
    let object = &staged.object;
    let route_namespace = object.metadata.namespace.clone();
    let route_name = object.metadata.name.as_str();
    let host = service_dns_name(
        &staged.service_name,
        &staged.service_namespace,
        &acc.options.cluster_domain,
    );
    let kind_tag = object.kind.to_ascii_lowercase();
    let proxy_prefix = format!("{GAMMA_ROUTE_PROXY_ID_PREFIX}{kind_tag}");
    let upstream_prefix = format!("{GAMMA_ROUTE_UPSTREAM_ID_PREFIX}{kind_tag}");
    // `.` never appears in a namespace or Service name, so the digest input
    // (which keeps it) is unambiguous; the readable id folds it to `-`.
    let service_suffix = format!("{}.{}", staged.service_namespace, staged.service_name);
    // A redirect that changes neither scheme nor port keeps the port the client
    // addressed: the scoped Service port, or the Service's only port.
    let all_ports = service_port_numbers(acc, &staged.service_namespace, &staged.service_name);
    let redirect_default_port = match staged.ports.as_ref() {
        Some(ports) if ports.len() == 1 => ports.iter().next().copied(),
        _ if all_ports.len() == 1 => all_ports.iter().next().copied(),
        _ => None,
    };

    let mut resources = GammaRouteResources::default();
    let mut saw_match = false;
    let mut kept_match = false;
    let no_rules = Vec::new();
    let rules = object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .unwrap_or(&no_rules);
    for (rule_index, rule) in rules.iter().enumerate() {
        if rule.get("sessionPersistence").is_some() && resources.blocked.is_none() {
            resources.blocked = Some(GammaParentOutcome::UnsupportedValue {
                message: format!(
                    "rules[{rule_index}].sessionPersistence is not applied by mesh data planes, \
                     which rebind every backend onto the Service's mesh transport"
                ),
            });
        }
        let all_entries = route_match_entry_descriptors(object, rule);
        saw_match |= !all_entries.is_empty();
        let entry_descriptors: Vec<RouteMatchEntryDescriptor> = all_entries
            .into_iter()
            .filter(|entry| !descriptor_claimed(claimed, &entry.descriptor, staged.ports.as_ref()))
            .collect();
        let descriptors = dedup_route_match_descriptors(
            entry_descriptors
                .iter()
                .map(|entry| entry.descriptor.clone())
                .collect(),
        );
        if descriptors.is_empty() {
            continue;
        }
        kept_match = true;
        resources.descriptors.extend(descriptors.iter().cloned());
        let mut match_paths: Vec<String> = descriptors
            .iter()
            .map(|descriptor| descriptor.listen_path.clone())
            .collect();
        match_paths.sort();
        match_paths.dedup();

        let request_transform = gateway_request_header_modifier_rules(rule);
        let response_transform = gateway_response_header_modifier_rules(rule);
        let redirect = gateway_request_redirect_value(object, rule, redirect_default_port)?;
        let rewrite = gateway_url_rewrite_value(rule);
        let timeouts = gateway_route_rule_timeouts(rule);
        let retry = gateway_route_rule_retry(rule);
        let mut backend_resolution = gamma_route_backends(object, rule, acc, &mut resources)?;
        // Upstream `HTTPRouteRule.backendRefs`: with no backend and no filter
        // that answers the request itself, every matching request gets a 500,
        // exactly as on a Gateway-bound route.
        if object.kind == "HTTPRoute"
            && backend_resolution.backends.is_empty()
            && backend_resolution.fault_reason.is_none()
            && redirect.is_none()
            && (!request_transform.is_empty()
                || !response_transform.is_empty()
                || rewrite.is_some()
                || !timeouts.is_empty()
                || retry.is_some())
        {
            backend_resolution.fault_reason = Some(BackendRefFaultReason::NoServiceableBackend);
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
                    ZERO_WEIGHT_BACKEND_HOST.to_string(),
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
                let upstream_id = gateway_api_source_bound_id(
                    &upstream_prefix,
                    &object.kind,
                    &route_namespace,
                    route_name,
                    &format!("{service_suffix}-{rule_index}"),
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

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
            let entries_for_path: Vec<RouteMatchEntryDescriptor> = entry_descriptors
                .iter()
                .filter(|entry| entry.descriptor.listen_path == listen_path)
                .cloned()
                .collect();
            let suffix = if match_count > 1 {
                format!("{service_suffix}-{rule_index}-{match_index}")
            } else {
                format!("{service_suffix}-{rule_index}")
            };
            let proxy_id = gateway_api_source_bound_id(
                &proxy_prefix,
                &object.kind,
                &route_namespace,
                route_name,
                &suffix,
                GATEWAY_API_ROUTE_DERIVED_PLUGIN_ID_PREFIX_LEN,
            );
            let destination = MeshRouteDispatchDestination {
                backend_host: backend_host.as_str(),
                backend_port,
                upstream_id: upstream_id.as_deref(),
                requires_node_waypoint_authz,
            };
            let mut proxy = proxy_for_route(RouteProxySpec {
                id: proxy_id.clone(),
                namespace: route_namespace.clone(),
                hosts: vec![host.clone()],
                listen_path: Some(listen_path.clone()),
                strip_listen_path: false,
                preserve_host_header: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: BackendScheme::Http,
                listen_port: None,
                retry: None,
                backend_read_timeout_ms: None,
            });
            let (mut dispatch_rules, mut has_path_only_match) = http_route_dispatch_rules_for_proxy(
                object,
                rule,
                rule_index,
                Some(listen_path.as_str()),
                destination,
                &HashSet::new(),
                &entries_for_path,
                actions,
            );
            if let Some(ports) = staged.ports.as_ref() {
                dispatch_rules = port_scoped_rules(PortScopedRules {
                    object,
                    rule,
                    rule_index,
                    rules: dispatch_rules,
                    synthesize_path_only: has_path_only_match && !has_route_actions,
                    entries: &entries_for_path,
                    destination,
                    actions,
                    ports,
                });
                has_path_only_match = false;
            }
            let rules_have_request_transform =
                dispatch_rules_carry_field(&dispatch_rules, "request_transform");
            let rules_have_response_transform =
                dispatch_rules_carry_field(&dispatch_rules, "response_transform");
            if let Some(mut plugin) = mesh_route_dispatch_plugin_from_rules(
                &proxy_id,
                &route_namespace,
                dispatch_rules,
                !has_path_only_match,
            ) {
                sort_dispatch_rules(&mut plugin);
                let mut route_plugins = Vec::new();
                if rules_have_request_transform {
                    route_plugins.push(route_request_transformer_plugin_for_proxy(
                        &proxy_id,
                        &route_namespace,
                    ));
                }
                if rules_have_response_transform {
                    route_plugins.push(route_response_transformer_plugin_for_proxy(
                        &proxy_id,
                        &route_namespace,
                    ));
                }
                route_plugins.push(plugin);
                attach_route_plugins_to_proxy(&mut proxy, &route_plugins);
                resources.plugins.extend(route_plugins);
            }
            resources.proxies.push(proxy);
        }
    }
    resources.every_match_claimed = saw_match && !kept_match;
    Ok(resources)
}

/// Inputs of [`port_scoped_rules`].
struct PortScopedRules<'a> {
    object: &'a K8sObject,
    rule: &'a Value,
    rule_index: usize,
    rules: Vec<Value>,
    /// The rule has path-only matches that would otherwise be served by the
    /// proxy's default backend; each needs its own dispatch rule so the port
    /// predicate can guard it.
    synthesize_path_only: bool,
    entries: &'a [RouteMatchEntryDescriptor],
    destination: MeshRouteDispatchDestination<'a>,
    actions: RouteRuleActions<'a>,
    ports: &'a BTreeSet<u16>,
}

/// Guard every dispatch rule of a port-scoped attachment with the
/// `mesh_route_dispatch` `port` predicate (the destination port the client
/// addressed), one rule per scoped port. The route is then `reject_unmatched`:
/// a request on another port matches none of its rules.
fn port_scoped_rules(input: PortScopedRules<'_>) -> Vec<Value> {
    let PortScopedRules {
        object,
        rule,
        rule_index,
        mut rules,
        synthesize_path_only,
        entries,
        destination,
        actions,
        ports,
    } = input;
    if synthesize_path_only {
        match rule
            .get("matches")
            .and_then(Value::as_array)
            .filter(|matches| !matches.is_empty())
        {
            None => {
                let entry = gateway_api_default_path_prefix_match();
                rules.push(gateway_api_dispatch_route_rule(
                    object,
                    Value::Object(Map::new()),
                    rule_index,
                    0,
                    destination,
                    actions,
                    &entry,
                ));
            }
            Some(matches) => {
                for entry_descriptor in entries {
                    let Some(entry) = matches.get(entry_descriptor.match_index) else {
                        continue;
                    };
                    if object.kind != "GRPCRoute"
                        && http_route_dispatch_match_criteria(entry).is_empty()
                    {
                        rules.push(gateway_api_dispatch_route_rule(
                            object,
                            Value::Object(Map::new()),
                            rule_index,
                            entry_descriptor.match_index,
                            destination,
                            actions,
                            entry,
                        ));
                    }
                }
            }
        }
    }
    let mut scoped = Vec::with_capacity(rules.len().saturating_mul(ports.len()));
    for rule_value in rules {
        for port in ports {
            let mut scoped_rule = rule_value.clone();
            if let Some(criteria) = scoped_rule.get_mut("match").and_then(Value::as_object_mut) {
                criteria.insert("port".to_string(), json!(port));
                scoped.push(scoped_rule);
            }
        }
    }
    scoped
}

/// Resolve one rule's `backendRefs` to mesh Service backends.
///
/// Each backend is the Service host (`<svc>.<ns>.svc.<cluster domain>`) on its
/// port, never an endpoint expansion: the data plane rebinds it onto the
/// Service port's mesh transport. Reference admission (ReferenceGrant for
/// another namespace, ExternalName refusal, EndpointSlice attribution) and the
/// fail-closed fault for an unresolvable share are exactly the Gateway-bound
/// route's.
fn gamma_route_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
    resources: &mut GammaRouteResources,
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
        let (backend_kind, backend_namespace) =
            match checked_backend_namespace(object, backend_ref, acc, object.kind.as_str()) {
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
                    message: "a ServiceImport backendRef is not served by mesh data planes, \
                              which route only to modeled Services"
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
                message: "a backendRef names a Service in another namespace; mesh data planes \
                          refuse a carried route with a cross-namespace destination until issue \
                          #7499 lands, so this route is not carried"
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
/// Service there. Only exact Service host forms count; a wildcard host never
/// names one Service.
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
        if binding.name.starts_with(GAMMA_ROUTE_BINDING_NAME_PREFIX) {
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
/// precedence per `(route namespace, Service)` group, materialize the
/// survivors, write the mesh bindings and record every parent's outcome.
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
                 {service_namespace:?}/{service_name:?} in this namespace; a VirtualService \
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

    // GEP-1294: on one Service port, GRPCRoute wins over HTTPRoute.
    let mut grpc_cover: Option<Option<BTreeSet<u16>>> = None;
    for route in eligible
        .iter()
        .filter(|route| route.object.kind == "GRPCRoute")
    {
        grpc_cover = Some(match (grpc_cover.take(), route.ports.as_ref()) {
            (Some(None), _) | (_, None) => None,
            (Some(Some(mut covered)), Some(ports)) => {
                covered.extend(ports.iter().copied());
                Some(covered)
            }
            (None, Some(ports)) => Some(ports.clone()),
        });
    }

    let host = service_dns_name(service_name, service_namespace, &acc.options.cluster_domain);
    let producer = route_namespace == service_namespace;
    let mut claimed = ClaimedDescriptors::new();
    let mut covered: Option<BTreeSet<u16>> = Some(BTreeSet::new());
    let mut any_materialized = false;
    for route in eligible {
        if route.object.kind == "HTTPRoute"
            && let Some(grpc_ports) = grpc_cover.as_ref()
            && port_scopes_overlap(grpc_ports.as_ref(), route.ports.as_ref())
        {
            record_outcome(
                acc,
                &route,
                &GammaParentOutcome::Conflicted {
                    message: format!(
                        "a GRPCRoute attached to the same port of Service \
                         {service_namespace:?}/{service_name:?} takes precedence over this \
                         HTTPRoute (GEP-1294 route type specificity)"
                    ),
                },
            );
            continue;
        }
        // Built once already in the per-object pass; this build only applies
        // the older routes' claims, so its warnings would be duplicates.
        let warnings_before = acc.warnings.len();
        let built = build_route_resources(acc, &route, &claimed);
        acc.warnings.truncate(warnings_before);
        let resources = match built {
            Ok(resources) => resources,
            Err(error) => {
                record_outcome(
                    acc,
                    &route,
                    &GammaParentOutcome::UnsupportedValue {
                        message: format!("Ferrum could not translate this route: {error}"),
                    },
                );
                continue;
            }
        };
        if resources.every_match_claimed {
            record_outcome(
                acc,
                &route,
                &GammaParentOutcome::Conflicted {
                    message: format!(
                        "every match of this route is already claimed by an older route on \
                         Service {service_namespace:?}/{service_name:?} (Gateway API route \
                         merging: the oldest route wins)"
                    ),
                },
            );
            continue;
        }
        let occupied = resources.proxies.iter().any(|proxy| {
            acc.config.proxies.iter().any(|existing| {
                !is_gamma_route_proxy_id(&existing.id) && occupies_same_route_slot(existing, proxy)
            })
        });
        if occupied {
            record_outcome(
                acc,
                &route,
                &GammaParentOutcome::Conflicted {
                    message: format!(
                        "another route already serves a path of host {host:?} in this namespace; \
                         a GAMMA route never takes over a route slot it does not own"
                    ),
                },
            );
            continue;
        }
        let descriptors = resources.descriptors.clone();
        if upsert_route_resources(acc, resources, &route.object.kind) {
            any_materialized = true;
            for descriptor in descriptors {
                claimed
                    .entry(descriptor)
                    .or_default()
                    .push(route.ports.clone());
            }
            covered = match (covered, route.ports.as_ref()) {
                (Some(mut covered), Some(ports)) => {
                    covered.extend(ports.iter().copied());
                    Some(covered)
                }
                _ => None,
            };
            record_outcome(acc, &route, &GammaParentOutcome::Programmed { producer });
        } else {
            record_outcome(acc, &route, &GammaParentOutcome::NoRules);
        }
    }
    if !any_materialized {
        return;
    }

    let route_proxy_ids = group_proxy_ids(acc, route_namespace, &host);

    // Ports of the Service no attached route covers keep plain Service
    // routing: on every route path they pass through to the Service port.
    let service_ports = service_port_numbers(acc, service_namespace, service_name);
    let uncovered: Vec<u16> = match covered.as_ref() {
        Some(covered) => service_ports.difference(covered).copied().collect(),
        None => Vec::new(),
    };
    if !uncovered.is_empty() {
        add_pass_through_rules(acc, route_namespace, &host, &route_proxy_ids, &uncovered);
    }
    // GAMMA: once routes are attached, a request that matches none of them is
    // rejected. The Service's plain route would otherwise still serve every
    // path no attached route claims, so the group gets a `/` catch-all that
    // answers 404 (and passes uncovered ports through) unless an attached
    // route already owns `/`.
    let owns_root = acc.config.proxies.iter().any(|proxy| {
        route_proxy_ids.contains(&proxy.id)
            && proxy.namespace == route_namespace
            && proxy.listen_path.as_deref() == Some("/")
    });
    if !owns_root {
        add_unmatched_catch_all(
            acc,
            UnmatchedCatchAll {
                route_namespace,
                service_namespace,
                service_name,
                host: &host,
                service_port: service_ports.iter().next().copied().unwrap_or(80),
                uncovered: &uncovered,
            },
        );
    }

    let binding_proxy_ids = group_proxy_ids(acc, route_namespace, &host);
    if !binding_proxy_ids.is_empty() {
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
                proxy_ids: binding_proxy_ids,
            });
    }
}

/// Every GAMMA proxy of one `(route namespace, Service host)` group.
fn group_proxy_ids(acc: &K8sAccumulator, route_namespace: &str, host: &str) -> Vec<String> {
    acc.config
        .proxies
        .iter()
        .filter(|proxy| {
            proxy.namespace == route_namespace
                && is_gamma_route_proxy_id(&proxy.id)
                && proxy.hosts.len() == 1
                && proxy.hosts[0] == host
        })
        .map(|proxy| proxy.id.clone())
        .collect()
}

/// Inputs of [`add_unmatched_catch_all`].
struct UnmatchedCatchAll<'a> {
    route_namespace: &'a str,
    service_namespace: &'a str,
    service_name: &'a str,
    host: &'a str,
    service_port: u16,
    uncovered: &'a [u16],
}

/// Body of the 404 a GAMMA catch-all answers.
const GAMMA_UNMATCHED_BODY: &str =
    r#"{"error":"no route attached to this Service matched the request"}"#;

/// gRPC `UNIMPLEMENTED`, the gRPC mapping of HTTP 404.
const GRPC_STATUS_UNIMPLEMENTED: u32 = 12;

/// Add the group's `/` catch-all: pass-through rules for the uncovered Service
/// ports, then a rule that matches every remaining request and aborts it with
/// a 404. The rules carry no precedence metadata, so their order is kept.
fn add_unmatched_catch_all(acc: &mut K8sAccumulator, input: UnmatchedCatchAll<'_>) {
    let UnmatchedCatchAll {
        route_namespace,
        service_namespace,
        service_name,
        host,
        service_port,
        uncovered,
    } = input;
    let proxy_id = gateway_api_source_bound_id(
        GAMMA_UNMATCHED_PROXY_ID_PREFIX,
        "Service",
        route_namespace,
        &format!("{service_namespace}.{service_name}"),
        "unmatched",
        GATEWAY_API_ROUTE_DERIVED_PLUGIN_ID_PREFIX_LEN,
    );
    let mut rules: Vec<Value> = uncovered
        .iter()
        .map(|port| pass_through_rule(host, *port))
        .collect();
    rules.push(json!({
        "match": {},
        "destination": {
            "backend_host": host,
            "backend_port": service_port,
            "requires_node_waypoint_authz": true,
        },
        "fault": {
            "abort": {
                "status_code": 404,
                "percentage": 100.0,
                "grpc_status": GRPC_STATUS_UNIMPLEMENTED,
                "body": GAMMA_UNMATCHED_BODY,
            }
        },
    }));
    let Some(plugin) =
        mesh_route_dispatch_plugin_from_rules(&proxy_id, route_namespace, rules, true)
    else {
        return;
    };
    let mut proxy = proxy_for_route(RouteProxySpec {
        id: proxy_id.clone(),
        namespace: route_namespace.to_string(),
        hosts: vec![host.to_string()],
        listen_path: Some("/".to_string()),
        strip_listen_path: false,
        preserve_host_header: false,
        backend_host: host.to_string(),
        backend_port: service_port,
        upstream_id: None,
        backend_scheme: BackendScheme::Http,
        listen_port: None,
        retry: None,
        backend_read_timeout_ms: None,
    });
    // Never take over a `/` slot another source already serves for this host.
    if acc
        .config
        .proxies
        .iter()
        .any(|existing| occupies_same_route_slot(existing, &proxy))
    {
        return;
    }
    attach_route_plugins_to_proxy(&mut proxy, std::slice::from_ref(&plugin));
    let key = namespaced_resource_key(&proxy.namespace, &proxy.id);
    if matches!(
        acc.upsert_proxy(proxy, SourceKind::GatewayApi),
        ProxyUpsert::Ignored
    ) {
        return;
    }
    acc.config.plugin_configs.push(plugin);
    if let Some(key) = key {
        acc.gateway_api_route_proxy_kinds
            .insert(key, "Service".to_string());
    }
}

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

/// Upsert one attachment's resources, merging each proxy into the GAMMA proxy
/// already serving its slot (an older route of the same kind under the
/// Gateway API merging rules, or the other kind on disjoint ports). Returns
/// whether any proxy materialized.
fn upsert_route_resources(
    acc: &mut K8sAccumulator,
    resources: GammaRouteResources,
    route_kind: &str,
) -> bool {
    for upstream in resources.upstreams {
        acc.upsert_upstream(upstream);
    }
    let mut plugins_by_proxy: HashMap<String, Vec<PluginConfig>> = HashMap::new();
    for plugin in resources.plugins {
        if let Some(proxy_id) = plugin.proxy_id.clone() {
            plugins_by_proxy.entry(proxy_id).or_default().push(plugin);
        }
    }
    let mut materialized = false;
    for proxy in resources.proxies {
        let route_plugins = plugins_by_proxy.remove(&proxy.id).unwrap_or_default();
        let sibling_kind = acc
            .config
            .proxies
            .iter()
            .find(|existing| {
                is_gamma_route_proxy_id(&existing.id) && occupies_same_route_slot(existing, &proxy)
            })
            .and_then(|existing| namespaced_resource_key(&existing.namespace, &existing.id))
            .and_then(|key| acc.gateway_api_route_proxy_kinds.get(&key).cloned());
        if let Some(sibling_kind) = sibling_kind {
            if merge_http_route_proxy(acc, &proxy, &route_plugins, &sibling_kind).is_some() {
                materialized = true;
            }
            continue;
        }
        let key = namespaced_resource_key(&proxy.namespace, &proxy.id);
        if matches!(
            acc.upsert_proxy(proxy, SourceKind::GatewayApi),
            ProxyUpsert::Ignored
        ) {
            continue;
        }
        acc.config.plugin_configs.extend(route_plugins);
        if let Some(key) = key {
            acc.gateway_api_route_proxy_kinds
                .insert(key, route_kind.to_string());
        }
        materialized = true;
    }
    materialized
}

/// Append one pass-through rule per uncovered Service port to every GAMMA
/// proxy of a port-scoped group: a request to such a port reaches the Service
/// on that port, as if no route were attached to it.
fn add_pass_through_rules(
    acc: &mut K8sAccumulator,
    route_namespace: &str,
    host: &str,
    proxy_ids: &[String],
    uncovered: &[u16],
) {
    for proxy_id in proxy_ids {
        let rules: Vec<Value> = uncovered
            .iter()
            .map(|port| pass_through_rule(host, *port))
            .collect();
        match dispatch_plugin_index(&acc.config.plugin_configs, route_namespace, proxy_id) {
            Some(index) => append_dispatch_rules(&mut acc.config.plugin_configs[index], rules),
            None => {
                let Some(plugin) =
                    mesh_route_dispatch_plugin_from_rules(proxy_id, route_namespace, rules, true)
                else {
                    continue;
                };
                if let Some(proxy) = acc
                    .config
                    .proxies
                    .iter_mut()
                    .find(|proxy| proxy.namespace == route_namespace && proxy.id == *proxy_id)
                {
                    attach_route_plugins_to_proxy(proxy, std::slice::from_ref(&plugin));
                    acc.config.plugin_configs.push(plugin);
                }
            }
        }
    }
}
