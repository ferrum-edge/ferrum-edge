use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::types::BackendScheme;
use crate::modes::mesh::config::{
    AppProtocol, MeshService, MeshWaypointBinding, MeshWaypointServiceRef, ServicePort,
};

use super::{
    GatewayApiRouteConflict, GatewayApiRouteConflictKey, K8sAccumulator, K8sObject, K8sResourceKey,
    K8sTranslateError, K8sTranslationOptions, MeshRouteDispatchDestination, RouteBackend,
    RouteProxySpec, SourceKind, attach_route_plugins_to_proxy, exact_path_listen_path,
    invalid_resource, mesh_route_dispatch_plugin_from_rules, optional_port_field,
    optional_target_weight_field, port_from_u64, proxy_for_route, resource_id, service_dns_name,
    string_array, string_field, upstream_for_route,
};
use crate::config::types::{PluginConfig, Proxy};

// Use an absolute DNS name (trailing dot) so resolvers must query this exact
// label and cannot append search domains from resolv.conf.
const ZERO_WEIGHT_BACKEND_HOST: &str = "ferrum-zero-weight.invalid.";
const ZERO_WEIGHT_BACKEND_PORT: u16 = 65535;
const GATEWAY_API_DISPATCH_PRECEDENCE_KEY: &str = "_ferrum_gateway_api_precedence";

/// `Gateway.spec.gatewayClassName` values that mark a GAMMA Waypoint
/// Gateway. Both the Istio canonical value and a Ferrum-native alias are
/// honored so operators migrating from Istio do not have to retag.
const WAYPOINT_GATEWAY_CLASS_NAMES: &[&str] = &["istio-waypoint", "ferrum-waypoint"];

/// Service label naming the GAMMA Waypoint a Service routes through.
/// `None` (the literal string) opts the Service out of any inherited
/// namespace-level waypoint binding. Annotations are accepted as a
/// compatibility fallback for file/native sources that already use them.
const KEY_USE_WAYPOINT: &str = "istio.io/use-waypoint";

/// Optional Service label that points `istio.io/use-waypoint` at a waypoint
/// Gateway in a namespace other than the Service's namespace. Annotations are
/// accepted as a compatibility fallback.
const KEY_USE_WAYPOINT_NAMESPACE: &str = "istio.io/use-waypoint-namespace";

/// Gateway/Service label setting which traffic the waypoint handles:
/// `service` (default), `workload`, `all`, or `none`. Stored verbatim on
/// the binding so future Istio enum additions don't require a Ferrum-side
/// schema change. Annotations are accepted as a compatibility fallback.
const KEY_WAYPOINT_FOR: &str = "istio.io/waypoint-for";

#[derive(Debug, Clone)]
struct GatewayApiRouteConflictCandidate {
    resource: K8sResourceKey,
    creation_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteMatchDescriptor {
    listen_path: String,
    match_signature: String,
}

#[derive(Debug, Clone)]
struct RouteMatchEntryDescriptor {
    match_index: usize,
    descriptor: RouteMatchDescriptor,
}

#[derive(Debug, Clone)]
struct RouteHostScope {
    proxy_hosts: Vec<String>,
    conflict_hostname: String,
    suffix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayApiDispatchRulePrecedence {
    has_precedence: bool,
    method_match: bool,
    header_count: usize,
    query_param_count: usize,
    creation_timestamp: Option<DateTime<Utc>>,
    namespace: String,
    name: String,
    rule_index: usize,
    match_index: usize,
}

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "Gateway" => {
            if is_waypoint_gateway(object) {
                add_waypoint_binding(acc, object);
            }
            for service in mesh_services_from_gateway(object)? {
                acc.mesh.services.push(service);
            }
            Ok(true)
        }
        "HTTPRoute" => {
            let (proxies, plugins) = http_route_resources(object, acc)?;
            upsert_http_route_resources(acc, proxies, plugins);
            Ok(true)
        }
        "GRPCRoute" => {
            let (proxies, plugins) = http_route_resources(object, acc)?;
            for proxy in proxies {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            acc.config.plugin_configs.extend(plugins);
            Ok(true)
        }
        "TCPRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Tcp)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "TLSRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Tcps)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "ReferenceGrant" => Ok(true),
        _ => Ok(false),
    }
}

pub(super) fn collect_reference_grant(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    for from in object
        .spec
        .get("from")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let from_namespace = string_field(from, "namespace").ok_or_else(|| {
            invalid_resource(object, "ReferenceGrant spec.from[].namespace is required")
        })?;
        let from_group = string_field(from, "group").unwrap_or_default();
        let from_kind = string_field(from, "kind").ok_or_else(|| {
            invalid_resource(object, "ReferenceGrant spec.from[].kind is required")
        })?;

        for to in object
            .spec
            .get("to")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let to_kind = string_field(to, "kind").ok_or_else(|| {
                invalid_resource(object, "ReferenceGrant spec.to[].kind is required")
            })?;
            let to_group = string_field(to, "group").unwrap_or_default();
            acc.add_reference_grant(
                from_namespace.to_string(),
                from_group.to_string(),
                from_kind.to_string(),
                object.metadata.namespace.clone(),
                to_group.to_string(),
                to_kind.to_string(),
            );
        }
    }
    Ok(())
}

/// True when this Gateway is a GAMMA Waypoint Gateway (gatewayClassName is
/// one of `istio-waypoint` / `ferrum-waypoint`). Slice projection only
/// considers waypoint Gateways when computing `MeshConfig.waypoint_bindings`.
pub(super) fn is_waypoint_gateway(object: &K8sObject) -> bool {
    let Some(class) = string_field(&object.spec, "gatewayClassName") else {
        return false;
    };
    WAYPOINT_GATEWAY_CLASS_NAMES
        .iter()
        .any(|expected| class.eq_ignore_ascii_case(expected))
}

/// Insert (or update) a `MeshWaypointBinding` for this Gateway. Gateway
/// resources contribute the binding shell — `name` + `namespace` — and
/// honor a label/annotation-level `istio.io/waypoint-for` default if present.
/// Bound services are added later by `add_service_waypoint_binding` from
/// `collect_service`.
pub(super) fn add_waypoint_binding(acc: &mut super::K8sAccumulator, object: &K8sObject) {
    let waypoint_for = metadata_key(object, KEY_WAYPOINT_FOR)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "service".to_string());
    if let Some(existing) = acc
        .mesh
        .waypoint_bindings
        .iter_mut()
        .find(|b| b.name == object.metadata.name && b.namespace == object.metadata.namespace)
    {
        // Gateway-level label/annotation always wins over service-supplied
        // defaults because the Gateway is the canonical owner of the
        // waypoint identity.
        existing.waypoint_for = waypoint_for;
    } else {
        acc.mesh.waypoint_bindings.push(MeshWaypointBinding {
            name: object.metadata.name.clone(),
            namespace: object.metadata.namespace.clone(),
            waypoint_for,
            services: Vec::new(),
        });
    }
}

/// Append this Service to the matching waypoint binding when the
/// `istio.io/use-waypoint` label/annotation is set (and not `None`). Creates the
/// binding shell when the Gateway hasn't been observed yet so service +
/// gateway translation can land in either order.
pub(super) fn add_service_waypoint_binding(acc: &mut super::K8sAccumulator, object: &K8sObject) {
    let Some(waypoint) =
        metadata_key(object, KEY_USE_WAYPOINT).filter(|s| !s.eq_ignore_ascii_case("none"))
    else {
        return;
    };
    let waypoint_name = waypoint.to_string();
    let waypoint_namespace = metadata_key(object, KEY_USE_WAYPOINT_NAMESPACE)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| object.metadata.namespace.clone());
    let waypoint_for_override = metadata_key(object, KEY_WAYPOINT_FOR).map(ToOwned::to_owned);

    let service_ref = MeshWaypointServiceRef {
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
    };

    if let Some(existing) = acc
        .mesh
        .waypoint_bindings
        .iter_mut()
        .find(|b| b.name == waypoint_name && b.namespace == waypoint_namespace)
    {
        if !existing.services.contains(&service_ref) {
            existing.services.push(service_ref);
        }
        return;
    }
    acc.mesh.waypoint_bindings.push(MeshWaypointBinding {
        name: waypoint_name,
        namespace: waypoint_namespace,
        waypoint_for: waypoint_for_override.unwrap_or_else(|| "service".to_string()),
        services: vec![service_ref],
    });
}

fn metadata_key<'a>(object: &'a K8sObject, key: &str) -> Option<&'a str> {
    object
        .metadata
        .labels
        .get(key)
        .or_else(|| object.metadata.annotations.get(key))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn route_conflicts(
    objects: &[K8sObject],
    options: &K8sTranslationOptions,
) -> Vec<GatewayApiRouteConflict> {
    let mut candidates_by_key: HashMap<
        GatewayApiRouteConflictKey,
        Vec<GatewayApiRouteConflictCandidate>,
    > = HashMap::new();

    for object in objects
        .iter()
        .filter(|object| super::includes_object_namespace(options, object))
        .filter(|object| matches!(object.kind.as_str(), "HTTPRoute" | "GRPCRoute"))
    {
        let resource = K8sResourceKey::from_object(object);
        let creation_timestamp = object
            .metadata
            .creation_timestamp
            .as_deref()
            .and_then(parse_k8s_timestamp);
        for key in route_conflict_keys(object) {
            candidates_by_key
                .entry(key)
                .or_default()
                .push(GatewayApiRouteConflictCandidate {
                    resource: resource.clone(),
                    creation_timestamp,
                });
        }
    }

    let mut conflicts = Vec::new();
    for (key, mut candidates) in candidates_by_key {
        candidates.sort_by(compare_conflict_candidates);
        candidates.dedup_by(|left, right| left.resource == right.resource);
        let Some(winner) = candidates.first().cloned() else {
            continue;
        };
        for loser in candidates.into_iter().skip(1) {
            conflicts.push(GatewayApiRouteConflict {
                key: key.clone(),
                winner: winner.resource.clone(),
                loser: loser.resource,
            });
        }
    }
    conflicts.sort_by(|left, right| {
        (&left.loser, &left.key, &left.winner).cmp(&(&right.loser, &right.key, &right.winner))
    });
    conflicts.dedup_by(|left, right| left.loser == right.loser && left.key == right.key);
    conflicts
}

pub(crate) fn route_conflict_keys(object: &K8sObject) -> Vec<GatewayApiRouteConflictKey> {
    let hostnames = route_hostnames(object);
    let parent_refs = route_parent_ref_keys(object);
    let route_family = object.kind.to_ascii_lowercase();
    let mut keys = Vec::new();

    for rule in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for descriptor in route_match_descriptors(object, rule) {
            for parent_ref in &parent_refs {
                for hostname in &hostnames {
                    keys.push(GatewayApiRouteConflictKey {
                        route_family: route_family.clone(),
                        parent_ref: parent_ref.clone(),
                        hostname: hostname.clone(),
                        listen_path: descriptor.listen_path.clone(),
                        match_signature: route_conflict_match_signature(&descriptor),
                    });
                }
            }
        }
    }

    keys.sort();
    keys.dedup();
    keys
}

fn route_conflict_match_signature(descriptor: &RouteMatchDescriptor) -> String {
    descriptor.match_signature.clone()
}

fn upsert_http_route_resources(
    acc: &mut K8sAccumulator,
    proxies: Vec<Proxy>,
    plugins: Vec<PluginConfig>,
) {
    let mut plugins_by_proxy: HashMap<String, Vec<PluginConfig>> = HashMap::new();
    for plugin in plugins {
        if let Some(proxy_id) = plugin.proxy_id.clone() {
            plugins_by_proxy.entry(proxy_id).or_default().push(plugin);
        } else {
            acc.config.plugin_configs.push(plugin);
        }
    }

    for proxy in proxies {
        let route_plugins = plugins_by_proxy.remove(&proxy.id).unwrap_or_default();
        if !merge_http_route_proxy(acc, proxy.clone(), &route_plugins) {
            acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            acc.config.plugin_configs.extend(route_plugins);
        }
    }

    for (_, plugins) in plugins_by_proxy {
        acc.config.plugin_configs.extend(plugins);
    }
}

fn merge_http_route_proxy(
    acc: &mut K8sAccumulator,
    proxy: Proxy,
    route_plugins: &[PluginConfig],
) -> bool {
    let Some(existing_index) = acc
        .config
        .proxies
        .iter()
        .position(|existing| can_merge_http_route_proxy(acc, existing, &proxy))
    else {
        return false;
    };

    let new_dispatch = route_plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch");
    let existing_id = acc.config.proxies[existing_index].id.clone();
    let existing_dispatch_index = dispatch_plugin_index(&acc.config.plugin_configs, &existing_id);
    if new_dispatch.is_none() && existing_dispatch_index.is_none() {
        return false;
    }

    let new_has_default = dispatch_reject_unmatched(new_dispatch) == Some(false)
        || (new_dispatch.is_none() && route_plugins.is_empty());
    let existing_has_default = existing_dispatch_index
        .and_then(|index| dispatch_reject_unmatched(Some(&acc.config.plugin_configs[index])))
        != Some(true);

    if new_has_default {
        replace_proxy_default_route(&mut acc.config.proxies[existing_index], &proxy);
    }

    if let Some(plugin) = new_dispatch {
        let new_rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(index) = existing_dispatch_index {
            append_dispatch_rules(&mut acc.config.plugin_configs[index], new_rules);
            set_dispatch_reject_unmatched(
                &mut acc.config.plugin_configs[index],
                !(existing_has_default || new_has_default),
            );
        } else {
            let mut plugin = retarget_dispatch_plugin(plugin.clone(), &existing_id);
            set_dispatch_reject_unmatched(&mut plugin, false);
            sort_dispatch_rules(&mut plugin);
            attach_route_plugins_to_proxy(
                &mut acc.config.proxies[existing_index],
                std::slice::from_ref(&plugin),
            );
            acc.config.plugin_configs.push(plugin);
        }
    } else if let Some(index) = existing_dispatch_index {
        set_dispatch_reject_unmatched(&mut acc.config.plugin_configs[index], false);
    }

    true
}

fn can_merge_http_route_proxy(acc: &K8sAccumulator, existing: &Proxy, proxy: &Proxy) -> bool {
    acc.proxy_sources.get(&existing.id) == Some(&SourceKind::GatewayApi)
        && existing.namespace == proxy.namespace
        && existing.listen_path == proxy.listen_path
        && existing.hosts == proxy.hosts
}

fn dispatch_plugin_index(plugins: &[PluginConfig], proxy_id: &str) -> Option<usize> {
    plugins.iter().position(|plugin| {
        plugin.plugin_name == "mesh_route_dispatch" && plugin.proxy_id.as_deref() == Some(proxy_id)
    })
}

fn dispatch_reject_unmatched(plugin: Option<&PluginConfig>) -> Option<bool> {
    plugin.and_then(|plugin| {
        plugin
            .config
            .get("reject_unmatched")
            .and_then(Value::as_bool)
    })
}

fn retarget_dispatch_plugin(mut plugin: PluginConfig, proxy_id: &str) -> PluginConfig {
    plugin.id = format!("istio-vs-mrd-{proxy_id}");
    plugin.proxy_id = Some(proxy_id.to_string());
    plugin
}

fn append_dispatch_rules(plugin: &mut PluginConfig, rules: Vec<Value>) {
    if rules.is_empty() {
        return;
    }
    if let Some(existing_rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) {
        existing_rules.extend(rules);
        sort_dispatch_rule_values(existing_rules);
    }
}

pub(super) fn finalize_dispatch_plugin_precedence(plugins: &mut [PluginConfig]) {
    for plugin in plugins {
        if plugin.plugin_name != "mesh_route_dispatch" {
            continue;
        }
        sort_dispatch_rules(plugin);
        strip_dispatch_rule_precedence(plugin);
    }
}

pub(super) fn dispatch_rule_internal_metadata_present(plugins: &[PluginConfig]) -> bool {
    plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .filter_map(|plugin| plugin.config.get("rules").and_then(Value::as_array))
        .flatten()
        .any(|rule| {
            rule.as_object()
                .is_some_and(|object| object.keys().any(|key| key.starts_with("_ferrum_")))
        })
}

fn sort_dispatch_rules(plugin: &mut PluginConfig) {
    if let Some(rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) {
        sort_dispatch_rule_values(rules);
    }
}

fn sort_dispatch_rule_values(rules: &mut [Value]) {
    if !rules
        .iter()
        .any(|rule| rule.get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY).is_some())
    {
        return;
    }
    rules.sort_by(|left, right| {
        let left_precedence = dispatch_rule_precedence(left);
        let right_precedence = dispatch_rule_precedence(right);
        compare_dispatch_rule_precedence(&left_precedence, &right_precedence)
    });
}

fn strip_dispatch_rule_precedence(plugin: &mut PluginConfig) {
    let Some(rules) = plugin.config.get_mut("rules").and_then(Value::as_array_mut) else {
        return;
    };
    for rule in rules {
        if let Some(object) = rule.as_object_mut() {
            object.remove(GATEWAY_API_DISPATCH_PRECEDENCE_KEY);
        }
    }
}

fn dispatch_rule_precedence(rule: &Value) -> GatewayApiDispatchRulePrecedence {
    let metadata = rule
        .get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY)
        .and_then(Value::as_object);
    GatewayApiDispatchRulePrecedence {
        has_precedence: metadata.is_some(),
        method_match: precedence_bool(metadata, "method_match"),
        header_count: precedence_usize(metadata, "header_count"),
        query_param_count: precedence_usize(metadata, "query_param_count"),
        creation_timestamp: metadata
            .and_then(|metadata| metadata.get("creation_timestamp"))
            .and_then(Value::as_str)
            .and_then(parse_k8s_timestamp),
        namespace: precedence_string(metadata, "namespace"),
        name: precedence_string(metadata, "name"),
        rule_index: precedence_usize(metadata, "rule_index"),
        match_index: precedence_usize(metadata, "match_index"),
    }
}

fn precedence_bool(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> bool {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn precedence_usize(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> usize {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn precedence_string(metadata: Option<&serde_json::Map<String, Value>>, key: &str) -> String {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn compare_dispatch_rule_precedence(
    left: &GatewayApiDispatchRulePrecedence,
    right: &GatewayApiDispatchRulePrecedence,
) -> Ordering {
    right
        .has_precedence
        .cmp(&left.has_precedence)
        .then_with(|| right.method_match.cmp(&left.method_match))
        .then_with(|| right.header_count.cmp(&left.header_count))
        .then_with(|| right.query_param_count.cmp(&left.query_param_count))
        .then_with(|| {
            compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp)
        })
        .then_with(|| (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name)))
        .then_with(|| left.rule_index.cmp(&right.rule_index))
        .then_with(|| left.match_index.cmp(&right.match_index))
}

fn set_dispatch_reject_unmatched(plugin: &mut PluginConfig, reject_unmatched: bool) {
    if let Some(config) = plugin.config.as_object_mut() {
        config.insert(
            "reject_unmatched".to_string(),
            Value::Bool(reject_unmatched),
        );
    }
}

/// Overlay the new proxy's "default route" fields onto an existing proxy that
/// is being preserved across a same-path collapse. The fields listed here are
/// the only ones the route-translation layer can supply — listener identity
/// (id, namespace, hosts, listen_path, listen_port, protocol family),
/// plugin-set state (resolved_tls, dispatch_kind), and frontend / pool /
/// admission policy come from elsewhere and must NOT be overwritten by a
/// dispatch-rule collapse. If a future field becomes route-derivable, it must
/// be added here AND a regression test added; otherwise traffic for the
/// collapsed default route silently retains stale per-proxy policy.
fn replace_proxy_default_route(existing: &mut Proxy, proxy: &Proxy) {
    existing.backend_host.clone_from(&proxy.backend_host);
    existing.backend_port = proxy.backend_port;
    existing.upstream_id.clone_from(&proxy.upstream_id);
    existing.retry.clone_from(&proxy.retry);
    existing.backend_read_timeout_ms = proxy.backend_read_timeout_ms;
}

fn route_match_descriptors(object: &K8sObject, rule: &Value) -> Vec<RouteMatchDescriptor> {
    dedup_route_match_descriptors(
        route_match_entry_descriptors(object, rule)
            .into_iter()
            .map(|entry| entry.descriptor)
            .collect(),
    )
}

fn route_match_entry_descriptors(
    object: &K8sObject,
    rule: &Value,
) -> Vec<RouteMatchEntryDescriptor> {
    let Some(matches) = rule.get("matches").and_then(Value::as_array) else {
        return vec![RouteMatchEntryDescriptor {
            match_index: 0,
            descriptor: default_route_match_descriptor(),
        }];
    };
    if matches.is_empty() {
        return vec![RouteMatchEntryDescriptor {
            match_index: 0,
            descriptor: default_route_match_descriptor(),
        }];
    }

    matches
        .iter()
        .enumerate()
        .filter_map(|(match_index, entry)| {
            route_match_descriptor_for_entry(object, entry).map(|descriptor| {
                RouteMatchEntryDescriptor {
                    match_index,
                    descriptor,
                }
            })
        })
        .collect()
}

fn dedup_route_match_descriptors(
    mut descriptors: Vec<RouteMatchDescriptor>,
) -> Vec<RouteMatchDescriptor> {
    descriptors.sort_by(|left, right| {
        (&left.listen_path, &left.match_signature)
            .cmp(&(&right.listen_path, &right.match_signature))
    });
    descriptors.dedup();
    descriptors
}

fn default_route_match_descriptor() -> RouteMatchDescriptor {
    RouteMatchDescriptor {
        listen_path: "/".to_string(),
        match_signature: "{}".to_string(),
    }
}

fn route_match_descriptor_for_entry(
    object: &K8sObject,
    entry: &Value,
) -> Option<RouteMatchDescriptor> {
    if object.kind == "GRPCRoute" {
        // GRPCRoute method-only/header-only matches (no explicit path) must NOT
        // default to "/" — that creates a catch-all proxy that routes ALL traffic
        // to the backend, bypassing method-specificity. Drop pathless matches
        // until per-method dispatch is implemented.
        let listen_path = entry.get("path").and_then(http_path_match)?;
        return Some(RouteMatchDescriptor {
            listen_path,
            match_signature: "{}".to_string(),
        });
    }

    if http_route_match_has_untranslated_non_path_predicate(entry) {
        return None;
    }

    let listen_path = if let Some(path) = entry.get("path").and_then(http_path_match) {
        path
    } else if entry.as_object().is_some_and(|object| object.is_empty())
        || http_route_match_has_supported_non_path_predicate(entry)
    {
        "/".to_string()
    } else {
        return None;
    };

    Some(RouteMatchDescriptor {
        listen_path,
        match_signature: http_route_match_signature(entry),
    })
}

fn http_route_match_signature(entry: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(method) = string_field(entry, "method") {
        parts.push(format!("method={}", json_string(method)));
    }

    let mut headers = Vec::new();
    if let Some(headers_array) = entry.get("headers").and_then(Value::as_array) {
        for header in headers_array {
            if !gateway_match_type_is_exact(header) {
                continue;
            }
            let Some(name) = string_field(header, "name") else {
                continue;
            };
            let Some(value) = string_field(header, "value") else {
                continue;
            };
            headers.push(format!(
                "{}={}",
                name.to_ascii_lowercase(),
                json_string(value)
            ));
        }
    }
    headers.sort();
    for header in headers {
        parts.push(format!("header:{header}"));
    }

    let mut query_params = Vec::new();
    if let Some(params_array) = entry.get("queryParams").and_then(Value::as_array) {
        for param in params_array {
            if !gateway_match_type_is_exact(param) {
                continue;
            }
            let Some(name) = string_field(param, "name") else {
                continue;
            };
            let Some(value) = string_field(param, "value") else {
                continue;
            };
            query_params.push(format!("{}={}", json_string(name), json_string(value)));
        }
    }
    query_params.sort();
    for param in query_params {
        parts.push(format!("query:{param}"));
    }

    if parts.is_empty() {
        "{}".to_string()
    } else {
        parts.join("|")
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

fn route_hostnames(object: &K8sObject) -> Vec<String> {
    let mut hostnames: Vec<String> = string_array(&object.spec, "hostnames")
        .into_iter()
        .map(|hostname| hostname.to_ascii_lowercase())
        .collect();
    if hostnames.is_empty() {
        hostnames.push("*".to_string());
    }
    hostnames.sort();
    hostnames.dedup();
    hostnames
}

fn route_parent_ref_keys(object: &K8sObject) -> Vec<String> {
    let mut refs: Vec<String> = object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|parent| {
            let group = string_field(parent, "group").unwrap_or("gateway.networking.k8s.io");
            let kind = string_field(parent, "kind").unwrap_or("Gateway");
            let namespace = string_field(parent, "namespace").unwrap_or(&object.metadata.namespace);
            let name = string_field(parent, "name").unwrap_or("*");
            let section = string_field(parent, "sectionName").unwrap_or("*");
            let port = parent
                .get("port")
                .and_then(Value::as_u64)
                .map_or_else(|| "*".to_string(), |port| port.to_string());
            format!("{group}/{kind}/{namespace}/{name}/{section}/{port}")
        })
        .collect();
    if refs.is_empty() {
        refs.push(format!(
            "gateway.networking.k8s.io/Gateway/{}/{}/*/*",
            object.metadata.namespace, "*"
        ));
    }
    refs.sort();
    refs.dedup();
    refs
}

fn parse_k8s_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn compare_creation_timestamps(
    left: &Option<DateTime<Utc>>,
    right: &Option<DateTime<Utc>>,
) -> Ordering {
    match (left, right) {
        (Some(left_ts), Some(right_ts)) => left_ts.cmp(right_ts),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_conflict_candidates(
    left: &GatewayApiRouteConflictCandidate,
    right: &GatewayApiRouteConflictCandidate,
) -> Ordering {
    compare_creation_timestamps(&left.creation_timestamp, &right.creation_timestamp).then_with(
        || {
            (&left.resource.namespace, &left.resource.name)
                .cmp(&(&right.resource.namespace, &right.resource.name))
        },
    )
}

fn mesh_services_from_gateway(object: &K8sObject) -> Result<Vec<MeshService>, K8sTranslateError> {
    let mut services = Vec::new();
    object
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .try_for_each(|listener| {
            let Some(raw_port) = listener.get("port").and_then(Value::as_u64) else {
                return Ok(());
            };
            let port = port_from_u64(object, raw_port, "listeners[].port")?;
            let name = string_field(listener, "name").unwrap_or("listener");
            services.push(MeshService {
                name: format!("{}-{name}", object.metadata.name),
                namespace: object.metadata.namespace.clone(),
                ports: vec![ServicePort {
                    port,
                    protocol: app_protocol(string_field(listener, "protocol")),
                    name: Some(name.to_string()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(services)
}

fn ensure_route_parent_refs_allowed(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<(), K8sTranslateError> {
    let Some(parent_refs) = object.spec.get("parentRefs").and_then(Value::as_array) else {
        return Ok(());
    };
    if parent_refs.is_empty() {
        return Ok(());
    }

    for parent_ref in parent_refs {
        let parent_kind = string_field(parent_ref, "kind").unwrap_or("Gateway");
        let parent_group = string_field(parent_ref, "group").unwrap_or("gateway.networking.k8s.io");
        if parent_kind != "Gateway" || parent_group != "gateway.networking.k8s.io" {
            continue;
        }
        let parent_namespace =
            string_field(parent_ref, "namespace").unwrap_or(&object.metadata.namespace);
        if parent_namespace != object.metadata.namespace {
            return Err(invalid_resource(
                object,
                format!(
                    "{} parentRef.namespace '{}' is not permitted; only same-namespace Gateway attachments are accepted",
                    object.kind, parent_namespace
                ),
            ));
        }

        if let Some(section_name) = string_field(parent_ref, "sectionName")
            && !gateway_has_listener(acc, parent_namespace, section_name)
        {
            return Err(invalid_resource(
                object,
                format!(
                    "{} parentRef.sectionName '{}' does not match any known Gateway listener in namespace '{}'",
                    object.kind, section_name, parent_namespace
                ),
            ));
        }
    }

    Ok(())
}

fn gateway_has_listener(acc: &K8sAccumulator, namespace: &str, listener_name: &str) -> bool {
    acc.mesh.services.iter().any(|service| {
        service.namespace == namespace && service.name.ends_with(&format!("-{listener_name}"))
    })
}

type HttpRouteResources = (Vec<Proxy>, Vec<PluginConfig>);

fn http_route_resources(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<HttpRouteResources, K8sTranslateError> {
    ensure_route_parent_refs_allowed(object, acc)?;
    let hostnames: Vec<String> = string_array(&object.spec, "hostnames")
        .into_iter()
        .map(|hostname| hostname.to_ascii_lowercase())
        .collect();
    let conflict_hostnames = route_hostnames(object);
    let parent_refs = route_parent_ref_keys(object);
    let route_family = object.kind.to_ascii_lowercase();
    let losing_conflict_keys: HashSet<GatewayApiRouteConflictKey> = acc
        .gateway_api_conflict_losers
        .get(&K8sResourceKey::from_object(object))
        .into_iter()
        .flat_map(|conflicts| conflicts.iter().map(|conflict| conflict.key.clone()))
        .collect();
    let route_kind = object.kind.to_ascii_lowercase();
    let mut proxies = Vec::new();
    let mut plugins = Vec::new();

    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let entry_descriptors = route_match_entry_descriptors(object, rule);
        let descriptors = dedup_route_match_descriptors(
            entry_descriptors
                .iter()
                .map(|entry| entry.descriptor.clone())
                .collect(),
        );
        if descriptors.is_empty() {
            continue;
        }
        let mut match_paths: Vec<String> = descriptors
            .iter()
            .map(|descriptor| descriptor.listen_path.clone())
            .collect();
        match_paths.sort();
        match_paths.dedup();

        let backends = route_backends(object, rule, acc)?;
        let (backend_host, backend_port, upstream_id, mut pending_upstream) = if backends.is_empty()
        {
            if !has_only_zero_weight_backend_refs(rule) {
                continue;
            }
            (
                ZERO_WEIGHT_BACKEND_HOST.to_string(),
                ZERO_WEIGHT_BACKEND_PORT,
                None,
                None,
            )
        } else if backends.len() == 1 {
            let Some(backend) = backends.into_iter().next() else {
                continue;
            };
            (backend.host, backend.port, None, None)
        } else {
            let route_suffix = format!("{route_kind}-{rule_index}");
            let upstream_id = resource_id(
                "gwapi-route-upstream",
                &object.metadata.namespace,
                &object.metadata.name,
                &route_suffix,
            );
            let upstream = upstream_for_route(
                upstream_id.clone(),
                object.metadata.namespace.clone(),
                backends,
            );
            (String::new(), 0, Some(upstream_id), Some(upstream))
        };

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
            let entry_descriptors_for_path: Vec<_> = entry_descriptors
                .iter()
                .filter(|entry| entry.descriptor.listen_path == listen_path)
                .cloned()
                .collect();
            let descriptors_for_path = dedup_route_match_descriptors(
                entry_descriptors_for_path
                    .iter()
                    .map(|entry| entry.descriptor.clone())
                    .collect(),
            );
            let host_scopes = route_host_scopes_for_path(
                &hostnames,
                &conflict_hostnames,
                &parent_refs,
                &route_family,
                &descriptors_for_path,
                &losing_conflict_keys,
            );
            if host_scopes.is_empty() {
                continue;
            }
            if let Some(upstream) = pending_upstream.take() {
                acc.upsert_upstream(upstream);
            }
            let suffix = if match_count == 1 {
                format!("{route_kind}-{rule_index}")
            } else {
                format!("{route_kind}-{rule_index}-{match_index}")
            };

            for host_scope in host_scopes {
                let scoped_suffix = host_scope.suffix.as_ref().map_or_else(
                    || suffix.clone(),
                    |host_suffix| format!("{suffix}-{host_suffix}"),
                );
                let proxy_id = resource_id(
                    "gwapi-route",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &scoped_suffix,
                );
                let mut proxy = proxy_for_route(RouteProxySpec {
                    id: proxy_id.clone(),
                    namespace: object.metadata.namespace.clone(),
                    hosts: host_scope.proxy_hosts,
                    listen_path: Some(listen_path.clone()),
                    strip_listen_path: false,
                    backend_host: backend_host.clone(),
                    backend_port,
                    upstream_id: upstream_id.clone(),
                    backend_scheme: BackendScheme::Http,
                    listen_port: None,
                    retry: None,
                    backend_read_timeout_ms: None,
                });

                if object.kind == "HTTPRoute" {
                    let skipped_descriptors = skipped_descriptors_for_host(
                        &parent_refs,
                        &route_family,
                        &host_scope.conflict_hostname,
                        &descriptors_for_path,
                        &losing_conflict_keys,
                    );
                    let (rules, has_path_only_match) = http_route_dispatch_rules_for_proxy(
                        object,
                        rule,
                        rule_index,
                        Some(listen_path.as_str()),
                        MeshRouteDispatchDestination {
                            backend_host: backend_host.as_str(),
                            backend_port,
                            upstream_id: upstream_id.as_deref(),
                        },
                        &skipped_descriptors,
                        &entry_descriptors_for_path,
                    );
                    if let Some(mut plugin) = mesh_route_dispatch_plugin_from_rules(
                        &proxy_id,
                        &object.metadata.namespace,
                        rules,
                        !has_path_only_match,
                    ) {
                        sort_dispatch_rules(&mut plugin);
                        attach_route_plugins_to_proxy(&mut proxy, std::slice::from_ref(&plugin));
                        plugins.push(plugin);
                    }
                }

                proxies.push(proxy);
            }
        }
    }

    Ok((proxies, plugins))
}

fn route_host_scopes_for_path(
    spec_hostnames: &[String],
    conflict_hostnames: &[String],
    parent_refs: &[String],
    route_family: &str,
    descriptors_for_path: &[RouteMatchDescriptor],
    losing_conflict_keys: &HashSet<GatewayApiRouteConflictKey>,
) -> Vec<RouteHostScope> {
    if losing_conflict_keys.is_empty() {
        return vec![RouteHostScope {
            proxy_hosts: spec_hostnames.to_vec(),
            conflict_hostname: conflict_hostnames
                .first()
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
            suffix: None,
        }];
    }

    conflict_hostnames
        .iter()
        .enumerate()
        .filter_map(|(index, hostname)| {
            let has_surviving_match = descriptors_for_path.iter().any(|descriptor| {
                !descriptor_conflicts_for_host(
                    parent_refs,
                    route_family,
                    hostname,
                    descriptor,
                    losing_conflict_keys,
                )
            });
            if !has_surviving_match {
                return None;
            }

            Some(RouteHostScope {
                proxy_hosts: proxy_hosts_for_conflict_hostname(spec_hostnames, hostname),
                conflict_hostname: hostname.clone(),
                suffix: Some(format!("host{index}")),
            })
        })
        .collect()
}

fn proxy_hosts_for_conflict_hostname(spec_hostnames: &[String], hostname: &str) -> Vec<String> {
    if spec_hostnames.is_empty() && hostname == "*" {
        Vec::new()
    } else {
        vec![hostname.to_string()]
    }
}

fn skipped_descriptors_for_host(
    parent_refs: &[String],
    route_family: &str,
    hostname: &str,
    descriptors_for_path: &[RouteMatchDescriptor],
    losing_conflict_keys: &HashSet<GatewayApiRouteConflictKey>,
) -> HashSet<RouteMatchDescriptor> {
    descriptors_for_path
        .iter()
        .filter(|descriptor| {
            descriptor_conflicts_for_host(
                parent_refs,
                route_family,
                hostname,
                descriptor,
                losing_conflict_keys,
            )
        })
        .cloned()
        .collect()
}

fn descriptor_conflicts_for_host(
    parent_refs: &[String],
    route_family: &str,
    hostname: &str,
    descriptor: &RouteMatchDescriptor,
    losing_conflict_keys: &HashSet<GatewayApiRouteConflictKey>,
) -> bool {
    parent_refs.iter().any(|parent_ref| {
        losing_conflict_keys.contains(&GatewayApiRouteConflictKey {
            route_family: route_family.to_string(),
            parent_ref: parent_ref.clone(),
            hostname: hostname.to_string(),
            listen_path: descriptor.listen_path.clone(),
            match_signature: route_conflict_match_signature(descriptor),
        })
    })
}

fn has_only_zero_weight_backend_refs(rule: &Value) -> bool {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return false;
    };
    if backend_refs.is_empty() {
        return false;
    }

    backend_refs
        .iter()
        .all(|backend_ref| backend_ref.get("weight").and_then(Value::as_u64) == Some(0))
}

fn http_route_dispatch_rules_for_proxy(
    object: &K8sObject,
    rule: &Value,
    rule_index: usize,
    listen_path: Option<&str>,
    route_destination: MeshRouteDispatchDestination<'_>,
    skipped_descriptors: &HashSet<RouteMatchDescriptor>,
    entry_descriptors: &[RouteMatchEntryDescriptor],
) -> (Vec<Value>, bool) {
    let Some(matches) = rule.get("matches").and_then(Value::as_array) else {
        return (Vec::new(), true);
    };
    if matches.is_empty() {
        return (Vec::new(), true);
    }

    let mut rules = Vec::new();
    let mut has_path_only_match = false;
    for entry_descriptor in entry_descriptors {
        let match_index = entry_descriptor.match_index;
        let Some(entry) = matches.get(match_index) else {
            continue;
        };
        let descriptor = &entry_descriptor.descriptor;
        let entry_path = descriptor.listen_path.as_str();
        if let Some(listen_path) = listen_path
            && entry_path != listen_path
        {
            continue;
        }
        if skipped_descriptors.contains(descriptor) {
            continue;
        }

        let mut match_criteria = serde_json::Map::new();
        if let Some(method) = string_field(entry, "method") {
            match_criteria.insert("methods".to_string(), serde_json::json!([method]));
        }

        if let Some(headers_array) = entry.get("headers").and_then(Value::as_array) {
            let mut headers = serde_json::Map::new();
            for header in headers_array {
                if !gateway_match_type_is_exact(header) {
                    continue;
                }
                let Some(name) = string_field(header, "name") else {
                    continue;
                };
                let Some(value) = string_field(header, "value") else {
                    continue;
                };
                let name = name.to_ascii_lowercase();
                if !headers.contains_key(&name) {
                    headers.insert(name, Value::String(value.to_string()));
                }
            }
            if !headers.is_empty() {
                match_criteria.insert("headers".to_string(), Value::Object(headers));
            }
        }

        if let Some(params_array) = entry.get("queryParams").and_then(Value::as_array) {
            let mut params = serde_json::Map::new();
            for param in params_array {
                if !gateway_match_type_is_exact(param) {
                    continue;
                }
                let Some(name) = string_field(param, "name") else {
                    continue;
                };
                let Some(value) = string_field(param, "value") else {
                    continue;
                };
                let name = name.to_string();
                if !params.contains_key(&name) {
                    params.insert(name, Value::String(value.to_string()));
                }
            }
            if !params.is_empty() {
                match_criteria.insert("query_params".to_string(), Value::Object(params));
            }
        }

        if match_criteria.is_empty() {
            has_path_only_match = true;
            continue;
        }

        let mut destination = serde_json::Map::new();
        if let Some(uid) = route_destination.upstream_id {
            destination.insert("upstream_id".to_string(), Value::String(uid.to_string()));
        } else {
            destination.insert(
                "backend_host".to_string(),
                Value::String(route_destination.backend_host.to_string()),
            );
            destination.insert(
                "backend_port".to_string(),
                serde_json::json!(route_destination.backend_port),
            );
        }

        let mut route_rule = serde_json::Map::new();
        route_rule.insert("match".to_string(), Value::Object(match_criteria));
        route_rule.insert("destination".to_string(), Value::Object(destination));
        route_rule.insert(
            GATEWAY_API_DISPATCH_PRECEDENCE_KEY.to_string(),
            gateway_api_dispatch_rule_precedence(object, entry, rule_index, match_index),
        );
        rules.push(Value::Object(route_rule));
    }

    (rules, has_path_only_match)
}

fn gateway_api_dispatch_rule_precedence(
    object: &K8sObject,
    entry: &Value,
    rule_index: usize,
    match_index: usize,
) -> Value {
    let mut precedence = serde_json::Map::new();
    precedence.insert(
        "method_match".to_string(),
        Value::Bool(string_field(entry, "method").is_some()),
    );
    precedence.insert(
        "header_count".to_string(),
        serde_json::json!(translated_header_match_count(entry)),
    );
    precedence.insert(
        "query_param_count".to_string(),
        serde_json::json!(translated_query_param_match_count(entry)),
    );
    if let Some(creation_timestamp) = object.metadata.creation_timestamp.as_deref() {
        precedence.insert(
            "creation_timestamp".to_string(),
            Value::String(creation_timestamp.to_string()),
        );
    }
    precedence.insert(
        "namespace".to_string(),
        Value::String(object.metadata.namespace.clone()),
    );
    precedence.insert(
        "name".to_string(),
        Value::String(object.metadata.name.clone()),
    );
    precedence.insert("rule_index".to_string(), serde_json::json!(rule_index));
    precedence.insert("match_index".to_string(), serde_json::json!(match_index));
    Value::Object(precedence)
}

fn translated_header_match_count(entry: &Value) -> usize {
    let mut names = HashSet::new();
    if let Some(headers) = entry.get("headers").and_then(Value::as_array) {
        for header in headers {
            if !gateway_match_type_is_exact(header) {
                continue;
            }
            let Some(name) = string_field(header, "name") else {
                continue;
            };
            if string_field(header, "value").is_some() {
                names.insert(name.to_ascii_lowercase());
            }
        }
    }
    names.len()
}

fn translated_query_param_match_count(entry: &Value) -> usize {
    let mut names = HashSet::new();
    if let Some(params) = entry.get("queryParams").and_then(Value::as_array) {
        for param in params {
            if !gateway_match_type_is_exact(param) {
                continue;
            }
            let Some(name) = string_field(param, "name") else {
                continue;
            };
            if string_field(param, "value").is_some() {
                names.insert(name.to_string());
            }
        }
    }
    names.len()
}

fn http_route_match_has_supported_non_path_predicate(entry: &Value) -> bool {
    string_field(entry, "method").is_some()
        || entry
            .get("headers")
            .and_then(Value::as_array)
            .is_some_and(|headers| {
                headers.iter().any(|header| {
                    gateway_match_type_is_exact(header)
                        && string_field(header, "name").is_some()
                        && string_field(header, "value").is_some()
                })
            })
        || entry
            .get("queryParams")
            .and_then(Value::as_array)
            .is_some_and(|params| {
                params.iter().any(|param| {
                    gateway_match_type_is_exact(param)
                        && string_field(param, "name").is_some()
                        && string_field(param, "value").is_some()
                })
            })
}

fn http_route_match_has_untranslated_non_path_predicate(entry: &Value) -> bool {
    entry
        .get("headers")
        .and_then(Value::as_array)
        .is_some_and(|headers| {
            headers
                .iter()
                .any(gateway_header_query_match_is_untranslated)
        })
        || entry
            .get("queryParams")
            .and_then(Value::as_array)
            .is_some_and(|params| {
                params
                    .iter()
                    .any(gateway_header_query_match_is_untranslated)
            })
}

fn gateway_header_query_match_is_untranslated(value: &Value) -> bool {
    !gateway_match_type_is_exact(value)
        || string_field(value, "name").is_none()
        || string_field(value, "value").is_none()
}

fn gateway_match_type_is_exact(value: &Value) -> bool {
    matches!(string_field(value, "type"), None | Some("Exact"))
}

fn route_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &mut K8sAccumulator,
) -> Result<Vec<RouteBackend>, K8sTranslateError> {
    let mut backends = Vec::new();
    let mut skipped_zero = 0usize;
    for backend_ref in rule
        .get("backendRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let weight = backend_weight(object, backend_ref)?;
        if weight == 0 {
            skipped_zero += 1;
            continue;
        }
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let backend_namespace =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        let backend_port =
            optional_port_field(object, backend_ref.get("port"), "backendRefs[].port")?.unwrap_or(
                if object.kind == "GRPCRoute" {
                    50051
                } else {
                    80
                },
            );
        backends.push(RouteBackend {
            host: service_dns_name(
                backend_name,
                &backend_namespace,
                &acc.options.cluster_domain,
            ),
            port: backend_port,
            weight,
        });
    }
    if skipped_zero > 0 {
        if backends.is_empty() {
            acc.warnings.push(format!(
                "{} rule has only zero-weight backendRefs; emitted blackhole backend",
                object.kind
            ));
        } else {
            acc.warnings.push(format!(
                "{} skipped {} zero-weight backendRef(s)",
                object.kind, skipped_zero
            ));
        }
    }
    Ok(backends)
}

fn backend_weight(object: &K8sObject, backend_ref: &Value) -> Result<u32, K8sTranslateError> {
    optional_target_weight_field(object, backend_ref, "backendRefs[].weight", 1)
}

fn l4_route_proxies(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
    scheme: BackendScheme,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    ensure_route_parent_refs_allowed(object, acc)?;
    let mut proxies = Vec::new();
    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(backend_ref) = first_backend_ref(object, rule, acc)? else {
            continue;
        };
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let backend_namespace =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        let raw_backend_port =
            backend_ref
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    invalid_resource(object, "TCPRoute/TLSRoute backendRefs[].port is required")
                })?;
        let backend_port = port_from_u64(
            object,
            raw_backend_port,
            "TCPRoute/TLSRoute backendRefs[].port",
        )?;

        proxies.push(proxy_for_route(RouteProxySpec {
            id: resource_id(
                "gwapi-l4",
                &object.metadata.namespace,
                &object.metadata.name,
                &rule_index.to_string(),
            ),
            namespace: object.metadata.namespace.clone(),
            hosts: string_array(&object.spec, "hostnames"),
            listen_path: None,
            strip_listen_path: false,
            backend_host: service_dns_name(
                backend_name,
                &backend_namespace,
                &acc.options.cluster_domain,
            ),
            backend_port,
            upstream_id: None,
            backend_scheme: scheme,
            listen_port: Some(backend_port),
            retry: None,
            backend_read_timeout_ms: None,
        }));
    }
    Ok(proxies)
}

fn checked_backend_namespace(
    object: &K8sObject,
    backend_ref: &Value,
    acc: &K8sAccumulator,
    from_kind: &str,
) -> Result<String, K8sTranslateError> {
    let backend_namespace =
        string_field(backend_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let to_group = string_field(backend_ref, "group").unwrap_or_default();
    let to_kind = string_field(backend_ref, "kind").unwrap_or("Service");
    validate_supported_backend_ref(object, to_group, to_kind)?;

    if backend_namespace == object.metadata.namespace {
        return Ok(backend_namespace.to_string());
    }

    if acc.reference_grant_allows(
        &object.metadata.namespace,
        api_group(&object.api_version),
        from_kind,
        backend_namespace,
        to_group,
        to_kind,
    ) {
        Ok(backend_namespace.to_string())
    } else {
        Err(invalid_resource(
            object,
            format!(
                "{} backendRef to {} in namespace '{}' requires a matching ReferenceGrant",
                from_kind, to_kind, backend_namespace
            ),
        ))
    }
}

fn validate_supported_backend_ref(
    object: &K8sObject,
    to_group: &str,
    to_kind: &str,
) -> Result<(), K8sTranslateError> {
    if to_group.is_empty() && to_kind == "Service" {
        return Ok(());
    }

    Err(invalid_resource(
        object,
        format!(
            "unsupported backendRef target group '{}' kind '{}'; only core Service backendRefs are supported",
            to_group, to_kind
        ),
    ))
}

fn api_group(api_version: &str) -> &str {
    // Core Kubernetes API versions such as "v1" have no slash; Gateway API
    // represents that core group as the empty string in ReferenceGrant fields.
    api_version
        .split_once('/')
        .map(|(group, _version)| group)
        .unwrap_or_default()
}

fn first_backend_ref<'a>(
    object: &K8sObject,
    rule: &'a Value,
    acc: &mut K8sAccumulator,
) -> Result<Option<&'a Value>, K8sTranslateError> {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return Ok(None);
    };

    let mut selected_backend = None;
    let mut skipped_zero = 0usize;
    for backend_ref in backend_refs {
        let weight = backend_weight(object, backend_ref)?;
        if weight > 0 {
            selected_backend.get_or_insert(backend_ref);
        } else {
            skipped_zero += 1;
        }
    }

    if let Some(backend_ref) = selected_backend {
        if skipped_zero > 0 {
            acc.warnings.push(format!(
                "{} skipped {} zero-weight backendRef(s)",
                object.kind, skipped_zero
            ));
        }
        return Ok(Some(backend_ref));
    }

    if skipped_zero > 0 {
        acc.warnings.push(format!(
            "{} rule has only zero-weight backendRefs; no proxy was materialized",
            object.kind
        ));
    }
    Ok(None)
}

fn http_path_match(path: &Value) -> Option<String> {
    let value = string_field(path, "value")?;
    match string_field(path, "type").unwrap_or("PathPrefix") {
        "Exact" => Some(exact_path_listen_path(value)),
        "RegularExpression" => Some(format!("~{value}")),
        _ => Some(value.to_string()),
    }
}

fn app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        "https" | "tls" => AppProtocol::Tls,
        "grpc" => AppProtocol::Grpc,
        "tcp" => AppProtocol::Tcp,
        _ => AppProtocol::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::TrustDomain;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec,
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn object_in_namespace(kind: &str, namespace: &str, spec: Value) -> K8sObject {
        K8sObject {
            metadata: K8sMetadata {
                namespace: namespace.to_string(),
                generation: None,
                ..object(kind, Value::Null).metadata
            },
            spec,
            ..object(kind, Value::Null)
        }
    }

    fn route_with_name_and_created_at(name: &str, created_at: &str) -> K8sObject {
        let mut route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        route.metadata.name = name.to_string();
        route.metadata.creation_timestamp = Some(created_at.to_string());
        route
    }

    #[test]
    fn translates_http_route_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].hosts, vec!["api.example.com"]);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/api")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn conflicting_http_routes_use_oldest_creation_timestamp_winner() {
        let newer = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result =
            translate_k8s_objects(&[newer, older], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "oldest route must win the conflicting host/path"
        );
        assert!(result.warnings.iter().any(
            |warning| warning.contains("api-b") && warning.contains("winner is default/api-a")
        ));
    }

    #[test]
    fn translation_surfaces_conflict_list_to_status_writer() {
        // The status writer reuses `K8sTranslation.route_conflicts` so it
        // doesn't recompute conflicts (and so invalid, translator-skipped
        // routes don't leak into a valid sibling's `Conflicted` condition).
        // Guard the wiring: the same conflict that drove the warning must
        // also appear on the translation's exposed conflict list.
        let newer = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result =
            translate_k8s_objects(&[newer, older], options()).expect("translation succeeds");

        assert!(
            result
                .route_conflicts
                .iter()
                .any(|conflict| conflict.loser.name == "api-b" && conflict.winner.name == "api-a"),
            "translator must surface conflict for the losing route on K8sTranslation: {:?}",
            result.route_conflicts
        );
    }

    #[test]
    fn conflicting_http_route_timestamp_tie_uses_name_winner() {
        let right = route_with_name_and_created_at("api-b", "2026-01-01T00:00:00Z");
        let left = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");

        let result =
            translate_k8s_objects(&[right, left], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "lexicographically earlier route name must win timestamp ties"
        );
    }

    #[test]
    fn conflicting_http_routes_normalize_hostname_case() {
        let mut upper = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        upper.spec["hostnames"] = serde_json::json!(["Api.Example.Com"]);
        let lower = route_with_name_and_created_at("api-b", "2026-01-02T00:00:00Z");

        let result =
            translate_k8s_objects(&[lower, upper], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-a"),
            "case-equivalent hostnames must share one conflict bucket"
        );
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("host=api.example.com") && warning.contains("winner is default/api-a")
        }));
    }

    #[test]
    fn conflicting_http_route_drops_match_when_any_parent_ref_loses() {
        let mut winner = route_with_name_and_created_at("api-old", "2026-01-01T00:00:00Z");
        winner.spec["parentRefs"] = serde_json::json!([{"name": "edge-a"}]);

        let mut loser = route_with_name_and_created_at("api-new", "2026-01-02T00:00:00Z");
        loser.spec["parentRefs"] = serde_json::json!([{"name": "edge-a"}, {"name": "edge-b"}]);

        let result =
            translate_k8s_objects(&[loser, winner], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.proxies[0].id.contains("api-old"),
            "route losing on one parentRef must not materialize an unscoped proxy"
        );
        assert!(result.config.validate_unique_listen_paths().is_ok());
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("api-new")
                && warning.contains("parent=gateway.networking.k8s.io/Gateway/default/edge-a/*/*")
                && warning.contains("winner is default/api-old")
        }));
    }

    #[test]
    fn http_route_conflicts_preserve_match_predicates_per_path() {
        let mut get_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET"
                    }],
                    "backendRefs": [{"name": "api-get", "port": 8080}]
                }]
            }),
        );
        get_route.metadata.name = "api-get".to_string();
        get_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut post_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "POST"
                    }],
                    "backendRefs": [{"name": "api-post", "port": 8081}]
                }]
            }),
        );
        post_route.metadata.name = "api-post".to_string();
        post_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[get_route, post_route], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.validate_unique_listen_paths().is_ok(),
            "merged predicate routes must not produce duplicate host/path proxies"
        );
        assert!(
            result
                .warnings
                .iter()
                .all(|warning| !warning.contains("api-post")),
            "distinct match predicates must not conflict: {:?}",
            result.warnings
        );
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8080));
        assert_eq!(rules[1]["match"]["methods"][0].as_str(), Some("POST"));
        assert!(
            rules[1]["destination"]["backend_port"].as_u64() == Some(8081),
            "POST route must keep its own backend destination"
        );
    }

    #[test]
    fn http_route_dispatch_prefers_more_specific_gateway_api_match() {
        let mut header_only = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-env", "value": "prod"}]
                    }],
                    "backendRefs": [{"name": "api-header", "port": 8080}]
                }]
            }),
        );
        header_only.metadata.name = "api-header".to_string();
        header_only.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut method_and_header = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "method": "GET",
                        "headers": [{"name": "x-env", "value": "prod"}]
                    }],
                    "backendRefs": [{"name": "api-get-header", "port": 8081}]
                }]
            }),
        );
        method_and_header.metadata.name = "api-get-header".to_string();
        method_and_header.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[header_only, method_and_header], options())
            .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        let rules = plugin.config["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8081));
        assert_eq!(rules[1]["destination"]["backend_port"].as_u64(), Some(8080));
        assert!(
            rules
                .iter()
                .all(|rule| rule.get(GATEWAY_API_DISPATCH_PRECEDENCE_KEY).is_none()),
            "internal sort metadata must not leak into the translated config"
        );
    }

    #[test]
    fn http_route_dispatch_specificity_ties_use_route_creation_order() {
        let mut newer = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-newer", "value": "yes"}]
                    }],
                    "backendRefs": [{"name": "api-newer", "port": 8081}]
                }]
            }),
        );
        newer.metadata.name = "api-newer".to_string();
        newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let mut older = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-older", "value": "yes"}]
                    }],
                    "backendRefs": [{"name": "api-older", "port": 8080}]
                }]
            }),
        );
        older.metadata.name = "api-older".to_string();
        older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[newer, older], options()).expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("merged predicate routes need dispatch rules");
        let rules = plugin.config["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(8080));
        assert_eq!(rules[1]["destination"]["backend_port"].as_u64(), Some(8081));
    }

    #[test]
    fn http_route_conflicts_include_parent_ref_port() {
        let mut port_80_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge", "port": 80}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-http", "port": 8080}]
                }]
            }),
        );
        port_80_route.metadata.name = "api-http".to_string();
        port_80_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());

        let mut port_8080_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge", "port": 8080}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-alt", "port": 8081}]
                }]
            }),
        );
        port_8080_route.metadata.name = "api-alt".to_string();
        port_8080_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[port_80_route, port_8080_route], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(
            result.warnings.is_empty(),
            "port-distinct parentRefs must not conflict: {:?}",
            result.warnings
        );
    }

    #[test]
    fn conflicting_http_route_skips_only_conflicting_rule() {
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut mixed = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api-b", "port": 8080}]
                    },
                    {
                        "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                        "backendRefs": [{"name": "admin", "port": 9090}]
                    }
                ]
            }),
        );
        mixed.metadata.name = "api-b".to_string();
        mixed.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[older, mixed], options()).expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-a") && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b") && proxy.listen_path.as_deref() == Some("/admin")
        }));
        assert!(!result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b") && proxy.listen_path.as_deref() == Some("/api")
        }));
    }

    #[test]
    fn conflicting_weighted_http_route_does_not_emit_orphan_upstream() {
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut weighted_loser = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [
                        {"name": "api-v1", "port": 8080, "weight": 90},
                        {"name": "api-v2", "port": 8081, "weight": 10}
                    ]
                }]
            }),
        );
        weighted_loser.metadata.name = "api-b".to_string();
        weighted_loser.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[older, weighted_loser], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(
            result.config.upstreams.is_empty(),
            "fully conflicted weighted route must not leave an unreferenced upstream"
        );
    }

    #[test]
    fn conflicting_http_route_drops_match_with_surviving_parent_ref() {
        let older = route_with_name_and_created_at("api-a", "2026-01-01T00:00:00Z");
        let mut mixed_parent_route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}, {"name": "edge-alt"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api-b", "port": 8080}]
                }]
            }),
        );
        mixed_parent_route.metadata.name = "api-b".to_string();
        mixed_parent_route.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result = translate_k8s_objects(&[older, mixed_parent_route], options())
            .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert!(result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-a") && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(!result.config.proxies.iter().any(|proxy| {
            proxy.id.contains("api-b") && proxy.listen_path.as_deref() == Some("/api")
        }));
        assert!(result.config.validate_unique_listen_paths().is_ok());
    }

    #[test]
    fn conflicting_grpc_route_warning_explains_shared_path_limit() {
        let mut greeter = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/grpc"}}],
                    "backendRefs": [{"name": "greeter", "port": 50051}]
                }]
            }),
        );
        greeter.metadata.name = "greeter".to_string();
        greeter.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
        let mut goodbye = object(
            "GRPCRoute",
            serde_json::json!({
                "hostnames": ["grpc.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/grpc"}}],
                    "backendRefs": [{"name": "goodbye", "port": 50052}]
                }]
            }),
        );
        goodbye.metadata.name = "goodbye".to_string();
        goodbye.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());

        let result =
            translate_k8s_objects(&[greeter, goodbye], options()).expect("translation succeeds");

        // Two GRPCRoutes with the same path on the same host conflict — only one wins
        assert_eq!(result.config.proxies.len(), 1);
    }

    #[test]
    fn translates_http_route_exact_path_to_exact_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "Exact", "value": "/api.v1"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/api.v1")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn translates_http_route_regular_expression_path_to_regex_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "RegularExpression", "value": "/v[0-9]+/items"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("~/v[0-9]+/items")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn http_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [
                            {"name": "api-v1", "port": 8080, "weight": 90},
                            {"name": "api-v2", "port": 8081, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 8081);
    }

    #[test]
    fn http_route_creates_proxy_per_match() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"path": {"type": "PathPrefix", "value": "/v2"}}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let paths: Vec<_> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.listen_path.as_deref())
            .collect();
        assert_eq!(paths, vec![Some("/v1"), Some("/v2")]);
        assert!(
            result
                .config
                .proxies
                .iter()
                .all(|proxy| proxy.backend_port == 8080)
        );
    }

    #[test]
    fn http_route_emits_dispatch_for_predicate_only_pathless_matches() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"headers": [{"name": "x-tenant", "value": "a"}]},
                            {"method": "GET"}
                        ],
                        "backendRefs": [
                            {"name": "api-a", "port": 8080},
                            {"name": "api-b", "port": 8081}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.upstreams.len(), 1);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("predicate-only HTTPRoute emits mesh_route_dispatch");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[1]["match"]["headers"]["x-tenant"].as_str(), Some("a"));
        assert_eq!(
            rules[0]["destination"]["upstream_id"].as_str(),
            result.config.proxies[0].upstream_id.as_deref()
        );
    }

    #[test]
    fn http_route_dispatch_matchers_keep_first_duplicate_header_and_query_name() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{
                            "headers": [
                                {"name": "X-Tenant", "value": "first"},
                                {"name": "x-tenant", "value": "second"}
                            ],
                            "queryParams": [
                                {"name": "version", "value": "v1"},
                                {"name": "version", "value": "v2"}
                            ]
                        }],
                        "backendRefs": [
                            {"name": "api-a", "port": 8080},
                            {"name": "api-b", "port": 8081}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("predicate-only HTTPRoute emits mesh_route_dispatch");
        let rule_match = &plugin.config["rules"][0]["match"];
        assert_eq!(rule_match["headers"]["x-tenant"].as_str(), Some("first"));
        assert_eq!(rule_match["query_params"]["version"].as_str(), Some("v1"));
    }

    #[test]
    fn http_route_dispatch_skips_partially_supported_predicate_matches() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [
                                    {"name": "x-tenant", "value": "a"},
                                    {"type": "RegularExpression", "name": "x-scope", "value": "prod|dev"}
                                ]
                            },
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [{"name": "x-tenant", "value": "b"}],
                                "queryParams": [
                                    {"name": "version", "value": "v2"},
                                    {"type": "RegularExpression", "name": "debug", "value": "true|false"}
                                ]
                            },
                            {
                                "path": {"type": "PathPrefix", "value": "/api"},
                                "headers": [{"name": "x-tenant", "value": "c"}],
                                "queryParams": [{"name": "version", "value": "v3"}]
                            }
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("supported HTTPRoute match emits mesh_route_dispatch");
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        let rule_match = &rules[0]["match"];
        assert_eq!(rule_match["headers"]["x-tenant"].as_str(), Some("c"));
        assert_eq!(rule_match["query_params"]["version"].as_str(), Some("v3"));
    }

    #[test]
    fn http_route_rejects_cross_namespace_gateway_parent_ref() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "parentRefs": [{
                        "name": "shared-gw",
                        "namespace": "platform"
                    }],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                        "backendRefs": [{"name": "admin", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace parentRef should fail closed");

        assert!(
            err.to_string()
                .contains("only same-namespace Gateway attachments are accepted")
        );
    }

    #[test]
    fn http_route_keeps_empty_match_as_default_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn http_route_keeps_pathless_predicate_in_mixed_rule() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"headers": [{"name": "x-tenant", "value": "a"}]}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let paths: HashSet<_> = result
            .config
            .proxies
            .iter()
            .filter_map(|proxy| proxy.listen_path.as_deref())
            .collect();
        assert_eq!(paths, HashSet::from(["/v1", "/"]));
        let catch_all = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
            .expect("pathless predicate catch-all proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(catch_all.id.as_str())
            })
            .expect("catch-all proxy has dispatch rule");
        assert_eq!(
            plugin.config["rules"][0]["match"]["headers"]["x-tenant"].as_str(),
            Some("a")
        );
    }

    #[test]
    fn grpc_route_drops_pathless_method_only_matches() {
        // GRPCRoute method-only matches (no explicit path) must NOT create
        // a catch-all "/" proxy. Until per-method dispatch is implemented,
        // pathless matches are dropped to prevent overbroad traffic routing.
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"method": {"service": "helloworld.Greeter", "method": "SayHello"}},
                            {"method": {"service": "helloworld.Greeter", "method": "SayGoodbye"}}
                        ],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result.config.proxies.is_empty(),
            "pathless GRPCRoute matches should not produce proxies"
        );
    }

    #[test]
    fn grpc_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/helloworld.Greeter"}}
                        ],
                        "backendRefs": [
                            {"name": "grpc-v1", "port": 50051, "weight": 90},
                            {"name": "grpc-v2", "port": 50052, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/helloworld.Greeter")
        );
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 50052);
    }

    #[test]
    fn gateway_api_weighted_upstream_ids_include_route_kind() {
        let result = translate_k8s_objects(
            &[
                object(
                    "HTTPRoute",
                    serde_json::json!({
                        "hostnames": ["api.example.com"],
                        "rules": [{
                            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                            "backendRefs": [
                                {"name": "api-v1", "port": 8080, "weight": 90},
                                {"name": "api-v2", "port": 8081, "weight": 10}
                            ]
                        }]
                    }),
                ),
                object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [
                                {"path": {"type": "PathPrefix", "value": "/helloworld.Greeter"}}
                            ],
                            "backendRefs": [
                                {"name": "grpc-v1", "port": 50051, "weight": 90},
                                {"name": "grpc-v2", "port": 50052, "weight": 10}
                            ]
                        }]
                    }),
                ),
            ],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert_eq!(result.config.upstreams.len(), 2);
        assert_ne!(result.config.upstreams[0].id, result.config.upstreams[1].id);
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("httproute"))
        );
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("grpcroute"))
        );
        assert_eq!(
            result
                .config
                .proxies
                .iter()
                .filter_map(|proxy| proxy.upstream_id.as_deref())
                .collect::<HashSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn http_route_keeps_all_zero_weight_rule_as_blackhole() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                            "backendRefs": [{"name": "admin", "port": 8080, "weight": 0}]
                        },
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [{"name": "api", "port": 8080}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        let admin_proxy = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/admin"))
            .expect("admin route proxy exists");
        assert_eq!(admin_proxy.backend_host, ZERO_WEIGHT_BACKEND_HOST);
        assert_eq!(admin_proxy.backend_port, ZERO_WEIGHT_BACKEND_PORT);
        assert!(admin_proxy.upstream_id.is_none());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn http_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 8080, "weight": 0},
                            {"name": "stable", "port": 9090, "weight": 100}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 9090);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn http_route_omitted_weight_defaults_to_one_and_skips_zero_sibling() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 8080, "weight": 0},
                            {"name": "stable", "port": 9090}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 9090);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn http_route_rejects_backend_weight_above_ferrum_limit() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 8080, "weight": 65536}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("oversized backend weight should fail translation");

        assert!(
            err.to_string()
                .contains("weight must be between 0 and 65535")
        );
    }

    #[test]
    fn http_route_rejects_malformed_backend_weights() {
        for weight in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("high"),
        ] {
            let err = translate_k8s_objects(
                &[object(
                    "HTTPRoute",
                    serde_json::json!({
                        "rules": [{
                            "backendRefs": [{"name": "api", "port": 8080, "weight": weight}]
                        }]
                    }),
                )],
                options(),
            )
            .expect_err("malformed backend weight should fail translation");

            assert!(
                err.to_string()
                    .contains("weight must be between 0 and 65535")
            );
        }
    }

    #[test]
    fn translates_tcp_route_to_stream_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 5432}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn tcp_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 5432, "weight": 0},
                            {"name": "stable", "port": 5433, "weight": 1}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 5433);
        assert_eq!(result.config.proxies[0].listen_port, Some(5433));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn tls_route_with_only_zero_weight_backend_refs_is_not_materialized() {
        let result = translate_k8s_objects(
            &[object(
                "TLSRoute",
                serde_json::json!({
                    "hostnames": ["db.example.com"],
                    "rules": [{
                        "backendRefs": [{"name": "dark", "port": 15443, "weight": 0}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn rejects_gateway_api_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid port must fail closed");

        assert!(err.to_string().contains("backendRefs[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_gateway_listener_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "Gateway",
                serde_json::json!({
                    "listeners": [{"name": "http", "port": 70000, "protocol": "HTTP"}]
                }),
            )],
            options(),
        )
        .expect_err("invalid listener port must fail closed");

        assert!(err.to_string().contains("listeners[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_l4_route_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid L4 backend port must fail closed");

        assert!(
            err.to_string()
                .contains("TCPRoute/TLSRoute backendRefs[].port")
        );
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_without_reference_grant() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "name": "api",
                            "namespace": "backend",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace backendRef must fail closed");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn skips_zero_weight_cross_namespace_backend_ref_without_reference_grant() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "api", "port": 8080},
                            {
                                "name": "staged-api",
                                "namespace": "backend",
                                "port": 8081,
                                "weight": 0
                            }
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("zero-weight cross-namespace backendRef should not require a ReferenceGrant");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_when_reference_grant_from_group_mismatches() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant group must match route API group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_when_reference_grant_to_group_mismatches() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "example.com",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant target group must match backendRef group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn rejects_unsupported_backend_ref_kind() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "group": "example.com",
                            "kind": "Backend",
                            "name": "api",
                            "namespace": "default",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("non-Service backendRefs must fail closed");

        assert!(
            err.to_string()
                .contains("only core Service backendRefs are supported")
        );
    }

    #[test]
    fn accepts_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let options =
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

        let result = translate_k8s_objects(&[route, grant], options)
            .expect("ReferenceGrant should authorize backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.backend.svc.cluster.local"
        );
    }

    #[test]
    fn excluded_namespace_reference_grant_does_not_authorize_included_route() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );
        let options = options().with_source_namespaces(vec!["default".to_string()]);

        let err = translate_k8s_objects(&[route, grant], options)
            .expect_err("ReferenceGrant from an excluded namespace must not authorize the route");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn accepts_tcp_route_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 5432
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "TCPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let options =
            options().with_source_namespaces(vec!["default".to_string(), "backend".to_string()]);

        let result = translate_k8s_objects(&[route, grant], options)
            .expect("ReferenceGrant should authorize TCPRoute backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "db.backend.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn rejects_tls_route_cross_namespace_backend_ref_when_reference_grant_from_group_mismatches() {
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "hostnames": ["db.example.com"],
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 15443
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "TLSRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant group must match TLSRoute API group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn http_route_uses_custom_cluster_domain() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["app.example.com"],
                "rules": [{
                    "backendRefs": [{ "name": "stable", "port": 8080 }]
                }]
            }),
        );

        let opts = options().with_cluster_domain("corp.example".to_string());
        let result =
            translate_k8s_objects(&[route], opts).expect("custom cluster domain should work");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.corp.example"
        );
    }

    #[test]
    fn tcp_route_uses_custom_cluster_domain() {
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{ "name": "db", "port": 5432 }]
                }]
            }),
        );

        let opts = options().with_cluster_domain("corp.example".to_string());
        let result =
            translate_k8s_objects(&[route], opts).expect("custom cluster domain should work");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "db.default.svc.corp.example"
        );
    }
}
