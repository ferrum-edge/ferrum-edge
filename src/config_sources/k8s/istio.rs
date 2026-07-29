use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AccessLogFilter, AppProtocol, ConditionMatch, JwtHeader, MeshAccessLoggingConfig,
    MeshConsistentHash, MeshCorsOriginMatch, MeshCorsPolicy, MeshDestinationRule, MeshEndpoint,
    MeshJwtRule, MeshLoadBalancer, MeshLocalityDistribute, MeshLocalityFailover,
    MeshLocalityLbSetting, MeshMetricsConfig, MeshOutlierDetection, MeshPolicy, MeshProxyConfig,
    MeshRequestAuthentication, MeshRule, MeshSidecar, MeshSidecarEgress, MeshSidecarIngress,
    MeshSimpleLb, MeshSubset, MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig,
    MeshTrafficPolicy, MeshTrafficPolicyTls, MeshVirtualServiceCorsPolicy, MetricTagOverride,
    MtlsMode, PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
    Resolution, ServiceEntry, ServiceEntryLocation, ServicePort, SourceNegationMatch,
    TagOverrideOperation, TelemetryTracingMode, TracingProvider, Workload, WorkloadPort,
    WorkloadSelector, is_mesh_condition_ip_key, is_supported_mesh_condition_key,
    mesh_condition_has_values, validate_mesh_condition_ip_block,
};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions,
    MeshRouteDispatchDestination, MeshRouteDispatchPolicy, RouteBackend, RouteProxySpec,
    SourceKind, attach_route_plugins_to_proxy, exact_path_listen_path, invalid_resource,
    mesh_route_dispatch_can_emit_rule, mesh_route_dispatch_has_unsupported_predicate,
    mesh_route_dispatch_plugin_from_rules, mesh_route_dispatch_rules_for_proxy,
    optional_port_field, optional_target_weight_field, parse_istio_duration_ms, port_from_u64,
    proxy_for_route, request_termination_plugin_for_proxy, resource_id,
    route_backends_require_node_waypoint_authz, route_local_fault_delay_for_rule,
    route_local_fault_value_for_rule, route_request_transformer_plugin_for_proxy,
    route_response_transformer_plugin_for_proxy, sidecar_selector_from_istio, string_array,
    string_field, string_map, upstream_for_route, workload_entry_service_key_from_host,
    workload_selector_from_istio,
};
use crate::config::types::{
    BackendScheme, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH, MAX_RETRIES, MAX_TARGET_WEIGHT, MAX_TIMEOUT_MS,
    PluginConfig, Proxy, RetryConfig, validate_backend_tls_san_allow_list_entry,
    validate_backend_tls_sni,
};
use crate::plugins::mesh::workload_metrics::{
    is_recognized_unsupported_istio_metric_family, validate_istio_telemetry_config,
};

const URI_LESS_MATCH_LISTEN_PATH: &str = "~.*";

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "AuthorizationPolicy" => {
            acc.mesh
                .mesh_policies
                .push(authorization_policy(&acc.options, object)?);
            Ok(true)
        }
        "PeerAuthentication" => {
            let peer_auth = peer_authentication(&acc.options, object)?;
            acc.mesh.peer_authentications.push(peer_auth);
            Ok(true)
        }
        "ServiceEntry" => {
            acc.mesh.service_entries.push(service_entry(object)?);
            Ok(true)
        }
        "WorkloadEntry" => {
            acc.mesh.workloads.push(workload_entry(acc, object)?);
            Ok(true)
        }
        "VirtualService" => {
            let (proxies, upstreams, plugins) = virtual_service_routes(object, acc)?;
            for upstream in upstreams {
                acc.upsert_upstream(upstream);
            }
            for proxy in proxies {
                acc.upsert_proxy(proxy, SourceKind::Istio);
            }
            for plugin in plugins {
                acc.config.plugin_configs.push(plugin);
            }
            Ok(true)
        }
        "DestinationRule" => {
            let dr = destination_rule(acc, object)?;
            acc.mesh.destination_rules.push(dr);
            Ok(true)
        }
        "RequestAuthentication" => {
            acc.mesh
                .request_authentications
                .push(request_authentication(acc, object)?);
            Ok(true)
        }
        "Sidecar" => {
            let sidecar = sidecar(acc, object)?;
            acc.mesh.sidecars.push(sidecar);
            Ok(true)
        }
        "Telemetry" => {
            let telemetry = telemetry(acc, object)?;
            acc.mesh.telemetry_resources.push(telemetry);
            Ok(true)
        }
        "ProxyConfig" => {
            acc.mesh
                .proxy_configs
                .push(proxy_config(&acc.options, object)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn authorization_policy(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Result<MeshPolicy, K8sTranslateError> {
    let action = match string_field(&object.spec, "action").unwrap_or("ALLOW") {
        "ALLOW" => PolicyAction::Allow,
        "DENY" => PolicyAction::Deny,
        "AUDIT" => PolicyAction::Audit,
        other => {
            return Err(invalid_resource(
                object,
                format!("AuthorizationPolicy action '{other}' is unsupported"),
            ));
        }
    };

    if object.spec.get("targetRefs").is_some() {
        return Err(invalid_resource(
            object,
            "AuthorizationPolicy targetRefs are not supported yet; use selector or namespace scope",
        ));
    }

    let scope = istio_policy_scope(options, object, object.spec.get("selector"));

    let mut rules = Vec::new();
    for rule in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        rules.extend(mesh_rules(object, rule, action)?);
    }
    if rules.is_empty() && action == PolicyAction::Allow {
        tracing::warn!(
            namespace = %object.metadata.namespace,
            policy = %object.metadata.name,
            "Istio ALLOW AuthorizationPolicy has no rules; emitting synthetic never-match allow rule to preserve allow-nothing semantics",
        );
        rules.push(allow_nothing_rule());
    }

    Ok(MeshPolicy {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        rules,
    })
}

fn allow_nothing_rule() -> MeshRule {
    MeshRule {
        never_matches: true,
        action: PolicyAction::Allow,
        ..MeshRule::default()
    }
}

fn mesh_rules(
    object: &K8sObject,
    rule: &Value,
    action: PolicyAction,
) -> Result<Vec<MeshRule>, K8sTranslateError> {
    let sources: Vec<&Value> = rule
        .get("from")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|source_entry| source_entry.get("source").unwrap_or(&Value::Null))
        .collect();
    // Fail closed on any source field we do not yet support, mirroring the
    // `to.operation` side (`validate_supported_operation_fields`). Without
    // this gate, an unsupported source key (e.g. a future Istio field) would
    // be silently dropped and the rule would match more traffic than the
    // operator authored.
    for source in &sources {
        validate_supported_source_fields(object, source)?;
    }
    let mut to = Vec::new();
    let mut has_unconstrained_to = false;
    for request in rule
        .get("to")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|to| request_match(object, to.get("operation").unwrap_or(&Value::Null)))
    {
        let request = request?;
        if request_match_is_unconstrained(&request) {
            has_unconstrained_to = true;
        } else {
            to.push(request);
        }
    }
    if has_unconstrained_to {
        to.clear();
    }
    let mut when = Vec::new();
    if let Some(when_value) = rule.get("when") {
        let conditions = when_value
            .as_array()
            .ok_or_else(|| invalid_resource(object, "rules[].when must be an array"))?;
        for (index, condition) in conditions.iter().enumerate() {
            when.push(condition_match(object, index, condition)?);
        }
    }

    if sources.is_empty() {
        return Ok(vec![MeshRule {
            from: Vec::new(),
            to,
            when,
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: SourceNegationMatch::default(),
            never_matches: false,
            action,
        }]);
    }

    sources
        .into_iter()
        .map(|source| {
            Ok(MeshRule {
                from: principal_matches(object, source)?,
                to: to.clone(),
                when: when.clone(),
                request_principals: string_array(source, "requestPrincipals"),
                not_request_principals: string_array(source, "notRequestPrincipals"),
                source_negation: source_negation_match(object, source)?,
                never_matches: false,
                action,
            })
        })
        .collect()
}

fn principal_matches(
    object: &K8sObject,
    source: &Value,
) -> Result<Vec<PrincipalMatch>, K8sTranslateError> {
    let principals = string_array(source, "principals");
    let service_accounts = service_account_principal_patterns(object, source, "serviceAccounts")?;
    let namespaces = string_array(source, "namespaces");
    let trust_domains = string_array(source, "trustDomains");

    if !service_accounts.is_empty() && (!principals.is_empty() || !namespaces.is_empty()) {
        return Err(invalid_resource(
            object,
            "rules[].from[].source.serviceAccounts cannot be set with principals or namespaces"
                .to_string(),
        ));
    }

    let principal_patterns = if service_accounts.is_empty() {
        principals
    } else {
        service_accounts
    };
    if principal_patterns.is_empty() && namespaces.is_empty() && trust_domains.is_empty() {
        return Ok(Vec::new());
    }

    let principal_patterns = optional_match_values(principal_patterns);
    let namespaces = optional_match_values(namespaces);
    let trust_domains = optional_match_values(trust_domains);

    let mut matches = Vec::new();
    for principal in &principal_patterns {
        for namespace in &namespaces {
            for trust_domain in &trust_domains {
                matches.push(PrincipalMatch {
                    spiffe_id_pattern: principal.clone(),
                    namespace_pattern: namespace.clone(),
                    trust_domain: None,
                    trust_domain_pattern: trust_domain.clone(),
                });
            }
        }
    }

    Ok(matches)
}

fn optional_match_values(values: Vec<String>) -> Vec<Option<String>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.into_iter().map(Some).collect()
    }
}

fn service_account_principal_patterns(
    object: &K8sObject,
    source: &Value,
    field: &str,
) -> Result<Vec<String>, K8sTranslateError> {
    string_array(source, field)
        .into_iter()
        .map(|service_account| service_account_principal_pattern(object, field, &service_account))
        .collect()
}

fn service_account_principal_pattern(
    object: &K8sObject,
    field: &str,
    service_account: &str,
) -> Result<String, K8sTranslateError> {
    if service_account.contains('*') {
        return Err(invalid_resource(
            object,
            format!("rules[].from[].source.{field} '{service_account}' must not contain wildcards"),
        ));
    }

    let (namespace, service_account) = match service_account.split_once('/') {
        Some((namespace, service_account)) if !service_account.contains('/') => {
            (namespace, service_account)
        }
        Some(_) => {
            return Err(invalid_resource(
                object,
                format!(
                    "rules[].from[].source.{field} '{service_account}' must be '<serviceaccount>' or '<namespace>/<serviceaccount>'"
                ),
            ));
        }
        None => (object.metadata.namespace.as_str(), service_account),
    };

    if namespace.is_empty() || service_account.is_empty() {
        return Err(invalid_resource(
            object,
            format!(
                "rules[].from[].source.{field} '{service_account}' must include a non-empty namespace and service account"
            ),
        ));
    }

    Ok(format!("*/ns/{namespace}/sa/{service_account}"))
}

/// Translate the conjunctive source-negative / IP-block fields of one Istio
/// `from[].source` block into a [`SourceNegationMatch`]. IP blocks are
/// validated here so a malformed CIDR rejects the resource (fail-closed)
/// rather than silently never matching at request time.
fn source_negation_match(
    object: &K8sObject,
    source: &Value,
) -> Result<SourceNegationMatch, K8sTranslateError> {
    let parse_ip_blocks =
        |field: &str| -> Result<Vec<crate::modes::mesh::config::ParsedCidr>, K8sTranslateError> {
            string_array(source, field)
                .into_iter()
                .map(|block| {
                    crate::modes::mesh::config::ParsedCidr::parse(&block).map_err(|reason| {
                        invalid_resource(
                            object,
                            format!("rules[].from[].source.{field} '{block}' is invalid: {reason}"),
                        )
                    })
                })
                .collect()
        };

    let mut not_spiffe_id_patterns = string_array(source, "notPrincipals");
    not_spiffe_id_patterns.extend(service_account_principal_patterns(
        object,
        source,
        "notServiceAccounts",
    )?);

    Ok(SourceNegationMatch {
        not_spiffe_id_patterns,
        not_namespace_patterns: string_array(source, "notNamespaces"),
        not_trust_domain_patterns: string_array(source, "notTrustDomains"),
        ip_blocks: parse_ip_blocks("ipBlocks")?,
        not_ip_blocks: parse_ip_blocks("notIpBlocks")?,
        remote_ip_blocks: parse_ip_blocks("remoteIpBlocks")?,
        not_remote_ip_blocks: parse_ip_blocks("notRemoteIpBlocks")?,
    })
}

/// Reject any `from[].source` field that the translator does not yet support
/// so the resource fails closed instead of silently admitting more traffic.
/// Mirrors [`validate_supported_operation_fields`] on the `to.operation` side.
fn validate_supported_source_fields(
    object: &K8sObject,
    source: &Value,
) -> Result<(), K8sTranslateError> {
    for key in source
        .as_object()
        .into_iter()
        .flat_map(|fields| fields.keys())
    {
        match key.as_str() {
            "principals"
            | "notPrincipals"
            | "serviceAccounts"
            | "notServiceAccounts"
            | "namespaces"
            | "notNamespaces"
            | "trustDomains"
            | "notTrustDomains"
            | "ipBlocks"
            | "notIpBlocks"
            | "remoteIpBlocks"
            | "notRemoteIpBlocks"
            | "requestPrincipals"
            | "notRequestPrincipals" => {}
            _ => {
                return Err(invalid_resource(
                    object,
                    format!("rules[].from[].source.{key} is unsupported"),
                ));
            }
        }
    }
    Ok(())
}

fn request_match(object: &K8sObject, operation: &Value) -> Result<RequestMatch, K8sTranslateError> {
    validate_supported_operation_fields(object, operation)?;
    let (ports, port_patterns) = operation_ports(object, operation, "ports")?;
    let (not_ports, not_port_patterns) = operation_ports(object, operation, "notPorts")?;
    if !not_port_patterns.is_empty() {
        return Err(invalid_resource(
            object,
            "rules[].to[].operation.notPorts wildcard patterns are unsupported \
             (use literal numeric ports)"
                .to_string(),
        ));
    }

    Ok(RequestMatch {
        methods: string_array(operation, "methods"),
        paths: string_array(operation, "paths"),
        hosts: string_array(operation, "hosts"),
        headers: HashMap::new(),
        ports,
        port_patterns,
        not_methods: string_array(operation, "notMethods"),
        not_paths: string_array(operation, "notPaths"),
        not_hosts: string_array(operation, "notHosts"),
        not_ports,
    })
}

fn validate_supported_operation_fields(
    object: &K8sObject,
    operation: &Value,
) -> Result<(), K8sTranslateError> {
    for key in operation
        .as_object()
        .into_iter()
        .flat_map(|fields| fields.keys())
    {
        match key.as_str() {
            "methods" | "paths" | "hosts" | "ports" | "notMethods" | "notPaths" | "notHosts"
            | "notPorts" => {}
            _ => {
                return Err(invalid_resource(
                    object,
                    format!("rules[].to[].operation.{key} is unsupported"),
                ));
            }
        }
    }
    Ok(())
}

fn operation_ports(
    object: &K8sObject,
    operation: &Value,
    field: &str,
) -> Result<(Vec<u16>, Vec<String>), K8sTranslateError> {
    let mut ports = Vec::new();
    let mut port_patterns = Vec::new();
    for port in string_array(operation, field) {
        if is_istio_port_pattern(&port) {
            port_patterns.push(port);
            continue;
        }
        ports.push(port_from_string(
            object,
            &port,
            &format!("rules[].to[].operation.{field}"),
        )?);
    }
    Ok((ports, port_patterns))
}

fn is_istio_port_pattern(port: &str) -> bool {
    if port == "*" {
        return true;
    }
    if let Some(prefix) = port.strip_suffix('*') {
        return !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit());
    }
    if let Some(suffix) = port.strip_prefix('*') {
        return !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

fn request_match_is_unconstrained(request: &RequestMatch) -> bool {
    request.methods.is_empty()
        && request.paths.is_empty()
        && request.hosts.is_empty()
        && request.headers.is_empty()
        && request.ports.is_empty()
        && request.port_patterns.is_empty()
        && request.not_methods.is_empty()
        && request.not_paths.is_empty()
        && request.not_hosts.is_empty()
        && request.not_ports.is_empty()
}

fn condition_match(
    object: &K8sObject,
    index: usize,
    value: &Value,
) -> Result<ConditionMatch, K8sTranslateError> {
    let key = string_field(value, "key").ok_or_else(|| {
        invalid_resource(object, format!("rules[].when[{index}].key is required"))
    })?;
    if !is_supported_mesh_condition_key(key) {
        return Err(invalid_resource(
            object,
            format!("rules[].when[{index}].key '{key}' is unsupported"),
        ));
    }
    let values = string_array(value, "values");
    let not_values = string_array(value, "notValues");
    let condition = ConditionMatch {
        key: key.to_string(),
        values,
        not_values,
    };
    if !mesh_condition_has_values(&condition) {
        return Err(invalid_resource(
            object,
            format!("rules[].when[{index}].key '{key}' must set values or notValues"),
        ));
    }
    if is_mesh_condition_ip_key(key) {
        validate_condition_ip_blocks(object, index, "values", &condition.values)?;
        validate_condition_ip_blocks(object, index, "notValues", &condition.not_values)?;
    }
    Ok(condition)
}

fn validate_condition_ip_blocks(
    object: &K8sObject,
    condition_index: usize,
    field: &str,
    values: &[String],
) -> Result<(), K8sTranslateError> {
    for (value_index, value) in values.iter().enumerate() {
        validate_mesh_condition_ip_block(value).map_err(|error| {
            invalid_resource(
                object,
                format!(
                    "rules[].when[{condition_index}].{field}[{value_index}] '{value}' is invalid: {error}"
                ),
            )
        })?;
    }
    Ok(())
}

fn peer_authentication(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Result<PeerAuthentication, K8sTranslateError> {
    let mtls = object.spec.get("mtls").unwrap_or(&Value::Null);
    let effective_mtls_mode = mtls_mode(string_field(mtls, "mode").unwrap_or("PERMISSIVE"))
        .map_err(|message| invalid_resource(object, format!("mtls.mode {message}")))?;
    let mut port_overrides = HashMap::new();
    for (port, value) in object
        .spec
        .get("portLevelMtls")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|ports| ports.iter())
    {
        let port = port_from_string(object, port, "portLevelMtls")?;
        let mode =
            mtls_mode(string_field(value, "mode").unwrap_or("PERMISSIVE")).map_err(|message| {
                invalid_resource(object, format!("portLevelMtls[{port}].mode {message}"))
            })?;
        port_overrides.insert(port, mode);
    }

    let selector = object.spec.get("selector");
    let scope = istio_policy_scope(options, object, selector);
    let selector = match &scope {
        PolicyScope::WorkloadSelector { selector } => Some(selector.clone()),
        PolicyScope::MeshWide | PolicyScope::Namespace { .. } => None,
    };

    Ok(PeerAuthentication {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope: Some(scope),
        selector,
        mtls_mode: effective_mtls_mode,
        port_overrides,
    })
}

/// Translate an Istio `Sidecar` resource into a [`MeshSidecar`].
///
/// Parses:
///   - `spec.workloadSelector.matchLabels` → [`MeshSidecar::workload_selector`]
///     with the Sidecar's own namespace. Istio only treats selector-less root
///     namespace Sidecars as global defaults; labeled root Sidecars remain
///     namespace-scoped.
///   - `spec.egress[].hosts` → [`MeshSidecarEgress::hosts`] (verbatim — the
///     slice builder parses each entry via `MeshSidecarEgress::parse_host_pattern`).
///   - `spec.egress[].port.number` → [`MeshSidecarEgress::port`] (optional).
///   - `spec.ingress[]` → [`MeshSidecarIngress`] (port, protocol, name, bind,
///     and `defaultEndpoint`). Per Istio semantics, when `ingress` is present
///     it replaces the workload's default per-service-port inbound listeners;
///     the slice builder resolves each entry to a routable loopback target and
///     the inbound materializer emits routes from them (see
///     `materialize_sidecar_inbound_proxies`). Unix-socket `defaultEndpoint`s
///     and non-HTTP-family listeners are parsed but cannot be modeled and stay
///     in the `deferred_fields` report (resolved fail-closed downstream).
///
/// `outboundTrafficPolicy` is still not translated here — it stays in the
/// documented "deferred" table until a separate PR lands it.
fn sidecar(
    _acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshSidecar, K8sTranslateError> {
    let workload_selector = match object.spec.get("workloadSelector") {
        Some(selector_value) => {
            let labels = sidecar_selector_from_istio(Some(selector_value));
            if labels.is_empty() {
                None
            } else {
                Some(WorkloadSelector {
                    labels,
                    namespace: Some(object.metadata.namespace.clone()),
                })
            }
        }
        None => None,
    };

    let mut egress = Vec::new();
    let mut egress_inherits_defaults = false;
    match object.spec.get("egress") {
        None => {
            // Istio: omitted egress inherits the namespace default outbound
            // scope. Keep it distinct from an explicit empty `egress: []`,
            // which means block all.
            egress_inherits_defaults = true;
        }
        Some(raw_egress) => {
            let entries = raw_egress
                .as_array()
                .ok_or_else(|| invalid_resource(object, "Sidecar egress must be an array"))?;
            for entry in entries {
                let hosts_value = entry.get("hosts").ok_or_else(|| {
                    invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    )
                })?;
                let hosts_array = hosts_value.as_array().ok_or_else(|| {
                    invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    )
                })?;
                if hosts_array.is_empty() {
                    return Err(invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    ));
                }
                let hosts: Vec<String> = hosts_array
                    .iter()
                    .map(|host| {
                        host.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            invalid_resource(
                                object,
                                "Sidecar egress[].hosts must be a non-empty array of strings",
                            )
                        })
                    })
                    .collect::<Result<_, _>>()?;
                let port = match entry.get("port") {
                    Some(port_obj) => optional_port_field(
                        object,
                        port_obj.get("number"),
                        "Sidecar egress[].port.number",
                    )?,
                    None => None,
                };
                egress.push(MeshSidecarEgress { hosts, port });
            }
        }
    }

    // `spec.ingress[]` — custom inbound listeners. Each entry MUST declare a
    // `port.number` and a `defaultEndpoint`; everything else is optional. We
    // translate the entry shape here (parse + validate the required fields) and
    // defer the routable/unsupported decision (Unix sockets, non-HTTP-family,
    // arbitrary IPs) to `MeshSidecarIngress::resolve` at slice build, so the
    // status writer can keep unsupported entries in `deferred_fields` while
    // accepting the resource.
    let mut ingress = Vec::new();
    // Istio distinguishes an OMITTED `ingress` block (keep automatic
    // per-service-port inbound defaults) from a DECLARED one — including an
    // explicit empty `ingress: []`, which configures the workload's inbound
    // listeners explicitly and REPLACES the defaults. Record presence so the
    // slice builder suppresses the default inbound routes for an explicit-empty
    // ingress instead of falling back to the service-port defaults. Mirrors
    // `egress_inherits_defaults`'s omitted-vs-explicit-empty distinction.
    let ingress_declared = object.spec.get("ingress").is_some();
    if let Some(raw_ingress) = object.spec.get("ingress") {
        let entries = raw_ingress
            .as_array()
            .ok_or_else(|| invalid_resource(object, "Sidecar ingress must be an array"))?;
        for entry in entries {
            let port_obj = entry
                .get("port")
                .ok_or_else(|| invalid_resource(object, "Sidecar ingress[].port is required"))?;
            let port = optional_port_field(
                object,
                port_obj.get("number"),
                "Sidecar ingress[].port.number",
            )?
            .ok_or_else(|| {
                invalid_resource(
                    object,
                    "Sidecar ingress[].port.number is required and must be 1-65535",
                )
            })?;
            // Use the ingress-specific classifier (NOT the generic
            // `app_protocol`): a custom inbound listener routes only recognized
            // HTTP-family protocols; a missing or mistyped protocol maps to a
            // non-HTTP `AppProtocol` so resolution defers it fail-closed instead
            // of exposing it on the HTTP request path (`https` still routes).
            let protocol =
                sidecar_ingress_app_protocol(port_obj.get("protocol").and_then(Value::as_str));
            let name = port_obj
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let bind = entry
                .get("bind")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            // `defaultEndpoint` is OPTIONAL in Istio (an entry without one
            // forwards nowhere). We accept it as-is; resolution treats an empty
            // or unsupported endpoint as a non-modeled (deferred) listener
            // rather than rejecting the whole resource.
            let default_endpoint = entry
                .get("defaultEndpoint")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_default();
            ingress.push(MeshSidecarIngress {
                port,
                protocol,
                name,
                bind,
                default_endpoint,
            });
        }
    }

    Ok(MeshSidecar {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        workload_selector,
        egress_inherits_defaults,
        egress,
        ingress_declared,
        ingress,
    })
}

fn request_authentication(
    acc: &K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshRequestAuthentication, K8sTranslateError> {
    let scope = istio_policy_scope(&acc.options, object, object.spec.get("selector"));

    let jwt_rules: Vec<MeshJwtRule> = object
        .spec
        .get("jwtRules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| translate_jwt_rule(object, rule))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MeshRequestAuthentication {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        jwt_rules,
    })
}

fn translate_jwt_rule(object: &K8sObject, rule: &Value) -> Result<MeshJwtRule, K8sTranslateError> {
    let issuer = string_field(rule, "issuer")
        .ok_or_else(|| {
            invalid_resource(
                object,
                "RequestAuthentication jwtRules[].issuer is required",
            )
        })?
        .to_string();

    let audiences = optional_string_array(
        object,
        rule,
        "audiences",
        "RequestAuthentication jwtRules[].audiences",
    )?;
    let jwks_uri = string_field(rule, "jwksUri").map(ToOwned::to_owned);
    let jwks = string_field(rule, "jwks").map(ToOwned::to_owned);

    let from_headers = jwt_from_headers(object, rule)?;

    let from_params = optional_string_array(
        object,
        rule,
        "fromParams",
        "RequestAuthentication jwtRules[].fromParams",
    )?;
    let forward_original_token = rule
        .get("forwardOriginalToken")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(MeshJwtRule {
        issuer,
        audiences,
        jwks_uri,
        jwks,
        from_headers,
        from_params,
        forward_original_token,
    })
}

fn jwt_from_headers(object: &K8sObject, rule: &Value) -> Result<Vec<JwtHeader>, K8sTranslateError> {
    let Some(raw) = rule.get("fromHeaders") else {
        return Ok(Vec::new());
    };
    let Some(headers) = raw.as_array() else {
        return Err(invalid_resource(
            object,
            "RequestAuthentication jwtRules[].fromHeaders must be an array of objects",
        ));
    };

    headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let name = string_field(header, "name").ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "RequestAuthentication jwtRules[].fromHeaders[{index}].name is required"
                    ),
                )
            })?;
            let prefix = match header.get("prefix") {
                Some(prefix) => {
                    let prefix = prefix.as_str().ok_or_else(|| {
                        invalid_resource(
                            object,
                            format!(
                                "RequestAuthentication jwtRules[].fromHeaders[{index}].prefix must be a string"
                            ),
                        )
                    })?;
                    (!prefix.is_empty()).then_some(prefix)
                }
                None => None,
            };
            Ok(JwtHeader {
                name: name.to_string(),
                prefix: prefix.map(ToOwned::to_owned),
            })
        })
        .collect()
}

fn istio_policy_scope(
    options: &K8sTranslationOptions,
    object: &K8sObject,
    selector: Option<&Value>,
) -> PolicyScope {
    let is_root_namespace = object.metadata.namespace == options.istio_root_namespace;
    let selector_namespace = (!is_root_namespace).then(|| object.metadata.namespace.clone());
    match workload_selector_from_istio(selector, selector_namespace) {
        Some(selector) => PolicyScope::WorkloadSelector { selector },
        None if is_root_namespace => PolicyScope::MeshWide,
        None => PolicyScope::Namespace {
            namespace: object.metadata.namespace.clone(),
        },
    }
}

fn optional_string_array(
    object: &K8sObject,
    value: &Value,
    key: &str,
    display_path: &str,
) -> Result<Vec<String>, K8sTranslateError> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = raw.as_array() else {
        return Err(invalid_resource(
            object,
            format!("{display_path} must be an array of strings"),
        ));
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                invalid_resource(object, format!("{display_path}[{index}] must be a string"))
            })
        })
        .collect()
}

fn port_from_string(object: &K8sObject, raw: &str, field: &str) -> Result<u16, K8sTranslateError> {
    let parsed = raw.parse::<u64>().map_err(|_| {
        invalid_resource(
            object,
            format!("{field} must be a numeric port between 1 and 65535 (got {raw})"),
        )
    })?;
    port_from_u64(object, parsed, field)
}

fn destination_rule(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshDestinationRule, K8sTranslateError> {
    let host_raw = string_field(&object.spec, "host")
        .ok_or_else(|| invalid_resource(object, "DestinationRule requires spec.host"))?;
    let host = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(invalid_resource(
            object,
            "DestinationRule spec.host must be a non-empty hostname",
        ));
    }

    let traffic_policy = object
        .spec
        .get("trafficPolicy")
        .map(|tp| translate_traffic_policy(acc, object, tp, TrafficPolicyScope::TopLevelOrPort))
        .transpose()?
        .filter(traffic_policy_has_applied_fields);

    let port_level_settings = object
        .spec
        .get("trafficPolicy")
        .and_then(|tp| tp.get("portLevelSettings"))
        .map(|pls| translate_port_level_settings(acc, object, pls))
        .transpose()?
        .unwrap_or_default();

    let subsets = object
        .spec
        .get("subsets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|subset| translate_subset(acc, object, subset))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MeshDestinationRule {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        host,
        traffic_policy,
        port_level_settings,
        subsets,
    })
}

/// Parse Istio `trafficPolicy.portLevelSettings` into a per-port
/// [`MeshTrafficPolicy`] map keyed by port number. Each entry is a regular
/// traffic-policy block scoped to one port; the cold-path apply pass layers
/// the resolved policy onto the matching upstream's `port_overrides`.
fn translate_port_level_settings(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<HashMap<u16, MeshTrafficPolicy>, K8sTranslateError> {
    let entries = value.as_array().ok_or_else(|| {
        invalid_resource(object, "trafficPolicy.portLevelSettings must be an array")
    })?;

    let mut out = HashMap::with_capacity(entries.len());
    let mut seen_ports = HashSet::with_capacity(entries.len());
    for entry in entries {
        let port_value = entry
            .get("port")
            .and_then(|p| p.get("number"))
            .ok_or_else(|| {
                invalid_resource(
                    object,
                    "trafficPolicy.portLevelSettings[].port.number is required",
                )
            })?;
        let port_u64 = port_value.as_u64().ok_or_else(|| {
            invalid_resource(
                object,
                "trafficPolicy.portLevelSettings[].port.number must be an integer",
            )
        })?;
        if port_u64 == 0 || port_u64 > u16::MAX as u64 {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.portLevelSettings[].port.number must be 1-65535 (got {port_u64})"
                ),
            ));
        }
        let port = port_u64 as u16;

        if !seen_ports.insert(port) {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.portLevelSettings has duplicate port {port}"),
            ));
        }
        let policy =
            translate_traffic_policy(acc, object, entry, TrafficPolicyScope::TopLevelOrPort)?;
        if traffic_policy_has_applied_fields(&policy) {
            out.insert(port, policy);
        }
    }
    Ok(out)
}

fn traffic_policy_has_applied_fields(policy: &MeshTrafficPolicy) -> bool {
    policy != &MeshTrafficPolicy::default()
}

/// Where a `trafficPolicy` block sits in a DestinationRule. This scopes the
/// deferred-warning emission for `connectionPool.http` fields that are applied
/// at top-level / `portLevelSettings` but NOT for subsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficPolicyScope {
    /// `spec.trafficPolicy` or a `spec.trafficPolicy.portLevelSettings[]` entry.
    /// `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests}`
    /// are projected here.
    TopLevelOrPort,
    /// `spec.subsets[].trafficPolicy`. The mesh apply path turns subsets into
    /// `SubsetTrafficPolicy` (LB / TLS / connect-timeout / passive-health only),
    /// so `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests}`
    /// NEVER reach the `port_overrides` / effective `Proxy` for a subset — they
    /// are deferred.
    Subset,
}

fn translate_traffic_policy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
    scope: TrafficPolicyScope,
) -> Result<MeshTrafficPolicy, K8sTranslateError> {
    let tcp = value.get("connectionPool").and_then(|cp| cp.get("tcp"));

    let connect_timeout_ms = tcp
        .and_then(|tcp| string_field(tcp, "connectTimeout"))
        .and_then(parse_istio_duration_ms);

    let max_connections = tcp
        .map(|tcp| translate_tcp_max_connections(object, tcp))
        .transpose()?
        .flatten();

    let tcp_keepalive = tcp
        .and_then(|tcp| tcp.get("tcpKeepalive"))
        .map(|ka| translate_tcp_keepalive(object, ka))
        .transpose()?
        .filter(|cfg| !cfg.is_empty());

    let connection_pool_http = value
        .get("connectionPool")
        .and_then(|cp| cp.get("http"))
        .map(|http| translate_connection_pool_http(acc, object, http, scope))
        .transpose()?
        .flatten();

    let outlier_detection = value
        .get("outlierDetection")
        .map(|od| translate_outlier_detection(object, od))
        .transpose()?;

    let load_balancer = value
        .get("loadBalancer")
        .and_then(|lb| {
            (lb.get("simple").is_some()
                || lb.get("consistentHash").is_some()
                || lb.get("localityLbSetting").is_none())
            .then(|| translate_load_balancer(acc, object, lb))
        })
        .transpose()?;

    // `localityLbSetting` lives under `trafficPolicy.loadBalancer.localityLbSetting`
    // in the Istio v1beta1 schema. Parse it independently of the algorithm so
    // operators that configure only `localityLbSetting` (no simple/consistentHash
    // change) still get weighted distribution and failover semantics.
    let locality_lb_setting = value
        .get("loadBalancer")
        .and_then(|lb| lb.get("localityLbSetting"))
        .map(|setting| translate_locality_lb_setting(object, setting))
        .transpose()?;

    let tls = value
        .get("tls")
        .map(|tls| translate_client_tls_settings(object, tls))
        .transpose()?;

    Ok(MeshTrafficPolicy {
        connect_timeout_ms,
        outlier_detection,
        load_balancer,
        tls,
        locality_lb_setting,
        max_connections,
        tcp_keepalive,
        connection_pool_http,
    })
}

/// Parse `connectionPool.tcp.maxConnections`. Istio's schema typing is
/// `int32`; values <= 0 are rejected with an error so operators see the
/// misconfiguration at translate time rather than silently dropping the cap.
/// Values > `u32::MAX` cannot occur because the upper bound is already the
/// Istio CRD's `int32` validation, but the explicit clamp keeps the parse
/// total even when callers feed us unvalidated JSON.
fn translate_tcp_max_connections(
    object: &K8sObject,
    tcp: &Value,
) -> Result<Option<u32>, K8sTranslateError> {
    let Some(value) = tcp.get("maxConnections") else {
        return Ok(None);
    };
    let raw = value.as_i64().ok_or_else(|| {
        invalid_resource(
            object,
            "trafficPolicy.connectionPool.tcp.maxConnections must be an integer",
        )
    })?;
    if raw <= 0 {
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.connectionPool.tcp.maxConnections must be positive, got {raw}"),
        ));
    }
    if raw > i64::from(u32::MAX) {
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.connectionPool.tcp.maxConnections ({raw}) exceeds u32::MAX"),
        ));
    }
    Ok(Some(raw as u32))
}

/// Translate Istio `connectionPool.tcp.tcpKeepalive` into Ferrum's typed
/// keepalive override. Each subfield is independently optional. `time` and
/// `interval` are `google.protobuf.Duration` strings; sub-second values are
/// rejected because the underlying `TCP_KEEPIDLE` / `TCP_KEEPINTVL` socket
/// options are specified in seconds on every supported platform. `probes` is
/// `uint32`; zero is rejected because the socket option requires at least one
/// probe before declaring the connection dead.
fn translate_tcp_keepalive(
    object: &K8sObject,
    keepalive: &Value,
) -> Result<crate::config::types::TcpKeepaliveCfg, K8sTranslateError> {
    let time_seconds = match string_field(keepalive, "time") {
        Some(raw) => Some(parse_keepalive_duration_seconds(object, "time", raw)?),
        None => None,
    };
    let interval_seconds = match string_field(keepalive, "interval") {
        Some(raw) => Some(parse_keepalive_duration_seconds(object, "interval", raw)?),
        None => None,
    };
    let probes = match keepalive.get("probes") {
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                invalid_resource(
                    object,
                    "trafficPolicy.connectionPool.tcp.tcpKeepalive.probes must be a non-negative integer",
                )
            })?;
            if raw == 0 {
                return Err(invalid_resource(
                    object,
                    "trafficPolicy.connectionPool.tcp.tcpKeepalive.probes must be positive",
                ));
            }
            if raw > u64::from(u32::MAX) {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.connectionPool.tcp.tcpKeepalive.probes ({raw}) exceeds u32::MAX"
                    ),
                ));
            }
            Some(raw as u32)
        }
        None => None,
    };
    Ok(crate::config::types::TcpKeepaliveCfg {
        time_seconds,
        interval_seconds,
        probes,
    })
}

/// Parse an Istio duration into whole seconds. Sub-second values (e.g.,
/// `"500ms"`) are rejected — TCP_KEEPIDLE / TCP_KEEPINTVL are specified in
/// seconds on every supported platform, and rounding silently would let an
/// operator's intent (idle probe at 1.5s) come up at 1s with no warning.
fn parse_keepalive_duration_seconds(
    object: &K8sObject,
    field: &str,
    raw: &str,
) -> Result<u32, K8sTranslateError> {
    let ms = parse_istio_duration_ms(raw).ok_or_else(|| {
        invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.tcp.tcpKeepalive.{field} '{raw}' is not a valid Istio duration"
            ),
        )
    })?;
    if ms == 0 {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.tcp.tcpKeepalive.{field} must be at least 1s, got '{raw}'"
            ),
        ));
    }
    if ms % 1000 != 0 {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.tcp.tcpKeepalive.{field} '{raw}' must be a whole number of seconds (sub-second precision is not supported by TCP keepalive socket options)"
            ),
        ));
    }
    let seconds = ms / 1000;
    if seconds > u64::from(u32::MAX) {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.tcp.tcpKeepalive.{field} '{raw}' exceeds u32::MAX seconds"
            ),
        ));
    }
    Ok(seconds as u32)
}

/// Translate Istio `connectionPool.http` into Ferrum's typed HTTP overlay.
///
/// Supported fields: `idleTimeout`, `http2MaxRequests`, `h2UpgradePolicy`,
/// `maxRetries`, and `http1MaxPendingRequests`. `maxRequestsPerConnection` is
/// parsed and validated for operator feedback, but is NOT projected because the
/// runtime does not have close-after-N-requests behavior for the shared backend
/// pools. At top-level / `portLevelSettings` scope every supported field is
/// projected. (`h2UpgradePolicy` / `maxRetries` / `http1MaxPendingRequests` are
/// still deferred-warned for a SUBSET `trafficPolicy` — see the `scope` note
/// below — because a subset's `SubsetTrafficPolicy` carries no
/// `connectionPool.http`.) Returning `Ok(None)` from this function signals
/// "block was present but no supported field was set" so the caller can skip
/// emitting an empty overlay on the slice.
///
/// `maxRetries` semantics differ honestly from Envoy: Envoy's
/// `connectionPool.http.maxRetries` is a cluster-wide outstanding-retry
/// concurrency budget; Ferrum's retry model is per-request, so the field is
/// projected as a per-request retry-count CAP (see `docs/mesh.md` and
/// `cap_proxy_retry_for_target`). It is still validated as a positive
/// integer here (zero/negative rejected) like the other uint32 knobs.
///
/// `http1MaxPendingRequests` is honestly reinterpreted as a max-concurrent-
/// in-flight-HTTP/1.1-requests cap, NOT Envoy's connection-pending-queue:
/// reqwest's `send()` resolves at response headers with no connection-acquire
/// hook, so true pending-queue depth is unmeasurable (see `docs/mesh.md`;
/// "upstream overflow" → 503). Scoped to the reqwest/H1 dispatch path; validated
/// as a positive integer here (zero rejected) like the other uint32 knobs.
///
/// `scope` distinguishes top-level/`portLevelSettings` (where `h2UpgradePolicy`
/// / `maxRetries` / `http1MaxPendingRequests` ARE applied) from a SUBSET
/// `trafficPolicy` (where the mesh apply path builds a `SubsetTrafficPolicy`
/// that carries no `connectionPool.http`, so those fields are genuinely NOT
/// applied). For a subset scope they are deferred-warned + surfaced in the
/// DestinationRule `status.ferrum.translation.deferred_fields` (codex round-1
/// Finding 4), matching reality; do NOT try to wire subset connectionPool.http
/// through `SubsetTrafficPolicy`. Validation (positive int / valid enum) still
/// runs in every scope so a malformed subset value still fails closed.
fn translate_connection_pool_http(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    http: &Value,
    scope: TrafficPolicyScope,
) -> Result<Option<crate::modes::mesh::config::MeshConnectionPoolHttp>, K8sTranslateError> {
    use crate::modes::mesh::config::MeshConnectionPoolHttp;

    // `maxRequestsPerConnection` is parsed and validated so malformed
    // DestinationRules still fail closed, but it is not carried on the mesh
    // overlay: the runtime has no close-after-N backend request behavior for
    // the shared reqwest/direct-H2/gRPC/H3/HBONE pools. Keep this warning and
    // `DEFERRED_CONNECTION_POOL_HTTP_FIELDS` in `istio_status.rs` in sync.
    if let Some(v) = http.get("maxRequestsPerConnection") {
        let _ = translate_http_uint32(object, "maxRequestsPerConnection", v, true)?;
        acc.warnings.push(format!(
            "DestinationRule {}/{}: connectionPool.http.maxRequestsPerConnection is parsed and validated but not applied (backend close-after-N-requests is unsupported); use http2MaxRequests for HTTP/2-family concurrency instead",
            object.metadata.namespace, object.metadata.name
        ));
    }
    let idle_timeout_ms = match string_field(http, "idleTimeout") {
        Some(raw) => Some(parse_http_idle_timeout_ms(object, raw)?),
        None => None,
    };
    let http2_max_requests = match http.get("http2MaxRequests") {
        Some(v) => Some(translate_http_uint32(object, "http2MaxRequests", v, false)?),
        None => None,
    };
    let h2_upgrade_policy = match http.get("h2UpgradePolicy") {
        Some(v) => translate_h2_upgrade_policy(object, v)?,
        None => None,
    };
    // Reject zero/negative `maxRetries` (mirrors `http2MaxRequests`). A
    // configured cap of 0 would be ambiguous against our per-request-cap
    // interpretation (it would zero out an existing retry policy, which is
    // not what an operator setting an Envoy outstanding-retry budget means);
    // fail closed at translate time rather than silently disabling retries.
    let max_retries = match http.get("maxRetries") {
        Some(v) => Some(translate_http_uint32(object, "maxRetries", v, false)?),
        None => None,
    };

    // `http1MaxPendingRequests` — the HTTP/1.1 connection-pending-queue cap.
    // Validated as a positive integer like the other uint32 knobs (zero
    // rejected: a `0` pending cap would shed every H1 request, which is not
    // what an operator setting a pending budget means). Applied at runtime as
    // a per-`(host, port)` pending gate on the reqwest/H1 dispatch path (503
    // "upstream overflow" when full); see `Proxy.pool_http1_max_pending_requests`
    // and `src/backend_pending_limit.rs`. No longer deferred at top-level/port.
    let http1_max_pending_requests = match http.get("http1MaxPendingRequests") {
        Some(v) => Some(translate_http_uint32(
            object,
            "http1MaxPendingRequests",
            v,
            false,
        )?),
        None => None,
    };

    // Subset-scoped `h2UpgradePolicy` / `maxRetries` / `http1MaxPendingRequests`:
    // applied at top-level / `portLevelSettings`, but a SUBSET's
    // `SubsetTrafficPolicy` carries no `connectionPool.http`, so inside a subset
    // they are genuinely NOT applied. Warn + surface as deferred (codex round-1
    // Finding 4) and DROP them from the (unused) subset overlay so no dead value
    // rides the slice. Keep this list in sync with
    // `SUBSET_DEFERRED_CONNECTION_POOL_HTTP_FIELDS` in
    // `src/k8s_controller/istio_status.rs`.
    let (h2_upgrade_policy, max_retries, http1_max_pending_requests) = match scope {
        TrafficPolicyScope::TopLevelOrPort => {
            (h2_upgrade_policy, max_retries, http1_max_pending_requests)
        }
        TrafficPolicyScope::Subset => {
            for field in ["h2UpgradePolicy", "maxRetries", "http1MaxPendingRequests"] {
                if http.get(field).is_some() {
                    acc.warnings.push(format!(
                        "DestinationRule {}/{}: subsets[].trafficPolicy.connectionPool.http.{field} is parsed and validated but not applied for subsets (subset traffic policy carries LB/TLS/connectTimeout/passive-health only); apply it at top-level or portLevelSettings instead",
                        object.metadata.namespace, object.metadata.name
                    ));
                }
            }
            // Not applied for subsets — do not carry the value on the overlay.
            (None, None, None)
        }
    };

    let overlay = MeshConnectionPoolHttp {
        max_requests_per_connection: None,
        idle_timeout_ms,
        http2_max_requests,
        h2_upgrade_policy,
        max_retries,
        http1_max_pending_requests,
    };
    if overlay == MeshConnectionPoolHttp::default() {
        Ok(None)
    } else {
        Ok(Some(overlay))
    }
}

/// Parse `connectionPool.http.h2UpgradePolicy`. Istio's enum is `DEFAULT`,
/// `DO_NOT_UPGRADE`, `UPGRADE`. `DEFAULT` maps to the explicit
/// `H2UpgradePolicy::Default` variant (NOT `None`): dispatch treats it like
/// absent (probe-driven), but carrying it lets an EXPLICIT port-level
/// `DEFAULT` clear an inherited top-level `UPGRADE`/`DO_NOT_UPGRADE` for that
/// port (see `apply_connection_pool_http_to_port_override`), which a collapse
/// to `None` (indistinguishable from absent) could not do. Unknown values
/// fail closed at translate time rather than silently defaulting — a typo
/// should surface, not be guessed.
fn translate_h2_upgrade_policy(
    object: &K8sObject,
    value: &Value,
) -> Result<Option<crate::config::types::H2UpgradePolicy>, K8sTranslateError> {
    use crate::config::types::H2UpgradePolicy;
    let raw = value.as_str().ok_or_else(|| {
        invalid_resource(
            object,
            "trafficPolicy.connectionPool.http.h2UpgradePolicy must be a string",
        )
    })?;
    match raw {
        "DEFAULT" => Ok(Some(H2UpgradePolicy::Default)),
        "UPGRADE" => Ok(Some(H2UpgradePolicy::Upgrade)),
        "DO_NOT_UPGRADE" => Ok(Some(H2UpgradePolicy::DoNotUpgrade)),
        other => Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.http.h2UpgradePolicy '{other}' is not a valid value (expected DEFAULT, UPGRADE, or DO_NOT_UPGRADE)"
            ),
        )),
    }
}

/// Parse a uint32 `connectionPool.http.*` knob. Negative and non-integer
/// values are always rejected. `allow_zero` controls the lower bound: most
/// knobs (`http2MaxRequests`, `maxRetries`) reject `0` as ambiguous, but
/// `maxRequestsPerConnection` accepts `0` as Istio's documented "unlimited"
/// sentinel. The field is still deferred, but accepting `0` keeps validation
/// compatible with Istio while status/warnings make the no-op visible.
fn translate_http_uint32(
    object: &K8sObject,
    field: &str,
    value: &Value,
    allow_zero: bool,
) -> Result<u32, K8sTranslateError> {
    let raw = value.as_i64().ok_or_else(|| {
        invalid_resource(
            object,
            format!("trafficPolicy.connectionPool.http.{field} must be an integer"),
        )
    })?;
    let lower_bound_violated = if allow_zero { raw < 0 } else { raw <= 0 };
    if lower_bound_violated {
        let requirement = if allow_zero {
            "must be non-negative"
        } else {
            "must be positive"
        };
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.connectionPool.http.{field} {requirement}, got {raw}"),
        ));
    }
    if raw > i64::from(u32::MAX) {
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.connectionPool.http.{field} ({raw}) exceeds u32::MAX"),
        ));
    }
    Ok(raw as u32)
}

/// Parse `connectionPool.http.idleTimeout` (`google.protobuf.Duration`
/// string) into milliseconds. Sub-second precision is rejected because the
/// downstream `Proxy.pool_idle_timeout_seconds` field is whole-second
/// granular and silently rounding `500ms` to `1s` would not match the
/// operator's intent. Zero is rejected for the same reason (the H1/H2 pool
/// treats `0s` as "no idle reuse" which is almost certainly a misconfig).
///
/// Upper bound mirrors `crate::config::types::MAX_POOL_IDLE_TIMEOUT` (1
/// hour). The per-target Cow-clone in `resolve_effective_proxy_for_target`
/// writes the resolved seconds value directly onto `Proxy` without re-running
/// `validate_fields()`, so an `idleTimeout` above the proxy-level cap would
/// silently bypass that validator. Rejecting here keeps the translate path
/// and the admin admit path consistent.
fn parse_http_idle_timeout_ms(object: &K8sObject, raw: &str) -> Result<u64, K8sTranslateError> {
    let ms = parse_istio_duration_ms(raw).ok_or_else(|| {
        invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.http.idleTimeout '{raw}' is not a valid Istio duration"
            ),
        )
    })?;
    if ms == 0 {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.http.idleTimeout must be at least 1s, got '{raw}'"
            ),
        ));
    }
    if ms % 1000 != 0 {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.http.idleTimeout '{raw}' must be a whole number of seconds (sub-second precision is not supported by the proxy idle-timeout field)"
            ),
        ));
    }
    let max_ms = crate::config::types::MAX_POOL_IDLE_TIMEOUT.saturating_mul(1_000);
    if ms > max_ms {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.connectionPool.http.idleTimeout '{raw}' exceeds the proxy idle-timeout cap of {}s",
                crate::config::types::MAX_POOL_IDLE_TIMEOUT
            ),
        ));
    }
    Ok(ms)
}

fn translate_locality_lb_setting(
    object: &K8sObject,
    value: &Value,
) -> Result<MeshLocalityLbSetting, K8sTranslateError> {
    let enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        // Istio's default for `enabled` is true when the block is present.
        .unwrap_or(true);

    let has_distribute = value.get("distribute").is_some();
    let has_failover = value.get("failover").is_some();
    let has_failover_priority = value.get("failoverPriority").is_some();
    let mode_count = has_distribute as u8 + has_failover as u8 + has_failover_priority as u8;
    if mode_count > 1 {
        return Err(invalid_resource(
            object,
            "trafficPolicy.loadBalancer.localityLbSetting must set only one of \
             distribute, failover, or failoverPriority",
        ));
    }
    if has_failover_priority {
        return Err(invalid_resource(
            object,
            "trafficPolicy.loadBalancer.localityLbSetting.failoverPriority is not supported",
        ));
    }

    let distribute = if let Some(entries) = value.get("distribute") {
        let arr = entries.as_array().ok_or_else(|| {
            invalid_resource(
                object,
                "trafficPolicy.loadBalancer.localityLbSetting.distribute must be an array",
            )
        })?;
        let mut out = Vec::with_capacity(arr.len());
        for (idx, entry) in arr.iter().enumerate() {
            let from = string_field(entry, "from")
                .ok_or_else(|| {
                    invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].from is required"
                        ),
                    )
                })?
                .to_string();
            if !is_valid_locality_pattern(&from) {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].from \
                         '{from}' is not a valid region[/zone[/subzone]] locality"
                    ),
                ));
            }
            let to_obj = entry.get("to").and_then(Value::as_object).ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].to is required"
                    ),
                )
            })?;
            let mut to = std::collections::BTreeMap::new();
            for (locality, weight) in to_obj {
                if !is_valid_locality_pattern(locality) {
                    return Err(invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].to \
                             key '{locality}' is not a valid region[/zone[/subzone]] locality"
                        ),
                    ));
                }
                let weight_u64 = weight.as_u64().ok_or_else(|| {
                    invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].to \
                             value for '{locality}' must be a non-negative integer"
                        ),
                    )
                })?;
                if weight_u64 > u64::from(u32::MAX) {
                    return Err(invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].to \
                             value for '{locality}' exceeds u32::MAX"
                        ),
                    ));
                }
                to.insert(locality.clone(), weight_u64 as u32);
            }
            if to.is_empty() {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.distribute[{idx}].to \
                         must not be empty"
                    ),
                ));
            }
            out.push(MeshLocalityDistribute { from, to });
        }
        out
    } else {
        Vec::new()
    };

    let failover = if let Some(entries) = value.get("failover") {
        let arr = entries.as_array().ok_or_else(|| {
            invalid_resource(
                object,
                "trafficPolicy.loadBalancer.localityLbSetting.failover must be an array",
            )
        })?;
        let mut out = Vec::with_capacity(arr.len());
        for (idx, entry) in arr.iter().enumerate() {
            let from = string_field(entry, "from")
                .ok_or_else(|| {
                    invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.failover[{idx}].from is required"
                        ),
                    )
                })?
                .to_string();
            if !is_valid_failover_region(&from) {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.failover[{idx}].from \
                         '{from}' is not a valid region name"
                    ),
                ));
            }
            let to = string_field(entry, "to")
                .ok_or_else(|| {
                    invalid_resource(
                        object,
                        format!(
                            "trafficPolicy.loadBalancer.localityLbSetting.failover[{idx}].to is required"
                        ),
                    )
                })?
                .to_string();
            if !is_valid_failover_region(&to) {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.failover[{idx}].to \
                         '{to}' is not a valid region name"
                    ),
                ));
            }
            if from == to {
                return Err(invalid_resource(
                    object,
                    format!(
                        "trafficPolicy.loadBalancer.localityLbSetting.failover[{idx}] cannot fail \
                         over a region to itself ('{from}')"
                    ),
                ));
            }
            out.push(MeshLocalityFailover { from, to });
        }
        out
    } else {
        Vec::new()
    };

    Ok(MeshLocalityLbSetting {
        enabled,
        distribute,
        failover,
    })
}

fn is_valid_locality_pattern(raw: &str) -> bool {
    if !has_valid_locality_segments(raw) {
        return false;
    }
    let Some(locality) = crate::config::types::LocalityPreference::parse(raw) else {
        return false;
    };
    if locality.region == "*" {
        return locality.zone.is_none() && locality.sub_zone.is_none();
    }
    if locality.zone.as_deref() == Some("*") {
        return locality.sub_zone.is_none();
    }
    true
}

fn has_valid_locality_segments(raw: &str) -> bool {
    let mut count = 0usize;
    for segment in raw.split('/') {
        count += 1;
        if count > 3 || segment.is_empty() || segment != segment.trim() {
            return false;
        }
    }
    count > 0
}

fn is_valid_failover_region(raw: &str) -> bool {
    let Some(locality) = crate::config::types::LocalityPreference::parse(raw) else {
        return false;
    };
    raw == raw.trim()
        && !raw.contains('/')
        && locality.region != "*"
        && locality.zone.is_none()
        && locality.sub_zone.is_none()
}

/// Translate Istio `DestinationRule.trafficPolicy.tls` (a.k.a.
/// `ClientTLSSettings`) into a `MeshTrafficPolicyTls`.
///
/// `mode` maps:
/// - `DISABLE` -> `MtlsMode::Disable`
/// - `SIMPLE` -> `MtlsMode::Simple`
/// - `MUTUAL` -> `MtlsMode::Mutual`
/// - `ISTIO_MUTUAL` -> `MtlsMode::IstioMutual`
///
/// Validation:
/// - `ISTIO_MUTUAL` rejects explicit `clientCertificate`/`privateKey`/
///   `caCertificates` — Istio reuses the workload's SPIFFE identity material.
/// - `MUTUAL` requires both `clientCertificate` AND `privateKey` (matches
///   Istio's `pilot-validation`).
fn translate_client_tls_settings(
    object: &K8sObject,
    value: &Value,
) -> Result<MeshTrafficPolicyTls, K8sTranslateError> {
    let mode_raw = string_field(value, "mode").unwrap_or("SIMPLE");
    let mode = match mode_raw {
        "DISABLE" => MtlsMode::Disable,
        "SIMPLE" => MtlsMode::Simple,
        "MUTUAL" => MtlsMode::Mutual,
        "ISTIO_MUTUAL" => MtlsMode::IstioMutual,
        other => {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.tls.mode '{other}' is unsupported (expected one of \
                     DISABLE, SIMPLE, MUTUAL, ISTIO_MUTUAL)"
                ),
            ));
        }
    };

    let sni = string_field(value, "sni").map(ToOwned::to_owned);
    let ca_certificates = string_field(value, "caCertificates").map(ToOwned::to_owned);
    let client_certificate = string_field(value, "clientCertificate").map(ToOwned::to_owned);
    let private_key = string_field(value, "privateKey").map(ToOwned::to_owned);
    let subject_alt_names = string_array(value, "subjectAltNames");
    if subject_alt_names.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.tls.subjectAltNames must not have more than {} entries (got {})",
                MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
                subject_alt_names.len()
            ),
        ));
    }
    for (idx, san) in subject_alt_names.iter().enumerate() {
        if san.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.tls.subjectAltNames[{idx}] must not exceed {} characters (got {})",
                    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
                    san.len()
                ),
            ));
        }
        if let Err(e) = validate_backend_tls_san_allow_list_entry(san) {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.tls.subjectAltNames[{idx}]: {e}"),
            ));
        }
    }
    if let Some(ref sni_value) = sni
        && let Err(e) = validate_backend_tls_sni(sni_value)
    {
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.tls.sni: {e}"),
        ));
    }
    let insecure_skip_verify = value
        .get("insecureSkipVerify")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match mode {
        MtlsMode::IstioMutual => {
            if client_certificate.is_some() || private_key.is_some() || ca_certificates.is_some() {
                return Err(invalid_resource(
                    object,
                    "trafficPolicy.tls.mode=ISTIO_MUTUAL must not set \
                     clientCertificate/privateKey/caCertificates — Istio reuses the \
                     workload's SPIFFE identity material",
                ));
            }
        }
        MtlsMode::Mutual => {
            if client_certificate.is_none() || private_key.is_none() {
                return Err(invalid_resource(
                    object,
                    "trafficPolicy.tls.mode=MUTUAL requires both clientCertificate and \
                     privateKey",
                ));
            }
        }
        MtlsMode::Disable | MtlsMode::Simple => {}
        // PeerAuthentication-side modes can't be set via DR.tls.mode in Istio;
        // translation above only emits the four client-side modes.
        MtlsMode::Strict | MtlsMode::Permissive => {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.tls.mode '{mode_raw}' is not a client-side TLS mode"),
            ));
        }
    }

    Ok(MeshTrafficPolicyTls {
        mode,
        sni,
        ca_certificates,
        client_certificate,
        private_key,
        subject_alt_names,
        insecure_skip_verify,
    })
}

fn translate_outlier_detection(
    object: &K8sObject,
    value: &Value,
) -> Result<MeshOutlierDetection, K8sTranslateError> {
    let consecutive_errors = value
        .get("consecutive5xxErrors")
        .or_else(|| value.get("consecutiveErrors"))
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());

    let interval_seconds = string_field(value, "interval")
        .and_then(parse_istio_duration_secs)
        .filter(|seconds| *seconds > 0);

    let base_ejection_seconds =
        string_field(value, "baseEjectionTime").and_then(parse_istio_duration_secs);

    let max_ejection_percent = value
        .get("maxEjectionPercent")
        .and_then(Value::as_u64)
        .map(|v| {
            if v <= 100 {
                Ok(v as u8)
            } else {
                Err(invalid_resource(
                    object,
                    format!("outlierDetection.maxEjectionPercent must be 0-100 (got {v})"),
                ))
            }
        })
        .transpose()?;

    Ok(MeshOutlierDetection {
        consecutive_errors,
        interval_seconds,
        base_ejection_seconds,
        max_ejection_percent,
    })
}

fn translate_load_balancer(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<MeshLoadBalancer, K8sTranslateError> {
    if let Some(simple) = string_field(value, "simple") {
        let algorithm = match simple {
            "ROUND_ROBIN" => MeshSimpleLb::RoundRobin,
            "LEAST_REQUEST" | "LEAST_CONN" => MeshSimpleLb::LeastRequest,
            "RANDOM" => MeshSimpleLb::Random,
            "PASSTHROUGH" => {
                acc.warnings.push(format!(
                    "DestinationRule {}/{} loadBalancer.simple=PASSTHROUGH dials the captured original destination when it matches a configured upstream target; requests with no captured original destination (e.g. non-mesh / non-captured paths) or one that matches no target fall back to round-robin",
                    object.metadata.namespace, object.metadata.name
                ));
                MeshSimpleLb::Passthrough
            }
            other => {
                return Err(invalid_resource(
                    object,
                    format!("loadBalancer.simple '{other}' is unsupported"),
                ));
            }
        };
        return Ok(MeshLoadBalancer::Simple(algorithm));
    }

    if let Some(ch) = value.get("consistentHash") {
        let http_header_name = string_field(ch, "httpHeaderName").map(ToOwned::to_owned);
        let http_cookie_name = ch
            .get("httpCookie")
            .and_then(|cookie| string_field(cookie, "name"))
            .map(ToOwned::to_owned);
        let use_source_ip = ch
            .get("useSourceIp")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let set_count = u8::from(http_header_name.is_some())
            + u8::from(http_cookie_name.is_some())
            + u8::from(use_source_ip);
        if set_count > 1 {
            return Err(invalid_resource(
                object,
                "loadBalancer.consistentHash must set exactly one of httpHeaderName, httpCookie, or useSourceIp",
            ));
        }
        if set_count == 0 {
            return Err(invalid_resource(
                object,
                "loadBalancer.consistentHash requires one of httpHeaderName, httpCookie, or useSourceIp",
            ));
        }
        return Ok(MeshLoadBalancer::ConsistentHash(MeshConsistentHash {
            http_header_name,
            http_cookie_name,
            use_source_ip,
        }));
    }

    // Default to RoundRobin when loadBalancer is present but empty
    Ok(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin))
}

fn translate_subset(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<MeshSubset, K8sTranslateError> {
    let name = string_field(value, "name")
        .ok_or_else(|| invalid_resource(object, "DestinationRule subset requires a name"))?
        .to_string();
    let labels = string_map(value.get("labels").unwrap_or(&Value::Null));
    let traffic_policy = value
        .get("trafficPolicy")
        .map(|tp| translate_traffic_policy(acc, object, tp, TrafficPolicyScope::Subset))
        .transpose()?
        .filter(traffic_policy_has_applied_fields);

    // A subset's `connectionPool.tcp.connectTimeout`, `tls`, and the full
    // `outlierDetection` (both the *thresholds* and the `maxEjectionPercent`
    // *cap*) are now applied per-subset by the cold-path apply in
    // `src/modes/mesh/mod.rs`: the thresholds via the subset passive-health
    // overlay consulted by `passive_health_for_target`, and the cap via
    // `LoadBalancerCache::max_ejection_percent_resolved_from` with the SAME
    // per-port > per-subset > upstream precedence. So no per-subset
    // outlier-detection field is deferred here anymore.

    Ok(MeshSubset {
        name,
        labels,
        traffic_policy,
    })
}

/// Translate an Istio PeerAuthentication `mtls.mode` string into [`MtlsMode`].
///
/// Istio defines exactly four values: `UNSET`, `DISABLE`, `PERMISSIVE`, and
/// `STRICT`. `UNSET` means "inherit from the next-higher tier"; Ferrum models
/// that inheritance through `resolve_effective_mtls_mode` precedence, so an
/// explicit `UNSET` contributes the same default posture as `PERMISSIVE` here
/// (unchanged from prior behaviour).
///
/// A genuinely unknown value (e.g. a typo like `STICT`) is **rejected** rather
/// than silently treated as `PERMISSIVE`. Otherwise a malformed
/// PeerAuthentication would quietly downgrade a workload's inbound mTLS from the
/// intended `STRICT` to `PERMISSIVE`; the error instead surfaces to the operator
/// as `FerrumAccepted=False`.
fn mtls_mode(value: &str) -> Result<MtlsMode, String> {
    match value {
        "STRICT" => Ok(MtlsMode::Strict),
        "PERMISSIVE" | "UNSET" => Ok(MtlsMode::Permissive),
        "DISABLE" => Ok(MtlsMode::Disable),
        other => Err(format!(
            "unsupported value '{other}' (expected one of UNSET, DISABLE, PERMISSIVE, STRICT)"
        )),
    }
}

fn service_entry(object: &K8sObject) -> Result<ServiceEntry, K8sTranslateError> {
    let hosts = string_array(&object.spec, "hosts");
    if hosts.is_empty() {
        return Err(invalid_resource(object, "ServiceEntry requires spec.hosts"));
    }

    let mut endpoints = Vec::new();
    for endpoint in object
        .spec
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(address) = string_field(endpoint, "address") else {
            continue;
        };
        let mut ports = HashMap::new();
        for (name, port) in endpoint
            .get("ports")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|ports| ports.iter())
        {
            if let Some(raw_port) = port.as_u64() {
                ports.insert(
                    name.clone(),
                    port_from_u64(object, raw_port, "endpoints[].ports")?,
                );
            }
        }
        endpoints.push(MeshEndpoint {
            address: address.to_string(),
            ports,
            labels: endpoint.get("labels").map(string_map).unwrap_or_default(),
            network: string_field(endpoint, "network").map(ToOwned::to_owned),
        });
    }

    Ok(ServiceEntry {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        hosts,
        endpoints,
        resolution: match string_field(&object.spec, "resolution").unwrap_or("NONE") {
            "DNS" => Resolution::Dns,
            "STATIC" => Resolution::Static,
            _ => Resolution::None,
        },
        location: match string_field(&object.spec, "location").unwrap_or("MESH_EXTERNAL") {
            "MESH_INTERNAL" => ServiceEntryLocation::MeshInternal,
            _ => ServiceEntryLocation::MeshExternal,
        },
        ports: service_ports(object)?,
        export_to: string_array(&object.spec, "exportTo"),
        workload_selector: object
            .spec
            .get("workloadSelector")
            .and_then(|selector| selector.get("labels"))
            .map(string_map)
            .map(|labels| WorkloadSelector {
                namespace: Some(object.metadata.namespace.clone()),
                labels,
            }),
    })
}

fn workload_entry(acc: &K8sAccumulator, object: &K8sObject) -> Result<Workload, K8sTranslateError> {
    // Treat empty-string `serviceAccount` as missing (Istio semantics: missing
    // or empty → fall back to `"default"` for SVID issuance). Without this
    // collapse, an empty string would propagate into the SPIFFE path
    // `ns/{ns}/sa/`, which the SPIFFE parser rejects as a trailing-slash error
    // and surfaces a confusing translation failure to operators.
    let service_account_raw =
        string_field(&object.spec, "serviceAccount").filter(|s| !s.is_empty());
    let path = format!(
        "ns/{}/sa/{}",
        object.metadata.namespace,
        service_account_raw.unwrap_or("default")
    );
    let spiffe_id = SpiffeId::from_parts(&acc.options.trust_domain, &path)
        .map_err(|e| invalid_resource(object, format!("invalid workload SPIFFE ID: {e}")))?;

    let weight = object
        .spec
        .get("weight")
        .map(|w| {
            let raw = w.as_u64().ok_or_else(|| {
                invalid_resource(
                    object,
                    "WorkloadEntry.weight must be a non-negative integer",
                )
            })?;
            if raw > u64::from(MAX_TARGET_WEIGHT) {
                return Err(invalid_resource(
                    object,
                    format!("WorkloadEntry.weight must be 0..={MAX_TARGET_WEIGHT} (got {raw})"),
                ));
            }
            Ok(raw as u32)
        })
        .transpose()?;

    // Empty-string `locality` is operator intent for "unset"; collapse to
    // None so downstream consumers don't need to special-case empty strings.
    let locality = string_field(&object.spec, "locality")
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let service_raw = object
        .spec
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or(&object.metadata.name);
    let service_key = workload_entry_service_key_from_host(
        service_raw,
        &object.metadata.namespace,
        &acc.options.cluster_domain,
    );
    match service_key.as_ref() {
        Some(key) if key.namespace != object.metadata.namespace => {
            return Err(invalid_resource(
                object,
                format!(
                    "WorkloadEntry.service '{service_raw}' references Service namespace '{}' but WorkloadEntry namespace is '{}'; cross-namespace WorkloadEntry service hosts are not supported",
                    key.namespace, object.metadata.namespace
                ),
            ));
        }
        _ => {}
    }
    let service_name = service_key
        .map(|key| key.name)
        .unwrap_or_else(|| service_raw.to_string());

    Ok(Workload {
        spiffe_id: spiffe_id.clone(),
        selector: WorkloadSelector {
            labels: object
                .spec
                .get("labels")
                .map(string_map)
                .unwrap_or_default(),
            namespace: Some(object.metadata.namespace.clone()),
        },
        service_name,
        addresses: string_field(&object.spec, "address")
            .map(|address| vec![address.to_string()])
            .unwrap_or_default(),
        ports: workload_ports(object)?,
        trust_domain: acc.options.trust_domain.clone(),
        namespace: object.metadata.namespace.clone(),
        network: string_field(&object.spec, "network").map(ToOwned::to_owned),
        cluster: string_field(&object.spec, "cluster").map(ToOwned::to_owned),
        weight,
        locality,
        service_account: service_account_raw.map(ToOwned::to_owned),
        // WorkloadEntry is a VM/static workload with no Kubernetes pod UID;
        // node-waypoint scope falls back to SPIFFE keying for these.
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    })
}

type VsRouteResult = (
    Vec<crate::config::types::Proxy>,
    Vec<crate::config::types::Upstream>,
    Vec<PluginConfig>,
);

struct PendingRouteDispatch {
    proxy: Proxy,
    route_plugins: Vec<PluginConfig>,
    rules: Vec<Value>,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
}

fn stash_pending_route_dispatch(
    pending: &mut Vec<(Option<String>, PendingRouteDispatch)>,
    listen_path: Option<String>,
    proxy: Proxy,
    route_plugins: Vec<PluginConfig>,
    rules: Vec<Value>,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
) {
    if let Some((_, bucket)) = pending.iter_mut().find(|(key, _)| *key == listen_path) {
        bucket.proxy = proxy;
        bucket.route_plugins = route_plugins;
        bucket.rules.extend(rules);
        bucket.is_uri_less_catch_all = is_uri_less_catch_all;
        bucket.force_terminate |= force_terminate;
    } else {
        pending.push((
            listen_path,
            PendingRouteDispatch {
                proxy,
                route_plugins,
                rules,
                is_uri_less_catch_all,
                force_terminate,
            },
        ));
    }
}

fn take_collapsible_pending_route_dispatches(
    pending: &mut Vec<(Option<String>, PendingRouteDispatch)>,
    target_listen_path: &Option<String>,
) -> Vec<(Option<String>, PendingRouteDispatch)> {
    let mut matches = Vec::new();
    let mut index = 0;
    while index < pending.len() {
        if can_collapse_listen_path_into(&pending[index].0, target_listen_path) {
            matches.push(pending.remove(index));
        } else {
            index += 1;
        }
    }
    matches
}

fn add_uri_guard_to_collapsed_rules(
    rules: &mut [Value],
    source_listen_path: &Option<String>,
    target_listen_path: &Option<String>,
) {
    if source_listen_path == target_listen_path {
        return;
    }
    let Some(uri_match) = uri_match_for_literal_listen_path(source_listen_path) else {
        return;
    };
    for rule in rules {
        let Some(match_obj) = rule.get_mut("match").and_then(Value::as_object_mut) else {
            continue;
        };
        match_obj.entry("uri").or_insert_with(|| uri_match.clone());
    }
}

fn uri_match_for_literal_listen_path(listen_path: &Option<String>) -> Option<Value> {
    let listen_path = listen_path.as_deref()?;
    if let Some(path) = listen_path.strip_prefix('=') {
        return Some(serde_json::json!({ "exact": path }));
    }
    if listen_path.starts_with('~') {
        return None;
    }
    Some(serde_json::json!({ "prefix": listen_path }))
}

fn route_has_uncollapsible_local_policy(route_plugins: &[PluginConfig]) -> bool {
    !route_plugins.is_empty()
}

#[allow(clippy::too_many_arguments)]
fn materialize_route_candidate(
    proxies: &mut Vec<Proxy>,
    plugins: &mut Vec<PluginConfig>,
    deferred_uri_less_proxies: &mut Vec<Proxy>,
    deferred_uri_less_plugins: &mut Vec<PluginConfig>,
    namespace: &str,
    mut proxy: Proxy,
    mut route_plugins: Vec<PluginConfig>,
    dispatch_rules: Vec<Value>,
    reject_unmatched: bool,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
) {
    let terminate_unconditionally = force_terminate && dispatch_rules.is_empty();
    if terminate_unconditionally {
        route_plugins.push(request_termination_plugin_for_proxy(
            &proxy.id,
            namespace,
            "unsupported Istio VirtualService match predicate",
        ));
    }

    // Auto-emit request_/response_transformer instances when any dispatch
    // rule carries route-level header transforms and this route does not
    // already carry an operator-configured request_transformer /
    // response_transformer. The mesh_route_dispatch plugin publishes the
    // per-rule transforms onto `RequestContext` at match time; without a
    // consumer plugin on the proxy, those overrides would never apply.
    //
    // Operator-configured proxy-scoped plugins win because we only emit
    // when none exists in `route_plugins`. Operators who configure a global
    // request_transformer on the gateway should be aware that a VS-driven
    // proxy will use the auto-emitted instance (proxy-scope replaces same-
    // named global) — keep route-level transforms out of the VS when that
    // is undesired.
    let dispatch_rules_have_request_transform =
        dispatch_rules_carry_transform(&dispatch_rules, "request_transform");
    let dispatch_rules_have_response_transform =
        dispatch_rules_carry_transform(&dispatch_rules, "response_transform");
    if dispatch_rules_have_request_transform
        && !route_plugins
            .iter()
            .any(|p| p.plugin_name == "request_transformer")
    {
        route_plugins.push(route_request_transformer_plugin_for_proxy(
            &proxy.id, namespace,
        ));
    }
    if dispatch_rules_have_response_transform
        && !route_plugins
            .iter()
            .any(|p| p.plugin_name == "response_transformer")
    {
        route_plugins.push(route_response_transformer_plugin_for_proxy(
            &proxy.id, namespace,
        ));
    }

    let reject_unmatched = reject_unmatched || force_terminate;
    if let Some(plugin) = mesh_route_dispatch_plugin_from_rules(
        &proxy.id,
        namespace,
        dispatch_rules,
        reject_unmatched,
    ) {
        route_plugins.push(plugin);
    }

    attach_route_plugins_to_proxy(&mut proxy, &route_plugins);
    if is_uri_less_catch_all {
        deferred_uri_less_plugins.extend(route_plugins);
        deferred_uri_less_proxies.push(proxy);
    } else {
        plugins.extend(route_plugins);
        proxies.push(proxy);
    }
}

/// Returns `true` if any rule in `dispatch_rules` carries a non-empty array
/// under `field` (`"request_transform"` or `"response_transform"`). Used to
/// decide whether the translator must auto-emit a transformer plugin
/// instance on the proxy.
fn dispatch_rules_carry_transform(dispatch_rules: &[Value], field: &str) -> bool {
    dispatch_rules.iter().any(|rule| {
        rule.get(field)
            .and_then(Value::as_array)
            .is_some_and(|arr| !arr.is_empty())
    })
}

/// Reject the L4 (`tcp[]`/`tls[]`) match predicates Ferrum's stream layer cannot
/// express. A stream proxy routes by `listen_port` (plus SNI for passthrough
/// TLS) and has no source-identity or CIDR matching, so silently dropping these
/// would mis-route — fail closed instead. `sniHosts`/`port` are consumed by the
/// caller.
fn reject_unsupported_l4_match(
    object: &K8sObject,
    m: &Value,
    kind: &str,
) -> Result<(), K8sTranslateError> {
    for field in [
        "sourceLabels",
        "sourceSubnets",
        "destinationSubnets",
        "gateways",
        "sourceNamespace",
    ] {
        if m.get(field).is_some() {
            return Err(invalid_resource(
                object,
                format!(
                    "VirtualService {kind}[] match.{field} is not supported (Ferrum stream routing keys on port{} only); remove it or model the route as an explicit stream Proxy",
                    if kind == "tls" { " and SNI" } else { "" }
                ),
            ));
        }
    }
    Ok(())
}

/// Resolve the single backend `(host, port)` of an L4 route block. Weighted
/// multi-destination L4 splitting is rejected fail-closed: a Ferrum stream proxy
/// forwards to one backend, so splitting would need an upstream-backed stream
/// proxy (a separate feature) rather than being silently collapsed to one leg.
fn l4_route_destination(
    object: &K8sObject,
    block: &Value,
    kind: &str,
    acc: &K8sAccumulator,
) -> Result<(String, u16), K8sTranslateError> {
    let routes = block
        .get("route")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_resource(
                object,
                format!("VirtualService {kind}[] block requires a route destination"),
            )
        })?;
    if routes.len() > 1 {
        return Err(invalid_resource(
            object,
            format!(
                "VirtualService {kind}[] weighted multi-destination splitting is not supported; use a single destination"
            ),
        ));
    }
    let dest = routes
        .first()
        .and_then(|r| r.get("destination"))
        .ok_or_else(|| {
            invalid_resource(
                object,
                format!("VirtualService {kind}[] route requires a destination"),
            )
        })?;
    let host = string_field(dest, "host").ok_or_else(|| {
        invalid_resource(
            object,
            format!("VirtualService {kind}[] route.destination.host is required"),
        )
    })?;
    let port = resolve_destination_port(object, dest, host, acc)?.ok_or_else(|| {
        invalid_resource(
            object,
            format!(
                "VirtualService {kind}[] route.destination.port is required for stream routing"
            ),
        )
    })?;
    Ok((host.to_string(), port))
}

fn virtual_service_l4_proxy_id(
    route_kind: &str,
    namespace: &str,
    vs_name: &str,
    block_index: usize,
    match_index: usize,
) -> String {
    // Keep the reconciler-managed `istio-vs-` prefix while reserving an
    // underscore-delimited L4 namespace. Kubernetes object names cannot contain
    // underscores, and the generated numeric suffix does not either, so HTTP
    // VirtualService IDs built as `istio-vs-<namespace>-<name>-<suffix>` cannot
    // collide with L4 IDs for hyphenated names such as `foo-tls`.
    format!("istio-vs-l4_{route_kind}__{namespace}__{vs_name}__{block_index}-{match_index}")
        .replace(['/', '.'], "-")
}

/// Translate VirtualService L4 routes into Ferrum stream proxies, reusing the
/// same stream + SNI machinery as gateway / east-west passthrough:
///   - `spec.tls[]` → a **passthrough** TCP proxy keyed by SNI (`hosts =
///     match.sniHosts`), forwarding the encrypted bytes to the destination (no
///     TLS termination).
///   - `spec.tcp[]` → a plain TCP proxy keyed by `listen_port`.
///
/// `match.port` selects the listen port (falling back to the destination port
/// when omitted). Unsupported match predicates (source-identity / CIDR /
/// gateways) and weighted splitting fail closed via the helpers above.
fn virtual_service_l4_proxies(
    object: &K8sObject,
    acc: &K8sAccumulator,
) -> Result<Vec<Proxy>, K8sTranslateError> {
    let namespace = &object.metadata.namespace;
    let vs_name = &object.metadata.name;
    let mut proxies = Vec::new();

    if let Some(blocks) = object.spec.get("tls").and_then(Value::as_array) {
        for (bi, block) in blocks.iter().enumerate() {
            let (backend_host, backend_port) = l4_route_destination(object, block, "tls", acc)?;
            let matches = block
                .get("match")
                .and_then(Value::as_array)
                .filter(|matches| !matches.is_empty())
                .ok_or_else(|| {
                    invalid_resource(
                        object,
                        "VirtualService tls[] route requires a non-empty match with sniHosts",
                    )
                })?;
            for (mi, m) in matches.iter().enumerate() {
                reject_unsupported_l4_match(object, m, "tls")?;
                let sni_hosts = string_array(m, "sniHosts");
                if sni_hosts.is_empty() {
                    return Err(invalid_resource(
                        object,
                        "VirtualService tls[] match requires sniHosts for SNI routing",
                    ));
                }
                let listen_port = optional_port_field(object, m.get("port"), "tls[].match.port")?
                    .unwrap_or(backend_port);
                let mut proxy = super::proxy_for_route(super::RouteProxySpec {
                    id: virtual_service_l4_proxy_id("tls", namespace, vs_name, bi, mi),
                    namespace: namespace.clone(),
                    hosts: sni_hosts,
                    listen_path: None,
                    strip_listen_path: false,
                    preserve_host_header: false,
                    backend_host: backend_host.clone(),
                    backend_port,
                    upstream_id: None,
                    backend_scheme: crate::config::types::BackendScheme::Tcp,
                    listen_port: Some(listen_port),
                    retry: None,
                    backend_read_timeout_ms: None,
                });
                proxy.passthrough = true;
                proxies.push(proxy);
            }
        }
    }

    if let Some(blocks) = object.spec.get("tcp").and_then(Value::as_array) {
        for (bi, block) in blocks.iter().enumerate() {
            let (backend_host, backend_port) = l4_route_destination(object, block, "tcp", acc)?;
            let listen_ports: Vec<u16> = match block.get("match").and_then(Value::as_array) {
                Some(ms) if !ms.is_empty() => {
                    let mut ports = Vec::with_capacity(ms.len());
                    for m in ms {
                        reject_unsupported_l4_match(object, m, "tcp")?;
                        if m.get("sniHosts").is_some() {
                            return Err(invalid_resource(
                                object,
                                "VirtualService tcp[] match must not set sniHosts; use tls[] for SNI routing",
                            ));
                        }
                        ports.push(
                            optional_port_field(object, m.get("port"), "tcp[].match.port")?
                                .unwrap_or(backend_port),
                        );
                    }
                    ports
                }
                _ => vec![backend_port],
            };
            for (mi, port) in listen_ports.into_iter().enumerate() {
                let proxy = super::proxy_for_route(super::RouteProxySpec {
                    id: virtual_service_l4_proxy_id("tcp", namespace, vs_name, bi, mi),
                    namespace: namespace.clone(),
                    hosts: Vec::new(),
                    listen_path: None,
                    strip_listen_path: false,
                    preserve_host_header: false,
                    backend_host: backend_host.clone(),
                    backend_port,
                    upstream_id: None,
                    backend_scheme: crate::config::types::BackendScheme::Tcp,
                    listen_port: Some(port),
                    retry: None,
                    backend_read_timeout_ms: None,
                });
                proxies.push(proxy);
            }
        }
    }

    Ok(proxies)
}

fn virtual_service_routes(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<VsRouteResult, K8sTranslateError> {
    // L4 routing: `spec.tls[]` (SNI passthrough) and `spec.tcp[]` (port) are
    // materialized into Ferrum stream proxies below, reusing the gateway /
    // east-west stream + SNI machinery. Match predicates Ferrum's stream layer
    // cannot express (source-identity / CIDR / gateways) and weighted splitting
    // fail closed inside `virtual_service_l4_proxies`.
    let hosts = string_array(&object.spec, "hosts");
    let mut proxies = virtual_service_l4_proxies(object, acc)?;
    let mut upstreams = Vec::new();
    let mut plugins = Vec::new();
    let mut deferred_uri_less_proxies = Vec::new();
    let mut deferred_uri_less_plugins = Vec::new();
    let mut pending_uri_less_route: Option<PendingRouteDispatch> = None;
    let mut pending_scoped_routes: Vec<(Option<String>, PendingRouteDispatch)> = Vec::new();
    let http_routes: Vec<&Value> = object
        .spec
        .get("http")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();

    // Issue #1973: ALSO carry a translatable `http[].corsPolicy` on the mesh
    // block (per VS host) so mesh sidecar DPs can synthesize the `cors` plugin
    // onto their materialized outbound routes — the gateway-proxy-scoped
    // plugin emitted below never rides the mesh slice. Rules (codex round 1):
    // - SIDECAR-BOUND ONLY, resolved PER `http[]` ENTRY: `spec.gateways`
    //   naming only ingress gateways (no reserved `mesh` entry) means the VS
    //   as a whole does not apply to sidecars (an omitted `gateways` defaults
    //   to mesh) — but Istio's `HTTPMatchRequest.gateways` OVERRIDES the
    //   top-level list per match, so an entry whose match names `mesh` still
    //   applies to sidecars (and, conversely, a mesh-bound VS's
    //   ingress-scoped matches do not). The VS-level default is therefore
    //   threaded into the per-entry predicate rather than short-circuiting
    //   the whole VS.
    // - Host-level application: the FIRST SIDECAR-APPLICABLE `http[]` entry
    //   decides everything (Istio evaluates `http[]` in order, first match
    //   wins). If it is host-wide-representable (no match, or a catch-all
    //   `/` prefix — see `http_entry_cors_applies_host_wide`) its
    //   translatable corsPolicy is carried; if it carries no corsPolicy, its
    //   policy is untranslatable, or it is PREDICATE-SCOPED (narrower uri,
    //   headers, …), NOTHING is carried — a scoped entry wins part of the
    //   host's traffic with its own (possibly absent) CORS, so promoting a
    //   LATER host-wide policy would enforce CORS (preflight answering,
    //   disallowed-Origin rejects) on traffic whose winning route has none.
    //   Entries invisible to sidecars (non-mesh match gateways under a
    //   mesh-bound VS, or no mesh override under an ingress-only VS)
    //   neither donate nor suppress.
    // - `spec.exportTo` visibility is carried for slice narrowing; an omitted
    //   exportTo becomes an explicit `["*"]` so Istio's public default is
    //   preserved (the mesh model's EMPTY export_to is namespace-local by
    //   Ferrum convention, matching ServiceEntry).
    // The extraction reuses the SAME `cors_policy_translatable` +
    // `cors_allowed_origins` gates as `route_cors_plugin`, so slice-carried
    // and gateway-projected CORS can never disagree on representability.
    let vs_gateways = string_array(&object.spec, "gateways");
    let vs_applies_to_sidecars =
        vs_gateways.is_empty() || vs_gateways.iter().any(|gateway| gateway == "mesh");
    if let Some(mesh_cors) = http_routes
        .iter()
        .find(|http| http_entry_applies_to_sidecars(http, vs_applies_to_sidecars))
        .filter(|http| http_entry_cors_applies_host_wide(http, vs_applies_to_sidecars))
        .and_then(|http| http.get("corsPolicy"))
        .and_then(mesh_cors_policy_from_value)
    {
        let export_to = {
            let declared = string_array(&object.spec, "exportTo");
            if declared.is_empty() {
                vec!["*".to_string()]
            } else {
                declared
            }
        };
        for host in &hosts {
            acc.mesh
                .virtual_service_cors_policies
                .push(MeshVirtualServiceCorsPolicy {
                    name: object.metadata.name.clone(),
                    namespace: object.metadata.namespace.clone(),
                    host: host.clone(),
                    export_to: export_to.clone(),
                    cors: mesh_cors.clone(),
                });
        }
    }

    for (index, http) in http_routes.iter().copied().enumerate() {
        let route_candidates = route_candidate_paths(http);
        if route_candidates.is_empty() {
            continue;
        }

        // Per-http[] traffic-management actions projected onto every emitted
        // dispatch rule (or, for mirror, attached as a proxy-scoped plugin).
        // Extracted before the backend check because a `redirect` route is
        // valid with NO backend — Istio forbids `route` + `redirect` together.
        let route_rewrite_value = route_rewrite_value(http);
        let route_redirect_value = route_redirect_value(object, http)?;

        let backends = route_backends(object, http, acc, index)?;
        if backends.is_empty() {
            // A redirect answers the request itself, so a backend-less redirect
            // route is materialized as a proxy whose dispatch rule short-
            // circuits. Any other backend-less route (including a stray mirror
            // with no primary `route`) is skipped as before — there is nothing
            // to forward to.
            if route_redirect_value.is_none() {
                continue;
            }
        };

        let (backend_host, backend_port, upstream_id, requires_node_waypoint_authz) =
            if backends.is_empty() {
                // Redirect-only route: no backend. The dispatch rule omits the
                // destination and the redirect fires before backend dispatch.
                (String::new(), 0, None, false)
            } else if backends.len() == 1 {
                let Some(backend) = backends.into_iter().next() else {
                    continue;
                };
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(std::slice::from_ref(&backend));
                (
                    backend.host,
                    backend.port,
                    None,
                    requires_node_waypoint_authz,
                )
            } else {
                let requires_node_waypoint_authz =
                    route_backends_require_node_waypoint_authz(&backends);
                let upstream_id = resource_id(
                    "istio-vs-upstream",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &index.to_string(),
                );
                upstreams.push(upstream_for_route(
                    upstream_id.clone(),
                    object.metadata.namespace.clone(),
                    backends,
                ));
                (
                    String::new(),
                    0,
                    Some(upstream_id),
                    requires_node_waypoint_authz,
                )
            };

        let retry = route_retry_config(http);
        let timeout_ms = route_timeout_ms(http);

        let match_count = route_candidates.len();
        for (match_index, (listen_path, force_terminate_current)) in
            route_candidates.into_iter().enumerate()
        {
            let is_uri_less_catch_all = listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH);
            let mut route_plugins = Vec::new();
            let suffix = if match_count == 1 {
                index.to_string()
            } else {
                format!("{index}-{match_index}")
            };
            let proxy_id = resource_id(
                "istio-vs",
                &object.metadata.namespace,
                &object.metadata.name,
                &suffix,
            );

            // Istio `http[].mirror`: attach a proxy-scoped `request_mirror`
            // plugin. Mirror is a per-route action; making it a route-local
            // plugin means a route that must be collapsed with siblings fails
            // closed (via `route_has_uncollapsible_local_policy`) rather than
            // silently mirroring the siblings' traffic too. This reuses the
            // battle-tested `request_mirror` plugin instead of duplicating its
            // fire-and-forget task plumbing on the dispatch hot path.
            if let Some(mirror_plugin) = route_mirror_plugin(object, http, acc, &proxy_id)? {
                route_plugins.push(mirror_plugin);
            }

            // Istio `http[].corsPolicy`: translate to a proxy-scoped `cors`
            // plugin when the origins are representable — `allowOrigins[]`
            // exact/prefix/regex `StringMatch` (exact projected LITERALLY, regex
            // compiled under explicit bounds) or the legacy `allowOrigin` list.
            // A matcher outside those bounds is left unprojected (warned +
            // reported as a deferred field) rather than silently approximated
            // or widened. Like mirror this is a route-local plugin, so a route
            // that must collapse with siblings fails closed via
            // `route_has_uncollapsible_local_policy` — route-local CORS never
            // leaks onto a sibling route.
            if let Some(cors_plugin) = route_cors_plugin(object, http, &proxy_id) {
                route_plugins.push(cors_plugin);
            }

            // Project the VirtualService `http[].fault` (if any) onto every
            // emitted dispatch rule rather than spinning up a separate
            // proxy-scoped `fault_injection` plugin. The per-rule
            // representation collapses cleanly with sibling routes — the
            // historical fail-closed escape hatch
            // (`route_has_uncollapsible_local_policy` returning true on a
            // fault-carrying merged route) is no longer needed for fault.
            if let Some(delay) = http
                .get("fault")
                .and_then(route_local_fault_delay_for_rule)
                .filter(|delay| delay.was_clamped())
            {
                let warning = format!(
                    "VirtualService {}/{} http[{index}].fault.delay.fixedDelay is {} ms; \
                     clamping to Ferrum's {} ms fault-delay cap",
                    object.metadata.namespace,
                    object.metadata.name,
                    delay.requested_ms,
                    delay.applied_ms,
                );
                tracing::warn!(
                    resource = %object.metadata.name,
                    namespace = %object.metadata.namespace,
                    http_route_index = index,
                    requested_delay_ms = delay.requested_ms,
                    applied_delay_ms = delay.applied_ms,
                    "{warning}"
                );
                acc.warnings.push(warning);
            }
            let route_fault_value = http.get("fault").and_then(route_local_fault_value_for_rule);

            let consumes_pending_uri_less = pending_uri_less_route.is_some();
            let overlaps_pending_scoped = pending_scoped_routes
                .iter()
                .any(|(key, _)| listen_paths_overlap_for_route_order(key, &listen_path));
            let dispatch_listen_path = if overlaps_pending_scoped {
                collapsed_listen_path_for_route_order(
                    listen_path.clone(),
                    pending_scoped_routes.iter().filter_map(|(key, _)| {
                        listen_paths_overlap_for_route_order(key, &listen_path).then_some(key)
                    }),
                )
                .or_else(|| listen_path.clone())
            } else {
                listen_path.clone()
            };
            let consumes_pending_scoped = pending_scoped_routes
                .iter()
                .any(|(key, _)| can_collapse_listen_path_into(key, &dispatch_listen_path));

            let (current_route_rules, has_uri_only_match) = mesh_route_dispatch_rules_for_proxy(
                http,
                dispatch_listen_path.as_deref(),
                MeshRouteDispatchDestination {
                    backend_host: backend_host.as_str(),
                    backend_port,
                    upstream_id: upstream_id.as_deref(),
                    requires_node_waypoint_authz,
                },
                MeshRouteDispatchPolicy {
                    timeout_ms,
                    timeout_disabled: timeout_ms.is_none(),
                    retry: retry.as_ref(),
                    retry_disabled: retry.is_none(),
                    fault: route_fault_value.as_ref(),
                    rewrite: route_rewrite_value.as_ref(),
                    redirect: route_redirect_value.as_ref(),
                },
                false,
            );

            let mut proxy = proxy_for_route(RouteProxySpec {
                id: proxy_id,
                namespace: object.metadata.namespace.clone(),
                hosts: hosts.clone(),
                listen_path: dispatch_listen_path.clone(),
                strip_listen_path: false,
                preserve_host_header: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: BackendScheme::Http,
                listen_port: None,
                retry: retry.clone(),
                backend_read_timeout_ms: timeout_ms,
            });

            // `mesh_route_dispatch` candidates whose every in-scope match entry
            // is guarded by method/header/queryParam predicates cannot stand as
            // independent proxies when a later route has the same listen_path:
            // a predicate miss must fall through to the later route, but Ferrum's
            // hot router selects exactly one proxy. Stash those guarded rules and
            // prepend them to the later materialized proxy. URI-less guarded
            // rules are stashed globally and decorate every later concrete route;
            // a synthetic `~.*` catch-all is emitted at the end for paths no later
            // route handles.
            let current_route_has_rules = !current_route_rules.is_empty();
            let guarded_route =
                force_terminate_current || (current_route_has_rules && !has_uri_only_match);
            let has_later_same_path = guarded_route
                && !is_uri_less_catch_all
                && http_routes.iter().skip(index + 1).any(|later| {
                    route_candidate_paths(later).iter().any(|(later_path, _)| {
                        listen_paths_overlap_for_route_order(&dispatch_listen_path, later_path)
                    })
                });
            let has_later_any_path = is_uri_less_catch_all
                && http_routes
                    .iter()
                    .skip(index + 1)
                    .any(|later| !route_candidate_paths(later).is_empty());
            let collapse_required = has_later_same_path
                || consumes_pending_scoped
                || (is_uri_less_catch_all
                    && (has_later_any_path || pending_uri_less_route.is_some()));
            if route_has_uncollapsible_local_policy(&route_plugins)
                && (consumes_pending_uri_less
                    || overlaps_pending_scoped
                    || (guarded_route && collapse_required))
            {
                return Err(invalid_resource(
                    object,
                    format!(
                        "VirtualService HTTP route {index} uses a route-local plugin (e.g. traffic mirror) on a route that must be merged with another route; Ferrum cannot apply that proxy-scoped plugin per mesh_route_dispatch rule"
                    ),
                ));
            }

            if guarded_route && (is_uri_less_catch_all || has_later_same_path) {
                if is_uri_less_catch_all {
                    if let Some(bucket) = pending_uri_less_route.as_mut() {
                        bucket.proxy = proxy;
                        bucket.route_plugins = route_plugins;
                        bucket.rules.extend(current_route_rules);
                        bucket.is_uri_less_catch_all = true;
                        bucket.force_terminate |= force_terminate_current;
                    } else {
                        pending_uri_less_route = Some(PendingRouteDispatch {
                            proxy,
                            route_plugins,
                            rules: current_route_rules,
                            is_uri_less_catch_all: true,
                            force_terminate: force_terminate_current,
                        });
                    }
                } else {
                    stash_pending_route_dispatch(
                        &mut pending_scoped_routes,
                        dispatch_listen_path.clone(),
                        proxy,
                        route_plugins,
                        current_route_rules,
                        false,
                        force_terminate_current,
                    );
                }
                continue;
            }

            let mut dispatch_rules = Vec::new();
            let mut force_terminate = force_terminate_current;
            if let Some(bucket) = pending_uri_less_route.as_ref() {
                dispatch_rules.extend(bucket.rules.iter().cloned());
                force_terminate |= bucket.force_terminate;
            }
            for (bucket_path, bucket) in pending_scoped_routes.iter().filter(|(key, _)| {
                listen_paths_overlap_for_route_order(key, &listen_path)
                    && !can_collapse_listen_path_into(key, &dispatch_listen_path)
            }) {
                let mut rules = bucket.rules.clone();
                add_uri_guard_to_collapsed_rules(&mut rules, bucket_path, &dispatch_listen_path);
                dispatch_rules.extend(rules);
                force_terminate |= bucket.force_terminate;
            }
            let scoped_buckets = take_collapsible_pending_route_dispatches(
                &mut pending_scoped_routes,
                &dispatch_listen_path,
            );
            if !scoped_buckets.is_empty() {
                proxy.listen_path = dispatch_listen_path.clone();
            }
            for (bucket_path, bucket) in scoped_buckets {
                let mut rules = bucket.rules;
                add_uri_guard_to_collapsed_rules(&mut rules, &bucket_path, &dispatch_listen_path);
                dispatch_rules.extend(rules);
                force_terminate |= bucket.force_terminate;
            }

            dispatch_rules.extend(current_route_rules);
            let reject_unmatched = guarded_route && !force_terminate;

            materialize_route_candidate(
                &mut proxies,
                &mut plugins,
                &mut deferred_uri_less_proxies,
                &mut deferred_uri_less_plugins,
                &object.metadata.namespace,
                proxy,
                route_plugins,
                dispatch_rules,
                reject_unmatched,
                is_uri_less_catch_all,
                force_terminate,
            );
        }
    }

    for (_, bucket) in pending_scoped_routes {
        materialize_route_candidate(
            &mut proxies,
            &mut plugins,
            &mut deferred_uri_less_proxies,
            &mut deferred_uri_less_plugins,
            &object.metadata.namespace,
            bucket.proxy,
            bucket.route_plugins,
            bucket.rules,
            true,
            bucket.is_uri_less_catch_all,
            bucket.force_terminate,
        );
    }
    if let Some(bucket) = pending_uri_less_route {
        materialize_route_candidate(
            &mut proxies,
            &mut plugins,
            &mut deferred_uri_less_proxies,
            &mut deferred_uri_less_plugins,
            &object.metadata.namespace,
            bucket.proxy,
            bucket.route_plugins,
            bucket.rules,
            true,
            true,
            bucket.force_terminate,
        );
    }

    plugins.extend(deferred_uri_less_plugins);
    proxies.extend(deferred_uri_less_proxies);

    Ok((proxies, upstreams, plugins))
}

fn route_candidate_paths(http: &Value) -> Vec<(Option<String>, bool)> {
    let supported_paths = match_paths(http);
    let mut seen_paths: HashSet<Option<String>> = HashSet::with_capacity(supported_paths.len());
    let mut candidates = Vec::with_capacity(supported_paths.len());
    for path in supported_paths {
        seen_paths.insert(path.clone());
        candidates.push((path, false));
    }

    for path in unsupported_match_paths(http) {
        if seen_paths.insert(path.clone()) {
            candidates.push((path, true));
        } else if let Some((_, force_terminate)) = candidates
            .iter_mut()
            .find(|(candidate_path, _)| candidate_path == &path)
        {
            *force_terminate = true;
        }
    }

    candidates
}

fn match_paths(http: &Value) -> Vec<Option<String>> {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return vec![Some("/".to_string())];
    };
    if matches.is_empty() {
        return vec![Some("/".to_string())];
    }

    let mut seen_paths: HashSet<Option<String>> = HashSet::new();
    let mut paths: Vec<Option<String>> = matches
        .iter()
        // Istio forbids empty HTTPMatchRequest blocks; URI-less entries depend on
        // unsupported predicates such as headers/method/queryParams, so do not
        // broaden them into Ferrum catch-all routes.
        .filter(|m| !mesh_route_dispatch_has_unsupported_predicate(m))
        // `entry_listen_path` widens to a case-insensitive regex listen_path
        // when `ignoreUriCase: true` is set on the entry; for the default
        // case-sensitive shape it returns the same value as `path_match`.
        // Going through this shared helper keeps proxy materialization and
        // dispatch-rule scoping in lock-step (T1-B.5).
        .filter_map(|m| entry_listen_path(m).map(Some))
        .filter(|listen_path| seen_paths.insert(listen_path.clone()))
        .collect();

    // Materialize a regex catch-all listen_path when at least one match entry
    // has NO URI predicate but DOES carry a fully-supported non-URI predicate
    // (`method.exact`, `headers.X.exact`, `queryParams.X.exact`).
    // Without this, an `http.match[]` consisting only of header/method/
    // queryParam predicates produces no listen_path → no proxy → the
    // operator's predicates are silently dropped and traffic that should
    // have been routed by header is unroutable. The mesh_route_dispatch
    // plugin scopes match entries to the listen_path it's installed on,
    // so any URI-bearing siblings stay on their own proxy and do not
    // bleed onto the catch-all. The synthetic path is regex (`~.*`) rather
    // than prefix `/` so Ferrum's prefix-before-regex router does not let
    // a URI-less sibling shadow real prefix URI routes. The translator
    // defers these catch-all proxies until after all URI-derived proxies so
    // they also do not shadow later regex URI routes.
    if !seen_paths.contains(&Some(URI_LESS_MATCH_LISTEN_PATH.to_string()))
        && matches
            .iter()
            .any(|m| m.get("uri").is_none() && mesh_route_dispatch_can_emit_rule(m))
    {
        paths.push(Some(URI_LESS_MATCH_LISTEN_PATH.to_string()));
    }

    paths
}

fn unsupported_match_paths(http: &Value) -> Vec<Option<String>> {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return Vec::new();
    };
    if matches.is_empty() {
        return Vec::new();
    }

    let mut seen_paths: HashSet<Option<String>> = HashSet::new();
    let mut paths = Vec::new();
    for entry in matches
        .iter()
        .filter(|entry| mesh_route_dispatch_has_unsupported_predicate(entry))
    {
        // T1-B.5: `ignoreUriCase: true` is no longer classified as
        // unsupported, so the dedicated broadening branch is gone. Any
        // remaining unsupported entry stays scoped to its URI when one
        // is present; URI-less unsupported entries fail closed on the
        // synthetic catch-all proxy. A non-bool `ignoreUriCase` value
        // (operator misconfiguration that escapes CRD validation) keeps
        // failing closed via `mesh_route_dispatch_has_unsupported_predicate`,
        // and `entry_listen_path` will simply ignore the malformed flag
        // and produce the case-sensitive listen_path — the request
        // termination plugin still applies on that scoped proxy.
        let listen_path = entry_listen_path(entry)
            .map(Some)
            .unwrap_or_else(|| Some(URI_LESS_MATCH_LISTEN_PATH.to_string()));
        if seen_paths.insert(listen_path.clone()) {
            paths.push(listen_path);
        }
    }

    paths
}

fn route_backends(
    object: &K8sObject,
    http: &Value,
    acc: &mut K8sAccumulator,
    route_index: usize,
) -> Result<Vec<RouteBackend>, K8sTranslateError> {
    let mut backends = Vec::new();
    let routes: Vec<_> = http
        .get("route")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let preserve_single_destination = routes.len() == 1;
    let mut skipped_zero = 0usize;
    let mut active_route_without_backend = false;
    for route in routes {
        let weight = route_weight(object, route)?;
        if weight == 0 && !preserve_single_destination {
            skipped_zero += 1;
            continue;
        }
        let Some(destination) = route.get("destination") else {
            active_route_without_backend = true;
            continue;
        };
        let Some(host) = string_field(destination, "host") else {
            return Err(invalid_resource(
                object,
                "VirtualService route.destination.host is required",
            ));
        };
        let port = resolve_destination_port(object, destination, host, acc)?.unwrap_or(80);
        let service_identity = service_host_components(
            host,
            &object.metadata.namespace,
            &acc.options.cluster_domain,
        )
        .and_then(|(svc, ns)| {
            acc.service_port_exists(ns, svc, port)
                .then(|| (ns.to_string(), svc.to_string(), port))
        });
        backends.push(RouteBackend {
            host: host.to_string(),
            port,
            weight,
            service_namespace: service_identity
                .as_ref()
                .map(|(namespace, _, _)| namespace.clone()),
            service_name: service_identity
                .as_ref()
                .map(|(_, service, _)| service.clone()),
            service_port: service_identity.map(|(_, _, port)| port),
        });
    }
    if skipped_zero > 0 {
        if backends.is_empty() && !active_route_without_backend {
            acc.warnings.push(format!(
                "VirtualService '{}' HTTP route {} has only zero-weight split destinations; no proxy was materialized",
                object.metadata.name, route_index
            ));
        } else {
            acc.warnings.push(format!(
                "VirtualService '{}' HTTP route {} skipped {} zero-weight split destination(s)",
                object.metadata.name, route_index, skipped_zero
            ));
        }
    }
    Ok(backends)
}

/// Resolve `destination.port` to a numeric port. Accepts either
/// `port.number` (integer) or `port.name` (string), with the latter looked
/// up against the `Service.spec.ports[].name` index built in the
/// translator pre-pass. Hosts that point at a service outside the loaded
/// namespace set (cluster-external hosts, foreign namespaces) and lack a
/// numeric port fall back to the caller's default — matching today's
/// behavior of "no port specified".
fn resolve_destination_port(
    object: &K8sObject,
    destination: &Value,
    host: &str,
    acc: &K8sAccumulator,
) -> Result<Option<u16>, K8sTranslateError> {
    let Some(port_value) = destination.get("port") else {
        return Ok(None);
    };
    if let Some(numeric) = port_value.get("number") {
        return optional_port_field(object, Some(numeric), "route.destination.port.number");
    }
    let Some(name) = string_field(port_value, "name") else {
        return Ok(None);
    };
    let cluster_domain = &acc.options.cluster_domain;
    let Some((svc, ns)) = service_host_components(host, &object.metadata.namespace, cluster_domain)
    else {
        return Err(invalid_resource(
            object,
            format!(
                "VirtualService route.destination.host '{}' is not a recognized in-cluster service form; \
                 port.name resolution only supports <svc>, <svc>.<ns>, <svc>.<ns>.svc, or \
                 <svc>.<ns>.svc.{} (optional trailing dot)",
                host, cluster_domain
            ),
        ));
    };
    match acc.lookup_service_port(ns, svc, name) {
        Some(port) => Ok(Some(port)),
        None => Err(invalid_resource(
            object,
            format!(
                "VirtualService route.destination.port.name '{}' did not match any port on Service {}/{}",
                name, ns, svc
            ),
        )),
    }
}

/// Parse an Istio destination host into `(service_name, namespace)` as borrowed
/// slices of either `host` or `default_namespace` — no allocation.
///
/// Accepted shapes (all may carry an optional trailing `.` root anchor):
///   - `<svc>` — short form; inherits the caller's default namespace
///   - `<svc>.<ns>` — two-label form
///   - `<svc>.<ns>.svc` — three-label form (final label MUST be `svc`)
///   - `<svc>.<ns>.svc.<cluster_domain>` — FQDN form (cluster_domain is
///     configurable via `FERRUM_K8S_CLUSTER_DOMAIN`, default `cluster.local`)
///
/// Any other shape — including external hosts (`api.example.com`), foreign
/// FQDNs (`foo.bar.tld.invalid`), partial suffixes (`<svc>.<ns>.cluster.local`,
/// `<svc>.<ns>.svc.cluster`), or hosts whose FQDN suffix doesn't match the
/// configured cluster domain — returns `None`. Empty labels (leading/trailing
/// dots that aren't the root anchor, consecutive dots) are also rejected.
/// Callers MUST treat `None` as "this host is not a Kubernetes service
/// reference" and surface a clear error instead of attempting a service lookup.
fn service_host_components<'a>(
    host: &'a str,
    default_namespace: &'a str,
    cluster_domain: &str,
) -> Option<(&'a str, &'a str)> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    // Reject empty strings, leading/trailing dots, and consecutive dots in one
    // pass over the borrowed slice — avoids the Vec<&str> allocation the old
    // `split('.').collect()` + `any(empty)` shape required.
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.contains("..")
    {
        return None;
    }
    // Limit to four splits: <svc>.<ns>.svc.<domain-rest>. The fourth split
    // captures the entire cluster-domain suffix verbatim so we can compare it
    // against `cluster_domain` with `eq_ignore_ascii_case` and no `join(".")`.
    let mut labels = trimmed.splitn(4, '.');
    let svc = labels.next()?;
    let Some(ns) = labels.next() else {
        return Some((svc, default_namespace));
    };
    let Some(third) = labels.next() else {
        return Some((svc, ns));
    };
    if third != "svc" {
        return None;
    }
    let Some(domain) = labels.next() else {
        return Some((svc, ns));
    };
    if domain.eq_ignore_ascii_case(cluster_domain) {
        Some((svc, ns))
    } else {
        None
    }
}

fn route_weight(object: &K8sObject, route: &Value) -> Result<u32, K8sTranslateError> {
    optional_target_weight_field(object, route, "VirtualService route.weight", 0)
}

/// Extract Istio VirtualService `http[].retries` into a Ferrum [`RetryConfig`].
///
/// Maps:
///   - `retries.attempts` -> `max_retries`
///   - `retries.retryOn` -> `retryable_status_codes` (from `5xx`, `gateway-error`,
///     or bare numeric codes) and `retry_on_connect_failure` (from `connect-failure`,
///     `reset`, `refused-stream`)
///
/// Returns `None` when no `retries` block is present or when `attempts` is zero.
fn route_retry_config(http: &Value) -> Option<RetryConfig> {
    let retries = http.get("retries")?;
    let attempts = retries.get("attempts").and_then(Value::as_u64).unwrap_or(0);
    if attempts == 0 {
        return None;
    }

    let mut retry = RetryConfig {
        max_retries: attempts.min(u64::from(MAX_RETRIES)) as u32,
        ..RetryConfig::default()
    };

    if let Some(retry_on) = string_field(retries, "retryOn") {
        let mut status_codes = Vec::new();
        let mut connect_failure = false;

        for token in retry_on.split(',').map(str::trim) {
            match token {
                "5xx" => {
                    status_codes.extend(500..=599);
                }
                "retriable-status-codes" => {
                    status_codes.extend(retriable_status_codes(retries));
                }
                "connect-failure" | "reset" | "refused-stream" => {
                    connect_failure = true;
                }
                "gateway-error" => {
                    status_codes.extend_from_slice(&[502, 503, 504]);
                }
                other => {
                    if let Ok(code @ 100..=599) = other.parse::<u16>() {
                        status_codes.push(code);
                    }
                }
            }
        }

        status_codes.sort_unstable();
        status_codes.dedup();
        if !status_codes.is_empty() {
            retry.retryable_status_codes = status_codes;
        }
        retry.retry_on_connect_failure = connect_failure;
    }

    Some(retry)
}

fn retriable_status_codes(retries: &Value) -> impl Iterator<Item = u16> + '_ {
    retries
        .get("retriableStatusCodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .filter(|code| (100..=599).contains(code))
        .map(|code| code as u16)
}

fn route_timeout_ms(http: &Value) -> Option<u64> {
    let raw = string_field(http, "timeout")?;
    parse_istio_duration_ms(raw).map(|ms| ms.min(MAX_TIMEOUT_MS))
}

/// Project an Istio `VirtualService.http[].rewrite` block into the per-rule
/// `RouteRewriteConfig` JSON shape consumed by `mesh_route_dispatch`.
///
/// Maps `rewrite.uri` -> `uri` and `rewrite.authority` -> `authority`. The
/// `match_prefix` field is filled per emitted rule by
/// `mesh_route_dispatch_rules_for_proxy` from each match entry's URI prefix —
/// it is NOT derived here. Returns `None` when neither field is present so a
/// `rewrite: {}` block does not emit an inert action.
fn route_rewrite_value(http: &Value) -> Option<Value> {
    let rewrite = http.get("rewrite")?.as_object()?;
    let mut out = serde_json::Map::new();
    if let Some(uri) = rewrite.get("uri").and_then(Value::as_str)
        && !uri.is_empty()
    {
        out.insert("uri".to_string(), Value::String(uri.to_string()));
    }
    if let Some(authority) = rewrite.get("authority").and_then(Value::as_str)
        && !authority.is_empty()
    {
        out.insert(
            "authority".to_string(),
            Value::String(authority.to_string()),
        );
    }
    if out.is_empty() {
        return None;
    }
    Some(Value::Object(out))
}

/// Project an Istio `VirtualService.http[].redirect` block into the per-rule
/// `RouteRedirectConfig` JSON shape consumed by `mesh_route_dispatch`.
///
/// Maps `redirect.uri` -> `uri`, `redirect.authority` -> `authority`,
/// `redirect.scheme` -> `scheme`, `redirect.port` -> `port`,
/// `redirect.derivePort` -> `derive_port`, and `redirect.redirectCode` ->
/// `redirect_code` (default 301). `port` and `derivePort` are mutually
/// exclusive (Istio oneof); invalid or unrepresentable values fail closed with
/// field-specific diagnostics. Returns `None` when the block has no
/// target-changing field so an inert `redirect: {}` does not short-circuit
/// every request with an unchanged Location.
fn route_redirect_value(
    object: &K8sObject,
    http: &Value,
) -> Result<Option<Value>, K8sTranslateError> {
    let Some(redirect) = http.get("redirect").and_then(Value::as_object) else {
        return Ok(None);
    };
    let has_port = redirect.get("port").is_some_and(|v| !v.is_null());
    let has_derive_port = redirect.get("derivePort").is_some_and(|v| !v.is_null());
    if has_port && has_derive_port {
        return Err(invalid_resource(
            object,
            "VirtualService http[].redirect.port and derivePort are mutually exclusive",
        ));
    }

    let mut out = serde_json::Map::new();
    if let Some(uri) = redirect.get("uri").and_then(Value::as_str)
        && !uri.is_empty()
    {
        out.insert("uri".to_string(), Value::String(uri.to_string()));
    }
    if let Some(authority) = redirect.get("authority").and_then(Value::as_str)
        && !authority.is_empty()
    {
        out.insert(
            "authority".to_string(),
            Value::String(authority.to_string()),
        );
    }
    if let Some(scheme) = redirect.get("scheme").and_then(Value::as_str)
        && !scheme.is_empty()
    {
        out.insert("scheme".to_string(), Value::String(scheme.to_string()));
    }
    if let Some(port_value) = redirect.get("port").filter(|v| !v.is_null()) {
        let Some(port) = port_value.as_u64() else {
            return Err(invalid_resource(
                object,
                "VirtualService http[].redirect.port must be an integer in the 1-65535 range",
            ));
        };
        if port == 0 || port > u64::from(u16::MAX) {
            return Err(invalid_resource(
                object,
                "VirtualService http[].redirect.port must be in the 1-65535 range",
            ));
        }
        out.insert("port".to_string(), serde_json::json!(port));
    }
    if has_derive_port {
        let Some(derive) = redirect.get("derivePort").and_then(Value::as_str) else {
            return Err(invalid_resource(
                object,
                "VirtualService http[].redirect.derivePort must be \
                 FROM_PROTOCOL_DEFAULT or FROM_REQUEST_PORT",
            ));
        };
        match derive {
            "FROM_PROTOCOL_DEFAULT" | "FROM_REQUEST_PORT" => {
                out.insert("derive_port".to_string(), Value::String(derive.to_string()));
            }
            other => {
                return Err(invalid_resource(
                    object,
                    format!(
                        "VirtualService http[].redirect.derivePort must be \
                         FROM_PROTOCOL_DEFAULT or FROM_REQUEST_PORT, got {other:?}"
                    ),
                ));
            }
        }
    }
    // `redirectCode` defaults to 301 in Istio. Carry it explicitly only when
    // the operator set a value; the plugin defaults the field otherwise.
    if let Some(code_value) = redirect.get("redirectCode") {
        let Some(code) = code_value.as_u64() else {
            return Err(invalid_resource(
                object,
                "VirtualService http[].redirect.redirectCode must be an integer in the 300-399 range",
            ));
        };
        if !(300..=399).contains(&code) {
            return Err(invalid_resource(
                object,
                format!(
                    "VirtualService http[].redirect.redirectCode must be in the 300-399 range, got {code}"
                ),
            ));
        }
        out.insert("redirect_code".to_string(), serde_json::json!(code));
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(Value::Object(out)))
}

/// Build a proxy-scoped `request_mirror` plugin config for an Istio
/// `VirtualService.http[].mirror` (+ `mirrorPercentage` / legacy
/// `mirrorPercent`). Returns `None` when no `mirror` destination is present.
/// Returns `Err` when the mirror destination is malformed (missing host, or a
/// `port.name` that does not resolve) so the bug is surfaced rather than the
/// mirror silently dropped.
fn route_mirror_plugin(
    object: &K8sObject,
    http: &Value,
    acc: &K8sAccumulator,
    proxy_id: &str,
) -> Result<Option<PluginConfig>, K8sTranslateError> {
    let Some(mirror) = http.get("mirror") else {
        return Ok(None);
    };
    let Some(host) = string_field(mirror, "host") else {
        return Err(invalid_resource(
            object,
            "VirtualService http[].mirror.host is required",
        ));
    };
    let port = resolve_destination_port(object, mirror, host, acc)?.unwrap_or(80);

    // `mirrorPercentage.value` is a float 0-100; the legacy `mirrorPercent` is
    // an integer. Default (neither present) is 100% per Istio.
    let percentage = if let Some(value) = http
        .get("mirrorPercentage")
        .and_then(|m| m.get("value"))
        .and_then(Value::as_f64)
    {
        value.clamp(0.0, 100.0)
    } else if let Some(percent) = http.get("mirrorPercent").and_then(Value::as_u64) {
        percent.min(100) as f64
    } else {
        100.0
    };

    // A 0% mirror is a no-op; skip emitting the plugin entirely so the proxy
    // does not carry an inert instance (and the route can still collapse).
    if percentage == 0.0 {
        return Ok(None);
    }

    let now = chrono::Utc::now();
    Ok(Some(PluginConfig {
        id: format!("istio-vs-mirror-{proxy_id}"),
        plugin_name: "request_mirror".to_string(),
        namespace: object.metadata.namespace.clone(),
        config: serde_json::json!({
            "mirror_host": host,
            "mirror_port": port,
            "percentage": percentage,
        }),
        scope: crate::config::types::PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }))
}

fn parse_istio_duration_secs(raw: &str) -> Option<u64> {
    parse_istio_duration_ms(raw).map(|ms| if ms == 0 { 0 } else { ms.div_ceil(1000) })
}

/// Collect a present list of strings from a `corsPolicy` array field while
/// preserving explicit emptiness. Missing and malformed fields return `None`;
/// [`cors_string_arrays_plugin_valid`] distinguishes those cases before any
/// projection occurs.
fn cors_string_array(cors: &Value, key: &str) -> Option<Vec<String>> {
    cors.get(key)
        .and_then(Value::as_array)?
        .iter()
        .map(|value| value.as_str().map(str::to_string))
        .collect()
}

#[derive(Clone, Copy)]
enum IstioUnmatchedPreflights {
    Forward,
    Ignore,
}

fn cors_unmatched_preflights(cors: &Value) -> Result<IstioUnmatchedPreflights, ()> {
    match cors.get("unmatchedPreflights") {
        None => Ok(IstioUnmatchedPreflights::Forward),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("UNSPECIFIED") => {
            Ok(IstioUnmatchedPreflights::Forward)
        }
        Some(Value::String(value)) if value.eq_ignore_ascii_case("FORWARD") => {
            Ok(IstioUnmatchedPreflights::Forward)
        }
        Some(Value::String(value)) if value.eq_ignore_ascii_case("IGNORE") => {
            Ok(IstioUnmatchedPreflights::Ignore)
        }
        _ => Err(()),
    }
}

/// Extract CORS allowed origins from an Istio `corsPolicy`, mapped to the
/// `cors` plugin's `allowed_origins` form (a JSON array). Supports the full
/// Istio `allowOrigins[]` `StringMatch` set — `exact` (emitted as
/// `{"exact": ...}`, the plugin's LITERAL matcher), `prefix` (emitted as
/// `{"prefix": ...}`), and `regex` (emitted as `{"regex": ...}`) — plus the
/// legacy `allowOrigin` string list (exact strings, projected through the same
/// literal `{"exact": ...}` matcher). The `cors` plugin matches these the same
/// way Ferrum matches Istio `StringMatch` elsewhere: byte-literal exact,
/// literal prefix, RE2 full match for regex.
///
/// Every exact is emitted as the OBJECT matcher, never as the plugin's
/// plain-string form (issue #3254): the plain-string form is native syntax that
/// canonicalizes the value and reads a leading `*` as wildcard-subdomain
/// syntax, so projecting `*.example.com` or `https://Example.com:443` through
/// it would authorize origins the source never matched. The object matcher
/// preserves the source string byte-for-byte, which is why those shapes are now
/// translatable at all instead of being deferred.
///
/// Returns `None` (policy left unprojected, surfaced as a `deferred_fields`
/// entry by the status writer) when there is no origin list, when the list
/// exceeds the shared matcher-count bound, when any entry is not a single-key
/// `exact`/`prefix`/`regex` `StringMatch` (an unknown or multi-key matcher is
/// fail-closed, not approximated), or when any matcher fails the plugin's own
/// bounded admission (empty/whitespace-only exact, empty prefix, over-budget
/// value, un-compilable or over-complex regex) — so a policy this returns
/// `Some` for is ALWAYS projectable into a valid `cors` plugin config (no
/// translate-then-silently-drop gap). `cors_policy_translatable` and the actual
/// projection both go through here, so the predicate and the emitted config can
/// never disagree on which shapes are representable.
fn cors_allowed_origins(cors: &Value) -> Option<Vec<Value>> {
    if let Some(arr) = cors.get("allowOrigins").and_then(Value::as_array) {
        crate::plugins::cors::validate_origin_matcher_count(arr.len()).ok()?;
        let mut origins = Vec::with_capacity(arr.len());
        for entry in arr {
            origins.push(cors_origin_matcher_value(entry)?);
        }
        (!origins.is_empty()).then_some(origins)
    } else if let Some(arr) = cors.get("allowOrigin").and_then(Value::as_array) {
        // Deprecated Istio field: a plain list of exact origin strings with the
        // SAME literal semantics as the StringMatch `exact` arm — the two forms
        // project into the identical `{"exact": ...}` plugin shape.
        crate::plugins::cors::validate_origin_matcher_count(arr.len()).ok()?;
        let mut origins = Vec::with_capacity(arr.len());
        for entry in arr {
            origins.push(cors_exact_origin_matcher_value(entry.as_str()?)?);
        }
        (!origins.is_empty()).then_some(origins)
    } else {
        None
    }
}

/// Project one Istio exact origin (`allowOrigins[].exact` or a legacy
/// `allowOrigin` list entry) onto the `cors` plugin's LITERAL `{"exact": ...}`
/// matcher, preserving the source string byte-for-byte.
///
/// Exact `*` is Istio's documented allow-all value and is emitted verbatim; the
/// plugin maps that one value to its wildcard policy. Every other value stays a
/// literal — including one that looks like native wildcard syntax
/// (`*.example.com`) and one that is not the canonical browser serialization
/// (`https://Example.com:443`). Returns `None` only for values the plugin
/// itself refuses (empty/whitespace-only, or over the shared byte bound), so
/// the deferred verdict and the emitted config cannot diverge.
fn cors_exact_origin_matcher_value(exact: &str) -> Option<Value> {
    if exact != "*" {
        crate::plugins::cors::validate_literal_exact_origin(exact).ok()?;
    }
    Some(serde_json::json!({ "exact": exact }))
}

/// Map one Istio `allowOrigins[]` `StringMatch` entry to the `cors` plugin's
/// `allowed_origins` entry form. Returns `None` (unrepresentable → policy stays
/// deferred) when the entry is not an object carrying EXACTLY ONE
/// `exact` / `prefix` / `regex` string, or when the matcher fails the plugin's
/// own bounded admission (`plugins::cors::{validate_literal_exact_origin,
/// validate_origin_prefix, compile_origin_regex}` — do not fork).
/// `regex` is compiled here (cold path) purely to gate translatability under
/// the same byte/complexity bounds — the plugin re-compiles it at config time
/// as the runtime matcher; an invalid pattern is never reflected into a header.
fn cors_origin_matcher_value(entry: &Value) -> Option<Value> {
    let obj = entry.as_object()?;
    // Istio `StringMatch` contract: EXACTLY ONE recognized key with a string
    // value, nothing else. A malformed matcher (extra/unknown key, a non-string
    // value, or multiple keys — e.g. `{"prefix":"x","regex":123}`) is NOT
    // representable, so return None and leave the policy DEFERRED (fail-closed)
    // rather than silently dropping the bad key and approximating it. Mirrors
    // `CorsPlugin::parse_origin_matcher` via the shared StringMatch validator, so
    // the translator, the plugin, and the deferred-field status writer agree.
    if !super::string_match_has_exactly_one_supported_operator(entry, &["exact", "prefix", "regex"])
    {
        return None;
    }
    let exact = obj.get("exact").and_then(Value::as_str);
    let prefix = obj.get("prefix").and_then(Value::as_str);
    let regex = obj.get("regex").and_then(Value::as_str);

    match (exact, prefix, regex) {
        (Some(exact), None, None) => cors_exact_origin_matcher_value(exact),
        (None, Some(prefix), None) => {
            crate::plugins::cors::validate_origin_prefix(prefix).ok()?;
            Some(serde_json::json!({ "prefix": prefix }))
        }
        (None, None, Some(regex)) => {
            // Only translatable if it compiles WITHIN the plugin's explicit
            // byte/complexity bounds — otherwise the projected plugin config
            // would fail validation and be silently dropped, defeating the
            // route's CORS policy. Keep it deferred instead.
            crate::plugins::cors::compile_origin_regex(regex).ok()?;
            Some(serde_json::json!({ "regex": regex }))
        }
        _ => None,
    }
}

/// Whether a VirtualService `http[].corsPolicy` can be faithfully translated to
/// a `cors` plugin. Shared by the translator (emit vs. warn-and-skip), the
/// mesh-slice carry, and the Istio status writer (deferred-field reporting) so
/// they never disagree on whether a given policy is projected. A policy is
/// translatable when it has at least one representable origin
/// (`allowOrigins[]` `exact`/`prefix`/`regex` `StringMatch` — `regex` must
/// compile within the shared bounds — or the legacy `allowOrigin` exact list),
/// any `maxAge` parses as a duration, and every
/// `allowMethods`/`allowHeaders`/`exposeHeaders` entry passes the plugin's own
/// method/header-name admission. Credentialed exact `*` is deferred because the
/// native wildcard representation cannot emit the concrete request origin
/// required for credentialed CORS. A malformed/unknown origin matcher, an
/// un-compilable or over-complex `regex`, an over-budget matcher list, or an
/// invalid method/header token likewise makes the policy non-translatable so it
/// is left unprojected (deferred) rather than silently approximated or failing
/// `CorsPlugin` construction after translation. Exact origins are projected
/// LITERALLY (issue #3254), so a wildcard-shaped or non-canonical exact is
/// representable and no longer deferred — it simply keeps the source's literal
/// matching.
pub(crate) fn cors_policy_translatable(cors: &Value) -> bool {
    let allowed_origins = cors_allowed_origins(cors);
    let origins_ok = allowed_origins.is_some();
    let max_age_ok = match cors.get("maxAge") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => parse_istio_duration_secs(s).is_some(),
        _ => false,
    };
    let allow_credentials_ok = matches!(
        cors.get("allowCredentials"),
        None | Some(Value::Null) | Some(Value::Bool(_))
    );
    // Exacts are emitted as `{"exact": ...}` matcher objects (issue #3254), so
    // the allow-all screen must inspect that shape — a bare-string check would
    // silently stop firing and let credentialed allow-all project, where the
    // plugin would then drop credentials.
    let credentialed_wildcard_ok = !matches!(cors.get("allowCredentials"), Some(Value::Bool(true)))
        || !allowed_origins
            .as_ref()
            .is_some_and(|origins| origins.iter().any(cors_origin_value_is_allow_all));
    origins_ok
        && max_age_ok
        && allow_credentials_ok
        && credentialed_wildcard_ok
        && cors_unmatched_preflights(cors).is_ok()
        && cors_string_arrays_plugin_valid(cors)
}

/// Whether one PROJECTED `allowed_origins` entry carries Istio's documented
/// allow-all value. Covers both emitted shapes so the screen cannot go inert
/// when the projection changes: the `{"exact": "*"}` matcher object this
/// translator emits, and a bare `"*"` string (the plugin's native allow-all
/// form, which the mesh carrier may still produce).
fn cors_origin_value_is_allow_all(origin: &Value) -> bool {
    match origin {
        Value::String(value) => value == "*",
        Value::Object(map) => map.get("exact").and_then(Value::as_str) == Some("*"),
        _ => false,
    }
}

/// Whether the projected `allowMethods`/`allowHeaders`/`exposeHeaders` lists
/// would be accepted by `CorsPlugin` construction: the plugin rejects padded
/// or empty values, invalid HTTP methods, and invalid
/// header names (shared `plugins::cors::{validate_method,validate_header_name}`
/// admission — do not fork). `cors_string_array` emits the collected strings
/// verbatim, so a bad token would otherwise fail plugin construction AFTER
/// translation instead of deferring the policy here. An absent list is
/// projected as explicit empty so Istio omission is preserved.
fn cors_string_arrays_plugin_valid(cors: &Value) -> bool {
    fn list_ok(cors: &Value, key: &str, validate: fn(&str, &str) -> Result<(), String>) -> bool {
        match cors.get(key) {
            None => true,
            Some(Value::Array(_)) => cors_string_array(cors, key).is_some_and(|values| {
                values.iter().all(|value| {
                    let trimmed = value.trim();
                    !trimmed.is_empty()
                        && trimmed.len() == value.len()
                        && validate(key, value).is_ok()
                })
            }),
            _ => false,
        }
    }
    list_ok(cors, "allowMethods", crate::plugins::cors::validate_method)
        && list_ok(
            cors,
            "allowHeaders",
            crate::plugins::cors::validate_header_name,
        )
        && list_ok(
            cors,
            "exposeHeaders",
            crate::plugins::cors::validate_header_name,
        )
}

/// Build a proxy-scoped `cors` plugin for an Istio `VirtualService.http[].corsPolicy`.
/// Returns `None` when there is no `corsPolicy`, or when the policy is not
/// faithfully representable (a malformed/unknown origin matcher, an
/// un-compilable `regex`, or an unparseable `maxAge`) — in that case it is left
/// unprojected (warned, and reported as a deferred field by the status writer)
/// rather than failing the whole VirtualService or silently approximating.
/// `allowOrigins[]` `exact`/`prefix`/`regex` `StringMatch` and the legacy
/// `allowOrigin` exact list are all projected. This reuses the existing `cors`
/// plugin instead of duplicating preflight/header logic, mirroring the
/// `request_mirror` approach for `http[].mirror`.
/// Whether ONE `match[]` block applies to sidecars. Istio's
/// `HTTPMatchRequest.gateways` OVERRIDES the top-level `spec.gateways` list:
/// a match carrying `gateways` applies to sidecars iff it names the reserved
/// `mesh` gateway, regardless of the VS-level scope; a match without them
/// inherits `vs_applies_to_sidecars` (the VS-level `spec.gateways` scope).
fn match_entry_applies_to_sidecars(
    predicates: &serde_json::Map<String, Value>,
    vs_applies_to_sidecars: bool,
) -> bool {
    match predicates.get("gateways") {
        None => vs_applies_to_sidecars,
        Some(value) => value
            .as_array()
            .map(|gateways| {
                gateways
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|gateway| gateway == "mesh")
            })
            .unwrap_or(false),
    }
}

/// Whether a VirtualService `http[]` entry is part of the SIDECAR's route
/// table at all: its `match[]` is omitted/empty (inheriting the VS-level
/// scope), or SOME match block applies to sidecars per
/// `match_entry_applies_to_sidecars`. Entries this rejects are invisible to
/// sidecars — they neither donate a CORS policy nor suppress a later one.
fn http_entry_applies_to_sidecars(http: &Value, vs_applies_to_sidecars: bool) -> bool {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return vs_applies_to_sidecars;
    };
    if matches.is_empty() {
        return vs_applies_to_sidecars;
    }
    matches.iter().any(|entry| {
        entry.as_object().is_some_and(|predicates| {
            match_entry_applies_to_sidecars(predicates, vs_applies_to_sidecars)
        })
    })
}

/// Whether a VirtualService `http[]` entry's CORS policy can honestly be
/// applied HOST-WIDE on materialized mesh routes (which are host-routed `/`):
/// its `match[]` is omitted/empty (inheriting `vs_applies_to_sidecars`), or
/// SOME match both applies to sidecars (`match_entry_applies_to_sidecars`)
/// and constrains nothing beyond a catch-all `/` uri prefix (`name` and
/// `ignoreUriCase` are non-scoping metadata). An entry scoped by any other
/// predicate — a narrower uri, `headers`, `port`, `sourceLabels`, `method`,
/// `queryParams`, `withoutHeaders`, … — is route-scoped: promoting its CORS
/// host-wide would enforce it (including disallowed-Origin 403s) on traffic
/// the predicates never matched. Implies `http_entry_applies_to_sidecars`.
fn http_entry_cors_applies_host_wide(http: &Value, vs_applies_to_sidecars: bool) -> bool {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return vs_applies_to_sidecars;
    };
    if matches.is_empty() {
        return vs_applies_to_sidecars;
    }
    matches.iter().any(|entry| {
        let Some(predicates) = entry.as_object() else {
            return false;
        };
        if !match_entry_applies_to_sidecars(predicates, vs_applies_to_sidecars) {
            return false;
        }
        for (key, value) in predicates {
            match key.as_str() {
                // Sidecar applicability already established above.
                "gateways" => {}
                "uri" => {
                    let catch_all = value
                        .get("prefix")
                        .and_then(Value::as_str)
                        .map(|prefix| prefix == "/" || prefix.is_empty())
                        .unwrap_or(false);
                    if !catch_all {
                        return false;
                    }
                }
                // Route-name metadata, not a routing predicate.
                "name" => {}
                // URI-comparison semantics, not a routing predicate: with a
                // catch-all `/` prefix (the only uri this predicate accepts),
                // case-insensitive comparison narrows nothing.
                "ignoreUriCase" => {}
                // Any other predicate is route scoping — fail closed to
                // "not host-wide" for unknown/future predicates too.
                _ => return false,
            }
        }
        true
    })
}

/// Build the mesh-slice-carried CORS policy from a `http[].corsPolicy` value
/// (issue #1973). Returns `None` for a non-translatable policy — the SAME
/// verdict `route_cors_plugin` reaches, because both funnel through
/// `cors_policy_translatable` / `cors_allowed_origins`; a projection-
/// equivalence unit test pins the two emissions against each other.
fn mesh_cors_policy_from_value(cors: &Value) -> Option<MeshCorsPolicy> {
    if !cors_policy_translatable(cors) {
        return None;
    }
    let mut allowed_origins = Vec::new();
    for origin in cors_allowed_origins(cors)? {
        let matcher = match &origin {
            // Kept for the native allow-all string form; the translator itself
            // now emits every exact as a `{"exact": ...}` matcher object.
            Value::String(exact) => MeshCorsOriginMatch::Exact(exact.clone()),
            Value::Object(map) => {
                if let Some(exact) = map.get("exact").and_then(Value::as_str) {
                    MeshCorsOriginMatch::Exact(exact.to_string())
                } else if let Some(prefix) = map.get("prefix").and_then(Value::as_str) {
                    MeshCorsOriginMatch::Prefix(prefix.to_string())
                } else {
                    // `cors_allowed_origins` only emits the supported shapes;
                    // anything else is a translatability bug upstream — stay
                    // fail-closed rather than approximate.
                    let regex = map.get("regex").and_then(Value::as_str)?;
                    MeshCorsOriginMatch::Regex(regex.to_string())
                }
            }
            _ => return None,
        };
        allowed_origins.push(matcher);
    }
    Some(MeshCorsPolicy {
        allowed_origins,
        allowed_methods: cors_string_array(cors, "allowMethods").unwrap_or_default(),
        allowed_headers: cors_string_array(cors, "allowHeaders").unwrap_or_default(),
        exposed_headers: cors_string_array(cors, "exposeHeaders").unwrap_or_default(),
        max_age_seconds: cors
            .get("maxAge")
            .and_then(Value::as_str)
            .and_then(parse_istio_duration_secs),
        allow_credentials: cors.get("allowCredentials").and_then(Value::as_bool),
        unmatched_preflights: match cors.get("unmatchedPreflights") {
            None => None,
            Some(_) => Some(match cors_unmatched_preflights(cors).ok()? {
                IstioUnmatchedPreflights::Forward => {
                    crate::modes::mesh::config::MeshCorsUnmatchedPreflights::Forward
                }
                IstioUnmatchedPreflights::Ignore => {
                    crate::modes::mesh::config::MeshCorsUnmatchedPreflights::Ignore
                }
            }),
        },
    })
}

fn route_cors_plugin(object: &K8sObject, http: &Value, proxy_id: &str) -> Option<PluginConfig> {
    let cors = http.get("corsPolicy")?;
    // `cors_policy_translatable` is the single shared gate; the actual origin
    // projection below goes through the SAME `cors_allowed_origins`, so the
    // predicate and the emitted config can never disagree on representability.
    if !cors_policy_translatable(cors) {
        tracing::warn!(
            namespace = %object.metadata.namespace,
            name = %object.metadata.name,
            "VirtualService http[].corsPolicy is not faithfully translatable (allowOrigins[] \
             must be exact/prefix/regex StringMatch, or the legacy allowOrigin exact list, \
             within the bounded matcher count/size and with a compilable, bounded-complexity \
             regex, plus well-typed methods, headers, credentials, unmatched-preflight mode, \
             and maxAge; credentialed exact '*' cannot be represented safely); leaving it \
             unprojected. Configure the `cors` plugin directly."
        );
        return None;
    }
    // Guaranteed non-empty `Some` by `cors_policy_translatable`.
    let origins = cors_allowed_origins(cors).unwrap_or_default();

    let mut config = serde_json::Map::new();
    config.insert("allowed_origins".to_string(), serde_json::json!(origins));
    config.insert(
        "allowed_methods".to_string(),
        serde_json::json!(cors_string_array(cors, "allowMethods").unwrap_or_default()),
    );
    config.insert(
        "allowed_headers".to_string(),
        serde_json::json!(cors_string_array(cors, "allowHeaders").unwrap_or_default()),
    );
    config.insert(
        "exposed_headers".to_string(),
        serde_json::json!(cors_string_array(cors, "exposeHeaders").unwrap_or_default()),
    );
    if let Some(max_age) = cors
        .get("maxAge")
        .and_then(Value::as_str)
        .and_then(parse_istio_duration_secs)
    {
        config.insert("max_age".to_string(), serde_json::json!(max_age));
    }
    if let Some(allow_creds) = cors.get("allowCredentials").and_then(Value::as_bool) {
        config.insert(
            "allow_credentials".to_string(),
            serde_json::json!(allow_creds),
        );
    }
    let unmatched = match cors_unmatched_preflights(cors).ok()? {
        IstioUnmatchedPreflights::Forward => "forward",
        IstioUnmatchedPreflights::Ignore => "ignore",
    };
    config.insert(
        "unmatched_preflights".to_string(),
        serde_json::json!(unmatched),
    );

    let now = chrono::Utc::now();
    Some(PluginConfig {
        id: format!("istio-vs-cors-{proxy_id}"),
        plugin_name: "cors".to_string(),
        namespace: object.metadata.namespace.clone(),
        config: Value::Object(config),
        scope: crate::config::types::PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
}

pub(super) fn path_match(uri: &Value) -> Option<String> {
    if let Some(prefix) = string_field(uri, "prefix") {
        return Some(prefix.to_string());
    }
    if let Some(exact) = string_field(uri, "exact") {
        return Some(exact_path_listen_path(exact));
    }
    string_field(uri, "regex").map(|pattern| format!("~{pattern}"))
}

/// Compute the listen_path that an Istio match entry contributes to.
///
/// For `ignoreUriCase: false` (the default), this returns the same value as
/// [`path_match`] — the existing prefix / exact / regex listen_path
/// representations are case-sensitive by construction.
///
/// For `ignoreUriCase: true` (T1-B.5), widens exact/prefix URI matches to a
/// case-insensitive regex listen_path so the proxy router admits both casings:
///
/// - `prefix: "/Api"`  →  `~(?i:/Api.*)`
/// - `exact: "/Api"`   →  `~(?i:/Api)` (auto-anchored to `^(?i:/Api)$`)
/// - `regex: "<pat>"`  →  `~<pat>` (`ignoreUriCase` is exact/prefix-only
///   in Istio and therefore does not rewrite regex matches)
///
/// Literal exact/prefix operands are regex-escaped before widening. Istio
/// `StringMatch.exact` / `.prefix` are literal strings, so `/v1.0` must not
/// behave like `/v1<any>0` after it moves into Ferrum's regex router tier.
///
/// Both [`match_paths`] and [`mesh_route_dispatch_rules_for_proxy`] route
/// through this helper so the listen_path used at proxy materialization and
/// the listen_path used at dispatch-rule scoping stay in lock-step — without
/// the shared helper, a widened proxy would never get its dispatch rule
/// emitted because the bare `path_match` value (`/Api`) would never equal
/// the widened key (`~(?i:/Api.*)`).
pub(super) fn entry_listen_path(entry: &Value) -> Option<String> {
    let uri = entry.get("uri")?;
    let ignore_uri_case = entry
        .get("ignoreUriCase")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !ignore_uri_case {
        return path_match(uri);
    }
    if let Some(prefix) = string_field(uri, "prefix") {
        // `prefix` semantics in Istio = "string prefix" (matches `/api`,
        // `/api/foo`, AND `/apixyz`). Ferrum's prefix listen_path has the
        // same semantics, so the case-insensitive regex must end with `.*`
        // to NOT be auto-anchored to `$` (which would degrade prefix to
        // exact). `anchor_regex_pattern` won't re-add a trailing `$` when
        // the pattern already ends with one — `.*` covers both anchoring
        // and the optional path-tail.
        return Some(format!("~(?i:{}.*)", regex::escape(prefix)));
    }
    if let Some(exact) = string_field(uri, "exact") {
        // No trailing `.*` here — the auto-anchoring (`^...$`) gives us
        // exact-equality semantics case-insensitively.
        return Some(format!("~(?i:{})", regex::escape(exact)));
    }
    string_field(uri, "regex").map(|pattern| format!("~{pattern}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteralListenPathKind {
    Exact,
    Prefix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiteralListenPathShape {
    escaped_lower: String,
    kind: LiteralListenPathKind,
    generated_ignore_case: bool,
}

fn generated_ignore_case_listen_path_shape(path: &str) -> Option<(String, LiteralListenPathKind)> {
    let body = path.strip_prefix("~(?i:")?.strip_suffix(')')?;
    if let Some(prefix) = body.strip_suffix(".*") {
        return Some((
            escaped_literal_listen_path_lower(prefix)?,
            LiteralListenPathKind::Prefix,
        ));
    }
    Some((
        escaped_literal_listen_path_lower(body)?,
        LiteralListenPathKind::Exact,
    ))
}

fn escaped_literal_listen_path_lower(pattern: &str) -> Option<String> {
    let mut lowered = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next()?;
            if !is_regex_meta_character(escaped) {
                return None;
            }
            lowered.push('\\');
            lowered.push(escaped.to_ascii_lowercase());
        } else {
            if is_regex_meta_character(ch) {
                return None;
            }
            lowered.push(ch.to_ascii_lowercase());
        }
    }
    Some(lowered)
}

fn is_regex_meta_character(ch: char) -> bool {
    matches!(
        ch,
        '\\' | '.'
            | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '|'
            | '['
            | ']'
            | '{'
            | '}'
            | '^'
            | '$'
            | '#'
            | '&'
            | '-'
            | '~'
    )
}

fn literal_listen_path_shape(path: &str) -> Option<LiteralListenPathShape> {
    if let Some((escaped_lower, kind)) = generated_ignore_case_listen_path_shape(path) {
        return Some(LiteralListenPathShape {
            escaped_lower,
            kind,
            generated_ignore_case: true,
        });
    }
    if let Some(exact) = path.strip_prefix('=') {
        return Some(LiteralListenPathShape {
            escaped_lower: regex::escape(exact).to_ascii_lowercase(),
            kind: LiteralListenPathKind::Exact,
            generated_ignore_case: false,
        });
    }
    if path.starts_with('~') {
        return None;
    }
    Some(LiteralListenPathShape {
        escaped_lower: regex::escape(path).to_ascii_lowercase(),
        kind: LiteralListenPathKind::Prefix,
        generated_ignore_case: false,
    })
}

fn literal_shapes_overlap(left: &LiteralListenPathShape, right: &LiteralListenPathShape) -> bool {
    match (left.kind, right.kind) {
        (LiteralListenPathKind::Exact, LiteralListenPathKind::Exact) => {
            left.escaped_lower == right.escaped_lower
        }
        (LiteralListenPathKind::Prefix, LiteralListenPathKind::Prefix) => {
            left.escaped_lower.starts_with(&right.escaped_lower)
                || right.escaped_lower.starts_with(&left.escaped_lower)
        }
        (LiteralListenPathKind::Prefix, LiteralListenPathKind::Exact) => {
            right.escaped_lower.starts_with(&left.escaped_lower)
        }
        (LiteralListenPathKind::Exact, LiteralListenPathKind::Prefix) => {
            left.escaped_lower.starts_with(&right.escaped_lower)
        }
    }
}

fn literal_shape_contains(
    container: &LiteralListenPathShape,
    candidate: &LiteralListenPathShape,
) -> bool {
    match (container.kind, candidate.kind) {
        (LiteralListenPathKind::Exact, LiteralListenPathKind::Exact) => {
            container.escaped_lower == candidate.escaped_lower
        }
        (LiteralListenPathKind::Exact, LiteralListenPathKind::Prefix) => false,
        (LiteralListenPathKind::Prefix, LiteralListenPathKind::Exact)
        | (LiteralListenPathKind::Prefix, LiteralListenPathKind::Prefix) => candidate
            .escaped_lower
            .starts_with(&container.escaped_lower),
    }
}

pub(super) fn listen_paths_overlap_for_route_order(
    left: &Option<String>,
    right: &Option<String>,
) -> bool {
    if left == right {
        return true;
    }
    let (Some(left), Some(right)) = (left.as_deref(), right.as_deref()) else {
        return false;
    };
    let left_generated = generated_ignore_case_listen_path_shape(left).is_some();
    let right_generated = generated_ignore_case_listen_path_shape(right).is_some();
    if !left_generated && !right_generated {
        return false;
    }
    let Some(left_shape) = literal_listen_path_shape(left) else {
        return false;
    };
    let Some(right_shape) = literal_listen_path_shape(right) else {
        return false;
    };
    literal_shapes_overlap(&left_shape, &right_shape)
}

fn can_collapse_listen_path_into(source: &Option<String>, target: &Option<String>) -> bool {
    if source == target {
        return true;
    }
    let (Some(source), Some(target)) = (source.as_deref(), target.as_deref()) else {
        return false;
    };
    let Some(target_shape) = literal_listen_path_shape(target) else {
        return false;
    };
    if !target_shape.generated_ignore_case {
        return false;
    }
    let Some(source_shape) = literal_listen_path_shape(source) else {
        return false;
    };
    literal_shape_contains(&target_shape, &source_shape)
}

fn generated_prefix_listen_path(shape: &LiteralListenPathShape) -> Option<String> {
    (shape.kind == LiteralListenPathKind::Prefix)
        .then(|| format!("~(?i:{}.*)", shape.escaped_lower))
}

fn collapsed_listen_path_for_route_order<'a>(
    current: Option<String>,
    pending_keys: impl Iterator<Item = &'a Option<String>>,
) -> Option<String> {
    let mut paths = vec![current];
    paths.extend(pending_keys.cloned());
    for candidate in &paths {
        if paths
            .iter()
            .all(|path| can_collapse_listen_path_into(path, candidate))
        {
            return candidate.clone();
        }
    }
    let mut prefix_shapes = paths
        .iter()
        .filter_map(|path| path.as_deref().and_then(literal_listen_path_shape))
        .filter(|shape| shape.kind == LiteralListenPathKind::Prefix)
        .collect::<Vec<_>>();
    prefix_shapes.sort_by_key(|shape| shape.escaped_lower.len());
    for shape in prefix_shapes {
        let Some(candidate) = generated_prefix_listen_path(&shape) else {
            continue;
        };
        if paths
            .iter()
            .all(|path| can_collapse_listen_path_into(path, &Some(candidate.clone())))
        {
            return Some(candidate);
        }
    }
    None
}

fn service_ports(object: &K8sObject) -> Result<Vec<ServicePort>, K8sTranslateError> {
    let mut ports = Vec::new();
    object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .try_for_each(|port| {
            let Some(raw_port) = port.get("number").and_then(Value::as_u64) else {
                return Ok(());
            };
            // Istio ServiceEntry `targetPort` is a numeric container port.
            let target_port = port
                .get("targetPort")
                .and_then(Value::as_u64)
                .and_then(|v| u16::try_from(v).ok())
                .map(crate::modes::mesh::config::ServiceTargetPort::Number);
            ports.push(ServicePort {
                port: port_from_u64(object, raw_port, "ports[].number")?,
                protocol: app_protocol(string_field(port, "protocol")),
                name: string_field(port, "name").map(ToOwned::to_owned),
                target_port,
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(ports)
}

fn workload_ports(object: &K8sObject) -> Result<Vec<WorkloadPort>, K8sTranslateError> {
    let mut workload_ports = Vec::new();
    object
        .spec
        .get("ports")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|ports| ports.iter())
        .try_for_each(|(name, port)| {
            let Some(raw_port) = port.as_u64() else {
                return Ok(());
            };
            workload_ports.push(WorkloadPort {
                port: port_from_u64(object, raw_port, "ports")?,
                protocol: AppProtocol::Unknown,
                name: Some(name.clone()),
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(workload_ports)
}

/// Map an Istio `ServiceEntry` port `protocol` token to an [`AppProtocol`].
///
/// The ServiceEntry port `protocol` field is the L4/L7 transport descriptor (its
/// only protocol field — there is no separate `appProtocol` on a ServiceEntry
/// port), so `protocol: UDP` mirrors the K8s Service L4 mapping
/// (`core::workload_port_protocol`) to `AppProtocol::Udp` rather than the
/// `Unknown` (HTTP-family) catch-all — otherwise a UDP ServiceEntry would still
/// be classified HTTP-family and routed into HTTP/stream materialization. UDP is
/// inert in this F3 §3.3 stage (no UDP capture/egress yet); the classification
/// just keeps it partitioned out of the other lanes. Unrecognized tokens (e.g.
/// `sctp`) stay `Unknown`.
fn app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        "http2" => AppProtocol::Http2,
        "grpc" => AppProtocol::Grpc,
        "tcp" => AppProtocol::Tcp,
        "tls" => AppProtocol::Tls,
        "udp" => AppProtocol::Udp,
        "mongo" => AppProtocol::Mongo,
        "redis" => AppProtocol::Redis,
        "mysql" => AppProtocol::Mysql,
        "postgres" => AppProtocol::Postgres,
        _ => AppProtocol::Unknown,
    }
}

/// Whether an Istio `ServiceEntry` `spec.ports[].protocol` string names a UDP
/// port.
///
/// Routes the raw token through the SAME [`app_protocol`] classifier the
/// ServiceEntry translator uses to populate `ServicePort.protocol`, then checks
/// for [`AppProtocol::Udp`] — so the Istio status writer's UDP-deferral
/// detection can never diverge from what the translator classifies (and thus
/// from what the EgressGateway materializer skips as inert in F3 §3.3 stage 1,
/// which keys off `AppProtocol::Udp`). Used by `istio_status::service_entry_status`
/// to surface the deferred UDP egress lane in `deferred_fields`. Shared (like
/// [`cors_policy_translatable`] / [`sidecar_ingress_protocol_is_http_family`]) so
/// the predicate lives in one place and translation/materialization and the
/// status report stay in lock-step.
pub(crate) fn service_entry_port_protocol_is_udp(protocol: Option<&str>) -> bool {
    matches!(app_protocol(protocol), AppProtocol::Udp)
}

/// Map a Sidecar `ingress[].port.protocol` string to the `AppProtocol` carried on
/// [`MeshSidecarIngress`], distinguishing a recognized protocol from an
/// unrecognized one.
///
/// Unlike the generic [`app_protocol`] (which collapses BOTH `https` and a typo
/// like `HTPS` — and a missing value — to `AppProtocol::Unknown`, the HTTP-family
/// catch-all), this classifier is fail-closed for a custom inbound listener: it
/// routes ONLY explicitly recognized HTTP-family protocol tokens and maps
/// everything else — recognized non-HTTP (`tcp`/`tls`/db), a MISSING protocol
/// (Istio defaults an unset port protocol to TCP), and an UNRECOGNIZED string —
/// to a non-HTTP-family `AppProtocol` so `MeshSidecarIngress::resolve` defers it
/// (`NonHttpProtocol`) instead of exposing a non-HTTP / mistyped listener on the
/// HTTP request path. `https` is recognized HTTP-family (a TLS-terminated HTTP
/// listener) and stays modeled — so the round-1 HTTPS-routing behavior is
/// preserved while typos and unset protocols fail closed. Never returns
/// `AppProtocol::Unknown` (no ingress entry relies on the catch-all), keeping
/// this independent of the service-port `Unknown → HTTP` convention.
fn sidecar_ingress_app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        // `http2`/`h2`, `grpc`/`grpc-web`, and `https` are all HTTP/2-capable,
        // TLS-terminated-or-not HTTP-family listeners that Ferrum models on the
        // HTTP request path.
        "http2" | "h2" | "https" => AppProtocol::Http2,
        "grpc" | "grpc-web" => AppProtocol::Grpc,
        // Recognized non-HTTP protocols defer (raw-TCP inbound is not modeled
        // here). A MISSING or UNRECOGNIZED protocol also lands here (Istio
        // defaults an unset port protocol to TCP; a typo must not be guessed as
        // HTTP), so `resolve()` reports it as a deferred non-HTTP listener.
        _ => AppProtocol::Tcp,
    }
}

/// Whether a Sidecar `ingress[].port.protocol` string names an HTTP-family
/// listener Ferrum materializes (vs. a stream/raw-TCP listener — or a missing /
/// mistyped protocol — it defers).
///
/// Routes the raw string through the SAME [`sidecar_ingress_app_protocol`]
/// mapping the ingress translator stores on [`MeshSidecarIngress`] and the SAME
/// [`is_http_family_app_protocol`](crate::modes::mesh::config::is_http_family_app_protocol)
/// predicate `MeshSidecarIngress::resolve` uses, so the translator/resolution
/// side and the Istio status writer's deferred-field report can never disagree on
/// whether a listener is modeled. `https` is recognized HTTP-family and reported
/// as modeled; an unrecognized protocol (`HTPS` typo) or a missing one is
/// reported as a deferred non-HTTP listener, matching resolution. Shared (like
/// [`cors_policy_translatable`]) to keep the predicate in one place.
pub(crate) fn sidecar_ingress_protocol_is_http_family(protocol: Option<&str>) -> bool {
    crate::modes::mesh::config::is_http_family_app_protocol(sidecar_ingress_app_protocol(protocol))
}

fn telemetry(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshTelemetryResource, K8sTranslateError> {
    let scope = istio_policy_scope(&acc.options, object, object.spec.get("selector"));

    let tracing = object
        .spec
        .get("tracing")
        .and_then(Value::as_array)
        .map(|entries| {
            // GAP-3F: Telemetry.tracing[].match.mode is preserved end-to-end so
            // the auto-injected `workload_metrics` plugin can emit CLIENT spans
            // for outbound mesh hops. The merged mode tracks the union across
            // every entry (server-only by default → either side becomes
            // CLIENT_AND_SERVER when both appear).
            let mut merged = MeshTracingConfig {
                mode: None,
                sampling_percentage: None,
                disable_span_reporting: None,
                custom_tags: HashMap::new(),
                custom_header_tags: HashMap::new(),
                custom_env_tags: HashMap::new(),
                providers: Vec::new(),
            };
            let mut emits_server = false;
            let mut emits_client = false;
            let mut saw_entry = false;
            for t in entries {
                let mode = telemetry_tracing_mode(object, t)?;
                // Istio default mode is SERVER for ambient/sidecar inbound and
                // CLIENT for sidecar outbound. The translator treats an unset
                // mode as SERVER to match the pre-GAP-3F default; mesh runtime
                // direction stamping then selects whichever side the listener
                // represents.
                let resolved_mode = mode.unwrap_or(TelemetryTracingMode::Server);
                emits_server |= resolved_mode.emits_server();
                emits_client |= resolved_mode.emits_client();
                saw_entry = true;
                let sampling = telemetry_sampling_percentage(object, t)?;
                let mut custom_header_tags: HashMap<String, String> = HashMap::new();
                let mut custom_env_tags: HashMap<String, String> = HashMap::new();
                let mut custom_tags: HashMap<String, String> = HashMap::new();
                if let Some(tags) = t.get("customTags").and_then(Value::as_object) {
                    for (key, val) in tags {
                        // Istio customTags: { tagName: { literal: { value: "v" } } }
                        // | { header: { name, defaultValue? } }
                        // | { environment: { name, defaultValue? } }
                        if let Some(header_name) = val
                            .get("header")
                            .and_then(|h| h.get("name"))
                            .and_then(Value::as_str)
                        {
                            custom_header_tags.insert(key.clone(), header_name.to_string());
                            if let Some(value) = val
                                .get("header")
                                .and_then(|header| header.get("defaultValue"))
                                .and_then(Value::as_str)
                            {
                                custom_tags.insert(key.clone(), value.to_string());
                            }
                            continue;
                        }

                        if let Some(literal) = val
                            .get("literal")
                            .and_then(|l| l.get("value"))
                            .and_then(Value::as_str)
                        {
                            custom_tags.insert(key.clone(), literal.to_string());
                            continue;
                        }

                        if let Some(env_tag) = val.get("environment") {
                            let Some(name) = env_tag
                                .get("name")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|name| !name.is_empty())
                            else {
                                return Err(invalid_resource(
                                    object,
                                    format!(
                                        "Telemetry tracing customTags.{key}.environment.name is required"
                                    ),
                                ));
                            };
                            // Carry a typed DP lookup. Never resolve the
                            // controller-host environment here — sidecar env is
                            // only known on the target data plane.
                            custom_env_tags.insert(key.clone(), name.to_string());
                            if let Some(default_value) = env_tag
                                .get("defaultValue")
                                .and_then(Value::as_str)
                            {
                                custom_tags.insert(key.clone(), default_value.to_string());
                            }
                            continue;
                        }
                    }
                }
                let providers = telemetry_tracing_providers(acc, object, t)?;
                if sampling.is_some() {
                    merged.sampling_percentage = sampling;
                }
                if let Some(disabled) = t.get("disableSpanReporting").and_then(Value::as_bool) {
                    merged.disable_span_reporting = Some(disabled);
                }
                merged.merge_custom_tag_sources(
                    &custom_tags,
                    &custom_header_tags,
                    &custom_env_tags,
                );
                if !providers.is_empty() {
                    extend_unique_tracing_providers(&mut merged.providers, providers);
                }
            }
            // Collapse the per-entry union into a single resolved mode. When
            // `tracing[]` is non-empty but every entry resolved to neither
            // direction (`Some(false), Some(false)` is unreachable in practice
            // since `resolved_mode` always picks at least one), we still emit
            // the merged config so providers and sampling propagate.
            merged.mode = match (emits_server, emits_client) {
                (true, true) => Some(TelemetryTracingMode::ClientAndServer),
                (true, false) => Some(TelemetryTracingMode::Server),
                (false, true) => Some(TelemetryTracingMode::Client),
                (false, false) => None,
            };
            Ok::<_, K8sTranslateError>(saw_entry.then_some(merged))
        })
        .transpose()?
        .flatten();

    let metrics = object
        .spec
        .get("metrics")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .map(|m| {
            let mut tag_overrides = Vec::new();
            let mut disabled_metrics = Vec::new();
            if let Some(overrides) = m.get("overrides").and_then(Value::as_array) {
                for ovr in overrides {
                    let matched_metric =
                        match ovr.get("match").and_then(|matcher| matcher.get("metric")) {
                            Some(Value::String(metric)) => metric.as_str(),
                            Some(_) => {
                                return Err(invalid_resource(
                                    object,
                                    "Telemetry metrics.overrides[].match.metric must be a string",
                                ));
                            }
                            None => "ALL_METRICS",
                        };
                    let ignored_metric_family =
                        is_recognized_unsupported_istio_metric_family(matched_metric);
                    if ovr
                        .get("disabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        disabled_metrics.push(matched_metric.to_string());
                    }
                    if let Some(tags) = ovr.get("tagOverrides").and_then(Value::as_object) {
                        for (tag_name, tag_spec) in tags {
                            let operation = if ignored_metric_family {
                                // Preserve one no-op entry so workload_metrics emits its
                                // bounded ignored-family diagnostic, but do not validate
                                // policy for a metric family Ferrum never records.
                                TagOverrideOperation::Remove
                            } else {
                                let op = tag_spec
                                    .get("operation")
                                    .and_then(Value::as_str)
                                    .unwrap_or("");
                                match op {
                                    "REMOVE" => TagOverrideOperation::Remove,
                                    "UPSERT" => {
                                        let value = telemetry_metric_upsert_literal(
                                            object, tag_name, tag_spec,
                                        )?;
                                        TagOverrideOperation::Set { value }
                                    }
                                    "" => {
                                        return Err(invalid_resource(
                                            object,
                                            format!(
                                                "Telemetry metrics.overrides[].tagOverrides.{tag_name}.operation is required"
                                            ),
                                        ));
                                    }
                                    _ => {
                                        return Err(invalid_resource(
                                            object,
                                            format!(
                                                "Telemetry metrics.overrides[].tagOverrides.{tag_name}.operation '{op}' is unsupported"
                                            ),
                                        ));
                                    }
                                }
                            };
                            tag_overrides.push(MetricTagOverride {
                                metric: Some(matched_metric.to_string()),
                                name: tag_name.clone(),
                                operation,
                            });
                        }
                    }
                }
            }
            Ok::<_, K8sTranslateError>(MeshMetricsConfig {
                tag_overrides,
                disabled_metrics,
            })
        })
        .transpose()?;

    validate_istio_telemetry_config(tracing.as_ref(), metrics.as_ref()).map_err(|message| {
        let detail = message
            .strip_prefix("workload_metrics: ")
            .unwrap_or(&message);
        invalid_resource(
            object,
            format!("Telemetry workload_metrics configuration is invalid: {detail}"),
        )
    })?;

    let access_logging = object
        .spec
        .get("accessLogging")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .map(|al| {
            let disabled = al.get("disabled").and_then(Value::as_bool).unwrap_or(false);
            let filter = al
                .get("filter")
                .and_then(|f| f.get("expression"))
                .and_then(Value::as_str)
                .map(parse_access_log_filter_expression)
                .transpose()
                .map_err(|message| invalid_resource(object, message))?
                .flatten();
            Ok::<_, K8sTranslateError>(MeshAccessLoggingConfig {
                enabled: !disabled,
                filter,
            })
        })
        .transpose()?;

    Ok(MeshTelemetryResource {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        config: MeshTelemetryConfig {
            tracing,
            metrics,
            access_logging,
        },
    })
}

fn telemetry_metric_upsert_literal(
    object: &K8sObject,
    tag_name: &str,
    tag_spec: &Value,
) -> Result<String, K8sTranslateError> {
    let expression = tag_spec
        .get("value")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid_resource(
                object,
                format!(
                    "Telemetry metrics.overrides[].tagOverrides.{tag_name}.UPSERT value is required"
                ),
            )
        })?;
    serde_json::from_str::<String>(expression).map_err(|_| {
        invalid_resource(
            object,
            format!(
                "Telemetry metrics.overrides[].tagOverrides.{tag_name}.UPSERT value must be a double-quoted string literal; CEL expressions are unsupported"
            ),
        )
    })
}

fn telemetry_sampling_percentage(
    object: &K8sObject,
    tracing_entry: &Value,
) -> Result<Option<f64>, K8sTranslateError> {
    let Some(value) = tracing_entry.get("randomSamplingPercentage") else {
        return Ok(None);
    };
    let Some(sampling) = value.as_f64() else {
        return Err(invalid_resource(
            object,
            "Telemetry tracing.randomSamplingPercentage must be a finite number between 0 and 100",
        ));
    };
    if !sampling.is_finite() || !(0.0..=100.0).contains(&sampling) {
        return Err(invalid_resource(
            object,
            format!(
                "Telemetry tracing.randomSamplingPercentage must be between 0 and 100 (got {sampling})"
            ),
        ));
    }
    Ok(Some(sampling))
}

fn extend_unique_tracing_providers(
    current: &mut Vec<TracingProvider>,
    providers: Vec<TracingProvider>,
) {
    for provider in providers {
        if !current.contains(&provider) {
            current.push(provider);
        }
    }
}

/// Extract every `tracing[].providers[]` entry as [`TracingProvider`]s.
///
/// Mirrors Istio's Telemetry CRD: `providers[]` is a list of named provider
/// references. Inline providers fan out to the injected workload metrics
/// exporter. Name-only entries resolve through the translation-time MeshConfig
/// provider registry when the root `istio` ConfigMap is present.
///
/// Istio's standard provider model defines providers once at the mesh-config
/// level (`meshConfig.extensionProviders`) and references them by name from
/// Telemetry resources. This translator also keeps the existing inline
/// provider shorthand for Ferrum-native test and fixture manifests.
fn telemetry_tracing_providers(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    tracing_entry: &Value,
) -> Result<Vec<TracingProvider>, K8sTranslateError> {
    let Some(providers_value) = tracing_entry.get("providers") else {
        return Ok(default_telemetry_tracing_providers(acc, object));
    };
    let Some(providers) = providers_value.as_array() else {
        return Err(invalid_resource(
            object,
            "Telemetry tracing.providers must be an array",
        ));
    };
    if providers.is_empty() {
        return Ok(default_telemetry_tracing_providers(acc, object));
    }
    let mut translated = Vec::new();
    for entry in providers {
        let Some(provider) = telemetry_tracing_provider(acc, object, entry)? else {
            continue;
        };
        translated.push(provider);
    }
    Ok(translated)
}

fn telemetry_tracing_provider(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    entry: &Value,
) -> Result<Option<TracingProvider>, K8sTranslateError> {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_resource(object, "Telemetry tracing.providers[].name is required"))?
        .trim();
    if name.is_empty() {
        return Err(invalid_resource(
            object,
            "Telemetry tracing.providers[].name must not be empty",
        ));
    }
    let is_reference_only = entry
        .as_object()
        .map(|obj| obj.keys().all(|k| k == "name"))
        .unwrap_or(false);
    if is_reference_only {
        if let Some(provider) = acc.mesh_config_registry.tracing_provider(name).cloned() {
            return Ok(Some(provider));
        }
        warn_missing_mesh_config_provider(acc, object, name);
        return Ok(None);
    }
    let provider = match name {
        "zipkin" => {
            let url = telemetry_provider_string_field(object, entry, "zipkin", "url")?;
            TracingProvider::Zipkin { url }
        }
        "datadog" => {
            let agent_url = telemetry_provider_string_field_aliased(
                object,
                entry,
                "datadog",
                "agentUrl",
                &["agent_url"],
            )?;
            let service = entry
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_string);
            TracingProvider::Datadog { agent_url, service }
        }
        "lightstep" => {
            let collector_url = telemetry_provider_string_field_aliased(
                object,
                entry,
                "lightstep",
                "collectorUrl",
                &["collector_url"],
            )?;
            let access_token_env = telemetry_provider_string_field_aliased(
                object,
                entry,
                "lightstep",
                "accessTokenEnv",
                &["access_token_env"],
            )?;
            TracingProvider::Lightstep {
                collector_url,
                access_token_env,
            }
        }
        "opentelemetry" => {
            let endpoint =
                telemetry_provider_string_field(object, entry, "opentelemetry", "endpoint")?;
            TracingProvider::OpenTelemetry { endpoint }
        }
        other => {
            let warning = format!(
                "Telemetry {}/{} tracing.providers[] name '{}' is not a recognised inline \
                 provider type (supported: zipkin/datadog/lightstep/opentelemetry); \
                 meshConfig.extensionProviders lookup only resolves entries shaped as \
                 `{{name: \"...\"}}` (no extra fields) — provider skipped",
                object.metadata.namespace, object.metadata.name, other
            );
            tracing::warn!(
                resource = %object.metadata.name,
                namespace = %object.metadata.namespace,
                provider_name = other,
                "{warning}"
            );
            acc.warnings.push(warning);
            return Ok(None);
        }
    };
    Ok(Some(provider))
}

fn default_telemetry_tracing_providers(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Vec<TracingProvider> {
    let names: Vec<String> = acc
        .mesh_config_registry
        .default_tracing_provider_names()
        .to_vec();
    let mut providers = Vec::new();
    for name in names {
        if let Some(provider) = acc.mesh_config_registry.tracing_provider(&name).cloned() {
            providers.push(provider);
        } else {
            warn_missing_mesh_config_provider(acc, object, &name);
        }
    }
    providers
}

fn warn_missing_mesh_config_provider(acc: &mut K8sAccumulator, object: &K8sObject, name: &str) {
    let warning = if acc.mesh_config_registry.is_known_non_tracing_provider(name) {
        format!(
            "Telemetry {}/{} references meshConfig extensionProvider '{}' which is declared but \
             not a tracing provider type Ferrum supports (zipkin/datadog/lightstep/opentelemetry); \
             provider skipped",
            object.metadata.namespace, object.metadata.name, name
        )
    } else {
        format!(
            "Telemetry {}/{} references unknown meshConfig extensionProvider '{}'; provider skipped",
            object.metadata.namespace, object.metadata.name, name
        )
    };
    tracing::warn!(
        resource = %object.metadata.name,
        namespace = %object.metadata.namespace,
        provider_name = name,
        "{warning}"
    );
    acc.warnings.push(warning);
}

fn telemetry_tracing_mode(
    object: &K8sObject,
    tracing_entry: &Value,
) -> Result<Option<TelemetryTracingMode>, K8sTranslateError> {
    let Some(mode) = tracing_entry
        .get("match")
        .and_then(|m| m.get("mode"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    match mode {
        "SERVER" | "server" => Ok(Some(TelemetryTracingMode::Server)),
        "CLIENT_AND_SERVER" | "client_and_server" => {
            Ok(Some(TelemetryTracingMode::ClientAndServer))
        }
        "CLIENT" | "client" => Ok(Some(TelemetryTracingMode::Client)),
        other => Err(invalid_resource(
            object,
            format!("Telemetry tracing.match.mode '{other}' is unsupported"),
        )),
    }
}

fn telemetry_provider_string_field(
    object: &K8sObject,
    entry: &Value,
    provider_name: &str,
    field: &str,
) -> Result<String, K8sTranslateError> {
    telemetry_provider_string_field_aliased(object, entry, provider_name, field, &[])
}

/// Read a required string field, trying the canonical (camelCase) name first
/// then any provided aliases. Non-empty after trim is required. The returned
/// value is trimmed so stray whitespace in CRDs (e.g. `"url": " http://zipkin:9411 "`)
/// does not propagate into pool keys, DNS resolvers, or URL parsers downstream.
fn telemetry_provider_string_field_aliased(
    object: &K8sObject,
    entry: &Value,
    provider_name: &str,
    field: &str,
    aliases: &[&str],
) -> Result<String, K8sTranslateError> {
    std::iter::once(field)
        .chain(aliases.iter().copied())
        .find_map(|name| {
            entry
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| {
            invalid_resource(
                object,
                format!(
                    "Telemetry tracing.providers[] '{provider_name}' is missing required field '{field}'"
                ),
            )
        })
}

/// Translate an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) CRD into a
/// [`MeshProxyConfig`].
///
/// ProxyConfig fields are config-time only — they shape the data plane's
/// startup posture (concurrency, image) and tracing sampling but do not
/// affect the request path. Fields:
///
/// - `metadata.name` -> `name`
/// - `metadata.namespace` -> `namespace`
/// - `spec.selector` + root-namespace rule -> [`PolicyScope`] (via
///   [`istio_policy_scope`]). A ProxyConfig in the Istio root namespace
///   with no selector applies mesh-wide; with a selector it applies to
///   matching workloads across the mesh. In any other namespace, no
///   selector means namespace-default and a selector narrows further.
/// - `spec.concurrency` -> `concurrency` (rejected as invalid if outside
///   `u32` range)
/// - `spec.image.imageType` -> `image` (informational)
/// - `spec.environmentVariables` -> `environment`
/// - `spec.tracing.sampling` -> `tracing_sampling` (percentage 0-100,
///   merged into `workload_metrics.sampling_percentage` at slice-apply time;
///   non-numeric or out-of-range values are rejected as invalid rather than
///   silently dropped, matching `Telemetry.tracing.randomSamplingPercentage`).
///   This is a Ferrum mesh-model field with **no counterpart in Istio's
///   `networking.istio.io/v1beta1` ProxyConfig CRD** — see the note on the
///   parse below.
fn proxy_config(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Result<MeshProxyConfig, K8sTranslateError> {
    let scope = istio_policy_scope(options, object, object.spec.get("selector"));

    let concurrency = match object.spec.get("concurrency") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.concurrency must be a non-negative integer (got {value})"
                    ),
                )
            })?;
            Some(u32::try_from(raw).map_err(|_| {
                invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.concurrency must fit in u32 (0..={}), got {raw}",
                        u32::MAX
                    ),
                )
            })?)
        }
    };

    let image = object
        .spec
        .get("image")
        .and_then(|img| img.get("imageType"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let environment = object
        .spec
        .get("environmentVariables")
        .map(string_map)
        .unwrap_or_default();

    // Fail closed on a malformed or out-of-range sampling percentage the same
    // way `Telemetry.tracing.randomSamplingPercentage` does: silently
    // accepting one would push an invalid
    // `workload_metrics.sampling_percentage` onto every matching workload and
    // contradict the documented "percentage 0-100" contract. A rejection is
    // surfaced on the resource as `FerrumAccepted=False`/`Invalid`.
    //
    // Reachability: Istio's `proxyconfigs.networking.istio.io` v1beta1 CRD has
    // a *structural* spec schema whose only properties are `selector`,
    // `concurrency`, `image`, and `environmentVariables` — there is no
    // `tracing` property and no `x-kubernetes-preserve-unknown-fields` on
    // `spec`. A `spec.tracing.sampling` applied to a real cluster is therefore
    // pruned by the Kubernetes API server and never reaches the CRD watcher;
    // the field is populated over native `MeshSubscribe` / file / xDS mesh
    // config instead. This branch is deliberate defense-in-depth for any
    // object feed that is not API-server-pruned (and for a future CRD schema
    // that adds the field), not a live K8s admission gate.
    let tracing_sampling = match object
        .spec
        .get("tracing")
        .and_then(|tracing| tracing.get("sampling"))
    {
        None | Some(Value::Null) => None,
        Some(value) => {
            let sampling = value.as_f64().ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.tracing.sampling must be a number between 0 and 100 \
                         (got {value})"
                    ),
                )
            })?;
            if !sampling.is_finite() || !(0.0..=100.0).contains(&sampling) {
                return Err(invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.tracing.sampling must be between 0 and 100 \
                         (got {sampling})"
                    ),
                ));
            }
            Some(sampling)
        }
    };

    Ok(MeshProxyConfig {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        concurrency,
        image,
        environment,
        tracing_sampling,
    })
}

/// Parse simple filter expressions like `response.code >= 400` into an
/// [`AccessLogFilter`]. Returns `Ok(None)` for expressions without supported
/// access-log predicates and `Err` for malformed supported predicates.
fn parse_access_log_filter_expression(expr: &str) -> Result<Option<AccessLogFilter>, String> {
    if expr.contains("||") {
        return Err(
            "Telemetry access log filter expressions with '||' are not supported".to_string(),
        );
    }

    let mut filter = AccessLogFilter {
        status_code_min: None,
        status_code_max: None,
        min_latency_ms: None,
        errors_only: false,
    };
    let mut matched = false;

    // Split on && to handle compound expressions
    for part in expr.split("&&") {
        let part = part.trim();
        if part.starts_with("response.code") || part.starts_with("response.status") {
            let Some(val) = extract_numeric_comparison(part) else {
                return Err(
                    "Telemetry access log response.code filter must use a numeric comparison"
                        .to_string(),
                );
            };
            apply_status_code_comparison(&mut filter, val)?;
            matched = true;
        } else if part.starts_with("response.duration") {
            let Some(val) = extract_numeric_comparison(part) else {
                return Err(
                    "Telemetry access log response.duration filter must use a numeric comparison"
                        .to_string(),
                );
            };
            match val {
                Comparison::Gte(n) => {
                    merge_min_latency_ms(&mut filter.min_latency_ms, n)?;
                }
                Comparison::Gt(n) => {
                    merge_min_latency_ms(&mut filter.min_latency_ms, comparison_increment(n)?)?;
                }
                Comparison::Lte(_) | Comparison::Lt(_) | Comparison::Eq(_) => {
                    return Err(
                        "Telemetry access log response.duration filters only support '>' and '>='"
                            .to_string(),
                    );
                }
            }
            matched = true;
        }
    }

    if matched { Ok(Some(filter)) } else { Ok(None) }
}

fn apply_status_code_comparison(
    filter: &mut AccessLogFilter,
    comparison: Comparison,
) -> Result<(), String> {
    match comparison {
        Comparison::Gte(n) => merge_status_code_min(&mut filter.status_code_min, n)?,
        Comparison::Gt(n) => {
            merge_status_code_min(&mut filter.status_code_min, comparison_increment(n)?)?
        }
        Comparison::Lte(n) => merge_status_code_max(&mut filter.status_code_max, n)?,
        Comparison::Lt(n) => {
            merge_status_code_max(&mut filter.status_code_max, comparison_decrement(n)?)?
        }
        Comparison::Eq(n) => {
            merge_status_code_min(&mut filter.status_code_min, n)?;
            merge_status_code_max(&mut filter.status_code_max, n)?;
        }
    }
    Ok(())
}

fn merge_status_code_min(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
}

fn merge_status_code_max(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.min(value)));
    Ok(())
}

fn merge_min_latency_ms(current: &mut Option<u64>, value: i64) -> Result<(), String> {
    let value = duration_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
}

fn status_code_value(value: i64) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| {
        format!("Telemetry access log response code filter value {value} is outside 0..=65535")
    })
}

fn duration_value(value: i64) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| {
        format!("Telemetry access log duration filter value {value} must be non-negative")
    })
}

fn comparison_increment(value: i64) -> Result<i64, String> {
    value
        .checked_add(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} overflows"))
}

fn comparison_decrement(value: i64) -> Result<i64, String> {
    value
        .checked_sub(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} underflows"))
}

enum Comparison {
    Gte(i64),
    Gt(i64),
    Lte(i64),
    Lt(i64),
    Eq(i64),
}

fn extract_numeric_comparison(expr: &str) -> Option<Comparison> {
    let ops = [">=", "<=", ">", "<", "=="];
    for op in ops {
        if let Some(idx) = expr.find(op) {
            let val_str = expr[idx + op.len()..].trim();
            let val: i64 = val_str.parse().ok()?;
            return match op {
                ">=" => Some(Comparison::Gte(val)),
                ">" => Some(Comparison::Gt(val)),
                "<=" => Some(Comparison::Lte(val)),
                "<" => Some(Comparison::Lt(val)),
                "==" => Some(Comparison::Eq(val)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::ParsedCidr;
    use crate::modes::mesh::policy::{
        MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    };
    use crate::modes::mesh::slice::MeshSlice;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn options_for_namespace(namespace: &str) -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            namespace.to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn proxy_has_plugin(proxy: &Proxy, plugin: &PluginConfig) -> bool {
        proxy
            .plugins
            .iter()
            .any(|assoc| assoc.plugin_config_id == plugin.id)
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        object_with_metadata(kind, "security.istio.io/v1", "sample", "default", spec)
    }

    fn object_with_metadata(
        kind: &str,
        api_version: &str,
        name: &str,
        namespace: &str,
        spec: Value,
    ) -> K8sObject {
        K8sObject {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
                namespace: namespace.to_string(),
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

    fn istio_mesh_config(mesh_yaml: &str) -> K8sObject {
        object_with_metadata(
            "ConfigMap",
            "v1",
            "istio",
            "istio-system",
            serde_json::json!({
                "data": {
                    "mesh": mesh_yaml,
                }
            }),
        )
    }

    fn translated_authorization_policy(spec: Value) -> MeshPolicy {
        let result = translate_k8s_objects(&[object("AuthorizationPolicy", spec)], options())
            .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        mesh.mesh_policies
            .into_iter()
            .next()
            .expect("one translated mesh policy")
    }

    #[test]
    fn translates_authorization_policy() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "selector": {"matchLabels": {"app": "api"}},
                    "rules": [{
                        "from": [{"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}}],
                        "to": [{"operation": {"methods": ["POST"], "paths": ["/admin/*"], "ports": ["8080"]}}],
                        "when": [{"key": "request.auth.claims[iss]", "values": ["issuer-a"]}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.mesh_policies.len(), 1);
        assert_eq!(mesh.mesh_policies[0].rules[0].action, PolicyAction::Deny);
        assert_eq!(mesh.mesh_policies[0].rules[0].to[0].ports, vec![8080]);
    }

    #[test]
    fn translates_allow_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}}
        }));

        assert!(matches!(
            &policy.scope,
            PolicyScope::WorkloadSelector { .. }
        ));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert!(policy.rules[0].never_matches);
        assert!(policy.rules[0].from.is_empty());

        let decision = evaluate_mesh_authorization(
            &MeshSlice {
                mesh_policies: vec![policy],
                ..MeshSlice::default()
            },
            &MeshAuthzRequest::default(),
        );
        assert_eq!(
            decision,
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn translates_namespace_allow_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW"
        }));

        assert!(matches!(
            &policy.scope,
            PolicyScope::Namespace { namespace } if namespace == "default"
        ));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert!(policy.rules[0].never_matches);
    }

    #[test]
    fn root_namespace_authorization_policy_without_selector_is_mesh_wide() {
        let result = translate_k8s_objects(
            &[object_with_metadata(
                "AuthorizationPolicy",
                "security.istio.io/v1",
                "global-deny",
                "istio-config",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{}]
                }),
            )],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert!(matches!(mesh.mesh_policies[0].scope, PolicyScope::MeshWide));
    }

    #[test]
    fn root_namespace_authorization_policy_selector_is_mesh_wide_by_labels() {
        let result = translate_k8s_objects(
            &[object_with_metadata(
                "AuthorizationPolicy",
                "security.istio.io/v1",
                "global-selector",
                "istio-config",
                serde_json::json!({
                    "action": "ALLOW",
                    "selector": {"matchLabels": {"app": "api"}},
                    "rules": [{}]
                }),
            )],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert!(
            matches!(&mesh.mesh_policies[0].scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() && selector.labels.get("app") == Some(&"api".to_string()))
        );
    }

    #[test]
    fn rejects_authorization_policy_target_refs_until_supported() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "targetRefs": [{
                        "kind": "Service",
                        "name": "payments"
                    }],
                    "rules": [{}]
                }),
            )],
            options(),
        )
        .expect_err("targetRefs must fail closed until target scoping is implemented");

        assert!(err.to_string().contains("targetRefs"));
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn translates_missing_action_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({}));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert!(policy.rules[0].never_matches);
    }

    #[test]
    fn translates_deny_authorization_policy_without_rules_to_noop() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "DENY"
        }));

        assert_eq!(policy.rules, Vec::new());
    }

    #[test]
    fn translates_audit_authorization_policy_without_rules_to_noop() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "AUDIT"
        }));

        assert_eq!(policy.rules, Vec::new());
    }

    #[test]
    fn translates_service_entry() {
        let result = translate_k8s_objects(
            &[object(
                "ServiceEntry",
                serde_json::json!({
                    "hosts": ["api.EXAMPLE.com"],
                    "resolution": "DNS",
                    "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.service_entries[0].hosts, vec!["api.example.com"]);
        assert_eq!(mesh.service_entries[0].ports[0].protocol, AppProtocol::Tls);
    }

    #[test]
    fn service_entry_udp_port_classifies_as_udp_app_protocol() {
        // An Istio ServiceEntry port with `protocol: UDP` must classify as the
        // distinct `AppProtocol::Udp` (mirroring the K8s Service L4 mapping), NOT
        // the `Unknown` (HTTP-family) catch-all it landed in before — otherwise a
        // UDP ServiceEntry would be mis-routed into HTTP/stream materialization.
        // The ServiceEntry `protocol` field is the L4 transport descriptor.
        let result = translate_k8s_objects(
            &[object(
                "ServiceEntry",
                serde_json::json!({
                    "hosts": ["dns.external.com"],
                    "resolution": "DNS",
                    "ports": [{"number": 53, "name": "dns", "protocol": "UDP"}]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.service_entries[0].ports[0].port, 53);
        assert_eq!(
            mesh.service_entries[0].ports[0].protocol,
            AppProtocol::Udp,
            "ServiceEntry protocol: UDP must classify as AppProtocol::Udp"
        );
    }

    #[test]
    fn app_protocol_classifies_udp_token() {
        // Direct unit on the ServiceEntry protocol classifier: `udp`/`UDP` →
        // `Udp`; an unrecognized transport (e.g. sctp) stays `Unknown`; the
        // existing recognized tokens are unaffected.
        assert_eq!(app_protocol(Some("udp")), AppProtocol::Udp);
        assert_eq!(app_protocol(Some("UDP")), AppProtocol::Udp);
        assert_eq!(app_protocol(Some("tcp")), AppProtocol::Tcp);
        assert_eq!(app_protocol(Some("sctp")), AppProtocol::Unknown);
        assert_eq!(app_protocol(None), AppProtocol::Unknown);
    }

    #[test]
    fn rejects_istio_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "ServiceEntry",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "ports": [{"number": 70000, "name": "http", "protocol": "HTTP"}]
                }),
            )],
            options(),
        )
        .expect_err("invalid port must fail closed");

        assert!(err.to_string().contains("ports[].number"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_authorization_policy_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["70000"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid AuthorizationPolicy port must fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn preserves_authorization_policy_wildcard_ports() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("wildcard AuthorizationPolicy port must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["*"]);
    }

    #[test]
    fn preserves_authorization_policy_prefix_port_patterns() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["8*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("prefix AuthorizationPolicy port pattern must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["8*"]);
    }

    #[test]
    fn preserves_authorization_policy_suffix_port_patterns() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["*43"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("suffix AuthorizationPolicy port pattern must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["*43"]);
    }

    #[test]
    fn rejects_authorization_policy_mid_string_port_patterns() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["8*9"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("mid-string AuthorizationPolicy port pattern is unsupported");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("8*9"));
    }

    #[test]
    fn rejects_authorization_policy_non_numeric_non_pattern_ports() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["http"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("named AuthorizationPolicy port is not representable");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("http"));
    }

    #[test]
    fn validates_later_authorization_policy_to_entries_after_unconstrained_match() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [
                            {"operation": {}},
                            {"operation": {"ports": ["70000"]}}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("later invalid AuthorizationPolicy port must still fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_unsupported_authorization_policy_operation_fields() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{
                        "to": [{"operation": {"someUnsupportedField": ["foo"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported operation fields must fail closed");

        assert!(
            err.to_string()
                .contains("rules[].to[].operation.someUnsupportedField")
        );
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_unsupported_authorization_policy_when_key() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{
                        "when": [{
                            "key": "destination.labels[app]",
                            "values": ["payments"]
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported when keys must fail closed");

        assert!(
            err.to_string()
                .contains("rules[].when[0].key 'destination.labels[app]'")
        );
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_authorization_policy_when_without_values() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{
                        "when": [{
                            "key": "connection.sni"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("when conditions without values/notValues must fail closed");

        assert!(err.to_string().contains("rules[].when[0]"));
        assert!(err.to_string().contains("values or notValues"));
    }

    #[test]
    fn rejects_malformed_authorization_policy_ip_when_value() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{
                        "when": [{
                            "key": "source.ip",
                            "values": ["10.0.0.0/40"]
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed source.ip when CIDR must fail closed");

        assert!(err.to_string().contains("rules[].when[0].values[0]"));
        assert!(err.to_string().contains("10.0.0.0/40"));
        assert!(err.to_string().contains("prefix length"));
    }

    #[test]
    fn translates_authorization_policy_negative_match_fields() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}},
            "rules": [{
                "to": [{"operation": {
                    "methods": ["GET"],
                    "notMethods": ["POST", "DELETE"],
                    "notPaths": ["/admin/*"],
                    "notHosts": ["evil.example.com"],
                    "notPorts": ["8080"]
                }}]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        let operation = &policy.rules[0].to[0];
        assert_eq!(operation.methods, vec!["GET".to_string()]);
        assert_eq!(
            operation.not_methods,
            vec!["POST".to_string(), "DELETE".to_string()]
        );
        assert_eq!(operation.not_paths, vec!["/admin/*".to_string()]);
        // Host is normalised to ASCII-lowercase at config-load time.
        assert_eq!(operation.not_hosts, vec!["evil.example.com".to_string()]);
        assert_eq!(operation.not_ports, vec![8080]);
    }

    #[test]
    fn negative_match_operation_alone_is_constrained() {
        // An operation that has ONLY negative-match fields is still a
        // constraint — the translator must not collapse it to "any".
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}},
            "rules": [{
                "to": [{"operation": {"notMethods": ["POST"]}}]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].to.len(), 1);
        assert_eq!(policy.rules[0].to[0].not_methods, vec!["POST".to_string()]);
        assert!(policy.rules[0].to[0].methods.is_empty());
    }

    #[test]
    fn rejects_authorization_policy_not_ports_wildcard_pattern() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"notPorts": ["8*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("wildcard notPorts patterns must fail closed");

        assert!(err.to_string().contains("notPorts"));
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_authorization_policy_not_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"notPorts": ["70000"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid notPorts must fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.notPorts"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn authorization_policy_negative_match_round_trip_decision() {
        // ALLOW with methods=[GET] AND notPaths=[/admin/*]:
        // - GET /api allowed (positive method match, negative path mismatch)
        // - GET /admin/users denied (positive method match BUT negative path matches → rule fails → implicit deny)
        // - POST /api denied (positive method does not match → implicit deny)
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "selector": {"matchLabels": {"app": "api"}},
                    "rules": [{
                        "to": [{"operation": {
                            "methods": ["GET"],
                            "notPaths": ["/admin/*"]
                        }}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let slice = MeshSlice {
            mesh_policies: mesh.mesh_policies,
            ..MeshSlice::default()
        };

        let get_api = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/api/items".to_string()),
            ..MeshAuthzRequest::default()
        };
        let get_admin = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/admin/users".to_string()),
            ..MeshAuthzRequest::default()
        };
        let post_api = MeshAuthzRequest {
            method: Some("POST".to_string()),
            path: Some("/api/items".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_api),
            MeshAuthzDecision::Allow
        );
        assert!(matches!(
            evaluate_mesh_authorization(&slice, &get_admin),
            MeshAuthzDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_mesh_authorization(&slice, &post_api),
            MeshAuthzDecision::Deny { .. }
        ));
    }

    #[test]
    fn rejects_peer_authentication_port_level_mtls_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "PeerAuthentication",
                serde_json::json!({
                    "mtls": {"mode": "PERMISSIVE"},
                    "portLevelMtls": {
                        "70000": {"mode": "STRICT"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("invalid PeerAuthentication port must fail closed");

        assert!(err.to_string().contains("portLevelMtls"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn root_namespace_peer_authentication_without_nonempty_selector_is_mesh_wide() {
        for selector in [
            None,
            Some(Value::Null),
            Some(serde_json::json!({"matchLabels": {}})),
        ] {
            let mut spec = serde_json::json!({
                "mtls": {"mode": "STRICT"}
            });
            if let Some(selector) = selector {
                spec["selector"] = selector;
            }
            let mut peer_auth = object("PeerAuthentication", spec);
            peer_auth.metadata.namespace = "istio-config".to_string();

            let result = translate_k8s_objects(
                &[peer_auth],
                options_for_namespace("istio-config")
                    .with_istio_root_namespace("istio-config".to_string()),
            )
            .expect("translation succeeds");

            let mesh = result.config.mesh.expect("mesh config");
            assert!(matches!(
                mesh.peer_authentications[0].scope,
                Some(PolicyScope::MeshWide)
            ));
        }
    }

    #[test]
    fn empty_peer_authentication_selectors_are_namespace_scoped() {
        for (case, selector) in [
            ("null", Value::Null),
            ("empty matchLabels", serde_json::json!({"matchLabels": {}})),
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "PeerAuthentication",
                    serde_json::json!({
                        "selector": selector,
                        "mtls": {"mode": "STRICT"},
                        "portLevelMtls": {
                            "8080": {"mode": "DISABLE"}
                        }
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");

            let mesh = result.config.mesh.expect("mesh config");
            let peer_auth = &mesh.peer_authentications[0];
            assert!(
                matches!(
                    &peer_auth.scope,
                    Some(PolicyScope::Namespace { namespace }) if namespace == "default"
                ),
                "{case} selector must use namespace scope"
            );
            assert!(
                peer_auth.selector.is_none(),
                "{case} selector must not become a workload selector"
            );
            assert_eq!(
                crate::modes::mesh::slice::resolve_effective_mtls_mode(
                    std::slice::from_ref(peer_auth),
                    "default",
                    &HashMap::<String, String>::new(),
                    8080,
                ),
                MtlsMode::Strict,
                "portLevelMtls must remain ignored for a {case} selector"
            );
        }
    }

    #[test]
    fn rejects_virtual_service_destination_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 70000}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid VirtualService destination port must fail closed");

        assert!(err.to_string().contains("route.destination.port.number"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn translates_workload_entry_vm_metadata() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "VM-API.Example",
                    "serviceAccount": "api",
                    "service": "api",
                    "network": "network-a",
                    "cluster": "cluster-a",
                    "labels": {"app": "api"},
                    "ports": {"http": 8080}
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert_eq!(workload.addresses, vec!["vm-api.example"]);
        assert_eq!(workload.network.as_deref(), Some("network-a"));
        assert_eq!(workload.cluster.as_deref(), Some("cluster-a"));
        assert_eq!(
            workload.spiffe_id.as_str(),
            "spiffe://cluster.local/ns/default/sa/api"
        );
        assert_eq!(workload.service_account.as_deref(), Some("api"));
    }

    #[test]
    fn workload_entry_cross_namespace_service_host_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "service": "reviews.prod.svc.cluster.local"
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace WorkloadEntry service host must fail closed");

        let err = err.to_string();
        assert!(
            err.contains("WorkloadEntry.service"),
            "error should mention WorkloadEntry.service: {err}"
        );
        assert!(
            err.contains("reviews.prod.svc.cluster.local"),
            "error should include the offending host: {err}"
        );
        assert!(
            err.contains("cross-namespace"),
            "error should identify the unsupported cross-namespace reference: {err}"
        );
    }

    #[test]
    fn workload_entry_two_label_cross_namespace_service_host_is_preserved() {
        let mut prod_service = object(
            "Service",
            serde_json::json!({
                "ports": [{"port": 80}]
            }),
        );
        prod_service.metadata.name = "reviews".to_string();
        prod_service.metadata.namespace = "prod".to_string();
        let result = translate_k8s_objects(
            &[
                prod_service,
                object(
                    "WorkloadEntry",
                    serde_json::json!({
                        "address": "10.0.1.5",
                        "service": "reviews.prod"
                    }),
                ),
            ],
            options().with_source_namespaces(Vec::new()),
        )
        .expect("two-label cross-namespace WorkloadEntry service host should stay literal");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].service_name, "reviews.prod");
    }

    #[test]
    fn workload_entry_two_label_dns_service_name_is_preserved() {
        let mut com_service = object(
            "Service",
            serde_json::json!({
                "ports": [{"port": 80}]
            }),
        );
        com_service.metadata.name = "placeholder".to_string();
        com_service.metadata.namespace = "com".to_string();
        let result = translate_k8s_objects(
            &[
                com_service,
                object(
                    "WorkloadEntry",
                    serde_json::json!({
                        "address": "10.0.1.5",
                        "service": "example.com"
                    }),
                ),
            ],
            options().with_source_namespaces(Vec::new()),
        )
        .expect("two-label DNS WorkloadEntry service should remain valid");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].service_name, "example.com");
    }

    #[test]
    fn workload_entry_weight_and_locality_translate() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "serviceAccount": "api",
                    "weight": 42,
                    "locality": "us-west-2/us-west-2a/sub-a"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert_eq!(workload.weight, Some(42));
        assert_eq!(
            workload.locality.as_deref(),
            Some("us-west-2/us-west-2a/sub-a")
        );
    }

    #[test]
    fn workload_entry_weight_above_max_target_weight_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "weight": 70_000
                }),
            )],
            options(),
        )
        .expect_err("weight exceeds MAX_TARGET_WEIGHT must fail");
        assert!(
            err.to_string().contains("WorkloadEntry.weight"),
            "error should mention WorkloadEntry.weight: {err}"
        );
    }

    #[test]
    fn workload_entry_omitted_optionals_are_none() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert!(workload.weight.is_none());
        assert!(workload.locality.is_none());
        assert!(workload.service_account.is_none());
        // SPIFFE still falls back to "default" SA for SVID issuance.
        assert!(workload.spiffe_id.as_str().ends_with("/sa/default"));
    }

    #[test]
    fn workload_entry_weight_zero_is_accepted() {
        // Istio uses `weight: 0` to mean "drain / no traffic". The translator
        // must not reject it; the runtime LB layer interprets the value when
        // building weighted locality-aware target sets.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "weight": 0
                }),
            )],
            options(),
        )
        .expect("weight=0 must translate");
        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].weight, Some(0));
    }

    #[test]
    fn workload_entry_empty_service_account_falls_back_to_default() {
        // Istio treats missing OR empty `serviceAccount` as `"default"` for
        // SVID issuance. The translator must not surface the SPIFFE parser's
        // trailing-slash error to operators when YAML serialization yields
        // `serviceAccount: ""`.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "serviceAccount": ""
                }),
            )],
            options(),
        )
        .expect("empty serviceAccount must translate");
        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert!(workload.service_account.is_none());
        assert!(workload.spiffe_id.as_str().ends_with("/sa/default"));
    }

    #[test]
    fn workload_entry_empty_locality_collapses_to_none() {
        // Empty-string locality is operator intent for "unset"; downstream
        // consumers should not have to special-case it.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "locality": ""
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        assert!(mesh.workloads[0].locality.is_none());
    }

    #[test]
    fn workload_entry_locality_is_free_form() {
        // The translator stores `locality` verbatim — it does not validate the
        // `region/zone/subzone` slash convention. Locality-aware routing (when
        // wired) is responsible for any parsing.
        for raw in [
            "us-west-2/us-west-2a/sub-a",
            "us-west-2/us-west-2a",
            "us-west-2",
            "single-token-no-slashes",
            "//empty/region",
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "WorkloadEntry",
                    serde_json::json!({
                        "address": "10.0.1.5",
                        "locality": raw
                    }),
                )],
                options(),
            )
            .unwrap_or_else(|e| panic!("locality {raw:?} must translate: {e}"));
            let mesh = result.config.mesh.expect("mesh config");
            assert_eq!(
                mesh.workloads[0].locality.as_deref(),
                Some(raw),
                "locality must be stored verbatim",
            );
        }
    }

    #[test]
    fn translates_virtual_service_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/v1"));
        assert!(!result.config.proxies[0].strip_listen_path);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn translates_virtual_service_exact_uri_to_exact_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"exact": "/v1.items"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/v1.items")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn translates_virtual_service_regex_uri_to_regex_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"regex": "/v[0-9]+/items"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
    fn virtual_service_without_match_defaults_to_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
    }

    #[test]
    fn virtual_service_redirect_route_materializes_proxy_without_zero_weight_warning() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // A redirect route has no `route[]` backend but is no longer silently
        // dropped — it materializes a proxy carrying a mesh_route_dispatch
        // redirect rule.
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/old")
        );
        let dispatch = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(result.config.proxies[0].id.as_str())
            })
            .expect("redirect route emits a mesh_route_dispatch plugin");
        let rules = dispatch.config["rules"].as_array().expect("rules array");
        assert!(
            rules.iter().any(|r| r
                .get("redirect")
                .and_then(|d| d.get("uri"))
                .and_then(Value::as_str)
                == Some("/new")),
            "redirect rule must carry the rewritten uri: {rules:?}"
        );
        // The redirect rule must omit the backend destination (no `route[]`).
        assert!(
            rules.iter().all(|r| r.get("destination").is_none()),
            "redirect-only route must not emit a backend destination: {rules:?}"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_preserves_weighted_destinations() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 80},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}, "weight": 20}
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
        assert_eq!(result.config.upstreams[0].targets[0].weight, 80);
        assert_eq!(
            result.config.upstreams[0].targets[1].host,
            "api-v2.default.svc.cluster.local"
        );
    }

    #[test]
    fn lossy_virtual_service_ids_in_two_namespaces_both_survive() {
        // resource_id joins with dashes, so ns `a` / name `b-c` collides with
        // ns `a-b` / name `c` on the bare proxy and upstream id strings.
        let vs_a = object_with_metadata(
            "VirtualService",
            "networking.istio.io/v1",
            "b-c",
            "a",
            serde_json::json!({
                "hosts": ["a.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "route": [
                        {"destination": {"host": "api-v1.a.svc.cluster.local", "port": {"number": 8080}}, "weight": 70},
                        {"destination": {"host": "api-v2.a.svc.cluster.local", "port": {"number": 8081}}, "weight": 30}
                    ]
                }]
            }),
        );
        let vs_b = object_with_metadata(
            "VirtualService",
            "networking.istio.io/v1",
            "c",
            "a-b",
            serde_json::json!({
                "hosts": ["b.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "route": [
                        {"destination": {"host": "api-v1.a-b.svc.cluster.local", "port": {"number": 9080}}, "weight": 60},
                        {"destination": {"host": "api-v2.a-b.svc.cluster.local", "port": {"number": 9081}}, "weight": 40}
                    ]
                }]
            }),
        );

        let expected_proxy_id = resource_id("istio-vs", "a", "b-c", "0");
        let expected_upstream_id = resource_id("istio-vs-upstream", "a", "b-c", "0");
        assert_eq!(
            expected_proxy_id,
            resource_id("istio-vs", "a-b", "c", "0"),
            "fixture must exercise the lossy dash-join collision"
        );
        assert_eq!(
            expected_upstream_id,
            resource_id("istio-vs-upstream", "a-b", "c", "0"),
            "fixture must exercise the lossy upstream dash-join collision"
        );

        let result = translate_k8s_objects(
            &[vs_a, vs_b],
            options().with_source_namespaces(vec!["a".to_string(), "a-b".to_string()]),
        )
        .expect("lossy cross-namespace VirtualServices must both translate");

        let proxy_a = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "a" && proxy.id == expected_proxy_id)
            .expect("namespace a proxy must survive");
        let proxy_b = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.namespace == "a-b" && proxy.id == expected_proxy_id)
            .expect("namespace a-b proxy must survive");
        assert_eq!(proxy_a.hosts, vec!["a.example.com".to_string()]);
        assert_eq!(proxy_b.hosts, vec!["b.example.com".to_string()]);

        let upstream_a = result
            .config
            .upstreams
            .iter()
            .find(|upstream| upstream.namespace == "a" && upstream.id == expected_upstream_id)
            .expect("namespace a upstream must survive");
        let upstream_b = result
            .config
            .upstreams
            .iter()
            .find(|upstream| upstream.namespace == "a-b" && upstream.id == expected_upstream_id)
            .expect("namespace a-b upstream must survive");
        assert_eq!(upstream_a.targets[0].weight, 70);
        assert_eq!(upstream_b.targets[0].weight, 60);
        assert_eq!(
            proxy_a.upstream_id.as_deref(),
            Some(expected_upstream_id.as_str())
        );
        assert_eq!(
            proxy_b.upstream_id.as_deref(),
            Some(expected_upstream_id.as_str())
        );
    }

    #[test]
    fn virtual_service_skips_zero_weight_destination_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "dark.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0},
                            {"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 9090}}, "weight": 100}
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
                .any(|warning| warning.contains("zero-weight split destination"))
        );
    }

    #[test]
    fn virtual_service_skips_all_omitted_weights_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_skips_omitted_weight_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 100},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}}
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
            "api-v1.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight split destination"))
        );
    }

    #[test]
    fn virtual_service_skips_all_zero_weight_destinations_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}, "weight": 0}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_keeps_single_zero_weight_destination() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0}
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
            "api.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn virtual_service_creates_proxy_per_uri_match() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/v1"}},
                            {"uri": {"prefix": "/v2"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
    fn virtual_service_emits_catch_all_for_explicit_pathless_matches() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-tenant": {"exact": "a"}}},
                            {"method": {"exact": "GET"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some(URI_LESS_MATCH_LISTEN_PATH)
        );
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "mesh_route_dispatch emitted for pathless multi-predicate match"
        );
    }

    #[test]
    fn virtual_service_keeps_pathless_predicate_in_mixed_rule() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/v1"}},
                            {"headers": {"x-tenant": {"exact": "a"}}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let listen_paths: HashSet<_> = result
            .config
            .proxies
            .iter()
            .filter_map(|p| p.listen_path.as_deref())
            .collect();
        assert_eq!(
            listen_paths,
            HashSet::from(["/v1", URI_LESS_MATCH_LISTEN_PATH])
        );
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "mesh_route_dispatch emitted for pathless predicate in mixed rule"
        );
    }

    #[test]
    fn virtual_service_rejects_route_weight_above_ferrum_limit() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [
                            {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 65536}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("oversized route weight should fail translation");

        assert!(
            err.to_string()
                .contains("weight must be between 0 and 65535")
        );
    }

    #[test]
    fn virtual_service_rejects_malformed_route_weights() {
        for weight in [serde_json::json!(-1), serde_json::json!(1.5)] {
            let err = translate_k8s_objects(
                &[object(
                    "VirtualService",
                    serde_json::json!({
                        "hosts": ["api.example.com"],
                        "http": [{
                            "route": [
                                {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": weight}
                            ]
                        }]
                    }),
                )],
                options(),
            )
            .expect_err("malformed route weight should fail translation");

            assert!(
                err.to_string()
                    .contains("weight must be between 0 and 65535")
            );
        }
    }

    // ── RequestAuthentication ────────────────────────────────────────────

    #[test]
    fn translates_request_authentication_with_selector() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "selector": {"matchLabels": {"app": "httpbin"}},
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "audiences": ["my-app"],
                        "fromHeaders": [
                            {"name": "Authorization", "prefix": "Bearer "},
                            {"name": "X-Custom-Token"},
                            {"name": "X-Raw-Token", "prefix": ""}
                        ],
                        "fromParams": ["access_token"],
                        "forwardOriginalToken": true
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications.len(), 1);
        let ra = &mesh.request_authentications[0];
        assert_eq!(ra.name, "sample");
        assert_eq!(ra.namespace, "default");
        assert!(
            matches!(&ra.scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.as_deref() == Some("default") && selector.labels.get("app") == Some(&"httpbin".to_string()))
        );
        assert_eq!(ra.jwt_rules.len(), 1);
        let rule = &ra.jwt_rules[0];
        assert_eq!(rule.issuer, "https://accounts.google.com");
        assert_eq!(
            rule.jwks_uri.as_deref(),
            Some("https://www.googleapis.com/oauth2/v3/certs")
        );
        assert_eq!(rule.audiences, vec!["my-app"]);
        assert_eq!(rule.from_headers.len(), 3);
        assert_eq!(rule.from_headers[0].name, "Authorization");
        assert_eq!(rule.from_headers[0].prefix.as_deref(), Some("Bearer "));
        assert_eq!(rule.from_headers[1].name, "X-Custom-Token");
        assert!(rule.from_headers[1].prefix.is_none());
        assert_eq!(rule.from_headers[2].name, "X-Raw-Token");
        assert!(rule.from_headers[2].prefix.is_none());
        assert_eq!(rule.from_params, vec!["access_token"]);
        assert!(rule.forward_original_token);
    }

    #[test]
    fn request_authentication_rejects_malformed_from_headers() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "fromHeaders": [
                            {"prefix": "Bearer "}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed fromHeaders should fail translation");

        assert!(
            err.to_string()
                .contains("RequestAuthentication jwtRules[].fromHeaders[0].name is required")
        );
    }

    #[test]
    fn request_authentication_rejects_malformed_from_header_prefix() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "fromHeaders": [
                            {"name": "Authorization", "prefix": 42}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed fromHeaders prefix should fail translation");

        assert!(
            err.to_string().contains(
                "RequestAuthentication jwtRules[].fromHeaders[0].prefix must be a string"
            )
        );
    }

    #[test]
    fn root_namespace_request_authentication_selector_is_mesh_wide_by_labels() {
        let mut ra = object(
            "RequestAuthentication",
            serde_json::json!({
                "selector": {"matchLabels": {"app": "httpbin"}},
                "jwtRules": [{
                    "issuer": "https://accounts.google.com",
                    "jwksUri": "https://www.googleapis.com/oauth2/v3/certs"
                }]
            }),
        );
        ra.metadata.namespace = "istio-config".to_string();

        let result = translate_k8s_objects(
            &[ra],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let scope = &mesh.request_authentications[0].scope;
        assert!(
            matches!(scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() && selector.labels.get("app") == Some(&"httpbin".to_string()))
        );
    }

    #[test]
    fn translates_request_authentication_without_selector_to_namespace_scope() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwksUri": "https://auth.example.com/.well-known/jwks.json"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let ra = &mesh.request_authentications[0];
        assert!(matches!(
            &ra.scope,
            PolicyScope::Namespace { namespace } if namespace == "default"
        ));
    }

    #[test]
    fn root_namespace_telemetry_selector_is_mesh_wide_by_labels() {
        let mut telemetry = object(
            "Telemetry",
            serde_json::json!({
                "selector": {"matchLabels": {"app": "gateway"}},
                "tracing": [{"randomSamplingPercentage": 10.0}]
            }),
        );
        telemetry.metadata.namespace = "istio-config".to_string();

        let result = translate_k8s_objects(
            &[telemetry],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let scope = &mesh.telemetry_resources[0].scope;
        assert!(
            matches!(scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() && selector.labels.get("app") == Some(&"gateway".to_string()))
        );
    }

    #[test]
    fn telemetry_header_tags_are_runtime_header_references() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "tenant": {"header": {"name": "x-tenant"}},
                            "region": {"literal": {"value": "us-east"}}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert_eq!(tracing.sampling_percentage, None);
        assert_eq!(
            tracing.custom_header_tags.get("tenant").map(String::as_str),
            Some("x-tenant")
        );
        assert_eq!(
            tracing.custom_tags.get("region").map(String::as_str),
            Some("us-east")
        );
        assert!(!tracing.custom_tags.contains_key("tenant"));
    }

    #[test]
    fn telemetry_metric_tag_overrides_preserve_match_scope() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "metrics": [{
                        "overrides": [
                            {
                                "match": {"metric": "REQUEST_COUNT"},
                                "tagOverrides": {
                                    "source_workload": {"operation": "REMOVE"}
                                }
                            },
                            {
                                "match": {"metric": "REQUEST_DURATION"},
                                "tagOverrides": {
                                    "response_flags": {
                                        "operation": "UPSERT",
                                        "value": "\"duration-only\""
                                    }
                                }
                            }
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let metrics = result.config.mesh.expect("mesh config").telemetry_resources[0]
            .config
            .metrics
            .clone()
            .expect("metrics config");
        assert_eq!(metrics.tag_overrides.len(), 2);
        assert_eq!(
            metrics.tag_overrides[0].metric.as_deref(),
            Some("REQUEST_COUNT")
        );
        assert_eq!(
            metrics.tag_overrides[1].metric.as_deref(),
            Some("REQUEST_DURATION")
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_carries_default_and_typed_lookup() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "region": {
                                "environment": {
                                    "name": "FERRUM_TEST_TELEMETRY_REGION_UNSET",
                                    "defaultValue": "us-east-1"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert_eq!(
            tracing.custom_tags.get("region").map(String::as_str),
            Some("us-east-1")
        );
        assert_eq!(
            tracing.custom_env_tags.get("region").map(String::as_str),
            Some("FERRUM_TEST_TELEMETRY_REGION_UNSET")
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_without_default_is_carried_not_dropped() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "cluster": {
                                "environment": {
                                    "name": "ISTIO_META_CLUSTER_ID"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert!(
            !tracing.custom_tags.contains_key("cluster"),
            "no defaultValue means no literal fallback at translation"
        );
        assert_eq!(
            tracing.custom_env_tags.get("cluster").map(String::as_str),
            Some("ISTIO_META_CLUSTER_ID")
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_does_not_resolve_controller_host_env() {
        // Structural proof only: the translator carries `defaultValue` plus a
        // typed `custom_env_tags` lookup and never reads process environment.
        // Do not mutate the process environment — Rust 2024 forbids unsynchronized
        // `set_var` under the parallel test harness, and host env is not the DP.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "env_tag": {
                                "environment": {
                                    "name": "FERRUM_TEST_TELEMETRY_ENV_TAG",
                                    "defaultValue": "fallback-value"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert_eq!(
            tracing.custom_tags.get("env_tag").map(String::as_str),
            Some("fallback-value"),
            "controller must not read host env as the data plane"
        );
        assert_eq!(
            tracing.custom_env_tags.get("env_tag").map(String::as_str),
            Some("FERRUM_TEST_TELEMETRY_ENV_TAG")
        );
        assert!(
            tracing
                .custom_tags
                .values()
                .all(|value| value != "live-env-value"),
            "translated literals must stay at defaultValue, never a host env read"
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_rejects_missing_name() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "env_tag": {
                                "environment": {
                                    "defaultValue": "fallback"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("environment tag without name must fail closed");

        let message = err.to_string();
        assert!(
            message.contains("environment.name is required"),
            "expected field-specific rejection, got {message}"
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_rejects_empty_name() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "env_tag": {
                                "environment": {
                                    "name": "   "
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("empty environment name must fail closed");

        let message = err.to_string();
        assert!(
            message.contains("environment.name is required"),
            "expected field-specific rejection, got {message}"
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_rejects_invalid_env_var_name() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "env_tag": {
                                "environment": {
                                    "name": "BAD-NAME"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid environment variable name must fail closed");

        let message = err.to_string();
        assert!(
            message.contains("invalid environment variable name"),
            "expected env-var name rejection, got {message}"
        );
    }

    #[test]
    fn telemetry_environment_custom_tag_rejects_sensitive_env_var_name() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "credential": {
                                "environment": {
                                    "name": "FERRUM_ADMIN_JWT_SECRET"
                                }
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("credential-bearing environment variable must fail closed");

        let message = err.to_string();
        assert!(
            message.contains("cannot copy a credential-bearing environment variable"),
            "expected sensitive env-var rejection, got {message}"
        );
        assert!(
            !message.contains("FERRUM_ADMIN_JWT_SECRET"),
            "credential-bearing environment variable name must not be echoed"
        );
    }

    #[test]
    fn telemetry_tracing_entries_replace_custom_tag_source_exclusively() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [
                        {
                            "customTags": {
                                "cluster": {
                                    "environment": {
                                        "name": "ISTIO_META_CLUSTER_ID",
                                        "defaultValue": "fallback-cluster"
                                    }
                                },
                                "region": {"literal": {"value": "old-region"}},
                                "zone": {
                                    "environment": {
                                        "name": "ISTIO_META_ZONE",
                                        "defaultValue": "fallback-zone"
                                    }
                                }
                            }
                        },
                        {
                            "customTags": {
                                "cluster": {"literal": {"value": "literal-cluster"}},
                                "region": {
                                    "environment": {
                                        "name": "FERRUM_REGION"
                                    }
                                },
                                "zone": {
                                    "header": {
                                        "name": "x-zone"
                                    }
                                }
                            }
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert_eq!(
            tracing.custom_tags.get("cluster").map(String::as_str),
            Some("literal-cluster")
        );
        assert!(!tracing.custom_env_tags.contains_key("cluster"));
        assert!(!tracing.custom_tags.contains_key("region"));
        assert_eq!(
            tracing.custom_env_tags.get("region").map(String::as_str),
            Some("FERRUM_REGION")
        );
        assert!(!tracing.custom_tags.contains_key("zone"));
        assert!(!tracing.custom_env_tags.contains_key("zone"));
        assert_eq!(
            tracing.custom_header_tags.get("zone").map(String::as_str),
            Some("x-zone")
        );
    }

    #[test]
    fn telemetry_tracing_entries_merge_custom_tags_and_providers() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [
                        {
                            "randomSamplingPercentage": 15.0,
                            "customTags": {
                                "env": {"literal": {"value": "staging"}},
                                "mesh": {"literal": {"value": "ferrum"}}
                            },
                            "providers": [{
                                "name": "zipkin",
                                "url": "http://zipkin:9411/api/v2/spans"
                            }]
                        },
                        {
                            "customTags": {
                                "env": {"literal": {"value": "prod"}},
                                "region": {"literal": {"value": "us-east"}}
                            },
                            "providers": [{
                                "name": "opentelemetry",
                                "endpoint": "http://otel:4318/v1/traces"
                            }]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert_eq!(tracing.sampling_percentage, Some(15.0));
        assert_eq!(
            tracing.custom_tags.get("env").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            tracing.custom_tags.get("mesh").map(String::as_str),
            Some("ferrum")
        );
        assert_eq!(
            tracing.custom_tags.get("region").map(String::as_str),
            Some("us-east")
        );
        assert_eq!(tracing.providers.len(), 2);
        assert!(matches!(
            tracing.providers.first(),
            Some(TracingProvider::Zipkin { .. })
        ));
        assert!(matches!(
            tracing.providers.get(1),
            Some(TracingProvider::OpenTelemetry { .. })
        ));
    }

    #[test]
    fn telemetry_tracing_rejects_invalid_sampling_percentage() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{"randomSamplingPercentage": 150.0}]
                }),
            )],
            options(),
        )
        .expect_err("out-of-range sampling should fail closed");

        assert!(
            err.to_string()
                .contains("randomSamplingPercentage must be between 0 and 100"),
            "got: {err}"
        );

        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{"randomSamplingPercentage": "100"}]
                }),
            )],
            options(),
        )
        .expect_err("non-numeric sampling should fail closed");

        assert!(
            err.to_string()
                .contains("randomSamplingPercentage must be a finite number"),
            "got: {err}"
        );
    }

    #[test]
    fn telemetry_access_log_filter_with_or_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.code >= 500 || response.duration >= 1000"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("OR filters should fail closed");

        assert!(err.to_string().contains("with '||' are not supported"));
    }

    #[test]
    fn telemetry_access_log_duration_gt_preserves_strict_semantics() {
        let filter = parse_access_log_filter_expression("response.duration > 100")
            .expect("filter parses")
            .expect("filter is present");

        assert_eq!(filter.min_latency_ms, Some(101));
    }

    #[test]
    fn telemetry_access_log_duration_unsupported_comparator_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.duration <= 100"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported duration comparator should fail closed");

        assert!(
            err.to_string()
                .contains("response.duration filters only support")
        );
    }

    #[test]
    fn telemetry_access_log_repeated_status_predicates_intersect() {
        let filter =
            parse_access_log_filter_expression("response.code >= 500 && response.code >= 400")
                .expect("filter parses")
                .expect("filter is present");

        assert_eq!(filter.status_code_min, Some(500));
        assert_eq!(filter.status_code_max, None);

        let filter =
            parse_access_log_filter_expression("response.code <= 599 && response.code <= 499")
                .expect("filter parses")
                .expect("filter is present");

        assert_eq!(filter.status_code_min, None);
        assert_eq!(filter.status_code_max, Some(499));
    }

    #[test]
    fn telemetry_access_log_repeated_duration_predicates_intersect() {
        let filter = parse_access_log_filter_expression(
            "response.duration >= 1000 && response.duration >= 500",
        )
        .expect("filter parses")
        .expect("filter is present");

        assert_eq!(filter.min_latency_ms, Some(1000));
    }

    #[test]
    fn telemetry_access_log_malformed_status_filter_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.code != 500"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed status filter should fail closed");

        assert!(
            err.to_string()
                .contains("response.code filter must use a numeric comparison")
        );
    }

    #[test]
    fn telemetry_tracing_zipkin_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin",
                            "url": "http://zipkin.istio-system:9411/api/v2/spans"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://zipkin.istio-system:9411/api/v2/spans");
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "agentUrl": "http://datadog-agent:8126",
                            "service": "reviews"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert_eq!(service.as_deref(), Some("reviews"));
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_snake_case_alias_still_accepted() {
        // Backward compat: operators who wrote against the first draft used
        // `agent_url`. The translator accepts both spellings so manifests
        // captured before the camelCase canonicalisation keep working.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "agent_url": "http://datadog-agent:8126"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert!(service.is_none(), "service omitted in manifest");
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_missing_agent_url_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "service": "reviews"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("missing required field should fail closed");

        let msg = err.to_string();
        assert!(
            msg.contains("datadog"),
            "error must mention provider: {msg}"
        );
        assert!(
            msg.contains("agentUrl"),
            "error must mention missing field: {msg}"
        );
    }

    #[test]
    fn telemetry_tracing_lightstep_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "lightstep",
                            "collectorUrl": "https://ingest.lightstep.com:443",
                            "accessTokenEnv": "LIGHTSTEP_ACCESS_TOKEN"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            provider @ TracingProvider::Lightstep {
                collector_url,
                access_token_env,
            } => {
                assert_eq!(collector_url, "https://ingest.lightstep.com:443");
                assert_eq!(access_token_env, "LIGHTSTEP_ACCESS_TOKEN");
                let debug = format!("{provider:?}");
                assert!(debug.contains("LIGHTSTEP_ACCESS_TOKEN"));
                let serialized = serde_json::to_string(provider).expect("provider serializes");
                assert!(serialized.contains("LIGHTSTEP_ACCESS_TOKEN"));
                assert!(!serialized.contains("secret-token"));
            }
            other => panic!("expected Lightstep, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_opentelemetry_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "opentelemetry",
                            "endpoint": "http://otel-collector.istio-system:4317"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            TracingProvider::OpenTelemetry { endpoint } => {
                assert_eq!(endpoint, "http://otel-collector.istio-system:4317");
            }
            other => panic!("expected OpenTelemetry, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_without_providers_block_has_no_provider() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "randomSamplingPercentage": 25.0
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert_eq!(tracing.sampling_percentage, Some(25.0));
        assert!(
            tracing.providers.is_empty(),
            "providers omitted, provider should be None"
        );
    }

    #[test]
    fn telemetry_tracing_unknown_provider_name_gracefully_skipped() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "stackdriver",
                            "endpoint": "https://example.com"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("unknown provider name should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.providers.is_empty(),
            "unrecognised provider name should be skipped, not surfaced"
        );
    }

    #[test]
    fn telemetry_tracing_name_only_reference_gracefully_skipped() {
        // Standard Istio pattern: providers[].name references a
        // meshConfig.extensionProviders entry with no inline fields.
        // Without a root meshConfig registry entry, the translator should
        // gracefully skip these rather than failing.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("name-only reference should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.providers.is_empty(),
            "name-only reference should be skipped when extensionProviders lookup misses"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("unknown meshConfig extensionProvider 'zipkin'")),
            "unknown name-only provider should produce an operator-visible warning"
        );
    }

    #[test]
    fn telemetry_tracing_name_only_reference_resolves_from_mesh_config() {
        let result = translate_k8s_objects(
            &[
                object(
                    "Telemetry",
                    serde_json::json!({
                        "tracing": [{
                            "providers": [{
                                "name": "zipkin-prod"
                            }]
                        }]
                    }),
                ),
                istio_mesh_config(
                    r#"
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
"#,
                ),
            ],
            options(),
        )
        .expect("meshConfig-backed provider reference should translate");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        match tracing.providers.first().expect("provider translated") {
            TracingProvider::Zipkin { url } => {
                assert_eq!(
                    url,
                    "http://zipkin.istio-system.svc.cluster.local:9411/api/v2/spans"
                );
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
        assert!(
            result.warnings.is_empty(),
            "resolved meshConfig provider should not warn: {:?}",
            result.warnings
        );
    }

    #[test]
    fn telemetry_tracing_default_provider_resolves_from_mesh_config() {
        let result = translate_k8s_objects(
            &[
                istio_mesh_config(
                    r#"
defaultProviders:
  tracing:
  - otel-default
extensionProviders:
- name: otel-default
  opentelemetry:
    service: otel-collector.istio-system.svc.cluster.local
    port: 4318
"#,
                ),
                object(
                    "Telemetry",
                    serde_json::json!({
                        "tracing": [{
                            "randomSamplingPercentage": 25.0
                        }]
                    }),
                ),
            ],
            options(),
        )
        .expect("meshConfig default provider should translate");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert_eq!(tracing.sampling_percentage, Some(25.0));
        match tracing
            .providers
            .first()
            .expect("default provider translated")
        {
            TracingProvider::OpenTelemetry { endpoint } => {
                assert_eq!(
                    endpoint,
                    "http://otel-collector.istio-system.svc.cluster.local:4318"
                );
            }
            other => panic!("expected OpenTelemetry, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_custom_extension_provider_name_gracefully_skipped() {
        // Custom extensionProvider names like "my-zipkin" are valid Istio
        // references but not one of the four inline provider types.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "my-zipkin"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("custom provider name should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.providers.is_empty(),
            "custom extensionProvider reference should be skipped"
        );
    }

    #[test]
    fn telemetry_tracing_multiple_providers_surfaces_all_inline_entries() {
        // Istio's Telemetry CRD allows `providers[]` to list multiple entries.
        // Ferrum fans out spans to every inline provider while still allowing
        // name-only meshConfig references to resolve through the registry.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [
                            {
                                "name": "zipkin",
                                "url": "http://zipkin.istio-system:9411/api/v2/spans"
                            },
                            {
                                "name": "datadog",
                                "agentUrl": "http://datadog-agent:8126"
                            }
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert_eq!(tracing.providers.len(), 2);
        match &tracing.providers[0] {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://zipkin.istio-system:9411/api/v2/spans");
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
        match &tracing.providers[1] {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert!(service.is_none());
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_provider_without_sampling_still_surfaces() {
        // Provider configuration is independent from sampling. A Telemetry
        // block with only `providers[]` (no `randomSamplingPercentage`)
        // should still surface the provider — sampling is allowed to come
        // from a less-specific Telemetry resource via merge_tracing_config.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin",
                            "url": "http://zipkin.istio-system:9411/api/v2/spans"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.sampling_percentage.is_none(),
            "sampling omitted in manifest"
        );
        assert!(
            !tracing.providers.is_empty(),
            "provider should surface independently of sampling"
        );
    }

    #[test]
    fn telemetry_tracing_disable_span_reporting_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "disableSpanReporting": true,
                        "providers": [{
                            "name": "opentelemetry",
                            "endpoint": "http://otel-collector:4318/v1/traces"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert_eq!(tracing.disable_span_reporting, Some(true));
        assert_eq!(tracing.providers.len(), 1);
    }

    #[test]
    fn telemetry_tracing_client_and_server_modes_both_carry_providers() {
        // GAP-3F: both CLIENT and SERVER entries flow through the translator;
        // the merged mode becomes CLIENT_AND_SERVER and providers from both
        // sides accumulate so each can fire on the matching listener.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [
                        {
                            "match": {"mode": "CLIENT"},
                            "providers": [{
                                "name": "zipkin",
                                "url": "http://client-zipkin:9411/api/v2/spans"
                            }]
                        },
                        {
                            "match": {"mode": "SERVER"},
                            "providers": [{
                                "name": "zipkin",
                                "url": "http://server-zipkin:9411/api/v2/spans"
                            }]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config emitted");
        assert_eq!(tracing.mode, Some(TelemetryTracingMode::ClientAndServer));
        let urls: Vec<&str> = tracing
            .providers
            .iter()
            .filter_map(|p| match p {
                TracingProvider::Zipkin { url } => Some(url.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            urls.contains(&"http://client-zipkin:9411/api/v2/spans"),
            "CLIENT-side provider must survive translation: {urls:?}"
        );
        assert!(
            urls.contains(&"http://server-zipkin:9411/api/v2/spans"),
            "SERVER-side provider must survive translation: {urls:?}"
        );
    }

    #[test]
    fn telemetry_tracing_client_and_server_mode_keeps_provider_and_resolves_mode() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "match": {"mode": "CLIENT_AND_SERVER"},
                        "providers": [{
                            "name": "zipkin",
                            "url": "http://shared-zipkin:9411/api/v2/spans"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config emitted");
        assert_eq!(tracing.mode, Some(TelemetryTracingMode::ClientAndServer));
        match tracing
            .providers
            .first()
            .expect("shared provider translated")
        {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://shared-zipkin:9411/api/v2/spans");
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
    }

    #[test]
    fn translates_request_authentication_with_empty_jwt_rules() {
        let result = translate_k8s_objects(
            &[object("RequestAuthentication", serde_json::json!({}))],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications.len(), 1);
        assert!(mesh.request_authentications[0].jwt_rules.is_empty());
    }

    #[test]
    fn translates_request_authentication_with_inline_jwks() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwks": "{\"keys\":[{\"kty\":\"RSA\"}]}"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let rule = &mesh.request_authentications[0].jwt_rules[0];
        assert!(rule.jwks_uri.is_none());
        assert_eq!(rule.jwks.as_deref(), Some("{\"keys\":[{\"kty\":\"RSA\"}]}"));
    }

    #[test]
    fn translates_request_authentication_multiple_jwt_rules() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [
                        {
                            "issuer": "https://first.example.com",
                            "jwksUri": "https://first.example.com/jwks"
                        },
                        {
                            "issuer": "https://second.example.com",
                            "jwksUri": "https://second.example.com/jwks",
                            "audiences": ["aud-a", "aud-b"]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications[0].jwt_rules.len(), 2);
        assert_eq!(
            mesh.request_authentications[0].jwt_rules[0].issuer,
            "https://first.example.com"
        );
        assert_eq!(
            mesh.request_authentications[0].jwt_rules[1].audiences,
            vec!["aud-a", "aud-b"]
        );
    }

    #[test]
    fn rejects_request_authentication_jwt_rule_without_issuer() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "jwksUri": "https://example.com/jwks"
                    }]
                }),
            )],
            options(),
        )
        .expect_err("missing issuer must fail");

        assert!(err.to_string().contains("issuer is required"));
    }

    #[test]
    fn translates_request_authentication_no_warning_emitted() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwksUri": "https://auth.example.com/jwks"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // Should NOT emit a warning now that it's fully translated
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("RequestAuthentication"))
        );
    }

    // ── DestinationRule ────────────────────────────────────────────────

    #[test]
    fn translates_destination_rule_connection_pool() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "connectTimeout": "5s"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.destination_rules.len(), 1);
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.host, "reviews.default.svc.cluster.local");
        let tp = dr.traffic_policy.as_ref().expect("traffic policy");
        assert_eq!(tp.connect_timeout_ms, Some(5000));
    }

    #[test]
    fn translates_destination_rule_outlier_detection() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "consecutive5xxErrors": 5,
                            "interval": "10s",
                            "baseEjectionTime": "30s",
                            "maxEjectionPercent": 50
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let od = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .outlier_detection
            .as_ref()
            .expect("outlier detection");
        assert_eq!(od.consecutive_errors, Some(5));
        assert_eq!(od.interval_seconds, Some(10));
        assert_eq!(od.base_ejection_seconds, Some(30));
        assert_eq!(od.max_ejection_percent, Some(50));
    }

    #[test]
    fn translates_destination_rule_lb_round_robin() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "ROUND_ROBIN"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)
        ));
    }

    #[test]
    fn translates_destination_rule_lb_least_request() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "LEAST_REQUEST"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)
        ));
    }

    #[test]
    fn translates_destination_rule_lb_random() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "RANDOM"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(lb, MeshLoadBalancer::Simple(MeshSimpleLb::Random)));
    }

    #[test]
    fn translates_destination_rule_consistent_hash_header() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "httpHeaderName": "x-user-id"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        match lb {
            MeshLoadBalancer::ConsistentHash(ch) => {
                assert_eq!(ch.http_header_name.as_deref(), Some("x-user-id"));
                assert!(!ch.use_source_ip);
            }
            _ => panic!("expected consistent hash"),
        }
    }

    #[test]
    fn translates_destination_rule_consistent_hash_source_ip() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "useSourceIp": true
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        match lb {
            MeshLoadBalancer::ConsistentHash(ch) => {
                assert!(ch.use_source_ip);
            }
            _ => panic!("expected consistent hash"),
        }
    }

    #[test]
    fn translates_destination_rule_subsets() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [
                        {
                            "name": "v1",
                            "labels": {"version": "v1"}
                        },
                        {
                            "name": "v2",
                            "labels": {"version": "v2"},
                            "trafficPolicy": {
                                "loadBalancer": {"simple": "RANDOM"}
                            }
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.destination_rules[0].subsets.len(), 2);
        assert_eq!(mesh.destination_rules[0].subsets[0].name, "v1");
        assert_eq!(
            mesh.destination_rules[0].subsets[0].labels.get("version"),
            Some(&"v1".to_string())
        );
        assert!(
            mesh.destination_rules[0].subsets[0]
                .traffic_policy
                .is_none()
        );
        assert_eq!(mesh.destination_rules[0].subsets[1].name, "v2");
        assert!(
            mesh.destination_rules[0].subsets[1]
                .traffic_policy
                .is_some()
        );
    }

    #[test]
    fn destination_rule_rejects_missing_host() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "RANDOM"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("missing host must fail");

        assert!(err.to_string().contains("requires spec.host"));
    }

    #[test]
    fn destination_rule_rejects_unsupported_lb() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "MAGLEV"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unsupported LB must fail");

        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn destination_rule_rejects_outlier_ejection_percent_above_100() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "maxEjectionPercent": 101
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("invalid max ejection percent must fail");

        assert!(
            err.to_string()
                .contains("outlierDetection.maxEjectionPercent must be 0-100")
        );
    }

    #[test]
    fn destination_rule_rejects_subset_without_name() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{"labels": {"version": "v1"}}]
                }),
            )],
            options(),
        )
        .expect_err("subset without name must fail");

        assert!(err.to_string().contains("subset requires a name"));
    }

    #[test]
    fn destination_rule_no_warning_emitted() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("DestinationRule"))
        );
    }

    #[test]
    fn destination_rule_host_is_lowercased() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "Reviews.Default.SVC.Cluster.Local"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0].host,
            "reviews.default.svc.cluster.local"
        );
    }

    #[test]
    fn destination_rule_connect_timeout_ms_format() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "api.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "connectTimeout": "100ms"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tp = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy");
        assert_eq!(tp.connect_timeout_ms, Some(100));
    }

    #[test]
    fn destination_rule_rejects_empty_host() {
        let err = translate_k8s_objects(
            &[object("DestinationRule", serde_json::json!({"host": ""}))],
            options(),
        )
        .expect_err("empty host must fail");
        assert!(err.to_string().contains("non-empty hostname"));
    }

    #[test]
    fn destination_rule_rejects_dot_only_host() {
        let err = translate_k8s_objects(
            &[object("DestinationRule", serde_json::json!({"host": "."}))],
            options(),
        )
        .expect_err("dot-only host must fail");
        assert!(err.to_string().contains("non-empty hostname"));
    }

    #[test]
    fn destination_rule_lb_least_conn_alias_translates() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "LEAST_CONN"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)
        ));
    }

    #[test]
    fn destination_rule_consistent_hash_rejects_multiple_options() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "httpHeaderName": "x-user-id",
                                "useSourceIp": true
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("multi-option consistentHash must fail");
        assert!(err.to_string().contains("must set exactly one"));
    }

    #[test]
    fn destination_rule_consistent_hash_rejects_no_options() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("empty consistentHash must fail");
        assert!(err.to_string().contains("requires one of"));
    }

    #[test]
    fn destination_rule_passthrough_emits_warning() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "PASSTHROUGH"}
                    }
                }),
            )],
            options(),
        )
        .expect("PASSTHROUGH translates with warning");
        assert!(
            result.warnings.iter().any(|w| w.contains("PASSTHROUGH")
                && w.contains("original destination")
                && w.contains("round-robin")),
            "expected PASSTHROUGH true-passthrough-with-RR-fallback warning, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_subset_connect_timeout_applied_threshold_only_outlier_no_warn() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "connectionPool": {"tcp": {"connectTimeout": "5s"}},
                            "outlierDetection": {"consecutive5xxErrors": 3}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("subset traffic policy still translates");

        // Per-subset connectTimeout is now applied (overrides backend connect
        // timeout for subset-bound proxies), so it carries onto the mesh DR
        // subset and is NOT warned as ignored.
        let mesh = result.config.mesh.as_ref().expect("mesh config");
        let subset_tp = mesh.destination_rules[0].subsets[0]
            .traffic_policy
            .as_ref()
            .expect("subset traffic policy translated");
        assert_eq!(
            subset_tp.connect_timeout_ms,
            Some(5000),
            "subset connectTimeout 5s translates to 5000ms on the mesh DR subset"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("subset 'v1'") && w.contains("connectTimeout")),
            "subset connectTimeout is applied now and must not warn, got {:?}",
            result.warnings
        );
        // A threshold-only subset outlierDetection (no maxEjectionPercent) is
        // fully applied per-subset, so it must NOT warn about the ejection cap.
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("subset 'v1'") && w.contains("outlierDetection")),
            "threshold-only subset outlierDetection must not warn, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_subset_outlier_max_ejection_percent_does_not_warn() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "outlierDetection": {
                                "consecutive5xxErrors": 3,
                                "maxEjectionPercent": 50
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("subset traffic policy translates");

        // The maxEjectionPercent *cap* is now applied per-subset (resolved with
        // the same per-port > per-subset > upstream precedence as the
        // thresholds), so a subset that sets it must NOT surface any residual
        // upstream-level-cap warning.
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("subset 'v1'") && w.contains("maxEjectionPercent")),
            "subset maxEjectionPercent is applied per-subset now and must not warn, got {:?}",
            result.warnings
        );
    }

    // -- VirtualService mirror / rewrite / redirect / L4 -----------------

    fn dispatch_plugin(result: &crate::config_sources::k8s::K8sTranslation) -> &PluginConfig {
        result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin")
    }

    fn dispatch_rules(plugin: &PluginConfig) -> &Vec<Value> {
        plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array")
    }

    #[test]
    fn virtual_service_mirror_emits_request_mirror_plugin() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "mirror": {"host": "shadow.default.svc.cluster.local", "port": {"number": 9090}},
                        "mirrorPercentage": {"value": 25.0}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mirror = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "request_mirror")
            .expect("request_mirror plugin emitted for http[].mirror");
        assert_eq!(
            mirror.config["mirror_host"].as_str(),
            Some("shadow.default.svc.cluster.local")
        );
        assert_eq!(mirror.config["mirror_port"].as_u64(), Some(9090));
        assert_eq!(mirror.config["percentage"].as_f64(), Some(25.0));
        // The mirror plugin is proxy-scoped to the route's proxy.
        assert_eq!(
            mirror.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        // The mirror plugin config must construct cleanly.
        crate::plugins::validate_plugin_config("request_mirror", &mirror.config)
            .expect("emitted request_mirror config is valid");
    }

    #[test]
    fn virtual_service_zero_percent_mirror_emits_no_plugin() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "mirror": {"host": "shadow.default.svc.cluster.local", "port": {"number": 9090}},
                        "mirrorPercentage": {"value": 0.0}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "request_mirror"),
            "0% mirror must not emit an inert plugin"
        );
    }

    #[test]
    fn virtual_service_mirror_missing_host_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "mirror": {"port": {"number": 9090}}
                    }]
                }),
            )],
            options(),
        )
        .expect_err("mirror without host must fail closed");
        assert!(format!("{err}").contains("mirror.host"), "got: {err}");
    }

    #[test]
    fn virtual_service_rewrite_uri_projects_onto_dispatch_rule() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "rewrite": {"uri": "/v2", "authority": "internal.example.com"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let rewrite = rules
            .iter()
            .find_map(|r| r.get("rewrite"))
            .expect("a rule carries the rewrite action");
        assert_eq!(rewrite["uri"].as_str(), Some("/v2"));
        assert_eq!(rewrite["authority"].as_str(), Some("internal.example.com"));
        // The match was a prefix, so prefix-rewrite semantics apply.
        assert_eq!(rewrite["match_prefix"].as_str(), Some("/api"));
        // The emitted config must construct cleanly.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        MeshRouteDispatch::new(&plugin.config).expect("rewrite dispatch config is valid");
    }

    #[test]
    fn virtual_service_rewrite_exact_match_replaces_whole_path() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"exact": "/legacy"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "rewrite": {"uri": "/v2"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let rewrite = rules
            .iter()
            .find_map(|r| r.get("rewrite"))
            .expect("rewrite action present");
        // Exact match → no match_prefix → whole-path replacement.
        assert!(
            rewrite.get("match_prefix").is_none(),
            "exact match must not carry a prefix: {rewrite:?}"
        );
    }

    #[test]
    fn virtual_service_redirect_projects_onto_dispatch_rule() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "redirectCode": 302}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let redirect = rules
            .iter()
            .find_map(|r| r.get("redirect"))
            .expect("redirect action present");
        assert_eq!(redirect["uri"].as_str(), Some("/new"));
        assert_eq!(redirect["redirect_code"].as_u64(), Some(302));
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        MeshRouteDispatch::new(&plugin.config).expect("redirect dispatch config is valid");
    }

    #[test]
    fn virtual_service_redirect_rejects_out_of_range_redirect_code() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "redirectCode": 404}
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid redirectCode must fail closed");

        assert!(
            err.to_string()
                .contains("redirectCode must be in the 300-399 range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn virtual_service_redirect_projects_explicit_port() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "port": 8443}
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect.port must translate");
        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let redirect = rules
            .iter()
            .find_map(|r| r.get("redirect"))
            .expect("redirect action present");
        assert_eq!(redirect["uri"].as_str(), Some("/new"));
        assert_eq!(redirect["port"].as_u64(), Some(8443));
        assert!(redirect.get("derive_port").is_none());
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        MeshRouteDispatch::new(&plugin.config).expect("redirect dispatch config is valid");
    }

    #[test]
    fn virtual_service_redirect_projects_derive_port_from_request_port() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"derivePort": "FROM_REQUEST_PORT", "scheme": "https"}
                    }]
                }),
            )],
            options(),
        )
        .expect("redirect.derivePort must translate");
        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let redirect = rules
            .iter()
            .find_map(|r| r.get("redirect"))
            .expect("redirect action present");
        assert_eq!(redirect["derive_port"].as_str(), Some("FROM_REQUEST_PORT"));
        assert_eq!(redirect["scheme"].as_str(), Some("https"));
        assert!(redirect.get("port").is_none());
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        MeshRouteDispatch::new(&plugin.config).expect("redirect dispatch config is valid");
    }

    #[test]
    fn virtual_service_redirect_projects_derive_port_from_protocol_default() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {
                            "uri": "/secure",
                            "scheme": "https",
                            "derivePort": "FROM_PROTOCOL_DEFAULT"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("FROM_PROTOCOL_DEFAULT must translate");
        let plugin = dispatch_plugin(&result);
        let rules = dispatch_rules(plugin);
        let redirect = rules
            .iter()
            .find_map(|r| r.get("redirect"))
            .expect("redirect action present");
        assert_eq!(
            redirect["derive_port"].as_str(),
            Some("FROM_PROTOCOL_DEFAULT")
        );
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        MeshRouteDispatch::new(&plugin.config).expect("redirect dispatch config is valid");
    }

    #[test]
    fn virtual_service_redirect_rejects_port_and_derive_port_together() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"port": 8443, "derivePort": "FROM_REQUEST_PORT"}
                    }]
                }),
            )],
            options(),
        )
        .expect_err("port + derivePort must fail closed");
        assert!(
            err.to_string()
                .contains("port and derivePort are mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn virtual_service_redirect_rejects_invalid_port() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "port": 0}
                    }]
                }),
            )],
            options(),
        )
        .expect_err("port 0 must fail closed");
        assert!(
            err.to_string()
                .contains("redirect.port must be in the 1-65535 range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn virtual_service_redirect_rejects_unknown_derive_port() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"derivePort": "FROM_X_FORWARDED_PORT"}
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unknown derivePort must fail closed");
        assert!(
            err.to_string().contains("redirect.derivePort must be"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn virtual_service_redirect_port_update_and_delete() {
        // Create → update → delete across successive translations, matching the
        // K8s controller's full re-translate ownership model.
        let with_port = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "port": 8443}
                    }]
                }),
            )],
            options(),
        )
        .expect("create with port");
        let redirect = dispatch_rules(dispatch_plugin(&with_port))
            .iter()
            .find_map(|r| r.get("redirect").cloned())
            .expect("redirect present after create");
        assert_eq!(redirect["port"].as_u64(), Some(8443));

        let with_derive = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new", "derivePort": "FROM_REQUEST_PORT"}
                    }]
                }),
            )],
            options(),
        )
        .expect("update to derivePort");
        let redirect = dispatch_rules(dispatch_plugin(&with_derive))
            .iter()
            .find_map(|r| r.get("redirect").cloned())
            .expect("redirect present after update");
        assert_eq!(redirect["derive_port"].as_str(), Some("FROM_REQUEST_PORT"));
        assert!(redirect.get("port").is_none());

        let deleted = translate_k8s_objects(&[], options()).expect("delete VirtualService");
        assert!(
            deleted
                .config
                .plugin_configs
                .iter()
                .filter(|p| p.plugin_name == "mesh_route_dispatch")
                .all(|p| {
                    p.config
                        .get("rules")
                        .and_then(|r| r.as_array())
                        .into_iter()
                        .flatten()
                        .all(|rule| rule.get("redirect").is_none())
                }),
            "delete must drop redirect-bearing dispatch rules"
        );
        assert!(
            !deleted
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("/old")),
            "delete must drop the redirect proxy"
        );
    }

    #[test]
    fn virtual_service_tcp_route_materializes_stream_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["db.example.com"],
                    "tcp": [{
                        "match": [{"port": 3306}],
                        "route": [{"destination": {"host": "mysql.default.svc.cluster.local", "port": {"number": 3306}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("VirtualService L4 tcp routing now translates to a stream proxy");
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_port == Some(3306))
            .expect("tcp[] materializes a stream proxy on the matched port");
        assert_eq!(proxy.backend_host, "mysql.default.svc.cluster.local");
        assert_eq!(proxy.backend_port, 3306);
        assert_eq!(
            proxy.backend_scheme,
            Some(crate::config::types::BackendScheme::Tcp)
        );
        assert!(!proxy.passthrough, "plain tcp[] is not passthrough");
        assert!(
            proxy.listen_path.is_none(),
            "stream proxy has no listen_path"
        );
    }

    #[test]
    fn virtual_service_tls_route_materializes_passthrough_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["secure.example.com"],
                    "tls": [{
                        "match": [{"sniHosts": ["secure.example.com"]}],
                        "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 443}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("VirtualService L4 tls routing now translates to a passthrough proxy");
        // No match.port → listen port falls back to the destination port (443).
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_port == Some(443))
            .expect("tls[] materializes a passthrough proxy");
        assert!(proxy.passthrough, "tls[] SNI routing is passthrough");
        assert_eq!(proxy.hosts, vec!["secure.example.com".to_string()]);
        assert_eq!(proxy.backend_host, "backend.default.svc.cluster.local");
        assert_eq!(proxy.backend_port, 443);
    }

    #[test]
    fn virtual_service_tls_route_empty_match_fails_closed() {
        // An empty `match: []` on a tls[] route carries no sniHosts to key SNI
        // routing on. It must be rejected (same as a missing match) rather than
        // silently emitting no proxy while status reports the VS accepted.
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["secure.example.com"],
                    "tls": [{
                        "match": [],
                        "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 443}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("empty tls[] match must fail closed, not silently drop the route");
        assert!(
            format!("{err:?}").contains("non-empty match"),
            "expected a non-empty-match rejection, got {err:?}"
        );
    }

    #[test]
    fn virtual_service_l4_proxy_ids_do_not_collide_with_http_route_ids() {
        let http_vs = object_with_metadata(
            "VirtualService",
            "networking.istio.io/v1",
            "foo-tls",
            "default",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [
                        {"uri": {"prefix": "/v1"}},
                        {"uri": {"prefix": "/v2"}}
                    ],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                }]
            }),
        );
        let tls_vs = object_with_metadata(
            "VirtualService",
            "networking.istio.io/v1",
            "foo",
            "default",
            serde_json::json!({
                "hosts": ["secure.example.com"],
                "tls": [{
                    "match": [{"sniHosts": ["secure.example.com"], "port": 8443}],
                    "route": [{"destination": {"host": "secure.default.svc.cluster.local", "port": {"number": 443}}}]
                }]
            }),
        );

        let result = translate_k8s_objects(&[http_vs, tls_vs], options())
            .expect("HTTP and L4 VirtualServices translate without generated-ID shadowing");
        let ids: Vec<&str> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.id.as_str())
            .collect();

        assert!(
            ids.contains(&"istio-vs-default-foo-tls-0-0"),
            "HTTP route keeps its historical generated ID, got {ids:?}"
        );
        let l4_proxy = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_port == Some(8443))
            .expect("TLS stream proxy must materialize instead of being shadowed");
        assert_eq!(l4_proxy.backend_host, "secure.default.svc.cluster.local");
        assert!(
            l4_proxy
                .id
                .starts_with("istio-vs-l4_tls__default__foo__0-0"),
            "L4 proxy must use a boundary-safe ID namespace, got {}",
            l4_proxy.id
        );
    }

    #[test]
    fn virtual_service_l4_proxy_ids_use_managed_prefix() {
        // Generated L4 stream proxies must carry the `istio-vs-` managed prefix
        // so the K8s reconciler's cleanup allowlist removes them on VS
        // delete/change instead of leaking + duplicating across reconciles.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["secure.example.com"],
                    "tls": [{
                        "match": [{"sniHosts": ["secure.example.com"], "port": 8443}],
                        "route": [{"destination": {"host": "backend.default.svc.cluster.local", "port": {"number": 443}}}]
                    }],
                    "tcp": [{
                        "match": [{"port": 9000}],
                        "route": [{"destination": {"host": "raw.default.svc.cluster.local", "port": {"number": 9000}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("VS L4 routing translates");
        let l4: Vec<&str> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_port == Some(8443) || p.listen_port == Some(9000))
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(l4.len(), 2, "both L4 proxies materialize, got {l4:?}");
        for id in &l4 {
            assert!(
                id.starts_with("istio-vs-") && !id.starts_with("__"),
                "L4 proxy id must use the managed istio-vs- prefix for reconciler cleanup, got {id}"
            );
        }
    }

    // -- VirtualService fault injection / retry / timeout ----------------

    /// Extract the per-rule `fault` from the first rule of a
    /// `mesh_route_dispatch` plugin config. URI-only matches produce a
    /// single catch-all rule with `match: {}`; that rule's `fault` field
    /// is what we assert in the VS fault tests below.
    fn dispatch_rule_fault(plugin: &PluginConfig) -> &Value {
        assert_eq!(plugin.plugin_name, "mesh_route_dispatch");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        let rule = rules.first().expect("at least one rule");
        rule.get("fault").expect("rule should carry fault action")
    }

    #[test]
    fn virtual_service_extracts_route_local_fault_abort() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 50.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        // VS fault is now carried per dispatch rule rather than as a
        // separate proxy-scoped `fault_injection` plugin. The translator
        // emits exactly one plugin (mesh_route_dispatch) for the URI-only
        // catch-all rule.
        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        assert_eq!(plugin.plugin_name, "mesh_route_dispatch");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        let fault = dispatch_rule_fault(plugin);
        let abort = fault.get("abort").expect("abort sub-action");
        assert_eq!(abort["status_code"], 503);
        assert_eq!(abort["percentage"], 50.0);
    }

    #[test]
    fn virtual_service_extracts_route_local_fault_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "5s",
                                "percentage": {"value": 25.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let delay = fault.get("delay").expect("delay sub-action");
        assert_eq!(delay["duration_ms"], 5000);
        assert_eq!(delay["percentage"], 25.0);
    }

    #[test]
    fn virtual_service_extracts_route_local_fault_abort_and_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 500,
                                "percentage": {"value": 10.0}
                            },
                            "delay": {
                                "fixedDelay": "2s",
                                "percentage": {"value": 30.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        assert!(fault.get("abort").is_some());
        assert!(fault.get("delay").is_some());
        assert_eq!(fault["abort"]["status_code"], 500);
        assert_eq!(fault["delay"]["duration_ms"], 2000);
    }

    #[test]
    fn virtual_service_clamps_retries_to_ferrum_max() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 101,
                            "retryOn": "5xx"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config should be set");
        assert_eq!(retry.max_retries, MAX_RETRIES);
    }

    #[test]
    fn virtual_service_maps_retries_to_proxy_retry_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 3,
                            "retryOn": "5xx,connect-failure"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let proxy = &result.config.proxies[0];
        let retry = proxy.retry.as_ref().expect("retry config should be set");
        assert_eq!(retry.max_retries, 3);
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.contains(&500));
        assert!(retry.retryable_status_codes.contains(&502));
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&504));
    }

    #[test]
    fn virtual_service_maps_gateway_error_retry_on() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "gateway-error"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.max_retries, 2);
        assert!(retry.retryable_status_codes.contains(&502));
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&504));
        assert!(!retry.retryable_status_codes.contains(&500));
        assert!(!retry.retry_on_connect_failure);
    }

    #[test]
    fn virtual_service_retriable_status_codes_uses_explicit_codes() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "retriable-status-codes",
                            "retriableStatusCodes": [409, 425, 503, 700]
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.retryable_status_codes, vec![409, 425, 503]);
    }

    #[test]
    fn virtual_service_retry_5xx_covers_full_server_error_range() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 1,
                            "retryOn": "5xx"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.retryable_status_codes.len(), 100);
        assert!(retry.retryable_status_codes.contains(&500));
        assert!(retry.retryable_status_codes.contains(&599));
    }

    #[test]
    fn virtual_service_retry_5xx_allows_explicit_non_5xx_codes() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 1,
                            "retryOn": "5xx,400,401,403,404,connect-failure"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert_eq!(retry.retryable_status_codes.len(), 104);
        assert!(retry.retryable_status_codes.contains(&400));
        assert!(retry.retryable_status_codes.contains(&599));
        assert!(retry.retry_on_connect_failure);
        assert!(retry.validate_fields().is_ok());
    }

    #[test]
    fn virtual_service_zero_retry_attempts_produces_no_retry_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {"attempts": 0}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies[0].retry.is_none());
    }

    #[test]
    fn virtual_service_retries_without_retry_on_defaults_to_connect_retry() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 3
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert_eq!(retry.max_retries, 3);
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.is_empty());
    }

    #[test]
    fn virtual_service_retries_refused_stream_sets_connect_retry() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "refused-stream"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.is_empty());
    }

    #[test]
    fn virtual_service_retries_numeric_code_out_of_range_filtered() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 1,
                            "retryOn": "503,9999,42,418"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&418));
        assert!(!retry.retryable_status_codes.contains(&9999));
        assert!(!retry.retryable_status_codes.contains(&42));
    }

    #[test]
    fn virtual_service_maps_timeout_to_backend_read_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "5s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 5000);
    }

    #[test]
    fn virtual_service_clamps_timeout_to_ferrum_max() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "25h"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].backend_read_timeout_ms,
            MAX_TIMEOUT_MS
        );
    }

    #[test]
    fn virtual_service_maps_millisecond_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "500ms"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 500);
    }

    #[test]
    fn virtual_service_maps_fractional_second_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "1.5s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 1500);
    }

    #[test]
    fn virtual_service_timeout_extended_units() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "2m"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 120_000);
    }

    #[test]
    fn virtual_service_timeout_and_retry_combined() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "10s",
                        "retries": {"attempts": 2, "retryOn": "connect-failure,reset"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = &result.config.proxies[0];
        assert_eq!(proxy.backend_read_timeout_ms, 10_000);
        let retry = proxy.retry.as_ref().expect("retry config");
        assert_eq!(retry.max_retries, 2);
        assert!(retry.retry_on_connect_failure);
    }

    #[test]
    fn virtual_service_retry_shared_across_multiple_uri_matches() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/v1"}},
                            {"uri": {"prefix": "/v2"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {"attempts": 3, "retryOn": "5xx"},
                        "timeout": "3s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        for proxy in &result.config.proxies {
            assert_eq!(proxy.backend_read_timeout_ms, 3000);
            let retry = proxy.retry.as_ref().expect("retry config");
            assert_eq!(retry.max_retries, 3);
        }
    }

    #[test]
    fn virtual_service_no_fault_or_retry_or_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.plugin_configs.is_empty());
        assert!(result.config.proxies[0].retry.is_none());
        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 30_000);
    }

    #[test]
    fn virtual_service_weighted_destinations_with_retry() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 80},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}, "weight": 20}
                        ],
                        "retries": {"attempts": 2, "retryOn": "5xx"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.max_retries, 2);
    }

    #[test]
    fn virtual_service_fault_delay_ms_format() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "250ms",
                                "percent": 100.0
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let delay = fault.get("delay").expect("delay sub-action");
        assert_eq!(delay["duration_ms"], 250);
        assert_eq!(delay["percentage"], 100.0);
    }

    #[test]
    fn virtual_service_fault_delay_above_runtime_cap_is_clamped_and_warned() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "1h",
                                "percentage": {"value": 100.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        assert_eq!(fault["delay"]["duration_ms"], 60_000);
        assert_eq!(fault["delay"]["percentage"], 100.0);
        assert!(result.warnings.iter().any(|warning| {
            warning.contains("http[0].fault.delay.fixedDelay")
                && warning.contains("clamping")
                && warning.contains("60000 ms")
        }));
    }

    #[test]
    fn virtual_service_fault_abort_defaults_percentage_100() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let abort = fault.get("abort").expect("abort sub-action");
        assert_eq!(abort["percentage"], 100.0);
    }

    #[test]
    fn virtual_service_fault_abort_zero_percentage_skips_subfield() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.plugin_configs.is_empty());
    }

    #[test]
    fn virtual_service_fault_zero_abort_keeps_valid_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            },
                            "delay": {
                                "fixedDelay": "100ms",
                                "percentage": {"value": 25.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        assert!(fault.get("abort").is_none());
        let delay = fault.get("delay").expect("delay sub-action");
        assert_eq!(delay["duration_ms"], 100);
        assert_eq!(delay["percentage"], 25.0);
    }

    #[test]
    fn virtual_service_fault_ignores_invalid_generated_plugin_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/zero-delay"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "0s",
                                "percentage": {"value": 100.0}
                            }
                        }
                    }, {
                        "match": [{"uri": {"prefix": "/zero-percent"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            }
                        }
                    }, {
                        "match": [{"uri": {"prefix": "/bad-percent"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percent": 101.0
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 3);
        assert!(result.config.plugin_configs.is_empty());
    }

    #[test]
    fn virtual_service_fault_abort_grpc_status_string() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 200,
                                "grpcStatus": "UNAVAILABLE",
                                "percentage": {"value": 30.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let abort = fault.get("abort").expect("abort sub-action");
        assert_eq!(abort["grpc_status"], 14);
        assert_eq!(abort["status_code"], 200);
    }

    #[test]
    fn virtual_service_fault_abort_grpc_status_numeric() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 200,
                                "grpcStatus": 13,
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let abort = fault.get("abort").expect("abort sub-action");
        assert_eq!(abort["grpc_status"], 13);
    }

    #[test]
    fn virtual_service_fault_abort_invalid_grpc_status_dropped() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "grpcStatus": "NOT_A_REAL_CODE",
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let fault = dispatch_rule_fault(plugin);
        let abort = fault.get("abort").expect("abort sub-action");
        assert!(abort.get("grpc_status").is_none());
        assert_eq!(abort["status_code"], 503);
    }

    #[test]
    fn virtual_service_fault_plugin_scoped_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        assert_eq!(plugin.plugin_name, "mesh_route_dispatch");
        assert!(matches!(
            plugin.scope,
            crate::config::types::PluginScope::Proxy
        ));
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert!(
            proxy_has_plugin(&result.config.proxies[0], plugin),
            "generated mesh_route_dispatch config must be associated with the proxy or PluginCache will not instantiate it"
        );
        // The route-local fault must ride on the dispatch rule.
        let fault = dispatch_rule_fault(plugin);
        assert_eq!(fault["abort"]["status_code"], 503);
    }

    // -- mesh_route_dispatch ----------------------------------------------

    #[test]
    fn virtual_service_method_match_emits_plugin_by_default() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "GET"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted");
        assert!(matches!(
            plugin.scope,
            crate::config::types::PluginScope::Proxy
        ));
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| plugin.proxy_id.as_deref() == Some(p.id.as_str()))
            .expect("plugin proxy exists");
        assert!(
            proxy_has_plugin(proxy, plugin),
            "generated mesh_route_dispatch config must be associated with its proxy"
        );
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        let methods = rules[0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        assert_eq!(methods[0].as_str(), Some("GET"));
        // VirtualService match semantics: requests that miss the predicates
        // must NOT fall through to the proxy's default backend.
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "VS-emitted mesh_route_dispatch must enforce match semantics via reject_unmatched"
        );
    }

    #[test]
    fn virtual_service_method_match_preserves_exact_case() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "get"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        let methods = rules[0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        assert_eq!(methods[0].as_str(), Some("get"));
    }

    #[test]
    fn virtual_service_method_regex_match_emits_plugin_with_tagged_regex() {
        // T1-B.2: VirtualService `method.regex` is now a first-class
        // mesh_route_dispatch predicate. The translator must emit the
        // tagged `{regex: "..."}` shape, NOT the legacy bare-string form
        // (which would compile as Exact), and the plugin construction must
        // succeed (regex compiled at config load time, not per request).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"regex": "^(POST|PUT|PATCH)$"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for regex method");
        let methods = plugin.config["rules"][0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        assert_eq!(methods.len(), 1);
        let method_entry = &methods[0];
        assert!(
            method_entry.is_object(),
            "regex method must emit as tagged StringMatch object, got: {method_entry}"
        );
        assert_eq!(
            method_entry["regex"].as_str(),
            Some("^(POST|PUT|PATCH)$"),
            "regex predicate must round-trip the pattern literally"
        );
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "method regex must NOT cause fail-closed request_termination anymore"
        );

        // The plugin must load successfully from the translator's JSON shape
        // (regex compiled at config-load time). A bad shape would error here.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_method_prefix_match_emits_plugin_with_tagged_prefix() {
        // T1-B.2 sibling of the regex case: `prefix` method matchers are
        // also now first-class. Tagged shape required for the plugin to
        // pick the Prefix matcher arm instead of Exact.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"prefix": "PO"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for prefix method");
        let methods = plugin.config["rules"][0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        let method_entry = &methods[0];
        assert!(
            method_entry.is_object(),
            "prefix method must emit as tagged StringMatch object, got: {method_entry}"
        );
        assert_eq!(method_entry["prefix"].as_str(), Some("PO"));

        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_uri_only_match_does_not_emit_plugin() {
        // URI-only matches still get the env-var path translated, but no
        // mesh_route_dispatch plugin is emitted because there are no
        // non-URI predicates.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|p| p.plugin_name != "mesh_route_dispatch"),
            "URI-only match should not emit mesh_route_dispatch"
        );
    }

    #[test]
    fn virtual_service_regex_uri_with_ignored_predicates_fails_closed() {
        // Unsupported non-URI match shapes (regex method/header/queryParam)
        // cannot be enforced by mesh_route_dispatch. A match entry with URI
        // plus only unsupported predicate types must not materialize a naked
        // URI proxy, because that would forward every regex-URI request
        // without the method/header/query gates.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"regex": "/v[0-9]+/api"},
                            "method": {"regex": "GET|POST"},
                            "headers": {"x-canary": {"regex": "v[0-9]+"}},
                            "queryParams": {"variant": {"regex": "beta|stable"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|p| p.plugin_name != "mesh_route_dispatch"),
            "URI plus ignored predicates should not emit mesh_route_dispatch"
        );
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("~/v[0-9]+/api"))
            .expect("URI plus unsupported predicates materializes a terminating proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("unsupported predicates attach a termination plugin");
        assert!(proxy_has_plugin(proxy, plugin));
    }

    #[test]
    fn virtual_service_header_match_emits_plugin_with_headers() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted");
        let headers = &plugin.config["rules"][0]["match"]["headers"];
        assert_eq!(headers["x-canary"].as_str(), Some("v2"));
    }

    #[test]
    fn virtual_service_header_regex_match_emits_plugin_with_tagged_regex() {
        // T1-B.1: VirtualService `headers.X.regex` is now a first-class
        // mesh_route_dispatch predicate. The translator must emit the
        // tagged `{regex: "..."}` shape, NOT the legacy bare-string form
        // (which would compile as Exact), and the plugin construction must
        // succeed (regex compiled at config load time, not per request).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-user": {"regex": "^admin-.*"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for regex header");
        let header_value = &plugin.config["rules"][0]["match"]["headers"]["x-user"];
        assert!(
            header_value.is_object(),
            "regex header must emit as tagged StringMatch object, got: {header_value}"
        );
        assert_eq!(
            header_value["regex"].as_str(),
            Some("^admin-.*"),
            "regex predicate must round-trip the pattern literally"
        );
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "header regex must NOT cause fail-closed request_termination anymore"
        );

        // The plugin must load successfully from the translator's JSON shape
        // (regex compiled at config-load time). A bad shape would error here.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_header_prefix_match_emits_plugin_with_tagged_prefix() {
        // T1-B.1 sibling of the regex case: `prefix` header matchers are
        // also now first-class. Tagged shape required for the plugin to
        // pick the Prefix matcher arm instead of Exact.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-tenant": {"prefix": "admin-"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for prefix header");
        let header_value = &plugin.config["rules"][0]["match"]["headers"]["x-tenant"];
        assert!(
            header_value.is_object(),
            "prefix header must emit as tagged StringMatch object, got: {header_value}"
        );
        assert_eq!(header_value["prefix"].as_str(), Some("admin-"));

        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_mixed_uri_only_and_header_match_disables_reject_unmatched() {
        // Codex P1 (#3237393205): a VirtualService whose `match[]` mixes a
        // URI-only branch with a URI+header branch on the same URI must let
        // plain `/api` requests fall through to the proxy's default backend.
        // Istio `match[]` entries are ORed -- the URI-only entry is an
        // unconditional catch-all for this listen_path. With
        // `reject_unmatched: true` the silently dropped URI-only branch
        // turned legitimate traffic into 404s.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should still be emitted to surface predicates");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "URI-only sibling does not become a rule; the header branch does"
        );
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "URI-only catch-all sibling must disable reject_unmatched so plain `/api` traffic still reaches the default backend"
        );
    }

    #[test]
    fn virtual_service_match_rules_scoped_to_listen_path() {
        // Codex P1 (#3232888791): match entries from a sibling URI branch
        // must not bleed into a path-specific proxy. A `match[]` with
        // `[{uri:/api}, {uri:/v2, headers:...}]` produces two proxies
        // (`/api`, `/v2`); the header rule belongs only to the `/v2`
        // proxy. Without scoping, the `/v2` header rule fires on `/api`
        // requests too, violating VirtualService semantics.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {
                                "uri": {"prefix": "/v2"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let api_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        let v2_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/v2"))
            .expect("/v2 proxy");

        // The /api branch is URI-only -- no rule applies to this proxy and
        // every request matches the unconditional URI branch, so we emit
        // no plugin at all (would-be plugin has zero rules).
        let api_plugin = result.config.plugin_configs.iter().find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(api_proxy.id.as_str())
        });
        assert!(
            api_plugin.is_none(),
            "/api proxy has only a URI-only branch -- no mesh_route_dispatch plugin should be emitted"
        );

        // The /v2 branch has a header predicate. Its proxy must get a
        // plugin with the header rule AND `reject_unmatched: true` (no
        // URI-only sibling in scope for this listen_path).
        let v2_plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
            })
            .expect("/v2 proxy mesh_route_dispatch plugin");
        let v2_rules = v2_plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert_eq!(v2_rules.len(), 1, "/v2 proxy sees only its own header rule");
        assert_eq!(
            v2_rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            v2_plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "/v2 has no URI-only sibling -- reject_unmatched stays on so traffic without x-canary 404s"
        );
    }

    #[test]
    fn virtual_service_unsupported_sibling_predicate_does_not_disable_reject_unmatched() {
        // Codex P1 (#3237631705): a `match[]` mixing one supported
        // `method.exact` rule with one unsupported sibling rule must NOT
        // collapse the unsupported entry onto the URI-only catch-all
        // branch. Doing so would flip `reject_unmatched` to false and
        // forward requests the operator gated (e.g., requests sneaking past
        // a route that only allows GET via `.exact` and hoped to allow
        // matching traffic via a sibling predicate the translator does not
        // honor). `method.regex` is now first-class supported (T1-B.2) and
        // `authority` is now first-class supported (T1-B.3); use
        // `sourceLabels` here (still unsupported -- sibling PRs cover
        // `sourceNamespace` / `ignoreUriCase` separately) to keep
        // exercising the fail-closed sibling path.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "method": {"exact": "GET"}},
                            {"uri": {"prefix": "/api"}, "sourceLabels": {"app": "billing"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for the GET branch");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "supported method.exact rule emitted; unsupported sourceLabels sibling skipped"
        );
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported predicate sibling must NOT relax reject_unmatched -- gated traffic should 404 instead of leaking through"
        );
    }

    #[test]
    fn virtual_service_authority_exact_match_emits_plugin_with_bare_string() {
        // T1-B.3: VirtualService `authority.exact` is now a first-class
        // mesh_route_dispatch predicate. The translator emits the
        // bare-string back-compat form for `exact` (matching how header
        // and method `exact` matchers are emitted), and the plugin
        // construction must succeed (predicate compiled at config-load
        // time, not per request).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com", "*.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "authority": {"exact": "internal.example.com"}
                        }],
                        "route": [{"destination": {"host": "internal.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for authority predicate");
        let authority_value = &plugin.config["rules"][0]["match"]["authority"];
        assert!(
            authority_value.is_string(),
            "exact authority must emit as bare string for wire back-compat, got: {authority_value}"
        );
        assert_eq!(authority_value.as_str(), Some("internal.example.com"));
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "authority exact must NOT cause fail-closed request_termination anymore"
        );

        // The plugin must load successfully from the translator's JSON shape.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_authority_prefix_match_emits_plugin_with_tagged_prefix() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["*.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "authority": {"prefix": "api."}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for prefix authority");
        let authority_value = &plugin.config["rules"][0]["match"]["authority"];
        assert!(
            authority_value.is_object(),
            "prefix authority must emit as tagged StringMatch object, got: {authority_value}"
        );
        assert_eq!(authority_value["prefix"].as_str(), Some("api."));

        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_authority_regex_match_emits_plugin_with_tagged_regex() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["*.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "authority": {"regex": "^api\\.(prod|staging)\\.example\\.com$"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for regex authority");
        let authority_value = &plugin.config["rules"][0]["match"]["authority"];
        assert!(
            authority_value.is_object(),
            "regex authority must emit as tagged StringMatch object, got: {authority_value}"
        );
        assert_eq!(
            authority_value["regex"].as_str(),
            Some("^api\\.(prod|staging)\\.example\\.com$"),
            "regex predicate must round-trip the pattern literally"
        );

        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_uri_less_authority_only_match_materializes_catch_all_proxy() {
        // An `http.match[]` that contains only an `authority` predicate (no
        // URI) is now legitimate, just like the header-only catch-all case
        // already documented above: it routes "any URI with this authority"
        // on the listed hosts. Without first-class authority support, this
        // would have been silently dropped via the unsupported-key list.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["*.example.com"],
                    "http": [{
                        "match": [
                            {"authority": {"prefix": "api."}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // A URI-less, supported-predicate catch-all proxy materializes
        // and carries the mesh_route_dispatch plugin so the authority
        // predicate is actually enforced.
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin must be emitted for authority-only catch-all");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1, "single authority-only rule emitted");
        assert_eq!(
            rules[0]["match"]["authority"]["prefix"].as_str(),
            Some("api.")
        );
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "authority-only predicate must NOT cause fail-closed request_termination"
        );
    }

    #[test]
    fn virtual_service_unsupported_authority_shape_still_fails_closed() {
        // An `authority` value whose shape is not a StringMatch (e.g., a
        // bare string in the VS spec, which Istio's CRD does not accept,
        // or a typo'd operator) is treated as unsupported so the route
        // falls closed via `request_termination` rather than silently
        // accepting the route as URI-only.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "authority": "internal.example.com"}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // The unsupported-shape entry should NOT yield a mesh_route_dispatch
        // rule; instead the URI proxy is guarded by a request_termination so
        // gated traffic doesn't sneak through.
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        assert!(
            result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            }),
            "non-StringMatch authority shape must fail closed"
        );
    }

    #[test]
    fn virtual_service_unsupported_authority_operator_still_fails_closed() {
        // An `authority` object whose only operator is not in the
        // supported set (`exact` / `prefix` / `regex`) is treated as
        // unsupported. Istio does not expose other operators today, but
        // future-proofing here means an unknown operator can't leak past
        // the gate.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "authority": {"contains": "internal"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        assert!(
            result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            }),
            "unknown authority operator must fail closed"
        );
    }

    #[test]
    fn virtual_service_multi_operator_authority_still_fails_closed() {
        // Istio StringMatch objects carry exactly one operator. Do not
        // partially extract `exact` from a malformed object such as
        // `{exact, prefix}` or `{exact, contains}` — both would widen a route
        // the operator intended to gate.
        for (case, authority) in [
            (
                "two supported operators",
                serde_json::json!({"exact": "internal.example.com", "prefix": "internal."}),
            ),
            (
                "supported plus unknown operator",
                serde_json::json!({"exact": "internal.example.com", "contains": "internal"}),
            ),
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "VirtualService",
                    serde_json::json!({
                        "hosts": ["api.example.com"],
                        "http": [{
                            "match": [
                                {"uri": {"prefix": "/api"}, "authority": authority}
                            ],
                            "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }]
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");

            let proxy = result
                .config
                .proxies
                .iter()
                .find(|p| p.listen_path.as_deref() == Some("/api"))
                .unwrap_or_else(|| panic!("{case}: /api proxy"));
            assert!(
                result.config.plugin_configs.iter().any(|p| {
                    p.plugin_name == "request_termination"
                        && p.proxy_id.as_deref() == Some(proxy.id.as_str())
                }),
                "{case}: malformed authority StringMatch must fail closed"
            );
        }
    }

    #[test]
    fn virtual_service_invalid_authority_values_fail_closed_before_plugin_load() {
        // Keep translator validation aligned with mesh_route_dispatch load-time
        // validation. If these shapes emitted a rule, plugin-cache rebuild would
        // reject the whole instance and leave the selected proxy forwarding to
        // its default backend instead of failing closed.
        for (case, authority) in [
            ("empty exact", serde_json::json!({"exact": ""})),
            ("empty prefix", serde_json::json!({"prefix": ""})),
            ("empty regex", serde_json::json!({"regex": ""})),
            ("invalid regex", serde_json::json!({"regex": "["})),
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "VirtualService",
                    serde_json::json!({
                        "hosts": ["api.example.com"],
                        "http": [{
                            "match": [
                                {"uri": {"prefix": "/api"}, "authority": authority}
                            ],
                            "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }]
                    }),
                )],
                options(),
            )
            .expect("translation succeeds");

            let proxy = result
                .config
                .proxies
                .iter()
                .find(|p| p.listen_path.as_deref() == Some("/api"))
                .unwrap_or_else(|| panic!("{case}: /api proxy"));
            assert!(
                result.config.plugin_configs.iter().any(|p| {
                    p.plugin_name == "request_termination"
                        && p.proxy_id.as_deref() == Some(proxy.id.as_str())
                }),
                "{case}: invalid authority value must fail closed"
            );
            assert!(
                !result.config.plugin_configs.iter().any(|p| {
                    p.plugin_name == "mesh_route_dispatch"
                        && p.proxy_id.as_deref() == Some(proxy.id.as_str())
                }),
                "{case}: invalid authority value must not emit a plugin-cache-rejected rule"
            );
        }
    }

    #[test]
    fn virtual_service_unsupported_source_labels_predicate_does_not_disable_reject_unmatched() {
        // Codex P1 (#3237631705): an unsupported non-URI predicate must NOT
        // disable `reject_unmatched`. An entry consisting of `uri` plus an
        // unsupported predicate is NOT a URI-only catch-all -- it's URI
        // plus an unsupported predicate. Treating it as URI-only would
        // forward requests that don't carry the gated predicate.
        //
        // `authority` is now first-class supported (T1-B.3), so this test
        // uses `sourceLabels` (still unsupported -- sibling PRs cover
        // `sourceNamespace`, etc.) to keep exercising the fail-closed
        // sibling path.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                            {"uri": {"prefix": "/api"}, "sourceLabels": {"app": "billing"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "only the supported header rule survives; sourceLabels-bearing sibling is skipped"
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported sibling predicate must NOT collapse onto URI-only catch-all"
        );
    }

    #[test]
    fn virtual_service_source_namespace_match_emits_plugin_with_string_predicate() {
        // T1-B.4: VirtualService `sourceNamespace` is now a first-class
        // mesh_route_dispatch predicate. The translator emits it as a bare
        // string under the `source_namespace` field (Istio: exact-only, no
        // `prefix`/`regex` arms in the CRD), and the plugin must load the
        // shape successfully (predicate compiled at config-load time, not
        // per request). Previously this predicate fell through to a
        // proxy-scoped `request_termination` instead of being enforced.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "sourceNamespace": "prod"
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted for sourceNamespace");
        let source_ns = &plugin.config["rules"][0]["match"]["source_namespace"];
        assert!(
            source_ns.is_string(),
            "sourceNamespace must emit as a bare string for wire shape, got: {source_ns}"
        );
        assert_eq!(source_ns.as_str(), Some("prod"));
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "sourceNamespace must NOT cause fail-closed request_termination anymore"
        );

        // The plugin must load successfully from the translator's JSON shape.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_uri_less_source_namespace_only_match_materializes_catch_all_proxy() {
        // A URI-less entry whose only predicate is `sourceNamespace` is now
        // first-class supported. It routes "any URI from this namespace" on
        // the listed hosts, matching the existing header-only catch-all path
        // (`URI_LESS_MATCH_LISTEN_PATH`). Without first-class support, this
        // would have been silently dropped via the unsupported-key list.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"sourceNamespace": "prod"}
                        ],
                        "route": [{"destination": {"host": "prod.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect(
                "mesh_route_dispatch plugin must be emitted for sourceNamespace-only catch-all",
            );
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1, "single sourceNamespace-only rule emitted");
        assert_eq!(rules[0]["match"]["source_namespace"].as_str(), Some("prod"));
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == plugin.proxy_id.as_deref()
            }),
            "sourceNamespace-only predicate must NOT cause fail-closed request_termination"
        );
    }

    #[test]
    fn virtual_service_non_string_source_namespace_still_fails_closed() {
        // The Istio CRD types `sourceNamespace` as a bare string. Any other
        // JSON shape (object with operator keys, array, bool, number) is
        // outside the CRD and treated as unsupported so the route falls
        // closed via `request_termination` rather than silently widening.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "sourceNamespace": {"prefix": "prod"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        assert!(
            result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            }),
            "non-string sourceNamespace shape must fail closed"
        );
    }

    #[test]
    fn virtual_service_empty_string_source_namespace_fails_closed_not_open() {
        // Regression: an empty-string `sourceNamespace: ""` previously passed
        // the translator's "supported predicate" check (because `Value::as_str`
        // returns `Some("")`) and was emitted verbatim into the plugin rule.
        // The plugin's `normalize_source_namespace` then rejected it at
        // construction time, the whole `mesh_route_dispatch` plugin was
        // silently dropped at cache rebuild, and `reject_unmatched: true`
        // no longer fired — letting gated traffic flow to the default backend.
        //
        // The translator must classify empty / whitespace-only strings as
        // unsupported predicates so the route is gated by `request_termination`
        // (fail-closed) rather than relying on runtime plugin validation.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "sourceNamespace": ""}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        assert!(
            result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            }),
            "empty-string sourceNamespace must fail closed via request_termination"
        );
        // And the mesh_route_dispatch plugin (if any was emitted for the
        // proxy) must not carry an empty `source_namespace` rule that the
        // plugin would reject at construction.
        for plugin in &result.config.plugin_configs {
            if plugin.plugin_name != "mesh_route_dispatch"
                || plugin.proxy_id.as_deref() != Some(proxy.id.as_str())
            {
                continue;
            }
            let rules = plugin
                .config
                .get("rules")
                .and_then(Value::as_array)
                .expect("rules array");
            for rule in rules {
                let ns = rule
                    .get("match")
                    .and_then(|m| m.get("source_namespace"))
                    .and_then(Value::as_str);
                assert_ne!(
                    ns,
                    Some(""),
                    "translator must not emit empty source_namespace into plugin rule"
                );
            }
        }
    }

    #[test]
    fn virtual_service_whitespace_only_source_namespace_fails_closed_not_open() {
        // A whitespace-only `sourceNamespace: "   "` is also invalid (the
        // plugin's `normalize_source_namespace` rejects whitespace). Same
        // failure mode and same fail-closed remediation as empty-string.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "sourceNamespace": "   "}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        assert!(
            result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            }),
            "whitespace-only sourceNamespace must fail closed via request_termination"
        );
    }

    #[test]
    fn virtual_service_header_only_match_materializes_catch_all() {
        // Codex P2 (#3237631709): a VirtualService whose `match[]`
        // contains only non-URI predicates (no `uri` block at all) is a
        // legitimate Istio configuration -- it routes "any URI with these
        // predicates" on the listed hosts. Previously the translator
        // dropped such routes entirely because match_paths was URI-driven.
        // Materialize a regex catch-all proxy + mesh_route_dispatch plugin
        // so the operator's predicates are actually enforced without
        // shadowing real prefix/regex routes.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("regex catch-all proxy materialized for header-only match");
        assert_eq!(proxy.hosts, vec!["api.example.com".to_string()]);

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("plugin attached to the catch-all proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "header-only match with no URI-only sibling keeps reject_unmatched on"
        );
    }

    #[test]
    fn virtual_service_header_only_match_decorates_later_default_route() {
        // Regression for the URI-less catch-all routing order: Ferrum routes
        // prefix paths before regex paths, so a generated `~.*` header-only
        // proxy loses to a later default `/` proxy. Attach the earlier
        // URI-less rule to the later default proxy as an override instead:
        // matching traffic diverts to canary, non-matching traffic stays on
        // the default backend.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"headers": {"x-canary": {"exact": "v2"}}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later default proxy");

        let matched = crate::router_cache::RouterCache::new(&result.config, 0)
            .find_proxy(Some("api.example.com"), "/anything")
            .expect("default prefix proxy should match");
        assert_eq!(
            matched.proxy.id, stable_proxy.id,
            "the later default prefix is the proxy the hot router selects"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("prior URI-less rule decorates later default proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(9090));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "misses must fall through to the selected default proxy backend"
        );
    }

    #[test]
    fn virtual_service_unsupported_uri_less_predicate_decorates_later_default_with_termination() {
        // Unsupported URI-less predicates cannot be represented by
        // mesh_route_dispatch. If they were skipped, the later default route
        // would serve requests that Istio gated. Collapse a terminating plugin
        // onto the selected default proxy instead. `authority` is now
        // first-class supported (T1-B.3); use `sourceLabels` (still
        // unsupported -- sibling PRs cover `sourceNamespace` separately) to
        // keep exercising the fail-closed path now that header regex/prefix
        // and authority are first-class predicates.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"sourceLabels": {"app": "billing"}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later default proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("unsupported URI-less predicate terminates the selected proxy");
        assert!(proxy_has_plugin(stable_proxy, plugin));
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "unsupported predicate must not emit a partial dispatch rule"
        );
    }

    #[test]
    fn virtual_service_ignore_uri_case_match_emits_case_insensitive_proxy_and_dispatch_rule() {
        // T1-B.5: `ignoreUriCase: true` is now first-class. The translator
        // widens the URI's listen_path to a case-insensitive regex so the
        // proxy router admits both casings, and emits a `mesh_route_dispatch`
        // rule carrying the original URI predicate + `ignore_uri_case: true`
        // so the plugin re-evaluates with ASCII case folding. A later
        // same-shape case-sensitive sibling must collapse onto the widened
        // proxy; otherwise Ferrum's prefix tier would select `/api` before
        // the widened regex and reverse Istio route order.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/Api"},
                                "ignoreUriCase": true,
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // The selected proxy uses the widened regex listen_path so both
        // `/Api*` and `/api*` hit one hot-router entry. Its default backend is
        // the later stable route; the prior canary route is guarded by the
        // dispatch plugin below.
        let widened_listen_path = "~(?i:/Api.*)";
        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some(widened_listen_path)
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("same-shape ignoreUriCase route collapses onto widened stable proxy");

        // The dispatch rules carry the prior guarded canary branch first,
        // then the later stable branch guarded by its original case-sensitive
        // URI. Without the second explicit URI predicate, widened `/API*`
        // traffic that misses the canary header would fall through to stable.
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch rule emitted for ignoreUriCase branch");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2, "canary rule plus guarded stable fallback");

        let match_obj = &rules[0]["match"];
        assert_eq!(match_obj["uri"]["prefix"].as_str(), Some("/Api"));
        assert_eq!(match_obj["ignore_uri_case"].as_bool(), Some(true));
        assert_eq!(match_obj["headers"]["x-canary"].as_str(), Some("v2"));
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(rules[1]["match"]["uri"]["prefix"].as_str(), Some("/api"));
        assert!(
            rules[1]["match"].get("ignore_uri_case").is_none(),
            "fallback route stays case-sensitive"
        );
        assert_eq!(
            rules[1]["destination"]["backend_host"].as_str(),
            Some("stable.default.svc.cluster.local")
        );
        assert_eq!(
            plugin.config["reject_unmatched"].as_bool(),
            Some(true),
            "widened proxy must reject casings that neither route admitted"
        );

        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("/api")),
            "the same-shape later route must not remain in the prefix tier"
        );

        // The plugin must construct from the translator's JSON shape — bad
        // schema or missing field would error here at load time.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_ignore_uri_case_collapsed_predicate_route_keeps_uri_guard() {
        // Same-shape collapse must guard every later route with its original
        // URI, not just URI-only fallbacks. Otherwise a later `/api` + method
        // rule installed on the widened `~(?i:/Api.*)` proxy would admit
        // `/API*` when the earlier case-insensitive canary misses.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/Api"},
                                "ignoreUriCase": true,
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "method": {"exact": "GET"}
                            }],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("~(?i:/Api.*)")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later predicate route collapses onto widened stable proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch plugin");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(rules[1]["match"]["uri"]["prefix"].as_str(), Some("/api"));
        assert!(
            rules[1]["match"].get("ignore_uri_case").is_none(),
            "later predicate route must keep case-sensitive URI semantics"
        );
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
    }

    #[test]
    fn virtual_service_ignore_uri_case_later_widened_route_guards_pending_case_sensitive_rule() {
        // Inverse order: the first route is case-sensitive `/api` with a
        // header gate; the later route is widened by `ignoreUriCase`. The
        // pending first-route rule is moved onto the widened proxy and must
        // carry its original `/api` URI guard, or `/API*` with the header
        // would incorrectly route to canary.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{
                                "uri": {"prefix": "/Api"},
                                "ignoreUriCase": true
                            }],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("~(?i:/Api.*)")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later widened route consumes pending case-sensitive route");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch plugin");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(rules[0]["match"]["uri"]["prefix"].as_str(), Some("/api"));
        assert!(
            rules[0]["match"].get("ignore_uri_case").is_none(),
            "pending case-sensitive route must not inherit ignore_uri_case"
        );
        assert_eq!(rules[1]["match"]["uri"]["prefix"].as_str(), Some("/Api"));
        assert_eq!(rules[1]["match"]["ignore_uri_case"].as_bool(), Some(true));
    }

    #[test]
    fn virtual_service_ignore_uri_case_later_exact_synthesizes_widened_prefix_proxy() {
        // The earlier route is a case-sensitive prefix; the later route is a
        // case-insensitive exact inside that prefix. Ferrum's prefix tier would
        // otherwise keep the stale `/api` proxy ahead of the later regex exact
        // route and return 404 on predicate misses instead of falling through.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{
                                "uri": {"exact": "/Api"},
                                "ignoreUriCase": true
                            }],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("/api")),
            "stale prefix proxy must be consumed by the synthesized widened proxy"
        );
        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("~(?i:/api.*)")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later exact route materializes on synthesized widened prefix proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch plugin");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["match"]["uri"]["prefix"].as_str(), Some("/api"));
        assert!(rules[0]["match"].get("ignore_uri_case").is_none());
        assert_eq!(rules[1]["match"]["uri"]["exact"].as_str(), Some("/Api"));
        assert_eq!(rules[1]["match"]["ignore_uri_case"].as_bool(), Some(true));
    }

    #[test]
    fn virtual_service_ignore_uri_case_chained_inverse_collapse_consumes_later_prefix() {
        // The second route synthesizes a widened prefix to consume the first
        // route. A third route inside that widened prefix must also collapse;
        // otherwise Ferrum's prefix tier would select `/api/foo` before the
        // widened regex proxy and bypass the earlier ordered rules.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{
                                "uri": {"exact": "/Api"},
                                "ignoreUriCase": true
                            }],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api/foo"}}],
                            "route": [{"destination": {"host": "foo.default.svc.cluster.local", "port": {"number": 7070}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| { matches!(p.listen_path.as_deref(), Some("/api") | Some("/api/foo")) }),
            "case-sensitive prefix-tier siblings must be consumed by the widened proxy"
        );
        let foo_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("~(?i:/api.*)")
                    && p.backend_host == "foo.default.svc.cluster.local"
            })
            .expect("third route materializes on the synthesized widened prefix proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(foo_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch plugin");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["match"]["uri"]["prefix"].as_str(), Some("/api"));
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert!(rules[0]["match"].get("ignore_uri_case").is_none());
        assert_eq!(rules[1]["match"]["uri"]["exact"].as_str(), Some("/Api"));
        assert_eq!(rules[1]["match"]["ignore_uri_case"].as_bool(), Some(true));
        assert_eq!(
            rules[2]["match"]["uri"]["prefix"].as_str(),
            Some("/api/foo")
        );
        assert!(rules[2]["match"].get("ignore_uri_case").is_none());
        assert_eq!(plugin.config["reject_unmatched"].as_bool(), Some(true));
    }

    #[test]
    fn virtual_service_ignore_uri_case_prefix_collapses_later_exact_route() {
        // Ferrum routes exact/prefix tiers before regex. A later exact route
        // inside an earlier widened prefix must therefore collapse onto the
        // widened proxy, with the exact route guarded by its original URI, so
        // the exact tier cannot bypass the earlier VirtualService route.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/Api"},
                                "ignoreUriCase": true,
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"exact": "/api/admin"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("=/api/admin")),
            "later exact route must not stay in the exact tier"
        );
        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("~(?i:/Api.*)")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later exact route collapses onto widened proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("mesh_route_dispatch plugin");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(
            rules[1]["match"]["uri"]["exact"].as_str(),
            Some("/api/admin")
        );
        assert!(rules[1]["match"].get("ignore_uri_case").is_none());
    }

    #[test]
    fn virtual_service_ignore_uri_case_exact_emits_anchored_case_insensitive_regex() {
        // `uri.exact: "/Api"` + `ignoreUriCase: true` widens to
        // `~(?i:/Api)`, which auto-anchors to `^(?i:/Api)$` — full-equality
        // matching, case-insensitive. Different from prefix (which ends
        // with `.*`).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"exact": "/Api"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("~(?i:/Api)"))
            .expect("ignoreUriCase exact emits a regex listen_path without `.*`");
        assert_eq!(proxy.backend_host, "canary.default.svc.cluster.local");

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("dispatch rule emitted for exact ignoreUriCase");
        let match_obj = &plugin.config["rules"][0]["match"];
        assert_eq!(match_obj["uri"]["exact"].as_str(), Some("/Api"));
        assert_eq!(match_obj["ignore_uri_case"].as_bool(), Some(true));
    }

    #[test]
    fn virtual_service_ignore_uri_case_prefix_escapes_literal_regex_chars() {
        // Istio prefix operands are literal strings. After widening into the
        // regex router tier, characters like `.` and `+` must remain literal
        // rather than becoming regex operators that admit unrelated paths.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/v1.0+"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(r"~(?i:/v1\.0\+.*)"))
            .expect("literal prefix chars are regex-escaped");
        assert_eq!(proxy.backend_host, "canary.default.svc.cluster.local");
    }

    #[test]
    fn virtual_service_operator_case_insensitive_regex_is_not_literal_collapse_shape() {
        // Only translator-generated ignoreUriCase exact/prefix paths are
        // eligible for literal containment collapse. Operator-authored regex
        // listen_paths may also start with `(?i:...)`, but real regex syntax
        // such as alternation is not a literal URI shape and must not be fed
        // through the exact/prefix containment helpers.
        assert!(!listen_paths_overlap_for_route_order(
            &Some("~(?i:/api|/store)".to_string()),
            &Some("/api".to_string())
        ));
        assert!(!can_collapse_listen_path_into(
            &Some("~(?i:/api|/store)".to_string()),
            &Some("~(?i:/api.*)".to_string())
        ));
    }

    #[test]
    fn virtual_service_ignore_uri_case_without_uri_predicate_is_gracefully_ignored() {
        // `ignoreUriCase: true` has no semantic meaning without a `uri`
        // predicate — the flag changes URI case folding, and there's no URI
        // to fold. The translator silently drops the flag and emits a normal
        // dispatch rule for the supported sibling predicates (here a header
        // exact match) so the rest of the match remains routable. We do
        // NOT emit `ignore_uri_case: true` on the dispatch rule — the
        // plugin would reject `ignore_uri_case: true` without `uri` at
        // load time, which would break the gateway.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "ignoreUriCase": true,
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // URI-less entry lands on the synthetic catch-all proxy.
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("URI-less header-only entry creates the synthetic catch-all proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("dispatch rule emitted for header-only entry");
        let match_obj = &plugin.config["rules"][0]["match"];
        assert_eq!(match_obj["headers"]["x-canary"].as_str(), Some("v2"));
        assert!(
            match_obj.get("uri").is_none(),
            "no URI predicate to fold — `uri` must be omitted from the dispatch rule"
        );
        assert!(
            match_obj.get("ignore_uri_case").is_none(),
            "the flag is meaningless without a URI predicate and must NOT be emitted \
             (the plugin would reject `ignore_uri_case: true` without `uri`)"
        );

        // The plugin must construct from the translator's JSON shape.
        use crate::plugins::mesh_route_dispatch::MeshRouteDispatch;
        let _ = MeshRouteDispatch::new(&plugin.config)
            .expect("translator output must construct the plugin");
    }

    #[test]
    fn virtual_service_ignore_uri_case_regex_keeps_operator_regex_case_sensitive() {
        // Istio documents `ignoreUriCase` as exact/prefix-only. Regex URI
        // matches keep the operator-supplied regex unchanged and the dispatch
        // rule does not carry `ignore_uri_case`.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"regex": "^/api/v[0-9]+"},
                            "ignoreUriCase": true
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("~^/api/v[0-9]+"))
            .expect("ignoreUriCase regex keeps the raw regex listen_path");
        assert_eq!(proxy.backend_host, "canary.default.svc.cluster.local");
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.config
                        .pointer("/rules/0/match/ignore_uri_case")
                        .and_then(Value::as_bool)
                        == Some(true)
            }),
            "regex URI matches must not receive exact/prefix-only ignore_uri_case"
        );
    }

    #[test]
    fn virtual_service_ignore_uri_case_false_uses_regular_uri_match() {
        // Explicit `ignoreUriCase: false` is equivalent to Istio's default
        // case-sensitive path matching and must not be treated as unsupported.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": false
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/Api"))
            .expect("regular case-sensitive URI proxy");
        assert_eq!(proxy.backend_host, "canary.default.svc.cluster.local");
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "request_termination"),
            "ignoreUriCase=false must not emit fail-closed termination"
        );
    }

    #[test]
    fn virtual_service_ignore_uri_case_false_with_other_unsupported_predicate_stays_uri_scoped() {
        // If some other predicate is unsupported, an explicit
        // `ignoreUriCase: false` should not broaden the fail-closed proxy to
        // the synthetic URI-less catch-all. `method.regex` is now first-class
        // supported (T1-B.2) and `authority` is now first-class supported
        // (T1-B.3); use `sourceLabels` (still unsupported) to keep
        // exercising the fail-closed sibling path.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": false,
                            "sourceLabels": {"app": "billing"}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/Api"))
            .expect("fail-closed proxy stays scoped to the URI match");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("unsupported sourceLabels predicate terminates the URI-scoped proxy");
        assert!(proxy_has_plugin(proxy, plugin));
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "ignoreUriCase=false must not force URI-less fail-closed broadening"
        );
    }

    #[test]
    fn virtual_service_same_path_guarded_route_decorates_later_default() {
        // Ordered Istio http[] routes with the same URI must behave like
        // route-list fall-through: a canary header branch can divert matches,
        // while misses continue to the later stable route. Two Ferrum proxies
        // with the same host+listen_path cannot express that, so the earlier
        // guarded branch is collapsed into a dispatch rule on the later proxy.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let api_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some("/api"))
            .collect();
        assert_eq!(
            api_proxies.len(),
            1,
            "same-path ordered routes must collapse to one proxy"
        );
        let stable_proxy = api_proxies[0];
        assert_eq!(
            stable_proxy.backend_host,
            "stable.default.svc.cluster.local"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("canary branch decorates the stable proxy");
        assert!(proxy_has_plugin(stable_proxy, plugin));
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(9090));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "predicate misses must fall through to the later stable backend"
        );
    }

    #[test]
    fn virtual_service_same_path_mixed_supported_and_unsupported_match_fails_closed_on_miss() {
        // If one match entry on a route is representable and a sibling on the
        // same listen_path is not, preserve the supported dispatch rule but
        // keep reject_unmatched enabled after collapse. Otherwise traffic that
        // might have matched the unsupported predicate would leak to the later
        // default route. `method.regex` is now first-class supported
        // (T1-B.2) and `authority` is now first-class supported (T1-B.3);
        // use `sourceLabels` (still unsupported) here to keep exercising the
        // fail-closed sibling path.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"uri": {"prefix": "/api"}, "method": {"exact": "GET"}},
                                {"uri": {"prefix": "/api"}, "sourceLabels": {"app": "billing"}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let api_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some("/api"))
            .collect();
        assert_eq!(api_proxies.len(), 1);
        let stable_proxy = api_proxies[0];
        assert_eq!(
            stable_proxy.backend_host,
            "stable.default.svc.cluster.local"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("supported rule decorates the stable proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported sibling must make predicate misses fail closed"
        );
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            }),
            "a supported dispatch rule can fail closed with reject_unmatched instead of terminating every request"
        );
    }

    #[test]
    fn virtual_service_same_path_guarded_route_carries_local_timeout_on_rule() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "timeout": "250ms",
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("route-local timeout is represented on the dispatch rule");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/api")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later stable proxy");
        assert_eq!(stable_proxy.backend_read_timeout_ms, 30_000);
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("canary branch decorates stable proxy");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["timeout_ms"].as_u64(), Some(250));
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
    }

    #[test]
    fn virtual_service_same_path_guarded_route_without_timeout_sets_timeout_disabled() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("route without timeout must not force dispatch timeout");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/api")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later stable proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("canary branch decorates stable proxy");
        let rules = plugin.config["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["timeout_disabled"].as_bool(), Some(true));
        assert!(
            rules[0].get("timeout_ms").is_none(),
            "unconfigured VirtualService timeout should clear inherited proxy timeout instead"
        );
    }

    #[test]
    fn virtual_service_multiple_uri_less_routes_collapse_in_order() {
        // Multiple URI-less guarded routes all materialize as `~.*`; emitting
        // one proxy per route would make the first reject misses before the
        // second can match. Collapse them into one ordered rule list.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{"headers": {"x-canary": {"exact": "v2"}}}],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"headers": {"x-region": {"exact": "east"}}}],
                            "route": [{"destination": {"host": "east.default.svc.cluster.local", "port": {"number": 8081}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let catch_all_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .collect();
        assert_eq!(
            catch_all_proxies.len(),
            1,
            "URI-less guarded route list must collapse to one catch-all proxy"
        );
        let proxy = catch_all_proxies[0];
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("collapsed catch-all has dispatch plugin");
        assert!(proxy_has_plugin(proxy, plugin));
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(
            rules[1]["match"]["headers"]["x-region"].as_str(),
            Some("east")
        );
        assert_eq!(
            rules[1]["destination"]["backend_host"].as_str(),
            Some("east.default.svc.cluster.local")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "with no later default route, misses must still fail closed"
        );
    }

    #[test]
    fn virtual_service_header_only_match_does_not_shadow_later_regex_route() {
        // Codex P1 (#3238865239): regex routes are first-match in config
        // order. An earlier URI-less rule materialized as `~.*` must be
        // deferred after later regex URI routes; otherwise it wins routing
        // and 404s predicate misses before the later regex route can run.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"headers": {"x-canary": {"exact": "v2"}}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [
                                {"uri": {"regex": "/v[0-9]+/api"}}
                            ],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let stable_index = result
            .config
            .proxies
            .iter()
            .position(|p| {
                p.listen_path.as_deref() == Some("~/v[0-9]+/api")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later regex URI proxy");
        let catch_all_index = result
            .config
            .proxies
            .iter()
            .position(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("deferred URI-less catch-all proxy");
        assert!(
            stable_index < catch_all_index,
            "later regex URI proxy must be indexed before the synthetic catch-all"
        );

        let stable_proxy = &result.config.proxies[stable_index];
        let matched = crate::router_cache::RouterCache::new(&result.config, 0)
            .find_proxy(Some("api.example.com"), "/v1/api")
            .expect("regex URI proxy should match");
        assert_eq!(
            matched.proxy.id, stable_proxy.id,
            "the hot router should select the later regex route, not the `~.*` catch-all"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("prior URI-less rule decorates later regex proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "predicate misses must fall through to the selected regex route backend"
        );
    }

    #[test]
    fn virtual_service_header_only_match_materializes_by_default() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "catch-all materialized for header-only match"
        );
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "mesh_route_dispatch emitted for header-only match"
        );
    }

    #[test]
    fn virtual_service_header_only_match_with_unsupported_predicates_fails_closed() {
        // A URI-less entry whose only predicate type is unsupported cannot
        // be enforced by mesh_route_dispatch. Materializing a catch-all to
        // the route's backend would silently widen past the operator's
        // intent. Emit a terminating catch-all instead, so a later broader
        // route cannot accidentally serve the guarded traffic. `authority`
        // is now first-class supported (T1-B.3); use `sourceLabels` (still
        // unsupported -- sibling PRs cover `sourceNamespace` separately).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"sourceLabels": {"app": "billing"}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "unsupported predicates must not emit a partial dispatch plugin"
        );
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("terminating catch-all proxy materialized");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("termination plugin attached");
        assert!(proxy_has_plugin(proxy, plugin));
    }

    #[test]
    fn virtual_service_header_only_match_with_partial_unsupported_predicates_fails_closed() {
        // A URI-less entry with one exact predicate and one unsupported
        // predicate is unsafe to materialize: mesh_route_dispatch would skip
        // the partial rule, leaving an unguarded catch-all proxy behind. The
        // translator emits a terminating catch-all instead. Header regex /
        // prefix and `authority` are now first-class supported predicates, so
        // we use a still-unsupported sibling key (`sourceLabels`) to keep
        // exercising partial-extraction fail-closed.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {
                                "headers": {
                                    "x-canary": {"exact": "v2"}
                                },
                                "sourceLabels": {"app": "billing"}
                            }
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("terminating catch-all proxy materialized");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("termination plugin attached");
        assert!(proxy_has_plugin(proxy, plugin));
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "partial URI-less predicates must not emit a dispatch plugin"
        );
    }

    #[test]
    fn virtual_service_mixed_uri_and_header_only_match_emits_both_proxies() {
        // A `match[]` mixing one URI entry and one URI-less header entry
        // must produce BOTH proxies: the URI-derived `/api` AND a regex
        // catch-all for the URI-less header rule. Without the catch-all,
        // `/other` requests carrying the header would 404 even though
        // Istio semantics route them via the URI-less branch.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let api_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("URI-derived /api proxy");
        let catch_all = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("URI-less catch-all proxy");
        assert_ne!(api_proxy.id, catch_all.id);

        // The catch-all proxy MUST have a plugin (the URI-less header
        // rule). The `/api` proxy ALSO has a plugin because the URI-less
        // header entry applies to every listen_path of this http rule,
        // and the URI-only `/api` entry triggers has_uri_only_match.
        let api_plugin = result.config.plugin_configs.iter().find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(api_proxy.id.as_str())
        });
        let catch_all_plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(catch_all.id.as_str())
            })
            .expect("catch-all proxy has the URI-less header rule attached");

        // /api proxy: URI-only branch keeps reject_unmatched off so
        // unrelated traffic to /api still routes.
        if let Some(plugin) = api_plugin {
            assert_eq!(
                plugin
                    .config
                    .get("reject_unmatched")
                    .and_then(Value::as_bool),
                Some(false),
                "URI-only sibling on /api proxy disables reject_unmatched"
            );
        }
        assert_eq!(
            catch_all_plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "catch-all proxy has no URI-only sibling in scope, so reject_unmatched stays on"
        );
    }

    #[test]
    fn virtual_service_mixed_regex_uri_and_header_only_uses_regex_catch_all() {
        // Ferrum routes prefixes before regexes. If the URI-less header
        // branch were materialized as prefix `/`, it would shadow the real
        // regex URI branch and reject requests that should match it.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"regex": "/v[0-9]+/api"}},
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("~/v[0-9]+/api")),
            "regex URI branch must still materialize"
        );
        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "URI-less branch should use regex catch-all"
        );
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("/")),
            "URI-less branch must not become prefix `/`, which shadows regex routes"
        );
    }

    #[test]
    fn virtual_service_partial_predicate_extraction_skips_rule() {
        // Codex P1 (#3237631705) follow-on: an entry with one supported
        // and one unsupported predicate is also unsafe to emit as a
        // partial rule. `method=GET + sourceLabels` cannot be honored
        // (the sourceLabels predicate is dropped), so emitting a rule with
        // only `methods=[GET]` would silently widen the route to match GET
        // regardless of the gated workload. Skip the entry entirely;
        // `reject_unmatched: true` 404s the request, which is the
        // fail-closed VirtualService semantic. Header regex / prefix and
        // `authority` are now first-class supported predicates, so we use a
        // still-unsupported sibling key (`sourceLabels`) to exercise this
        // partial-extraction path.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                            {
                                "uri": {"prefix": "/api"},
                                "method": {"exact": "GET"},
                                "sourceLabels": {"app": "billing"}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "only the fully-supported header rule emits; the partial-extraction entry is skipped"
        );
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2"),
            "the emitted rule is the fully-supported one"
        );
        assert!(
            rules[0]["match"].get("methods").is_none(),
            "method=GET from the partial entry must NOT leak onto the surviving rule"
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
        );
    }

    #[test]
    fn parse_istio_duration_ms_formats() {
        assert_eq!(parse_istio_duration_ms("5s"), Some(5000));
        assert_eq!(parse_istio_duration_ms("1.5s"), Some(1500));
        assert_eq!(parse_istio_duration_ms("500ms"), Some(500));
        assert_eq!(parse_istio_duration_ms("0s"), Some(0));
        assert_eq!(parse_istio_duration_ms("0ms"), Some(0));
        assert_eq!(parse_istio_duration_ms("-1s"), None);
        assert_eq!(parse_istio_duration_ms("-500ms"), None);
        assert_eq!(parse_istio_duration_ms("NaN s"), None);
        assert_eq!(parse_istio_duration_ms("10"), None);
        assert_eq!(parse_istio_duration_ms("30m"), Some(1_800_000));
        assert_eq!(parse_istio_duration_ms("2h"), Some(7_200_000));
        assert_eq!(parse_istio_duration_ms("1.5h"), Some(5_400_000));
        assert_eq!(parse_istio_duration_ms("5000us"), Some(5));
        assert_eq!(parse_istio_duration_ms("100us"), Some(1));
        assert_eq!(parse_istio_duration_ms("999ns"), Some(1));
    }

    #[test]
    fn translates_authorization_policy_request_principals() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "requestPrincipals": [
                            "https://accounts.google.com/*",
                            "https://auth.example.com/admin"
                        ]
                    }
                }]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(
            policy.rules[0].request_principals,
            vec![
                "https://accounts.google.com/*".to_string(),
                "https://auth.example.com/admin".to_string(),
            ]
        );
    }

    #[test]
    fn translates_authorization_policy_request_principals_empty() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}}]
            }]
        }));

        assert!(
            policy.rules[0].request_principals.is_empty(),
            "no requestPrincipals should produce empty list"
        );
    }

    #[test]
    fn translates_authorization_policy_source_negation_and_ip_blocks() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "principals": ["spiffe://cluster.local/ns/default/sa/web"],
                        "notPrincipals": ["cluster.local/ns/default/sa/legacy"],
                        "notNamespaces": ["kube-system"],
                        "ipBlocks": ["10.0.0.0/8"],
                        "notIpBlocks": ["10.1.0.0/16"],
                        "remoteIpBlocks": ["203.0.113.0/24"],
                        "notRemoteIpBlocks": ["198.51.100.0/24"],
                        "notRequestPrincipals": ["https://issuer/admin"]
                    }
                }]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        let rule = &policy.rules[0];
        assert_eq!(rule.from.len(), 1, "positive principal preserved");
        assert_eq!(
            rule.not_request_principals,
            vec!["https://issuer/admin".to_string()]
        );
        let neg = &rule.source_negation;
        assert_eq!(
            neg.not_spiffe_id_patterns,
            vec!["cluster.local/ns/default/sa/legacy".to_string()]
        );
        assert_eq!(neg.not_namespace_patterns, vec!["kube-system".to_string()]);
        assert_eq!(
            neg.ip_blocks,
            vec![ParsedCidr::parse("10.0.0.0/8").unwrap()]
        );
        assert_eq!(
            neg.not_ip_blocks,
            vec![ParsedCidr::parse("10.1.0.0/16").unwrap()]
        );
        assert_eq!(
            neg.remote_ip_blocks,
            vec![ParsedCidr::parse("203.0.113.0/24").unwrap()]
        );
        assert_eq!(
            neg.not_remote_ip_blocks,
            vec![ParsedCidr::parse("198.51.100.0/24").unwrap()]
        );
    }

    #[test]
    fn authorization_policy_rejects_unsupported_source_field() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "from": [{"source": {"someFutureField": ["x"]}}]
                    }]
                }),
            )],
            options(),
        );
        let err = result.expect_err("unsupported source field must reject the resource");
        assert!(
            err.to_string()
                .contains("source.someFutureField is unsupported"),
            "error should name the unsupported field, got: {err}"
        );
    }

    #[test]
    fn authorization_policy_rejects_malformed_ip_block() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "from": [{"source": {"ipBlocks": ["10.0.0.0/40"]}}]
                    }]
                }),
            )],
            options(),
        );
        let err = result.expect_err("malformed CIDR must reject the resource");
        assert!(
            err.to_string().contains("ipBlocks") && err.to_string().contains("invalid"),
            "error should flag the bad CIDR, got: {err}"
        );
    }

    #[test]
    fn authorization_policy_remote_ip_blocks_enforced_end_to_end() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{"source": {"remoteIpBlocks": ["203.0.113.0/24"]}}]
            }]
        }));
        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };
        let inside = MeshAuthzRequest {
            remote_ip: Some("203.0.113.9".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &inside),
            MeshAuthzDecision::Allow
        );
        let outside = MeshAuthzRequest {
            remote_ip: Some("198.51.100.9".parse().unwrap()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &outside),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn authorization_policy_from_entries_remain_or_alternatives() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [
                    {"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}},
                    {"source": {"requestPrincipals": ["https://auth.example.com/admin"]}}
                ]
            }]
        }));

        assert_eq!(
            policy.rules.len(),
            2,
            "each from[] source should become its own OR alternative"
        );
        assert_eq!(policy.rules[0].from.len(), 1);
        assert!(policy.rules[0].request_principals.is_empty());
        assert!(policy.rules[1].from.is_empty());
        assert_eq!(
            policy.rules[1].request_principals,
            vec!["https://auth.example.com/admin".to_string()]
        );

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let spiffe_only = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &spiffe_only),
            MeshAuthzDecision::Allow
        );

        let jwt_only = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/admin".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &jwt_only),
            MeshAuthzDecision::Allow
        );

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn authorization_policy_from_entry_keeps_principal_and_jwt_together() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "principals": ["spiffe://cluster.local/ns/default/sa/web"],
                        "requestPrincipals": ["https://auth.example.com/admin"]
                    }
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let spiffe_only = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &spiffe_only),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let both = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            request_principal: Some("https://auth.example.com/admin".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &both),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn authorization_policy_from_entry_ands_principals_and_namespaces() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "principals": ["cluster.local/ns/default/sa/web"],
                        "namespaces": ["default"]
                    }
                }]
            }]
        }));

        let rule = &policy.rules[0];
        assert_eq!(rule.from.len(), 1);
        assert_eq!(
            rule.from[0].spiffe_id_pattern.as_deref(),
            Some("cluster.local/ns/default/sa/web")
        );
        assert_eq!(rule.from[0].namespace_pattern.as_deref(), Some("default"));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let web = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &web),
            MeshAuthzDecision::Allow
        );

        let same_namespace_other_sa = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/other").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &same_namespace_other_sa),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn authorization_policy_service_accounts_match_istio_source_identity() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "serviceAccounts": ["web", "payments/api"]
                    }
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let default_web = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &default_web),
            MeshAuthzDecision::Allow
        );

        let payments_api = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://partner.local/ns/payments/sa/api").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &payments_api),
            MeshAuthzDecision::Allow
        );

        let other = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/other/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &other),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn authorization_policy_trust_domains_and_not_service_accounts_apply() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "trustDomains": ["cluster.*"],
                        "notTrustDomains": ["cluster.bad"],
                        "notServiceAccounts": ["legacy"]
                    }
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let client = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &client),
            MeshAuthzDecision::Allow
        );

        let denied_sa = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/legacy").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &denied_sa),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let denied_td = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.bad/ns/default/sa/client").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &denied_td),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let outside_td = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://partner.local/ns/default/sa/client").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &outside_td),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_principals_block_anonymous_requests_in_authz_evaluation() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {"requestPrincipals": ["*"]}
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let anon = MeshAuthzRequest::default();
        assert_eq!(
            evaluate_mesh_authorization(&slice, &anon),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let authed = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/user".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &authed),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn parse_istio_duration_rejects_negative_non_finite_and_overflow() {
        assert_eq!(parse_istio_duration_ms("-1s"), None);
        assert_eq!(parse_istio_duration_ms("NaNs"), None);
        assert_eq!(parse_istio_duration_ms("infms"), None);
        assert_eq!(
            parse_istio_duration_ms("999999999999999999999999999999m"),
            None
        );
    }

    #[test]
    fn parse_istio_duration_secs_rounds_positive_subseconds_up() {
        assert_eq!(parse_istio_duration_secs("0.5s"), Some(1));
        assert_eq!(parse_istio_duration_secs("1.1s"), Some(2));
        assert_eq!(parse_istio_duration_secs("0s"), Some(0));
    }

    #[test]
    fn destination_rule_outlier_interval_ignores_zero_and_rounds_subsecond() {
        let zero_interval = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "interval": "0s"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = zero_interval.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0]
                .traffic_policy
                .as_ref()
                .and_then(|policy| policy.outlier_detection.as_ref())
                .and_then(|outlier| outlier.interval_seconds),
            None
        );

        let subsecond_interval = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "interval": "0.5s"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = subsecond_interval.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0]
                .traffic_policy
                .as_ref()
                .and_then(|policy| policy.outlier_detection.as_ref())
                .and_then(|outlier| outlier.interval_seconds),
            Some(1)
        );
    }

    // ── ProxyConfig translation ─────────────────────────────────────────

    #[test]
    fn translates_proxy_config_with_all_fields_populated() {
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({
                    "selector": {"matchLabels": {"app": "api"}},
                    "concurrency": 4,
                    "image": {"imageType": "distroless"},
                    "environmentVariables": {
                        "GOMAXPROCS": "4",
                        "PILOT_ENABLE_FOO": "true"
                    },
                    "tracing": {"sampling": 42.5}
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        assert_eq!(pc.name, "sample");
        assert_eq!(pc.namespace, "default");
        match &pc.scope {
            PolicyScope::WorkloadSelector { selector } => {
                assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
                assert_eq!(selector.namespace.as_deref(), Some("default"));
            }
            other => panic!("expected WorkloadSelector scope, got {other:?}"),
        }
        assert_eq!(pc.concurrency, Some(4));
        assert_eq!(pc.image.as_deref(), Some("distroless"));
        assert_eq!(
            pc.environment.get("GOMAXPROCS").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            pc.environment.get("PILOT_ENABLE_FOO").map(String::as_str),
            Some("true")
        );
        assert_eq!(pc.tracing_sampling, Some(42.5));
    }

    #[test]
    fn translates_proxy_config_without_selector_is_namespace_default() {
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({
                    "concurrency": 2
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::Namespace { namespace } => {
                assert_eq!(namespace, "default");
            }
            other => panic!("expected Namespace scope, got {other:?}"),
        }
        assert_eq!(pc.namespace, "default");
        assert_eq!(pc.concurrency, Some(2));
    }

    #[test]
    fn translates_proxy_config_omits_unset_fields() {
        let result =
            translate_k8s_objects(&[object("ProxyConfig", serde_json::json!({}))], options())
                .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::Namespace { namespace } => assert_eq!(namespace, "default"),
            other => panic!("expected Namespace scope, got {other:?}"),
        }
        assert!(pc.concurrency.is_none());
        assert!(pc.image.is_none());
        assert!(pc.environment.is_empty());
        assert!(pc.tracing_sampling.is_none());
    }

    #[test]
    fn translates_root_namespace_proxy_config_without_selector_is_mesh_wide() {
        // A ProxyConfig in the Istio root namespace with no selector is the
        // canonical Istio pattern for a mesh-wide default. The previous
        // namespace-only filter dropped this entirely; PolicyScope::MeshWide
        // is the fix.
        let result = translate_k8s_objects(
            &[K8sObject {
                api_version: "networking.istio.io/v1beta1".to_string(),
                kind: "ProxyConfig".to_string(),
                metadata: K8sMetadata {
                    name: "mesh-default".to_string(),
                    uid: String::new(),
                    namespace: "istio-config".to_string(),
                    generation: None,
                    labels: HashMap::new(),
                    creation_timestamp: None,
                    deletion_timestamp: None,
                    annotations: HashMap::new(),
                },
                spec: serde_json::json!({"tracing": {"sampling": 5.0}}),
                status: Value::Object(serde_json::Map::new()),
            }],
            options_for_namespace("default")
                .with_istio_root_namespace("istio-config".to_string())
                .with_source_namespaces(vec!["default".to_string(), "istio-config".to_string()]),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        assert!(
            matches!(pc.scope, PolicyScope::MeshWide),
            "expected MeshWide, got {:?}",
            pc.scope
        );
        assert_eq!(pc.tracing_sampling, Some(5.0));
    }

    #[test]
    fn translates_root_namespace_proxy_config_with_selector_is_mesh_wide_selector() {
        // A ProxyConfig in the Istio root namespace with a selector applies
        // to matching workloads across all namespaces. Encoded as
        // PolicyScope::WorkloadSelector with namespace=None — same pattern
        // as Telemetry / RequestAuthentication.
        let result = translate_k8s_objects(
            &[K8sObject {
                api_version: "networking.istio.io/v1beta1".to_string(),
                kind: "ProxyConfig".to_string(),
                metadata: K8sMetadata {
                    name: "mesh-api".to_string(),
                    uid: String::new(),
                    namespace: "istio-config".to_string(),
                    generation: None,
                    labels: HashMap::new(),
                    creation_timestamp: None,
                    deletion_timestamp: None,
                    annotations: HashMap::new(),
                },
                spec: serde_json::json!({
                    "selector": {"matchLabels": {"app": "api"}},
                    "tracing": {"sampling": 50.0}
                }),
                status: Value::Object(serde_json::Map::new()),
            }],
            options_for_namespace("default")
                .with_istio_root_namespace("istio-config".to_string())
                .with_source_namespaces(vec!["default".to_string(), "istio-config".to_string()]),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::WorkloadSelector { selector } => {
                assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
                assert!(
                    selector.namespace.is_none(),
                    "root-namespace selector must drop namespace pin"
                );
            }
            other => panic!("expected WorkloadSelector with no namespace, got {other:?}"),
        }
        assert_eq!(pc.tracing_sampling, Some(50.0));
    }

    #[test]
    fn proxy_config_concurrency_overflow_is_rejected() {
        // Out-of-range concurrency must surface as an InvalidResource error
        // instead of silently clamping to u32::MAX.
        let err = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({"concurrency": 9_999_999_999_u64}),
            )],
            options(),
        )
        .expect_err("overflow must be rejected");

        match err {
            K8sTranslateError::InvalidResource { kind, message, .. } => {
                assert_eq!(kind, "ProxyConfig");
                assert!(
                    message.contains("concurrency"),
                    "error message must mention concurrency: {message}"
                );
            }
            other => panic!("expected InvalidResource, got {other:?}"),
        }
    }

    #[test]
    fn proxy_config_concurrency_invalid_json_forms_are_rejected() {
        // A present-but-invalid concurrency value must surface as
        // InvalidResource — not silently dropped via the `as_u64` filter.
        let bad_values = [
            ("string", serde_json::json!("4")),
            ("float", serde_json::json!(4.5)),
            ("negative", serde_json::json!(-1)),
            ("bool", serde_json::json!(true)),
            ("array", serde_json::json!([4])),
            ("object", serde_json::json!({"n": 4})),
        ];

        for (label, bad) in bad_values {
            let err = translate_k8s_objects(
                &[object(
                    "ProxyConfig",
                    serde_json::json!({"concurrency": bad}),
                )],
                options(),
            )
            .expect_err(&format!("expected InvalidResource for {label}"));
            match err {
                K8sTranslateError::InvalidResource { kind, message, .. } => {
                    assert_eq!(kind, "ProxyConfig", "case {label}");
                    assert!(
                        message.contains("concurrency"),
                        "case {label}: error must mention concurrency: {message}"
                    );
                }
                other => panic!("case {label}: expected InvalidResource, got {other:?}"),
            }
        }
    }

    #[test]
    fn proxy_config_concurrency_null_is_treated_as_unset() {
        // Explicit JSON null is semantically equivalent to omitting the
        // field — both mean "use the data plane default."
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({"concurrency": serde_json::Value::Null}),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        assert!(mesh.proxy_configs[0].concurrency.is_none());
    }

    #[test]
    fn proxy_config_tracing_sampling_rejects_unusable_values() {
        // Mirror Telemetry.tracing.randomSamplingPercentage and the
        // concurrency fail-closed contract: a present-but-unusable sampling
        // value must surface as InvalidResource so FerrumAccepted=False
        // rather than silently dropping (string) or pushing an out-of-range
        // percentage into every matching workload's workload_metrics.
        //
        // Istio's v1beta1 ProxyConfig CRD has no `tracing` property in its
        // structural spec schema, so on a real cluster the API server prunes
        // `spec.tracing` before the watcher sees it. These cases pin the
        // translator contract for non-pruned object feeds; they are not a
        // claim that an operator can set this field via `kubectl apply`.
        let bad_values = [
            ("out_of_range_high", serde_json::json!(5000.0)),
            ("out_of_range_low", serde_json::json!(-1.0)),
            ("string", serde_json::json!("50")),
            ("bool", serde_json::json!(true)),
            ("array", serde_json::json!([50.0])),
            ("object", serde_json::json!({"n": 50.0})),
        ];

        for (label, bad) in bad_values {
            let err = translate_k8s_objects(
                &[object(
                    "ProxyConfig",
                    serde_json::json!({ "tracing": { "sampling": bad } }),
                )],
                options(),
            )
            .expect_err(&format!("expected InvalidResource for {label}"));
            match err {
                K8sTranslateError::InvalidResource { kind, message, .. } => {
                    assert_eq!(kind, "ProxyConfig", "case {label}");
                    assert!(
                        message.contains("spec.tracing.sampling"),
                        "case {label}: error must name tracing.sampling: {message}"
                    );
                }
                other => panic!("case {label}: expected InvalidResource, got {other:?}"),
            }
        }

        // Inclusive bounds and an integer JSON number stay accepted.
        for accepted in [
            serde_json::json!(0.0),
            serde_json::json!(100.0),
            serde_json::json!(50),
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "ProxyConfig",
                    serde_json::json!({ "tracing": { "sampling": accepted } }),
                )],
                options(),
            )
            .unwrap_or_else(|error| panic!("sampling {accepted} must be accepted: {error}"));
            let mesh = result.config.mesh.expect("mesh config");
            assert_eq!(
                mesh.proxy_configs[0].tracing_sampling,
                accepted.as_f64(),
                "accepted sampling must round-trip"
            );
        }

        // Explicit JSON null is unset, matching concurrency semantics.
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({ "tracing": { "sampling": serde_json::Value::Null } }),
            )],
            options(),
        )
        .expect("null sampling is unset");
        assert!(
            result.config.mesh.unwrap().proxy_configs[0]
                .tracing_sampling
                .is_none()
        );
    }

    #[test]
    fn proxy_config_workload_selector_wins_over_namespace_default() {
        // Two ProxyConfigs in same namespace: one namespace-default (no
        // selector), one with a workload selector. Slice resolution must
        // prefer the workload-scoped one for a matching workload.
        use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
        use std::collections::BTreeMap;

        let result = translate_k8s_objects(
            &[
                object(
                    "ProxyConfig",
                    serde_json::json!({"tracing": {"sampling": 10.0}}),
                ),
                K8sObject {
                    api_version: "networking.istio.io/v1beta1".to_string(),
                    kind: "ProxyConfig".to_string(),
                    metadata: K8sMetadata {
                        name: "api-overrides".to_string(),
                        uid: String::new(),
                        namespace: "default".to_string(),
                        generation: None,
                        labels: HashMap::new(),
                        creation_timestamp: None,
                        deletion_timestamp: None,
                        annotations: HashMap::new(),
                    },
                    spec: serde_json::json!({
                        "selector": {"matchLabels": {"app": "api"}},
                        "tracing": {"sampling": 99.0}
                    }),
                    status: Value::Object(serde_json::Map::new()),
                },
            ],
            options(),
        )
        .expect("translation succeeds");
        let gateway_config = result.config;
        assert_eq!(gateway_config.mesh.as_ref().unwrap().proxy_configs.len(), 2);

        let request = MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            cluster_domain: "cluster.local".to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };
        let slice = MeshSlice::from_gateway_config(&gateway_config, request);
        // Both should match — namespace-default applies to any workload, and
        // the workload-scoped one applies to `app=api`.
        assert_eq!(slice.proxy_configs.len(), 2);

        let resolved = slice
            .resolved_proxy_config()
            .expect("expected resolved proxy_config");
        assert_eq!(resolved.tracing_sampling, Some(99.0));
        assert_eq!(resolved.name, "api-overrides");
    }
    // ── DestinationRule trafficPolicy.tls ───────────────────────────────

    #[test]
    fn translates_destination_rule_tls_simple_with_ca() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "caCertificates": "/etc/certs/ca.pem",
                            "sni": "reviews.example.com"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Simple);
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
        assert_eq!(tls.sni.as_deref(), Some("reviews.example.com"));
        assert!(tls.client_certificate.is_none());
        assert!(tls.private_key.is_none());
        assert!(!tls.insecure_skip_verify);
    }

    #[test]
    fn translates_destination_rule_tls_mutual_with_cert_and_key() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "caCertificates": "/etc/certs/ca.pem",
                            "clientCertificate": "/etc/certs/client.pem",
                            "privateKey": "/etc/certs/client.key",
                            "subjectAltNames": ["spiffe://example/sa/reviews"],
                            "insecureSkipVerify": false
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Mutual);
        assert_eq!(
            tls.client_certificate.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(tls.private_key.as_deref(), Some("/etc/certs/client.key"));
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
        assert_eq!(
            tls.subject_alt_names,
            vec!["spiffe://example/sa/reviews".to_string()]
        );
        assert!(!tls.insecure_skip_verify);
    }

    #[test]
    fn translates_destination_rule_tls_rejects_too_many_subject_alt_names() {
        let too_many_sans: Vec<String> = (0..=MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES)
            .map(|i| format!("san-{i}.example.com"))
            .collect();
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": too_many_sans
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("too many subjectAltNames must fail");

        assert!(
            err.to_string()
                .contains("subjectAltNames must not have more than"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_overlong_subject_alt_name() {
        let overlong_san = format!(
            "{}.example.com",
            "a".repeat(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)
        );
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": [overlong_san]
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("overlong subjectAltNames entry must fail");

        assert!(
            err.to_string()
                .contains("subjectAltNames[0] must not exceed"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_invalid_sni() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "sni": "*.mesh.internal"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("wildcard SNI must fail");

        assert!(
            err.to_string().contains("trafficPolicy.tls.sni"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_invalid_san_content() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": ["spiffe://cluster.local"]
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("SPIFFE URI without path must fail");

        assert!(err.to_string().contains("subjectAltNames[0]"), "got: {err}");
    }

    #[test]
    fn translates_destination_rule_tls_mutual_rejects_missing_cert_or_key() {
        // MUTUAL requires BOTH clientCertificate AND privateKey.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "clientCertificate": "/etc/certs/client.pem"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("MUTUAL without privateKey must fail");
        assert!(
            err.to_string()
                .contains("MUTUAL requires both clientCertificate and privateKey"),
            "got: {err}"
        );

        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "privateKey": "/etc/certs/client.key"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("MUTUAL without clientCertificate must fail");
        assert!(
            err.to_string()
                .contains("MUTUAL requires both clientCertificate and privateKey"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual() {
        // ISTIO_MUTUAL must not carry explicit cert/key/CA — Istio reuses
        // the workload's SPIFFE identity material.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "sni": "reviews.example.com"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::IstioMutual);
        assert!(tls.client_certificate.is_none());
        assert!(tls.private_key.is_none());
        assert!(tls.ca_certificates.is_none());
        assert_eq!(tls.sni.as_deref(), Some("reviews.example.com"));
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual_rejects_explicit_cert() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "clientCertificate": "/etc/certs/client.pem",
                            "privateKey": "/etc/certs/client.key"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("ISTIO_MUTUAL with explicit cert/key must fail");
        assert!(
            err.to_string()
                .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual_rejects_explicit_ca() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "caCertificates": "/etc/certs/ca.pem"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("ISTIO_MUTUAL with explicit CA must fail");
        assert!(
            err.to_string()
                .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_disable() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"mode": "DISABLE"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Disable);
    }

    #[test]
    fn translates_destination_rule_tls_insecure_skip_verify() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "insecureSkipVerify": true
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert!(tls.insecure_skip_verify);
    }

    #[test]
    fn destination_rule_without_tls_translates_to_none() {
        // Preserves today's behavior: no tls block in DR -> MeshTrafficPolicy.tls is None.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "ROUND_ROBIN"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tp = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy");
        assert!(tp.tls.is_none());
    }

    #[test]
    fn destination_rule_rejects_unsupported_tls_mode() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"mode": "BANANA"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unsupported TLS mode must fail");
        assert!(
            err.to_string()
                .contains("trafficPolicy.tls.mode 'BANANA' is unsupported"),
            "got: {err}"
        );
    }

    #[test]
    fn destination_rule_subset_tls_is_parsed_without_warning() {
        // Per-subset trafficPolicy.tls is now applied per-subset by the
        // cold-path apply in `src/modes/mesh/mod.rs::resolve_subset_traffic_policy_tls`
        // and projected onto `Proxy.resolved_tls` for proxies that select the
        // subset via `upstream_subset`. The translator parses it onto
        // `MeshSubset.traffic_policy.tls` with no warning.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "tls": {
                                "mode": "SIMPLE",
                                "caCertificates": "/etc/certs/v1-ca.pem"
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let subset = &mesh.destination_rules[0].subsets[0];
        let tls = subset
            .traffic_policy
            .as_ref()
            .expect("subset traffic policy")
            .tls
            .as_ref()
            .expect("subset tls");
        assert_eq!(tls.mode, MtlsMode::Simple);
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/v1-ca.pem"));

        // No translator-level warning is emitted because the per-subset TLS
        // overlay is applied on the cold path.
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("trafficPolicy.tls is parsed but not yet applied per-subset")),
            "expected no per-subset tls warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_tls_defaults_to_simple_mode() {
        // Istio defaults `tls.mode` to SIMPLE when the field is omitted from
        // the block. Preserve that semantics.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"caCertificates": "/etc/certs/ca.pem"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Simple);
    }

    // ── Service.spec.ports[].name resolution ──────────────────────────────

    fn service_with_named_ports(name: &str, namespace: &str, ports: &[(&str, u16)]) -> K8sObject {
        let ports_json: Vec<Value> = ports
            .iter()
            .map(|(name, port)| serde_json::json!({"name": name, "port": *port}))
            .collect();
        K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
                namespace: namespace.to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: serde_json::json!({ "ports": ports_json }),
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn virtual_service_with_destination(name: &str, destination: Value) -> K8sObject {
        K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "VirtualService".to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": destination}]
                }]
            }),
            status: Value::Object(serde_json::Map::new()),
        }
    }

    #[test]
    fn vs_destination_port_name_resolves_against_collected_service() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080), ("grpc", 9090)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_number_still_wins_over_name() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"number": 7777, "name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        // Explicit `number` takes precedence even when both are set.
        assert_eq!(result.config.proxies[0].backend_port, 7777);
    }

    #[test]
    fn vs_destination_port_name_short_host_uses_vs_namespace() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews",
                "port": {"name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_unknown_fails_closed() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "missing-port"}
            }),
        );

        let err = translate_k8s_objects(&[svc, vs], options())
            .expect_err("unknown port name must fail closed");
        assert!(
            err.to_string().contains("missing-port"),
            "error must name the missing port: {err}"
        );
    }

    #[test]
    fn vs_destination_no_port_defaults_to_80() {
        // No port block at all — preserve today's "default to 80" behavior
        // regardless of whether a matching Service exists.
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local"
            }),
        );

        let result = translate_k8s_objects(&[vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 80);
    }

    #[test]
    fn service_object_is_not_translated_as_warning() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let result = translate_k8s_objects(&[svc], options()).expect("translation succeeds");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("Ignoring unsupported Kubernetes resource kind 'Service'")),
            "Service kind must be consumed by the port-name pre-pass, not warned: {:?}",
            result.warnings
        );
    }

    #[test]
    fn vs_destination_port_name_isolates_services_by_namespace() {
        // Two services named `reviews` in different namespaces with the same
        // port name but different port numbers; lookup must resolve against
        // the namespace embedded in the destination host, not the first match.
        let svc_default = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let svc_prod = service_with_named_ports("reviews", "prod", &[("http", 9090)]);
        let vs_default = virtual_service_with_destination(
            "reviews-default",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let mut vs_prod = virtual_service_with_destination(
            "reviews-prod",
            serde_json::json!({
                "host": "reviews.prod.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        // Cross-namespace destination is allowed: VS in `default` pointing at
        // a Service in `prod` — must resolve to the prod port number.
        vs_prod.metadata.namespace = "default".to_string();
        let result = translate_k8s_objects(
            &[svc_default, svc_prod, vs_default, vs_prod],
            options().with_source_namespaces(vec!["default".to_string(), "prod".to_string()]),
        )
        .expect("translation succeeds");
        let default_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.id.contains("reviews-default"))
            .expect("default-namespace proxy materialized");
        let prod_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.id.contains("reviews-prod"))
            .expect("prod-namespace proxy materialized");
        assert_eq!(default_proxy.backend_port, 8080);
        assert_eq!(prod_proxy.backend_port, 9090);
    }

    #[test]
    fn vs_destination_short_host_isolates_services_by_vs_namespace() {
        // Short host (`reviews`) must inherit the VS's own namespace, NOT the
        // first matching service in any namespace. Two services with the same
        // name in different namespaces; the short-host VS in `prod` must pick
        // the `prod` service.
        let svc_default = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let svc_prod = service_with_named_ports("reviews", "prod", &[("http", 9090)]);
        let mut vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews",
                "port": {"name": "http"}
            }),
        );
        vs.metadata.namespace = "prod".to_string();
        let result = translate_k8s_objects(
            &[svc_default, svc_prod, vs],
            options().with_source_namespaces(vec!["default".to_string(), "prod".to_string()]),
        )
        .expect("translation succeeds");
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_port, 9090);
    }

    #[test]
    fn service_with_unnamed_ports_does_not_panic_and_lookup_misses() {
        // K8s allows Service ports without a `name` field. Those entries are
        // silently skipped by the indexer (no panic, no error). A VS that
        // references such a Service by port name must still fail closed
        // because the name was never indexed.
        let svc = K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: "reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: serde_json::json!({
                "ports": [
                    {"port": 8080},                           // no name
                    {"name": "grpc", "port": 9090}            // named entry survives
                ]
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let vs_missing = virtual_service_with_destination(
            "vs-missing",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc.clone(), vs_missing], options())
            .expect_err("unnamed Service ports must not satisfy a name lookup");
        assert!(
            err.to_string().contains("http"),
            "error must name the missing port: {err}"
        );

        // The named entry is still indexed and resolvable.
        let vs_grpc = virtual_service_with_destination(
            "vs-grpc",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "grpc"}
            }),
        );
        let result =
            translate_k8s_objects(&[svc, vs_grpc], options()).expect("named entry still resolves");
        assert_eq!(result.config.proxies[0].backend_port, 9090);
    }

    #[test]
    fn service_with_no_ports_field_does_not_panic() {
        // Service objects with no `spec.ports` array at all must not panic
        // the pre-pass — we just index an empty entry.
        let svc = K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: "reviews".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
                annotations: HashMap::new(),
            },
            spec: serde_json::json!({}),
            status: Value::Object(serde_json::Map::new()),
        };
        let result =
            translate_k8s_objects(&[svc], options()).expect("Service with no ports must not panic");
        assert!(result.config.proxies.is_empty());
    }

    #[test]
    fn vs_destination_port_name_resolves_with_trailing_dot_fqdn() {
        // Trailing dot is a valid DNS-FQDN form (root anchor); the host parser
        // must treat `reviews.default.svc.cluster.local.` the same as the
        // non-anchored FQDN. Otherwise hand-written Istio configs that copy
        // from `dig` output fail closed for no good reason.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local.",
                "port": {"name": "http"}
            }),
        );
        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_resolves_with_svc_only_suffix() {
        // `<svc>.<ns>.svc` (no cluster domain) is another canonical short
        // form Istio docs reference — the parser must take only the first
        // two labels and discard the `.svc` suffix.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc",
                "port": {"name": "http"}
            }),
        );
        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn service_objects_are_processed_regardless_of_input_order() {
        // The pre-pass design must tolerate arbitrary input order — a
        // VirtualService that appears BEFORE its Service in the input slice
        // must still resolve the port name. Two-pass translation guarantees
        // this, but a regression to single-pass would silently fail closed.
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let result = translate_k8s_objects(&[vs, svc], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_rejects_external_host() {
        // External hosts that happen to share a first/second label with a
        // real in-cluster Service must NOT trigger a service lookup. Before
        // this guard, `api.example.com` would silently parse as service=api,
        // namespace=example and either resolve against an unrelated Service
        // or emit a misleading "Service example/api not found" error.
        let svc = service_with_named_ports("api", "example", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "external-vs",
            serde_json::json!({
                "host": "api.example.com",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc, vs], options())
            .expect_err("external host must not be resolved against a Service");
        let msg = err.to_string();
        assert!(
            msg.contains("not a recognized in-cluster service form"),
            "error must explain the host shape rejection: {msg}"
        );
        assert!(
            msg.contains("api.example.com"),
            "error must echo the offending host: {msg}"
        );
    }

    #[test]
    fn vs_destination_port_name_rejects_partial_cluster_suffix() {
        // `<svc>.<ns>.cluster.local` (missing the `.svc.` infix) and
        // `<svc>.<ns>.svc.cluster` (missing the `.local` tail) are NOT valid
        // Kubernetes service DNS forms — accepting them silently encourages
        // operator typos to resolve against real services.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [
            "reviews.default.cluster.local",
            "reviews.default.svc.cluster",
            "reviews.default.svc.cluster.local.extra",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let err = translate_k8s_objects(&[svc.clone(), vs], options())
                .err()
                .unwrap_or_else(|| panic!("host '{host}' must be rejected"));
            assert!(
                err.to_string()
                    .contains("not a recognized in-cluster service form"),
                "host '{host}' must hit shape rejection: {err}"
            );
        }
    }

    #[test]
    fn vs_destination_port_name_rejects_empty_labels() {
        // Leading dots, consecutive dots, and lone-dot hosts produce empty
        // labels — the parser must reject these rather than picking the empty
        // string up as a service name.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [".reviews", "reviews..default", "."] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let err = translate_k8s_objects(&[svc.clone(), vs], options())
                .expect_err("empty-label host must be rejected");
            assert!(
                err.to_string()
                    .contains("not a recognized in-cluster service form"),
                "host '{host}' must hit shape rejection: {err}"
            );
        }
    }

    #[test]
    fn vs_destination_port_name_accepts_trailing_dot_on_short_forms() {
        // Trailing dot must apply uniformly across all accepted shapes, not
        // only the 5-label FQDN. Otherwise an operator typing `reviews.` or
        // `reviews.default.` gets an inconsistent rejection vs. the FQDN.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [
            "reviews.",
            "reviews.default.",
            "reviews.default.svc.",
            "reviews.default.svc.cluster.local.",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let result = translate_k8s_objects(&[svc.clone(), vs], options())
                .unwrap_or_else(|e| panic!("trailing-dot host '{host}' must resolve: {e}"));
            assert_eq!(result.config.proxies[0].backend_port, 8080);
        }
    }

    #[test]
    fn vs_destination_port_name_resolves_custom_cluster_domain() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let opts = options().with_cluster_domain("corp.example".to_string());
        for host in [
            "reviews.default.svc.corp.example",
            "reviews.default.svc.corp.example.",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let result = translate_k8s_objects(&[svc.clone(), vs], opts.clone())
                .unwrap_or_else(|e| panic!("custom domain host '{host}' must resolve: {e}"));
            assert_eq!(result.config.proxies[0].backend_port, 8080);
        }
    }

    #[test]
    fn vs_destination_port_name_rejects_wrong_cluster_domain() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let opts = options().with_cluster_domain("corp.example".to_string());
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc, vs], opts)
            .expect_err("cluster.local must be rejected when domain is corp.example");
        let msg = err.to_string();
        assert!(
            msg.contains("not a recognized in-cluster service form"),
            "error must explain shape rejection: {msg}"
        );
        assert!(
            msg.contains("corp.example"),
            "error must show the configured cluster domain: {msg}"
        );
    }

    // ── DestinationRule connectionPool TCP (maxConnections, tcpKeepalive) ─

    #[test]
    fn destination_rule_translates_top_level_tcp_max_connections() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "connectTimeout": "1s",
                                "maxConnections": 50
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        let tp = dr.traffic_policy.as_ref().expect("traffic policy");
        assert_eq!(tp.connect_timeout_ms, Some(1000));
        assert_eq!(tp.max_connections, Some(50));
        assert!(tp.tcp_keepalive.is_none());
    }

    #[test]
    fn destination_rule_translates_top_level_tcp_keepalive_full() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "tcpKeepalive": {
                                    "time": "300s",
                                    "interval": "30s",
                                    "probes": 3
                                }
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        let tp = dr.traffic_policy.as_ref().expect("traffic policy");
        let keepalive = tp.tcp_keepalive.as_ref().expect("tcp_keepalive");
        assert_eq!(keepalive.time_seconds, Some(300));
        assert_eq!(keepalive.interval_seconds, Some(30));
        assert_eq!(keepalive.probes, Some(3));
    }

    #[test]
    fn destination_rule_translates_partial_tcp_keepalive() {
        // Operators commonly tune only `time` (idle delay) and rely on
        // sysctl defaults for the rest. Each subfield independently optional.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "tcpKeepalive": {"time": "600s"}
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let keepalive = dr
            .traffic_policy
            .as_ref()
            .unwrap()
            .tcp_keepalive
            .as_ref()
            .unwrap();
        assert_eq!(keepalive.time_seconds, Some(600));
        assert!(keepalive.interval_seconds.is_none());
        assert!(keepalive.probes.is_none());
    }

    #[test]
    fn destination_rule_translates_port_level_tcp_max_connections() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {
                                    "tcp": {
                                        "maxConnections": 25,
                                        "tcpKeepalive": {
                                            "time": "120s",
                                            "interval": "10s",
                                            "probes": 5
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let port_policy = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        assert_eq!(port_policy.max_connections, Some(25));
        let keepalive = port_policy.tcp_keepalive.as_ref().expect("keepalive");
        assert_eq!(keepalive.time_seconds, Some(120));
        assert_eq!(keepalive.interval_seconds, Some(10));
        assert_eq!(keepalive.probes, Some(5));
    }

    #[test]
    fn destination_rule_rejects_negative_max_connections() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"tcp": {"maxConnections": -1}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("negative cap must fail");
        assert!(
            err.to_string().contains("maxConnections must be positive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_max_connections() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"tcp": {"maxConnections": 0}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero cap must fail");
        assert!(
            err.to_string().contains("maxConnections must be positive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_sub_second_tcp_keepalive_time() {
        // TCP_KEEPIDLE / TCP_KEEPALIVE are second-granular on every supported
        // OS. Silently rounding `500ms` to `1s` would change the operator's
        // configured idle delay; rejecting at translate time surfaces the
        // misconfiguration immediately.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {"tcpKeepalive": {"time": "500ms"}}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("sub-second keepalive time must fail");
        assert!(
            err.to_string().contains("whole number of seconds"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_tcp_keepalive_interval() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {"tcpKeepalive": {"interval": "0s"}}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero keepalive interval must fail");
        assert!(
            err.to_string().contains("must be at least 1s"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_tcp_keepalive_probes() {
        // `TCP_KEEPCNT` requires at least one probe — zero would yield no
        // detection at all (the socket would never declare the peer dead).
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {"tcpKeepalive": {"probes": 0}}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero probes must fail");
        assert!(
            err.to_string().contains("probes must be positive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_translates_negative_keepalive_duration_rejected() {
        // Negative durations fall out of `parse_istio_duration_ms` as `None`,
        // which the translator surfaces as a "not a valid Istio duration"
        // error rather than silently dropping the field.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {"tcpKeepalive": {"time": "-1s"}}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("negative duration must fail");
        assert!(
            err.to_string().contains("not a valid Istio duration"),
            "unexpected: {err}"
        );
    }

    // ── DestinationRule portLevelSettings ────────────────────────────────

    #[test]
    fn destination_rule_translates_single_port_level_setting() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {"tcp": {"connectTimeout": "750ms"}},
                                "loadBalancer": {"simple": "LEAST_REQUEST"},
                                "tls": {"mode": "ISTIO_MUTUAL"}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.port_level_settings.len(), 1);
        let policy = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        assert_eq!(policy.connect_timeout_ms, Some(750));
        assert!(matches!(
            policy.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest))
        ));
        // portLevelSettings[].tls is now resolved onto the per-port override and
        // applied per-port (see src/modes/mesh/mod.rs), so it parses into the
        // port policy and must NOT emit the old "not enforced per-port" warning.
        assert!(
            policy.tls.is_some(),
            "port-level tls must parse into the port policy, got {policy:?}"
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("not enforced per-port")),
            "stale per-port tls warning must be gone, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_translates_two_distinct_port_level_settings() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {"tcp": {"connectTimeout": "750ms"}},
                                "loadBalancer": {"simple": "LEAST_REQUEST"}
                            },
                            {
                                "port": {"number": 9090},
                                "connectionPool": {"tcp": {"connectTimeout": "2s"}},
                                "loadBalancer": {"simple": "RANDOM"}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.port_level_settings.len(), 2);

        let p8080 = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        assert_eq!(p8080.connect_timeout_ms, Some(750));
        assert!(matches!(
            p8080.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest))
        ));

        let p9090 = dr.port_level_settings.get(&9090).expect("port 9090 entry");
        assert_eq!(p9090.connect_timeout_ms, Some(2000));
        assert!(matches!(
            p9090.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random))
        ));
    }

    #[test]
    fn destination_rule_rejects_port_level_settings_port_out_of_range() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 70000},
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port out of range must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("portLevelSettings") && msg.contains("1-65535"),
            "expected port out-of-range error, got {msg}"
        );

        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 0},
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port zero must fail");
        assert!(
            err.to_string().contains("1-65535"),
            "expected port zero error, got {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_port_level_settings_without_port_number() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port.number missing must fail");
        assert!(
            err.to_string().contains("port.number is required"),
            "expected port.number required error, got {err}"
        );
    }

    // ── DestinationRule connectionPool HTTP (T1-C) ───────────────────────

    #[test]
    fn destination_rule_translates_top_level_connection_pool_http_supported_fields() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": {
                                "maxRequestsPerConnection": 100,
                                "idleTimeout": "300s",
                                "http2MaxRequests": 1000
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        let tp = dr.traffic_policy.as_ref().expect("traffic policy");
        let http = tp.connection_pool_http.as_ref().expect("http overlay");
        assert!(
            http.max_requests_per_connection.is_none(),
            "maxRequestsPerConnection is validated but deferred, not projected"
        );
        assert_eq!(http.idle_timeout_ms, Some(300_000));
        assert_eq!(http.http2_max_requests, Some(1000));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("maxRequestsPerConnection") && w.contains("not applied") }),
            "unsupported maxRequestsPerConnection must warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_translates_partial_connection_pool_http() {
        // Operators commonly set only one knob — verify that partial overlays
        // round-trip without auto-filling other fields.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": {"http2MaxRequests": 500}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let http = dr
            .traffic_policy
            .as_ref()
            .unwrap()
            .connection_pool_http
            .as_ref()
            .unwrap();
        assert_eq!(http.http2_max_requests, Some(500));
        assert!(http.max_requests_per_connection.is_none());
        assert!(http.idle_timeout_ms.is_none());
    }

    #[test]
    fn destination_rule_translates_port_level_connection_pool_http() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {
                                    "http": {
                                        "maxRequestsPerConnection": 50,
                                        "idleTimeout": "60s",
                                        "http2MaxRequests": 200
                                    }
                                }
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let port_policy = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        let http = port_policy
            .connection_pool_http
            .as_ref()
            .expect("port http overlay");
        assert!(
            http.max_requests_per_connection.is_none(),
            "maxRequestsPerConnection is deferred at port level too"
        );
        assert_eq!(http.idle_timeout_ms, Some(60_000));
        assert_eq!(http.http2_max_requests, Some(200));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("maxRequestsPerConnection") && w.contains("not applied") }),
            "port-level unsupported maxRequestsPerConnection must warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_skips_empty_connection_pool_http_block() {
        // An operator who writes `connectionPool: { http: {} }` should not
        // wind up with an `Some(overlay)` that gets materialised onto every
        // port — empty overlays must collapse to `None` so the apply pass
        // sees "no HTTP overlay configured".
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {}}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let dr = &result.config.mesh.unwrap().destination_rules[0];
        assert!(
            dr.traffic_policy
                .as_ref()
                .and_then(|tp| tp.connection_pool_http.as_ref())
                .is_none(),
            "empty connectionPool.http must collapse to None"
        );
    }

    #[test]
    fn destination_rule_rejects_negative_max_requests_per_connection() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"maxRequestsPerConnection": -5}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("negative maxRequestsPerConnection must fail");
        assert!(
            err.to_string()
                .contains("maxRequestsPerConnection must be non-negative"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_accepts_zero_max_requests_per_connection_but_defers_it() {
        // Istio's documented "unlimited" sentinel for maxRequestsPerConnection
        // is `0`; keep accepting it for validation compatibility, but do not
        // carry the unsupported field into the mesh overlay.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"maxRequestsPerConnection": 0}}
                    }
                }),
            )],
            options(),
        )
        .expect("zero maxRequestsPerConnection (Istio unlimited) must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert!(
            dr.traffic_policy.is_none(),
            "maxRequestsPerConnection-only trafficPolicy must not synthesize an effective policy"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("maxRequestsPerConnection") && w.contains("not applied") }),
            "unsupported maxRequestsPerConnection must warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_drops_port_level_max_requests_only_policy() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {
                                    "http": {"maxRequestsPerConnection": 2}
                                }
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("maxRequestsPerConnection-only port policy must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert!(
            dr.traffic_policy.is_none(),
            "top-level trafficPolicy containing only portLevelSettings must not become a default policy"
        );
        assert!(
            dr.port_level_settings.is_empty(),
            "maxRequestsPerConnection-only portLevelSettings entry must not synthesize an effective port policy"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("maxRequestsPerConnection") && w.contains("not applied") }),
            "unsupported maxRequestsPerConnection must warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_rejects_duplicate_port_level_settings_even_when_first_is_deferred_only() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {
                                    "http": {"maxRequestsPerConnection": 2}
                                }
                            },
                            {
                                "port": {"number": 8080},
                                "connectionPool": {
                                    "http": {"idleTimeout": "30s"}
                                }
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("duplicate port must still fail");

        assert!(
            err.to_string().contains("duplicate port 8080"),
            "unexpected duplicate-port error: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_http2_max_requests() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"http2MaxRequests": 0}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero http2MaxRequests must fail");
        assert!(
            err.to_string()
                .contains("http2MaxRequests must be positive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_sub_second_idle_timeout() {
        // `Proxy.pool_idle_timeout_seconds` is whole-second granular —
        // silently rounding `500ms` to `1s` would not match the operator's
        // configured idle window, so reject at translate time.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"idleTimeout": "500ms"}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("sub-second idleTimeout must fail");
        assert!(
            err.to_string().contains("whole number of seconds"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_idle_timeout() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"idleTimeout": "0s"}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero idleTimeout must fail");
        assert!(
            err.to_string().contains("idleTimeout must be at least 1s"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_unparseable_idle_timeout() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"idleTimeout": "not-a-duration"}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unparseable idleTimeout must fail");
        assert!(
            err.to_string().contains("not a valid Istio duration"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_idle_timeout_above_proxy_cap() {
        // The proxy-level `pool_idle_timeout_seconds` validator caps the
        // field at `MAX_POOL_IDLE_TIMEOUT` (1 h). The per-target Cow-clone
        // in `resolve_effective_proxy_for_target` writes the resolved seconds
        // value directly onto a `Proxy` clone without re-running
        // `validate_fields()`, so an `idleTimeout` above that cap would
        // bypass the validator silently. Reject in the translator so the K8s
        // surface stays consistent with admin-API admission.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"idleTimeout": "7200s"}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("idleTimeout above proxy cap must fail");
        assert!(
            err.to_string()
                .contains("exceeds the proxy idle-timeout cap"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_projects_top_level_http_connection_pool_knobs_without_warning() {
        // After F5.1's final knob, ALL of `maxRetries`, `h2UpgradePolicy`, and
        // `http1MaxPendingRequests` are projected at top-level/portLevelSettings
        // and must NOT warn. `maxRequestsPerConnection` is the only top-level
        // deferred connectionPool.http knob. Every supported field lands on the overlay.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": {
                                "http1MaxPendingRequests": 1024,
                                "maxRetries": 5,
                                "h2UpgradePolicy": "UPGRADE",
                                "http2MaxRequests": 250
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        // None of the top-level connectionPool.http knobs warn anymore.
        for field in ["http1MaxPendingRequests", "maxRetries", "h2UpgradePolicy"] {
            assert!(
                !result.warnings.iter().any(|w| w.contains(field)),
                "{field} is projected now and must not warn; warnings = {:?}",
                result.warnings
            );
        }
        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let http = dr
            .traffic_policy
            .as_ref()
            .unwrap()
            .connection_pool_http
            .as_ref()
            .unwrap();
        // Every supported field landed on the overlay, including the new one.
        assert_eq!(http.http2_max_requests, Some(250));
        assert_eq!(http.max_retries, Some(5));
        assert_eq!(
            http.h2_upgrade_policy,
            Some(crate::config::types::H2UpgradePolicy::Upgrade)
        );
        assert_eq!(http.http1_max_pending_requests, Some(1024));
        // Unset fields stay None.
        assert!(http.max_requests_per_connection.is_none());
        assert!(http.idle_timeout_ms.is_none());
    }

    #[test]
    fn destination_rule_rejects_zero_http1_max_pending_requests() {
        // A `0` pending cap would shed every H1 request; reject at translate
        // time like the other uint32 knobs rather than silently disabling.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": { "http1MaxPendingRequests": 0 }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero http1MaxPendingRequests must fail closed");
        assert!(
            err.to_string().contains("http1MaxPendingRequests"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn destination_rule_translates_h2_upgrade_policy_and_max_retries() {
        use crate::config::types::H2UpgradePolicy;
        // DO_NOT_UPGRADE + maxRetries on the top-level connectionPool.http.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": {
                                "h2UpgradePolicy": "DO_NOT_UPGRADE",
                                "maxRetries": 2
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let http = dr
            .traffic_policy
            .as_ref()
            .unwrap()
            .connection_pool_http
            .as_ref()
            .unwrap();
        assert_eq!(http.h2_upgrade_policy, Some(H2UpgradePolicy::DoNotUpgrade));
        assert_eq!(http.max_retries, Some(2));
        // No warning for the now-projected fields.
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("h2UpgradePolicy") || w.contains("maxRetries")),
            "projected fields must not warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_h2_upgrade_policy_default_is_carried_explicitly() {
        use crate::config::types::H2UpgradePolicy;
        // Istio's `DEFAULT` means "probe-driven" at the dispatch fork, but it is
        // carried as the explicit `H2UpgradePolicy::Default` variant (NOT
        // collapsed to `None`) so an EXPLICIT port-level `DEFAULT` can later
        // clear an inherited top-level `UPGRADE`/`DO_NOT_UPGRADE` for that port.
        // (codex round-1 Finding 3.)
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"h2UpgradePolicy": "DEFAULT"}}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let dr = &result.config.mesh.unwrap().destination_rules[0];
        let http = dr
            .traffic_policy
            .as_ref()
            .and_then(|p| p.connection_pool_http.as_ref())
            .expect("explicit DEFAULT synthesizes an overlay carrying Default");
        assert_eq!(http.h2_upgrade_policy, Some(H2UpgradePolicy::Default));
        // No warning: DEFAULT is a recognized value, not deferred.
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("h2UpgradePolicy")),
            "DEFAULT must not warn; warnings = {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_port_level_default_clears_inherited_top_level_policy() {
        use crate::config::types::H2UpgradePolicy;
        // codex round-1 Finding 3: a top-level `UPGRADE` plus a port-level
        // EXPLICIT `DEFAULT` must resolve that port to probe-driven (Default),
        // NOT inherit the top-level UPGRADE. We assert the TRANSLATION carries
        // the distinction (top-level Upgrade, port-level explicit Default); the
        // mesh-apply layering (`apply_connection_pool_http_to_port_override`)
        // then overwrites the inherited slot — covered by the mesh port-policy
        // integration test.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"h2UpgradePolicy": "UPGRADE"}},
                        "portLevelSettings": [{
                            "port": {"number": 8080},
                            "connectionPool": {"http": {"h2UpgradePolicy": "DEFAULT"}}
                        }]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let dr = &result.config.mesh.unwrap().destination_rules[0];
        // Top-level carries Upgrade.
        assert_eq!(
            dr.traffic_policy
                .as_ref()
                .unwrap()
                .connection_pool_http
                .as_ref()
                .unwrap()
                .h2_upgrade_policy,
            Some(H2UpgradePolicy::Upgrade)
        );
        // Port 8080 carries explicit Default (distinguishable from absent) so
        // the apply layer can clear the inherited Upgrade for that port.
        assert_eq!(
            dr.port_level_settings
                .get(&8080)
                .unwrap()
                .connection_pool_http
                .as_ref()
                .unwrap()
                .h2_upgrade_policy,
            Some(H2UpgradePolicy::Default)
        );
    }

    #[test]
    fn destination_rule_subset_http_connection_pool_knobs_deferred_with_warning() {
        use crate::config::types::H2UpgradePolicy;
        // codex round-1 Finding 4 (+ F5.1 final knob): top-level
        // h2UpgradePolicy/maxRetries/http1MaxPendingRequests are APPLIED (no
        // warning), but the SAME fields inside a subset's trafficPolicy are NOT
        // applied (subset -> SubsetTrafficPolicy carries no connectionPool.http),
        // so they must warn (and be dropped from the subset overlay), matching
        // reality.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    // Top-level: applied, must NOT warn.
                    "trafficPolicy": {
                        "connectionPool": {"http": {"h2UpgradePolicy": "UPGRADE", "maxRetries": 4, "http1MaxPendingRequests": 32}}
                    },
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        // Subset: ignored, must warn + drop.
                        "trafficPolicy": {
                            "connectionPool": {"http": {
                                "h2UpgradePolicy": "DO_NOT_UPGRADE",
                                "maxRetries": 9,
                                "http1MaxPendingRequests": 16
                            }}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // Subset-scoped warnings present for ALL THREE fields.
        for field in ["h2UpgradePolicy", "maxRetries", "http1MaxPendingRequests"] {
            assert!(
                result.warnings.iter().any(|w| {
                    w.contains("subsets[].trafficPolicy.connectionPool.http")
                        && w.contains(field)
                        && w.contains("not applied for subsets")
                }),
                "expected a subset-scoped deferral warning for {field}; warnings = {:?}",
                result.warnings
            );
        }

        let dr = &result.config.mesh.unwrap().destination_rules[0];
        // Top-level fields ARE applied (carried on the overlay).
        let top = dr
            .traffic_policy
            .as_ref()
            .unwrap()
            .connection_pool_http
            .as_ref()
            .unwrap();
        assert_eq!(top.h2_upgrade_policy, Some(H2UpgradePolicy::Upgrade));
        assert_eq!(top.max_retries, Some(4));
        assert_eq!(top.http1_max_pending_requests, Some(32));

        // Subset fields are DROPPED (not applied), so the subset's HTTP overlay
        // carries none (and with only the deferred fields set, no overlay).
        let subset = &dr.subsets[0];
        assert!(
            subset
                .traffic_policy
                .as_ref()
                .and_then(|tp| tp.connection_pool_http.as_ref())
                .is_none(),
            "subset connectionPool.http with only the deferred fields must not \
             synthesize an overlay: {:?}",
            subset.traffic_policy
        );
    }

    #[test]
    fn destination_rule_subset_invalid_h2_upgrade_policy_still_fails_closed() {
        // Even though subset connectionPool.http is deferred, a malformed value
        // must still fail closed at translate time (validation runs in every
        // scope), not be silently accepted-then-dropped.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "connectionPool": {"http": {"h2UpgradePolicy": "NOPE"}}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid subset h2UpgradePolicy must fail closed");
        assert!(
            err.to_string().contains("h2UpgradePolicy")
                && err.to_string().contains("not a valid value"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_invalid_h2_upgrade_policy() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"h2UpgradePolicy": "MAYBE"}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unknown h2UpgradePolicy must fail closed");
        assert!(
            err.to_string().contains("h2UpgradePolicy")
                && err.to_string().contains("not a valid value"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_zero_max_retries() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"maxRetries": 0}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("zero maxRetries must fail");
        assert!(
            err.to_string().contains("maxRetries must be positive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_negative_max_retries() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {"http": {"maxRetries": -1}}
                    }
                }),
            )],
            options(),
        )
        .expect_err("negative maxRetries must fail");
        assert!(
            err.to_string().contains("maxRetries must be positive"),
            "unexpected: {err}"
        );
    }

    // ── Sidecar translator ──────────────────────────────────────────────

    #[test]
    fn sidecar_with_workload_selector_and_egress_translates_correctly() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {
                        "labels": {"app": "frontend"}
                    },
                    "egress": [
                        {
                            "hosts": [
                                "./reviews.default.svc.cluster.local",
                                "*/external.example.com"
                            ],
                            "port": {"number": 8080}
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // Sidecar must NOT produce the old Phase-D warning. Port scoping is
        // parsed into the mesh model and enforced later when the Sidecar
        // enforcement gate is enabled.
        assert!(
            !result.warnings.iter().any(|w| w.contains("Phase D")),
            "Sidecar translation must not emit the deferred warning; warnings = {:?}",
            result.warnings
        );
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("egress port scoping")),
            "Sidecar egress port should not emit a stale unsupported warning; warnings = {:?}",
            result.warnings
        );

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        let sc = &mesh.sidecars[0];
        assert_eq!(sc.name, "sample");
        assert_eq!(sc.namespace, "default");
        let selector = sc
            .workload_selector
            .as_ref()
            .expect("workload selector parsed");
        assert_eq!(
            selector.labels.get("app").map(String::as_str),
            Some("frontend")
        );
        assert_eq!(selector.namespace.as_deref(), Some("default"));
        assert!(!sc.egress_inherits_defaults);
        assert_eq!(sc.egress.len(), 1);
        assert_eq!(
            sc.egress[0].hosts,
            vec![
                "./reviews.default.svc.cluster.local".to_string(),
                "*/external.example.com".to_string(),
            ]
        );
        assert_eq!(sc.egress[0].port, Some(8080));
    }

    #[test]
    fn sidecar_without_workload_selector_is_namespace_default() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["./reviews.default.svc.cluster.local"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(mesh.sidecars[0].workload_selector.is_none());
        assert!(!mesh.sidecars[0].egress_inherits_defaults);
        assert_eq!(mesh.sidecars[0].egress[0].port, None);
    }

    #[test]
    fn sidecar_with_omitted_egress_inherits_outbound_defaults() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"labels": {"app": "frontend"}},
                    "ingress": [
                        {"port": {"number": 8080, "protocol": "HTTP", "name": "http"}}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(mesh.sidecars[0].egress_inherits_defaults);
        assert!(mesh.sidecars[0].egress.is_empty());
    }

    #[test]
    fn sidecar_translator_emits_no_warning_for_valid_resource() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result.warnings.is_empty(),
            "valid Sidecar must produce no warnings; got {:?}",
            result.warnings
        );
    }

    #[test]
    fn sidecar_in_root_namespace_translates_without_scope_warning() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options().with_istio_root_namespace("default".to_string()),
        )
        .expect("translation succeeds");

        assert!(
            result.warnings.is_empty(),
            "root namespace Sidecar is now a supported cluster-wide default; warnings = {:?}",
            result.warnings
        );
        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.istio_root_namespace, "default");
        assert_eq!(mesh.sidecars.len(), 1);
        assert_eq!(mesh.sidecars[0].namespace, "default");
    }

    #[test]
    fn sidecar_root_namespace_workload_selector_is_namespace_scoped() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"labels": {"app": "frontend"}},
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options().with_istio_root_namespace("default".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let selector = mesh.sidecars[0]
            .workload_selector
            .as_ref()
            .expect("selector should be preserved");
        assert_eq!(selector.namespace.as_deref(), Some("default"));
        assert_eq!(
            selector.labels.get("app").map(String::as_str),
            Some("frontend")
        );
    }

    #[test]
    fn sidecar_with_empty_workload_selector_labels_is_namespace_default() {
        // workloadSelector present but labels empty → treat as no
        // selector. Mirrors Istio: a Sidecar with an empty selector applies
        // to every workload in the namespace (i.e. namespace-default).
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"labels": {}},
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(
            mesh.sidecars[0].workload_selector.is_none(),
            "empty labels should round-trip to no selector"
        );
    }

    #[test]
    fn sidecar_matchlabels_selector_remains_compatibility_fallback() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"matchLabels": {"app": "frontend"}},
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let selector = mesh.sidecars[0]
            .workload_selector
            .as_ref()
            .expect("fallback matchLabels selector should be preserved");
        assert_eq!(
            selector.labels.get("app").map(String::as_str),
            Some("frontend")
        );
    }

    #[test]
    fn sidecar_with_invalid_port_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {
                            "hosts": ["./svc.default.svc.cluster.local"],
                            "port": {"number": 0}
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect_err("port 0 should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].port.number"),
            "error must reference the field; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_missing_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"port": {"number": 8080}}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("missing hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_empty_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": []}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("empty hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_non_string_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["./svc.default.svc.cluster.local", 42]}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("non-string hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }

    #[test]
    fn sidecar_ingress_translates_listener_fields() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [
                        {
                            "port": {"number": 8443, "protocol": "HTTP", "name": "https"},
                            "bind": "127.0.0.1",
                            "defaultEndpoint": "127.0.0.1:8080"
                        },
                        {
                            "port": {"number": 9000, "protocol": "GRPC"},
                            "defaultEndpoint": "unix:///var/run/grpc.sock"
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("ingress translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        let sc = &mesh.sidecars[0];
        assert_eq!(sc.ingress.len(), 2);
        assert_eq!(sc.ingress[0].port, 8443);
        assert_eq!(sc.ingress[0].protocol, AppProtocol::Http);
        assert_eq!(sc.ingress[0].name.as_deref(), Some("https"));
        assert_eq!(sc.ingress[0].bind.as_deref(), Some("127.0.0.1"));
        assert_eq!(sc.ingress[0].default_endpoint, "127.0.0.1:8080");
        // The unix-socket entry is parsed (deferred later), not rejected.
        assert_eq!(sc.ingress[1].port, 9000);
        assert_eq!(sc.ingress[1].default_endpoint, "unix:///var/run/grpc.sock");
    }

    #[test]
    fn sidecar_ingress_missing_port_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect_err("ingress without a port must be rejected");
        assert!(
            err.to_string().contains("Sidecar ingress[].port"),
            "error must reference the missing port; got {err}"
        );
    }

    #[test]
    fn sidecar_ingress_zero_port_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 0}, "defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect_err("ingress port 0 must be rejected");
        assert!(
            err.to_string().contains("ingress[].port.number"),
            "error must reference the invalid port; got {err}"
        );
    }

    #[test]
    fn sidecar_ingress_non_array_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({"ingress": {"port": {"number": 8443}}}),
            )],
            options(),
        )
        .expect_err("non-array ingress must be rejected");
        assert!(
            err.to_string().contains("Sidecar ingress must be an array"),
            "error must reference the array shape; got {err}"
        );
    }

    #[test]
    fn sidecar_ingress_omitted_default_endpoint_accepted() {
        // Istio allows omitting defaultEndpoint; the translator accepts it
        // (the entry is deferred — not modeled — at resolution).
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 8443, "protocol": "HTTP"}}]
                }),
            )],
            options(),
        )
        .expect("omitted defaultEndpoint is accepted");
        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars[0].ingress.len(), 1);
        assert!(mesh.sidecars[0].ingress[0].default_endpoint.is_empty());
    }

    #[test]
    fn sidecar_explicit_empty_ingress_is_declared() {
        // Codex round-2 P1: an explicit `ingress: []` is DISTINCT from an omitted
        // ingress block. Istio treats a declared (even empty) ingress as
        // replacing the default per-service-port inbound listeners, so the
        // translator records the declaration via `ingress_declared` — the slice
        // builder then suppresses the default inbound routes (fail-closed) rather
        // than exposing the service-port defaults.
        let result = translate_k8s_objects(
            &[object("Sidecar", serde_json::json!({ "ingress": [] }))],
            options(),
        )
        .expect("explicit empty ingress is accepted");
        let mesh = result.config.mesh.expect("mesh config");
        let sc = &mesh.sidecars[0];
        assert!(sc.ingress.is_empty(), "no listener entries resolved");
        assert!(
            sc.ingress_declared,
            "explicit `ingress: []` must mark the Sidecar as having DECLARED ingress"
        );
    }

    #[test]
    fn sidecar_omitted_ingress_is_not_declared() {
        // The complement: an OMITTED ingress block keeps the automatic
        // per-service-port inbound defaults, so `ingress_declared` stays false.
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({ "egress": [{"hosts": ["./*"]}] }),
            )],
            options(),
        )
        .expect("sidecar without ingress is accepted");
        let mesh = result.config.mesh.expect("mesh config");
        let sc = &mesh.sidecars[0];
        assert!(sc.ingress.is_empty());
        assert!(
            !sc.ingress_declared,
            "an omitted ingress block must NOT mark ingress as declared"
        );
    }

    #[test]
    fn sidecar_nonempty_ingress_is_declared() {
        // A non-empty ingress always declares (independent of the explicit-empty
        // marker), so the existing non-empty translation path keeps suppressing
        // the defaults.
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 8443, "protocol": "HTTP"}, "defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect("non-empty ingress is accepted");
        let mesh = result.config.mesh.expect("mesh config");
        assert!(mesh.sidecars[0].ingress_declared);
    }

    #[test]
    fn sidecar_ingress_https_protocol_is_http_family() {
        // Codex round-2 P2 (preserve round-1): an HTTPS listener is a recognized
        // HTTP-family protocol and is modeled (mapped to a routable AppProtocol),
        // NOT deferred.
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 8443, "protocol": "HTTPS"}, "defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect("https ingress is accepted");
        let mesh = result.config.mesh.expect("mesh config");
        let entry = &mesh.sidecars[0].ingress[0];
        assert!(
            crate::modes::mesh::config::is_http_family_app_protocol(entry.protocol),
            "an HTTPS ingress listener must be HTTP-family (modeled), got {:?}",
            entry.protocol
        );
        assert!(
            entry.resolve().is_ok(),
            "an HTTPS listener with a loopback defaultEndpoint must resolve to a route"
        );
    }

    #[test]
    fn sidecar_ingress_unrecognized_protocol_is_deferred() {
        // Codex round-2 P2: a TYPO like `HTPS` must NOT be routed as HTTP. The
        // ingress-specific classifier maps it to a non-HTTP AppProtocol so
        // resolution defers it (NonHttpProtocol) instead of exposing a
        // non-modeled listener on the HTTP request path.
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 8443, "protocol": "HTPS"}, "defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect("the resource is still accepted; the entry is deferred");
        let mesh = result.config.mesh.expect("mesh config");
        let entry = &mesh.sidecars[0].ingress[0];
        assert!(
            !crate::modes::mesh::config::is_http_family_app_protocol(entry.protocol),
            "a mistyped protocol must NOT be HTTP-family, got {:?}",
            entry.protocol
        );
        assert!(
            matches!(
                entry.resolve(),
                Err(crate::modes::mesh::config::IngressListenerUnsupported::NonHttpProtocol)
            ),
            "a mistyped protocol must defer as a non-HTTP listener, not route"
        );
    }

    #[test]
    fn sidecar_ingress_missing_protocol_is_deferred() {
        // A MISSING protocol on a custom inbound listener defers (Istio defaults
        // an unset port protocol to TCP; Ferrum fails closed rather than guessing
        // HTTP for an explicitly declared listener). Distinct from the
        // service-port default path, where an unknown appProtocol stays HTTP.
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "ingress": [{"port": {"number": 8443}, "defaultEndpoint": "127.0.0.1:8080"}]
                }),
            )],
            options(),
        )
        .expect("the resource is accepted; the entry is deferred");
        let mesh = result.config.mesh.expect("mesh config");
        let entry = &mesh.sidecars[0].ingress[0];
        assert!(
            !crate::modes::mesh::config::is_http_family_app_protocol(entry.protocol),
            "a missing protocol must NOT be HTTP-family, got {:?}",
            entry.protocol
        );
        assert!(matches!(
            entry.resolve(),
            Err(crate::modes::mesh::config::IngressListenerUnsupported::NonHttpProtocol)
        ));
    }

    #[test]
    fn sidecar_ingress_protocol_classifier_lockstep() {
        // The status-writer predicate and the translator's carried-protocol
        // mapping must agree on routability for every class (lock-step).
        for (proto, want_modeled) in [
            (Some("HTTP"), true),
            (Some("http2"), true),
            (Some("GRPC"), true),
            (Some("HTTPS"), true),
            (Some("TCP"), false),
            (Some("TLS"), false),
            (Some("HTPS"), false), // typo
            (Some("nonsense"), false),
            (None, false), // missing → TCP default → deferred
        ] {
            let status_says =
                crate::config_sources::k8s::sidecar_ingress_protocol_is_http_family(proto);
            let translator_says = crate::modes::mesh::config::is_http_family_app_protocol(
                sidecar_ingress_app_protocol(proto),
            );
            assert_eq!(
                status_says, translator_says,
                "status writer and translator disagree on protocol {proto:?}"
            );
            assert_eq!(
                status_says, want_modeled,
                "protocol {proto:?} routability mismatch"
            );
        }
    }
}
