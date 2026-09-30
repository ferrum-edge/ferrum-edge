//! External regressions for HTTPRoute / GRPCRoute parent attachment
//! materialization (issue #3612 / PR #3677).
//!
//! Port-aware routing keys each claim on the concrete Gateway listener behind
//! it. A declared Gateway `parentRef` that resolves no concrete,
//! materializable listener must fail closed: emit no proxy, upstream, plugin,
//! or materialized-parent record for that parent — including an absent Gateway
//! and sectionName/port/policy gates that clear no listener. Falling back to a
//! listener-less claim would expose the backend on unrelated frontends while
//! status reports `NoMatchingParent` / `NotAllowedByListeners`.
//!
//! The same gate applies to conflict keys: an unmaterializable declared parent
//! must not invent a cross-kind traffic-ownership domain. HTTPRoute + GRPCRoute
//! on a hostname-mismatched managed Gateway keep the attachment-failure status
//! (`Programmed=False`) and never report `Conflicted`. An absent Gateway cannot
//! prove controller ownership, so Ferrum opens no traffic and correctly leaves
//! status untouched. The deliberately parentless legacy shape
//! (`spec.parentRefs` absent) still materializes a listener-less claim and still
//! arbitrates cross-kind on that global claim, without claiming route status.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::plan_gateway_api_status_updates;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: kind.to_string(),
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
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "ferrum",
        json!({"controllerName": "ferrum.io/gateway-controller"}),
    )
}

fn http_gateway(name: &str, port: u16) -> K8sObject {
    object(
        "Gateway",
        name,
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": port,
                "protocol": "HTTP",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    )
}

fn hostname_mismatched_gateway(name: &str, port: u16) -> K8sObject {
    object(
        "Gateway",
        name,
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": port,
                "protocol": "HTTP",
                "hostname": "other.example.com",
                "allowedRoutes": {
                    "namespaces": {"from": "All"},
                    "kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]
                }
            }]
        }),
    )
}

fn http_route(name: &str, parent_refs: Option<Value>) -> K8sObject {
    http_route_with_hostname(name, "api.example.com", parent_refs)
}

fn http_route_with_hostname(name: &str, hostname: &str, parent_refs: Option<Value>) -> K8sObject {
    let mut spec = json!({
        "hostnames": [hostname],
        "rules": [{
            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
            "backendRefs": [{"name": "api", "port": 8080}]
        }]
    });
    if let Some(parent_refs) = parent_refs {
        spec["parentRefs"] = parent_refs;
    }
    object("HTTPRoute", name, spec)
}

fn grpc_route(name: &str, parent_refs: Option<Value>) -> K8sObject {
    grpc_route_with_hostname(name, "grpc.example.com", parent_refs)
}

fn grpc_route_with_hostname(name: &str, hostname: &str, parent_refs: Option<Value>) -> K8sObject {
    let mut spec = json!({
        "hostnames": [hostname],
        "rules": [{
            "matches": [{"method": {"service": "example.Echo", "method": "Get"}}],
            "backendRefs": [{"name": "grpc-api", "port": 50051}]
        }]
    });
    if let Some(parent_refs) = parent_refs {
        spec["parentRefs"] = parent_refs;
    }
    object("GRPCRoute", name, spec)
}

fn assert_no_http_family_traffic(objects: &[K8sObject], kind: &str, name: &str) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");

    assert!(
        result.config.proxies.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no proxy, got {:?}",
        result
            .config
            .proxies
            .iter()
            .map(|proxy| (proxy.id.clone(), proxy.listen_port, proxy.backend_port))
            .collect::<Vec<_>>()
    );
    assert!(
        result.config.upstreams.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no upstream, got {:?}",
        result.config.upstreams
    );
    assert!(
        result.config.plugin_configs.is_empty(),
        "{kind} {name}: declared unresolved parent must emit no plugin, got {:?}",
        result.config.plugin_configs
    );
    assert!(
        !result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == kind && entry.route.name == name),
        "{kind} {name}: declared unresolved parent must leave no materialized-parent record, got {:?}",
        result.materialized_route_parents
    );
}

fn parent_condition_status(
    updates: &[ferrum_edge::k8s_controller::status::GatewayApiStatusUpdate],
    kind: &str,
    name: &str,
    condition_type: &str,
) -> Option<(String, String)> {
    let route_update = updates
        .iter()
        .find(|update| update.kind == kind && update.name == name)?;
    let parents = route_update.status["parents"].as_array()?;
    let conditions = parents.first()?.get("conditions")?.as_array()?;
    conditions.iter().find_map(|condition| {
        if condition["type"].as_str() == Some(condition_type) {
            Some((
                condition["status"].as_str()?.to_string(),
                condition["reason"].as_str()?.to_string(),
            ))
        } else {
            None
        }
    })
}

fn assert_status_not_programmed(objects: &[K8sObject], kind: &str, name: &str, reason: &str) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    let route_update = updates
        .iter()
        .find(|update| update.kind == kind && update.name == name)
        .unwrap_or_else(|| panic!("expected status update for {kind}/{name}"));
    let parents = route_update.status["parents"]
        .as_array()
        .expect("parents array");
    assert!(
        !parents.is_empty(),
        "{kind}/{name} must still surface a parent status entry"
    );
    let conditions = parents[0]["conditions"]
        .as_array()
        .expect("parent conditions");
    let accepted = conditions
        .iter()
        .find(|condition| condition["type"] == "Accepted")
        .expect("Accepted condition");
    let programmed = conditions
        .iter()
        .find(|condition| condition["type"] == "Programmed")
        .expect("Programmed condition");
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], reason);
    assert_eq!(programmed["status"], "False");
    assert_ne!(
        programmed["reason"], "Programmed",
        "{kind}/{name} must not report Programmed while the declared parent resolves no listener"
    );
}

fn assert_no_ferrum_route_status(objects: &[K8sObject]) {
    let updates = plan_gateway_api_status_updates(objects, options(), &[]);
    assert!(
        updates
            .iter()
            .all(|update| !matches!(update.kind.as_str(), "HTTPRoute" | "GRPCRoute")),
        "Ferrum must not claim status without a parent owned by its controller: {updates:?}"
    );
}

/// Shared assertion for HTTPRoute + GRPCRoute on an unmaterializable parent:
/// neither route serves traffic, neither invents a Conflicted ownership loss,
/// and both keep the attachment-failure reason with Programmed=False.
fn assert_unresolved_cross_kind_pair_is_attachment_failure(
    objects: &[K8sObject],
    attachment_reason: &str,
) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    assert!(
        result.config.proxies.is_empty(),
        "neither unresolved route may materialize a proxy: {:?}",
        result.config.proxies
    );
    assert!(
        result.materialized_route_parents.is_empty(),
        "neither unresolved route may record a materialized parent: {:?}",
        result.materialized_route_parents
    );
    assert!(
        result.route_conflicts.is_empty(),
        "unmaterializable parents must not invent route conflicts: {:?}",
        result.route_conflicts
    );

    let updates = plan_gateway_api_status_updates(objects, options(), &result.route_conflicts);
    for (kind, name) in [("HTTPRoute", "web"), ("GRPCRoute", "grpc")] {
        let (accepted_status, accepted_reason) =
            parent_condition_status(&updates, kind, name, "Accepted")
                .unwrap_or_else(|| panic!("expected Accepted for {kind}/{name}"));
        let (programmed_status, programmed_reason) =
            parent_condition_status(&updates, kind, name, "Programmed")
                .unwrap_or_else(|| panic!("expected Programmed for {kind}/{name}"));
        assert_eq!(accepted_status, "False");
        assert_eq!(
            accepted_reason, attachment_reason,
            "{kind}/{name} must keep the attachment-failure reason, not Conflicted"
        );
        assert_ne!(
            accepted_reason, "Conflicted",
            "{kind}/{name} must not report Accepted reason Conflicted"
        );
        assert_eq!(programmed_status, "False");
        assert_ne!(
            programmed_reason, "Programmed",
            "{kind}/{name} must not report Programmed while attachment failed"
        );
        if let Some((conflicted_status, _)) =
            parent_condition_status(&updates, kind, name, "Conflicted")
        {
            assert_eq!(
                conflicted_status, "False",
                "{kind}/{name} must not be Conflicted=True for an unmaterializable parent"
            );
        }
    }
}

/// A literal path match that itself contains `;` declares a path parameter,
/// so its translated proxy opts in to path parameters instead of being
/// unreachable and refused at admission (GHSA-fcqw-793q-wg5x). Every other
/// route keeps the default refusal.
#[test]
fn a_literal_path_match_with_a_semicolon_opts_in_to_path_parameters() {
    for (path, expected) in [
        (json!({"type": "PathPrefix", "value": "/api;v=1"}), true),
        (json!({"type": "Exact", "value": "/api;v=1"}), true),
        (json!({"type": "PathPrefix", "value": "/api"}), false),
    ] {
        let mut route = http_route("sample", None);
        route.spec["rules"][0]["matches"][0]["path"] = path.clone();
        let result = translate_k8s_objects(&[route], options()).expect("translation succeeds");
        assert!(
            !result.config.proxies.is_empty(),
            "{path}: the route must materialize"
        );
        for proxy in &result.config.proxies {
            assert_eq!(proxy.allow_path_parameters, expected, "{path}");
        }
    }
}

/// No `parentRefs` at all: the route still programs traffic, port-agnostically.
#[test]
fn a_route_without_parent_refs_materializes_a_listener_less_claim() {
    let result = translate_k8s_objects(&[http_route("sample", None)], options())
        .expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "a parentRef-less HTTPRoute must still materialize: {:?}",
        result.config.proxies
    );
    assert_eq!(result.config.proxies[0].listen_port, None);
    assert_eq!(result.config.proxies[0].backend_port, 8080);
}

/// A declared Gateway parent naming an absent Gateway must open nothing. Since
/// the missing object cannot prove controller ownership, Ferrum must also leave
/// the Route status untouched.
#[test]
fn httproute_with_unknown_gateway_parent_materializes_no_traffic() {
    let route = http_route("sample", Some(json!([{"name": "not-in-this-snapshot"}])));
    assert_no_http_family_traffic(std::slice::from_ref(&route), "HTTPRoute", "sample");
    assert_no_ferrum_route_status(&[route]);
}

/// Same fail-closed gate for GRPCRoute.
#[test]
fn grpcroute_with_unknown_gateway_parent_materializes_no_traffic() {
    let route = grpc_route("sample", Some(json!([{"name": "not-in-this-snapshot"}])));
    assert_no_http_family_traffic(std::slice::from_ref(&route), "GRPCRoute", "sample");
    assert_no_ferrum_route_status(&[route]);
}

/// A Gateway that exists but shares no hostname intersection with the route
/// resolves no concrete listener and must also fail closed rather than falling
/// back to a listener-less claim.
#[test]
fn httproute_with_mismatched_gateway_listener_materializes_no_traffic() {
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 8081,
                "protocol": "HTTP",
                "hostname": "other.example.com",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    let route = http_route("sample", Some(json!([{"name": "edge"}])));
    let objects = [gateway_class(), gateway, route];
    assert_no_http_family_traffic(&objects, "HTTPRoute", "sample");
    assert_status_not_programmed(
        &objects,
        "HTTPRoute",
        "sample",
        "NoMatchingListenerHostname",
    );
}

#[test]
fn grpcroute_with_mismatched_gateway_listener_materializes_no_traffic() {
    let gateway = object(
        "Gateway",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 8082,
                "protocol": "HTTP",
                "hostname": "other.example.com",
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    let route = grpc_route("sample", Some(json!([{"name": "edge"}])));
    let objects = [gateway_class(), gateway, route];
    assert_no_http_family_traffic(&objects, "GRPCRoute", "sample");
    assert_status_not_programmed(
        &objects,
        "GRPCRoute",
        "sample",
        "NoMatchingListenerHostname",
    );
}

/// HTTPRoute + GRPCRoute naming the same absent Gateway must not invent a
/// cross-kind Conflicted loss. Neither attaches, and Ferrum cannot claim status
/// for a parent whose controller ownership is unknown.
#[test]
fn httproute_and_grpcroute_on_absent_gateway_do_not_conflict() {
    let mut http = http_route_with_hostname(
        "web",
        "shared.example.com",
        Some(json!([{"name": "missing-gateway"}])),
    );
    http.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc = grpc_route_with_hostname(
        "grpc",
        "shared.example.com",
        Some(json!([{"name": "missing-gateway"}])),
    );
    grpc.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    let objects = [http, grpc];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    assert!(result.config.proxies.is_empty());
    assert!(result.materialized_route_parents.is_empty());
    assert!(result.route_conflicts.is_empty());
    assert_no_ferrum_route_status(&objects);
}

/// Same rule when the Gateway exists but its listener hostname matches neither
/// route: no materialization, no Conflicted, attachment failure only.
#[test]
fn httproute_and_grpcroute_on_mismatched_listener_hostname_do_not_conflict() {
    let mut http =
        http_route_with_hostname("web", "shared.example.com", Some(json!([{"name": "edge"}])));
    http.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc = grpc_route_with_hostname(
        "grpc",
        "shared.example.com",
        Some(json!([{"name": "edge"}])),
    );
    grpc.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    let objects = [
        gateway_class(),
        hostname_mismatched_gateway("edge", 8083),
        http,
        grpc,
    ];
    assert_unresolved_cross_kind_pair_is_attachment_failure(&objects, "NoMatchingListenerHostname");
}

/// Parentless HTTPRoute vs GRPCRoute still contend on the listener-less global
/// claim: both would otherwise serve the same traffic.
#[test]
fn parentless_httproute_and_grpcroute_still_conflict_on_shared_hostname() {
    let mut http = http_route_with_hostname("web", "shared.example.com", None);
    http.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc = grpc_route_with_hostname("grpc", "shared.example.com", None);
    grpc.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());
    let objects = [http, grpc];

    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    assert!(
        result
            .route_conflicts
            .iter()
            .any(|conflict| conflict.winner.kind == "HTTPRoute"
                && conflict.winner.name == "web"
                && conflict.loser.kind == "GRPCRoute"
                && conflict.loser.name == "grpc"),
        "parentless cross-kind overlap must still conflict: {:?}",
        result.route_conflicts
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_port == 8080),
        "older parentless HTTPRoute must still materialize"
    );
    assert!(
        !result
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_port == 50051),
        "newer parentless GRPCRoute must lose the listener-less claim"
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &result.route_conflicts);
    assert!(
        updates
            .iter()
            .all(|update| !matches!(update.kind.as_str(), "HTTPRoute" | "GRPCRoute")),
        "parentless routes have no controller-owned parent status entry: {updates:?}"
    );
}

/// Once the Gateway listener IS in the snapshot, the claim is stamped with
/// that listener's port.
#[test]
fn a_resolved_httproute_listener_still_stamps_the_port_on_the_claim() {
    let objects = [
        gateway_class(),
        http_gateway("edge", 8081),
        http_route("sample", Some(json!([{"name": "edge"}]))),
    ];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "the resolved claim must materialize once: {:?}",
        result.config.proxies
    );
    assert_eq!(
        result.config.proxies[0].listen_port,
        Some(8081),
        "a resolved listener must stamp its own port"
    );
    assert!(
        result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == "HTTPRoute" && entry.route.name == "sample"),
        "a resolved listener must record a materialized parent"
    );
}

#[test]
fn a_resolved_grpcroute_listener_still_stamps_the_port_on_the_claim() {
    let objects = [
        gateway_class(),
        http_gateway("edge", 8082),
        grpc_route("sample", Some(json!([{"name": "edge"}]))),
    ];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "the resolved GRPCRoute claim must materialize once: {:?}",
        result.config.proxies
    );
    assert_eq!(
        result.config.proxies[0].listen_port,
        Some(8082),
        "a resolved GRPCRoute listener must stamp its own port"
    );
    assert_eq!(result.config.proxies[0].backend_port, 50051);
    assert!(
        result
            .materialized_route_parents
            .iter()
            .any(|entry| entry.route.kind == "GRPCRoute" && entry.route.name == "sample"),
        "a resolved GRPCRoute listener must record a materialized parent"
    );
}

/// Two parentRef selectors can name the SAME Gateway listener — `{name: edge}`
/// beside `{name: edge, sectionName: http}`, or a `sectionName` and a `port`
/// reference to one listener. The materialized proxy id is keyed by
/// `(hostname, listener)`, so both claims must collapse into ONE scope that
/// carries both parentRefs.
///
/// Emitting one scope per parentRef produced two proxies with an identical id.
/// The duplicate then re-entered the same-listener merge carrying no plugins of
/// its own (the first copy had already claimed them), which cleared
/// `reject_unmatched` on the surviving dispatch plugin — serving every request
/// that does not satisfy the route's header predicate to the default backend.
#[test]
fn two_parent_refs_naming_one_listener_collapse_into_a_single_claim() {
    let route = object(
        "HTTPRoute",
        "sample",
        json!({
            "parentRefs": [{"name": "edge"}, {"name": "edge", "sectionName": "http"}],
            "hostnames": ["api.example.com"],
            "rules": [{
                "matches": [{
                    "path": {"type": "PathPrefix", "value": "/api"},
                    "headers": [{"type": "Exact", "name": "x-env", "value": "prod"}]
                }],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );
    let objects = [gateway_class(), http_gateway("edge", 8084), route];
    let result = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert_eq!(
        result.config.proxies.len(),
        1,
        "two parentRefs onto one listener must materialize exactly one proxy: {:?}",
        result.config.proxies
    );
    let dispatch: Vec<_> = result
        .config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .collect();
    assert_eq!(
        dispatch.len(),
        1,
        "one collapsed claim owns exactly one dispatch plugin: {dispatch:?}"
    );
    let dispatch_config = &dispatch[0].config;
    assert_eq!(
        dispatch_config["reject_unmatched"],
        json!(true),
        "a header-gated route must keep rejecting unmatched requests: {dispatch_config:?}"
    );
}
