//! Gateway API GAMMA routes: `HTTPRoute` / `GRPCRoute` with `Service`
//! parentRefs (issue #7538).
//!
//! These tests pin the control-plane half: translation into the mesh route
//! set (`istio-vs-gamma_*` proxies, `istio-vs-upstream-gamma_*` upstreams and a
//! `gamma_<ns>_<svc>` `mesh.virtual_service_http_routes` binding), parent
//! resolution (`port`, `sectionName`, unknown/headless/ExternalName Services),
//! precedence (VirtualService over GAMMA, GRPCRoute over HTTPRoute, oldest
//! route keeps an identical match), refusals with the Gateway-bound route's
//! `Accepted=False` reasons, and `status.parents[]` under the mesh controller
//! name.

use std::collections::HashMap;

use ferrum_edge::config::types::{GatewayConfig, PluginConfig, Proxy};
use ferrum_edge::config_sources::k8s::{
    GammaParentKey, GammaParentOutcome, K8sMetadata, K8sObject, K8sResourceKey, K8sTranslation,
    K8sTranslationOptions, translate_k8s_objects, translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, FERRUM_MESH_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use ferrum_edge::modes::mesh::config::MeshVirtualServiceHttpRoutes;
use serde_json::{Value, json};

const HTTP_ROUTE_API: &str = "gateway.networking.k8s.io/v1";
const OLDER: &str = "2024-01-01T00:00:00Z";
const NEWER: &str = "2024-06-01T00:00:00Z";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_source_namespaces(vec!["default".to_string(), "clients".to_string()])
}

fn object(kind: &str, api_version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some(OLDER.to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

/// A selector-backed ClusterIP Service with the given `(name, port)` ports.
fn service(namespace: &str, name: &str, ports: &[(&str, u16)]) -> K8sObject {
    let ports: Vec<Value> = ports
        .iter()
        .map(|(port_name, port)| json!({"name": port_name, "port": port, "protocol": "TCP"}))
        .collect();
    object(
        "Service",
        "v1",
        namespace,
        name,
        json!({"selector": {"app": name}, "ports": ports, "clusterIP": "10.96.0.10"}),
    )
}

fn http_route(namespace: &str, name: &str, spec: Value) -> K8sObject {
    object("HTTPRoute", HTTP_ROUTE_API, namespace, name, spec)
}

fn created_at(mut object: K8sObject, timestamp: &str) -> K8sObject {
    object.metadata.creation_timestamp = Some(timestamp.to_string());
    object
}

fn service_parent(name: &str) -> Value {
    json!({"group": "", "kind": "Service", "name": name})
}

/// A producer HTTPRoute on `default/reviews`: a header-guarded 90/10 split to
/// `reviews` and `ratings`.
fn split_route_spec() -> Value {
    json!({
        "parentRefs": [service_parent("reviews")],
        "rules": [{
            "matches": [{
                "path": {"type": "PathPrefix", "value": "/api"},
                "headers": [{"name": "x-version", "value": "v2"}]
            }],
            "backendRefs": [
                {"name": "reviews", "port": 8080, "weight": 90},
                {"name": "ratings", "port": 8080, "weight": 10}
            ]
        }]
    })
}

fn base_services() -> Vec<K8sObject> {
    vec![
        service("default", "reviews", &[("http", 8080)]),
        service("default", "ratings", &[("http", 8080)]),
    ]
}

fn translate(objects: &[K8sObject]) -> K8sTranslation {
    translate_k8s_objects(objects, options()).expect("snapshot translates")
}

fn gamma_proxies(config: &GatewayConfig) -> Vec<&Proxy> {
    config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with("istio-vs-gamma_"))
        .collect()
}

/// GAMMA route proxies, without the per-Service unmatched catch-all.
fn route_proxies(config: &GatewayConfig) -> Vec<&Proxy> {
    gamma_proxies(config)
        .into_iter()
        .filter(|proxy| !proxy.id.starts_with("istio-vs-gamma_unmatched"))
        .collect()
}

fn catch_all(config: &GatewayConfig) -> Option<&Proxy> {
    gamma_proxies(config)
        .into_iter()
        .find(|proxy| proxy.id.starts_with("istio-vs-gamma_unmatched"))
}

fn gamma_binding<'a>(
    config: &'a GatewayConfig,
    namespace: &str,
    name: &str,
) -> Option<&'a MeshVirtualServiceHttpRoutes> {
    config.mesh.as_ref().and_then(|mesh| {
        mesh.virtual_service_http_routes
            .iter()
            .find(|binding| binding.namespace == namespace && binding.name == name)
    })
}

fn dispatch_plugin<'a>(config: &'a GatewayConfig, proxy: &Proxy) -> &'a PluginConfig {
    config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("route proxy carries mesh_route_dispatch")
}

fn outcome(
    translation: &K8sTranslation,
    route: &K8sObject,
    parent_ref: &str,
) -> Option<GammaParentOutcome> {
    translation
        .gamma_route_parents
        .get(&GammaParentKey {
            route: K8sResourceKey::from_object(route),
            parent_ref: parent_ref.to_string(),
        })
        .cloned()
}

fn route_parents_status(objects: &[K8sObject], kind: &str, name: &str) -> Vec<Value> {
    plan_gateway_api_status_updates(objects, options(), &[])
        .into_iter()
        .find(|update| update.kind == kind && update.name == name)
        .unwrap_or_else(|| panic!("{kind} {name} gets a status update"))
        .status["parents"]
        .as_array()
        .expect("parents array")
        .clone()
}

fn mesh_parent(parents: &[Value]) -> &Value {
    parents
        .iter()
        .find(|parent| parent["controllerName"] == json!(FERRUM_MESH_CONTROLLER_NAME))
        .expect("a parent under the mesh controller name")
}

fn condition<'a>(parent: &'a Value, condition_type: &str) -> &'a Value {
    parent["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .find(|condition| condition["type"] == json!(condition_type))
        .unwrap_or_else(|| panic!("condition {condition_type}"))
}

fn assert_condition(parent: &Value, condition_type: &str, status: &str, reason: &str) {
    let found = condition(parent, condition_type);
    assert_eq!(found["status"], json!(status), "{condition_type}: {found}");
    assert_eq!(found["reason"], json!(reason), "{condition_type}: {found}");
}

#[test]
fn producer_route_translates_into_the_mesh_route_set_and_binding() {
    let route = http_route("default", "reviews-route", split_route_spec());
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    let config = &translation.config;

    let proxies = route_proxies(config);
    assert_eq!(proxies.len(), 1, "one rule, one listen path");
    let proxy = proxies[0];
    assert_eq!(proxy.listen_path.as_deref(), Some("/api"));
    assert!(proxy.id.starts_with("istio-vs-gamma_httproute-"));
    assert!(proxy.id.contains("__"), "source-bound digest suffix");
    assert_eq!(proxy.namespace, "default");
    assert_eq!(proxy.hosts, vec!["reviews.default.svc.cluster.local"]);
    assert_eq!(proxy.listen_port, None, "a mesh route opens no listener");
    assert!(
        !config
            .proxies
            .iter()
            .any(|proxy| proxy.id.starts_with("gwapi-route-")),
        "a Service parent never materializes a Gateway route"
    );

    let upstream_id = proxy
        .upstream_id
        .as_deref()
        .expect("weighted split upstream");
    assert!(upstream_id.starts_with("istio-vs-upstream-gamma_httproute-"));
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .expect("split upstream translated");
    let mut targets: Vec<(&str, u16)> = upstream
        .targets
        .iter()
        .map(|target| (target.host.as_str(), target.port))
        .collect();
    targets.sort();
    assert_eq!(
        targets,
        vec![
            ("ratings.default.svc.cluster.local", 8080),
            ("reviews.default.svc.cluster.local", 8080)
        ],
        "backends are Service hosts the data plane rebinds, never endpoint IPs"
    );

    let dispatch = dispatch_plugin(config, proxy);
    assert_eq!(dispatch.id, format!("istio-vs-mrd-{}", proxy.id));
    assert_eq!(
        dispatch.config["reject_unmatched"],
        json!(true),
        "a request matching no rule of the attached route is rejected"
    );
    assert!(
        !dispatch.config.to_string().contains("_ferrum_"),
        "internal precedence metadata is stripped"
    );

    // GAMMA rejects requests no attached route matches: the paths the route
    // does not claim get a `/` catch-all that aborts with 404, instead of
    // falling through to the plain Service route.
    let unmatched = catch_all(config).expect("unmatched catch-all");
    assert_eq!(unmatched.listen_path.as_deref(), Some("/"));
    assert_eq!(unmatched.hosts, vec!["reviews.default.svc.cluster.local"]);
    let unmatched_rules = dispatch_plugin(config, unmatched).config["rules"]
        .as_array()
        .expect("rules")
        .clone();
    assert_eq!(unmatched_rules.len(), 1);
    assert_eq!(unmatched_rules[0]["match"], json!({}));
    assert_eq!(
        unmatched_rules[0]["fault"]["abort"]["status_code"],
        json!(404)
    );
    assert_eq!(
        unmatched_rules[0]["fault"]["abort"]["percentage"],
        json!(100.0)
    );

    let binding =
        gamma_binding(config, "default", "gamma_default_reviews").expect("GAMMA mesh binding");
    assert_eq!(binding.export_to, vec!["*".to_string()], "producer route");
    let mut bound = binding.proxy_ids.clone();
    bound.sort();
    let mut expected = vec![proxy.id.clone(), unmatched.id.clone()];
    expected.sort();
    assert_eq!(bound, expected);

    assert_eq!(
        outcome(&translation, &route, "core/Service/default/reviews/*/*"),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
}

#[test]
fn producer_route_status_reports_the_service_parent_under_the_mesh_controller() {
    let mut objects = base_services();
    objects.push(http_route("default", "reviews-route", split_route_spec()));
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-route");
    assert_eq!(parents.len(), 1, "only the Service parent: {parents:?}");
    assert!(
        !parents
            .iter()
            .any(|parent| parent["controllerName"] == json!(FERRUM_GATEWAY_CONTROLLER_NAME))
    );
    let parent = mesh_parent(&parents);
    assert_eq!(parent["parentRef"], service_parent("reviews"));
    assert_condition(parent, "Accepted", "True", "Accepted");
    assert_condition(parent, "ResolvedRefs", "True", "ResolvedRefs");
    assert_condition(parent, "Programmed", "True", "Programmed");
    assert_condition(parent, "Conflicted", "False", "NoConflicts");
    let message = condition(parent, "Programmed")["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("Sidecar and NodeWaypoint"),
        "status names where the route applies: {message}"
    );
}

#[test]
fn consumer_route_with_a_local_backend_is_namespace_local() {
    let route = http_route(
        "clients",
        "reviews-timeouts",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "namespace": "default"}],
            "rules": [{
                "timeouts": {"request": "100ms"},
                "backendRefs": [{"name": "reviews-proxy", "port": 8080}]
            }]
        }),
    );
    let mut objects = base_services();
    objects.push(service("clients", "reviews-proxy", &[("http", 8080)]));
    objects.push(route.clone());
    let translation = translate(&objects);
    let config = &translation.config;

    let proxies = gamma_proxies(config);
    assert_eq!(proxies.len(), 1);
    assert_eq!(
        proxies[0].namespace, "clients",
        "routes live in the route namespace"
    );
    assert_eq!(proxies[0].hosts, vec!["reviews.default.svc.cluster.local"]);
    let binding =
        gamma_binding(config, "clients", "gamma_default_reviews").expect("consumer binding");
    assert!(
        binding.export_to.is_empty(),
        "a consumer route applies only to clients in its own namespace"
    );
    let dispatch = dispatch_plugin(config, proxies[0]);
    assert!(
        dispatch.config.to_string().contains("request_timeout_ms"),
        "rule timeouts ride the dispatch rule exactly as for a Gateway route"
    );
    assert_eq!(
        outcome(&translation, &route, "core/Service/default/reviews/*/*"),
        Some(GammaParentOutcome::Programmed { producer: false })
    );
}

#[test]
fn cross_namespace_backend_needs_a_reference_grant_and_waits_for_cross_namespace_carriage() {
    let route_spec = json!({
        "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "namespace": "default"}],
        "rules": [{"backendRefs": [{"name": "reviews", "namespace": "default", "port": 8080}]}]
    });
    let route = http_route("clients", "reviews-consumer", route_spec);

    // No ReferenceGrant: the backend is refused exactly as on a Gateway route
    // (fail-closed 500, ResolvedRefs=False/RefNotPermitted).
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    let proxies = gamma_proxies(&translation.config);
    assert_eq!(proxies.len(), 1);
    let dispatch = dispatch_plugin(&translation.config, proxies[0]);
    assert!(
        dispatch.config.to_string().contains("ReferenceGrant"),
        "the unresolved share fails closed with the backendRef fault"
    );
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-consumer");
    assert_condition(
        mesh_parent(&parents),
        "ResolvedRefs",
        "False",
        "RefNotPermitted",
    );

    // Granted: the backend resolves, but mesh data planes refuse a carried
    // route with a cross-namespace destination until #7499 lands, so the
    // route is accepted and reported Pending instead of being carried inert.
    let grant = object(
        "ReferenceGrant",
        "gateway.networking.k8s.io/v1beta1",
        "default",
        "clients-to-reviews",
        json!({
            "from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "clients"}],
            "to": [{"group": "", "kind": "Service"}]
        }),
    );
    objects.push(grant);
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(gamma_binding(&translation.config, "clients", "gamma_default_reviews").is_none());
    assert!(matches!(
        outcome(&translation, &route, "core/Service/default/reviews/*/*"),
        Some(GammaParentOutcome::Pending { .. })
    ));
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-consumer");
    let parent = mesh_parent(&parents);
    assert_condition(parent, "Accepted", "True", "Accepted");
    assert_condition(parent, "ResolvedRefs", "True", "ResolvedRefs");
    assert_condition(parent, "Programmed", "False", "Pending");
}

#[test]
fn unresolvable_service_parents_are_refused_with_no_matching_parent() {
    let headless = object(
        "Service",
        "v1",
        "default",
        "headless",
        json!({"selector": {"app": "headless"}, "clusterIP": "None", "ports": [{"name": "http", "port": 8080}]}),
    );
    let external = object(
        "Service",
        "v1",
        "default",
        "external",
        json!({"type": "ExternalName", "externalName": "example.com", "ports": [{"name": "http", "port": 8080}]}),
    );
    let cases = [
        (
            "missing",
            json!({"group": "", "kind": "Service", "name": "missing"}),
        ),
        (
            "headless",
            json!({"group": "", "kind": "Service", "name": "headless"}),
        ),
        (
            "external",
            json!({"group": "", "kind": "Service", "name": "external"}),
        ),
        (
            "wrong-port",
            json!({"group": "", "kind": "Service", "name": "reviews", "port": 9999}),
        ),
        (
            "wrong-section",
            json!({"group": "", "kind": "Service", "name": "reviews", "sectionName": "grpc"}),
        ),
        (
            "section-port-disagree",
            json!({"group": "", "kind": "Service", "name": "multi", "sectionName": "http", "port": 9090}),
        ),
    ];
    for (name, parent_ref) in cases {
        let route = http_route(
            "default",
            name,
            json!({
                "parentRefs": [parent_ref.clone()],
                "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
            }),
        );
        let mut objects = base_services();
        objects.push(service(
            "default",
            "multi",
            &[("http", 8080), ("admin", 9090)],
        ));
        objects.push(headless.clone());
        objects.push(external.clone());
        objects.push(route.clone());
        let translation = translate(&objects);
        assert!(
            gamma_proxies(&translation.config).is_empty(),
            "{name}: nothing is carried"
        );
        let key = ferrum_edge_gamma_key(&parent_ref);
        assert!(
            matches!(
                outcome(&translation, &route, &key),
                Some(GammaParentOutcome::NoMatchingParent { .. })
            ),
            "{name}: {:?}",
            outcome(&translation, &route, &key)
        );
        let parents = route_parents_status(&objects, "HTTPRoute", name);
        let parent = mesh_parent(&parents);
        assert_condition(parent, "Accepted", "False", "NoMatchingParent");
        assert_condition(parent, "Programmed", "False", "NoMatchingParent");
    }
}

/// The parent key translation records an outcome under, for a parentRef in
/// the `default` namespace.
fn ferrum_edge_gamma_key(parent_ref: &Value) -> String {
    let name = parent_ref["name"].as_str().unwrap_or("*");
    let section = parent_ref["sectionName"].as_str().unwrap_or("*");
    let port = parent_ref["port"]
        .as_u64()
        .map_or_else(|| "*".to_string(), |port| port.to_string());
    format!("core/Service/default/{name}/{section}/{port}")
}

#[test]
fn unsupported_filters_refuse_the_route_with_the_gateway_route_reason() {
    let route = http_route(
        "default",
        "mirrored",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{
                "filters": [{
                    "type": "RequestMirror",
                    "requestMirror": {"backendRef": {"name": "ratings", "port": 8080}}
                }],
                "backendRefs": [{"name": "reviews", "port": 8080}]
            }]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translation");
    assert!(
        skipped.contains_key(&K8sResourceKey::from_object(&route)),
        "the whole route is refused, never silently stripped"
    );
    assert!(gamma_proxies(&translation.config).is_empty());
    let parents = route_parents_status(&objects, "HTTPRoute", "mirrored");
    let parent = mesh_parent(&parents);
    assert_condition(parent, "Accepted", "False", "IncompatibleFilters");
    assert_condition(parent, "Programmed", "False", "TranslationFailed");
}

#[test]
fn session_persistence_is_refused_for_the_service_parent() {
    let route = http_route(
        "default",
        "sticky",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{
                "sessionPersistence": {"sessionName": "s", "type": "Cookie"},
                "backendRefs": [{"name": "reviews", "port": 8080}, {"name": "ratings", "port": 8080}]
            }]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(matches!(
        outcome(&translation, &route, "core/Service/default/reviews/*/*"),
        Some(GammaParentOutcome::UnsupportedValue { .. })
    ));
    let parents = route_parents_status(&objects, "HTTPRoute", "sticky");
    assert_condition(
        mesh_parent(&parents),
        "Accepted",
        "False",
        "UnsupportedValue",
    );
}

#[test]
fn a_mesh_bound_virtual_service_takes_precedence_over_gamma_routes() {
    let virtual_service = object(
        "VirtualService",
        "networking.istio.io/v1",
        "default",
        "reviews-vs",
        json!({
            "hosts": ["reviews"],
            "http": [{"route": [{"destination": {"host": "reviews", "port": {"number": 8080}}}]}]
        }),
    );
    let route = http_route("default", "reviews-route", split_route_spec());
    let mut objects = base_services();
    objects.push(virtual_service);
    objects.push(route.clone());
    let translation = translate(&objects);
    let config = &translation.config;

    assert!(gamma_proxies(config).is_empty(), "never apply both");
    let mesh = config.mesh.as_ref().expect("mesh block");
    assert!(
        mesh.virtual_service_http_routes
            .iter()
            .any(|binding| binding.name == "reviews-vs"),
        "the VirtualService binding is untouched"
    );
    assert!(
        !mesh
            .virtual_service_http_routes
            .iter()
            .any(|binding| binding.name.starts_with("gamma_"))
    );
    let lost = outcome(&translation, &route, "core/Service/default/reviews/*/*");
    let Some(GammaParentOutcome::Conflicted { message }) = lost else {
        panic!("the GAMMA route loses: {lost:?}");
    };
    assert!(message.contains("reviews-vs"), "{message}");

    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-route");
    let parent = mesh_parent(&parents);
    assert_condition(parent, "Accepted", "False", "Conflicted");
    assert_condition(parent, "Programmed", "False", "Conflicted");
    assert_condition(parent, "Conflicted", "True", "Conflicted");
}

#[test]
fn grpc_route_wins_over_http_route_on_the_same_service() {
    let grpc = object(
        "GRPCRoute",
        HTTP_ROUTE_API,
        "default",
        "reviews-grpc",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{
                "matches": [{"method": {"service": "reviews.v1.Reviews", "method": "Get"}}],
                "backendRefs": [{"name": "reviews", "port": 8080}]
            }]
        }),
    );
    let http = created_at(
        http_route("default", "reviews-http", split_route_spec()),
        OLDER,
    );
    let mut objects = base_services();
    objects.push(created_at(grpc.clone(), NEWER));
    objects.push(http.clone());
    let translation = translate(&objects);

    let proxies = route_proxies(&translation.config);
    assert!(!proxies.is_empty());
    assert!(
        proxies
            .iter()
            .all(|proxy| proxy.id.starts_with("istio-vs-gamma_grpcroute-")),
        "only the GRPCRoute is carried"
    );
    assert!(matches!(
        outcome(&translation, &http, "core/Service/default/reviews/*/*"),
        Some(GammaParentOutcome::Conflicted { .. })
    ));
    assert_eq!(
        outcome(
            &translation,
            &created_at(grpc, NEWER),
            "core/Service/default/reviews/*/*"
        ),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
}

#[test]
fn routes_on_one_service_merge_and_the_oldest_keeps_an_identical_match() {
    let path_route = |name: &str, path: &str, backend: &str| {
        http_route(
            "default",
            name,
            json!({
                "parentRefs": [service_parent("reviews")],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": path}}],
                    "backendRefs": [{"name": backend, "port": 8080}]
                }]
            }),
        )
    };

    // Distinct paths: both routes are carried under one binding.
    let a = created_at(path_route("route-a", "/a", "reviews"), OLDER);
    let b = created_at(path_route("route-b", "/b", "ratings"), NEWER);
    let mut objects = base_services();
    objects.push(b.clone());
    objects.push(a.clone());
    let translation = translate(&objects);
    let binding = gamma_binding(&translation.config, "default", "gamma_default_reviews")
        .expect("one binding per Service");
    assert_eq!(
        binding.proxy_ids.len(),
        3,
        "both routes plus the unmatched catch-all"
    );
    for route in [&a, &b] {
        assert_eq!(
            outcome(&translation, route, "core/Service/default/reviews/*/*"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );
    }

    // Identical match: the older route keeps it, whatever the snapshot order.
    let older = created_at(path_route("older", "/same", "reviews"), OLDER);
    let newer = created_at(path_route("newer", "/same", "ratings"), NEWER);
    for order in [
        [older.clone(), newer.clone()],
        [newer.clone(), older.clone()],
    ] {
        let mut objects = base_services();
        objects.extend(order);
        let translation = translate(&objects);
        let proxies: Vec<&Proxy> = route_proxies(&translation.config)
            .into_iter()
            .filter(|proxy| proxy.listen_path.as_deref() == Some("/same"))
            .collect();
        assert_eq!(proxies.len(), 1, "one slot, one proxy");
        assert_eq!(
            proxies[0].backend_host, "reviews.default.svc.cluster.local",
            "the older route's backend serves the shared match"
        );
        assert_eq!(
            outcome(&translation, &older, "core/Service/default/reviews/*/*"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );
        assert!(matches!(
            outcome(&translation, &newer, "core/Service/default/reviews/*/*"),
            Some(GammaParentOutcome::Conflicted { .. })
        ));
    }
}

#[test]
fn a_port_scoped_parent_guards_every_rule_and_passes_other_ports_through() {
    for parent_ref in [
        json!({"group": "", "kind": "Service", "name": "multi", "port": 8080}),
        json!({"group": "", "kind": "Service", "name": "multi", "sectionName": "http"}),
    ] {
        let route = http_route(
            "default",
            "multi-route",
            json!({
                "parentRefs": [parent_ref],
                "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
            }),
        );
        let mut objects = base_services();
        objects.push(service(
            "default",
            "multi",
            &[("http", 8080), ("admin", 9090)],
        ));
        objects.push(route);
        let translation = translate(&objects);
        let config = &translation.config;
        let proxies = gamma_proxies(config);
        assert_eq!(proxies.len(), 1, "the route owns `/`, so no catch-all");
        let dispatch = dispatch_plugin(config, proxies[0]);
        assert_eq!(dispatch.config["reject_unmatched"], json!(true));
        let rules = dispatch.config["rules"].as_array().expect("rules");
        let ports: Vec<u64> = rules
            .iter()
            .map(|rule| {
                rule["match"]["port"]
                    .as_u64()
                    .expect("every rule is port-guarded")
            })
            .collect();
        assert!(ports.contains(&8080), "the route's own port: {rules:?}");
        let pass_through = rules
            .iter()
            .find(|rule| rule["match"]["port"] == json!(9090))
            .expect("the unattached port passes through");
        assert_eq!(
            pass_through["destination"]["backend_host"],
            json!("multi.default.svc.cluster.local")
        );
        assert_eq!(pass_through["destination"]["backend_port"], json!(9090));
    }
}

#[test]
fn a_parent_port_covering_every_service_port_is_unscoped() {
    let route = http_route(
        "default",
        "reviews-route",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "port": 8080}],
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(route);
    let translation = translate(&objects);
    let proxies = gamma_proxies(&translation.config);
    assert_eq!(proxies.len(), 1);
    assert!(
        !translation
            .config
            .plugin_configs
            .iter()
            .any(
                |plugin| plugin.proxy_id.as_deref() == Some(proxies[0].id.as_str())
                    && plugin.config.to_string().contains("\"port\"")
            ),
        "a single-port Service needs no port predicate"
    );
}

#[test]
fn deleting_the_route_withdraws_the_mesh_route_set() {
    let mut objects = base_services();
    objects.push(http_route("default", "reviews-route", split_route_spec()));
    assert!(!gamma_proxies(&translate(&objects).config).is_empty());
    let withdrawn = translate(&base_services());
    assert!(gamma_proxies(&withdrawn.config).is_empty());
    assert!(
        withdrawn
            .config
            .upstreams
            .iter()
            .all(|upstream| !upstream.id.starts_with("istio-vs-upstream-gamma_"))
    );
    assert!(withdrawn.gamma_route_parents.is_empty());
}

#[test]
fn http_and_grpc_routes_on_disjoint_ports_of_one_service_both_serve() {
    let http = http_route(
        "default",
        "multi-http",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "multi", "port": 8080}],
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
        }),
    );
    let grpc = object(
        "GRPCRoute",
        HTTP_ROUTE_API,
        "default",
        "multi-grpc",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "multi", "port": 9090}],
            "rules": [{
                "matches": [{"method": {"service": "multi.v1.Multi", "method": "Get"}}],
                "backendRefs": [{"name": "ratings", "port": 8080}]
            }]
        }),
    );
    for order in [[http.clone(), grpc.clone()], [grpc.clone(), http.clone()]] {
        let mut objects = base_services();
        objects.push(service(
            "default",
            "multi",
            &[("http", 8080), ("grpc", 9090)],
        ));
        objects.extend(order);
        let translation = translate(&objects);
        let config = &translation.config;

        // GEP-1294 only refuses a route type on a Service+port pair another
        // type also claims; disjoint ports keep both.
        assert_eq!(
            outcome(&translation, &http, "core/Service/default/multi/*/8080"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );
        assert_eq!(
            outcome(&translation, &grpc, "core/Service/default/multi/*/9090"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );

        let proxies = route_proxies(config);
        assert!(!proxies.is_empty());
        let mut rules: Vec<Value> = Vec::new();
        for proxy in &proxies {
            let dispatch = dispatch_plugin(config, proxy);
            assert_eq!(dispatch.config["reject_unmatched"], json!(true));
            // Every carried instance must construct, merged slot included.
            ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch::new(&dispatch.config)
                .expect("merged dispatch instance constructs");
            rules.extend(
                dispatch.config["rules"]
                    .as_array()
                    .expect("rules")
                    .iter()
                    .cloned(),
            );
        }
        let to_backend =
            |rule: &Value, host: &str| rule["destination"]["backend_host"] == json!(host);
        assert!(
            rules.iter().all(|rule| rule["match"]["port"].is_u64()),
            "every rule is port-guarded, so the two route tables never mix: {rules:?}"
        );
        assert!(
            rules.iter().any(|rule| rule["match"]["port"] == json!(8080)
                && to_backend(rule, "reviews.default.svc.cluster.local")),
            "the HTTPRoute serves port 8080: {rules:?}"
        );
        assert!(
            rules.iter().any(|rule| rule["match"]["port"] == json!(9090)
                && to_backend(rule, "ratings.default.svc.cluster.local")),
            "the GRPCRoute serves port 9090: {rules:?}"
        );
        assert!(
            !rules.iter().any(|rule| rule["match"]["port"] == json!(8080)
                && to_backend(rule, "ratings.default.svc.cluster.local")),
            "the GRPCRoute never answers on the HTTPRoute's port"
        );
        assert!(
            !rules.iter().any(|rule| rule["match"]["port"] == json!(9090)
                && to_backend(rule, "reviews.default.svc.cluster.local")),
            "the HTTPRoute never answers on the GRPCRoute's port"
        );
        let mut slots: Vec<(&str, Option<&str>)> = gamma_proxies(config)
            .iter()
            .map(|proxy| (proxy.namespace.as_str(), proxy.listen_path.as_deref()))
            .collect();
        let total = slots.len();
        slots.sort();
        slots.dedup();
        assert_eq!(slots.len(), total, "no duplicate route slot");
    }
}
