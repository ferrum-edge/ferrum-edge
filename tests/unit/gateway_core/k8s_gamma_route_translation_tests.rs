//! Gateway API GAMMA routes: `HTTPRoute` / `GRPCRoute` with `Service`
//! parentRefs (issue #7538).
//!
//! These tests pin the control-plane half: translation of every route attached
//! to one Service from one namespace into ONE mesh route (an
//! `istio-vs-gamma_service-*` `/` proxy whose single `mesh_route_dispatch`
//! instance carries every rule with an explicit path predicate, ordered by
//! Gateway API precedence, `reject_unmatched`), its
//! `istio-vs-upstream-gamma_*` upstreams and `gamma_<ns>_<svc>` binding; parent
//! resolution; producer/consumer ReferenceGrant rules; precedence; refusals with
//! the Gateway-bound `Accepted=False` reasons; and `status.parents[]` under the
//! mesh controller name.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::run_before_proxy_hooks_for_test;
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
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, create_plugin};
use serde_json::{Value, json};

const HTTP_ROUTE_API: &str = "gateway.networking.k8s.io/v1";
const OLDER: &str = "2024-01-01T00:00:00Z";
const NEWER: &str = "2024-06-01T00:00:00Z";
const REVIEWS: &str = "reviews.default.svc.cluster.local";
const RATINGS: &str = "ratings.default.svc.cluster.local";

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
/// Port names follow the Istio convention (`http*` / `grpc*` are HTTP-family).
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

fn grpc_route(namespace: &str, name: &str, spec: Value) -> K8sObject {
    object("GRPCRoute", HTTP_ROUTE_API, namespace, name, spec)
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

/// The group's one route proxy.
fn gamma_proxy(config: &GatewayConfig) -> &Proxy {
    let proxies = gamma_proxies(config);
    assert_eq!(proxies.len(), 1, "one route per Service: {proxies:?}");
    proxies[0]
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

fn dispatch_rules(config: &GatewayConfig) -> Vec<Value> {
    dispatch_plugin(config, gamma_proxy(config)).config["rules"]
        .as_array()
        .expect("rules")
        .clone()
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

fn route_status(objects: &[K8sObject], kind: &str, name: &str) -> Value {
    plan_gateway_api_status_updates(objects, options(), &[])
        .into_iter()
        .find(|update| update.kind == kind && update.name == name)
        .unwrap_or_else(|| panic!("{kind} {name} gets a status update"))
        .status
}

fn route_parents_status(objects: &[K8sObject], kind: &str, name: &str) -> Vec<Value> {
    route_status(objects, kind, name)["parents"]
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

const PARENT: &str = "core/Service/default/reviews/*/*";

/// What the group's dispatch instance does with one request: the selected
/// destination host, or the rejection status.
#[derive(Debug, PartialEq, Eq)]
enum Dispatched {
    To(String),
    Upstream(String),
    Rejected(u16),
    Continue,
}

async fn dispatch(
    config: &GatewayConfig,
    method: &str,
    path: &str,
    request_headers: &[(&str, &str)],
) -> Dispatched {
    let proxy = gamma_proxy(config);
    let plugin_config = dispatch_plugin(config, proxy);
    let plugin: Arc<dyn Plugin> = create_plugin("mesh_route_dispatch", &plugin_config.config)
        .expect("dispatch plugin builds")
        .expect("dispatch plugin exists");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    let mut headers: HashMap<String, String> = request_headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    headers.insert("host".to_string(), REVIEWS.to_string());
    ctx.headers = headers.clone();
    ctx.matched_proxy = Some(Arc::new(proxy.clone()));
    match run_before_proxy_hooks_for_test(&[plugin], &mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => Dispatched::Rejected(status_code),
        _ => match (
            ctx.route_override_backend_host.clone(),
            ctx.route_override_upstream_id.clone(),
        ) {
            (Some(host), _) => Dispatched::To(host),
            (None, Some(upstream)) => Dispatched::Upstream(upstream),
            (None, None) => Dispatched::Continue,
        },
    }
}

#[test]
fn producer_route_translates_into_one_service_route_and_binding() {
    let route = http_route("default", "reviews-route", split_route_spec());
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    let config = &translation.config;

    let proxy = gamma_proxy(config);
    assert!(proxy.id.starts_with("istio-vs-gamma_service-"));
    assert!(proxy.id.contains("__"), "source-bound digest suffix");
    assert_eq!(proxy.namespace, "default");
    assert_eq!(proxy.listen_path.as_deref(), Some("/"));
    assert_eq!(
        proxy.hosts,
        vec![REVIEWS.to_string(), "10.96.0.10".to_string()],
        "the Service host and its cluster IP"
    );
    assert_eq!(proxy.listen_port, None, "a mesh route opens no listener");
    assert!(
        !config
            .proxies
            .iter()
            .any(|proxy| proxy.id.starts_with("gwapi-route-")),
        "a Service parent never materializes a Gateway route"
    );

    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| {
            upstream
                .id
                .starts_with("istio-vs-upstream-gamma_httproute-")
        })
        .expect("split upstream translated");
    let mut targets: Vec<(&str, u16)> = upstream
        .targets
        .iter()
        .map(|target| (target.host.as_str(), target.port))
        .collect();
    targets.sort();
    assert_eq!(
        targets,
        vec![(RATINGS, 8080), (REVIEWS, 8080)],
        "backends are Service hosts the data plane rebinds, never endpoint IPs"
    );

    let dispatch = dispatch_plugin(config, proxy);
    assert_eq!(dispatch.id, format!("istio-vs-mrd-{}", proxy.id));
    assert_eq!(dispatch.config["reject_unmatched"], json!(true));
    assert!(
        !dispatch.config.to_string().contains("_ferrum_"),
        "internal precedence metadata is stripped"
    );
    MeshRouteDispatch::new(&dispatch.config).expect("the carried instance constructs");
    let rules = dispatch_rules(config);
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0]["match"]["uri"],
        json!({"regex": "/api(/.*)?"}),
        "PathPrefix keeps element-wise semantics"
    );
    assert_eq!(rules[0]["match"]["headers"], json!({"x-version": "v2"}));

    let binding =
        gamma_binding(config, "default", "gamma_default_reviews").expect("GAMMA mesh binding");
    assert_eq!(binding.export_to, vec!["*".to_string()], "producer route");
    assert_eq!(binding.proxy_ids, vec![proxy.id.clone()]);

    assert_eq!(
        outcome(&translation, &route, PARENT),
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

/// F2: a rule on a longer path never hides a matching rule on a shorter path
/// or a regex path; a miss on every rule is rejected, never forwarded to the
/// plain Service.
#[tokio::test]
async fn every_rule_of_the_service_is_evaluated_in_gateway_api_precedence() {
    let route = http_route(
        "default",
        "reviews-route",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [
                {
                    "matches": [{
                        "path": {"type": "PathPrefix", "value": "/api"},
                        "headers": [{"name": "x-version", "value": "v2"}]
                    }],
                    "backendRefs": [{"name": "ratings", "port": 8080}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                    "backendRefs": [{"name": "reviews", "port": 8080}]
                }
            ]
        }),
    );
    let regex_route = created_at(
        http_route(
            "default",
            "reviews-regex",
            json!({
                "parentRefs": [service_parent("reviews")],
                "rules": [{
                    "matches": [{"path": {"type": "RegularExpression", "value": "/v[0-9]+/.*"}}],
                    "backendRefs": [{"name": "ratings", "port": 8080}]
                }]
            }),
        ),
        NEWER,
    );
    let mut objects = base_services();
    objects.push(route);
    objects.push(regex_route);
    let config = translate(&objects).config;

    assert_eq!(
        dispatch(&config, "GET", "/api/items", &[("x-version", "v2")]).await,
        Dispatched::To(RATINGS.to_string()),
        "the guarded /api rule serves a matching request"
    );
    assert_eq!(
        dispatch(&config, "GET", "/api/items", &[]).await,
        Dispatched::To(REVIEWS.to_string()),
        "an /api request missing the header falls to the / rule, not a 404"
    );
    assert_eq!(
        dispatch(&config, "GET", "/apix", &[("x-version", "v2")]).await,
        Dispatched::To(REVIEWS.to_string()),
        "PathPrefix /api never matches /apix"
    );
    // A regex rule from another route is evaluated after every prefix rule:
    // the / prefix rule wins for /v1/x, as the router orders prefix before
    // regex for Gateway-bound routes.
    assert_eq!(
        dispatch(&config, "GET", "/v1/x", &[]).await,
        Dispatched::To(REVIEWS.to_string())
    );
}

#[tokio::test]
async fn a_regex_only_route_is_reachable_and_unmatched_requests_are_rejected() {
    let route = http_route(
        "default",
        "reviews-regex",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{
                "matches": [{"path": {"type": "RegularExpression", "value": "/v[0-9]+/.*"}}],
                "backendRefs": [{"name": "ratings", "port": 8080}]
            }]
        }),
    );
    let mut objects = base_services();
    objects.push(route);
    let config = translate(&objects).config;
    assert_eq!(
        dispatch(&config, "GET", "/v2/items", &[]).await,
        Dispatched::To(RATINGS.to_string())
    );
    assert_eq!(
        dispatch(&config, "GET", "/other", &[]).await,
        Dispatched::Rejected(404),
        "GAMMA rejects a request no attached route matches"
    );
}

#[test]
fn identical_matches_are_served_by_the_oldest_route_in_any_snapshot_order() {
    let path_route = |name: &str, backend: &str| {
        http_route(
            "default",
            name,
            json!({
                "parentRefs": [service_parent("reviews")],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/same"}}],
                    "backendRefs": [{"name": backend, "port": 8080}]
                }]
            }),
        )
    };
    let older = created_at(path_route("older", "reviews"), OLDER);
    let newer = created_at(path_route("newer", "ratings"), NEWER);
    for order in [
        [older.clone(), newer.clone()],
        [newer.clone(), older.clone()],
    ] {
        let mut objects = base_services();
        objects.extend(order);
        let translation = translate(&objects);
        let rules = dispatch_rules(&translation.config);
        assert_eq!(rules.len(), 2, "both rules are carried, ordered: {rules:?}");
        assert_eq!(
            rules[0]["destination"]["backend_host"],
            json!(REVIEWS),
            "the older route's identical match comes first"
        );
        for route in [&older, &newer] {
            assert_eq!(
                outcome(&translation, route, PARENT),
                Some(GammaParentOutcome::Programmed { producer: true })
            );
        }
    }
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

    let proxy = gamma_proxy(config);
    assert_eq!(
        proxy.namespace, "clients",
        "routes live in the route namespace"
    );
    assert_eq!(proxy.hosts[0], REVIEWS);
    let binding =
        gamma_binding(config, "clients", "gamma_default_reviews").expect("consumer binding");
    assert!(
        binding.export_to.is_empty(),
        "a consumer route applies only to clients in its own namespace"
    );
    assert!(
        gamma_binding(config, "default", "gamma_default_reviews").is_none(),
        "a consumer route never writes a binding another namespace receives"
    );
    let rules = dispatch_rules(config);
    assert!(
        rules[0].get("request_timeout_ms").is_some(),
        "rule timeouts ride the dispatch rule exactly as for a Gateway route"
    );
    assert_eq!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Programmed { producer: false })
    );
}

/// Consumer routes need no ReferenceGrant for a cross-namespace backendRef
/// (upstream GAMMA; the MESH-HTTP `MeshConsumerRoute` test relies on it). Until
/// cross-namespace legs are carried (#7499) the route is accepted and `Pending`.
#[test]
fn consumer_route_cross_namespace_backend_needs_no_reference_grant() {
    let route = http_route(
        "clients",
        "reviews-consumer",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "namespace": "default"}],
            "rules": [{"backendRefs": [{"name": "reviews", "namespace": "default", "port": 8080}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(matches!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Pending { .. })
    ));
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-consumer");
    let parent = mesh_parent(&parents);
    assert_condition(parent, "Accepted", "True", "Accepted");
    assert_condition(parent, "ResolvedRefs", "True", "ResolvedRefs");
    assert_condition(parent, "Programmed", "False", "Pending");
}

/// A producer route redirects every client's traffic, so a backendRef into a
/// third namespace needs that namespace's ReferenceGrant.
#[test]
fn producer_route_backend_in_another_namespace_needs_a_reference_grant() {
    let route = http_route(
        "default",
        "reviews-producer",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{"backendRefs": [{"name": "proxy", "namespace": "clients", "port": 8080}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(service("clients", "proxy", &[("http", 8080)]));
    objects.push(route.clone());

    let translation = translate(&objects);
    let rules = dispatch_rules(&translation.config);
    assert!(
        rules[0].to_string().contains("ReferenceGrant"),
        "the ungranted share fails closed with the backendRef 500 fault"
    );
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-producer");
    assert_condition(
        mesh_parent(&parents),
        "ResolvedRefs",
        "False",
        "RefNotPermitted",
    );

    objects.push(object(
        "ReferenceGrant",
        "gateway.networking.k8s.io/v1beta1",
        "clients",
        "default-to-proxy",
        json!({
            "from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "default"}],
            "to": [{"group": "", "kind": "Service"}]
        }),
    ));
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(matches!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Pending { .. })
    ));
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-producer");
    assert_condition(
        mesh_parent(&parents),
        "ResolvedRefs",
        "True",
        "ResolvedRefs",
    );
}

/// A consumer route can never route to a Service the control plane does not
/// expose (outside its namespaces, so outside every data plane's `ns`
/// ceiling): the share fails closed.
#[test]
fn consumer_route_to_a_target_outside_the_watch_scope_is_refused() {
    let route = http_route(
        "clients",
        "reviews-elsewhere",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "reviews", "namespace": "default"}],
            "rules": [{"backendRefs": [{"name": "hidden", "namespace": "elsewhere", "port": 8080}]}]
        }),
    );
    // `elsewhere` is outside this control plane's namespaces, so its Service
    // never enters the inventory a data plane could be handed.
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    let rules = dispatch_rules(&translation.config);
    assert!(
        rules[0]["fault"]["abort"]["status_code"] == json!(500),
        "an unexposed target is unroutable: {rules:?}"
    );
    assert!(
        !rules[0].to_string().contains("hidden.elsewhere"),
        "the unexposed Service is never a destination"
    );
    let parents = route_parents_status(&objects, "HTTPRoute", "reviews-elsewhere");
    assert_condition(
        mesh_parent(&parents),
        "ResolvedRefs",
        "False",
        "BackendNotFound",
    );
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
        (
            "non-http-port",
            json!({"group": "", "kind": "Service", "name": "multi", "sectionName": "db"}),
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
            &[("http", 8080), ("http-admin", 9090), ("db", 5432)],
        ));
        objects.push(headless.clone());
        objects.push(external.clone());
        objects.push(route.clone());
        let translation = translate(&objects);
        assert!(
            gamma_proxies(&translation.config).is_empty(),
            "{name}: nothing is carried"
        );
        let key = default_parent_key(&parent_ref);
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
fn default_parent_key(parent_ref: &Value) -> String {
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

/// F8: an unsupported match predicate on any rule refuses the Service parent
/// instead of being dropped while a supported sibling keeps it programmed.
#[test]
fn unsupported_match_predicates_refuse_the_service_parent() {
    let route = http_route(
        "default",
        "regex-header",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [
                {
                    "matches": [{"headers": [{"name": "x-a", "value": "1"}]}],
                    "backendRefs": [{"name": "reviews", "port": 8080}]
                },
                {
                    "matches": [{"headers": [{"type": "RegularExpression", "name": "x-b", "value": "v.*"}]}],
                    "backendRefs": [{"name": "ratings", "port": 8080}]
                }
            ]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(matches!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::UnsupportedValue { .. })
    ));
    let parents = route_parents_status(&objects, "HTTPRoute", "regex-header");
    assert_condition(
        mesh_parent(&parents),
        "Accepted",
        "False",
        "UnsupportedValue",
    );
}

/// F10: an authority rewrite the Sidecar data plane would drop is refused, not
/// advertised as programmed.
#[test]
fn hostname_rewrites_must_name_the_single_backend_service() {
    let rewrite_route = |name: &str, hostname: &str| {
        http_route(
            "default",
            name,
            json!({
                "parentRefs": [service_parent("reviews")],
                "rules": [{
                    "filters": [{"type": "URLRewrite", "urlRewrite": {"hostname": hostname}}],
                    "backendRefs": [{"name": "ratings", "port": 8080}]
                }]
            }),
        )
    };
    let foreign = rewrite_route("foreign", "api.example.com");
    let mut objects = base_services();
    objects.push(foreign.clone());
    let translation = translate(&objects);
    assert!(gamma_proxies(&translation.config).is_empty());
    assert!(matches!(
        outcome(&translation, &foreign, PARENT),
        Some(GammaParentOutcome::UnsupportedValue { .. })
    ));

    let own = rewrite_route("own", "ratings.default.svc.cluster.local");
    let mut objects = base_services();
    objects.push(own.clone());
    let translation = translate(&objects);
    assert_eq!(
        outcome(&translation, &own, PARENT),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
}

/// F11: a matching HTTP rule with no backend and no answering filter returns a
/// 500; it never falls through to the plain Service.
#[test]
fn a_rule_without_backends_answers_500() {
    let route = http_route(
        "default",
        "no-backend",
        json!({
            "parentRefs": [service_parent("reviews")],
            "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/api"}}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let translation = translate(&objects);
    let rules = dispatch_rules(&translation.config);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["fault"]["abort"]["status_code"], json!(500));
    assert_eq!(rules[0]["fault"]["abort"]["percentage"], json!(100.0));
    assert_eq!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
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
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::UnsupportedValue { .. })
    ));
}

fn reviews_virtual_service(export_to: Option<Value>) -> K8sObject {
    let mut spec = json!({
        "hosts": ["reviews"],
        "http": [{"route": [{"destination": {"host": "reviews", "port": {"number": 8080}}}]}]
    });
    if let Some(export_to) = export_to {
        spec["exportTo"] = export_to;
    }
    object(
        "VirtualService",
        "networking.istio.io/v1",
        "default",
        "reviews-vs",
        spec,
    )
}

#[test]
fn a_mesh_bound_virtual_service_takes_precedence_over_gamma_routes() {
    let route = http_route("default", "reviews-route", split_route_spec());
    let mut objects = base_services();
    objects.push(reviews_virtual_service(None));
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
    let lost = outcome(&translation, &route, PARENT);
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

/// F9: a VirtualService the route namespace's clients never receive (its
/// `exportTo` excludes its own namespace) does not suppress the GAMMA route.
#[test]
fn an_unexported_virtual_service_does_not_suppress_gamma() {
    let route = http_route("default", "reviews-route", split_route_spec());
    let mut objects = base_services();
    objects.push(reviews_virtual_service(Some(json!(["other"]))));
    objects.push(route.clone());
    let translation = translate(&objects);
    assert_eq!(gamma_proxies(&translation.config).len(), 1);
    assert_eq!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
}

#[test]
fn grpc_route_wins_over_http_route_on_the_same_port() {
    let grpc = created_at(
        grpc_route(
            "default",
            "reviews-grpc",
            json!({
                "parentRefs": [service_parent("reviews")],
                "rules": [{
                    "matches": [{"method": {"service": "reviews.v1.Reviews", "method": "Get"}}],
                    "backendRefs": [{"name": "reviews", "port": 8080}]
                }]
            }),
        ),
        NEWER,
    );
    let http = http_route("default", "reviews-http", split_route_spec());
    let mut objects = base_services();
    objects.push(grpc.clone());
    objects.push(http.clone());
    let translation = translate(&objects);
    assert!(matches!(
        outcome(&translation, &http, PARENT),
        Some(GammaParentOutcome::Conflicted { .. })
    ));
    assert_eq!(
        outcome(&translation, &grpc, PARENT),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
    assert!(
        dispatch_rules(&translation.config)
            .iter()
            .all(|rule| rule["match"]["headers"]["content-type"].is_object()),
        "only the GRPCRoute's rules are carried"
    );
}

/// F5: an HTTPRoute loses only the ports a GRPCRoute claims; its other
/// parentRef keeps serving.
#[test]
fn port_overlap_with_a_grpc_route_withdraws_only_the_overlapping_parent() {
    let multi = service("default", "multi", &[("http", 8080), ("http-admin", 9090)]);
    let http = http_route(
        "default",
        "multi-http",
        json!({
            "parentRefs": [
                {"group": "", "kind": "Service", "name": "multi", "sectionName": "http"},
                {"group": "", "kind": "Service", "name": "multi", "sectionName": "http-admin"}
            ],
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
        }),
    );
    let grpc = grpc_route(
        "default",
        "multi-grpc",
        json!({
            "parentRefs": [{"group": "", "kind": "Service", "name": "multi", "sectionName": "http"}],
            "rules": [{"backendRefs": [{"name": "ratings", "port": 8080}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(multi);
    objects.push(http.clone());
    objects.push(grpc.clone());
    let translation = translate(&objects);
    assert!(matches!(
        outcome(&translation, &http, "core/Service/default/multi/http/*"),
        Some(GammaParentOutcome::Conflicted { .. })
    ));
    assert_eq!(
        outcome(
            &translation,
            &http,
            "core/Service/default/multi/http-admin/*"
        ),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
    let rules = dispatch_rules(&translation.config);
    assert!(
        rules.iter().any(|rule| rule["match"]["port"] == json!(9090)
            && rule["destination"]["backend_host"] == json!(REVIEWS)),
        "the HTTPRoute keeps serving its admin port: {rules:?}"
    );
    assert!(
        !rules.iter().any(|rule| rule["match"]["port"] == json!(8080)
            && rule["destination"]["backend_host"] == json!(REVIEWS)),
        "the HTTPRoute never answers on the GRPCRoute's port"
    );
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
    let grpc = grpc_route(
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
        assert_eq!(
            outcome(&translation, &http, "core/Service/default/multi/*/8080"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );
        assert_eq!(
            outcome(&translation, &grpc, "core/Service/default/multi/*/9090"),
            Some(GammaParentOutcome::Programmed { producer: true })
        );
        let proxy = gamma_proxy(config);
        let dispatch = dispatch_plugin(config, proxy);
        MeshRouteDispatch::new(&dispatch.config).expect("the shared instance constructs");
        let rules = dispatch_rules(config);
        assert!(
            rules.iter().all(|rule| rule["match"]["port"].is_u64()),
            "every rule is port-guarded, so the two route tables never mix: {rules:?}"
        );
        assert!(rules.iter().any(|rule| rule["match"]["port"] == json!(8080)
            && rule["destination"]["backend_host"] == json!(REVIEWS)));
        assert!(rules.iter().any(|rule| rule["match"]["port"] == json!(9090)
            && rule["destination"]["backend_host"] == json!(RATINGS)));
        assert!(
            !rules.iter().any(|rule| rule["match"]["port"] == json!(8080)
                && rule["destination"]["backend_host"] == json!(RATINGS))
        );
        assert!(
            !rules.iter().any(|rule| rule["match"]["port"] == json!(9090)
                && rule["destination"]["backend_host"] == json!(REVIEWS))
        );
    }
}

#[test]
fn a_port_scoped_parent_guards_every_rule_and_passes_other_http_ports_through() {
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
            &[("http", 8080), ("http-admin", 9090), ("db", 5432)],
        ));
        objects.push(route);
        let config = translate(&objects).config;
        let rules = dispatch_rules(&config);
        assert!(
            rules.iter().all(|rule| rule["match"]["port"].is_u64()),
            "every rule is port-guarded: {rules:?}"
        );
        assert_eq!(
            rules[0]["match"]["port"],
            json!(8080),
            "the route's own port first"
        );
        let pass_through = rules
            .iter()
            .find(|rule| rule["match"]["port"] == json!(9090))
            .expect("the unattached HTTP port passes through");
        assert_eq!(
            pass_through["destination"]["backend_host"],
            json!("multi.default.svc.cluster.local")
        );
        assert_eq!(pass_through["destination"]["backend_port"], json!(9090));
        assert!(
            !rules
                .iter()
                .any(|rule| rule["match"]["port"] == json!(5432)),
            "a non-HTTP port gets no HTTP pass-through"
        );
    }
}

#[test]
fn a_parent_port_covering_every_http_port_is_unscoped() {
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
    let rules = dispatch_rules(&translate(&objects).config);
    assert!(
        rules.iter().all(|rule| rule["match"].get("port").is_none()),
        "a single-port Service needs no port predicate: {rules:?}"
    );
}

/// F6: a Gateway parent the route cannot attach to never withdraws its
/// independent Service attachment.
#[test]
fn a_refused_gateway_parent_keeps_the_service_attachment() {
    let route = http_route(
        "default",
        "both-parents",
        json!({
            "parentRefs": [
                {"name": "missing-gateway", "sectionName": "http"},
                service_parent("reviews")
            ],
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
        }),
    );
    let mut objects = base_services();
    objects.push(route.clone());
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translation");
    assert!(
        !skipped.contains_key(&K8sResourceKey::from_object(&route)),
        "the route is not refused as a whole"
    );
    assert_eq!(
        outcome(&translation, &route, PARENT),
        Some(GammaParentOutcome::Programmed { producer: true })
    );
    let parents = route_parents_status(&objects, "HTTPRoute", "both-parents");
    assert_condition(mesh_parent(&parents), "Accepted", "True", "Accepted");
}

/// F7: two Service attachments of one route can never derive one id.
#[test]
fn distinct_service_attachments_get_distinct_ids() {
    let route = http_route(
        "default",
        "two-services",
        json!({
            "parentRefs": [service_parent("app"), service_parent("app-0")],
            "rules": [
                {
                    "matches": [
                        {"path": {"type": "PathPrefix", "value": "/a"}},
                        {"path": {"type": "PathPrefix", "value": "/b"}}
                    ],
                    "backendRefs": [{"name": "reviews", "port": 8080}, {"name": "ratings", "port": 8080}]
                },
                {"backendRefs": [{"name": "reviews", "port": 8080}, {"name": "ratings", "port": 8080}]}
            ]
        }),
    );
    let mut objects = base_services();
    objects.push(service("default", "app", &[("http", 8080)]));
    objects.push(service("default", "app-0", &[("http", 8080)]));
    objects.push(route);
    let config = translate(&objects).config;
    let mut proxy_ids: Vec<&str> = gamma_proxies(&config)
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    assert_eq!(proxy_ids.len(), 2, "one route per Service");
    proxy_ids.sort();
    proxy_ids.dedup();
    assert_eq!(proxy_ids.len(), 2);
    let mut upstream_ids: Vec<&str> = config
        .upstreams
        .iter()
        .filter(|upstream| upstream.id.starts_with("istio-vs-upstream-gamma_"))
        .map(|upstream| upstream.id.as_str())
        .collect();
    assert_eq!(upstream_ids.len(), 4, "two rules for each of two Services");
    upstream_ids.sort();
    upstream_ids.dedup();
    assert_eq!(upstream_ids.len(), 4, "no id is derived twice");
}

/// F12: Ferrum's parent entries never push `status.parents` past the schema
/// bound of 32, and never displace another controller's entries.
#[test]
fn route_status_parents_stay_within_the_schema_bound() {
    let mut parent_refs = vec![service_parent("reviews")];
    for index in 0..4 {
        parent_refs
            .push(json!({"group": "", "kind": "Service", "name": format!("missing-{index}")}));
    }
    let mut route = http_route(
        "default",
        "crowded",
        json!({
            "parentRefs": parent_refs,
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}]
        }),
    );
    let foreign: Vec<Value> = (0..30)
        .map(|index| {
            json!({
                "parentRef": {"group": "", "kind": "Service", "name": format!("other-{index}")},
                "controllerName": "example.com/other-mesh",
                "conditions": []
            })
        })
        .collect();
    route.status = json!({"parents": foreign});
    let mut objects = base_services();
    objects.push(route);
    let status = route_status(&objects, "HTTPRoute", "crowded");
    let parents = status["parents"].as_array().expect("parents");
    assert!(parents.len() <= 32, "{} parents", parents.len());
    assert_eq!(
        parents
            .iter()
            .filter(|parent| parent["controllerName"] == json!("example.com/other-mesh"))
            .count(),
        30,
        "every other controller's entry is kept"
    );
}

#[test]
fn deleting_the_route_withdraws_the_mesh_route() {
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
