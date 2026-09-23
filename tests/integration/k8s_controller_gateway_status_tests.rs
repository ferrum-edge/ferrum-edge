//! Integration coverage for Gateway API status concurrency and typed route
//! materialization records.

use ferrum_edge::config::types::MAX_FRONTEND_TLS_CERTIFICATE_SOURCES;
use ferrum_edge::config_sources::k8s::{
    GatewayApiListenerKey, GatewayApiListenerParentKind, K8sMetadata, K8sObject,
    K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, GatewayApiStatusWriter,
    plan_gateway_api_status_updates,
};
use http::{Method, Request, Response, StatusCode};
use kube::Client;
use kube::client::Body;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tower::service_fn;

#[derive(Default)]
struct MockKubeState {
    get_count: usize,
    patch_bodies: Vec<Value>,
}

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(3),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn route_status_update() -> GatewayApiStatusUpdate {
    GatewayApiStatusUpdate {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        namespace: "default".to_string(),
        name: "api".to_string(),
        status: json!({
            "parents": [{
                "parentRef": {"name": "edge"},
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 3,
                    "reason": "Accepted",
                    "message": "Ferrum accepted this route",
                    "lastTransitionTime": "2026-07-13T00:00:00Z"
                }]
            }]
        }),
        patch_gateway_addresses: false,
        patch_gateway_listeners: false,
    }
}

fn live_route(resource_version: &str, foreign_controller: &str) -> Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": "api",
            "namespace": "default",
            "resourceVersion": resource_version
        },
        "status": {
            "parents": [{
                "parentRef": {"name": "foreign-edge"},
                "controllerName": foreign_controller,
                "conditions": [{"type": "Accepted", "status": "True"}]
            }]
        }
    })
}

fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("serialize mock Kubernetes response"),
        ))
        .expect("build mock Kubernetes response")
}

fn conflict_response() -> Response<Body> {
    json_response(
        StatusCode::CONFLICT,
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": "the object has been modified",
            "reason": "Conflict",
            "details": {
                "group": "gateway.networking.k8s.io",
                "kind": "httproutes",
                "name": "api"
            },
            "code": 409
        }),
    )
}

fn mock_kube_client(state: Arc<Mutex<MockKubeState>>) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            let method = request.method().clone();
            assert_eq!(
                request.uri().path(),
                "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes/api/status"
            );
            if method == Method::PATCH {
                assert_eq!(
                    request
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/merge-patch+json")
                );
            }
            let body = request
                .into_body()
                .collect_bytes()
                .await
                .expect("read mock Kubernetes request body");
            let response = match method {
                Method::GET => {
                    let mut state = state.lock().expect("lock mock Kubernetes state");
                    let response = if state.get_count == 0 {
                        live_route("1", "example.com/initial-controller")
                    } else {
                        live_route("2", "example.com/concurrent-controller")
                    };
                    state.get_count += 1;
                    json_response(StatusCode::OK, response)
                }
                Method::PATCH => {
                    let patch: Value =
                        serde_json::from_slice(&body).expect("parse status patch body");
                    let mut state = state.lock().expect("lock mock Kubernetes state");
                    state.patch_bodies.push(patch.clone());
                    if state.patch_bodies.len() == 1 {
                        conflict_response()
                    } else {
                        json_response(
                            StatusCode::OK,
                            json!({
                                "apiVersion": "gateway.networking.k8s.io/v1",
                                "kind": "HTTPRoute",
                                "metadata": {
                                    "name": "api",
                                    "namespace": "default",
                                    "resourceVersion": "3"
                                },
                                "status": patch["status"].clone()
                            }),
                        )
                    }
                }
                _ => json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    json!({"apiVersion": "v1", "kind": "Status", "code": 405}),
                ),
            };
            Ok::<_, Infallible>(response)
        }
    });
    Client::new(service, "default")
}

#[tokio::test]
async fn route_status_conflict_refetches_and_preserves_concurrent_foreign_parent() {
    let state = Arc::new(Mutex::new(MockKubeState::default()));
    let writer = GatewayApiStatusWriter::new(mock_kube_client(state.clone()));

    writer
        .patch_updates(vec![route_status_update()])
        .await
        .expect("route status retry should succeed");

    let state = state.lock().expect("lock mock Kubernetes state");
    assert_eq!(state.get_count, 2, "a 409 must trigger a fresh status read");
    assert_eq!(state.patch_bodies.len(), 2);

    let first = &state.patch_bodies[0];
    assert_eq!(first["metadata"]["resourceVersion"].as_str(), Some("1"));
    assert!(has_parent(first, "example.com/initial-controller"));

    let retried = &state.patch_bodies[1];
    assert_eq!(retried["metadata"]["resourceVersion"].as_str(), Some("2"));
    assert!(has_parent(retried, "example.com/concurrent-controller"));
    assert!(!has_parent(retried, "example.com/initial-controller"));
    assert!(has_parent(retried, FERRUM_GATEWAY_CONTROLLER_NAME));
}

fn has_parent(patch: &Value, controller_name: &str) -> bool {
    patch["status"]["parents"]
        .as_array()
        .is_some_and(|parents| {
            parents
                .iter()
                .any(|parent| parent["controllerName"].as_str() == Some(controller_name))
        })
}

#[test]
fn typed_route_parent_mapping_is_emitted_and_drives_programmed_status() {
    let gateway_class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{"name": "web", "port": 80, "protocol": "HTTP"}]
        }),
    );
    let route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "api",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
        }),
    );
    let objects = vec![gateway_class, gateway, route];
    let translation = translate_k8s_objects(&objects, options()).expect("route should materialize");

    assert!(translation.materialized_route_parents.iter().any(|entry| {
        entry.route.api_version == "gateway.networking.k8s.io/v1"
            && entry.route.kind == "HTTPRoute"
            && entry.route.namespace == "default"
            && entry.route.name == "api"
            && entry.parent_ref == "gateway.networking.k8s.io/Gateway/default/edge/web/*"
    }));

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    let route_update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == "api")
        .expect("route status update");
    let conditions = route_update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions");
    assert!(conditions.iter().any(|condition| {
        condition["type"].as_str() == Some("Programmed")
            && condition["status"].as_str() == Some("True")
    }));
}

/// Gateway API v1.5.1 `GRPCRouteSpec`: an HTTPRoute and a GRPCRoute attached to
/// the same listener with intersecting hostnames must resolve to exactly one
/// accepted Route (oldest `creationTimestamp`, then `{namespace}/{name}`), and
/// `GRPCRouteRule` forbids merging rules between the two kinds. The losing
/// Route must materialize nothing and must be reported `Accepted=False` with
/// the route-conflict reason, independent of the order objects are observed in.
#[test]
fn cross_kind_listener_overlap_rejects_the_whole_losing_route_in_status() {
    let gateway_class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "web",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]}
            }]
        }),
    );
    let mut http_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "web",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["edge.example.com"],
            "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
        }),
    );
    http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc_route = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "grpc",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"method": {"method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]
        }),
    );
    grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    for objects in [
        vec![
            gateway_class.clone(),
            gateway.clone(),
            http_route.clone(),
            grpc_route.clone(),
        ],
        vec![
            grpc_route.clone(),
            http_route.clone(),
            gateway.clone(),
            gateway_class.clone(),
        ],
    ] {
        let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");

        // The losing GRPCRoute materializes no traffic state at all.
        assert!(
            !translation
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.backend_port == 50051),
            "the rejected GRPCRoute must not produce a proxy"
        );
        assert!(
            !translation
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
            "the rejected GRPCRoute must not produce dispatch rules"
        );
        assert!(
            !translation
                .materialized_route_parents
                .iter()
                .any(|entry| entry.route.kind == "GRPCRoute"),
            "the rejected GRPCRoute must not claim a materialized parent"
        );

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);

        let grpc_update = updates
            .iter()
            .find(|update| update.kind == "GRPCRoute" && update.name == "grpc")
            .expect("the rejected GRPCRoute gets a status update");
        let conditions = grpc_update.status["parents"][0]["conditions"]
            .as_array()
            .expect("route parent conditions");
        let accepted = conditions
            .iter()
            .find(|condition| condition["type"].as_str() == Some("Accepted"))
            .expect("an Accepted condition");
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("Conflicted"));
        assert!(
            accepted["message"]
                .as_str()
                .is_some_and(|message| message.contains("forbids merging")),
            "the conflict message must name the cross-kind rule: {accepted:?}"
        );

        // The winning HTTPRoute is unaffected.
        let http_update = updates
            .iter()
            .find(|update| update.kind == "HTTPRoute" && update.name == "web")
            .expect("the accepted HTTPRoute gets a status update");
        let conditions = http_update.status["parents"][0]["conditions"]
            .as_array()
            .expect("route parent conditions");
        assert!(conditions.iter().any(|condition| {
            condition["type"].as_str() == Some("Accepted")
                && condition["status"].as_str() == Some("True")
        }));
        assert!(conditions.iter().any(|condition| {
            condition["type"].as_str() == Some("Programmed")
                && condition["status"].as_str() == Some("True")
        }));
    }
}

fn gateway_class() -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    )
}

fn cross_kind_gateway(listeners: Value) -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({"gatewayClassName": "ferrum", "listeners": listeners}),
    )
}

fn accepted_condition(update: &GatewayApiStatusUpdate) -> Value {
    update.status["parents"][0]["conditions"]
        .as_array()
        .expect("route parent conditions")
        .iter()
        .find(|condition| condition["type"].as_str() == Some("Accepted"))
        .expect("an Accepted condition")
        .clone()
}

/// A parentRef selects listeners; it is not itself a listener identity. A
/// wildcard reference and a `sectionName` reference naming the same listener
/// attach to the same listener, so Gateway API v1.5.1's HTTPRoute/GRPCRoute
/// merge prohibition applies and the newer Route is rejected whole — while the
/// route status still reports the *original* parentRef shape the operator wrote.
#[test]
fn cross_kind_conflict_resolves_across_wildcard_and_section_name_parent_refs() {
    let gateway = cross_kind_gateway(json!([{
        "name": "web",
        "port": 80,
        "protocol": "HTTP",
        "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]}
    }]));
    let mut http_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "web",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "hostnames": ["edge.example.com"],
            "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
        }),
    );
    http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc_route = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "grpc",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"method": {"method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]
        }),
    );
    grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    for objects in [
        vec![
            gateway_class(),
            gateway.clone(),
            http_route.clone(),
            grpc_route.clone(),
        ],
        vec![
            grpc_route.clone(),
            http_route.clone(),
            gateway.clone(),
            gateway_class(),
        ],
    ] {
        let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");

        assert!(
            !translation
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.backend_port == 50051),
            "the rejected GRPCRoute must not produce a proxy"
        );
        assert!(
            !translation
                .materialized_route_parents
                .iter()
                .any(|entry| entry.route.kind == "GRPCRoute"),
            "the rejected GRPCRoute must not claim a materialized parent"
        );

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);

        let grpc_update = updates
            .iter()
            .find(|update| update.kind == "GRPCRoute" && update.name == "grpc")
            .expect("the rejected GRPCRoute gets a status update");
        assert_eq!(
            grpc_update.status["parents"][0]["parentRef"]["sectionName"].as_str(),
            Some("web"),
            "route status must report the parentRef the operator wrote"
        );
        let accepted = accepted_condition(grpc_update);
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("Conflicted"));

        let http_update = updates
            .iter()
            .find(|update| update.kind == "HTTPRoute" && update.name == "web")
            .expect("the accepted HTTPRoute gets a status update");
        assert!(
            http_update.status["parents"][0]["parentRef"]
                .get("sectionName")
                .is_none(),
            "the wildcard parentRef must not gain a section name: {:?}",
            http_update.status
        );
        let accepted = accepted_condition(http_update);
        assert_eq!(accepted["status"].as_str(), Some("True"));
    }
}

/// The mirror case: two wildcard parentRefs share the literal `*/*` selector,
/// but `allowedRoutes.kinds` sends each kind to a different listener, so the
/// Routes never share one and neither may be rejected.
#[test]
fn cross_kind_wildcard_parent_refs_on_kind_disjoint_listeners_are_both_accepted() {
    let gateway = cross_kind_gateway(json!([
        {
            "name": "web",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}]}
        },
        {
            "name": "grpc",
            "port": 8080,
            "protocol": "HTTP",
            "allowedRoutes": {"kinds": [{"kind": "GRPCRoute"}]}
        }
    ]));
    // Distinct listen paths keep dispatch lists separate; port-aware
    // representation also stamps distinct listener ports onto each proxy.
    let mut http_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "web",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                "backendRefs": [{"name": "web", "port": 8080}]
            }]
        }),
    );
    http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc_route = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "grpc",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"method": {"service": "pkg.Svc", "method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]
        }),
    );
    grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    let objects = vec![gateway_class(), gateway, http_route, grpc_route];
    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    assert!(
        translation.route_conflicts.is_empty(),
        "kind-disjoint listeners are not a shared listener: {:?}",
        translation.route_conflicts
    );
    let mut ports: Vec<u16> = translation
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.backend_port)
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, vec![8080, 50051]);

    let updates =
        plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
    for (kind, name) in [("HTTPRoute", "web"), ("GRPCRoute", "grpc")] {
        let update = updates
            .iter()
            .find(|update| update.kind == kind && update.name == name)
            .unwrap_or_else(|| panic!("{kind} {name} gets a status update"));
        let accepted = accepted_condition(update);
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "{kind} {name} must stay accepted: {accepted:?}"
        );
    }
}

/// The fail-closed edge between the two cases above: one wildcard parentRef
/// reaches a shared listener *and* a GRPCRoute-only listener. It loses the
/// cross-kind arbitration on the shared listener. With port-aware
/// representation it retains the grpc-only claim, keeps Accepted=True for the
/// surviving parent, and continues to program traffic on that listener.
#[test]
fn cross_kind_wildcard_claim_losing_one_listener_retains_sibling_claims() {
    let gateway = cross_kind_gateway(json!([
        {
            "name": "shared",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]}
        },
        {
            "name": "grpc-only",
            "port": 8080,
            "protocol": "HTTP",
            "allowedRoutes": {"kinds": [{"kind": "GRPCRoute"}]}
        }
    ]));
    // The HTTPRoute pins the shared listener and is older, so it wins there.
    let mut http_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "web",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "shared"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                "backendRefs": [{"name": "web", "port": 8080}]
            }]
        }),
    );
    http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc_route = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "grpc",
        "default",
        json!({
            "parentRefs": [{"name": "edge"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"method": {"service": "pkg.Svc", "method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]
        }),
    );
    grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());

    for objects in [
        vec![
            gateway_class(),
            gateway.clone(),
            http_route.clone(),
            grpc_route.clone(),
        ],
        vec![
            grpc_route.clone(),
            http_route.clone(),
            gateway.clone(),
            gateway_class(),
        ],
    ] {
        let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");

        let mut ports: Vec<u16> = translation
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        ports.sort_unstable();
        assert_eq!(
            ports,
            vec![8080, 50051],
            "the GRPCRoute loses on the shared listener but retains the grpc-only claim"
        );
        assert!(
            translation
                .config
                .proxies
                .iter()
                .any(|proxy| { proxy.backend_port == 50051 && proxy.listen_port == Some(8080) }),
            "retained GRPCRoute claim must be scoped to the grpc-only listener"
        );
        assert!(
            translation
                .materialized_route_parents
                .iter()
                .any(|entry| entry.route.kind == "GRPCRoute"),
            "the retained GRPCRoute must claim a materialized parent"
        );

        let conflict = translation
            .route_conflicts
            .iter()
            .find(|conflict| conflict.loser.kind == "GRPCRoute")
            .expect("the shared-listener loss must still be reported as a conflict");
        assert_eq!(conflict.winner.kind, "HTTPRoute");
        assert_eq!(conflict.winner.name, "web");
        assert_eq!(conflict.key.listen_port, Some(80));

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
        let grpc_update = updates
            .iter()
            .find(|update| update.kind == "GRPCRoute" && update.name == "grpc")
            .expect("the GRPCRoute gets a status update");
        let accepted = accepted_condition(grpc_update);
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "partial listener loss must keep Accepted=True: {accepted:?}"
        );

        let http_update = updates
            .iter()
            .find(|update| update.kind == "HTTPRoute" && update.name == "web")
            .expect("the accepted HTTPRoute gets a status update");
        assert_eq!(
            accepted_condition(http_update)["status"].as_str(),
            Some("True")
        );
    }
}

/// Gateway API v1.5.1 scopes the merge prohibition to the HTTP family, and
/// Ferrum now claims `TCPRoute` through live black-box conformance checks. The
/// whole-route cross-kind rejection must therefore stay confined to
/// HTTPRoute/GRPCRoute: an L4 route sharing a Gateway with a losing GRPCRoute
/// keeps its stream proxy and is never reported `Conflicted`.
///
/// Widening the arbitration to "any two different route kinds" would withdraw a
/// TCPRoute whenever an HTTPRoute contended on the same Gateway — a regression
/// only the 90-minute conformance lab would otherwise catch.
#[test]
fn cross_kind_rejection_does_not_reach_l4_routes_on_the_same_gateway() {
    let gateway = cross_kind_gateway(json!([
        {
            "name": "web",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {"kinds": [{"kind": "HTTPRoute"}, {"kind": "GRPCRoute"}]}
        },
        {
            "name": "db",
            "port": 15432,
            "protocol": "TCP",
            "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
        }
    ]));
    let mut http_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "web",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["edge.example.com"],
            "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
        }),
    );
    http_route.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut grpc_route = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "grpc",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["edge.example.com"],
            "rules": [{
                "matches": [{"method": {"service": "pkg.Svc", "method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]
        }),
    );
    grpc_route.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());
    // Deliberately the newest object: an order- or timestamp-driven widening of
    // the arbitration would pick this one as the loser.
    let mut tcp_route = object(
        "gateway.networking.k8s.io/v1alpha2",
        "TCPRoute",
        "db",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "db"}],
            "rules": [{"backendRefs": [{"name": "db", "port": 5432}]}]
        }),
    );
    tcp_route.metadata.creation_timestamp = Some("2026-03-01T00:00:00Z".to_string());

    let objects = vec![gateway_class(), gateway, http_route, grpc_route, tcp_route];
    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");

    // The HTTP-family arbitration still runs, and it names only the GRPCRoute.
    assert!(
        translation
            .route_conflicts
            .iter()
            .any(|conflict| conflict.loser.kind == "GRPCRoute"),
        "the newer GRPCRoute must still lose the cross-kind arbitration: {:?}",
        translation.route_conflicts
    );
    let l4_arbitrated = translation
        .route_conflicts
        .iter()
        .any(|conflict| conflict.loser.kind == "TCPRoute" || conflict.winner.kind == "TCPRoute");
    assert!(
        !l4_arbitrated,
        "an L4 route must never take part in HTTPRoute/GRPCRoute arbitration: {:?}",
        translation.route_conflicts
    );

    // The TCPRoute still materializes its stream proxy on the TCP listener.
    let tcp_proxy = translation
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.backend_port == 5432)
        .expect("the TCPRoute must still materialize a stream proxy");
    assert_eq!(tcp_proxy.listen_port, Some(15432));

    // ...and the winning HTTPRoute is unaffected, while the loser stays absent.
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_port == 8080),
        "the winning HTTPRoute must still materialize"
    );
    assert!(
        !translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_port == 50051),
        "the rejected GRPCRoute must not produce a proxy"
    );
}

// ── Same-port listener conflicts on `Gateway.status.listeners[]` ────────────
//
// `refuse_incompatible_same_port_listeners()` makes a listener non-
// materializable when one numeric port is claimed with physically
// incompatible frontend shapes. Status must say so: a refused listener
// reports `Conflicted=True`, `Programmed=False`, and `Accepted=False`
// (`PortUnavailable`) — never `Accepted=True` / `NoConflicts`.

fn tls_secret_object(name: &str) -> K8sObject {
    tls_secret_object_in(name, "default")
}

fn tls_secret_object_in(name: &str, namespace: &str) -> K8sObject {
    use base64::Engine as _;
    let cert = include_str!("../certs/server.crt");
    let key = include_str!("../certs/server.key");
    object(
        "v1",
        "Secret",
        name,
        namespace,
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": base64::engine::general_purpose::STANDARD.encode(cert),
                "tls.key": base64::engine::general_purpose::STANDARD.encode(key),
            }
        }),
    )
}

fn listener_status<'a>(update: &'a GatewayApiStatusUpdate, name: &str) -> &'a Value {
    update.status["listeners"]
        .as_array()
        .expect("listener statuses")
        .iter()
        .find(|listener| listener["name"].as_str() == Some(name))
        .expect("the listener must be reported")
}

fn listener_condition<'a>(listener: &'a Value, condition_type: &str) -> &'a Value {
    listener["conditions"]
        .as_array()
        .expect("listener conditions")
        .iter()
        .find(|condition| condition["type"].as_str() == Some(condition_type))
        .unwrap_or_else(|| panic!("a {condition_type} condition"))
}

fn gateway_update(objects: &[K8sObject], name: &str) -> GatewayApiStatusUpdate {
    gateway_update_with_options(objects, options(), name)
}

fn gateway_update_with_options(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    name: &str,
) -> GatewayApiStatusUpdate {
    plan_gateway_api_status_updates(objects, options, &[])
        .into_iter()
        .find(|update| update.kind == "Gateway" && update.name == name)
        .expect("a Gateway status update")
}

fn assert_listener_refused(update: &GatewayApiStatusUpdate, name: &str, reason: &str) {
    let listener = listener_status(update, name);
    let conflicted = listener_condition(listener, "Conflicted");
    assert_eq!(
        conflicted["status"].as_str(),
        Some("True"),
        "listener {name} must report Conflicted=True: {conflicted:?}"
    );
    assert_eq!(
        conflicted["reason"].as_str(),
        Some(reason),
        "listener {name} conflict reason: {conflicted:?}"
    );
    let accepted = listener_condition(listener, "Accepted");
    assert_eq!(
        accepted["status"].as_str(),
        Some("False"),
        "a refused listener must not report Accepted=True: {accepted:?}"
    );
    assert_eq!(accepted["reason"].as_str(), Some("PortUnavailable"));
    let programmed = listener_condition(listener, "Programmed");
    assert_eq!(
        programmed["status"].as_str(),
        Some("False"),
        "a refused listener must not report Programmed=True: {programmed:?}"
    );
}

#[test]
fn a_plaintext_and_tls_listener_sharing_a_port_both_report_conflicted() {
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "plain",
                    "port": 8443,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "secure",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "b.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }
            ]
        }),
    );
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![class, gateway, tls_secret_object("app-cert")];

    let update = gateway_update(&objects, "edge");
    assert_listener_refused(&update, "plain", "ProtocolConflict");
    assert_listener_refused(&update, "secure", "ProtocolConflict");
    let expected_message = "Port \"8443\" is claimed by both plaintext and an effective TLS-serving \
         frontend shape, so every conflicting claim on this port is refused \
         (Conflicted).";
    for name in ["plain", "secure"] {
        let conflicted = listener_condition(listener_status(&update, name), "Conflicted");
        assert_eq!(
            conflicted["message"].as_str(),
            Some(expected_message),
            "listener {name} status must use fixed port/category wording: {conflicted:?}"
        );
        let message = conflicted["message"].as_str().unwrap_or_default();
        assert!(
            !message.contains("Gateway/default/edge")
                && !message.contains("#plain")
                && !message.contains("#secure")
                && !message.contains("a.example.com")
                && !message.contains("b.example.com")
                && !message.contains("app-cert")
                && !message.contains("Gateway API listeners ["),
            "Gateway status Conflicted message must not disclose resource identities: {message}"
        );
    }

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert_eq!(
        translation.listener_conflicts.len(),
        2,
        "translation must refuse both plaintext and effective TLS claims: {:?}",
        translation.listener_conflicts
    );
    for (key, conflict) in &translation.listener_conflicts {
        assert_eq!(
            conflict.reason, "ProtocolConflict",
            "listener {key} must report ProtocolConflict"
        );
        assert_eq!(conflict.message, expected_message);
        assert!(
            !conflict.message.contains(&key.to_string())
                && !conflict.message.contains("a.example.com")
                && !conflict.message.contains("b.example.com")
                && !conflict.message.contains("app-cert")
                && !conflict.message.contains("Gateway API listeners ["),
            "physical conflict message must not disclose resource identities: {} => {}",
            key,
            conflict.message
        );
    }
}

/// HTTP-family vs raw TCP on one TCP port is a physical family conflict.
/// Both Gateway listeners must report Conflicted / PortUnavailable and the
/// translation conflict map must agree — not merely withdraw config.
#[test]
fn http_and_raw_tcp_listeners_sharing_a_port_both_report_conflicted() {
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "http",
                    "port": 8080,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "tcp",
                    "port": 8080,
                    "protocol": "TCP",
                    "allowedRoutes": {
                        "kinds": [{"kind": "TCPRoute"}],
                        "namespaces": {"from": "All"}
                    }
                }
            ]
        }),
    );
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![class, gateway];

    let update = gateway_update(&objects, "edge");
    assert_listener_refused(&update, "http", "ProtocolConflict");
    assert_listener_refused(&update, "tcp", "ProtocolConflict");

    // Reversed listener order must not change status.
    let mut reversed = objects.clone();
    if let Some(listeners) = reversed[1]
        .spec
        .get_mut("listeners")
        .and_then(Value::as_array_mut)
    {
        listeners.reverse();
    }
    let reversed_update = gateway_update(&reversed, "edge");
    assert_listener_refused(&reversed_update, "http", "ProtocolConflict");
    assert_listener_refused(&reversed_update, "tcp", "ProtocolConflict");

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert_eq!(
        translation.listener_conflicts.len(),
        2,
        "translation must refuse both HTTP and TCP claims: {:?}",
        translation.listener_conflicts
    );
    for listener in ["http", "tcp"] {
        let key = GatewayApiListenerKey {
            namespace: "default".to_string(),
            parent_kind: GatewayApiListenerParentKind::Gateway,
            gateway: "edge".to_string(),
            listener: listener.to_string(),
        };
        let conflict = translation
            .listener_conflicts
            .get(&key)
            .unwrap_or_else(|| panic!("missing conflict for {listener}"));
        assert_eq!(conflict.reason, "ProtocolConflict");
        assert_eq!(
            conflict.message,
            "Port \"8080\" is claimed by incompatible protocol families on the same TCP \
             transport (HTTP-family vs raw stream), so every conflicting claim on this \
             port is refused (Conflicted)."
        );
    }
    assert!(
        translation.warnings.iter().any(|warning| {
            warning.contains(
                "Gateway \"default\"/\"edge\" listener \"http\" rejected: ProtocolConflict",
            )
        }) && translation.warnings.iter().any(|warning| {
            warning.contains(
                "Gateway \"default\"/\"edge\" listener \"tcp\" rejected: ProtocolConflict",
            )
        }),
        "warnings must agree with status withdrawal: {:?}",
        translation.warnings
    );
    // One family-arbitration decision — not a second plaintext-vs-TLS refuse message.
    assert_eq!(
        translation
            .warnings
            .iter()
            .filter(|warning| {
                warning.contains("both plaintext and an effective TLS-serving frontend shape")
            })
            .count(),
        0,
        "HTTP+TCP must not also emit plaintext-vs-TLS refuse warnings: {:?}",
        translation.warnings
    );
}

#[test]
fn physically_refused_hostname_winner_does_not_conflict_the_surviving_listener() {
    let mut older = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-old",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "plain",
                    "port": 8443,
                    "protocol": "HTTP"
                },
                {
                    "name": "secure",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "shop.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert-old"}]}
                }
            ]
        }),
    );
    older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut survivor = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-new",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "secure",
                "port": 9443,
                "protocol": "HTTPS",
                "hostname": "shop.example.com",
                "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert-new"}]}
            }]
        }),
    );
    survivor.metadata.creation_timestamp = Some("2026-06-01T00:00:00Z".to_string());
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![
        class,
        survivor,
        older,
        tls_secret_object("cert-old"),
        tls_secret_object("cert-new"),
    ];

    let old_update = gateway_update(&objects, "edge-old");
    assert_listener_refused(&old_update, "plain", "ProtocolConflict");
    assert_listener_refused(&old_update, "secure", "ProtocolConflict");

    let surviving_update = gateway_update(&objects, "edge-new");
    let surviving_listener = listener_status(&surviving_update, "secure");
    let conflicted = listener_condition(surviving_listener, "Conflicted");
    assert_eq!(conflicted["status"].as_str(), Some("False"));
    assert_eq!(conflicted["reason"].as_str(), Some("NoConflicts"));

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| source.gateway == "edge-new")
    );
    assert!(translation.frontend_tls_hostname_conflicts.is_empty());
}

#[test]
fn oversized_cap_loser_does_not_reserve_hostname_from_healthy_listener() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let oversized_refs = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1)
        .map(|index| json!({"name": format!("oversized-cert-{index}")}))
        .collect::<Vec<_>>();
    let mut oversized = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-oversized",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 8443,
                "protocol": "HTTPS",
                "hostname": "shop.example.com",
                "tls": {"mode": "Terminate", "certificateRefs": oversized_refs},
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    oversized.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut healthy = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-healthy",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 9443,
                "protocol": "HTTPS",
                "hostname": "shop.example.com",
                "tls": {"mode": "Terminate", "certificateRefs": [{"name": "healthy-cert"}]},
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    healthy.metadata.creation_timestamp = Some("2026-06-01T00:00:00Z".to_string());
    let healthy_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "healthy-route",
        "default",
        json!({
            "parentRefs": [{"name": "edge-healthy", "sectionName": "https"}],
            "rules": [{"backendRefs": [{"name": "backend", "port": 8080}]}]
        }),
    );
    let oversized_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "oversized-route",
        "default",
        json!({
            "parentRefs": [{"name": "edge-oversized", "sectionName": "https"}],
            "rules": [{"backendRefs": [{"name": "backend", "port": 8080}]}]
        }),
    );
    let mut objects = vec![
        class,
        oversized,
        healthy,
        healthy_route,
        oversized_route,
        tls_secret_object("healthy-cert"),
    ];
    objects.extend(
        (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1)
            .map(|index| tls_secret_object(&format!("oversized-cert-{index}"))),
    );

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert_eq!(translation.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        translation.config.frontend_tls_certificate_sources[0].gateway,
        "edge-healthy"
    );
    assert!(translation.frontend_tls_hostname_conflicts.is_empty());
    assert!(translation.warnings.iter().any(|warning| {
        warning.contains("edge-oversized")
            && warning.contains("Gateway frontend TLS certificate limit")
    }));
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.id.contains("healthy-route")),
        "the capacity-fitting listener must retain its route"
    );
    assert!(
        translation
            .config
            .proxies
            .iter()
            .all(|proxy| !proxy.id.contains("oversized-route")),
        "the cap loser must not retain its route"
    );

    let healthy_update = gateway_update(&objects, "edge-healthy");
    let healthy_listener = listener_status(&healthy_update, "https");
    assert_eq!(
        listener_condition(healthy_listener, "Conflicted")["status"].as_str(),
        Some("False")
    );
    assert_eq!(
        listener_condition(healthy_listener, "Programmed")["status"].as_str(),
        Some("True")
    );
    let oversized_update = gateway_update(&objects, "edge-oversized");
    let oversized_listener = listener_status(&oversized_update, "https");
    assert_eq!(
        listener_condition(oversized_listener, "Conflicted")["status"].as_str(),
        Some("False"),
        "a cap refusal is not a hostname collision"
    );
    assert_eq!(
        listener_condition(oversized_listener, "Programmed")["status"].as_str(),
        Some("False")
    );
}

#[test]
fn non_fitting_hostname_claim_after_cap_fill_does_not_suppress_later_claim() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let fill_listeners = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES - 1)
        .map(|index| {
            json!({
                "name": format!("fill-{index:03}"),
                "port": 10000 + index,
                "protocol": "HTTPS",
                "hostname": format!("fill-{index}.example.com"),
                "tls": {"mode": "Terminate", "certificateRefs": [{"name": "fill-cert"}]},
                "allowedRoutes": {"namespaces": {"from": "All"}}
            })
        })
        .collect::<Vec<_>>();
    let mut fill = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-fill",
        "default",
        json!({"gatewayClassName": "ferrum", "listeners": fill_listeners}),
    );
    fill.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    let mut non_fitting = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-non-fitting",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 20000,
                "protocol": "HTTPS",
                "hostname": "shop.example.com",
                "tls": {
                    "mode": "Terminate",
                    "certificateRefs": [{"name": "blocked-a"}, {"name": "blocked-b"}]
                },
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    non_fitting.metadata.creation_timestamp = Some("2026-02-01T00:00:00Z".to_string());
    let mut healthy = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge-healthy",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "https",
                "port": 20001,
                "protocol": "HTTPS",
                "hostname": "shop.example.com",
                "tls": {"mode": "Terminate", "certificateRefs": [{"name": "healthy-cert"}]},
                "allowedRoutes": {"namespaces": {"from": "All"}}
            }]
        }),
    );
    healthy.metadata.creation_timestamp = Some("2026-03-01T00:00:00Z".to_string());
    let healthy_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "healthy-route",
        "default",
        json!({
            "parentRefs": [{"name": "edge-healthy", "sectionName": "https"}],
            "rules": [{"backendRefs": [{"name": "backend", "port": 8080}]}]
        }),
    );
    let blocked_route = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "blocked-route",
        "default",
        json!({
            "parentRefs": [{"name": "edge-non-fitting", "sectionName": "https"}],
            "rules": [{"backendRefs": [{"name": "backend", "port": 8080}]}]
        }),
    );
    let objects = vec![
        class,
        healthy,
        non_fitting,
        fill,
        healthy_route,
        blocked_route,
        tls_secret_object("fill-cert"),
        tls_secret_object("blocked-a"),
        tls_secret_object("blocked-b"),
        tls_secret_object("healthy-cert"),
    ];

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    assert_eq!(
        translation.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
    );
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| {
                source.gateway == "edge-healthy"
                    && source.hostname.as_deref() == Some("shop.example.com")
            })
    );
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.gateway != "edge-non-fitting")
    );
    assert!(translation.frontend_tls_hostname_conflicts.is_empty());
    assert!(translation.warnings.iter().any(|warning| {
        warning.contains("edge-non-fitting")
            && warning.contains("Gateway frontend TLS certificate limit")
    }));
    assert!(
        translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.id.contains("healthy-route")),
        "the later one-certificate claim must materialize its route"
    );
    assert!(
        translation
            .config
            .proxies
            .iter()
            .all(|proxy| !proxy.id.contains("blocked-route")),
        "the non-fitting listener must not retain its route"
    );

    let healthy_update = gateway_update(&objects, "edge-healthy");
    let healthy_listener = listener_status(&healthy_update, "https");
    assert_eq!(
        listener_condition(healthy_listener, "Conflicted")["status"].as_str(),
        Some("False")
    );
    assert_eq!(
        listener_condition(healthy_listener, "Programmed")["status"].as_str(),
        Some("True")
    );
    let non_fitting_update = gateway_update(&objects, "edge-non-fitting");
    let non_fitting_listener = listener_status(&non_fitting_update, "https");
    assert_eq!(
        listener_condition(non_fitting_listener, "Conflicted")["status"].as_str(),
        Some("False"),
        "the cap loser must not own status conflict precedence"
    );
    assert_eq!(
        listener_condition(non_fitting_listener, "Programmed")["status"].as_str(),
        Some("False")
    );
}

/// Physically refused same-port listeners must not be advertised as
/// MeshServices. A healthy sibling on a different port must still be exposed.
#[test]
fn physically_refused_same_port_listeners_are_not_emitted_as_mesh_services() {
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "plain",
                    "port": 8443,
                    "protocol": "HTTP",
                    "hostname": "a.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "secure",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "b.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "healthy",
                    "port": 8080,
                    "protocol": "HTTP",
                    "hostname": "healthy.example.com",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }
            ]
        }),
    );
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![class, gateway, tls_secret_object("app-cert")];

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    let services = translation
        .config
        .mesh
        .as_ref()
        .map(|mesh| mesh.services.as_slice())
        .unwrap_or(&[]);
    let names: Vec<&str> = services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    assert!(
        !names
            .iter()
            .any(|name| *name == "gateway-4-edge-plain" || *name == "gateway-4-edge-secure"),
        "refused same-port listeners must not become MeshServices: {names:?}"
    );
    assert!(
        names.contains(&"gateway-4-edge-healthy"),
        "healthy plaintext sibling on another port must remain exposed: {names:?}"
    );
    assert!(
        services.iter().any(|service| {
            service.name == "gateway-4-edge-healthy"
                && service.ports.len() == 1
                && service.ports[0].port == 8080
        }),
        "healthy winner must keep its listen port: {services:?}"
    );
}

/// Gateway API v1.5.1 defines HTTP-family listener distinctness on
/// `(port, hostname)` and states that "the `tls` field is not used for
/// determining if a listener is distinct". Sibling HTTPS listeners with
/// disjoint hostnames and *different* `certificateRefs` are therefore distinct
/// and must keep reporting `Accepted=True` / no `Conflicted`. Ferrum retains
/// both listener-owned certificates as SNI candidates, so each listener can
/// materialize its routes without serving traffic under its sibling's
/// certificate.
///
/// This is the shape the upstream conformance suite exercises with
/// `same-namespace-with-https-listener` and the ReferenceGrant Gateways, which
/// all share port 443 inside `gateway-conformance-infra`.
#[test]
fn tls_listeners_sharing_a_port_in_one_namespace_with_different_credentials_stay_accepted() {
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "first",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "a.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert-a"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "second",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "b.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert-b"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }
            ]
        }),
    );
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![
        class,
        gateway,
        tls_secret_object("cert-a"),
        tls_secret_object("cert-b"),
    ];

    let update = gateway_update(&objects, "edge");
    for name in ["first", "second"] {
        let listener = listener_status(&update, name);
        let conflicted = listener_condition(listener, "Conflicted");
        assert_eq!(
            conflicted["status"].as_str(),
            Some("False"),
            "listener {name} differs only by TLS credential, which is not a distinctness \
             field: {conflicted:?}"
        );
        let accepted = listener_condition(listener, "Accepted");
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "listener {name} must stay Accepted: {accepted:?}"
        );
    }
}

/// The exact upstream conformance shape: two *different* Gateways in one
/// namespace both claim port 443 with catch-all HTTPS listeners naming
/// different Secrets (`GatewaySecretReferenceGrant*` beside
/// `same-namespace-with-https-listener`). Both stay Accepted because this is
/// not a physical port conflict. Both report Programmed because Ferrum serves
/// both listener-owned certificates through SNI selection.
#[test]
fn tls_listeners_sharing_a_port_across_gateways_in_one_namespace_stay_accepted() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway_for = |name: &str, secret: &str| {
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            name,
            "default",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": secret}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        )
    };
    let objects = vec![
        class,
        gateway_for("edge", "cert-a"),
        gateway_for("reference-grant-edge", "cert-b"),
        tls_secret_object("cert-a"),
        tls_secret_object("cert-b"),
    ];

    for gateway in ["edge", "reference-grant-edge"] {
        let update = gateway_update(&objects, gateway);
        let listener = listener_status(&update, "https");
        let conflicted = listener_condition(listener, "Conflicted");
        assert_eq!(
            conflicted["status"].as_str(),
            Some("False"),
            "Gateway {gateway} must not be reported Conflicted: {conflicted:?}"
        );
        let accepted = listener_condition(listener, "Accepted");
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "Gateway {gateway} listener must stay Accepted: {accepted:?}"
        );
        let programmed = listener_condition(listener, "Programmed");
        assert_eq!(
            programmed["status"].as_str(),
            Some("True"),
            "every admitted SNI listener must report Programmed: {programmed:?}"
        );
    }
}

/// Two same-namespace Gateways with different credentials are both exposed as
/// MeshServices and retain their listener-owned SNI candidates.
#[test]
fn same_namespace_tls_gateways_are_both_emitted_as_mesh_services() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway_for = |name: &str, secret: &str| {
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            name,
            "default",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": secret}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        )
    };
    let objects = vec![
        class,
        gateway_for("edge", "cert-a"),
        gateway_for("reference-grant-edge", "cert-b"),
        tls_secret_object("cert-a"),
        tls_secret_object("cert-b"),
    ];

    let translation = translate_k8s_objects(&objects, options()).expect("translation");
    let services = translation
        .config
        .mesh
        .as_ref()
        .map(|mesh| mesh.services.as_slice())
        .unwrap_or(&[]);
    let names: Vec<&str> = services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    assert!(
        names.contains(&"gateway-4-edge-https"),
        "first SNI listener must remain exposed: {names:?}"
    );
    assert!(
        names.contains(&"gateway-20-reference-grant-edge-https"),
        "second SNI listener must remain exposed: {names:?}"
    );
    assert_eq!(
        names.iter().filter(|name| name.ends_with("-https")).count(),
        2,
        "both TLS MeshServices must be exposed: {names:?}"
    );
    assert!(
        translation.warnings.iter().all(|warning| {
            !warning.contains("k8s://")
                && !warning.contains("sha256=")
                && !warning.contains("#tls.crt")
                && !warning.contains("#tls.key")
        }),
        "frontend TLS warnings must not expose credential source metadata: {:?}",
        translation.warnings
    );
    // Reversed object order must preserve both listeners.
    let mut reversed = objects.clone();
    reversed.reverse();
    let reversed_translation =
        translate_k8s_objects(&reversed, options()).expect("reversed translation");
    let reversed_names: Vec<&str> = reversed_translation
        .config
        .mesh
        .as_ref()
        .map(|mesh| {
            mesh.services
                .iter()
                .map(|service| service.name.as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        reversed_names.contains(&"gateway-4-edge-https"),
        "order-independent first-listener exposure: {reversed_names:?}"
    );
    assert!(
        reversed_names.contains(&"gateway-20-reference-grant-edge-https"),
        "order-independent second-listener exposure: {reversed_names:?}"
    );
}

/// Across Gateway namespaces, physical compatibility is decided from each
/// namespace's complete admitted certificate set. Disagreeing sets on one
/// socket stay fail-closed on every effective claim.
#[test]
fn tls_listeners_on_one_port_across_namespaces_with_different_certs_conflict() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway_for = |name: &str, namespace: &str, secret: &str| {
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            name,
            namespace,
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "hostname": format!("{name}.example.com"),
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": secret}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        )
    };
    let objects = vec![
        class,
        gateway_for("edge", "default", "cert-a"),
        gateway_for("other-edge", "other", "cert-b"),
        tls_secret_object_in("cert-a", "default"),
        tls_secret_object_in("cert-b", "other"),
    ];
    let namespaces = vec!["default".to_string(), "other".to_string()];
    let options = options().with_source_namespaces(namespaces);

    let update = gateway_update_with_options(&objects, options.clone(), "edge");
    assert_listener_refused(&update, "https", "HostnameConflict");
    let other = gateway_update_with_options(&objects, options, "other-edge");
    assert_listener_refused(&other, "https", "HostnameConflict");
}

/// Two namespaces expose the same complete `{X,Y}` certificate set on one
/// port. The physical socket can satisfy both plans, so neither namespace may
/// manufacture a `HostnameConflict`.
#[test]
fn matching_certificate_sets_across_namespaces_are_not_a_conflict() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway_for = |name: &str, namespace: &str, secret: Value| {
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            name,
            namespace,
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "hostname": format!("{name}.example.com"),
                        "tls": {"mode": "Terminate", "certificateRefs": [secret]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        )
    };
    let grant = object(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        "allow-other-gateway-cert",
        "default",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "namespace": "other"
            }],
            "to": [
                {"group": "", "kind": "Secret", "name": "cert-a"},
                {"group": "", "kind": "Secret", "name": "cert-b"}
            ]
        }),
    );
    // Both namespaces terminate with the same complete set through the
    // cross-namespace ReferenceGrant.
    let objects = vec![
        class,
        grant,
        gateway_for("edge-a", "default", json!({"name": "cert-a"})),
        gateway_for("edge-b", "default", json!({"name": "cert-b"})),
        gateway_for(
            "other-edge",
            "other",
            json!({"name": "cert-a", "namespace": "default"}),
        ),
        gateway_for(
            "other-edge-b",
            "other",
            json!({"name": "cert-b", "namespace": "default"}),
        ),
        tls_secret_object_in("cert-a", "default"),
        tls_secret_object_in("cert-b", "default"),
    ];
    let namespaces = vec!["default".to_string(), "other".to_string()];
    let options = options().with_source_namespaces(namespaces);

    for gateway in ["edge-a", "edge-b", "other-edge", "other-edge-b"] {
        let update = gateway_update_with_options(&objects, options.clone(), gateway);
        let listener = listener_status(&update, "https");
        let conflicted = listener_condition(listener, "Conflicted");
        assert_eq!(
            conflicted["status"].as_str(),
            Some("False"),
            "Gateway {gateway} belongs to a matching complete certificate set: {conflicted:?}"
        );
        let accepted = listener_condition(listener, "Accepted");
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "Gateway {gateway} must stay Accepted: {accepted:?}"
        );
    }

    // Reversed object order must not change the status decision.
    let mut reversed = objects.clone();
    reversed.reverse();
    for gateway in ["edge-a", "edge-b", "other-edge", "other-edge-b"] {
        let update = gateway_update_with_options(&reversed, options.clone(), gateway);
        let conflicted = listener_condition(listener_status(&update, "https"), "Conflicted");
        assert_eq!(
            conflicted["status"].as_str(),
            Some("False"),
            "order-independent status for {gateway}: {conflicted:?}"
        );
    }

    let translation = translate_k8s_objects(&objects, options.clone()).expect("translation");
    assert!(
        translation.listener_conflicts.is_empty(),
        "translation must agree with status: no physical conflict when effective slots share a credential: {:?}",
        translation.listener_conflicts
    );
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| source.namespace == "default" && source.cert_path.contains("/cert-a#")),
        "default must retain the cert-a SNI candidate"
    );
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| source.namespace == "other" && source.cert_path.contains("/cert-a#")),
        "other must retain the shared cert-a credential"
    );
    assert!(
        translation
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| source.namespace == "other" && source.cert_path.contains("/cert-b#")),
        "other must retain the shared cert-b credential"
    );
}

/// When two namespaces' complete certificate sets on one port differ, every
/// effective TLS claim on that physical socket is refused symmetrically.
#[test]
fn different_certificate_sets_across_namespaces_refuse_every_effective_claim() {
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let gateway_for = |name: &str, namespace: &str, secret: &str| {
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            name,
            namespace,
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [
                    {
                        "name": "https",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "hostname": format!("{name}.example.com"),
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": secret}]},
                        "allowedRoutes": {"namespaces": {"from": "All"}}
                    }
                ]
            }),
        )
    };
    let objects = vec![
        class,
        gateway_for("edge-a", "default", "cert-a"),
        gateway_for("edge-b", "default", "cert-b"),
        gateway_for("other-edge", "other", "cert-b"),
        tls_secret_object_in("cert-a", "default"),
        tls_secret_object_in("cert-b", "default"),
        tls_secret_object_in("cert-b", "other"),
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "sibling-route",
            "default",
            json!({
                "parentRefs": [{"name": "edge-b", "sectionName": "https"}],
                "hostnames": ["edge-b.example.com"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/sibling"}}],
                    "backendRefs": [{"name": "backend", "port": 8080}]
                }]
            }),
        ),
    ];
    let namespaces = vec!["default".to_string(), "other".to_string()];
    let options = options().with_source_namespaces(namespaces);

    // Effective sets are default→{cert-a, cert-b}, other→{cert-b}. Every
    // listener participating in either incompatible plan must be refused.
    let edge_a = gateway_update_with_options(&objects, options.clone(), "edge-a");
    assert_listener_refused(&edge_a, "https", "HostnameConflict");
    let other = gateway_update_with_options(&objects, options.clone(), "other-edge");
    assert_listener_refused(&other, "https", "HostnameConflict");

    let edge_b = gateway_update_with_options(&objects, options.clone(), "edge-b");
    assert_listener_refused(&edge_b, "https", "HostnameConflict");

    let expected_message = "Port \"8443\" has incompatible effective TLS credential sets across \
         namespaces, so every conflicting claim on this port is refused \
         (Conflicted).";
    for (update, gateway) in [
        (&edge_a, "edge-a"),
        (&edge_b, "edge-b"),
        (&other, "other-edge"),
    ] {
        let conflicted = listener_condition(listener_status(update, "https"), "Conflicted");
        assert_eq!(
            conflicted["message"].as_str(),
            Some(expected_message),
            "Gateway {gateway} status must use fixed port/category wording: {conflicted:?}"
        );
        let message = conflicted["message"].as_str().unwrap_or_default();
        assert!(
            !message.contains("Gateway/")
                && !message.contains(gateway)
                && !message.contains("#https")
                && !message.contains("cert-a")
                && !message.contains("cert-b")
                && !message.contains("Gateway API listeners ["),
            "Gateway {gateway} Conflicted message must not disclose resource identities: {message}"
        );
    }

    let translation = translate_k8s_objects(&objects, options).expect("translation");
    assert!(
        translation
            .listener_conflicts
            .contains_key(&GatewayApiListenerKey {
                namespace: "default".to_string(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: "edge-a".to_string(),
                listener: "https".to_string(),
            }),
        "translation must refuse the default effective claim: {:?}",
        translation.listener_conflicts
    );
    assert!(
        translation
            .listener_conflicts
            .contains_key(&GatewayApiListenerKey {
                namespace: "other".to_string(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: "other-edge".to_string(),
                listener: "https".to_string(),
            }),
        "translation must refuse the other-namespace effective claim: {:?}",
        translation.listener_conflicts
    );
    assert!(
        translation
            .listener_conflicts
            .contains_key(&GatewayApiListenerKey {
                namespace: "default".to_string(),
                parent_kind: GatewayApiListenerParentKind::Gateway,
                gateway: "edge-b".to_string(),
                listener: "https".to_string(),
            }),
        "translation must refuse every listener in the incompatible default namespace plan: {:?}",
        translation.listener_conflicts
    );
    for (key, conflict) in &translation.listener_conflicts {
        assert_eq!(conflict.reason, "HostnameConflict");
        assert_eq!(
            conflict.message, expected_message,
            "cross-namespace credential conflict must use fixed port/category wording"
        );
        assert!(
            !conflict.message.contains(&key.to_string())
                && !conflict
                    .message
                    .contains(&format!("{}.example.com", key.gateway))
                && !conflict.message.contains("cert-a")
                && !conflict.message.contains("cert-b")
                && !conflict.message.contains("k8s://")
                && !conflict.message.contains("#tls.")
                && !conflict.message.contains("Gateway API listeners ["),
            "physical conflict message must not disclose resource or credential identities: {} => {}",
            key,
            conflict.message
        );
    }
    assert!(
        translation.config.proxies.is_empty(),
        "a physically refused listener must materialize no routes: {:?}",
        translation.config.proxies
    );
}

/// A compatible same-port pair must stay clean: no `Conflicted`, and the
/// listeners keep their ordinary `Accepted=True` reporting.
#[test]
fn compatible_same_port_listeners_report_no_conflict() {
    let gateway = object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "edge",
        "default",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                {
                    "name": "first",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "a.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                },
                {
                    "name": "second",
                    "port": 8443,
                    "protocol": "HTTPS",
                    "hostname": "b.example.com",
                    "tls": {"mode": "Terminate", "certificateRefs": [{"name": "app-cert"}]},
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }
            ]
        }),
    );
    let class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        "default",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    );
    let objects = vec![class, gateway, tls_secret_object("app-cert")];

    let update = gateway_update(&objects, "edge");
    for name in ["first", "second"] {
        let listener = listener_status(&update, name);
        let conflicted = listener_condition(listener, "Conflicted");
        assert_eq!(
            conflicted["status"].as_str(),
            Some("False"),
            "listener {name} must not be reported Conflicted: {conflicted:?}"
        );
        let accepted = listener_condition(listener, "Accepted");
        assert_eq!(
            accepted["status"].as_str(),
            Some("True"),
            "listener {name} must stay Accepted: {accepted:?}"
        );
    }
}

/// A plaintext HTTP Gateway named `name` exposing one listener `http` on `port`.
fn plain_gateway(name: &str, port: u16) -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        name,
        "default",
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

/// An HTTPRoute claiming `/api` on `app.example.com` through the `http`
/// listener of every named Gateway.
fn slot_claim_route(name: &str, gateways: &[&str]) -> K8sObject {
    let parent_refs: Vec<Value> = gateways
        .iter()
        .map(|gateway| json!({"name": gateway, "sectionName": "http"}))
        .collect();
    object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        name,
        "default",
        json!({
            "parentRefs": parent_refs,
            "hostnames": ["app.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                "backendRefs": [{"name": "web", "port": 8080}]
            }]
        }),
    )
}

/// Listener identity must not be derived by lossy punctuation replacement.
/// Both Gateway names are valid, but `edge.a` and `edge-a` sanitize to the same
/// Ferrum ID fragment. A Route attached to both must retain two distinct proxy
/// resources and both listener ports.
#[test]
fn punctuation_colliding_gateway_names_keep_distinct_listener_claims() {
    let dotted = plain_gateway("edge.a", 8080);
    let dashed = plain_gateway("edge-a", 9090);
    let route = slot_claim_route("route-a", &["edge.a", "edge-a"]);
    let objects = vec![gateway_class(), dotted, dashed, route];

    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let mut ports: Vec<u16> = translation
        .config
        .proxies
        .iter()
        .filter_map(|proxy| proxy.listen_port)
        .collect();
    ports.sort_unstable();
    assert_eq!(
        ports,
        vec![8080, 9090],
        "lossy listener IDs must not overwrite one of the two claims: {:?}",
        translation.config.proxies
    );

    let ids: std::collections::HashSet<&str> = translation
        .config
        .proxies
        .iter()
        .map(|proxy| proxy.id.as_str())
        .collect();
    assert_eq!(ids.len(), 2, "each listener claim needs a unique proxy ID");
}

fn route_update<'a>(
    updates: &'a [GatewayApiStatusUpdate],
    name: &str,
) -> &'a GatewayApiStatusUpdate {
    updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == name)
        .unwrap_or_else(|| panic!("a status update for HTTPRoute {name}"))
}

/// One condition of the `status.parents[]` entry whose parentRef names
/// `gateway`. Keyed on the parentRef the operator wrote, so a multi-parent
/// Route can be asserted parent by parent.
fn parent_condition<'a>(
    update: &'a GatewayApiStatusUpdate,
    gateway: &str,
    condition_type: &str,
) -> &'a Value {
    let parent = update.status["parents"]
        .as_array()
        .expect("route parents")
        .iter()
        .find(|parent| parent["parentRef"]["name"].as_str() == Some(gateway))
        .unwrap_or_else(|| panic!("a status.parents[] entry for {gateway}"));
    parent["conditions"]
        .as_array()
        .expect("parent conditions")
        .iter()
        .find(|condition| condition["type"].as_str() == Some(condition_type))
        .unwrap_or_else(|| panic!("a {condition_type} condition for {gateway}"))
}

fn assert_condition(condition: &Value, status: &str, reason: &str, context: &str) {
    assert_eq!(
        condition["status"].as_str(),
        Some(status),
        "{context}: {condition:?}"
    );
    assert_eq!(
        condition["reason"].as_str(),
        Some(reason),
        "{context}: {condition:?}"
    );
}

/// Two different Gateway API listeners materialize one physical
/// `(namespace, hosts, listen path, listen port)` route slot. The translator
/// refuses both claims fail closed, so neither Route may report a materialized
/// Ferrum parent: a Route advertising `Programmed=True` for a slot the data
/// plane withdrew is exactly the contradiction issue #3612 has to close.
///
/// Both observation orders are checked. The refusal is symmetric, so which
/// claim the translator saw first must not decide what status reports.
#[test]
fn same_slot_listener_ambiguity_reports_both_routes_conflicted_in_status() {
    let gateway_a = plain_gateway("edge-a", 8080);
    let gateway_b = plain_gateway("edge-b", 8080);
    let route_a = slot_claim_route("route-a", &["edge-a"]);
    let route_b = slot_claim_route("route-b", &["edge-b"]);

    for objects in [
        vec![
            gateway_class(),
            gateway_a.clone(),
            gateway_b.clone(),
            route_a.clone(),
            route_b.clone(),
        ],
        vec![
            gateway_class(),
            gateway_b.clone(),
            gateway_a.clone(),
            route_b.clone(),
            route_a.clone(),
        ],
    ] {
        let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
        assert!(
            translation.config.proxies.is_empty(),
            "an ambiguous same-slot claim must materialize nothing: {:?}",
            translation.config.proxies
        );
        assert!(
            translation.materialized_route_parents.is_empty(),
            "a refused claim must leave no materialized parent behind: {:?}",
            translation.materialized_route_parents
        );

        let mut refused: Vec<String> = Vec::new();
        for attachment in &translation.refused_route_attachments {
            let listener = match attachment.listener.as_ref() {
                Some(listener) => listener.to_string(),
                None => "<unresolved>".to_string(),
            };
            refused.push(format!("{} on {listener}", attachment.route.name));
        }
        refused.sort();
        assert_eq!(
            refused,
            vec![
                "route-a on Gateway/default/edge-a#http".to_string(),
                "route-b on Gateway/default/edge-b#http".to_string(),
            ],
            "both claims must be refused, each named by its exact listener"
        );

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
        for (route, gateway) in [("route-a", "edge-a"), ("route-b", "edge-b")] {
            let update = route_update(&updates, route);
            assert_condition(
                parent_condition(update, gateway, "Accepted"),
                "False",
                "Conflicted",
                &format!("{route} must not report Accepted for a refused slot"),
            );
            assert_condition(
                parent_condition(update, gateway, "Programmed"),
                "False",
                "Conflicted",
                &format!("{route} must not report Programmed for a refused slot"),
            );
            let conflicted = parent_condition(update, gateway, "Conflicted");
            assert_condition(
                conflicted,
                "True",
                "Conflicted",
                &format!("{route} must report the ambiguity as a conflict"),
            );
            let message = conflicted["message"].as_str().unwrap_or_default();
            let expected = format!("default/{gateway}#http");
            assert!(
                message.contains(&expected),
                "the conflict message must name the refused listener: {message}"
            );
        }
    }
}

/// The refusal is confined to the exact listener-scoped claim. A Route with one
/// refused parentRef and one surviving parentRef keeps serving — and keeps
/// reporting `Accepted`/`Programmed` — on the survivor, while only the refused
/// parentRef is withdrawn. Rejecting the whole Route here would take a healthy
/// listener offline in status for a collision it never participated in.
#[test]
fn a_route_with_one_refused_and_one_surviving_parent_keeps_the_survivor() {
    let gateway_a = plain_gateway("edge-a", 8080);
    let gateway_b = plain_gateway("edge-b", 8080);
    // A third listener on its own port: the contested claim cannot reach it.
    let gateway_c = plain_gateway("edge-c", 9090);
    let route_a = slot_claim_route("route-a", &["edge-a", "edge-c"]);
    let route_b = slot_claim_route("route-b", &["edge-b"]);

    for objects in [
        vec![
            gateway_class(),
            gateway_a.clone(),
            gateway_b.clone(),
            gateway_c.clone(),
            route_a.clone(),
            route_b.clone(),
        ],
        vec![
            gateway_class(),
            gateway_c.clone(),
            gateway_b.clone(),
            gateway_a.clone(),
            route_b.clone(),
            route_a.clone(),
        ],
    ] {
        let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
        let listen_ports: Vec<Option<u16>> = translation
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.listen_port)
            .collect();
        assert_eq!(
            listen_ports,
            vec![Some(9090)],
            "only the uncontested :9090 claim may materialize: {:?}",
            translation.config.proxies
        );

        let parents: Vec<&str> = translation
            .materialized_route_parents
            .iter()
            .filter(|entry| entry.route.name == "route-a")
            .map(|entry| entry.parent_ref.as_str())
            .collect();
        assert!(
            parents.iter().any(|parent| parent.contains("edge-c")),
            "the surviving parentRef must keep its record: {parents:?}"
        );
        assert!(
            !parents.iter().any(|parent| parent.contains("edge-a")),
            "the refused parentRef must lose its record: {parents:?}"
        );

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
        let update = route_update(&updates, "route-a");
        assert_condition(
            parent_condition(update, "edge-c", "Accepted"),
            "True",
            "Accepted",
            "the surviving parentRef must stay Accepted",
        );
        assert_condition(
            parent_condition(update, "edge-c", "Programmed"),
            "True",
            "Programmed",
            "the surviving parentRef must stay Programmed",
        );
        assert_condition(
            parent_condition(update, "edge-c", "Conflicted"),
            "False",
            "NoConflicts",
            "the surviving parentRef must report no conflict",
        );
        assert_condition(
            parent_condition(update, "edge-a", "Accepted"),
            "False",
            "Conflicted",
            "the refused parentRef must not report Accepted",
        );
        assert_condition(
            parent_condition(update, "edge-a", "Programmed"),
            "False",
            "Conflicted",
            "the refused parentRef must not report Programmed",
        );

        let other = route_update(&updates, "route-b");
        assert_condition(
            parent_condition(other, "edge-b", "Programmed"),
            "False",
            "Conflicted",
            "the colliding Route must not report Programmed either",
        );
    }
}

/// Unsupported Gateway API actions must agree across translation and status,
/// including a valid first rule followed by an unsupported second rule.
#[test]
fn unsupported_http_and_grpc_route_features_are_refused_before_materialization() {
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;

    let supported_rule = json!({
        "backendRefs": [{"name": "api", "port": 8080, "filters": []}],
        "filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {
            "set": [{"name": "x-admission-control", "value": "retained"}]
        }}]
    });
    let unsupported = [
        (
            json!({"filters": [{"type": "ExtensionRef", "extensionRef": {"group": "example.test", "kind": "Filter", "name": "missing"}}]}),
            "IncompatibleFilters",
        ),
        (
            json!({"filters": [{"type": "CORS", "cors": {"allowOrigins": [{"exact": "https://example.test"}]}}]}),
            "IncompatibleFilters",
        ),
        // A repeated at-most-once filter is a conflicting declaration, not a
        // stackable one.
        (
            json!({"filters": [
                {"type": "ResponseHeaderModifier", "responseHeaderModifier": {"remove": ["x-one"]}},
                {"type": "ResponseHeaderModifier", "responseHeaderModifier": {"remove": ["x-two"]}},
            ]}),
            "IncompatibleFilters",
        ),
        // Ferrum strips protocol-managed response headers by design; a route
        // filter may not put one back.
        (
            json!({"filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                "set": [{"name": "Transfer-Encoding", "value": "chunked"}]
            }}]}),
            "UnsupportedValue",
        ),
        // A Trailers-Only gRPC error carries its status in the response
        // headers, so a route filter may not rewrite or strip it.
        (
            json!({"filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                "remove": ["grpc-status"]
            }}]}),
            "UnsupportedValue",
        ),
        (
            json!({"filters": [{"type": "RequestMirror", "requestMirror": {"backendRef": {"name": "mirror", "port": 8080}}}]}),
            "IncompatibleFilters",
        ),
        (
            json!({"backendRefs": [{"name": "api", "port": 8080, "filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {"remove": ["x-secret"]}}]}]}),
            "IncompatibleFilters",
        ),
        // `retry` (experimental channel) is not implemented on either kind.
        (json!({"retry": {"attempts": 2}}), "UnsupportedValue"),
        (
            json!({"futureRuleAction": {"enabled": true}}),
            "UnsupportedValue",
        ),
        (
            json!({"filters": [{"type": "FutureFilter", "futureFilter": {}}]}),
            "UnsupportedValue",
        ),
        (
            json!({"filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {"futureAction": ["x-secret"]}}]}),
            "IncompatibleFilters",
        ),
        (
            json!({"filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {}, "responseHeaderModifier": {"remove": ["x-secret"]}}]}),
            "IncompatibleFilters",
        ),
    ];
    // `URLRewrite` and `RequestRedirect` are HTTPRoute-only upstream, so a
    // GRPCRoute asking for either keeps the fail-closed refusal. So does a
    // GRPCRoute rule carrying `timeouts`, a field only HTTPRoute defines.
    let grpc_only_unsupported = [
        (
            json!({"filters": [{"type": "URLRewrite", "urlRewrite": {"hostname": "rewritten.test"}}]}),
            "IncompatibleFilters",
        ),
        (
            json!({"filters": [{"type": "RequestRedirect", "requestRedirect": {"statusCode": 302}}]}),
            "IncompatibleFilters",
        ),
        (json!({"timeouts": {"request": "1s"}}), "UnsupportedValue"),
    ];
    // An HTTPRoute may use either, but never both in one rule: a redirect
    // answers the request itself, so the rewrite could never be honored. Its
    // `timeouts` are validated exactly as the pinned CRD does: a value outside
    // the GEP-2257 duration grammar and a `backendRequest` longer than a
    // non-zero `request` (the CRD's CEL rule) are malformed (`Invalid`); a
    // sub-field the CRD does not define is `UnsupportedValue`.
    let http_only_unsupported = [
        (
            json!({"filters": [
                {"type": "URLRewrite", "urlRewrite": {"hostname": "rewritten.test"}},
                {"type": "RequestRedirect", "requestRedirect": {"statusCode": 302}},
            ]}),
            "IncompatibleFilters",
        ),
        (json!({"timeouts": {"request": "1x"}}), "Invalid"),
        (json!({"timeouts": {"request": "500"}}), "Invalid"),
        (json!({"timeouts": {"request": "123456s"}}), "Invalid"),
        (json!({"timeouts": {"request": "1s1s1s1s1s"}}), "Invalid"),
        (json!({"timeouts": {"backendRequest": 5}}), "Invalid"),
        (json!({"timeouts": "1s"}), "Invalid"),
        (
            json!({"timeouts": {"request": "1s", "backendRequest": "1500ms"}}),
            "Invalid",
        ),
        (json!({"timeouts": {"idle": "1s"}}), "UnsupportedValue"),
    ];
    for kind in ["HTTPRoute", "GRPCRoute"] {
        let kind_cases: Vec<_> = unsupported
            .iter()
            .chain(if kind == "GRPCRoute" {
                grpc_only_unsupported.iter()
            } else {
                http_only_unsupported.iter()
            })
            .collect();
        for (case_index, (patch, reason)) in kind_cases.iter().enumerate() {
            let mut bad_rule = supported_rule.clone();
            bad_rule
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let mut objects = vec![
                gateway_class(),
                cross_kind_gateway(json!([
                    {"name": "web", "port": 80, "protocol": "HTTP"}
                ])),
            ];
            for (name, hostname, rules) in [
                ("good", "good.test", json!([supported_rule.clone()])),
                ("bad", "bad.test", json!([supported_rule.clone(), bad_rule])),
            ] {
                objects.push(object(
                    "gateway.networking.k8s.io/v1",
                    kind,
                    name,
                    "default",
                    json!({"parentRefs": [{"name": "edge", "sectionName": "web"}],
                        "hostnames": [hostname], "rules": rules}),
                ));
            }
            let (translation, skipped) =
                translate_k8s_objects_collecting_skips(&objects, options())
                    .expect("valid sibling must survive a rejected route");
            assert_eq!(skipped.len(), 1, "{kind} case {case_index}: {skipped:?}");
            assert_eq!(skipped.keys().next().unwrap().name, "bad");
            assert!(
                translation
                    .materialized_route_parents
                    .iter()
                    .all(|entry| entry.route.name != "bad")
            );
            assert!(
                translation
                    .materialized_route_parents
                    .iter()
                    .any(|entry| entry.route.name == "good")
            );
            assert!(
                translation
                    .config
                    .proxies
                    .iter()
                    .all(|proxy| !proxy.hosts.contains(&"bad.test".to_string()))
            );
            assert!(
                translation
                    .config
                    .plugin_configs
                    .iter()
                    .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"
                        && plugin.config.to_string().contains("x-admission-control"))
            );

            for plugin in &translation.config.plugin_configs {
                ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
                    .unwrap_or_else(|error| {
                        panic!("{kind} case {case_index}: {}: {error}", plugin.plugin_name)
                    });
            }
            let updates =
                plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
            for (name, status) in [("bad", "False"), ("good", "True")] {
                let update = updates
                    .iter()
                    .find(|update| update.kind == kind && update.name == name)
                    .unwrap();
                let accepted = accepted_condition(update);
                assert_eq!(
                    accepted["status"], status,
                    "{kind} case {case_index}: {update:?}"
                );
                assert_eq!(
                    accepted["reason"],
                    if name == "bad" { *reason } else { "Accepted" }
                );
                let conditions = update.status["parents"][0]["conditions"]
                    .as_array()
                    .unwrap();
                let programmed = conditions
                    .iter()
                    .find(|condition| condition["type"] == "Programmed")
                    .unwrap();
                assert_eq!(
                    programmed["status"], status,
                    "{kind} case {case_index}: {update:?}"
                );
            }
        }
    }
}

/// The supported filter control must reach the backend, not merely appear in
/// serialized dispatch configuration beside a rejected route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supported_gateway_request_headers_reach_backend_beside_rejected_route() {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::harness::GatewayHarness;
    use crate::scaffolding::ports::reserve_port;
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;
    use std::time::Duration;

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::custom(|request| {
            request.method == "GET"
                && request.path == "/admission"
                && request.header("x-set") == Some("retained")
                && request.header("x-added") == Some("added")
                && request.header("x-remove").is_none()
        })))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");
    let service = object(
        "v1",
        "Service",
        "api",
        "default",
        json!({
            "clusterIP": "10.96.0.10",
            "ports": [{"name": "http", "port": 8080, "targetPort": backend_port}]
        }),
    );
    let mut endpoints = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "api-manual",
        "default",
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": backend_port}],
            "endpoints": [{"addresses": ["127.0.0.1"], "conditions": {"ready": true}}]
        }),
    );
    endpoints
        .metadata
        .labels
        .insert("kubernetes.io/service-name".to_string(), "api".to_string());
    let supported_rule = json!({
        "backendRefs": [{"name": "api", "port": 8080}],
        "filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {
            "set": [{"name": "x-set", "value": "retained"}],
            "add": [{"name": "x-added", "value": "added"}],
            "remove": ["x-remove"]
        }}]
    });
    let mut unsupported_rule = supported_rule.clone();
    unsupported_rule["filters"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "type": "RequestMirror", "requestMirror": {"backendRef": {"name": "mirror", "port": 8080}}
        }));
    let objects = vec![
        gateway_class(),
        cross_kind_gateway(json!([{"name": "web", "port": 80, "protocol": "HTTP"}])),
        service,
        endpoints,
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "good",
            "default",
            json!({
                "parentRefs": [{"name": "edge", "sectionName": "web"}],
                "hostnames": ["good.test"], "rules": [supported_rule]
            }),
        ),
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "bad",
            "default",
            json!({
                "parentRefs": [{"name": "edge", "sectionName": "web"}],
                "hostnames": ["bad.test"], "rules": [unsupported_rule]
            }),
        ),
    ];
    let opts = options().with_pod_discovery_enabled(true);
    let (mut translation, skipped) = translate_k8s_objects_collecting_skips(&objects, opts.clone())
        .expect("translate mixed routes");
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped.keys().next().unwrap().name, "bad");
    let updates = plan_gateway_api_status_updates(&objects, opts, &translation.route_conflicts);
    for (name, expected) in [("good", "True"), ("bad", "False")] {
        let update = updates
            .iter()
            .find(|update| update.kind == "HTTPRoute" && update.name == name)
            .unwrap();
        assert_eq!(accepted_condition(update)["status"], expected);
    }
    assert_eq!(translation.config.proxies.len(), 1);
    assert_eq!(translation.config.proxies[0].backend_host, "127.0.0.1");
    assert_eq!(translation.config.proxies[0].backend_port, backend_port);
    // The harness owns an ephemeral listener instead of binding Gateway port
    // 80. Keep the translated route, destination and filter configuration.
    translation.config.proxies[0].listen_port = None;
    // Translation returns an internal snapshot; the file-mode fixture needs
    // the versioned envelope normally supplied by its configuration source.
    translation.config.version = ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string();
    let yaml = serde_yaml::to_string(&translation.config).expect("serialize translated config");
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .env("FERRUM_NAMESPACE", "default")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("start translated gateway");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let response = client
        .get(harness.proxy_url("/admission"))
        .header("host", "good.test")
        .header("x-set", "original")
        .header("x-remove", "secret")
        .send()
        .await
        .expect("supported route response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "pong");
    backend.assert_no_matcher_mismatches().await;
    assert_eq!(backend.received_requests().await.len(), 1);
    let refused = client
        .get(harness.proxy_url("/admission"))
        .header("host", "bad.test")
        .send()
        .await
        .expect("rejected route response");
    assert_eq!(refused.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(
        backend.received_requests().await.len(),
        1,
        "rejected route must not reach backend"
    );
}

/// Shared fixture for the rule-filter data-plane tests: a `Service` +
/// `EndpointSlice` pair pointing at a locally spawned backend, plus the
/// `GatewayClass`/`Gateway` the routes attach to.
fn route_filter_cluster_objects(
    backend_port: u16,
) -> Vec<ferrum_edge::config_sources::k8s::K8sObject> {
    let service = object(
        "v1",
        "Service",
        "api",
        "default",
        json!({
            "clusterIP": "10.96.0.11",
            "ports": [{"name": "http", "port": 8080, "targetPort": backend_port}]
        }),
    );
    let mut endpoints = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "api-manual",
        "default",
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": backend_port}],
            "endpoints": [{"addresses": ["127.0.0.1"], "conditions": {"ready": true}}]
        }),
    );
    endpoints
        .metadata
        .labels
        .insert("kubernetes.io/service-name".to_string(), "api".to_string());
    vec![
        gateway_class(),
        cross_kind_gateway(json!([{"name": "web", "port": 80, "protocol": "HTTP"}])),
        service,
        endpoints,
    ]
}

/// Translate `route` and hand the result to a running gateway.
///
/// The harness owns an ephemeral listener instead of binding Gateway port 80,
/// so every generated proxy's `listen_port` is cleared; everything else —
/// routes, destinations, dispatch rules and generated plugins — is exactly what
/// the translator produced.
async fn spawn_translated_route_gateway(
    objects: &[ferrum_edge::config_sources::k8s::K8sObject],
    extra_plugins: Vec<ferrum_edge::config::types::PluginConfig>,
) -> crate::scaffolding::harness::GatewayHarness {
    spawn_translated_route_gateway_with(objects, extra_plugins, |_| {}).await
}

/// [`spawn_translated_route_gateway`] with a hook that edits the translated
/// config before it is served — for operator policy the Gateway API cannot
/// express yet (for example a proxy retry policy).
async fn spawn_translated_route_gateway_with(
    objects: &[ferrum_edge::config_sources::k8s::K8sObject],
    extra_plugins: Vec<ferrum_edge::config::types::PluginConfig>,
    edit: impl FnOnce(&mut ferrum_edge::config::types::GatewayConfig),
) -> crate::scaffolding::harness::GatewayHarness {
    use crate::scaffolding::harness::GatewayHarness;
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;

    let opts = options().with_pod_discovery_enabled(true);
    let (mut translation, skipped) =
        translate_k8s_objects_collecting_skips(objects, opts.clone()).expect("translate route");
    assert!(skipped.is_empty(), "route must be accepted: {skipped:?}");
    let updates = plan_gateway_api_status_updates(objects, opts, &translation.route_conflicts);
    for update in updates
        .iter()
        .filter(|update| matches!(update.kind.as_str(), "HTTPRoute" | "GRPCRoute"))
    {
        assert_eq!(
            accepted_condition(update)["status"],
            "True",
            "{}/{} must be Accepted: {update:?}",
            update.kind,
            update.name
        );
    }
    // Every emitted plugin must construct, or an "Accepted" route would carry
    // configuration no data plane can load.
    for plugin in &translation.config.plugin_configs {
        ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
            .unwrap_or_else(|error| panic!("{}: {error}", plugin.plugin_name));
    }
    for proxy in &mut translation.config.proxies {
        proxy.listen_port = None;
    }
    translation.config.plugin_configs.extend(extra_plugins);
    edit(&mut translation.config);
    translation.config.version = ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string();
    let yaml = serde_yaml::to_string(&translation.config).expect("serialize translated config");
    GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .env("FERRUM_NAMESPACE", "default")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("start translated gateway")
}

fn global_response_transformer(
    rules: serde_json::Value,
) -> ferrum_edge::config::types::PluginConfig {
    use ferrum_edge::config::types::{PluginConfig, PluginScope};
    let now = chrono::Utc::now();
    PluginConfig {
        labels: Default::default(),
        id: "operator-global-response-transformer".to_string(),
        plugin_name: "response_transformer".to_string(),
        namespace: "default".to_string(),
        config: json!({ "rules": rules }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// `ResponseHeaderModifier` must reach the CLIENT through the real data plane,
/// apply only to the rule that declared it, and compose with — not suppress —
/// an operator's global `response_transformer`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_response_header_modifier_reaches_the_client_through_the_data_plane() {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::ports::reserve_port;
    use std::time::Duration;

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "x-set".into(),
            value: "origin".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "x-remove".into(),
            value: "leaked".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "x-appended".into(),
            value: "origin".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let mut objects = route_filter_cluster_objects(backend_port);
    objects.push(object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "headers",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["headers.test"],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/modified"}}],
                    "backendRefs": [{"name": "api", "port": 8080}],
                    "filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "set": [{"name": "x-set", "value": "route"}],
                        "add": [
                            {"name": "x-added", "value": "route"},
                            {"name": "x-appended", "value": "route"}
                        ],
                        "remove": ["x-remove"]
                    }}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/plain"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                },
                // No backendRefs and no RequestRedirect: upstream requires a
                // 500, not a forward to an unresolvable backend.
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/nobackend"}}],
                    "filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "set": [{"name": "x-set", "value": "route"}]
                    }}]
                }
            ]
        }),
    ));

    // An operator's global response transformer must keep running its own
    // static rules; the route filter is applied last and wins on a shared name.
    let global = global_response_transformer(json!([
        {"operation": "add", "target": "header", "key": "x-global", "value": "on"},
        {"operation": "update", "target": "header", "key": "x-set", "value": "global"}
    ]));
    let harness = spawn_translated_route_gateway(&objects, vec![global]).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let modified = client
        .get(harness.proxy_url("/modified/thing"))
        .header("host", "headers.test")
        .send()
        .await
        .expect("filtered route response");
    assert_eq!(modified.status(), reqwest::StatusCode::OK);
    let headers = modified.headers().clone();
    assert_eq!(headers.get("x-set").unwrap(), "route", "set must overwrite");
    assert_eq!(headers.get("x-added").unwrap(), "route", "add must apply");
    assert_eq!(
        headers.get("x-appended").unwrap(),
        "origin,route",
        "add must append to a header the backend already sent, not replace it"
    );
    assert!(headers.get("x-remove").is_none(), "remove must apply");
    assert_eq!(
        headers.get("x-global").unwrap(),
        "on",
        "a route filter must not suppress the global transformer"
    );
    assert_eq!(modified.text().await.unwrap(), "pong");

    // The sibling rule declared no filter and must observe the backend's own
    // headers, with only the global transformer applied.
    let plain = client
        .get(harness.proxy_url("/plain/thing"))
        .header("host", "headers.test")
        .send()
        .await
        .expect("sibling route response");
    assert_eq!(plain.status(), reqwest::StatusCode::OK);
    let headers = plain.headers().clone();
    assert_eq!(
        headers.get("x-set").unwrap(),
        "global",
        "the sibling rule must not inherit the route filter"
    );
    assert!(headers.get("x-added").is_none());
    assert_eq!(headers.get("x-appended").unwrap(), "origin");
    assert_eq!(headers.get("x-remove").unwrap(), "leaked");
    assert_eq!(headers.get("x-global").unwrap(), "on");

    let backendless = client
        .get(harness.proxy_url("/nobackend/thing"))
        .header("host", "headers.test")
        .send()
        .await
        .expect("backendless rule response");
    assert_eq!(
        backendless.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "a filter-only rule with no backendRefs must answer 500"
    );

    backend.assert_no_matcher_mismatches().await;
    assert_eq!(
        backend.received_requests().await.len(),
        2,
        "the backendless rule must never reach a backend"
    );
}

/// `URLRewrite` must change what the BACKEND observes — path, preserved query
/// and authority — for the rule that declared it and for no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_url_rewrite_reaches_the_backend_through_the_data_plane() {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::ports::reserve_port;
    use std::time::Duration;

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let mut objects = route_filter_cluster_objects(backend_port);
    objects.push(object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "rewrites",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["rewrite.test"],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}],
                    "filters": [{"type": "URLRewrite", "urlRewrite": {
                        "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}
                    }}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/full"}}],
                    "backendRefs": [{"name": "api", "port": 8080}],
                    "filters": [{"type": "URLRewrite", "urlRewrite": {
                        "hostname": "internal.example.test",
                        "path": {"type": "ReplaceFullPath", "replaceFullPath": "/one"}
                    }}]
                },
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": "/plain"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }
            ]
        }),
    ));

    let harness = spawn_translated_route_gateway(&objects, Vec::new()).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    for path in ["/api/users?q=1", "/full/deep/path", "/plain/thing"] {
        let response = client
            .get(harness.proxy_url(path))
            .header("host", "rewrite.test")
            .send()
            .await
            .unwrap_or_else(|error| panic!("{path}: {error}"));
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
    }

    backend.assert_no_matcher_mismatches().await;
    let observed = backend.received_requests().await;
    let seen: Vec<(String, String)> = observed
        .iter()
        .map(|request| {
            (
                request.path.clone(),
                request.header("host").unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        vec![
            // ReplacePrefixMatch replaces the matched prefix and keeps the
            // untouched suffix and query string.
            ("/v2/users?q=1".to_string(), "rewrite.test".to_string()),
            // ReplaceFullPath discards the whole path; hostname rebases the
            // backend-facing authority.
            ("/one".to_string(), "internal.example.test".to_string()),
            // The sibling rule declared no rewrite.
            ("/plain/thing".to_string(), "rewrite.test".to_string()),
        ]
    );
}

/// A GRPCRoute `ResponseHeaderModifier` must reach the client as response
/// metadata over a real gRPC call, preserving the message and the terminal
/// `grpc-status`.
///
/// It also pins the cost operators must know about: a rule-level response-header
/// policy governs the response TRAILERS of the requests it applies to (a route
/// override can name any field at request time), so that rule's non-reserved
/// backend trailers are governed away. The filter does not modify trailers — it
/// suppresses them. The sibling rule on the same route, which declares no
/// filter, keeps its application trailers, which is what proves the drop comes
/// from attaching the policy rather than from gRPC translation. The merged-proxy
/// variant of that guarantee is
/// `merged_grpc_route_sibling_without_response_header_modifier_keeps_trailers`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_route_response_header_modifier_reaches_the_client_and_preserves_status() {
    use crate::scaffolding::backends::grpc::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
    use crate::scaffolding::clients::grpc::GrpcClient;
    use crate::scaffolding::ports::reserve_port;
    use bytes::Bytes;

    let rpc_script = || {
        vec![
            GrpcStep::AcceptRpc(MatchRpc::any()),
            GrpcStep::SendInitialHeadersOverride(vec![
                ("content-type", "application/grpc".to_string()),
                ("x-set", "origin".to_string()),
                ("x-remove", "leaked".to_string()),
            ]),
            GrpcStep::RespondMessage(Bytes::from_static(b"pong")),
            GrpcStep::RespondStatusWithTrailers {
                code: 0,
                message: "",
                trailers: vec![("x-trailer", "kept".to_string())],
            },
        ]
    };
    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .steps(rpc_script())
        .steps(rpc_script())
        .spawn()
        .expect("spawn grpc backend");

    let mut objects = route_filter_cluster_objects(backend_port);
    objects.push(object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "metadata",
        "default",
        json!({
            // No `hostnames`: the h2c client's `:authority` is the harness's
            // ephemeral loopback address, and an added `host` header that
            // disagreed with it would be refused by protocol validation before
            // routing ever ran.
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [
                {
                    "matches": [{"method": {"service": "echo.Echo", "method": "Filtered"}}],
                    "backendRefs": [{"name": "api", "port": 8080}],
                    "filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "set": [{"name": "x-set", "value": "route"}],
                        "add": [{"name": "x-added", "value": "route"}],
                        "remove": ["x-remove"]
                    }}]
                },
                {
                    "matches": [{"method": {"service": "echo.Echo", "method": "Plain"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }
            ]
        }),
    ));

    let harness = spawn_translated_route_gateway(&objects, Vec::new()).await;
    let target = harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();
    let client = GrpcClient::h2c(target);

    let filtered = client
        .unary("/echo.Echo/Filtered", Bytes::from_static(b"ping"))
        .await
        .expect("filtered grpc call");
    assert_eq!(filtered.http_status, 200);
    assert_eq!(
        filtered.headers.get("x-set").unwrap(),
        "route",
        "set must overwrite gRPC response metadata"
    );
    assert_eq!(filtered.headers.get("x-added").unwrap(), "route");
    assert!(
        filtered.headers.get("x-remove").is_none(),
        "remove must apply to the initial metadata"
    );
    assert_eq!(filtered.grpc_status(), Some(0), "status must be preserved");
    assert_eq!(
        filtered.messages,
        vec![Bytes::from_static(b"pong")],
        "the message must be preserved"
    );
    let trailers = filtered.trailers.as_ref().expect("terminal trailers");
    assert!(
        trailers.get("x-trailer").is_none(),
        "a response-header policy governs this rule's non-reserved trailers away: {trailers:?}"
    );

    let plain = client
        .unary("/echo.Echo/Plain", Bytes::from_static(b"ping"))
        .await
        .expect("unfiltered grpc call");
    assert_eq!(plain.http_status, 200);
    assert_eq!(
        plain.headers.get("x-set").unwrap(),
        "origin",
        "the sibling rule must not inherit the route filter"
    );
    assert_eq!(plain.headers.get("x-remove").unwrap(), "leaked");
    assert!(plain.headers.get("x-added").is_none());
    assert_eq!(plain.grpc_status(), Some(0));
    assert_eq!(
        plain
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-trailer")),
        Some(&"kept".parse().unwrap()),
        "a rule with no response-header filter keeps its application trailers"
    );

    assert_eq!(backend.received_stream_count(), 2);
    assert_eq!(backend.matcher_mismatches(), 0);
}

/// Removing a rule filter must withdraw everything it generated — the dispatch
/// action AND the auto-emitted consumer plugin — rather than leaving a stale
/// resource behind.
#[test]
fn removing_a_rule_filter_withdraws_its_generated_resources() {
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;

    let route_with = |filters: serde_json::Value| {
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "withdrawn",
            "default",
            json!({
                "parentRefs": [{"name": "edge", "sectionName": "web"}],
                "hostnames": ["withdraw.test"],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}],
                    "filters": filters
                }]
            }),
        )
    };
    let translate = |filters: serde_json::Value| {
        let mut objects = route_filter_cluster_objects(19_999);
        objects.push(route_with(filters));
        let (translation, skipped) =
            translate_k8s_objects_collecting_skips(&objects, options()).expect("translate route");
        assert!(skipped.is_empty(), "{skipped:?}");
        translation.config
    };

    let with_filters = translate(json!([
        {"type": "URLRewrite", "urlRewrite": {
            "path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}
        }},
        {"type": "ResponseHeaderModifier", "responseHeaderModifier": {"remove": ["x-secret"]}}
    ]));
    let dispatch = |config: &ferrum_edge::config::types::GatewayConfig| {
        config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .map(|plugin| plugin.config.clone())
    };
    let rules = dispatch(&with_filters).expect("dispatch plugin");
    assert_eq!(rules["rules"][0]["rewrite"]["uri"], "/v2");
    assert!(rules["rules"][0]["response_transform"].is_array());
    assert!(
        with_filters
            .plugin_configs
            .iter()
            .any(|plugin| plugin.plugin_name == "response_transformer")
    );

    let without_filters = translate(json!([]));
    assert!(
        without_filters
            .plugin_configs
            .iter()
            .all(|plugin| plugin.plugin_name != "response_transformer"),
        "the auto-emitted consumer must be withdrawn with its filter"
    );
    match dispatch(&without_filters) {
        // A filter-less single-prefix rule needs no dispatch rule at all.
        None => {}
        Some(config) => {
            let rule = &config["rules"][0];
            assert!(rule.get("rewrite").is_none(), "{config}");
            assert!(rule.get("response_transform").is_none(), "{config}");
        }
    }
}

/// Drive one filtered and one unfiltered gRPC call through translated routes
/// that MERGE onto a single proxy, and prove the response-trailer cost of
/// `ResponseHeaderModifier` stays on the rule that declared it.
///
/// Same-kind routes sharing a host, listener and path collapse into one proxy,
/// one `mesh_route_dispatch`, and one rules-free `response_transformer`
/// consumer. The consumer's unbounded trailer policy is request-conditional:
/// it applies only when the matched dispatch rule published a response
/// transform. The filtered call is selected by the `x-variant: filtered`
/// request header; the plain call matches the sibling that declared no filter.
async fn assert_merged_sibling_keeps_trailers(
    filtered_route: ferrum_edge::config_sources::k8s::K8sObject,
    plain_route: ferrum_edge::config_sources::k8s::K8sObject,
    call_path: &str,
) {
    use crate::scaffolding::backends::grpc::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
    use crate::scaffolding::clients::grpc::GrpcClient;
    use crate::scaffolding::ports::reserve_port;
    use bytes::Bytes;
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;

    let rpc_script = || {
        vec![
            GrpcStep::AcceptRpc(MatchRpc::any()),
            GrpcStep::SendInitialHeadersOverride(vec![
                ("content-type", "application/grpc".to_string()),
                ("x-set", "origin".to_string()),
            ]),
            GrpcStep::RespondMessage(Bytes::from_static(b"pong")),
            GrpcStep::RespondStatusWithTrailers {
                code: 0,
                message: "",
                trailers: vec![("x-trailer", "kept".to_string())],
            },
        ]
    };
    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .steps(rpc_script())
        .steps(rpc_script())
        .spawn()
        .expect("spawn grpc backend");

    let kind = filtered_route.kind.clone();
    let mut objects = route_filter_cluster_objects(backend_port);
    objects.push(filtered_route);
    objects.push(plain_route);

    // Premise: both routes really did merge onto ONE proxy that carries ONE
    // consumer, and only the filtered rule publishes a response transform.
    // Without this, two separate proxies would pass the traffic assertions
    // below vacuously.
    let (translation, skipped) = translate_k8s_objects_collecting_skips(
        &objects,
        options().with_pod_discovery_enabled(true),
    )
    .expect("translate merged routes");
    assert!(skipped.is_empty(), "{kind}: {skipped:?}");
    assert_eq!(
        translation.config.proxies.len(),
        1,
        "{kind}: the two routes must merge onto one proxy: {:?}",
        translation.config.proxies
    );
    let consumers: Vec<_> = translation
        .config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "response_transformer")
        .collect();
    assert_eq!(consumers.len(), 1, "{kind}: one shared consumer");
    assert_eq!(
        consumers[0].proxy_id.as_deref(),
        Some(translation.config.proxies[0].id.as_str())
    );
    let dispatch = translation
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("merged dispatch plugin");
    let transformed_rules = dispatch.config["rules"]
        .as_array()
        .expect("dispatch rules")
        .iter()
        .filter(|rule| rule.get("response_transform").is_some())
        .count();
    assert_eq!(transformed_rules, 1, "{kind}: {}", dispatch.config);

    let harness = spawn_translated_route_gateway(&objects, Vec::new()).await;
    let target = harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();
    let client = GrpcClient::h2c(target);

    let filtered = client
        .unary_with_headers(
            call_path,
            Bytes::from_static(b"ping"),
            &[("x-variant", "filtered".to_string())],
        )
        .await
        .expect("filtered grpc call");
    assert_eq!(filtered.http_status, 200, "{kind}");
    assert_eq!(
        filtered.headers.get("x-set").unwrap(),
        "route",
        "{kind}: the header-gated rule's filter must apply"
    );
    assert_eq!(filtered.grpc_status(), Some(0), "{kind}");
    assert_eq!(filtered.messages, vec![Bytes::from_static(b"pong")]);
    assert!(
        filtered
            .trailers
            .as_ref()
            .expect("terminal trailers")
            .get("x-trailer")
            .is_none(),
        "{kind}: the rule that declared the filter pays the trailer cost"
    );

    let plain = client
        .unary(call_path, Bytes::from_static(b"ping"))
        .await
        .expect("sibling grpc call");
    assert_eq!(plain.http_status, 200, "{kind}");
    assert_eq!(
        plain.headers.get("x-set").unwrap(),
        "origin",
        "{kind}: the merged sibling must not inherit the filter"
    );
    assert_eq!(plain.grpc_status(), Some(0), "{kind}");
    assert_eq!(plain.messages, vec![Bytes::from_static(b"pong")]);
    assert_eq!(
        plain
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-trailer")),
        Some(&"kept".parse().unwrap()),
        "{kind}: a merged sibling rule without the filter keeps its application trailers"
    );

    assert_eq!(backend.received_stream_count(), 2);
    assert_eq!(backend.matcher_mismatches(), 0);
}

fn x_set_response_header_filter() -> serde_json::Value {
    json!([{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
        "set": [{"name": "x-set", "value": "route"}]
    }}])
}

/// Two GRPCRoutes — possibly owned by different teams — on one listener with no
/// hostnames: a header-only match and a match-less rule both materialize on
/// `/`, so they merge onto one proxy. Only the header-gated rule declares a
/// `ResponseHeaderModifier`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merged_grpc_route_sibling_without_response_header_modifier_keeps_trailers() {
    let filtered = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "team-a",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{
                "matches": [{"headers": [{"name": "x-variant", "value": "filtered"}]}],
                "backendRefs": [{"name": "api", "port": 8080}],
                "filters": x_set_response_header_filter()
            }]
        }),
    );
    let plain = object(
        "gateway.networking.k8s.io/v1",
        "GRPCRoute",
        "team-b",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]
        }),
    );
    assert_merged_sibling_keeps_trailers(filtered, plain, "/echo.Echo/Ping").await;
}

/// The HTTPRoute shape of the same merge: two routes on one shared `PathPrefix`,
/// one of them header-gated with the filter. gRPC calls carry the traffic
/// because they are the HTTP flavor whose application trailers reach a client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merged_http_route_sibling_without_response_header_modifier_keeps_trailers() {
    let filtered = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "team-a",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{
                "matches": [{
                    "path": {"type": "PathPrefix", "value": "/echo.Echo"},
                    "headers": [{"name": "x-variant", "value": "filtered"}]
                }],
                "backendRefs": [{"name": "api", "port": 8080}],
                "filters": x_set_response_header_filter()
            }]
        }),
    );
    let plain = object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "team-b",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/echo.Echo"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );
    assert_merged_sibling_keeps_trailers(filtered, plain, "/echo.Echo/Ping").await;
}

/// A `Service` + `EndpointSlice` pair naming one locally spawned backend, so a
/// single HTTPRoute can reach backends with different scripted behavior.
fn scripted_service_objects(
    name: &str,
    cluster_ip: &str,
    backend_port: u16,
) -> Vec<ferrum_edge::config_sources::k8s::K8sObject> {
    let service = object(
        "v1",
        "Service",
        name,
        "default",
        json!({
            "clusterIP": cluster_ip,
            "ports": [{"name": "http", "port": 8080, "targetPort": backend_port}]
        }),
    );
    let mut endpoints = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        &format!("{name}-manual"),
        "default",
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": backend_port}],
            "endpoints": [{"addresses": ["127.0.0.1"], "conditions": {"ready": true}}]
        }),
    );
    endpoints
        .metadata
        .labels
        .insert("kubernetes.io/service-name".to_string(), name.to_string());
    vec![service, endpoints]
}

/// A backend that holds every request for `delay` before answering `200 pong`.
async fn spawn_delayed_backend(
    delay: std::time::Duration,
) -> (u16, crate::scaffolding::backends::ScriptedHttp1Backend) {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::ports::reserve_port;

    let reservation = reserve_port().await.expect("reserve delayed backend");
    let port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::Sleep(delay))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn delayed backend");
    (port, backend)
}

/// A backend that answers response headers at once and then trickles a
/// close-delimited body (no `Content-Length`, so the gateway streams it rather
/// than eagerly buffering it) one byte every 100 ms for about four seconds.
async fn spawn_trickling_backend() -> (u16, crate::scaffolding::backends::ScriptedHttp1Backend) {
    use crate::scaffolding::backends::{HttpStep, ScriptedHttp1Backend};
    use crate::scaffolding::ports::reserve_port;

    let reservation = reserve_port().await.expect("reserve trickling backend");
    let port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::TrickleBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: vec![b'x'; 40],
            chunk_size: 1,
            pause: std::time::Duration::from_millis(100),
        })
        .spawn()
        .expect("spawn trickling backend");
    (port, backend)
}

fn timeouts_route(rules: Value) -> ferrum_edge::config_sources::k8s::K8sObject {
    object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "timeouts",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "hostnames": ["timeouts.test"],
            "rules": rules
        }),
    )
}

/// Rule-level `timeouts` must reach the data plane and apply to exactly the
/// rule that declared them:
///
/// * `timeouts.request` bounds the whole transaction. Before the response head
///   the client gets the gateway's `504`; once the head is committed a still
///   streaming body is cut at the deadline, never completed cleanly.
/// * `timeouts.backendRequest` bounds one backend attempt (the wait for its
///   response head) and answers the ordinary backend-timeout `504`, while the
///   rule's larger `request` budget still bounds the whole transaction —
///   including a body the per-attempt bound never sees.
/// * `0s` disables either bound, and a sibling rule without `timeouts` keeps
///   the proxy defaults.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_timeouts_reach_the_data_plane() {
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;
    use std::time::{Duration, Instant};

    let (slow_port, slow) = spawn_delayed_backend(Duration::from_millis(1500)).await;
    let (trickle_port, _trickle) = spawn_trickling_backend().await;

    let mut objects = route_filter_cluster_objects(slow_port);
    let trickle_objects = scripted_service_objects("trickle", "10.96.0.12", trickle_port);
    objects.extend(trickle_objects);
    let route = timeouts_route(json!([
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/request"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "500ms"}
        },
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/untimed"}}],
            "backendRefs": [{"name": "api", "port": 8080}]
        },
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/disabled"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "0s", "backendRequest": "0s"}
        },
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/attempt"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "5s", "backendRequest": "300ms"}
        },
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/stream"}}],
            "backendRefs": [{"name": "trickle", "port": 8080}],
            "timeouts": {"request": "800ms", "backendRequest": "800ms"}
        }
    ]));
    objects.push(route);

    // The policy stays on the emitted dispatch rules: no generated proxy
    // carries it, so a merged or sibling rule cannot inherit it.
    let (translation, skipped) = translate_k8s_objects_collecting_skips(
        &objects,
        options().with_pod_discovery_enabled(true),
    )
    .expect("translate timeouts route");
    assert!(skipped.is_empty(), "{skipped:?}");
    for proxy in &translation.config.proxies {
        assert_eq!(
            proxy.backend_read_timeout_ms, 30_000,
            "{}: rule timeouts must not be promoted onto the proxy",
            proxy.id
        );
    }

    let harness = spawn_translated_route_gateway(&objects, Vec::new()).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let get = |path: &'static str| {
        client
            .get(harness.proxy_url(path))
            .header("host", "timeouts.test")
            .send()
    };

    // (a) The total deadline expires before the response head: gateway 504.
    let started = Instant::now();
    let response = get("/request/thing").await.expect("response");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        response
            .headers()
            .get("x-gateway-error")
            .and_then(|value| value.to_str().ok()),
        Some("backend_timeout")
    );
    let body = response.text().await.unwrap();
    assert_eq!(body, r#"{"error":"Request timeout"}"#);
    // The body already proves the deadline answered rather than the 1.5s
    // backend; the deadline is anchored at receipt, so it cannot fire early.
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed < Duration::from_secs(5),
        "the 500ms request deadline must answer at the deadline: {elapsed:?}"
    );

    // (d) The sibling rule declares no timeouts and waits out the backend.
    let response = get("/untimed/thing").await.expect("sibling response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "pong");

    // `0s` disables both bounds, as the CRD specifies.
    let response = get("/disabled/thing").await.expect("disabled response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "pong");

    // (c) `backendRequest` bounds the single attempt well inside the larger
    // request budget, and answers the backend-timeout 504 rather than the
    // request-deadline one.
    let started = Instant::now();
    let response = get("/attempt/thing").await.expect("response");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    let body = response.text().await.unwrap();
    // The backend-timeout body proves the per-attempt bound fired, not the
    // 5s request budget or the backend's own 1.5s answer.
    assert_eq!(body, r#"{"error":"Backend timeout"}"#);
    assert!(
        elapsed < Duration::from_secs(5),
        "the 300ms backendRequest bound must end the attempt: {elapsed:?}"
    );

    // (b) The head arrives at once and the per-attempt bound never trips on the
    // 100ms trickle, but the 800ms request deadline still ends the body with
    // an error instead of a clean end of message.
    let started = Instant::now();
    let response = get("/stream/thing").await.expect("response head");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.bytes().await;
    let elapsed = started.elapsed();
    assert!(
        body.is_err(),
        "a body cut by the request deadline must not complete cleanly: {body:?}"
    );
    assert!(
        elapsed < Duration::from_millis(3_500),
        "the 800ms request deadline must cut the ~4s trickle: {elapsed:?}"
    );

    // Every rule that reached the delayed backend dialed it exactly once.
    let paths: Vec<String> = slow
        .received_requests()
        .await
        .iter()
        .map(|request| request.path.clone())
        .collect();
    for path in [
        "/request/thing",
        "/untimed/thing",
        "/disabled/thing",
        "/attempt/thing",
    ] {
        let dialed = paths.iter().filter(|seen| seen.as_str() == path).count();
        assert_eq!(dialed, 1, "{path}: {paths:?}");
    }
}

/// A global `http_logging` instance that ships every transaction summary to a
/// local collector, one summary per batch, so a test can assert what the
/// gateway recorded rather than only what the client saw.
fn transaction_log_capture(endpoint_url: String) -> ferrum_edge::config::types::PluginConfig {
    use ferrum_edge::config::types::{PluginConfig, PluginScope};
    let now = chrono::Utc::now();
    PluginConfig {
        labels: Default::default(),
        id: "timeouts-transaction-log".to_string(),
        plugin_name: "http_logging".to_string(),
        namespace: "default".to_string(),
        config: json!({
            "endpoint_url": endpoint_url,
            "batch_size": 1,
            "flush_interval_ms": 100
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// The first transaction summary the collector received for `path`.
async fn wait_for_transaction_summary(collector: &wiremock::MockServer, path: &str) -> Value {
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let requests = collector.received_requests().await.unwrap_or_default();
        let summary = requests
            .iter()
            .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
            .filter_map(|batch| batch.as_array().cloned())
            .flatten()
            .find(|summary| summary["request_path"] == path);
        if let Some(summary) = summary {
            return summary;
        }
        assert!(
            std::time::Instant::now() < give_up,
            "no transaction summary for {path} reached the collector"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The request deadline is ONE absolute budget across every backend attempt
/// and the retry backoff between them. Gateway API `retry` is still refused, so
/// the retry policy here is operator configuration on the generated proxy; the
/// deadline itself comes from the translated rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_request_timeout_spans_retry_attempts_and_backoff() {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::ports::reserve_port;
    use ferrum_edge::config::types::{BackoffStrategy, RetryConfig};
    use std::time::{Duration, Instant};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 503,
            reason: "Service Unavailable".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "0".into(),
        })
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&collector)
        .await;

    let mut objects = route_filter_cluster_objects(backend_port);
    let route = timeouts_route(json!([
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/deadline"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "1900ms"}
        },
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/retries"}}],
            "backendRefs": [{"name": "api", "port": 8080}]
        }
    ]));
    objects.push(route);
    let log_capture = transaction_log_capture(format!("{}/logs", collector.uri()));
    let harness = spawn_translated_route_gateway_with(&objects, vec![log_capture], |config| {
        for proxy in &mut config.proxies {
            proxy.retry = Some(RetryConfig {
                max_retries: 2,
                retryable_status_codes: vec![503],
                retryable_methods: vec!["GET".to_string()],
                backoff: BackoffStrategy::Fixed { delay_ms: 1_000 },
                retry_on_connect_failure: false,
            });
        }
    })
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    // Each attempt answers at once, so attempts start at ~0ms and ~1000ms and
    // the next backoff would end at ~2000ms, past the 1900ms budget: the
    // budget expires INSIDE that backoff. The ~900ms between the second
    // attempt and the deadline keeps that phase deterministic on a slow
    // runner, and the deadline is anchored at receipt, so the response can
    // never arrive before it.
    let started = Instant::now();
    let response = client
        .get(harness.proxy_url("/deadline/thing"))
        .header("host", "timeouts.test")
        .send()
        .await
        .expect("deadline response");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    let body = response.text().await.unwrap();
    assert_eq!(body, r#"{"error":"Request timeout"}"#);
    assert!(
        elapsed >= Duration::from_millis(1_800) && elapsed < Duration::from_secs(4),
        "the deadline must end the retry loop at ~1900ms: {elapsed:?}"
    );

    // Without a route deadline the same retry policy runs to exhaustion: the
    // initial attempt plus two retries, ending with the backend's 503.
    let response = client
        .get(harness.proxy_url("/retries/thing"))
        .header("host", "timeouts.test")
        .send()
        .await
        .expect("retry-exhaustion response");
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    let observed = backend.received_requests().await;
    let attempts = |path: &str| {
        observed
            .iter()
            .filter(|request| request.path == path)
            .count()
    };
    assert_eq!(
        attempts("/deadline/thing"),
        2,
        "the deadline must stop the retry planner before a third attempt"
    );
    assert_eq!(attempts("/retries/thing"), 3);

    // The transaction log names the phase that expired, and the terminal is
    // health-neutral: the budget ran out in the gateway's own backoff, and the
    // attempts that led into it were already recorded on their own.
    let summary = wait_for_transaction_summary(&collector, "/deadline/thing").await;
    assert_eq!(summary["response_status_code"], 504, "{summary}");
    assert_eq!(
        summary["metadata"]["route_request_timeout"], "retry_backoff",
        "{summary}"
    );
    assert_eq!(
        summary["error_class"], "dispatch_policy_rejected",
        "{summary}"
    );
}

/// A breaker that opens on the first recorded failure, so one attribution
/// decision is directly observable as the next request's status.
fn trip_on_first_failure(config: &mut ferrum_edge::config::types::GatewayConfig) {
    use ferrum_edge::config::types::CircuitBreakerConfig;
    for proxy in &mut config.proxies {
        proxy.circuit_breaker = Some(CircuitBreakerConfig {
            failure_threshold: 1,
            timeout_seconds: 60,
            ..CircuitBreakerConfig::default()
        });
    }
}

/// The route deadline is charged to a backend only when that backend held the
/// request. A client that stalls its upload while the gateway is still
/// collecting it (retries force the request body to be buffered before any
/// dial) is cut by the deadline, but the backend was never asked: the breaker
/// records nothing, so the next request is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_request_timeout_does_not_charge_a_stalled_upload_to_the_backend() {
    use ferrum_edge::config::types::{BackoffStrategy, RetryConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (backend_port, backend) = spawn_delayed_backend(Duration::ZERO).await;
    let mut objects = route_filter_cluster_objects(backend_port);
    let route = timeouts_route(json!([
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/upload"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "700ms"}
        }
    ]));
    objects.push(route);
    let harness = spawn_translated_route_gateway_with(&objects, Vec::new(), |config| {
        trip_on_first_failure(config);
        for proxy in &mut config.proxies {
            proxy.retry = Some(RetryConfig {
                max_retries: 1,
                retryable_status_codes: vec![503],
                retryable_methods: vec!["GET".to_string(), "POST".to_string()],
                backoff: BackoffStrategy::Fixed { delay_ms: 10 },
                retry_on_connect_failure: false,
            });
        }
    })
    .await;

    // Declare 64 body bytes, send 7, and stall.
    let address = harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();
    let mut upload = tokio::net::TcpStream::connect(&address)
        .await
        .expect("connect to the gateway");
    let partial_upload = [
        "POST /upload/thing HTTP/1.1\r\n",
        "Host: timeouts.test\r\n",
        "Content-Length: 64\r\n\r\n",
        "partial",
    ]
    .concat();
    upload
        .write_all(partial_upload.as_bytes())
        .await
        .expect("write the partial upload");
    let mut head = Vec::new();
    let read_head = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = upload.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            head.extend_from_slice(&buf[..read]);
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    assert!(
        matches!(read_head, Ok(Ok(()))),
        "read the gateway's answer: {read_head:?}"
    );
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 504"),
        "the deadline must end the stalled upload with the gateway 504: {head}"
    );

    // A failure charged to the backend would have opened its breaker.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let response = client
        .get(harness.proxy_url("/upload/thing"))
        .header("host", "timeouts.test")
        .send()
        .await
        .expect("follow-up response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "pong");

    let methods: Vec<String> = backend
        .received_requests()
        .await
        .iter()
        .map(|request| request.method.clone())
        .collect();
    assert_eq!(
        methods,
        vec!["GET".to_string()],
        "the stalled upload must never reach the backend"
    );
}

/// The other side of the same rule: a backend that holds the request and
/// withholds its response head past the deadline IS charged, so its breaker
/// opens and the next request is refused without a dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_request_timeout_charges_a_backend_that_stalls_response_headers() {
    use std::time::Duration;

    let (backend_port, backend) = spawn_delayed_backend(Duration::from_millis(1_500)).await;
    let mut objects = route_filter_cluster_objects(backend_port);
    let route = timeouts_route(json!([
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/slow"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "500ms"}
        }
    ]));
    objects.push(route);
    let harness =
        spawn_translated_route_gateway_with(&objects, Vec::new(), trip_on_first_failure).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let get = || {
        client
            .get(harness.proxy_url("/slow/thing"))
            .header("host", "timeouts.test")
            .send()
    };

    let response = get().await.expect("deadline response");
    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

    let response = get().await.expect("breaker response");
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-gateway-error")
            .and_then(|value| value.to_str().ok()),
        Some("circuit_breaker_open")
    );
    assert_eq!(
        backend.received_requests().await.len(),
        1,
        "the open breaker must refuse the second request before any dial"
    );
}

/// A body the route deadline cuts after the backend already answered is the
/// route's own policy, not a backend fault: the breaker records nothing, and
/// the next request is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_request_timeout_body_cut_is_not_charged_to_the_backend() {
    use std::time::Duration;

    let (trickle_port, _trickle) = spawn_trickling_backend().await;
    let mut objects = route_filter_cluster_objects(trickle_port);
    let route = timeouts_route(json!([
        {
            "matches": [{"path": {"type": "PathPrefix", "value": "/stream"}}],
            "backendRefs": [{"name": "api", "port": 8080}],
            "timeouts": {"request": "800ms"}
        }
    ]));
    objects.push(route);
    let harness =
        spawn_translated_route_gateway_with(&objects, Vec::new(), trip_on_first_failure).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let get = || {
        client
            .get(harness.proxy_url("/stream/thing"))
            .header("host", "timeouts.test")
            .send()
    };

    let response = get().await.expect("response head");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.bytes().await.is_err(),
        "the deadline must cut the ~4s trickle"
    );

    // The cut was recorded before the client saw it end; a charged failure
    // would have opened the breaker for this request.
    let response = get().await.expect("follow-up response head");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// A gRPC call routed by an HTTPRoute folds the rule's request deadline into
/// its RPC deadline: the client gets `DEADLINE_EXCEEDED`, not an HTTP 504 it
/// cannot parse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_route_request_timeout_ends_grpc_calls_with_deadline_exceeded() {
    use crate::scaffolding::backends::grpc::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
    use crate::scaffolding::clients::grpc::GrpcClient;
    use crate::scaffolding::ports::reserve_port;
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .steps(vec![
            GrpcStep::AcceptRpc(MatchRpc::any()),
            GrpcStep::Sleep(Duration::from_secs(3)),
            GrpcStep::SendInitialHeaders,
            GrpcStep::RespondMessage(Bytes::from_static(b"pong")),
            GrpcStep::RespondStatus {
                code: 0,
                message: "",
            },
        ])
        .spawn()
        .expect("spawn grpc backend");

    let mut objects = route_filter_cluster_objects(backend_port);
    objects.push(object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        "grpc-timeouts",
        "default",
        json!({
            "parentRefs": [{"name": "edge", "sectionName": "web"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/echo.Echo"}}],
                "backendRefs": [{"name": "api", "port": 8080}],
                "timeouts": {"request": "500ms"}
            }]
        }),
    ));
    let harness = spawn_translated_route_gateway(&objects, Vec::new()).await;
    let target = harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();
    let client = GrpcClient::h2c(target);

    let started = Instant::now();
    let response = client
        .unary("/echo.Echo/Ping", Bytes::from_static(b"ping"))
        .await
        .expect("grpc call");
    let elapsed = started.elapsed();
    assert_eq!(response.http_status, 200);
    assert_eq!(response.grpc_status(), Some(4), "DEADLINE_EXCEEDED");
    assert!(
        elapsed < Duration::from_millis(2_900),
        "the 500ms route deadline must end the call before the 3s backend: {elapsed:?}"
    );
}

/// Removing a rule's `timeouts` withdraws the policy: the regenerated dispatch
/// rule carries no deadline, and the same request that timed out is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_rule_timeouts_withdraws_the_deadline() {
    use ferrum_edge::config_sources::k8s::translate_k8s_objects_collecting_skips;
    use std::time::Duration;

    let (slow_port, _slow) = spawn_delayed_backend(Duration::from_millis(800)).await;
    let rule = |timeouts: Option<Value>| {
        let mut rule = json!({
            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
            "backendRefs": [{"name": "api", "port": 8080}]
        });
        if let Some(timeouts) = timeouts {
            rule["timeouts"] = timeouts;
        }
        rule
    };
    let emitted_dispatch_rules = |objects: &[ferrum_edge::config_sources::k8s::K8sObject]| {
        let (translation, skipped) = translate_k8s_objects_collecting_skips(
            objects,
            options().with_pod_discovery_enabled(true),
        )
        .expect("translate");
        assert!(skipped.is_empty(), "{skipped:?}");
        translation
            .config
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .flat_map(|plugin| plugin.config["rules"].as_array().cloned())
            .flatten()
            .collect::<Vec<Value>>()
    };

    let timed_timeouts = json!({"request": "300ms", "backendRequest": "250ms"});
    let timed_rule = rule(Some(timed_timeouts));
    let mut timed = route_filter_cluster_objects(slow_port);
    timed.push(timeouts_route(json!([timed_rule])));
    let rules = emitted_dispatch_rules(timed.as_slice());
    let projected = rules
        .iter()
        .any(|rule| rule["request_timeout_ms"] == json!(300) && rule["timeout_ms"] == json!(250));
    assert!(projected, "{rules:?}");

    let mut untimed = route_filter_cluster_objects(slow_port);
    untimed.push(timeouts_route(json!([rule(None)])));
    let rules = emitted_dispatch_rules(untimed.as_slice());
    let withdrawn = rules.iter().all(|rule| {
        ["request_timeout_ms", "timeout_ms", "timeout_disabled"]
            .iter()
            .all(|field| rule.get(field).is_none())
    });
    assert!(withdrawn, "{rules:?}");

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    for (objects, expected) in [
        (timed.as_slice(), reqwest::StatusCode::GATEWAY_TIMEOUT),
        (untimed.as_slice(), reqwest::StatusCode::OK),
    ] {
        let harness = spawn_translated_route_gateway(objects, Vec::new()).await;
        let response = client
            .get(harness.proxy_url("/api/thing"))
            .header("host", "timeouts.test")
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), expected);
    }
}
