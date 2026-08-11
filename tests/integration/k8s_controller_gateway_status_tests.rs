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
    let expected_message = "Port 8443 is claimed by both plaintext and an effective TLS-serving \
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
            "Port 8080 is claimed by incompatible protocol families on the same TCP \
             transport (HTTP-family vs raw stream), so every conflicting claim on this \
             port is refused (Conflicted)."
        );
    }
    assert!(
        translation.warnings.iter().any(|warning| {
            warning.contains("Gateway default/edge listener http rejected: ProtocolConflict")
        }) && translation.warnings.iter().any(|warning| {
            warning.contains("Gateway default/edge listener tcp rejected: ProtocolConflict")
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

    let expected_message = "Port 8443 has incompatible effective TLS credential sets across \
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
