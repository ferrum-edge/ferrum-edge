//! Integration coverage for Gateway API status concurrency and typed route
//! materialization records.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
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
    // Distinct listen paths: Ferrum materializes Gateway API HTTP-family routes
    // as port-agnostic `(hosts, listen_path)` proxies, so two Routes surviving
    // on different listeners still occupy different route-table slots.
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
/// reaches a shared listener *and* a GRPCRoute-only listener, emitting a single
/// `(parentRef, hostname)` claim. It loses the cross-kind arbitration on the
/// shared listener and would otherwise be accepted on the GRPCRoute-only one.
///
/// Ferrum materializes HTTP-family Gateway API routes as port-agnostic
/// `(hosts, listen_path)` proxies, so a claim kept for the listener it won
/// cannot be restricted to that listener — it would still route on the shared
/// listener, exactly where Gateway API forbids HTTPRoute/GRPCRoute merging.
/// The claim is therefore withdrawn whole: the GRPCRoute contributes no proxy,
/// no upstream, no plugin, and no materialized parent anywhere, and is reported
/// `Accepted=False`/`Conflicted` — independent of object observation order.
#[test]
fn cross_kind_wildcard_claim_losing_one_listener_is_withdrawn_from_all_listeners() {
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
    // Its distinct listen path means the GRPCRoute would have had a route-table
    // slot of its own had the claim been kept — the withdrawal is the conflict
    // decision, not a `(hosts, listen_path)` collision.
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

        // The losing GRPCRoute materializes no traffic state on *either*
        // listener, including the one it would otherwise have won.
        let ports: Vec<u16> = translation
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        assert_eq!(
            ports,
            vec![8080],
            "the withdrawn GRPCRoute must not keep the grpc-only listener"
        );
        assert!(
            !translation
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.targets.iter().any(|target| target.port == 50051)),
            "the withdrawn GRPCRoute must not leave an upstream: {:?}",
            translation.config.upstreams
        );
        assert!(
            !translation
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
            "the withdrawn GRPCRoute must contribute no dispatch rules"
        );
        assert!(
            !translation
                .materialized_route_parents
                .iter()
                .any(|entry| entry.route.kind == "GRPCRoute"),
            "the withdrawn GRPCRoute must claim no materialized parent"
        );

        // ...and the withdrawal is reported, naming a real applicable winner.
        let conflict = translation
            .route_conflicts
            .iter()
            .find(|conflict| conflict.loser.kind == "GRPCRoute")
            .expect("the withdrawal must be reported as a conflict");
        assert_eq!(conflict.winner.kind, "HTTPRoute");
        assert_eq!(conflict.winner.name, "web");

        let updates =
            plan_gateway_api_status_updates(&objects, options(), &translation.route_conflicts);
        let grpc_update = updates
            .iter()
            .find(|update| update.kind == "GRPCRoute" && update.name == "grpc")
            .expect("the withdrawn GRPCRoute gets a status update");
        let accepted = accepted_condition(grpc_update);
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("Conflicted"));

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
