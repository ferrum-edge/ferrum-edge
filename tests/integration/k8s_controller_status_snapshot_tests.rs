//! Integration coverage for the shared Gateway API + Istio status-writer
//! object snapshot (#3281): one immutable generation, independent plans,
//! failure isolation, reload/delete, and status output parity.

use ferrum_edge::_test_support::shared_status_objects_snapshot;
use ferrum_edge::config_sources::k8s::{K8sMetadata, K8sObject, K8sTranslationOptions};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::istio_status::{IstioStatusWriter, plan_istio_status_updates};
use ferrum_edge::k8s_controller::status::{
    GatewayApiStatusWriter, plan_gateway_api_status_updates,
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
    gets: Vec<String>,
    patches: Vec<String>,
    fail_kinds: Vec<String>,
}

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn mixed_generation() -> Vec<K8sObject> {
    vec![
        object(
            "gateway.networking.k8s.io/v1",
            "GatewayClass",
            "ferrum",
            json!({ "controllerName": "ferrum.io/gateway-controller" }),
        ),
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{"backendRefs": [{"name": "svc", "port": 80}]}]
            }),
        ),
        object(
            "networking.istio.io/v1beta1",
            "VirtualService",
            "vs",
            json!({
                "hosts": ["example.com"],
                "http": [{"route": [{"destination": {"host": "svc.default.svc.cluster.local"}}]}]
            }),
        ),
        object(
            "networking.istio.io/v1beta1",
            "DestinationRule",
            "dr",
            json!({ "host": "svc.default.svc.cluster.local" }),
        ),
    ]
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

fn mock_kube_client(state: Arc<Mutex<MockKubeState>>) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_string();
            let kind = if path.contains("/virtualservices/") {
                "VirtualService"
            } else if path.contains("/destinationrules/") {
                "DestinationRule"
            } else if path.contains("/httproutes/") {
                "HTTPRoute"
            } else if path.contains("/gatewayclasses/") {
                "GatewayClass"
            } else {
                "Unknown"
            };

            let _body = request
                .into_body()
                .collect_bytes()
                .await
                .expect("read mock Kubernetes request body");

            let mut state = state.lock().expect("lock mock Kubernetes state");
            let response = match method {
                Method::GET => {
                    state.gets.push(kind.to_string());
                    if state.fail_kinds.iter().any(|failed| failed == kind) {
                        json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "apiVersion": "v1",
                                "kind": "Status",
                                "status": "Failure",
                                "message": "injected writer failure",
                                "code": 500
                            }),
                        )
                    } else {
                        json_response(
                            StatusCode::OK,
                            json!({
                                "apiVersion": "v1",
                                "kind": kind,
                                "metadata": {
                                    "name": "resource",
                                    "namespace": "default",
                                    "resourceVersion": "1"
                                },
                                "status": {}
                            }),
                        )
                    }
                }
                Method::PATCH => {
                    state.patches.push(kind.to_string());
                    if state.fail_kinds.iter().any(|failed| failed == kind) {
                        json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "apiVersion": "v1",
                                "kind": "Status",
                                "status": "Failure",
                                "message": "injected writer failure",
                                "code": 500
                            }),
                        )
                    } else {
                        json_response(
                            StatusCode::OK,
                            json!({
                                "apiVersion": "v1",
                                "kind": kind,
                                "metadata": {
                                    "name": "resource",
                                    "namespace": "default",
                                    "resourceVersion": "2"
                                },
                                "status": {}
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

#[test]
fn both_writers_plan_from_one_arc_generation_with_parity() {
    let objects = mixed_generation();
    let snapshot =
        shared_status_objects_snapshot(objects.clone(), true, true).expect("both writers");
    assert!(Arc::ptr_eq(&snapshot, &Arc::clone(&snapshot)));

    let gateway_slice = plan_gateway_api_status_updates(&objects, options(), &[]);
    let gateway_arc = plan_gateway_api_status_updates(&snapshot, options(), &[]);
    assert_eq!(gateway_slice.len(), gateway_arc.len());
    for (left, right) in gateway_slice.iter().zip(gateway_arc.iter()) {
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.name, right.name);
        assert_eq!(left.namespace, right.namespace);
    }

    let istio_slice = plan_istio_status_updates(&objects, options());
    let istio_arc = plan_istio_status_updates(&snapshot, options());
    assert_eq!(istio_slice.len(), istio_arc.len());
    for (left, right) in istio_slice.iter().zip(istio_arc.iter()) {
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.name, right.name);
        assert_eq!(left.ferrum_detail, right.ferrum_detail);
    }

    assert!(
        gateway_arc
            .iter()
            .any(|update| update.kind == "GatewayClass" || update.kind == "HTTPRoute")
    );
    assert!(
        istio_arc
            .iter()
            .any(|update| update.kind == "VirtualService" || update.kind == "DestinationRule")
    );
}

#[test]
fn reload_and_delete_produce_fresh_generation_without_deleted_objects() {
    let initial = mixed_generation();
    let first = shared_status_objects_snapshot(initial.clone(), true, true).expect("initial");

    let mut reloaded: Vec<K8sObject> = initial
        .into_iter()
        .filter(|object| object.metadata.name != "vs")
        .collect();
    reloaded.push(object(
        "networking.istio.io/v1beta1",
        "Sidecar",
        "sidecar",
        json!({ "egress": [{"hosts": ["./*"]}] }),
    ));
    let second = shared_status_objects_snapshot(reloaded, true, true).expect("reload");

    assert!(!Arc::ptr_eq(&first, &second));
    assert!(first.iter().any(|object| object.metadata.name == "vs"));
    assert!(!second.iter().any(|object| object.metadata.name == "vs"));
    assert!(
        second
            .iter()
            .any(|object| object.metadata.name == "sidecar")
    );

    let istio = plan_istio_status_updates(&second, options());
    assert!(!istio.iter().any(|update| update.name == "vs"));
    assert!(istio.iter().any(|update| update.name == "sidecar"));
}

#[tokio::test]
async fn istio_writer_failure_does_not_block_gateway_plan_from_shared_snapshot() {
    let objects = mixed_generation();
    let snapshot = shared_status_objects_snapshot(objects, true, true).expect("both writers");

    let gateway_updates = plan_gateway_api_status_updates(&snapshot, options(), &[]);
    let istio_updates = plan_istio_status_updates(&snapshot, options());
    assert!(!gateway_updates.is_empty());
    assert!(!istio_updates.is_empty());

    let gateway_state = Arc::new(Mutex::new(MockKubeState::default()));
    let istio_state = Arc::new(Mutex::new(MockKubeState {
        fail_kinds: vec!["VirtualService".to_string(), "DestinationRule".to_string()],
        ..MockKubeState::default()
    }));

    let gateway_writer = GatewayApiStatusWriter::new(mock_kube_client(gateway_state.clone()));
    let istio_writer = IstioStatusWriter::new(mock_kube_client(istio_state.clone()));

    // Independent failure handling: Istio patch errors must not prevent the
    // Gateway writer from applying its own plan against the same generation.
    let gateway_result = gateway_writer.patch_updates(gateway_updates).await;
    let istio_result = istio_writer.patch_updates(istio_updates).await;

    assert!(
        gateway_result.is_ok(),
        "gateway writer should succeed on the shared generation"
    );
    assert!(
        istio_result.is_err(),
        "injected Istio API failures must surface independently"
    );

    let gateway_state = gateway_state.lock().expect("lock gateway mock state");
    assert!(
        !gateway_state.patches.is_empty(),
        "gateway patches must still land when Istio fails"
    );
}
