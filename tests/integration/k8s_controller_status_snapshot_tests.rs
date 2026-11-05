//! Integration coverage for the shared Gateway API + Istio status-writer
//! object snapshot (#3281): one immutable generation, independent plans,
//! failure isolation, reload/delete, and status output parity. Also pins that
//! the reconciler's dispatch runs the two writers' batches concurrently.

use ferrum_edge::_test_support::{run_status_patchers_for_test, shared_status_objects_snapshot};
use ferrum_edge::config_sources::k8s::{K8sMetadata, K8sObject, K8sTranslationOptions};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::istio_status::{IstioStatusWriter, plan_istio_status_updates};
use ferrum_edge::k8s_controller::metrics::ControllerMetrics;
use ferrum_edge::k8s_controller::status::{
    GatewayApiStatusWriter, plan_gateway_api_status_updates,
};
use http::{Method, Request, Response, StatusCode};
use kube::Client;
use kube::client::Body;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::service_fn;

#[derive(Default)]
struct MockKubeState {
    gets: Vec<String>,
    patches: Vec<String>,
    /// Kind of every request (GET or PATCH) in the order the mock handled it.
    requests: Vec<String>,
    fail_kinds: Vec<String>,
}

/// How long one mock API request waits for the other writer's batch to reach
/// the API server. Comfortably below the 5 s per-request status budget, so a
/// sequential dispatch still completes (and fails the overlap assertion)
/// instead of timing out.
const PEER_WAIT: Duration = Duration::from_secs(2);

/// Rendezvous between the two writers' mock API servers. Every request marks
/// its own writer as in flight, then waits (bounded by [`PEER_WAIT`]) for the
/// peer writer to send a request too. `overlapped` records that the peer was
/// seen while this writer's request was still open.
struct WriterGate {
    arrived: CancellationToken,
    peer: CancellationToken,
    overlapped: AtomicBool,
}

fn writer_gates() -> (Arc<WriterGate>, Arc<WriterGate>) {
    let gateway_arrived = CancellationToken::new();
    let istio_arrived = CancellationToken::new();
    let gateway = Arc::new(WriterGate {
        arrived: gateway_arrived.clone(),
        peer: istio_arrived.clone(),
        overlapped: AtomicBool::new(false),
    });
    let istio = Arc::new(WriterGate {
        arrived: istio_arrived,
        peer: gateway_arrived,
        overlapped: AtomicBool::new(false),
    });
    (gateway, istio)
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
    mock_kube_client_with_gates(state, None)
}

/// Mock API server dispatched by path. Live reads and patch responses echo the
/// object's name and its `uid-{name}` UID (the fixtures' UID scheme), so both
/// writers' identity guards pass and their PATCHes land. With `gates`
/// (Gateway API gate, Istio gate), every request first meets its writer's
/// rendezvous, so one client can serve both writers as in production.
fn mock_kube_client_with_gates(
    state: Arc<Mutex<MockKubeState>>,
    gates: Option<(Arc<WriterGate>, Arc<WriterGate>)>,
) -> Client {
    let service = service_fn(move |request: Request<Body>| {
        let state = state.clone();
        let gates = gates.clone();
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
            let name = path
                .trim_end_matches("/status")
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let uid = format!("uid-{name}");

            let gate = gates.and_then(|(gateway, istio)| match kind {
                "GatewayClass" | "HTTPRoute" => Some(gateway),
                "VirtualService" | "DestinationRule" => Some(istio),
                _ => None,
            });
            if let Some(gate) = gate {
                gate.arrived.cancel();
                if tokio::time::timeout(PEER_WAIT, gate.peer.cancelled())
                    .await
                    .is_ok()
                {
                    gate.overlapped.store(true, Ordering::SeqCst);
                }
            }

            let _body = request
                .into_body()
                .collect_bytes()
                .await
                .expect("read mock Kubernetes request body");

            let mut state = state.lock().expect("lock mock Kubernetes state");
            let response = match method {
                Method::GET => {
                    state.gets.push(kind.to_string());
                    state.requests.push(kind.to_string());
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
                                    "name": name,
                                    "namespace": "default",
                                    "uid": uid,
                                    "resourceVersion": "1"
                                },
                                "status": {}
                            }),
                        )
                    }
                }
                Method::PATCH => {
                    state.patches.push(kind.to_string());
                    state.requests.push(kind.to_string());
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
                                    "name": name,
                                    "namespace": "default",
                                    "uid": uid,
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

#[tokio::test]
async fn reconcile_dispatch_runs_gateway_and_istio_batches_concurrently() {
    // EDGE-CP-3: the reconcile loop must be held for the slower batch, not the
    // sum. As in production, both writers share one kube client and one
    // metrics Arc. Each mock API request waits for the other writer's batch
    // to reach the API server; a sequential dispatch would let the Gateway API
    // batch finish before the Istio batch issues anything.
    let (gateway_gate, istio_gate) = writer_gates();
    let state = Arc::new(Mutex::new(MockKubeState::default()));
    let client = mock_kube_client_with_gates(
        state.clone(),
        Some((gateway_gate.clone(), istio_gate.clone())),
    );
    let metrics = Arc::new(ControllerMetrics::new());
    let gateway_writer = GatewayApiStatusWriter::new(client.clone()).with_metrics(metrics.clone());
    let istio_writer = IstioStatusWriter::new(client).with_metrics(metrics.clone());

    run_status_patchers_for_test(
        Some(gateway_writer),
        Some(istio_writer),
        mixed_generation(),
        options(),
        &metrics,
    )
    .await;

    assert!(
        gateway_gate.overlapped.load(Ordering::SeqCst),
        "the Istio batch must reach the API server while the Gateway API batch is in flight"
    );
    assert!(
        istio_gate.overlapped.load(Ordering::SeqCst),
        "the Istio batch's requests must observe the Gateway API batch's requests"
    );
    let state = state.lock().expect("lock mock Kubernetes state");
    assert!(
        state
            .patches
            .iter()
            .any(|kind| kind == "GatewayClass" || kind == "HTTPRoute"),
        "Gateway API status patches must land: {:?}",
        state.patches
    );
    assert!(
        state
            .patches
            .iter()
            .any(|kind| kind == "VirtualService" || kind == "DestinationRule"),
        "Istio status patches must land: {:?}",
        state.patches
    );
    assert_eq!(
        metrics.status_batch_timeouts.load(Ordering::Relaxed),
        0,
        "neither batch may hit the reconciler backstop"
    );
    assert_eq!(
        metrics.status_request_timeouts.load(Ordering::Relaxed),
        0,
        "no status request may exhaust its budget"
    );
    assert_eq!(
        metrics
            .gateway_api_status_window_failed_batches
            .load(Ordering::Relaxed),
        0,
        "the Gateway API batch must succeed"
    );
}

#[tokio::test]
async fn reconcile_dispatch_keeps_writer_failures_isolated_when_concurrent() {
    // A failing Gateway API batch must not stop the concurrently running Istio
    // batch on the shared client, and it must still record exactly one failed
    // batch on the status-plan cursor (cursor retry semantics are unchanged,
    // #6370).
    let (gateway_gate, istio_gate) = writer_gates();
    let state = Arc::new(Mutex::new(MockKubeState {
        fail_kinds: vec!["GatewayClass".to_string(), "HTTPRoute".to_string()],
        ..MockKubeState::default()
    }));
    let client = mock_kube_client_with_gates(
        state.clone(),
        Some((gateway_gate.clone(), istio_gate.clone())),
    );
    let metrics = Arc::new(ControllerMetrics::new());
    let gateway_writer = GatewayApiStatusWriter::new(client.clone()).with_metrics(metrics.clone());
    let istio_writer = IstioStatusWriter::new(client).with_metrics(metrics.clone());

    run_status_patchers_for_test(
        Some(gateway_writer),
        Some(istio_writer),
        mixed_generation(),
        options(),
        &metrics,
    )
    .await;

    assert!(
        gateway_gate.overlapped.load(Ordering::SeqCst),
        "the failing Gateway API batch must overlap the Istio batch"
    );
    assert_eq!(
        metrics
            .gateway_api_status_window_failed_batches
            .load(Ordering::Relaxed),
        1,
        "the failed Gateway API batch keeps its cursor-retry accounting"
    );
    let state = state.lock().expect("lock mock Kubernetes state");
    assert!(
        state
            .gets
            .iter()
            .any(|kind| kind == "GatewayClass" || kind == "HTTPRoute"),
        "the Gateway API batch must have run: {:?}",
        state.gets
    );
    assert!(
        state
            .patches
            .iter()
            .any(|kind| kind == "VirtualService" || kind == "DestinationRule"),
        "Istio status patches must land despite the Gateway API failure: {:?}",
        state.patches
    );
}

#[tokio::test]
async fn reconcile_dispatch_runs_large_istio_batch_after_gateway_batch() {
    // An Istio plan larger than STATUS_PATCH_PARALLELISM (32) starts every
    // update at once, so it must not overlap the Gateway API batch on the
    // shared client: dispatch stays sequential, Gateway API first.
    let mut objects = mixed_generation();
    objects.extend((0..40).map(|index| {
        object(
            "networking.istio.io/v1beta1",
            "VirtualService",
            &format!("vs-{index}"),
            json!({
                "hosts": [format!("host-{index}.example.com")],
                "http": [{"route": [{"destination": {"host": "svc.default.svc.cluster.local"}}]}]
            }),
        )
    }));
    let istio_plan = plan_istio_status_updates(&objects, options()).len();
    assert!(
        istio_plan > 32,
        "fixture must plan more Istio updates than the overlap threshold, got {istio_plan}"
    );

    let state = Arc::new(Mutex::new(MockKubeState::default()));
    let client = mock_kube_client(state.clone());
    let metrics = Arc::new(ControllerMetrics::new());
    let gateway_writer = GatewayApiStatusWriter::new(client.clone()).with_metrics(metrics.clone());
    let istio_writer = IstioStatusWriter::new(client).with_metrics(metrics.clone());

    run_status_patchers_for_test(
        Some(gateway_writer),
        Some(istio_writer),
        objects,
        options(),
        &metrics,
    )
    .await;

    let state = state.lock().expect("lock mock Kubernetes state");
    let is_gateway = |kind: &String| kind == "GatewayClass" || kind == "HTTPRoute";
    let last_gateway = state
        .requests
        .iter()
        .rposition(is_gateway)
        .expect("the Gateway API batch must reach the API server");
    let first_istio = state
        .requests
        .iter()
        .position(|kind| !is_gateway(kind))
        .expect("the Istio batch must reach the API server");
    assert!(
        last_gateway < first_istio,
        "the Gateway API batch must finish before any Istio request starts: {:?}",
        state.requests
    );
    assert!(
        state.patches.iter().any(is_gateway),
        "Gateway API status patches must land: {:?}",
        state.patches
    );
    assert_eq!(
        state
            .patches
            .iter()
            .filter(|kind| *kind == "VirtualService" || *kind == "DestinationRule")
            .count(),
        istio_plan,
        "every planned Istio status patch must land"
    );
}
