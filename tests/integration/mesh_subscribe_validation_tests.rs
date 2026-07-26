//! MeshSubscribe response-validation coverage (issue #2457).
//!
//! Two layers:
//!
//! 1. The centralized validator
//!    (`modes::mesh::config_consumer::update_validation`) both mesh config
//!    consumers share — wrong node, wrong namespace, envelope/slice version
//!    mismatch, missing/incompatible `ferrum_version`, pinned workload
//!    SPIFFE / waypoint scope, and the valid matching response.
//! 2. The live native `MeshSubscribe` stream against an in-process control
//!    plane that deliberately answers with responses that are NOT bound to the
//!    subscription: the data plane must never install them, must keep its
//!    last-good slice, and must fail over to a control plane that answers
//!    correctly.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::grpc::dp_client::GrpcJwtSecret;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::modes::mesh::config_consumer::native_client::{
    NativeMeshClientConfig, NativeMeshConfigConsumer, start_native_mesh_client_with_shutdown,
};
use ferrum_edge::modes::mesh::config_consumer::update_validation::MeshUpdateConsumer;
use ferrum_edge::modes::mesh::config_consumer::update_validation::MeshUpdateExpectation;
use ferrum_edge::modes::mesh::config_consumer::update_validation::MeshUpdateRejectReason;
use ferrum_edge::modes::mesh::config_consumer::update_validation::validate_mesh_config_update;
use ferrum_edge::modes::mesh::config_consumer::update_validation::validate_update_ferrum_version;
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::prometheus_helpers::render_mesh_observability_metrics;

const NODE_ID: &str = "dp-node-a";
const NAMESPACE: &str = "alpha";
const SPIFFE: &str = "spiffe://cluster.local/ns/alpha/sa/api";
const WAYPOINT: &str = "api-waypoint";
const JWT_SECRET: &str = "mesh-subscribe-validation-secret-0000";
const NATIVE: MeshUpdateConsumer = MeshUpdateConsumer::Native;

// ── Fixtures ───────────────────────────────────────────────────────────────

fn client_config(waypoint: Option<&str>, spiffe: Option<&str>) -> NativeMeshClientConfig {
    NativeMeshClientConfig {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        workload_spiffe_id: spiffe.map(str::to_string),
        waypoint_name: waypoint.map(str::to_string),
        labels: HashMap::new(),
        ambient_udp_source_scoping: false,
        primary_retry_secs: 0,
    }
}

fn expectation(waypoint: Option<&str>, spiffe: Option<&str>) -> MeshUpdateExpectation {
    let request = client_config(waypoint, spiffe).subscribe_request(ferrum_edge::FERRUM_VERSION);
    MeshUpdateExpectation::from_subscribe_request(&request)
}

/// A slice a faithful control plane would return for that subscription.
fn bound_slice() -> MeshSlice {
    MeshSlice {
        node_id: NODE_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        version: "v1".to_string(),
        ..MeshSlice::default()
    }
}

fn update_for(slice: &MeshSlice) -> MeshConfigUpdate {
    MeshConfigUpdate {
        version: slice.version.clone(),
        timestamp: 1,
        mesh_slice_json: serde_json::to_string(slice).expect("slice serializes"),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        heartbeat: false,
    }
}

fn heartbeat() -> MeshConfigUpdate {
    MeshConfigUpdate {
        version: "v1".to_string(),
        timestamp: 1,
        mesh_slice_json: String::new(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        heartbeat: true,
    }
}

/// Reason a response was refused. Panics when it was accepted.
fn reason_for(
    update: &MeshConfigUpdate,
    expected: &MeshUpdateExpectation,
) -> MeshUpdateRejectReason {
    let rejection = validate_mesh_config_update(update, expected, NATIVE)
        .expect_err("response must be rejected");
    rejection.reason()
}

// ── Centralized validator ──────────────────────────────────────────────────

#[test]
fn validator_accepts_a_faithfully_bound_response() {
    let expected = expectation(Some(WAYPOINT), Some(SPIFFE));
    let slice = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        waypoint_name: Some(WAYPOINT.to_string()),
        ..bound_slice()
    };
    let update = update_for(&slice);

    let accepted = validate_mesh_config_update(&update, &expected, NATIVE)
        .expect("a response echoing the subscription is accepted");

    assert_eq!(accepted.node_id, NODE_ID);
    assert_eq!(accepted.namespace, NAMESPACE);
}

#[test]
fn validator_rejects_wrong_node_and_namespace() {
    let expected = expectation(None, None);

    let wrong_node = MeshSlice {
        node_id: "dp-node-b".to_string(),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&wrong_node), &expected),
        MeshUpdateRejectReason::NodeIdMismatch
    );

    let wrong_namespace = MeshSlice {
        namespace: "beta".to_string(),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&wrong_namespace), &expected),
        MeshUpdateRejectReason::NamespaceMismatch
    );
}

#[test]
fn validator_requires_envelope_version_to_equal_slice_version() {
    let expected = expectation(None, None);
    let desynced = MeshConfigUpdate {
        version: "v-envelope".to_string(),
        ..update_for(&bound_slice())
    };

    assert_eq!(
        reason_for(&desynced, &expected),
        MeshUpdateRejectReason::EnvelopeVersionMismatch
    );
}

#[test]
fn validator_requires_present_and_compatible_ferrum_version() {
    let expected = expectation(None, None);

    let unversioned = MeshConfigUpdate {
        ferrum_version: String::new(),
        ..update_for(&bound_slice())
    };
    assert_eq!(
        reason_for(&unversioned, &expected),
        MeshUpdateRejectReason::MissingFerrumVersion
    );

    let incompatible = MeshConfigUpdate {
        ferrum_version: "999.999.0".to_string(),
        ..update_for(&bound_slice())
    };
    assert_eq!(
        reason_for(&incompatible, &expected),
        MeshUpdateRejectReason::IncompatibleFerrumVersion
    );

    // Heartbeats ride the same compatibility contract in both consumers.
    let remote = MeshUpdateConsumer::RemoteDiscovery;
    for consumer in [NATIVE, remote] {
        assert!(validate_update_ferrum_version("", consumer).is_err());
        assert!(validate_update_ferrum_version("999.999.0", consumer).is_err());
        let current = ferrum_edge::FERRUM_VERSION;
        assert!(validate_update_ferrum_version(current, consumer).is_ok());
    }
}

/// A pinned scope is validated in BOTH directions the protocol can express: a
/// different echoed value and an omitted one. Treating an omitted echo as a
/// pass would let any response bypass the scope gate by dropping the field.
#[test]
fn validator_rejects_unechoed_and_mismatched_pinned_scope() {
    let expected = expectation(Some(WAYPOINT), Some(SPIFFE));

    let omitted_workload = MeshSlice {
        waypoint_name: Some(WAYPOINT.to_string()),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&omitted_workload), &expected),
        MeshUpdateRejectReason::WorkloadScopeMismatch
    );

    let other_workload = MeshSlice {
        workload_spiffe_id: Some("spiffe://cluster.local/ns/alpha/sa/x".to_string()),
        waypoint_name: Some(WAYPOINT.to_string()),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&other_workload), &expected),
        MeshUpdateRejectReason::WorkloadScopeMismatch
    );

    let omitted_waypoint = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&omitted_waypoint), &expected),
        MeshUpdateRejectReason::WaypointScopeMismatch
    );

    let other_waypoint = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        waypoint_name: Some("other-waypoint".to_string()),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&other_waypoint), &expected),
        MeshUpdateRejectReason::WaypointScopeMismatch
    );
}

/// When the subscription pins no scope there is no unambiguous expectation to
/// compare an echo against, so the scope fields are not gated — the node and
/// namespace binding still is.
#[test]
fn validator_does_not_gate_scope_the_request_never_pinned() {
    let expected = expectation(None, None);
    let scoped = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        waypoint_name: Some(WAYPOINT.to_string()),
        ..bound_slice()
    };
    let update = update_for(&scoped);

    validate_mesh_config_update(&update, &expected, NATIVE)
        .expect("an unpinned subscription does not gate echoed scope");
}

#[test]
fn validator_rejects_a_heartbeat_frame_on_the_install_path() {
    let expected = expectation(None, None);

    assert_eq!(
        reason_for(&heartbeat(), &expected),
        MeshUpdateRejectReason::UnexpectedHeartbeat
    );
}

/// Rejections are observable with bounded, non-secret labels: the counter is
/// keyed only by `{consumer,reason}` and carries no control-plane-supplied
/// value.
#[test]
fn rejections_increment_a_reason_labelled_metric() {
    let expected = expectation(None, None);
    let label = MeshUpdateRejectReason::NodeIdMismatch.as_metric_label();
    let series = format!(
        "ferrum_mesh_config_update_rejections_total{{consumer=\"native\",reason=\"{label}\"}}"
    );
    let before = rendered_counter(&series);

    let wrong_node = MeshSlice {
        node_id: "dp-node-b".to_string(),
        ..bound_slice()
    };
    assert_eq!(
        reason_for(&update_for(&wrong_node), &expected),
        MeshUpdateRejectReason::NodeIdMismatch
    );

    let after = rendered_counter(&series);
    assert!(
        after > before,
        "the rejection must increment {series} (before={before}, after={after})"
    );
}

fn rendered_counter(series: &str) -> u64 {
    let mut rendered = String::new();
    render_mesh_observability_metrics(&mut rendered);
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(series))
        .and_then(|rest| rest.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ── Live native MeshSubscribe stream ───────────────────────────────────────

/// An in-process control plane that replays a fixed script of frames and then
/// keeps the stream open, so the data plane observes exactly the responses the
/// test wrote.
#[derive(Clone)]
struct ScriptedMeshCp {
    updates: Arc<Vec<MeshConfigUpdate>>,
    subscribe_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl MeshConfigSync for ScriptedMeshCp {
    type MeshSubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        _request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        let items: Vec<Result<MeshConfigUpdate, Status>> =
            self.updates.iter().cloned().map(Ok).collect();
        let scripted = tokio_stream::iter(items);
        let held_open = tokio_stream::pending::<Result<MeshConfigUpdate, Status>>();
        let stream: Self::MeshSubscribeStream = Box::pin(scripted.chain(held_open));
        Ok(Response::new(stream))
    }
}

struct CpHandle {
    url: String,
    subscribe_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl CpHandle {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
    }
}

async fn start_cp(updates: Vec<MeshConfigUpdate>) -> CpHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub CP");
    let addr = listener.local_addr().expect("stub CP addr");
    let subscribe_count = Arc::new(AtomicUsize::new(0));
    let cp = ScriptedMeshCp {
        updates: Arc::new(updates),
        subscribe_count: subscribe_count.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let incoming = TcpListenerStream::new(listener);
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(MeshConfigSyncServer::new(cp))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    CpHandle {
        url: format!("http://{addr}"),
        subscribe_count,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

type ClientHandle = (watch::Sender<bool>, tokio::task::JoinHandle<()>);

fn spawn_client(cp_urls: Vec<String>, state: MeshRuntimeState) -> ClientHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(start_native_mesh_client_with_shutdown(
        cp_urls,
        GrpcJwtSecret::new(JWT_SECRET.to_string()),
        client_config(None, Some(SPIFFE)),
        state,
        shutdown_rx,
        None,
        None,
    ));
    (shutdown_tx, handle)
}

async fn stop_client(client: ClientHandle) {
    let (shutdown_tx, handle) = client;
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
}

/// A control plane answering with a slice for another node never replaces the
/// data plane's last-good slice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_stream_keeps_last_good_slice_when_response_is_unbound() {
    let unbound = MeshSlice {
        node_id: "dp-node-b".to_string(),
        namespace: "beta".to_string(),
        version: "v-unbound".to_string(),
        ..MeshSlice::default()
    };
    let cp = start_cp(vec![update_for(&unbound)]).await;

    // Seed a last-good slice the way a previously accepted update would.
    let state = MeshRuntimeState::new();
    let last_good = MeshSlice {
        version: "v-last-good".to_string(),
        ..bound_slice()
    };
    state.install_slice(last_good);

    let client = spawn_client(vec![cp.url.clone()], state.clone());
    tokio::time::sleep(Duration::from_millis(700)).await;

    let snapshot = state.snapshot();
    let slice = snapshot
        .as_ref()
        .as_ref()
        .expect("last-good slice retained");
    assert_eq!(
        slice.version, "v-last-good",
        "an unbound response must not replace the last-good slice"
    );
    assert_eq!(slice.node_id, NODE_ID);

    stop_client(client).await;
    cp.shutdown().await;
}

/// An unbound response drops the stream, so multi-CP failover moves to the next
/// control plane — which serves a correctly bound slice that DOES install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_stream_fails_over_to_a_control_plane_that_answers_this_node() {
    let unbound = MeshSlice {
        node_id: "dp-node-b".to_string(),
        version: "v-unbound".to_string(),
        ..bound_slice()
    };
    let bad_cp = start_cp(vec![update_for(&unbound)]).await;

    let bound = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        version: "v-bound".to_string(),
        ..bound_slice()
    };
    let good_cp = start_cp(vec![update_for(&bound)]).await;

    let state = MeshRuntimeState::new();
    let urls = vec![bad_cp.url.clone(), good_cp.url.clone()];
    let client = spawn_client(urls, state.clone());

    let first_slice = state.wait_for_first_slice();
    tokio::time::timeout(Duration::from_secs(15), first_slice)
        .await
        .expect("the data plane must fail over and install the bound slice");

    let snapshot = state.snapshot();
    let slice = snapshot.as_ref().as_ref().expect("slice installed");
    assert_eq!(slice.version, "v-bound");
    assert_eq!(slice.node_id, NODE_ID);
    assert!(
        bad_cp.subscribe_count.load(Ordering::Relaxed) >= 1,
        "the unbound control plane must have been dialed first"
    );

    stop_client(client).await;
    bad_cp.shutdown().await;
    good_cp.shutdown().await;
}

/// A content-level fault (envelope version desynced from the slice) drops only
/// that frame: the stream stays open and a later, correct frame still applies.
/// Heartbeats stay explicit and install nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_stream_skips_bad_frames_and_applies_the_next_valid_one() {
    // Bound to the subscription in every way EXCEPT the version envelope, so
    // the frame is refused for content, not for binding.
    let echoed = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        ..bound_slice()
    };
    let desynced = MeshConfigUpdate {
        version: "v-envelope".to_string(),
        ..update_for(&echoed)
    };
    let valid = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        version: "v-applied".to_string(),
        ..bound_slice()
    };
    let script = vec![heartbeat(), desynced, update_for(&valid)];
    let cp = start_cp(script).await;

    let state = MeshRuntimeState::new();
    let client = spawn_client(vec![cp.url.clone()], state.clone());

    let first_slice = state.wait_for_first_slice();
    tokio::time::timeout(Duration::from_secs(10), first_slice)
        .await
        .expect("the valid frame after a skipped one must still apply");

    let snapshot = state.snapshot();
    let slice = snapshot.as_ref().as_ref().expect("slice installed");
    assert_eq!(slice.version, "v-applied");
    assert_eq!(
        cp.subscribe_count.load(Ordering::Relaxed),
        1,
        "a content-level fault must not tear down and re-subscribe"
    );

    stop_client(client).await;
    cp.shutdown().await;
}

/// The consumer is the last gate before `install_slice`: even called directly,
/// an unbound response never mutates runtime state.
#[test]
fn consumer_never_installs_an_unbound_response() {
    let state = MeshRuntimeState::new();
    let expected = expectation(None, Some(SPIFFE));
    let consumer = NativeMeshConfigConsumer::new(state.clone(), expected);
    let unbound = MeshSlice {
        node_id: "dp-node-b".to_string(),
        ..bound_slice()
    };

    assert!(consumer.apply_update(&update_for(&unbound)).is_err());
    assert!(!state.has_first_slice());
    assert!(state.snapshot().as_ref().is_none());

    let bound = MeshSlice {
        workload_spiffe_id: Some(SPIFFE.to_string()),
        ..bound_slice()
    };
    consumer
        .apply_update(&update_for(&bound))
        .expect("a bound response applies");
    assert!(state.has_first_slice());
}
