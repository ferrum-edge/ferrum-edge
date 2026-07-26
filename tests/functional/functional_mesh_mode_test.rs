//! Functional runtime coverage for `FERRUM_MODE=mesh`.
//!
//! This test spawns the real `ferrum-edge` binary and a lightweight native
//! `MeshSubscribe` control-plane stub. It verifies the binary can authenticate
//! to a CP URL, consume an initial mesh slice, build the mesh runtime, and bind
//! its sidecar listeners. Unit/integration tests cover the detailed projection
//! and request-path behavior; this locks in the process-level startup contract.
//!
//! Run with:
//!   cargo test --test functional_tests functional_mesh_mode -- --ignored --nocapture

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, StreamExt, stream};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::{
    IntervalStream, ReceiverStream, TcpListenerStream, UnboundedReceiverStream, UnixListenerStream,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::auth::MESH_LOCAL_SUBSCRIBE_AUDIENCE;
use ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{ConfigUpdate, MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::{
    SpiffeWorkloadApi, SpiffeWorkloadApiServer,
};
use ferrum_edge::identity::workload_api::proto::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest,
    X509svidResponse,
};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshPolicy, MeshRule, MeshService, MtlsMode,
    MultiClusterConfig, PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, ServicePort,
    ServiceTargetPort, TrustBundle, TrustBundleSet, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::XdsAdsServer;

use crate::common::ensure_gateway_built;
use crate::scaffolding::ports::reserve_port;

const GRPC_SECRET: &str = "ferrum-edge-functional-mesh-grpc-secret00";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_ATTEMPTS: u32 = 3;
// Cross-cluster gateway A's outbound slice/routes can still be materializing
// after its listener binds (and, in the live matrix, after the source sidecar
// consumes its CP slice). Both the positive and negative arms therefore poll for
// the FIRST authoritative routed response, retrying only transient setup /
// route-not-converged outcomes, bounded by this deadline.
const CROSS_CLUSTER_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);
const CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const CROSS_CLUSTER_TLS_REJECTION_BODY: &str = "HBONE backend unavailable: TLS handshake failed";
const CROSS_CLUSTER_WS_REJECTION_MARKER: &str =
    "authoritative cross-cluster WebSocket mTLS rejection";

fn binary_path() -> PathBuf {
    let debug = PathBuf::from("./target/debug/ferrum-edge");
    if debug.exists() {
        return debug;
    }
    PathBuf::from("./target/release/ferrum-edge")
}

#[derive(Clone)]
struct StaticMeshControlPlane {
    slice: Arc<MeshSlice>,
    request_tx: watch::Sender<Option<MeshSubscribeRequest>>,
    subscribe_count: Arc<AtomicUsize>,
}

fn verify_mesh_grpc_auth(metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| Status::unauthenticated("missing authorization token"))?;
    let key = DecodingKey::from_secret(GRPC_SECRET.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp", "iat", "sub", "iss"]
        .into_iter()
        .map(str::to_string)
        .collect();
    validation.set_issuer(&[DEFAULT_CP_DP_JWT_ISSUER]);
    validation.set_audience(&[MESH_LOCAL_SUBSCRIBE_AUDIENCE]);
    decode::<Value>(token, &key, &validation)
        .map(|_| ())
        .map_err(|err| Status::unauthenticated(format!("invalid authorization token: {err}")))
}

#[tonic::async_trait]
impl MeshConfigSync for StaticMeshControlPlane {
    type MeshSubscribeStream = Pin<Box<dyn Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        verify_mesh_grpc_auth(request.metadata())?;
        let request = request.into_inner();
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        // Model a real control plane: the returned slice is scoped to the
        // subscription (`MeshSlice::from_gateway_config` echoes node/namespace
        // /workload/waypoint verbatim), and the DP fails a response closed when
        // it is not bound to its own request (issue #2457).
        let slice = MeshSlice {
            node_id: request.node_id.clone(),
            namespace: request.namespace.clone(),
            workload_spiffe_id: Some(request.workload_spiffe_id.clone())
                .filter(|value| !value.is_empty()),
            waypoint_name: Some(request.waypoint_name.clone())
                .filter(|value| !value.trim().is_empty()),
            ..self.slice.as_ref().clone()
        };
        let _ = self.request_tx.send(Some(request));

        let update = MeshConfigUpdate {
            version: slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: serde_json::to_string(&slice)
                .map_err(|e| Status::internal(format!("serialize mesh slice: {e}")))?,
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            heartbeat: false,
        };
        let heartbeat = MeshConfigUpdate {
            version: self.slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: String::new(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            heartbeat: true,
        };
        let heartbeats = IntervalStream::new(tokio::time::interval(Duration::from_secs(60)))
            .map(move |_| Ok(heartbeat.clone()));
        let stream = stream::once(async move { Ok(update) }).chain(heartbeats);
        Ok(Response::new(Box::pin(stream)))
    }
}

struct MeshCpHandle {
    addr: std::net::SocketAddr,
    request_rx: watch::Receiver<Option<MeshSubscribeRequest>>,
    subscribe_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl MeshCpHandle {
    async fn shutdown(mut self) {
        shutdown_grpc_server(&mut self.shutdown_tx, &mut self.task).await;
    }
}

async fn start_static_mesh_cp(slice: MeshSlice) -> MeshCpHandle {
    start_static_mesh_cp_on(
        slice,
        "127.0.0.1:0".parse().expect("loopback CP bind"),
        None,
    )
    .await
}

/// Variant used by the root/netns live source-capture test. The control plane
/// listens on the host side of a veth so a Sidecar process running inside the
/// throwaway pod netns can subscribe without sharing the host network namespace.
async fn start_static_mesh_cp_on(
    slice: MeshSlice,
    bind_addr: SocketAddr,
    advertised_ip: Option<std::net::IpAddr>,
) -> MeshCpHandle {
    let listener = TcpListener::bind(bind_addr).await.expect("bind mesh CP");
    let bound_addr = listener.local_addr().expect("mesh CP local addr");
    let addr = SocketAddr::new(advertised_ip.unwrap_or(bound_addr.ip()), bound_addr.port());
    let (request_tx, request_rx) = watch::channel(None);
    let subscribe_count = Arc::new(AtomicUsize::new(0));
    let cp = StaticMeshControlPlane {
        slice: Arc::new(slice),
        request_tx,
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
    MeshCpHandle {
        addr,
        request_rx,
        subscribe_count,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

struct XdsCpHandle {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl XdsCpHandle {
    async fn shutdown(mut self) {
        shutdown_grpc_server(&mut self.shutdown_tx, &mut self.task).await;
    }
}

async fn shutdown_grpc_server(
    shutdown_tx: &mut Option<oneshot::Sender<()>>,
    task: &mut tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }
    match tokio::time::timeout(Duration::from_secs(2), &mut *task).await {
        Ok(_) => {}
        Err(_) => {
            task.abort();
            let _ = (&mut *task).await;
        }
    }
}

async fn start_xds_cp(config: GatewayConfig) -> XdsCpHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind xDS CP");
    let addr = listener.local_addr().expect("xDS CP local addr");
    let config = Arc::new(ArcSwap::from_pointee(config));
    let (update_tx, _) = broadcast::channel::<ConfigUpdate>(8);
    let server = XdsAdsServer::new(
        config,
        update_tx,
        GRPC_SECRET.to_string(),
        DEFAULT_CP_DP_JWT_ISSUER.to_string(),
        "ferrum".to_string(),
        32,
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let incoming = TcpListenerStream::new(listener);
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    XdsCpHandle {
        addr,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

fn initial_mesh_slice(node_id: &str) -> MeshSlice {
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        ..MeshSlice::default()
    }
}

fn east_west_service_slice(node_id: &str) -> MeshSlice {
    let spiffe_id = SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/reviews")
        .expect("valid service SPIFFE ID");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: spiffe_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: "reviews".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: 18080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").expect("valid trust domain"),
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("reviews".to_string()),
            pod_uid: Some("functional-reviews-pod".to_string()),
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "reviews".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: 18080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id }],
            protocol_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

fn test_cert_path(file_name: &str) -> String {
    std::fs::canonicalize(PathBuf::from("tests/certs").join(file_name))
        .expect("canonicalize test cert path")
        .to_str()
        .expect("test cert path is UTF-8")
        .to_string()
}

fn scrub_ferrum_env(cmd: &mut Command) {
    for (key, _) in std::env::vars() {
        if key.starts_with("FERRUM_") {
            cmd.env_remove(key);
        }
    }
}

struct MeshPorts {
    inbound: u16,
    outbound: u16,
    hbone: u16,
    egress: u16,
    east_west: u16,
}

/// Ports already handed to mesh gateway subprocesses in this test process.
///
/// A reservation must be released before a subprocess can bind it. Without
/// remembering released ports, the kernel can immediately return the same port
/// to a later `reserve_mesh_ports()` call before either subprocess starts. The
/// gateway's reusable listeners can then both bind that address and
/// nondeterministically receive each other's fixture traffic.
static USED_MESH_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

async fn reserve_unique_mesh_port() -> u16 {
    loop {
        let reservation = reserve_port().await.expect("reserve unique mesh port");
        let port = reservation.port;
        let inserted = USED_MESH_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(port);
        if inserted {
            return reservation.drop_and_take_port();
        }
    }
}

async fn reserve_mesh_ports() -> MeshPorts {
    MeshPorts {
        inbound: reserve_unique_mesh_port().await,
        outbound: reserve_unique_mesh_port().await,
        hbone: reserve_unique_mesh_port().await,
        egress: reserve_unique_mesh_port().await,
        east_west: reserve_unique_mesh_port().await,
    }
}

struct MeshGatewaySpawnOptions<'a> {
    cp_addr: SocketAddr,
    ports: MeshPorts,
    node_id: &'a str,
    config_protocol: &'a str,
    topology: &'a str,
    waypoint_name: Option<&'a str>,
    env_overrides: Vec<(&'a str, String)>,
}

fn spawn_mesh_gateway(temp: &TempDir, options: MeshGatewaySpawnOptions<'_>) -> Child {
    let mut cmd = Command::new(binary_path());
    configure_mesh_gateway_command(&mut cmd, temp, options);
    cmd.spawn().expect("spawn mesh gateway")
}

#[cfg(target_os = "linux")]
fn spawn_mesh_gateway_in_netns(
    temp: &TempDir,
    options: MeshGatewaySpawnOptions<'_>,
    netns_pid: u32,
) -> Child {
    spawn_mesh_gateway_in_netns_as_uid(temp, options, netns_pid, 1337)
}

#[cfg(target_os = "linux")]
fn spawn_mesh_gateway_in_netns_as_uid(
    temp: &TempDir,
    options: MeshGatewaySpawnOptions<'_>,
    netns_pid: u32,
    uid: u32,
) -> Child {
    let mut cmd = Command::new("nsenter");
    cmd.arg(format!("--net=/proc/{netns_pid}/ns/net"))
        .arg("--")
        .arg("setpriv")
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={uid}"))
        .args(["--clear-groups", "--"])
        .arg(binary_path());
    configure_mesh_gateway_command(&mut cmd, temp, options);
    cmd.spawn().expect("spawn mesh gateway inside pod netns")
}

#[cfg(target_os = "linux")]
fn spawn_mesh_gateway_in_netns_as_root(
    temp: &TempDir,
    options: MeshGatewaySpawnOptions<'_>,
    netns_pid: u32,
) -> Child {
    let mut cmd = Command::new("nsenter");
    cmd.arg(format!("--net=/proc/{netns_pid}/ns/net"))
        .arg("--")
        .arg(binary_path());
    configure_mesh_gateway_command(&mut cmd, temp, options);
    cmd.spawn()
        .expect("spawn privileged mesh gateway inside pod netns")
}

fn configure_mesh_gateway_command(
    cmd: &mut Command,
    temp: &TempDir,
    options: MeshGatewaySpawnOptions<'_>,
) {
    let stdout =
        std::fs::File::create(temp.path().join("mesh.stdout.log")).expect("create stdout capture");
    let stderr =
        std::fs::File::create(temp.path().join("mesh.stderr.log")).expect("create stderr capture");
    std::fs::create_dir_all(temp.path().join("node-waypoint-pods"))
        .expect("create node-waypoint pod registry dir");
    scrub_ferrum_env(cmd);
    cmd.args(["run"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .env("FERRUM_MODE", "mesh")
        .env("FERRUM_LOG_LEVEL", "info")
        .env("FERRUM_NAMESPACE", "ferrum")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", "0")
        .env("FERRUM_PROXY_HTTP_PORT", "0")
        .env("FERRUM_ADMIN_HTTP_PORT", "0")
        .env("FERRUM_CP_DP_GRPC_JWT_SECRET", GRPC_SECRET)
        // Mesh mode now fails closed without a CA backend (the PERMISSIVE-no-CA
        // startup gate). These runtime tests exercise mesh plumbing, not
        // workload identity, so explicitly acknowledge the no-CA dev posture.
        .env("FERRUM_MESH_ALLOW_NO_CA", "true")
        .env(
            "FERRUM_DP_CP_GRPC_URLS",
            format!("http://{}", options.cp_addr),
        )
        .env("FERRUM_MESH_CONFIG_PROTOCOL", options.config_protocol)
        .env("FERRUM_MESH_TOPOLOGY", options.topology)
        .env("FERRUM_MESH_NODE_ID", options.node_id)
        .env(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            format!("127.0.0.1:{}", options.ports.inbound),
        )
        .env(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            format!("127.0.0.1:{}", options.ports.outbound),
        )
        .env(
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            format!("127.0.0.1:{}", options.ports.hbone),
        )
        .env(
            "FERRUM_MESH_EGRESS_LISTEN_ADDR",
            format!("127.0.0.1:{}", options.ports.egress),
        )
        .env(
            "FERRUM_MESH_EAST_WEST_LISTEN_PORT",
            options.ports.east_west.to_string(),
        )
        .env("FERRUM_MESH_DNS_PROXY_ENABLED", "false")
        .env("FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS", "0")
        .env(
            "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR",
            temp.path().join("node-waypoint-pods"),
        );
    if let Some(waypoint_name) = options.waypoint_name {
        cmd.env("FERRUM_MESH_WAYPOINT_NAME", waypoint_name);
    }
    for (key, value) in options.env_overrides {
        cmd.env(key, value);
    }
}

fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll mesh gateway child") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn captured_output(temp: &TempDir) -> String {
    let stderr = std::fs::read_to_string(temp.path().join("mesh.stderr.log")).unwrap_or_default();
    let stdout = std::fs::read_to_string(temp.path().join("mesh.stdout.log")).unwrap_or_default();
    format!("{stderr}\n{stdout}")
}

async fn wait_for_mesh_subscribe(
    request_rx: &mut watch::Receiver<Option<MeshSubscribeRequest>>,
    timeout: Duration,
) -> Option<MeshSubscribeRequest> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(request) = request_rx.borrow().clone() {
            return Some(request);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        if tokio::time::timeout(remaining, request_rx.changed())
            .await
            .is_err()
        {
            return None;
        }
    }
}

async fn wait_for_tcp_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn tcp_port_stays_closed(port: u16, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return false;
        }
        if Instant::now() >= deadline {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_starts_after_native_mesh_subscribe() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-node-{attempt}");
        let cp = start_static_mesh_cp(initial_mesh_slice(&node_id)).await;
        let mut request_rx = cp.request_rx.clone();
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let outbound_port = ports.outbound;
        let temp = TempDir::new().expect("temp dir");
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: Vec::new(),
            },
        );

        let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
        let inbound_listening = wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await;
        let outbound_listening = wait_for_tcp_port(outbound_port, Duration::from_secs(5)).await;

        kill_child(&mut child);
        let subscribe_count = cp.subscribe_count.load(Ordering::Relaxed);
        cp.shutdown().await;

        match (subscribe, inbound_listening, outbound_listening) {
            (Some(request), true, true) => {
                assert_eq!(request.node_id, node_id);
                assert_eq!(request.namespace, "ferrum");
                assert!(
                    subscribe_count >= 1,
                    "expected at least one MeshSubscribe request"
                );
                return;
            }
            (subscribe, inbound_listening, outbound_listening) => {
                last_failure = format!(
                    "attempt {attempt}: subscribe={:?}, inbound_listening={inbound_listening}, \
                     outbound_listening={outbound_listening}\n{}",
                    subscribe.as_ref().map(|r| (&r.node_id, &r.namespace)),
                    captured_output(&temp)
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    panic!("mesh mode did not start after {RETRY_ATTEMPTS} attempts\n{last_failure}");
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_native_topology_listeners_match_contract() {
    ensure_gateway_built().expect("gateway binary built");

    struct Case {
        topology: &'static str,
        waypoint_name: Option<&'static str>,
        expected_open: fn(&MeshPorts) -> Vec<u16>,
        expected_closed: fn(&MeshPorts) -> Vec<u16>,
    }

    let cases = [
        Case {
            topology: "ambient",
            waypoint_name: None,
            expected_open: |ports| vec![ports.outbound, ports.hbone],
            expected_closed: |ports| vec![ports.inbound, ports.egress],
        },
        Case {
            topology: "node_waypoint",
            waypoint_name: None,
            expected_open: |ports| vec![ports.hbone],
            expected_closed: |ports| vec![ports.inbound, ports.outbound, ports.egress],
        },
        Case {
            topology: "service_waypoint",
            waypoint_name: Some("functional-waypoint"),
            expected_open: |ports| vec![ports.hbone],
            expected_closed: |ports| vec![ports.inbound, ports.outbound, ports.egress],
        },
    ];

    'cases: for case in cases {
        let mut last_failure = String::new();
        for attempt in 1..=RETRY_ATTEMPTS {
            let node_id = format!("functional-mesh-{}-node-{attempt}", case.topology);
            let cp = start_static_mesh_cp(initial_mesh_slice(&node_id)).await;
            let mut request_rx = cp.request_rx.clone();
            let ports = reserve_mesh_ports().await;
            let open_ports = (case.expected_open)(&ports);
            let closed_ports = (case.expected_closed)(&ports);
            let temp = TempDir::new().expect("temp dir");
            let mut child = spawn_mesh_gateway(
                &temp,
                MeshGatewaySpawnOptions {
                    cp_addr: cp.addr,
                    ports,
                    node_id: &node_id,
                    config_protocol: "native",
                    topology: case.topology,
                    waypoint_name: case.waypoint_name,
                    env_overrides: Vec::new(),
                },
            );

            let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
            let mut all_open = true;
            for port in &open_ports {
                if !wait_for_tcp_port(*port, STARTUP_TIMEOUT).await {
                    all_open = false;
                    break;
                }
            }
            let mut all_closed = true;
            if all_open {
                for port in &closed_ports {
                    if !tcp_port_stays_closed(*port, Duration::from_millis(500)).await {
                        all_closed = false;
                        break;
                    }
                }
            }

            kill_child(&mut child);
            cp.shutdown().await;

            let waypoint_name_matches = subscribe
                .as_ref()
                .map(|request| request.waypoint_name.as_str() == case.waypoint_name.unwrap_or(""))
                .unwrap_or(false);
            if subscribe.is_some() && waypoint_name_matches && all_open && all_closed {
                continue 'cases;
            }

            last_failure = format!(
                "attempt {attempt}: subscribe={:?}, open_ports={:?}, closed_ports={:?}, \
                 waypoint_name_matches={waypoint_name_matches}, all_open={all_open}, \
                 all_closed={all_closed}\n{}",
                subscribe
                    .as_ref()
                    .map(|r| (&r.node_id, &r.namespace, &r.waypoint_name)),
                open_ports,
                closed_ports,
                captured_output(&temp)
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        panic!(
            "topology {} listener contract failed after {RETRY_ATTEMPTS} attempts\n{last_failure}",
            case.topology
        );
    }
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_east_west_gateway_materializes_service_listener() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-east-west-node-{attempt}");
        let cp = start_static_mesh_cp(east_west_service_slice(&node_id)).await;
        let mut request_rx = cp.request_rx.clone();
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let outbound_port = ports.outbound;
        let hbone_port = ports.hbone;
        let egress_port = ports.egress;
        let east_west_port = ports.east_west;
        let temp = TempDir::new().expect("temp dir");
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "east_west_gateway",
                waypoint_name: None,
                env_overrides: Vec::new(),
            },
        );

        let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
        let east_west_listening = wait_for_tcp_port(east_west_port, STARTUP_TIMEOUT).await;
        let direct_mesh_ports_closed =
            tcp_port_stays_closed(inbound_port, Duration::from_millis(500)).await
                && tcp_port_stays_closed(outbound_port, Duration::from_millis(500)).await
                && tcp_port_stays_closed(hbone_port, Duration::from_millis(500)).await
                && tcp_port_stays_closed(egress_port, Duration::from_millis(500)).await;

        kill_child(&mut child);
        cp.shutdown().await;

        if subscribe.is_some() && east_west_listening && direct_mesh_ports_closed {
            return;
        }

        last_failure = format!(
            "attempt {attempt}: subscribe={:?}, east_west_listening={east_west_listening}, \
             direct_mesh_ports_closed={direct_mesh_ports_closed}\n{}",
            subscribe.as_ref().map(|r| (&r.node_id, &r.namespace)),
            captured_output(&temp)
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!(
        "east-west mesh gateway did not bind materialized service listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_egress_gateway_binds_mtls_listener_with_tls_material() {
    ensure_gateway_built().expect("gateway binary built");

    let cert_path = test_cert_path("server.crt");
    let key_path = test_cert_path("server.key");
    let client_ca_path = cert_path.clone();
    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-egress-node-{attempt}");
        let cp = start_static_mesh_cp(initial_mesh_slice(&node_id)).await;
        let mut request_rx = cp.request_rx.clone();
        let ports = reserve_mesh_ports().await;
        let egress_port = ports.egress;
        let temp = TempDir::new().expect("temp dir");
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "egress_gateway",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.clone()),
                    ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.clone()),
                    (
                        "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH",
                        client_ca_path.clone(),
                    ),
                ],
            },
        );

        let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
        let egress_listening = wait_for_tcp_port(egress_port, STARTUP_TIMEOUT).await;

        kill_child(&mut child);
        cp.shutdown().await;

        if subscribe.is_some() && egress_listening {
            return;
        }

        last_failure = format!(
            "attempt {attempt}: subscribe={:?}, egress_listening={egress_listening}\n{}",
            subscribe.as_ref().map(|r| (&r.node_id, &r.namespace)),
            captured_output(&temp)
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!(
        "egress mesh gateway did not bind mTLS listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_rejects_service_waypoint_without_waypoint_name() {
    ensure_gateway_built().expect("gateway binary built");

    let node_id = "functional-mesh-service-waypoint-missing-name";
    let cp = start_static_mesh_cp(initial_mesh_slice(node_id)).await;
    let ports = reserve_mesh_ports().await;
    let temp = TempDir::new().expect("temp dir");
    let mut child = spawn_mesh_gateway(
        &temp,
        MeshGatewaySpawnOptions {
            cp_addr: cp.addr,
            ports,
            node_id,
            config_protocol: "native",
            topology: "service_waypoint",
            waypoint_name: None,
            env_overrides: Vec::new(),
        },
    );

    let status = wait_for_child_exit(&mut child, Duration::from_secs(10)).await;
    if status.is_none() {
        kill_child(&mut child);
    }
    cp.shutdown().await;

    let output = captured_output(&temp);
    assert!(
        matches!(status, Some(status) if !status.success()),
        "service_waypoint without waypoint name should exit non-zero; status={status:?}\n{output}"
    );
    assert!(
        output.contains("FERRUM_MESH_WAYPOINT_NAME is required"),
        "service_waypoint validation error missing from output\n{output}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_rejects_egress_gateway_without_mtls_material() {
    ensure_gateway_built().expect("gateway binary built");

    let node_id = "functional-mesh-egress-missing-mtls";
    let cp = start_static_mesh_cp(initial_mesh_slice(node_id)).await;
    let mut request_rx = cp.request_rx.clone();
    let ports = reserve_mesh_ports().await;
    let egress_port = ports.egress;
    let temp = TempDir::new().expect("temp dir");
    let mut child = spawn_mesh_gateway(
        &temp,
        MeshGatewaySpawnOptions {
            cp_addr: cp.addr,
            ports,
            node_id,
            config_protocol: "native",
            topology: "egress_gateway",
            waypoint_name: None,
            env_overrides: Vec::new(),
        },
    );

    let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
    let status = wait_for_child_exit(&mut child, STARTUP_TIMEOUT).await;
    if status.is_none() {
        kill_child(&mut child);
    }
    cp.shutdown().await;

    let output = captured_output(&temp);
    assert!(
        subscribe.is_some(),
        "egress gateway should consume the initial mesh slice before mTLS validation fails\n{output}"
    );
    assert!(
        matches!(status, Some(status) if !status.success()),
        "egress_gateway without TLS material should exit non-zero; status={status:?}\n{output}"
    );
    assert!(
        output.contains(
            "FERRUM_MESH_TOPOLOGY=egress_gateway requires a TLS server identity for the egress mTLS listener"
        ),
        "egress_gateway mTLS validation error missing from output\n{output}"
    );
    assert!(
        tcp_port_stays_closed(egress_port, Duration::from_millis(500)).await,
        "egress mTLS listener should not bind after failed validation\n{output}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_starts_after_xds_ads() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-xds-node-{attempt}");
        let cp = start_xds_cp(GatewayConfig::default()).await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let outbound_port = ports.outbound;
        let temp = TempDir::new().expect("temp dir");
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "xds",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: Vec::new(),
            },
        );

        let inbound_listening = wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await;
        let outbound_listening = wait_for_tcp_port(outbound_port, STARTUP_TIMEOUT).await;

        kill_child(&mut child);
        cp.shutdown().await;

        if inbound_listening && outbound_listening {
            return;
        }

        last_failure = format!(
            "attempt {attempt}: inbound_listening={inbound_listening}, \
             outbound_listening={outbound_listening}\n{}",
            captured_output(&temp)
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("mesh mode did not start from xDS ADS after {RETRY_ATTEMPTS} attempts\n{last_failure}");
}

// ── Runtime inbound mTLS fail-closed enforcement (issue #1523) ──────────────

/// Generated gateway SVID file paths (leaf cert + PKCS#8 key + trust bundle).
struct GeneratedGatewaySvid {
    cert_path: String,
    key_path: String,
    trust_bundle_path: String,
}

/// Write a valid gateway SVID (a SPIFFE-SAN leaf signed by a fresh root, plus
/// that root as the trust bundle) into `dir`, returning the three file paths.
/// Mirrors the SVID shape `load_svid_bundle_from_files` accepts so the running
/// mesh loads it as a real workload identity.
fn generate_gateway_svid(dir: &std::path::Path, spiffe_id: &str) -> GeneratedGatewaySvid {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    // Root CA — also serves as the trust bundle.
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    // Leaf SVID carrying the SPIFFE URI SAN, signed by the root.
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
    leaf_params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    let cert_path = dir.join("gateway-svid.crt");
    let key_path = dir.join("gateway-svid.key");
    let trust_bundle_path = dir.join("gateway-svid-bundle.pem");
    std::fs::write(&cert_path, leaf_cert.pem()).expect("write svid cert");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write svid key");
    std::fs::write(&trust_bundle_path, ca_pem).expect("write trust bundle");

    let to_str = |p: PathBuf| p.to_str().expect("svid path is UTF-8").to_string();
    GeneratedGatewaySvid {
        cert_path: to_str(cert_path),
        key_path: to_str(key_path),
        trust_bundle_path: to_str(trust_bundle_path),
    }
}

/// A mesh slice whose (namespace-scoped) PeerAuthentication resolves the inbound
/// mTLS mode to DISABLE, so the inbound termination listener would serve
/// plaintext.
fn disable_peer_auth_slice(node_id: &str) -> MeshSlice {
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-disable".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Disable,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Production mesh must FAIL CLOSED when the resolved inbound listener would
/// serve plaintext. Here a valid gateway SVID loads (so ProxyState construction
/// succeeds), but PeerAuthentication resolves to DISABLE — the runtime inbound
/// fail-closed gate must refuse to start instead of binding a plaintext sidecar
/// inbound listener. (FERRUM_MESH_ALLOW_NO_CA is set by the spawn helper; this
/// asserts production ignores it.)
#[ignore]
#[tokio::test]
async fn functional_mesh_mode_production_refuses_plaintext_inbound_listener() {
    ensure_gateway_built().expect("gateway binary built");

    let node_id = "functional-mesh-prod-disable-refuse";
    let temp = TempDir::new().expect("temp dir");
    let svid = generate_gateway_svid(temp.path(), "spiffe://cluster.local/ns/ferrum/sa/test");
    let cp = start_static_mesh_cp(disable_peer_auth_slice(node_id)).await;
    let mut request_rx = cp.request_rx.clone();
    let ports = reserve_mesh_ports().await;
    let inbound_port = ports.inbound;
    let mut child = spawn_mesh_gateway(
        &temp,
        MeshGatewaySpawnOptions {
            cp_addr: cp.addr,
            ports,
            node_id,
            config_protocol: "native",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svid.trust_bundle_path.clone(),
                ),
            ],
        },
    );

    let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
    let status = wait_for_child_exit(&mut child, STARTUP_TIMEOUT).await;
    if status.is_none() {
        kill_child(&mut child);
    }
    cp.shutdown().await;

    let output = captured_output(&temp);
    assert!(
        subscribe.is_some(),
        "sidecar should consume the initial mesh slice before the inbound fail-closed gate runs\n{output}"
    );
    assert!(
        matches!(status, Some(status) if !status.success()),
        "production mesh with a DISABLE (plaintext) inbound listener should exit non-zero; status={status:?}\n{output}"
    );
    assert!(
        output.contains("FERRUM_MESH_PRODUCTION_MODE=true") && output.contains("inbound"),
        "expected the runtime inbound fail-closed refusal in output\n{output}"
    );
    assert!(
        tcp_port_stays_closed(inbound_port, Duration::from_millis(500)).await,
        "a plaintext inbound listener must not bind after the fail-closed refusal\n{output}"
    );
}

/// A valid gateway SVID, with NO explicit FERRUM_FRONTEND_TLS_* material, must
/// back the inbound listener's server identity so it serves mTLS (issue #1523,
/// gap #3). In production this is self-checking: if the SVID did NOT back the
/// server identity, the listener would resolve to plaintext under the default
/// PERMISSIVE mode and the runtime gate would refuse to start — so a bound
/// inbound listener on a live child proves the SVID backs an mTLS-capable one.
#[ignore]
#[tokio::test]
async fn functional_mesh_mode_production_binds_mtls_inbound_with_gateway_svid() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-prod-svid-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let svid = generate_gateway_svid(temp.path(), "spiffe://cluster.local/ns/ferrum/sa/test");
        let cp = start_static_mesh_cp(initial_mesh_slice(&node_id)).await;
        let mut request_rx = cp.request_rx.clone();
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svid.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
        let inbound_listening = wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await;

        kill_child(&mut child);
        cp.shutdown().await;

        if subscribe.is_some() && inbound_listening {
            return;
        }

        last_failure = format!(
            "attempt {attempt}: subscribe={:?}, inbound_listening={inbound_listening}\n{}",
            subscribe.as_ref().map(|r| (&r.node_id, &r.namespace)),
            captured_output(&temp)
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!(
        "production mesh did not bind an mTLS inbound listener from gateway SVID material after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

/// Server + client SVIDs under a **shared** CA. `generate_gateway_svid` mints a
/// fresh CA per call, so it can't drive a two-sided handshake; this signs both
/// leaves from one root. The CA is returned both as the server's trust-bundle
/// file (for `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`) and in PEM for the client
/// probe's root store, and each leaf carries a `127.0.0.1` SAN so a standard
/// rustls client can verify the server SVID by address.
struct MeshPeerSvids {
    /// The server leaf's SPIFFE ID, pinned client-side during the handshake.
    server_spiffe: String,
    server_cert_path: String,
    server_key_path: String,
    trust_bundle_path: String,
    ca_pem: String,
    /// CA private key (PEM) so tests can re-issue the server leaf from the
    /// SAME CA — the SVID-rotation keystone overwrites the server SVID files
    /// in place and expects the inbound listener to pick the new leaf up.
    ca_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    /// A client leaf signed by the **same CA** but bearing a SPIFFE ID in a trust
    /// domain the server's bundle does not recognize. It chains to the CA, so a
    /// chain-only verifier would admit it; the SPIFFE trust-domain verifier must
    /// reject it. This isolates "requires a valid peer SVID" from chain validation.
    untrusted_td_client_cert_pem: String,
    untrusted_td_client_key_pem: String,
}

fn generate_mesh_peer_svids(
    dir: &std::path::Path,
    server_spiffe: &str,
    client_spiffe: &str,
) -> MeshPeerSvids {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose, SanType,
    };

    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    // Shared root CA — also the trust bundle both peers verify against.
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf = |spiffe: &str| -> (String, String) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let id = SpiffeId::new(spiffe).expect("valid SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
        // Loopback SAN so the test's rustls client can verify the server SVID by
        // address (mesh peer verification is SPIFFE-SAN-based; the test client
        // uses ordinary WebPKI name checking against 127.0.0.1).
        params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
            )));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.signed_by(&key, &issuer).expect("leaf cert");
        (cert.pem(), key.serialize_pem())
    };

    let (server_cert_pem, server_key_pem) = leaf(server_spiffe);
    let (client_cert_pem, client_key_pem) = leaf(client_spiffe);
    // Same CA, but a trust domain the server bundle does not recognize — admitted
    // by chain validation, must be rejected by the SPIFFE trust-domain verifier.
    let (untrusted_td_client_cert_pem, untrusted_td_client_key_pem) =
        leaf("spiffe://untrusted.example/ns/default/sa/client");

    let server_cert_path = dir.join("server-svid.crt");
    let server_key_path = dir.join("server-svid.key");
    let trust_bundle_path = dir.join("mesh-ca.pem");
    std::fs::write(&server_cert_path, &server_cert_pem).expect("write server cert");
    std::fs::write(&server_key_path, &server_key_pem).expect("write server key");
    std::fs::write(&trust_bundle_path, &ca_pem).expect("write trust bundle");

    let to_str = |p: PathBuf| p.to_str().expect("svid path is UTF-8").to_string();
    MeshPeerSvids {
        server_spiffe: server_spiffe.to_string(),
        server_cert_path: to_str(server_cert_path),
        server_key_path: to_str(server_key_path),
        trust_bundle_path: to_str(trust_bundle_path),
        ca_pem,
        ca_key_pem,
        client_cert_pem,
        client_key_pem,
        untrusted_td_client_cert_pem,
        untrusted_td_client_key_pem,
    }
}

/// Re-issue the server SVID leaf from the SAME CA (same SPIFFE identity, fresh
/// key) and overwrite the on-disk cert/key files in place — exactly what an
/// external SVID rotator does. The gateway's SVID file watcher should pick the
/// change up within its poll interval and the inbound listener should start
/// presenting the new leaf without a restart.
fn rotate_server_svid_files(peers: &MeshPeerSvids) {
    use rcgen::{
        CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, Issuer, KeyPair, SanType,
    };
    let ca_key = KeyPair::from_pem(&peers.ca_key_pem).expect("ca key from pem");
    let issuer = Issuer::from_ca_cert_pem(&peers.ca_pem, ca_key).expect("issuer from ca pem");
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("rotated leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(&peers.server_spiffe).expect("valid SPIFFE ID");
    params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = params.signed_by(&key, &issuer).expect("rotated leaf cert");
    std::fs::write(&peers.server_cert_path, cert.pem()).expect("overwrite server cert");
    std::fs::write(&peers.server_key_path, key.serialize_pem()).expect("overwrite server key");
}

/// Complete one mTLS handshake against the inbound listener and return the
/// server's presented leaf certificate (DER), verifying it chains to `ca_pem`
/// and carries `expected_server_spiffe`. Used to observe WHICH leaf the
/// listener serves across an SVID rotation.
async fn mesh_inbound_server_leaf(
    port: u16,
    ca_pem: &str,
    expected_server_spiffe: &str,
    client_identity: (&str, &str),
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|c| c.ok()) {
        roots.add(cert)?;
    }
    let provider = rustls::crypto::ring::default_provider();
    let (cert_pem, key_pem) = client_identity;
    let chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or("no client private key in PEM")?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())?;
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .map_err(|_| "tls handshake timed out")??;
    let (_io, conn) = tls.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("server presented no certificate")?;
    let server_id = ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(leaf.as_ref())
        .map_err(|e| format!("server leaf lacks a valid SPIFFE URI SAN: {e}"))?;
    let expected = SpiffeId::new(expected_server_spiffe)?;
    if server_id != expected {
        return Err(
            format!("server SPIFFE ID '{server_id}' does not match expected '{expected}'").into(),
        );
    }
    Ok(leaf.as_ref().to_vec())
}

/// A mesh slice whose mesh-wide PeerAuthentication resolves the inbound mTLS mode
/// to STRICT, so the sidecar inbound listener requires + verifies a peer cert.
fn strict_peer_auth_slice(node_id: &str) -> MeshSlice {
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Drive a real mTLS connection to the sidecar inbound listener at
/// `127.0.0.1:port`, verifying the server SVID against `ca_pem` (the leaf carries
/// a loopback SAN) **and** pinning the server's SPIFFE URI SAN to
/// `expected_server_spiffe`. With `client_identity = Some((cert_pem, key_pem))`
/// the client presents a client SVID; with `None` it presents none. Returns
/// `Ok(())` only when the **two-sided handshake completes, the presented server
/// leaf carries the expected SPIFFE identity, and the server accepts client-auth**.
///
/// Server-identity pin: WebPKI name checking only proves the leaf chains to
/// `ca_pem` and is valid for `127.0.0.1`, so a same-CA cert with a wrong/missing
/// SPIFFE URI SAN would still satisfy `connect()`. We therefore re-extract the
/// peer leaf's SPIFFE ID post-handshake (the same extractor the inbound verifier
/// uses) and require it to match.
///
/// TLS 1.3 subtlety: the client's `connect()` returns before the server validates
/// the client certificate, so a STRICT server rejecting a missing/untrusted client
/// cert is only observable *post*-handshake — it fires a `certificate required`
/// fatal alert that surfaces on the next read. We therefore probe one read while
/// sending nothing: an accepted peer leaves the server holding the connection open
/// for the HTTP request (header-read timeout is 10s, so a 3s read blocks → times
/// out → `Ok`), while a rejected peer's connection is torn down by the alert (read
/// errors or hits immediate EOF → `Err`). This distinguishes a client-auth failure
/// from any post-handshake HTTP behavior.
async fn mesh_inbound_mtls_connect(
    port: u16,
    ca_pem: &str,
    expected_server_spiffe: &str,
    client_identity: Option<(&str, &str)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncReadExt;

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|c| c.ok()) {
        roots.add(cert)?;
    }
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let config = match client_identity {
        Some((cert_pem, key_pem)) => {
            let chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .filter_map(|c| c.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or("no client private key in PEM")?;
            builder.with_client_auth_cert(chain, key)?
        }
        None => builder.with_no_client_auth(),
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())?;
    // `connect()` resolving `Ok` proves the server SVID verified against `ca_pem`;
    // under TLS 1.3 it does not yet prove the server accepted *our* client-auth.
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .map_err(|_| "tls handshake timed out")??;

    // Pin the server SPIFFE identity from the presented leaf (chaining to the CA
    // and a loopback SAN is not enough — see the doc comment). Reuses the inbound
    // verifier's own URI-SAN extractor so this can't drift from production.
    {
        let (_io, conn) = tls.get_ref();
        let server_leaf = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("server presented no certificate")?;
        let server_id =
            ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(server_leaf.as_ref())
                .map_err(|e| format!("server leaf lacks a valid SPIFFE URI SAN: {e}"))?;
        let expected = SpiffeId::new(expected_server_spiffe)
            .map_err(|e| format!("invalid expected server SPIFFE ID: {e}"))?;
        if server_id != expected {
            return Err(format!(
                "server SPIFFE ID '{server_id}' does not match expected '{expected}'"
            )
            .into());
        }
    }

    // Send nothing and read once to observe the post-handshake client-auth verdict
    // (see the doc comment): block→timeout = accepted, alert/EOF = rejected.
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await {
        Err(_) => Ok(()), // server holding the connection open for our request → accepted
        Ok(Ok(0)) => {
            Err("server closed the connection post-handshake (client-auth rejected)".into())
        }
        Ok(Ok(_)) => Ok(()), // server sent application/preface data → accepted
        Ok(Err(e)) => Err(format!("post-handshake read failed (client-auth rejected): {e}").into()),
    }
}

/// Live two-sided mTLS into the sidecar inbound listener (P1 keystone, Increment
/// A — beyond #1525, which only asserts the listener *binds*). With a STRICT
/// PeerAuthentication and the gateway SVID backing the inbound server identity,
/// three real peers probe the listener, each also pinning the **server's** SPIFFE
/// ID from the presented leaf:
/// - a **shared-CA** client SVID completes the handshake and is **accepted**;
/// - a client presenting **no** certificate is **rejected** by mTLS client-auth;
/// - a client whose SVID chains to the same CA but lives in an **untrusted trust
///   domain** is **rejected** — proving the SPIFFE trust-domain verifier enforces,
///   not merely chain validation (the regression Codex flagged).
/// The request→authz→backend leg (which needs real capture/routing) is covered by
/// the kind `mesh-e2e-sidecar` workflow (Increment B). The spawn is retried with
/// fresh ports per the `tests/**` bind-race rule; the mTLS assertions are not.
/// F1 keystone: the SVID-backed inbound server identity ROTATES LIVE. After an
/// external rotator re-issues the server SVID files in place (same SPIFFE id,
/// fresh leaf/key), the gateway's SVID file watcher installs the new bundle and
/// the inbound listener starts presenting the NEW leaf — no restart. Before
/// this, the inbound server cert was pinned at startup and kept serving the old
/// leaf until it expired.
#[ignore]
#[tokio::test]
async fn functional_mesh_inbound_server_identity_rotates_with_svid_files() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-inbound-svid-rotation-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(
            temp.path(),
            "spiffe://cluster.local/ns/ferrum/sa/server",
            "spiffe://cluster.local/ns/default/sa/client",
        );
        let cp = start_static_mesh_cp(strict_peer_auth_slice(&node_id)).await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    (
                        "FERRUM_GATEWAY_SVID_CERT_PATH",
                        peers.server_cert_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_KEY_PATH",
                        peers.server_key_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        peers.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let client_identity = (
            peers.client_cert_pem.as_str(),
            peers.client_key_pem.as_str(),
        );
        let leaf_before = mesh_inbound_server_leaf(
            inbound_port,
            &peers.ca_pem,
            &peers.server_spiffe,
            client_identity,
        )
        .await;
        let leaf_before = match leaf_before {
            Ok(leaf) => leaf,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                cp.shutdown().await;
                panic!("startup leaf probe failed: {e}\n{output}");
            }
        };

        // External rotation: overwrite the SVID files in place (same SPIFFE
        // identity, same CA, fresh leaf + key).
        rotate_server_svid_files(&peers);

        // The SVID file watcher polls every second; give it a bounded window
        // and require the served leaf to CHANGE while keeping the identity.
        let mut rotated_leaf: Option<Vec<u8>> = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            match mesh_inbound_server_leaf(
                inbound_port,
                &peers.ca_pem,
                &peers.server_spiffe,
                client_identity,
            )
            .await
            {
                Ok(leaf) if leaf != leaf_before => {
                    rotated_leaf = Some(leaf);
                    break;
                }
                // Old leaf still served (rotation not picked up yet) or a
                // transient handshake error mid-swap: keep polling.
                Ok(_) | Err(_) => {}
            }
        }

        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        assert!(
            rotated_leaf.is_some(),
            "inbound listener kept presenting the startup leaf for 10s after the \
             SVID files rotated; the SVID-backed inbound identity must rotate \
             live\n{output}"
        );
        return;
    }

    panic!(
        "mesh gateway never bound its inbound listener after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    );
}

/// Mint a fresh server leaf (SPIFFE URI SAN + `127.0.0.1` SAN) signed by the
/// shared test CA, returned as `(leaf_der, pkcs8_key_der)` — the wire shape the
/// SPIFFE Workload API streams in an `X509SVID`. A fresh key each call means a
/// rotation produces an observably different leaf, exactly like a real agent
/// re-issuing the workload's SVID.
fn mint_spire_server_leaf(
    ca_pem: &str,
    ca_key_pem: &str,
    server_spiffe: &str,
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{
        CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    let ca_key = KeyPair::from_pem(ca_key_pem).expect("ca key from pem");
    let issuer = Issuer::from_ca_cert_pem(ca_pem, ca_key).expect("issuer from ca pem");
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(server_spiffe).expect("valid SPIFFE ID");
    params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = params.signed_by(&key, &issuer).expect("leaf cert");
    (cert.der().as_ref().to_vec(), key.serialize_der())
}

/// DER of the first certificate in a PEM bundle — the trust anchor the Workload
/// API ships in `X509SVID.bundle`.
fn ca_der_from_pem(ca_pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .next()
        .expect("at least one CA cert in PEM")
        .expect("valid CA DER")
        .as_ref()
        .to_vec()
}

/// Build one `X509SVIDResponse` carrying a freshly-minted leaf + key + the CA
/// trust bundle — the single-identity default response a SPIRE agent streams.
fn build_stub_x509_response(
    ca_pem: &str,
    ca_key_pem: &str,
    server_spiffe: &str,
) -> X509svidResponse {
    let (leaf_der, key_der) = mint_spire_server_leaf(ca_pem, ca_key_pem, server_spiffe);
    X509svidResponse {
        svids: vec![X509svid {
            spiffe_id: server_spiffe.to_string(),
            x509_svid: leaf_der,
            x509_svid_key: key_der,
            bundle: ca_der_from_pem(ca_pem),
            hint: String::new(),
        }],
        crl: Vec::new(),
        federated_bundles: HashMap::new(),
    }
}

/// Minimal in-process SPIFFE Workload API server standing in for a SPIRE agent.
/// `FetchX509SVID` streams an initial SVID immediately and pushes a freshly
/// re-issued one every time `rotation_tx` is bumped; the other RPCs are
/// unimplemented (the gateway only consumes the X.509 SVID stream).
struct StubWorkloadApi {
    ca_pem: String,
    ca_key_pem: String,
    server_spiffe: String,
    rotation_tx: watch::Sender<u64>,
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for StubWorkloadApi {
    type FetchX509SVIDStream =
        Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send + 'static>>;

    async fn fetch_x509svid(
        &self,
        _request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let ca_pem = self.ca_pem.clone();
        let ca_key_pem = self.ca_key_pem.clone();
        let server_spiffe = self.server_spiffe.clone();
        let mut rotation_rx = self.rotation_tx.subscribe();

        let (tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = tx.send(Ok(build_stub_x509_response(
            &ca_pem,
            &ca_key_pem,
            &server_spiffe,
        )));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = rotation_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    _ = tx.closed() => return,
                }
                if tx
                    .send(Ok(build_stub_x509_response(
                        &ca_pem,
                        &ca_key_pem,
                        &server_spiffe,
                    )))
                    .is_err()
                {
                    return;
                }
            }
        });

        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(
            out_rx,
        ))))
    }

    type FetchX509BundlesStream =
        Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_x509_bundles(
        &self,
        _request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        Err(Status::unimplemented("stub: fetch_x509_bundles"))
    }

    async fn fetch_jwtsvid(
        &self,
        _request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Err(Status::unimplemented("stub: fetch_jwtsvid"))
    }

    type FetchJWTBundlesStream =
        Pin<Box<dyn Stream<Item = Result<JwtBundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Err(Status::unimplemented("stub: fetch_jwt_bundles"))
    }

    async fn validate_jwtsvid(
        &self,
        _request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(Status::unimplemented("stub: validate_jwtsvid"))
    }
}

struct StubWorkloadApiHandle {
    rotation_tx: watch::Sender<u64>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl StubWorkloadApiHandle {
    /// Trigger a workload SVID rotation: existing `FetchX509SVID` streams push a
    /// freshly re-issued leaf.
    fn rotate(&self) {
        self.rotation_tx.send_modify(|n| *n = n.saturating_add(1));
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        match tokio::time::timeout(Duration::from_secs(2), &mut self.task).await {
            Ok(_) => {}
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
            }
        }
    }
}

/// Bind the stub Workload API server to `sock_path` and serve it until shutdown.
async fn start_stub_workload_api(
    sock_path: PathBuf,
    ca_pem: String,
    ca_key_pem: String,
    server_spiffe: String,
) -> StubWorkloadApiHandle {
    let (rotation_tx, _) = watch::channel(0u64);
    let stub = StubWorkloadApi {
        ca_pem,
        ca_key_pem,
        server_spiffe,
        rotation_tx: rotation_tx.clone(),
    };
    let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind stub workload API UDS");
    let incoming = UnixListenerStream::new(listener);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(SpiffeWorkloadApiServer::new(stub))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    StubWorkloadApiHandle {
        rotation_tx,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

/// F1 §2.1 keystone: with `FERRUM_MESH_CA_BACKEND=spire` (and no file-based
/// gateway SVID material), the gateway fetches its own SVID from the SPIRE Agent
/// Workload API and serves it as the inbound mTLS server identity — and that
/// identity ROTATES LIVE. Production mode is on, so the startup readiness gate
/// is fail-closed: the gateway only binds once the first SVID has arrived.
///
/// A real mTLS peer (shared-CA client SVID, server SPIFFE pinned) observes the
/// presented leaf; after the stub agent re-issues the SVID, the inbound listener
/// starts presenting the NEW leaf with no restart — proving the spire backend
/// feeds the same live-rotating slot the file watcher does.
#[ignore]
#[tokio::test]
async fn functional_mesh_inbound_identity_from_spire_workload_api_rotates() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-spire-ca-backend-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/server";
        let peers = generate_mesh_peer_svids(
            temp.path(),
            server_spiffe,
            "spiffe://cluster.local/ns/default/sa/client",
        );
        // In-process SPIRE-agent stand-in on a Unix socket the gateway dials.
        let sock_path = temp.path().join("workload-api.sock");
        let stub = start_stub_workload_api(
            sock_path.clone(),
            peers.ca_pem.clone(),
            peers.ca_key_pem.clone(),
            server_spiffe.to_string(),
        )
        .await;
        let cp = start_static_mesh_cp(strict_peer_auth_slice(&node_id)).await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_MESH_CA_BACKEND", "spire".to_string()),
                    (
                        "FERRUM_MESH_SPIRE_AGENT_SOCKET",
                        sock_path.to_str().expect("sock path utf8").to_string(),
                    ),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", server_spiffe.to_string()),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            stub.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let client_identity = (
            peers.client_cert_pem.as_str(),
            peers.client_key_pem.as_str(),
        );
        let leaf_before =
            mesh_inbound_server_leaf(inbound_port, &peers.ca_pem, server_spiffe, client_identity)
                .await;
        let leaf_before = match leaf_before {
            Ok(leaf) => leaf,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                cp.shutdown().await;
                stub.shutdown().await;
                panic!("spire-backed startup leaf probe failed: {e}\n{output}");
            }
        };

        // Rotate the workload SVID at the agent; the gateway's fetch loop should
        // install the new leaf and the inbound listener present it — no restart.
        stub.rotate();

        let mut rotated_leaf: Option<Vec<u8>> = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            match mesh_inbound_server_leaf(
                inbound_port,
                &peers.ca_pem,
                server_spiffe,
                client_identity,
            )
            .await
            {
                Ok(leaf) if leaf != leaf_before => {
                    rotated_leaf = Some(leaf);
                    break;
                }
                Ok(_) | Err(_) => {}
            }
        }

        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;
        stub.shutdown().await;

        assert!(
            rotated_leaf.is_some(),
            "inbound listener kept presenting the startup leaf for 10s after the SPIRE \
             Workload API rotated the SVID; the spire CA backend must feed the live-rotating \
             gateway SVID slot\n{output}"
        );
        return;
    }

    panic!(
        "mesh gateway never bound its inbound listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_strict_inbound_requires_peer_svid() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-strict-mtls-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(
            temp.path(),
            "spiffe://cluster.local/ns/ferrum/sa/server",
            "spiffe://cluster.local/ns/default/sa/client",
        );
        let cp = start_static_mesh_cp(strict_peer_auth_slice(&node_id)).await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    (
                        "FERRUM_GATEWAY_SVID_CERT_PATH",
                        peers.server_cert_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_KEY_PATH",
                        peers.server_key_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        peers.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            // Startup / port-bind flake — retry with fresh ports.
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Listener is up — run the real mTLS assertions (these are not retried).
        // Every probe also pins the server SVID to `peers.server_spiffe`.
        let with_cert = mesh_inbound_mtls_connect(
            inbound_port,
            &peers.ca_pem,
            &peers.server_spiffe,
            Some((&peers.client_cert_pem, &peers.client_key_pem)),
        )
        .await;
        let no_cert =
            mesh_inbound_mtls_connect(inbound_port, &peers.ca_pem, &peers.server_spiffe, None)
                .await;
        let untrusted_td = mesh_inbound_mtls_connect(
            inbound_port,
            &peers.ca_pem,
            &peers.server_spiffe,
            Some((
                &peers.untrusted_td_client_cert_pem,
                &peers.untrusted_td_client_key_pem,
            )),
        )
        .await;

        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        assert!(
            with_cert.is_ok(),
            "a peer presenting a shared-CA SVID must complete the inbound mTLS handshake \
             and be accepted by STRICT client-auth (server SVID pinned to '{}'): \
             {with_cert:?}\n{output}",
            peers.server_spiffe
        );
        assert!(
            no_cert.is_err(),
            "STRICT inbound must reject a peer presenting no client certificate: \
             {no_cert:?}\n{output}"
        );
        assert!(
            untrusted_td.is_err(),
            "STRICT inbound must reject a client whose SVID chains to the CA but is in an \
             untrusted trust domain — proves SPIFFE verification, not just chain validation: \
             {untrusted_td:?}\n{output}"
        );
        return;
    }

    panic!(
        "production sidecar never bound its mTLS inbound listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

/// A minimal HTTP/1.1 backend standing in for the sidecar's co-located
/// application. Binds an ephemeral loopback port (held by the accept loop, never
/// dropped/rebound) and replies `200` with a distinctive `backend-ok` body to any
/// request. The body is the reliable "request reached the backend" signal: an
/// allowed request relays this body to the client, while a denied request gets a
/// sidecar-generated 403 without it. (Connection counts are unreliable here — the
/// capability-registry refresh probes the backend regardless of authz/warmup.)
async fn start_echo_backend() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let port = listener.local_addr().expect("echo backend addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = b"backend-ok\n";
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
            });
        }
    });
    port
}

/// One-shot echo backend with a caller-chosen body, so multi-port routing
/// assertions can tell WHICH backend served the request.
async fn start_labeled_echo_backend(label: &'static str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind labeled echo backend");
    let port = listener.local_addr().expect("echo backend addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    label.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(label.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    port
}

/// Drive a real HTTP request over mTLS into the sidecar inbound listener and
/// return the HTTP status. Mirrors `mesh_inbound_mtls_connect`'s TLS setup
/// (root = `ca_pem`, client SVID, server SPIFFE pin) but then sends a `GET` and
/// parses the response status line — so the caller can assert the materialized
/// inbound route + `mesh_authz` verdict (200 reached-backend vs 403 denied).
async fn mesh_inbound_http_get(
    port: u16,
    ca_pem: &str,
    expected_server_spiffe: &str,
    client_identity: Option<(&str, &str)>,
    host: &str,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|c| c.ok()) {
        roots.add(cert)?;
    }
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let config = match client_identity {
        Some((cert_pem, key_pem)) => {
            let chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .filter_map(|c| c.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or("no client private key in PEM")?;
            builder.with_client_auth_cert(chain, key)?
        }
        None => builder.with_no_client_auth(),
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())?;
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .map_err(|_| "tls handshake timed out")??;

    // Pin the server SPIFFE identity from the presented leaf (same rigor as
    // mesh_inbound_mtls_connect — a same-CA loopback cert is not enough).
    {
        let (_io, conn) = tls.get_ref();
        let server_leaf = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("server presented no certificate")?;
        let server_id =
            ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(server_leaf.as_ref())
                .map_err(|e| format!("server leaf lacks a valid SPIFFE URI SAN: {e}"))?;
        let expected = SpiffeId::new(expected_server_spiffe)
            .map_err(|e| format!("invalid expected server SPIFFE ID: {e}"))?;
        if server_id != expected {
            return Err(format!(
                "server SPIFFE ID '{server_id}' does not match expected '{expected}'"
            )
            .into());
        }
    }

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp))
        .await
        .map_err(|_| "response read timed out")??;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse HTTP status line from response: {text:?}"))?;
    Ok((status, text))
}

/// A plaintext HTTP/1.1 GET (no TLS), returning the response status + full text.
/// Used to probe the outbound capture listener, which must NOT serve the
/// materialized inbound routes.
async fn plaintext_http_get(
    port: u16,
    host: &str,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "connect timed out")??;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tcp.write_all(request.as_bytes()).await?;
    tcp.flush().await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut resp))
        .await
        .map_err(|_| "response read timed out")??;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse HTTP status line from response: {text:?}"))?;
    Ok((status, text))
}

/// A mesh slice that makes the local workload (`server_spiffe`) back a single
/// HTTP service `echo` on `backend_port`, under STRICT PeerAuthentication, with
/// a MeshWide authz policy that ALLOWs (or DENYs) the client principal. The
/// inbound materializer turns the service into a loopback route to the echo
/// backend; `mesh_authz` then decides whether the request reaches it.
fn inbound_authz_slice(
    node_id: &str,
    server_spiffe: &str,
    client_spiffe: &str,
    backend_port: u16,
    allow: bool,
) -> MeshSlice {
    let server_id = SpiffeId::new(server_spiffe).expect("server SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let http_port = WorkloadPort {
        port: backend_port,
        protocol: AppProtocol::Http,
        name: Some("http".to_string()),
    };
    let server_workload = Workload {
        spiffe_id: server_id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: Some("ferrum".to_string()),
        },
        service_name: "echo".to_string(),
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![http_port],
        trust_domain: trust_domain.clone(),
        namespace: "ferrum".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("echo".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let echo_service = MeshService {
        cluster_ips: Vec::new(),
        name: "echo".to_string(),
        namespace: "ferrum".to_string(),
        ports: vec![ServicePort {
            port: backend_port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: server_id,
        }],
        protocol_overrides: HashMap::new(),
    };
    let policy = MeshPolicy {
        name: if allow { "allow-client" } else { "deny-client" }.to_string(),
        namespace: "ferrum".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(client_spiffe.to_string()),
                namespace_pattern: None,
                trust_domain: Some(trust_domain),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: if allow {
                PolicyAction::Allow
            } else {
                PolicyAction::Deny
            },
        }],
    };
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![server_workload],
        services: vec![echo_service],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        mesh_policies: vec![policy],
        ..MeshSlice::default()
    }
}

/// Spawn a production sidecar fed a routing+authz slice, stand up a loopback echo
/// backend, and drive one authorized client request over mTLS. Returns the HTTP
/// status + backend hit count. Spawn/bind flakes are retried with fresh ports;
/// the request/assertions are not. `allow` selects an ALLOW vs DENY authz policy
/// for the client principal.
async fn drive_inbound_authz_request(allow: bool) -> Result<(u16, String, bool), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";
    let label = if allow { "allow" } else { "deny" };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-inbound-authz-{label}-{attempt}");
        let temp = TempDir::new().map_err(|e| format!("temp dir: {e}"))?;
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let backend_port = start_echo_backend().await;

        let cp = start_static_mesh_cp(inbound_authz_slice(
            &node_id,
            server_spiffe,
            client_spiffe,
            backend_port,
            allow,
        ))
        .await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let outbound_port = ports.outbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    // No startup warmup probes to the materialized backend; the
                    // assertion keys on the relayed response body, not hit counts.
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", server_spiffe.to_string()),
                    (
                        "FERRUM_GATEWAY_SVID_CERT_PATH",
                        peers.server_cert_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_KEY_PATH",
                        peers.server_key_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        peers.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let inbound = mesh_inbound_http_get(
            inbound_port,
            &peers.ca_pem,
            server_spiffe,
            Some((&peers.client_cert_pem, &peers.client_key_pem)),
            "echo.ferrum.svc.cluster.local",
            "/",
        )
        .await;

        // The materialized inbound route must NOT be served on the outbound
        // capture listener: a plaintext request there for the local service FQDN
        // must not be shortcut to the loopback backend (outbound L7 routing isn't
        // materialized yet, so it should 404). `outbound_serves_route` is true
        // only if the outbound listener actually relayed the backend.
        let _ = wait_for_tcp_port(outbound_port, STARTUP_TIMEOUT).await;
        let outbound =
            plaintext_http_get(outbound_port, "echo.ferrum.svc.cluster.local", "/").await;
        let outbound_serves_route = match &outbound {
            Ok((status, body)) => *status == 200 && body.contains("backend-ok"),
            Err(_) => false,
        };

        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        return match inbound {
            Ok((status, body)) => Ok((status, body, outbound_serves_route)),
            Err(e) => Err(format!("inbound mTLS HTTP GET failed: {e}\n{output}")),
        };
    }

    Err(format!(
        "production sidecar never bound its inbound listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// P1 keystone (Increment B): the **live inbound datapath**. An authorized peer's
/// real HTTP request flows over mTLS into the sidecar, through the materialized
/// inbound route, past `mesh_authz`, and reaches the co-located backend (200).
/// This is what the inbound route materializer makes possible — before it, the
/// request 404'd with no proxy to route to.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_inbound_allows_authorized_peer_to_backend() {
    let (status, body, outbound_serves_route) = drive_inbound_authz_request(true)
        .await
        .expect("authorized inbound case");
    assert_eq!(
        status, 200,
        "an authorized peer's request must traverse the materialized inbound route to the local backend (200); body: {body:?}"
    );
    assert!(
        body.contains("backend-ok"),
        "the authorized response must carry the local backend's body: {body:?}"
    );
    assert!(
        !outbound_serves_route,
        "the materialized inbound route must NOT be served on the outbound capture listener"
    );
}

/// P1 keystone (Increment B): `mesh_authz` enforcement on the live inbound
/// datapath. A peer the policy DENYs completes mTLS but is rejected with 403
/// **before** the request reaches the local backend.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_inbound_denies_unauthorized_peer() {
    let (status, body, _) = drive_inbound_authz_request(false)
        .await
        .expect("unauthorized inbound case");
    assert_eq!(
        status, 403,
        "a denied peer's request must be rejected by mesh_authz (403); body: {body:?}"
    );
    assert!(
        !body.contains("backend-ok"),
        "a denied request must NOT reach the local backend (no backend body): {body:?}"
    );
}

/// A multi-port slice for the INBOUND disambiguation keystone: the local
/// `echo` service declares TWO HTTP service ports (8080 / 9090) whose numeric
/// targetPorts point at two distinguishable loopback backends. The inbound
/// materializer emits one per-port loopback sibling for each; the request
/// path selects by the request's explicit authority port — exactly the
/// channel a peer sidecar's multi-port egress rewrites into `:authority`.
fn inbound_multi_port_slice(
    node_id: &str,
    server_spiffe: &str,
    client_spiffe: &str,
    backend_a_port: u16,
    backend_b_port: u16,
) -> MeshSlice {
    let mut slice =
        inbound_authz_slice(node_id, server_spiffe, client_spiffe, backend_a_port, true);
    slice.services[0].ports = vec![
        ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http-a".to_string()),
            target_port: Some(ServiceTargetPort::Number(backend_a_port)),
        },
        ServicePort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-b".to_string()),
            target_port: Some(ServiceTargetPort::Number(backend_b_port)),
        },
    ];
    slice
}

/// Multi-port INBOUND keystone: a peer's request carrying an explicit
/// authority port (`Host: echo...:8080` / `:9090`) — what a multi-port-aware
/// egress sidecar sends — reaches the matching per-port loopback backend,
/// and a port-less request to the multi-port service fails closed (502)
/// instead of being guessed onto one port's backend.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_inbound_multi_port_routes_by_authority_port() {
    ensure_gateway_built().expect("gateway build");
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-inbound-multiport-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let backend_a = start_labeled_echo_backend("backend-a").await;
        let backend_b = start_labeled_echo_backend("backend-b").await;

        let cp = start_static_mesh_cp(inbound_multi_port_slice(
            &node_id,
            server_spiffe,
            client_spiffe,
            backend_a,
            backend_b,
        ))
        .await;
        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", server_spiffe.to_string()),
                    (
                        "FERRUM_GATEWAY_SVID_CERT_PATH",
                        peers.server_cert_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_KEY_PATH",
                        peers.server_key_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        peers.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let get = |host: &'static str| {
            let ca = peers.ca_pem.clone();
            let cert = peers.client_cert_pem.clone();
            let key = peers.client_key_pem.clone();
            async move {
                mesh_inbound_http_get(
                    inbound_port,
                    &ca,
                    server_spiffe,
                    Some((&cert, &key)),
                    host,
                    "/",
                )
                .await
            }
        };

        let port_a = get("echo.ferrum.svc.cluster.local:8080").await;
        let port_b = get("echo.ferrum.svc.cluster.local:9090").await;
        let portless = get("echo.ferrum.svc.cluster.local").await;
        let unmatched = get("echo.ferrum.svc.cluster.local:7777").await;
        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        let (status_a, body_a) = port_a.expect("authority :8080 request");
        assert_eq!(status_a, 200, "authority :8080 must route; {output}");
        assert!(
            body_a.contains("backend-a") && !body_a.contains("backend-b"),
            "authority :8080 must reach port 8080's backend, got: {body_a:?}"
        );
        let (status_b, body_b) = port_b.expect("authority :9090 request");
        assert_eq!(status_b, 200, "authority :9090 must route; {output}");
        assert!(
            body_b.contains("backend-b") && !body_b.contains("backend-a"),
            "authority :9090 must reach port 9090's backend, got: {body_b:?}"
        );
        let (status_portless, body_portless) = portless.expect("port-less request");
        assert_eq!(
            status_portless, 502,
            "a port-less request to a multi-port service must fail closed, \
             never be guessed onto one port's backend; body: {body_portless:?}\n{output}"
        );
        let (status_unmatched, body_unmatched) = unmatched.expect("unmatched-port request");
        assert_eq!(
            status_unmatched, 502,
            "an authority port the service does not declare must fail closed; \
             body: {body_unmatched:?}\n{output}"
        );
        return;
    }

    panic!(
        "production sidecar never bound its inbound listener after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    );
}

// ── Live OUTBOUND (egress) datapath: point A → point B over the mesh ─────────
//
// These are the egress keystones: TWO real gateways on one host. Gateway A
// captures a plaintext app request on its outbound listener, routes it through
// the materialized egress route, and originates the topology's mesh transport —
// Ambient HBONE (HTTP/2 CONNECT over SVID-mTLS to B's :15008-equivalent) or
// Sidecar SVID-mTLS HTTP/2 (to B's inbound :15006-equivalent). Gateway B
// terminates the mTLS, verifies A's SVID against the shared mesh CA, and
// delivers the request to the point-B echo backend. The non-default test ports
// ride FERRUM_MESH_EGRESS_{HBONE,MTLS}_PORT → `mesh.{hbone,mtls}_port` tags.

/// Two gateway SVID file-sets minted under ONE shared mesh CA, so gateways A
/// and B mutually verify over the same trust bundle. Mirrors
/// `generate_gateway_svid`'s leaf shape (SPIFFE URI SAN, client+server EKU).
struct TwoGatewaySvids {
    a: GeneratedGatewaySvid,
    b: GeneratedGatewaySvid,
}

fn generate_two_gateway_svids(
    dir: &std::path::Path,
    a_spiffe: &str,
    b_spiffe: &str,
) -> TwoGatewaySvids {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let trust_bundle_path = dir.join("mesh-egress-ca.pem");
    std::fs::write(&trust_bundle_path, &ca_pem).expect("write trust bundle");
    let bundle = trust_bundle_path
        .to_str()
        .expect("bundle path is UTF-8")
        .to_string();

    let mint = |prefix: &str, spiffe: &str| -> GeneratedGatewaySvid {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let id = SpiffeId::new(spiffe).expect("valid SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.signed_by(&key, &issuer).expect("leaf cert");

        let cert_path = dir.join(format!("{prefix}-svid.crt"));
        let key_path = dir.join(format!("{prefix}-svid.key"));
        std::fs::write(&cert_path, cert.pem()).expect("write svid cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write svid key");
        GeneratedGatewaySvid {
            cert_path: cert_path.to_str().expect("path utf8").to_string(),
            key_path: key_path.to_str().expect("path utf8").to_string(),
            trust_bundle_path: bundle.clone(),
        }
    };

    TwoGatewaySvids {
        a: mint("gateway-a", a_spiffe),
        b: mint("gateway-b", b_spiffe),
    }
}

/// The egress slice BOTH gateways consume: one in-mesh HTTP service `svc-b`
/// backed by gateway B's workload at `127.0.0.1:backend_port`, under STRICT
/// PeerAuthentication. The same slice serves both roles — B's inbound
/// materializer recognizes `b_spiffe` as local (via
/// `FERRUM_MESH_WORKLOAD_SPIFFE_ID`) and builds the loopback route; A's
/// outbound materializer (whose workload identity differs) builds the egress
/// route whose targets dial B.
fn egress_service_slice(node_id: &str, b_spiffe: &str, backend_port: u16) -> MeshSlice {
    let b_id = SpiffeId::new(b_spiffe).expect("b SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: b_id.clone(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "svc-b".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "svc-b".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-b".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-b".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: b_id }],
            protocol_overrides: HashMap::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Drive one captured app request from gateway A to the echo backend behind
/// gateway B over the given topology's egress transport. `client_trusted`
/// selects whether A's gateway SVID chains to the shared mesh CA (the mTLS
/// hooks negative: an untrusted A must NOT reach the backend). Returns the
/// final HTTP status + response body observed at point A's captured client.
async fn drive_egress_a_to_b(
    topology: &str,
    client_trusted: bool,
) -> Result<(u16, String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-mesh-egress-{topology}-{trust_label}-a-{attempt}");
        let node_b = format!("functional-mesh-egress-{topology}-{trust_label}-b-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
        // An untrusted A mints its OWN CA + SVID: its cert does not chain to the
        // mesh CA (B rejects it) and its bundle does not contain the mesh CA (A
        // rejects B). Either side failing must fail the request closed.
        let a_svid = if client_trusted {
            svids.a
        } else {
            generate_gateway_svid(temp_a.path(), a_spiffe)
        };
        let backend_port = start_echo_backend().await;

        let cp_b =
            start_static_mesh_cp(egress_service_slice(&node_b, b_spiffe, backend_port)).await;
        let cp_a =
            start_static_mesh_cp(egress_service_slice(&node_a, b_spiffe, backend_port)).await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_transport_port = match topology {
            "sidecar" => ports_b.inbound,
            "ambient" => ports_b.hbone,
            other => return Err(format!("unsupported egress topology {other}")),
        };

        // Gateway B: the destination. Its workload identity makes the slice's
        // svc-b local, so (sidecar) the inbound materializer routes
        // :inbound → 127.0.0.1:backend_port, or (ambient) the HBONE relay
        // tunnels CONNECT authorities directly.
        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(b_transport_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B transport listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            cp_a.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Gateway A: the source. Its egress dial port points the materialized
        // outbound targets at B's transport listener. Ambient keeps warmup ON so
        // the HBONE capability probe classifies B Supported before the request
        // (the fail-closed `hbone_required` gate refuses dispatch on an
        // unprobed target).
        let mut a_env = vec![
            ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
            // Debug-level logs so capability-probe outcomes (logged at debug)
            // surface in the captured output on test failures.
            ("FERRUM_LOG_LEVEL", "debug".to_string()),
            ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                a_svid.trust_bundle_path.clone(),
            ),
        ];
        match topology {
            "sidecar" => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()));
                a_env.push(("FERRUM_MESH_EGRESS_MTLS_PORT", b_transport_port.to_string()));
            }
            _ => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "true".to_string()));
                a_env.push((
                    "FERRUM_MESH_EGRESS_HBONE_PORT",
                    b_transport_port.to_string(),
                ));
            }
        }
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                cp_addr: cp_a.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: a_env,
            },
        );
        if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway A outbound listener never bound\n{}",
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Point A's captured app request. Retried briefly: the HBONE capability
        // probe and pool warmup race the first request, and a 502 from the
        // fail-closed gate is expected to converge to 200 once classified. The
        // negative (untrusted) case asserts the FINAL state instead — it must
        // never converge to 200.
        let deadline = Instant::now() + Duration::from_secs(15);
        let last: Result<(u16, String), String> = loop {
            let attempt =
                match plaintext_http_get(a_outbound_port, "svc-b.ferrum.svc.cluster.local", "/")
                    .await
                {
                    Ok((status, body)) => {
                        if status == 200 && body.contains("backend-ok") {
                            break Ok((status, body));
                        }
                        Ok((status, body))
                    }
                    Err(e) => Err(format!("egress GET failed: {e}")),
                };
            if Instant::now() >= deadline {
                break attempt;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };

        let output_a = captured_output(&temp_a);
        let output_b = captured_output(&temp_b);
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        cp_a.shutdown().await;
        cp_b.shutdown().await;

        // Carry both gateways' captured logs so a failed assertion (locally or
        // in CI) shows WHY the datapath did not converge.
        let logs = format!("--- gateway A ---\n{output_a}\n--- gateway B ---\n{output_b}");
        return match last {
            Ok((status, body)) => Ok((status, body, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "egress gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Egress keystone (Ambient): a captured plaintext request at gateway A reaches
/// the echo backend behind gateway B over **HBONE** — outbound capture →
/// materialized egress route → HBONE CONNECT over SVID-mTLS (peer pinned to
/// B's workload identity) → B's transparent relay → point-B backend → response
/// relayed back to point A.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_egress_routes_a_to_b_over_hbone() {
    let (status, body, logs) = drive_egress_a_to_b("ambient", true)
        .await
        .expect("ambient egress drive");
    assert_eq!(
        status, 200,
        "the captured request must traverse A's HBONE egress to B's backend; body: {body:?}\n{logs}"
    );
    assert!(
        body.contains("backend-ok"),
        "the response must carry point B's backend body: {body:?}\n{logs}"
    );
}

/// Egress keystone (Sidecar): a captured plaintext request at gateway A reaches
/// the echo backend behind gateway B over **plain SVID-mTLS HTTP/2** to B's
/// inbound listener — outbound capture → materialized egress route → mTLS
/// origination (peer pinned to B's workload identity) → B's STRICT inbound
/// termination → materialized loopback route → point-B backend → response back
/// to point A. HBONE is never involved: this is Sidecar's transport.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_egress_routes_a_to_b_over_mtls() {
    let (status, body, logs) = drive_egress_a_to_b("sidecar", true)
        .await
        .expect("sidecar egress drive");
    assert_eq!(
        status, 200,
        "the captured request must traverse A's SVID-mTLS egress to B's backend; body: {body:?}\n{logs}"
    );
    assert!(
        body.contains("backend-ok"),
        "the response must carry point B's backend body: {body:?}\n{logs}"
    );
}

/// Egress mTLS negative (Sidecar): a gateway whose SVID does NOT chain to the
/// mesh CA must not reach point B. A's client config rejects B's server SVID
/// (unknown CA) and B's STRICT inbound rejects A's client cert — both fail the
/// request closed at A's captured client, proving the egress transport really
/// verifies SVIDs rather than blindly tunneling.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_egress_rejects_untrusted_client_gateway() {
    let (status, body, logs) = drive_egress_a_to_b("sidecar", false)
        .await
        .expect("untrusted egress drive");
    assert_ne!(
        status, 200,
        "an untrusted gateway's egress request must fail closed, not reach the backend\n{logs}"
    );
    assert!(
        !body.contains("backend-ok"),
        "no backend body may leak through an unverified mTLS session: {body:?}\n{logs}"
    );
}

// ── gRPC over the Sidecar mesh-mTLS egress transport (issue #2003) ──────────

/// What the h2c gRPC client at point A observed: HTTP status, response
/// HEADERS, collected DATA bytes, and response TRAILERS. `trailers` is empty
/// when the stream ended without a trailers frame — e.g. a Trailers-Only
/// gateway refusal, whose `grpc-status` rides the response headers instead.
#[derive(Debug, Default)]
struct GrpcEgressResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    trailers: HashMap<String, String>,
}

/// gRPC unary wire framing: `[compressed=0][len: u32 BE][payload]`.
fn grpc_framed_payload(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(payload);
    body
}

/// h2c gRPC echo backend that responds with REAL HTTP/2 trailers: one DATA
/// frame echoing the request body, then a trailers frame carrying
/// `grpc-status: 0` and a custom `x-mesh-trailer` marker. Unlike the
/// header-encoded Trailers-Only shape, this exercises the full
/// data-then-trailers relay the mesh-mTLS gRPC path must preserve end-to-end.
async fn start_grpc_trailers_echo_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC trailers echo backend");
    let port = listener.local_addr().expect("backend local addr").port();

    tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body_bytes))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                    trailers.insert(
                        "x-mesh-trailer",
                        hyper::header::HeaderValue::from_static("echo-ok"),
                    );
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx); // channel EOF ends the stream after the trailers

                    let response = hyper::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("x-echo-path", &path)
                        .body(StreamBody::new(ReceiverStream::new(rx)))
                        .expect("build gRPC trailers echo response");
                    Ok::<_, hyper::Error>(response)
                });
                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{e}").contains("connection closed")
                {
                    eprintln!("gRPC trailers echo backend error: {e}");
                }
            });
        }
    });

    port
}

/// One captured gRPC request at point A's outbound listener: h2c
/// (prior-knowledge HTTP/2) with `content-type: application/grpc` and the
/// service FQDN as `:authority`, collecting the response DATA frames AND the
/// trailers frame separately so trailer preservation is actually asserted.
async fn grpc_egress_request(
    port: u16,
    authority: &str,
    path: &str,
    framed_body: &[u8],
) -> Result<GrpcEgressResponse, Box<dyn std::error::Error + Send + Sync>> {
    grpc_egress_request_to(
        SocketAddr::from(([127, 0, 0, 1], port)),
        authority,
        path,
        framed_body,
    )
    .await
}

async fn grpc_egress_request_to(
    address: SocketAddr,
    authority: &str,
    path: &str,
    framed_body: &[u8],
) -> Result<GrpcEgressResponse, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out")??;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::copy_from_slice(framed_body)))?;
    let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .map_err(|_| "gRPC response headers timed out")??;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    let mut body_bytes = Vec::new();
    let mut trailers = HashMap::new();
    let mut body = response.into_body();
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(10), body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => return Err(Box::new(e)),
            Ok(None) => break,
            Err(_) => return Err("gRPC response body timed out".into()),
        };
        if frame.is_data() {
            if let Ok(data) = frame.into_data() {
                body_bytes.extend_from_slice(&data);
            }
        } else if frame.is_trailers()
            && let Ok(map) = frame.into_trailers()
        {
            for (k, v) in &map {
                if let Ok(vs) = v.to_str() {
                    trailers.insert(k.as_str().to_string(), vs.to_string());
                }
            }
        }
    }
    conn_task.abort();

    Ok(GrpcEgressResponse {
        status,
        headers,
        body: body_bytes,
        trailers,
    })
}

/// Drive one captured gRPC request from gateway A to the trailers-echo gRPC
/// backend behind gateway B over the given topology's egress transport,
/// polling until `converged` accepts a response or the deadline lapses.
/// Mirrors [`drive_egress_a_to_b`]; returns the FINAL observed response plus
/// both gateways' captured logs so the caller can assert either convergence
/// (positive/fail-closed cases) or the final state (negative cases).
async fn drive_grpc_egress_a_to_b(
    topology: &str,
    client_trusted: bool,
    converged: fn(&GrpcEgressResponse) -> bool,
) -> Result<(GrpcEgressResponse, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };
    let payload = b"ferrum-mesh-grpc-payload";
    let framed = grpc_framed_payload(payload);

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-mesh-grpc-{topology}-{trust_label}-a-{attempt}");
        let node_b = format!("functional-mesh-grpc-{topology}-{trust_label}-b-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
        // Untrusted A mints its OWN CA + SVID (same negative shape as
        // `drive_egress_a_to_b`): neither side can verify the other.
        let a_svid = if client_trusted {
            svids.a
        } else {
            generate_gateway_svid(temp_a.path(), a_spiffe)
        };
        let backend_port = start_grpc_trailers_echo_backend().await;

        let cp_b =
            start_static_mesh_cp(egress_service_slice(&node_b, b_spiffe, backend_port)).await;
        let cp_a =
            start_static_mesh_cp(egress_service_slice(&node_a, b_spiffe, backend_port)).await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_transport_port = match topology {
            "sidecar" => ports_b.inbound,
            "ambient" => ports_b.hbone,
            other => return Err(format!("unsupported egress topology {other}")),
        };

        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(b_transport_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B transport listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            cp_a.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let mut a_env = vec![
            ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
            ("FERRUM_LOG_LEVEL", "debug".to_string()),
            ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                a_svid.trust_bundle_path.clone(),
            ),
        ];
        match topology {
            "sidecar" => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()));
                a_env.push(("FERRUM_MESH_EGRESS_MTLS_PORT", b_transport_port.to_string()));
            }
            _ => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "true".to_string()));
                a_env.push((
                    "FERRUM_MESH_EGRESS_HBONE_PORT",
                    b_transport_port.to_string(),
                ));
            }
        }
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                cp_addr: cp_a.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: a_env,
            },
        );
        if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway A outbound listener never bound\n{}",
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Poll the captured gRPC request. The route materialization and (on
        // Ambient) the capability probe race the first request, so early
        // responses can be route-miss rejects; poll until the caller's
        // convergence predicate accepts one or the deadline lapses. Negative
        // cases pass a predicate that never accepts and assert the FINAL state.
        let deadline = Instant::now() + Duration::from_secs(15);
        let last: Result<GrpcEgressResponse, String> = loop {
            let observed = grpc_egress_request(
                a_outbound_port,
                "svc-b.ferrum.svc.cluster.local",
                "/echo.Mesh/Call",
                &framed,
            )
            .await
            .map_err(|e| format!("gRPC egress request failed: {e}"));
            match observed {
                Ok(resp) if converged(&resp) => break Ok(resp),
                other => {
                    if Instant::now() >= deadline {
                        break other;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };

        let output_a = captured_output(&temp_a);
        let output_b = captured_output(&temp_b);
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        cp_a.shutdown().await;
        cp_b.shutdown().await;

        let logs = format!("--- gateway A ---\n{output_a}\n--- gateway B ---\n{output_b}");
        return match last {
            Ok(resp) => Ok((resp, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "gRPC egress gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// gRPC keystone (Sidecar, issue #2003): a captured native-gRPC request at
/// gateway A rides A's **SVID-mTLS HTTP/2 egress** (never the direct-dial gRPC
/// pool) to the gRPC backend behind gateway B, and the backend's REAL HTTP/2
/// trailers (`grpc-status`, custom trailer) survive the whole relay back to
/// point A's client — the mesh-mTLS path's `StreamingH2` arm preserves
/// trailers after hop-by-hop filtering.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_egress_grpc_routes_a_to_b_with_trailers() {
    let (resp, logs) = drive_grpc_egress_a_to_b("sidecar", true, |resp| {
        resp.status == 200
            && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")
            && resp
                .body
                .windows(b"ferrum-mesh-grpc-payload".len())
                .any(|w| w == b"ferrum-mesh-grpc-payload")
    })
    .await
    .expect("sidecar gRPC egress drive");
    assert_eq!(
        resp.status, 200,
        "the captured gRPC request must traverse A's SVID-mTLS egress to B's gRPC backend: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "the backend's grpc-status TRAILER must survive the mesh-mTLS relay: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("x-mesh-trailer").map(String::as_str),
        Some("echo-ok"),
        "custom (non-hop-by-hop) trailers must survive the mesh-mTLS relay: {resp:?}\n{logs}"
    );
    assert!(
        resp.body
            .windows(b"ferrum-mesh-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-grpc-payload"),
        "the echoed gRPC payload must ride the relayed DATA frames: {resp:?}\n{logs}"
    );
}

/// gRPC mTLS negative (Sidecar, issue #2003): an untrusted gateway A (SVID not
/// chaining to the mesh CA) must NEVER complete a gRPC call to B — the gRPC
/// dispatch rides the same verified SVID-mTLS transport as HTTP, so an
/// unverifiable peer fails closed instead of falling back to a direct dial.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_egress_grpc_rejects_untrusted_client_gateway() {
    let (resp, logs) = drive_grpc_egress_a_to_b("sidecar", false, |resp| {
        // Success shape must never be observed; poll to the deadline.
        resp.status == 200 && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")
    })
    .await
    .expect("untrusted gRPC egress drive");
    assert!(
        !(resp.status == 200 && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")),
        "an untrusted gateway's gRPC request must fail closed, not complete: {resp:?}\n{logs}"
    );
    assert!(
        !resp
            .body
            .windows(b"ferrum-mesh-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-grpc-payload"),
        "no backend payload may leak through an unverified mTLS session: {resp:?}\n{logs}"
    );
}

/// gRPC fail-closed (Ambient, issue #2003): a captured native-gRPC request to
/// an HBONE-tagged destination is refused BEFORE any dial with a Trailers-Only
/// gRPC UNAVAILABLE (HTTP 200 + `grpc-status: 14` in the response HEADERS) —
/// the HBONE inner protocol is HTTP/1.1 and cannot carry gRPC trailers, and a
/// direct plaintext dial would silently bypass the mesh transport. The refusal
/// must never converge to a completed call.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_egress_grpc_fails_closed_unavailable() {
    let (resp, logs) = drive_grpc_egress_a_to_b("ambient", true, |resp| {
        resp.status == 200 && resp.headers.get("grpc-status").map(String::as_str) == Some("14")
    })
    .await
    .expect("ambient gRPC fail-closed drive");
    assert_eq!(
        resp.status, 200,
        "the HBONE gRPC refusal rides HTTP 200 Trailers-Only encoding: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.headers.get("grpc-status").map(String::as_str),
        Some("14"),
        "gRPC to an HBONE-tagged target must fail closed with UNAVAILABLE: {resp:?}\n{logs}"
    );
    assert!(
        resp.body.is_empty(),
        "the fail-closed refusal must not carry any backend bytes (no dial happened): {resp:?}\n{logs}"
    );
}

// ── Cross-cluster east-west egress (Sidecar mesh-mTLS, two trust domains) ────

/// A minted SVID's on-disk cert/key paths. The issuing CA PEM is returned
/// separately by the minters (so the OTHER cluster's slice can federate this
/// CA's root for cross-trust-domain verification).
struct CrossClusterSvid {
    cert_path: String,
    key_path: String,
}

/// Mint a fresh CA and a leaf SVID carrying `spiffe_id`'s URI SAN under it,
/// writing the cert/key/bundle into `dir` under `prefix`. Returns the SVID
/// material + `(CA PEM, Issuer)` so additional leaves can be minted under the
/// SAME CA via [`mint_cross_cluster_svid_under`] (e.g. the east-west gateway B
/// and dest C both under cluster-B's CA).
fn mint_cross_cluster_svid(
    dir: &std::path::Path,
    prefix: &str,
    spiffe_id: &str,
) -> (
    CrossClusterSvid,
    (String, rcgen::Issuer<'static, rcgen::KeyPair>),
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
    params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.signed_by(&leaf_key, &issuer).expect("leaf cert");

    let cert_path = dir.join(format!("{prefix}-svid.crt"));
    let key_path = dir.join(format!("{prefix}-svid.key"));
    let bundle_path = dir.join(format!("{prefix}-bundle.pem"));
    std::fs::write(&cert_path, cert.pem()).expect("write svid cert");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write svid key");
    std::fs::write(&bundle_path, &ca_pem).expect("write trust bundle");
    let to_str = |p: PathBuf| p.to_str().expect("path utf8").to_string();
    (
        CrossClusterSvid {
            cert_path: to_str(cert_path),
            key_path: to_str(key_path),
        },
        (ca_pem, issuer),
    )
}

/// Mint a leaf SVID under an ALREADY-minted CA `issuer` (same trust domain), so
/// the east-west gateway and the destination workload can both chain to one
/// cluster CA. Writes cert/key/bundle and returns the SVID material.
fn mint_cross_cluster_svid_under(
    dir: &std::path::Path,
    prefix: &str,
    spiffe_id: &str,
    ca_pem: &str,
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
) -> CrossClusterSvid {
    use rcgen::{
        CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
    params
        .subject_alt_names
        .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.signed_by(&leaf_key, issuer).expect("leaf cert");

    let cert_path = dir.join(format!("{prefix}-svid.crt"));
    let key_path = dir.join(format!("{prefix}-svid.key"));
    let bundle_path = dir.join(format!("{prefix}-bundle.pem"));
    std::fs::write(&cert_path, cert.pem()).expect("write svid cert");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write svid key");
    std::fs::write(&bundle_path, ca_pem).expect("write trust bundle");
    let to_str = |p: PathBuf| p.to_str().expect("path utf8").to_string();
    CrossClusterSvid {
        cert_path: to_str(cert_path),
        key_path: to_str(key_path),
    }
}

/// Poll the complete destination path until the east-west listener accepts an
/// SNI-routed mTLS connection and the destination presents its expected SVID.
/// A bare TCP connect only proves that the passthrough listener has bound; this
/// probe also proves that its destination route is live and that the downstream
/// mesh listener has installed its server SVID before a test request is driven.
async fn wait_for_cross_cluster_destination_ready(
    east_west_port: u16,
    service_sni: &str,
    expected_destination_spiffe: &str,
    readiness_client_spiffe: &str,
    readiness_client_svid: &CrossClusterSvid,
    readiness_client_bundle_path: &std::path::Path,
    timeout: Duration,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;

    let bundle = ferrum_edge::identity::file_loader::load_svid_bundle_from_files(
        std::path::Path::new(&readiness_client_svid.cert_path),
        std::path::Path::new(&readiness_client_svid.key_path),
        readiness_client_bundle_path,
        Some(readiness_client_spiffe),
    )
    .map_err(|error| format!("load readiness client SVID: {error}"))?;
    let expected_client = SpiffeId::new(readiness_client_spiffe)
        .map_err(|error| format!("invalid readiness client SPIFFE ID: {error}"))?;
    if bundle.spiffe_id != expected_client {
        return Err(format!(
            "readiness client SVID '{}' does not match expected '{}'",
            bundle.spiffe_id, expected_client
        ));
    }
    let bundle_slot = Arc::new(ArcSwap::from_pointee(Some(bundle)));
    let expected_peer = SpiffeId::new(expected_destination_spiffe)
        .map_err(|error| format!("invalid destination SPIFFE ID: {error}"))?;
    let tls_config = ferrum_edge::tls::build_spiffe_outbound_config(
        bundle_slot,
        Some(expected_peer),
        None,
        vec![b"h2".to_vec()],
        Arc::new(Vec::new()),
    )
    .map_err(|error| format!("build readiness client TLS config: {error}"))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let deadline = Instant::now() + timeout;
    let mut last_error = "readiness probe did not run".to_string();

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "east-west destination did not become mTLS-ready: {last_error}"
            ));
        }

        let probe = async {
            let tcp = TcpStream::connect(("127.0.0.1", east_west_port))
                .await
                .map_err(|error| format!("connect east-west listener: {error}"))?;
            let server_name = rustls::pki_types::ServerName::try_from(service_sni.to_string())
                .map_err(|error| format!("invalid readiness SNI: {error}"))?;
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|error| format!("destination mTLS handshake: {error}"))?;

            // TLS 1.3 can surface a server-side client-auth rejection after the
            // client handshake future resolves. An accepted mesh listener stays
            // open waiting for HTTP/2 bytes; an alert/EOF is not readiness.
            let mut byte = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(250), tls.read(&mut byte)).await {
                Err(_) => Ok(()),
                Ok(Ok(0)) => Err("destination closed after the mTLS handshake".to_string()),
                Ok(Ok(_)) => Ok(()),
                Ok(Err(error)) => Err(format!("destination rejected readiness client: {error}")),
            }
        };

        match tokio::time::timeout(remaining.min(Duration::from_secs(5)), probe).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => last_error = error,
            Err(_) => last_error = "readiness probe timed out".to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Classify one cross-cluster HTTP attempt into an AUTHORITATIVE routed response
/// (`Ok`) versus a TRANSIENT setup / route-not-converged outcome (`Err`) to
/// retry. The two authoritative outcomes are a `200` backend success and the
/// live route's `502` `HBONE ... TLS handshake failed` mesh-mTLS rejection;
/// everything else — a connection/TLS-handshake establishment error or the
/// source gateway's route-miss / upstream-overflow statuses (404/503/bare 502)
/// while its outbound slice is still materializing — is transient. The
/// authoritative response is returned so the caller asserts it strictly, exactly
/// once. Shared by the positive (asserts `== 200`) and negative (asserts the
/// `502` rejection / `!= 200`) arms, preserving the round-1 negative signature so
/// neither retries an authoritative-but-wrong response.
fn classify_cross_cluster_http(
    result: Result<(u16, String), String>,
) -> Result<(u16, String), String> {
    match result {
        Ok((200, body)) => Ok((200, body)),
        Ok((502, body)) if body.contains(CROSS_CLUSTER_TLS_REJECTION_BODY) => Ok((502, body)),
        Ok((status, body)) => Err(format!("route not converged: HTTP {status}: {body:?}")),
        Err(error) => Err(format!("request error: {error}")),
    }
}

/// Poll a cross-cluster HTTP request until gateway A's outbound route converges
/// and returns an AUTHORITATIVE response (see [`classify_cross_cluster_http`]).
/// The FIRST authoritative response is returned so the caller asserts it
/// strictly, exactly once — a regression is never retried away — while only
/// transient route-miss / setup outcomes are retried until the route
/// materializes. Serves both the positive and negative arms.
async fn wait_for_authoritative_cross_cluster_http(
    outbound_port: u16,
    request_label: &str,
) -> Result<(u16, String), String> {
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;

    loop {
        let last_observation = match classify_cross_cluster_http(
            plaintext_http_get(outbound_port, "svc-c.ferrum.svc.cluster.local", "/")
                .await
                .map_err(|error| error.to_string()),
        ) {
            Ok((status, body)) => return Ok((status, body)),
            Err(transient) => transient,
        };

        if Instant::now() >= deadline {
            return Err(format!(
                "{request_label} route never reached an authoritative response within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last observation: {last_observation}"
            ));
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    }
}

fn is_authoritative_cross_cluster_grpc_rejection(response: &GrpcEgressResponse) -> bool {
    response.status == 200
        && response.headers.get("grpc-status").map(String::as_str) == Some("14")
        && response.headers.get("grpc-message").map(String::as_str)
            == Some("sidecar mTLS backend unavailable")
        && response.body.is_empty()
}

/// A cross-cluster gRPC route-miss emitted by the source gateway before its
/// outbound slice materializes. Two shapes qualify: the
/// `normalize_reject_response(NOT_FOUND, grpc=true)` Trailers-Only `grpc-status:
/// 5` (NOT_FOUND) with no backend body, or a bare HTTP route-miss /
/// upstream-overflow status (`404`/`503`/`502`) carrying NO gRPC trailers —
/// symmetric with [`classify_cross_cluster_http`]'s transient 404/503/bare-502
/// set. Any response that reached the routed / backend layer always carries a
/// `grpc-status` (the mesh-mTLS rejection uses `grpc-status: 14`; a backend
/// reply uses `grpc-status: 0`), so a genuinely routed-but-wrong result is never
/// classified as a route-miss and is asserted immediately instead of retried.
fn cross_cluster_grpc_is_route_miss(response: &GrpcEgressResponse) -> bool {
    let grpc_status = response
        .headers
        .get("grpc-status")
        .or_else(|| response.trailers.get("grpc-status"))
        .map(String::as_str);
    if response.status == 200 && grpc_status == Some("5") && response.body.is_empty() {
        return true;
    }
    matches!(response.status, 404 | 502 | 503) && grpc_status.is_none()
}

/// gRPC counterpart of [`wait_for_authoritative_cross_cluster_http`]. Retries
/// ONLY the source gateway's route-miss shapes (see
/// [`cross_cluster_grpc_is_route_miss`]) and connection/setup errors while A's
/// outbound slice materializes. EVERY response that reached the routed / backend
/// layer — the mesh-mTLS Trailers-Only UNAVAILABLE rejection, a backend success,
/// or a genuinely routed-but-wrong result (an unexpected `grpc-status`, a 5xx, a
/// missing trailer set) — is authoritative and returned so the caller asserts it
/// strictly, exactly once. A real regression therefore fails loudly instead of
/// being retried away into a timeout. Serves both the positive (asserts success)
/// and negative (asserts the rejection) arms, preserving the round-1 negative
/// signature.
async fn wait_for_authoritative_cross_cluster_grpc(
    outbound_port: u16,
    framed_body: &[u8],
) -> Result<GrpcEgressResponse, String> {
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;

    loop {
        let last_observation = match grpc_egress_request(
            outbound_port,
            "svc-c.ferrum.svc.cluster.local",
            "/echo.Mesh/Call",
            framed_body,
        )
        .await
        {
            Ok(response) if cross_cluster_grpc_is_route_miss(&response) => {
                format!("route not converged: {response:?}")
            }
            Ok(response) => return Ok(response),
            Err(error) => format!("request error: {error}"),
        };

        if Instant::now() >= deadline {
            return Err(format!(
                "cross-cluster gRPC route never reached an authoritative response within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last observation: {last_observation}"
            ));
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    }
}

/// True when a tungstenite handshake failure rendered by
/// [`format_ws_handshake_error`] is a `502` upgrade failure — the shape of the
/// live cross-cluster route's mesh-mTLS rejection. This matches on STATUS only.
/// The JSON marker body ([`CROSS_CLUSTER_TLS_REJECTION_BODY`]) may be ABSENT
/// even on a genuine rejection: our patched tungstenite client fills
/// `Error::Http`'s body from just the bytes already read after the response
/// headers (`vendor/tungstenite-0.29.0-ferrum-patched/src/handshake/client.rs`),
/// so a rejection whose JSON body lands in a later packet surfaces status-only.
/// Body presence is therefore NOT a reliable authoritative signal on its own —
/// [`wait_for_authoritative_cross_cluster_ws_path`] corroborates a status-only
/// `502` against the shared HTTP classifier before treating it as authoritative,
/// and still treats any non-`502` status as transient route-apply noise.
fn cross_cluster_ws_error_is_502(error: &str) -> bool {
    error.contains("HTTP status 502") || error.contains("HTTP error: 502")
}

/// Corroborate a status-only WebSocket `502` upgrade failure via the shared HTTP
/// classifier: issue ONE plaintext HTTP GET through the SAME outbound port and
/// cross-cluster route as the WebSocket upgrade. Unlike the tungstenite upgrade
/// path, the HTTP client drains the full response body, so
/// [`classify_cross_cluster_http`] deterministically distinguishes the live
/// route's authoritative `502` HBONE/mTLS handshake-failure rejection (body
/// carries [`CROSS_CLUSTER_TLS_REJECTION_BODY`]) from transient route-apply
/// noise. Returns `true` ONLY for that authoritative `502` rejection; a `200`
/// backend success or any transient route-miss / connection-setup outcome
/// returns `false`, so the WebSocket `502` stays transient and the caller keeps
/// polling. This never promotes a transient route-miss to authoritative, so it
/// cannot manufacture a vacuous negative pass.
async fn cross_cluster_route_http_rejection_confirmed(outbound_port: u16) -> bool {
    matches!(
        classify_cross_cluster_http(
            plaintext_http_get(outbound_port, "svc-c.ferrum.svc.cluster.local", "/")
                .await
                .map_err(|error| error.to_string()),
        ),
        Ok((502, _))
    )
}

/// Poll a cross-cluster WebSocket upgrade past A's route-apply window. A
/// completed upgrade (`Ok`) and the live route's authoritative 502 backend-dial
/// rejection are both returned immediately (the 502 as an `Err` carrying
/// [`CROSS_CLUSTER_WS_REJECTION_MARKER`]). A `502` counts as the authoritative
/// rejection when its body carries [`CROSS_CLUSTER_TLS_REJECTION_BODY`] OR, when
/// tungstenite surfaced the `502` status-only (body split into a later packet),
/// when [`cross_cluster_route_http_rejection_confirmed`] corroborates it via the
/// shared HTTP classifier on the same outbound route. Only route-miss / transient
/// upgrade failures — including a status-only 502 emitted while the route
/// materializes and NOT yet corroborated — are retried. The FIRST authoritative
/// outcome therefore cannot be retried away, so the positive arm fails loudly on
/// an unexpected rejection and the negative arm fails loudly on an unexpected
/// success (and never passes vacuously on a transient setup 502).
async fn wait_for_authoritative_cross_cluster_ws(
    outbound_port: u16,
    payload: &str,
) -> Result<String, String> {
    wait_for_authoritative_cross_cluster_ws_path(outbound_port, "/", payload).await
}

/// [`wait_for_authoritative_cross_cluster_ws`] on an arbitrary request path, for
/// the path-preservation positive drive.
async fn wait_for_authoritative_cross_cluster_ws_path(
    outbound_port: u16,
    path: &str,
    payload: &str,
) -> Result<String, String> {
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;

    loop {
        let last_observation = match mesh_websocket_echo_roundtrip_path(
            outbound_port,
            "svc-c.ferrum.svc.cluster.local",
            path,
            payload,
        )
        .await
        {
            Ok(reply) => return Ok(reply),
            Err(error) if cross_cluster_ws_error_is_502(&error) => {
                // A `502` upgrade failure is the shape of the live route's
                // mesh-mTLS rejection. When tungstenite captured the JSON marker
                // body we classify it directly; otherwise (the body split into a
                // packet the handshake read never saw) corroborate the rejection
                // via the shared HTTP classifier probe on the SAME outbound route
                // — which drains the full body — before treating the `502` as
                // authoritative. A `502` that neither carries the marker nor
                // corroborates is transient route-apply noise and is retried, so
                // a genuine rejection is never flaked away as a timeout and a
                // transient setup `502` never manufactures a vacuous pass.
                if error.contains(CROSS_CLUSTER_TLS_REJECTION_BODY)
                    || cross_cluster_route_http_rejection_confirmed(outbound_port).await
                {
                    return Err(format!("{CROSS_CLUSTER_WS_REJECTION_MARKER}: {error}"));
                }
                format!("transient WebSocket 502 while route converges: {error}")
            }
            Err(error) => error,
        };

        if Instant::now() >= deadline {
            return Err(format!(
                "cross-cluster WebSocket route never reached an authoritative response \
                 within {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last observation: {last_observation}"
            ));
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    }
}

/// A config-layer `TrustBundle` (base64 DER) for `trust_domain` from a CA PEM.
fn config_trust_bundle(trust_domain: &str, ca_pem: &str) -> TrustBundle {
    use base64::Engine;
    let der = ca_der_from_pem(ca_pem);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    TrustBundle {
        trust_domain: TrustDomain::new(trust_domain).expect("trust domain"),
        x509_authorities: vec![b64],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }
}

/// A `TrustBundleSet` with `local` = own CA and `federated` = the peer's CA, so
/// a slice can verify cross-trust-domain peers (set directly in the static
/// slice — no live federation poller in the functional test).
fn federated_trust_bundle_set(
    local_td: &str,
    local_ca_pem: &str,
    federated_td: &str,
    federated_ca_pem: &str,
) -> TrustBundleSet {
    TrustBundleSet {
        local: config_trust_bundle(local_td, local_ca_pem),
        federated: vec![config_trust_bundle(federated_td, federated_ca_pem)],
    }
}

/// Destination (gateway C) slice: Sidecar, trust domain B. Serves `svc-c`
/// inbound (STRICT mTLS) → the echo backend at `127.0.0.1:backend_port`. Its
/// `trust_bundles` federate cluster-A's CA so C's STRICT inbound accepts the
/// client A's SVID (trust domain A).
fn cross_cluster_dest_slice(
    node_id: &str,
    c_spiffe: &str,
    backend_port: u16,
    b_local_ca_pem: &str,
    a_ca_pem: &str,
) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "svc-c".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "svc-c".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            // C is the LOCAL workload here; leave cluster/network UNSET so
            // `workload_is_local` (SPIFFE + cluster match) recognizes it as local
            // and materializes the inbound loopback route. A mismatched `cluster`
            // (vs C's unset local cluster) would classify it non-local and skip
            // inbound materialization → 404.
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        trust_bundles: Some(federated_trust_bundle_set(
            "cluster-b.local",
            b_local_ca_pem,
            "cluster.local",
            a_ca_pem,
        )),
        ..MeshSlice::default()
    }
}

/// East-west gateway (B) slice: topology EastWestGateway, trust domain B. SNI
/// passthrough — its per-service inbound for `svc-c` forwards SNI=`svc-c` FQDN →
/// C's sidecar inbound listener at `127.0.0.1:c_inbound_port`.
///
/// TEST-REALISM MODELING (Codex round-1 finding #7 — NOT a client/datapath bug):
/// the CLIENT (gateway A) datapath is correct — it dials the east-west gateway
/// with the destination service FQDN as the ClientHello SNI, exactly as a real
/// cross-cluster sidecar would. In a real injected-sidecar destination, the
/// gateway forwards the opaque TLS to the destination workload's APP port, and
/// the destination pod's INBOUND iptables capture REDIRECTS that app-port traffic
/// to the sidecar's `:15006` mTLS listener (the same model same-cluster east-west
/// INBOUND uses — `build_east_west_service_targets` forwards to the workload
/// app/target port, NOT `:15006`). The functional test cannot run iptables, so it
/// COLLAPSES that destination-side redirect by modeling the service port (and the
/// east-west "workload" address) as C's sidecar inbound mTLS listener directly
/// (`c_inbound_port`) — so the passthrough lands straight on the listener that
/// terminates the client mTLS. This is a test-harness limitation, not a client
/// bug; the live two-cluster k8s fixture (Stage 2) exercises the realistic
/// app-port→`:15006` iptables path. See `docs/mesh.md` (cross-cluster east-west).
fn cross_cluster_east_west_slice(node_id: &str, c_spiffe: &str, c_inbound_port: u16) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        // The east-west passthrough forwards SNI → the service workload addr:port;
        // here that "workload" is C's INBOUND mTLS listener (modeling the
        // destination's inbound iptables redirect — see the fn doc).
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: "svc-c".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: c_inbound_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: c_inbound_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Client (gateway A) slice: Sidecar, trust domain A. Declares `svc-c` with a
/// REMOTE workload (network net-b, trust domain B) and a `MultiClusterConfig`
/// whose `EastWestGateway{network:net-b, host:127.0.0.1, port:b_east_west_port}`
/// fronts net-b. Its `trust_bundles` federate cluster-B's CA so A's outbound
/// (trust-domain-only) verification accepts C's server SVID (trust domain B).
fn cross_cluster_client_slice(
    node_id: &str,
    c_spiffe: &str,
    service_port: u16,
    b_east_west_port: u16,
    a_local_ca_pem: &str,
    b_ca_pem: &str,
) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        // The REMOTE workload of svc-c (trust domain B, network net-b). Its
        // address is a remote pod IP that must NEVER be dialed directly — the
        // cross-cluster target dials the east-west gateway instead.
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: "svc-c".to_string(),
            addresses: vec!["10.244.7.7".to_string()],
            ports: vec![WorkloadPort {
                port: service_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            network: Some("net-b".to_string()),
            cluster: Some("cluster-b".to_string()),
            weight: None,
            locality: Some("remote-cluster-b/net-b".to_string()),
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            // Authoritative remote marker (set by remote-poll ingestion in
            // production; set here directly so `workload_is_remote` classifies
            // it remote without a live discovery poll).
            remote_provenance: true,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: service_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            federation_endpoint: None,
            remote_clusters: Vec::new(),
            east_west_gateways: vec![EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "ferrum".to_string(),
                host: "127.0.0.1".to_string(),
                port: b_east_west_port,
                sni_hosts: vec!["svc-c.ferrum.svc.cluster.local".to_string()],
                trust_domain: Some(TrustDomain::new("cluster-b.local").expect("trust domain")),
                network: Some("net-b".to_string()),
            }],
        }),
        trust_bundles: Some(federated_trust_bundle_set(
            "cluster.local",
            a_local_ca_pem,
            "cluster-b.local",
            b_ca_pem,
        )),
        ..MeshSlice::default()
    }
}

/// Drive one captured app request from client gateway A across the east-west
/// gateway B to the echo backend behind dest gateway C, over two trust domains
/// with a federated bundle. `client_trusted` selects whether A's SVID chains to
/// a CA in C's federated trust set (the negative: an untrusted A must NOT reach
/// C's backend). Returns `(status, body, combined_logs)`.
async fn drive_cross_cluster_egress(client_trusted: bool) -> Result<(u16, String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let c_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/svc-c";
    let b_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/ew-gateway";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-mesh-xc-{trust_label}-a-{attempt}");
        let node_b = format!("functional-mesh-xc-{trust_label}-b-{attempt}");
        let node_c = format!("functional-mesh-xc-{trust_label}-c-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let temp_c = TempDir::new().map_err(|e| format!("temp dir c: {e}"))?;

        // Cluster-B CA backs both the east-west gateway B and the dest C.
        let (c_svid, b_ca) = mint_cross_cluster_svid(temp_c.path(), "gateway-c", c_spiffe);
        let b_ca_pem = b_ca.0.clone();
        let b_svid =
            mint_cross_cluster_svid_under(temp_b.path(), "gateway-b", b_spiffe, &b_ca_pem, &b_ca.1);

        // Cluster-A CA backs client A. A trusted A chains to its own CA, which
        // C federates; an UNTRUSTED A mints a separate CA that C does NOT
        // federate (and whose bundle does not contain B's CA), so both
        // directions of the handshake fail closed.
        let (a_svid, a_ca_pem) = {
            let (svid, ca) = mint_cross_cluster_svid(temp_a.path(), "gateway-a", a_spiffe);
            (svid, ca.0)
        };
        // The CA A's identity actually chains to (for C's federated set): the
        // trusted A federates A's real CA; the untrusted case federates a
        // DIFFERENT throwaway CA so C never trusts the real A.
        let a_ca_for_c_federation = if client_trusted {
            a_ca_pem.clone()
        } else {
            // A throwaway CA unrelated to A's SVID — C federates this, so A's
            // real SVID is rejected by C's STRICT inbound.
            let (_throwaway, throwaway_ca) = mint_cross_cluster_svid(
                temp_c.path(),
                "throwaway-a",
                "spiffe://cluster.local/ns/ferrum/sa/nobody",
            );
            throwaway_ca.0
        };
        // Symmetrically, the B CA A federates: the trusted A federates B's real
        // CA (so A accepts C's server SVID); the untrusted A federates a
        // throwaway so A also rejects C.
        let b_ca_for_a_federation = if client_trusted {
            b_ca_pem.clone()
        } else {
            let (_throwaway, throwaway_ca) = mint_cross_cluster_svid(
                temp_a.path(),
                "throwaway-b",
                "spiffe://cluster-b.local/ns/ferrum/sa/nobody",
            );
            throwaway_ca.0
        };

        let backend_port = start_echo_backend().await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let ports_c = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_east_west_port = ports_b.east_west;
        let c_inbound_port = ports_c.inbound;

        let cp_c = start_static_mesh_cp(cross_cluster_dest_slice(
            &node_c,
            c_spiffe,
            backend_port,
            &b_ca_pem,
            &a_ca_for_c_federation,
        ))
        .await;
        let cp_b = start_static_mesh_cp(cross_cluster_east_west_slice(
            &node_b,
            c_spiffe,
            c_inbound_port,
        ))
        .await;
        let cp_a = start_static_mesh_cp(cross_cluster_client_slice(
            &node_a,
            c_spiffe,
            backend_port,
            b_east_west_port,
            &a_ca_pem,
            &b_ca_for_a_federation,
        ))
        .await;

        // Gateway C (dest): serves svc-c inbound STRICT → echo backend.
        let mut child_c = spawn_mesh_gateway(
            &temp_c,
            MeshGatewaySpawnOptions {
                cp_addr: cp_c.addr,
                ports: ports_c,
                node_id: &node_c,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", c_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", c_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", c_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_c
                            .path()
                            .join("gateway-c-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(c_inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway C inbound listener never bound\n{}",
                captured_output(&temp_c)
            );
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Gateway B (east-west): SNI passthrough → C's inbound.
        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology: "east_west_gateway",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", b_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", b_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_b
                            .path()
                            .join("gateway-b-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(b_east_west_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B east-west listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }
        if let Err(error) = wait_for_cross_cluster_destination_ready(
            b_east_west_port,
            "svc-c.ferrum.svc.cluster.local",
            c_spiffe,
            b_spiffe,
            &b_svid,
            &temp_b.path().join("gateway-b-bundle.pem"),
            STARTUP_TIMEOUT,
        )
        .await
        {
            last_failure = format!(
                "attempt {attempt}: gateway B/C mTLS path never became ready: {error}\n\
                 --- gateway B ---\n{}\n--- gateway C ---\n{}",
                captured_output(&temp_b),
                captured_output(&temp_c)
            );
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Gateway A (client): outbound capture → cross-cluster egress route.
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                cp_addr: cp_a.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_LOG_LEVEL", "debug".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_a
                            .path()
                            .join("gateway-a-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway A outbound listener never bound\n{}",
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Both arms poll for A's FIRST authoritative routed response past the
        // outbound slice/route-apply window (the B/C readiness gate only proves
        // the B->C path is mTLS-ready, not that A's route has converged),
        // retrying only transient route-miss / setup outcomes. The trusted arm
        // then asserts `== 200` and the untrusted arm `!= 200`; neither can
        // retry an authoritative-but-wrong response, so a regression is never
        // hidden and a transient route miss never masquerades as fail-closed.
        let last =
            wait_for_authoritative_cross_cluster_http(a_outbound_port, "cross-cluster egress")
                .await;

        let output_a = captured_output(&temp_a);
        let output_b = captured_output(&temp_b);
        let output_c = captured_output(&temp_c);
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;

        let logs = format!(
            "--- gateway A (client) ---\n{output_a}\n--- gateway B (east-west) ---\n{output_b}\n\
             --- gateway C (dest) ---\n{output_c}"
        );
        return match last {
            Ok((status, body)) => Ok((status, body, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "cross-cluster gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Cross-cluster keystone (Sidecar mesh-mTLS): a captured plaintext request at
/// client gateway A (trust domain A) reaches the echo backend behind dest
/// gateway C (trust domain B) THROUGH the east-west gateway B — outbound capture
/// → materialized CROSS-CLUSTER egress target (dial the remote east-west gateway
/// with SNI = the destination service FQDN, TRUST-DOMAIN-ONLY peer verification)
/// → B's SNI passthrough → C's STRICT inbound (verifies A's client SVID via the
/// FEDERATED bundle) → materialized loopback route → C's backend → response back
/// to A.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_egress_routes_a_to_c_over_east_west() {
    let (status, body, logs) = drive_cross_cluster_egress(true)
        .await
        .expect("cross-cluster egress drive");
    assert_eq!(
        status, 200,
        "the captured request must traverse A's cross-cluster egress through the east-west \
         gateway to C's backend; body: {body:?}\n{logs}"
    );
    assert!(
        body.contains("backend-ok"),
        "the response must carry the destination backend body: {body:?}\n{logs}"
    );
}

/// Cross-cluster negative: a client gateway A whose SVID is NOT in the
/// destination's federated trust set must not reach C. C's STRICT inbound
/// rejects A's client cert (untrusted CA) and A rejects C's server SVID
/// (untrusted CA) — both fail the request closed, proving the cross-cluster
/// transport really verifies SVIDs against the federated bundle (trust-domain
/// membership, not blind tunneling) and never falls back to plaintext.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_egress_rejects_untrusted_client() {
    let (status, body, logs) = drive_cross_cluster_egress(false)
        .await
        .expect("untrusted cross-cluster egress drive");
    assert_ne!(
        status, 200,
        "an untrusted client gateway's cross-cluster request must fail closed, not reach \
         the destination backend\n{logs}"
    );
    assert!(
        !body.contains("backend-ok"),
        "no destination backend body may leak through an unverified cross-cluster mTLS \
         session: {body:?}\n{logs}"
    );
}

// ── Cross-cluster L7 app protocols (Sidecar mesh-mTLS): gRPC + WebSocket ──────
//
// The gRPC and WebSocket counterparts of the cross-cluster keystone above
// (issue #2010). Both ride the SAME three-gateway east-west fixture (client A
// sidecar → east-west B SNI-passthrough → dest C sidecar, two trust domains,
// federated bundle) and the SAME cross-cluster mesh-mTLS transport the HTTP
// keystone proved — the app protocol is a runtime flavor layered on top, so only
// the C-side backend and the driving request differ. The 3-gateway setup +
// SVID minting + bind-retry is factored into one fixture helper reusing the
// `cross_cluster_{dest,east_west,client}_slice` builders (the HTTP driver keeps
// its own inline copy so this change cannot regress the proven keystone path).

/// A running Sidecar cross-cluster east-west fixture: client A's outbound
/// capture port plus every child process / control plane / temp dir, so a driver
/// can drive app requests against `a_outbound_port` then tear it all down.
struct SidecarCrossClusterFixture {
    child_a: Child,
    child_b: Child,
    child_c: Child,
    cp_a: MeshCpHandle,
    cp_b: MeshCpHandle,
    cp_c: MeshCpHandle,
    // Held so the temp dirs (SVID material + gateway logs) outlive the run; read
    // by `logs()` and cleaned up on drop.
    temp_a: TempDir,
    temp_b: TempDir,
    temp_c: TempDir,
    a_outbound_port: u16,
}

impl SidecarCrossClusterFixture {
    /// Combined A/B/C gateway logs (read while the processes are still alive,
    /// before [`Self::shutdown`]).
    fn logs(&self) -> String {
        format!(
            "--- gateway A (client) ---\n{}\n--- gateway B (east-west) ---\n{}\n\
             --- gateway C (dest) ---\n{}",
            captured_output(&self.temp_a),
            captured_output(&self.temp_b),
            captured_output(&self.temp_c),
        )
    }

    async fn shutdown(mut self) {
        kill_child(&mut self.child_a);
        kill_child(&mut self.child_b);
        kill_child(&mut self.child_c);
        self.cp_a.shutdown().await;
        self.cp_b.shutdown().await;
        self.cp_c.shutdown().await;
    }
}

/// Start the three-gateway Sidecar cross-cluster fixture for one attempt, or
/// return `None` (after cleaning up) on any bind failure so the caller retries
/// with fresh ports/dirs. `backend_port` is C's already-spawned app backend (its
/// inbound loopback route targets it, and it drives the client/dest slice service
/// port), so gRPC / WebSocket / HTTP all share this identical topology.
async fn try_start_sidecar_cross_cluster_fixture(
    attempt: u32,
    client_trusted: bool,
    backend_port: u16,
) -> Option<SidecarCrossClusterFixture> {
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let c_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/svc-c";
    let b_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/ew-gateway";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };
    let node_a = format!("functional-mesh-xc-l7-{trust_label}-a-{attempt}");
    let node_b = format!("functional-mesh-xc-l7-{trust_label}-b-{attempt}");
    let node_c = format!("functional-mesh-xc-l7-{trust_label}-c-{attempt}");
    let temp_a = TempDir::new().ok()?;
    let temp_b = TempDir::new().ok()?;
    let temp_c = TempDir::new().ok()?;

    // Cluster-B CA backs both the east-west gateway B and the dest C; cluster-A
    // CA backs client A. The untrusted case federates throwaway CAs both ways so
    // neither side can verify the other (identical shape to the HTTP driver).
    let (c_svid, b_ca) = mint_cross_cluster_svid(temp_c.path(), "gateway-c", c_spiffe);
    let b_ca_pem = b_ca.0.clone();
    let b_svid =
        mint_cross_cluster_svid_under(temp_b.path(), "gateway-b", b_spiffe, &b_ca_pem, &b_ca.1);
    let (a_svid, a_ca_pem) = {
        let (svid, ca) = mint_cross_cluster_svid(temp_a.path(), "gateway-a", a_spiffe);
        (svid, ca.0)
    };
    let a_ca_for_c_federation = if client_trusted {
        a_ca_pem.clone()
    } else {
        mint_cross_cluster_svid(
            temp_c.path(),
            "throwaway-a",
            "spiffe://cluster.local/ns/ferrum/sa/nobody",
        )
        .1
        .0
    };
    let b_ca_for_a_federation = if client_trusted {
        b_ca_pem.clone()
    } else {
        mint_cross_cluster_svid(
            temp_a.path(),
            "throwaway-b",
            "spiffe://cluster-b.local/ns/ferrum/sa/nobody",
        )
        .1
        .0
    };

    let ports_a = reserve_mesh_ports().await;
    let ports_b = reserve_mesh_ports().await;
    let ports_c = reserve_mesh_ports().await;
    let a_outbound_port = ports_a.outbound;
    let b_east_west_port = ports_b.east_west;
    let c_inbound_port = ports_c.inbound;

    let cp_c = start_static_mesh_cp(cross_cluster_dest_slice(
        &node_c,
        c_spiffe,
        backend_port,
        &b_ca_pem,
        &a_ca_for_c_federation,
    ))
    .await;
    let cp_b = start_static_mesh_cp(cross_cluster_east_west_slice(
        &node_b,
        c_spiffe,
        c_inbound_port,
    ))
    .await;
    let cp_a = start_static_mesh_cp(cross_cluster_client_slice(
        &node_a,
        c_spiffe,
        backend_port,
        b_east_west_port,
        &a_ca_pem,
        &b_ca_for_a_federation,
    ))
    .await;

    // Gateway C (dest): serves svc-c inbound STRICT → the app backend.
    let mut child_c = spawn_mesh_gateway(
        &temp_c,
        MeshGatewaySpawnOptions {
            cp_addr: cp_c.addr,
            ports: ports_c,
            node_id: &node_c,
            config_protocol: "native",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", c_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", c_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", c_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_c
                        .path()
                        .join("gateway-c-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(c_inbound_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    // Gateway B (east-west): SNI passthrough → C's inbound.
    let mut child_b = spawn_mesh_gateway(
        &temp_b,
        MeshGatewaySpawnOptions {
            cp_addr: cp_b.addr,
            ports: ports_b,
            node_id: &node_b,
            config_protocol: "native",
            topology: "east_west_gateway",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", b_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", b_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_b
                        .path()
                        .join("gateway-b-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(b_east_west_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }
    if wait_for_cross_cluster_destination_ready(
        b_east_west_port,
        "svc-c.ferrum.svc.cluster.local",
        c_spiffe,
        b_spiffe,
        &b_svid,
        &temp_b.path().join("gateway-b-bundle.pem"),
        STARTUP_TIMEOUT,
    )
    .await
    .is_err()
    {
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    // Gateway A (client): outbound capture → cross-cluster egress route.
    let mut child_a = spawn_mesh_gateway(
        &temp_a,
        MeshGatewaySpawnOptions {
            cp_addr: cp_a.addr,
            ports: ports_a,
            node_id: &node_a,
            config_protocol: "native",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_LOG_LEVEL", "debug".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_a
                        .path()
                        .join("gateway-a-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    Some(SidecarCrossClusterFixture {
        child_a,
        child_b,
        child_c,
        cp_a,
        cp_b,
        cp_c,
        temp_a,
        temp_b,
        temp_c,
        a_outbound_port,
    })
}

/// Drive one captured native-gRPC request from client gateway A across the
/// east-west gateway B to the gRPC trailers-echo backend behind dest gateway C
/// (two trust domains, federated bundle). The trusted path sends exactly one
/// assertion-bearing call after the fixture's mTLS readiness gate; the
/// untrusted path additionally waits for A's live-route rejection signature.
async fn drive_cross_cluster_grpc_egress(
    client_trusted: bool,
) -> Result<(GrpcEgressResponse, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let payload = b"ferrum-mesh-xc-grpc-payload";
    let framed = grpc_framed_payload(payload);

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let backend_port = start_grpc_trailers_echo_backend().await;
        let Some(fixture) =
            try_start_sidecar_cross_cluster_fixture(attempt, client_trusted, backend_port).await
        else {
            last_failure = format!("attempt {attempt}: cross-cluster fixture never bound");
            continue;
        };

        // Both arms poll for A's FIRST authoritative gRPC response past the
        // route-apply window (only the NOT_FOUND route-miss / connection errors
        // are retried); the trusted arm asserts success and the untrusted arm
        // asserts the mesh-mTLS rejection, so neither retries an
        // authoritative-but-wrong response.
        let last =
            wait_for_authoritative_cross_cluster_grpc(fixture.a_outbound_port, &framed).await;

        let logs = fixture.logs();
        fixture.shutdown().await;
        return match last {
            Ok(resp) => Ok((resp, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "cross-cluster gRPC gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Cross-cluster gRPC keystone (Sidecar mesh-mTLS, issue #2010): a captured
/// native-gRPC request at client gateway A (trust domain A) reaches the gRPC
/// trailers-echo backend behind dest gateway C (trust domain B) THROUGH the
/// east-west gateway B — outbound capture → materialized CROSS-CLUSTER
/// `mesh.mtls` egress target (dial the remote east-west gateway with SNI = the
/// destination service FQDN, TRUST-DOMAIN-ONLY peer verification) → the SAME
/// mesh-mTLS `StreamingH2` relay the HTTP/gRPC path uses → B's SNI passthrough →
/// C's STRICT inbound → C's gRPC backend. The backend's REAL HTTP/2 trailers
/// (`grpc-status`, a custom trailer) survive the whole two-trust-domain relay, and
/// the remote workload pod IP (`10.244.7.7`) is NEVER dialed directly.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_grpc_routes_a_to_c_over_east_west_with_trailers() {
    let (resp, logs) = drive_cross_cluster_grpc_egress(true)
        .await
        .expect("cross-cluster gRPC egress drive");
    assert_eq!(
        resp.status, 200,
        "the captured gRPC request must traverse A's cross-cluster mesh-mTLS egress through the \
         east-west gateway to C's gRPC backend: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "the backend's grpc-status TRAILER must survive the cross-cluster mesh-mTLS relay: \
         {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("x-mesh-trailer").map(String::as_str),
        Some("echo-ok"),
        "custom (non-hop-by-hop) trailers must survive the cross-cluster relay: {resp:?}\n{logs}"
    );
    assert!(
        resp.body
            .windows(b"ferrum-mesh-xc-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-xc-grpc-payload"),
        "the echoed gRPC payload must ride the relayed DATA frames: {resp:?}\n{logs}"
    );
    // The remote pod IP is never dialed directly — the request rides the
    // east-west gateway. A direct dial of the unroutable 10.244.7.7 would have
    // failed the call; its success proves the gateway path was used.
    assert!(
        !logs.contains("10.244.7.7:"),
        "the remote workload pod IP must never be dialed directly (east-west only)\n{logs}"
    );
}

/// Cross-cluster gRPC negative (Sidecar mesh-mTLS, issue #2010): an untrusted
/// gateway A (SVID not in C's federated trust set) must NEVER complete a
/// cross-cluster gRPC call — the dispatch rides the SAME verified mesh-mTLS
/// transport as HTTP, so an unverifiable peer fails closed instead of falling
/// back to a direct dial of the remote workload.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_grpc_rejects_untrusted_client() {
    let (resp, logs) = drive_cross_cluster_grpc_egress(false)
        .await
        .expect("untrusted cross-cluster gRPC egress drive");
    assert!(
        is_authoritative_cross_cluster_grpc_rejection(&resp),
        "an untrusted gateway's live cross-cluster gRPC route must return the mesh-mTLS \
         Trailers-Only UNAVAILABLE rejection: {resp:?}\n{logs}"
    );
    assert!(
        !resp
            .body
            .windows(b"ferrum-mesh-xc-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-xc-grpc-payload"),
        "no backend payload may leak through an unverified cross-cluster mTLS session: \
         {resp:?}\n{logs}"
    );
}

/// Drive one captured WebSocket upgrade from client gateway A across the
/// east-west gateway B to the WS echo backend behind dest gateway C. Returns
/// `Ok((reply, logs))` on a completed roundtrip; `Err` when the upgrade never
/// completes (the expected fail-closed outcome for an untrusted A).
async fn drive_cross_cluster_ws_egress(client_trusted: bool) -> Result<(String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let backend_port = start_websocket_echo_backend().await;
        let Some(fixture) =
            try_start_sidecar_cross_cluster_fixture(attempt, client_trusted, backend_port).await
        else {
            last_failure = format!("attempt {attempt}: cross-cluster fixture never bound");
            continue;
        };

        // Both arms poll for A's FIRST authoritative WS outcome past the
        // route-apply window (only route-miss / transient upgrade failures are
        // retried); a completed upgrade or the live 502 rejection returns at
        // once, so the trusted arm fails loudly on an unexpected rejection and
        // the untrusted arm fails loudly on an unexpected success.
        let last =
            wait_for_authoritative_cross_cluster_ws(fixture.a_outbound_port, "mesh-xc-ws-hello")
                .await;

        let logs = fixture.logs();
        fixture.shutdown().await;
        return match last {
            Ok(reply) => Ok((reply, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "cross-cluster WS gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Cross-cluster WebSocket keystone (Sidecar mesh-mTLS, issue #2010): a
/// WebSocket upgrade captured at client gateway A reaches the WS echo backend
/// behind dest gateway C THROUGH the east-west gateway B, over an **RFC 8441
/// Extended CONNECT carried on the cross-cluster mesh-mTLS transport** (dial the
/// remote east-west gateway with SNI = the destination service FQDN,
/// TRUST-DOMAIN-ONLY peer verification — the same `MeshMtlsDialPlan` the HTTP
/// path resolves). B's SNI passthrough delivers the Extended CONNECT to C's
/// STRICT `:15006` inbound, which bridges it to the local WS app. Proves the WS
/// upgrade rides the SAME cross-cluster secured transport as HTTP/gRPC.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_ws_routes_a_to_c_over_east_west() {
    let (reply, logs) = drive_cross_cluster_ws_egress(true)
        .await
        .expect("cross-cluster websocket egress drive");
    assert!(
        reply.contains("backend-ws:mesh-xc-ws-hello"),
        "the WebSocket frame must traverse A's cross-cluster mesh-mTLS Extended CONNECT egress \
         through the east-west gateway to C's WS backend and echo back; reply: {reply:?}\n{logs}"
    );
}

/// Cross-cluster WebSocket negative (Sidecar mesh-mTLS, issue #2010): an
/// untrusted gateway A must not reach C's WS backend. The cross-cluster mesh-mTLS
/// dial underpinning the Extended CONNECT fails SVID verification (A rejects C's
/// server SVID; C's STRICT inbound rejects A's client cert), so the upgrade fails
/// closed — never a plaintext / wrong-SNI dial, never a backend frame.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_cross_cluster_ws_rejects_untrusted_client() {
    match drive_cross_cluster_ws_egress(false).await {
        Ok((reply, logs)) => panic!(
            "an untrusted gateway's cross-cluster WebSocket egress must reject the upgrade, not \
             establish a backend session: {reply:?}\n{logs}"
        ),
        Err(error) => assert!(
            error.contains(CROSS_CLUSTER_WS_REJECTION_MARKER),
            "the negative must reach the live route's authoritative mTLS rejection, not pass on \
             a transient route/setup failure: {error}"
        ),
    }
}

// ── Ambient (HBONE) cross-cluster east-west e2e ──────────────────────────────
//
// The HBONE counterpart of the Sidecar cross-cluster keystone above. Client A
// (Ambient) reaches the echo backend behind dest C (Ambient) THROUGH east-west
// gateway B. A's captured request materializes a PER-POD cross-cluster HBONE
// target (dial the remote east-west gateway over SVID-mTLS with the destination
// service FQDN as the outer-TLS SNI, the inner HBONE CONNECT `:authority` = the
// destination pod addr:app-port, TRUST-DOMAIN-ONLY peer verification). B's SNI
// passthrough delivers the outer TLS to C's HBONE :15008 listener; C's
// transparent HBONE relay (open-relay guard) dials the CONNECT authority → C's
// backend.

/// Destination (gateway C) slice for the Ambient cross-cluster path: Ambient
/// topology, trust domain B. Its workload addr:port (`127.0.0.1:backend_port`)
/// is the inner HBONE CONNECT `:authority` C's transparent relay dials under the
/// open-relay guard (loopback + a slice-declared workload port — so the
/// authority is admitted and reaches the echo backend). `trust_bundles` federate
/// cluster-A's CA so C's HBONE inbound peer-verifier accepts client A's SVID
/// (trust domain A). No materialized inbound routes (Ambient) — the relay handles
/// the CONNECT.
fn cross_cluster_ambient_dest_slice(
    node_id: &str,
    c_spiffe: &str,
    backend_port: u16,
    b_local_ca_pem: &str,
    a_ca_pem: &str,
) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "svc-c".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "svc-c".to_string(),
            // Loopback + the backend port — the inner CONNECT authority the relay
            // dials. Loopback passes the open-relay guard as long as a workload
            // declares the port; dialing it reaches the echo backend.
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        // STRICT inbound: the HBONE listener requires + verifies the peer SVID.
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        trust_bundles: Some(federated_trust_bundle_set(
            "cluster-b.local",
            b_local_ca_pem,
            "cluster.local",
            a_ca_pem,
        )),
        ..MeshSlice::default()
    }
}

/// East-west gateway (B) slice for the Ambient cross-cluster path: topology
/// EastWestGateway, trust domain B. SNI passthrough → C's HBONE :15008 listener
/// (`c_hbone_port`). The east-west "workload" addr:port models that listener.
///
/// TEST-REALISM MODELING (same as the Sidecar east-west slice — NOT a datapath
/// bug): a real cross-cluster Ambient client dials the east-west gateway with the
/// destination service FQDN as the outer-TLS SNI; the gateway forwards the opaque
/// TLS to the destination workload's HBONE listener. The functional test cannot
/// run a flat dest network / iptables, so it models the east-west "workload" as
/// C's HBONE listener directly (`c_hbone_port`) and (in the client slice) the
/// remote pod address as loopback, so the passthrough lands on C's HBONE
/// terminator and the inner CONNECT authority is a loopback port C can dial. The
/// live two-cluster fixture exercises the realistic pod-IP path.
fn cross_cluster_ambient_east_west_slice(
    node_id: &str,
    c_spiffe: &str,
    c_hbone_port: u16,
) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: "svc-c".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: c_hbone_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: c_hbone_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Client (gateway A) slice for the Ambient cross-cluster path: Ambient topology,
/// trust domain A. Declares `svc-c` with a REMOTE workload (network net-b, trust
/// domain B) whose address is LOOPBACK + the backend port (so the materialized
/// per-pod cross-cluster HBONE target's identity = the inner CONNECT authority
/// `127.0.0.1:backend_port`, which C's relay can dial under the open-relay
/// guard), and a `MultiClusterConfig` whose `EastWestGateway{network:net-b,
/// host:127.0.0.1, port:b_east_west_port}` fronts net-b. `trust_bundles` federate
/// cluster-B's CA so A's outbound (trust-domain-only) verification accepts C's
/// server SVID (trust domain B).
fn cross_cluster_ambient_client_slice(
    node_id: &str,
    c_spiffe: &str,
    backend_port: u16,
    b_east_west_port: u16,
    a_local_ca_pem: &str,
    b_ca_pem: &str,
) -> MeshSlice {
    let c_id = SpiffeId::new(c_spiffe).expect("c SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: c_id.clone(),
            selector: WorkloadSelector::default(),
            service_name: "svc-c".to_string(),
            // The remote pod address. In production this is a real remote pod IP
            // (slice-declared on both sides); the test collapses it to loopback +
            // the backend port so the inner CONNECT authority is a loopback port
            // C can dial (the in-cluster Ambient e2e collapses the same way).
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster-b.local").expect("trust domain"),
            namespace: "ferrum".to_string(),
            network: Some("net-b".to_string()),
            cluster: Some("cluster-b".to_string()),
            weight: None,
            locality: Some("remote-cluster-b/net-b".to_string()),
            service_account: Some("svc-c".to_string()),
            pod_uid: None,
            node_waypoint: None,
            // Authoritative remote marker (set by remote-poll ingestion in
            // production; set directly so `workload_is_remote` classifies it
            // remote without a live discovery poll).
            remote_provenance: true,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-c".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: backend_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: c_id }],
            protocol_overrides: HashMap::new(),
        }],
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            federation_endpoint: None,
            remote_clusters: Vec::new(),
            east_west_gateways: vec![EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "ferrum".to_string(),
                host: "127.0.0.1".to_string(),
                port: b_east_west_port,
                sni_hosts: vec!["svc-c.ferrum.svc.cluster.local".to_string()],
                trust_domain: Some(TrustDomain::new("cluster-b.local").expect("trust domain")),
                network: Some("net-b".to_string()),
            }],
        }),
        trust_bundles: Some(federated_trust_bundle_set(
            "cluster.local",
            a_local_ca_pem,
            "cluster-b.local",
            b_ca_pem,
        )),
        ..MeshSlice::default()
    }
}

/// Drive one captured app request from Ambient client gateway A across east-west
/// gateway B to the echo backend behind Ambient dest gateway C, over two trust
/// domains with a federated bundle, over HBONE. `client_trusted` selects whether
/// A's SVID chains to a CA in C's federated trust set (the negative: an untrusted
/// A must NOT reach C's backend). Returns `(status, body, combined_logs)`.
async fn drive_ambient_cross_cluster_egress(
    client_trusted: bool,
) -> Result<(u16, String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let c_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/svc-c";
    let b_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/ew-gateway";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-mesh-amb-xc-{trust_label}-a-{attempt}");
        let node_b = format!("functional-mesh-amb-xc-{trust_label}-b-{attempt}");
        let node_c = format!("functional-mesh-amb-xc-{trust_label}-c-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let temp_c = TempDir::new().map_err(|e| format!("temp dir c: {e}"))?;

        // Cluster-B CA backs both the east-west gateway B and the dest C.
        let (c_svid, b_ca) = mint_cross_cluster_svid(temp_c.path(), "gateway-c", c_spiffe);
        let b_ca_pem = b_ca.0.clone();
        let b_svid =
            mint_cross_cluster_svid_under(temp_b.path(), "gateway-b", b_spiffe, &b_ca_pem, &b_ca.1);

        let (a_svid, a_ca_pem) = {
            let (svid, ca) = mint_cross_cluster_svid(temp_a.path(), "gateway-a", a_spiffe);
            (svid, ca.0)
        };
        // The CA A actually chains to, for C's federated set: trusted federates
        // A's real CA; untrusted federates a DIFFERENT throwaway CA so C never
        // trusts the real A (both directions fail closed).
        let a_ca_for_c_federation = if client_trusted {
            a_ca_pem.clone()
        } else {
            let (_throwaway, throwaway_ca) = mint_cross_cluster_svid(
                temp_c.path(),
                "throwaway-a",
                "spiffe://cluster.local/ns/ferrum/sa/nobody",
            );
            throwaway_ca.0
        };
        let b_ca_for_a_federation = if client_trusted {
            b_ca_pem.clone()
        } else {
            let (_throwaway, throwaway_ca) = mint_cross_cluster_svid(
                temp_a.path(),
                "throwaway-b",
                "spiffe://cluster-b.local/ns/ferrum/sa/nobody",
            );
            throwaway_ca.0
        };

        let backend_port = start_echo_backend().await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let ports_c = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_east_west_port = ports_b.east_west;
        let c_hbone_port = ports_c.hbone;

        let cp_c = start_static_mesh_cp(cross_cluster_ambient_dest_slice(
            &node_c,
            c_spiffe,
            backend_port,
            &b_ca_pem,
            &a_ca_for_c_federation,
        ))
        .await;
        let cp_b = start_static_mesh_cp(cross_cluster_ambient_east_west_slice(
            &node_b,
            c_spiffe,
            c_hbone_port,
        ))
        .await;
        let cp_a = start_static_mesh_cp(cross_cluster_ambient_client_slice(
            &node_a,
            c_spiffe,
            backend_port,
            b_east_west_port,
            &a_ca_pem,
            &b_ca_for_a_federation,
        ))
        .await;

        // Gateway C (dest, Ambient): HBONE relay → echo backend.
        let mut child_c = spawn_mesh_gateway(
            &temp_c,
            MeshGatewaySpawnOptions {
                cp_addr: cp_c.addr,
                ports: ports_c,
                node_id: &node_c,
                config_protocol: "native",
                topology: "ambient",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", c_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", c_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", c_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_c
                            .path()
                            .join("gateway-c-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(c_hbone_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway C HBONE listener never bound\n{}",
                captured_output(&temp_c)
            );
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Gateway B (east-west): SNI passthrough → C's HBONE listener.
        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology: "east_west_gateway",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", b_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", b_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_b
                            .path()
                            .join("gateway-b-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(b_east_west_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B east-west listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }
        if let Err(error) = wait_for_cross_cluster_destination_ready(
            b_east_west_port,
            "svc-c.ferrum.svc.cluster.local",
            c_spiffe,
            b_spiffe,
            &b_svid,
            &temp_b.path().join("gateway-b-bundle.pem"),
            STARTUP_TIMEOUT,
        )
        .await
        {
            last_failure = format!(
                "attempt {attempt}: ambient gateway B/C mTLS path never became ready: {error}\n\
                 --- gateway B ---\n{}\n--- gateway C ---\n{}",
                captured_output(&temp_b),
                captured_output(&temp_c)
            );
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Gateway A (client, Ambient): outbound capture → cross-cluster HBONE
        // egress route. Warmup is OFF: the cross-cluster HBONE path BYPASSES the
        // capability registry (it dials the gateway :15443, not a probeable
        // :15008 workload), so no probe is needed — and a probe to the east-west
        // gateway would not classify it.
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                cp_addr: cp_a.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "native",
                topology: "ambient",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_LOG_LEVEL", "debug".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        temp_a
                            .path()
                            .join("gateway-a-bundle.pem")
                            .to_str()
                            .expect("bundle path utf8")
                            .to_string(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway A outbound listener never bound\n{}",
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

        // Both arms poll for A's FIRST authoritative routed response past the
        // outbound route-apply window, retrying only transient route-miss / setup
        // outcomes; the trusted arm asserts `== 200` and the untrusted `!= 200`,
        // so neither retries an authoritative-but-wrong response and a transient
        // route miss never masquerades as fail-closed.
        let last = wait_for_authoritative_cross_cluster_http(
            a_outbound_port,
            "ambient cross-cluster egress",
        )
        .await;

        let output_a = captured_output(&temp_a);
        let output_b = captured_output(&temp_b);
        let output_c = captured_output(&temp_c);
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;

        let logs = format!(
            "--- gateway A (client) ---\n{output_a}\n--- gateway B (east-west) ---\n{output_b}\n\
             --- gateway C (dest) ---\n{output_c}"
        );
        return match last {
            Ok((status, body)) => Ok((status, body, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "ambient cross-cluster gateways never bound their listeners after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    ))
}

/// Cross-cluster keystone (Ambient HBONE): a captured plaintext request at
/// Ambient client gateway A (trust domain A) reaches the echo backend behind
/// Ambient dest gateway C (trust domain B) THROUGH east-west gateway B —
/// outbound capture → materialized PER-POD CROSS-CLUSTER HBONE target (dial the
/// remote east-west gateway over SVID-mTLS with the destination service FQDN as
/// the outer-TLS SNI, the inner HBONE CONNECT `:authority` = the destination pod
/// addr:app-port, TRUST-DOMAIN-ONLY peer verification) → B's SNI passthrough →
/// C's HBONE :15008 listener (verifies A's client SVID via the FEDERATED bundle)
/// → C's transparent relay (open-relay guard) → C's backend → response back to A.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_cross_cluster_egress_routes_a_to_c_over_east_west() {
    let (status, body, logs) = drive_ambient_cross_cluster_egress(true)
        .await
        .expect("ambient cross-cluster egress drive");
    assert_eq!(
        status, 200,
        "the captured request must traverse A's cross-cluster HBONE egress through the east-west \
         gateway to C's backend; body: {body:?}\n{logs}"
    );
    assert!(
        body.contains("backend-ok"),
        "the response must carry the destination backend body: {body:?}\n{logs}"
    );
}

/// Cross-cluster negative (Ambient HBONE): a client gateway A whose SVID is NOT
/// in the destination's federated trust set must not reach C. C's HBONE inbound
/// rejects A's client cert (untrusted CA) and A rejects C's server SVID
/// (untrusted CA) — both fail the request closed, proving the cross-cluster HBONE
/// transport really verifies SVIDs against the federated bundle (trust-domain
/// membership, not blind tunneling) and never falls back to plaintext.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_cross_cluster_egress_rejects_untrusted_client() {
    let (status, body, logs) = drive_ambient_cross_cluster_egress(false)
        .await
        .expect("untrusted ambient cross-cluster egress drive");
    assert_ne!(
        status, 200,
        "an untrusted client gateway's cross-cluster HBONE request must fail closed, not reach \
         the destination backend\n{logs}"
    );
    assert!(
        !body.contains("backend-ok"),
        "no destination backend body may leak through an unverified cross-cluster HBONE \
         session: {body:?}\n{logs}"
    );
}

// ── Cross-cluster WebSocket (Ambient HBONE) ──────────────────────────────────
//
// The WebSocket counterpart of the Ambient cross-cluster keystone (issue #2010):
// the WS upgrade rides the SAME per-pod cross-cluster HBONE byte tunnel the HTTP
// path proved (dial the remote east-west gateway with the destination service
// FQDN as the outer-TLS SNI + trust-domain-only verification; inner CONNECT
// `:authority` = the destination pod addr:app-port), with an inner HTTP/1.1
// WebSocket handshake spoken THROUGH the tunnel to C's transparent HBONE relay.
// Only the backend + driving request differ from the HTTP driver, so the
// three-gateway Ambient setup is factored into one fixture helper.

/// A running Ambient cross-cluster east-west fixture (client A Ambient →
/// east-west B SNI-passthrough → dest C Ambient, two trust domains, federated
/// bundle) — the Ambient counterpart of [`SidecarCrossClusterFixture`].
struct AmbientCrossClusterFixture {
    child_a: Child,
    child_b: Child,
    child_c: Child,
    cp_a: MeshCpHandle,
    cp_b: MeshCpHandle,
    cp_c: MeshCpHandle,
    temp_a: TempDir,
    temp_b: TempDir,
    temp_c: TempDir,
    a_outbound_port: u16,
}

impl AmbientCrossClusterFixture {
    fn logs(&self) -> String {
        format!(
            "--- gateway A (client) ---\n{}\n--- gateway B (east-west) ---\n{}\n\
             --- gateway C (dest) ---\n{}",
            captured_output(&self.temp_a),
            captured_output(&self.temp_b),
            captured_output(&self.temp_c),
        )
    }

    async fn shutdown(mut self) {
        kill_child(&mut self.child_a);
        kill_child(&mut self.child_b);
        kill_child(&mut self.child_c);
        self.cp_a.shutdown().await;
        self.cp_b.shutdown().await;
        self.cp_c.shutdown().await;
    }
}

/// Start the three-gateway Ambient cross-cluster fixture for one attempt, or
/// return `None` (after cleaning up) on any bind failure. `backend_port` is C's
/// already-spawned app backend (its HBONE relay open-relay guard admits the
/// loopback workload addr:port), so HTTP / WebSocket share this topology.
async fn try_start_ambient_cross_cluster_fixture(
    attempt: u32,
    client_trusted: bool,
    backend_port: u16,
) -> Option<AmbientCrossClusterFixture> {
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let c_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/svc-c";
    let b_spiffe = "spiffe://cluster-b.local/ns/ferrum/sa/ew-gateway";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };
    let node_a = format!("functional-mesh-amb-xc-ws-{trust_label}-a-{attempt}");
    let node_b = format!("functional-mesh-amb-xc-ws-{trust_label}-b-{attempt}");
    let node_c = format!("functional-mesh-amb-xc-ws-{trust_label}-c-{attempt}");
    let temp_a = TempDir::new().ok()?;
    let temp_b = TempDir::new().ok()?;
    let temp_c = TempDir::new().ok()?;

    let (c_svid, b_ca) = mint_cross_cluster_svid(temp_c.path(), "gateway-c", c_spiffe);
    let b_ca_pem = b_ca.0.clone();
    let b_svid =
        mint_cross_cluster_svid_under(temp_b.path(), "gateway-b", b_spiffe, &b_ca_pem, &b_ca.1);
    let (a_svid, a_ca_pem) = {
        let (svid, ca) = mint_cross_cluster_svid(temp_a.path(), "gateway-a", a_spiffe);
        (svid, ca.0)
    };
    let a_ca_for_c_federation = if client_trusted {
        a_ca_pem.clone()
    } else {
        mint_cross_cluster_svid(
            temp_c.path(),
            "throwaway-a",
            "spiffe://cluster.local/ns/ferrum/sa/nobody",
        )
        .1
        .0
    };
    let b_ca_for_a_federation = if client_trusted {
        b_ca_pem.clone()
    } else {
        mint_cross_cluster_svid(
            temp_a.path(),
            "throwaway-b",
            "spiffe://cluster-b.local/ns/ferrum/sa/nobody",
        )
        .1
        .0
    };

    let ports_a = reserve_mesh_ports().await;
    let ports_b = reserve_mesh_ports().await;
    let ports_c = reserve_mesh_ports().await;
    let a_outbound_port = ports_a.outbound;
    let b_east_west_port = ports_b.east_west;
    let c_hbone_port = ports_c.hbone;

    let cp_c = start_static_mesh_cp(cross_cluster_ambient_dest_slice(
        &node_c,
        c_spiffe,
        backend_port,
        &b_ca_pem,
        &a_ca_for_c_federation,
    ))
    .await;
    let cp_b = start_static_mesh_cp(cross_cluster_ambient_east_west_slice(
        &node_b,
        c_spiffe,
        c_hbone_port,
    ))
    .await;
    let cp_a = start_static_mesh_cp(cross_cluster_ambient_client_slice(
        &node_a,
        c_spiffe,
        backend_port,
        b_east_west_port,
        &a_ca_pem,
        &b_ca_for_a_federation,
    ))
    .await;

    // Gateway C (dest, Ambient): HBONE relay → the app backend.
    let mut child_c = spawn_mesh_gateway(
        &temp_c,
        MeshGatewaySpawnOptions {
            cp_addr: cp_c.addr,
            ports: ports_c,
            node_id: &node_c,
            config_protocol: "native",
            topology: "ambient",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", c_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", c_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", c_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_c
                        .path()
                        .join("gateway-c-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(c_hbone_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    // Gateway B (east-west): SNI passthrough → C's HBONE listener.
    let mut child_b = spawn_mesh_gateway(
        &temp_b,
        MeshGatewaySpawnOptions {
            cp_addr: cp_b.addr,
            ports: ports_b,
            node_id: &node_b,
            config_protocol: "native",
            topology: "east_west_gateway",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", b_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", b_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_b
                        .path()
                        .join("gateway-b-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(b_east_west_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }
    if wait_for_cross_cluster_destination_ready(
        b_east_west_port,
        "svc-c.ferrum.svc.cluster.local",
        c_spiffe,
        b_spiffe,
        &b_svid,
        &temp_b.path().join("gateway-b-bundle.pem"),
        STARTUP_TIMEOUT,
    )
    .await
    .is_err()
    {
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    // Gateway A (client, Ambient): outbound capture → cross-cluster HBONE egress.
    let mut child_a = spawn_mesh_gateway(
        &temp_a,
        MeshGatewaySpawnOptions {
            cp_addr: cp_a.addr,
            ports: ports_a,
            node_id: &node_a,
            config_protocol: "native",
            topology: "ambient",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_LOG_LEVEL", "debug".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    temp_a
                        .path()
                        .join("gateway-a-bundle.pem")
                        .to_str()
                        .expect("bundle path utf8")
                        .to_string(),
                ),
            ],
        },
    );
    if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        kill_child(&mut child_c);
        cp_a.shutdown().await;
        cp_b.shutdown().await;
        cp_c.shutdown().await;
        return None;
    }

    Some(AmbientCrossClusterFixture {
        child_a,
        child_b,
        child_c,
        cp_a,
        cp_b,
        cp_c,
        temp_a,
        temp_b,
        temp_c,
        a_outbound_port,
    })
}

/// Drive one captured WebSocket upgrade from Ambient client gateway A across the
/// east-west gateway B to the WS echo backend behind Ambient dest gateway C.
/// Returns `Ok((reply, logs))` on a completed roundtrip; `Err` when the upgrade
/// never completes (the expected fail-closed outcome for an untrusted A).
async fn drive_ambient_cross_cluster_ws_egress(
    client_trusted: bool,
) -> Result<(String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let backend_port = start_websocket_echo_backend().await;
        let Some(fixture) =
            try_start_ambient_cross_cluster_fixture(attempt, client_trusted, backend_port).await
        else {
            last_failure = format!("attempt {attempt}: ambient cross-cluster fixture never bound");
            continue;
        };

        // Both arms poll for A's FIRST authoritative WS outcome past the
        // route-apply window (only route-miss / transient upgrade failures are
        // retried); the trusted arm fails loudly on an unexpected rejection and
        // the untrusted arm fails loudly on an unexpected success.
        let last = wait_for_authoritative_cross_cluster_ws(
            fixture.a_outbound_port,
            "mesh-amb-xc-ws-hello",
        )
        .await;

        let logs = fixture.logs();
        fixture.shutdown().await;
        return match last {
            Ok(reply) => Ok((reply, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "ambient cross-cluster WS gateways never bound their listeners after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    ))
}

/// Cross-cluster WebSocket keystone (Ambient HBONE, issue #2010): a WebSocket
/// upgrade captured at Ambient client gateway A reaches the WS echo backend
/// behind Ambient dest gateway C THROUGH east-west gateway B, over the per-pod
/// cross-cluster HBONE byte tunnel (dial the remote east-west gateway with the
/// destination service FQDN as the outer-TLS SNI + trust-domain-only
/// verification; inner CONNECT `:authority` = the destination pod addr:app-port)
/// with an inner HTTP/1.1 WebSocket handshake spoken THROUGH the tunnel to C's
/// transparent HBONE relay. Proves Ambient cross-cluster WS rides the SAME
/// secured transport as the HTTP path.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_cross_cluster_ws_routes_a_to_c_over_east_west() {
    let (reply, logs) = drive_ambient_cross_cluster_ws_egress(true)
        .await
        .expect("ambient cross-cluster websocket egress drive");
    assert!(
        reply.contains("backend-ws:mesh-amb-xc-ws-hello"),
        "the WebSocket frame must traverse A's cross-cluster HBONE byte-tunnel egress through the \
         east-west gateway to C's WS backend and echo back; reply: {reply:?}\n{logs}"
    );
}

/// Cross-cluster WebSocket negative (Ambient HBONE, issue #2010): an untrusted
/// gateway A must not reach C's WS backend. The cross-cluster HBONE dial
/// underpinning the byte tunnel fails SVID verification (A rejects C's server
/// SVID; C's HBONE listener rejects A's client cert), so the upgrade fails
/// closed — never a plaintext / wrong-SNI dial, never a backend frame.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_cross_cluster_ws_rejects_untrusted_client() {
    match drive_ambient_cross_cluster_ws_egress(false).await {
        Ok((reply, logs)) => panic!(
            "an untrusted gateway's cross-cluster Ambient WebSocket egress must reject the \
             upgrade, not establish a backend session: {reply:?}\n{logs}"
        ),
        Err(error) => assert!(
            error.contains(CROSS_CLUSTER_WS_REJECTION_MARKER),
            "the negative must reach the live route's authoritative mTLS rejection, not pass on \
             a transient route/setup failure: {error}"
        ),
    }
}

/// Cross-cluster Ambient WS egress driver that drives a NON-ROOT request path
/// (`/ws/echo?room=42`) against a path-capturing WS echo backend, then returns
/// the echoed reply (which embeds the path the backend actually observed).
/// Mirrors [`drive_ambient_cross_cluster_ws_egress`] but with the path-echo
/// backend so the test can assert the client `:path` is preserved through the
/// cross-cluster HBONE byte tunnel (issue #2010 codex Finding 1).
async fn drive_ambient_cross_cluster_ws_path_egress() -> Result<(String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;

    const CLIENT_PATH: &str = "/ws/echo?room=42";
    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let backend_port = start_websocket_path_echo_backend().await;
        let Some(fixture) =
            try_start_ambient_cross_cluster_fixture(attempt, true, backend_port).await
        else {
            last_failure = format!("attempt {attempt}: ambient cross-cluster fixture never bound");
            continue;
        };

        // Poll for A's FIRST authoritative WS outcome on the non-root path past
        // the route-apply window, retrying only transient route-miss / upgrade
        // failures so the positive path-preservation assertion runs exactly once.
        let last = wait_for_authoritative_cross_cluster_ws_path(
            fixture.a_outbound_port,
            CLIENT_PATH,
            "mesh-amb-xc-ws-path-hello",
        )
        .await;

        let logs = fixture.logs();
        fixture.shutdown().await;
        return match last {
            Ok(reply) => Ok((reply, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "ambient cross-cluster WS path gateways never bound their listeners after \
         {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Cross-cluster WebSocket PATH-PRESERVATION regression (Ambient HBONE, issue
/// #2010 codex Finding 1): a WebSocket upgrade to a non-root path
/// (`/ws/echo?room=42`) must reach C's backend on THAT EXACT path — not `/`.
/// Before the fix, the caller derived `path_and_query` by parsing a backend URL
/// whose authority was the cross-cluster scoped synthetic `mesh-xc-hbone|...`
/// host; that authority is not a valid URI, so the parse failed and the path
/// silently collapsed to `/`, upgrading every cross-cluster WS endpoint against
/// the root. The fix rewrites the authority to the real pod addr
/// (`mesh.hbone_authority_host`) before parsing (mirroring `proxy_to_backend_hbone`),
/// so the client path survives. The path-echo backend echoes the path it
/// observed, so this asserts the exact non-root path arrived.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_cross_cluster_ws_preserves_request_path() {
    let (reply, logs) = drive_ambient_cross_cluster_ws_path_egress()
        .await
        .expect("ambient cross-cluster websocket path-preservation egress drive");
    // The echoed reply is `backend-ws-path:<observed_path>:<text>`; the observed
    // path MUST be the full non-root client target, proving it was not collapsed
    // to `/` by the synthetic-host URL parse failure.
    assert!(
        reply.contains("backend-ws-path:/ws/echo?room=42:mesh-amb-xc-ws-path-hello"),
        "the cross-cluster Ambient WS upgrade must reach the backend on the exact client path \
         `/ws/echo?room=42` (not `/`); reply: {reply:?}\n{logs}"
    );
    // Guard against a false pass if the path ever silently degrades to root.
    assert!(
        !reply.contains("backend-ws-path:/:"),
        "the cross-cluster Ambient WS path must not collapse to `/`; reply: {reply:?}\n{logs}"
    );
}

/// Cross-cluster WebSocket HOST-FALLBACK regression (Ambient HBONE, issue #2010
/// codex round 2): with a route that does NOT preserve the client Host
/// (`preserve_host_header == false`, as ordinary gateway/SD proxies use) — or a
/// client that sends no Host at all — the inner WebSocket handshake `Host` must
/// fall back to the REAL destination pod addr (`app_host`, from
/// `mesh.hbone_authority_host`), NOT to `target.host`.
///
/// For a cross-cluster target `target.host` is the scoped synthetic
/// `mesh-xc-hbone|...` identity, which is not a valid URI authority, so a
/// `target.host` fallback would build `ws://mesh-xc-hbone|...` and
/// `into_client_request()` would ABORT the upgrade AFTER the HBONE tunnel is
/// already established. The fix carries `app_host` into that fallback (mirroring
/// `proxy_to_backend_hbone`, whose backend Host is `app_host` when the client
/// Host is not preserved), so the WS URI stays valid and the upgrade completes.
///
/// This asserts the exact selection performed at the inner-request build site in
/// `connect_mesh_websocket_backend` via the shared `hbone_ws_inner_host` helper.
/// It is a focused-logic regression rather than a full A→B→C e2e because mesh
/// materialization hardwires the outbound egress route to
/// `preserve_host_header = true` (and outbound routing requires the Host), so no
/// mesh fixture can drive the `preserve_host_header == false` branch end-to-end;
/// the helper is the single source of the Host used by both the WS byte-tunnel
/// handshake and the parallel `proxy_to_backend_hbone` relay. Mirrors the
/// `functional_mesh_ambient_cross_cluster_ws_*` fixture's cross-cluster shape
/// (synthetic `mesh-xc-hbone|...` host + real pod `app_host`). CI-validated
/// (not run locally under this change).
#[test]
fn functional_mesh_ambient_cross_cluster_ws_host_fallback_uses_app_host() {
    use ferrum_edge::proxy::hbone_pool::hbone_ws_inner_host;

    // Cross-cluster shape: `target.host` is the scoped synthetic identity that is
    // NOT a valid URI authority; `app_host` is the real remote pod addr the dest
    // relay dials (what `mesh.hbone_authority_host` carries in production).
    let synthetic_target_host = "mesh-xc-hbone|10.9.9.9|15443|10.244.5.5";
    let app_host = "10.244.5.5";
    let port = 8080u16;

    // preserve_host_header == false + a present client Host ⇒ fallback to
    // `app_host` (the fixed behavior), never the synthetic `target.host`.
    let inner = hbone_ws_inner_host(
        Some("svc-c.ferrum.svc.cluster.local"),
        false,
        app_host,
        port,
    );
    assert_eq!(
        inner, "10.244.5.5:8080",
        "with preserve_host_header=false the cross-cluster WS inner Host must be the real pod \
         app_host, so `ws://{inner}` is a valid upgrade URI"
    );
    assert!(
        !inner.contains(synthetic_target_host),
        "the cross-cluster WS inner Host must never fall back to the synthetic `target.host` \
         (`{synthetic_target_host}`), which is an invalid WS URI authority"
    );

    // No client Host (client omitted it) ⇒ same `app_host` fallback regardless of
    // preserve_host_header, so the upgrade URI is still valid.
    assert_eq!(
        hbone_ws_inner_host(None, true, app_host, port),
        "10.244.5.5:8080",
        "an absent client Host must fall back to the real pod app_host"
    );
    assert_eq!(
        hbone_ws_inner_host(Some(""), true, app_host, port),
        "10.244.5.5:8080",
        "an empty client Host must fall back to the real pod app_host"
    );

    // preserve_host_header == true + a real client Host ⇒ the client Host rides
    // through unchanged (the existing preserved-Host path, unregressed).
    assert_eq!(
        hbone_ws_inner_host(Some("svc-c.ferrum.svc.cluster.local"), true, app_host, port),
        "svc-c.ferrum.svc.cluster.local",
        "a preserved non-empty client Host must ride through unchanged"
    );

    // IN-CLUSTER invariant: `app_host == target.host` (no authority-host tag), so
    // the fallback is byte-identical to the pre-fix `target.host` behavior.
    let in_cluster_host = "orders.default.svc.cluster.local";
    assert_eq!(
        hbone_ws_inner_host(None, false, in_cluster_host, port),
        "orders.default.svc.cluster.local:8080",
        "in-cluster targets (app_host == target.host) keep the prior fallback byte-for-byte"
    );
}

// ── Localized file config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`) ────────

/// JSON mesh document equivalent of `inbound_authz_slice`: the same routing +
/// authz content, but expressed as the file source's `{ "mesh": ... }`
/// document so the data plane builds the slice locally.
fn inbound_authz_mesh_document(
    server_spiffe: &str,
    client_spiffe: &str,
    backend_port: u16,
    allow: bool,
) -> String {
    let slice = inbound_authz_slice("unused", server_spiffe, client_spiffe, backend_port, allow);
    let mesh = MeshConfig {
        workloads: slice.workloads,
        services: slice.services,
        peer_authentications: slice.peer_authentications,
        mesh_policies: slice.mesh_policies,
        ..MeshConfig::default()
    };
    serde_json::to_string(&serde_json::json!({ "mesh": mesh })).expect("mesh document serializes")
}

/// Keystone for the localized file source: a mesh data plane with **no control
/// plane** loads its slice from disk, materializes the sidecar inbound route,
/// serves an authorized peer's mTLS request to the co-located backend, and
/// hot-applies a DENY policy when the document changes and SIGHUP arrives —
/// all through the same datapath the native/xDS keystones exercise.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_mesh_file_source_serves_inbound_and_reloads_on_sighup() {
    ensure_gateway_built().expect("gateway build");
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";

    let mut last_failure = String::new();
    'attempts: for attempt in 1..=RETRY_ATTEMPTS {
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let backend_port = start_echo_backend().await;

        let mesh_doc_path = temp.path().join("mesh.json");
        std::fs::write(
            &mesh_doc_path,
            inbound_authz_mesh_document(server_spiffe, client_spiffe, backend_port, true),
        )
        .expect("write mesh document");
        let mesh_doc_env = mesh_doc_path
            .to_str()
            .expect("mesh document path is UTF-8")
            .to_string();

        let ports = reserve_mesh_ports().await;
        let inbound_port = ports.inbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                // The file protocol consumes no CP; the harness's default
                // FERRUM_DP_CP_GRPC_URLS points at a dead port and must be
                // ignored by the file source.
                cp_addr: "127.0.0.1:1".parse().expect("dummy addr"),
                ports,
                node_id: &format!("functional-mesh-file-source-{attempt}"),
                config_protocol: "file",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_FILE_CONFIG_PATH", mesh_doc_env),
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", server_spiffe.to_string()),
                    (
                        "FERRUM_GATEWAY_SVID_CERT_PATH",
                        peers.server_cert_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_KEY_PATH",
                        peers.server_key_path.clone(),
                    ),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        peers.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: inbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue 'attempts;
        }

        // Phase 1: the file-built slice materializes the inbound route and an
        // authorized peer reaches the local backend.
        let (status, body) = match mesh_inbound_http_get(
            inbound_port,
            &peers.ca_pem,
            server_spiffe,
            Some((&peers.client_cert_pem, &peers.client_key_pem)),
            "echo.ferrum.svc.cluster.local",
            "/",
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("inbound mTLS HTTP GET failed: {e}\n{output}");
            }
        };
        assert_eq!(
            status,
            200,
            "an authorized peer must reach the backend through the file-built slice; body: \
             {body:?}\n{}",
            captured_output(&temp)
        );
        assert!(
            body.contains("backend-ok"),
            "the response must carry the local backend's body: {body:?}"
        );

        // Phase 2: rewrite the document with a DENY policy for the client
        // principal and SIGHUP the gateway; the reload must take effect
        // without a restart.
        std::fs::write(
            &mesh_doc_path,
            inbound_authz_mesh_document(server_spiffe, client_spiffe, backend_port, false),
        )
        .expect("rewrite mesh document");
        let pid = child.id().to_string();
        let hup = Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .expect("send SIGHUP");
        assert!(hup.success(), "SIGHUP delivery failed for pid {pid}");

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match mesh_inbound_http_get(
                inbound_port,
                &peers.ca_pem,
                server_spiffe,
                Some((&peers.client_cert_pem, &peers.client_key_pem)),
                "echo.ferrum.svc.cluster.local",
                "/",
            )
            .await
            {
                Ok((403, denied_body)) => {
                    assert!(
                        !denied_body.contains("backend-ok"),
                        "a denied request must not reach the backend: {denied_body:?}"
                    );
                    kill_child(&mut child);
                    return;
                }
                Ok(_) | Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Ok((other, other_body)) => {
                    let output = captured_output(&temp);
                    kill_child(&mut child);
                    panic!(
                        "SIGHUP-reloaded DENY policy never enforced: last status {other} body \
                         {other_body:?}\n{output}"
                    );
                }
                Err(e) => {
                    let output = captured_output(&temp);
                    kill_child(&mut child);
                    panic!("inbound request failed while awaiting reload: {e}\n{output}");
                }
            }
        }
    }

    panic!(
        "mesh file-source gateway never bound its inbound listener after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    );
}

// ── Multi-port egress original-destination fail-closed ──────────────────────

/// Slice with one in-mesh service exposing TWO HTTP-family ports backed by a
/// remote workload — the multi-port shape that materializes per-port outbound
/// siblings disambiguated by `SO_ORIGINAL_DST`.
fn multi_port_egress_slice(node_id: &str, b_spiffe: &str, backend_port: u16) -> MeshSlice {
    let mut slice = egress_service_slice(node_id, b_spiffe, backend_port);
    slice.services[0].ports.push(ServicePort {
        port: backend_port.wrapping_add(1),
        protocol: AppProtocol::Grpc,
        name: Some("grpc".to_string()),
        target_port: None,
    });
    // This test exercises only the OUTBOUND capture listener's routing
    // decision; the gateway runs without SVID material, and the inherited
    // STRICT PeerAuthentication would make the inbound listener's missing
    // server identity fatal at startup. Default (PERMISSIVE) suffices here.
    slice.peer_authentications.clear();
    slice
}

/// A captured request to a MULTI-port service without a captured original
/// destination must be rejected 502 (fail-closed), never forwarded to an
/// arbitrary port's backend. A direct (non-REDIRECTed) dial of the outbound
/// capture listener is exactly the "no orig-dst" condition, so this exercises
/// the production fail-closed arm end-to-end without needing iptables.
#[ignore]
#[tokio::test]
async fn functional_mesh_outbound_multi_port_without_orig_dst_fails_closed() {
    ensure_gateway_built().expect("gateway build");
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-origdst-multiport-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let backend_port = start_echo_backend().await;
        let cp =
            start_static_mesh_cp(multi_port_egress_slice(&node_id, b_spiffe, backend_port)).await;
        let ports = reserve_mesh_ports().await;
        let outbound_port = ports.outbound;
        // Ambient arm; the Sidecar topology has its own variant below (both
        // materialize per-port egress and demand orig-dst for multi-port).
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "ambient",
                waypoint_name: None,
                env_overrides: Vec::new(),
            },
        );

        if !wait_for_tcp_port(outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: outbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let result = plaintext_http_get(outbound_port, "svc-b.ferrum.svc.cluster.local", "/").await;
        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        let (status, body) = result.expect("plaintext GET against the outbound listener");
        assert_eq!(
            status, 502,
            "a multi-port service without a captured original destination must fail closed; \
             body: {body:?}\n{output}"
        );
        assert!(
            !body.contains("backend-ok"),
            "the request must never reach a port's backend by guessing: {body:?}"
        );
        return;
    }

    panic!(
        "mesh gateway never bound its outbound listener after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    );
}

/// Sidecar variant of the multi-port orig-dst fail-closed arm: with the
/// destination-side inbound disambiguation landed, Sidecar multi-port egress
/// now MATERIALIZES per-port routes — so a direct (orig-dst-less) dial gets
/// the selection-time 502, not a no-route 404, and is never guessed onto a
/// port's backend.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_outbound_multi_port_without_orig_dst_fails_closed() {
    ensure_gateway_built().expect("gateway build");
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-sidecar-origdst-multiport-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let backend_port = start_echo_backend().await;
        let cp =
            start_static_mesh_cp(multi_port_egress_slice(&node_id, b_spiffe, backend_port)).await;
        let ports = reserve_mesh_ports().await;
        let outbound_port = ports.outbound;
        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: Vec::new(),
            },
        );

        if !wait_for_tcp_port(outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: outbound listener never bound\n{}",
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let result = plaintext_http_get(outbound_port, "svc-b.ferrum.svc.cluster.local", "/").await;
        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        let (status, body) = result.expect("plaintext GET against the outbound listener");
        assert_eq!(
            status, 502,
            "a Sidecar multi-port service without a captured original destination must fail \
             closed at selection (the gate lift materializes its per-port routes); \
             body: {body:?}\n{output}"
        );
        assert!(
            !body.contains("backend-ok"),
            "the request must never reach a port's backend by guessing: {body:?}"
        );
        return;
    }

    panic!(
        "mesh gateway never bound its outbound listener after {RETRY_ATTEMPTS} \
         attempts\n{last_failure}"
    );
}

/// Start a WebSocket echo server on a fresh TCP port. The destination gateway
/// B's inbound loopback route targets this as the local application: B's
/// inbound listener terminates the source's WebSocket-over-mesh Extended
/// CONNECT and bridges it to this server over a plain HTTP/1.1 upgrade. The
/// server echoes every text/binary frame back with a `backend-ws:` prefix so
/// the test can prove frames traversed the full A→B→app→B→A datapath, then
/// honors a Close.
async fn start_websocket_echo_backend() -> u16 {
    use futures_util::{SinkExt, StreamExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket echo backend");
    let port = listener
        .local_addr()
        .expect("websocket echo backend addr")
        .port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await else {
                    return;
                };
                use tokio_tungstenite::tungstenite::Message;
                // A recv error ends the session (the `while let Some(Ok(..))`
                // simply stops looping), which is all an echo server needs.
                while let Some(Ok(msg)) = ws.next().await {
                    let send_result = match msg {
                        Message::Text(text) => {
                            ws.send(Message::Text(format!("backend-ws:{text}").into()))
                                .await
                        }
                        Message::Binary(bytes) => ws.send(Message::Binary(bytes)).await,
                        Message::Ping(payload) => ws.send(Message::Pong(payload)).await,
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => Ok(()),
                    };
                    if send_result.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Start a WebSocket echo server that captures the inner upgrade's request
/// **path+query** (via `accept_hdr_async`) and echoes it back in-band as
/// `backend-ws-path:<path_and_query>:<text>`. Used to prove the cross-cluster
/// Ambient WS egress PRESERVES the client `:path` through the HBONE byte tunnel
/// (issue #2010 codex Finding 1): before the fix, the synthetic
/// `mesh-xc-hbone|...` authority made the caller's URL fail to parse and the
/// path silently collapsed to `/`. The captured path lets the client assert the
/// exact non-root path arrived at the backend.
// The `accept_hdr_async` callback returns tungstenite's large `ErrorResponse`
// in its `Err` arm — the same accepted shape as `functional_websocket_test.rs`.
#[allow(clippy::result_large_err)]
async fn start_websocket_path_echo_backend() -> u16 {
    use futures_util::{SinkExt, StreamExt};
    use std::sync::{Arc, Mutex};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket path-echo backend");
    let port = listener
        .local_addr()
        .expect("websocket path-echo backend addr")
        .port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Capture the inner HTTP/1.1 upgrade request target the relay
                // forwarded. `accept_hdr_async`'s callback sees the raw request,
                // so record its path+query for the client to assert on.
                let observed_path = Arc::new(Mutex::new(String::from("<none>")));
                let observed_path_cb = Arc::clone(&observed_path);
                let callback = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                     resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    let pq = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_else(|| req.uri().path().to_string());
                    if let Ok(mut slot) = observed_path_cb.lock() {
                        *slot = pq;
                    }
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(sock, callback).await else {
                    return;
                };
                use tokio_tungstenite::tungstenite::Message;
                let path_snapshot = observed_path
                    .lock()
                    .map(|slot| slot.clone())
                    .unwrap_or_else(|_| String::from("<lock-poisoned>"));
                while let Some(Ok(msg)) = ws.next().await {
                    let send_result = match msg {
                        Message::Text(text) => {
                            ws.send(Message::Text(
                                format!("backend-ws-path:{path_snapshot}:{text}").into(),
                            ))
                            .await
                        }
                        Message::Binary(bytes) => ws.send(Message::Binary(bytes)).await,
                        Message::Ping(payload) => ws.send(Message::Pong(payload)).await,
                        Message::Close(_) => {
                            let _ = ws.send(Message::Close(None)).await;
                            break;
                        }
                        _ => Ok(()),
                    };
                    if send_result.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Open a plaintext HTTP/1.1 WebSocket upgrade to gateway A's outbound capture
/// listener (the same channel `plaintext_http_get` uses), send one text frame,
/// and return the echoed reply. The `Host` selects A's `mesh.mtls` egress route
/// to svc-b; the WebSocket upgrade then rides A's Sidecar mesh-mTLS Extended
/// CONNECT to B. Errors (handshake refused, no echo) are returned so the driver
/// can retry / assert fail-closed.
async fn mesh_websocket_echo_roundtrip(
    port: u16,
    host: &str,
    payload: &str,
) -> Result<String, String> {
    mesh_websocket_echo_roundtrip_path(port, host, "/", payload).await
}

/// Same as [`mesh_websocket_echo_roundtrip`] but drives an arbitrary request
/// `path` (e.g. `/ws/echo?room=x`) instead of `/`, so a test can assert the
/// client `:path`+query is preserved end-to-end across a mesh WS egress.
async fn mesh_websocket_echo_roundtrip_path(
    port: u16,
    host: &str,
    path: &str,
    payload: &str,
) -> Result<String, String> {
    mesh_websocket_echo_roundtrip_to(
        SocketAddr::from(([127, 0, 0, 1], port)),
        host,
        path,
        payload,
    )
    .await
}

/// Render a tungstenite handshake failure into a diagnostic string that, for an
/// HTTP error response, INCLUDES the response body. `tokio_tungstenite`'s
/// `Display` surfaces only the status line, dropping the JSON body that
/// distinguishes the live route's authoritative mesh-mTLS rejection
/// ([`CROSS_CLUSTER_TLS_REJECTION_BODY`]) from a bare setup `502`. Preserving the
/// body lets the WS classifier stay symmetric with the HTTP one.
fn format_ws_handshake_error(error: tokio_tungstenite::tungstenite::Error) -> String {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::Http(response) => {
            let status = response.status();
            let body = response
                .body()
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            format!("websocket handshake failed: HTTP status {status}; body: {body:?}")
        }
        other => format!("websocket handshake failed: {other}"),
    }
}

async fn mesh_websocket_echo_roundtrip_to(
    address: SocketAddr,
    host: &str,
    path: &str,
    payload: &str,
) -> Result<String, String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .map_err(|_| "websocket connect timed out".to_string())?
        .map_err(|e| format!("websocket connect failed: {e}"))?;

    // Build the upgrade request with the egress-route Host (tungstenite would
    // otherwise key the Host off the raw 127.0.0.1 address and miss the route).
    let mut request = format!("ws://{host}{path}")
        .into_client_request()
        .map_err(|e| format!("build ws request: {e}"))?;
    request.headers_mut().insert(
        "host",
        host.parse().map_err(|e| format!("host header: {e}"))?,
    );

    let (mut ws, _resp) = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::client_async(request, tcp),
    )
    .await
    .map_err(|_| "websocket handshake timed out".to_string())?
    .map_err(format_ws_handshake_error)?;

    ws.send(Message::Text(payload.to_string().into()))
        .await
        .map_err(|e| format!("websocket send failed: {e}"))?;

    let reply = loop {
        let msg = tokio::time::timeout(Duration::from_secs(8), ws.next())
            .await
            .map_err(|_| "websocket reply timed out".to_string())?
            .ok_or_else(|| "websocket closed before reply".to_string())?
            .map_err(|e| format!("websocket recv failed: {e}"))?;
        match msg {
            Message::Text(text) => break text.to_string(),
            // Ignore control frames while waiting for the echoed data frame.
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(frame) => {
                return Err(format!("websocket closed before echo: {frame:?}"));
            }
            other => return Err(format!("unexpected websocket frame: {other:?}")),
        }
    };
    let _ = ws.send(Message::Close(None)).await;
    Ok(reply)
}

/// Two-gateway WebSocket egress driver, mirroring [`drive_egress_a_to_b`] but
/// proxying a WebSocket upgrade instead of a plain GET. Reuses the same SVID,
/// slice, port, and gateway-spawn machinery; only the backend (a WS echo
/// server) and the client (a WS handshake + frame round-trip) differ.
/// Returns `Ok(echoed_payload)` on success, `Err(diagnostic)` otherwise.
async fn drive_websocket_egress_a_to_b(
    topology: &str,
    client_trusted: bool,
) -> Result<(String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_a = format!("functional-mesh-ws-egress-{topology}-{trust_label}-a-{attempt}");
        let node_b = format!("functional-mesh-ws-egress-{topology}-{trust_label}-b-{attempt}");
        let temp_a = TempDir::new().map_err(|e| format!("temp dir a: {e}"))?;
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
        let a_svid = if client_trusted {
            svids.a
        } else {
            generate_gateway_svid(temp_a.path(), a_spiffe)
        };
        let backend_port = start_websocket_echo_backend().await;

        let cp_b =
            start_static_mesh_cp(egress_service_slice(&node_b, b_spiffe, backend_port)).await;
        let cp_a =
            start_static_mesh_cp(egress_service_slice(&node_a, b_spiffe, backend_port)).await;
        let ports_a = reserve_mesh_ports().await;
        let ports_b = reserve_mesh_ports().await;
        let a_outbound_port = ports_a.outbound;
        let b_transport_port = match topology {
            "sidecar" => ports_b.inbound,
            "ambient" => ports_b.hbone,
            other => return Err(format!("unsupported ws egress topology {other}")),
        };

        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );
        if !wait_for_tcp_port(b_transport_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B transport listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            cp_a.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let mut a_env = vec![
            ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
            ("FERRUM_LOG_LEVEL", "debug".to_string()),
            ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", a_svid.cert_path.clone()),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", a_svid.key_path.clone()),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                a_svid.trust_bundle_path.clone(),
            ),
        ];
        match topology {
            "sidecar" => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()));
                a_env.push(("FERRUM_MESH_EGRESS_MTLS_PORT", b_transport_port.to_string()));
            }
            _ => {
                a_env.push(("FERRUM_POOL_WARMUP_ENABLED", "true".to_string()));
                a_env.push((
                    "FERRUM_MESH_EGRESS_HBONE_PORT",
                    b_transport_port.to_string(),
                ));
            }
        }
        let mut child_a = spawn_mesh_gateway(
            &temp_a,
            MeshGatewaySpawnOptions {
                cp_addr: cp_a.addr,
                ports: ports_a,
                node_id: &node_a,
                config_protocol: "native",
                topology,
                waypoint_name: None,
                env_overrides: a_env,
            },
        );
        if !wait_for_tcp_port(a_outbound_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway A outbound listener never bound\n{}",
                captured_output(&temp_a)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Open the WebSocket through A's outbound listener. Retried briefly for
        // the same warmup/probe convergence reason as the HTTP egress driver;
        // the untrusted negative asserts the FINAL state (never a success).
        let deadline = Instant::now() + Duration::from_secs(15);
        let last: Result<String, String> = loop {
            let attempt = mesh_websocket_echo_roundtrip(
                a_outbound_port,
                "svc-b.ferrum.svc.cluster.local",
                "mesh-ws-hello",
            )
            .await;
            if let Ok(ref reply) = attempt
                && reply.contains("backend-ws:mesh-ws-hello")
            {
                break attempt;
            }
            if Instant::now() >= deadline {
                break attempt;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };

        let output_a = captured_output(&temp_a);
        let output_b = captured_output(&temp_b);
        kill_child(&mut child_a);
        kill_child(&mut child_b);
        cp_a.shutdown().await;
        cp_b.shutdown().await;

        let logs = format!("--- gateway A ---\n{output_a}\n--- gateway B ---\n{output_b}");
        return match last {
            Ok(reply) => Ok((reply, logs)),
            Err(e) => Err(format!("{e}\n{logs}")),
        };
    }

    Err(format!(
        "ws egress gateways never bound their listeners after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// WebSocket egress keystone (Sidecar, F2 §3.2): a WebSocket upgrade captured at
/// gateway A reaches the WS echo backend behind gateway B over an **RFC 8441
/// Extended CONNECT carried on plain SVID-mTLS HTTP/2** to B's inbound listener
/// — outbound capture → materialized `mesh.mtls` egress route → WS handler
/// opens an Extended CONNECT over mesh-mTLS (peer pinned to B's workload
/// identity) → B's STRICT inbound termination recognizes the Extended CONNECT
/// WebSocket → bridges to the local WS app → frames echo back to A. Proves the
/// WS upgrade rides the SAME secured transport as Sidecar HTTP egress instead of
/// the pre-mesh plaintext dial.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_ws_egress_routes_a_to_b_over_mtls() {
    let (reply, logs) = drive_websocket_egress_a_to_b("sidecar", true)
        .await
        .expect("sidecar websocket egress drive");
    assert!(
        reply.contains("backend-ws:mesh-ws-hello"),
        "the WebSocket frame must traverse A's SVID-mTLS Extended CONNECT egress to B's WS \
         backend and echo back; reply: {reply:?}\n{logs}"
    );
}

/// WebSocket egress mTLS negative (Sidecar): a source gateway whose SVID does
/// NOT chain to the mesh CA must not reach B's WS backend. The mesh-mTLS dial
/// underpinning the Extended CONNECT fails SVID verification (A rejects B's
/// server SVID; B's STRICT inbound rejects A's client cert), so the WebSocket
/// upgrade fails closed — it must never echo a backend frame. Proves the WS
/// egress path really verifies SVIDs rather than blindly tunneling.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_ws_egress_rejects_untrusted_client_gateway() {
    // The driver returns `Err` when the WebSocket upgrade never completes (the
    // expected fail-closed outcome for an untrusted gateway: the mesh-mTLS dial
    // underpinning the Extended CONNECT fails SVID verification before a 101).
    // It returns `Ok(reply)` only if a handshake somehow succeeded — in which
    // case the reply must NOT carry a backend frame.
    if let Ok((reply, logs)) = drive_websocket_egress_a_to_b("sidecar", false).await {
        assert!(
            !reply.contains("backend-ws:"),
            "an untrusted gateway's WebSocket egress must fail closed, not echo a backend \
             frame: {reply:?}\n{logs}"
        );
    }
}

/// WebSocket egress keystone (Ambient, F2 §3.2): a WebSocket upgrade captured at
/// gateway A reaches the WS echo backend behind Ambient gateway B over a **BARE
/// HBONE CONNECT byte tunnel** to B's `:15008` HBONE listener, with the
/// WebSocket spoken as an inner HTTP/1.1 upgrade THROUGH the tunnel — NOT an
/// Extended CONNECT. Ambient/Waypoint materialize NO inbound routes, so B's
/// transparent HBONE relay (`build_inbound_hbone_relay_proxy`, bare-CONNECT-
/// gated) byte-copies the tunnel straight to the loopback WS app, which performs
/// the upgrade. This is the codex-finding-#1 fix: the prior implementation sent a
/// `:protocol=websocket` Extended CONNECT to `:15008`, which the relay EXCLUDES
/// (it requires `:protocol` absent) so it 404'd for every Ambient destination.
/// Proves Ambient WS egress actually works end-to-end A→B→app→B→A over HBONE.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_ws_egress_routes_a_to_b_over_hbone() {
    let (reply, logs) = drive_websocket_egress_a_to_b("ambient", true)
        .await
        .expect("ambient websocket egress drive");
    assert!(
        reply.contains("backend-ws:mesh-ws-hello"),
        "the WebSocket frame must traverse A's HBONE byte-tunnel egress to B's WS backend \
         (inner H1 upgrade relayed to the loopback app) and echo back; reply: {reply:?}\n{logs}"
    );
}

/// WebSocket egress HBONE negative (Ambient): a source gateway whose SVID does
/// NOT chain to the mesh CA must not reach B's WS backend. The HBONE byte-tunnel
/// dial underpinning the WebSocket fails SVID verification (A rejects B's server
/// SVID; B's HBONE listener rejects A's client cert), so the upgrade fails
/// closed — it must never echo a backend frame. Proves the Ambient WS egress
/// path verifies SVIDs rather than blindly tunneling, and never silently falls
/// back to a plaintext dial of a `mesh.hbone` destination.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_ws_egress_rejects_untrusted_client_gateway() {
    // The driver returns `Err` when the upgrade never completes (the expected
    // fail-closed outcome: the HBONE dial underpinning the WebSocket fails SVID
    // verification before the inner handshake). It returns `Ok(reply)` only if a
    // handshake somehow succeeded — in which case the reply must NOT carry a
    // backend frame.
    if let Ok((reply, logs)) = drive_websocket_egress_a_to_b("ambient", false).await {
        assert!(
            !reply.contains("backend-ws:"),
            "an untrusted gateway's Ambient WebSocket egress must fail closed, not echo a \
             backend frame: {reply:?}\n{logs}"
        );
    }
}

// ===================================================================
// UDP §3.3 Stage 7 — functional destination tests
// ===================================================================
//
// These drive a `udp`-marked HTTP/2 CONNECT directly at a spawned mesh gateway
// B's inbound HBONE relay (`handle_hbone_udp_request`), exercising the
// DESTINATION half of the datagram-over-mesh datapath end-to-end: a framed
// datagram in -> local UDP echo backend -> framed datagram back. The source
// side TPROXY capture is NOT needed (the client synthesizes the `udp` CONNECT),
// so these run without root/netns. The full source-capture e2e (TPROXY ->
// tunnel -> unframe -> app -> return-source-spoofing) is covered by the
// Linux/root-gated `functional_mesh_live_source_capture_*` tests below.

/// Test-only server-cert verifier that accepts any certificate. The functional
/// gateway SVIDs carry only a SPIFFE URI SAN (no IP/DNS SAN), so a standard
/// rustls name check against `127.0.0.1` would reject B's server cert; the real
/// mesh peer verification is SPIFFE-aware. These tests exercise the UDP RELAY
/// datapath, not the client's verification of the server — and gateway B still
/// verifies OUR client SVID with its real SPIFFE verifier, so accepting B's
/// cert here is just plumbing.
#[derive(Debug)]
struct AnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AnyServerCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// A mesh slice declaring svc-b's workload with a single UDP service port, so
/// gateway B (which owns `b_spiffe`) recognizes the workload as local and its
/// inbound open-relay guard admits a `udp` CONNECT to `127.0.0.1:<udp_port>`.
/// STRICT PeerAuthentication so B requires + verifies the client SVID.
fn udp_dest_slice(node_id: &str, b_spiffe: &str, udp_port: u16) -> MeshSlice {
    let b_id = SpiffeId::new(b_spiffe).expect("b SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: b_id.clone(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "svc-b".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "svc-b".to_string(),
            addresses: vec!["127.0.0.1".to_string()],
            ports: vec![WorkloadPort {
                port: udp_port,
                protocol: AppProtocol::Udp,
                name: Some("udp".to_string()),
            }],
            trust_domain,
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("svc-b".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "svc-b".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: udp_port,
                protocol: AppProtocol::Udp,
                name: Some("udp".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: b_id }],
            protocol_overrides: HashMap::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// Bind a UDP echo backend on loopback; returns (port, task). Echoes each
/// datagram back to its sender. Holds the socket for the task's lifetime.
async fn start_udp_echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp echo backend");
    let port = socket.local_addr().expect("udp echo local addr").port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], src).await;
        }
    });
    (port, handle)
}

/// Build an mTLS HTTP/2 client config presenting `svid`'s leaf cert + key, with
/// the permissive server-cert verifier (see [`AnyServerCert`]). ALPN `h2`.
fn udp_dest_client_config(svid: &GeneratedGatewaySvid) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pem = std::fs::read(&svid.cert_path).expect("read client svid cert");
    let key_pem = std::fs::read(&svid.key_path).expect("read client svid key");
    let chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse client svid key")
        .expect("client svid key present");
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServerCert))
        .with_client_auth_cert(chain, key)
        .expect("client config");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// Read exactly one length-delimited datagram (`[u16 BE len][payload]`) from an
/// h2 response body, accumulating chunks until a full frame is buffered. The
/// relay keeps the response stream OPEN (it is a tunnel), so this must stop at
/// the first complete frame rather than draining to EOF.
async fn read_one_framed_reply(
    body: &mut h2::RecvStream,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    tokio::time::timeout(timeout, async {
        loop {
            if buf.len() >= 2 {
                let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if buf.len() >= 2 + len {
                    return Ok(buf[2..2 + len].to_vec());
                }
            }
            match body.data().await {
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(format!("response body error: {e}")),
                None => return Err("response body ended before a full datagram".to_string()),
            }
        }
    })
    .await
    .map_err(|_| "timed out reading framed reply".to_string())?
}

/// Open mTLS H2 to B, send a `udp` CONNECT + one framed `ping`, return
/// (status, optional framed reply).
async fn drive_one_udp_connect(
    hbone_port: u16,
    authority: &str,
    client_svid: &GeneratedGatewaySvid,
) -> Result<(u16, Option<Vec<u8>>), String> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", hbone_port))
        .await
        .map_err(|e| format!("connect B: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(udp_dest_client_config(client_svid));
    let server_name = rustls::pki_types::ServerName::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
    );
    // Bound the handshakes: if the HBONE port is bound but the TLS server wedges
    // (or a regression binds a non-TLS listener), an unbounded handshake await
    // would hang the ignored test forever before reaching the later timeouts.
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client TLS handshake timed out".to_string())?
        .map_err(|e| format!("client TLS handshake: {e}"))?;
    let (mut sender, conn) =
        tokio::time::timeout(Duration::from_secs(10), h2::client::handshake(tls))
            .await
            .map_err(|_| "h2 handshake timed out".to_string())?
            .map_err(|e| format!("h2 handshake: {e}"))?;
    let conn_task = tokio::spawn(conn);

    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority)
        .header("x-ferrum-mesh-protocol", "udp")
        .body(())
        .map_err(|e| format!("build CONNECT: {e}"))?;
    let (response_fut, mut send_body) = sender
        .send_request(req, false)
        .map_err(|e| format!("send CONNECT: {e}"))?;

    let mut framed = bytes::BytesMut::new();
    ferrum_edge::proxy::mesh_udp_frame::encode_datagram(&mut framed, b"ping")
        .map_err(|e| format!("encode datagram: {e}"))?;
    // Keep the request stream OPEN (end_stream=false) so the relay stays alive
    // for the return datagram.
    let _ = send_body.send_data(framed.freeze(), false);

    let resp = tokio::time::timeout(Duration::from_secs(10), response_fut)
        .await
        .map_err(|_| "CONNECT response timed out".to_string())?
        .map_err(|e| format!("CONNECT response: {e}"))?;
    let status = resp.status().as_u16();

    let reply = if status == 200 {
        let mut response_body = resp.into_body();
        Some(
            read_one_framed_reply(&mut response_body, Duration::from_secs(5))
                .await
                .map_err(|e| format!("read reply: {e}"))?,
        )
    } else {
        None
    };

    conn_task.abort();
    Ok((status, reply))
}

/// Outcome of a UDP dest drive AFTER the gateway came up. Distinguishes a
/// completed CONNECT from a connection/handshake failure so a SETUP failure
/// (gateway never built/bound — returned as the outer `Err`) can never be
/// mistaken for an expected fail-closed rejection.
enum UdpDestOutcome {
    /// The CONNECT completed: (status, optional framed reply payload).
    Connected(u16, Option<Vec<u8>>),
    /// The connection/handshake/request failed before a CONNECT response — the
    /// expected outcome for an untrusted (cert-rejected) peer.
    ConnectFailed(String),
}

/// Spawn gateway B (Ambient inbound HBONE terminator) over a slice declaring a
/// UDP svc-b workload, then drive a single `udp` CONNECT at its HBONE port.
/// `client_trusted` selects whether the client SVID chains to B's mesh CA;
/// `dial_declared_port` selects an in-allowlist vs off-allowlist authority.
/// The outer `Err` is a SETUP failure (gateway never built/bound after retries)
/// — callers must treat it as a test failure, NOT a fail-closed pass. `Ok`
/// carries the [`UdpDestOutcome`] of the actual CONNECT attempt.
async fn drive_udp_dest_connect(
    client_trusted: bool,
    dial_declared_port: bool,
) -> Result<UdpDestOutcome, String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/svc-b";
    let trust_label = if client_trusted {
        "trusted"
    } else {
        "untrusted"
    };

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_b = format!("functional-mesh-udp-dest-{trust_label}-b-{attempt}");
        let temp_b = TempDir::new().map_err(|e| format!("temp dir b: {e}"))?;
        let temp_client = TempDir::new().map_err(|e| format!("temp dir client: {e}"))?;
        let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
        // An untrusted client mints its OWN CA: its cert does not chain to B's
        // mesh CA, so B's STRICT inbound rejects the handshake (fail closed).
        let client_svid = if client_trusted {
            svids.a
        } else {
            generate_gateway_svid(temp_client.path(), a_spiffe)
        };

        let (udp_port, echo) = start_udp_echo_backend().await;
        let cp_b = start_static_mesh_cp(udp_dest_slice(&node_b, b_spiffe, udp_port)).await;
        let ports_b = reserve_mesh_ports().await;
        let hbone_port = ports_b.hbone;

        let mut child_b = spawn_mesh_gateway(
            &temp_b,
            MeshGatewaySpawnOptions {
                cp_addr: cp_b.addr,
                ports: ports_b,
                node_id: &node_b,
                config_protocol: "native",
                topology: "ambient",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        if !wait_for_tcp_port(hbone_port, STARTUP_TIMEOUT).await {
            last_failure = format!(
                "attempt {attempt}: gateway B HBONE listener never bound\n{}",
                captured_output(&temp_b)
            );
            kill_child(&mut child_b);
            cp_b.shutdown().await;
            echo.abort();
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let dial_port = if dial_declared_port {
            udp_port
        } else {
            // A port no workload declares — the open-relay guard must refuse it.
            udp_port.checked_add(1).unwrap_or(1)
        };
        let authority = format!("127.0.0.1:{dial_port}");

        let outcome = drive_one_udp_connect(hbone_port, &authority, &client_svid).await;

        let logs = captured_output(&temp_b);
        kill_child(&mut child_b);
        cp_b.shutdown().await;
        echo.abort();

        return Ok(match outcome {
            Ok((status, reply)) => UdpDestOutcome::Connected(status, reply),
            Err(e) => UdpDestOutcome::ConnectFailed(format!("{e}\n--- gateway B ---\n{logs}")),
        });
    }

    Err(format!(
        "udp dest gateway never bound after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Stage 7 keystone (destination side): a `udp`-marked HBONE CONNECT into a mesh
/// gateway is unframed into a local `UdpSocket`, the datagram echoes off a local
/// backend, and the reply is framed back byte-for-byte — exercising
/// `handle_hbone_udp_request` / `relay_hbone_udp` end-to-end over real SVID-mTLS
/// with no source-side TPROXY.
#[ignore]
#[tokio::test]
async fn functional_mesh_udp_dest_relays_datagram_round_trip() {
    // `.expect` on the outer Result = the gateway must come up (setup failure is a
    // test failure, never a silent pass).
    match drive_udp_dest_connect(true, true)
        .await
        .expect("udp dest setup")
    {
        UdpDestOutcome::Connected(status, reply) => {
            assert_eq!(status, 200, "the udp CONNECT must be accepted by B's relay");
            assert_eq!(
                reply.as_deref(),
                Some(&b"ping"[..]),
                "the echoed datagram must return framed byte-for-byte"
            );
        }
        UdpDestOutcome::ConnectFailed(e) => {
            panic!("a trusted udp CONNECT must connect and round-trip, not fail closed: {e}")
        }
    }
}

/// Stage 7 fail-closed (open-relay guard): a `udp` CONNECT whose authority is a
/// port the slice does NOT declare is refused at the destination — the inbound
/// open-relay guard admits only loopback / slice-declared workload addr+port, so
/// an authenticated peer can never ride a `udp` CONNECT to an arbitrary port.
#[ignore]
#[tokio::test]
async fn functional_mesh_udp_dest_off_allowlist_authority_is_refused() {
    match drive_udp_dest_connect(true, false)
        .await
        .expect("udp dest setup")
    {
        UdpDestOutcome::Connected(status, reply) => {
            assert_ne!(
                status, 200,
                "a udp CONNECT to an undeclared port must be refused, not relayed"
            );
            assert!(
                reply.is_none(),
                "a refused CONNECT must not return a relayed datagram"
            );
        }
        UdpDestOutcome::ConnectFailed(e) => panic!(
            "an off-allowlist CONNECT should reach B and be refused (non-200), \
             not fail to connect: {e}"
        ),
    }
}

/// Stage 7 fail-closed (peer authentication): a client whose SVID does NOT chain
/// to B's mesh CA must not reach the relay. B's STRICT inbound rejects the
/// handshake, failing the request closed before any datagram is relayed. (Under
/// STRICT the rejection is at the TLS layer; the handler-level
/// `peer_spiffe_id.is_none()` 403 stays predicate-pinned — this asserts the
/// equivalent fail-closed OUTCOME at the transport boundary.)
#[ignore]
#[tokio::test]
async fn functional_mesh_udp_dest_untrusted_peer_fails_closed() {
    // `.expect` ensures a SETUP failure (gateway never bound) is a test failure,
    // not a false "fail-closed" pass — the bug codex flagged. Only a genuine
    // CONNECT-attempt failure counts as the expected fail-closed outcome.
    match drive_udp_dest_connect(false, true)
        .await
        .expect("udp dest setup")
    {
        // Expected: the mTLS handshake fails closed before any CONNECT response.
        UdpDestOutcome::ConnectFailed(_) => {}
        // If a connection somehow established, it must NOT have relayed a datagram.
        UdpDestOutcome::Connected(status, reply) => {
            assert_ne!(
                status, 200,
                "an untrusted client's udp CONNECT must fail closed, not be relayed"
            );
            assert!(
                reply.is_none(),
                "no datagram may be relayed for an untrusted peer"
            );
        }
    }
}

// ===================================================================
// Live source-capture e2e — root + Linux netns only (#2038)
// ===================================================================

#[cfg(target_os = "linux")]
fn live_source_capture_tests_required() -> bool {
    std::env::var("FERRUM_LIVE_TESTS_REQUIRED")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn skip_or_fail_live_source_capture(reason: &str) {
    if live_source_capture_tests_required() {
        panic!("required live source-capture test prerequisite missing: {reason}");
    }
    eprintln!("SKIP: {reason}");
}

#[cfg(target_os = "linux")]
fn live_source_capture_prerequisites() -> bool {
    // Safety: `geteuid` is always sound and never fails.
    if unsafe { libc::geteuid() } != 0 {
        skip_or_fail_live_source_capture("not root; cannot create/enter network namespaces");
        return false;
    }
    for binary in [
        "unshare",
        "nsenter",
        "setpriv",
        "sh",
        "ip",
        "iptables",
        "iptables-save",
    ] {
        let present = Command::new("sh")
            .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|status| status.success());
        if !present {
            skip_or_fail_live_source_capture(&format!("`{binary}` is unavailable"));
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
struct LiveGatewayChild(Option<Child>);

#[cfg(target_os = "linux")]
impl LiveGatewayChild {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = child.id();
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            for _ in 0..50 {
                if child.try_wait().is_ok_and(|status| status.is_some()) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn poll_status(&mut self) -> String {
        match self.0.as_mut().map(Child::try_wait) {
            Some(Ok(Some(status))) => format!("exited with {status}"),
            Some(Ok(None)) => "still running".to_string(),
            Some(Err(error)) => format!("status check failed: {error}"),
            None => "already stopped".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveGatewayChild {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A pod-shaped network namespace plus a synthetic cgroup directory. Production
/// cgroup resolution only needs `cgroup.procs`, so this lets the real manager and
/// backend resolve `/proc/<pid>/ns/net` without mutating the runner's cgroup tree.
#[cfg(target_os = "linux")]
struct LivePodNetns {
    child: Child,
    cgroup_dir: TempDir,
}

#[cfg(target_os = "linux")]
impl LivePodNetns {
    fn spawn(default_via_loopback: bool) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;

        let route = if default_via_loopback {
            "ip route add default dev lo || exit 98;"
        } else {
            ""
        };
        let script = format!(
            "set -e; command -v ip >/dev/null 2>&1 || exit 97; \
             ip link set lo up || exit 98; {route} exec sleep 300"
        );
        let mut child = Command::new("unshare")
            .args(["--net", "sh", "-c", &script])
            .spawn()
            .map_err(|error| format!("spawn unshare netns child: {error}"))?;

        let host_netns_inode = match std::fs::metadata("/proc/self/ns/net") {
            Ok(metadata) => metadata.ino(),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("read host netns identity: {error}"));
            }
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let _ = child.wait();
                    return Err(format!(
                        "netns child exited during setup with code {:?}",
                        status.code()
                    ));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("poll netns child: {error}"));
                }
                Ok(None) => {
                    let child_netns_inode =
                        std::fs::metadata(format!("/proc/{}/ns/net", child.id()))
                            .map(|metadata| metadata.ino())
                            .ok();
                    if child_netns_inode.is_some_and(|inode| inode != host_netns_inode) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("netns child did not unshare within 3s".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }

        // Give the child shell a bounded moment to finish loopback/default-route
        // setup after `unshare(2)` changed the namespace identity.
        std::thread::sleep(Duration::from_millis(100));
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = child.wait();
                return Err(format!(
                    "netns child exited after unshare with code {:?}",
                    status.code()
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("poll configured netns child: {error}"));
            }
            Ok(None) => {}
        }

        let cgroup_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("temp cgroup dir: {error}"));
            }
        };
        if let Err(error) = std::fs::write(
            cgroup_dir.path().join("cgroup.procs"),
            format!("{}\n", child.id()),
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("write synthetic cgroup.procs: {error}"));
        }
        Ok(Self { child, cgroup_dir })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn publish(&self, registry_dir: &std::path::Path, pod_uid: &str) -> Result<PathBuf, String> {
        self.publish_with_identity(registry_dir, pod_uid, None)
    }

    fn publish_with_identity(
        &self,
        registry_dir: &std::path::Path,
        pod_uid: &str,
        spiffe_id: Option<&str>,
    ) -> Result<PathBuf, String> {
        std::fs::create_dir_all(registry_dir)
            .map_err(|error| format!("create pod registry: {error}"))?;
        let path = registry_dir.join(pod_uid);
        let mut contents = format!("{}\n", self.cgroup_dir.path().display());
        if let Some(spiffe_id) = spiffe_id {
            contents.push_str(&format!("spiffe_id={spiffe_id}\n"));
        }
        std::fs::write(&path, contents)
            .map_err(|error| format!("publish pod registry entry: {error}"))?;
        Ok(path)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LivePodNetns {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn run_in_live_netns<T, F>(pid: u32, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    use std::os::fd::AsRawFd;

    std::thread::spawn(move || {
        let netns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
            .map_err(|error| format!("open pod netns: {error}"))?;
        // Safety: `netns` is an open network-namespace handle owned by this
        // throwaway thread; the thread exits without returning to the runtime.
        if unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!("setns: {}", std::io::Error::last_os_error()));
        }
        operation()
    })
    .join()
    .map_err(|_| "pod-netns operation thread panicked".to_string())?
}

#[cfg(target_os = "linux")]
fn run_async_in_live_netns<T, F, Fut>(pid: u32, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + 'static,
{
    run_in_live_netns(pid, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("build pod-netns runtime: {error}"))?;
        runtime.block_on(operation())
    })
}

#[cfg(target_os = "linux")]
fn netns_command(pid: u32, script: &str) -> Result<String, String> {
    let output = Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .args(["--", "sh", "-c", script])
        .output()
        .map_err(|error| format!("run netns command: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "netns command failed ({:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct UdpCaptureSnapshot {
    output_jumps: usize,
    reinject_jumps: usize,
    outbound_jumps: usize,
    route_rules: usize,
    listeners: usize,
    ferrum_rule_lines: usize,
}

#[cfg(target_os = "linux")]
fn udp_capture_snapshot(pid: u32, capture_port: u16) -> Result<UdpCaptureSnapshot, String> {
    let rules = netns_command(pid, "iptables-save -t mangle")?;
    let route_rules = netns_command(pid, "ip rule show")?
        .lines()
        .filter(|line| line.contains("lookup 33133"))
        .count();
    let port_suffix = format!(":{:04X}", capture_port);
    // Read procfs from a single-threaded process whose own network namespace is
    // the pod's. An in-process `setns` only switches the calling test thread,
    // while `/proc/self/net` may still resolve through the multithreaded test
    // process and report the host namespace instead.
    let listener_tables = netns_command(pid, "cat /proc/net/udp /proc/net/udp6")?;
    let listeners = listener_tables
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|local| local.ends_with(&port_suffix))
        })
        .count();
    Ok(UdpCaptureSnapshot {
        output_jumps: rules
            .lines()
            .filter(|line| {
                line.starts_with("-A OUTPUT ") && line.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
            })
            .count(),
        reinject_jumps: rules
            .lines()
            .filter(|line| {
                line.starts_with("-A PREROUTING ") && line.contains("FERRUM_MESH_UDP_REINJECT")
            })
            .count(),
        outbound_jumps: rules
            .lines()
            .filter(|line| {
                line.starts_with("-A PREROUTING ") && line.contains("FERRUM_MESH_UDP_OUTBOUND")
            })
            .count(),
        route_rules,
        listeners,
        ferrum_rule_lines: rules
            .lines()
            .filter(|line| {
                line.contains("FERRUM_MESH_UDP") || line.contains("FERRUM_UDP_FAIL_CLOSED")
            })
            .count(),
    })
}

#[cfg(target_os = "linux")]
fn wait_for_udp_capture_snapshot(
    pid: u32,
    capture_port: u16,
    active: bool,
    timeout: Duration,
) -> Result<UdpCaptureSnapshot, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let observation = match udp_capture_snapshot(pid, capture_port) {
            Ok(snapshot) => {
                let ready = if active {
                    snapshot.output_jumps == 1
                        && snapshot.reinject_jumps == 1
                        && snapshot.outbound_jumps == 1
                        && snapshot.route_rules == 1
                        && snapshot.listeners == 1
                } else {
                    snapshot.ferrum_rule_lines == 0
                        && snapshot.route_rules == 0
                        && snapshot.listeners == 0
                };
                if ready {
                    return Ok(snapshot);
                }
                format!("{snapshot:?}")
            }
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "UDP capture state did not become {} within {timeout:?}; last={}",
                if active { "active" } else { "absent" },
                observation
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "linux")]
fn udp_round_trip_from_netns(
    pid: u32,
    destination: SocketAddr,
    payload: &'static [u8],
    timeout: Duration,
) -> Result<(Vec<u8>, SocketAddr), String> {
    run_in_live_netns(pid, move || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")
            .map_err(|error| format!("bind pod UDP client: {error}"))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("set UDP client timeout: {error}"))?;
        socket
            .send_to(payload, destination)
            .map_err(|error| format!("send UDP to {destination}: {error}"))?;
        let mut buf = [0u8; 2048];
        let (n, source) = socket
            .recv_from(&mut buf)
            .map_err(|error| format!("receive UDP reply: {error}"))?;
        Ok((buf[..n].to_vec(), source))
    })
}

#[cfg(target_os = "linux")]
async fn start_counting_udp_echo() -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind live source-capture UDP echo");
    let port = socket.local_addr().expect("UDP echo address").port();
    let received = Arc::new(AtomicUsize::new(0));
    let received_task = received.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            received_task.fetch_add(1, Ordering::Relaxed);
            if socket.send_to(&buf[..n], peer).await.is_err() {
                return;
            }
        }
    });
    (port, received, task)
}

#[cfg(target_os = "linux")]
fn live_source_capture_slice(
    node_id: &str,
    b_spiffe: &str,
    workload_address: &str,
    cluster_ip: &str,
    service_port: u16,
    protocol: AppProtocol,
) -> MeshSlice {
    let b_id = SpiffeId::new(b_spiffe).expect("live source-capture B SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![Workload {
            spiffe_id: b_id.clone(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "source-capture-echo".to_string())]),
                namespace: Some("ferrum".to_string()),
            },
            service_name: "source-capture-echo".to_string(),
            addresses: vec![workload_address.to_string()],
            ports: vec![WorkloadPort {
                port: service_port,
                protocol,
                name: Some("live-source-capture".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").expect("live trust domain"),
            namespace: "ferrum".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some("source-capture-echo".to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        services: vec![MeshService {
            cluster_ips: vec![cluster_ip.to_string()],
            name: "source-capture-echo".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: service_port,
                protocol,
                name: Some("live-source-capture".to_string()),
                target_port: None,
            }],
            workloads: vec![WorkloadRef { spiffe_id: b_id }],
            protocol_overrides: HashMap::new(),
        }],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        ..MeshSlice::default()
    }
}

/// The status-2 regression diagnostic below keys on this literal, which the Ambient UDP
/// producer emits from `IptablesPlan::udp_fail_closed_script` (see
/// `src/capture/mod.rs`, the `-C OUTPUT` guard-inspect branch). It is a shared
/// substring of the runtime line `<binary> could not inspect active UDP
/// fail-closed guard (status <N>)`, so it matches regardless of the iptables
/// backend's actual `<binary>`/status. If the source message ever drifts, the
/// diagnostic would stop identifying the regression clearly — so
/// `udp_fail_closed_guard_probe_literal_matches_source` below
/// reconstructs the guard script via the same pub constructor and fails loudly
/// the moment this literal no longer appears in it.
#[cfg(target_os = "linux")]
const UDP_FAIL_CLOSED_GUARD_PROBE_LITERAL: &str =
    "could not inspect active UDP fail-closed guard (status ";

/// Drift guard for `UDP_FAIL_CLOSED_GUARD_PROBE_LITERAL`. Builds the fail-closed
/// UDP guard script from the exact pub constructor the producer runs and asserts
/// the diagnostic literal is still present, so a source-side wording change
/// breaks this fast unit-style check instead of the root-only live lane.
#[cfg(target_os = "linux")]
#[test]
fn udp_fail_closed_guard_probe_literal_matches_source() {
    let mut config = ferrum_edge::capture::CaptureConfig::explicit(15006, 15001);
    config.mode = ferrum_edge::capture::CaptureMode::Iptables;
    config.udp_capture_enabled = true;
    config.ip6tables_mode = ferrum_edge::capture::Ip6TablesMode::Disabled;
    let script = ferrum_edge::capture::IptablesPlan::udp_fail_closed_script(&config);
    assert!(
        !script.is_empty(),
        "UDP fail-closed guard script must be non-empty for a UDP-capture config"
    );
    assert!(
        script.contains(UDP_FAIL_CLOSED_GUARD_PROBE_LITERAL),
        "the UDP fail-closed guard-inspect literal drifted in src/capture/mod.rs; update \
         UDP_FAIL_CLOSED_GUARD_PROBE_LITERAL and the live regression diagnostic together.\n--- script ---\n{script}"
    );
}

/// Full Ambient producer path: the real `NetnsUdpCaptureManager` resolves a
/// synthetic cgroup, the real backend installs production UDP-only TPROXY rules
/// and binds capture/reply sockets inside the pod netns, and the captured flow
/// traverses gateway A's HBONE datagram tunnel plus gateway B's real destination
/// relay before returning from the original VIP:port.
#[cfg(target_os = "linux")]
#[ignore = "requires root + netns + iptables/TPROXY + iproute2"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_mesh_live_source_capture_udp_manager_hbone_round_trip() {
    if !live_source_capture_prerequisites() {
        return;
    }
    ensure_gateway_built().expect("build gateway for live UDP source-capture test");

    const VIP: &str = "192.0.2.40";
    const UNROUTABLE_VIP: &str = "192.0.2.41";
    const POD_UID: &str = "functional-udp-source-capture-pod";
    let capture_port = ferrum_edge::capture::DEFAULT_UDP_OUTBOUND_PORT;
    let pod = match LivePodNetns::spawn(true) {
        Ok(pod) => pod,
        Err(error) => {
            skip_or_fail_live_source_capture(&format!("cannot create UDP pod netns: {error}"));
            return;
        }
    };
    let registry = TempDir::new().expect("UDP pod registry tempdir");
    let registry_entry = pod
        .publish(registry.path(), POD_UID)
        .expect("publish UDP pod registry entry");

    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/udp-echo";
    let temp_a_disabled = TempDir::new().expect("disabled gateway A tempdir");
    let temp_a = TempDir::new().expect("gateway A tempdir");
    let temp_b = TempDir::new().expect("gateway B tempdir");
    let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
    let (echo_port, echo_received, echo_task) = start_counting_udp_echo().await;
    let node_a = "functional-live-udp-source-a";
    let node_b = "functional-live-udp-source-b";
    let cp_a = start_static_mesh_cp(live_source_capture_slice(
        node_a,
        b_spiffe,
        "127.0.0.1",
        VIP,
        echo_port,
        AppProtocol::Udp,
    ))
    .await;
    let cp_b = start_static_mesh_cp(live_source_capture_slice(
        node_b,
        b_spiffe,
        "127.0.0.1",
        VIP,
        echo_port,
        AppProtocol::Udp,
    ))
    .await;

    let ports_b = reserve_mesh_ports().await;
    let b_hbone_port = ports_b.hbone;
    let mut gateway_b = LiveGatewayChild::new(spawn_mesh_gateway(
        &temp_b,
        MeshGatewaySpawnOptions {
            cp_addr: cp_b.addr,
            ports: ports_b,
            node_id: node_b,
            config_protocol: "native",
            topology: "ambient",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_LOG_LEVEL", "debug".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svids.b.trust_bundle_path.clone(),
                ),
            ],
        },
    ));
    assert!(
        wait_for_tcp_port(b_hbone_port, STARTUP_TIMEOUT).await,
        "UDP destination HBONE listener did not bind\n{}",
        captured_output(&temp_b)
    );

    // Disabled-mode negative: the same enrolled pod produces no rules and no
    // capture socket. The cleanup manager is allowed to run, but it must never
    // install state while the feature flag is off.
    let ports_disabled = reserve_mesh_ports().await;
    let disabled_outbound = ports_disabled.outbound;
    let mut disabled_a = LiveGatewayChild::new(spawn_mesh_gateway(
        &temp_a_disabled,
        MeshGatewaySpawnOptions {
            cp_addr: cp_a.addr,
            ports: ports_disabled,
            node_id: node_a,
            config_protocol: "native",
            topology: "ambient",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.a.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.a.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svids.a.trust_bundle_path.clone(),
                ),
                (
                    "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR",
                    registry.path().display().to_string(),
                ),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_IP6TABLES_ENABLED", "false".to_string()),
            ],
        },
    ));
    assert!(
        wait_for_tcp_port(disabled_outbound, STARTUP_TIMEOUT).await,
        "UDP-disabled gateway A did not start\n{}",
        captured_output(&temp_a_disabled)
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    wait_for_udp_capture_snapshot(pod.pid(), capture_port, false, Duration::from_secs(6))
        .expect("capture-disabled pod must have no UDP rules/listener");
    disabled_a.stop();

    // #2085 fixed fresh-netns installation by checking generation-A chain
    // existence before probing the OUTPUT jump. The live gate below therefore
    // treats every installation timeout, including the old status-2 signature,
    // as a real regression.
    let ports_a = reserve_mesh_ports().await;
    let a_outbound = ports_a.outbound;
    let mut gateway_a = LiveGatewayChild::new(spawn_mesh_gateway(
        &temp_a,
        MeshGatewaySpawnOptions {
            cp_addr: cp_a.addr,
            ports: ports_a,
            node_id: node_a,
            config_protocol: "native",
            topology: "ambient",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_LOG_LEVEL", "debug".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "true".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.a.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.a.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svids.a.trust_bundle_path.clone(),
                ),
                (
                    "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR",
                    registry.path().display().to_string(),
                ),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true".to_string()),
                ("FERRUM_MESH_CAPTURE_UDP_PORT", capture_port.to_string()),
                ("FERRUM_MESH_IP6TABLES_ENABLED", "false".to_string()),
                ("FERRUM_MESH_EGRESS_HBONE_PORT", b_hbone_port.to_string()),
            ],
        },
    ));
    assert!(
        wait_for_tcp_port(a_outbound, STARTUP_TIMEOUT).await,
        "UDP source gateway A did not start\n{}",
        captured_output(&temp_a)
    );
    if let Err(error) =
        wait_for_udp_capture_snapshot(pod.pid(), capture_port, true, Duration::from_secs(20))
    {
        let status = gateway_a.poll_status();
        let gateway_a_output = captured_output(&temp_a);
        // #2085 made first-install detection portable by checking chain existence
        // before probing the OUTPUT jump. A status-2 guard-inspection error is now
        // a genuine xtables/runtime regression and must fail the required live lane.
        let status_2_regression = gateway_a_output.contains(UDP_FAIL_CLOSED_GUARD_PROBE_LITERAL)
            && gateway_a_output.contains("guard (status 2)");
        panic!(
            "real manager/backend must install one UDP producer: {error}; gateway A {status}; \
             status-2 guard regression after #2085 fix: {status_2_regression}\n{gateway_a_output}"
        );
    }

    // Let at least two additional 2s reconcile passes run, then prove neither
    // the manager nor the idempotent scripts duplicated listeners/rules/routes.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let reconciled = udp_capture_snapshot(pod.pid(), capture_port)
        .expect("inspect reconciled UDP producer state");
    assert_eq!(
        reconciled.output_jumps, 1,
        "duplicate OUTPUT jump: {reconciled:?}"
    );
    assert_eq!(
        reconciled.reinject_jumps, 1,
        "duplicate reinject jump: {reconciled:?}"
    );
    assert_eq!(
        reconciled.outbound_jumps, 1,
        "duplicate outbound jump: {reconciled:?}"
    );
    assert_eq!(
        reconciled.route_rules, 1,
        "duplicate fwmark rule: {reconciled:?}"
    );
    assert_eq!(
        reconciled.listeners, 1,
        "duplicate UDP listener: {reconciled:?}"
    );

    let destination: SocketAddr = format!("{VIP}:{echo_port}").parse().expect("UDP VIP");
    let deadline = Instant::now() + Duration::from_secs(18);
    let (reply, source) = loop {
        match udp_round_trip_from_netns(
            pod.pid(),
            destination,
            b"udp-source-capture-live",
            Duration::from_secs(3),
        ) {
            Ok(result) => break result,
            Err(error) if Instant::now() < deadline => {
                eprintln!("UDP source-capture retry while HBONE capability converges: {error}");
            }
            Err(error) => panic!(
                "full UDP source-capture round trip timed out: {error}\n--- gateway A ---\n{}\n--- gateway B ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b)
            ),
        }
    };
    assert_eq!(reply, b"udp-source-capture-live");
    assert_eq!(
        source, destination,
        "the pod client must see the reply sourced from its original VIP:port"
    );

    // Strict route negative: a second TEST-NET VIP is still TPROXY-captured, but
    // it is absent from `mesh_udp_egress`, so no tunnel/backend traffic occurs.
    let received_before = echo_received.load(Ordering::Relaxed);
    let unroutable: SocketAddr = format!("{UNROUTABLE_VIP}:{echo_port}")
        .parse()
        .expect("unroutable UDP VIP");
    assert!(
        udp_round_trip_from_netns(
            pod.pid(),
            unroutable,
            b"must-fail-closed",
            Duration::from_secs(2),
        )
        .is_err(),
        "a UDP destination absent from the route table must fail closed"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        echo_received.load(Ordering::Relaxed),
        received_before,
        "unroutable UDP must not reach the destination echo"
    );

    // Pod deletion: this netns producer test intentionally runs no node-agent.
    // Simulate that separate process only after observing the producer's durable
    // ack requirement. Node-agent unit coverage exercises the real responder,
    // including verified removal, refusal, and restart recovery; only then may
    // the producer remove its retained guard and every remaining rule/route.
    std::fs::remove_file(&registry_entry).expect("delete UDP pod registry entry");
    let ack_required = registry.path().join(".udp-ack-required").join(POD_UID);
    let ack_deadline = Instant::now() + Duration::from_secs(5);
    while !ack_required.exists() && Instant::now() < ack_deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        ack_required.exists(),
        "producer did not request the node-agent UDP close acknowledgement\n{}",
        captured_output(&temp_a)
    );
    let not_ready_dir = registry.path().join(".udp-not-ready");
    std::fs::create_dir_all(&not_ready_dir).expect("create UDP not-ready ack directory");
    std::fs::write(not_ready_dir.join(POD_UID), b"")
        .expect("publish node-agent UDP not-ready acknowledgement");
    wait_for_udp_capture_snapshot(pod.pid(), capture_port, false, Duration::from_secs(12))
        .expect("pod deletion must remove UDP rules/listener");

    // Closing A ends the CONNECT stream. B's relay-completion log is emitted
    // only by `handle_hbone_udp_request` after it accepted the UDP-marked HBONE
    // CONNECT and relayed the framed datagrams, so this proves the round trip did
    // not pass through a direct/plaintext dial from A to the loopback echo.
    gateway_a.stop();
    assert!(
        wait_for_captured_output(
            &temp_b,
            "HBONE UDP tunnel relay completed",
            Duration::from_secs(5),
        )
        .await,
        "gateway B did not confirm the UDP HBONE relay\n{}",
        captured_output(&temp_b)
    );
    gateway_b.stop();
    cp_a.shutdown().await;
    cp_b.shutdown().await;
    echo_task.abort();
}

#[cfg(target_os = "linux")]
struct LiveVethPod {
    pod: LivePodNetns,
    host_if: String,
    host_ip: std::net::Ipv4Addr,
}

#[cfg(target_os = "linux")]
impl LiveVethPod {
    fn spawn() -> Result<Self, String> {
        Self::spawn_indexed(8)
    }

    /// Create a veth-backed namespace on `10.203.<subnet_octet>.0/30`.
    ///
    /// The original source-capture gate owns octet 8. The live two-cluster
    /// fixture uses distinct octets for source cluster A, cluster B's
    /// east-west gateway, and cluster B's destination pod so all three can be
    /// alive at once without sharing namespace-local state or interface names.
    fn spawn_indexed(subnet_octet: u8) -> Result<Self, String> {
        let pod = LivePodNetns::spawn(false)?;
        let suffix = format!("{:x}{subnet_octet:02x}", std::process::id());
        let suffix = &suffix[suffix.len().saturating_sub(8)..];
        let host_if = format!("fh{suffix}");
        let pod_if = format!("fp{suffix}");
        let host_ip = std::net::Ipv4Addr::new(10, 203, subnet_octet, 1);
        let pod_ip = std::net::Ipv4Addr::new(10, 203, subnet_octet, 2);
        let _ = Command::new("ip").args(["link", "del", &host_if]).status();
        let setup = Command::new("ip")
            .args([
                "link", "add", &host_if, "type", "veth", "peer", "name", &pod_if,
            ])
            .status()
            .map_err(|error| format!("create veth: {error}"))?;
        if !setup.success() {
            return Err(format!("create veth failed with {setup}"));
        }
        let move_peer = Command::new("ip")
            .args(["link", "set", &pod_if, "netns", &pod.pid().to_string()])
            .status()
            .map_err(|error| format!("move veth peer: {error}"))?;
        if !move_peer.success() {
            let _ = Command::new("ip").args(["link", "del", &host_if]).status();
            return Err(format!("move veth peer failed with {move_peer}"));
        }
        let host_cidr = format!("{host_ip}/30");
        for args in [
            vec!["addr", "add", host_cidr.as_str(), "dev", host_if.as_str()],
            vec!["link", "set", host_if.as_str(), "up"],
        ] {
            let status = Command::new("ip")
                .args(args.iter().copied())
                .status()
                .map_err(|error| format!("configure host veth: {error}"))?;
            if !status.success() {
                let _ = Command::new("ip").args(["link", "del", &host_if]).status();
                return Err(format!("host veth command {args:?} failed with {status}"));
            }
        }
        if let Err(error) = netns_command(
            pod.pid(),
            &format!(
                "set -e; ip addr add {pod_ip}/30 dev {pod_if}; \
                 ip link set {pod_if} up; ip route add default via {host_ip} dev {pod_if}"
            ),
        ) {
            let _ = Command::new("ip").args(["link", "del", &host_if]).status();
            return Err(error);
        }
        Ok(Self {
            pod,
            host_if,
            host_ip,
        })
    }

    fn pod_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(10, 203, self.host_ip.octets()[2], 2)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveVethPod {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_if])
            .status();
    }
}

#[cfg(target_os = "linux")]
async fn start_tcp_echo_all_interfaces() -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("bind live TCP echo");
    let port = listener.local_addr().expect("TCP echo address").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let _ = stream.write_all(&buf[..n]).await;
            });
        }
    });
    (port, task)
}

#[cfg(target_os = "linux")]
fn make_source_svids_readable_by_sidecar(temp: &TempDir, svids: &TwoGatewaySvids) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
        .expect("make SVID tempdir traversable");
    for path in [
        &svids.a.cert_path,
        &svids.a.key_path,
        &svids.a.trust_bundle_path,
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .expect("make source SVID fixture readable by uid 1337");
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_tcp_port_in_netns(pid: u32, port: u16, timeout: Duration) -> bool {
    wait_for_tcp_addr_in_netns(pid, SocketAddr::from(([127, 0, 0, 1], port)), timeout).await
}

#[cfg(target_os = "linux")]
async fn wait_for_tcp_addr_in_netns(pid: u32, address: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let connected = run_in_live_netns(pid, move || {
            Ok(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok())
        })
        .unwrap_or(false);
        if connected {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_captured_output(temp: &TempDir, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if captured_output(temp).contains(needle) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(target_os = "linux")]
fn tcp_round_trip_from_netns(
    pid: u32,
    destination: SocketAddr,
    payload: &'static [u8],
) -> Result<(Vec<u8>, SocketAddr), String> {
    use std::io::{Read, Write};

    run_in_live_netns(pid, move || {
        let mut stream = std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(5))
            .map_err(|error| format!("connect TCP VIP {destination}: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("set TCP read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| format!("set TCP write timeout: {error}"))?;
        stream
            .write_all(payload)
            .map_err(|error| format!("write TCP payload: {error}"))?;
        let mut reply = vec![0u8; payload.len()];
        stream
            .read_exact(&mut reply)
            .map_err(|error| format!("read TCP echo: {error}"))?;
        let peer = stream
            .peer_addr()
            .map_err(|error| format!("read TCP peer address: {error}"))?;
        Ok((reply, peer))
    })
}

/// Raw-TCP counterpart to the UDP live gate: production iptables REDIRECT rules
/// capture a client in a fresh pod netns, `SO_ORIGINAL_DST` selects the strict
/// VIP:port route, and a real Sidecar source opens the mesh-mTLS CONNECT tunnel
/// to gateway B's destination relay and TCP echo.
#[cfg(target_os = "linux")]
#[ignore = "requires root + netns/veth + iptables REDIRECT"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_mesh_live_source_capture_raw_tcp_mtls_round_trip() {
    if !live_source_capture_prerequisites() {
        return;
    }
    ensure_gateway_built().expect("build gateway for live raw-TCP source-capture test");

    const VIP: &str = "192.0.2.50";
    let veth = match LiveVethPod::spawn() {
        Ok(veth) => veth,
        Err(error) => {
            skip_or_fail_live_source_capture(&format!(
                "cannot create raw-TCP pod netns/veth: {error}"
            ));
            return;
        }
    };
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/tcp-echo";
    let temp_a = TempDir::new().expect("TCP gateway A tempdir");
    let temp_b = TempDir::new().expect("TCP gateway B tempdir");
    let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, b_spiffe);
    make_source_svids_readable_by_sidecar(&temp_b, &svids);
    let (echo_port, echo_task) = start_tcp_echo_all_interfaces().await;
    let workload_address = veth.host_ip.to_string();
    let node_a = "functional-live-tcp-source-a";
    let node_b = "functional-live-tcp-source-b";
    let cp_a = start_static_mesh_cp_on(
        live_source_capture_slice(
            node_a,
            b_spiffe,
            &workload_address,
            VIP,
            echo_port,
            AppProtocol::Tcp,
        ),
        "0.0.0.0:0".parse().expect("wildcard CP bind"),
        Some(std::net::IpAddr::V4(veth.host_ip)),
    )
    .await;
    let cp_b = start_static_mesh_cp(live_source_capture_slice(
        node_b,
        b_spiffe,
        &workload_address,
        VIP,
        echo_port,
        AppProtocol::Tcp,
    ))
    .await;

    let ports_b = reserve_mesh_ports().await;
    let b_inbound = ports_b.inbound;
    let mut gateway_b = LiveGatewayChild::new(spawn_mesh_gateway(
        &temp_b,
        MeshGatewaySpawnOptions {
            cp_addr: cp_b.addr,
            ports: ports_b,
            node_id: node_b,
            config_protocol: "native",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", b_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svids.b.trust_bundle_path.clone(),
                ),
                (
                    "FERRUM_MESH_INBOUND_LISTEN_ADDR",
                    format!("0.0.0.0:{b_inbound}"),
                ),
            ],
        },
    ));
    assert!(
        wait_for_tcp_port(b_inbound, STARTUP_TIMEOUT).await,
        "raw-TCP destination mesh-mTLS listener did not bind\n{}",
        captured_output(&temp_b)
    );

    let ports_a = reserve_mesh_ports().await;
    let a_inbound = ports_a.inbound;
    let a_outbound = ports_a.outbound;
    let mut gateway_a = LiveGatewayChild::new(spawn_mesh_gateway_in_netns(
        &temp_a,
        MeshGatewaySpawnOptions {
            cp_addr: cp_a.addr,
            ports: ports_a,
            node_id: node_a,
            config_protocol: "native",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                ("FERRUM_LOG_LEVEL", "debug".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", a_spiffe.to_string()),
                ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.a.cert_path.clone()),
                ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.a.key_path.clone()),
                (
                    "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                    svids.a.trust_bundle_path.clone(),
                ),
                ("FERRUM_MESH_CAPTURE_MODE", "iptables".to_string()),
                ("FERRUM_MESH_PROXY_UID", "1337".to_string()),
                ("FERRUM_MESH_EGRESS_MTLS_PORT", b_inbound.to_string()),
            ],
        },
        veth.pod.pid(),
    ));
    assert!(
        wait_for_tcp_port_in_netns(veth.pod.pid(), a_outbound, STARTUP_TIMEOUT).await,
        "raw-TCP source Sidecar listener did not bind inside the pod netns\n{}",
        captured_output(&temp_a)
    );

    let mut capture_config = ferrum_edge::capture::CaptureConfig::explicit(a_inbound, a_outbound);
    capture_config.mode = ferrum_edge::capture::CaptureMode::Iptables;
    capture_config.proxy_uid = Some(1337);
    capture_config.ip6tables_mode = ferrum_edge::capture::Ip6TablesMode::Disabled;
    let setup_script = ferrum_edge::capture::IptablesPlan::for_config(&capture_config).script();
    netns_command(veth.pod.pid(), &setup_script).expect("install production TCP REDIRECT rules");

    // Gateway A runs as uid 1337 inside the pod netns. Deny that uid direct
    // access to the echo port while leaving B's mesh-mTLS listener reachable.
    // A plaintext/direct-target regression therefore cannot reach the backend;
    // the round trip can succeed only through B's CONNECT relay (which runs in
    // the host netns and dials the echo as the destination gateway).
    netns_command(
        veth.pod.pid(),
        &format!(
            "iptables -w 5 -t filter -I OUTPUT 1 -p tcp --dport {echo_port} \
             -m owner --uid-owner 1337 -j REJECT"
        ),
    )
    .expect("isolate raw-TCP echo from gateway A direct dials");

    let destination: SocketAddr = format!("{VIP}:{echo_port}").parse().expect("TCP VIP");
    let (reply, peer) = tcp_round_trip_from_netns(
        veth.pod.pid(),
        destination,
        b"raw-tcp-source-capture-live",
    )
    .unwrap_or_else(|error| {
        panic!(
            "full raw-TCP source-capture round trip failed: {error}\n--- gateway A ---\n{}\n--- gateway B ---\n{}",
            captured_output(&temp_a),
            captured_output(&temp_b)
        )
    });
    assert_eq!(reply, b"raw-tcp-source-capture-live");
    assert_eq!(
        peer, destination,
        "the REDIRECTed TCP client must retain the original VIP:port as its peer"
    );

    gateway_a.stop();
    gateway_b.stop();
    cp_a.shutdown().await;
    cp_b.shutdown().await;
    echo_task.abort();
}

// ===================================================================
// Live two-cluster cross-cluster matrix — root + Linux netns + SPIRE (#2083)
// ===================================================================

#[cfg(target_os = "linux")]
const LIVE_XC_TD_A: &str = "cluster-a.test";
#[cfg(target_os = "linux")]
const LIVE_XC_TD_B: &str = "cluster-b.test";
#[cfg(target_os = "linux")]
const LIVE_XC_ID_A: &str = "spiffe://cluster-a.test/ns/ferrum/sa/client";
#[cfg(target_os = "linux")]
const LIVE_XC_ID_A_AMBIENT: &str = "spiffe://cluster-a.test/ns/ferrum/sa/ambient-client";
#[cfg(target_os = "linux")]
const LIVE_XC_ID_A_UNFEDERATED: &str = "spiffe://cluster-a.test/ns/ferrum/sa/unfederated-client";
#[cfg(target_os = "linux")]
const LIVE_XC_ID_B: &str = "spiffe://cluster-b.test/ns/ferrum/sa/destination";
#[cfg(target_os = "linux")]
const LIVE_XC_SOURCE_POD_UID: &str = "11111111-2222-4333-8444-555555555555";

#[cfg(target_os = "linux")]
const LIVE_XC_HTTP_PORT: u16 = 18080;
#[cfg(target_os = "linux")]
const LIVE_XC_GRPC_PORT: u16 = 18081;
#[cfg(target_os = "linux")]
const LIVE_XC_SIDECAR_WS_PORT: u16 = 18082;
#[cfg(target_os = "linux")]
const LIVE_XC_AMBIENT_WS_PORT: u16 = 18083;
#[cfg(target_os = "linux")]
const LIVE_XC_MULTI_A_PORT: u16 = 18084;
#[cfg(target_os = "linux")]
const LIVE_XC_MULTI_B_PORT: u16 = 18085;
#[cfg(target_os = "linux")]
const LIVE_XC_TCP_PORT: u16 = 18086;
#[cfg(target_os = "linux")]
const LIVE_XC_UDP_PORT: u16 = 18087;

#[cfg(target_os = "linux")]
const LIVE_XC_TCP_VIP: &str = "192.0.2.86";
#[cfg(target_os = "linux")]
const LIVE_XC_UDP_VIP: &str = "192.0.2.87";
#[cfg(target_os = "linux")]
const LIVE_XC_MULTI_VIP: &str = "192.0.2.84";

#[cfg(target_os = "linux")]
fn live_xc_spire_script() -> PathBuf {
    std::fs::canonicalize("tests/functional/fixtures/two_cluster_spire.sh")
        .expect("canonicalize two-cluster SPIRE helper")
}

#[cfg(target_os = "linux")]
fn run_live_xc_spire(args: &[&str]) -> Result<String, String> {
    let output = Command::new(live_xc_spire_script())
        .args(args)
        .output()
        .map_err(|error| format!("run two-cluster SPIRE helper {args:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "two-cluster SPIRE helper {args:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
struct LiveTwoClusterSpire {
    cluster_a: TempDir,
    cluster_b: TempDir,
    bundle_a_pem: String,
    bundle_b_pem: String,
}

#[cfg(target_os = "linux")]
struct LiveXcSpireSetupGuard {
    roots: Vec<String>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl Drop for LiveXcSpireSetupGuard {
    fn drop(&mut self) {
        if self.armed {
            for root in &self.roots {
                let _ = run_live_xc_spire(&["stop", root]);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl LiveTwoClusterSpire {
    async fn start() -> Result<Self, String> {
        let cluster_a = TempDir::new().map_err(|error| format!("SPIRE A tempdir: {error}"))?;
        let cluster_b = TempDir::new().map_err(|error| format!("SPIRE B tempdir: {error}"))?;
        let port_a = reserve_port()
            .await
            .map_err(|error| format!("reserve SPIRE A port: {error}"))?
            .drop_and_take_port();
        let port_b = reserve_port()
            .await
            .map_err(|error| format!("reserve SPIRE B port: {error}"))?
            .drop_and_take_port();
        let a_root = cluster_a.path().display().to_string();
        let b_root = cluster_b.path().display().to_string();
        run_live_xc_spire(&["start", &a_root, LIVE_XC_TD_A, &port_a.to_string()])?;
        let mut setup_guard = LiveXcSpireSetupGuard {
            roots: vec![a_root.clone(), b_root.clone()],
            armed: true,
        };
        run_live_xc_spire(&["start", &b_root, LIVE_XC_TD_B, &port_b.to_string()])?;
        run_live_xc_spire(&["federate", &a_root, LIVE_XC_TD_A, &b_root, LIVE_XC_TD_B])?;
        run_live_xc_spire(&[
            "register",
            &a_root,
            LIVE_XC_TD_A,
            LIVE_XC_ID_A,
            LIVE_XC_TD_B,
            "1337",
        ])?;
        run_live_xc_spire(&[
            "register",
            &a_root,
            LIVE_XC_TD_A,
            LIVE_XC_ID_A_AMBIENT,
            LIVE_XC_TD_B,
            "0",
        ])?;
        run_live_xc_spire(&[
            "register",
            &a_root,
            LIVE_XC_TD_A,
            LIVE_XC_ID_A_UNFEDERATED,
            "",
            "1338",
        ])?;
        run_live_xc_spire(&[
            "register",
            &b_root,
            LIVE_XC_TD_B,
            LIVE_XC_ID_B,
            LIVE_XC_TD_A,
            "1337",
        ])?;
        let bundle_a_pem = std::fs::read_to_string(cluster_a.path().join("bundle.pem"))
            .map_err(|error| format!("read SPIRE A bundle: {error}"))?;
        let bundle_b_pem = std::fs::read_to_string(cluster_b.path().join("bundle.pem"))
            .map_err(|error| format!("read SPIRE B bundle: {error}"))?;
        setup_guard.armed = false;
        Ok(Self {
            cluster_a,
            cluster_b,
            bundle_a_pem,
            bundle_b_pem,
        })
    }

    fn agent_socket_a(&self) -> String {
        self.cluster_a
            .path()
            .join("agent.sock")
            .display()
            .to_string()
    }

    fn agent_socket_b(&self) -> String {
        self.cluster_b
            .path()
            .join("agent.sock")
            .display()
            .to_string()
    }

    fn wait_for_cluster_b_svid(&self, workload_id: &str, workload_uid: u32) -> Result<(), String> {
        let root = self.cluster_b.path().display().to_string();
        let uid = workload_uid.to_string();
        run_live_xc_spire(&["wait-svid", &root, workload_id, &uid]).map(|_| ())
    }

    fn diagnostics(&self) -> String {
        let read = |root: &std::path::Path, name: &str| {
            std::fs::read_to_string(root.join(name)).unwrap_or_else(|error| format!("<{error}>"))
        };
        format!(
            "--- SPIRE A server ---\n{}\n--- SPIRE A agent ---\n{}\n\
             --- SPIRE B server ---\n{}\n--- SPIRE B agent ---\n{}",
            read(self.cluster_a.path(), "server.log"),
            read(self.cluster_a.path(), "agent.log"),
            read(self.cluster_b.path(), "server.log"),
            read(self.cluster_b.path(), "agent.log"),
        )
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveTwoClusterSpire {
    fn drop(&mut self) {
        let _ = run_live_xc_spire(&["stop", &self.cluster_a.path().display().to_string()]);
        let _ = run_live_xc_spire(&["stop", &self.cluster_b.path().display().to_string()]);
    }
}

#[cfg(target_os = "linux")]
fn live_xc_ports() -> Vec<WorkloadPort> {
    [
        (LIVE_XC_HTTP_PORT, AppProtocol::Http, "http"),
        (LIVE_XC_GRPC_PORT, AppProtocol::Grpc, "grpc"),
        (LIVE_XC_SIDECAR_WS_PORT, AppProtocol::Http, "sidecar-ws"),
        (LIVE_XC_AMBIENT_WS_PORT, AppProtocol::Http, "ambient-ws"),
        (LIVE_XC_MULTI_A_PORT, AppProtocol::Http, "multi-a"),
        (LIVE_XC_MULTI_B_PORT, AppProtocol::Http, "multi-b"),
        (LIVE_XC_TCP_PORT, AppProtocol::Tcp, "tcp"),
        (LIVE_XC_UDP_PORT, AppProtocol::Udp, "udp"),
    ]
    .into_iter()
    .map(|(port, protocol, name)| WorkloadPort {
        port,
        protocol,
        name: Some(name.to_string()),
    })
    .collect()
}

#[cfg(target_os = "linux")]
fn live_xc_service(
    name: &str,
    ports: &[(u16, AppProtocol, &str)],
    workload: &SpiffeId,
    cluster_ips: Vec<String>,
) -> MeshService {
    MeshService {
        cluster_ips,
        name: name.to_string(),
        namespace: "ferrum".to_string(),
        ports: ports
            .iter()
            .map(|(port, protocol, port_name)| ServicePort {
                port: *port,
                protocol: *protocol,
                name: Some((*port_name).to_string()),
                target_port: None,
            })
            .collect(),
        workloads: vec![WorkloadRef {
            spiffe_id: workload.clone(),
        }],
        protocol_overrides: HashMap::new(),
    }
}

#[cfg(target_os = "linux")]
fn live_xc_services(workload: &SpiffeId) -> Vec<MeshService> {
    vec![live_xc_service(
        "live-matrix",
        &[
            (LIVE_XC_HTTP_PORT, AppProtocol::Http, "http"),
            (LIVE_XC_GRPC_PORT, AppProtocol::Grpc, "grpc"),
            (LIVE_XC_SIDECAR_WS_PORT, AppProtocol::Http, "sidecar-ws"),
            (LIVE_XC_AMBIENT_WS_PORT, AppProtocol::Http, "ambient-ws"),
            (LIVE_XC_MULTI_A_PORT, AppProtocol::Http, "multi-a"),
            (LIVE_XC_MULTI_B_PORT, AppProtocol::Http, "multi-b"),
            (LIVE_XC_TCP_PORT, AppProtocol::Tcp, "tcp"),
            (LIVE_XC_UDP_PORT, AppProtocol::Udp, "udp"),
        ],
        workload,
        vec![
            LIVE_XC_MULTI_VIP.to_string(),
            LIVE_XC_TCP_VIP.to_string(),
            LIVE_XC_UDP_VIP.to_string(),
        ],
    )]
}

#[cfg(target_os = "linux")]
fn live_xc_workload(address: String, remote: bool) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(LIVE_XC_ID_B).expect("live B SPIFFE id"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "live-matrix".to_string())]),
            namespace: Some("ferrum".to_string()),
        },
        service_name: "live-matrix".to_string(),
        addresses: vec![address],
        ports: live_xc_ports(),
        trust_domain: TrustDomain::new(LIVE_XC_TD_B).expect("live B trust domain"),
        namespace: "ferrum".to_string(),
        network: remote.then(|| "net-b".to_string()),
        cluster: remote.then(|| "cluster-b".to_string()),
        weight: None,
        locality: remote.then(|| "cluster-b/net-b".to_string()),
        service_account: Some("destination".to_string()),
        pod_uid: Some("live-xc-destination".to_string()),
        node_waypoint: None,
        remote_provenance: remote,
    }
}

#[cfg(target_os = "linux")]
fn live_xc_dest_slice(
    node_id: &str,
    dest_ip: std::net::Ipv4Addr,
    bundle_b: &str,
    bundle_a: &str,
) -> MeshSlice {
    let workload_id = SpiffeId::new(LIVE_XC_ID_B).expect("live B SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![live_xc_workload(dest_ip.to_string(), false)],
        services: live_xc_services(&workload_id),
        peer_authentications: vec![PeerAuthentication {
            name: "strict-live-cross-cluster".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        trust_bundles: Some(federated_trust_bundle_set(
            LIVE_XC_TD_B,
            bundle_b,
            LIVE_XC_TD_A,
            bundle_a,
        )),
        ..MeshSlice::default()
    }
}

#[cfg(target_os = "linux")]
fn live_xc_east_west_slice(node_id: &str, dest_ip: std::net::Ipv4Addr) -> MeshSlice {
    let workload_id = SpiffeId::new(LIVE_XC_ID_B).expect("live B SPIFFE id");
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![live_xc_workload(dest_ip.to_string(), false)],
        services: live_xc_services(&workload_id),
        ..MeshSlice::default()
    }
}

#[cfg(target_os = "linux")]
fn live_xc_source_slice(
    node_id: &str,
    dest_ip: std::net::Ipv4Addr,
    east_west_ip: std::net::Ipv4Addr,
    east_west_port: u16,
) -> MeshSlice {
    let workload_id = SpiffeId::new(LIVE_XC_ID_B).expect("live B SPIFFE id");
    let services = live_xc_services(&workload_id);
    let sni_hosts = services
        .iter()
        .map(|service| format!("{}.ferrum.svc.cluster.local", service.name))
        .collect();
    let source_id = SpiffeId::new(LIVE_XC_ID_A_AMBIENT).expect("live Ambient A SPIFFE id");
    let source_workload = Workload {
        spiffe_id: source_id,
        selector: WorkloadSelector::default(),
        service_name: "live-source".to_string(),
        addresses: vec!["127.0.0.1".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new(LIVE_XC_TD_A).expect("live A trust domain"),
        namespace: "ferrum".to_string(),
        network: Some("net-a".to_string()),
        cluster: Some("cluster-a".to_string()),
        weight: None,
        locality: None,
        service_account: Some("client".to_string()),
        pod_uid: Some(LIVE_XC_SOURCE_POD_UID.to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![live_xc_workload(dest_ip.to_string(), true)],
        ambient_udp_source_workloads: vec![source_workload],
        services,
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            federation_endpoint: None,
            remote_clusters: Vec::new(),
            east_west_gateways: vec![EastWestGateway {
                name: "cluster-b-east-west".to_string(),
                namespace: "ferrum".to_string(),
                host: east_west_ip.to_string(),
                port: east_west_port,
                sni_hosts,
                trust_domain: Some(TrustDomain::new(LIVE_XC_TD_B).expect("live B trust domain")),
                network: Some("net-b".to_string()),
            }],
        }),
        // Outbound trust intentionally comes from the selected SPIRE-issued
        // X509-SVID's federated bundle. The unfederated identity negative uses
        // the same slice and therefore cannot inherit peer trust from config.
        trust_bundles: None,
        ..MeshSlice::default()
    }
}

#[cfg(target_os = "linux")]
fn live_xc_spire_env(
    socket: String,
    workload_id: &str,
    dns_resolver: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
        ("FERRUM_MESH_ALLOW_NO_CA", "false".to_string()),
        ("FERRUM_MESH_CA_BACKEND", "spire_agent".to_string()),
        ("FERRUM_MESH_SPIRE_AGENT_SOCKET", socket),
        ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", workload_id.to_string()),
        ("FERRUM_DNS_RESOLVER_ADDRESS", dns_resolver.to_string()),
        ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
        ("FERRUM_LOG_LEVEL", "debug".to_string()),
    ]
}

#[cfg(target_os = "linux")]
struct LiveXcDnsServer {
    resolver: String,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl LiveXcDnsServer {
    async fn start(advertised_ip: std::net::Ipv4Addr) -> Result<Self, String> {
        let socket = tokio::net::UdpSocket::bind(SocketAddr::from((advertised_ip, 0)))
            .await
            .map_err(|error| format!("bind live fixture DNS responder: {error}"))?;
        let port = socket
            .local_addr()
            .map_err(|error| format!("read live fixture DNS address: {error}"))?
            .port();
        let task = tokio::spawn(async move {
            let mut request = [0u8; 2048];
            loop {
                let Ok((size, peer)) = socket.recv_from(&mut request).await else {
                    return;
                };
                if size < 12 {
                    continue;
                }
                let mut response = request[..size].to_vec();
                response[2] = 0x81;
                response[3] = 0x83;
                response[6..12].fill(0);
                let _ = socket.send_to(&response, peer).await;
            }
        });
        Ok(Self {
            resolver: format!("{advertised_ip}:{port}"),
            task,
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveXcDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(target_os = "linux")]
async fn live_xc_http_backend(listener: TcpListener, label: &'static str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                label.len(),
                label
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(target_os = "linux")]
async fn live_xc_grpc_backend(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let service = service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();
                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                    let _ = tx.send(Ok(Frame::data(body))).await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                    trailers.insert(
                        "x-live-two-cluster",
                        hyper::header::HeaderValue::from_static("grpc-ok"),
                    );
                    let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    drop(tx);
                    Ok::<_, hyper::Error>(
                        hyper::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(StreamBody::new(ReceiverStream::new(rx)))
                            .expect("build live gRPC response"),
                    )
                },
            );
            let _ = Http2ServerBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(target_os = "linux")]
async fn live_xc_websocket_backend(listener: TcpListener) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                return;
            };
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(text) => {
                        if ws
                            .send(Message::Text(format!("backend-ws:{text}").into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Message::Binary(bytes) => {
                        if ws.send(Message::Binary(bytes)).await.is_err() {
                            return;
                        }
                    }
                    Message::Close(_) => {
                        let _ = ws.send(Message::Close(None)).await;
                        return;
                    }
                    Message::Ping(bytes) => {
                        let _ = ws.send(Message::Pong(bytes)).await;
                    }
                    _ => {}
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn live_xc_tcp_backend(listener: TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if let Ok(size) = socket.read(&mut buf).await {
                let _ = socket.write_all(&buf[..size]).await;
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn live_xc_udp_backend(socket: tokio::net::UdpSocket) {
    let mut buf = [0u8; 65535];
    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        if socket.send_to(&buf[..size], peer).await.is_err() {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
struct LiveXcBackends {
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl LiveXcBackends {
    fn start(netns_pid: u32) -> Result<Self, String> {
        use std::os::fd::AsRawFd;

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let setup = (|| -> Result<tokio::runtime::Runtime, String> {
                let netns = std::fs::File::open(format!("/proc/{netns_pid}/ns/net"))
                    .map_err(|error| format!("open destination netns: {error}"))?;
                // Safety: this dedicated backend thread never returns to a
                // different namespace-aware runtime after setns.
                if unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err(format!(
                        "enter destination netns: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("build destination backend runtime: {error}"))
            })();
            let runtime = match setup {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let bind_tcp = |port| async move {
                    TcpListener::bind(("0.0.0.0", port))
                        .await
                        .map_err(|error| format!("bind destination TCP port {port}: {error}"))
                };
                let listeners = futures_util::future::try_join_all(
                    [
                        LIVE_XC_HTTP_PORT,
                        LIVE_XC_GRPC_PORT,
                        LIVE_XC_SIDECAR_WS_PORT,
                        LIVE_XC_AMBIENT_WS_PORT,
                        LIVE_XC_MULTI_A_PORT,
                        LIVE_XC_MULTI_B_PORT,
                        LIVE_XC_TCP_PORT,
                    ]
                    .into_iter()
                    .map(bind_tcp),
                )
                .await;
                let mut listeners = match listeners {
                    Ok(listeners) => listeners.into_iter(),
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let udp = match tokio::net::UdpSocket::bind(("0.0.0.0", LIVE_XC_UDP_PORT)).await {
                    Ok(socket) => socket,
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "bind destination UDP port {LIVE_XC_UDP_PORT}: {error}"
                        )));
                        return;
                    }
                };
                tokio::spawn(live_xc_http_backend(
                    listeners.next().expect("HTTP listener"),
                    "http-live-ok",
                ));
                tokio::spawn(live_xc_grpc_backend(
                    listeners.next().expect("gRPC listener"),
                ));
                tokio::spawn(live_xc_websocket_backend(
                    listeners.next().expect("Sidecar WS listener"),
                ));
                tokio::spawn(live_xc_websocket_backend(
                    listeners.next().expect("Ambient WS listener"),
                ));
                tokio::spawn(live_xc_http_backend(
                    listeners.next().expect("multi A listener"),
                    "multi-a-ok",
                ));
                tokio::spawn(live_xc_http_backend(
                    listeners.next().expect("multi B listener"),
                    "multi-b-ok",
                ));
                tokio::spawn(live_xc_tcp_backend(listeners.next().expect("TCP listener")));
                tokio::spawn(live_xc_udp_backend(udp));
                let _ = ready_tx.send(Ok(()));
                while shutdown_rx.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| format!("wait for destination backends: {error}"))??;
        Ok(Self {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveXcBackends {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn live_xc_wrong_trust_domain_slice(
    node_id: &str,
    dest_ip: std::net::Ipv4Addr,
    east_west_ip: std::net::Ipv4Addr,
    east_west_port: u16,
) -> MeshSlice {
    let mut slice = live_xc_source_slice(node_id, dest_ip, east_west_ip, east_west_port);
    let wrong_id = SpiffeId::new("spiffe://cluster-wrong.test/ns/ferrum/sa/destination")
        .expect("wrong-domain test SPIFFE id");
    slice.workloads[0].spiffe_id = wrong_id.clone();
    slice.workloads[0].trust_domain =
        TrustDomain::new("cluster-wrong.test").expect("wrong test trust domain");
    for service in &mut slice.services {
        service.workloads = vec![WorkloadRef {
            spiffe_id: wrong_id.clone(),
        }];
    }
    if let Some(multi_cluster) = &mut slice.multi_cluster
        && let Some(gateway) = multi_cluster.east_west_gateways.first_mut()
    {
        gateway.trust_domain =
            Some(TrustDomain::new("cluster-wrong.test").expect("wrong test trust domain"));
    }
    slice
}

#[cfg(target_os = "linux")]
fn live_xc_missing_sni_slice(
    node_id: &str,
    dest_ip: std::net::Ipv4Addr,
    east_west_ip: std::net::Ipv4Addr,
    east_west_port: u16,
) -> MeshSlice {
    let mut slice = live_xc_source_slice(node_id, dest_ip, east_west_ip, east_west_port);
    if let Some(multi_cluster) = &mut slice.multi_cluster
        && let Some(gateway) = multi_cluster.east_west_gateways.first_mut()
    {
        // Keep the gateway structurally valid while ensuring it owns no SNI
        // acceptable for the requested service. Materialization therefore
        // omits the cross-cluster target and the request is refused pre-dial.
        gateway.sni_hosts = vec!["unrelated.ferrum.svc.cluster.local".to_string()];
    }
    slice
}

#[cfg(target_os = "linux")]
struct LiveXcHostNetwork {
    forward_chain: String,
    output_chain: String,
    previous_forwarding: String,
    ambient_capture: Option<(String, u16)>,
}

#[cfg(target_os = "linux")]
impl LiveXcHostNetwork {
    fn install(
        source_ip: std::net::Ipv4Addr,
        east_west_ip: std::net::Ipv4Addr,
        dest_ip: std::net::Ipv4Addr,
    ) -> Result<Self, String> {
        let previous_forwarding = Command::new("sysctl")
            .args(["-n", "net.ipv4.ip_forward"])
            .output()
            .map_err(|error| format!("read host IPv4 forwarding: {error}"))?;
        if !previous_forwarding.status.success() {
            return Err(format!(
                "read host IPv4 forwarding failed: {}",
                String::from_utf8_lossy(&previous_forwarding.stderr)
            ));
        }
        let previous_forwarding = String::from_utf8_lossy(&previous_forwarding.stdout)
            .trim()
            .to_string();
        let forwarding = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output()
            .map_err(|error| format!("enable host IPv4 forwarding: {error}"))?;
        if !forwarding.status.success() {
            return Err(format!(
                "enable host IPv4 forwarding failed: {}",
                String::from_utf8_lossy(&forwarding.stderr)
            ));
        }
        let forward_chain = format!("FXC{:x}", std::process::id());
        let output_chain = format!("FXO{:x}", std::process::id());
        let script = format!(
            "set -e; \
             iptables -w 5 -t filter -N {forward_chain}; \
             iptables -w 5 -t filter -N {output_chain}; \
             iptables -w 5 -t filter -I FORWARD 1 -j {forward_chain}; \
             iptables -w 5 -t filter -I OUTPUT 1 -j {output_chain}; \
             iptables -w 5 -t filter -A {forward_chain} -s {source_ip} -d {dest_ip} -j REJECT; \
             iptables -w 5 -t filter -A {forward_chain} -s {source_ip} -d {east_west_ip} -j ACCEPT; \
             iptables -w 5 -t filter -A {forward_chain} -s {east_west_ip} -d {dest_ip} -j ACCEPT; \
             iptables -w 5 -t filter -A {forward_chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
             iptables -w 5 -t filter -A {forward_chain} -j RETURN; \
             iptables -w 5 -t filter -A {output_chain} -p tcp -d {dest_ip} \
               -m conntrack --ctstate NEW -j REJECT; \
             iptables -w 5 -t filter -A {output_chain} -p udp -d {dest_ip} \
               --dport {LIVE_XC_UDP_PORT} -j REJECT; \
             iptables -w 5 -t filter -A {output_chain} -j RETURN"
        );
        let installed = Command::new("sh")
            .args(["-c", &script])
            .status()
            .map_err(|error| format!("install live cross-cluster host firewall: {error}"))?;
        if !installed.success() {
            let _ = Command::new("sh")
                .args([
                    "-c",
                    &format!(
                        "iptables -w 5 -t filter -D FORWARD -j {forward_chain} 2>/dev/null || true; \
                         iptables -w 5 -t filter -D OUTPUT -j {output_chain} 2>/dev/null || true; \
                         iptables -w 5 -t filter -F {forward_chain} 2>/dev/null || true; \
                         iptables -w 5 -t filter -F {output_chain} 2>/dev/null || true; \
                         iptables -w 5 -t filter -X {forward_chain} 2>/dev/null || true; \
                         iptables -w 5 -t filter -X {output_chain} 2>/dev/null || true"
                    ),
                ])
                .status();
            let _ = Command::new("sysctl")
                .args(["-w", &format!("net.ipv4.ip_forward={previous_forwarding}")])
                .status();
            return Err("install live cross-cluster host firewall failed".to_string());
        }
        Ok(Self {
            forward_chain,
            output_chain,
            previous_forwarding,
            ambient_capture: None,
        })
    }

    fn install_ambient_capture(
        &mut self,
        source_if: &str,
        ambient_outbound: u16,
    ) -> Result<(), String> {
        // The Ambient node proxy runs in the host netns. Redirect the source
        // pod's VIP flow as it enters the host so SO_ORIGINAL_DST on the host
        // listener still carries the service port used for multi-port routing.
        let rule = format!(
            "iptables -w 5 -t nat -I PREROUTING 1 -i {source_if} \
             -p tcp -d {LIVE_XC_MULTI_VIP} --dport {LIVE_XC_AMBIENT_WS_PORT} \
             -j REDIRECT --to-ports {ambient_outbound}"
        );
        let installed = Command::new("sh")
            .args(["-c", &rule])
            .status()
            .map_err(|error| format!("install Ambient WebSocket host capture: {error}"))?;
        if !installed.success() {
            return Err("install Ambient WebSocket host capture failed".to_string());
        }
        self.ambient_capture = Some((source_if.to_string(), ambient_outbound));
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveXcHostNetwork {
    fn drop(&mut self) {
        if let Some((source_if, ambient_outbound)) = &self.ambient_capture {
            let _ = Command::new("sh")
                .args([
                    "-c",
                    &format!(
                        "iptables -w 5 -t nat -D PREROUTING -i {source_if} \
                         -p tcp -d {LIVE_XC_MULTI_VIP} --dport {LIVE_XC_AMBIENT_WS_PORT} \
                         -j REDIRECT --to-ports {ambient_outbound} 2>/dev/null || true"
                    ),
                ])
                .status();
        }
        let _ = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "iptables -w 5 -t filter -D FORWARD -j {0} 2>/dev/null || true; \
                     iptables -w 5 -t filter -D OUTPUT -j {1} 2>/dev/null || true; \
                     iptables -w 5 -t filter -F {0} 2>/dev/null || true; \
                     iptables -w 5 -t filter -F {1} 2>/dev/null || true; \
                     iptables -w 5 -t filter -X {0} 2>/dev/null || true; \
                     iptables -w 5 -t filter -X {1} 2>/dev/null || true",
                    self.forward_chain, self.output_chain
                ),
            ])
            .status();
        let _ = Command::new("sysctl")
            .args([
                "-w",
                &format!("net.ipv4.ip_forward={}", self.previous_forwarding),
            ])
            .status();
    }
}

#[cfg(target_os = "linux")]
fn live_xc_install_destination_capture(
    dest_pid: u32,
    sidecar_inbound: u16,
    ambient_hbone: u16,
) -> Result<(), String> {
    let mut script = format!(
        "set -e; iptables -w 5 -t nat -N FERRUM_XC_INBOUND; \
         iptables -w 5 -t nat -A PREROUTING -p tcp -j FERRUM_XC_INBOUND; \
         iptables -w 5 -t nat -A FERRUM_XC_INBOUND -p tcp --dport {sidecar_inbound} -j RETURN; \
         iptables -w 5 -t nat -A FERRUM_XC_INBOUND -p tcp --dport {ambient_hbone} -j RETURN; "
    );
    for port in [
        LIVE_XC_HTTP_PORT,
        LIVE_XC_GRPC_PORT,
        LIVE_XC_SIDECAR_WS_PORT,
        LIVE_XC_MULTI_A_PORT,
        LIVE_XC_MULTI_B_PORT,
        LIVE_XC_TCP_PORT,
    ] {
        script.push_str(&format!(
            "iptables -w 5 -t nat -A FERRUM_XC_INBOUND -p tcp --dport {port} \
             -j REDIRECT --to-ports {sidecar_inbound}; "
        ));
    }
    for port in [LIVE_XC_AMBIENT_WS_PORT, LIVE_XC_UDP_PORT] {
        script.push_str(&format!(
            "iptables -w 5 -t nat -A FERRUM_XC_INBOUND -p tcp --dport {port} \
             -j REDIRECT --to-ports {ambient_hbone}; "
        ));
    }
    netns_command(dest_pid, &script).map(|_| ())
}

#[cfg(target_os = "linux")]
struct LiveXcGatewaySpawnOptions {
    node_id: &'static str,
    topology: &'static str,
    netns_pid: Option<u32>,
    run_uid: Option<u32>,
    env: Vec<(&'static str, String)>,
}

#[cfg(target_os = "linux")]
fn live_xc_spawn_gateway(
    temp: &TempDir,
    cp_addr: SocketAddr,
    ports: MeshPorts,
    spawn: LiveXcGatewaySpawnOptions,
) -> LiveGatewayChild {
    let LiveXcGatewaySpawnOptions {
        node_id,
        topology,
        netns_pid,
        run_uid,
        mut env,
    } = spawn;
    env.push((
        "FERRUM_MESH_INBOUND_LISTEN_ADDR",
        format!("0.0.0.0:{}", ports.inbound),
    ));
    env.push((
        "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
        format!("0.0.0.0:{}", ports.outbound),
    ));
    env.push((
        "FERRUM_MESH_HBONE_LISTEN_ADDR",
        format!("0.0.0.0:{}", ports.hbone),
    ));
    let options = MeshGatewaySpawnOptions {
        cp_addr,
        ports,
        node_id,
        config_protocol: "native",
        topology,
        waypoint_name: None,
        env_overrides: env,
    };
    let child = match (netns_pid, run_uid) {
        (Some(netns_pid), Some(uid)) => {
            spawn_mesh_gateway_in_netns_as_uid(temp, options, netns_pid, uid)
        }
        (Some(netns_pid), None) => spawn_mesh_gateway_in_netns_as_root(temp, options, netns_pid),
        (None, None) => spawn_mesh_gateway(temp, options),
        (None, Some(_)) => unreachable!("host-netns live gateways run as the test user"),
    };
    LiveGatewayChild::new(child)
}

#[cfg(target_os = "linux")]
struct LiveTwoClusterFixture {
    source: LiveVethPod,
    _east_west: LiveVethPod,
    destination: LiveVethPod,
    _host_network: LiveXcHostNetwork,
    _dns: LiveXcDnsServer,
    _spire: LiveTwoClusterSpire,
    _backends: LiveXcBackends,
    _registry: TempDir,
    _registry_entry: PathBuf,
    sidecar_source: LiveGatewayChild,
    ambient_source: LiveGatewayChild,
    unfederated_source: LiveGatewayChild,
    wrong_td_source: LiveGatewayChild,
    missing_sni_source: LiveGatewayChild,
    east_west_gateway: LiveGatewayChild,
    sidecar_destination: LiveGatewayChild,
    ambient_destination: LiveGatewayChild,
    cp_sidecar_source: MeshCpHandle,
    cp_ambient_source: MeshCpHandle,
    cp_unfederated_source: MeshCpHandle,
    cp_wrong_td_source: MeshCpHandle,
    cp_missing_sni_source: MeshCpHandle,
    cp_east_west: MeshCpHandle,
    cp_sidecar_destination: MeshCpHandle,
    cp_ambient_destination: MeshCpHandle,
    temp_sidecar_source: TempDir,
    temp_ambient_source: TempDir,
    temp_unfederated_source: TempDir,
    temp_wrong_td_source: TempDir,
    temp_missing_sni_source: TempDir,
    temp_east_west: TempDir,
    temp_sidecar_destination: TempDir,
    temp_ambient_destination: TempDir,
    sidecar_destination_inbound: u16,
    ambient_destination_hbone: u16,
    sidecar_inbound: u16,
    sidecar_outbound: u16,
    ambient_outbound: u16,
    unfederated_outbound: u16,
    wrong_td_outbound: u16,
    missing_sni_outbound: u16,
    tcp_capture_installed: bool,
}

#[cfg(target_os = "linux")]
impl LiveTwoClusterFixture {
    async fn start() -> Result<Self, String> {
        let source = LiveVethPod::spawn_indexed(20)?;
        let east_west = LiveVethPod::spawn_indexed(21)?;
        let destination = LiveVethPod::spawn_indexed(22)?;
        let mut host_network =
            LiveXcHostNetwork::install(source.pod_ip(), east_west.pod_ip(), destination.pod_ip())?;
        let dns = LiveXcDnsServer::start(source.host_ip).await?;
        let spire = LiveTwoClusterSpire::start().await?;
        let backends = LiveXcBackends::start(destination.pod.pid())?;
        let registry = TempDir::new().map_err(|error| format!("live registry tempdir: {error}"))?;
        let registry_entry = source.pod.publish_with_identity(
            registry.path(),
            LIVE_XC_SOURCE_POD_UID,
            Some(LIVE_XC_ID_A_AMBIENT),
        )?;

        let temp_sidecar_source = TempDir::new().map_err(|e| format!("source tempdir: {e}"))?;
        let temp_ambient_source = TempDir::new().map_err(|e| format!("ambient tempdir: {e}"))?;
        let temp_unfederated_source =
            TempDir::new().map_err(|e| format!("unfederated tempdir: {e}"))?;
        let temp_wrong_td_source = TempDir::new().map_err(|e| format!("wrong-TD tempdir: {e}"))?;
        let temp_missing_sni_source =
            TempDir::new().map_err(|e| format!("missing-SNI tempdir: {e}"))?;
        let temp_east_west = TempDir::new().map_err(|e| format!("east-west tempdir: {e}"))?;
        let temp_sidecar_destination =
            TempDir::new().map_err(|e| format!("sidecar dest tempdir: {e}"))?;
        let temp_ambient_destination =
            TempDir::new().map_err(|e| format!("ambient dest tempdir: {e}"))?;

        let ports_sidecar_destination = reserve_mesh_ports().await;
        let sidecar_destination_inbound = ports_sidecar_destination.inbound;
        let ports_ambient_destination = reserve_mesh_ports().await;
        let ambient_destination_hbone = ports_ambient_destination.hbone;
        let ports_east_west = reserve_mesh_ports().await;
        let east_west_port = ports_east_west.east_west;

        let cp_sidecar_destination = start_static_mesh_cp_on(
            live_xc_dest_slice(
                "live-xc-sidecar-destination",
                destination.pod_ip(),
                &spire.bundle_b_pem,
                &spire.bundle_a_pem,
            ),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(destination.host_ip)),
        )
        .await;
        let cp_ambient_destination = start_static_mesh_cp_on(
            live_xc_dest_slice(
                "live-xc-ambient-destination",
                destination.pod_ip(),
                &spire.bundle_b_pem,
                &spire.bundle_a_pem,
            ),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(destination.host_ip)),
        )
        .await;
        let cp_east_west = start_static_mesh_cp_on(
            live_xc_east_west_slice("live-xc-east-west", destination.pod_ip()),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(east_west.host_ip)),
        )
        .await;

        let sidecar_destination = live_xc_spawn_gateway(
            &temp_sidecar_destination,
            cp_sidecar_destination.addr,
            ports_sidecar_destination,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-sidecar-destination",
                topology: "sidecar",
                netns_pid: Some(destination.pod.pid()),
                run_uid: Some(1337),
                env: live_xc_spire_env(spire.agent_socket_b(), LIVE_XC_ID_B, &dns.resolver),
            },
        );
        if !wait_for_tcp_port_in_netns(
            destination.pod.pid(),
            sidecar_destination_inbound,
            STARTUP_TIMEOUT,
        )
        .await
        {
            return Err(format!(
                "sidecar destination did not bind\n{}\n{}",
                captured_output(&temp_sidecar_destination),
                spire.diagnostics()
            ));
        }
        let ambient_destination = live_xc_spawn_gateway(
            &temp_ambient_destination,
            cp_ambient_destination.addr,
            ports_ambient_destination,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-ambient-destination",
                topology: "ambient",
                netns_pid: Some(destination.pod.pid()),
                run_uid: Some(1337),
                env: live_xc_spire_env(spire.agent_socket_b(), LIVE_XC_ID_B, &dns.resolver),
            },
        );
        if !wait_for_tcp_port_in_netns(
            destination.pod.pid(),
            ambient_destination_hbone,
            STARTUP_TIMEOUT,
        )
        .await
        {
            return Err(format!(
                "ambient destination did not bind\n{}\n{}",
                captured_output(&temp_ambient_destination),
                spire.diagnostics()
            ));
        }
        live_xc_install_destination_capture(
            destination.pod.pid(),
            sidecar_destination_inbound,
            ambient_destination_hbone,
        )?;

        let east_west_gateway = live_xc_spawn_gateway(
            &temp_east_west,
            cp_east_west.addr,
            ports_east_west,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-east-west",
                topology: "east_west_gateway",
                netns_pid: Some(east_west.pod.pid()),
                run_uid: Some(1337),
                env: live_xc_spire_env(spire.agent_socket_b(), LIVE_XC_ID_B, &dns.resolver),
            },
        );
        if !wait_for_tcp_port_in_netns(east_west.pod.pid(), east_west_port, STARTUP_TIMEOUT).await {
            return Err(format!(
                "east-west gateway did not bind\n{}\n{}",
                captured_output(&temp_east_west),
                spire.diagnostics()
            ));
        }
        spire.wait_for_cluster_b_svid(LIVE_XC_ID_B, 1337)?;
        let east_west_address = SocketAddr::from((east_west.pod_ip(), east_west_port));
        if !wait_for_tcp_addr_in_netns(source.pod.pid(), east_west_address, STARTUP_TIMEOUT).await {
            return Err(format!(
                "source cluster could not connect to the SVID-ready east-west listener\n{}\n{}",
                captured_output(&temp_east_west),
                spire.diagnostics()
            ));
        }

        let source_slice = |node_id| {
            live_xc_source_slice(
                node_id,
                destination.pod_ip(),
                east_west.pod_ip(),
                east_west_port,
            )
        };
        let cp_sidecar_source = start_static_mesh_cp_on(
            source_slice("live-xc-sidecar-source"),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(source.host_ip)),
        )
        .await;
        let cp_ambient_source = start_static_mesh_cp_on(
            source_slice("live-xc-ambient-source"),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(source.host_ip)),
        )
        .await;
        let cp_unfederated_source = start_static_mesh_cp_on(
            source_slice("live-xc-unfederated-source"),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(source.host_ip)),
        )
        .await;
        let cp_wrong_td_source = start_static_mesh_cp_on(
            live_xc_wrong_trust_domain_slice(
                "live-xc-wrong-td-source",
                destination.pod_ip(),
                east_west.pod_ip(),
                east_west_port,
            ),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(source.host_ip)),
        )
        .await;
        let cp_missing_sni_source = start_static_mesh_cp_on(
            live_xc_missing_sni_slice(
                "live-xc-missing-sni-source",
                destination.pod_ip(),
                east_west.pod_ip(),
                east_west_port,
            ),
            "0.0.0.0:0".parse().expect("wildcard CP bind"),
            Some(std::net::IpAddr::V4(source.host_ip)),
        )
        .await;

        let ports_sidecar_source = reserve_mesh_ports().await;
        let sidecar_inbound = ports_sidecar_source.inbound;
        let sidecar_outbound = ports_sidecar_source.outbound;
        let mut sidecar_env =
            live_xc_spire_env(spire.agent_socket_a(), LIVE_XC_ID_A, &dns.resolver);
        sidecar_env.extend([
            ("FERRUM_MESH_CAPTURE_MODE", "iptables".to_string()),
            ("FERRUM_MESH_PROXY_UID", "1337".to_string()),
        ]);
        let sidecar_source = live_xc_spawn_gateway(
            &temp_sidecar_source,
            cp_sidecar_source.addr,
            ports_sidecar_source,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-sidecar-source",
                topology: "sidecar",
                netns_pid: Some(source.pod.pid()),
                run_uid: Some(1337),
                env: sidecar_env,
            },
        );

        let ports_ambient_source = reserve_mesh_ports().await;
        let ambient_outbound = ports_ambient_source.outbound;
        host_network.install_ambient_capture(&source.host_if, ambient_outbound)?;
        let udp_capture_port = ferrum_edge::capture::DEFAULT_UDP_OUTBOUND_PORT;
        let mut ambient_env =
            live_xc_spire_env(spire.agent_socket_a(), LIVE_XC_ID_A_AMBIENT, &dns.resolver);
        ambient_env.extend([
            ("FERRUM_POOL_WARMUP_ENABLED", "true".to_string()),
            (
                "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR",
                registry.path().display().to_string(),
            ),
            ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true".to_string()),
            ("FERRUM_MESH_CAPTURE_UDP_PORT", udp_capture_port.to_string()),
            ("FERRUM_MESH_IP6TABLES_ENABLED", "false".to_string()),
        ]);
        let mut ambient_source = live_xc_spawn_gateway(
            &temp_ambient_source,
            cp_ambient_source.addr,
            ports_ambient_source,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-ambient-source",
                topology: "ambient",
                // Ambient is a node proxy: it must stay outside workload
                // namespaces so the per-pod UDP producer can distinguish the
                // registry target from its own host/proxy namespace.
                netns_pid: None,
                run_uid: None,
                env: ambient_env,
            },
        );

        let ports_unfederated = reserve_mesh_ports().await;
        let unfederated_outbound = ports_unfederated.outbound;
        let unfederated_source = live_xc_spawn_gateway(
            &temp_unfederated_source,
            cp_unfederated_source.addr,
            ports_unfederated,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-unfederated-source",
                topology: "sidecar",
                netns_pid: Some(source.pod.pid()),
                run_uid: Some(1338),
                env: live_xc_spire_env(
                    spire.agent_socket_a(),
                    LIVE_XC_ID_A_UNFEDERATED,
                    &dns.resolver,
                ),
            },
        );

        let ports_wrong_td = reserve_mesh_ports().await;
        let wrong_td_outbound = ports_wrong_td.outbound;
        let wrong_td_source = live_xc_spawn_gateway(
            &temp_wrong_td_source,
            cp_wrong_td_source.addr,
            ports_wrong_td,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-wrong-td-source",
                topology: "sidecar",
                netns_pid: Some(source.pod.pid()),
                run_uid: Some(1337),
                env: live_xc_spire_env(spire.agent_socket_a(), LIVE_XC_ID_A, &dns.resolver),
            },
        );

        let ports_missing_sni = reserve_mesh_ports().await;
        let missing_sni_outbound = ports_missing_sni.outbound;
        let missing_sni_source = live_xc_spawn_gateway(
            &temp_missing_sni_source,
            cp_missing_sni_source.addr,
            ports_missing_sni,
            LiveXcGatewaySpawnOptions {
                node_id: "live-xc-missing-sni-source",
                topology: "sidecar",
                netns_pid: Some(source.pod.pid()),
                run_uid: Some(1337),
                env: live_xc_spire_env(spire.agent_socket_a(), LIVE_XC_ID_A, &dns.resolver),
            },
        );

        for (label, port, temp) in [
            ("sidecar source", sidecar_outbound, &temp_sidecar_source),
            (
                "unfederated source",
                unfederated_outbound,
                &temp_unfederated_source,
            ),
            ("wrong-TD source", wrong_td_outbound, &temp_wrong_td_source),
            (
                "missing-SNI source",
                missing_sni_outbound,
                &temp_missing_sni_source,
            ),
        ] {
            if !wait_for_tcp_port_in_netns(source.pod.pid(), port, STARTUP_TIMEOUT).await {
                return Err(format!(
                    "{label} did not bind\n{}\n{}",
                    captured_output(temp),
                    spire.diagnostics()
                ));
            }
        }
        let ambient_address = SocketAddr::from((source.host_ip, ambient_outbound));
        if !wait_for_tcp_addr_in_netns(source.pod.pid(), ambient_address, STARTUP_TIMEOUT).await {
            return Err(format!(
                "ambient source did not bind outside the workload netns\n{}\n{}",
                captured_output(&temp_ambient_source),
                spire.diagnostics()
            ));
        }
        if let Err(error) = wait_for_udp_capture_snapshot(
            source.pod.pid(),
            udp_capture_port,
            true,
            Duration::from_secs(20),
        ) {
            let status = ambient_source.poll_status();
            return Err(format!(
                "{error}; ambient source {status}\n{}\n{}",
                captured_output(&temp_ambient_source),
                spire.diagnostics()
            ));
        }

        Ok(Self {
            source,
            _east_west: east_west,
            destination,
            _host_network: host_network,
            _dns: dns,
            _spire: spire,
            _backends: backends,
            _registry: registry,
            _registry_entry: registry_entry,
            sidecar_source,
            ambient_source,
            unfederated_source,
            wrong_td_source,
            missing_sni_source,
            east_west_gateway,
            sidecar_destination,
            ambient_destination,
            cp_sidecar_source,
            cp_ambient_source,
            cp_unfederated_source,
            cp_wrong_td_source,
            cp_missing_sni_source,
            cp_east_west,
            cp_sidecar_destination,
            cp_ambient_destination,
            temp_sidecar_source,
            temp_ambient_source,
            temp_unfederated_source,
            temp_wrong_td_source,
            temp_missing_sni_source,
            temp_east_west,
            temp_sidecar_destination,
            temp_ambient_destination,
            sidecar_destination_inbound,
            ambient_destination_hbone,
            sidecar_inbound,
            sidecar_outbound,
            ambient_outbound,
            unfederated_outbound,
            wrong_td_outbound,
            missing_sni_outbound,
            tcp_capture_installed: false,
        })
    }

    fn diagnostics(&self) -> String {
        format!(
            "--- source sidecar ---\n{}\n--- source ambient ---\n{}\n\
             --- source unfederated ---\n{}\n--- source wrong trust domain ---\n{}\n\
             --- source missing SNI ---\n{}\n--- east-west gateway ---\n{}\n\
             --- destination sidecar ---\n{}\n--- destination ambient ---\n{}\n{}",
            captured_output(&self.temp_sidecar_source),
            captured_output(&self.temp_ambient_source),
            captured_output(&self.temp_unfederated_source),
            captured_output(&self.temp_wrong_td_source),
            captured_output(&self.temp_missing_sni_source),
            captured_output(&self.temp_east_west),
            captured_output(&self.temp_sidecar_destination),
            captured_output(&self.temp_ambient_destination),
            self._spire.diagnostics(),
        )
    }

    fn install_tcp_capture(&mut self) -> Result<(), String> {
        if self.tcp_capture_installed {
            return Ok(());
        }
        let mut config = ferrum_edge::capture::CaptureConfig::explicit(
            self.sidecar_inbound,
            self.sidecar_outbound,
        );
        config.mode = ferrum_edge::capture::CaptureMode::Iptables;
        config.proxy_uid = Some(1337);
        config.ip6tables_mode = ferrum_edge::capture::Ip6TablesMode::Disabled;
        config.exclude_ports.extend([
            self.sidecar_outbound,
            self.ambient_outbound,
            self.unfederated_outbound,
            self.wrong_td_outbound,
            self.missing_sni_outbound,
        ]);
        let script = ferrum_edge::capture::IptablesPlan::for_config(&config).script();
        netns_command(self.source.pod.pid(), &script)?;
        self.tcp_capture_installed = true;
        Ok(())
    }

    async fn websocket(
        &self,
        destination: SocketAddr,
        host: &'static str,
        payload: &'static str,
    ) -> Result<String, String> {
        run_async_in_live_netns(self.source.pod.pid(), move || async move {
            mesh_websocket_echo_roundtrip_to(destination, host, "/", payload).await
        })
    }

    async fn ambient_websocket(
        &self,
        host: &'static str,
        payload: &'static str,
    ) -> Result<String, String> {
        let address = format!("{LIVE_XC_MULTI_VIP}:{LIVE_XC_AMBIENT_WS_PORT}")
            .parse()
            .expect("Ambient WebSocket VIP");
        run_async_in_live_netns(self.source.pod.pid(), move || async move {
            mesh_websocket_echo_roundtrip_to(address, host, "/", payload).await
        })
    }

    async fn grpc(&self) -> Result<GrpcEgressResponse, String> {
        let framed = grpc_framed_payload(b"live-two-cluster-grpc");
        let destination = format!("{LIVE_XC_MULTI_VIP}:{LIVE_XC_GRPC_PORT}")
            .parse()
            .expect("gRPC VIP");
        run_async_in_live_netns(self.source.pod.pid(), move || async move {
            grpc_egress_request_to(
                destination,
                "live-matrix.ferrum.svc.cluster.local:18081",
                "/echo.Mesh/Call",
                &framed,
            )
            .await
            .map_err(|error| format!("live cross-cluster gRPC request: {error}"))
        })
    }

    async fn shutdown(mut self) {
        self.sidecar_source.stop();
        self.ambient_source.stop();
        self.unfederated_source.stop();
        self.wrong_td_source.stop();
        self.missing_sni_source.stop();
        self.east_west_gateway.stop();
        self.sidecar_destination.stop();
        self.ambient_destination.stop();
        self.cp_sidecar_source.shutdown().await;
        self.cp_ambient_source.shutdown().await;
        self.cp_unfederated_source.shutdown().await;
        self.cp_wrong_td_source.shutdown().await;
        self.cp_missing_sni_source.shutdown().await;
        self.cp_east_west.shutdown().await;
        self.cp_sidecar_destination.shutdown().await;
        self.cp_ambient_destination.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
fn live_xc_http_get_from_vip(
    pid: u32,
    destination: SocketAddr,
    host: &'static str,
) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    run_in_live_netns(pid, move || {
        let mut stream = std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(5))
            .map_err(|error| format!("connect HTTP VIP {destination}: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .map_err(|error| format!("set HTTP VIP timeout: {error}"))?;
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|error| format!("write HTTP VIP request: {error}"))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("read HTTP VIP response: {error}"))?;
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| format!("malformed HTTP VIP response: {response:?}"))?;
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
            .unwrap_or_default();
        Ok((status, body))
    })
}

#[cfg(target_os = "linux")]
fn live_xc_http_get_from_outbound_capture(
    pid: u32,
    outbound: u16,
    host: &'static str,
) -> Result<(u16, String), String> {
    // Each negative gateway needs the same original-destination signal as the
    // production Sidecar capture listener. Keep this rule request-scoped so it
    // cannot steer another row through the wrong negative gateway.
    let rule = format!(
        "-p tcp -d {LIVE_XC_MULTI_VIP} --dport {LIVE_XC_HTTP_PORT} \
         -j REDIRECT --to-ports {outbound}"
    );
    netns_command(pid, &format!("iptables -w 5 -t nat -I OUTPUT 1 {rule}"))?;
    let destination = format!("{LIVE_XC_MULTI_VIP}:{LIVE_XC_HTTP_PORT}")
        .parse()
        .expect("negative HTTP VIP");
    let observed = live_xc_http_get_from_vip(pid, destination, host);
    let cleanup = netns_command(pid, &format!("iptables -w 5 -t nat -D OUTPUT {rule}"));
    match (observed, cleanup) {
        (Ok(response), Ok(_)) => Ok(response),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(format!("remove negative HTTP capture: {error}")),
        (Err(request_error), Err(cleanup_error)) => Err(format!(
            "{request_error}; remove negative HTTP capture: {cleanup_error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn live_xc_udp_round_trip(
    pid: u32,
    source_ip: std::net::Ipv4Addr,
    destination: SocketAddr,
    payload: &'static [u8],
) -> Result<(Vec<u8>, SocketAddr), String> {
    run_in_live_netns(pid, move || {
        let socket = std::net::UdpSocket::bind(SocketAddr::from((source_ip, 0)))
            .map_err(|error| format!("bind veth-backed UDP client: {error}"))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(12)))
            .map_err(|error| format!("set UDP client timeout: {error}"))?;
        socket
            .send_to(payload, destination)
            .map_err(|error| format!("send UDP to {destination}: {error}"))?;
        let mut buf = [0u8; 2048];
        let (size, source) = socket
            .recv_from(&mut buf)
            .map_err(|error| format!("receive UDP reply: {error}"))?;
        Ok((buf[..size].to_vec(), source))
    })
}

#[cfg(target_os = "linux")]
async fn live_xc_test_http(fixture: &LiveTwoClusterFixture) {
    let destination = format!("{LIVE_XC_MULTI_VIP}:{LIVE_XC_HTTP_PORT}")
        .parse()
        .expect("HTTP VIP");
    // The fixture only proves listener binds, SVID issuance, and TCP
    // reachability — not that the source sidecar consumed its CP slice and
    // materialized the route. Poll for the FIRST authoritative response,
    // retrying only transient route-miss / setup outcomes, then assert once.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let (status, body) = loop {
        let transient = match classify_cross_cluster_http(live_xc_http_get_from_vip(
            fixture.source.pod.pid(),
            destination,
            "live-matrix.ferrum.svc.cluster.local:18080",
        )) {
            Ok(response) => break response,
            Err(transient) => transient,
        };
        if Instant::now() >= deadline {
            panic!(
                "HTTP did not cross the live east-west/destination-capture path within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    };
    assert_eq!(
        status,
        200,
        "live cross-cluster HTTP status; body: {body:?}\n{}",
        fixture.diagnostics()
    );
    assert!(
        body.contains("http-live-ok"),
        "live cross-cluster HTTP body: {body:?}\n{}",
        fixture.diagnostics()
    );
}

#[cfg(target_os = "linux")]
async fn live_xc_test_grpc(fixture: &LiveTwoClusterFixture) {
    // Poll for the FIRST authoritative gRPC response past the source-slice
    // convergence window, retrying only the NOT_FOUND route-miss / connection
    // errors, then assert the routed result once.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let response = loop {
        let transient = match fixture.grpc().await {
            Ok(response) if cross_cluster_grpc_is_route_miss(&response) => {
                format!("route not converged: {response:?}")
            }
            Ok(response) => break response,
            Err(error) => format!("request error: {error}"),
        };
        if Instant::now() >= deadline {
            panic!(
                "Sidecar gRPC did not cross the live fixture within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    };
    assert_eq!(
        response.status,
        200,
        "live cross-cluster gRPC status: {response:?}\n{}",
        fixture.diagnostics()
    );
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "live cross-cluster grpc-status trailer: {response:?}\n{}",
        fixture.diagnostics()
    );
    assert_eq!(
        response
            .trailers
            .get("x-live-two-cluster")
            .map(String::as_str),
        Some("grpc-ok"),
        "live cross-cluster custom trailer: {response:?}\n{}",
        fixture.diagnostics()
    );
    assert!(
        response
            .body
            .windows(b"live-two-cluster-grpc".len())
            .any(|window| window == b"live-two-cluster-grpc"),
        "live cross-cluster gRPC body: {response:?}\n{}",
        fixture.diagnostics()
    );
}

#[cfg(target_os = "linux")]
async fn live_xc_test_sidecar_websocket(fixture: &LiveTwoClusterFixture) {
    let destination = format!("{LIVE_XC_MULTI_VIP}:{LIVE_XC_SIDECAR_WS_PORT}")
        .parse()
        .expect("sidecar WebSocket VIP");
    // Poll past the source-slice convergence window: a completed upgrade is the
    // authoritative result (asserted once); only transient upgrade / route-miss
    // failures are retried.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let reply = loop {
        let transient = match fixture
            .websocket(
                destination,
                "live-matrix.ferrum.svc.cluster.local:18082",
                "sidecar-live",
            )
            .await
        {
            Ok(reply) => break reply,
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            panic!(
                "Sidecar WebSocket live cross-cluster row failed within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    };
    assert_eq!(reply, "backend-ws:sidecar-live");
}

#[cfg(target_os = "linux")]
async fn live_xc_test_ambient_websocket(fixture: &LiveTwoClusterFixture) {
    // Poll past the source-slice convergence window: a completed upgrade is the
    // authoritative result (asserted once); only transient upgrade / route-miss
    // failures are retried.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let reply = loop {
        let transient = match fixture
            .ambient_websocket("live-matrix.ferrum.svc.cluster.local:18083", "ambient-live")
            .await
        {
            Ok(reply) => break reply,
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            panic!(
                "Ambient HBONE WebSocket live cross-cluster row failed within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    };
    assert_eq!(reply, "backend-ws:ambient-live");
}

#[cfg(target_os = "linux")]
fn live_xc_test_multi_port(fixture: &mut LiveTwoClusterFixture) {
    fixture
        .install_tcp_capture()
        .expect("install source production TCP capture");
    for (port, expected, host) in [
        (
            LIVE_XC_MULTI_A_PORT,
            "multi-a-ok",
            "live-matrix.ferrum.svc.cluster.local:18084",
        ),
        (
            LIVE_XC_MULTI_B_PORT,
            "multi-b-ok",
            "live-matrix.ferrum.svc.cluster.local:18085",
        ),
    ] {
        let destination = format!("{LIVE_XC_MULTI_VIP}:{port}")
            .parse()
            .expect("multi-port VIP");
        // Poll past the source-slice convergence window, retrying only transient
        // route-miss / setup outcomes, then assert the alias route once.
        let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
        let (status, body) = loop {
            let transient = match classify_cross_cluster_http(live_xc_http_get_from_vip(
                fixture.source.pod.pid(),
                destination,
                host,
            )) {
                Ok(response) => break response,
                Err(transient) => transient,
            };
            if Instant::now() >= deadline {
                panic!(
                    "multi-port p{port} alias row failed within \
                     {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                    fixture.diagnostics()
                );
            }
            std::thread::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL);
        };
        assert_eq!(status, 200, "p{port} alias response: {body:?}");
        assert_eq!(body, expected, "p{port} routed to the wrong backend");
    }
}

#[cfg(target_os = "linux")]
fn live_xc_test_raw_tcp(fixture: &mut LiveTwoClusterFixture) {
    fixture
        .install_tcp_capture()
        .expect("install source production TCP capture");
    let destination = format!("{LIVE_XC_TCP_VIP}:{LIVE_XC_TCP_PORT}")
        .parse()
        .expect("raw TCP VIP");
    // Poll past the source-slice convergence window: a completed round trip is
    // the authoritative result (asserted once); only transient connection /
    // route-miss failures are retried.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let (reply, peer) = loop {
        let transient = match tcp_round_trip_from_netns(
            fixture.source.pod.pid(),
            destination,
            b"live-two-cluster-raw-tcp",
        ) {
            Ok(result) => break result,
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            panic!(
                "raw TCP cross-cluster capture/tunnel failed within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        std::thread::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL);
    };
    assert_eq!(reply, b"live-two-cluster-raw-tcp");
    assert_eq!(peer, destination, "the captured TCP peer must stay the VIP");
}

#[cfg(target_os = "linux")]
async fn live_xc_test_udp(fixture: &mut LiveTwoClusterFixture) {
    let destination = format!("{LIVE_XC_UDP_VIP}:{LIVE_XC_UDP_PORT}")
        .parse()
        .expect("UDP VIP");
    // Poll past the source-slice convergence window: a framed reply is the
    // authoritative result (asserted once); only transient send / no-reply
    // failures before the route materializes are retried.
    let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
    let (reply, source) = loop {
        let transient = match live_xc_udp_round_trip(
            fixture.source.pod.pid(),
            fixture.source.pod_ip(),
            destination,
            b"live-two-cluster-udp-frame",
        ) {
            Ok(result) => break result,
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            panic!(
                "UDP framed cross-cluster capture/tunnel failed within \
                 {CROSS_CLUSTER_CONVERGENCE_TIMEOUT:?}; last transient error: {transient}\n{}",
                fixture.diagnostics()
            );
        }
        tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
    };
    assert_eq!(reply, b"live-two-cluster-udp-frame");
    assert_eq!(
        source, destination,
        "the UDP response must spoof the original VIP:port source"
    );
    fixture.ambient_source.stop();
    assert!(
        wait_for_captured_output(
            &fixture.temp_ambient_destination,
            "HBONE UDP tunnel relay completed",
            Duration::from_secs(5),
        )
        .await,
        "destination did not confirm framed UDP relay\n{}",
        fixture.diagnostics()
    );
}

#[cfg(target_os = "linux")]
async fn live_xc_test_fail_closed_negatives(fixture: &LiveTwoClusterFixture) {
    for (label, outbound) in [
        ("wrong trust domain", fixture.wrong_td_outbound),
        ("unfederated peer", fixture.unfederated_outbound),
    ] {
        let observed = live_xc_http_get_from_outbound_capture(
            fixture.source.pod.pid(),
            outbound,
            "live-matrix.ferrum.svc.cluster.local:18080",
        );
        assert!(
            !matches!(observed, Ok((200, ref body)) if body.contains("http-live-ok")),
            "{label} must fail closed, not reach the destination: {observed:?}\n{}",
            fixture.diagnostics()
        );
    }

    let east_west_before = captured_output(&fixture.temp_east_west);
    let observed = live_xc_http_get_from_outbound_capture(
        fixture.source.pod.pid(),
        fixture.missing_sni_outbound,
        "live-matrix.ferrum.svc.cluster.local:18080",
    );
    assert!(
        !matches!(observed, Ok((200, ref body)) if body.contains("http-live-ok")),
        "missing SNI ownership must fail closed: {observed:?}\n{}",
        fixture.diagnostics()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let east_west_after = captured_output(&fixture.temp_east_west);
    let request_scoped_output = east_west_after
        .strip_prefix(&east_west_before)
        .unwrap_or(&east_west_after);
    assert!(
        !request_scoped_output.contains("p18080.live-matrix.ferrum.svc.cluster.local"),
        "a missing SNI override must be refused before any east-west dial: \
         {request_scoped_output}"
    );
}

/// Privileged gate for the real cross-cluster boundary. One shared fixture
/// stands up two join-token SPIRE servers/agents with federated bundles, source
/// cluster A, cluster B's east-west namespace, and cluster B's captured
/// destination pod. Each protocol helper below drives a distinct production
/// datapath through that same topology; direct A -> destination routing is
/// rejected by the host firewall so a passing row necessarily used the
/// east-west gateway.
#[cfg(target_os = "linux")]
#[ignore = "requires root, netns/veth/iptables, and SPIRE server/agent binaries"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_mesh_live_two_cluster_cross_cluster_protocol_matrix() {
    if !live_source_capture_prerequisites() {
        return;
    }
    for binary in ["spire-server", "spire-agent", "sysctl"] {
        let present = Command::new("sh")
            .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|status| status.success());
        if !present {
            skip_or_fail_live_source_capture(&format!("`{binary}` is unavailable"));
            return;
        }
    }
    ensure_gateway_built().expect("build gateway for live two-cluster test");
    eprintln!("LIVE_XC_STAGE fixture:start");
    let mut fixture = LiveTwoClusterFixture::start()
        .await
        .unwrap_or_else(|error| panic!("start live two-cluster fixture: {error}"));
    eprintln!("LIVE_XC_STAGE fixture:ready");

    let direct = run_in_live_netns(fixture.source.pod.pid(), {
        let destination = SocketAddr::from((fixture.destination.pod_ip(), LIVE_XC_HTTP_PORT));
        move || {
            Ok(std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(1)).is_ok())
        }
    })
    .expect("probe forbidden direct source-to-destination route");
    assert!(
        !direct,
        "source cluster A can reach the destination pod directly; fixture isolation is invalid"
    );
    let destination = SocketAddr::from((fixture.destination.pod_ip(), LIVE_XC_HTTP_PORT));
    assert!(
        !std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(1)).is_ok(),
        "the host-network Ambient gateway can reach the destination pod directly; fixture isolation is invalid"
    );
    for (gateway, port) in [
        ("Sidecar", fixture.sidecar_destination_inbound),
        ("Ambient", fixture.ambient_destination_hbone),
    ] {
        let destination = SocketAddr::from((fixture.destination.pod_ip(), port));
        assert!(
            !std::net::TcpStream::connect_timeout(&destination, Duration::from_secs(1)).is_ok(),
            "the host can reach the destination {gateway} gateway inbound port {port}; fixture isolation is invalid"
        );
    }

    eprintln!("LIVE_XC_STAGE ambient_ws:start");
    live_xc_test_ambient_websocket(&fixture).await;
    eprintln!("LIVE_XC_STAGE ambient_ws:ok");
    eprintln!("LIVE_XC_STAGE udp:start");
    live_xc_test_udp(&mut fixture).await;
    eprintln!("LIVE_XC_STAGE udp:ok");
    eprintln!("LIVE_XC_STAGE negatives:start");
    live_xc_test_fail_closed_negatives(&fixture).await;
    eprintln!("LIVE_XC_STAGE negatives:ok");
    fixture
        .install_tcp_capture()
        .expect("install source production TCP capture");
    eprintln!("LIVE_XC_STAGE http:start");
    live_xc_test_http(&fixture).await;
    eprintln!("LIVE_XC_STAGE http:ok");
    eprintln!("LIVE_XC_STAGE grpc:start");
    live_xc_test_grpc(&fixture).await;
    eprintln!("LIVE_XC_STAGE grpc:ok");
    eprintln!("LIVE_XC_STAGE sidecar_ws:start");
    live_xc_test_sidecar_websocket(&fixture).await;
    eprintln!("LIVE_XC_STAGE sidecar_ws:ok");
    eprintln!("LIVE_XC_STAGE multi_port:start");
    live_xc_test_multi_port(&mut fixture);
    eprintln!("LIVE_XC_STAGE multi_port:ok");
    eprintln!("LIVE_XC_STAGE raw_tcp:start");
    live_xc_test_raw_tcp(&mut fixture);
    eprintln!("LIVE_XC_STAGE raw_tcp:ok");

    eprintln!("LIVE_XC_STAGE shutdown:start");
    fixture.shutdown().await;
    eprintln!("LIVE_XC_STAGE shutdown:ok");
}
