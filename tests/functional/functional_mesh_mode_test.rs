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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use futures_util::{Stream, StreamExt, stream};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot, watch};
use tokio_stream::wrappers::{IntervalStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{ConfigUpdate, MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain, spiffe_id_to_san};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshService, MtlsMode, PeerAuthentication, ServicePort, Workload, WorkloadPort,
    WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::xds::XdsAdsServer;

use crate::common::ensure_gateway_built;
use crate::scaffolding::ports::reserve_port;

const GRPC_SECRET: &str = "ferrum-edge-functional-mesh-grpc-secret00";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_ATTEMPTS: u32 = 3;

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
        let _ = self.request_tx.send(Some(request));

        let update = MeshConfigUpdate {
            version: self.slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: serde_json::to_string(self.slice.as_ref())
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
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mesh CP");
    let addr = listener.local_addr().expect("mesh CP local addr");
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
        }],
        services: vec![MeshService {
            name: "reviews".to_string(),
            namespace: "ferrum".to_string(),
            ports: vec![ServicePort {
                port: 18080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
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

async fn reserve_mesh_ports() -> MeshPorts {
    MeshPorts {
        inbound: reserve_port()
            .await
            .expect("reserve mesh inbound port")
            .drop_and_take_port(),
        outbound: reserve_port()
            .await
            .expect("reserve mesh outbound port")
            .drop_and_take_port(),
        hbone: reserve_port()
            .await
            .expect("reserve mesh hbone port")
            .drop_and_take_port(),
        egress: reserve_port()
            .await
            .expect("reserve mesh egress port")
            .drop_and_take_port(),
        east_west: reserve_port()
            .await
            .expect("reserve mesh east-west port")
            .drop_and_take_port(),
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
    let stdout =
        std::fs::File::create(temp.path().join("mesh.stdout.log")).expect("create stdout capture");
    let stderr =
        std::fs::File::create(temp.path().join("mesh.stderr.log")).expect("create stderr capture");
    std::fs::create_dir_all(temp.path().join("node-waypoint-pods"))
        .expect("create node-waypoint pod registry dir");
    let mut cmd = Command::new(binary_path());
    scrub_ferrum_env(&mut cmd);
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
    cmd.spawn().expect("spawn mesh gateway")
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
        output
            .contains("FERRUM_MESH_TOPOLOGY=egress_gateway requires FERRUM_FRONTEND_TLS_CERT_PATH"),
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
        client_cert_pem,
        client_key_pem,
        untrusted_td_client_cert_pem,
        untrusted_td_client_key_pem,
    }
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
