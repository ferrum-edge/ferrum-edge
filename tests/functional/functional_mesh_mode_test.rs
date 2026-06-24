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
use tokio_stream::wrappers::{
    IntervalStream, TcpListenerStream, UnboundedReceiverStream, UnixListenerStream,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::config::types::GatewayConfig;
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
    AppProtocol, MeshConfig, MeshPolicy, MeshRule, MeshService, MtlsMode, PeerAuthentication,
    PolicyAction, PolicyScope, PrincipalMatch, ServicePort, ServiceTargetPort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
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
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "websocket connect timed out".to_string())?
    .map_err(|e| format!("websocket connect failed: {e}"))?;

    // Build the upgrade request with the egress-route Host (tungstenite would
    // otherwise key the Host off the raw 127.0.0.1 address and miss the route).
    let mut request = format!("ws://{host}/")
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
    .map_err(|e| format!("websocket handshake failed: {e}"))?;

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
// tunnel -> unframe -> app -> return-source-spoofing) still needs a live
// netns/root env and is tracked separately as the remaining UDP gap.

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
