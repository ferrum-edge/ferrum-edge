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

use ferrum_edge::config::EnvConfig;
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
    AppProtocol, EastWestGateway, MeshConfig, MeshConsistentHash, MeshDestinationRule,
    MeshEndpoint, MeshLoadBalancer, MeshPolicy, MeshRule, MeshService, MeshSimpleLb,
    MeshTrafficPolicy, MtlsMode, MultiClusterConfig, PeerAuthentication, PolicyAction, PolicyScope,
    PolicyTargetAttachment, PrincipalMatch, Resolution, ServiceEntry, ServiceEntryLocation,
    ServicePort, ServiceTargetPort, TrustBundle, TrustBundleSet, Workload, WorkloadPort,
    WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::proxy::ConfigApplyOutcome;
use ferrum_edge::xds::XdsAdsServer;

use crate::common::{
    TrustedProjectedGateway, TrustedProjectedGatewayOptions, ensure_gateway_built,
    run_trusted_projected_gateway_test,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{Http3Client, Http3GrpcStream};
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
            // The stub echoes the slice's own revision onto the envelope, the
            // same duplicate-stamp contract the real CP honours; a mismatch is
            // a consumer-side rejection (issue #2473).
            config_authority: slice
                .revision
                .as_ref()
                .map(|revision| revision.authority.clone())
                .unwrap_or_default(),
            config_sequence: slice
                .revision
                .as_ref()
                .map_or(0, |revision| revision.sequence),
            session_token: "functional-test-session".to_string(),
        };
        let heartbeat = MeshConfigUpdate {
            version: self.slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: String::new(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            heartbeat: true,
            config_authority: String::new(),
            config_sequence: 0,
            session_token: String::new(),
        };
        let heartbeats = IntervalStream::new(tokio::time::interval(Duration::from_secs(60)))
            .map(move |_| Ok(heartbeat.clone()));
        let stream = stream::once(async move { Ok(update) }).chain(heartbeats);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn report_mesh_slice_status(
        &self,
        _request: Request<ferrum_edge::grpc::proto::MeshSliceStatusReport>,
    ) -> Result<Response<ferrum_edge::grpc::proto::MeshSliceStatusResponse>, Status> {
        Ok(Response::new(
            ferrum_edge::grpc::proto::MeshSliceStatusResponse {},
        ))
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
    let listener = bind_fixture_listener(bind_addr)
        .await
        .expect("bind mesh CP");
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
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind xDS CP");
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
            service_namespace: None,
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
            uid: None,
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

fn used_mesh_ports() -> &'static Mutex<HashSet<u16>> {
    USED_MESH_PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// True when `port` has already been handed to a mesh gateway subprocess in this
/// test process. Such a port belongs to that subprocess alone — see
/// [`bind_fixture_listener`].
fn mesh_port_is_reserved(port: u16) -> bool {
    used_mesh_ports()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(&port)
}

async fn reserve_unique_mesh_port() -> u16 {
    loop {
        let reservation = reserve_port().await.expect("reserve unique mesh port");
        let port = reservation.port;
        let inserted = used_mesh_ports()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(port);
        if inserted {
            return reservation.drop_and_take_port();
        }
    }
}

/// Bind attempts [`bind_fixture_listener_where`] makes before giving up.
const FIXTURE_BIND_ATTEMPTS: u32 = 32;

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Bind an ephemeral listener for a fixture-owned server (a control plane, an
/// echo backend, …) on a port no mesh gateway subprocess has been given.
///
/// ## Why this is not a plain `TcpListener::bind(":0")` (issue #2132)
///
/// [`reserve_unique_mesh_port`] must RELEASE its listener before handing the
/// port to a subprocess that binds it itself, so between the release and the
/// gateway's own bind the port is free and the kernel can hand it straight back
/// to the next `:0` bind in this process. The cross-cluster fixtures reserve all
/// fifteen gateway ports first and only then bind their three control planes, so
/// a control plane could land on a port already promised to a gateway. The
/// gateway then failed startup with `Address already in use`, exited — and
/// `wait_for_tcp_port` still succeeded, because the control plane was listening
/// on that very port. `USED_MESH_PORTS` alone did not cover this: it only stops
/// one mesh reservation reusing another.
///
/// Re-rolling here closes that window from the fixture side; the child-bound
/// readiness gate ([`wait_for_gateway_listener`]) covers the cross-PROCESS case
/// (another test binding our released port), which no in-process bookkeeping
/// can see.
async fn bind_fixture_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    bind_fixture_listener_where(addr, |port| !mesh_port_is_reserved(port)).await
}

/// [`bind_fixture_listener`] with an injectable acceptance predicate, so the
/// re-roll itself is directly testable.
///
/// Rejected listeners are HELD until an acceptable port is found, so the kernel
/// cannot hand the same rejected port back on the next attempt. A non-ephemeral
/// (explicit, non-zero) bind address is returned as-is: the caller asked for
/// that exact port.
async fn bind_fixture_listener_where(
    addr: SocketAddr,
    acceptable: impl Fn(u16) -> bool,
) -> std::io::Result<TcpListener> {
    if addr.port() != 0 {
        return TcpListener::bind(addr).await;
    }
    let mut rejected = Vec::new();
    for _ in 0..FIXTURE_BIND_ATTEMPTS {
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        if acceptable(port) {
            return Ok(listener);
        }
        rejected.push(listener);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "no acceptable ephemeral port for a fixture listener after \
             {FIXTURE_BIND_ATTEMPTS} attempts"
        ),
    ))
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

#[cfg(target_os = "linux")]
fn ephemeral_port_range_in_netns(pid: u32) -> Result<(u16, u16), String> {
    run_in_live_netns(pid, || {
        let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .map_err(|error| format!("read netns ephemeral port range: {error}"))?;
        let mut fields = raw.split_whitespace();
        let first = fields
            .next()
            .ok_or_else(|| "netns ephemeral port range is empty".to_string())?
            .parse::<u16>()
            .map_err(|error| format!("parse netns ephemeral port range start: {error}"))?;
        let last = fields
            .next()
            .ok_or_else(|| "netns ephemeral port range has no end".to_string())?
            .parse::<u16>()
            .map_err(|error| format!("parse netns ephemeral port range end: {error}"))?;
        if fields.next().is_some() || first > last {
            return Err(format!("invalid netns ephemeral port range: {raw:?}"));
        }
        Ok((first, last))
    })
}

/// Select a listener port in the gateway's actual network namespace and
/// outside that namespace's ephemeral range.
///
/// A host-namespace `127.0.0.1:0` reservation does not protect the same port
/// number in a pod namespace. Worse, selecting an ephemeral number lets an
/// already-running gateway claim it as a source port after the reservation is
/// dropped but before the next gateway binds. The live two-cluster fixture
/// starts several gateways in one source namespace, so that race can make a
/// later listener fail with `EADDRINUSE`. Binding each candidate in the target
/// namespace proves it is currently free; keeping it outside the kernel's
/// ephemeral allocation range prevents an outbound connection from stealing it
/// during the handoff.
#[cfg(target_os = "linux")]
fn reserve_unique_mesh_port_in_netns(pid: u32) -> Result<u16, String> {
    let (ephemeral_first, ephemeral_last) = ephemeral_port_range_in_netns(pid)?;
    for port in 10_240..=u16::MAX {
        if (ephemeral_first..=ephemeral_last).contains(&port) || mesh_port_is_reserved(port) {
            continue;
        }
        let listener = run_in_live_netns(pid, move || {
            match std::net::TcpListener::bind(("0.0.0.0", port)) {
                Ok(listener) => Ok(Some(listener)),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
                Err(error) => Err(format!("probe netns mesh port {port}: {error}")),
            }
        })?;
        let Some(listener) = listener else {
            continue;
        };
        let inserted = used_mesh_ports()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(port);
        if inserted {
            drop(listener);
            return Ok(port);
        }
    }
    Err(format!(
        "no free non-ephemeral mesh port in netns {pid} outside \
         {ephemeral_first}-{ephemeral_last}"
    ))
}

#[cfg(target_os = "linux")]
fn reserve_mesh_ports_in_netns(pid: u32) -> Result<MeshPorts, String> {
    Ok(MeshPorts {
        inbound: reserve_unique_mesh_port_in_netns(pid)?,
        outbound: reserve_unique_mesh_port_in_netns(pid)?,
        hbone: reserve_unique_mesh_port_in_netns(pid)?,
        egress: reserve_unique_mesh_port_in_netns(pid)?,
        east_west: reserve_unique_mesh_port_in_netns(pid)?,
    })
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
    make_mesh_registry_owned_by_uid(temp, uid);
    cmd.spawn().expect("spawn mesh gateway inside pod netns")
}

#[cfg(target_os = "linux")]
fn make_mesh_registry_owned_by_uid(temp: &TempDir, uid: u32) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let registry_dir = temp.path().join("node-waypoint-pods");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o711))
        .expect("make mesh fixture tempdir traversable");
    let registry_path = CString::new(registry_dir.as_os_str().as_bytes())
        .expect("mesh fixture registry path has no NUL");
    // SAFETY: `registry_path` is a live NUL-terminated CString and both IDs
    // are the numeric uid/gid passed to the immediately following `setpriv`.
    let result = unsafe { libc::chown(registry_path.as_ptr(), uid, uid) };
    assert_eq!(
        result,
        0,
        "chown mesh fixture registry: {}",
        std::io::Error::last_os_error()
    );
    std::fs::set_permissions(&registry_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restrict mesh fixture registry to gateway uid");
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

/// Outcome of waiting for a SPAWNED mesh gateway to bind one of its own
/// listeners. See [`wait_for_gateway_listener`].
#[derive(Debug)]
enum GatewayListenerReadiness {
    /// The port accepted a connection while the child was still running.
    Ready,
    /// The child exited before the port was proven ready. Whatever may be
    /// listening on that port is NOT this gateway.
    ChildExited(String),
    /// The child is still running but never bound the port in time.
    Timeout,
}

impl GatewayListenerReadiness {
    fn is_ready(&self) -> bool {
        matches!(self, GatewayListenerReadiness::Ready)
    }

    /// One-line diagnostic for a fixture's `last_failure` string.
    fn describe(&self, label: &str, port: u16) -> String {
        match self {
            GatewayListenerReadiness::Ready => format!("{label} bound port {port}"),
            GatewayListenerReadiness::ChildExited(status) => format!(
                "{label} exited during startup ({status}) — port {port} is NOT owned by this \
                 gateway (a competing listener can make a bare port probe succeed anyway)"
            ),
            GatewayListenerReadiness::Timeout => {
                format!("{label} never bound port {port} within the startup timeout")
            }
        }
    }
}

/// Non-blocking check for a spawned gateway that has already exited.
fn gateway_child_exited(child: &mut Child) -> Option<ExitStatus> {
    child.try_wait().expect("poll mesh gateway child")
}

/// The first labelled gateway in `children` that has already exited, rendered as
/// a diagnostic. `None` means every gateway is still running.
///
/// A fixture whose gateway died mid-run is VOID: its ports were never owned by
/// the process the driver believed it was talking to, so any observation made
/// against them — success, failure, or fail-closed rejection — proves nothing.
fn exited_gateway_diagnostic(children: &mut [(&str, &mut Child)]) -> Option<String> {
    for (label, child) in children.iter_mut() {
        if let Some(status) = gateway_child_exited(child) {
            return Some(format!("{label} exited during the run ({status})"));
        }
    }
    None
}

/// Wait for a spawned mesh gateway to bind `port`, with readiness tied to THAT
/// CHILD rather than to "something answers on this port" (issue #2132).
///
/// A bare [`wait_for_tcp_port`] probe asks only whether the port is reachable.
/// When a gateway loses a startup bind race it logs `Address already in use` and
/// exits, yet the probe still succeeds against whichever process actually holds
/// the port — so the driver treats a foreign listener as gateway readiness and
/// then reports that process's connection reset as a mesh datapath failure. That
/// is precisely the failure captured in
/// <https://github.com/ferrum-edge/ferrum-edge/actions/runs/30342386051>.
///
/// The child is polled BEFORE each probe and again after a successful one, so a
/// child that dies at any point during the window is reported as
/// [`GatewayListenerReadiness::ChildExited`] and the caller can consume its
/// bounded attempt and retry with fresh ports, temp dirs, and control planes.
async fn wait_for_gateway_listener(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> GatewayListenerReadiness {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = gateway_child_exited(child) {
            return GatewayListenerReadiness::ChildExited(status.to_string());
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            // Re-check liveness: a gateway can fail a LATER listener's bind and
            // exit after this one came up, which would leave the just-probed
            // port owned by nobody (or by the competitor) moments later.
            if let Some(status) = gateway_child_exited(child) {
                return GatewayListenerReadiness::ChildExited(status.to_string());
            }
            return GatewayListenerReadiness::Ready;
        }
        if Instant::now() >= deadline {
            return GatewayListenerReadiness::Timeout;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Harness contract guards for the mesh gateway port/readiness fix (#2132) ───

/// This test file's own source, baked in at compile time so the check works from
/// a relocated nextest archive with no cwd assumptions.
const MESH_MODE_TEST_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/functional/functional_mesh_mode_test.rs"
));

/// Mesh fixtures that spawn gateway subprocesses under a bounded retry loop.
/// Every one of them must gate readiness on the SPAWNED CHILD.
const CHILD_BOUND_READINESS_FIXTURES: &[&str] = &[
    "drive_dr_live_visibility",
    "drive_egress_a_to_b",
    "drive_grpc_egress_a_to_b",
    "drive_websocket_egress_a_to_b",
    "drive_cross_cluster_egress",
    "drive_ambient_cross_cluster_egress",
    "try_start_sidecar_cross_cluster_fixture",
    "try_start_ambient_cross_cluster_fixture",
    "drive_sidecar_ingress_connect_relay",
    "functional_mesh_sidecar_ingress_stream_reload_withdraws_declared_listener",
    "drive_waypoint_target_refs",
];

/// Drivers that must void an attempt whose gateway died mid-run.
const DEAD_GATEWAY_VOIDING_DRIVERS: &[&str] = &[
    "drive_dr_live_visibility",
    "drive_egress_a_to_b",
    "drive_grpc_egress_a_to_b",
    "drive_websocket_egress_a_to_b",
    "drive_cross_cluster_egress",
    "drive_ambient_cross_cluster_egress",
    "drive_cross_cluster_grpc_egress",
    "drive_cross_cluster_ws_egress",
    "drive_ambient_cross_cluster_ws_egress",
    "drive_ambient_cross_cluster_ws_path_egress",
    "drive_sidecar_ingress_connect_relay",
    "functional_mesh_sidecar_ingress_stream_reload_withdraws_declared_listener",
    "drive_waypoint_target_refs",
];

/// Extract one top-level `async fn <name>` body from [`MESH_MODE_TEST_SOURCE`].
///
/// Both boundaries are asserted: a missing `async fn` header and a missing
/// closing `\n}\n` both panic rather than silently returning a slice. An
/// over-captured body (a boundary that swallowed the rest of the file) makes the
/// callers FAIL rather than pass, because the surrounding file still contains
/// the very `wait_for_tcp_port(` calls they forbid.
fn mesh_test_fn_body(name: &str) -> &'static str {
    let header = format!("\nasync fn {name}(");
    let start = MESH_MODE_TEST_SOURCE
        .find(&header)
        .unwrap_or_else(|| panic!("`async fn {name}(` not found in this test file's source"))
        + 1;
    let rest = &MESH_MODE_TEST_SOURCE[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("no top-level closing brace found for `async fn {name}`"));
    let body = &rest[..end];
    assert!(
        body.len() > 200,
        "extracted body for `async fn {name}` is implausibly short ({} bytes) — the \
         extraction boundaries drifted",
        body.len()
    );
    body
}

/// Readiness for a spawned mesh gateway must be tied to THAT CHILD, never to a
/// bare "something accepts on this port" probe (issue #2132).
///
/// A bare [`wait_for_tcp_port`] succeeds against a competing listener that won a
/// startup bind race on a dropped port reservation, so the driver then reports
/// the competitor's connection reset as a mesh datapath failure. This guard
/// fails the moment one of these fixtures reverts to that shape.
#[test]
fn multi_gateway_fixtures_gate_readiness_on_the_spawned_child() {
    for name in CHILD_BOUND_READINESS_FIXTURES {
        let body = mesh_test_fn_body(name);
        assert!(
            body.contains("spawn_mesh_gateway("),
            "`{name}` no longer spawns a mesh gateway; update \
             CHILD_BOUND_READINESS_FIXTURES to match the fixture it became"
        );
        assert!(
            body.contains("wait_for_gateway_listener("),
            "`{name}` must gate gateway readiness on `wait_for_gateway_listener` so a child \
             that exits during startup consumes its bounded attempt (issue #2132)"
        );
        assert!(
            !body.contains("wait_for_tcp_port("),
            "`{name}` gates a spawned gateway on a bare `wait_for_tcp_port` probe again — that \
             probe cannot tell this gateway's listener from a competing process that won the \
             bind race on the same dropped reservation (issue #2132)"
        );
    }
}

/// Every multi-gateway driver must void an attempt whose gateway died mid-run,
/// instead of reporting the resulting transport error as a datapath result.
#[test]
fn multi_gateway_drivers_void_attempts_whose_gateway_died() {
    for name in DEAD_GATEWAY_VOIDING_DRIVERS {
        let body = mesh_test_fn_body(name);
        assert!(
            body.contains("exited_gateway_diagnostic(") || body.contains("exited_gateway()"),
            "`{name}` must void an attempt whose gateway exited during the run — its ports were \
             never owned by the process it believed it was driving (issue #2132)"
        );
    }
}

/// The fixture-owned control planes and backends must not bind a port already
/// promised to a mesh gateway subprocess (issue #2132).
#[test]
fn fixture_servers_bind_through_the_mesh_port_aware_helper() {
    for name in [
        "start_static_mesh_cp_on",
        "start_xds_cp",
        "start_echo_backend",
        "start_labeled_echo_backend",
        "start_grpc_trailers_echo_backend",
        "start_websocket_echo_backend",
        "start_websocket_path_echo_backend",
        "start_tagged_tcp_backend",
        "start_loopback_tcp_echo",
    ] {
        let body = mesh_test_fn_body(name);
        assert!(
            body.contains("bind_fixture_listener("),
            "`{name}` must bind through `bind_fixture_listener` so it can never take a port \
             already handed to a mesh gateway subprocess (issue #2132)"
        );
    }
}

/// [`bind_fixture_listener_where`] must re-roll past a rejected port rather than
/// returning it, and must not hand back the rejected port on a later attempt.
#[tokio::test]
async fn fixture_listener_bind_rerolls_past_a_rejected_port() {
    let predicate_calls = AtomicUsize::new(0);
    let rejected = Mutex::new(None);
    let listener = bind_fixture_listener_where(loopback_ephemeral(), |port| {
        if predicate_calls.fetch_add(1, Ordering::Relaxed) == 0 {
            let mut rejected_slot = rejected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *rejected_slot = Some(port);
            false
        } else {
            true
        }
    })
    .await
    .expect("fixture listener bind");
    let port = listener.local_addr().expect("fixture addr").port();
    let rejected = rejected
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .expect("predicate records its rejected first candidate");
    assert_eq!(
        predicate_calls.load(Ordering::Relaxed),
        2,
        "the test must exercise exactly one rejected bind and one accepted re-roll"
    );
    assert_ne!(
        port, rejected,
        "bind_fixture_listener_where returned the port its predicate rejected"
    );
}

/// A port handed to a mesh gateway subprocess is registered, and fixture-owned
/// listeners never bind one.
#[tokio::test]
async fn fixture_listeners_never_take_a_reserved_mesh_port() {
    let ports = reserve_mesh_ports().await;
    for (label, port) in [
        ("inbound", ports.inbound),
        ("outbound", ports.outbound),
        ("hbone", ports.hbone),
        ("egress", ports.egress),
        ("east_west", ports.east_west),
    ] {
        assert!(
            mesh_port_is_reserved(port),
            "mesh {label} port {port} was handed to a gateway without being registered — the \
             no-reuse protection would not cover it"
        );
    }

    // Hold every listener for the duration so each bind draws a distinct port.
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(
            bind_fixture_listener(loopback_ephemeral())
                .await
                .expect("fixture listener bind"),
        );
    }
    for listener in &held {
        let port = listener.local_addr().expect("fixture addr").port();
        assert!(
            !mesh_port_is_reserved(port),
            "a fixture listener bound port {port}, which is already promised to a mesh gateway \
             subprocess — the gateway would fail startup with EADDRINUSE while a bare port probe \
             kept succeeding (issue #2132)"
        );
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

// ── DestinationRule visibility + lookup tier, on the real data plane ─────────
//
// Issues #2465 (`exportTo` visibility) and #2469 (client → service → root
// lookup hierarchy). Static/integration coverage proves the resolver in
// isolation; these cases prove the SHIPPED BINARY resolves one winner across
// three namespaces and that the winner is observable ON THE WIRE, not merely
// present in a prepared config.
//
// The observable is load balancing across two labelled backends behind one
// destination:
//
// * no applicable rule  → the materialized upstream keeps its default
//   ROUND_ROBIN, so consecutive requests reach BOTH backends;
// * an applicable `consistentHash{useSourceIp}` rule → every request from the
//   one fixture client IP pins to a SINGLE backend.
//
// That makes "the rule applied" and "the rule did not apply" two different
// wire outcomes with no timing component, so each scenario below is a
// deterministic accept/reject of one visibility or tier decision.
//
// The subscriber (client) namespace is the gateway's own `FERRUM_NAMESPACE`;
// the destination is declared by a ServiceEntry in a DIFFERENT namespace, and
// the mesh root namespace is a third.

/// Client (subscriber) namespace — Istio's FIRST lookup tier.
const DR_LIVE_CLIENT_NAMESPACE: &str = "ferrum";
/// Namespace that DECLARES the destination — the SECOND lookup tier.
const DR_LIVE_SERVICE_NAMESPACE: &str = "beta";
/// `meshConfig.rootNamespace` — the THIRD (fallback) lookup tier.
const DR_LIVE_ROOT_NAMESPACE: &str = "istio-system";
/// Destination host. Egress upstream targets are the ServiceEntry's own static
/// endpoint addresses, so the DestinationRule host is that address.
const DR_LIVE_DESTINATION_HOST: &str = "127.0.0.1";
/// Requests driven after the route converges. Round-robin over two backends
/// reaches both well within this count; a consistent-hash winner cannot.
const DR_LIVE_REQUESTS: usize = 8;

/// One DestinationRule for the shared destination host.
///
/// `sticky = true` requests `consistentHash{useSourceIp}` (the fixture client
/// always dials from one loopback address, so the hash pins ONE backend);
/// `sticky = false` requests an explicit `ROUND_ROBIN`, which is also the
/// materialized default — that is deliberate, because it lets a CLIENT-tier
/// rule visibly override a sticky service/root-tier rule.
fn dr_live_rule(
    name: &str,
    namespace: &str,
    export_to: &[&str],
    sticky: bool,
) -> MeshDestinationRule {
    let load_balancer = if sticky {
        MeshLoadBalancer::ConsistentHash(MeshConsistentHash {
            http_header_name: None,
            http_cookie_name: None,
            use_source_ip: true,
        })
    } else {
        MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)
    };
    MeshDestinationRule {
        name: name.to_string(),
        namespace: namespace.to_string(),
        host: DR_LIVE_DESTINATION_HOST.to_string(),
        traffic_policy: Some(MeshTrafficPolicy {
            load_balancer: Some(load_balancer),
            ..MeshTrafficPolicy::default()
        }),
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
        export_to: export_to.iter().map(|entry| entry.to_string()).collect(),
    }
}

/// Extract the labelled backend's entity body from `mesh_inbound_http_get`'s
/// full HTTP/1 response. Policy assertions must never key on gateway-managed
/// headers such as `Date`: doing so both rejects a correct response as an
/// unknown label and makes a sticky-backend sample appear to change when the
/// requests cross a wall-clock second.
fn dr_live_backend_label(response: &str) -> Result<String, String> {
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("response has no HTTP header/body boundary: {response:?}"))?;
    let label = body.trim();
    if label == "backend-a" || label == "backend-b" {
        Ok(label.to_string())
    } else {
        Err(format!(
            "response entity is not a fixture backend label: {label:?}; response={response:?}"
        ))
    }
}

/// Slice for the live DestinationRule cases: one externally-declared
/// destination in `beta` with two labelled endpoints, plus whatever rules the
/// scenario is testing.
fn dr_live_slice(
    node_id: &str,
    backend_a: u16,
    backend_b: u16,
    destination_rules: Vec<MeshDestinationRule>,
) -> MeshSlice {
    let endpoint = |port: u16| MeshEndpoint {
        address: DR_LIVE_DESTINATION_HOST.to_string(),
        ports: HashMap::from([("http".to_string(), port)]),
        labels: HashMap::new(),
        network: None,
    };
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: DR_LIVE_CLIENT_NAMESPACE.to_string(),
        version: Utc::now().to_rfc3339(),
        istio_root_namespace: DR_LIVE_ROOT_NAMESPACE.to_string(),
        service_entries: vec![ServiceEntry {
            name: "dr-live-external".to_string(),
            namespace: DR_LIVE_SERVICE_NAMESPACE.to_string(),
            hosts: vec![DR_LIVE_DESTINATION_HOST.to_string()],
            endpoints: vec![endpoint(backend_a), endpoint(backend_b)],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            // The DESTINATION is visible mesh-wide on purpose: every scenario
            // below varies only the DestinationRules' visibility/tier, never
            // whether the subscriber can see the service at all.
            export_to: vec!["*".to_string()],
            workload_selector: None,
        }],
        destination_rules,
        ..MeshSlice::default()
    }
}

/// Spawn a real egress-gateway mesh data plane for `destination_rules`, drive
/// [`DR_LIVE_REQUESTS`] mTLS requests at the destination, and return the set of
/// backend labels that actually served them.
///
/// Attempt discipline follows the harness contract: readiness is bound to the
/// spawned child, an attempt whose gateway died mid-run is VOID (retried with
/// fresh ports/dirs/control plane), and the route-convergence poll stops at the
/// FIRST authoritative response — the measured requests are then driven exactly
/// once each and every one of them must succeed.
async fn drive_dr_live_visibility(
    scenario: &str,
    destination_rules: Vec<MeshDestinationRule>,
) -> HashSet<String> {
    ensure_gateway_built().expect("gateway binary built");
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/egress";
    let client_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-dr-live-{scenario}-{attempt}");
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let backend_a = start_labeled_echo_backend("backend-a").await;
        let backend_b = start_labeled_echo_backend("backend-b").await;

        let cp = start_static_mesh_cp(dr_live_slice(
            &node_id,
            backend_a,
            backend_b,
            destination_rules.clone(),
        ))
        .await;
        let ports = reserve_mesh_ports().await;
        let egress_port = ports.egress;
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

        let readiness = wait_for_gateway_listener(&mut child, egress_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("egress gateway", egress_port),
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            continue;
        }

        let ca_pem = peers.ca_pem.clone();
        let client_cert_pem = peers.client_cert_pem.clone();
        let client_key_pem = peers.client_key_pem.clone();
        let request = || {
            let ca = ca_pem.clone();
            let cert = client_cert_pem.clone();
            let key = client_key_pem.clone();
            async move {
                mesh_inbound_http_get(
                    egress_port,
                    &ca,
                    server_spiffe,
                    Some((&cert, &key)),
                    DR_LIVE_DESTINATION_HOST,
                    "/",
                )
                .await
            }
        };

        // Convergence only: the egress route table can still be publishing when
        // the listener accepts. Retried outcomes are non-authoritative
        // (transport setup / route not yet materialized) and bounded.
        let deadline = Instant::now() + CROSS_CLUSTER_CONVERGENCE_TIMEOUT;
        let mut observed: HashSet<String> = HashSet::new();
        let mut converged = None;
        while Instant::now() < deadline {
            match request().await {
                Ok((200, response)) => match dr_live_backend_label(&response) {
                    Ok(label) => {
                        converged = Some(label);
                        break;
                    }
                    Err(error) => {
                        last_failure = format!("attempt {attempt}: {error}");
                        break;
                    }
                },
                Ok((status, body)) => {
                    last_failure =
                        format!("attempt {attempt}: convergence status {status}, body {body:?}");
                }
                Err(error) => {
                    last_failure = format!("attempt {attempt}: convergence error {error}");
                }
            }
            let died = exited_gateway_diagnostic(&mut [("egress gateway", &mut child)]);
            if let Some(diagnostic) = died {
                last_failure = format!("attempt {attempt}: {diagnostic}");
                break;
            }
            tokio::time::sleep(CROSS_CLUSTER_CONVERGENCE_POLL_INTERVAL).await;
        }

        let Some(first_body) = converged else {
            last_failure = format!("{last_failure}\n{}", captured_output(&temp));
            kill_child(&mut child);
            cp.shutdown().await;
            continue;
        };
        observed.insert(first_body);

        // Authoritative measurement: each remaining request is driven exactly
        // once and must be served.
        let mut measurement_failure = None;
        for index in 1..DR_LIVE_REQUESTS {
            match request().await {
                Ok((200, response)) => match dr_live_backend_label(&response) {
                    Ok(label) => {
                        observed.insert(label);
                    }
                    Err(error) => {
                        measurement_failure = Some(format!("request {index}: {error}"));
                        break;
                    }
                },
                Ok((status, body)) => {
                    measurement_failure =
                        Some(format!("request {index} returned {status}, body {body:?}"));
                    break;
                }
                Err(error) => {
                    measurement_failure = Some(format!("request {index} failed: {error}"));
                    break;
                }
            }
        }

        let gateway_died = exited_gateway_diagnostic(&mut [("egress gateway", &mut child)]);
        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        // An attempt whose gateway died mid-run is VOID: its transport errors
        // describe a dead process, not a policy decision.
        if let Some(diagnostic) = gateway_died {
            last_failure = format!("attempt {attempt}: {diagnostic}\n{output}");
            continue;
        }
        if let Some(failure) = measurement_failure {
            panic!("[{scenario}] {failure}\n{output}");
        }
        assert!(
            observed
                .iter()
                .all(|label| label == "backend-a" || label == "backend-b"),
            "[{scenario}] unexpected backend labels {observed:?}\n{output}"
        );
        return observed;
    }

    panic!("[{scenario}] no attempt produced a converged egress datapath\n{last_failure}");
}

/// #2465, on the wire: a DestinationRule declared `exportTo: ["."]` in the
/// DESTINATION's namespace is invisible to a subscriber in another namespace,
/// so it must not change that subscriber's traffic. If visibility leaked, the
/// sticky rule would apply and every request would pin to one backend.
#[ignore]
#[tokio::test]
async fn functional_mesh_dr_namespace_local_rule_does_not_reach_another_namespace() {
    let observed = drive_dr_live_visibility(
        "hidden-service-rule",
        vec![dr_live_rule(
            "service-dr",
            DR_LIVE_SERVICE_NAMESPACE,
            &["."],
            true,
        )],
    )
    .await;

    assert_eq!(
        observed.len(),
        2,
        "a DestinationRule exported only to its own namespace must not govern a \
         subscriber in another namespace; the default round-robin must still reach \
         both backends, but traffic pinned to {observed:?}"
    );
}

/// Control for the case above: the SAME sticky rule, exported mesh-wide from
/// the root namespace, DOES reach the subscriber. Without this the previous
/// assertion could pass simply because the rule never applies at all.
#[ignore]
#[tokio::test]
async fn functional_mesh_dr_root_namespace_rule_applies_when_exported() {
    let observed = drive_dr_live_visibility(
        "visible-root-rule",
        vec![dr_live_rule(
            "root-dr",
            DR_LIVE_ROOT_NAMESPACE,
            &["*"],
            true,
        )],
    )
    .await;

    assert_eq!(
        observed.len(),
        1,
        "a mesh-wide root-namespace DestinationRule must govern this subscriber, \
         pinning every request to one backend; observed {observed:?}"
    );
}

/// #2469, on the wire: with visible rules at ALL THREE tiers, the CLIENT
/// namespace's rule wins outright. The service- and root-tier rules are sticky
/// and the client-tier rule is round-robin, so a wrong winner pins traffic to
/// one backend. That also inverts Ferrum's pre-#2469 "layer every match in
/// `(namespace, name)` order, last writer wins" behaviour: `istio-system` sorts
/// after the `ferrum` client namespace, so the old code would have applied the
/// sticky root rule last and won with it.
#[ignore]
#[tokio::test]
async fn functional_mesh_dr_client_namespace_rule_wins_over_service_and_root() {
    let observed = drive_dr_live_visibility(
        "client-tier-wins",
        vec![
            dr_live_rule("service-dr", DR_LIVE_SERVICE_NAMESPACE, &["*"], true),
            dr_live_rule("root-dr", DR_LIVE_ROOT_NAMESPACE, &["*"], true),
            dr_live_rule("client-dr", DR_LIVE_CLIENT_NAMESPACE, &["*"], false),
        ],
    )
    .await;

    assert_eq!(
        observed.len(),
        2,
        "the client-namespace DestinationRule must win the lookup outright, so its \
         round-robin governs and both backends serve; traffic instead behaved like a \
         service/root-tier winner and pinned to {observed:?}"
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
    let listener = bind_fixture_listener(loopback_ephemeral())
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
    let listener = bind_fixture_listener(loopback_ephemeral())
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
        service_namespace: None,
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
        uid: None,
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

/// Live slice for issue #3244: a WorkloadEntry whose SPIFFE/identity stays in
/// `vms` while `service_namespace` stamps an authorized attachment to
/// `prod/reviews`. A same-name decoy Service in `vms` also lists the workload
/// SPIFFE so a regression that keys inbound hosts by the identity namespace
/// would incorrectly admit `reviews.vms...`.
fn cross_namespace_workload_entry_inbound_slice(
    node_id: &str,
    server_spiffe: &str,
    client_spiffe: &str,
    backend_port: u16,
) -> MeshSlice {
    let server_id = SpiffeId::new(server_spiffe).expect("server SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let http_port = WorkloadPort {
        port: backend_port,
        protocol: AppProtocol::Http,
        name: Some("http".to_string()),
    };
    let workload = Workload {
        spiffe_id: server_id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
            namespace: Some("vms".to_string()),
        },
        service_name: "reviews".to_string(),
        service_namespace: Some("prod".to_string()),
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![http_port],
        trust_domain: trust_domain.clone(),
        namespace: "vms".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews-vm".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let attached_service = MeshService {
        cluster_ips: Vec::new(),
        name: "reviews".to_string(),
        namespace: "prod".to_string(),
        ports: vec![ServicePort {
            port: backend_port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: server_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    };
    // Decoy: same service name in the WorkloadEntry identity namespace. Membership
    // includes the workload SPIFFE so a wrong-namespace host match would be a
    // real confused-deputy regression rather than an empty-membership miss.
    let decoy_identity_namespace_service = MeshService {
        cluster_ips: Vec::new(),
        name: "reviews".to_string(),
        namespace: "vms".to_string(),
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
        uid: None,
    };
    let policy = MeshPolicy {
        name: "allow-client".to_string(),
        namespace: "vms".to_string(),
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
            action: PolicyAction::Allow,
        }],
    };
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "vms".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![workload],
        services: vec![attached_service, decoy_identity_namespace_service],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "vms".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        mesh_policies: vec![policy],
        ..MeshSlice::default()
    }
}

/// Spawn a production sidecar whose local WorkloadEntry is attached to a
/// Service in another namespace, then drive one authorized inbound request for
/// the attached Service FQDN and one for the identity-namespace decoy FQDN.
/// Spawn/bind flakes retry with fresh ports; the two Host observations do not.
async fn drive_cross_namespace_workload_entry_inbound()
-> Result<(u16, String, u16, String, String), String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let server_spiffe = "spiffe://cluster.local/ns/vms/sa/reviews-vm";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";
    let attached_host = "reviews.prod.svc.cluster.local";
    let decoy_host = "reviews.vms.svc.cluster.local";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-we-xns-inbound-{attempt}");
        let temp = TempDir::new().map_err(|e| format!("temp dir: {e}"))?;
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let backend_port = start_echo_backend().await;

        let cp = start_static_mesh_cp(cross_namespace_workload_entry_inbound_slice(
            &node_id,
            server_spiffe,
            client_spiffe,
            backend_port,
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
                    // Subscription/identity namespace is the WorkloadEntry's own
                    // namespace; the attached Service lives in `prod`.
                    ("FERRUM_NAMESPACE", "vms".to_string()),
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

        let readiness = wait_for_gateway_listener(&mut child, inbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe(
                    "cross-namespace WorkloadEntry inbound listener",
                    inbound_port,
                ),
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            continue;
        }

        let attached = mesh_inbound_http_get(
            inbound_port,
            &peers.ca_pem,
            server_spiffe,
            Some((&peers.client_cert_pem, &peers.client_key_pem)),
            attached_host,
            "/",
        )
        .await;
        let decoy = mesh_inbound_http_get(
            inbound_port,
            &peers.ca_pem,
            server_spiffe,
            Some((&peers.client_cert_pem, &peers.client_key_pem)),
            decoy_host,
            "/",
        )
        .await;

        if let Some(exited) =
            exited_gateway_diagnostic(&mut [("cross-namespace WorkloadEntry gateway", &mut child)])
        {
            last_failure = format!("attempt {attempt}: {exited}\n{}", captured_output(&temp));
            kill_child(&mut child);
            cp.shutdown().await;
            continue;
        }

        let output = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;

        let attached = attached.map_err(|e| {
            format!("attached Service host GET ({attached_host}) failed: {e}\n{output}")
        })?;
        let decoy = decoy.map_err(|e| {
            format!("identity-namespace decoy host GET ({decoy_host}) failed: {e}\n{output}")
        })?;
        return Ok((attached.0, attached.1, decoy.0, decoy.1, output));
    }

    Err(format!(
        "cross-namespace WorkloadEntry inbound gateway never bound after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Issue #3244 live datapath: an authorized peer reaches a WorkloadEntry
/// backend only through the attached cross-namespace Service identity
/// (`reviews.prod...`). The same-name Service in the WorkloadEntry identity
/// namespace (`reviews.vms...`) must not be routable to that backend.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_inbound_routes_cross_namespace_workload_entry_via_attached_service()
 {
    let (attached_status, attached_body, decoy_status, decoy_body, logs) =
        drive_cross_namespace_workload_entry_inbound()
            .await
            .expect("cross-namespace WorkloadEntry inbound drive");
    assert_eq!(
        attached_status, 200,
        "Host reviews.prod.svc.cluster.local must reach the WorkloadEntry backend through the \
         attached Service namespace; body: {attached_body:?}\n{logs}"
    );
    assert!(
        attached_body.contains("backend-ok"),
        "attached Service response must carry the WorkloadEntry backend body: {attached_body:?}\n{logs}"
    );
    assert!(
        !(decoy_status == 200 && decoy_body.contains("backend-ok")),
        "Host reviews.vms.svc.cluster.local must NOT reach the WorkloadEntry backend via the \
         identity-namespace decoy Service; status={decoy_status} body={decoy_body:?}\n{logs}"
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
            service_namespace: None,
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
            uid: None,
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
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_transport_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B transport listener", b_transport_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so the observation above proves nothing about the mesh
        // datapath — a competing listener on a dropped reservation can answer a
        // bare port probe and then reset the connection (issue #2132). Void the
        // attempt and retry with fresh ports, temp dirs, and control planes.
        // Nothing here retries an observation from a HEALTHY fixture, so
        // authoritative protocol responses and fail-closed security assertions
        // are still made exactly once.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A", &mut child_a),
            ("gateway B", &mut child_b),
        ]);
        if let Some(exited) = exited {
            last_failure = format!(
                "attempt {attempt}: {exited}\n--- gateway A ---\n{}\n--- gateway B ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

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

#[derive(Debug)]
struct MeshRetryBackendObservation {
    repeated: Vec<Vec<u8>>,
    repeated_bin: Vec<Vec<u8>>,
    te: Option<Vec<u8>>,
    content_lengths: Vec<Vec<u8>>,
    x_forwarded_for: Option<Vec<u8>>,
    x_forwarded_proto: Option<Vec<u8>>,
    baggage: Option<Vec<u8>>,
    body: Vec<u8>,
    trailers: Option<hyper::HeaderMap>,
}

fn mesh_retry_mtls_server_config(svid: &GeneratedGatewaySvid) -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_pem = std::fs::read(&svid.trust_bundle_path).expect("read mesh retry trust bundle");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()).filter_map(|cert| cert.ok()) {
        roots.add(cert).expect("add mesh retry client root");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("build mesh retry client verifier");
    let cert_pem = std::fs::read(&svid.cert_path).expect("read mesh retry server SVID");
    let key_pem = std::fs::read(&svid.key_path).expect("read mesh retry server key");
    let chain = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|cert| cert.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse mesh retry server key")
        .expect("mesh retry server key present");
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("build mesh retry server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// Classification of the first byte on a mesh-retry mTLS fixture connection.
///
/// File-mode gateways still run an initial backend-capability refresh that dials
/// plaintext backends with the HTTP/2 prior-knowledge preface (`PRI *…`, first
/// byte `0x50` / `b'P'`) even when `FERRUM_POOL_WARMUP_ENABLED=false`. That same
/// preface is also how a plaintext application attempt begins, so `b'P'` alone
/// cannot prove a connection is harmless preflight. Classification therefore
/// requires the fixture's application phase bit sampled at accept time:
/// * preflight + `P` → discard as the known capability probe,
/// * application phase + `P` → hard-fail (the mTLS bypass under test),
/// * any other first byte → application record (must be TLS `0x16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshRetryInboundFirstByte {
    PreflightCapabilityProbe,
    ApplicationPlaintextHttp2,
    ApplicationRecord(u8),
}

fn classify_mesh_retry_inbound_first_byte(
    first_byte: u8,
    application_phase_armed_at_accept: bool,
) -> MeshRetryInboundFirstByte {
    if first_byte == b'P' {
        if application_phase_armed_at_accept {
            MeshRetryInboundFirstByte::ApplicationPlaintextHttp2
        } else {
            MeshRetryInboundFirstByte::PreflightCapabilityProbe
        }
    } else {
        MeshRetryInboundFirstByte::ApplicationRecord(first_byte)
    }
}

/// Pins the probe/application correlation boundary without running the live
/// gateway fixture: `P` is preflight only before application-phase arming, and
/// the same byte hard-fails afterward so a plaintext application attempt cannot
/// be discarded as a capability probe.
#[test]
fn mesh_retry_mtls_first_byte_classification_is_phase_armed() {
    assert_eq!(
        classify_mesh_retry_inbound_first_byte(b'P', false),
        MeshRetryInboundFirstByte::PreflightCapabilityProbe,
        "preflight may discard the known h2c capability-probe preface"
    );
    assert_eq!(
        classify_mesh_retry_inbound_first_byte(b'P', true),
        MeshRetryInboundFirstByte::ApplicationPlaintextHttp2,
        "post-arm plaintext HTTP/2 preface must hard-fail as the mTLS bypass"
    );
    assert_eq!(
        classify_mesh_retry_inbound_first_byte(0x16, false),
        MeshRetryInboundFirstByte::ApplicationRecord(0x16)
    );
    assert_eq!(
        classify_mesh_retry_inbound_first_byte(0x16, true),
        MeshRetryInboundFirstByte::ApplicationRecord(0x16)
    );
    assert_eq!(
        classify_mesh_retry_inbound_first_byte(b'G', true),
        MeshRetryInboundFirstByte::ApplicationRecord(b'G'),
        "non-preface bytes are application records regardless of phase"
    );
}

/// Source guard: the live mesh-retry mTLS fixture must phase-arm observation
/// around the application request instead of unconditionally discarding every
/// `P` connection (which would also mask a plaintext application attempt).
#[test]
fn mesh_retry_mtls_fixture_phase_arms_before_application_request() {
    let backend = mesh_test_fn_body("start_mesh_retry_mtls_backend");
    assert!(
        backend.contains("classify_mesh_retry_inbound_first_byte("),
        "fixture must classify first bytes through the phase-armed helper"
    );
    assert!(
        backend.contains("MeshRetryInboundFirstByte::PreflightCapabilityProbe"),
        "fixture must preserve preflight capability-probe discard"
    );
    assert!(
        backend.contains("MeshRetryInboundFirstByte::ApplicationPlaintextHttp2"),
        "fixture must hard-fail post-arm plaintext HTTP/2 prefaces"
    );
    assert!(
        backend.contains("armed_at_accept"),
        "fixture must sample application phase at accept time"
    );
    assert!(
        backend.contains("successful secured retry must begin with a TLS handshake record"),
        "fixture must keep the successful-retry TLS 0x16 assertion"
    );
    // Build the forbidden pattern from parts so this assertion's own source
    // text does not trip the `include_str!` self-scan.
    let unconditional_p_discard = [
        "if record_type[0] == b'",
        "P' {\n                drop(stream);\n                continue;",
    ]
    .concat();
    assert!(
        !backend.contains(&unconditional_p_discard),
        "regression: unconditionally discarding every first-byte `P` connection \
         masks a plaintext HTTP/2 application attempt as a capability probe"
    );

    let live = mesh_test_fn_body(
        "functional_mesh_mtls_retry_replays_exact_grpc_request_once_and_rejects_native_trailers_inner",
    );
    let arm = live
        .find("arm_application_phase")
        .expect("live fixture must arm application phase before the request");
    let request = live
        .find("grpc_mesh_retry_request(gateway.proxy_http_port, &payload, None)")
        .expect("live fixture application request not found");
    assert!(
        arm < request,
        "application phase must be armed before the secured mesh retry request"
    );
    assert!(
        live.contains("0x16"),
        "live fixture must keep the failed-attempt TLS handshake assertion"
    );
    assert!(
        live.contains("application_hits.load(Ordering::SeqCst), 1"),
        "live fixture must keep the single application-delivery assertion"
    );
}

/// Hold one destination port for the failed application attempt and its retry.
///
/// The returned [`watch::Sender`] arms application-phase observation. Callers
/// must arm it only after gateway readiness and immediately before the test's
/// application request so startup h2c capability probes accepted in preflight
/// can be discarded without also masking a post-arm plaintext application
/// attempt. Once armed:
/// 1. a first byte of `P` panics (plaintext HTTP/2 is the bypass under test),
/// 2. the first application record is observed (must be TLS `0x16`) and dropped,
/// 3. the next application record must also be `0x16`, is prepended, completes
///    mTLS, and serves one gRPC request.
///
/// Keeping the listener bound throughout removes the close/rebind race that
/// would make a retry fixture timing-dependent.
async fn start_mesh_retry_mtls_backend(
    listener: TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    application_hits: Arc<AtomicUsize>,
) -> (
    watch::Sender<bool>,
    oneshot::Receiver<u8>,
    oneshot::Receiver<MeshRetryBackendObservation>,
    tokio::task::JoinHandle<()>,
) {
    use std::io::Error as IoError;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    /// Re-inject a consumed first TLS record byte before rustls reads the socket.
    struct PrefixedTcpStream {
        prefix: Option<u8>,
        inner: TcpStream,
    }

    impl AsyncRead for PrefixedTcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), IoError>> {
            if let Some(byte) = self.prefix.take() {
                if buf.remaining() == 0 {
                    self.prefix = Some(byte);
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&[byte]);
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PrefixedTcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, IoError>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), IoError>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    let (application_phase_tx, mut application_phase_rx) = watch::channel(false);
    let (first_record_tx, first_record_rx) = oneshot::channel();
    let (observation_tx, observation_rx) = oneshot::channel();
    let observation_tx = Arc::new(Mutex::new(Some(observation_tx)));
    let task = tokio::spawn(async move {
        let mut first_record_tx = Some(first_record_tx);
        let success = loop {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
                .await
                .expect("mesh retry accept timed out")
                .expect("accept mesh retry connection");
            // Sample the phase at accept so a capability probe that connected
            // during preflight stays preflight even if the test arms before the
            // first byte is read.
            let armed_at_accept = *application_phase_rx.borrow();
            let mut record_type = [0u8; 1];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut record_type))
                .await
                .expect("mesh retry connection sent no bytes")
                .expect("read mesh retry record type");
            match classify_mesh_retry_inbound_first_byte(record_type[0], armed_at_accept) {
                MeshRetryInboundFirstByte::PreflightCapabilityProbe => {
                    drop(stream);
                    continue;
                }
                MeshRetryInboundFirstByte::ApplicationPlaintextHttp2 => {
                    panic!(
                        "mesh retry fixture saw plaintext HTTP/2 preface after application \
                         phase arming; this is the mTLS bypass under test, not a capability probe"
                    );
                }
                MeshRetryInboundFirstByte::ApplicationRecord(record) => {
                    if !armed_at_accept {
                        application_phase_rx
                            .wait_for(|armed| *armed)
                            .await
                            .expect("mesh retry application phase arm dropped");
                    }
                    if let Some(tx) = first_record_tx.take() {
                        let _ = tx.send(record);
                        // Failed application attempt: observe the TLS record, then
                        // drop before handshake/request so the gateway retries once.
                        drop(stream);
                        continue;
                    }
                    break PrefixedTcpStream {
                        prefix: Some(record),
                        inner: stream,
                    };
                }
            }
        };

        assert_eq!(
            success.prefix,
            Some(0x16),
            "successful secured retry must begin with a TLS handshake record"
        );

        let tls = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_rustls::TlsAcceptor::from(server_config).accept(success),
        )
        .await
        .expect("mesh retry mTLS handshake timed out")
        .expect("mesh retry mTLS handshake failed");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "secured retry must negotiate HTTP/2"
        );

        let observation_tx = Arc::clone(&observation_tx);
        let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let observation_tx = Arc::clone(&observation_tx);
            let application_hits = Arc::clone(&application_hits);
            async move {
                application_hits.fetch_add(1, Ordering::SeqCst);
                let repeated = req
                    .headers()
                    .get_all("x-repeated")
                    .iter()
                    .map(|value| value.as_bytes().to_vec())
                    .collect();
                let repeated_bin = req
                    .headers()
                    .get_all("x-repeated-bin")
                    .iter()
                    .map(|value| value.as_bytes().to_vec())
                    .collect();
                let te = req
                    .headers()
                    .get("te")
                    .map(|value| value.as_bytes().to_vec());
                let content_lengths: Vec<Vec<u8>> = req
                    .headers()
                    .get_all("content-length")
                    .iter()
                    .map(|value| value.as_bytes().to_vec())
                    .collect();
                let x_forwarded_for = req
                    .headers()
                    .get("x-forwarded-for")
                    .map(|value| value.as_bytes().to_vec());
                let x_forwarded_proto = req
                    .headers()
                    .get("x-forwarded-proto")
                    .map(|value| value.as_bytes().to_vec());
                let baggage = req
                    .headers()
                    .get("baggage")
                    .map(|value| value.as_bytes().to_vec());
                let collected = req.into_body().collect().await?;
                let trailers = collected.trailers().cloned();
                let body = collected.to_bytes().to_vec();
                if let Some(tx) = observation_tx.lock().expect("observation lock").take() {
                    let _ = tx.send(MeshRetryBackendObservation {
                        repeated,
                        repeated_bin,
                        te,
                        content_lengths,
                        x_forwarded_for,
                        x_forwarded_proto,
                        baggage,
                        body: body.clone(),
                        trailers,
                    });
                }

                let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
                let _ = tx.send(Ok(Frame::data(Bytes::from(body)))).await;
                let mut response_trailers = hyper::HeaderMap::new();
                response_trailers
                    .insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
                let _ = tx.send(Ok(Frame::trailers(response_trailers))).await;
                drop(tx);
                Ok::<_, hyper::Error>(
                    hyper::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(StreamBody::new(ReceiverStream::new(rx)))
                        .expect("build mesh retry response"),
                )
            }
        });
        let result = Http2ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls), service)
            .await;
        if let Err(error) = result
            && !error.to_string().contains("connection closed")
        {
            panic!("mesh retry HTTP/2 server failed: {error}");
        }
    });
    (application_phase_tx, first_record_rx, observation_rx, task)
}

async fn grpc_mesh_retry_request(
    port: u16,
    body: &[u8],
    request_trailers: Option<hyper::HeaderMap>,
) -> Result<GrpcEgressResponse, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "mesh retry client connect timed out")??;
    let (mut sender, connection) = tokio::time::timeout(
        Duration::from_secs(5),
        http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
    )
    .await
    .map_err(|_| "mesh retry client HTTP/2 handshake timed out")??;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut frames = vec![Ok::<_, std::convert::Infallible>(Frame::data(
        Bytes::copy_from_slice(body),
    ))];
    if let Some(trailers) = request_trailers {
        frames.push(Ok(Frame::trailers(trailers)));
    }
    let mut request = hyper::Request::builder()
        .method("POST")
        .uri("http://retry.mesh.test/echo.Mesh/Retry")
        .header("content-type", "application/grpc")
        .header("content-length", body.len().to_string())
        .header(
            "baggage",
            "source.principal=spiffe://attacker.invalid/ns/default/sa/forged,user.key=kept",
        )
        .header("te", "trailers")
        .body(StreamBody::new(stream::iter(frames)))?;
    request
        .headers_mut()
        .append("x-repeated", hyper::header::HeaderValue::from_static("one"));
    request
        .headers_mut()
        .append("x-repeated", hyper::header::HeaderValue::from_static("two"));
    request.headers_mut().append(
        "x-repeated-bin",
        hyper::header::HeaderValue::from_static("AAE="),
    );
    request.headers_mut().append(
        "x-repeated-bin",
        hyper::header::HeaderValue::from_static("AgM="),
    );

    let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(request))
        .await
        .map_err(|_| "mesh retry response headers timed out")??;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let mut response_body = Vec::new();
    let mut response_trailers = HashMap::new();
    let mut incoming = response.into_body();
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(10), incoming.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(error))) => return Err(Box::new(error)),
            Ok(None) => break,
            Err(_) => return Err("mesh retry response body timed out".into()),
        };
        if frame.is_data() {
            if let Ok(data) = frame.into_data() {
                response_body.extend_from_slice(&data);
            }
        } else if frame.is_trailers()
            && let Ok(trailers) = frame.into_trailers()
        {
            for (name, value) in &trailers {
                if let Ok(value) = value.to_str() {
                    response_trailers.insert(name.as_str().to_string(), value.to_string());
                }
            }
        }
    }
    connection_task.abort();
    let _ = connection_task.await;
    Ok(GrpcEgressResponse {
        status,
        headers,
        body: response_body,
        trailers: response_trailers,
    })
}

/// Live issue #3285 regression: a retry-enabled static target is admitted to
/// the Sidecar mesh transport. Its first connection dies after emitting a TLS
/// record but before an HTTP/2 request can be written; the replay succeeds over
/// a fresh SVID-mTLS connection with exact repeated/binary metadata and exactly
/// one application delivery. Native request trailers are then rejected before
/// another backend stream is admitted because this generic intake cannot prove
/// them safe to replay.
#[ignore]
#[test]
fn functional_mesh_mtls_retry_replays_exact_grpc_request_once_and_rejects_native_trailers() {
    run_trusted_projected_gateway_test(
        functional_mesh_mtls_retry_replays_exact_grpc_request_once_and_rejects_native_trailers_inner,
    );
}

async fn functional_mesh_mtls_retry_replays_exact_grpc_request_once_and_rejects_native_trailers_inner()
 {
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/retry-client";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/retry-backend";
    let identities = TempDir::new().expect("mesh retry identity tempdir");
    let svids = generate_two_gateway_svids(identities.path(), a_spiffe, b_spiffe);
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind held mesh retry listener");
    let backend_port = listener
        .local_addr()
        .expect("mesh retry listener addr")
        .port();
    let application_hits = Arc::new(AtomicUsize::new(0));
    let (arm_application_phase, first_record, observation, backend_task) =
        start_mesh_retry_mtls_backend(
            listener,
            mesh_retry_mtls_server_config(&svids.b),
            Arc::clone(&application_hits),
        )
        .await;

    // Trusted projection: mesh.* transport tags are stamped the way slice
    // materialization does, then fed to in-process `file::serve`. Operator
    // file-mode YAML must continue rejecting these tags.
    let config = format!(
        r#"version: "1"
proxies:
  - id: "mesh-mtls-live-retry"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    upstream_id: "mesh-mtls-live-retry-upstream"
    retry:
      max_retries: 1
      retryable_status_codes: []
      retryable_methods: ["POST"]
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 100
upstreams:
  - id: "mesh-mtls-live-retry-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        tags:
          mesh.mtls: "true"
          mesh.mtls_port: "{backend_port}"
          mesh.spiffe_id: "{b_spiffe}"
consumers: []
plugin_configs: []
"#
    );
    let env = EnvConfig {
        pool_warmup_enabled: false,
        gateway_svid_cert_path: Some(svids.a.cert_path.clone()),
        gateway_svid_key_path: Some(svids.a.key_path.clone()),
        gateway_svid_trust_bundle_path: Some(svids.a.trust_bundle_path.clone()),
        ..Default::default()
    };
    let mut gateway = TrustedProjectedGateway::spawn_from_yaml(
        &config,
        TrustedProjectedGatewayOptions {
            env,
            excluded_ports: vec![backend_port],
            ..TrustedProjectedGatewayOptions::default()
        },
    )
    .await
    .expect("spawn retry-enabled mesh gateway via trusted projection");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("mesh retry gateway ready");

    // Arm only after readiness and immediately before the application request so
    // startup h2c capability probes remain preflight, while any post-arm
    // plaintext `P` preface hard-fails as the mTLS bypass under test.
    arm_application_phase
        .send(true)
        .expect("mesh retry backend application phase receiver dropped");

    let payload = grpc_framed_payload(b"mesh-replay-body");
    let response = grpc_mesh_retry_request(gateway.proxy_http_port, &payload, None)
        .await
        .expect("secured mesh retry request");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), first_record)
            .await
            .expect("first TLS observation timed out")
            .expect("first TLS observation sender dropped"),
        0x16,
        "the failed application attempt must be a TLS handshake record, never plaintext HTTP"
    );
    let observed = tokio::time::timeout(Duration::from_secs(2), observation)
        .await
        .expect("successful retry observation timed out")
        .expect("successful retry observation sender dropped");
    assert_eq!(response.status, 200, "secured retry response: {response:?}");
    assert_eq!(
        response.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "successful retry must preserve response trailers: {response:?}"
    );
    assert_eq!(response.body, payload, "replayed body must be echoed once");
    assert_eq!(
        observed.body, payload,
        "backend must receive the exact replay bytes"
    );
    assert_eq!(
        observed.repeated,
        vec![b"one".to_vec(), b"two".to_vec()],
        "unchanged repeated metadata must retain separate field lines"
    );
    assert_eq!(
        observed.repeated_bin,
        vec![b"AAE=".to_vec(), b"AgM=".to_vec()],
        "unchanged repeated binary metadata must retain separate field lines"
    );
    assert_eq!(observed.te.as_deref(), Some(b"trailers".as_slice()));
    // The client's `content-length` field line is stripped with the rest of the
    // backend-request framing headers; hyper then regenerates a single
    // authoritative value from the replay body's exact size hint. Assert the
    // regenerated framing rather than its absence: a replayed client value would
    // survive as a second field line, and a stale value would disagree with the
    // bytes the backend actually received.
    assert!(
        observed.content_lengths.len() <= 1,
        "HTTP/2 mesh dispatch must not replay the client Content-Length: {observed:?}"
    );
    if let Some(value) = observed.content_lengths.first() {
        assert_eq!(
            value.as_slice(),
            payload.len().to_string().as_bytes(),
            "regenerated Content-Length must match the replayed body length"
        );
    }
    assert!(
        observed
            .x_forwarded_for
            .as_deref()
            .is_some_and(|value| value.starts_with(b"127.0.0.1")),
        "gateway-owned forwarding identity must be regenerated: {observed:?}"
    );
    assert_eq!(
        observed.x_forwarded_proto.as_deref(),
        Some(b"http".as_slice())
    );
    assert_eq!(
        observed.baggage.as_deref(),
        Some(b"user.key=kept".as_slice()),
        "identity baggage must be stripped without dropping unrelated baggage"
    );
    assert!(
        observed.trailers.is_none(),
        "ordinary unary request has no trailers"
    );
    assert_eq!(application_hits.load(Ordering::SeqCst), 1);

    let mut native_trailers = hyper::HeaderMap::new();
    native_trailers.insert(
        "x-native-request-trailer",
        hyper::header::HeaderValue::from_static("must-not-disappear"),
    );
    let rejected =
        grpc_mesh_retry_request(gateway.proxy_http_port, &payload, Some(native_trailers))
            .await
            .expect("native trailer refusal response");
    assert_eq!(
        rejected.status, 200,
        "gRPC refusal uses Trailers-Only HTTP 200"
    );
    assert_eq!(
        rejected.headers.get("grpc-status").map(String::as_str),
        Some("12"),
        "native trailers must fail closed before a retryable mesh dispatch: {rejected:?}"
    );
    assert_eq!(
        application_hits.load(Ordering::SeqCst),
        1,
        "native trailer refusal must not create another application stream"
    );

    gateway.shutdown().await;
    // In-process `TrustedProjectedGateway` keeps `ProxyState` (and its pooled
    // backend h2 client) alive until dropped; release it before joining the
    // fixture so the secured connection closes and the backend task can exit.
    drop(gateway);
    tokio::time::timeout(Duration::from_secs(5), backend_task)
        .await
        .expect("mesh retry backend teardown timed out")
        .expect("mesh retry backend task panicked");
}

/// h2c gRPC echo backend that responds with REAL HTTP/2 trailers: one DATA
/// frame echoing the request body, then a trailers frame carrying
/// `grpc-status: 0` and a custom `x-mesh-trailer` marker. Unlike the
/// header-encoded Trailers-Only shape, this exercises the full
/// data-then-trailers relay the mesh-mTLS gRPC path must preserve end-to-end.
async fn start_grpc_trailers_echo_backend() -> u16 {
    let listener = bind_fixture_listener(loopback_ephemeral())
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
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_transport_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B transport listener", b_transport_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so the observation above proves nothing about the mesh
        // datapath — a competing listener on a dropped reservation can answer a
        // bare port probe and then reset the connection (issue #2132). Void the
        // attempt and retry with fresh ports, temp dirs, and control planes.
        // Nothing here retries an observation from a HEALTHY fixture, so
        // authoritative protocol responses and fail-closed security assertions
        // are still made exactly once.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A", &mut child_a),
            ("gateway B", &mut child_b),
        ]);
        if let Some(exited) = exited {
            last_failure = format!(
                "attempt {attempt}: {exited}\n--- gateway A ---\n{}\n--- gateway B ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

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

/// gRPC keystone (Ambient, issue #3728): a captured native-gRPC request at
/// gateway A on the STANDARD HTTP/1.1+HTTP/2 frontend rides A's authenticated
/// **HBONE** egress to the gRPC backend behind gateway B, and the backend's REAL
/// HTTP/2 trailers (`grpc-status`, custom trailer) survive the whole relay back
/// to point A's client.
///
/// This is the exact call that used to be refused pre-dial with a Trailers-Only
/// UNAVAILABLE on this frontend while the H3 frontend served it. The refusal
/// described the GENERIC HTTP-family HBONE dispatch, whose inner HTTP/1.1 client
/// cannot carry gRPC trailers; native gRPC instead runs a nested
/// `hyper::client::conn::http2` client over the same authenticated CONNECT byte
/// tunnel, which is why the trailers below arrive as REAL trailers rather than
/// response headers.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_egress_grpc_routes_a_to_b_over_hbone_with_trailers() {
    let (resp, logs) = drive_grpc_egress_a_to_b("ambient", true, |resp| {
        resp.status == 200
            && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")
            && resp
                .body
                .windows(b"ferrum-mesh-grpc-payload".len())
                .any(|w| w == b"ferrum-mesh-grpc-payload")
    })
    .await
    .expect("ambient gRPC egress drive");
    assert_eq!(
        resp.status, 200,
        "the captured gRPC request must traverse A's HBONE egress to B's gRPC backend: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("grpc-status").map(String::as_str),
        Some("0"),
        "the backend's grpc-status TRAILER must survive the nested HTTP/2 connection \
         inside the HBONE tunnel: {resp:?}\n{logs}"
    );
    assert_eq!(
        resp.trailers.get("x-mesh-trailer").map(String::as_str),
        Some("echo-ok"),
        "custom (non-hop-by-hop) trailers must survive the HBONE relay: {resp:?}\n{logs}"
    );
    assert!(
        !resp.headers.contains_key("grpc-status"),
        "a completed RPC must NOT carry a header-borne grpc-status — that shape is the \
         gateway's Trailers-Only refusal, not the backend's answer: {resp:?}\n{logs}"
    );
    assert!(
        resp.body
            .windows(b"ferrum-mesh-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-grpc-payload"),
        "the echoed gRPC payload must ride the relayed DATA frames: {resp:?}\n{logs}"
    );
}

/// gRPC fail-closed negative (Ambient, issue #3728): an UNTRUSTED gateway A —
/// whose SVID does not chain to the mesh CA — must never complete a gRPC call
/// over HBONE. Reusing the mesh transport for native gRPC must not weaken its
/// identity boundary: an unverifiable peer fails closed rather than falling back
/// to an unauthenticated direct dial to the destination's app port.
#[ignore]
#[tokio::test]
async fn functional_mesh_ambient_egress_grpc_rejects_untrusted_client_gateway() {
    let (resp, logs) = drive_grpc_egress_a_to_b("ambient", false, |resp| {
        // Success shape must never be observed; poll to the deadline.
        resp.status == 200 && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")
    })
    .await
    .expect("untrusted ambient gRPC egress drive");
    assert!(
        !(resp.status == 200 && resp.trailers.get("grpc-status").map(String::as_str) == Some("0")),
        "an untrusted gateway's gRPC request must fail closed, not complete: {resp:?}\n{logs}"
    );
    assert!(
        !resp
            .body
            .windows(b"ferrum-mesh-grpc-payload".len())
            .any(|w| w == b"ferrum-mesh-grpc-payload"),
        "no backend payload may leak through an unauthenticated HBONE hop: {resp:?}\n{logs}"
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
/// 12` (UNIMPLEMENTED — Ferrum's HTTP 404→gRPC mapping) with no backend body,
/// or a bare HTTP route-miss / upstream-overflow status (`404`/`503`/`502`)
/// carrying NO gRPC trailers — symmetric with
/// [`classify_cross_cluster_http`]'s transient 404/503/bare-502 set. Any
/// response that reached the routed / backend layer always carries a
/// `grpc-status` (the mesh-mTLS rejection uses `grpc-status: 14`; a backend
/// reply uses `grpc-status: 0`), so a genuinely routed-but-wrong result is never
/// classified as a route-miss and is asserted immediately instead of retried.
fn cross_cluster_grpc_is_route_miss(response: &GrpcEgressResponse) -> bool {
    let grpc_status = response
        .headers
        .get("grpc-status")
        .or_else(|| response.trailers.get("grpc-status"))
        .map(String::as_str);
    if response.status == 200 && grpc_status == Some("12") && response.body.is_empty() {
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
            service_namespace: None,
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
            uid: None,
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
            service_namespace: None,
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
            uid: None,
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
            service_namespace: None,
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
            uid: None,
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
        let readiness =
            wait_for_gateway_listener(&mut child_c, c_inbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway C inbound listener", c_inbound_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_east_west_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B east-west listener", b_east_west_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so the observation above proves nothing about the mesh
        // datapath — a competing listener on a dropped reservation can answer a
        // bare port probe and then reset the connection (issue #2132). Void the
        // attempt and retry with fresh ports, temp dirs, and control planes.
        // Nothing here retries an observation from a HEALTHY fixture, so
        // authoritative protocol responses and fail-closed security assertions
        // are still made exactly once.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A (client)", &mut child_a),
            ("gateway B (east-west)", &mut child_b),
            ("gateway C (dest)", &mut child_c),
        ]);
        if let Some(exited) = exited {
            last_failure = format!(
                "attempt {attempt}: {exited}\n--- gateway A (client) ---\n{}\n\
                 --- gateway B (east-west) ---\n{}\n--- gateway C (dest) ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b),
                captured_output(&temp_c)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

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

    /// The first of this fixture's gateways that has already exited, if any.
    ///
    /// A dead gateway means its ports were never owned by the process the driver
    /// believed it was driving (issue #2132), so the attempt is void — see
    /// [`exited_gateway_diagnostic`].
    fn exited_gateway(&mut self) -> Option<String> {
        exited_gateway_diagnostic(&mut [
            ("gateway A (client)", &mut self.child_a),
            ("gateway B (east-west)", &mut self.child_b),
            ("gateway C (dest)", &mut self.child_c),
        ])
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
    if !wait_for_gateway_listener(&mut child_c, c_inbound_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
    if !wait_for_gateway_listener(&mut child_b, b_east_west_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
    if !wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
        let Some(mut fixture) =
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so this observation proves nothing about the mesh datapath
        // (issue #2132). Void the attempt and retry with fresh ports, temp dirs,
        // and control planes. A HEALTHY fixture's observation is never retried,
        // so authoritative protocol responses and fail-closed security
        // assertions are still made exactly once.
        if let Some(exited) = fixture.exited_gateway() {
            last_failure = format!("attempt {attempt}: {exited}\n{}", fixture.logs());
            fixture.shutdown().await;
            continue;
        }

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
        let Some(mut fixture) =
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so this observation proves nothing about the mesh datapath
        // (issue #2132). Void the attempt and retry with fresh ports, temp dirs,
        // and control planes. A HEALTHY fixture's observation is never retried,
        // so authoritative protocol responses and fail-closed security
        // assertions are still made exactly once.
        if let Some(exited) = fixture.exited_gateway() {
            last_failure = format!("attempt {attempt}: {exited}\n{}", fixture.logs());
            fixture.shutdown().await;
            continue;
        }

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
            service_namespace: None,
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
            uid: None,
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
            service_namespace: None,
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
            uid: None,
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
            service_namespace: None,
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
            uid: None,
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
        let readiness =
            wait_for_gateway_listener(&mut child_c, c_hbone_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway C HBONE listener", c_hbone_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_east_west_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B east-west listener", b_east_west_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so the observation above proves nothing about the mesh
        // datapath — a competing listener on a dropped reservation can answer a
        // bare port probe and then reset the connection (issue #2132). Void the
        // attempt and retry with fresh ports, temp dirs, and control planes.
        // Nothing here retries an observation from a HEALTHY fixture, so
        // authoritative protocol responses and fail-closed security assertions
        // are still made exactly once.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A (client)", &mut child_a),
            ("gateway B (east-west)", &mut child_b),
            ("gateway C (dest)", &mut child_c),
        ]);
        if let Some(exited) = exited {
            last_failure = format!(
                "attempt {attempt}: {exited}\n--- gateway A (client) ---\n{}\n\
                 --- gateway B (east-west) ---\n{}\n--- gateway C (dest) ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b),
                captured_output(&temp_c)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            kill_child(&mut child_c);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            cp_c.shutdown().await;
            continue;
        }

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

    /// The first of this fixture's gateways that has already exited, if any.
    ///
    /// A dead gateway means its ports were never owned by the process the driver
    /// believed it was driving (issue #2132), so the attempt is void — see
    /// [`exited_gateway_diagnostic`].
    fn exited_gateway(&mut self) -> Option<String> {
        exited_gateway_diagnostic(&mut [
            ("gateway A (client)", &mut self.child_a),
            ("gateway B (east-west)", &mut self.child_b),
            ("gateway C (dest)", &mut self.child_c),
        ])
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
    if !wait_for_gateway_listener(&mut child_c, c_hbone_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
    if !wait_for_gateway_listener(&mut child_b, b_east_west_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
    if !wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT)
        .await
        .is_ready()
    {
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
        let Some(mut fixture) =
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so this observation proves nothing about the mesh datapath
        // (issue #2132). Void the attempt and retry with fresh ports, temp dirs,
        // and control planes. A HEALTHY fixture's observation is never retried,
        // so authoritative protocol responses and fail-closed security
        // assertions are still made exactly once.
        if let Some(exited) = fixture.exited_gateway() {
            last_failure = format!("attempt {attempt}: {exited}\n{}", fixture.logs());
            fixture.shutdown().await;
            continue;
        }

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
        let Some(mut fixture) =
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so this observation proves nothing about the mesh datapath
        // (issue #2132). Void the attempt and retry with fresh ports, temp dirs,
        // and control planes. A HEALTHY fixture's observation is never retried,
        // so authoritative protocol responses and fail-closed security
        // assertions are still made exactly once.
        if let Some(exited) = fixture.exited_gateway() {
            last_failure = format!("attempt {attempt}: {exited}\n{}", fixture.logs());
            fixture.shutdown().await;
            continue;
        }

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
    let listener = bind_fixture_listener(loopback_ephemeral())
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
    let listener = bind_fixture_listener(loopback_ephemeral())
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
        let readiness =
            wait_for_gateway_listener(&mut child_b, b_transport_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway B transport listener", b_transport_port),
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
        let readiness =
            wait_for_gateway_listener(&mut child_a, a_outbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("gateway A outbound listener", a_outbound_port),
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

        // A gateway that exited during the run never owned the ports the driver
        // just drove, so the observation above proves nothing about the mesh
        // datapath — a competing listener on a dropped reservation can answer a
        // bare port probe and then reset the connection (issue #2132). Void the
        // attempt and retry with fresh ports, temp dirs, and control planes.
        // Nothing here retries an observation from a HEALTHY fixture, so
        // authoritative protocol responses and fail-closed security assertions
        // are still made exactly once.
        let exited = exited_gateway_diagnostic(&mut [
            ("gateway A", &mut child_a),
            ("gateway B", &mut child_b),
        ]);
        if let Some(exited) = exited {
            last_failure = format!(
                "attempt {attempt}: {exited}\n--- gateway A ---\n{}\n--- gateway B ---\n{}",
                captured_output(&temp_a),
                captured_output(&temp_b)
            );
            kill_child(&mut child_a);
            kill_child(&mut child_b);
            cp_a.shutdown().await;
            cp_b.shutdown().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

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
            service_namespace: None,
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
            uid: None,
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
// Sidecar `ingress[]` STREAM listeners over the authenticated
// mesh-mTLS CONNECT lane (issue #3260)
// ===================================================================

/// Reply tag of the loopback backend a declared `ingress[]` listener's
/// `defaultEndpoint` points at — the ONLY backend a remapped CONNECT may reach.
const INGRESS_ENDPOINT_TAG: &str = "ingress-default-endpoint";

/// Reply tag of a decoy bound on the DECLARED LISTENER port itself. That port
/// is also a declared workload port, so the ordinary inbound open-relay guard
/// WOULD admit a CONNECT to it — seeing this tag therefore means the dial was
/// relayed to the port the peer named instead of the `defaultEndpoint` the
/// operator mapped it onto.
const INGRESS_DECOY_TAG: &str = "listener-port-decoy";

/// Same decoy role for the SECOND listener port the reload phase declares.
const INGRESS_DECOY_B_TAG: &str = "listener-b-port-decoy";

/// Reply tag of a live loopback backend on a declared WORKLOAD port that the
/// `ingress[]` block does NOT declare. Seeing it means a declared ingress block
/// failed OPEN to the ordinary inbound relay surface it is supposed to replace.
const INGRESS_UNLISTED_TAG: &str = "unlisted-port-backend";

/// A raw-TCP loopback backend that TAGS every reply with `label`, so a relayed
/// byte stream proves WHICH loopback endpoint actually served it.
///
/// Holds its listener for the task's lifetime (never drop+rebind) and binds
/// through [`bind_fixture_listener`] so it can never take a port already handed
/// to a mesh gateway subprocess (issue #2132).
async fn start_tagged_tcp_backend(label: &'static str) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind tagged tcp backend");
    let port = listener.local_addr().expect("echo backend addr").port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let Ok(read) = sock.read(&mut buf).await else {
                    return;
                };
                let payload = String::from_utf8_lossy(&buf[..read]).trim().to_string();
                let reply = format!("{label}:{payload}\n");
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    (port, handle)
}

fn abort_backends(handles: &[tokio::task::JoinHandle<()>]) {
    for handle in handles {
        handle.abort();
    }
}

/// Outcome of ONE authenticated mesh-mTLS CONNECT into a Sidecar inbound
/// listener.
#[derive(Debug)]
struct IngressConnectOutcome {
    /// Status the destination sidecar returned for the CONNECT itself.
    status: u16,
    /// The tagged line the relayed loopback backend wrote back, when the tunnel
    /// opened. `None` for every refused CONNECT.
    relayed: Option<String>,
}

/// mTLS client config presenting the peer SVID and verifying the sidecar's
/// server SVID against the shared mesh CA. ALPN `h2` — the mesh-mTLS transport.
fn sidecar_ingress_client_config(
    peers: &MeshPeerSvids,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut peers.ca_pem.as_bytes()).filter_map(|c| c.ok()) {
        roots
            .add(cert)
            .map_err(|e| format!("add mesh CA root: {e}"))?;
    }
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("client protocol versions: {e}"))?
        .with_root_certificates(roots);
    let chain: Vec<_> = rustls_pemfile::certs(&mut peers.client_cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut peers.client_key_pem.as_bytes())
        .map_err(|e| format!("parse client SVID key: {e}"))?
        .ok_or_else(|| "no client SVID private key in PEM".to_string())?;
    let mut config = builder
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("client auth cert: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// Read one newline-terminated tagged line out of a relayed CONNECT tunnel.
///
/// The tunnel stays OPEN after the backend replies, so this stops at the first
/// `\n` rather than draining to EOF. A stream that ends with bytes buffered
/// still returns them, so a truncated reply is reported rather than silently
/// timing out.
async fn read_tagged_relay_reply(
    body: &mut h2::RecvStream,
    timeout: Duration,
) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::new();
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(end) = buf.iter().position(|byte| *byte == b'\n') {
                return Ok(String::from_utf8_lossy(&buf[..end]).into_owned());
            }
            match body.data().await {
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(format!("relay body error: {e}")),
                None if buf.is_empty() => {
                    return Err("relay closed before any backend bytes".to_string());
                }
                None => return Ok(String::from_utf8_lossy(&buf).into_owned()),
            }
        }
    })
    .await
    .map_err(|_| "timed out reading the relayed reply".to_string())?
}

/// Open a real mesh-mTLS HTTP/2 tunnel to a Sidecar's inbound listener and
/// drive ONE bare CONNECT at `authority`.
///
/// This is exactly the wire shape a peer Sidecar's raw-TCP egress opens: a
/// markerless HTTP/2 CONNECT over SVID-mTLS whose `:authority` is
/// `pod-ip:<declared listener port>`. It never touches the REDIRECT-captured
/// plaintext inbound table, so it is the identity-protected lane issue #3260
/// adds the `ingress[]` remap to.
async fn sidecar_ingress_connect(
    inbound_port: u16,
    authority: &str,
    peers: &MeshPeerSvids,
    payload: &str,
) -> Result<IngressConnectOutcome, String> {
    let config = sidecar_ingress_client_config(peers)?;
    let tcp = TcpStream::connect(("127.0.0.1", inbound_port))
        .await
        .map_err(|e| format!("connect sidecar inbound: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
        .map_err(|e| format!("server name: {e}"))?;
    // Bound the handshakes: a bound-but-wedged listener would otherwise hang
    // this ignored test forever, before any of the later deadlines apply.
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, tcp))
        .await
        .map_err(|_| "client TLS handshake timed out".to_string())?
        .map_err(|e| format!("client TLS handshake: {e}"))?;
    {
        // Pin the sidecar's SPIFFE identity from the presented leaf — a
        // same-CA loopback certificate is not proof we reached the workload.
        let (_io, conn) = tls.get_ref();
        let leaf = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| "sidecar presented no certificate".to_string())?;
        let presented = ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(leaf.as_ref())
            .map_err(|e| format!("sidecar leaf lacks a valid SPIFFE URI SAN: {e}"))?;
        let expected = SpiffeId::new(&peers.server_spiffe)
            .map_err(|e| format!("invalid expected sidecar SPIFFE ID: {e}"))?;
        if presented != expected {
            return Err(format!(
                "sidecar SPIFFE ID '{presented}' does not match expected '{expected}'"
            ));
        }
    }

    let (mut sender, conn) =
        tokio::time::timeout(Duration::from_secs(10), h2::client::handshake(tls))
            .await
            .map_err(|_| "h2 handshake timed out".to_string())?
            .map_err(|e| format!("h2 handshake: {e}"))?;
    let conn_task = tokio::spawn(conn);

    // No `x-ferrum-mesh-protocol` marker: the markerless default IS byte-stream
    // HBONE/mesh-mTLS CONNECT, which is what Sidecar raw-TCP egress sends.
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority)
        .body(())
        .map_err(|e| format!("build CONNECT: {e}"))?;
    let (response, mut send_body) = sender
        .send_request(request, false)
        .map_err(|e| format!("send CONNECT: {e}"))?;
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .map_err(|_| "CONNECT response timed out".to_string())?
        .map_err(|e| format!("CONNECT response: {e}"))?;
    let status = response.status().as_u16();

    // Only an accepted CONNECT has a tunnel to write into; a refusal must never
    // be probed for relayed bytes (that would mask a fail-open regression).
    let relayed = if status == 200 {
        send_body
            .send_data(Bytes::from(payload.to_string()), false)
            .map_err(|e| format!("write relay payload: {e}"))?;
        let mut body = response.into_body();
        Some(read_tagged_relay_reply(&mut body, Duration::from_secs(10)).await?)
    } else {
        None
    };

    conn_task.abort();
    Ok(IngressConnectOutcome { status, relayed })
}

/// The local `echo` workload plus its Service.
///
/// Every port in `workload_ports` is declared as a WORKLOAD port, so the
/// ordinary inbound open-relay guard (`inbound_hbone_relay_destination_allowed`)
/// would admit an authenticated CONNECT to any of them. That is what makes the
/// ingress assertions non-vacuous: refusals below come from the DECLARED
/// `ingress[]` surface replacing the ordinary one, not from a port the slice
/// never knew about.
fn sidecar_ingress_local_workload(
    server_spiffe: &str,
    workload_ports: &[u16],
) -> (Workload, MeshService) {
    let server_id = SpiffeId::new(server_spiffe).expect("server SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let workload = Workload {
        spiffe_id: server_id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: Some("ferrum".to_string()),
        },
        service_name: "echo".to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: workload_ports
            .iter()
            .map(|port| WorkloadPort {
                port: *port,
                protocol: AppProtocol::Tcp,
                name: None,
            })
            .collect(),
        trust_domain,
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
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "echo".to_string(),
        namespace: "ferrum".to_string(),
        ports: workload_ports
            .iter()
            .map(|port| ServicePort {
                port: *port,
                protocol: AppProtocol::Tcp,
                name: None,
                target_port: None,
            })
            .collect(),
        workloads: vec![WorkloadRef {
            spiffe_id: server_id,
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    };
    (workload, service)
}

/// Mesh slice whose applicable `Sidecar.ingress[]` was already RESOLVED control
/// plane side — the carrier lane a real CP/xDS deployment delivers. One STREAM
/// listener on `listener_port` forwards to `127.0.0.1:endpoint_port`, and the
/// fail-closed `sidecar_ingress_declared` marker replaces the ordinary inbound
/// surface for every other port. STRICT PeerAuthentication, so the sidecar
/// requires and verifies the peer SVID.
fn sidecar_ingress_stream_slice(
    node_id: &str,
    server_spiffe: &str,
    workload_ports: &[u16],
    listener_port: u16,
    endpoint_port: u16,
) -> MeshSlice {
    use ferrum_edge::modes::mesh::config::ResolvedIngressListener;

    let (workload, service) = sidecar_ingress_local_workload(server_spiffe, workload_ports);
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        workloads: vec![workload.clone()],
        services: vec![service.clone()],
        local_inbound_workloads: Some(vec![workload]),
        local_inbound_services: vec![service],
        local_ingress_listeners: vec![ResolvedIngressListener {
            port: listener_port,
            endpoint_host: "127.0.0.1".to_string(),
            endpoint_port,
            protocol: AppProtocol::Tcp,
            endpoint_unix_path: None,
            endpoint_unix_h2c: false,
            owner_namespace: "ferrum".to_string(),
            owner_service: "echo".to_string(),
        }],
        sidecar_ingress_declared: true,
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

/// File-source `{ "mesh": ... }` document for the same workload, expressed as a
/// RAW ingress-only `Sidecar` so the DATA PLANE runs the real
/// `Sidecar.ingress[]` resolution itself (`FERRUM_MESH_SIDECAR_ENFORCED=true`)
/// instead of consuming a control-plane-resolved listener set.
///
/// `ingress` is `(listener_port, endpoint_port)` pairs. `deny_listener_port`
/// adds a MeshWide `AuthorizationPolicy` DENY scoped to that DESTINATION port.
fn sidecar_ingress_mesh_document(
    server_spiffe: &str,
    workload_ports: &[u16],
    ingress: &[(u16, u16)],
    deny_listener_port: Option<u16>,
) -> String {
    use ferrum_edge::modes::mesh::config::{MeshSidecar, MeshSidecarIngress, RequestMatch};

    let (workload, service) = sidecar_ingress_local_workload(server_spiffe, workload_ports);
    let sidecar = MeshSidecar {
        name: "echo-ingress".to_string(),
        namespace: "ferrum".to_string(),
        workload_selector: None,
        // An ingress-only Sidecar omits `spec.egress`, so no egress scope
        // resolves and the listeners must anchor on the local service through
        // the decoupled path (F6 §6.2), not through egress narrowing.
        egress_inherits_defaults: true,
        egress: Vec::new(),
        // No explicit `spec.outboundTrafficPolicy`, so this Sidecar inherits the
        // mesh-wide policy (issue #3262).
        outbound_traffic_policy: None,
        ingress_declared: true,
        ingress: ingress
            .iter()
            .map(|(listener_port, endpoint_port)| MeshSidecarIngress {
                port: *listener_port,
                protocol: AppProtocol::Tcp,
                name: None,
                bind: None,
                default_endpoint: format!("127.0.0.1:{endpoint_port}"),
            })
            .collect(),
    };
    // Istio scopes `AuthorizationPolicy` `to.ports` to the DECLARED listener
    // port for a Sidecar ingress listener, never to its `defaultEndpoint`.
    let mesh_policies: Vec<MeshPolicy> = deny_listener_port
        .into_iter()
        .map(|port| MeshPolicy {
            name: "deny-ingress-listener-port".to_string(),
            namespace: "ferrum".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    ports: vec![port],
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Deny,
            }],
        })
        .collect();
    let mesh = MeshConfig {
        workloads: vec![workload],
        services: vec![service],
        sidecars: vec![sidecar],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        mesh_policies,
        ..MeshConfig::default()
    };
    serde_json::to_string(&serde_json::json!({ "mesh": mesh })).expect("mesh document serializes")
}

/// The two authoritative CONNECT observations one healthy sidecar fixture makes.
struct SidecarIngressProbes {
    /// CONNECT naming the DECLARED `ingress[]` listener port.
    declared: IngressConnectOutcome,
    /// CONNECT naming a declared workload port the `ingress[]` block omits.
    unlisted: IngressConnectOutcome,
}

/// Spawn a production Sidecar over a slice carrying one RESOLVED stream
/// `ingress[]` listener, then drive both authoritative CONNECTs against it.
///
/// Spawn/bind flakes are retried with fresh ports, temp dirs, control planes and
/// backends; the CONNECT observations themselves are made exactly once against a
/// healthy fixture. The outer `Err` is a SETUP failure — never a fail-closed
/// pass.
async fn drive_sidecar_ingress_connect_relay() -> Result<SidecarIngressProbes, String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-ingress-connect-{attempt}");
        let temp = TempDir::new().map_err(|e| format!("temp dir: {e}"))?;
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let (endpoint_port, endpoint) = start_tagged_tcp_backend(INGRESS_ENDPOINT_TAG).await;
        let (listener_port, decoy) = start_tagged_tcp_backend(INGRESS_DECOY_TAG).await;
        let (unlisted_port, unlisted) = start_tagged_tcp_backend(INGRESS_UNLISTED_TAG).await;
        let backends = [endpoint, decoy, unlisted];

        let cp = start_static_mesh_cp(sidecar_ingress_stream_slice(
            &node_id,
            server_spiffe,
            &[listener_port, unlisted_port],
            listener_port,
            endpoint_port,
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

        let readiness = wait_for_gateway_listener(&mut child, inbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("sidecar", inbound_port),
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            abort_backends(&backends);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let declared = sidecar_ingress_connect(
            inbound_port,
            &format!("127.0.0.1:{listener_port}"),
            &peers,
            "ping",
        )
        .await;
        let unlisted = sidecar_ingress_connect(
            inbound_port,
            &format!("127.0.0.1:{unlisted_port}"),
            &peers,
            "ping",
        )
        .await;

        let exited = exited_gateway_diagnostic(&mut [("sidecar", &mut child)]);
        let logs = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;
        abort_backends(&backends);

        // An attempt whose gateway died mid-run is VOID: the listener port was
        // never owned by the process these probes believed they reached.
        if let Some(diagnostic) = exited {
            last_failure = format!("attempt {attempt}: {diagnostic}\n{logs}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        return Ok(SidecarIngressProbes {
            declared: declared.map_err(|e| format!("declared-port CONNECT: {e}\n{logs}"))?,
            unlisted: unlisted.map_err(|e| format!("unlisted-port CONNECT: {e}\n{logs}"))?,
        });
    }

    Err(format!(
        "sidecar ingress gateway never came up after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

/// Issue #3260 keystone: the identity-protected Sidecar-to-Sidecar lane.
///
/// A real `ferrum-edge` Sidecar consumes a slice declaring one STREAM
/// `ingress[]` listener, and a genuine SVID-mTLS HTTP/2 CONNECT naming
/// `pod-ip:<declared listener port>` is relayed to that listener's loopback
/// `defaultEndpoint` — a DIFFERENT port, proven by the endpoint backend's tag
/// rather than the decoy bound on the declared port itself. The declared port
/// is the routing signal; the endpoint port is only where it lands.
///
/// The same run asserts the fail-closed half: a CONNECT naming a declared
/// WORKLOAD port the `ingress[]` block does NOT declare is refused, even though
/// a live backend is listening there and the ordinary open-relay guard would
/// have admitted it. Declaring `ingress[]` REPLACES the ordinary inbound
/// surface; falling through to it would be a fail-open regression.
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_ingress_stream_connect_relays_declared_listener_port() {
    // `.expect` on the outer Result: a setup failure is a test failure, never a
    // silent fail-closed pass.
    let probes = drive_sidecar_ingress_connect_relay()
        .await
        .expect("sidecar ingress fixture");
    let expected = format!("{INGRESS_ENDPOINT_TAG}:ping");

    assert_eq!(
        probes.declared.status, 200,
        "a CONNECT naming the declared ingress listener port must be accepted; relayed {:?}",
        probes.declared.relayed
    );
    assert_eq!(
        probes.declared.relayed.as_deref(),
        Some(expected.as_str()),
        "the declared listener must relay to its defaultEndpoint backend, not to the \
         listener port the peer named (decoy tag '{INGRESS_DECOY_TAG}')"
    );

    assert_ne!(
        probes.unlisted.status, 200,
        "a declared ingress[] block replaces the ordinary inbound surface: a CONNECT to an \
         UNLISTED workload port must be refused, not relayed"
    );
    assert!(
        probes.unlisted.relayed.is_none(),
        "a refused CONNECT must not carry relayed backend bytes: {:?}",
        probes.unlisted.relayed
    );
}

/// Issue #3260 live policy + reload: the DECLARED listener port is the security
/// signal, and a config refresh withdraws a listener on the live datapath.
///
/// Driven from the FILE source so the data plane resolves the raw
/// `Sidecar.ingress[]` itself (`FERRUM_MESH_SIDECAR_ENFORCED=true`) and SIGHUP
/// is a deterministic in-test config refresh — the only refresh this harness can
/// perform without standing up a second control plane (the `MeshSubscribe` stub
/// serves one slice then heartbeats).
///
/// * Phase 1 — the declared stream listener relays to its `defaultEndpoint`, and
///   an unlisted workload port is refused.
/// * Phase 2 — a MeshWide `AuthorizationPolicy` DENY scoped to the DECLARED
///   LISTENER port rejects the CONNECT (403). Authorizing on the
///   `defaultEndpoint` backend port instead would let that DENY fail OPEN.
/// * Phase 3 — a reload that declares a DIFFERENT listener withdraws the first:
///   the old port fails closed (neither relayed nor still 403 from phase 2) and
///   the new one relays to the same endpoint.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_ingress_stream_reload_withdraws_declared_listener() {
    ensure_gateway_built().expect("gateway build");
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";
    let client_spiffe = "spiffe://cluster.local/ns/default/sa/client";

    let mut last_failure = String::new();
    'attempts: for attempt in 1..=RETRY_ATTEMPTS {
        let temp = TempDir::new().expect("temp dir");
        let peers = generate_mesh_peer_svids(temp.path(), server_spiffe, client_spiffe);
        let (endpoint_port, endpoint) = start_tagged_tcp_backend(INGRESS_ENDPOINT_TAG).await;
        let (first_port, first_decoy) = start_tagged_tcp_backend(INGRESS_DECOY_TAG).await;
        let (second_port, second_decoy) = start_tagged_tcp_backend(INGRESS_DECOY_B_TAG).await;
        let (unlisted_port, unlisted) = start_tagged_tcp_backend(INGRESS_UNLISTED_TAG).await;
        let backends = [endpoint, first_decoy, second_decoy, unlisted];
        let reload_ports = SidecarIngressReloadPorts {
            endpoint: endpoint_port,
            first: first_port,
            second: second_port,
            unlisted: unlisted_port,
        };
        let workload_ports = reload_ports.workload_ports();

        let mesh_doc_path = temp.path().join("mesh.json");
        std::fs::write(
            &mesh_doc_path,
            sidecar_ingress_mesh_document(
                server_spiffe,
                &workload_ports,
                &[(first_port, endpoint_port)],
                None,
            ),
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
                // FERRUM_DP_CP_GRPC_URLS points at a dead port and is ignored.
                cp_addr: "127.0.0.1:1".parse().expect("dummy addr"),
                ports,
                node_id: &format!("functional-mesh-ingress-reload-{attempt}"),
                config_protocol: "file",
                topology: "sidecar",
                waypoint_name: None,
                env_overrides: vec![
                    ("FERRUM_MESH_FILE_CONFIG_PATH", mesh_doc_env),
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_MESH_SIDECAR_ENFORCED", "true".to_string()),
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

        let readiness = wait_for_gateway_listener(&mut child, inbound_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("sidecar", inbound_port),
                captured_output(&temp)
            );
            kill_child(&mut child);
            abort_backends(&backends);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue 'attempts;
        }

        let outcome = run_sidecar_ingress_reload_phases(
            inbound_port,
            &peers,
            &reload_ports,
            &mesh_doc_path,
            &mut child,
        )
        .await;

        // One cleanup path for every phase outcome, so a failed phase can never
        // leave the gateway subprocess or a fixture backend running.
        let exited = exited_gateway_diagnostic(&mut [("sidecar", &mut child)]);
        let output = captured_output(&temp);
        kill_child(&mut child);
        abort_backends(&backends);

        // An attempt whose gateway died mid-run is VOID: its inbound port was
        // never owned by the process these phases believed they were driving,
        // so retry with fresh ports, temp dirs and backends instead of
        // reporting the resulting transport error as a datapath result.
        if let Some(diagnostic) = exited {
            last_failure = format!("attempt {attempt}: {diagnostic}\n{output}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue 'attempts;
        }
        if let Err(e) = outcome {
            panic!("{e}\n{output}");
        }
        return;
    }

    panic!(
        "mesh file-source sidecar never came up after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    );
}

/// The four loopback ports the reload fixture juggles.
struct SidecarIngressReloadPorts {
    /// The shared `defaultEndpoint` backend both declared listeners map onto.
    endpoint: u16,
    /// The listener the first document declares, then withdraws.
    first: u16,
    /// The listener the reloaded document declares instead.
    second: u16,
    /// A declared workload port the `ingress[]` block never declares.
    unlisted: u16,
}

impl SidecarIngressReloadPorts {
    /// Every listener port stays a declared WORKLOAD port for the whole run, so
    /// a withdrawn listener remains a port the ordinary inbound open-relay guard
    /// WOULD have admitted. The withdrawal assertion then measures the ingress
    /// surface, not a shrinking workload port set.
    fn workload_ports(&self) -> [u16; 3] {
        [self.first, self.second, self.unlisted]
    }
}

/// The three live phases of the file-source reload fixture, run against one
/// healthy sidecar subprocess. Returns `Err` with a self-describing message so
/// the caller owns the single cleanup path.
async fn run_sidecar_ingress_reload_phases(
    inbound_port: u16,
    peers: &MeshPeerSvids,
    ports: &SidecarIngressReloadPorts,
    mesh_doc_path: &std::path::Path,
    child: &mut Child,
) -> Result<(), String> {
    let server_spiffe = peers.server_spiffe.as_str();
    let workload_ports = ports.workload_ports();
    let first_authority = format!("127.0.0.1:{}", ports.first);
    let second_authority = format!("127.0.0.1:{}", ports.second);
    let unlisted_authority = format!("127.0.0.1:{}", ports.unlisted);
    let expected = format!("{INGRESS_ENDPOINT_TAG}:ping");
    let reload_deadline = Duration::from_secs(20);

    // ── Phase 1: the resolved stream listener relays to its endpoint ──────
    let served = sidecar_ingress_connect(inbound_port, &first_authority, peers, "ping").await?;
    if served.status != 200 {
        return Err(format!(
            "a data-plane-resolved ingress[] stream listener must accept the CONNECT, got \
             status {} relayed {:?}",
            served.status, served.relayed
        ));
    }
    if served.relayed.as_deref() != Some(expected.as_str()) {
        return Err(format!(
            "the CONNECT must be relayed to the defaultEndpoint backend, not the declared \
             listener port's decoy; relayed {:?}",
            served.relayed
        ));
    }

    let unlisted_probe =
        sidecar_ingress_connect(inbound_port, &unlisted_authority, peers, "ping").await?;
    if unlisted_probe.status == 200 {
        return Err(format!(
            "a declared ingress[] block must refuse an unlisted workload port, not relay it; \
             relayed {:?}",
            unlisted_probe.relayed
        ));
    }

    // ── Phase 2: a DENY scoped to the DECLARED listener port ──────────────
    std::fs::write(
        mesh_doc_path,
        sidecar_ingress_mesh_document(
            server_spiffe,
            &workload_ports,
            &[(ports.first, ports.endpoint)],
            Some(ports.first),
        ),
    )
    .map_err(|e| format!("rewrite mesh document with a listener-port DENY: {e}"))?;
    sighup_mesh_gateway(child)?;
    // Authorizing on the `defaultEndpoint` backend port instead of the DECLARED
    // listener port would let this DENY fail OPEN — the CONNECT would keep
    // returning 200 and this wait would time out.
    let denied = wait_for_ingress_connect(
        inbound_port,
        &first_authority,
        peers,
        reload_deadline,
        |outcome| outcome.status == 403,
    )
    .await
    .map_err(|e| format!("listener-port DENY never fired after reload: {e}"))?;
    if denied.relayed.is_some() {
        return Err(format!(
            "a denied CONNECT must not reach the loopback endpoint: {:?}",
            denied.relayed
        ));
    }

    // ── Phase 3: withdraw that listener, declare a different one ──────────
    std::fs::write(
        mesh_doc_path,
        sidecar_ingress_mesh_document(
            server_spiffe,
            &workload_ports,
            &[(ports.second, ports.endpoint)],
            None,
        ),
    )
    .map_err(|e| format!("rewrite mesh document withdrawing the first listener: {e}"))?;
    sighup_mesh_gateway(child)?;
    // Neither 200 (relayed) nor 403 (phase 2's now-withdrawn DENY): under the
    // NEW document the withdrawn listener port must fail closed.
    let withdrawn = wait_for_ingress_connect(
        inbound_port,
        &first_authority,
        peers,
        reload_deadline,
        |outcome| outcome.status != 200 && outcome.status != 403,
    )
    .await
    .map_err(|e| format!("the withdrawn ingress listener never failed closed: {e}"))?;
    if withdrawn.relayed.is_some() {
        return Err(format!(
            "a withdrawn listener must not relay: {:?}",
            withdrawn.relayed
        ));
    }

    let updated = sidecar_ingress_connect(inbound_port, &second_authority, peers, "ping").await?;
    if updated.status != 200 {
        return Err(format!(
            "the reloaded document's NEW listener port must serve, got status {} relayed {:?}",
            updated.status, updated.relayed
        ));
    }
    if updated.relayed.as_deref() != Some(expected.as_str()) {
        return Err(format!(
            "the updated listener must relay to the same defaultEndpoint backend, not its own \
             decoy; relayed {:?}",
            updated.relayed
        ));
    }
    Ok(())
}

/// Deliver SIGHUP to a spawned mesh gateway so the file source reloads.
fn sighup_mesh_gateway(child: &mut Child) -> Result<(), String> {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-HUP", &pid])
        .status()
        .map_err(|e| format!("send SIGHUP to pid {pid}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("SIGHUP delivery failed for pid {pid}: {status}"))
    }
}

/// Poll an authenticated CONNECT until `accept` is satisfied or the deadline
/// passes.
///
/// Used ONLY to wait for a config refresh to land — never to retry a
/// steady-state observation from a healthy fixture.
async fn wait_for_ingress_connect(
    inbound_port: u16,
    authority: &str,
    peers: &MeshPeerSvids,
    timeout: Duration,
    accept: impl Fn(&IngressConnectOutcome) -> bool,
) -> Result<IngressConnectOutcome, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let last = match sidecar_ingress_connect(inbound_port, authority, peers, "ping").await {
            Ok(outcome) if accept(&outcome) => return Ok(outcome),
            Ok(outcome) => format!(
                "last CONNECT to {authority}: status {} relayed {:?}",
                outcome.status, outcome.relayed
            ),
            Err(e) => format!("last CONNECT to {authority} failed: {e}"),
        };
        if Instant::now() >= deadline {
            return Err(last);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

// ===================================================================
// Issue #3226 — AuthorizationPolicy targetRefs live datapath
// ===================================================================
//
// These drive a REAL byte-stream HBONE CONNECT at a spawned ServiceWaypoint
// gateway and assert the request OUTCOME, not just a translation shape:
//
//   * a matching `targetRefs` Gateway/Service attachment actually denies (403)
//     traffic that would otherwise be relayed (200 + echoed bytes);
//   * a sibling service behind the SAME waypoint is unaffected;
//   * the mixed `{Service reviews, Gateway other-waypoint}` case cannot broaden
//     onto that sibling through its unmatched Gateway arm.
//
// The waypoint terminates HBONE on :15008 and transparently relays a route-miss
// CONNECT to its authority, so two loopback TCP echoes on distinct ports stand
// in for two distinct destination Services. `mesh_authz` runs in the authorize
// phase, before the relay dials anything.

const WAYPOINT_TARGET_REFS_NAME: &str = "reviews-waypoint";
const WAYPOINT_TARGET_REFS_OTHER: &str = "other-waypoint";
const WAYPOINT_TARGET_REFS_NAMESPACE: &str = "ferrum";

/// Raw loopback TCP echo: the ServiceWaypoint byte-stream relay copies bytes
/// straight through, so an echo proves the relay actually completed. The
/// accepted-connection counter is what makes a DENY assertion real — a denied
/// request must leave this backend with ZERO connections, because `mesh_authz`
/// rejects in the authorize phase, before the relay dials anything.
async fn start_loopback_tcp_echo() -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind loopback TCP echo");
    let port = listener.local_addr().expect("TCP echo address").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                }
            });
        }
    });
    (port, accepted, task)
}

/// Destination workload for one Service behind the waypoint. Each service gets
/// its OWN loopback port so the two destinations are distinct backend keys, and
/// deliberately IDENTICAL selector labels so a regression that matched on
/// shared labels instead of exact Service identity would be caught.
fn waypoint_destination_workload(service: &str, port: u16) -> Workload {
    let spiffe = format!("spiffe://cluster.local/ns/{WAYPOINT_TARGET_REFS_NAMESPACE}/sa/{service}");
    Workload {
        spiffe_id: SpiffeId::new(&spiffe).expect("destination SPIFFE id"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "shared".to_string())]),
            namespace: Some(WAYPOINT_TARGET_REFS_NAMESPACE.to_string()),
        },
        service_name: service.to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn waypoint_destination_service(service: &str, port: u16) -> MeshService {
    let spiffe = format!("spiffe://cluster.local/ns/{WAYPOINT_TARGET_REFS_NAMESPACE}/sa/{service}");
    MeshService {
        cluster_ips: Vec::new(),
        name: service.to_string(),
        namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: SpiffeId::new(&spiffe).expect("destination SPIFFE id"),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    }
}

/// A ServiceWaypoint slice fronting two sibling Services (`reviews`,
/// `ratings`), under STRICT PeerAuthentication, with ONE DENY policy whose
/// `targetRefs` are supplied by the caller.
fn target_refs_waypoint_slice(
    node_id: &str,
    reviews_port: u16,
    ratings_port: u16,
    attachments: Vec<PolicyTargetAttachment>,
) -> MeshSlice {
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
        version: Utc::now().to_rfc3339(),
        // The DENY policy below is owned by this namespace, and one caller
        // attaches a `GatewayClass` arm. GatewayClass is cluster-scoped, so
        // only the Istio root namespace may own such a policy — declare this
        // namespace as root so the fixture is a VALID config and the property
        // under test stays "a non-matching class arm must not broaden", not
        // "an unowned class arm is accepted". Blank root provenance would be
        // normalized to `istio-system` and reject the policy.
        //
        // Inert otherwise on this DP path: the reconstructed root namespace is
        // read only by GatewayClass ownership validation and DestinationRule
        // tier arbitration, and this slice carries no DestinationRules.
        istio_root_namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
        waypoint_gateway_class: Some("istio-waypoint".to_string()),
        workloads: vec![
            waypoint_destination_workload("reviews", reviews_port),
            waypoint_destination_workload("ratings", ratings_port),
        ],
        services: vec![
            waypoint_destination_service("reviews", reviews_port),
            waypoint_destination_service("ratings", ratings_port),
        ],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-strict".to_string(),
            namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        mesh_policies: vec![MeshPolicy {
            name: "deny-targeted".to_string(),
            namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
            scope: PolicyScope::TargetRefs { attachments },
            rules: vec![MeshRule {
                action: PolicyAction::Deny,
                ..MeshRule::default()
            }],
        }],
        ..MeshSlice::default()
    }
}

/// Read exactly `expected` bytes back off the relay tunnel. The relay keeps the
/// response stream OPEN, so this stops at the expected length instead of
/// draining to EOF. Deterministic: it waits for the bytes the echo owes us and
/// fails on a closed stream — no sleeps, no retry-until-pass.
async fn read_relayed_bytes(
    body: &mut h2::RecvStream,
    expected: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(timeout, async {
        let mut buf: Vec<u8> = Vec::new();
        while buf.len() < expected {
            match body.data().await {
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => return Err(format!("relay body error: {e}")),
                None => return Err("relay body ended before the echoed bytes".to_string()),
            }
        }
        Ok(buf)
    })
    .await
    .map_err(|_| "timed out reading relayed bytes".to_string())?
}

/// Open mTLS H2 to the waypoint, send a MARKER-LESS (byte-stream) HBONE CONNECT
/// to `authority`, write `payload`, and return (status, echoed bytes).
async fn drive_one_waypoint_byte_connect(
    hbone_port: u16,
    authority: &str,
    client_svid: &GeneratedGatewaySvid,
    payload: &[u8],
) -> Result<(u16, Option<Vec<u8>>), String> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", hbone_port))
        .await
        .map_err(|e| format!("connect waypoint: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(udp_dest_client_config(client_svid));
    let server_name = rustls::pki_types::ServerName::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
    );
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
        .body(())
        .map_err(|e| format!("build CONNECT: {e}"))?;
    let (response_fut, mut send_body) = sender
        .send_request(req, false)
        .map_err(|e| format!("send CONNECT: {e}"))?;
    // Keep the request stream OPEN so the relay stays alive for the echo.
    let _ = send_body.send_data(bytes::Bytes::copy_from_slice(payload), false);

    let resp = tokio::time::timeout(Duration::from_secs(10), response_fut)
        .await
        .map_err(|_| "CONNECT response timed out".to_string())?
        .map_err(|e| format!("CONNECT response: {e}"))?;
    let status = resp.status().as_u16();

    let echoed = if status == 200 {
        let mut response_body = resp.into_body();
        Some(
            read_relayed_bytes(&mut response_body, payload.len(), Duration::from_secs(5))
                .await
                .map_err(|e| format!("read relayed bytes: {e}"))?,
        )
    } else {
        None
    };

    conn_task.abort();
    Ok((status, echoed))
}

/// The outcome of probing BOTH destinations behind one waypoint under one
/// `targetRefs` policy: CONNECT status, echoed bytes, and how many connections
/// that destination's backend actually accepted.
struct WaypointDestinationOutcome {
    status: u16,
    echoed: Option<Vec<u8>>,
    backend_connections: usize,
}

struct WaypointTargetRefsOutcome {
    reviews: WaypointDestinationOutcome,
    ratings: WaypointDestinationOutcome,
}

/// Spawn a ServiceWaypoint gateway fronting `reviews` + `ratings`, install one
/// `targetRefs` DENY policy, and probe BOTH destinations through the real HBONE
/// relay. The outer `Err` is a SETUP failure (gateway never built/bound after
/// retries) and must never be read as a fail-closed pass; a spawn/bind flake is
/// retried with fresh ports, the observations are made exactly once.
async fn drive_waypoint_target_refs(
    label: &str,
    attachments: Vec<PolicyTargetAttachment>,
) -> Result<WaypointTargetRefsOutcome, String> {
    ensure_gateway_built().map_err(|e| format!("gateway build: {e}"))?;
    let waypoint_spiffe = "spiffe://cluster.local/ns/ferrum/sa/reviews-waypoint";
    let client_spiffe = "spiffe://cluster.local/ns/ferrum/sa/client-app";

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-target-refs-{label}-{attempt}");
        let temp = TempDir::new().map_err(|e| format!("temp dir: {e}"))?;
        let svids = generate_two_gateway_svids(temp.path(), client_spiffe, waypoint_spiffe);

        let (reviews_port, reviews_hits, reviews_echo) = start_loopback_tcp_echo().await;
        let (ratings_port, ratings_hits, ratings_echo) = start_loopback_tcp_echo().await;

        let cp = start_static_mesh_cp(target_refs_waypoint_slice(
            &node_id,
            reviews_port,
            ratings_port,
            attachments.clone(),
        ))
        .await;
        let ports = reserve_mesh_ports().await;
        let hbone_port = ports.hbone;

        let mut child = spawn_mesh_gateway(
            &temp,
            MeshGatewaySpawnOptions {
                cp_addr: cp.addr,
                ports,
                node_id: &node_id,
                config_protocol: "native",
                topology: "service_waypoint",
                waypoint_name: Some(WAYPOINT_TARGET_REFS_NAME),
                env_overrides: vec![
                    ("FERRUM_MESH_PRODUCTION_MODE", "true".to_string()),
                    ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                    (
                        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                        waypoint_spiffe.to_string(),
                    ),
                    ("FERRUM_GATEWAY_SVID_CERT_PATH", svids.b.cert_path.clone()),
                    ("FERRUM_GATEWAY_SVID_KEY_PATH", svids.b.key_path.clone()),
                    (
                        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                        svids.b.trust_bundle_path.clone(),
                    ),
                ],
            },
        );

        let readiness = wait_for_gateway_listener(&mut child, hbone_port, STARTUP_TIMEOUT).await;
        if !readiness.is_ready() {
            last_failure = format!(
                "attempt {attempt}: {}\n{}",
                readiness.describe("service waypoint HBONE listener", hbone_port),
                captured_output(&temp)
            );
            kill_child(&mut child);
            cp.shutdown().await;
            reviews_echo.abort();
            ratings_echo.abort();
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let reviews = drive_one_waypoint_byte_connect(
            hbone_port,
            &format!("127.0.0.1:{reviews_port}"),
            &svids.a,
            b"reviews-payload",
        )
        .await;
        let ratings = drive_one_waypoint_byte_connect(
            hbone_port,
            &format!("127.0.0.1:{ratings_port}"),
            &svids.a,
            b"ratings-payload",
        )
        .await;

        // An attempt whose gateway died mid-run is VOID: its transport errors
        // are not authorization evidence. Retry with fresh ports/dirs/CP rather
        // than reporting a dead-process reset as a datapath or fail-closed
        // result (issue #2132).
        let died = exited_gateway_diagnostic(&mut [("service waypoint", &mut child)]);
        let logs = captured_output(&temp);
        kill_child(&mut child);
        cp.shutdown().await;
        reviews_echo.abort();
        ratings_echo.abort();

        if let Some(diagnostic) = died {
            last_failure = format!("attempt {attempt}: {diagnostic}\n{logs}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        return match (reviews, ratings) {
            (Ok((reviews_status, reviews_echoed)), Ok((ratings_status, ratings_echoed))) => {
                Ok(WaypointTargetRefsOutcome {
                    reviews: WaypointDestinationOutcome {
                        status: reviews_status,
                        echoed: reviews_echoed,
                        backend_connections: reviews_hits.load(Ordering::SeqCst),
                    },
                    ratings: WaypointDestinationOutcome {
                        status: ratings_status,
                        echoed: ratings_echoed,
                        backend_connections: ratings_hits.load(Ordering::SeqCst),
                    },
                })
            }
            (Err(e), _) | (_, Err(e)) => Err(format!(
                "waypoint CONNECT failed against a healthy gateway: {e}\n--- waypoint ---\n{logs}"
            )),
        };
    }

    Err(format!(
        "service waypoint never bound its HBONE listener after {RETRY_ATTEMPTS} attempts\n{last_failure}"
    ))
}

fn assert_relayed(outcome: &WaypointDestinationOutcome, payload: &[u8], what: &str) {
    assert_eq!(outcome.status, 200, "{what} must be relayed (200)");
    assert_eq!(
        outcome.echoed.as_deref(),
        Some(payload),
        "{what} must echo its payload back through the relay byte-for-byte"
    );
    assert!(
        outcome.backend_connections >= 1,
        "{what} must actually reach its backend"
    );
}

fn assert_denied(outcome: &WaypointDestinationOutcome, what: &str) {
    assert_eq!(
        outcome.status, 403,
        "{what} must be denied by mesh_authz (403)"
    );
    assert_eq!(
        outcome.backend_connections, 0,
        "{what} must be denied BEFORE the relay dials — its backend must see no connection"
    );
}

/// Baseline: with the DENY policy attached to ANOTHER waypoint, both
/// destinations relay. This is the control that makes the deny assertions below
/// meaningful — without it a 403 could just mean "the relay never worked".
#[ignore]
#[tokio::test]
async fn functional_mesh_waypoint_target_refs_non_matching_gateway_relays_both() {
    let outcome = drive_waypoint_target_refs(
        "other-gateway",
        vec![PolicyTargetAttachment::Gateway {
            namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
            name: WAYPOINT_TARGET_REFS_OTHER.to_string(),
        }],
    )
    .await
    .expect("waypoint targetRefs setup");

    assert_relayed(&outcome.reviews, b"reviews-payload", "reviews");
    assert_relayed(&outcome.ratings, b"ratings-payload", "ratings");
}

/// A matching `Gateway` targetRef changes a real request outcome: every
/// destination behind THIS waypoint is denied.
#[ignore]
#[tokio::test]
async fn functional_mesh_waypoint_target_refs_matching_gateway_denies_every_destination() {
    let outcome = drive_waypoint_target_refs(
        "matching-gateway",
        vec![PolicyTargetAttachment::Gateway {
            namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
            name: WAYPOINT_TARGET_REFS_NAME.to_string(),
        }],
    )
    .await
    .expect("waypoint targetRefs setup");

    assert_denied(&outcome.reviews, "reviews");
    assert_denied(&outcome.ratings, "ratings");
}

/// A matching `Service` targetRef denies only its own destination; the sibling
/// service behind the same waypoint is unaffected.
#[ignore]
#[tokio::test]
async fn functional_mesh_waypoint_target_refs_service_denies_only_its_destination() {
    let outcome = drive_waypoint_target_refs(
        "service",
        vec![PolicyTargetAttachment::Service {
            namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
            name: "reviews".to_string(),
        }],
    )
    .await
    .expect("waypoint targetRefs setup");

    assert_denied(&outcome.reviews, "reviews");
    assert_relayed(&outcome.ratings, b"ratings-payload", "ratings");
}

/// The live proof for the mixed-attachment scope bug: a policy listing BOTH a
/// matching Service and a NON-matching Gateway is legitimately retained at this
/// waypoint (its Service arm matches), and the unmatched Gateway arm must not
/// widen it onto the sibling destination. Before the fix this returned 403 for
/// `ratings` too.
#[ignore]
#[tokio::test]
async fn functional_mesh_waypoint_mixed_target_refs_do_not_broaden_to_sibling() {
    let outcome = drive_waypoint_target_refs(
        "mixed",
        vec![
            PolicyTargetAttachment::Service {
                namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
                name: "reviews".to_string(),
            },
            PolicyTargetAttachment::Gateway {
                namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
                name: WAYPOINT_TARGET_REFS_OTHER.to_string(),
            },
        ],
    )
    .await
    .expect("waypoint targetRefs setup");

    assert_denied(&outcome.reviews, "reviews");
    assert_relayed(
        &outcome.ratings,
        b"ratings-payload",
        "the sibling destination under a mixed-ref policy",
    );
}

/// The same broadening guard for a mixed `{Service, non-matching GatewayClass}`
/// policy: this waypoint's class is `istio-waypoint`, so the `ferrum-waypoint`
/// arm must not attach.
#[ignore]
#[tokio::test]
async fn functional_mesh_waypoint_mixed_gateway_class_target_refs_do_not_broaden_to_sibling() {
    let outcome = drive_waypoint_target_refs(
        "mixed-class",
        vec![
            PolicyTargetAttachment::Service {
                namespace: WAYPOINT_TARGET_REFS_NAMESPACE.to_string(),
                name: "reviews".to_string(),
            },
            PolicyTargetAttachment::GatewayClass {
                name: "ferrum-waypoint".to_string(),
            },
        ],
    )
    .await
    .expect("waypoint targetRefs setup");

    assert_denied(&outcome.reviews, "reviews");
    assert_relayed(
        &outcome.ratings,
        b"ratings-payload",
        "the sibling destination under a mixed class-ref policy",
    );
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

    /// SIGTERM and wait up to `grace` for the child to exit on its own.
    ///
    /// Returns whether it did. A `false` result means the child was force-killed
    /// mid-shutdown, so nothing downstream may treat its graceful-shutdown work
    /// (listener stop, gate-close handshake, iptables cleanup) as having run.
    /// `stop()`'s fixed 5s grace is shorter than the host-UDP gate-close
    /// acknowledgement budget, so a test that asserts a shutdown post-condition
    /// must use this instead.
    fn stop_gracefully(&mut self, grace: Duration) -> bool {
        let Some(mut child) = self.0.take() else {
            return false;
        };
        let pid = child.id();
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if child.try_wait().is_ok_and(|status| status.is_some()) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        false
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
fn udp_round_trip_from_netns_with_source(
    pid: u32,
    source_ip: std::net::IpAddr,
    destination: SocketAddr,
    payload: &'static [u8],
    timeout: Duration,
) -> Result<(Vec<u8>, SocketAddr), String> {
    run_in_live_netns(pid, move || {
        let socket = std::net::UdpSocket::bind(SocketAddr::new(source_ip, 0))
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
fn udp_round_trip_from_netns(
    pid: u32,
    destination: SocketAddr,
    payload: &'static [u8],
    timeout: Duration,
) -> Result<(Vec<u8>, SocketAddr), String> {
    udp_round_trip_from_netns_with_source(
        pid,
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        destination,
        payload,
        timeout,
    )
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
            service_namespace: None,
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
            uid: None,
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
///
/// Scope: source-capture producer + HBONE egress to a **host-loopback** UDP echo
/// (`start_counting_udp_echo` on `127.0.0.1`). Does **not** exercise the
/// enrolled-destination pod-netns relay path (destination workload inside its own
/// pod netns with registry mapping and tc-inbound admit) — tracked on #3621.
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
    let disabled_registry = TempDir::new().expect("disabled UDP pod registry tempdir");
    let _disabled_registry_entry = pod
        .publish(disabled_registry.path(), POD_UID)
        .expect("publish disabled UDP pod registry entry");
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
    // capture socket. This is an independent fixture ownership generation;
    // reusing its durable state for the enabled producer below would model an
    // unsafe disabled -> pod-netns rollout, which correctly requires an
    // explicit cleanup/finalize generation.
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
                    disabled_registry.path().display().to_string(),
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

/// Dual-stack host-side veth pair with `/32`+`/128` host routes so the production
/// host-UDP interface resolver (`discover_dedicated_veth_for_pod_ip[6]`) can find
/// the peer without `hostPID`/`setns`.
#[cfg(target_os = "linux")]
struct LiveHostUdpVethPod {
    pod: LivePodNetns,
    host_if: String,
    pod_v4: std::net::Ipv4Addr,
    pod_v6: std::net::Ipv6Addr,
}

#[cfg(target_os = "linux")]
impl LiveHostUdpVethPod {
    fn spawn(subnet_octet: u8) -> Result<Self, String> {
        let pod = LivePodNetns::spawn(false)?;
        let suffix = format!("{:x}{subnet_octet:02x}", std::process::id());
        let suffix = &suffix[suffix.len().saturating_sub(8)..];
        let host_if = format!("hu{suffix}");
        let pod_if = format!("pu{suffix}");
        let host_v4 = std::net::Ipv4Addr::new(10, 204, subnet_octet, 1);
        let pod_v4 = std::net::Ipv4Addr::new(10, 204, subnet_octet, 2);
        let host_v6: std::net::Ipv6Addr =
            format!("fd00:204:{subnet_octet:x}::1").parse().expect("v6");
        let pod_v6: std::net::Ipv6Addr =
            format!("fd00:204:{subnet_octet:x}::2").parse().expect("v6");
        let _ = Command::new("ip").args(["link", "del", &host_if]).status();
        let setup = Command::new("ip")
            .args([
                "link", "add", &host_if, "type", "veth", "peer", "name", &pod_if,
            ])
            .status()
            .map_err(|error| format!("create host-udp veth: {error}"))?;
        if !setup.success() {
            return Err(format!("create host-udp veth failed with {setup}"));
        }
        let move_peer = Command::new("ip")
            .args(["link", "set", &pod_if, "netns", &pod.pid().to_string()])
            .status()
            .map_err(|error| format!("move host-udp veth peer: {error}"))?;
        if !move_peer.success() {
            let _ = Command::new("ip").args(["link", "del", &host_if]).status();
            return Err(format!("move host-udp veth peer failed with {move_peer}"));
        }
        for args in [
            vec![
                "addr".to_string(),
                "add".to_string(),
                format!("{host_v4}/32"),
                "dev".to_string(),
                host_if.clone(),
            ],
            vec![
                "-6".to_string(),
                "addr".to_string(),
                "add".to_string(),
                format!("{host_v6}/128"),
                "dev".to_string(),
                host_if.clone(),
                "nodad".to_string(),
            ],
            vec![
                "link".to_string(),
                "set".to_string(),
                host_if.clone(),
                "up".to_string(),
            ],
            vec![
                "route".to_string(),
                "add".to_string(),
                format!("{pod_v4}/32"),
                "dev".to_string(),
                host_if.clone(),
            ],
            vec![
                "-6".to_string(),
                "route".to_string(),
                "add".to_string(),
                format!("{pod_v6}/128"),
                "dev".to_string(),
                host_if.clone(),
            ],
        ] {
            let status = Command::new("ip")
                .args(args.iter().map(String::as_str))
                .status()
                .map_err(|error| format!("configure host-udp host veth: {error}"))?;
            if !status.success() {
                let _ = Command::new("ip").args(["link", "del", &host_if]).status();
                return Err(format!(
                    "host-udp host veth command {args:?} failed with {status}"
                ));
            }
        }
        if let Err(error) = netns_command(
            pod.pid(),
            &format!(
                "set -e; \
                 ip addr add {pod_v4}/32 dev {pod_if}; \
                 ip -6 addr add {pod_v6}/128 dev {pod_if} nodad; \
                 ip link set {pod_if} up; \
                 ip route add {host_v4}/32 dev {pod_if}; \
                 ip -6 route add {host_v6}/128 dev {pod_if}; \
                 ip route add default via {host_v4} dev {pod_if}; \
                 ip -6 route add default via {host_v6} dev {pod_if}"
            ),
        ) {
            let _ = Command::new("ip").args(["link", "del", &host_if]).status();
            return Err(error);
        }
        Ok(Self {
            pod,
            host_if,
            pod_v4,
            pod_v6,
        })
    }

    fn publish_host_udp(
        &self,
        registry_dir: &std::path::Path,
        pod_uid: &str,
        spiffe_id: &str,
    ) -> Result<PathBuf, String> {
        std::fs::create_dir_all(registry_dir)
            .map_err(|error| format!("create host-udp registry: {error}"))?;
        let path = registry_dir.join(pod_uid);
        let contents = format!(
            "{}\nspiffe_id={spiffe_id}\nipv4={}\nipv6={}\n",
            self.pod.cgroup_dir.path().display(),
            self.pod_v4,
            self.pod_v6
        );
        std::fs::write(&path, contents)
            .map_err(|error| format!("publish host-udp registry entry: {error}"))?;
        Ok(path)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveHostUdpVethPod {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_if])
            .status();
    }
}

#[cfg(target_os = "linux")]
fn seed_host_udp_placement_state(registry_dir: &std::path::Path) -> Result<(), String> {
    // Host-netns placement refuses to start without durable predecessor proof
    // (#3703). Seed a completed host-netns ownership record so the production
    // ProxyHostUdpBackend path can RunStable in this disposable fixture.
    let path = registry_dir.join(".udp-placement-state-v1.json");
    std::fs::write(
        &path,
        r#"{"version":1,"active":"host-netns","pending":null,"completed":null}"#,
    )
    .map_err(|error| format!("seed host-udp placement state: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod host-udp placement state: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn checked_command_stdout(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{program} spawn failed: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} {args:?} failed with {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn capture_jump_count(rules: &str) -> usize {
    rules
        .lines()
        .filter(|line| line.starts_with("-A PREROUTING ") && line.contains("FERRUM_MESH_UDP_HOST"))
        .filter(|line| !line.contains("GUARD"))
        .count()
}

#[cfg(target_os = "linux")]
fn host_udp_capture_snapshot(
    capture_port: u16,
) -> Result<(usize, usize, usize, usize, usize), String> {
    let v4_rules = checked_command_stdout("iptables-save", &["-t", "mangle"])?;
    let v6_rules = checked_command_stdout("ip6tables-save", &["-t", "mangle"])?;
    let v4_route_rules = checked_command_stdout("ip", &["rule", "show"])?;
    let v6_route_rules = checked_command_stdout("ip", &["-6", "rule", "show"])?;
    let v4_routes = v4_route_rules
        .lines()
        .filter(|line| line.contains("lookup 33135"))
        .count();
    let v6_routes = v6_route_rules
        .lines()
        .filter(|line| line.contains("lookup 33135"))
        .count();
    let port_suffix = format!(":{:04X}", capture_port);
    let listeners = std::fs::read_to_string("/proc/net/udp")
        .unwrap_or_default()
        .lines()
        .chain(
            std::fs::read_to_string("/proc/net/udp6")
                .unwrap_or_default()
                .lines(),
        )
        .filter(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|local| local.ends_with(&port_suffix))
        })
        .count();
    Ok((
        capture_jump_count(&v4_rules),
        capture_jump_count(&v6_rules),
        v4_routes,
        v6_routes,
        listeners,
    ))
}

#[cfg(target_os = "linux")]
fn wait_for_host_udp_capture(
    capture_port: u16,
    active: bool,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match host_udp_capture_snapshot(capture_port) {
            Ok((v4_jumps, v6_jumps, v4_routes, v6_routes, listeners)) => {
                let ready = if active {
                    v4_jumps >= 1
                        && v6_jumps >= 1
                        && v4_routes >= 1
                        && v6_routes >= 1
                        && listeners >= 1
                } else {
                    v4_jumps == 0
                        && v6_jumps == 0
                        && v4_routes == 0
                        && v6_routes == 0
                        && listeners == 0
                };
                if ready {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "host UDP capture did not become {} (v4_jumps={v4_jumps} \
                         v6_jumps={v6_jumps} v4_routes={v4_routes} \
                         v6_routes={v6_routes} listeners={listeners})",
                        if active { "active" } else { "absent" }
                    ));
                }
            }
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Production `ProxyHostUdpBackend` live gate (#3705): Ambient host-network UDP
/// capture with two independent veth-backed workloads, IPv4 delivery, transparent
/// replies, and exact Ferrum-owned cleanup after shutdown.
#[cfg(target_os = "linux")]
#[ignore = "requires root + dual-stack veth + iptables/TPROXY + host-netns UDP placement"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_mesh_live_host_udp_capture_proxy_backend_round_trip() {
    if !live_source_capture_prerequisites() {
        return;
    }
    for binary in ["ip6tables", "ip6tables-save"] {
        let present = Command::new("sh")
            .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|status| status.success());
        if !present {
            skip_or_fail_live_source_capture(&format!("`{binary}` is unavailable"));
            return;
        }
    }
    ensure_gateway_built().expect("build gateway for host-UDP live test");

    const VIP_V4: &str = "192.0.2.90";
    const VIP_V6: &str = "2001:db8::90";
    // Registry filenames ARE the pod UIDs. `UdpSourceIdentity::new` (and therefore
    // production host-UDP enrollment) fail-closed unless the UID parses as a
    // Kubernetes UUID — the same shape `host_udp_capture_live_tests` and the
    // node-agent registry publish. Non-UUID labels leave `source_identity=None`
    // and surface as `reason=missing_identity` with capture never installed.
    const POD_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const POD_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let capture_port = ferrum_edge::capture::DEFAULT_UDP_OUTBOUND_PORT;

    let pod_a = match LiveHostUdpVethPod::spawn(21) {
        Ok(pod) => pod,
        Err(error) => {
            skip_or_fail_live_source_capture(&format!("cannot create host-UDP pod A: {error}"));
            return;
        }
    };
    let pod_b = match LiveHostUdpVethPod::spawn(22) {
        Ok(pod) => pod,
        Err(error) => {
            skip_or_fail_live_source_capture(&format!("cannot create host-UDP pod B: {error}"));
            return;
        }
    };

    let registry = TempDir::new().expect("host-UDP registry");
    seed_host_udp_placement_state(registry.path()).expect("seed placement state");
    let a_spiffe = "spiffe://cluster.local/ns/ferrum/sa/host-udp-a";
    let b_spiffe = "spiffe://cluster.local/ns/ferrum/sa/host-udp-b";
    let echo_spiffe = "spiffe://cluster.local/ns/ferrum/sa/host-udp-echo";
    let _entry_a = pod_a
        .publish_host_udp(registry.path(), POD_A, a_spiffe)
        .expect("publish pod A");
    let _entry_b = pod_b
        .publish_host_udp(registry.path(), POD_B, b_spiffe)
        .expect("publish pod B");

    let temp_a = TempDir::new().expect("gateway A tempdir");
    let temp_b = TempDir::new().expect("gateway B tempdir");
    let svids = generate_two_gateway_svids(temp_b.path(), a_spiffe, echo_spiffe);
    let (echo_port, _echo_received, echo_task) = start_counting_udp_echo().await;
    let node_a = "functional-live-host-udp-a";
    let node_b = "functional-live-host-udp-b";
    let mut slice_a = live_source_capture_slice(
        node_a,
        echo_spiffe,
        "127.0.0.1",
        VIP_V4,
        echo_port,
        AppProtocol::Udp,
    );
    slice_a.services[0].cluster_ips.push(VIP_V6.to_string());
    let mut slice_b = live_source_capture_slice(
        node_b,
        echo_spiffe,
        "127.0.0.1",
        VIP_V4,
        echo_port,
        AppProtocol::Udp,
    );
    slice_b.services[0].cluster_ips.push(VIP_V6.to_string());
    let cp_a = start_static_mesh_cp(slice_a).await;
    let cp_b = start_static_mesh_cp(slice_b).await;

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
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", echo_spiffe.to_string()),
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
        "host-UDP destination HBONE listener did not bind\n{}",
        captured_output(&temp_b)
    );

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
                (
                    "FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED",
                    "true".to_string(),
                ),
                ("FERRUM_MESH_CAPTURE_UDP_PORT", capture_port.to_string()),
                (
                    "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
                    "0.0.0.0/0,::/0".to_string(),
                ),
                ("FERRUM_MESH_IP6TABLES_ENABLED", "true".to_string()),
                ("FERRUM_MESH_EGRESS_HBONE_PORT", b_hbone_port.to_string()),
            ],
        },
    ));
    assert!(
        wait_for_tcp_port(a_outbound, STARTUP_TIMEOUT).await,
        "host-UDP source gateway A did not start\n{}",
        captured_output(&temp_a)
    );
    if let Err(error) = wait_for_host_udp_capture(capture_port, true, Duration::from_secs(25)) {
        panic!(
            "ProxyHostUdpBackend did not install host capture: {error}\n{}",
            captured_output(&temp_a)
        );
    }
    assert!(
        wait_for_captured_output(
            &temp_a,
            "Ambient host-network UDP capture enabled",
            Duration::from_secs(5),
        )
        .await,
        "gateway A must select the host-network UDP placement\n{}",
        captured_output(&temp_a)
    );

    let destination_v4: SocketAddr = format!("{VIP_V4}:{echo_port}")
        .parse()
        .expect("IPv4 UDP VIP");
    let deadline = Instant::now() + Duration::from_secs(20);
    let (reply_a, source_a) = loop {
        match udp_round_trip_from_netns_with_source(
            pod_a.pod.pid(),
            std::net::IpAddr::V4(pod_a.pod_v4),
            destination_v4,
            b"host-udp-a",
            Duration::from_secs(3),
        ) {
            Ok(result) => break result,
            Err(error) if Instant::now() < deadline => {
                eprintln!("host-UDP pod A retry: {error}");
            }
            Err(error) => panic!(
                "host-UDP pod A round trip failed: {error}\n{}",
                captured_output(&temp_a)
            ),
        }
    };
    assert_eq!(reply_a, b"host-udp-a");
    assert_eq!(source_a, destination_v4);

    let (reply_b, source_b) = udp_round_trip_from_netns_with_source(
        pod_b.pod.pid(),
        std::net::IpAddr::V4(pod_b.pod_v4),
        destination_v4,
        b"host-udp-b",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| {
        panic!(
            "host-UDP pod B round trip failed: {error}\n{}",
            captured_output(&temp_a)
        )
    });
    assert_eq!(reply_b, b"host-udp-b");
    assert_eq!(source_b, destination_v4);

    let destination_v6: SocketAddr = format!("[{VIP_V6}]:{echo_port}")
        .parse()
        .expect("IPv6 UDP VIP");
    for (pod, payload) in [
        (&pod_a, b"host-udp-a6" as &'static [u8]),
        (&pod_b, b"host-udp-b6" as &'static [u8]),
    ] {
        let (reply, source) = udp_round_trip_from_netns_with_source(
            pod.pod.pid(),
            std::net::IpAddr::V6(pod.pod_v6),
            destination_v6,
            payload,
            Duration::from_secs(5),
        )
        .unwrap_or_else(|error| {
            panic!(
                "host-UDP IPv6 round trip failed: {error}\n{}",
                captured_output(&temp_a)
            )
        });
        assert_eq!(reply, payload);
        assert_eq!(source, destination_v6);
    }

    // Shutdown is asserted against an EXACT outcome, never "whatever survived a
    // timeout". `ProxyHostUdpBackend::shutdown` has exactly two documented
    // branches, and both retire the capture path completely:
    //
    //   * acknowledged  - the node agent published `.udp-not-ready` for every
    //     pod, so `teardown_all()` removes every Ferrum-owned host object;
    //   * unacknowledged - the fail-closed branch installs the DROP guard over
    //     the still-enrolled interfaces FIRST, then removes the capture chain,
    //     the fwmark routing objects, and the capture listener.
    //
    // The acknowledgement wait is capped below mesh mode's background-task drain
    // so this unacknowledged fixture cannot be aborted mid-handshake (which would
    // leave jumps/routes installed after the process exits).
    //
    // No node agent runs in this fixture, so the unacknowledged branch is the
    // expected one; either way the branch actually taken must be proven by its
    // own post-condition rather than tolerated.
    assert!(
        gateway_a.stop_gracefully(Duration::from_secs(60)),
        "gateway A must complete its own shutdown; a force-killed child proves \
         nothing about ProxyHostUdpBackend cleanup\n{}",
        captured_output(&temp_a)
    );
    let retire_budget = Duration::from_secs(20);
    if let Err(error) = wait_for_host_udp_capture(capture_port, false, retire_budget) {
        panic!(
            "ProxyHostUdpBackend shutdown did not retire the host capture path: {error}\n{}",
            captured_output(&temp_a)
        );
    }

    let mangle = format!(
        "{}\n{}",
        checked_command_stdout("iptables-save", &["-t", "mangle"])
            .expect("read the IPv4 mangle table after host-UDP shutdown"),
        checked_command_stdout("ip6tables-save", &["-t", "mangle"])
            .expect("read the IPv6 mangle table after host-UDP shutdown")
    );
    assert!(
        !mangle.lines().any(|line| {
            line.starts_with("-A PREROUTING ")
                && line.contains("FERRUM_MESH_UDP_HOST")
                && !line.contains("GUARD")
        }),
        "the capture chain jump must be gone after shutdown\n{mangle}"
    );

    let logs = captured_output(&temp_a);
    let unacknowledged = logs.contains("node-agent did not acknowledge closing its UDP gates");
    if unacknowledged {
        // Narrowly justified retained-guard outcome: the guard is the ONLY thing
        // keeping a pod whose BPF gate is still open from escaping in plaintext,
        // so it must actually be installed and it must DROP.
        assert!(
            mangle.contains("FERRUM_MESH_UDP_HOST_GUARD_A")
                || mangle.contains("FERRUM_MESH_UDP_HOST_GUARD_B"),
            "an unacknowledged shutdown must retain an installed fail-closed \
             DROP guard\n{mangle}"
        );
        assert!(
            mangle.lines().any(|line| {
                line.contains("FERRUM_MESH_UDP_HOST_GUARD") && line.contains("-j DROP")
            }),
            "the retained shutdown guard must DROP the enrolled scope\n{mangle}"
        );
        assert!(
            !logs.contains("could not install the shutdown fail-closed guard"),
            "the shutdown guard install must succeed\n{logs}"
        );
    } else {
        // Acknowledged outcome (`teardown_all`): nothing Ferrum-owned may
        // survive at all, guard chains included.
        assert!(
            !mangle.contains("FERRUM_MESH_UDP_HOST"),
            "an acknowledged shutdown must remove every Ferrum-owned host UDP \
             object, guard chains included\n{mangle}"
        );
    }

    gateway_b.stop();
    cp_a.shutdown().await;
    cp_b.shutdown().await;
    echo_task.abort();
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
///
/// This proves the shared REDIRECT-captured `mesh_tcp_inbound` relay datapath
/// only. The issue #3260 Sidecar `ingress[]` STREAM lane has its OWN live
/// coverage, which does not need root/netns:
/// `functional_mesh_sidecar_ingress_stream_connect_relays_declared_listener_port`
/// and `functional_mesh_sidecar_ingress_stream_reload_withdraws_declared_listener`.
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
        uid: None,
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
        service_namespace: None,
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
        service_namespace: None,
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
        const START_ATTEMPTS: usize = 3;

        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match Self::start_once().await {
                Ok(fixture) => return Ok(fixture),
                Err(error) => {
                    failures.push(format!("attempt {attempt}: {error}"));
                }
            }
        }
        Err(format!(
            "live two-cluster fixture exhausted {START_ATTEMPTS} fresh setup attempts:\n{}",
            failures.join("\n")
        ))
    }

    async fn start_once() -> Result<Self, String> {
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

        let ports_sidecar_destination = reserve_mesh_ports_in_netns(destination.pod.pid())?;
        let sidecar_destination_inbound = ports_sidecar_destination.inbound;
        let ports_ambient_destination = reserve_mesh_ports_in_netns(destination.pod.pid())?;
        let ambient_destination_hbone = ports_ambient_destination.hbone;
        let ports_east_west = reserve_mesh_ports_in_netns(east_west.pod.pid())?;
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

        let ports_sidecar_source = reserve_mesh_ports_in_netns(source.pod.pid())?;
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

        let ports_unfederated = reserve_mesh_ports_in_netns(source.pod.pid())?;
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

        let ports_wrong_td = reserve_mesh_ports_in_netns(source.pod.pid())?;
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

        let ports_missing_sni = reserve_mesh_ports_in_netns(source.pod.pid())?;
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
fn live_xc_decode_chunked_body(mut data: &[u8]) -> Result<String, String> {
    let mut body = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "missing chunk-size terminator".to_string())?;
        let size_line = std::str::from_utf8(&data[..line_end])
            .map_err(|error| format!("non-UTF-8 chunk size: {error}"))?;
        let size_text = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("invalid chunk size {size_text:?}: {error}"))?;
        data = &data[line_end + 2..];
        if data.len() < size.saturating_add(2) {
            return Err(format!(
                "truncated chunk: declared {size} bytes, received {}",
                data.len()
            ));
        }
        if size == 0 {
            return String::from_utf8(body)
                .map_err(|error| format!("non-UTF-8 HTTP response body: {error}"));
        }
        body.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            return Err("missing chunk-data terminator".to_string());
        }
        data = &data[size + 2..];
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
        let (headers, wire_body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("HTTP VIP response has no header terminator: {response:?}"))?;
        let chunked = headers.lines().skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("transfer-encoding")
                    && value
                        .split(',')
                        .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            })
        });
        let body = if chunked {
            live_xc_decode_chunked_body(wire_body.as_bytes())
                .map_err(|error| format!("decode HTTP VIP chunked response: {error}"))?
        } else {
            wire_body.to_string()
        };
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

// ── Sidecar ingress Unix-socket backends (issue #3261) ───────────────────────
//
// These tests drive the REAL translation boundary: a `Sidecar` with
// `ingress[].defaultEndpoint: unix://…` rides the localized mesh file source,
// the data plane builds the slice itself (`MeshSlice::from_gateway_config` — the
// same materialization every CP path uses), materializes the tagged upstream,
// and then serves LIVE traffic over the socket. Nothing here hand-authors the
// reserved `mesh.unix_socket` tag, so a regression anywhere between the Sidecar
// spec and the dial fails the test.
//
// The inbound listener is plaintext (no SVID material, dev posture, an explicit
// PeerAuthentication DISABLE), so the client side is a plain TCP/HTTP client and
// the assertions stay about the Unix backend rather than about mTLS.

/// A minimal HTTP/1.1 server on a Unix-domain stream socket. Answers every
/// request with `name` plus the request line and forwarded Host, so a test can
/// prove WHICH socket served it and that header regeneration survived the
/// transport swap.
/// KEEP-ALIVE: one accepted connection serves an unbounded number of
/// pipelined-in-sequence requests. That is what makes the #3731 pooling
/// assertion meaningful — `accepts()` counts physical connections while
/// `hits()` counts requests, so a reusing gateway shows `accepts() < hits()`.
#[cfg(unix)]
struct UnixHttp1Backend {
    path: PathBuf,
    hits: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl UnixHttp1Backend {
    fn start(path: PathBuf, name: &'static str) -> Self {
        let listener = tokio::net::UnixListener::bind(&path).expect("bind unix http1 backend");
        let hits = Arc::new(AtomicUsize::new(0));
        let accepts = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let hits = Arc::clone(&hits_task);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    loop {
                        let n = match tokio::time::timeout(
                            Duration::from_secs(5),
                            stream.read(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => n,
                            _ => return,
                        };
                        hits.fetch_add(1, Ordering::SeqCst);
                        let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let request_line = request.lines().next().unwrap_or("").to_string();
                        let host = request
                            .lines()
                            .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                            .map(|line| line["host:".len()..].trim().to_string())
                            .unwrap_or_default();
                        let body = format!("{name}|{request_line}|{host}");
                        // A `/stream` request is answered with a CHUNKED
                        // response and no `Content-Length`, which is what forces
                        // the gateway down its STREAMING response path. That is
                        // the path #3731 must pool through an EOF-anchored lease,
                        // so `accepts()` on this fixture is the direct proof.
                        let response = if request_line.contains("/stream") {
                            // Two DATA chunks then the terminating zero chunk.
                            let mut chunked = format!(
                                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n{:x}\r\n{}\r\n",
                                body.len(),
                                body
                            );
                            chunked.push_str("7\r\n|chunk2\r\n0\r\n\r\n");
                            chunked
                        } else {
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        };
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                    }
                });
            }
        });
        Self {
            path,
            hits,
            accepts,
            task,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Physical connections accepted on this socket.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Simulate the app going away without rewriting config: stop serving and
    /// unlink the socket, so the next dial gets `ENOENT`.
    fn make_stale(&self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
impl Drop for UnixHttp1Backend {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A minimal **RFC 6455 WebSocket** server on a Unix-domain stream socket
/// (issue #3732).
///
/// Completes a real HTTP/1.1 upgrade (so the gateway's `101` + exact
/// `Sec-WebSocket-Accept` validation is genuinely exercised), then echoes
/// Text/Binary payloads back with a `echo:` prefix, answers Ping with Pong, and
/// mirrors Close. `accepts()` proves the WebSocket session opened its OWN
/// physical connection rather than borrowing a pooled HTTP/1.1 one.
#[cfg(unix)]
struct UnixWebSocketBackend {
    path: PathBuf,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl UnixWebSocketBackend {
    fn start(path: PathBuf) -> Self {
        let listener = tokio::net::UnixListener::bind(&path).expect("bind unix websocket backend");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use futures_util::{SinkExt, StreamExt};
                    use tokio_tungstenite::tungstenite::Message;

                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = ws.next().await {
                        let reply = match message {
                            Message::Text(text) => Message::Text(format!("echo:{text}").into()),
                            Message::Binary(bytes) => {
                                let mut echoed = b"echo:".to_vec();
                                echoed.extend_from_slice(&bytes);
                                Message::Binary(echoed.into())
                            }
                            Message::Ping(payload) => Message::Pong(payload),
                            Message::Close(frame) => {
                                let _ = ws.send(Message::Close(frame)).await;
                                return;
                            }
                            // Pong / raw frames need no reply.
                            _ => continue,
                        };
                        if ws.send(reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            path,
            accepts,
            task,
        }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

#[cfg(unix)]
impl Drop for UnixWebSocketBackend {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A minimal **h2c prior-knowledge HTTP/2** gRPC-shaped server on a
/// Unix-domain stream socket.
///
/// `/ferrum.Test/Echo` answers immediately with a DATA frame plus a terminal
/// `grpc-status: 0` TRAILER and echoes the received `grpc-timeout` back in a
/// header, so a test can prove trailers AND deadline propagation survived the
/// socket hop. `/ferrum.Test/Slow` sleeps well past any short deadline so the
/// gateway's deadline enforcement (and the resulting upstream cancellation) is
/// observable.
#[cfg(unix)]
struct UnixH2cBackend {
    path: PathBuf,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl UnixH2cBackend {
    fn start(path: PathBuf) -> Self {
        let listener = tokio::net::UnixListener::bind(&path).expect("bind unix h2c backend");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let service =
                        service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                            let received_timeout = req
                                .headers()
                                .get("grpc-timeout")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let te_trailers = req
                                .headers()
                                .get("te")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let slow = req.uri().path().ends_with("/Slow");
                            // Drain the request body so bidirectional streaming
                            // is genuinely exercised rather than short-circuited.
                            let _ = req.into_body().collect().await;
                            if slow {
                                tokio::time::sleep(Duration::from_millis(2_000)).await;
                            }
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert(
                                "grpc-status",
                                hyper::header::HeaderValue::from_static("0"),
                            );
                            trailers.insert(
                                "grpc-message",
                                hyper::header::HeaderValue::from_static("ok"),
                            );
                            let frames: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
                                Ok(Frame::data(Bytes::from_static(b"\x00\x00\x00\x00\x04unix"))),
                                Ok(Frame::trailers(trailers)),
                            ];
                            let body = StreamBody::new(stream::iter(frames));
                            let response = hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .header("x-received-grpc-timeout", received_timeout)
                                .header("x-received-te", te_trailers)
                                .body(body)
                                .expect("h2c grpc response builds");
                            Ok::<_, std::io::Error>(response)
                        });
                    let _ = Http2ServerBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            path,
            accepts,
            task,
        }
    }

    /// Physical connections accepted. Multiplexed RPCs must share one.
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

#[cfg(unix)]
impl Drop for UnixH2cBackend {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One `Sidecar` `ingress[]` entry for the mesh document below.
#[cfg(unix)]
struct UnixIngressEntry {
    listener_port: u16,
    protocol: AppProtocol,
    default_endpoint: String,
}

/// `{ "mesh": … }` file-source document: an `echo` workload/service in `ferrum`
/// plus a namespace-default `Sidecar` whose `ingress[]` is `entries`.
///
/// PeerAuthentication DISABLE keeps the inbound listener plaintext so the test
/// client needs no SVID; the Unix backend behavior under test is independent of
/// the inbound transport.
#[cfg(unix)]
fn unix_ingress_mesh_document(server_spiffe: &str, entries: &[UnixIngressEntry]) -> String {
    use ferrum_edge::modes::mesh::config::{MeshSidecar, MeshSidecarIngress};

    let server_id = SpiffeId::new(server_spiffe).expect("server SPIFFE id");
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let workload = Workload {
        spiffe_id: server_id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: Some("ferrum".to_string()),
        },
        service_name: "echo".to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain,
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
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "echo".to_string(),
        namespace: "ferrum".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: server_id,
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    };
    let sidecar = MeshSidecar {
        name: "echo-ingress".to_string(),
        namespace: "ferrum".to_string(),
        workload_selector: None,
        egress_inherits_defaults: true,
        egress: Vec::new(),
        // Declared even when the list is empty: that is how the withdrawal
        // phase proves the routes are gone rather than silently replaced by the
        // service-port defaults.
        ingress_declared: true,
        ingress: entries
            .iter()
            .map(|entry| MeshSidecarIngress {
                port: entry.listener_port,
                protocol: entry.protocol,
                name: None,
                bind: None,
                default_endpoint: entry.default_endpoint.clone(),
            })
            .collect(),
        outbound_traffic_policy: None,
    };
    // `local_inbound_services` is deliberately NOT set here: it is a
    // `serde(skip)` runtime back-projection the data plane resolves for itself
    // from the un-narrowed local view, so a document that tried to supply it
    // would be silently dropped rather than honored.
    let mesh = MeshConfig {
        workloads: vec![workload],
        services: vec![service],
        peer_authentications: vec![PeerAuthentication {
            name: "mesh-disable".to_string(),
            namespace: "ferrum".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Disable,
            port_overrides: HashMap::new(),
        }],
        sidecars: vec![sidecar],
        ..MeshConfig::default()
    };
    serde_json::to_string(&serde_json::json!({ "mesh": mesh })).expect("mesh document serializes")
}

/// Plain HTTP/1.1 request against the plaintext sidecar inbound listener.
/// Returns `(status, raw response)`.
#[cfg(unix)]
async fn plaintext_inbound_http1(
    port: u16,
    authority: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n");
    // Only default to `Connection: close` when the caller did not set its own —
    // the WebSocket case needs `Connection: Upgrade` for the flavor detector to
    // classify the request as an upgrade at all.
    let is_upgrade = extra_headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("upgrade") && !value.is_empty());
    if !extra_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        request.push_str("Connection: close\r\n");
    }
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    // Ordinary responses must be read through to TCP EOF. A quiet-after-headers
    // early exit drops the client socket while the gateway may still be polling
    // the streaming `ProxyBody` for `Ready(None)`, which #3731 treats as a
    // client disconnect and retires the exclusive Unix HTTP/1.1 pool lease —
    // producing one physical dial per request (hosted data-plane evidence).
    // Upgrade refusals may leave the connection open without EOF, so those
    // alone may finish on a short quiet period once headers have arrived.
    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => raw.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) if is_upgrade && raw.windows(4).any(|w| w == b"\r\n\r\n") => break,
            Err(_) => continue,
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("no status line in response: {text:?}"))?;
    Ok((status, text))
}

/// A gRPC-shaped h2c prior-knowledge request against the plaintext sidecar
/// inbound listener. Returns `(status, response headers, trailers)`.
#[cfg(unix)]
async fn plaintext_inbound_grpc(
    port: u16,
    authority: &str,
    path: &str,
    grpc_timeout: Option<&str>,
) -> Result<(u16, hyper::HeaderMap, hyper::HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(timeout) = grpc_timeout {
        builder = builder.header("grpc-timeout", timeout);
    }
    let request = builder.body(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x00")))?;
    let response =
        tokio::time::timeout(Duration::from_secs(15), sender.send_request(request)).await??;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let collected =
        tokio::time::timeout(Duration::from_secs(15), response.into_body().collect()).await??;
    let trailers = collected.trailers().cloned().unwrap_or_default();
    driver.abort();
    Ok((status, headers, trailers))
}

/// Read a gRPC status code from either the response headers (Trailers-Only) or
/// the terminal trailers.
#[cfg(unix)]
fn grpc_status_code(headers: &hyper::HeaderMap, trailers: &hyper::HeaderMap) -> Option<i32> {
    trailers
        .get("grpc-status")
        .or_else(|| headers.get("grpc-status"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
}

/// Keystone for issue #3261: a `Sidecar` ingress `defaultEndpoint: unix://…`
/// translated through the supported source path serves LIVE traffic over the
/// socket on HTTP/1.1 and on h2c (including native gRPC trailers and deadline
/// enforcement), refuses the cases Ferrum does not support, and stays
/// fail-closed for a socket outside the configured containment roots.
///
/// Also covers the lifecycle the acceptance criteria call out: update (re-point
/// to a different allowed socket on SIGHUP), withdrawal (the entry disappears),
/// and a stale socket (the app went away without a config change).
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_mesh_sidecar_ingress_unix_socket_serves_live_traffic() {
    ensure_gateway_built().expect("gateway build");
    let server_spiffe = "spiffe://cluster.local/ns/ferrum/sa/echo";

    let temp = TempDir::new().expect("temp dir");
    // The CONTAINMENT root. Only sockets strictly below it are admissible.
    let socket_root = temp.path().join("sockets");
    std::fs::create_dir_all(&socket_root).expect("create socket root");
    // Deliberately OUTSIDE the root, standing in for `/var/run/docker.sock`.
    let outside_root = temp.path().join("privileged");
    std::fs::create_dir_all(&outside_root).expect("create outside root");

    let http1_socket = socket_root.join("http1.sock");
    let h2c_socket = socket_root.join("h2c.sock");
    let ws_socket = socket_root.join("ws.sock");
    let outside_socket = outside_root.join("privileged.sock");

    let http1_backend = UnixHttp1Backend::start(http1_socket.clone(), "unix-http1-a");
    let h2c_backend = UnixH2cBackend::start(h2c_socket.clone());
    let ws_backend = UnixWebSocketBackend::start(ws_socket.clone());
    // A REAL, reachable socket that config points at but containment forbids:
    // the refusal must be the allowlist, not an absent socket.
    let outside_backend = UnixHttp1Backend::start(outside_socket.clone(), "must-never-be-reached");

    let unix_url = |path: &std::path::Path| format!("unix://{}", path.display());
    let phase_a = vec![
        UnixIngressEntry {
            listener_port: 8443,
            protocol: AppProtocol::Http,
            default_endpoint: unix_url(&http1_socket),
        },
        UnixIngressEntry {
            listener_port: 9443,
            protocol: AppProtocol::Grpc,
            default_endpoint: unix_url(&h2c_socket),
        },
        UnixIngressEntry {
            listener_port: 7443,
            protocol: AppProtocol::Http,
            default_endpoint: unix_url(&outside_socket),
        },
        // `http`-declared, so WebSocket upgrades ride the H1 Unix carrier
        // (issue #3732).
        UnixIngressEntry {
            listener_port: 6443,
            protocol: AppProtocol::Http,
            default_endpoint: unix_url(&ws_socket),
        },
    ];

    let mesh_doc_path = temp.path().join("mesh.json");
    std::fs::write(
        &mesh_doc_path,
        unix_ingress_mesh_document(server_spiffe, &phase_a),
    )
    .expect("write mesh document");

    let ports = reserve_mesh_ports().await;
    let inbound_port = ports.inbound;
    let mut child = spawn_mesh_gateway(
        &temp,
        MeshGatewaySpawnOptions {
            cp_addr: "127.0.0.1:1".parse().expect("dummy addr"),
            ports,
            node_id: "functional-mesh-unix-ingress",
            config_protocol: "file",
            topology: "sidecar",
            waypoint_name: None,
            env_overrides: vec![
                (
                    "FERRUM_MESH_FILE_CONFIG_PATH",
                    mesh_doc_path
                        .to_str()
                        .expect("mesh document path is UTF-8")
                        .to_string(),
                ),
                ("FERRUM_MESH_WORKLOAD_SPIFFE_ID", server_spiffe.to_string()),
                // `ingress[]` materialization is gated on enforcement, NOT dry-run.
                ("FERRUM_MESH_SIDECAR_ENFORCED", "true".to_string()),
                // THE containment allowlist. Without it every unix listener is
                // refused, which is asserted separately by the unit tests.
                (
                    "FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS",
                    socket_root
                        .to_str()
                        .expect("socket root is UTF-8")
                        .to_string(),
                ),
                // A Unix target's synthetic loopback `host:port` is never a
                // network dial target. Public-only IP egress must therefore
                // leave this socket path to its own containment, inode, and
                // peer-credential admission gates instead of rejecting the
                // carrier address before Unix dispatch.
                ("FERRUM_BACKEND_ALLOW_IPS", "public".to_string()),
                ("FERRUM_POOL_WARMUP_ENABLED", "false".to_string()),
            ],
        },
    );

    if !wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!("mesh inbound listener never bound\n{output}");
    }

    // ── (a) HTTP/1.1 over the socket, through real Sidecar translation ──
    let authority_8443 = "echo.ferrum.svc.cluster.local:8443";
    let (status, body) = match plaintext_inbound_http1(inbound_port, authority_8443, "/", &[]).await
    {
        Ok(result) => result,
        Err(e) => {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!("HTTP/1.1 request to the unix ingress listener failed: {e}\n{output}");
        }
    };
    if status != 200 || !body.contains("unix-http1-a") {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "a translated unix:// ingress listener must serve live HTTP/1.1 traffic from its \
             socket; status {status} body {body:?}\n{output}"
        );
    }
    assert!(
        http1_backend.hits() >= 1,
        "the HTTP/1.1 unix socket must have served the request"
    );

    // ── (b) native gRPC over h2c: trailers and `te: trailers` survive ──
    let authority_9443 = "echo.ferrum.svc.cluster.local:9443";
    let (grpc_status, grpc_headers, grpc_trailers) = match plaintext_inbound_grpc(
        inbound_port,
        authority_9443,
        "/ferrum.Test/Echo",
        Some("30S"),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!("gRPC request to the h2c unix ingress listener failed: {e}\n{output}");
        }
    };
    if grpc_status != 200 || grpc_status_code(&grpc_headers, &grpc_trailers) != Some(0) {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "gRPC over an h2c unix ingress listener must return OK with terminal trailers; \
             status {grpc_status} headers {grpc_headers:?} trailers {grpc_trailers:?}\n{output}"
        );
    }
    assert!(
        grpc_trailers.contains_key("grpc-status"),
        "the terminal grpc-status must arrive as a TRAILER, not a header: {grpc_trailers:?}"
    );
    assert_eq!(
        grpc_headers
            .get("x-received-te")
            .and_then(|v| v.to_str().ok()),
        Some("trailers"),
        "the gateway must regenerate `te: trailers` on the h2c socket hop"
    );
    let forwarded_deadline = grpc_headers
        .get("x-received-grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !forwarded_deadline.is_empty(),
        "the client's gRPC deadline must be propagated onto the socket hop"
    );

    // ── (c) deadline enforcement / upstream cancellation ──
    // 5 MILLISECONDS against a backend that sleeps 2s: the gateway must cancel
    // and answer DEADLINE_EXCEEDED rather than hang for the backend.
    let (slow_status, slow_headers, slow_trailers) = match plaintext_inbound_grpc(
        inbound_port,
        authority_9443,
        "/ferrum.Test/Slow",
        Some("5m"),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!("deadline-bounded gRPC request failed to complete: {e}\n{output}");
        }
    };
    let slow_code = grpc_status_code(&slow_headers, &slow_trailers);
    if slow_code != Some(4) {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "an exceeded gRPC deadline on the h2c unix hop must be DEADLINE_EXCEEDED (4); got \
             status {slow_status} code {slow_code:?} headers {slow_headers:?} trailers \
             {slow_trailers:?}\n{output}"
        );
    }

    // ── (d) gRPC against an `http`-declared (HTTP/1.1) socket is REFUSED ──
    // HTTP/1.1 cannot carry gRPC trailers, so this must be a clean gRPC
    // UNAVAILABLE, never a downgraded dial.
    let (h1_grpc_status, h1_grpc_headers, h1_grpc_trailers) =
        match plaintext_inbound_grpc(inbound_port, authority_8443, "/ferrum.Test/Echo", None).await
        {
            Ok(result) => result,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("gRPC request to the http-declared unix listener failed: {e}\n{output}");
            }
        };
    let h1_grpc_code = grpc_status_code(&h1_grpc_headers, &h1_grpc_trailers);
    if h1_grpc_status != 200 || h1_grpc_code != Some(14) {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "gRPC to an http-declared unix ingress listener must be refused UNAVAILABLE (14); \
             got status {h1_grpc_status} code {h1_grpc_code:?}\n{output}"
        );
    }

    // ── (e1) WebSocket over an `http`-declared unix socket WORKS (issue #3732) ──
    // A live RFC 6455 handshake through the admitted socket, then bidirectional
    // text, binary, ping/pong, and close — the exact payloads the backend saw.
    {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let ws_accepts_before = ws_backend.accepts();
        let ws_url = "ws://echo.ferrum.svc.cluster.local:6443/ws";
        let mut ws_request =
            match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                ws_url,
            ) {
                Ok(request) => request,
                Err(e) => {
                    let output = captured_output(&temp);
                    kill_child(&mut child);
                    panic!("building the unix-backed WebSocket request failed: {e}\n{output}");
                }
            };
        // The gateway routes on Host/`:authority`; the TCP dial is the local
        // inbound listener.
        ws_request.headers_mut().insert(
            "host",
            "echo.ferrum.svc.cluster.local:6443".parse().expect("host"),
        );
        let tcp = match tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await {
            Ok(tcp) => tcp,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("connecting to the mesh inbound listener failed: {e}\n{output}");
            }
        };
        let (mut ws, response) = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::client_async(ws_request, tcp),
        )
        .await
        {
            Ok(Ok(established)) => established,
            Ok(Err(e)) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!(
                    "a WebSocket upgrade to an http-declared unix ingress socket must \
                         complete; handshake failed: {e}\n{output}"
                );
            }
            Err(_) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("the unix-backed WebSocket handshake timed out\n{output}");
            }
        };
        assert_eq!(
            response.status().as_u16(),
            101,
            "a unix-backed WebSocket upgrade must be a real 101 Switching Protocols"
        );

        let exchange = async {
            ws.send(Message::Text("hello-unix".into()))
                .await
                .map_err(|e| format!("send text: {e}"))?;
            match ws.next().await {
                Some(Ok(Message::Text(text))) if text == "echo:hello-unix" => {}
                other => return Err(format!("unexpected text echo: {other:?}")),
            }
            ws.send(Message::Binary(vec![1u8, 2, 3].into()))
                .await
                .map_err(|e| format!("send binary: {e}"))?;
            match ws.next().await {
                Some(Ok(Message::Binary(bytes))) if bytes.as_ref() == b"echo:\x01\x02\x03" => {}
                other => return Err(format!("unexpected binary echo: {other:?}")),
            }
            ws.send(Message::Ping(vec![9u8].into()))
                .await
                .map_err(|e| format!("send ping: {e}"))?;
            match ws.next().await {
                Some(Ok(Message::Pong(payload))) if payload.as_ref() == b"\x09" => {}
                other => return Err(format!("unexpected pong: {other:?}")),
            }
            ws.send(Message::Close(None))
                .await
                .map_err(|e| format!("send close: {e}"))?;
            Ok::<(), String>(())
        };
        let ws_failure: Option<String> =
            match tokio::time::timeout(Duration::from_secs(10), exchange).await {
                Ok(Ok(())) => None,
                Ok(Err(reason)) => Some(reason),
                Err(_) => Some("bidirectional frame exchange timed out".to_string()),
            };
        if let Some(reason) = ws_failure {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!("unix-backed WebSocket relay failed: {reason}\n{output}");
        }
        // The session leases its OWN dedicated connection; it is never taken
        // from (or returned to) the HTTP/1.1 idle pool.
        if ws_backend.accepts() != ws_accepts_before + 1 {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!(
                "a WebSocket session must open exactly one dedicated unix connection; accepts \
                 went {ws_accepts_before} -> {}\n{output}",
                ws_backend.accepts()
            );
        }
    }

    // ── (e2) WebSocket over an `http2`/`grpc`-declared socket stays REFUSED ──
    // RFC 8441 Extended CONNECT over the h2c unix carrier is unimplemented, and
    // it must NOT be silently downgraded to an HTTP/1.1 upgrade the h2c-only app
    // cannot answer.
    let (ws_status, ws_body) = match plaintext_inbound_http1(
        inbound_port,
        authority_9443,
        "/ws",
        &[
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!("WebSocket upgrade attempt failed to complete: {e}\n{output}");
        }
    };
    if ws_status != 502 || !ws_body.contains("does not support WebSocket") {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "a WebSocket upgrade to an h2c unix-socket backend must be refused 502 with the \
             documented message; got status {ws_status} body {ws_body:?}\n{output}"
        );
    }

    // ── (e3) h2c stream multiplexing over ONE admitted connection (#3731) ──
    // Concurrent RPCs must share a single admitted physical connection instead
    // of each paying its own connect + h2c handshake.
    {
        let h2c_accepts_before = h2c_backend.accepts();
        let mut rpcs = Vec::new();
        for _ in 0..6 {
            rpcs.push(plaintext_inbound_grpc(
                inbound_port,
                authority_9443,
                "/ferrum.Test/Echo",
                None,
            ));
        }
        let results = futures_util::future::join_all(rpcs).await;
        for (index, result) in results.into_iter().enumerate() {
            match result {
                Ok((status, headers, trailers)) => {
                    if status != 200 || grpc_status_code(&headers, &trailers) != Some(0) {
                        let output = captured_output(&temp);
                        kill_child(&mut child);
                        panic!(
                            "multiplexed unix h2c RPC {index} must succeed with terminal \
                             trailers; status {status} headers {headers:?} trailers \
                             {trailers:?}\n{output}"
                        );
                    }
                }
                Err(e) => {
                    let output = captured_output(&temp);
                    kill_child(&mut child);
                    panic!("multiplexed unix h2c RPC {index} failed: {e}\n{output}");
                }
            }
        }
        let new_h2c_accepts = h2c_backend.accepts() - h2c_accepts_before;
        if new_h2c_accepts >= 6 {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!(
                "6 concurrent RPCs over an admitted unix h2c socket must share a pooled \
                 multiplexed connection; they opened {new_h2c_accepts} physical \
                 connections\n{output}"
            );
        }
    }

    // ── (e4) HTTP/1.1 keep-alive reuse over the admitted socket (#3731) ──
    // The point of the issue: many sequential live requests must be served by
    // SUBSTANTIALLY fewer physical backend connections than requests. Both
    // response shapes are exercised, because they take different pooling paths:
    //
    //   * `/` answers with a small `Content-Length` — inside the gateway's
    //     eager-buffer cutoff. Mesh ingress streams by default, so the Unix
    //     dispatch buffers such a response in-dispatch and checks the lease in
    //     before returning to the client-facing writer (a frontend
    //     `Connection: close` must not retire a still-reusable carrier). A
    //     declared length ABOVE that cutoff keeps streaming, exactly as on every
    //     other transport;
    //   * `/stream` answers CHUNKED with no `Content-Length`, so the gateway
    //     streams and the lease rides the response body, returning only on the
    //     body's clean end-of-stream.
    //
    // The bound is `<= 2` rather than `== 1` for one honest reason: the backend
    // may reap an idle keep-alive socket between two requests, which the pool
    // recovers from with exactly one extra dial. It is nowhere near `== 12`,
    // which is what an unpooled or check-in-less path would produce.
    for (label, path) in [("buffered", "/"), ("streaming", "/stream")] {
        let accepts_before = http1_backend.accepts();
        let hits_before = http1_backend.hits();
        for index in 0..12 {
            let (status, body) =
                match plaintext_inbound_http1(inbound_port, authority_8443, path, &[]).await {
                    Ok(result) => result,
                    Err(e) => {
                        let output = captured_output(&temp);
                        kill_child(&mut child);
                        panic!("pooled unix {label} request {index} failed: {e}\n{output}");
                    }
                };
            if status != 200 || !body.contains("unix-http1-a") {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!(
                    "pooled unix {label} request {index} must still be served correctly; got \
                     status {status} body {body:?}\n{output}"
                );
            }
            if path == "/stream" && !body.contains("|chunk2") {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!(
                    "the streaming unix response must be relayed to its last chunk; got \
                     {body:?}\n{output}"
                );
            }
        }
        let new_accepts = http1_backend.accepts() - accepts_before;
        let new_hits = http1_backend.hits() - hits_before;
        if new_hits != 12 || new_accepts > 2 {
            let output = captured_output(&temp);
            kill_child(&mut child);
            panic!(
                "12 sequential {label} unix requests must reuse one admitted HTTP/1.1 \
                 connection; got {new_hits} requests over {new_accepts} physical \
                 connections\n{output}"
            );
        }
    }

    // ── (f) containment: a real socket OUTSIDE the allowed roots never dials ──
    let (denied_status, denied_body) =
        match plaintext_inbound_http1(inbound_port, "echo.ferrum.svc.cluster.local:7443", "/", &[])
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("request to the out-of-root unix listener failed: {e}\n{output}");
            }
        };
    if denied_status == 200 || denied_body.contains("must-never-be-reached") {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "a unix socket outside FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS must never be dialed; \
             got status {denied_status} body {denied_body:?}\n{output}"
        );
    }
    assert_eq!(
        outside_backend.hits(),
        0,
        "the out-of-root socket must have received NO connection at all"
    );

    // ── (g) stale socket: the app vanished without a config change ──
    http1_backend.make_stale();
    let (stale_status, stale_body) =
        match plaintext_inbound_http1(inbound_port, authority_8443, "/", &[]).await {
            Ok(result) => result,
            Err(e) => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!("request to the stale unix socket failed: {e}\n{output}");
            }
        };
    if stale_status == 200 {
        let output = captured_output(&temp);
        kill_child(&mut child);
        panic!(
            "a removed unix socket must fail the request, not serve it; body \
             {stale_body:?}\n{output}"
        );
    }

    // ── (h) UPDATE: re-point the listener at a DIFFERENT allowed socket ──
    let updated_socket = socket_root.join("http1-b.sock");
    let updated_backend = UnixHttp1Backend::start(updated_socket.clone(), "unix-http1-b");
    std::fs::write(
        &mesh_doc_path,
        unix_ingress_mesh_document(
            server_spiffe,
            &[UnixIngressEntry {
                listener_port: 8443,
                protocol: AppProtocol::Http,
                default_endpoint: unix_url(&updated_socket),
            }],
        ),
    )
    .expect("rewrite mesh document for the update phase");
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .expect("send SIGHUP")
            .success(),
        "SIGHUP delivery failed for pid {pid}"
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match plaintext_inbound_http1(inbound_port, authority_8443, "/", &[]).await {
            Ok((200, body)) if body.contains("unix-http1-b") => break,
            _ if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            other => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!(
                    "the reloaded listener never dialed the new socket; last result \
                     {other:?}\n{output}"
                );
            }
        }
    }
    assert!(
        updated_backend.hits() >= 1,
        "the re-pointed socket must have served the request after reload"
    );

    // ── (i) WITHDRAWAL: the ingress entry disappears entirely ──
    // `ingress_declared` stays true with an EMPTY list, so Istio semantics say
    // the service-port defaults must NOT come back either.
    std::fs::write(
        &mesh_doc_path,
        unix_ingress_mesh_document(server_spiffe, &[]),
    )
    .expect("rewrite mesh document for the withdrawal phase");
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .expect("send SIGHUP")
            .success(),
        "SIGHUP delivery failed for pid {pid}"
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match plaintext_inbound_http1(inbound_port, authority_8443, "/", &[]).await {
            Ok((status, body)) if status != 200 && !body.contains("unix-http1-b") => break,
            _ if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            other => {
                let output = captured_output(&temp);
                kill_child(&mut child);
                panic!(
                    "a withdrawn unix ingress listener must stop routing; last result \
                     {other:?}\n{output}"
                );
            }
        }
    }

    // The polling request that observes the reload may be preceded by requests
    // served from the old atomic snapshot. Measure only after withdrawal is
    // visible, then prove a fresh request cannot reach the removed backend.
    let hits_after_withdrawal = updated_backend.hits();
    let (withdrawn_status, withdrawn_body) =
        plaintext_inbound_http1(inbound_port, authority_8443, "/", &[])
            .await
            .expect("post-withdrawal request must complete");
    assert!(
        withdrawn_status != 200 && !withdrawn_body.contains("unix-http1-b"),
        "a fresh request after withdrawal must remain unroutable; status {withdrawn_status} body \
         {withdrawn_body:?}"
    );
    assert_eq!(
        updated_backend.hits(),
        hits_after_withdrawal,
        "no request may reach the socket after its listener was withdrawn"
    );

    kill_child(&mut child);
}

// ── Live H3 → authenticated mesh-transport gRPC datapath (issue #3284) ───────
//
// The LIVE keystone for H3-to-gRPC mesh dispatch. Every test below drives a real
// `ferrum-edge` subprocess with a QUIC/HTTP-3 frontend, a real SPIFFE SVID
// loaded from files, real file-mode routing + upstream selection, and real
// authenticated mesh listeners in this test process. Nothing here calls
// `proxy_grpc_request_core`, `GrpcDispatchTransport`, or any other in-process
// helper, and nothing asserts on source text: the only input is a native gRPC
// RPC over QUIC, and the only outputs are what the mesh peer observed on the
// wire and what the H3 client received back.
//
// The lower-level transport coverage lives in
// `tests/integration/mesh_grpc_transport_tests.rs`; it is deliberately NOT a
// substitute for these, because it does not exercise the H3 frontend where the
// traffic behavior actually changes.

/// The gateway's own workload identity in these tests.
const H3_MESH_GATEWAY_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/h3-gateway";
/// The destination workload identity a same-cluster target PINS.
const H3_MESH_PEER_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/h3-peer";
/// A SECOND destination identity, for retry rotation and reload re-targeting.
const H3_MESH_PEER_B_SPIFFE: &str = "spiffe://cluster.local/ns/ferrum/sa/h3-peer-b";
/// The service FQDN a Sidecar peer's materialized inbound route matches.
const H3_MESH_SERVICE_AUTHORITY: &str = "h3-peer.ferrum.svc.cluster.local";
/// The destination service FQDN a CROSS-CLUSTER dial must present as SNI.
const H3_MESH_EASTWEST_SNI: &str = "h3-remote.ferrum.svc.cluster.local";
/// The gRPC method every test calls, under the proxy's `/mesh` listen path.
const H3_MESH_RPC_PATH: &str = "/mesh/h3.mesh.Echo/Call";
/// The path the peer must observe after `strip_listen_path`.
const H3_MESH_BACKEND_PATH: &str = "/h3.mesh.Echo/Call";

/// A declared APPLICATION port for a Sidecar target, reserved and then RELEASED
/// so nothing in this process can bind it.
///
/// The mesh-mTLS transport dials `mesh.mtls_port`, never this port, so an
/// authority assertion that names it proves the authority/dial-port split rather
/// than a coincidence — and once the mesh transport is WITHDRAWN, a dial to it
/// must find nothing listening. A fixed constant could not promise either, since
/// an unrelated process on the runner might hold it.
async fn h3_mesh_declared_app_port() -> u16 {
    reserve_unique_mesh_port().await
}

/// What a mesh peer observed for ONE accepted gRPC stream.
#[derive(Clone, Debug)]
struct H3MeshObservedRpc {
    scheme: String,
    authority: String,
    path: String,
    te: Option<String>,
    content_type: Option<String>,
    grpc_timeout: Option<String>,
    body: Vec<u8>,
    /// The DER of every client certificate the peer VERIFIED. Empty for an app
    /// behind an HBONE relay, which sees plaintext h2c inside the tunnel.
    client_cert_der: Vec<Vec<u8>>,
    /// The request stream ended with an HTTP/2 error rather than END_STREAM —
    /// the shape a client cancellation must propagate as.
    request_reset: bool,
}

impl H3MeshObservedRpc {
    /// Whether the client certificate chain this peer verified carries `id` as a
    /// SPIFFE URI SAN. Matched as an exact ASCII byte run in the raw DER (a URI
    /// SAN stores its value verbatim), so it is proof the gateway presented THAT
    /// workload SVID rather than merely completing some TLS handshake.
    fn presented_client_spiffe(&self, id: &str) -> bool {
        self.client_cert_der
            .iter()
            .any(|der| der.windows(id.len()).any(|w| w == id.as_bytes()))
    }
}

/// How a mesh gRPC peer answers each RPC it serves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum H3MeshPeerBehavior {
    /// Drain the request body, then answer HEADERS + DATA (echoing the request
    /// bytes) + real HTTP/2 TRAILERS.
    EchoAfterUpload,
    /// Answer HEADERS + DATA as soon as the FIRST request DATA frame lands — the
    /// bidirectional shape that deadlocks if the gateway buffers the H3 upload —
    /// then keep reading until the client half-closes or resets.
    RespondOnFirstRequestFrame,
    /// Observe the request and never answer, so the client `grpc-timeout`
    /// deadline is what ends the call.
    NeverRespond,
}

/// The response DATA a `RespondOnFirstRequestFrame` peer sends before the client
/// has half-closed.
const H3_MESH_EARLY_RESPONSE: &[u8] = b"early";

/// A live mesh listener under test, plus everything it observed. The accept loop
/// holds its own `Arc` clones of the observation slots, so a test can keep
/// reading them while the listener is still serving.
struct H3MeshPeer {
    /// The port the gateway is told to DIAL (`mesh.mtls_port` / `mesh.hbone_port`).
    port: u16,
    rpcs: Arc<Mutex<Vec<Arc<Mutex<H3MeshObservedRpc>>>>>,
    /// Every ClientHello SNI seen, in order. `None` is an absent SNI extension
    /// (what an IP-literal dial with no override produces).
    snis: Arc<Mutex<Vec<Option<String>>>>,
    /// TCP accepts, so a fail-closed refusal can be proven to have dialed
    /// NOTHING rather than merely to have failed late.
    accepts: Arc<AtomicUsize>,
    /// CONNECT `:authority` values an HBONE relay admitted.
    connects: Arc<Mutex<Vec<String>>>,
}

impl H3MeshPeer {
    fn observed_rpcs(&self) -> Vec<H3MeshObservedRpc> {
        self.rpcs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|rpc| {
                rpc.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            })
            .collect()
    }

    fn observed_snis(&self) -> Vec<Option<String>> {
        self.snis
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn observed_connects(&self) -> Vec<String> {
        self.connects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn accept_count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// The first gRPC stream this peer observed on the tested method, waiting up
    /// to `timeout`. Filtering on the method path discards any unrelated
    /// startup/capability connection so a datapath assertion cannot be satisfied
    /// by preflight.
    async fn wait_for_rpc(&self, timeout: Duration) -> H3MeshObservedRpc {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(rpc) = self
                .observed_rpcs()
                .into_iter()
                .find(|rpc| rpc.path == H3_MESH_BACKEND_PATH)
            {
                return rpc;
            }
            assert!(
                Instant::now() < deadline,
                "mesh peer on :{} never observed a gRPC stream for {H3_MESH_BACKEND_PATH}",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Wait until the observed RPC on the tested method reports a reset request
    /// stream, which is how a client cancellation reaches the peer.
    async fn wait_for_request_reset(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .observed_rpcs()
                .iter()
                .any(|rpc| rpc.path == H3_MESH_BACKEND_PATH && rpc.request_reset)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "mesh peer on :{} never observed the cancelled request stream reset",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// A rustls server-cert resolver presenting ONE certified SVID and recording the
/// ClientHello SNI of every handshake.
///
/// The SNI is the only channel that can prove a CROSS-CLUSTER dial applied
/// `mesh.eastwest_sni` rather than naming the east-west gateway it actually
/// connected to, so the mesh fixtures resolve their cert through this instead of
/// `with_single_cert`.
struct H3MeshSniResolver {
    certified: Arc<rustls::sign::CertifiedKey>,
    snis: Arc<Mutex<Vec<Option<String>>>>,
}

impl std::fmt::Debug for H3MeshSniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3MeshSniResolver").finish()
    }
}

impl rustls::server::ResolvesServerCert for H3MeshSniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.snis
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(client_hello.server_name().map(str::to_owned));
        Some(Arc::clone(&self.certified))
    }
}

/// An h2-ALPN mTLS server config presenting `svid` and requiring a client
/// certificate chained to the shared mesh CA — the peer half of the SVID-mTLS
/// hop, with SNI recording attached.
fn h3_mesh_server_config(
    svid: &GeneratedGatewaySvid,
    snis: Arc<Mutex<Vec<Option<String>>>>,
) -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_pem = std::fs::read(&svid.trust_bundle_path).expect("read mesh peer trust bundle");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()).filter_map(|cert| cert.ok()) {
        roots.add(cert).expect("add mesh peer client root");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("build mesh peer client verifier");
    let cert_pem = std::fs::read(&svid.cert_path).expect("read mesh peer SVID");
    let key_pem = std::fs::read(&svid.key_path).expect("read mesh peer key");
    let chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|cert| cert.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse mesh peer key")
        .expect("mesh peer key present");
    let signing_key =
        ferrum_edge::fips::any_supported_signing_key(&key).expect("mesh peer signing key");
    let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, signing_key));
    let resolver = Arc::new(H3MeshSniResolver { certified, snis });
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// One header value as a `String`, so the observed record can be built before the
/// request body is taken.
fn h3_mesh_header(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// Answer response HEADERS + one DATA frame, leaving the stream open for the
/// terminal TRAILERS.
fn h3_mesh_send_response_head(
    respond: &mut h2::server::SendResponse<Bytes>,
    body: &[u8],
) -> Option<h2::SendStream<Bytes>> {
    let response = hyper::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .expect("build mesh peer gRPC response");
    let mut send = respond.send_response(response, false).ok()?;
    send.send_data(Bytes::copy_from_slice(body), false).ok()?;
    Some(send)
}

/// Serve gRPC RPCs over an already-established byte stream, recording what each
/// one carried.
///
/// Generic over the transport so the Sidecar peer drives it over a terminated
/// SVID-mTLS socket and the Ambient app drives it over the plaintext h2c socket
/// behind the HBONE relay — the same server code, so a difference in the
/// assertions can only come from the transport under test.
///
/// Per-stream handling is SPAWNED: `h2::server::Connection::accept` is the
/// connection's only I/O driver, so awaiting a request body inline would stop
/// driving the connection and the body would never arrive.
async fn h3_mesh_serve_grpc<T>(
    io: T,
    behavior: H3MeshPeerBehavior,
    client_cert_der: Vec<Vec<u8>>,
    rpcs: Arc<Mutex<Vec<Arc<Mutex<H3MeshObservedRpc>>>>>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(accepted) = connection.accept().await {
        let Ok((request, respond)) = accepted else {
            return;
        };
        let rpcs = Arc::clone(&rpcs);
        let client_cert_der = client_cert_der.clone();
        tokio::spawn(async move {
            h3_mesh_serve_one_rpc(request, respond, behavior, client_cert_der, rpcs).await;
        });
    }
}

/// Observe and answer exactly ONE accepted gRPC stream per
/// [`H3MeshPeerBehavior`].
async fn h3_mesh_serve_one_rpc(
    request: hyper::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    behavior: H3MeshPeerBehavior,
    client_cert_der: Vec<Vec<u8>>,
    rpcs: Arc<Mutex<Vec<Arc<Mutex<H3MeshObservedRpc>>>>>,
) {
    let headers = request.headers().clone();
    let uri = request.uri().clone();
    let mut recv = request.into_body();
    let record = Arc::new(Mutex::new(H3MeshObservedRpc {
        scheme: uri.scheme_str().unwrap_or_default().to_string(),
        authority: uri
            .authority()
            .map(|authority| authority.to_string())
            .unwrap_or_default(),
        path: uri.path().to_string(),
        te: h3_mesh_header(&headers, "te"),
        content_type: h3_mesh_header(&headers, "content-type"),
        grpc_timeout: h3_mesh_header(&headers, "grpc-timeout"),
        body: Vec::new(),
        client_cert_der,
        request_reset: false,
    }));
    rpcs.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(Arc::clone(&record));

    if behavior == H3MeshPeerBehavior::NeverRespond {
        // Observe, then hold the stream open WITHOUT answering and without
        // dropping `respond` — dropping it would RST_STREAM, which the gateway
        // would classify as a connection failure instead of letting the client
        // deadline fire.
        h3_mesh_drain_request(&mut recv, &record).await;
        std::future::pending::<()>().await;
        return;
    }

    let mut send = if behavior == H3MeshPeerBehavior::RespondOnFirstRequestFrame {
        // Wait for exactly one request DATA frame — proof the gateway committed
        // the H3 upload incrementally instead of buffering it — then answer while
        // the client is still sending.
        let Some(Ok(first)) = recv.data().await else {
            return;
        };
        let _ = recv.flow_control().release_capacity(first.len());
        record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .body
            .extend_from_slice(&first);
        let Some(send) = h3_mesh_send_response_head(&mut respond, H3_MESH_EARLY_RESPONSE) else {
            return;
        };
        h3_mesh_drain_request(&mut recv, &record).await;
        send
    } else {
        h3_mesh_drain_request(&mut recv, &record).await;
        let echo = record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .body
            .clone();
        let Some(send) = h3_mesh_send_response_head(&mut respond, &echo) else {
            return;
        };
        send
    };

    let request_reset = record
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .request_reset;
    if request_reset {
        // A reset request stream has no terminal status to deliver.
        return;
    }
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("0"));
    trailers.insert(
        "grpc-message",
        hyper::header::HeaderValue::from_static("ok"),
    );
    trailers.insert(
        "x-mesh-peer-trailer",
        hyper::header::HeaderValue::from_static("real-http2-trailer"),
    );
    let _ = send.send_trailers(trailers);
}

/// Read the request body to END_STREAM, accumulating it, and mark the record when
/// the stream ends with an HTTP/2 error instead (a propagated cancellation).
async fn h3_mesh_drain_request(recv: &mut h2::RecvStream, record: &Arc<Mutex<H3MeshObservedRpc>>) {
    while let Some(chunk) = recv.data().await {
        match chunk {
            Ok(chunk) => {
                let _ = recv.flow_control().release_capacity(chunk.len());
                record
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .body
                    .extend_from_slice(&chunk);
            }
            Err(_) => {
                record
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .request_reset = true;
                return;
            }
        }
    }
}

/// A real SVID-mTLS HTTP/2 gRPC listener: the Sidecar peer's inbound
/// (`:15006`-style) listener.
async fn start_h3_mesh_mtls_peer(
    svid: &GeneratedGatewaySvid,
    behavior: H3MeshPeerBehavior,
) -> H3MeshPeer {
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind H3 mesh mTLS peer");
    let port = listener.local_addr().expect("mesh mTLS peer addr").port();
    let snis: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let rpcs: Arc<Mutex<Vec<Arc<Mutex<H3MeshObservedRpc>>>>> = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let config = h3_mesh_server_config(svid, Arc::clone(&snis));
    let peer = H3MeshPeer {
        port,
        rpcs: Arc::clone(&rpcs),
        snis,
        accepts: Arc::clone(&accepts),
        connects: Arc::new(Mutex::new(Vec::new())),
    };

    tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let rpcs = Arc::clone(&rpcs);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let client_cert_der = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .map(|chain| chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
                    .unwrap_or_default();
                h3_mesh_serve_grpc(tls, behavior, client_cert_der, rpcs).await;
            });
        }
    });

    peer
}

/// A plaintext h2c gRPC app — the destination workload behind an Ambient HBONE
/// relay. The relay byte-copies the tunnel into this socket, so the gateway's
/// NESTED HTTP/2 client has to negotiate and frame end to end.
async fn start_h3_mesh_h2c_app(behavior: H3MeshPeerBehavior) -> H3MeshPeer {
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind H3 mesh h2c app");
    let port = listener.local_addr().expect("h2c app addr").port();
    let rpcs: Arc<Mutex<Vec<Arc<Mutex<H3MeshObservedRpc>>>>> = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let peer = H3MeshPeer {
        port,
        rpcs: Arc::clone(&rpcs),
        snis: Arc::new(Mutex::new(Vec::new())),
        accepts: Arc::clone(&accepts),
        connects: Arc::new(Mutex::new(Vec::new())),
    };

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            let _ = tcp.set_nodelay(true);
            let rpcs = Arc::clone(&rpcs);
            tokio::spawn(async move {
                h3_mesh_serve_grpc(tcp, behavior, Vec::new(), rpcs).await;
            });
        }
    });

    peer
}

/// A real Ambient HBONE listener: SVID-mTLS + HTTP/2, admitting bare CONNECTs
/// and byte-copying each to its CONNECT `:authority` — exactly what the
/// destination-side transparent relay does, so the inner HTTP/2 gRPC connection
/// the gateway runs is genuinely tunnelled.
async fn start_h3_mesh_hbone_relay(svid: &GeneratedGatewaySvid) -> H3MeshPeer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind H3 mesh HBONE relay");
    let port = listener.local_addr().expect("HBONE relay addr").port();
    let snis: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let connects: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let config = h3_mesh_server_config(svid, Arc::clone(&snis));
    let peer = H3MeshPeer {
        port,
        rpcs: Arc::new(Mutex::new(Vec::new())),
        snis,
        accepts: Arc::clone(&accepts),
        connects: Arc::clone(&connects),
    };

    tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let connects = Arc::clone(&connects);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(accepted) = connection.accept().await {
                    let Ok((request, mut respond)) = accepted else {
                        return;
                    };
                    if request.method() != hyper::Method::CONNECT {
                        return;
                    }
                    let authority = request.uri().to_string();
                    connects
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(authority.clone());
                    // A real relay only dials what its open-relay guard admits;
                    // this fixture stays on loopback for the same reason.
                    if !authority.starts_with("127.0.0.1:") {
                        return;
                    }
                    let Ok(app) = TcpStream::connect(authority.as_str()).await else {
                        return;
                    };
                    let _ = app.set_nodelay(true);
                    let mut recv = request.into_body();
                    let response = hyper::Response::builder()
                        .status(200)
                        .body(())
                        .expect("build HBONE CONNECT response");
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };
                    let (mut app_read, mut app_write) = tokio::io::split(app);
                    tokio::spawn(async move {
                        while let Some(chunk) = recv.data().await {
                            let Ok(chunk) = chunk else { break };
                            let _ = recv.flow_control().release_capacity(chunk.len());
                            if app_write.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        let _ = app_write.shutdown().await;
                    });
                    tokio::spawn(async move {
                        // The fixture's frames are small (gRPC control frames and
                        // a few-byte message), so they always fit the default
                        // HTTP/2 window and need no explicit capacity
                        // reservation — the same simplification the HBONE pool
                        // echo relays make.
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            match app_read.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => {
                                    let chunk = Bytes::copy_from_slice(&buf[..read]);
                                    if send.send_data(chunk, false).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            });
        }
    });

    peer
}

/// A mesh listener that ACCEPTS and immediately closes, so a dial to it fails
/// PRE-WIRE — before any HTTP/2 request can be written — and is therefore
/// retry-eligible, while still RECORDING that it was dialed.
///
/// That recording is what makes retry rotation provable from outside the
/// gateway: if this peer's accept count is non-zero and the RPC nevertheless
/// succeeded, the attempt must have rotated onto the other target and
/// re-resolved ITS dial plan.
async fn start_h3_mesh_dead_peer() -> H3MeshPeer {
    let listener = bind_fixture_listener(loopback_ephemeral())
        .await
        .expect("bind H3 mesh dead peer");
    let port = listener.local_addr().expect("dead peer addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let peer = H3MeshPeer {
        port,
        rpcs: Arc::new(Mutex::new(Vec::new())),
        snis: Arc::new(Mutex::new(Vec::new())),
        accepts: Arc::clone(&accepts),
        connects: Arc::new(Mutex::new(Vec::new())),
    };

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::SeqCst);
            drop(tcp);
        }
    });

    peer
}

/// N gateway/peer SVID file-sets minted under ONE shared mesh CA, so every
/// identity in a topology mutually verifies through the same trust bundle.
/// [`generate_two_gateway_svids`] generalized to an arbitrary identity count.
fn generate_shared_ca_mesh_svid_set(
    dir: &std::path::Path,
    spiffe_ids: &[&str],
) -> Vec<GeneratedGatewaySvid> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose,
    };

    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("mesh ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("mesh ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).expect("mesh ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let trust_bundle_path = dir.join("h3-mesh-ca.pem");
    std::fs::write(&trust_bundle_path, &ca_pem).expect("write mesh trust bundle");
    let bundle = trust_bundle_path
        .to_str()
        .expect("bundle path is UTF-8")
        .to_string();

    spiffe_ids
        .iter()
        .enumerate()
        .map(|(index, spiffe)| {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
            let mut params = CertificateParams::default();
            params.distinguished_name = DistinguishedName::new();
            let id = SpiffeId::new(*spiffe).expect("valid SPIFFE ID");
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

            let cert_path = dir.join(format!("h3-mesh-{index}.crt"));
            let key_path = dir.join(format!("h3-mesh-{index}.key"));
            std::fs::write(&cert_path, cert.pem()).expect("write mesh SVID cert");
            std::fs::write(&key_path, key.serialize_pem()).expect("write mesh SVID key");
            GeneratedGatewaySvid {
                cert_path: cert_path.to_str().expect("path is UTF-8").to_string(),
                key_path: key_path.to_str().expect("path is UTF-8").to_string(),
                trust_bundle_path: bundle.clone(),
            }
        })
        .collect()
}

/// Frontend TLS material for the gateway's QUIC/HTTP-3 listener.
struct H3MeshFrontendCerts {
    cert_path: String,
    key_path: String,
    _dir: TempDir,
}

fn h3_mesh_frontend_certs() -> H3MeshFrontendCerts {
    let dir = TempDir::new().expect("h3 frontend cert tempdir");
    let ca = TestCa::new("h3-mesh-grpc-gw").expect("frontend ca");
    let (cert, key) = ca.valid().expect("frontend leaf");
    let cert_path = dir.path().join("frontend.crt");
    let key_path = dir.path().join("frontend.key");
    std::fs::write(&cert_path, &cert).expect("write frontend cert");
    std::fs::write(&key_path, &key).expect("write frontend key");
    H3MeshFrontendCerts {
        cert_path: cert_path.to_str().expect("path is UTF-8").to_string(),
        key_path: key_path.to_str().expect("path is UTF-8").to_string(),
        _dir: dir,
    }
}

/// One upstream-target YAML block (indented for `upstreams[].targets`) carrying
/// `tags` verbatim. The block is deserialized into a trusted projected
/// [`GatewayConfig`] and fed to in-process serve / `update_config` — the same
/// runtime boundary production mesh materialization uses — rather than being
/// written through the operator file-loader (which must keep rejecting `mesh.*`).
fn h3_mesh_target_yaml(host: &str, port: u16, tags: &[(&str, String)]) -> String {
    let mut block = String::new();
    block.push_str(&format!("      - host: \"{host}\"\n"));
    block.push_str(&format!("        port: {port}\n"));
    if !tags.is_empty() {
        block.push_str("        tags:\n");
        for (key, value) in tags {
            block.push_str(&format!("          {key}: \"{value}\"\n"));
        }
    }
    block
}

/// The upstream id every H3 mesh gRPC config declares. Shared with
/// `h3_mesh_reload`, which waits until the applied projection exposes these
/// upstream tags after a trusted `update_config`.
const H3_MESH_UPSTREAM_ID: &str = "h3-mesh-grpc-upstream";

/// Trusted-projected fixture YAML for ONE gRPC-serving proxy whose upstream
/// carries the supplied target blocks. `dead_backend_port` is the proxy's own
/// (unlistened) backend, so only a mesh dispatch can reach anything at all.
fn h3_mesh_grpc_config(dead_backend_port: u16, targets: &str, retry: bool) -> String {
    h3_mesh_grpc_config_with_generation(dead_backend_port, targets, retry, 0)
}

/// Like [`h3_mesh_grpc_config`], but stamps an advancing `updated_at` on the
/// proxy and upstream so `ConfigDelta` sees a real modification even when only
/// mesh target tags change (host/port stay fixed across projected reloads).
fn h3_mesh_grpc_config_with_generation(
    dead_backend_port: u16,
    targets: &str,
    retry: bool,
    generation: u32,
) -> String {
    let retry_block = if retry {
        "    retry:\n      max_retries: 1\n      retryable_status_codes: []\n      \
         retryable_methods: [\"POST\"]\n      retry_on_connect_failure: true\n      \
         backoff: !fixed\n        delay_ms: 50\n"
    } else {
        ""
    };
    // Bound to one minute of unique stamps — the reload test only needs a few
    // generations, and ConfigDelta keys modifications on `updated_at !=`.
    let stamp = format!("2026-08-08T00:00:{generation:02}Z");
    format!(
        r#"version: "1"
proxies:
  - id: "h3-mesh-grpc"
    listen_path: "/mesh"
    strip_listen_path: true
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {dead_backend_port}
    upstream_id: "{H3_MESH_UPSTREAM_ID}"
    backend_connect_timeout_ms: 3000
    backend_read_timeout_ms: 8000
    backend_write_timeout_ms: 8000
    updated_at: "{stamp}"
{retry_block}upstreams:
  - id: "{H3_MESH_UPSTREAM_ID}"
    algorithm: round_robin
    updated_at: "{stamp}"
    targets:
{targets}consumers: []
plugin_configs: []
"#
    )
}

/// Spawn an in-process gateway with a QUIC/HTTP-3 frontend and a real SPIFFE
/// SVID, feeding a **trusted projected** config (may carry reserved `mesh.*`
/// tags) through `file::serve` — the same boundary mesh materialization uses.
/// Returns the gateway plus the HTTPS/QUIC port to drive.
///
/// `reserved_ports` are ports this test's fixtures already own; the HTTPS port
/// is allocated from the mesh-port set so it cannot collide with them.
async fn spawn_h3_mesh_gateway(
    config_yaml: String,
    svid: &GeneratedGatewaySvid,
    frontend: &H3MeshFrontendCerts,
    reserved_ports: &[u16],
) -> (TrustedProjectedGateway, u16) {
    let env = EnvConfig {
        enable_http3: true,
        pool_warmup_enabled: false,
        tls_no_verify: true,
        frontend_tls_cert_path: Some(frontend.cert_path.clone()),
        frontend_tls_key_path: Some(frontend.key_path.clone()),
        gateway_svid_cert_path: Some(svid.cert_path.clone()),
        gateway_svid_key_path: Some(svid.key_path.clone()),
        gateway_svid_trust_bundle_path: Some(svid.trust_bundle_path.clone()),
        log_level: "warn".into(),
        ..Default::default()
    };

    let gateway = TrustedProjectedGateway::spawn_from_yaml(
        &config_yaml,
        TrustedProjectedGatewayOptions {
            env,
            enable_https: true,
            excluded_ports: reserved_ports.to_vec(),
            ..TrustedProjectedGatewayOptions::default()
        },
    )
    .await
    .expect("spawn H3 mesh gRPC gateway via trusted projection");
    gateway
        .wait_for_proxy_port(Duration::from_secs(15))
        .await
        .expect("H3 mesh gRPC gateway proxy port");
    let https_port = gateway
        .proxy_https_port
        .expect("H3 mesh gateway must expose an HTTPS/QUIC port");
    (gateway, https_port)
}

/// What the H3 client received for one RPC.
struct H3MeshRpcResult {
    status: http::StatusCode,
    headers: hyper::HeaderMap,
    body: Bytes,
    trailers: hyper::HeaderMap,
}

impl H3MeshRpcResult {
    /// The terminal `grpc-status`, from the trailers when the call reached the
    /// peer and from the response headers on a Trailers-Only gateway refusal.
    fn grpc_status(&self) -> Option<String> {
        h3_mesh_header(&self.trailers, "grpc-status")
            .or_else(|| h3_mesh_header(&self.headers, "grpc-status"))
    }

    fn grpc_message(&self) -> Option<String> {
        h3_mesh_header(&self.trailers, "grpc-message")
            .or_else(|| h3_mesh_header(&self.headers, "grpc-message"))
    }
}

/// Open the H3 gRPC stream, retrying only the QUIC HANDSHAKE so the test does not
/// race the frontend listener coming up. The RPC itself is driven exactly once —
/// an authoritative protocol/security observation must never be retried.
async fn h3_mesh_open_stream(
    client: &Http3Client,
    url: &str,
    metadata: &[(&str, &str)],
) -> Http3GrpcStream {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match client.open_grpc_stream_with_headers(url, metadata).await {
            Ok(stream) => return stream,
            Err(error) => {
                if Instant::now() >= deadline {
                    panic!("H3 gRPC stream never opened for {url}: {error}");
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

/// A length-prefixed gRPC message (1-byte flag + 4-byte BE length + payload).
fn h3_mesh_grpc_message(payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// One complete unary gRPC RPC over the gateway's QUIC/HTTP-3 frontend.
async fn h3_mesh_unary_rpc(
    https_port: u16,
    payload: &[u8],
    metadata: &[(&str, &str)],
) -> H3MeshRpcResult {
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}{H3_MESH_RPC_PATH}");
    let mut stream = h3_mesh_open_stream(&client, &url, metadata).await;
    stream
        .send_message(payload)
        .await
        .expect("send H3 gRPC request message");
    stream.finish().await.expect("half-close H3 gRPC request");
    let (status, headers) = stream
        .recv_response()
        .await
        .expect("H3 gRPC response headers");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("H3 gRPC response body and trailers");
    H3MeshRpcResult {
        status,
        headers,
        body,
        trailers,
    }
}

/// The same-cluster Sidecar `mesh.mtls` target tags: the peer's inbound mTLS
/// listener is dialed, the destination workload identity is PINNED, and the
/// request `:authority` is the destination SERVICE the peer routes on.
fn h3_mesh_mtls_tags(peer_port: u16, pinned_peer: &str) -> Vec<(&'static str, String)> {
    vec![
        ("mesh.mtls", "true".to_string()),
        ("mesh.mtls_port", peer_port.to_string()),
        ("mesh.spiffe_id", pinned_peer.to_string()),
        (
            "mesh.mtls_authority_host",
            H3_MESH_SERVICE_AUTHORITY.to_string(),
        ),
    ]
}

/// The same-cluster Ambient `mesh.hbone` target tags: the peer's HBONE listener
/// is dialed and the destination workload identity is PINNED. `target.port` is
/// the REAL app port, because that is what the destination relay CONNECTs to.
fn h3_mesh_hbone_tags(relay_port: u16, pinned_peer: &str) -> Vec<(&'static str, String)> {
    vec![
        ("mesh.hbone", "true".to_string()),
        ("mesh.hbone_port", relay_port.to_string()),
        ("mesh.spiffe_id", pinned_peer.to_string()),
    ]
}

// ── 1. Same-cluster Sidecar mesh mTLS ───────────────────────────────────────

/// A native gRPC RPC over the H3 frontend reaches a same-cluster Sidecar peer
/// over its authenticated SVID-mTLS hop, and the whole gRPC contract survives:
/// the peer sees THIS gateway's client SVID (so the hop was authenticated, not a
/// plaintext dial), the request `:authority` is the destination SERVICE rather
/// than the `:15006`-style dial port, `te: trailers` and the native content type
/// are intact, request DATA arrives byte-for-byte, and `grpc-status` /
/// `grpc-message` come back as REAL HTTP/2 trailers relayed onto H3 trailers.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_dispatches_over_same_cluster_sidecar_mesh_mtls() {
    let identities = TempDir::new().expect("h3 mesh mtls identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    let peer = start_h3_mesh_mtls_peer(&svids[1], H3MeshPeerBehavior::EchoAfterUpload).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let declared_app_port = h3_mesh_declared_app_port().await;
    let frontend = h3_mesh_frontend_certs();

    let targets = h3_mesh_target_yaml(
        "127.0.0.1",
        declared_app_port,
        &h3_mesh_mtls_tags(peer.port, H3_MESH_PEER_SPIFFE),
    );
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, peer.port, declared_app_port],
    )
    .await;

    let payload = h3_mesh_grpc_message(b"h3-sidecar-mtls");
    let result = h3_mesh_unary_rpc(https_port, b"h3-sidecar-mtls", &[]).await;

    assert_eq!(result.status.as_u16(), 200, "gRPC rides on HTTP 200");
    assert_eq!(
        result.grpc_status().as_deref(),
        Some("0"),
        "the mesh-mTLS RPC must succeed: {:?} / {:?}",
        result.headers,
        result.trailers
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "grpc-status").as_deref(),
        Some("0"),
        "the terminal status must arrive as REAL H3 trailers, not response headers"
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "x-mesh-peer-trailer").as_deref(),
        Some("real-http2-trailer"),
        "the peer's non-gRPC trailer must be relayed too"
    );
    assert_eq!(
        result.body.as_ref(),
        payload.as_slice(),
        "the peer's response DATA must relay byte-for-byte onto H3"
    );

    let observed = peer.wait_for_rpc(Duration::from_secs(10)).await;
    assert_eq!(
        observed.scheme, "https",
        "the Sidecar mTLS request is HTTPS"
    );
    assert!(
        observed.presented_client_spiffe(H3_MESH_GATEWAY_SPIFFE),
        "the peer must have verified THIS gateway's client SVID (authenticated \
         hop, never a plaintext dial)"
    );
    assert_eq!(
        observed.authority, H3_MESH_SERVICE_AUTHORITY,
        "the request :authority must be the destination SERVICE the peer routes \
         on, not the dial address"
    );
    assert!(
        !observed.authority.contains(&peer.port.to_string()),
        "the :authority must never name the inbound mTLS DIAL port"
    );
    assert_eq!(observed.path, H3_MESH_BACKEND_PATH);
    assert_eq!(observed.te.as_deref(), Some("trailers"));
    assert_eq!(observed.content_type.as_deref(), Some("application/grpc"));
    assert_eq!(
        observed.body, payload,
        "the H3 request DATA must reach the peer byte-for-byte"
    );

    gateway.shutdown().await;
}

// ── 2. Cross-cluster Sidecar mesh mTLS (east-west) ───────────────────────────

/// A native gRPC RPC over the H3 frontend reaches a CROSS-CLUSTER Sidecar
/// destination through its east-west gateway: the ClientHello carries the
/// destination-FQDN SNI override (`mesh.eastwest_sni`) rather than the gateway
/// address actually connected to, verification is scoped to the remote trust
/// domain with NO pod pinning, and real response trailers still arrive.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_dispatches_over_cross_cluster_sidecar_mesh_mtls() {
    let identities = TempDir::new().expect("h3 xc mtls identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    // The remote east-west gateway terminates the same SVID-mTLS hop.
    let eastwest = start_h3_mesh_mtls_peer(&svids[1], H3MeshPeerBehavior::EchoAfterUpload).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let frontend = h3_mesh_frontend_certs();

    // The HTTP-family cross-cluster Sidecar target's identity IS the gateway dial
    // endpoint; the destination rides the SNI override + authority host.
    let targets = h3_mesh_target_yaml(
        "127.0.0.1",
        eastwest.port,
        &[
            ("mesh.mtls", "true".to_string()),
            ("mesh.mtls_port", eastwest.port.to_string()),
            ("mesh.cross_cluster", "true".to_string()),
            ("mesh.eastwest_sni", H3_MESH_EASTWEST_SNI.to_string()),
            ("mesh.trust_domain", "cluster.local".to_string()),
            ("mesh.mtls_authority_host", H3_MESH_EASTWEST_SNI.to_string()),
        ],
    );
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, eastwest.port],
    )
    .await;

    let payload = h3_mesh_grpc_message(b"h3-xc-mtls");
    let result = h3_mesh_unary_rpc(https_port, b"h3-xc-mtls", &[]).await;

    assert_eq!(
        result.grpc_status().as_deref(),
        Some("0"),
        "the cross-cluster mesh-mTLS RPC must succeed: {:?} / {:?}",
        result.headers,
        result.trailers
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "grpc-status").as_deref(),
        Some("0"),
        "the terminal status must arrive as REAL H3 trailers"
    );
    assert_eq!(result.body.as_ref(), payload.as_slice());

    let observed = eastwest.wait_for_rpc(Duration::from_secs(10)).await;
    assert!(
        observed.presented_client_spiffe(H3_MESH_GATEWAY_SPIFFE),
        "the east-west hop must be authenticated with this gateway's SVID"
    );
    assert_eq!(
        observed.authority, H3_MESH_EASTWEST_SNI,
        "the inner request authority must name the destination service"
    );
    let snis = eastwest.observed_snis();
    assert!(
        snis.iter()
            .any(|sni| sni.as_deref() == Some(H3_MESH_EASTWEST_SNI)),
        "the east-west ClientHello must carry the destination-FQDN SNI override, \
         not the gateway address dialed; observed {snis:?}"
    );

    gateway.shutdown().await;
}

// ── 3. Same-cluster Ambient HBONE (nested HTTP/2 in the CONNECT tunnel) ──────

/// A native gRPC RPC over the H3 frontend reaches a same-cluster Ambient
/// destination through an authenticated HBONE CONNECT: the relay verifies THIS
/// gateway's SVID, the CONNECT `:authority` names the real destination app
/// address, and the NESTED HTTP/2 connection inside the byte tunnel carries
/// DATA and real `grpc-status` TRAILERS end to end — the exact framing the old
/// HTTP/1.1-inside-HBONE dispatch could not.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_dispatches_over_same_cluster_ambient_hbone() {
    let identities = TempDir::new().expect("h3 hbone identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    let app = start_h3_mesh_h2c_app(H3MeshPeerBehavior::EchoAfterUpload).await;
    let relay = start_h3_mesh_hbone_relay(&svids[1]).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let frontend = h3_mesh_frontend_certs();

    let targets = h3_mesh_target_yaml(
        "127.0.0.1",
        app.port,
        &h3_mesh_hbone_tags(relay.port, H3_MESH_PEER_SPIFFE),
    );
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, relay.port, app.port],
    )
    .await;

    let payload = h3_mesh_grpc_message(b"h3-ambient-hbone");
    let result = h3_mesh_unary_rpc(https_port, b"h3-ambient-hbone", &[]).await;

    assert_eq!(
        result.grpc_status().as_deref(),
        Some("0"),
        "the Ambient HBONE RPC must succeed: {:?} / {:?}",
        result.headers,
        result.trailers
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "grpc-status").as_deref(),
        Some("0"),
        "gRPC trailers must survive the nested HTTP/2 connection inside the tunnel"
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "x-mesh-peer-trailer").as_deref(),
        Some("real-http2-trailer")
    );
    assert_eq!(result.body.as_ref(), payload.as_slice());

    let connects = relay.observed_connects();
    assert!(
        connects
            .iter()
            .any(|authority| authority == &format!("127.0.0.1:{}", app.port)),
        "the CONNECT :authority must name the real destination app address; \
         observed {connects:?}"
    );

    let observed = app.wait_for_rpc(Duration::from_secs(10)).await;
    assert_eq!(
        observed.scheme, "http",
        "the inner Ambient application hop is h2c, not end-to-end HTTPS"
    );
    assert_eq!(observed.path, H3_MESH_BACKEND_PATH);
    assert_eq!(observed.te.as_deref(), Some("trailers"));
    assert_eq!(observed.content_type.as_deref(), Some("application/grpc"));
    assert_eq!(observed.body, payload);
    assert_eq!(
        observed.authority,
        format!("127.0.0.1:{}", app.port),
        "the inner request authority must be the destination's own app address"
    );

    gateway.shutdown().await;
}

// ── 4. Cross-cluster Ambient HBONE (east-west gateway) ──────────────────────

/// A native gRPC RPC over the H3 frontend reaches a CROSS-CLUSTER Ambient
/// destination through the remote east-west gateway. `target.host` is the scoped
/// SYNTHETIC identity the cross-cluster materializer stamps — never dialable —
/// so a successful RPC proves the dial used `mesh.hbone_dial_host`, and the
/// ClientHello must carry the destination-FQDN SNI override with
/// trust-domain-scoped verification instead of a pinned pod SPIFFE.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_dispatches_over_cross_cluster_ambient_hbone() {
    let identities = TempDir::new().expect("h3 xc hbone identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    let app = start_h3_mesh_h2c_app(H3MeshPeerBehavior::EchoAfterUpload).await;
    let eastwest = start_h3_mesh_hbone_relay(&svids[1]).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let frontend = h3_mesh_frontend_certs();

    let targets = h3_mesh_target_yaml(
        // Scoped synthetic identity, exactly as the cross-cluster materializer
        // stamps it: it must never be dialed or used as an authority.
        "mesh-xc-h3|h3-remote.ferrum.svc.cluster.local",
        app.port,
        &[
            ("mesh.hbone", "true".to_string()),
            ("mesh.cross_cluster", "true".to_string()),
            ("mesh.hbone_dial_host", "127.0.0.1".to_string()),
            ("mesh.hbone_port", eastwest.port.to_string()),
            ("mesh.hbone_authority_host", "127.0.0.1".to_string()),
            ("mesh.eastwest_sni", H3_MESH_EASTWEST_SNI.to_string()),
            ("mesh.trust_domain", "cluster.local".to_string()),
        ],
    );
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, eastwest.port, app.port],
    )
    .await;

    let payload = h3_mesh_grpc_message(b"h3-xc-hbone");
    let result = h3_mesh_unary_rpc(https_port, b"h3-xc-hbone", &[]).await;

    assert_eq!(
        result.grpc_status().as_deref(),
        Some("0"),
        "the cross-cluster Ambient HBONE RPC must succeed: {:?} / {:?}",
        result.headers,
        result.trailers
    );
    assert_eq!(
        h3_mesh_header(&result.trailers, "grpc-status").as_deref(),
        Some("0"),
        "gRPC trailers must survive the cross-cluster nested HTTP/2 tunnel"
    );
    assert_eq!(result.body.as_ref(), payload.as_slice());

    let snis = eastwest.observed_snis();
    assert!(
        snis.iter()
            .any(|sni| sni.as_deref() == Some(H3_MESH_EASTWEST_SNI)),
        "the east-west ClientHello must carry the destination-FQDN SNI override; \
         observed {snis:?}"
    );
    let connects = eastwest.observed_connects();
    assert!(
        connects
            .iter()
            .any(|authority| authority == &format!("127.0.0.1:{}", app.port)),
        "the CONNECT :authority must name the destination app address from \
         mesh.hbone_authority_host, never the synthetic target host; observed \
         {connects:?}"
    );

    let observed = app.wait_for_rpc(Duration::from_secs(10)).await;
    assert_eq!(
        observed.scheme, "http",
        "cross-cluster Ambient still terminates in a plaintext h2c app request"
    );
    assert_eq!(observed.body, payload);

    gateway.shutdown().await;
}

// ── 5. Streaming + cancellation over a mesh transport ───────────────────────

/// True client-streaming / bidirectional gRPC survives the mesh transport: the
/// Ambient peer answers after the FIRST request DATA frame — proof the gateway
/// committed the H3 upload incrementally instead of buffering it — and a client
/// cancellation then propagates through the nested HTTP/2 connection as a reset
/// request stream rather than being absorbed by the gateway.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_streams_and_cancels_over_ambient_hbone() {
    let identities = TempDir::new().expect("h3 hbone streaming identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    let app = start_h3_mesh_h2c_app(H3MeshPeerBehavior::RespondOnFirstRequestFrame).await;
    let relay = start_h3_mesh_hbone_relay(&svids[1]).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let frontend = h3_mesh_frontend_certs();

    let targets = h3_mesh_target_yaml(
        "127.0.0.1",
        app.port,
        &h3_mesh_hbone_tags(relay.port, H3_MESH_PEER_SPIFFE),
    );
    // No retry and no body plugins, so the H3 frontend takes the STREAMING
    // request bridge rather than draining the upload first.
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, relay.port, app.port],
    )
    .await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}{H3_MESH_RPC_PATH}");
    let mut stream = h3_mesh_open_stream(&client, &url, &[]).await;
    stream
        .send_message(b"h3-stream-first")
        .await
        .expect("send first H3 gRPC message");

    // The response must arrive BEFORE the client half-closes: the mesh transport
    // has to be genuinely full-duplex, not request-then-response.
    let (status, _headers) = stream
        .recv_response()
        .await
        .expect("response head before half-close");
    assert_eq!(status.as_u16(), 200);
    let first_chunk = stream
        .recv_data()
        .await
        .expect("response DATA before half-close");
    assert_eq!(
        first_chunk.as_deref(),
        Some(H3_MESH_EARLY_RESPONSE),
        "the peer's pre-half-close DATA must reach the H3 client"
    );

    let observed = app.wait_for_rpc(Duration::from_secs(10)).await;
    assert_eq!(observed.path, H3_MESH_BACKEND_PATH);
    assert_eq!(
        observed.body,
        h3_mesh_grpc_message(b"h3-stream-first"),
        "the first H3 DATA frame must have been committed incrementally"
    );

    // Cancel the upload direction while the RPC is live. It must reach the peer
    // as a reset request stream through the tunnel.
    stream.cancel_request_upload();
    app.wait_for_request_reset(Duration::from_secs(15)).await;

    gateway.shutdown().await;
}

// ── 6. Deadline propagation over a mesh transport ───────────────────────────

/// A client `grpc-timeout` is propagated onto the mesh transport and enforced by
/// the gateway: the Sidecar peer observes an outbound `grpc-timeout` on the
/// authenticated hop, and when it never answers the H3 client gets
/// DEADLINE_EXCEEDED (4) rather than hanging or receiving a connection error.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_propagates_the_deadline_over_sidecar_mesh_mtls() {
    let identities = TempDir::new().expect("h3 mesh deadline identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    let peer = start_h3_mesh_mtls_peer(&svids[1], H3MeshPeerBehavior::NeverRespond).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let declared_app_port = h3_mesh_declared_app_port().await;
    let frontend = h3_mesh_frontend_certs();

    let targets = h3_mesh_target_yaml(
        "127.0.0.1",
        declared_app_port,
        &h3_mesh_mtls_tags(peer.port, H3_MESH_PEER_SPIFFE),
    );
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, false),
        &svids[0],
        &frontend,
        &[dead_backend_port, peer.port, declared_app_port],
    )
    .await;

    let result = h3_mesh_unary_rpc(https_port, b"h3-deadline", &[("grpc-timeout", "700m")]).await;

    assert_eq!(
        result.grpc_status().as_deref(),
        Some("4"),
        "an unanswered mesh RPC must end as DEADLINE_EXCEEDED, not a connection \
         error: {:?} / {:?}",
        result.headers,
        result.trailers
    );

    let observed = peer.wait_for_rpc(Duration::from_secs(10)).await;
    assert!(
        observed
            .grpc_timeout
            .as_deref()
            .is_some_and(|timeout| !timeout.is_empty()),
        "the peer must have received a grpc-timeout on the mesh hop: {observed:?}"
    );

    gateway.shutdown().await;
}

// ── 7. Fail-closed refusal for unmaterializable mesh metadata ───────────────

/// Every malformed / unmaterializable mesh transport shape is refused BEFORE any
/// dial, with a fixed metadata-free client message: a corrupt identity pin, a
/// cross-cluster target missing its SNI override, a cross-cluster target missing
/// its remote trust domain, a cross-cluster target with no transport tag at all,
/// and a corrupted target declaring BOTH mesh transports. In every case the H3
/// client gets gRPC UNAVAILABLE (14), the peer's listener is never dialed, and
/// the refusal text leaks no SPIFFE ID, SNI name, or trust domain.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_mesh_transport_refuses_unmaterializable_metadata() {
    let identities = TempDir::new().expect("h3 mesh refusal identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[H3_MESH_GATEWAY_SPIFFE, H3_MESH_PEER_SPIFFE],
    );
    // A REACHABLE peer, so a refusal can only come from the transport gate and
    // never from an unreachable address.
    let peer = start_h3_mesh_mtls_peer(&svids[1], H3MeshPeerBehavior::EchoAfterUpload).await;
    let declared_app_port = h3_mesh_declared_app_port().await;
    let frontend = h3_mesh_frontend_certs();

    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        (
            "corrupt sidecar identity pin",
            vec![
                ("mesh.mtls", "true".to_string()),
                ("mesh.mtls_port", peer.port.to_string()),
                ("mesh.spiffe_id", "not-a-spiffe-id".to_string()),
            ],
        ),
        (
            "cross-cluster sidecar missing the SNI override",
            vec![
                ("mesh.mtls", "true".to_string()),
                ("mesh.mtls_port", peer.port.to_string()),
                ("mesh.cross_cluster", "true".to_string()),
                ("mesh.trust_domain", "cluster.local".to_string()),
            ],
        ),
        (
            "cross-cluster sidecar missing the remote trust domain",
            vec![
                ("mesh.mtls", "true".to_string()),
                ("mesh.mtls_port", peer.port.to_string()),
                ("mesh.cross_cluster", "true".to_string()),
                ("mesh.eastwest_sni", H3_MESH_EASTWEST_SNI.to_string()),
            ],
        ),
        (
            "cross-cluster with no mesh transport tag",
            vec![
                ("mesh.cross_cluster", "true".to_string()),
                ("mesh.trust_domain", "cluster.local".to_string()),
                ("mesh.eastwest_sni", H3_MESH_EASTWEST_SNI.to_string()),
            ],
        ),
        (
            "both mesh transports declared on one target",
            vec![
                ("mesh.mtls", "true".to_string()),
                ("mesh.mtls_port", peer.port.to_string()),
                ("mesh.hbone", "true".to_string()),
                ("mesh.hbone_port", peer.port.to_string()),
                ("mesh.spiffe_id", H3_MESH_PEER_SPIFFE.to_string()),
            ],
        ),
    ];

    // The mesh metadata a refusal must never echo to a client.
    let secrets = [
        H3_MESH_PEER_SPIFFE,
        H3_MESH_EASTWEST_SNI,
        "cluster.local",
        "not-a-spiffe-id",
    ];

    for (label, tags) in cases {
        let dead_backend_port = reserve_unique_mesh_port().await;
        let targets = h3_mesh_target_yaml("127.0.0.1", declared_app_port, &tags);
        let (mut gateway, https_port) = spawn_h3_mesh_gateway(
            h3_mesh_grpc_config(dead_backend_port, &targets, false),
            &svids[0],
            &frontend,
            &[dead_backend_port, peer.port, declared_app_port],
        )
        .await;

        let accepts_before = peer.accept_count();
        let result = h3_mesh_unary_rpc(https_port, b"h3-refused", &[]).await;

        assert_eq!(
            result.grpc_status().as_deref(),
            Some("14"),
            "{label}: an unmaterializable mesh transport must fail closed with \
             gRPC UNAVAILABLE: {:?} / {:?}",
            result.headers,
            result.trailers
        );
        assert!(
            result.body.is_empty(),
            "{label}: a pre-dial refusal must carry no response body"
        );
        assert_eq!(
            peer.accept_count(),
            accepts_before,
            "{label}: the refusal must happen BEFORE any dial to the peer"
        );
        let message = result.grpc_message().unwrap_or_default();
        for secret in secrets {
            assert!(
                !message.contains(secret),
                "{label}: the refusal message must not leak mesh identity \
                 metadata ({secret:?}): {message:?}"
            );
        }

        gateway.shutdown().await;
    }
}

// ── 8. Retry rotation re-resolves the rotated target's transport ────────────

/// Retry rotation re-resolves the transport PER ATTEMPT.
///
/// Two mesh-mTLS targets with DIFFERENT pinned workload identities and different
/// dial ports. The first target's peer accepts and immediately closes, so its
/// attempt fails PRE-WIRE and is retry-eligible; the rotation must land on the
/// SECOND target and dial over ITS OWN plan (a different pinned peer on a
/// different port). The dead peer's ACCEPT COUNT is what makes the rotation
/// provable from outside the gateway: it proves that target was really dialed,
/// so a successful RPC can only mean the attempt rotated and re-resolved. A
/// rotated attempt reusing the first target's dial plan would fail the second
/// peer's identity pin, and refusing a mesh-tagged rotation — which this bridge
/// did before #3284 — would fail closed with UNAVAILABLE.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_retry_rotation_re_resolves_the_mesh_transport() {
    let identities = TempDir::new().expect("h3 mesh rotation identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[
            H3_MESH_GATEWAY_SPIFFE,
            H3_MESH_PEER_SPIFFE,
            H3_MESH_PEER_B_SPIFFE,
        ],
    );
    let dead_peer = start_h3_mesh_dead_peer().await;
    let live_peer = start_h3_mesh_mtls_peer(&svids[2], H3MeshPeerBehavior::EchoAfterUpload).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let declared_app_port = h3_mesh_declared_app_port().await;
    let frontend = h3_mesh_frontend_certs();

    let mut targets = h3_mesh_target_yaml(
        "127.0.0.1",
        declared_app_port,
        &h3_mesh_mtls_tags(dead_peer.port, H3_MESH_PEER_SPIFFE),
    );
    targets.push_str(&h3_mesh_target_yaml(
        "127.0.0.1",
        declared_app_port,
        &h3_mesh_mtls_tags(live_peer.port, H3_MESH_PEER_B_SPIFFE),
    ));
    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        h3_mesh_grpc_config(dead_backend_port, &targets, true),
        &svids[0],
        &frontend,
        &[
            dead_backend_port,
            dead_peer.port,
            live_peer.port,
            declared_app_port,
        ],
    )
    .await;

    // Round-robin can start either target, so drive three RPCs and require EVERY
    // one to succeed. Each RPC is still driven exactly once — no observation is
    // retried; the loop widens coverage, it does not re-roll a verdict.
    let payload = h3_mesh_grpc_message(b"h3-rotation");
    for attempt in 1..=3 {
        let result = h3_mesh_unary_rpc(https_port, b"h3-rotation", &[]).await;
        assert_eq!(
            result.grpc_status().as_deref(),
            Some("0"),
            "RPC {attempt}: a retry rotation onto a mesh-tagged target must \
             re-resolve ITS transport and succeed, never fail closed: {:?} / {:?}",
            result.headers,
            result.trailers
        );
        assert_eq!(
            result.body.as_ref(),
            payload.as_slice(),
            "RPC {attempt}: the rotated mesh attempt must relay the peer's DATA"
        );
        assert_eq!(
            h3_mesh_header(&result.trailers, "grpc-status").as_deref(),
            Some("0"),
            "RPC {attempt}: the rotated mesh attempt must relay REAL trailers"
        );
    }
    assert!(
        dead_peer.accept_count() > 0,
        "the first mesh target must really have been dialed, so a successful RPC \
         proves the attempt rotated onto the second target's own dial plan"
    );

    let observed = live_peer.wait_for_rpc(Duration::from_secs(10)).await;
    assert!(
        observed.presented_client_spiffe(H3_MESH_GATEWAY_SPIFFE),
        "the rotated attempt must still be an authenticated mesh hop"
    );
    assert_eq!(observed.body, payload);

    gateway.shutdown().await;
}

// ── 9. Configuration update / reload / withdrawal ──────────────────────────

/// The live transport follows configuration TRANSITIONS, not just first-start
/// construction. One trusted-projected gateway is driven through three
/// in-process `update_config` applications (the mesh materialization boundary):
///
/// 1. the mesh target is RE-POINTED at a second peer with a different pinned
///    workload identity — the RPC must move to that peer over its own dial plan;
/// 2. the mesh transport tags are WITHDRAWN, leaving an untagged target — the
///    RPC must stop reaching the mesh listener entirely;
/// 3. the mesh target is restored but its identity pin is CORRUPTED — the RPC
///    must fail closed with UNAVAILABLE and dial nothing.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_h3_grpc_mesh_transport_follows_reload_and_withdrawal() {
    let identities = TempDir::new().expect("h3 mesh reload identity tempdir");
    let svids = generate_shared_ca_mesh_svid_set(
        identities.path(),
        &[
            H3_MESH_GATEWAY_SPIFFE,
            H3_MESH_PEER_SPIFFE,
            H3_MESH_PEER_B_SPIFFE,
        ],
    );
    let peer_a = start_h3_mesh_mtls_peer(&svids[1], H3MeshPeerBehavior::EchoAfterUpload).await;
    let peer_b = start_h3_mesh_mtls_peer(&svids[2], H3MeshPeerBehavior::EchoAfterUpload).await;
    let dead_backend_port = reserve_unique_mesh_port().await;
    let declared_app_port = h3_mesh_declared_app_port().await;
    let frontend = h3_mesh_frontend_certs();

    let config_for = |tags: &[(&'static str, String)], generation: u32| {
        let targets = h3_mesh_target_yaml("127.0.0.1", declared_app_port, tags);
        h3_mesh_grpc_config_with_generation(dead_backend_port, &targets, false, generation)
    };

    let (mut gateway, https_port) = spawn_h3_mesh_gateway(
        config_for(&h3_mesh_mtls_tags(peer_a.port, H3_MESH_PEER_SPIFFE), 0),
        &svids[0],
        &frontend,
        &[
            dead_backend_port,
            peer_a.port,
            peer_b.port,
            declared_app_port,
        ],
    )
    .await;

    let payload = h3_mesh_grpc_message(b"h3-reload");
    let first = h3_mesh_unary_rpc(https_port, b"h3-reload", &[]).await;
    assert_eq!(
        first.grpc_status().as_deref(),
        Some("0"),
        "the initial mesh target must serve the RPC: {:?}",
        first.headers
    );
    peer_a.wait_for_rpc(Duration::from_secs(10)).await;

    // 1. UPDATE: re-point the mesh target at peer B (different pinned identity).
    let peer_b_tags = h3_mesh_mtls_tags(peer_b.port, H3_MESH_PEER_B_SPIFFE);
    h3_mesh_reload(&gateway, config_for(&peer_b_tags, 1), &peer_b_tags).await;
    let retargeted = h3_mesh_unary_rpc(https_port, b"h3-reload", &[]).await;
    assert_eq!(
        retargeted.grpc_status().as_deref(),
        Some("0"),
        "the re-pointed mesh target must serve the RPC after reload: {:?}",
        retargeted.headers
    );
    assert_eq!(retargeted.body.as_ref(), payload.as_slice());
    let observed_b = peer_b.wait_for_rpc(Duration::from_secs(10)).await;
    assert!(
        observed_b.presented_client_spiffe(H3_MESH_GATEWAY_SPIFFE),
        "the re-pointed hop must still be authenticated"
    );

    // 2. WITHDRAWAL: drop the mesh transport tags entirely. The target becomes an
    //    ordinary direct-dial one, so the mesh listener must stop being reached.
    let peer_b_accepts = peer_b.accept_count();
    h3_mesh_reload(&gateway, config_for(&[], 2), &[]).await;
    let withdrawn = h3_mesh_unary_rpc(https_port, b"h3-reload", &[]).await;
    assert_ne!(
        withdrawn.grpc_status().as_deref(),
        Some("0"),
        "with the mesh transport withdrawn, the declared app port is not \
         listening, so the RPC must not succeed: {:?} / {:?}",
        withdrawn.headers,
        withdrawn.trailers
    );
    assert_eq!(
        peer_b.accept_count(),
        peer_b_accepts,
        "a withdrawn mesh transport must never keep dialing the peer's mesh \
         listener"
    );

    // 3. CORRUPTED UPDATE: restore the mesh transport with an unusable identity
    //    pin. It must fail closed, not fall back to a direct dial.
    let peer_a_accepts = peer_a.accept_count();
    let corrupted_tags = [
        ("mesh.mtls", "true".to_string()),
        ("mesh.mtls_port", peer_a.port.to_string()),
        ("mesh.spiffe_id", "not-a-spiffe-id".to_string()),
    ];
    h3_mesh_reload(&gateway, config_for(&corrupted_tags, 3), &corrupted_tags).await;
    let corrupted = h3_mesh_unary_rpc(https_port, b"h3-reload", &[]).await;
    assert_eq!(
        corrupted.grpc_status().as_deref(),
        Some("14"),
        "a reload onto an unmaterializable identity must fail closed with \
         UNAVAILABLE: {:?} / {:?}",
        corrupted.headers,
        corrupted.trailers
    );
    assert_eq!(
        peer_a.accept_count(),
        peer_a_accepts,
        "the fail-closed reload must not dial the peer"
    );

    gateway.shutdown().await;
}

/// Apply a new trusted projected config via `ProxyState::update_config` and wait
/// until the live projection exposes the expected upstream target tags.
///
/// This is the mesh materialization reload boundary — not SIGHUP / file-loader
/// reload, which must keep rejecting operator-authored `mesh.*` tags. Polling
/// the applied projection observes convergence directly without spending a
/// datapath RPC, so each step's authoritative protocol / fail-closed observation
/// is still made exactly once against a known-converged gateway.
async fn h3_mesh_reload(
    gateway: &TrustedProjectedGateway,
    config_yaml: String,
    expected_tags: &[(&'static str, String)],
) {
    let outcome = gateway.apply_projected_yaml(&config_yaml);
    assert!(
        matches!(outcome, ConfigApplyOutcome::Applied),
        "trusted projected H3 mesh reload must apply, got {outcome:?}"
    );

    let expected: HashMap<String, String> = expected_tags
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match gateway.live_upstream_tags(H3_MESH_UPSTREAM_ID) {
            Some(live) if live == expected => return,
            live => {
                assert!(
                    Instant::now() < deadline,
                    "trusted projected reload never exposed expected mesh target tags \
                     {expected:?}; live={live:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}
