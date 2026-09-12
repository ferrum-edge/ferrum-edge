//! Shared live-traffic scaffolding for the DestinationRule
//! `connectionPool.http.http2MaxRequests` destination-wide active-request
//! breaker (issue #3775).
//!
//! Every test that consumes this module starts a REAL in-process Ferrum
//! gateway (`ferrum_edge::modes::file::serve`) over a config that has been
//! through `prepare_gateway_config_for_mesh`, so the DestinationRule → dispatch
//! policy → admission-funnel chain is exercised end to end rather than
//! asserted from source text. The observable contract in every case is:
//!
//! * a held backend exchange keeps its permit for the WHOLE exchange, so a
//!   second request to the same logical destination is shed;
//! * the shed happens BEFORE any backend dial (the fixture's hit counter is the
//!   proof) and carries the documented `503` body;
//! * the permit is released on every terminal path, proven by a later request
//!   reaching the backend.
//!
//! Not `_test.rs`, so the functional CI shard-coverage guard
//! (`functional_ci_shard_coverage_test`) does not require a shard entry for it;
//! the three consumer modules carry their own.

#![allow(dead_code)]

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};

use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};

/// Gateway namespace. Also the first component of every destination lane key.
pub(super) const NS: &str = "ferrum";
/// Logical destination under test — the lane's `destination` component.
pub(super) const UPSTREAM_ID: &str = "dest-active-upstream";
/// A SECOND logical destination whose endpoints are deliberately the SAME
/// address as [`UPSTREAM_ID`], so tests can prove the lane is keyed by logical
/// identity and not by the resolved backend host/port.
pub(super) const SIBLING_UPSTREAM_ID: &str = "dest-active-sibling-upstream";

pub(super) const JWT_SECRET: &str = "ferrum-edge-destination-active-requests-secret";
pub(super) const JWT_ISSUER: &str = "ferrum-edge-destination-active-requests";

/// The exact client-visible body a saturated destination returns. Documented in
/// `docs/mesh.md`; asserted verbatim so a silent wording/status change cannot
/// pass as "some 503 happened".
pub(super) const OVERFLOW_BODY: &str = r#"{"error":"Destination active request limit reached"}"#;

// ───────────────────────────────────────────────────────────────────────────
// Gateway
// ───────────────────────────────────────────────────────────────────────────

pub(super) struct RunningGateway {
    /// Plaintext HTTP listener port. `0` when the gateway was started H3-only.
    pub http_port: u16,
    /// HTTPS/QUIC listener port. `0` when HTTP/3 was not requested.
    pub https_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RunningGateway {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        match timeout(Duration::from_secs(10), self.join).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => panic!("destination-breaker gateway task panicked: {join_err}"),
            Err(_) => panic!("destination-breaker gateway shutdown timed out"),
        }
    }
}

/// Start an in-process file-mode gateway over a mesh-prepared config.
///
/// `enable_h3` additionally binds a colocated TCP/UDP HTTPS listener with the
/// repository's functional test certificate, matching
/// `functional_h3_local_policy_test`.
pub(super) async fn start_gateway(
    config: GatewayConfig,
    enable_h3: bool,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let admin_port = admin.port;

    let (https_listener, https_port) = if enable_h3 {
        let (https_tcp, https_udp) = reserve_colocated_tcp_udp().await?;
        let port = https_tcp.port;
        assert_eq!(port, https_udp.port, "colocated TCP/UDP ports must match");
        // The gateway rebinds the UDP side itself; hold only the TCP listener.
        drop(https_udp);
        (Some(https_tcp.into_listener()), port)
    } else {
        (None, 0)
    };

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: http_port,
        proxy_https_port: https_port,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(JWT_SECRET.to_string()),
        admin_jwt_issuer: JWT_ISSUER.to_string(),
        frontend_tls_cert_path: enable_h3.then(|| "tests/certs/server.crt".to_string()),
        frontend_tls_key_path: enable_h3.then(|| "tests/certs/server.key".to_string()),
        enable_http3: enable_h3,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NS.to_string(),
        ..EnvConfig::default()
    };

    let prepared = prepare_gateway_config_for_mesh(config, &mesh_runtime_config()).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("mesh preparation failed: {e}").into()
        },
    )?;

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let opts = ServeOptions {
        proxy_http: Some(http.into_listener()),
        proxy_https: https_listener,
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, prepared, opts, shutdown_tx.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {e}").into()
        })?;
    let join = tokio::spawn(async move {
        if let Err(err) = handles.join().await {
            panic!("destination-breaker gateway listener failed: {err}");
        }
    });

    Ok(RunningGateway {
        http_port,
        https_port,
        shutdown_tx,
        join,
    })
}

/// Prepare a config the same way [`start_gateway`] does, without serving it.
///
/// Used by the setup gates so a translation regression fails as a config
/// assertion instead of as a confusing traffic assertion.
pub(super) fn prepare_for_assertions(config: GatewayConfig) -> GatewayConfig {
    prepare_gateway_config_for_mesh(config, &mesh_runtime_config())
        .expect("mesh preparation for assertions")
}

/// Resolve the effective `http2MaxRequests` cap for a prepared proxy exactly as
/// production does (`resolve_backend_http2_max_requests`): explicit per-port
/// `portLevelSettings` entry first, then the inherited top-level/subset
/// fallback.
pub(super) fn projected_active_request_cap(
    config: &GatewayConfig,
    proxy_id: &str,
    policy_port: u16,
) -> Option<u32> {
    let proxy = config
        .proxies
        .iter()
        .find(|proxy| proxy.id == proxy_id)
        .unwrap_or_else(|| panic!("prepared proxy {proxy_id}"));
    proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&policy_port))
        .and_then(|entry| entry.http2_max_requests)
        .or_else(|| {
            proxy
                .dispatch_port_override_fallback
                .as_ref()
                .and_then(|fallback| fallback.http2_max_requests)
        })
}

/// Assert the DestinationRule projected the destination budget onto the proxy
/// dispatch policy, and that it did NOT leak into the per-connection HTTP/2
/// transport knob (`maxConcurrentStreams` → `pool_http2_max_concurrent_streams`),
/// which is the exact conflation issue #3775 exists to correct.
pub(super) fn assert_projected_active_request_cap(
    config: &GatewayConfig,
    proxy_id: &str,
    policy_port: u16,
    expected: Option<u32>,
) {
    assert_eq!(
        projected_active_request_cap(config, proxy_id, policy_port),
        expected,
        "prepared {proxy_id} must carry http2MaxRequests={expected:?} at port {policy_port}"
    );
    if expected.is_some() {
        let proxy = config
            .proxies
            .iter()
            .find(|proxy| proxy.id == proxy_id)
            .expect("prepared proxy");
        let fallback_streams = proxy
            .dispatch_port_override_fallback
            .as_ref()
            .and_then(|fallback| fallback.h2_max_concurrent_streams);
        assert_eq!(
            fallback_streams, None,
            "http2MaxRequests must not program the per-connection maxConcurrentStreams knob"
        );
    }
}

pub(super) fn mesh_runtime_config() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "destination-active-requests-node".to_string(),
        namespace: NS.to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_credential_policy: Default::default(),
        stock_xds_allow_plaintext: false,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        egress_gateway: None,
        workload_spiffe_id: None,
        waypoint_name: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
        locality_lb_strict: false,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Release gate
// ───────────────────────────────────────────────────────────────────────────

/// One-shot latch a fixture parks on. Latched-open is sticky, so a test can
/// release once and let every later exchange flow straight through.
pub(super) struct ReleaseGate {
    released: AtomicBool,
    notify: Notify,
}

impl ReleaseGate {
    pub fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// HTTP/1.1 holding backend
// ───────────────────────────────────────────────────────────────────────────

/// What a held HTTP/1.1 exchange does once the test releases the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HoldBehavior {
    /// Answer `200 OK` with a two-byte body and close.
    RespondOk,
    /// Drop the socket without any response — the backend-error/reset terminal
    /// path (gateway answers `502`).
    DropConnection,
}

/// Counting HTTP/1.1 backend whose every request parks on a shared gate.
///
/// Each accepted connection is served on its own task, so several concurrent
/// requests can be held at once; `hits` counts requests that actually reached
/// the fixture, which is what makes "the shed never dialed the backend"
/// observable.
pub(super) struct HoldingHttp1Backend {
    pub port: u16,
    hits: Arc<AtomicUsize>,
    release: Arc<ReleaseGate>,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
}

impl HoldingHttp1Backend {
    pub async fn spawn(behavior: HoldBehavior) -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind holding backend");
        let port = listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(ReleaseGate::new());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let task_hits = Arc::clone(&hits);
        let task_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted
                            .map_err(|e| format!("holding accept failed: {e}"))?;
                        let hits = Arc::clone(&task_hits);
                        let release = Arc::clone(&task_release);
                        children.spawn(async move {
                            serve_held_http(stream, &hits, &release, behavior).await
                        });
                    }
                    Some(joined) = children.join_next() => {
                        if let Err(join_err) = joined
                            && join_err.is_panic()
                        {
                            return Err(format!("holding connection panicked: {join_err}"));
                        }
                    }
                }
            }
            children.shutdown().await;
            Ok(())
        });
        Self {
            port,
            hits,
            release,
            shutdown_tx,
            task,
        }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn release(&self) {
        self.release.release();
    }

    /// Block until at least `expected` requests have reached the fixture.
    pub async fn wait_for_hits(&self, expected: usize, within: Duration) {
        wait_for_count(&self.hits, expected, within).await;
    }

    /// Assert the fixture's hit count is EXACTLY `expected` after a settle
    /// delay. This is the "shed before any backend dial" proof: a shed that
    /// leaked a dial would land here.
    pub async fn assert_hits_eq(&self, expected: usize, settle: Duration) {
        sleep(settle).await;
        assert_eq!(
            self.hits(),
            expected,
            "holding backend request count must be exactly {expected}"
        );
    }

    pub async fn shutdown(self) {
        self.release.release();
        let _ = self.shutdown_tx.send(true);
        match timeout(Duration::from_secs(10), self.task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => panic!("holding backend failed: {err}"),
            Ok(Err(join_err)) => panic!("holding backend panicked: {join_err}"),
            Err(_) => panic!("holding backend did not exit after shutdown"),
        }
    }
}

async fn serve_held_http(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    release: &ReleaseGate,
    behavior: HoldBehavior,
) -> Result<(), String> {
    if read_headers(&mut stream).await.is_err() {
        // A peer that hung up before completing its headers (an idle pooled
        // connection closing) is not a fixture failure.
        return Ok(());
    }
    hits.fetch_add(1, Ordering::SeqCst);
    release.wait().await;
    match behavior {
        HoldBehavior::RespondOk => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = stream.shutdown().await;
        }
        HoldBehavior::DropConnection => drop(stream),
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// HTTP/1.1 status-script backend
// ───────────────────────────────────────────────────────────────────────────

/// Sequential HTTP/1.1 backend that answers a fixed status script, one status
/// per accepted connection. Used for the retry drop/reacquire proof.
pub(super) struct StatusScriptHttp1Backend {
    pub port: u16,
    hits: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
}

impl StatusScriptHttp1Backend {
    pub async fn spawn(statuses: &[u16]) -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind status backend");
        let port = listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let script: Vec<u16> = statuses.to_vec();
        let task_hits = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted
                            .map_err(|e| format!("status accept failed: {e}"))?;
                        if read_headers(&mut stream).await.is_err() {
                            continue;
                        }
                        task_hits.fetch_add(1, Ordering::SeqCst);
                        let status = script.get(idx).copied().unwrap_or(200);
                        idx = idx.saturating_add(1);
                        let body = if status == 200 { "ok" } else { "no" };
                        let response = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                }
            }
            Ok(())
        });
        Self {
            port,
            hits,
            shutdown_tx,
            task,
        }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        match timeout(Duration::from_secs(10), self.task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => panic!("status-script backend failed: {err}"),
            Ok(Err(join_err)) => panic!("status-script backend panicked: {join_err}"),
            Err(_) => panic!("status-script backend did not exit after shutdown"),
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Shared utilities
// ───────────────────────────────────────────────────────────────────────────

pub(super) async fn wait_for_count(counter: &AtomicUsize, expected: usize, within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "backend saw {} requests, expected at least {expected}",
        counter.load(Ordering::SeqCst)
    );
}

/// Poll `probe` until it reports `true`, or panic naming `what`.
pub(super) async fn wait_until(within: Duration, what: &str, mut probe: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if probe() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn read_headers(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let mut read = 0usize;
    loop {
        let n = timeout(Duration::from_secs(15), stream.read(&mut buf[read..]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "header read timed out")
            })??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before request headers",
            ));
        }
        read += n;
        if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        if read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}
