//! Functional coverage for H3→HTTP bridge local dispatch-policy ordering.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests functional_h3_local_policy -- --ignored --nocapture`

use crate::scaffolding::clients::{Http3Client, Http3Response};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port};

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use ferrum_edge::modes::mesh::{MeshRuntimeConfig, prepare_gateway_config_for_mesh};
use http::StatusCode;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[ignore]
#[tokio::test]
async fn functional_h3_local_policy_pending_cap_rejects_before_backend_admission_and_retry() {
    let (backend_port, backend_hits, release_backend, backend_task) = spawn_holding_backend().await;
    let gateway = start_h3_policy_gateway(pending_cap_config(backend_port))
        .await
        .expect("start h3 pending-cap gateway");

    let first_client = Http3Client::insecure().expect("first h3 client");
    let first_url = format!(
        "https://localhost:{}/h3-local-policy/first",
        gateway.https_port
    );
    let first = tokio::spawn(async move { retry_h3_get(&first_client, &first_url).await });

    wait_for_hits(&backend_hits, 1, Duration::from_secs(10)).await;

    let second_client = Http3Client::insecure().expect("second h3 client");
    let second_url = format!(
        "https://localhost:{}/h3-local-policy/second",
        gateway.https_port
    );
    let second = retry_h3_get(&second_client, &second_url).await;
    assert_eq!(
        second.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "second request should be shed by the local pending cap, got {second:?}"
    );
    assert!(
        second.body_text().contains("pending request queue full"),
        "local pending-cap response must not be masked by backend admission or retry: {:?}",
        second.body_text()
    );
    assert_backend_hits_eq(&backend_hits, 1, Duration::from_millis(250)).await;

    release_backend.release();
    let first = first.await.expect("first h3 task joined");
    assert_eq!(
        first.status,
        StatusCode::OK,
        "first held request should complete successfully"
    );

    let third_client = Http3Client::insecure().expect("third h3 client");
    let third_url = format!(
        "https://localhost:{}/h3-local-policy/third",
        gateway.https_port
    );
    let third = retry_h3_get(&third_client, &third_url).await;
    assert_eq!(
        third.status,
        StatusCode::OK,
        "pending permit must be released after the held request completes"
    );
    assert_backend_hits_eq(&backend_hits, 2, Duration::from_millis(250)).await;

    gateway.shutdown().await;
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_h3_local_policy_backend_tls_sni_rejects_before_dial_and_admission() {
    let (backend_port, backend_hits, release_backend, backend_task) = spawn_holding_backend().await;
    let gateway = start_h3_policy_gateway(backend_tls_sni_config(backend_port))
        .await
        .expect("start h3 backend-SNI gateway");

    let hold_client = Http3Client::insecure().expect("hold h3 client");
    let hold_url = format!("https://localhost:{}/h3-admission-hold", gateway.https_port);
    let hold = tokio::spawn(async move { retry_h3_get(&hold_client, &hold_url).await });

    wait_for_hits(&backend_hits, 1, Duration::from_secs(10)).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!(
        "https://localhost:{}/h3-local-policy/sni",
        gateway.https_port
    );
    let resp = retry_h3_get(&client, &url).await;

    assert_eq!(
        resp.status,
        StatusCode::BAD_GATEWAY,
        "backend TLS SNI incompatibility should return 502, got {resp:?}"
    );
    assert_eq!(
        resp.headers
            .get("gateway-error-reason")
            .and_then(|value| value.to_str().ok()),
        Some("backend_tls_sni_requires_direct_h2")
    );
    assert_backend_hits_eq(&backend_hits, 1, Duration::from_millis(250)).await;

    release_backend.release();
    let hold = hold.await.expect("held h3 task joined");
    assert_eq!(
        hold.status,
        StatusCode::OK,
        "admission-saturating request should complete after release"
    );

    gateway.shutdown().await;
    backend_task.abort();
}

struct RunningH3Gateway {
    https_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RunningH3Gateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), self.join)
            .await
            .expect("h3 gateway shutdown timed out")
            .expect("h3 gateway join task panicked");
    }
}

async fn start_h3_policy_gateway(
    config: GatewayConfig,
) -> Result<RunningH3Gateway, Box<dyn std::error::Error + Send + Sync>> {
    let (https_tcp, https_udp) = reserve_colocated_tcp_udp().await?;
    let admin = reserve_port().await?;
    let https_port = https_tcp.port;
    let admin_port = admin.port;
    assert_eq!(https_port, https_udp.port);

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: 0,
        proxy_https_port: https_port,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(H3_POLICY_JWT_SECRET.to_string()),
        admin_jwt_issuer: H3_POLICY_JWT_ISSUER.to_string(),
        frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
        frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
        enable_http3: true,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: H3_POLICY_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let prepared = prepare_gateway_config_for_mesh(config, &mesh_runtime_config()?).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("mesh preparation failed: {e}").into()
        },
    )?;
    assert!(
        prepared.upstreams.iter().any(|upstream| {
            upstream.backend_tls_sni.as_deref() == Some("backend-sni.example.com")
                || upstream
                    .port_overrides
                    .values()
                    .any(|slot| slot.http1_max_pending_requests == Some(1) || slot.tls.is_some())
        }),
        "mesh DestinationRule was not projected onto upstream port overrides"
    );

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: H3_POLICY_JWT_SECRET.to_string(),
        issuer: H3_POLICY_JWT_ISSUER.to_string(),
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let opts = ServeOptions {
        proxy_https: Some(https_tcp.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };
    drop(https_udp);

    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, prepared, opts, shutdown_tx.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {e}").into()
        })?;
    let join = tokio::spawn(async move {
        if let Err(err) = handles.join().await {
            eprintln!("in-process h3 policy gateway listener panicked: {err}");
        }
    });

    Ok(RunningH3Gateway {
        https_port,
        shutdown_tx,
        join,
    })
}

fn mesh_runtime_config() -> Result<MeshRuntimeConfig, String> {
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        namespace: H3_POLICY_NAMESPACE.to_string(),
        mesh_config_protocol: "file".to_string(),
        mesh_file_config_path: Some("tests/fixtures/h3-local-policy-mesh.yaml".to_string()),
        ..EnvConfig::default()
    };
    MeshRuntimeConfig::from_env_config(&env_config)
}

const H3_POLICY_NAMESPACE: &str = "ferrum";
const H3_POLICY_UPSTREAM_ID: &str = "h3-local-policy-upstream";
const H3_POLICY_HOLD_UPSTREAM_ID: &str = "h3-local-policy-hold-upstream";
const H3_POLICY_JWT_SECRET: &str = "ferrum-edge-h3-local-policy-secret-0000";
const H3_POLICY_JWT_ISSUER: &str = "ferrum-edge-h3-local-policy";

fn pending_cap_config(backend_port: u16) -> GatewayConfig {
    h3_policy_config(
        backend_port,
        "http",
        json!({
            "connection_pool_http": {
                "http1_max_pending_requests": 1
            }
        }),
        Some(json!({
            "max_retries": 2,
            "retryable_status_codes": [503],
            "retryable_methods": ["GET"],
            "retry_on_connect_failure": true
        })),
    )
}

fn backend_tls_sni_config(backend_port: u16) -> GatewayConfig {
    let mut config = h3_policy_config(
        backend_port,
        "https",
        json!({
            "tls": {
                "sni": "backend-sni.example.com"
            }
        }),
        None,
    );
    config.proxies.push(
        serde_json::from_value(json!({
            "id": "h3-local-policy-admission-hold",
            "namespace": H3_POLICY_NAMESPACE,
            "listen_path": "/h3-admission-hold",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "upstream_id": H3_POLICY_HOLD_UPSTREAM_ID,
            "pool_enable_http2": false
        }))
        .expect("hold proxy config is valid"),
    );
    config.upstreams.push(
        serde_json::from_value(json!({
            "id": H3_POLICY_HOLD_UPSTREAM_ID,
            "namespace": H3_POLICY_NAMESPACE,
            "name": "H3 local policy admission hold upstream",
            "algorithm": "round_robin",
            "targets": [{
                "host": "127.0.0.1",
                "port": backend_port,
                "weight": 1
            }]
        }))
        .expect("hold upstream config is valid"),
    );
    config
}

fn h3_policy_config(
    backend_port: u16,
    backend_scheme: &str,
    traffic_policy: serde_json::Value,
    retry: Option<serde_json::Value>,
) -> GatewayConfig {
    let mut proxy = json!({
        "id": "h3-local-policy",
        "namespace": H3_POLICY_NAMESPACE,
        "listen_path": "/h3-local-policy",
        "backend_scheme": backend_scheme,
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "backend_tls_verify_server_cert": false,
        "strip_listen_path": true,
        "upstream_id": H3_POLICY_UPSTREAM_ID,
        "pool_enable_http2": false
    });
    if let Some(retry) = retry {
        proxy["retry"] = retry;
    }

    serde_json::from_value(json!({
        "version": "1",
        "proxies": [proxy],
        "upstreams": [{
            "id": H3_POLICY_UPSTREAM_ID,
            "namespace": H3_POLICY_NAMESPACE,
            "name": "H3 local policy upstream",
            "algorithm": "round_robin",
            "targets": [{
                "host": "127.0.0.1",
                "port": backend_port,
                "weight": 1
            }]
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "h3-local-policy-admission",
            "namespace": H3_POLICY_NAMESPACE,
            "plugin_name": "adaptive_concurrency",
            "scope": "global",
            "enabled": true,
            "config": {
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1,
                "key_by": "backend_target"
            }
        }],
        "mesh": {
            "destination_rules": [{
                "name": "h3-local-policy-dr",
                "namespace": H3_POLICY_NAMESPACE,
                "host": H3_POLICY_UPSTREAM_ID,
                "traffic_policy": traffic_policy
            }]
        }
    }))
    .expect("h3 policy config is valid")
}

struct ReleaseGate {
    released: AtomicBool,
    notify: Notify,
}

impl ReleaseGate {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

async fn spawn_holding_backend() -> (u16, Arc<AtomicUsize>, Arc<ReleaseGate>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind holding backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(ReleaseGate::new());
    let task = tokio::spawn(run_holding_backend(
        listener,
        Arc::clone(&hits),
        Arc::clone(&release),
    ));
    (port, hits, release, task)
}

async fn run_holding_backend(
    listener: TcpListener,
    hits: Arc<AtomicUsize>,
    release: Arc<ReleaseGate>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            let _ = read_http_request(stream, &hits, Some(release)).await;
        });
    }
}

async fn read_http_request(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    release: Option<Arc<ReleaseGate>>,
) -> std::io::Result<()> {
    let mut buf = vec![0; 8192];
    let mut read = 0;
    loop {
        let n = stream.read(&mut buf[read..]).await?;
        if n == 0 {
            return Ok(());
        }
        read += n;
        if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
    hits.fetch_add(1, Ordering::SeqCst);
    if let Some(release) = release {
        release.wait().await;
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn retry_h3_get(client: &Http3Client, url: &str) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.get(url).await {
            Ok(resp) => return resp,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 request did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

async fn wait_for_hits(hits: &AtomicUsize, expected: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if hits.load(Ordering::SeqCst) >= expected {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "backend saw {} hits, expected at least {expected}",
        hits.load(Ordering::SeqCst)
    );
}

async fn assert_backend_hits_eq(hits: &AtomicUsize, expected: usize, delay: Duration) {
    sleep(delay).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        expected,
        "unexpected backend admission count"
    );
}
