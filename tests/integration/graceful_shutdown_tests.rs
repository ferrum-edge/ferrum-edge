//! Integration tests for graceful shutdown of HTTP/1.1, HTTP/2, and HTTP/3
//! proxy listeners.
//!
//! Bugs covered:
//! - HTTP/2 connections used to keep accepting new streams indefinitely after
//!   the listener exited because the per-connection `serve_connection_with_upgrades`
//!   future was not signalled — clients only learnt about shutdown when
//!   `FERRUM_SHUTDOWN_DRAIN_SECONDS` finally elapsed and the runtime tore the
//!   socket down. The fix calls `Connection::graceful_shutdown()` on the pinned
//!   hyper connection so an HTTP/2 GOAWAY frame is sent and the client closes
//!   cleanly.
//! - HTTP/3 (QUIC) connections used to be torn down by a synchronous
//!   `endpoint.close()` inside the listener's `tokio::select!` — every
//!   in-flight stream observed an immediate CONNECTION_CLOSE, regardless of
//!   the configured drain window. The fix stops accepting via
//!   `set_server_config(None)`, waits for in-flight connections to drain
//!   (bounded by `FERRUM_SHUTDOWN_DRAIN_SECONDS`), and only then calls
//!   `endpoint.close()` + `wait_idle()`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};

// ── Test fixtures (mirrors grpc_proxy_tests + connection_pool_tests) ───────

fn create_test_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Graceful Shutdown Test {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_test_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        // Tests don't want the listener to skip the GOAWAY path. Use a
        // non-zero drain so the listener waits for in-flight requests if
        // the bug regresses.
        shutdown_drain_seconds: 5,
        max_connections: 0,
        ..ferrum_edge::config::EnvConfig::default()
    }
}

fn create_test_proxy_state(proxies: Vec<Proxy>) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig::default());
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
        mesh_revision: None,
        k8s_mesh_overlay: Default::default(),
    };
    ProxyState::new(config, dns_cache, create_test_env_config(), None, None)
        .unwrap()
        .0
}

/// Start a plain HTTP/1.1 backend that responds 200 OK on every request.
async fn start_h1_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Verify HTTP/2 connections receive a GOAWAY when the gateway shuts down,
/// instead of being held open until the drain timeout fires.
///
/// Pre-fix: the per-connection task awaited `serve_connection_with_upgrades`
/// indefinitely after the listener loop exited. The H2 client only saw the
/// connection close when the runtime dropped the socket, which never happened
/// inside the test because `start_proxy_listener_with_bound_listener` returns
/// once the listener exits — leaving the connection task orphaned. The H2
/// client `conn.await` would block until the test timeout fired.
///
/// Post-fix: the connection task observes the shutdown watch channel and
/// calls `Connection::graceful_shutdown()`, which sends GOAWAY. The H2 client
/// `conn.await` resolves promptly. We give it 2 seconds (well under the
/// 5-second drain configured above) to prove the shutdown is GOAWAY-driven
/// and not drain-timeout-driven.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_connection_receives_goaway_on_shutdown() {
    use hyper::client::conn::http2;

    let (backend_addr, _backend_handle) = start_h1_backend().await;
    let proxy = create_test_proxy("h2-shutdown", "/api", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });

    // Give the listener a moment to start its accept loop.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Open an H2 client connection. Drive a successful request first to
    // verify the connection is in the steady state (not still mid-handshake).
    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method("GET")
        .uri("/api/")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.expect("first request");
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.into_body().collect().await;

    // Now signal shutdown. Without graceful_shutdown(), the per-connection
    // task in the gateway would keep the H2 connection alive until the runtime
    // exits (5s drain in this test) — `conn_task` would block until then.
    let shutdown_start = std::time::Instant::now();
    shutdown_tx.send(true).expect("send shutdown");

    // The client connection task should resolve quickly: the server sent
    // GOAWAY and the client observes that as a clean connection close.
    let conn_result = tokio::time::timeout(Duration::from_secs(2), conn_task)
        .await
        .expect("H2 client connection did not close within 2s — GOAWAY missing");
    assert!(
        conn_result.is_ok(),
        "client conn task panicked: {conn_result:?}"
    );
    let elapsed = shutdown_start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "GOAWAY-driven shutdown should be sub-second, got {:?}",
        elapsed
    );

    // The listener task should also exit promptly once the per-connection
    // tasks finish (no orphaned guards keeping it pinned).
    let _ = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
}

/// Verify HTTP/1.1 keepalive connections are closed cleanly on shutdown.
/// Pre-fix the H1 connection's keepalive loop stayed open just like H2 — the
/// fix is the same `graceful_shutdown()` call on the hyper connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_keepalive_connection_closes_on_shutdown() {
    use http_body_util::Empty;
    use hyper::client::conn::http1;

    let (backend_addr, _backend_handle) = start_h1_backend().await;
    let proxy = create_test_proxy("h1-shutdown", "/api", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // H1 client with keepalive — issue a request, then keep the connection
    // idle. The hyper client's connection task only ends when the server
    // closes the socket.
    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Empty<Bytes>>(io).await.unwrap();
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method("GET")
        .uri("/api/")
        .header("host", "127.0.0.1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.expect("first request");
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.into_body().collect().await;
    drop(sender);

    let shutdown_start = std::time::Instant::now();
    shutdown_tx.send(true).expect("send shutdown");

    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task)
        .await
        .expect("H1 keepalive connection did not close within 2s after shutdown");

    let elapsed = shutdown_start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "graceful close should be sub-second, got {:?}",
        elapsed
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
}

/// Regression: when there are no in-flight requests, shutdown is essentially
/// instantaneous — the listener exits, all per-connection tasks observe
/// shutdown and close their pinned connection futures via
/// `graceful_shutdown()`, no drain wait is needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_with_no_active_connections_returns_immediately() {
    let (backend_addr, _backend_handle) = start_h1_backend().await;
    let proxy = create_test_proxy("idle-shutdown", "/api", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = std::time::Instant::now();
    shutdown_tx.send(true).expect("send shutdown");

    tokio::time::timeout(Duration::from_secs(1), listener_handle)
        .await
        .expect("listener did not exit within 1s")
        .expect("listener task panicked");

    assert!(
        start.elapsed() < Duration::from_secs(1),
        "idle shutdown should be sub-second"
    );
}

// ── HTTP/3 shutdown tests ─────────────────────────────────────────────────

/// Build a minimal `rustls::ServerConfig` suitable for the HTTP/3 listener.
/// QUIC mandates TLS 1.3 + ALPN = "h3"; the listener rebuilds the inner
/// config but reads the cert resolver from the one passed in, so this only
/// needs to install a working cert chain.
fn build_h3_test_tls_config(ca: &crate::scaffolding::certs::TestCa) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let (cert_pem, key_pem) = ca.valid().expect("test leaf cert");
    let mut cert_reader = cert_pem.as_bytes();
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|c| c.ok())
        .collect();
    let mut key_reader = key_pem.as_bytes();
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .expect("parse key")
        .expect("non-empty key");

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("with_single_cert");
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn build_h3_test_tls_policy() -> ferrum_edge::tls::TlsPolicy {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    ferrum_edge::tls::TlsPolicy {
        protocol_versions: vec![&rustls::version::TLS13],
        crypto_provider: provider,
        prefer_server_cipher_order: true,
        session_cache_size: 4096,
        early_data_max_size: 0,
    }
}

fn ensure_crypto_provider_installed() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Verify the HTTP/3 listener exits promptly (well under
/// `FERRUM_SHUTDOWN_DRAIN_SECONDS`) on shutdown when no QUIC connections
/// are active. Pre-fix this also exited promptly — but ALL connections
/// that DID exist were forcefully closed via synchronous `endpoint.close()`,
/// killing in-flight streams. The smoke test here is structural: it proves
/// the new shutdown sequence (`set_server_config(None)` → drain wait →
/// `endpoint.close()` → `wait_idle()`) executes end-to-end without
/// deadlocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_shutdown_with_no_connections_returns_promptly() {
    use ferrum_edge::http3::config::Http3ServerConfig;

    ensure_crypto_provider_installed();

    let ca = crate::scaffolding::certs::TestCa::new("h3-shutdown-test").expect("test CA");
    let tls_config = build_h3_test_tls_config(&ca);
    let tls_policy = build_h3_test_tls_policy();

    // Use file-mode env config but keep drain at 5s — the test expects
    // shutdown to return well before that limit even with the drain wait
    // logic in place.
    let mut env_config = create_test_env_config();
    env_config.enable_http3 = true;
    env_config.shutdown_drain_seconds = 5;
    let state = create_test_proxy_state_with_env(vec![], env_config);

    // Reserve a UDP socket for the QUIC listener via an ephemeral port.
    let udp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let h3_config = Http3ServerConfig::default();

    let listener_handle = tokio::spawn(async move {
        let _ = ferrum_edge::http3::server::start_http3_listener_with_signal(
            udp_addr,
            state,
            shutdown_rx,
            tls_config,
            h3_config,
            &tls_policy,
            ferrum_edge::http3::server::Http3ListenerOptions {
                client_ca_bundle_path: None,
                client_crls: Arc::new(Vec::new()),
                started_tx: None,
                frontend_tls_reload: None,
            },
        )
        .await;
    });

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let start = std::time::Instant::now();
    shutdown_tx.send(true).expect("signal shutdown");

    tokio::time::timeout(Duration::from_secs(2), listener_handle)
        .await
        .expect("H3 listener did not exit within 2s of shutdown")
        .expect("H3 listener task panicked");

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "H3 shutdown should be fast with no active connections, got {:?}",
        elapsed
    );
}

/// Verify the H3 listener honours `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` — the
/// drain wait is skipped entirely and the listener calls
/// `endpoint.close()` immediately, then `wait_idle()` (which is a no-op
/// when nothing is connected). With drain==0 the listener should exit even
/// faster than the standard path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_shutdown_with_zero_drain_returns_immediately() {
    use ferrum_edge::http3::config::Http3ServerConfig;

    ensure_crypto_provider_installed();

    let ca = crate::scaffolding::certs::TestCa::new("h3-zero-drain").expect("test CA");
    let tls_config = build_h3_test_tls_config(&ca);
    let tls_policy = build_h3_test_tls_policy();

    let mut env_config = create_test_env_config();
    env_config.enable_http3 = true;
    env_config.shutdown_drain_seconds = 0;
    let state = create_test_proxy_state_with_env(vec![], env_config);

    let udp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let h3_config = Http3ServerConfig::default();

    let listener_handle = tokio::spawn(async move {
        let _ = ferrum_edge::http3::server::start_http3_listener_with_signal(
            udp_addr,
            state,
            shutdown_rx,
            tls_config,
            h3_config,
            &tls_policy,
            ferrum_edge::http3::server::Http3ListenerOptions {
                client_ca_bundle_path: None,
                client_crls: Arc::new(Vec::new()),
                started_tx: None,
                frontend_tls_reload: None,
            },
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let start = std::time::Instant::now();
    shutdown_tx.send(true).expect("signal shutdown");

    tokio::time::timeout(Duration::from_secs(1), listener_handle)
        .await
        .expect("H3 listener did not exit within 1s of shutdown (drain=0)")
        .expect("H3 listener task panicked");

    assert!(
        start.elapsed() < Duration::from_secs(1),
        "H3 zero-drain shutdown should be sub-second, got {:?}",
        start.elapsed()
    );
}

/// Helper that takes a custom env_config so the H3 test can override
/// `enable_http3` / `shutdown_drain_seconds` independently.
fn create_test_proxy_state_with_env(
    proxies: Vec<Proxy>,
    env_config: ferrum_edge::config::EnvConfig,
) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig::default());
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: None,
        mesh_revision: None,
        k8s_mesh_overlay: Default::default(),
    };
    ProxyState::new(config, dns_cache, env_config, None, None)
        .unwrap()
        .0
}

/// Track that imports are exercised even on platforms where no individual
/// test references them in isolation.
#[allow(dead_code)]
fn _typecheck_dependencies() -> HashMap<String, ()> {
    HashMap::new()
}
