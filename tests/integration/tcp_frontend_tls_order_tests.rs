//! Regression tests for TCP frontend TLS connection ordering.
//!
//! For TLS-terminating TCP proxies, Ferrum must complete the downstream TLS
//! handshake and run stream-connect plugins before opening the backend socket.
//! That keeps frontend TLS failures and plugin rejects from consuming upstream
//! capacity or being misclassified as backend failures.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;
use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::ProxyProtocol;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::tcp_proxy::{TcpListenerConfig, TcpProxyMetrics, start_tcp_listener};
use ferrum_edge::request_epoch::RequestEpochStore;
use ferrum_edge::tls::NoVerifier;

use crate::scaffolding::ports::reserve_port;

const PROXY_ID: &str = "frontend-tls-order-proxy";
const DENY_LOCALHOST_PLUGIN_ID: &str = "deny-localhost";
const ALLOW_LOCALHOST_PLUGIN_ID: &str = "allow-localhost";
const STDOUT_LOGGING_PLUGIN_ID: &str = "stdout-logging";
#[cfg(unix)]
const STDOUT_LOGGING_CHILD_ENV: &str = "INTEGRATION_TEST_TCP_TLS_STDOUT_LOGGING_CHILD";
#[cfg(unix)]
const STDOUT_LOGGING_TEST_NAME: &str = concat!(
    "integration::tcp_frontend_tls_order_tests::",
    "tcp_tls_frontend_handshake_failure_logs_client_side_disconnect_summary",
);
const MAX_GATEWAY_ATTEMPTS: u32 = 3;
const PER_ATTEMPT_STARTED_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn tcp_tls_proxy(listen_port: u16, backend_port: u16, plugin_config_ids: &[String]) -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("frontend tls ordering".to_string()),
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: DispatchKind::from(BackendScheme::Tcp),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 1_000,
        backend_read_timeout_ms: 0,
        backend_write_timeout_ms: 0,
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
        plugins: plugin_config_ids
            .iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.clone(),
            })
            .collect(),
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(listen_port),
        frontend_tls: true,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(0),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn deny_localhost_plugin_config() -> PluginConfig {
    PluginConfig {
        id: DENY_LOCALHOST_PLUGIN_ID.to_string(),
        plugin_name: "ip_restriction".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "deny": ["127.0.0.1"],
            "mode": "deny_first"
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn allow_localhost_plugin_config() -> PluginConfig {
    PluginConfig {
        id: ALLOW_LOCALHOST_PLUGIN_ID.to_string(),
        plugin_name: "ip_restriction".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({
            "allow": ["127.0.0.1"],
            "mode": "allow_first"
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn stdout_logging_plugin_config() -> PluginConfig {
    PluginConfig {
        id: STDOUT_LOGGING_PLUGIN_ID.to_string(),
        plugin_name: "stdout_logging".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn build_frontend_tls_config() -> Arc<rustls::ServerConfig> {
    let cert_pem = std::fs::read("tests/certs/server.crt").expect("read test cert");
    let key_pem = std::fs::read("tests/certs/server.key").expect("read test key");

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .filter_map(|cert| cert.ok())
            .collect();
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse test key")
        .expect("test key exists");

    let provider = rustls::crypto::ring::default_provider();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build frontend TLS config"),
    )
}

fn insecure_tls_connector() -> tokio_rustls::TlsConnector {
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn spawn_counting_backend(
    listener: TcpListener,
    accepted: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _addr)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
            });
        }
    })
}

fn spawn_echo_backend(
    listener: TcpListener,
    accepted: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _addr)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    })
}

async fn spawn_tcp_tls_gateway_with_retry(
    backend_port: u16,
    plugin_configs: Vec<PluginConfig>,
) -> (u16, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let mut last_port = 0;
    for attempt in 1..=MAX_GATEWAY_ATTEMPTS {
        let frontend = reserve_port().await.expect("reserve frontend port");
        let listen_port = frontend.drop_and_take_port();
        last_port = listen_port;
        if let Some(handles) =
            try_spawn_tcp_tls_gateway(backend_port, listen_port, plugin_configs.clone()).await
        {
            return handles;
        }
        eprintln!(
            "TCP-TLS gateway start attempt {attempt}/{MAX_GATEWAY_ATTEMPTS} on port \
             {listen_port} failed; retrying"
        );
        if attempt < MAX_GATEWAY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    panic!(
        "TCP-TLS gateway listener never reported started=true after \
         {MAX_GATEWAY_ATTEMPTS} attempts; last attempted port: {last_port}"
    );
}

async fn try_spawn_tcp_tls_gateway(
    backend_port: u16,
    listen_port: u16,
    plugin_configs: Vec<PluginConfig>,
) -> Option<(u16, watch::Sender<bool>, tokio::task::JoinHandle<()>)> {
    let plugin_config_ids: Vec<String> = plugin_configs
        .iter()
        .map(|plugin_config| plugin_config.id.clone())
        .collect();
    let proxy = tcp_tls_proxy(listen_port, backend_port, &plugin_config_ids);
    let gateway_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plugin_cache = Arc::new(PluginCache::new(&gateway_config).expect("build plugin cache"));
    if !gateway_config.plugin_configs.is_empty() {
        let attached =
            plugin_cache.get_plugins_for_protocol("ferrum", PROXY_ID, ProxyProtocol::Tcp);
        let attached_names: Vec<&str> = attached.iter().map(|p| p.name()).collect();
        for plugin_config in &gateway_config.plugin_configs {
            assert!(
                attached_names.contains(&plugin_config.plugin_name.as_str()),
                "{} should attach to TCP/TLS proxy; got {:?}",
                plugin_config.plugin_name,
                attached_names
            );
        }
    }

    let consumer_index = Arc::new(ConsumerIndex::new(&gateway_config.consumers));
    let load_balancer_cache = Arc::new(LoadBalancerCache::new(&gateway_config));
    let request_epoch = Arc::new(RequestEpochStore::from_runtime_parts(
        gateway_config.clone(),
        &plugin_cache,
        &consumer_index,
        &load_balancer_cache,
    ));
    let started = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config_swap = Arc::new(ArcSwap::from_pointee(gateway_config));

    let listener_started = started.clone();
    let join = tokio::spawn(async move {
        let cfg = TcpListenerConfig {
            port: listen_port,
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            proxy_id: PROXY_ID.to_string(),
            proxy_namespace: ferrum_edge::config::types::default_namespace(),
            config: config_swap,
            dns_cache: DnsCache::new(DnsConfig::default()),
            request_epoch,
            health_checker: Arc::new(ferrum_edge::health_check::HealthChecker::new()),
            frontend_tls_slot: Arc::new(arc_swap::ArcSwap::new(Arc::new(Some(
                build_frontend_tls_config(),
            )))),
            shutdown: shutdown_rx,
            global_shutdown: None,
            metrics: Arc::new(TcpProxyMetrics::default()),
            tls_no_verify: false,
            tls_ca_bundle_path: None,
            tcp_idle_timeout_seconds: 0,
            tcp_half_close_max_wait_seconds: 0,
            frontend_tls_handshake_timeout_seconds: 2,
            circuit_breaker_cache: Arc::new(CircuitBreakerCache::new()),
            tls_policy: None,
            crls: Arc::new(Vec::new()),
            started: listener_started,
            sni_proxy_ids: None,
            adaptive_buffer: Arc::new(AdaptiveBufferTracker::new(
                true, true, 300, 8192, 262_144, 65_536, 6000,
            )),
            tcp_fastopen_enabled: false,
            tcp_listen_backlog: 2048,
            accept_threads: 1,
            tcp_fastopen_queue_len: 256,
            overload: Arc::new(OverloadState::new()),
            ktls_enabled: false,
            io_uring_splice_enabled: false,
            record_mesh_mtls_metric: false,
            mesh_outbound_enforcement: ferrum_edge::modes::mesh::outbound_enforcement::empty_slot(),
            node_waypoint_identity_resolver: None,
            trusted_proxies: Arc::new(TrustedProxies::none()),
        };
        let _ = start_tcp_listener(cfg).await;
    });

    let deadline = std::time::Instant::now() + PER_ATTEMPT_STARTED_TIMEOUT;
    loop {
        if started.load(Ordering::Acquire) {
            return Some((listen_port, shutdown_tx, join));
        }
        if join.is_finished() {
            let _ = join.await;
            return None;
        }
        if std::time::Instant::now() > deadline {
            let _ = shutdown_tx.send(true);
            join.abort();
            let _ = join.await;
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn shutdown_gateway_or_panic(
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
) {
    shutdown_tx
        .send(true)
        .expect("listener task should still hold the shutdown receiver");
    match tokio::time::timeout(TEST_TIMEOUT, join).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("listener task panicked during shutdown: {e:?}"),
        Err(_) => panic!("listener task did not exit within {TEST_TIMEOUT:?}"),
    }
}

async fn is_closed_by_peer<S>(stream: &mut S) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut probe = [0u8; 1];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, stream.read(&mut probe)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

async fn assert_backend_never_dialed(accepted: &AtomicUsize) {
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "frontend TLS setup failure or plugin rejection must not open a backend connection"
    );
}

async fn assert_backend_was_dialed(accepted: &AtomicUsize) {
    for _ in 0..100 {
        if accepted.load(Ordering::SeqCst) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("successful TCP/TLS setup should open a backend connection");
}

/// Pulls a stream summary out of stdout captured by [`StdoutRedirect`].
/// `stdout_logging` writes its JSON line straight to the process's
/// stdout fd through the installed non-blocking stdout sink, never through
/// a `tracing_subscriber::fmt`-backed buffer. The matching summary is the JSON
/// line carrying our proxy id.
fn parse_direct_write_stream_summary(captured: &str) -> Option<Value> {
    captured
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|line| {
            line.is_object() && line.get("proxy_id").and_then(Value::as_str) == Some(PROXY_ID)
        })
}

/// `libc::dup2` redirect of `STDOUT_FILENO` into a tempfile, so a test can
/// observe what the injected non-blocking `stdout_logging` sink emits. The
/// returned guard restores the original stdout fd on drop, even on panic.
///
/// The test body always runs in an explicit child process, so this process-
/// global redirect and the process-sink `OnceLock` cannot bleed into another
/// test under either nextest or the standard libtest runner. The single-threaded
/// `current_thread` runtime keeps gateway/listener tasks and the sink worker in
/// the same child process whose stdout is redirected.
#[cfg(unix)]
struct StdoutRedirect {
    file: tempfile::NamedTempFile,
    saved_fd: std::os::fd::RawFd,
}

#[cfg(unix)]
impl StdoutRedirect {
    fn install() -> Self {
        use std::os::fd::AsRawFd;
        let file = tempfile::NamedTempFile::new().expect("temp file for stdout capture");
        let target_fd = file.as_file().as_raw_fd();
        // SAFETY: `STDOUT_FILENO` is always a valid file descriptor in a
        // hosted Rust program; the dup/dup2 pair is the standard
        // stdout-redirect dance and is undone in `Drop`.
        let saved_fd = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved_fd >= 0, "dup(STDOUT_FILENO) failed");
        let rc = unsafe { libc::dup2(target_fd, libc::STDOUT_FILENO) };
        assert!(rc >= 0, "dup2(target, STDOUT_FILENO) failed");
        Self { file, saved_fd }
    }

    fn drain(&self) -> String {
        // Flush libc's stdout buffer and Rust's stdout buffer so anything
        // pending lands in the file before we read it.
        std::io::Write::flush(&mut std::io::stdout()).ok();
        unsafe {
            libc::fflush(std::ptr::null_mut());
        }
        std::fs::read_to_string(self.file.path()).unwrap_or_default()
    }
}

#[cfg(unix)]
impl Drop for StdoutRedirect {
    fn drop(&mut self) {
        // SAFETY: `saved_fd` came from `libc::dup(STDOUT_FILENO)` in
        // `install()` and we close it after restoring.
        unsafe {
            libc::dup2(self.saved_fd, libc::STDOUT_FILENO);
            libc::close(self.saved_fd);
        }
    }
}

#[tokio::test]
async fn tcp_tls_successful_plugin_pass_dials_backend_and_relays_data() {
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_accepts = Arc::new(AtomicUsize::new(0));
    let backend_task = spawn_echo_backend(backend.into_listener(), backend_accepts.clone());

    let (listen_port, shutdown_tx, join) =
        spawn_tcp_tls_gateway_with_retry(backend_port, vec![allow_localhost_plugin_config()]).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let tcp = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to frontend TLS listener");
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost").expect("valid test server name");
    let mut tls = insecure_tls_connector()
        .connect(server_name, tcp)
        .await
        .expect("frontend TLS handshake should complete");

    let payload = b"frontend-tls-happy-path";
    tls.write_all(payload)
        .await
        .expect("write payload through gateway");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(TEST_TIMEOUT, tls.read_exact(&mut echoed))
        .await
        .expect("timed out waiting for backend echo through gateway")
        .expect("read backend echo through gateway");
    assert_eq!(echoed, payload);
    assert_backend_was_dialed(&backend_accepts).await;

    let _ = tls.shutdown().await;
    backend_task.abort();
    let _ = backend_task.await;
    shutdown_gateway_or_panic(shutdown_tx, join).await;
}

#[tokio::test]
async fn tcp_tls_frontend_handshake_failure_does_not_connect_backend() {
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_accepts = Arc::new(AtomicUsize::new(0));
    let backend_task = spawn_counting_backend(backend.into_listener(), backend_accepts.clone());

    let (listen_port, shutdown_tx, join) =
        spawn_tcp_tls_gateway_with_retry(backend_port, Vec::new()).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let mut client = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to frontend TLS listener");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write invalid TLS bytes");
    let _ = client.shutdown().await;

    assert!(
        is_closed_by_peer(&mut client).await,
        "gateway should close clients that fail frontend TLS"
    );
    assert_backend_never_dialed(&backend_accepts).await;

    backend_task.abort();
    let _ = backend_task.await;
    shutdown_gateway_or_panic(shutdown_tx, join).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn tcp_tls_frontend_handshake_failure_logs_client_side_disconnect_summary() {
    if std::env::var_os(STDOUT_LOGGING_CHILD_ENV).is_none() {
        assert!(
            ferrum_edge::logging::access_log_writer().is_none(),
            "parent test process must not have process log sinks installed"
        );
        let status = std::process::Command::new(
            std::env::current_exe().expect("resolve integration test executable"),
        )
        .env(STDOUT_LOGGING_CHILD_ENV, "1")
        .args(["--exact", STDOUT_LOGGING_TEST_NAME, "--nocapture"])
        .status()
        .expect("run isolated stdout_logging integration test");
        assert!(status.success(), "isolated stdout_logging test failed");
        assert!(
            ferrum_edge::logging::access_log_writer().is_none(),
            "child test must not mutate the parent process log sinks"
        );
        return;
    }

    // Capture stdout at the libc fd level, then explicitly install the same
    // bounded non-blocking sink shape that the binary installs in this isolated
    // child. The redirect is undone on `Drop` for resilience against panic.
    let stdout_capture = StdoutRedirect::install();
    let sink_options = ferrum_edge::logging::NonBlockingOptions {
        record_capacity: 8,
        byte_capacity: 512 * 1024,
        max_record_bytes: 64 * 1024,
        shutdown_timeout: Duration::from_secs(1),
    };
    let (stdout_sink, mut stdout_guard) = ferrum_edge::logging::NonBlockingSink::spawn(
        ferrum_edge::logging::SinkName::Stdout,
        std::io::stdout(),
        sink_options,
    )
    .expect("spawn test stdout sink");
    let (stderr_sink, mut stderr_guard) = ferrum_edge::logging::NonBlockingSink::spawn(
        ferrum_edge::logging::SinkName::Stderr,
        std::io::sink(),
        sink_options,
    )
    .expect("spawn test stderr sink");
    stdout_sink
        .set_failure_fallback(stderr_sink.clone())
        .expect("install separate test stderr fallback");
    ferrum_edge::logging::set_process_log_sinks(stdout_sink, stderr_sink)
        .expect("install test process log sinks");

    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_accepts = Arc::new(AtomicUsize::new(0));
    let backend_task = spawn_counting_backend(backend.into_listener(), backend_accepts.clone());

    let (listen_port, shutdown_tx, join) =
        spawn_tcp_tls_gateway_with_retry(backend_port, vec![stdout_logging_plugin_config()]).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let mut client = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to frontend TLS listener");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write invalid TLS bytes");
    let _ = client.shutdown().await;
    assert!(
        is_closed_by_peer(&mut client).await,
        "gateway should close clients that fail frontend TLS"
    );
    assert_backend_never_dialed(&backend_accepts).await;

    // Poll the redirected stdout until the gateway has flushed the
    // stream summary (or we exceed `TEST_TIMEOUT`).
    let summary = {
        let mut summary = None;
        let deadline = std::time::Instant::now() + TEST_TIMEOUT;
        while std::time::Instant::now() < deadline {
            if let Some(found) = parse_direct_write_stream_summary(&stdout_capture.drain()) {
                summary = Some(found);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        summary.unwrap_or_else(|| {
            panic!(
                "stdout_logging did not emit a stream summary within {:?}; captured stdout:\n{}",
                TEST_TIMEOUT,
                stdout_capture.drain()
            )
        })
    };
    assert_eq!(
        summary.get("disconnect_direction").and_then(Value::as_str),
        Some("client_to_backend"),
        "frontend TLS failure should log as client-side direction: {summary}"
    );
    assert_eq!(
        summary.get("disconnect_cause").and_then(Value::as_str),
        Some("recv_error"),
        "frontend TLS failure should log as recv_error: {summary}"
    );
    assert_eq!(summary.get("bytes_sent").and_then(Value::as_u64), Some(0));
    assert_eq!(
        summary.get("bytes_received").and_then(Value::as_u64),
        Some(0)
    );
    assert!(
        summary
            .get("connection_error")
            .and_then(Value::as_str)
            .is_some_and(|err| err.contains("Frontend TLS handshake failed")),
        "stream summary should preserve frontend TLS setup error: {summary}"
    );

    backend_task.abort();
    let _ = backend_task.await;
    shutdown_gateway_or_panic(shutdown_tx, join).await;
    assert!(stdout_guard.shutdown(), "test stdout sink should drain");
    assert!(stderr_guard.shutdown(), "test stderr sink should drain");
    drop(stdout_capture);
}

#[tokio::test]
async fn tcp_tls_stream_plugin_rejection_does_not_connect_backend() {
    let backend = reserve_port().await.expect("reserve backend port");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_accepts = Arc::new(AtomicUsize::new(0));
    let backend_task = spawn_counting_backend(backend.into_listener(), backend_accepts.clone());

    let (listen_port, shutdown_tx, join) =
        spawn_tcp_tls_gateway_with_retry(backend_port, vec![deny_localhost_plugin_config()]).await;
    let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

    let tcp = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to frontend TLS listener");
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost").expect("valid test server name");
    let mut tls = insecure_tls_connector()
        .connect(server_name, tcp)
        .await
        .expect("frontend TLS handshake should complete before plugin rejection");

    let _ = tls.write_all(b"probe").await;
    assert!(
        is_closed_by_peer(&mut tls).await,
        "gateway should close clients rejected by stream-connect plugins"
    );
    assert_backend_never_dialed(&backend_accepts).await;

    backend_task.abort();
    let _ = backend_task.await;
    shutdown_gateway_or_panic(shutdown_tx, join).await;
}
