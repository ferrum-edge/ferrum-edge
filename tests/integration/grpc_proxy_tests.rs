//! Integration tests for gRPC reverse proxying through the gateway.
//!
//! These tests verify that:
//! - gRPC requests (application/grpc content-type) are routed through the gRPC proxy path
//! - HTTP/2 h2c (cleartext) works end-to-end
//! - gRPC trailers (grpc-status, grpc-message) are forwarded correctly
//! - gRPC error responses are properly formatted when backend is unavailable
//! - Auth plugins work with gRPC metadata (HTTP/2 headers)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackoffStrategy, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    PluginConfig, PluginScope, Proxy, ResponseBodyMode, RetryConfig, Upstream, UpstreamTarget,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;

/// Create a test proxy configured for gRPC backend.
fn create_grpc_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("gRPC Test Proxy {}", id)),
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

/// Create a test EnvConfig.
fn create_test_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::env_config::OperatingMode::File,
        log_level: "info".into(),
        enable_streaming_latency_tracking: false,
        proxy_http_port: 8000,
        proxy_https_port: 8443,
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        proxy_bind_address: "0.0.0.0".into(),
        admin_http_port: 9000,
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_bind_address: "0.0.0.0".into(),
        allow_insecure_admin_http: false,
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
        db_rejected_delta_backoff_initial_seconds: 1,
        db_rejected_delta_backoff_max_seconds: 30,
        db_rejected_delta_full_reload_threshold: 3,
        db_tls_mode: None,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        file_config_path: Some("/tmp/test-grpc-config.json".into()),
        db_config_backup_path: None,
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: None,
        cp_dp_grpc_jwt_secret: None,
        dp_cp_grpc_urls: Vec::new(),
        dp_cp_failover_primary_retry_secs: 300,
        cp_grpc_tls_cert_path: None,
        cp_grpc_tls_key_path: None,
        cp_grpc_tls_client_ca_path: None,
        dp_grpc_tls_ca_cert_path: None,
        dp_grpc_tls_client_cert_path: None,
        dp_grpc_tls_client_key_path: None,
        dp_grpc_tls_no_verify: false,
        max_header_size_bytes: 32768,
        max_single_header_size_bytes: 16384,
        max_request_body_size_bytes: 10_485_760,
        max_response_body_size_bytes: 10_485_760,
        response_buffer_cutoff_bytes: 65_536,
        h2_coalesce_target_bytes: 131_072,
        dns_ttl_override: None,
        dns_overrides: HashMap::new(),
        dns_resolver_address: None,
        dns_resolver_hosts_file: None,
        dns_order: None,
        dns_min_ttl: 5,
        dns_stale_ttl: 3600,
        dns_error_ttl: 1,
        dns_failed_retry_interval: 10,
        dns_warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
        admin_audit_enabled: false,
        admin_tls_no_verify: false,
        enable_http3: false,
        http3_idle_timeout: 30,
        http3_max_streams: 1000,
        http3_stream_receive_window: 8_388_608,
        http3_receive_window: 33_554_432,
        http3_send_window: 8_388_608,
        http3_connections_per_backend: 4,
        http3_pool_idle_timeout_seconds: 120,
        grpc_pool_ready_wait_ms: 1,
        pool_cleanup_interval_seconds: 30,
        tcp_idle_timeout_seconds: 300,
        udp_max_sessions: 10_000,
        udp_cleanup_interval_seconds: 10,
        tls_min_version: "1.2".into(),
        tls_max_version: "1.3".into(),
        tls_cipher_suites: None,
        tls_prefer_server_cipher_order: true,
        tls_curves: None,
        tls_session_cache_size: 4096,
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: String::new(),
        trusted_proxies: String::new(),
        dns_cache_max_size: 10_000,
        dns_slow_threshold_ms: None,
        real_ip_header: None,
        dtls_cert_path: None,
        dtls_key_path: None,
        dtls_client_ca_cert_path: None,
        plugin_http_slow_threshold_ms: 1000,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        migrate_action: "up".into(),
        migrate_dry_run: false,
        worker_threads: None,
        blocking_threads: None,
        max_connections: 0,
        tcp_listen_backlog: 2048,
        server_http2_max_concurrent_streams: 250,
        ..Default::default()
    }
}

/// Create a ProxyState configured with gRPC proxies.
fn create_test_proxy_state(proxies: Vec<Proxy>) -> ProxyState {
    create_test_proxy_state_with_env(proxies, create_test_env_config())
}

/// Like [`create_test_proxy_state`] but with caller-supplied plugin configs so
/// a test can attach response hooks (e.g. `response_transformer`).
fn create_test_proxy_state_with_plugins(
    proxies: Vec<Proxy>,
    plugin_configs: Vec<PluginConfig>,
) -> ProxyState {
    create_test_proxy_state_with_plugins_and_upstreams(proxies, plugin_configs, Vec::new())
}

fn create_test_proxy_state_with_plugins_and_upstreams(
    proxies: Vec<Proxy>,
    plugin_configs: Vec<PluginConfig>,
    upstreams: Vec<Upstream>,
) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    });
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams,
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let (state, _health_check_handles) =
        ProxyState::new(config, dns_cache, create_test_env_config(), None, None).unwrap();
    state
}

fn attach_grpc_web_deadline_plugins(
    proxy: &mut Proxy,
    deadline_config: serde_json::Value,
) -> Vec<PluginConfig> {
    let proxy_id = proxy.id.clone();
    proxy.plugins = vec![
        ferrum_edge::config::types::PluginAssociation {
            plugin_config_id: "grpc-web-bridge".to_string(),
        },
        ferrum_edge::config::types::PluginAssociation {
            plugin_config_id: "grpc-deadline".to_string(),
        },
    ];
    vec![
        PluginConfig {
            id: "grpc-web-bridge".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "grpc_web".to_string(),
            enabled: true,
            config: serde_json::json!({}),
            scope: PluginScope::Proxy,
            proxy_id: Some(proxy_id.clone()),
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        PluginConfig {
            id: "grpc-deadline".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "grpc_deadline".to_string(),
            enabled: true,
            config: deadline_config,
            scope: PluginScope::Proxy,
            proxy_id: Some(proxy_id),
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ]
}

fn create_test_upstream(id: &str, targets: Vec<UpstreamTarget>) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("gRPC Test Upstream {id}")),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn security_headers_plugin(id: &str) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "security_headers".to_string(),
        enabled: true,
        config: serde_json::json!({
            "override_existing": false,
            "hsts": true,
            "set": { "X-Security-Policy": "gateway-enforced" },
            "remove": []
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Like [`create_test_proxy_state`] but with a caller-supplied `EnvConfig` so a
/// test can override runtime limits (e.g. `max_grpc_recv_size_bytes`).
fn create_test_proxy_state_with_env(
    proxies: Vec<Proxy>,
    env_config: ferrum_edge::config::EnvConfig,
) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
        max_concurrent_refreshes: 64,
        shard_amount: 0,
    });
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let (state, _health_check_handles) =
        ProxyState::new(config, dns_cache, env_config, None, None).unwrap();
    state
}

/// Start a mock gRPC backend (h2c HTTP/2 server) that echoes requests.
///
/// The backend responds with:
/// - `grpc-status: 0` (OK) as a trailer
/// - The request path echoed in a custom `x-echo-path` header
/// - The request body echoed back
async fn start_mock_grpc_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let method = req.method().to_string();

                    // Check for custom test behavior headers
                    let test_status = req
                        .headers()
                        .get("x-test-grpc-status")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u32>().ok());
                    let test_message = req
                        .headers()
                        .get("x-test-grpc-message")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    // Collect the request body
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let grpc_status = test_status.unwrap_or(0);
                    let grpc_message = test_message.unwrap_or_else(|| "OK".to_string());

                    // Build response with gRPC trailers packed into headers
                    // (Trailers-Only encoding for simplicity in tests)
                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", grpc_status.to_string())
                        .header("grpc-message", &grpc_message)
                        .header("x-echo-path", &path)
                        .header("x-echo-method", &method)
                        .body(Full::new(body_bytes))
                        .unwrap();

                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    eprintln!("Mock gRPC backend connection error: {}", e);
                }
            });
        }
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

async fn start_connection_counting_backend()
-> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicUsize::new(0));
    let task_count = Arc::clone(&connection_count);
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_count.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, connection_count, handle)
}

/// Start the gateway proxy listener and return the address.
///
/// Uses an internal listener approach to avoid port race conditions:
/// we accept connections ourselves and feed them to the gateway's handler.
async fn start_test_gateway(state: ProxyState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let mut builder =
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                builder.http1().max_buf_size(state.max_header_size_bytes);
                builder
                    .http2()
                    .max_header_list_size(state.max_header_size_bytes as u32);

                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let addr = remote_addr;
                    async move {
                        ferrum_edge::proxy::handle_proxy_request(
                            req, state, addr, false, None, None,
                        )
                        .await
                    }
                });
                let _ = builder.serve_connection_with_upgrades(io, svc).await;
            });
        }
    });

    // Give the listener a moment to start
    tokio::time::sleep(Duration::from_millis(20)).await;

    (gateway_addr, handle)
}

/// Send a gRPC-like request through the gateway using hyper's HTTP/2 client.
async fn send_grpc_request(
    gateway_addr: SocketAddr,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");

    for (k, v) in extra_headers {
        req_builder = req_builder.header(*k, *v);
    }

    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    // Collect body
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();

    Ok((status, headers, body_bytes))
}

#[derive(Clone, Copy, Debug)]
enum TestHttpVersion {
    H1,
    H2,
}

async fn send_http_request(
    gateway_addr: SocketAddr,
    version: TestHttpVersion,
    method: Method,
    path: &str,
    content_type: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    send_http_request_with_accept(gateway_addr, version, method, path, content_type, None).await
}

async fn send_http_request_with_accept(
    gateway_addr: SocketAddr,
    version: TestHttpVersion,
    method: Method,
    path: &str,
    content_type: &str,
    accept: Option<&str>,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    send_http_request_with_body_and_accept(
        gateway_addr,
        version,
        method,
        path,
        content_type,
        accept,
        Bytes::from_static(&[0u8, 0, 0, 0, 0]),
    )
    .await
}

async fn send_http_request_with_body_and_accept(
    gateway_addr: SocketAddr,
    version: TestHttpVersion,
    method: Method,
    path: &str,
    content_type: &str,
    accept: Option<&str>,
    body: Bytes,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::TcpStream::connect(gateway_addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", content_type);
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    let request = request.body(Full::new(body))?;

    let response = match version {
        TestHttpVersion::H1 => {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                if let Err(error) = conn.await {
                    eprintln!("HTTP/1 test client connection error: {error}");
                }
            });
            sender.send_request(request).await?
        }
        TestHttpVersion::H2 => {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            tokio::spawn(async move {
                if let Err(error) = conn.await {
                    eprintln!("HTTP/2 test client connection error: {error}");
                }
            });
            sender.send_request(request).await?
        }
    };

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
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();
    Ok((status, headers, body))
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_accept_negotiates_h1_h2_success_and_rejection_paths() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;
    let mut proxy = create_grpc_proxy("grpc-web-accept", "/grpc-accept", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    attach_test_plugin(&mut proxy, "grpc-web-accept-plugin");
    let plugin = test_plugin_config(
        "grpc-web-accept-plugin",
        "grpc_web",
        "grpc-web-accept",
        serde_json::json!({}),
    );
    let state = create_test_proxy_state_with_plugins(vec![proxy], vec![plugin]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    for version in [TestHttpVersion::H1, TestHttpVersion::H2] {
        let (status, headers, encoded) = send_http_request_with_accept(
            gateway_addr,
            version,
            Method::POST,
            "/grpc-accept/my.Service/Unary",
            "application/grpc-web+json",
            Some("text/html, Application/Grpc-Web-Text+Json; charset=utf-8; Q=0.8"),
        )
        .await
        .unwrap_or_else(|error| panic!("{version:?} text-negotiated request failed: {error}"));
        assert_eq!(status, 200, "{version:?} text-negotiated status");
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc-web-text+json"),
            "{version:?} text-negotiated content type"
        );
        assert!(
            headers
                .get("vary")
                .is_some_and(|vary| vary.split(',').any(|token| token.trim() == "Accept")),
            "{version:?} negotiated response must vary on Accept"
        );
        let decoded = BASE64
            .decode(&encoded)
            .unwrap_or_else(|error| panic!("{version:?} response was not base64: {error}"));
        assert!(
            decoded
                .windows(b"grpc-status: 0".len())
                .any(|window| window == b"grpc-status: 0"),
            "{version:?} text response missing terminal status"
        );

        let text_request = BASE64.encode([0u8, 0, 0, 0, 0]);
        let (status, headers, binary) = send_http_request_with_body_and_accept(
            gateway_addr,
            version,
            Method::POST,
            "/grpc-accept/my.Service/Unary",
            "application/grpc-web-text+custom",
            Some("application/grpc-web; q=1"),
            Bytes::from(text_request),
        )
        .await
        .unwrap_or_else(|error| panic!("{version:?} binary-negotiated request failed: {error}"));
        assert_eq!(status, 200, "{version:?} binary-negotiated status");
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/grpc-web+custom"),
            "{version:?} binary-negotiated content type"
        );
        assert!(
            binary
                .windows(b"grpc-status: 0".len())
                .any(|window| window == b"grpc-status: 0"),
            "{version:?} binary response missing terminal status"
        );

        for accept in ["text/html", "application/grpc-web;q=broken"] {
            let (status, headers, body) = send_http_request_with_accept(
                gateway_addr,
                version,
                Method::POST,
                "/grpc-accept/my.Service/Unary",
                "application/grpc-web+proto",
                Some(accept),
            )
            .await
            .unwrap_or_else(|error| panic!("{version:?} rejected request failed: {error}"));
            assert_eq!(status, 406, "{version:?} rejected Accept {accept}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(headers.get("vary").map(String::as_str), Some("Accept"));
            assert!(!headers.contains_key("x-ferrum-grpc-web-accept-rejected"));
            assert!(String::from_utf8_lossy(&body).contains("Not Acceptable"));
        }
    }
}

fn test_plugin_config(
    id: &str,
    plugin_name: &str,
    proxy_id: &str,
    config: serde_json::Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        enabled: true,
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn attach_test_plugin(proxy: &mut Proxy, plugin_config_id: &str) {
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: plugin_config_id.to_string(),
    }];
}

// --- Integration Tests ---

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_early_rejects_are_browser_safe_on_h1_and_h2() {
    let backend_port = 9;

    let mut allowed = create_grpc_proxy("grpc-web-allowed", "/allowed", backend_port);
    allowed.allowed_methods = Some(vec!["POST".to_string()]);

    let non_post = create_grpc_proxy("grpc-web-non-post", "/non-post", backend_port);

    let mut terminated = create_grpc_proxy("grpc-web-terminated", "/terminated", backend_port);
    attach_test_plugin(&mut terminated, "grpc-web-termination");

    let mut authenticate =
        create_grpc_proxy("grpc-web-authenticate", "/authenticate", backend_port);
    attach_test_plugin(&mut authenticate, "grpc-web-key-auth");

    let mut authorize = create_grpc_proxy("grpc-web-authorize", "/authorize", backend_port);
    attach_test_plugin(&mut authorize, "grpc-web-access-control");

    let mut before_proxy =
        create_grpc_proxy("grpc-web-before-proxy", "/before-proxy", backend_port);
    attach_test_plugin(&mut before_proxy, "grpc-web-deadline");

    let plugins = vec![
        test_plugin_config(
            "grpc-web-termination",
            "request_termination",
            "grpc-web-terminated",
            serde_json::json!({"status_code": 503}),
        ),
        test_plugin_config(
            "grpc-web-key-auth",
            "key_auth",
            "grpc-web-authenticate",
            serde_json::json!({}),
        ),
        test_plugin_config(
            "grpc-web-access-control",
            "access_control",
            "grpc-web-authorize",
            serde_json::json!({"allowed_consumers": ["allowed"]}),
        ),
        test_plugin_config(
            "grpc-web-deadline",
            "grpc_deadline",
            "grpc-web-before-proxy",
            serde_json::json!({"reject_no_deadline": true}),
        ),
    ];
    let state = create_test_proxy_state_with_plugins(
        vec![
            allowed,
            non_post,
            terminated,
            authenticate,
            authorize,
            before_proxy,
        ],
        plugins,
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let cases = [
        (
            Method::POST,
            "/missing/pkg.Service/Call",
            "route miss",
            5u32,
        ),
        (
            Method::PUT,
            "/allowed/pkg.Service/Call",
            "allowed methods",
            12,
        ),
        (Method::GET, "/non-post/pkg.Service/Call", "non-POST", 3),
        (
            Method::POST,
            "/terminated/pkg.Service/Call",
            "on_request_received",
            14,
        ),
        (
            Method::POST,
            "/authenticate/pkg.Service/Call",
            "authenticate",
            16,
        ),
        (Method::POST, "/authorize/pkg.Service/Call", "authorize", 16),
        (
            Method::POST,
            "/before-proxy/pkg.Service/Call",
            "initial before_proxy",
            3,
        ),
    ];

    for version in [TestHttpVersion::H1, TestHttpVersion::H2] {
        for (method, path, phase, grpc_status) in &cases {
            let (status, headers, body) = send_http_request(
                gateway_addr,
                version,
                method.clone(),
                path,
                "application/grpc-web+proto",
            )
            .await
            .unwrap_or_else(|error| panic!("{version:?} {phase} request failed: {error}"));
            assert_eq!(status, 200, "{version:?} {phase} HTTP status");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc-web+proto"),
                "{version:?} {phase} content type"
            );
            assert!(
                !headers.contains_key("grpc-status") && !headers.contains_key("grpc-message"),
                "{version:?} {phase} terminal gRPC metadata must remain body-only"
            );
            assert_eq!(
                body.first(),
                Some(&0x80),
                "{version:?} {phase} trailer flag"
            );
            let expected = format!("grpc-status: {grpc_status}\r\n");
            assert!(
                body.windows(expected.len())
                    .any(|window| window == expected.as_bytes()),
                "{version:?} {phase} trailer body must contain {expected:?}"
            );
        }
    }

    let (status, headers, _) = send_http_request(
        gateway_addr,
        TestHttpVersion::H2,
        Method::POST,
        "/missing/pkg.Service/Call",
        "application/grpc-website",
    )
    .await
    .expect("deceptive content-type request");
    assert_eq!(status, 404);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );

    let (status, headers, body) = send_http_request(
        gateway_addr,
        TestHttpVersion::H2,
        Method::POST,
        "/missing/pkg.Service/Call",
        "application/grpc",
    )
    .await
    .expect("native gRPC route-miss request");
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("5"));
    assert!(
        body.is_empty(),
        "native gRPC reject must remain trailers-only"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_deadline_preflight_precedes_method_policy_on_h1_and_h2() {
    let backend_port = 9;

    let mut method_policy = create_grpc_proxy(
        "grpc-method-before-deadline",
        "/method-policy",
        backend_port,
    );
    method_policy.plugins = ["method-policy-router", "method-policy-deadline"]
        .into_iter()
        .map(
            |plugin_config_id| ferrum_edge::config::types::PluginAssociation {
                plugin_config_id: plugin_config_id.to_string(),
            },
        )
        .collect();

    let mut deadline_only = create_grpc_proxy("grpc-deadline-only", "/deadline-only", backend_port);
    attach_test_plugin(&mut deadline_only, "deadline-only");

    let plugins = vec![
        test_plugin_config(
            "method-policy-router",
            "grpc_method_router",
            "grpc-method-before-deadline",
            serde_json::json!({
                "allow_methods": ["pkg.Service/Allowed", "pkg.Service/RateLimited"],
                "deny_methods": ["pkg.Service/Denied"],
                "method_rate_limits": {
                    "pkg.Service/RateLimited": {
                        "max_requests": 1,
                        "window_seconds": 60
                    }
                }
            }),
        ),
        test_plugin_config(
            "method-policy-deadline",
            "grpc_deadline",
            "grpc-method-before-deadline",
            serde_json::json!({"reject_no_deadline": true}),
        ),
        test_plugin_config(
            "deadline-only",
            "grpc_deadline",
            "grpc-deadline-only",
            serde_json::json!({"reject_no_deadline": true}),
        ),
    ];
    let state = create_test_proxy_state_with_plugins(vec![method_policy, deadline_only], plugins);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    for version in [TestHttpVersion::H1, TestHttpVersion::H2] {
        for (path, case) in [
            (
                "/method-policy/pkg.Service/Denied",
                "method denial hidden by phase-zero deadline policy",
            ),
            (
                "/deadline-only/pkg.Service/Allowed",
                "deadline-only control",
            ),
        ] {
            let (status, headers, body) = send_http_request(
                gateway_addr,
                version,
                Method::POST,
                path,
                "application/grpc-web+proto",
            )
            .await
            .unwrap_or_else(|error| panic!("{version:?} {case} request failed: {error}"));
            assert_eq!(status, 200, "{version:?} {case} HTTP status");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/grpc-web+proto"),
                "{version:?} {case} content type"
            );
            let expected = "grpc-status: 3\r\n";
            assert!(
                body.windows(expected.len())
                    .any(|window| window == expected.as_bytes()),
                "{version:?} {case} must contain {expected:?}"
            );
        }
    }

    // Phase-zero deadline enforcement runs before stateful method policy, so
    // missing-deadline requests neither consume nor reveal the method bucket.
    for _ in 0..2 {
        let (status, _headers, body) = send_http_request(
            gateway_addr,
            TestHttpVersion::H2,
            Method::POST,
            "/method-policy/pkg.Service/RateLimited",
            "application/grpc-web+proto",
        )
        .await
        .expect("H2 rate/deadline ordering request");
        assert_eq!(status, 200);
        let expected = "grpc-status: 3\r\n";
        assert!(
            body.windows(expected.len())
                .any(|window| window == expected.as_bytes()),
            "rate/deadline ordering response must contain {expected:?}"
        );
    }

    let (status, headers, body) = send_http_request(
        gateway_addr,
        TestHttpVersion::H2,
        Method::POST,
        "/method-policy/pkg.Service/Denied",
        "application/grpc",
    )
    .await
    .expect("native H2 method/deadline ordering request");
    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("3"));
    assert!(
        body.is_empty(),
        "native gRPC rejection must remain bodyless"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_unary_proxy_through_gateway() {
    // Start mock gRPC backend
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    // Configure gateway with a gRPC proxy
    let proxy = create_grpc_proxy("grpc-1", "/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Send a gRPC request through the gateway
    let (status, headers, _body) = send_grpc_request(
        gateway_addr,
        "/grpc/my.Service/Echo",
        b"\x00\x00\x00\x00\x05hello",
        &[],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200, "gRPC responses use HTTP 200");
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "Response should have gRPC content type"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "gRPC status should be OK (0)"
    );
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.Service/Echo"),
        "Backend should receive stripped path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_path_stripping() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-strip", "/api/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let (status, headers, _body) =
        send_grpc_request(gateway_addr, "/api/grpc/my.Service/Method", b"", &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.Service/Method"),
        "Listen path should be stripped from backend request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_no_strip_listen_path() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let mut proxy = create_grpc_proxy("grpc-nostrip", "/grpc", backend_addr.port());
    proxy.strip_listen_path = false;
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let (status, headers, _body) =
        send_grpc_request(gateway_addr, "/grpc/my.Service/Method", b"", &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/grpc/my.Service/Method"),
        "Full path including listen_path should be sent to backend"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_error_status_forwarding() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-err", "/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Tell the mock backend to return grpc-status 5 (NOT_FOUND)
    let (status, headers, _body) = send_grpc_request(
        gateway_addr,
        "/grpc/my.Service/Missing",
        b"",
        &[
            ("x-test-grpc-status", "5"),
            ("x-test-grpc-message", "method not found"),
        ],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200, "gRPC errors still use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("5"),
        "Backend grpc-status should be forwarded"
    );
    assert_eq!(
        headers.get("grpc-message").map(|s| s.as_str()),
        Some("method not found"),
        "Backend grpc-message should be forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_backend_unavailable() {
    // Configure a proxy pointing to a port with no backend
    let proxy = create_grpc_proxy("grpc-down", "/grpc", 19999);
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let (status, headers, _body) =
        send_grpc_request(gateway_addr, "/grpc/my.Service/Echo", b"", &[])
            .await
            .expect("Request should complete even if backend is down");

    assert_eq!(status, 200, "gRPC errors use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("14"),
        "Backend unavailable should return grpc-status 14 (UNAVAILABLE)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_metadata_forwarding() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-meta", "/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Send request with custom gRPC metadata headers
    let (status, headers, _body) = send_grpc_request(
        gateway_addr,
        "/grpc/my.Service/Echo",
        b"",
        &[
            ("x-custom-metadata", "test-value"),
            ("authorization", "Bearer test-token"),
        ],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request with metadata should succeed"
    );
    // Method should be POST (standard for gRPC)
    assert_eq!(
        headers.get("x-echo-method").map(|s| s.as_str()),
        Some("POST"),
        "gRPC uses POST method"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_body_forwarding() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-body", "/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // gRPC messages are length-prefixed: [compressed:1byte][length:4bytes][message]
    let grpc_message = b"\x00\x00\x00\x00\x0bhello world";

    let (_status, _headers, body) =
        send_grpc_request(gateway_addr, "/grpc/my.Service/Echo", grpc_message, &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(
        body, grpc_message,
        "Backend should echo the gRPC message body"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_with_backend_path_prefix() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let mut proxy = create_grpc_proxy("grpc-prefix", "/grpc", backend_addr.port());
    proxy.backend_path = Some("/v2".to_string());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let (status, headers, _body) =
        send_grpc_request(gateway_addr, "/grpc/my.Service/Echo", b"", &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/v2/my.Service/Echo"),
        "Backend path prefix should be prepended"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_non_grpc_request_to_grpc_proxy_falls_through() {
    // When a non-gRPC request (no application/grpc content-type) hits a gRPC proxy,
    // it should fall through to the standard HTTP proxy path
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-fallback", "/api", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Send a regular HTTP request (not gRPC) via HTTP/1.1
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/api/health", gateway_addr))
        .header("content-type", "application/json")
        .send()
        .await
        .expect("HTTP request should succeed");

    // This will hit the standard HTTP proxy path and try to connect to the h2c backend
    // which will likely fail since it only speaks HTTP/2, but the point is it doesn't
    // go through the gRPC path (no application/grpc content-type)
    let _status = resp.status().as_u16();
    // We just verify we get a response (not a gRPC-formatted one)
    assert_ne!(
        resp.headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "Non-gRPC requests should not get gRPC-formatted responses"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_multiple_proxies() {
    // Test that multiple gRPC proxies on different paths work correctly
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy1 = create_grpc_proxy("grpc-users", "/users", backend_addr.port());
    let proxy2 = create_grpc_proxy("grpc-orders", "/orders", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy1, proxy2]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Request to first proxy
    let (status1, headers1, _) =
        send_grpc_request(gateway_addr, "/users/user.UserService/GetUser", b"", &[])
            .await
            .expect("First proxy request should succeed");

    assert_eq!(status1, 200);
    assert_eq!(
        headers1.get("x-echo-path").map(|s| s.as_str()),
        Some("/user.UserService/GetUser")
    );

    // Request to second proxy (reuse the h2 connection or make a new one)
    let (status2, headers2, _) = send_grpc_request(
        gateway_addr,
        "/orders/order.OrderService/CreateOrder",
        b"",
        &[],
    )
    .await
    .expect("Second proxy request should succeed");

    assert_eq!(status2, 200);
    assert_eq!(
        headers2.get("x-echo-path").map(|s| s.as_str()),
        Some("/order.OrderService/CreateOrder")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_unmatched_path_returns_grpc_error() {
    let (backend_addr, _backend_handle) = start_mock_grpc_backend().await;

    let proxy = create_grpc_proxy("grpc-specific", "/grpc", backend_addr.port());
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Send to a path that doesn't match any proxy
    let (status, headers, _body) =
        send_grpc_request(gateway_addr, "/unknown/my.Service/Echo", b"", &[])
            .await
            .expect("Request should complete");

    // gRPC requests get trailers-only gRPC errors (HTTP 200 + grpc-status)
    // instead of raw HTTP 404, so gRPC clients can parse the error properly
    assert_eq!(
        status, 200,
        "gRPC route miss should return HTTP 200 with grpc-status"
    );
    let grpc_status = headers.get("grpc-status").expect("should have grpc-status");
    assert_eq!(grpc_status, "5", "Route miss should map to NOT_FOUND (5)");
}

// ─────────────────────────────────────────────────────────────────────────
// Fix 4 regression tests: gRPC server-streaming response with retry
// configured should NOT buffer the entire response body before emitting
// trailers. Before the fix, `grpc_should_stream = !grpc_has_retry && ...`
// forced buffering whenever any retry policy was present, which held
// `grpc-status` trailer behind the final data frame and produced the
// 500 KB p99 = 732 ms pattern observed in CI.
// ─────────────────────────────────────────────────────────────────────────

/// Mock gRPC backend that sends a configurable number of DATA frames with
/// a delay between each, then a trailers-only response. Used to exercise
/// the streaming-response path with a visible gap between body and trailer
/// arrival — if the gateway were buffering, the trailer wall-clock would
/// trail the first data frame by at least N × per-frame delay.
///
/// Implemented as a driven `mpsc` channel rather than `async_stream` since
/// the workspace does not depend on `async-stream`. A backend task sends
/// Frames into the channel with the configured delay; a tokio-stream
/// wrapper converts the Receiver into a Stream for `StreamBody`.
async fn start_streaming_grpc_backend(
    num_frames: usize,
    frame_size: usize,
    per_frame_delay: Duration,
    security_policy_trailer: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use http_body::Frame;
    use http_body_util::StreamBody;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(move |_req: Request<Incoming>| async move {
                    // Channel capacity = 1 so the sender blocks after each
                    // enqueued frame until the gateway actually consumes
                    // it — this is what makes the delay visible end-to-
                    // end. If the channel were unbounded, the sender
                    // would dump all frames into the buffer and the
                    // apparent spread would collapse.
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<Frame<Bytes>, std::convert::Infallible>,
                    >(1);

                    tokio::spawn(async move {
                        for i in 0..num_frames {
                            if i > 0 {
                                tokio::time::sleep(per_frame_delay).await;
                            }
                            let bytes = vec![b'X'; frame_size];
                            if tx.send(Ok(Frame::data(Bytes::from(bytes)))).await.is_err() {
                                return;
                            }
                        }
                        // Terminal trailers frame.
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            hyper::header::HeaderName::from_static("grpc-status"),
                            hyper::header::HeaderValue::from_static("0"),
                        );
                        trailers.insert(
                            hyper::header::HeaderName::from_static("grpc-message"),
                            hyper::header::HeaderValue::from_static("OK"),
                        );
                        if security_policy_trailer {
                            trailers.insert(
                                hyper::header::HeaderName::from_static("x-security-policy"),
                                hyper::header::HeaderValue::from_static("backend-trailer-value"),
                            );
                            trailers.insert(
                                hyper::header::HeaderName::from_static("x-application-trailer"),
                                hyper::header::HeaderValue::from_static("application-value"),
                            );
                        }
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    });

                    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                    let body = StreamBody::new(stream);

                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(body)
                        .unwrap();

                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    eprintln!("Streaming backend connection error: {}", e);
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_buffered_non_empty_response_sends_status_as_trailer() {
    let (backend_addr, _backend_handle) =
        start_streaming_grpc_backend(1, 32, Duration::ZERO, false).await;

    let mut proxy = create_grpc_proxy("grpc-buffered-trailers", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let state = create_test_proxy_state(vec![proxy]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = sender.send_request(req).await.expect("request send failed");
    assert_eq!(response.status(), 200);
    assert!(
        response.headers().get("grpc-status").is_none(),
        "non-empty buffered gRPC responses must not send grpc-status as initial metadata"
    );

    let mut saw_data = false;
    let mut grpc_status = None;
    let mut grpc_message = None;
    let mut body = response.into_body();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.expect("response frame");
        if let Some(data) = frame.data_ref()
            && !data.is_empty()
        {
            saw_data = true;
        }
        if let Some(trailers) = frame.trailers_ref() {
            grpc_status = trailers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            grpc_message = trailers
                .get("grpc-message")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
        }
    }

    assert!(saw_data, "backend DATA frame was not forwarded");
    assert_eq!(grpc_status.as_deref(), Some("0"));
    assert_eq!(grpc_message.as_deref(), Some("OK"));
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_buffered_trailers_only_keeps_status_and_security_policy_initial() {
    let (backend_addr, _backend_handle) =
        start_streaming_grpc_backend(0, 0, Duration::ZERO, true).await;
    let mut proxy = create_grpc_proxy("grpc-trailers-only-policy", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let state = create_test_proxy_state_with_plugins(
        vec![proxy],
        vec![security_headers_plugin("grpc-trailers-only-security")],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let (status, headers, body) =
        send_grpc_request(gateway_addr, "/grpc/my.Service/Unary", b"", &[])
            .await
            .expect("trailers-only gRPC response");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("0"));
    assert_eq!(headers.get("grpc-message").map(String::as_str), Some("OK"));
    assert_eq!(
        headers.get("x-security-policy").map(String::as_str),
        Some("gateway-enforced")
    );
    assert_eq!(
        headers.get("strict-transport-security").map(String::as_str),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        headers.get("x-application-trailer").map(String::as_str),
        Some("application-value")
    );
}

/// Mock gRPC backend that sends a non-empty DATA frame plus a fixed trailer
/// fixture, with `x-dup-key` present in BOTH the initial headers
/// (`header-value`) and the trailers (`trailer-value`), an extra
/// `x-removed-trailer` trailer for a response hook to strip, an
/// `x-shadowed-removed` key duplicated across initial headers AND trailers
/// for a hook to strip from both, a trailer-only `set-cookie`, a shadowed
/// `x-powered-by`, and malformed duplicate `grpc-status` / `grpc-message`
/// initial headers (a non-Trailers-Only response must carry terminal status
/// only in the trailers).
async fn start_grpc_backend_with_trailer_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use http_body::Frame;
    use http_body_util::StreamBody;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(move |_req: Request<Incoming>| async move {
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert(
                        hyper::header::HeaderName::from_static("grpc-status"),
                        hyper::header::HeaderValue::from_static("0"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("grpc-message"),
                        hyper::header::HeaderValue::from_static("OK"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-dup-key"),
                        hyper::header::HeaderValue::from_static("trailer-value"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-removed-trailer"),
                        hyper::header::HeaderValue::from_static("should-not-reach-client"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-security-policy"),
                        hyper::header::HeaderValue::from_static("backend-trailer-value"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-shadowed-removed"),
                        hyper::header::HeaderValue::from_static("trailer-secret"),
                    );
                    trailers.insert(
                        hyper::header::SET_COOKIE,
                        hyper::header::HeaderValue::from_static("session=backend"),
                    );
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-powered-by"),
                        hyper::header::HeaderValue::from_static("backend-trailer"),
                    );
                    // Header-shadowed key that NO hook touches: the wire
                    // trailer must keep the backend's distinct trailing
                    // value, not be clobbered by the initial-header value.
                    trailers.insert(
                        hyper::header::HeaderName::from_static("x-dup-untouched"),
                        hyper::header::HeaderValue::from_static("trailer-untouched"),
                    );

                    // Deterministic frame delivery: a synchronous stream yields the
                    // DATA frame then the TRAILERS frame back-to-back. The previous
                    // spawned-task + mpsc body left a scheduling window between the
                    // two frames; under CI load that window could let the gateway's
                    // buffered gRPC collection observe stream completion before the
                    // trailers were flushed, which manifested as a flaky gateway
                    // gRPC error response (HTTP 200 + `application/grpc`) instead of
                    // the plugin-transformed response.
                    let frames: Vec<Result<Frame<Bytes>, std::convert::Infallible>> = vec![
                        // One valid uncompressed gRPC DATA message: flag 0x00,
                        // 12-byte big-endian payload length, then `grpc-payload`.
                        Ok(Frame::data(Bytes::from_static(
                            b"\x00\x00\x00\x00\x0cgrpc-payload",
                        ))),
                        Ok(Frame::trailers(trailers)),
                    ];
                    let body = StreamBody::new(tokio_stream::iter(frames));

                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("x-dup-key", "header-value")
                        .header("x-shadowed-removed", "header-secret")
                        .header("x-dup-untouched", "header-untouched")
                        .header("x-powered-by", "backend-header")
                        // Malformed duplicates: terminal status must only ride
                        // in the trailers for a non-empty response.
                        .header("grpc-status", "13")
                        .header("grpc-message", "bogus-initial-header-status")
                        .body(body)
                        .unwrap();

                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    eprintln!("Trailer-fixture backend connection error: {}", e);
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

/// gRPC backend that returns response HEADERS + one DATA frame, then ERRORS the
/// response body before any TRAILERS frame (no `grpc-status`). hyper resets the
/// response stream (RST_STREAM), so the gateway's buffered gRPC collection hits
/// a frame-read error mid-collection with no terminal status anywhere.
///
/// This forces, deterministically, the exact gateway backend-exchange failure
/// that issue #2041 hit intermittently under CI load ("stream completion
/// observed before the trailers were flushed"), which the gateway renders
/// through its gRPC backend-error arm.
async fn start_grpc_backend_that_errors_after_data_frame()
-> (SocketAddr, tokio::task::JoinHandle<()>) {
    use http_body::Frame;
    use http_body_util::StreamBody;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(move |_req: Request<Incoming>| async move {
                    // One DATA frame, then a body error → hyper RST_STREAMs the
                    // response before any TRAILERS frame, so the gateway sees a
                    // frame-read error with no grpc-status collected.
                    let frames: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
                        Ok(Frame::data(Bytes::from_static(b"grpc-payload"))),
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "backend reset before trailers",
                        )),
                    ];
                    let body = StreamBody::new(tokio_stream::iter(frames));

                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(body)
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });

                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

/// Buffered gRPC writeback reconciliation:
/// - a trailer key removed by a response hook (response_transformer `remove`)
///   must NOT be forwarded in the wire trailers;
/// - a header-shadowed key (sent by the backend in BOTH initial headers and
///   trailers) that a hook UPDATES must carry the sanitized value into both the
///   initial header and the wire TRAILERS frame (no unredacted trailer leak);
/// - a header-shadowed key that NO hook touches must keep the backend's distinct
///   trailing value on the wire (the header value must not clobber it);
/// - a header-shadowed key removed by a hook must be suppressed in BOTH the
///   initial headers and the wire trailers (no hidden trailer leak);
/// - malformed duplicate `grpc-status`/`grpc-message` initial headers are
///   stripped on the non-empty path: terminal status appears ONLY in the
///   trailers, with the backend's true trailing value.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_buffered_trailer_writeback_honors_hook_removal_and_duplicate_keys() {
    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;

    let mut proxy = create_grpc_proxy("grpc-trailer-writeback", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: "rt-trailer-remove".to_string(),
    }];
    let plugin = PluginConfig {
        id: "rt-trailer-remove".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "response_transformer".to_string(),
        enabled: true,
        config: serde_json::json!({
            "rules": [
                { "target": "header", "operation": "update", "key": "x-dup-key", "value": "redacted-by-hook" },
                { "target": "header", "operation": "remove", "key": "x-removed-trailer" },
                { "target": "header", "operation": "remove", "key": "x-shadowed-removed" }
            ]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-trailer-writeback".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let state = create_test_proxy_state_with_plugins(vec![proxy], vec![plugin]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = sender.send_request(req).await.expect("request send failed");
    assert_eq!(response.status(), 200);
    assert!(
        response.headers().get("grpc-status").is_none(),
        "grpc-status must not appear as initial metadata for non-empty responses, \
         even when a malformed backend duplicated it into the initial headers"
    );
    assert!(
        response.headers().get("grpc-message").is_none(),
        "grpc-message must not appear as initial metadata for non-empty responses"
    );
    assert_eq!(
        response
            .headers()
            .get("x-dup-key")
            .and_then(|v| v.to_str().ok()),
        Some("redacted-by-hook"),
        "hook-updated duplicate key must stay an initial header with the sanitized value"
    );
    assert_eq!(
        response
            .headers()
            .get("x-dup-untouched")
            .and_then(|v| v.to_str().ok()),
        Some("header-untouched"),
        "an untouched header-shadowed key must keep its initial-header value"
    );
    assert!(
        response.headers().get("x-removed-trailer").is_none(),
        "hook-removed key must not appear as an initial header"
    );
    assert!(
        response.headers().get("x-shadowed-removed").is_none(),
        "hook-removed shadowed key must not appear as an initial header"
    );

    let mut saw_data = false;
    let mut wire_trailers: Option<hyper::HeaderMap> = None;
    let mut body = response.into_body();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.expect("response frame");
        if let Some(data) = frame.data_ref()
            && !data.is_empty()
        {
            saw_data = true;
        }
        if let Some(trailers) = frame.trailers_ref() {
            wire_trailers = Some(trailers.clone());
        }
    }

    assert!(saw_data, "backend DATA frame was not forwarded");
    let trailers = wire_trailers.expect("wire TRAILERS frame missing");
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0"),
        "wire trailer must carry the backend's true trailing grpc-status, \
         not the malformed initial-header duplicate"
    );
    assert_eq!(
        trailers.get("grpc-message").and_then(|v| v.to_str().ok()),
        Some("OK"),
        "wire trailer must carry the backend's true trailing grpc-message"
    );
    assert_eq!(
        trailers.get("x-dup-key").and_then(|v| v.to_str().ok()),
        Some("redacted-by-hook"),
        "wire trailer must carry the hook-updated value for a header-shadowed key"
    );
    assert_eq!(
        trailers
            .get("x-dup-untouched")
            .and_then(|v| v.to_str().ok()),
        Some("trailer-untouched"),
        "an untouched header-shadowed key must keep the backend's true trailer \
         value on the wire, not be clobbered by the initial-header value"
    );
    assert!(
        trailers.get("x-removed-trailer").is_none(),
        "trailer removed by a response hook must not be forwarded to the client"
    );
    assert!(
        trailers.get("x-shadowed-removed").is_none(),
        "hook removal of a header-shadowed key must suppress the hidden trailer copy too"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_buffered_security_removal_wins_over_cookie_rehome_and_trailer_replay() {
    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;

    let mut proxy = create_grpc_proxy("grpc-security-removal", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let transformer = PluginConfig {
        id: "grpc-cookie-transformer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "response_transformer".to_string(),
        enabled: true,
        config: serde_json::json!({
            "rules": [{
                "target": "header",
                "operation": "update",
                "key": "Set-Cookie",
                "value": "session=mutated"
            }]
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut security = security_headers_plugin("grpc-security-removal-policy");
    security.config["remove"] = serde_json::json!(["Set-Cookie", "X-Powered-By"]);
    let state = create_test_proxy_state_with_plugins(vec![proxy], vec![transformer, security]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender
        .send_request(request)
        .await
        .expect("request send failed");

    assert_eq!(response.status(), 200);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "a later security policy must suppress the transformed trailer cookie after rehoming"
    );
    assert!(
        response.headers().get("x-powered-by").is_none(),
        "a later security policy must suppress the shadowed initial header"
    );
    assert!(response.headers().get("grpc-status").is_none());

    let mut saw_data = false;
    let mut wire_trailers = None;
    let mut body = response.into_body();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.expect("response frame");
        if let Some(data) = frame.data_ref()
            && !data.is_empty()
        {
            saw_data = true;
        }
        if let Some(trailers) = frame.trailers_ref() {
            wire_trailers = Some(trailers.clone());
        }
    }

    assert!(saw_data, "backend DATA frame was not forwarded");
    let trailers = wire_trailers.expect("wire TRAILERS frame missing");
    assert!(
        trailers.get("set-cookie").is_none(),
        "security removal must not leave the transformed cookie in trailers"
    );
    assert!(
        trailers.get("x-powered-by").is_none(),
        "security removal must not restore the shadowed application trailer"
    );
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "terminal gRPC status must remain on the trailer channel"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_buffered_security_policy_stays_initial_without_relocating_trailers() {
    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;
    let mut proxy = create_grpc_proxy("grpc-security-policy", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let state = create_test_proxy_state_with_plugins(
        vec![proxy],
        vec![security_headers_plugin("grpc-security-headers")],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender
        .send_request(request)
        .await
        .expect("request send failed");

    assert_eq!(
        response
            .headers()
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced"),
        "security policy must be present in client-visible initial headers"
    );
    assert_eq!(
        response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    assert!(response.headers().get("grpc-status").is_none());

    let mut trailers = None;
    let mut body = response.into_body();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.expect("response frame");
        if let Some(frame_trailers) = frame.trailers_ref() {
            trailers = Some(frame_trailers.clone());
        }
    }
    let trailers = trailers.expect("native gRPC trailers");
    assert_eq!(
        trailers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("backend-trailer-value"),
        "backend application trailer must remain on the trailer channel"
    );
    assert_eq!(
        trailers
            .get("x-dup-untouched")
            .and_then(|value| value.to_str().ok()),
        Some("trailer-untouched")
    );
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        trailers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("OK")
    );
}

/// gRPC-Web transformed responses must NOT carry native H2 trailers: the
/// `grpc_web` plugin re-encodes terminal status as a gRPC-Web trailer frame
/// appended to the body and relabels the content-type, so also emitting the
/// reconciled native TRAILERS frame would double-signal terminal status.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_transformed_response_suppresses_native_trailers() {
    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;

    let mut proxy = create_grpc_proxy("grpc-web-no-native-trailers", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: "grpc-web-bridge".to_string(),
    }];
    let plugin = PluginConfig {
        id: "grpc-web-bridge".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_web".to_string(),
        enabled: true,
        config: serde_json::json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-web-no-native-trailers".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let cookie_transformer = PluginConfig {
        id: "grpc-web-cookie-transformer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "response_transformer".to_string(),
        enabled: true,
        config: serde_json::json!({
            "rules": [{
                "target": "header",
                "operation": "update",
                "key": "Set-Cookie",
                "value": "session=mutated"
            }]
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut security_headers = security_headers_plugin("grpc-web-security-headers");
    security_headers.config["override_existing"] = serde_json::json!(true);
    security_headers.config["set"]["Content-Length"] = serde_json::json!("1");
    security_headers.config["remove"] = serde_json::json!(["Set-Cookie", "X-Powered-By"]);
    let state = create_test_proxy_state_with_plugins(
        vec![proxy],
        vec![plugin, cookie_transformer, security_headers],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // The backend exchange can very rarely blip under heavy parallel CI load (a
    // mid-response reset before the trailers reach the gateway). With the #2041
    // fix that now surfaces — correctly — as a gRPC-Web UNAVAILABLE error rather
    // than the success transform under test here, so retry a bounded number of
    // times to keep this success-path assertion deterministic. A genuine
    // transform regression fails on EVERY attempt (never embeds grpc-status: 0),
    // so the retry cannot mask one. The gateway-error SHAPE for the blip is
    // covered separately by `grpc_web_gateway_backend_error_is_grpc_web_shaped`.
    let mut succeeded = false;
    let mut status = 0u16;
    let mut content_type: Option<String> = None;
    let mut security_policy: Option<String> = None;
    let mut hsts: Option<String> = None;
    let mut content_length: Option<usize> = None;
    let mut had_grpc_status_header = true;
    let mut had_set_cookie_header = true;
    let mut had_x_powered_by_header = true;
    let mut body_bytes: Vec<u8> = Vec::new();
    let mut saw_native_trailers = false;

    for _attempt in 0..5 {
        let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Binary-mode gRPC-Web request: a single empty gRPC DATA frame
        // (flag 0x00 + 4-byte zero length) so framing is valid end-to-end.
        let req = Request::builder()
            .method("POST")
            .uri("/grpc/my.Service/Unary")
            .header("content-type", "application/grpc-web+proto")
            .body(Full::new(Bytes::from_static(&[0u8, 0, 0, 0, 0])))
            .unwrap();

        let response = sender.send_request(req).await.expect("request send failed");
        status = response.status().as_u16();
        content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        security_policy = response
            .headers()
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        hsts = response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        content_length = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        had_grpc_status_header = response.headers().get("grpc-status").is_some();
        had_set_cookie_header = response.headers().get("set-cookie").is_some();
        had_x_powered_by_header = response.headers().get("x-powered-by").is_some();

        body_bytes = Vec::new();
        saw_native_trailers = false;
        let mut body = response.into_body();
        while let Some(frame_result) = body.frame().await {
            let frame = frame_result.expect("response frame");
            if let Some(data) = frame.data_ref() {
                body_bytes.extend_from_slice(data);
            }
            if frame.is_trailers() {
                saw_native_trailers = true;
            }
        }

        // A successful backend exchange embeds the backend's true grpc-status: 0.
        if body_bytes
            .windows(b"grpc-status: 0".len())
            .any(|w| w == b"grpc-status: 0")
        {
            succeeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        succeeded,
        "backend exchange never succeeded within retries \
         (last content-type {content_type:?}, {} body bytes)",
        body_bytes.len()
    );
    assert_eq!(status, 200);
    assert_eq!(security_policy.as_deref(), Some("gateway-enforced"));
    assert_eq!(hsts.as_deref(), Some("max-age=31536000; includeSubDomains"));
    assert_eq!(
        content_type.as_deref(),
        Some("application/grpc-web+proto"),
        "response content-type must be rewritten to the gRPC-Web variant"
    );
    assert_eq!(
        content_length,
        Some(body_bytes.len()),
        "late security policy replay must preserve the transformed body length"
    );
    assert!(
        !had_grpc_status_header,
        "terminal status must ride in the gRPC-Web body trailer frame, \
         not the initial headers"
    );
    assert!(
        !had_set_cookie_header,
        "later security removal must win after transformed trailer-cookie rehoming"
    );
    assert!(
        !had_x_powered_by_header,
        "later security removal must suppress the shadowed backend field"
    );
    assert!(
        !saw_native_trailers,
        "gRPC-Web transformed responses must not emit native H2 trailers \
         (status is already embedded as a gRPC-Web trailer frame in the body)"
    );
    // The appended gRPC-Web trailer frame is flagged 0x80.
    assert!(
        body_bytes.contains(&0x80),
        "gRPC-Web body must contain a trailer frame (flag 0x80)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_text_keeps_security_policy_in_initial_headers() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;
    let mut proxy = create_grpc_proxy("grpc-web-text-security", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: "grpc-web-text-bridge".to_string(),
    }];
    let grpc_web = PluginConfig {
        id: "grpc-web-text-bridge".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_web".to_string(),
        enabled: true,
        config: serde_json::json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-web-text-security".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let state = create_test_proxy_state_with_plugins(
        vec![proxy],
        vec![
            grpc_web,
            security_headers_plugin("grpc-web-text-security-headers"),
        ],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let request_body = BASE64.encode([0u8, 0, 0, 0, 0]);
    let mut succeeded = false;
    let mut last_body = Vec::new();
    for _attempt in 0..5 {
        let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::builder()
            .method("POST")
            .uri("/grpc/my.Service/Unary")
            .header("content-type", "application/grpc-web-text+proto")
            .body(Full::new(Bytes::copy_from_slice(request_body.as_bytes())))
            .unwrap();
        let response = sender
            .send_request(request)
            .await
            .expect("gRPC-Web text request");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/grpc-web-text+proto")
        );
        assert_eq!(
            response
                .headers()
                .get("x-security-policy")
                .and_then(|value| value.to_str().ok()),
            Some("gateway-enforced")
        );
        assert_eq!(
            response
                .headers()
                .get("strict-transport-security")
                .and_then(|value| value.to_str().ok()),
            Some("max-age=31536000; includeSubDomains")
        );
        assert!(response.headers().get("grpc-status").is_none());

        let mut encoded_body = Vec::new();
        let mut saw_native_trailers = false;
        let mut body = response.into_body();
        while let Some(frame_result) = body.frame().await {
            let frame = frame_result.expect("response frame");
            if let Some(data) = frame.data_ref() {
                encoded_body.extend_from_slice(data);
            }
            if frame.is_trailers() {
                saw_native_trailers = true;
            }
        }
        assert!(!saw_native_trailers);
        last_body = BASE64.decode(&encoded_body).unwrap_or_default();
        if last_body
            .windows(b"grpc-status: 0".len())
            .any(|window| window == b"grpc-status: 0")
        {
            succeeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        succeeded,
        "text response never carried successful terminal status ({} decoded bytes)",
        last_body.len()
    );
    assert!(last_body.contains(&0x80));
}

/// #2041 regression: when the backend exchange FAILS gateway-side for a
/// gRPC-Web request (here the backend resets mid-response, before any
/// `grpc-status` trailer), the gateway must still emit a gRPC-Web-SHAPED error —
/// `content-type: application/grpc-web+proto` with the terminal status in a
/// gRPC-Web trailer frame in the body — NOT a raw `application/grpc`
/// trailers-only response a browser client cannot read. Before the fix the
/// gateway's gRPC backend-error arm returned `200 + application/grpc`, bypassing
/// the `grpc_web` response transform; that was the intermittent `application/grpc`
/// a gRPC-Web caller observed under CI load, reproduced here deterministically.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_gateway_backend_error_is_grpc_web_shaped() {
    let (backend_addr, _backend_handle) = start_grpc_backend_that_errors_after_data_frame().await;

    let mut proxy = create_grpc_proxy("grpc-web-backend-error", "/grpc", backend_addr.port());
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: "grpc-web-bridge".to_string(),
    }];
    let plugin = PluginConfig {
        id: "grpc-web-bridge".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_web".to_string(),
        enabled: true,
        config: serde_json::json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-web-backend-error".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut gateway_error_security = security_headers_plugin("grpc-web-backend-error-security");
    gateway_error_security.config["set"] = serde_json::json!({
        "X-Security-Policy": "gateway-enforced",
        "Connection": "close",
        "Keep-Alive": "timeout=5",
        "Proxy-Authenticate": "Basic realm=hostile",
        "Proxy-Connection": "close",
        "TE": "trailers",
        "Trailer": "x-hostile",
        "Transfer-Encoding": "chunked",
        "Upgrade": "h2c"
    });
    let state =
        create_test_proxy_state_with_plugins(vec![proxy], vec![plugin, gateway_error_security]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc-web+proto")
        .body(Full::new(Bytes::from_static(&[0u8, 0, 0, 0, 0])))
        .unwrap();

    let response = sender.send_request(req).await.expect("request send failed");

    // gRPC errors ride HTTP 200.
    assert_eq!(response.status(), 200);
    // The regression assertion: a gateway gRPC error for a gRPC-Web request must
    // be rendered in the gRPC-Web content-type, not the raw backend value.
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc-web+proto"),
        "a gateway gRPC error for a gRPC-Web request must use the gRPC-Web content-type, \
         not raw application/grpc"
    );
    assert_eq!(
        response
            .headers()
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced"),
        "gateway-generated gRPC-Web errors must retain initial-header policy"
    );
    assert_eq!(
        response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    for name in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        assert!(
            response.headers().get(name).is_none(),
            "terminal {name} metadata must remain in the gRPC-Web body trailer frame"
        );
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(
            response.headers().get(name).is_none(),
            "hop-by-hop {name} header leaked from gateway policy"
        );
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    // The terminal status rides in a gRPC-Web trailer frame (flag 0x80) in the body.
    assert!(
        body_bytes.contains(&0x80),
        "gRPC-Web error body must contain a trailer frame (flag 0x80)"
    );
    // UNAVAILABLE (14) is the gateway's gRPC status for a failed backend exchange.
    assert!(
        body_bytes
            .windows(b"grpc-status: 14".len())
            .any(|w| w == b"grpc-status: 14"),
        "gRPC-Web error body must embed the gateway's grpc-status: 14 (UNAVAILABLE)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_deadline_preflight_reject_is_grpc_web_shaped() {
    let mut proxy = create_grpc_proxy("grpc-web-deadline-preflight", "/grpc", 9);
    let plugin_configs = attach_grpc_web_deadline_plugins(
        &mut proxy,
        serde_json::json!({"reject_no_deadline": true}),
    );
    let state = create_test_proxy_state_with_plugins(vec![proxy], plugin_configs);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc-web+proto")
        .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
        .unwrap();
    let response = sender
        .send_request(request)
        .await
        .expect("deadline preflight response");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto")
    );
    assert!(
        response.headers().get("grpc-status").is_none(),
        "gRPC-Web terminal status must ride in the body trailer frame"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect preflight response")
        .to_bytes();
    assert_eq!(body.first(), Some(&0x80));
    assert!(
        body.windows(b"grpc-status: 3".len())
            .any(|window| window == b"grpc-status: 3"),
        "missing-timeout preflight rejection must embed INVALID_ARGUMENT in a gRPC-Web trailer frame"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn buffered_grpc_upload_deadline_preserves_gateway_deadline_contract() {
    use http_body::Frame;
    use http_body_util::StreamBody;

    let mut proxy = create_grpc_proxy("grpc-buffered-upload-deadline", "/grpc", 9);
    // Retry requires replayable request bytes, so the direct gRPC path must
    // collect the upload before it can dial. This makes the stalled upload a
    // true pre-dispatch buffering case instead of racing a fast connection
    // refusal from the intentionally unavailable test backend.
    proxy.retry = Some(ferrum_edge::config::types::RetryConfig {
        max_retries: 1,
        retryable_status_codes: vec![502, 503],
        retryable_methods: vec!["POST".to_string()],
        backoff: Default::default(),
        retry_on_connect_failure: true,
    });
    let plugin_configs =
        attach_grpc_web_deadline_plugins(&mut proxy, serde_json::json!({"max_deadline_ms": 5_000}));
    let state = create_test_proxy_state_with_plugins(vec![proxy], plugin_configs);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (_body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::convert::Infallible>>(1);
    let request_body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_rx));
    let request = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/ClientStreaming")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "50m")
        .body(request_body)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .expect("gateway must enforce the client RPC deadline")
        .expect("buffered upload deadline response");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    assert_eq!(
        response
            .headers()
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("Deadline exceeded at gateway"),
        "client deadline expiry must not collapse into the operator upload-timeout message"
    );
}

/// A backend-effective method rejection happens after prefix stripping and
/// target selection, but gRPC-Web clients must still receive the browser-safe
/// trailer-frame representation instead of a native gRPC Trailers-Only reply.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_backend_path_policy_reject_is_grpc_web_shaped() {
    let (backend_addr, _backend_handle) = start_grpc_backend_with_trailer_fixture().await;

    let mut proxy = create_grpc_proxy("grpc-web-method-policy", "/grpc", backend_addr.port());
    proxy.plugins = vec![
        ferrum_edge::config::types::PluginAssociation {
            plugin_config_id: "grpc-web-method-policy-bridge".to_string(),
        },
        ferrum_edge::config::types::PluginAssociation {
            plugin_config_id: "grpc-web-method-policy-router".to_string(),
        },
    ];
    let grpc_web = PluginConfig {
        id: "grpc-web-method-policy-bridge".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_web".to_string(),
        enabled: true,
        config: serde_json::json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-web-method-policy".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let method_router = PluginConfig {
        id: "grpc-web-method-policy-router".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_method_router".to_string(),
        enabled: true,
        config: serde_json::json!({
            "deny_methods": ["my.Service/Unary"]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-web-method-policy".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let state = create_test_proxy_state_with_plugins(vec![proxy], vec![grpc_web, method_router]);
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/Unary")
        .header("content-type", "application/grpc-web+proto")
        .body(Full::new(Bytes::from_static(&[0u8, 0, 0, 0, 0])))
        .unwrap();
    let response = sender
        .send_request(request)
        .await
        .expect("method-policy request send failed");

    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto")
    );
    assert!(!response.headers().contains_key("grpc-status"));
    assert!(!response.headers().contains_key("grpc-message"));
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .unwrap_or_default();
    assert!(
        body.contains(&0x80),
        "gRPC-Web reject must contain a trailer frame"
    );
    assert!(
        body.windows(b"grpc-status: 7".len())
            .any(|window| window == b"grpc-status: 7"),
        "method policy reject must embed PERMISSION_DENIED in the gRPC-Web body"
    );
}

/// A connect retry must not dial an alternate target whose effective path
/// would change the method authorized for the first target.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_retry_does_not_dial_path_changing_target() {
    let (unavailable_addr, unavailable_connections, _unavailable_handle) =
        start_connection_counting_backend().await;
    let (path_changing_addr, path_changing_connections, _path_changing_handle) =
        start_connection_counting_backend().await;

    let mut proxy = create_grpc_proxy("grpc-retry-method-policy", "/grpc", unavailable_addr.port());
    proxy.upstream_id = Some("grpc-retry-method-policy-upstream".to_string());
    proxy.retry = Some(RetryConfig {
        max_retries: 1,
        retryable_status_codes: Vec::new(),
        retryable_methods: vec!["POST".to_string()],
        backoff: BackoffStrategy::Fixed { delay_ms: 1 },
        retry_on_connect_failure: true,
    });
    proxy.plugins = vec![ferrum_edge::config::types::PluginAssociation {
        plugin_config_id: "grpc-retry-method-policy-router".to_string(),
    }];

    let method_router = PluginConfig {
        id: "grpc-retry-method-policy-router".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_method_router".to_string(),
        enabled: true,
        config: serde_json::json!({
            "allow_methods": ["/pkg.Service/Allowed"]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("grpc-retry-method-policy".to_string()),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let upstream = create_test_upstream(
        "grpc-retry-method-policy-upstream",
        vec![
            UpstreamTarget {
                host: "127.0.0.1".to_string(),
                port: unavailable_addr.port(),
                service_port_policy_key: None,
                weight: 100,
                tags: HashMap::new(),
                locality: None,
                path: Some("/pkg.Service".to_string()),
            },
            UpstreamTarget {
                host: "127.0.0.1".to_string(),
                port: path_changing_addr.port(),
                service_port_policy_key: None,
                weight: 100,
                tags: HashMap::new(),
                locality: None,
                path: Some("/admin.Service".to_string()),
            },
        ],
    );
    let state = create_test_proxy_state_with_plugins_and_upstreams(
        vec![proxy],
        vec![method_router],
        vec![upstream],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;
    let unavailable_before = unavailable_connections.load(Ordering::SeqCst);
    let path_changing_before = path_changing_connections.load(Ordering::SeqCst);

    let (status, headers, _body) = tokio::time::timeout(
        Duration::from_secs(5),
        send_grpc_request(gateway_addr, "/grpc/Allowed", b"", &[]),
    )
    .await
    .expect("gRPC retry request timed out")
    .expect("gRPC retry request failed");

    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("14"));
    assert!(
        unavailable_connections.load(Ordering::SeqCst) > unavailable_before,
        "initial target must fail during the h2c connect handshake"
    );
    assert_eq!(
        path_changing_connections.load(Ordering::SeqCst),
        path_changing_before,
        "path-changing retry target must not be dialed"
    );
}

/// Fix 4: with retry configured, a gRPC server-streaming response with
/// multiple data frames separated by delays must still reach the client
/// as distinct frames — the `grpc-status` trailer must NOT be delayed by
/// having the entire body buffered gateway-side.
///
/// Assertion strategy: consume the response frame-by-frame on the client
/// side and record the timestamp each frame arrives. If the gateway is
/// buffering, ALL frames (and the trailer) will land together after
/// `num_frames × per_frame_delay`. If streaming, the first frame arrives
/// quickly and later frames are spread out roughly by `per_frame_delay`.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_retry_enabled_does_not_stall_trailers_behind_streaming_body() {
    use std::time::Instant;

    // 5 data frames × 100 ms = 500 ms total body time. If the gateway
    // buffers we would see ALL frames arrive in a 500 ms burst at the
    // end, so the gap between first and last arrival would be ~0 ms.
    // If streaming, the gap should be ≥ 300 ms.
    const NUM_FRAMES: usize = 5;
    const FRAME_SIZE: usize = 1024;
    const PER_FRAME_DELAY_MS: u64 = 100;

    let (backend_addr, _backend_handle) = start_streaming_grpc_backend(
        NUM_FRAMES,
        FRAME_SIZE,
        Duration::from_millis(PER_FRAME_DELAY_MS),
        false,
    )
    .await;

    let mut proxy = create_grpc_proxy("grpc-stream", "/grpc", backend_addr.port());
    // Configure retry — before Fix 4 this would force buffering.
    proxy.retry = Some(ferrum_edge::config::types::RetryConfig {
        max_retries: 2,
        retryable_status_codes: vec![502, 503],
        retryable_methods: vec!["POST".to_string()],
        backoff: Default::default(),
        retry_on_connect_failure: true,
    });
    let state = create_test_proxy_state_with_plugins(
        vec![proxy],
        vec![security_headers_plugin("grpc-stream-security")],
    );
    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Send a request through the gateway using hyper's H2 client so we
    // can drive the response body frame-by-frame.
    use hyper::client::conn::http2;
    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/StreamingEcho")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from_static(b"")))
        .unwrap();

    let t_start = Instant::now();
    let response = sender.send_request(req).await.expect("request send failed");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert_eq!(
        response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );

    // Drive the body frame-by-frame.
    let mut body = response.into_body();
    let mut arrival_times: Vec<Duration> = Vec::new();
    let mut saw_trailer = false;
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.expect("frame error");
        let arrival = t_start.elapsed();
        arrival_times.push(arrival);
        if frame.is_trailers() {
            saw_trailer = true;
        }
    }

    assert!(saw_trailer, "client did not observe a trailers frame");
    assert!(
        arrival_times.len() >= NUM_FRAMES,
        "expected at least {} frames, got {}",
        NUM_FRAMES,
        arrival_times.len()
    );

    // If the gateway is buffering, first and last frame arrivals will
    // be within a few ms of each other (all land after the full body
    // is collected). If streaming, the spread should roughly equal
    // the inter-frame delay times (num_frames - 1).
    let first = arrival_times.first().copied().unwrap();
    let last = arrival_times.last().copied().unwrap();
    let spread = last.saturating_sub(first);

    // Require at least 60 % of the synthetic delay window to be observed
    // — this is comfortably above buffered-mode's ~0 ms spread and
    // robust to scheduler jitter.
    let expected_spread_ms = ((NUM_FRAMES as u64 - 1) * PER_FRAME_DELAY_MS) * 6 / 10;
    assert!(
        spread.as_millis() as u64 >= expected_spread_ms,
        "streamed-response trailer stall: arrival spread {} ms is below \
         the {} ms threshold expected for {}-frame × {} ms delay. \
         Raw timings: {:?}",
        spread.as_millis(),
        expected_spread_ms,
        NUM_FRAMES,
        PER_FRAME_DELAY_MS,
        arrival_times
    );
}

/// Backend for the streaming circuit-breaker tests.
///
/// It (a) DRAINS the request body in a background task so request DATA frames
/// keep flowing — this grants gateway→backend flow-control window so the gateway
/// actually polls (and size-checks) the client's frames — and (b) streams a
/// response with the given HTTP `status` that stays OPEN (one data frame, then a
/// long hold before trailers) so the client can keep the request stream open and
/// observe breaker state *during* response-body streaming, after response headers
/// have already reached the client.
async fn start_streaming_response_backend(
    status: u16,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(|req: Request<Incoming>| async move {
                    // (a) Drain the request body so the upload keeps advancing and
                    // the gateway polls the client's overflowing frame.
                    let mut req_body = req.into_body();
                    tokio::spawn(async move {
                        while let Some(frame) = req_body.frame().await {
                            if frame.is_err() {
                                break;
                            }
                        }
                    });

                    // (b) Stream a response that stays open well past the point
                    // where the client injects the overflow. Capacity 1 keeps the
                    // sender honest, but the long sleep is what holds it open.
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<Frame<Bytes>, std::convert::Infallible>,
                    >(1);
                    tokio::spawn(async move {
                        // One gRPC data frame (5-byte length prefix + empty msg).
                        let _ = tx
                            .send(Ok(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0]))))
                            .await;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            hyper::header::HeaderName::from_static("grpc-status"),
                            hyper::header::HeaderValue::from_static("0"),
                        );
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    });

                    let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/grpc")
                            .body(body)
                            .unwrap(),
                    )
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    eprintln!("Streaming response backend connection error: {}", e);
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

/// A representative clean gRPC streaming backend: 200 headers, one DATA frame,
/// then a real `grpc-status: 0` TRAILERS frame, with NO `content-length` — the
/// wire shape an actual gRPC server produces. Unlike `start_mock_grpc_backend`
/// (which packs `grpc-status` into the response *headers* with a fixed-length
/// `Full` body), this yields a trailers frame, so the gateway's response body
/// reaches a clean terminal (`ProxyBody::poll_frame` observes the trailers /
/// EOF) instead of being dropped after a satisfied `content-length`. The
/// #1649-item-3 deferred backend-dispatch outcome heals the breaker on that
/// clean terminal.
async fn start_clean_grpc_streaming_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use http_body::Frame;
    use http_body_util::StreamBody;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let mut req_body = req.into_body();
                    tokio::spawn(async move {
                        while let Some(frame) = req_body.frame().await {
                            if frame.is_err() {
                                break;
                            }
                        }
                    });
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<Frame<Bytes>, std::convert::Infallible>,
                    >(2);
                    tokio::spawn(async move {
                        // One empty gRPC data frame, then the grpc-status trailer.
                        let _ = tx
                            .send(Ok(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0]))))
                            .await;
                        let mut trailers = hyper::HeaderMap::new();
                        trailers.insert(
                            hyper::header::HeaderName::from_static("grpc-status"),
                            hyper::header::HeaderValue::from_static("0"),
                        );
                        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                    });
                    let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(body)
                            .unwrap(),
                    )
                });
                if let Err(e) = builder.serve_connection(io, service).await {
                    eprintln!("Clean gRPC streaming backend connection error: {}", e);
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, handle)
}

/// Issue #1412: a gRPC streaming client-upload overflow that trips DURING
/// response-body streaming (bidi / client-streaming) must record NEUTRAL for the
/// circuit breaker — it must NOT falsely heal a HALF_OPEN probe — and it must
/// release the probe slot at *upload* termination (not response completion).
///
/// This is the real end-to-end counterpart to the in-module
/// `grpc_streaming_cb_outcome` classification tests: it drives an actual H2
/// stream through the gateway so the deferred `GrpcStreamingProbeRecorder` path
/// (request-body `Drop` → breaker record) is exercised, not just the
/// `ProxyState`-free helper.
///
/// Before the fix the gateway sampled `request_body_exceeded` once at header
/// time (overflow not yet tripped) and recorded the backend 200 as a probe
/// success, healing the breaker to CLOSED.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_streaming_late_upload_overflow_during_response_records_neutral() {
    use ferrum_edge::config::types::CircuitBreakerConfig;
    use http_body::Frame;
    use http_body_util::StreamBody;

    // Small recv limit so a single follow-up frame overflows comfortably.
    const MAX_GRPC_RECV: usize = 1024;

    let (backend_addr, _backend_handle) = start_streaming_response_backend(200).await;

    let mut proxy = create_grpc_proxy("grpc-late-overflow", "/grpc", backend_addr.port());
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0, // OPEN -> HALF_OPEN immediately on next admission
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    });
    let cb_config = proxy.circuit_breaker.clone().unwrap();
    let backend_host = proxy.backend_host.clone();
    let backend_port = proxy.backend_port;
    let proxy_id = proxy.id.clone();

    let mut env = create_test_env_config();
    env.max_grpc_recv_size_bytes = MAX_GRPC_RECV;
    let state = create_test_proxy_state_with_env(vec![proxy], env);
    let inspect_state = state.clone();

    // Resolve the SAME breaker key the gateway uses (per-target for a single
    // backend proxy) and trip it to OPEN so the streaming request is admitted as
    // the sole HALF_OPEN probe.
    let cb_key = ferrum_edge::circuit_breaker::target_key(&backend_host, backend_port);
    let cb =
        inspect_state
            .circuit_breaker_cache
            .get_or_create(&proxy_id, Some(&cb_key), &cb_config);
    cb.record_failure(500, false, false);
    assert_eq!(
        cb.state_name(),
        "open",
        "breaker should be OPEN after a single failure (failure_threshold = 1)"
    );

    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // Open an H2 connection and send a request with a CHANNEL-backed body so we
    // can keep the request stream open and inject the overflow AFTER response
    // headers arrive (i.e. during response-body streaming).
    use hyper::client::conn::http2;
    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::convert::Infallible>>(4);
    let req_body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_rx));
    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/BidiOverflow")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(req_body)
        .unwrap();

    // Headers go on the wire immediately; the body streams from the channel.
    let response = sender.send_request(req).await.expect("send_request failed");
    assert_eq!(
        response.status(),
        200,
        "backend headers (200) must reach the client before the overflow"
    );

    // The probe was admitted and the gateway captured the 200 status, but the
    // upload has NOT terminated — nothing is recorded yet, so the probe slot is
    // still held and the breaker is still HALF_OPEN. (On the pre-fix path the
    // breaker would already have healed to CLOSED here.)
    assert_eq!(
        cb.state_name(),
        "half_open",
        "probe must be admitted (HALF_OPEN), not already healed, at header time"
    );
    assert_eq!(
        cb.half_open_in_flight(),
        1,
        "probe slot must still be held while the request upload is in flight"
    );

    // Now overflow the request body DURING response-body streaming.
    let overflow = Bytes::from(vec![b'X'; MAX_GRPC_RECV * 8]);
    let _ = body_tx.send(Ok(Frame::data(overflow))).await;
    // Drop the sender so the request stream terminates (END_STREAM) even if the
    // gateway has not already RST it for the overflow.
    drop(body_tx);

    // The gateway detects the overflow, RSTs the request, drops the streaming
    // request-body wrapper, and the deferred recorder fires NEUTRAL at upload
    // termination — releasing the probe slot. Poll until the slot is released.
    let mut released = false;
    for _ in 0..200 {
        if cb.half_open_in_flight() == 0 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        released,
        "deferred recorder must release the HALF_OPEN probe slot at upload \
         termination (half_open_in_flight never returned to 0)"
    );

    // The probe slot must be released at UPLOAD termination, not held for the
    // full (5 s) response-stream lifetime — the poll above completed well inside
    // that window, proving the slot was not pinned to response completion.

    // Decisive assertion: a late client-upload overflow is gateway-side, so it
    // records NEUTRAL — the breaker must NOT heal to CLOSED.
    assert_eq!(
        cb.state_name(),
        "half_open",
        "a late client-upload overflow must record NEUTRAL and leave the breaker \
         HALF_OPEN (it must not falsely heal the probe)"
    );
}

/// Companion to the late-overflow test: a CLEAN streaming probe (no overflow)
/// must still heal a HALF_OPEN breaker. Since #1649 item 3 the recorder only
/// releases the probe slot (NEUTRAL) at request-upload termination; the
/// backend-health SUCCESS that heals the breaker is recorded by the deferred
/// backend-dispatch outcome when the response body reaches a clean terminal.
/// This guards against the deferral accidentally dropping the success
/// classification (acceptance criterion: "a clean upload + 2xx backend still
/// heals"). Uses a representative streaming backend (real `grpc-status: 0`
/// trailers, no `content-length`) so the gateway observes a clean body terminal.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_streaming_clean_probe_heals_breaker_at_body_completion() {
    use ferrum_edge::config::types::CircuitBreakerConfig;

    let (backend_addr, _backend_handle) = start_clean_grpc_streaming_backend().await;

    let mut proxy = create_grpc_proxy("grpc-clean-heal", "/grpc", backend_addr.port());
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout_seconds: 0, // OPEN -> HALF_OPEN immediately on next admission
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    });
    let cb_config = proxy.circuit_breaker.clone().unwrap();
    let backend_host = proxy.backend_host.clone();
    let backend_port = proxy.backend_port;
    let proxy_id = proxy.id.clone();

    let state = create_test_proxy_state(vec![proxy]);
    let inspect_state = state.clone();

    let cb_key = ferrum_edge::circuit_breaker::target_key(&backend_host, backend_port);
    let cb =
        inspect_state
            .circuit_breaker_cache
            .get_or_create(&proxy_id, Some(&cb_key), &cb_config);
    cb.record_failure(500, false, false);
    assert_eq!(
        cb.state_name(),
        "open",
        "breaker should be OPEN after a failure"
    );

    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    // A normal streaming probe: the backend replies 200 (grpc-status 0). This
    // still uses the streaming fast path (no retry, no body plugins), so the
    // deferred backend-dispatch outcome owns the CB result.
    let (status, _headers, _body) = send_grpc_request(
        gateway_addr,
        "/grpc/my.Service/Echo",
        b"\x00\x00\x00\x00\x05hello",
        &[],
    )
    .await
    .expect("request failed");
    assert_eq!(status, 200);

    // The recorder releases the probe slot (NEUTRAL) at upload termination; the
    // deferred backend-dispatch outcome then records the backend 200 success when
    // the response body completes cleanly → the breaker heals (success_threshold
    // = 1). `send_grpc_request` collects the full body + trailers, so the
    // gateway's response body reaches its clean terminal.
    let mut healed = false;
    for _ in 0..200 {
        if cb.state_name() == "closed" {
            healed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        healed,
        "a clean 2xx streaming probe must heal the breaker via the deferred \
         backend-dispatch outcome at body completion (state was {})",
        cb.state_name()
    );
    assert_eq!(
        cb.half_open_in_flight(),
        0,
        "healing must release the HALF_OPEN probe slot"
    );
}

/// Regression guard for the deferral scope: a CLOSED-state (non-probe) streaming
/// request whose backend returns a failure status must trip the breaker at
/// RESPONSE-HEADER time, NOT be withheld until the request upload terminates.
/// Otherwise a long/slow bidi upload would keep the breaker closed and admit more
/// traffic to a failing backend. The deferred recorder is intentionally scoped to
/// HALF_OPEN probes only.
///
/// The request stream is kept OPEN (no EOF / no overflow) while we assert the
/// breaker has already opened — proving the failure was recorded eagerly, since a
/// deferred record would not have fired yet.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_streaming_closed_state_backend_failure_trips_breaker_at_header_time() {
    use ferrum_edge::config::types::CircuitBreakerConfig;
    use http_body::Frame;
    use http_body_util::StreamBody;

    // Backend returns HTTP 503 (a transport-level failure status) and holds the
    // stream open for 5 s.
    let (backend_addr, _backend_handle) = start_streaming_response_backend(503).await;

    let mut proxy = create_grpc_proxy("grpc-closed-fail", "/grpc", backend_addr.port());
    proxy.circuit_breaker = Some(CircuitBreakerConfig {
        failure_threshold: 1, // a single failure trips CLOSED -> OPEN
        success_threshold: 1,
        timeout_seconds: 60, // stays OPEN (no immediate HALF_OPEN); this is NOT a probe
        failure_status_codes: vec![503],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    });
    let cb_config = proxy.circuit_breaker.clone().unwrap();
    let backend_host = proxy.backend_host.clone();
    let backend_port = proxy.backend_port;
    let proxy_id = proxy.id.clone();

    // Breaker starts CLOSED (no pre-trip) — this request is a normal, non-probe
    // CLOSED-state request.
    let state = create_test_proxy_state(vec![proxy]);
    let inspect_state = state.clone();
    let cb_key = ferrum_edge::circuit_breaker::target_key(&backend_host, backend_port);
    let cb =
        inspect_state
            .circuit_breaker_cache
            .get_or_create(&proxy_id, Some(&cb_key), &cb_config);
    assert_eq!(cb.state_name(), "closed", "breaker should start CLOSED");

    let (gateway_addr, _gateway_handle) = start_test_gateway(state).await;

    use hyper::client::conn::http2;
    let stream = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Keep the request stream OPEN (channel body, no EOF) so the upload does not
    // terminate. A deferred record would therefore NOT fire.
    let (body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::convert::Infallible>>(4);
    let req_body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(body_rx));
    let req = Request::builder()
        .method("POST")
        .uri("/grpc/my.Service/SlowUpload")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(req_body)
        .unwrap();

    let response = sender.send_request(req).await.expect("send_request failed");
    assert_eq!(
        response.status(),
        503,
        "backend failure status reaches client"
    );

    // The breaker must already be OPEN — the failure was recorded at header time,
    // not deferred to upload termination (the upload is still open below).
    assert_eq!(
        cb.state_name(),
        "open",
        "a CLOSED-state streaming backend failure must trip the breaker at header \
         time, not wait for the (still-open) upload to terminate"
    );

    // Clean up: closing the body now must not change the already-recorded outcome.
    drop(body_tx);
    assert_eq!(
        cb.state_name(),
        "open",
        "breaker must remain OPEN after the upload terminates (no double-record)"
    );
}
