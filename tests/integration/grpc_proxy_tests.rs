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
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
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
        upstream_id: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
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
        admin_jwt_secret: None,
        db_type: None,
        db_url: None,
        db_poll_interval: 30,
        db_tls_enabled: false,
        db_tls_ca_cert_path: None,
        db_tls_client_cert_path: None,
        db_tls_client_key_path: None,
        db_tls_insecure: false,
        db_ssl_mode: None,
        db_ssl_root_cert: None,
        db_ssl_client_cert: None,
        db_ssl_client_key: None,
        file_config_path: Some("/tmp/test-grpc-config.json".into()),
        db_config_backup_path: None,
        db_failover_urls: Vec::new(),
        db_read_replica_url: None,
        cp_grpc_listen_addr: None,
        cp_dp_grpc_jwt_secret: None,
        dp_cp_grpc_url: None,
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
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
        tls_ca_bundle_path: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        frontend_tls_client_ca_bundle_path: None,
        admin_tls_client_ca_bundle_path: None,
        tls_no_verify: false,
        admin_read_only: false,
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
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
        try_tcp_on_error: true,
        num_concurrent_reqs: 3,
        max_active_requests: 512,
    });
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    ProxyState::new(config, dns_cache, create_test_env_config(), None).unwrap()
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

// --- Integration Tests ---

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
    let state = create_test_proxy_state(vec![proxy]);
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
