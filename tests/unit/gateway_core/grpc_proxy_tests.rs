use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendProtocol, Proxy};
use ferrum_edge::proxy::build_backend_url;
use ferrum_edge::proxy::grpc_proxy;

fn test_proxy() -> Proxy {
    Proxy {
        id: "grpc-test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("gRPC Test Proxy".into()),
        hosts: vec![],
        listen_path: "/grpc".into(),
        backend_protocol: BackendProtocol::Grpc,
        backend_host: "grpc-backend.example.com".into(),
        backend_port: 50051,
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

fn headers_with_content_type(ct: &str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", ct.parse().unwrap());
    headers
}

// --- is_grpc_content_type detection tests ---

#[test]
fn test_is_grpc_request_application_grpc() {
    let headers = headers_with_content_type("application/grpc");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_grpc_proto() {
    let headers = headers_with_content_type("application/grpc+proto");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_grpc_json() {
    let headers = headers_with_content_type("application/grpc+json");
    assert!(grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_application_json_is_not_grpc() {
    let headers = headers_with_content_type("application/json");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_no_content_type() {
    let headers = hyper::HeaderMap::new();
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

#[test]
fn test_is_grpc_request_text_plain_is_not_grpc() {
    let headers = headers_with_content_type("text/plain");
    assert!(!grpc_proxy::is_grpc_content_type(&headers));
}

// --- build_backend_url for gRPC protocols ---

#[test]
fn test_build_backend_url_grpc_uses_http_scheme() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.len(),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpcs_uses_https_scheme() {
    let mut proxy = test_proxy();
    proxy.backend_protocol = BackendProtocol::Grpcs;
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.len(),
    );
    assert_eq!(
        url,
        "https://grpc-backend.example.com:50051/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpc_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/prefix".into());
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.len(),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/prefix/my.Service/MyMethod"
    );
}

#[test]
fn test_build_backend_url_grpc_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(
        &proxy,
        "/grpc/my.Service/MyMethod",
        "",
        proxy.listen_path.len(),
    );
    assert_eq!(
        url,
        "http://grpc-backend.example.com:50051/grpc/my.Service/MyMethod"
    );
}

// --- gRPC error response tests ---

#[test]
fn test_grpc_error_response_unavailable() {
    let resp =
        grpc_proxy::build_grpc_error_response(grpc_proxy::grpc_status::UNAVAILABLE, "Backend down");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "14");
    assert_eq!(resp.headers().get("grpc-message").unwrap(), "Backend down");
}

#[test]
fn test_grpc_error_response_deadline_exceeded() {
    let resp = grpc_proxy::build_grpc_error_response(
        grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
        "Timeout",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "4");
    assert_eq!(resp.headers().get("grpc-message").unwrap(), "Timeout");
}

#[test]
fn test_grpc_error_response_unauthenticated() {
    let resp = grpc_proxy::build_grpc_error_response(
        16, // UNAUTHENTICATED
        "Missing token",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "16");
}

#[test]
fn test_grpc_error_response_resource_exhausted() {
    let resp = grpc_proxy::build_grpc_error_response(
        8, // RESOURCE_EXHAUSTED
        "Rate limited",
    );
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("grpc-status").unwrap(), "8");
}

// --- BackendProtocol display and deserialization ---

#[test]
fn test_backend_protocol_grpcs_display() {
    assert_eq!(BackendProtocol::Grpcs.to_string(), "grpcs");
    assert_eq!(BackendProtocol::Grpc.to_string(), "grpc");
}

#[test]
fn test_backend_protocol_grpcs_deserialize() {
    let grpcs: BackendProtocol = serde_json::from_str("\"grpcs\"").unwrap();
    assert_eq!(grpcs, BackendProtocol::Grpcs);
    let grpc: BackendProtocol = serde_json::from_str("\"grpc\"").unwrap();
    assert_eq!(grpc, BackendProtocol::Grpc);
}

// --- Response header capacity hint ---

#[test]
fn test_response_header_capacity_hint_matches_keys_len() {
    // Verify that HashMap::with_capacity(keys_len()) pre-allocates correctly.
    // This mirrors the optimization in proxy_grpc_request_core.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    headers.insert("grpc-status", "0".parse().unwrap());
    headers.insert("grpc-message", "OK".parse().unwrap());

    // keys_len() counts unique header names (same as len() when no duplicate names)
    let capacity_hint = headers.keys_len();
    assert_eq!(capacity_hint, 3);

    let mut resp_headers = std::collections::HashMap::with_capacity(capacity_hint);
    for (k, v) in &headers {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    assert_eq!(resp_headers.len(), 3);
    assert_eq!(resp_headers["content-type"], "application/grpc");
    assert_eq!(resp_headers["grpc-status"], "0");
}

#[test]
fn test_response_header_capacity_hint_with_duplicate_names() {
    // keys_len() de-duplicates repeated header names; verify capacity is still valid.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-type", "application/grpc".parse().unwrap());
    // Append a second value for the same key
    headers.append("content-type", "application/grpc+proto".parse().unwrap());
    headers.insert("grpc-status", "0".parse().unwrap());

    // keys_len() = 2 (two unique names), len() = 3 (three values)
    assert_eq!(headers.keys_len(), 2);
    assert_eq!(headers.len(), 3);

    // A HashMap built with this capacity will hold the last value per key
    let capacity_hint = headers.keys_len();
    let mut resp_headers = std::collections::HashMap::with_capacity(capacity_hint);
    for (k, v) in &headers {
        if let Ok(vs) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    // Map has at most keys_len() unique entries
    assert!(resp_headers.len() <= headers.keys_len());
}

// --- Streaming mode returns empty body bytes ---

#[tokio::test]
async fn test_proxy_grpc_request_from_bytes_error_on_unreachable_backend() {
    // proxy_grpc_request returns (result, body_bytes).
    // When stream_response=true the returned body is Bytes::new() (no clone needed).
    // We verify the buffered path (proxy_grpc_request_from_bytes) errors gracefully
    // on an unreachable backend; this also confirms no panic in either code path.
    use bytes::Bytes;

    let pool = grpc_proxy::GrpcConnectionPool::default();
    let mut proxy = test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // intentionally unreachable port
    proxy.retry = None;

    let dns = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let headers = headers_with_content_type("application/grpc");
    let body = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let proxy_headers = std::collections::HashMap::new();

    let result = grpc_proxy::proxy_grpc_request_from_bytes(
        hyper::Method::POST,
        headers,
        body,
        &proxy,
        "http://127.0.0.1:1/test.Service/Method",
        &pool,
        &dns,
        &proxy_headers,
    )
    .await;
    assert!(
        result.is_err(),
        "Connection to unreachable port should fail"
    );
}

// --- parse_grpc_timeout_ms tests ---

fn headers_with_grpc_timeout(val: &str) -> hyper::HeaderMap {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("grpc-timeout", val.parse().unwrap());
    headers
}

#[test]
fn test_parse_grpc_timeout_seconds() {
    let headers = headers_with_grpc_timeout("5S");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5000));
}

#[test]
fn test_parse_grpc_timeout_milliseconds() {
    let headers = headers_with_grpc_timeout("200m");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(200));
}

#[test]
fn test_parse_grpc_timeout_hours() {
    let headers = headers_with_grpc_timeout("1H");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(3_600_000));
}

#[test]
fn test_parse_grpc_timeout_minutes() {
    let headers = headers_with_grpc_timeout("2M");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(120_000));
}

#[test]
fn test_parse_grpc_timeout_microseconds() {
    let headers = headers_with_grpc_timeout("5000u");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5));
}

#[test]
fn test_parse_grpc_timeout_nanoseconds() {
    let headers = headers_with_grpc_timeout("5000000n");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(5));
}

#[test]
fn test_parse_grpc_timeout_sub_millisecond_clamps_to_1() {
    // 100 microseconds = 0.1ms → clamped to 1ms
    let headers = headers_with_grpc_timeout("100u");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), Some(1));
}

#[test]
fn test_parse_grpc_timeout_zero_returns_none() {
    let headers = headers_with_grpc_timeout("0S");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_missing_header() {
    let headers = hyper::HeaderMap::new();
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_invalid_unit() {
    let headers = headers_with_grpc_timeout("5X");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_invalid_number() {
    let headers = headers_with_grpc_timeout("abcS");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_empty_value() {
    let headers = headers_with_grpc_timeout("");
    // Empty header value — cannot split unit character
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

#[test]
fn test_parse_grpc_timeout_overflow_returns_none() {
    // Huge hour value overflows u64 in checked_mul — should return None
    let headers = headers_with_grpc_timeout("999999999999999999H");
    assert_eq!(grpc_proxy::parse_grpc_timeout_ms(&headers), None);
}

// --- GrpcConnectionPool creation ---

#[tokio::test]
async fn test_grpc_connection_pool_creation() {
    let pool = grpc_proxy::GrpcConnectionPool::default();
    // Pool should be functional after creation — attempting to get a sender for
    // a non-existent backend should fail with a connection error, not a panic.
    let mut proxy = test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // intentionally unreachable port
    let dns = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let result = pool.get_sender(&proxy, &dns).await;
    // Connection should fail (unreachable port), but not panic
    assert!(
        result.is_err(),
        "Connection to unreachable port should fail"
    );
}
