use chrono::Utc;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Proxy};
use ferrum_gateway::proxy::build_backend_url;
use ferrum_gateway::proxy::grpc_proxy;

fn test_proxy() -> Proxy {
    Proxy {
        id: "grpc-test".into(),
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
        pool_max_idle_per_host: None,
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
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

// --- GrpcConnectionPool creation ---

#[tokio::test]
async fn test_grpc_connection_pool_creation() {
    let pool = grpc_proxy::GrpcConnectionPool::default();
    // Pool should be functional after creation — attempting to get a sender for
    // a non-existent backend should fail with a connection error, not a panic.
    let mut proxy = test_proxy();
    proxy.backend_host = "127.0.0.1".to_string();
    proxy.backend_port = 1; // intentionally unreachable port
    let dns = ferrum_gateway::dns::DnsCache::new(ferrum_gateway::dns::DnsConfig::default());
    let result = pool.get_sender(&proxy, &dns).await;
    // Connection should fail (unreachable port), but not panic
    assert!(
        result.is_err(),
        "Connection to unreachable port should fail"
    );
}
