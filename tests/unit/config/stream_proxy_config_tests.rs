//! Tests for TCP/UDP stream proxy configuration types and validation.

use chrono::Utc;
use ferrum_gateway::config::types::{
    ActiveHealthCheck, AuthMode, BackendProtocol, GatewayConfig, HealthProbeType, Proxy,
};

fn make_stream_proxy(id: &str, protocol: BackendProtocol, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        name: None,
        hosts: vec![],
        listen_path: String::new(),
        backend_protocol: protocol,
        backend_host: "localhost".into(),
        backend_port: 5432,
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
        listen_port: Some(port),
        frontend_tls: false,
        udp_idle_timeout_seconds: 60,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_http_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        name: None,
        hosts: vec![],
        listen_path: listen_path.into(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "localhost".into(),
        backend_port: 3000,
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
        udp_idle_timeout_seconds: 60,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_config(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    }
}

// --- BackendProtocol helper method tests ---

#[test]
fn test_is_stream_proxy() {
    assert!(BackendProtocol::Tcp.is_stream_proxy());
    assert!(BackendProtocol::TcpTls.is_stream_proxy());
    assert!(BackendProtocol::Udp.is_stream_proxy());
    assert!(BackendProtocol::Dtls.is_stream_proxy());
    assert!(!BackendProtocol::Http.is_stream_proxy());
    assert!(!BackendProtocol::Https.is_stream_proxy());
    assert!(!BackendProtocol::Ws.is_stream_proxy());
    assert!(!BackendProtocol::Wss.is_stream_proxy());
    assert!(!BackendProtocol::Grpc.is_stream_proxy());
    assert!(!BackendProtocol::Grpcs.is_stream_proxy());
    assert!(!BackendProtocol::H3.is_stream_proxy());
}

#[test]
fn test_is_udp() {
    assert!(BackendProtocol::Udp.is_udp());
    assert!(BackendProtocol::Dtls.is_udp());
    assert!(!BackendProtocol::Tcp.is_udp());
    assert!(!BackendProtocol::TcpTls.is_udp());
    assert!(!BackendProtocol::Http.is_udp());
}

#[test]
fn test_is_tls_backend() {
    assert!(BackendProtocol::TcpTls.is_tls_backend());
    assert!(BackendProtocol::Dtls.is_tls_backend());
    assert!(!BackendProtocol::Tcp.is_tls_backend());
    assert!(!BackendProtocol::Udp.is_tls_backend());
    assert!(!BackendProtocol::Http.is_tls_backend());
}

// --- BackendProtocol serialization tests ---

#[test]
fn test_backend_protocol_display() {
    assert_eq!(BackendProtocol::Tcp.to_string(), "tcp");
    assert_eq!(BackendProtocol::TcpTls.to_string(), "tcp_tls");
    assert_eq!(BackendProtocol::Udp.to_string(), "udp");
    assert_eq!(BackendProtocol::Dtls.to_string(), "dtls");
}

#[test]
fn test_backend_protocol_serde_roundtrip() {
    for proto in [
        BackendProtocol::Tcp,
        BackendProtocol::TcpTls,
        BackendProtocol::Udp,
        BackendProtocol::Dtls,
    ] {
        let json = serde_json::to_string(&proto).unwrap();
        let parsed: BackendProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(proto, parsed);
    }
}

#[test]
fn test_tcp_tls_serde_rename() {
    let json = r#""tcp_tls""#;
    let proto: BackendProtocol = serde_json::from_str(json).unwrap();
    assert_eq!(proto, BackendProtocol::TcpTls);
}

// --- Stream proxy validation tests ---

#[test]
fn test_validate_stream_proxy_valid() {
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432),
        make_stream_proxy("udp1", BackendProtocol::Udp, 5353),
    ]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_validate_stream_proxy_missing_listen_port() {
    let mut proxy = make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432);
    proxy.listen_port = None;
    let config = test_config(vec![proxy]);
    let err = config.validate_stream_proxies().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("must have a listen_port"));
}

#[test]
fn test_validate_stream_proxy_duplicate_port() {
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432),
        make_stream_proxy("tcp2", BackendProtocol::TcpTls, 5432),
    ]);
    let err = config.validate_stream_proxies().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate listen_port"));
}

#[test]
fn test_validate_http_proxy_with_listen_port_rejected() {
    let mut proxy = make_http_proxy("http1", "/api");
    proxy.listen_port = Some(8080);
    let config = test_config(vec![proxy]);
    let err = config.validate_stream_proxies().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("must not set listen_port"));
}

#[test]
fn test_validate_mixed_http_and_stream_proxies() {
    let config = test_config(vec![
        make_http_proxy("http1", "/api"),
        make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432),
        make_stream_proxy("udp1", BackendProtocol::Udp, 5353),
    ]);
    assert!(config.validate_stream_proxies().is_ok());
}

// --- Normalize stream proxy paths ---

#[test]
fn test_normalize_stream_proxy_paths_tcp() {
    let mut config = test_config(vec![make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432)]);
    config.normalize_stream_proxy_paths();
    assert_eq!(config.proxies[0].listen_path, "__tcp:5432");
}

#[test]
fn test_normalize_stream_proxy_paths_udp() {
    let mut config = test_config(vec![make_stream_proxy("udp1", BackendProtocol::Udp, 5353)]);
    config.normalize_stream_proxy_paths();
    assert_eq!(config.proxies[0].listen_path, "__udp:5353");
}

#[test]
fn test_normalize_stream_proxy_paths_dtls() {
    let mut config = test_config(vec![make_stream_proxy(
        "dtls1",
        BackendProtocol::Dtls,
        4433,
    )]);
    config.normalize_stream_proxy_paths();
    assert_eq!(config.proxies[0].listen_path, "__udp:4433");
}

#[test]
fn test_normalize_stream_proxy_paths_tcp_tls() {
    let mut config = test_config(vec![make_stream_proxy(
        "tls1",
        BackendProtocol::TcpTls,
        5433,
    )]);
    config.normalize_stream_proxy_paths();
    assert_eq!(config.proxies[0].listen_path, "__tcp:5433");
}

#[test]
fn test_normalize_does_not_change_http_proxies() {
    let mut config = test_config(vec![make_http_proxy("http1", "/api/v1")]);
    config.normalize_stream_proxy_paths();
    assert_eq!(config.proxies[0].listen_path, "/api/v1");
}

// --- Proxy struct deserialization with stream fields ---

#[test]
fn test_tcp_proxy_yaml_deserialization() {
    let yaml = r#"
id: "tcp-proxy-1"
listen_path: ""
backend_protocol: tcp
backend_host: "db.example.com"
backend_port: 5432
listen_port: 15432
frontend_tls: true
udp_idle_timeout_seconds: 30
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.backend_protocol, BackendProtocol::Tcp);
    assert_eq!(proxy.listen_port, Some(15432));
    assert!(proxy.frontend_tls);
    assert_eq!(proxy.udp_idle_timeout_seconds, 30);
}

#[test]
fn test_udp_proxy_json_deserialization() {
    let json = r#"{
        "id": "udp-proxy-1",
        "listen_path": "",
        "backend_protocol": "udp",
        "backend_host": "dns.example.com",
        "backend_port": 53,
        "listen_port": 10053,
        "udp_idle_timeout_seconds": 120
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.backend_protocol, BackendProtocol::Udp);
    assert_eq!(proxy.listen_port, Some(10053));
    assert_eq!(proxy.udp_idle_timeout_seconds, 120);
    assert!(!proxy.frontend_tls);
}

#[test]
fn test_stream_proxy_defaults() {
    let json = r#"{
        "id": "tcp1",
        "listen_path": "",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.listen_port, None);
    assert!(!proxy.frontend_tls);
    assert_eq!(proxy.udp_idle_timeout_seconds, 60);
}

// --- HealthProbeType tests ---

#[test]
fn test_health_probe_type_default() {
    assert_eq!(HealthProbeType::default(), HealthProbeType::Http);
}

#[test]
fn test_health_probe_type_serde() {
    let tcp: HealthProbeType = serde_json::from_str(r#""tcp""#).unwrap();
    assert_eq!(tcp, HealthProbeType::Tcp);
    let udp: HealthProbeType = serde_json::from_str(r#""udp""#).unwrap();
    assert_eq!(udp, HealthProbeType::Udp);
}

#[test]
fn test_active_health_check_with_probe_type() {
    let json = r#"{
        "probe_type": "tcp",
        "interval_seconds": 5,
        "timeout_ms": 2000,
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
    }"#;
    let hc: ActiveHealthCheck = serde_json::from_str(json).unwrap();
    assert_eq!(hc.probe_type, HealthProbeType::Tcp);
    assert_eq!(hc.interval_seconds, 5);
    assert!(hc.udp_probe_payload.is_none());
}

#[test]
fn test_active_health_check_udp_probe_payload() {
    let json = r#"{
        "probe_type": "udp",
        "udp_probe_payload": "deadbeef"
    }"#;
    let hc: ActiveHealthCheck = serde_json::from_str(json).unwrap();
    assert_eq!(hc.probe_type, HealthProbeType::Udp);
    assert_eq!(hc.udp_probe_payload, Some("deadbeef".to_string()));
}
