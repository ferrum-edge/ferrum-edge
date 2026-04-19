//! Tests for TCP/UDP stream proxy configuration types and validation.

use chrono::Utc;
use ferrum_edge::config::types::{
    ActiveHealthCheck, AuthMode, BackendProtocol, GatewayConfig, HealthProbeType,
    MAX_TCP_IDLE_TIMEOUT, Proxy,
};

fn make_stream_proxy(id: &str, protocol: BackendProtocol, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: None,
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(port),
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

fn make_http_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
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

fn test_config(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
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

// --- Gateway port conflict validation ---

#[test]
fn test_validate_stream_proxy_no_gateway_port_conflicts() {
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendProtocol::Tcp, 5432),
        make_stream_proxy("udp1", BackendProtocol::Udp, 5353),
    ]);
    assert!(
        config
            .validate_stream_proxy_port_conflicts(&reserved)
            .is_ok()
    );
}

#[test]
fn test_validate_stream_proxy_conflicts_with_proxy_http_port() {
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![make_stream_proxy("tcp1", BackendProtocol::Tcp, 8000)]);
    let err = config
        .validate_stream_proxy_port_conflicts(&reserved)
        .unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("conflicts with a gateway reserved port"));
    assert!(err[0].contains("8000"));
}

#[test]
fn test_validate_stream_proxy_conflicts_with_admin_port() {
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![make_stream_proxy("udp1", BackendProtocol::Udp, 9000)]);
    let err = config
        .validate_stream_proxy_port_conflicts(&reserved)
        .unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("9000"));
}

#[test]
fn test_validate_stream_proxy_multiple_gateway_conflicts() {
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendProtocol::Tcp, 8000),
        make_stream_proxy("tcp2", BackendProtocol::TcpTls, 9443),
    ]);
    let err = config
        .validate_stream_proxy_port_conflicts(&reserved)
        .unwrap_err();
    assert_eq!(err.len(), 2);
}

#[test]
fn test_validate_http_proxy_ignored_for_port_conflicts() {
    // HTTP proxies don't have listen_port, so they should not trigger conflicts
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![make_http_proxy("http1", "/api")]);
    assert!(
        config
            .validate_stream_proxy_port_conflicts(&reserved)
            .is_ok()
    );
}

// --- Proxy struct deserialization with stream fields ---
//
// Stream proxies now route on listen_port and must NOT set listen_path. The
// deserializer no longer requires listen_path to be present (it is Option<_>
// with serde(default)); stream proxy fixtures simply omit the field entirely.

#[test]
fn test_tcp_proxy_yaml_deserialization() {
    let yaml = r#"
id: "tcp-proxy-1"
backend_protocol: tcp
backend_host: "db.example.com"
backend_port: 5432
listen_port: 15432
frontend_tls: true
udp_idle_timeout_seconds: 30
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.backend_protocol, BackendProtocol::Tcp);
    assert_eq!(proxy.listen_path, None);
    assert_eq!(proxy.listen_port, Some(15432));
    assert!(proxy.frontend_tls);
    assert_eq!(proxy.udp_idle_timeout_seconds, 30);
}

#[test]
fn test_udp_proxy_json_deserialization() {
    let json = r#"{
        "id": "udp-proxy-1",
        "backend_protocol": "udp",
        "backend_host": "dns.example.com",
        "backend_port": 53,
        "listen_port": 10053,
        "udp_idle_timeout_seconds": 120
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.backend_protocol, BackendProtocol::Udp);
    assert_eq!(proxy.listen_path, None);
    assert_eq!(proxy.listen_port, Some(10053));
    assert_eq!(proxy.udp_idle_timeout_seconds, 120);
    assert!(!proxy.frontend_tls);
}

#[test]
fn test_stream_proxy_defaults() {
    let json = r#"{
        "id": "tcp1",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.listen_path, None);
    assert_eq!(proxy.listen_port, None);
    assert!(!proxy.frontend_tls);
    assert_eq!(proxy.udp_idle_timeout_seconds, 60);
}

// --- TCP idle timeout tests ---

#[test]
fn test_tcp_idle_timeout_default_is_none() {
    let json = r#"{
        "id": "tcp1",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.tcp_idle_timeout_seconds, None);
}

#[test]
fn test_tcp_idle_timeout_explicit_value() {
    let json = r#"{
        "id": "tcp2",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432,
        "tcp_idle_timeout_seconds": 600
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.tcp_idle_timeout_seconds, Some(600));
}

#[test]
fn test_tcp_idle_timeout_zero_is_disabled() {
    let json = r#"{
        "id": "tcp3",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432,
        "tcp_idle_timeout_seconds": 0
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.tcp_idle_timeout_seconds, Some(0));
    // Validation should accept 0 (disabled)
    if let Err(errors) = proxy.validate_fields() {
        assert!(
            !errors.iter().any(|e| e.contains("tcp_idle_timeout")),
            "tcp_idle_timeout_seconds: 0 should be valid (disabled), got errors: {:?}",
            errors
        );
    }
}

#[test]
fn test_tcp_idle_timeout_max_is_valid() {
    let json = format!(
        r#"{{
        "id": "tcp4",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432,
        "tcp_idle_timeout_seconds": {}
    }}"#,
        MAX_TCP_IDLE_TIMEOUT
    );
    let proxy: Proxy = serde_json::from_str(&json).unwrap();
    assert_eq!(proxy.tcp_idle_timeout_seconds, Some(MAX_TCP_IDLE_TIMEOUT));
    if let Err(errors) = proxy.validate_fields() {
        assert!(
            !errors.iter().any(|e| e.contains("tcp_idle_timeout")),
            "tcp_idle_timeout_seconds at max should be valid, got errors: {:?}",
            errors
        );
    }
}

#[test]
fn test_tcp_idle_timeout_over_max_is_rejected() {
    let json = format!(
        r#"{{
        "id": "tcp5",
        "backend_protocol": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432,
        "tcp_idle_timeout_seconds": {}
    }}"#,
        MAX_TCP_IDLE_TIMEOUT + 1
    );
    let proxy: Proxy = serde_json::from_str(&json).unwrap();
    let result = proxy.validate_fields();
    assert!(
        matches!(&result, Err(errors) if errors.iter().any(|e| e.contains("tcp_idle_timeout_seconds"))),
        "tcp_idle_timeout_seconds above max should fail validation, got: {:?}",
        result
    );
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

// --- Passthrough mode tests ---

#[test]
fn test_passthrough_default_false() {
    let yaml = r#"
id: "tcp-pass-1"
backend_protocol: tcp
backend_host: "db.example.com"
backend_port: 5432
listen_port: 15432
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert!(!proxy.passthrough);
}

#[test]
fn test_passthrough_valid_tcp() {
    let mut proxy = make_stream_proxy("tcp-pass", BackendProtocol::Tcp, 15432);
    proxy.passthrough = true;
    proxy.frontend_tls = false;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_passthrough_valid_udp() {
    let mut proxy = make_stream_proxy("udp-pass", BackendProtocol::Udp, 10053);
    proxy.passthrough = true;
    proxy.frontend_tls = false;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_passthrough_rejected_on_http_proxy() {
    let mut proxy = make_http_proxy("http-pass", "/api");
    proxy.passthrough = true;
    let result = proxy.validate_fields();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("passthrough is only supported for stream proxies"))
    );
}

#[test]
fn test_passthrough_and_frontend_tls_mutually_exclusive() {
    let mut proxy = make_stream_proxy("tcp-both", BackendProtocol::Tcp, 15432);
    proxy.passthrough = true;
    proxy.frontend_tls = true;
    let result = proxy.validate_fields();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("passthrough and frontend_tls are mutually exclusive"))
    );
}

#[test]
fn test_passthrough_rejects_backend_tls_fields() {
    let mut proxy = make_stream_proxy("tcp-pass-tls", BackendProtocol::TcpTls, 15432);
    proxy.passthrough = true;
    proxy.backend_tls_client_cert_path = Some("/tmp/cert.pem".to_string());
    proxy.backend_tls_client_key_path = Some("/tmp/key.pem".to_string());
    let result = proxy.validate_fields();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| {
        e.contains("backend_tls_client_cert_path cannot be set when passthrough is true")
    }));
}

#[test]
fn test_passthrough_yaml_deserialization() {
    let yaml = r#"
id: "tcp-pass-yaml"
backend_protocol: tcp
backend_host: "db.internal"
backend_port: 5432
listen_port: 15432
passthrough: true
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert!(proxy.passthrough);
    assert!(!proxy.frontend_tls);
    assert_eq!(proxy.backend_protocol, BackendProtocol::Tcp);
}

// --- SNI-based port sharing tests ---

#[test]
fn test_passthrough_port_sharing_allowed() {
    let mut p1 = make_stream_proxy("pt-a", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-b", BackendProtocol::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["b.example.com".to_string()];

    let config = test_config(vec![p1, p2]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_port_sharing_with_catchall() {
    let mut p1 = make_stream_proxy("pt-specific", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["specific.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-catchall", BackendProtocol::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec![]; // catch-all

    let config = test_config(vec![p1, p2]);
    // Catch-all overlaps with everything — rejected
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("overlapping hosts")));
}

#[test]
fn test_passthrough_port_sharing_rejected_for_non_passthrough() {
    let mut p1 = make_stream_proxy("pt", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];

    let p2 = make_stream_proxy("non-pt", BackendProtocol::Tcp, 8444);
    // p2.passthrough is false by default

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("all proxies sharing a port must have passthrough: true"))
    );
}

#[test]
fn test_passthrough_port_sharing_overlapping_hosts_rejected() {
    let mut p1 = make_stream_proxy("pt-a", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["shared.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-b", BackendProtocol::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["shared.example.com".to_string()]; // overlaps with p1

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("overlapping hosts")));
}

#[test]
fn test_passthrough_port_sharing_wildcard_hosts() {
    let mut p1 = make_stream_proxy("pt-wild", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["*.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-other", BackendProtocol::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["other.org".to_string()];

    let config = test_config(vec![p1, p2]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_port_sharing_two_catchalls_rejected() {
    let mut p1 = make_stream_proxy("pt-a", BackendProtocol::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec![];

    let mut p2 = make_stream_proxy("pt-b", BackendProtocol::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec![];

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("at most one catch-all")));
}
