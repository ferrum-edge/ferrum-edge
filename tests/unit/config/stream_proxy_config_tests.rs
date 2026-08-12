//! Tests for TCP/UDP stream proxy configuration types and validation.

use chrono::Utc;
use ferrum_edge::config::types::{
    ActiveHealthCheck, AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig,
    HealthProbeType, MAX_TCP_IDLE_TIMEOUT, Proxy,
};
use ferrum_edge::proxy::stream_match::{
    MAX_STREAM_MATCH_ARMS, StreamMatchArm, StreamMatchCriteria,
};
use std::collections::BTreeMap;

fn make_stream_proxy(id: &str, scheme: BackendScheme, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(scheme),
        dispatch_kind: DispatchKind::from(scheme),
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
        listen_port: Some(port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn make_http_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
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
        ..Default::default()
    }
}

fn add_stream_match(proxy: &mut Proxy) {
    proxy.stream_match = Some(StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_subnets: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        }],
    });
}

// --- BackendScheme helper method tests ---

#[test]
fn test_is_stream() {
    assert!(BackendScheme::Tcp.is_stream());
    assert!(BackendScheme::Tcps.is_stream());
    assert!(BackendScheme::Udp.is_stream());
    assert!(BackendScheme::Dtls.is_stream());
    assert!(!BackendScheme::Http.is_stream());
    assert!(!BackendScheme::Https.is_stream());
}

#[test]
fn test_is_udp() {
    assert!(BackendScheme::Udp.is_udp());
    assert!(BackendScheme::Dtls.is_udp());
    assert!(!BackendScheme::Tcp.is_udp());
    assert!(!BackendScheme::Tcps.is_udp());
    assert!(!BackendScheme::Http.is_udp());
}

#[test]
fn test_is_tls_backend() {
    assert!(BackendScheme::Tcps.is_tls_backend());
    assert!(BackendScheme::Dtls.is_tls_backend());
    assert!(!BackendScheme::Tcp.is_tls_backend());
    assert!(!BackendScheme::Udp.is_tls_backend());
    assert!(!BackendScheme::Http.is_tls_backend());
}

// --- BackendScheme serialization tests ---

#[test]
fn test_backend_scheme_display() {
    assert_eq!(BackendScheme::Tcp.to_string(), "tcp");
    assert_eq!(BackendScheme::Tcps.to_string(), "tcps");
    assert_eq!(BackendScheme::Udp.to_string(), "udp");
    assert_eq!(BackendScheme::Dtls.to_string(), "dtls");
}

#[test]
fn test_backend_scheme_serde_roundtrip() {
    for scheme in [
        BackendScheme::Tcp,
        BackendScheme::Tcps,
        BackendScheme::Udp,
        BackendScheme::Dtls,
    ] {
        let json = serde_json::to_string(&scheme).unwrap();
        let parsed: BackendScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(scheme, parsed);
    }
}

#[test]
fn test_tcps_serde_name() {
    let json = r#""tcps""#;
    let scheme: BackendScheme = serde_json::from_str(json).unwrap();
    assert_eq!(scheme, BackendScheme::Tcps);
}

// --- Stream proxy validation tests ---

#[test]
fn test_validate_stream_proxy_valid() {
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendScheme::Tcp, 5432),
        make_stream_proxy("udp1", BackendScheme::Udp, 5353),
    ]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_validate_stream_proxy_missing_listen_port() {
    let mut proxy = make_stream_proxy("tcp1", BackendScheme::Tcp, 5432);
    proxy.listen_port = None;
    let config = test_config(vec![proxy]);
    let err = config.validate_stream_proxies().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("must have a listen_port"));
}

#[test]
fn test_validate_stream_proxy_duplicate_port() {
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendScheme::Tcp, 5432),
        make_stream_proxy("tcp2", BackendScheme::Tcps, 5432),
    ]);
    let err = config.validate_stream_proxies().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate listen_port"));
}

#[test]
fn test_shared_l4_listener_rejects_incompatible_listener_behavior() {
    let mut matched = make_stream_proxy("matched", BackendScheme::Tcp, 5432);
    add_stream_match(&mut matched);
    let mut different_scheme = make_stream_proxy("different-scheme", BackendScheme::Tcps, 5432);
    let errors = test_config(vec![matched.clone(), different_scheme.clone()])
        .validate_stream_proxies()
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("mixes backend schemes"))
    );

    different_scheme = make_stream_proxy("different-frontend", BackendScheme::Tcp, 5432);
    different_scheme.frontend_tls = true;
    let errors = test_config(vec![matched, different_scheme])
        .validate_stream_proxies()
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("mixes frontend_tls"))
    );

    let mut tls_matched = make_stream_proxy("tls-matched", BackendScheme::Tcps, 5432);
    add_stream_match(&mut tls_matched);
    tls_matched.resolved_tls = BackendTlsConfig::default_verify();
    let mut different_tls = make_stream_proxy("different-tls", BackendScheme::Tcps, 5432);
    different_tls.resolved_tls = BackendTlsConfig::default_verify();
    different_tls.resolved_tls.server_ca_cert_path = Some("/different/ca.pem".to_string());
    let errors = test_config(vec![tls_matched, different_tls])
        .validate_stream_proxies()
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("mixes backend TLS listener settings"))
    );
}

#[test]
fn test_stream_match_is_rejected_for_unimplemented_datagram_path() {
    for scheme in [BackendScheme::Udp, BackendScheme::Dtls] {
        let mut proxy = make_stream_proxy("datagram-match", scheme, 5353);
        add_stream_match(&mut proxy);
        let errors = proxy.validate_fields().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("only valid for tcp/tcps")),
            "{scheme} must not silently ignore stream_match: {errors:?}"
        );
    }
}

#[test]
fn test_direct_stream_match_rejects_invalid_kubernetes_identity_fields() {
    let invalid_arms = [
        StreamMatchArm {
            source_labels: BTreeMap::from([("bad key".to_string(), "ok".to_string())]),
            ..Default::default()
        },
        StreamMatchArm {
            source_labels: BTreeMap::from([("app".to_string(), "bad/value".to_string())]),
            ..Default::default()
        },
        StreamMatchArm {
            source_namespace: Some("Team_A".to_string()),
            ..Default::default()
        },
        StreamMatchArm {
            gateways: vec!["ingress".to_string()],
            ..Default::default()
        },
        StreamMatchArm {
            gateways: vec!["team-a/Bad_Name".to_string()],
            ..Default::default()
        },
        StreamMatchArm {
            source_subnets: vec!["10.0.0.0/999".to_string()],
            ..Default::default()
        },
    ];

    for arm in invalid_arms {
        let mut proxy = make_stream_proxy("invalid-direct-match", BackendScheme::Tcp, 5432);
        proxy.stream_match = Some(StreamMatchCriteria { arms: vec![arm] });
        let errors = proxy.validate_fields().unwrap_err();
        assert!(
            errors.iter().any(|error| error.contains("stream_match")),
            "direct config must reject invalid matcher fields: {errors:?}"
        );
    }
}

#[test]
fn test_direct_stream_match_accepts_empty_kubernetes_label_value() {
    let mut proxy = make_stream_proxy("empty-label-value", BackendScheme::Tcp, 5432);
    proxy.stream_match = Some(StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app.kubernetes.io/name".to_string(), String::new())]),
            ..Default::default()
        }],
    });
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_direct_stream_match_enforces_public_arm_bound() {
    let mut proxy = make_stream_proxy("too-many-arms", BackendScheme::Tcp, 5432);
    proxy.stream_match = Some(StreamMatchCriteria {
        arms: (0..=MAX_STREAM_MATCH_ARMS)
            .map(|_| StreamMatchArm {
                gateways: vec!["mesh".to_string()],
                ..Default::default()
            })
            .collect(),
    });
    let errors = proxy.validate_fields().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("at most") && error.contains("arms"))
    );
}

#[test]
fn test_validate_http_proxy_with_listen_port_allowed() {
    let mut proxy = make_http_proxy("http1", "/api");
    proxy.listen_port = Some(8080);
    let config = test_config(vec![proxy]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_validate_mixed_http_and_stream_proxies() {
    let config = test_config(vec![
        make_http_proxy("http1", "/api"),
        make_stream_proxy("tcp1", BackendScheme::Tcp, 5432),
        make_stream_proxy("udp1", BackendScheme::Udp, 5353),
    ]);
    assert!(config.validate_stream_proxies().is_ok());
}

// --- Gateway port conflict validation ---

#[test]
fn test_validate_stream_proxy_no_gateway_port_conflicts() {
    let reserved: std::collections::HashSet<u16> = [8000, 8443, 9000, 9443].into();
    let config = test_config(vec![
        make_stream_proxy("tcp1", BackendScheme::Tcp, 5432),
        make_stream_proxy("udp1", BackendScheme::Udp, 5353),
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
    let config = test_config(vec![make_stream_proxy("tcp1", BackendScheme::Tcp, 8000)]);
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
    let config = test_config(vec![make_stream_proxy("udp1", BackendScheme::Udp, 9000)]);
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
        make_stream_proxy("tcp1", BackendScheme::Tcp, 8000),
        make_stream_proxy("tcp2", BackendScheme::Tcps, 9443),
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
backend_scheme: tcp
backend_host: "db.example.com"
backend_port: 5432
listen_port: 15432
frontend_tls: true
udp_idle_timeout_seconds: 30
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
    assert_eq!(proxy.listen_path, None);
    assert_eq!(proxy.listen_port, Some(15432));
    assert!(proxy.frontend_tls);
    assert_eq!(proxy.udp_idle_timeout_seconds, 30);
}

#[test]
fn test_udp_proxy_json_deserialization() {
    let json = r#"{
        "id": "udp-proxy-1",
        "backend_scheme": "udp",
        "backend_host": "dns.example.com",
        "backend_port": 53,
        "listen_port": 10053,
        "udp_idle_timeout_seconds": 120
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Udp));
    assert_eq!(proxy.listen_path, None);
    assert_eq!(proxy.listen_port, Some(10053));
    assert_eq!(proxy.udp_idle_timeout_seconds, 120);
    assert!(!proxy.frontend_tls);
}

#[test]
fn test_stream_proxy_defaults() {
    let json = r#"{
        "id": "tcp1",
        "backend_scheme": "tcp",
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
        "backend_scheme": "tcp",
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
        "backend_scheme": "tcp",
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
        "backend_scheme": "tcp",
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
        "backend_scheme": "tcp",
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
        "backend_scheme": "tcp",
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
backend_scheme: tcp
backend_host: "db.example.com"
backend_port: 5432
listen_port: 15432
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert!(!proxy.passthrough);
}

#[test]
fn test_passthrough_valid_tcp() {
    let mut proxy = make_stream_proxy("tcp-pass", BackendScheme::Tcp, 15432);
    proxy.passthrough = true;
    proxy.frontend_tls = false;
    assert!(proxy.validate_fields().is_ok());
}

#[test]
fn test_passthrough_valid_udp() {
    let mut proxy = make_stream_proxy("udp-pass", BackendScheme::Udp, 10053);
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
    let mut proxy = make_stream_proxy("tcp-both", BackendScheme::Tcp, 15432);
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
    let mut proxy = make_stream_proxy("tcp-pass-tls", BackendScheme::Tcps, 15432);
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
backend_scheme: tcp
backend_host: "db.internal"
backend_port: 5432
listen_port: 15432
passthrough: true
"#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert!(proxy.passthrough);
    assert!(!proxy.frontend_tls);
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
}

// --- SNI-based port sharing tests ---

#[test]
fn test_passthrough_port_sharing_allowed() {
    let mut p1 = make_stream_proxy("pt-a", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-b", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["b.example.com".to_string()];

    let config = test_config(vec![p1, p2]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_shared_listener_rejects_mixed_scheme() {
    let mut plain = make_stream_proxy("pt-plain", BackendScheme::Tcp, 8444);
    plain.passthrough = true;
    plain.hosts = vec!["a.example.com".to_string()];

    let mut tls_scheme = make_stream_proxy("pt-tcps", BackendScheme::Tcps, 8444);
    tls_scheme.passthrough = true;
    tls_scheme.hosts = vec!["b.example.com".to_string()];

    let errors = test_config(vec![plain, tls_scheme])
        .validate_stream_proxies()
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("mixes backend schemes"))
    );
}

/// Issue #3264: an empty-`hosts` candidate is the group's DEFAULT route, not a
/// competing claim on every hostname. The runtime tier ladder puts it strictly
/// behind every exact and wildcard host, and `catch_all_count` already caps it
/// at one — so treating it as an "overlap" made both the documented third tier
/// and that cap unreachable in validated shared config.
#[test]
fn test_passthrough_port_sharing_with_catchall() {
    let mut p1 = make_stream_proxy("pt-specific", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["specific.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-catchall", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec![]; // catch-all / default route

    let config = test_config(vec![p1, p2]);
    assert!(
        config.validate_stream_proxies().is_ok(),
        "exactly one default route may coexist with named SNI routes: {:?}",
        config.validate_stream_proxies()
    );
}

#[test]
fn test_passthrough_port_sharing_rejected_for_non_passthrough() {
    let mut p1 = make_stream_proxy("pt", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];

    let p2 = make_stream_proxy("non-pt", BackendScheme::Tcp, 8444);
    // p2.passthrough is false by default

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("mixes passthrough and non-passthrough proxies"))
    );
}

#[test]
fn test_passthrough_port_sharing_overlapping_hosts_rejected() {
    let mut p1 = make_stream_proxy("pt-a", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["shared.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-b", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["shared.example.com".to_string()]; // overlaps with p1

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("overlapping hosts")));
}

#[test]
fn test_passthrough_overlapping_hosts_with_l4_match_preserve_order() {
    let mut first = make_stream_proxy("pt-first", BackendScheme::Tcp, 8444);
    first.passthrough = true;
    first.hosts = vec!["*.example.com".to_string()];
    add_stream_match(&mut first);

    let mut second = make_stream_proxy("pt-second", BackendScheme::Tcp, 8444);
    second.passthrough = true;
    second.hosts = vec!["secure.example.com".to_string()];
    add_stream_match(&mut second);

    let config = test_config(vec![first, second]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_port_sharing_mixed_stream_proxy_protocol_rejected() {
    // The PROXY header is parsed before the TLS ClientHello, so SNI-based
    // proxy resolution cannot vary the decision per proxy: every proxy
    // sharing a listener port must agree on stream_proxy_protocol.
    let mut p1 = make_stream_proxy("pt-pp", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];
    p1.stream_proxy_protocol = Some(true);

    let mut p2 = make_stream_proxy("pt-no-pp", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["b.example.com".to_string()];

    let config = test_config(vec![p1, p2]);
    let errors = config.validate_stream_proxies().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("mixes stream_proxy_protocol")),
        "expected mixed stream_proxy_protocol rejection, got: {errors:?}"
    );
}

#[test]
fn test_passthrough_port_sharing_uniform_stream_proxy_protocol_accepted() {
    let mut p1 = make_stream_proxy("pt-pp-a", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["a.example.com".to_string()];
    p1.stream_proxy_protocol = Some(true);

    let mut p2 = make_stream_proxy("pt-pp-b", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["b.example.com".to_string()];
    p2.stream_proxy_protocol = Some(true);

    let config = test_config(vec![p1, p2]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_port_sharing_wildcard_hosts() {
    let mut p1 = make_stream_proxy("pt-wild", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec!["*.example.com".to_string()];

    let mut p2 = make_stream_proxy("pt-other", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec!["other.org".to_string()];

    let config = test_config(vec![p1, p2]);
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_passthrough_port_sharing_two_catchalls_rejected() {
    let mut p1 = make_stream_proxy("pt-a", BackendScheme::Tcp, 8444);
    p1.passthrough = true;
    p1.hosts = vec![];

    let mut p2 = make_stream_proxy("pt-b", BackendScheme::Tcp, 8444);
    p2.passthrough = true;
    p2.hosts = vec![];

    let config = test_config(vec![p1, p2]);
    let result = config.validate_stream_proxies();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("at most one catch-all")));
}

// ── Issue #3264: general opaque-TLS SNI routing outside passthrough ──────────

/// Two ordinary `tcp` listeners distinguished only by SNI now form one shared
/// SNI-routed listener. Before #3264 this was rejected outright ("all proxies
/// sharing a port must have passthrough: true"), so a plain opaque TLS fanout
/// could not be expressed at all.
#[test]
fn opaque_tcp_listeners_may_share_a_port_when_distinguished_by_sni() {
    let mut a = make_stream_proxy("tenant-a", BackendScheme::Tcp, 8443);
    a.hosts = vec!["tenant-a.example.com".to_string()];
    let mut b = make_stream_proxy("tenant-b", BackendScheme::Tcp, 8443);
    b.hosts = vec!["tenant-b.example.com".to_string()];

    let config = test_config(vec![a, b]);
    assert!(
        config.validate_stream_proxies().is_ok(),
        "SNI-distinguished opaque tcp listeners must share a port: {:?}",
        config.validate_stream_proxies()
    );
}

/// The SNI group's uniqueness rules apply to ordinary `tcp` listeners exactly
/// as they do to passthrough ones: one hostname, one owner.
#[test]
fn opaque_tcp_sni_group_rejects_overlapping_hosts() {
    let mut a = make_stream_proxy("tenant-a", BackendScheme::Tcp, 8443);
    a.hosts = vec!["shared.example.com".to_string()];
    let mut b = make_stream_proxy("tenant-b", BackendScheme::Tcp, 8443);
    b.hosts = vec!["shared.example.com".to_string()];

    let errors = test_config(vec![a, b])
        .validate_stream_proxies()
        .expect_err("one hostname must not have two owners");
    assert!(errors.iter().any(|e| e.contains("overlapping hosts")));
}

/// A wildcard route and an exact route below it are NOT a conflict — the tier
/// ladder resolves them deterministically (exact beats wildcard).
#[test]
fn opaque_tcp_sni_group_allows_wildcard_plus_exact_and_one_catch_all() {
    let mut wild = make_stream_proxy("wild", BackendScheme::Tcp, 8443);
    wild.hosts = vec!["*.example.com".to_string()];
    let mut catch_all = make_stream_proxy("catch-all", BackendScheme::Tcp, 8443);
    catch_all.hosts = vec![];
    let mut other = make_stream_proxy("other", BackendScheme::Tcp, 8443);
    other.hosts = vec!["other.org".to_string()];

    let config = test_config(vec![wild, catch_all, other]);
    assert!(
        config.validate_stream_proxies().is_ok(),
        "{:?}",
        config.validate_stream_proxies()
    );
}

#[test]
fn opaque_tcp_sni_group_rejects_two_catch_alls() {
    let mut named = make_stream_proxy("named", BackendScheme::Tcp, 8443);
    named.hosts = vec!["a.example.com".to_string()];
    let first = make_stream_proxy("catch-all-1", BackendScheme::Tcp, 8443);
    let second = make_stream_proxy("catch-all-2", BackendScheme::Tcp, 8443);

    let errors = test_config(vec![named, first, second])
        .validate_stream_proxies()
        .expect_err("a port must not have two default routes");
    assert!(errors.iter().any(|e| e.contains("at most one catch-all")));
}

/// A shared listener socket is built from one representative before any route
/// is selected, so passthrough must be homogeneous on the port.
#[test]
fn shared_sni_port_rejects_mixed_passthrough() {
    let mut pt = make_stream_proxy("pt", BackendScheme::Tcp, 8443);
    pt.passthrough = true;
    pt.hosts = vec!["a.example.com".to_string()];
    let mut plain = make_stream_proxy("plain", BackendScheme::Tcp, 8443);
    plain.hosts = vec!["b.example.com".to_string()];

    let errors = test_config(vec![pt, plain])
        .validate_stream_proxies()
        .expect_err("mixed passthrough on one port must be rejected");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("mixes passthrough and non-passthrough proxies"))
    );
}

/// `hosts` is a TLS `server_name` predicate. On a listener that terminates or
/// re-originates crypto it can never be read, and silently ignoring it made an
/// operator believe the listener admitted one hostname when it admitted every
/// connection on the port. It is now a field-specific rejection.
#[test]
fn hosts_on_a_terminating_stream_listener_is_rejected_not_ignored() {
    let mut terminating = make_stream_proxy("tls-term", BackendScheme::Tcp, 8443);
    terminating.frontend_tls = true;
    terminating.hosts = vec!["a.example.com".to_string()];

    let errors = test_config(vec![terminating])
        .validate_stream_proxies()
        .expect_err("inert hosts must not be silently accepted");
    assert!(
        errors.iter().any(|e| e.contains("cannot route by SNI")),
        "{errors:?}"
    );
}

#[test]
fn hosts_on_a_backend_tls_originating_stream_listener_is_rejected() {
    let mut originating = make_stream_proxy("tcps", BackendScheme::Tcps, 8443);
    originating.hosts = vec!["a.example.com".to_string()];

    let errors = test_config(vec![originating])
        .validate_stream_proxies()
        .expect_err("tcps re-originates TLS, so hosts is not a route predicate");
    assert!(
        errors.iter().any(|e| e.contains("cannot route by SNI")),
        "{errors:?}"
    );
}

#[test]
fn hosts_on_a_non_passthrough_udp_listener_is_rejected() {
    let mut udp = make_stream_proxy("udp", BackendScheme::Udp, 8443);
    udp.hosts = vec!["a.example.com".to_string()];

    let errors = test_config(vec![udp])
        .validate_stream_proxies()
        .expect_err("a non-passthrough UDP listener has no ClientHello to peek");
    assert!(
        errors.iter().any(|e| e.contains("cannot route by SNI")),
        "{errors:?}"
    );
}

/// DTLS passthrough keeps using `hosts` for SNI routing (it peeks the DTLS
/// ClientHello), so the new rejection must not catch it.
#[test]
fn hosts_on_a_dtls_passthrough_listener_stays_valid() {
    let mut a = make_stream_proxy("dtls-a", BackendScheme::Dtls, 8443);
    a.passthrough = true;
    a.hosts = vec!["a.example.com".to_string()];
    let mut b = make_stream_proxy("dtls-b", BackendScheme::Dtls, 8443);
    b.passthrough = true;
    b.hosts = vec!["b.example.com".to_string()];

    let config = test_config(vec![a, b]);
    assert!(
        config.validate_stream_proxies().is_ok(),
        "{:?}",
        config.validate_stream_proxies()
    );
}

/// Two plain `tcp` listeners with neither hosts nor stream_match remain a plain
/// duplicate-port error: nothing distinguishes them.
#[test]
fn opaque_tcp_listeners_without_hosts_or_stream_match_still_conflict() {
    let errors = test_config(vec![
        make_stream_proxy("a", BackendScheme::Tcp, 8443),
        make_stream_proxy("b", BackendScheme::Tcp, 8443),
    ])
    .validate_stream_proxies()
    .expect_err("indistinguishable listeners must not share a port");
    assert!(errors.iter().any(|e| e.contains("Duplicate listen_port")));
}

/// `joins_opaque_tls_sni_plane` is the single predicate shared by validation and
/// listener grouping. Lock its truth table so the two cannot drift apart.
#[test]
fn opaque_tls_sni_plane_membership_truth_table() {
    let plain = make_stream_proxy("plain", BackendScheme::Tcp, 8443);
    assert!(plain.joins_opaque_tls_sni_plane());

    let mut terminating = make_stream_proxy("term", BackendScheme::Tcp, 8443);
    terminating.frontend_tls = true;
    assert!(!terminating.joins_opaque_tls_sni_plane());

    let originating = make_stream_proxy("tcps", BackendScheme::Tcps, 8443);
    assert!(!originating.joins_opaque_tls_sni_plane());

    let udp = make_stream_proxy("udp", BackendScheme::Udp, 8443);
    assert!(!udp.joins_opaque_tls_sni_plane());

    let mut udp_passthrough = make_stream_proxy("udp-pt", BackendScheme::Dtls, 8443);
    udp_passthrough.passthrough = true;
    assert!(
        udp_passthrough.joins_opaque_tls_sni_plane(),
        "DTLS passthrough peeks its own ClientHello and stays on the plane"
    );
}

/// The SNI conflict rule is tier-aware: only a tie INSIDE one tier is
/// ambiguous. Cross-tier pairs (exact under a wildcard, anything above the
/// catch-all) are resolved deterministically by the runtime ladder, so
/// rejecting them made the wildcard and default tiers unconfigurable.
#[test]
fn sni_conflict_rejection_is_tier_aware() {
    let case = |a: Vec<&str>, b: Vec<&str>| {
        let mut first = make_stream_proxy("first", BackendScheme::Tcp, 8443);
        first.hosts = a.into_iter().map(String::from).collect();
        let mut second = make_stream_proxy("second", BackendScheme::Tcp, 8443);
        second.hosts = b.into_iter().map(String::from).collect();
        test_config(vec![first, second])
            .validate_stream_proxies()
            .err()
            .map(|errors| errors.iter().any(|e| e.contains("overlapping hosts")))
            .unwrap_or(false)
    };

    // Same tier, same claim → ambiguous.
    assert!(case(vec!["a.example.com"], vec!["a.example.com"]));
    assert!(case(vec!["*.example.com"], vec!["*.example.com"]));
    // Nested wildcards can both match `x.a.example.com`.
    assert!(case(vec!["*.example.com"], vec!["*.a.example.com"]));
    assert!(case(vec!["*.a.example.com"], vec!["*.example.com"]));

    // Different tiers → deterministic, so allowed.
    assert!(!case(vec!["api.example.com"], vec!["*.example.com"]));
    assert!(!case(vec!["*.example.com"], vec!["api.example.com"]));
    assert!(!case(vec!["api.example.com"], vec![]));
    assert!(!case(vec![], vec!["api.example.com"]));

    // Unrelated names never conflict.
    assert!(!case(vec!["a.example.com"], vec!["b.example.com"]));
    assert!(!case(vec!["*.foo.com"], vec!["*.bar.com"]));
}
