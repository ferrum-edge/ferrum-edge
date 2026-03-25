use chrono::Utc;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, Proxy, ResponseBodyMode};
use ferrum_gateway::proxy::body::ProxyBody;
use http_body::Body;

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        name: Some("Test Proxy".into()),
        listen_path: "/api".into(),
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

// --- ResponseBodyMode config tests ---

#[test]
fn test_response_body_mode_defaults_to_stream() {
    let proxy = test_proxy();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_default_impl() {
    assert_eq!(ResponseBodyMode::default(), ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_buffer_variant() {
    let mut proxy = test_proxy();
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_response_body_mode_serde_stream() {
    let json = r#""stream""#;
    let mode: ResponseBodyMode = serde_json::from_str(json).unwrap();
    assert_eq!(mode, ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_serde_buffer() {
    let json = r#""buffer""#;
    let mode: ResponseBodyMode = serde_json::from_str(json).unwrap();
    assert_eq!(mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_response_body_mode_serde_roundtrip() {
    for mode in [ResponseBodyMode::Stream, ResponseBodyMode::Buffer] {
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ResponseBodyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }
}

#[test]
fn test_proxy_yaml_default_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_protocol: http
        backend_host: localhost
        backend_port: 3000
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

#[test]
fn test_proxy_yaml_buffer_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_protocol: http
        backend_host: localhost
        backend_port: 3000
        response_body_mode: buffer
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_proxy_yaml_stream_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_protocol: http
        backend_host: localhost
        backend_port: 3000
        response_body_mode: stream
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

// --- ProxyBody type tests ---

#[test]
fn test_proxy_body_full_from_bytes() {
    let body = ProxyBody::full(bytes::Bytes::from("hello world"));
    match body {
        ProxyBody::Full(_) => {} // expected
        _ => panic!("Expected Full variant"),
    }
}

#[test]
fn test_proxy_body_from_string() {
    let body = ProxyBody::from_string("hello");
    match body {
        ProxyBody::Full(_) => {} // expected
        _ => panic!("Expected Full variant"),
    }
}

#[test]
fn test_proxy_body_empty() {
    let body = ProxyBody::empty();
    assert!(body.is_end_stream());
    match body {
        ProxyBody::Full(_) => {} // expected
        _ => panic!("Expected Full variant"),
    }
}

// --- Plugin requires_response_body_buffering tests ---

#[test]
fn test_plugin_default_does_not_require_buffering() {
    use async_trait::async_trait;
    use ferrum_gateway::plugins::Plugin;

    struct TestPlugin;

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            "test_plugin"
        }
    }

    let plugin = TestPlugin;
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_plugin_can_require_buffering() {
    use async_trait::async_trait;
    use ferrum_gateway::plugins::Plugin;

    struct BufferingPlugin;

    #[async_trait]
    impl Plugin for BufferingPlugin {
        fn name(&self) -> &str {
            "buffering_plugin"
        }

        fn requires_response_body_buffering(&self) -> bool {
            true
        }
    }

    let plugin = BufferingPlugin;
    assert!(plugin.requires_response_body_buffering());
}

// --- ResponseBody enum tests ---

#[test]
fn test_response_body_buffered() {
    use ferrum_gateway::retry::ResponseBody;

    let body = ResponseBody::Buffered(b"hello".to_vec());
    match body {
        ResponseBody::Buffered(data) => assert_eq!(data, b"hello"),
        _ => panic!("Expected Buffered variant"),
    }
}

// --- Streaming mode determination logic tests ---

#[test]
fn test_streaming_mode_with_buffer_config() {
    let mut proxy = test_proxy();
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let should_stream = matches!(proxy.response_body_mode, ResponseBodyMode::Stream);
    assert!(!should_stream);
}

#[test]
fn test_streaming_mode_with_stream_config_no_plugins() {
    let proxy = test_proxy();
    let plugins: Vec<&dyn ferrum_gateway::plugins::Plugin> = vec![];
    let plugin_requires_buffering = plugins.iter().any(|p| p.requires_response_body_buffering());
    let should_stream =
        matches!(proxy.response_body_mode, ResponseBodyMode::Stream) && !plugin_requires_buffering;
    assert!(should_stream);
}
