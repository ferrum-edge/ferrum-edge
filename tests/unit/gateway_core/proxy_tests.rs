use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_edge::proxy::{build_backend_url, build_backend_url_with_target};
use ferrum_edge::router_cache::RouterCache;

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        name: Some("Test Proxy".into()),
        hosts: vec![],
        listen_path: "/api/v1".into(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "backend.example.com".into(),
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
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_build_backend_url_strip() {
    let proxy = test_proxy();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "", proxy.listen_path.len());
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_build_backend_url_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(&proxy, "/api/v1/users/123", "", proxy.listen_path.len());
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_build_backend_url_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/internal".into());
    let url = build_backend_url(&proxy, "/api/v1/users", "", proxy.listen_path.len());
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/search",
        "q=hello&page=1",
        proxy.listen_path.len(),
    );
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_build_backend_url_target_path_overrides_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.len(),
        Some("/v2"),
    );
    assert_eq!(url, "http://target.example.com:9090/v2/users");
}

#[test]
fn test_build_backend_url_target_path_none_uses_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.len(),
        None,
    );
    assert_eq!(url, "http://target.example.com:9090/v1/users");
}

#[test]
fn test_build_backend_url_target_path_with_no_backend_path() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.len(),
        Some("/service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/search",
        "q=hello",
        "target.example.com",
        9090,
        proxy.listen_path.len(),
        Some("/svc"),
    );
    assert_eq!(url, "http://target.example.com:9090/svc/search?q=hello");
}

#[test]
fn test_longest_prefix_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                listen_path: "/api".into(),
                id: "short".into(),
                ..test_proxy()
            },
            Proxy {
                listen_path: "/api/v1".into(),
                id: "long".into(),
                ..test_proxy()
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "long");
}

#[test]
fn test_no_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![Proxy {
            listen_path: "/api".into(),
            ..test_proxy()
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/other/path");
    assert!(matched.is_none());
}
