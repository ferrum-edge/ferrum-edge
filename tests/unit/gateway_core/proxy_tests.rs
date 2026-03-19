use chrono::Utc;
use ferrum_gateway::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_gateway::proxy::{build_backend_url, find_matching_proxy};

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        name: Some("Test Proxy".into()),
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
        pool_max_idle_per_host: None,
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_build_backend_url_strip() {
    let proxy = test_proxy();
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_build_backend_url_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(&proxy, "/api/v1/users/123", "");
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_build_backend_url_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/internal".into());
    let url = build_backend_url(&proxy, "/api/v1/users", "");
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url(&proxy, "/api/v1/search", "q=hello&page=1");
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_longest_prefix_match() {
    let config = GatewayConfig {
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
        loaded_at: Utc::now(),
    };
    let matched = find_matching_proxy(&config, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().id, "long");
}

#[test]
fn test_no_match() {
    let config = GatewayConfig {
        proxies: vec![Proxy {
            listen_path: "/api".into(),
            ..test_proxy()
        }],
        consumers: vec![],
        plugin_configs: vec![],
        loaded_at: Utc::now(),
    };
    let matched = find_matching_proxy(&config, "/other/path");
    assert!(matched.is_none());
}
