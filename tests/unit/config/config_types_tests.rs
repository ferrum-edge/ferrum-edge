use chrono::Utc;
use ferrum_gateway::config::types::{
    AuthMode, BackendProtocol, Consumer, GatewayConfig, PluginAssociation, PluginConfig, Proxy,
    Upstream, UpstreamTarget,
};
use std::collections::HashMap;

/// Helper to create a minimal proxy with required fields.
fn make_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        name: None,
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
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_tcp_keepalive_seconds: None,
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

/// Helper to create a minimal consumer.
fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.into(),
        username: username.into(),
        custom_id: None,
        credentials: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a minimal upstream.
fn make_upstream(id: &str) -> Upstream {
    Upstream {
        id: id.into(),
        name: None,
        targets: vec![UpstreamTarget {
            host: "localhost".into(),
            port: 3000,
            weight: 100,
            tags: HashMap::new(),
        }],
        algorithm: Default::default(),
        hash_on: None,
        health_checks: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create an empty gateway config.
fn empty_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    }
}

#[test]
fn test_unique_listen_paths_valid() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                id: "1".into(),
                name: None,
                listen_path: "/api/v1".into(),
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
                pool_max_idle_per_host: Some(10),
                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                udp_idle_timeout_seconds: 60,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Proxy {
                id: "2".into(),
                name: None,
                listen_path: "/api/v2".into(),
                backend_protocol: BackendProtocol::Http,
                backend_host: "localhost".into(),
                backend_port: 3001,
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
                pool_max_idle_per_host: Some(10),
                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                udp_idle_timeout_seconds: 60,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    };
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_unique_listen_paths_duplicate() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                id: "1".into(),
                name: None,
                listen_path: "/api/v1".into(),
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
                pool_max_idle_per_host: Some(10),
                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                udp_idle_timeout_seconds: 60,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Proxy {
                id: "2".into(),
                name: None,
                listen_path: "/api/v1".into(),
                backend_protocol: BackendProtocol::Http,
                backend_host: "localhost".into(),
                backend_port: 3001,
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
                pool_max_idle_per_host: Some(10),
                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                udp_idle_timeout_seconds: 60,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
    };
    assert!(config.validate_unique_listen_paths().is_err());
}

// ---- Consumer credential uniqueness tests ----

#[test]
fn test_unique_consumer_credentials_valid() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "key-aaa"}));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "key-bbb"}));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_consumer_credentials_duplicate_keyauth() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "same-key"}));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "same-key"}));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate keyauth API key"));
    // Verify the API key value is NOT in the error message (security)
    assert!(!err[0].contains("same-key"));
}

#[test]
fn test_unique_consumer_credentials_no_keyauth_ok() {
    // Consumers without keyauth credentials should not conflict
    let c1 = make_consumer("c1", "alice");
    let c2 = make_consumer("c2", "bob");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

// ---- Upstream name uniqueness tests ----

#[test]
fn test_unique_upstream_names_valid() {
    let mut u1 = make_upstream("u1");
    u1.name = Some("backend-api".into());
    let mut u2 = make_upstream("u2");
    u2.name = Some("backend-web".into());
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    assert!(config.validate_unique_upstream_names().is_ok());
}

#[test]
fn test_unique_upstream_names_duplicate() {
    let mut u1 = make_upstream("u1");
    u1.name = Some("backend-api".into());
    let mut u2 = make_upstream("u2");
    u2.name = Some("backend-api".into());
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    let err = config.validate_unique_upstream_names().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate upstream name 'backend-api'"));
}

#[test]
fn test_unique_upstream_names_none_allowed() {
    // Multiple upstreams with no name should be fine
    let u1 = make_upstream("u1");
    let u2 = make_upstream("u2");
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    assert!(config.validate_unique_upstream_names().is_ok());
}

// ---- Proxy name uniqueness tests ----

#[test]
fn test_unique_proxy_names_valid() {
    let mut p1 = make_proxy("p1", "/api");
    p1.name = Some("api-proxy".into());
    let mut p2 = make_proxy("p2", "/web");
    p2.name = Some("web-proxy".into());
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    assert!(config.validate_unique_proxy_names().is_ok());
}

#[test]
fn test_unique_proxy_names_duplicate() {
    let mut p1 = make_proxy("p1", "/api");
    p1.name = Some("my-proxy".into());
    let mut p2 = make_proxy("p2", "/web");
    p2.name = Some("my-proxy".into());
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    let err = config.validate_unique_proxy_names().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate proxy name 'my-proxy'"));
}

#[test]
fn test_unique_proxy_names_none_allowed() {
    let p1 = make_proxy("p1", "/api");
    let p2 = make_proxy("p2", "/web");
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    assert!(config.validate_unique_proxy_names().is_ok());
}

// ---- Upstream reference validation tests ----

#[test]
fn test_upstream_references_valid() {
    let u1 = make_upstream("upstream-1");
    let mut p1 = make_proxy("p1", "/api");
    p1.upstream_id = Some("upstream-1".into());
    let mut config = empty_config();
    config.upstreams = vec![u1];
    config.proxies = vec![p1];
    assert!(config.validate_upstream_references().is_ok());
}

#[test]
fn test_upstream_references_missing() {
    let mut p1 = make_proxy("p1", "/api");
    p1.upstream_id = Some("nonexistent".into());
    let mut config = empty_config();
    config.proxies = vec![p1];
    let err = config.validate_upstream_references().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("non-existent upstream_id 'nonexistent'"));
}

#[test]
fn test_upstream_references_none_ok() {
    // Proxies without upstream_id should pass
    let p1 = make_proxy("p1", "/api");
    let mut config = empty_config();
    config.proxies = vec![p1];
    assert!(config.validate_upstream_references().is_ok());
}

// ---- Plugin name uniqueness per proxy tests ----

#[test]
fn test_unique_plugins_per_proxy_valid() {
    let mut config = empty_config();
    config.plugin_configs = vec![
        PluginConfig {
            id: "pc1".into(),
            plugin_name: "rate_limiting".into(),
            config: serde_json::json!({}),
            scope: ferrum_gateway::config::types::PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        PluginConfig {
            id: "pc2".into(),
            plugin_name: "key_auth".into(),
            config: serde_json::json!({}),
            scope: ferrum_gateway::config::types::PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    let mut p1 = make_proxy("p1", "/api");
    p1.plugins = vec![
        PluginAssociation {
            plugin_config_id: "pc1".into(),
        },
        PluginAssociation {
            plugin_config_id: "pc2".into(),
        },
    ];
    config.proxies = vec![p1];
    assert!(config.validate_unique_plugins_per_proxy().is_ok());
}

#[test]
fn test_unique_plugins_per_proxy_duplicate() {
    let mut config = empty_config();
    config.plugin_configs = vec![
        PluginConfig {
            id: "pc1".into(),
            plugin_name: "rate_limiting".into(),
            config: serde_json::json!({"window_seconds": 60}),
            scope: ferrum_gateway::config::types::PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        PluginConfig {
            id: "pc2".into(),
            plugin_name: "rate_limiting".into(),
            config: serde_json::json!({"window_seconds": 120}),
            scope: ferrum_gateway::config::types::PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    let mut p1 = make_proxy("p1", "/api");
    p1.plugins = vec![
        PluginAssociation {
            plugin_config_id: "pc1".into(),
        },
        PluginAssociation {
            plugin_config_id: "pc2".into(),
        },
    ];
    config.proxies = vec![p1];
    let err = config.validate_unique_plugins_per_proxy().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("duplicate plugin 'rate_limiting'"));
}
