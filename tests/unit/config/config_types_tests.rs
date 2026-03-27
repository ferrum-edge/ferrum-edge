use chrono::Utc;
use ferrum_gateway::config::types::{
    AuthMode, BackendProtocol, Consumer, GatewayConfig, PluginAssociation, PluginConfig, Proxy,
    Upstream, UpstreamTarget, hosts_overlap, validate_host_entry, validate_resource_id,
    wildcard_matches,
};
use std::collections::HashMap;

/// Helper to create a minimal proxy with required fields.
fn make_proxy(id: &str, listen_path: &str) -> Proxy {
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
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
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
        service_discovery: None,
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
                hosts: vec![],
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
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
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
                hosts: vec![],
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
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
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
                hosts: vec![],
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
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
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
                hosts: vec![],
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
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
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

// ---- Resource ID validation tests ----

#[test]
fn test_validate_resource_id_valid_uuid() {
    assert!(validate_resource_id("f47ac10b-58cc-4372-a567-0e02b2c3d479").is_ok());
}

#[test]
fn test_validate_resource_id_valid_slug() {
    assert!(validate_resource_id("proxy-httpbin").is_ok());
    assert!(validate_resource_id("consumer.alice").is_ok());
    assert!(validate_resource_id("upstream_backend-v2").is_ok());
    assert!(validate_resource_id("a").is_ok());
    assert!(validate_resource_id("A1").is_ok());
}

#[test]
fn test_validate_resource_id_empty() {
    let err = validate_resource_id("").unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_validate_resource_id_too_long() {
    let long_id = "a".repeat(255);
    let err = validate_resource_id(&long_id).unwrap_err();
    assert!(err.contains("at most 254"));
}

#[test]
fn test_validate_resource_id_max_length_ok() {
    let id = "a".repeat(254);
    assert!(validate_resource_id(&id).is_ok());
}

#[test]
fn test_validate_resource_id_invalid_start() {
    assert!(validate_resource_id("-proxy").is_err());
    assert!(validate_resource_id(".proxy").is_err());
    assert!(validate_resource_id("_proxy").is_err());
}

#[test]
fn test_validate_resource_id_invalid_chars() {
    assert!(validate_resource_id("proxy httpbin").is_err()); // space
    assert!(validate_resource_id("proxy/httpbin").is_err()); // slash
    assert!(validate_resource_id("proxy@httpbin").is_err()); // at
    assert!(validate_resource_id("proxy!").is_err()); // exclamation
}

// ---- Resource ID format validation on GatewayConfig ----

#[test]
fn test_validate_resource_ids_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("proxy-1", "/api")];
    config.consumers = vec![make_consumer("consumer-1", "alice")];
    config.upstreams = vec![make_upstream("upstream-1")];
    assert!(config.validate_resource_ids().is_ok());
}

#[test]
fn test_validate_resource_ids_invalid_proxy_id() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("invalid id!", "/api")];
    let err = config.validate_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Proxy ID"));
}

#[test]
fn test_validate_resource_ids_invalid_consumer_id() {
    let mut config = empty_config();
    config.consumers = vec![make_consumer("bad id", "alice")];
    let err = config.validate_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Consumer ID"));
}

// ---- Resource ID uniqueness tests ----

#[test]
fn test_validate_unique_resource_ids_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p2", "/web")];
    config.consumers = vec![make_consumer("c1", "alice"), make_consumer("c2", "bob")];
    assert!(config.validate_unique_resource_ids().is_ok());
}

#[test]
fn test_validate_unique_resource_ids_duplicate_proxy() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p1", "/web")];
    let err = config.validate_unique_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate proxy ID 'p1'"));
}

#[test]
fn test_validate_unique_resource_ids_duplicate_consumer() {
    let mut config = empty_config();
    config.consumers = vec![make_consumer("c1", "alice"), make_consumer("c1", "bob")];
    let err = config.validate_unique_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate consumer ID 'c1'"));
}

#[test]
fn test_validate_unique_resource_ids_same_id_different_types_ok() {
    // Same ID across different resource types is fine
    let mut config = empty_config();
    config.proxies = vec![make_proxy("shared-id", "/api")];
    config.consumers = vec![make_consumer("shared-id", "alice")];
    config.upstreams = vec![make_upstream("shared-id")];
    assert!(config.validate_unique_resource_ids().is_ok());
}

// ---- Host validation tests ----

fn make_proxy_with_hosts(id: &str, listen_path: &str, hosts: Vec<&str>) -> Proxy {
    let mut p = make_proxy(id, listen_path);
    p.hosts = hosts.into_iter().map(String::from).collect();
    p
}

#[test]
fn test_validate_host_entry_valid_exact() {
    assert!(validate_host_entry("api.example.com").is_ok());
    assert!(validate_host_entry("example.com").is_ok());
    assert!(validate_host_entry("a.b.c.example.com").is_ok());
    assert!(validate_host_entry("localhost").is_ok());
    assert!(validate_host_entry("my-api.example.com").is_ok());
}

#[test]
fn test_validate_host_entry_valid_wildcard() {
    assert!(validate_host_entry("*.example.com").is_ok());
    assert!(validate_host_entry("*.a.example.com").is_ok());
}

#[test]
fn test_validate_host_entry_rejects_scheme() {
    let err = validate_host_entry("http://example.com").unwrap_err();
    assert!(err.contains("scheme"));
}

#[test]
fn test_validate_host_entry_rejects_port() {
    let err = validate_host_entry("example.com:8080").unwrap_err();
    assert!(err.contains("port"));
}

#[test]
fn test_validate_host_entry_rejects_path() {
    let err = validate_host_entry("example.com/path").unwrap_err();
    assert!(err.contains("path"));
}

#[test]
fn test_validate_host_entry_rejects_uppercase() {
    let err = validate_host_entry("API.example.com").unwrap_err();
    assert!(err.contains("lowercase"));
}

#[test]
fn test_validate_host_entry_rejects_invalid_wildcard() {
    // Wildcard not at start
    let err = validate_host_entry("api.*.com").unwrap_err();
    assert!(err.contains("wildcard"));

    // Bare wildcard
    let err = validate_host_entry("*").unwrap_err();
    assert!(err.contains("wildcard"));
}

#[test]
fn test_validate_host_entry_rejects_empty() {
    let err = validate_host_entry("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn test_wildcard_matches_single_level() {
    assert!(wildcard_matches("*.example.com", "api.example.com"));
    assert!(wildcard_matches("*.example.com", "admin.example.com"));
}

#[test]
fn test_wildcard_does_not_match_base_domain() {
    assert!(!wildcard_matches("*.example.com", "example.com"));
}

#[test]
fn test_wildcard_does_not_match_multi_level() {
    assert!(!wildcard_matches("*.example.com", "a.b.example.com"));
}

#[test]
fn test_wildcard_matches_exact_pattern() {
    // Non-wildcard pattern should do exact matching
    assert!(wildcard_matches("api.example.com", "api.example.com"));
    assert!(!wildcard_matches("api.example.com", "other.example.com"));
}

#[test]
fn test_hosts_overlap_both_empty_catch_all() {
    // Both catch-all → overlap
    assert!(hosts_overlap(&[], &[]));
}

#[test]
fn test_hosts_overlap_one_empty_catch_all() {
    // Catch-all overlaps with everything
    let hosts = vec!["api.example.com".to_string()];
    assert!(hosts_overlap(&hosts, &[]));
    assert!(hosts_overlap(&[], &hosts));
}

#[test]
fn test_hosts_overlap_disjoint() {
    let a = vec!["api.example.com".to_string()];
    let b = vec!["admin.example.com".to_string()];
    assert!(!hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_shared_host() {
    let a = vec!["api.example.com".to_string()];
    let b = vec![
        "api.example.com".to_string(),
        "admin.example.com".to_string(),
    ];
    assert!(hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_wildcard_matches_exact() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["api.example.com".to_string()];
    assert!(hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_wildcard_no_match() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["api.other.org".to_string()];
    assert!(!hosts_overlap(&a, &b));
}

// ---- Host+listen_path uniqueness validation tests ----

#[test]
fn test_unique_listen_paths_same_path_disjoint_hosts() {
    // Same listen_path but different hosts → OK
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/api", vec!["admin.example.com"]),
    ];
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_unique_listen_paths_same_path_overlapping_hosts() {
    // Same listen_path AND overlapping hosts → conflict
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/api", vec!["api.example.com"]),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Overlapping"));
}

#[test]
fn test_unique_listen_paths_same_path_catchall_conflict() {
    // Two catch-all proxies (no hosts) with same path → conflict
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p2", "/api")];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate listen_path"));
}

#[test]
fn test_unique_listen_paths_catchall_vs_specific_host() {
    // Catch-all overlaps with any specific host
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("p1", "/api"),
        make_proxy_with_hosts("p2", "/api", vec!["api.example.com"]),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn test_unique_listen_paths_different_paths_same_hosts_ok() {
    // Different listen_path → OK even with same hosts
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/web", vec!["api.example.com"]),
    ];
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_validate_hosts_valid() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/web", vec!["*.example.com"]),
    ];
    assert!(config.validate_hosts().is_ok());
}

#[test]
fn test_validate_hosts_invalid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy_with_hosts("p1", "/api", vec!["INVALID.COM"])];
    let err = config.validate_hosts().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("p1"));
}

#[test]
fn test_normalize_hosts() {
    let mut config = empty_config();
    let mut p = make_proxy("p1", "/api");
    p.hosts = vec!["API.EXAMPLE.COM".to_string()];
    config.proxies = vec![p];
    config.normalize_hosts();
    assert_eq!(config.proxies[0].hosts[0], "api.example.com");
}

#[test]
fn test_hosts_deserialization_default_empty() {
    // When hosts field is missing from JSON, it should default to empty vec
    let json = r#"{
        "id": "p1",
        "listen_path": "/api",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 3000
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert!(proxy.hosts.is_empty());
}

#[test]
fn test_hosts_deserialization_with_values() {
    let json = r#"{
        "id": "p1",
        "hosts": ["api.example.com", "*.example.org"],
        "listen_path": "/api",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 3000
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.hosts, vec!["api.example.com", "*.example.org"]);
}
