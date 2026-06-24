//! Admin API Cached Config Fallback Tests
//!
//! Tests that the admin API serves config from the in-memory cache when
//! the database is unavailable (resilience during data source outages).

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, PluginConfig, PluginScope,
    Proxy, Upstream, UpstreamTarget,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Test configuration
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    let jwt_config = JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    JwtManager::new(jwt_config)
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn generate_expired_test_token(config: &TestConfig) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": (now - chrono::Duration::seconds(900)).timestamp(),
        "nbf": (now - chrono::Duration::seconds(900)).timestamp(),
        "exp": (now - chrono::Duration::seconds(300)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn create_test_proxy(id: &str, listen_path: &str, host: &str, port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: host.to_string(),
        backend_port: port,
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
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a sample GatewayConfig with known test data.
fn create_test_gateway_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            create_test_proxy("proxy-1", "/api/v1", "backend1.example.com", 8080),
            create_test_proxy("proxy-2", "/api/v2", "backend2.example.com", 9090),
        ],
        consumers: vec![Consumer {
            id: "consumer-1".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            username: "alice".to_string(),
            custom_id: Some("alice-custom".to_string()),
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![PluginConfig {
            id: "plugin-cfg-1".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "rate_limiting".to_string(),
            config: json!({"limits": [{"scope": "default", "requests_per_minute": 100}]}),
            scope: PluginScope::Global,
            enabled: true,
            proxy_id: None,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn create_test_upstream(id: &str, name: &str) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(name.to_string()),
        targets: vec![UpstreamTarget {
            host: "10.0.0.1".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: Default::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Create a GatewayConfig that includes upstreams for testing upstream cache fallback.
fn create_test_gateway_config_with_upstreams() -> GatewayConfig {
    let mut config = create_test_gateway_config();
    config.upstreams = vec![
        create_test_upstream("upstream-1", "backend-pool-1"),
        create_test_upstream("upstream-2", "backend-pool-2"),
    ];
    config
}

/// Start an admin server with the given state on a random port, returns the base URL.
///
/// Binds once and moves the pre-bound listener directly into the spawned
/// task — no `drop(listener)` + re-bind step that another process could
/// race under parallel test load. Readiness is detected with a TCP probe
/// rather than a fixed sleep so a slow startup also cannot race the first
/// request.
async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();

    let state_clone = state.clone();
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(listener, state_clone, shutdown_rx_clone, None).await;
    });

    wait_for_admin_ready(actual_addr).await;
    (format!("http://{}", actual_addr), shutdown_tx)
}

/// Poll until the admin listener accepts a TCP connection.
///
/// 200 attempts × 10 ms = 2 s budget, well above any realistic in-process
/// startup time but bounded so a stuck listener fails the test fast.
async fn wait_for_admin_ready(addr: SocketAddr) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", addr);
}

/// Helper: GET request to the admin API, returns (status, body, X-Data-Source header).
async fn admin_get(
    base_url: &str,
    path: &str,
    token: &str,
) -> (reqwest::StatusCode, Value, Option<String>) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let data_source = resp
        .headers()
        .get("X-Data-Source")
        .map(|v| v.to_str().unwrap().to_string());
    let body: Value = resp.json().await.unwrap();
    (status, body, data_source)
}

// ---- List endpoints fallback tests ----

#[tokio::test]
async fn test_list_proxies_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/proxies", &token).await;

    assert_eq!(status, 200);
    let proxies = body["data"]
        .as_array()
        .expect("Should return envelope data array of proxies");
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0]["id"], "proxy-1");
    assert_eq!(proxies[1]["id"], "proxy-2");
    assert_eq!(
        data_source.as_deref(),
        Some("cached"),
        "Should indicate data is from cache"
    );
}

#[tokio::test]
async fn test_list_consumers_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/consumers", &token).await;

    assert_eq!(status, 200);
    let consumers = body["data"]
        .as_array()
        .expect("Should return envelope data array of consumers");
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0]["username"], "alice");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn test_list_plugin_configs_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/plugins/config", &token).await;

    assert_eq!(status, 200);
    let plugins = body["data"]
        .as_array()
        .expect("Should return envelope data array of plugin configs");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0]["plugin_name"], "rate_limiting");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

// ---- Get-by-ID endpoint fallback tests ----

#[tokio::test]
async fn test_get_proxy_by_id_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/proxies/proxy-2", &token).await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], "proxy-2");
    assert_eq!(body["listen_path"], "/api/v2");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn test_get_proxy_not_found_in_cache() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies/nonexistent", &token).await;

    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_get_consumer_by_id_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/consumers/consumer-1", &token).await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], "consumer-1");
    assert_eq!(body["username"], "alice");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn test_get_consumer_not_found_in_cache() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/consumers/nonexistent", &token).await;

    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_get_plugin_config_by_id_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) =
        admin_get(&base_url, "/plugins/config/plugin-cfg-1", &token).await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], "plugin-cfg-1");
    assert_eq!(body["plugin_name"], "rate_limiting");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn test_get_plugin_config_not_found_in_cache() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/plugins/config/nonexistent", &token).await;

    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

// ---- No cache and no DB: should return 503 ----

#[tokio::test]
async fn test_list_proxies_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No database and no cached config")
    );
}

#[tokio::test]
async fn test_list_consumers_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/consumers", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No database and no cached config")
    );
}

#[tokio::test]
async fn test_get_proxy_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies/any-id", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No database and no cached config")
    );
}

// ---- Health endpoint shows cached config status ----

#[tokio::test]
async fn test_health_endpoint_shows_cached_config_info() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    // Health endpoint does not require auth
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["cached_config"]["available"], true);
    assert_eq!(body["cached_config"]["proxy_count"], 2);
    assert_eq!(body["cached_config"]["consumer_count"], 1);
    assert!(body["cached_config"]["loaded_at"].is_string());
}

#[tokio::test]
async fn test_health_endpoint_shows_no_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["cached_config"]["available"], false);
}

#[tokio::test]
async fn test_health_endpoint_returns_503_until_startup_is_ready() {
    let tc = TestConfig::default();
    let startup_ready = Arc::new(AtomicBool::new(false));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: Some(startup_ready.clone()),
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "starting");
    assert_eq!(body["ready"], false);

    startup_ready.store(true, Ordering::Release);

    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["ready"], true);
}

// ---- Config updates are reflected in cached reads ----

#[tokio::test]
async fn test_cached_config_reflects_live_updates() {
    let tc = TestConfig::default();
    let cached = Arc::new(ArcSwap::new(Arc::new(create_test_gateway_config())));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(cached.clone()),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Initial read: 2 proxies
    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 2);

    // Simulate config update (e.g., from a polling loop or gRPC push)
    let mut updated_config = create_test_gateway_config();
    updated_config.proxies.push(create_test_proxy(
        "proxy-3",
        "/api/v3",
        "backend3.example.com",
        7070,
    ));
    cached.store(Arc::new(updated_config));

    // Read again: should see 3 proxies now
    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["data"].as_array().unwrap().len(),
        3,
        "Updated cached config should be reflected immediately"
    );
}

// ---- Pagination tests ----

/// Create a GatewayConfig with many proxies for pagination testing.
fn create_pagination_test_config() -> GatewayConfig {
    let mut proxies = Vec::new();
    let mut consumers = Vec::new();
    let mut plugin_configs = Vec::new();
    for i in 0..5 {
        proxies.push(create_test_proxy(
            &format!("proxy-{}", i),
            &format!("/api/v{}", i),
            "backend.example.com",
            8080,
        ));
        consumers.push(Consumer {
            id: format!("consumer-{}", i),
            namespace: ferrum_edge::config::types::default_namespace(),
            username: format!("user-{}", i),
            custom_id: None,
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        plugin_configs.push(PluginConfig {
            id: format!("plugin-cfg-{}", i),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "rate_limiting".to_string(),
            config: json!({"limits": [{"scope": "default", "requests_per_minute": 100}]}),
            scope: PluginScope::Global,
            enabled: true,
            proxy_id: None,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers,
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn create_pagination_admin_state(tc: &TestConfig) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_pagination_test_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    }
}

#[tokio::test]
async fn test_charges_requires_admin_jwt() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let client = reqwest::Client::new();

    let unauthenticated = client
        .get(format!("{}/charges", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: Value = unauthenticated.json().await.unwrap();
    assert_eq!(body["error"], "Missing Authorization header");

    let token = generate_test_token(&tc);
    let authenticated_json = client
        .get(format!("{}/charges?format=json", base_url))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(authenticated_json.status(), reqwest::StatusCode::OK);
    let body: Value = authenticated_json.json().await.unwrap();
    assert!(body["consumers"].is_object());

    let authenticated_prometheus = client
        .get(format!("{}/charges", base_url))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(authenticated_prometheus.status(), reqwest::StatusCode::OK);
    let content_type = authenticated_prometheus
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(content_type.starts_with("text/plain"));
    let body = authenticated_prometheus.text().await.unwrap();
    assert!(body.contains("ferrum_api_chargeable_calls_total"));

    let invalid = client
        .get(format!("{}/charges", base_url))
        .header("authorization", "Bearer not.a.jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);

    let expired_token = generate_expired_test_token(&tc);
    let expired = client
        .get(format!("{}/charges", base_url))
        .header("authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_proxies_without_pagination_returns_envelope() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;
    assert_eq!(status, 200);
    assert!(body["data"].is_array(), "Should have data field");
    assert_eq!(body["data"].as_array().unwrap().len(), 5);
    assert_eq!(body["pagination"]["offset"], 0);
    assert_eq!(body["pagination"]["limit"], 5);
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_proxies_with_limit_returns_paginated_envelope() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies?limit=2", &token).await;
    assert_eq!(status, 200);
    // With pagination params, should return envelope
    assert!(body["data"].is_array(), "Should have data field");
    assert_eq!(body["data"].as_array().unwrap().len(), 2);
    assert_eq!(body["pagination"]["offset"], 0);
    assert_eq!(body["pagination"]["limit"], 2);
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_proxies_with_offset_and_limit() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies?offset=2&limit=2", &token).await;
    assert_eq!(status, 200);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["id"], "proxy-2");
    assert_eq!(data[1]["id"], "proxy-3");
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_proxies_offset_beyond_total_returns_empty() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies?offset=100&limit=10", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_consumers_with_pagination() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/consumers?limit=3", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 3);
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_plugin_configs_with_pagination() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/plugins/config?limit=1&offset=4", &token).await;
    assert_eq!(status, 200);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["id"], "plugin-cfg-4");
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn test_list_upstreams_with_pagination() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Upstreams is empty, pagination should still work
    let (status, body, _) = admin_get(&base_url, "/upstreams?limit=10", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["pagination"]["total"], 0);
}

#[tokio::test]
async fn test_pagination_limit_clamped_to_max() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // limit=5000 exceeds MAX_PAGE_SIZE (1000), should be clamped
    let (status, body, _) = admin_get(&base_url, "/proxies?limit=5000", &token).await;
    assert_eq!(status, 200);
    // Should still return all 5 (since 5 < 1000)
    assert_eq!(body["data"].as_array().unwrap().len(), 5);
    assert_eq!(body["pagination"]["limit"], 1000);
}

// ---- Batch endpoint tests ----

use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};

async fn create_db_admin_state(tc: &TestConfig) -> (AdminState, tempfile::TempDir) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_batch.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let state = db_admin_state(tc, db, None);
    (state, temp_dir)
}

fn db_admin_state(
    tc: &TestConfig,
    db: DatabaseStore,
    cached_config: Option<GatewayConfig>,
) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: create_test_jwt_manager(tc),
        cached_config: cached_config.map(|config| Arc::new(ArcSwap::new(Arc::new(config)))),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    }
}

async fn admin_post(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}{}", base_url, path))
        .header("Authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

async fn admin_put(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}{}", base_url, path))
        .header("Authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

async fn admin_delete(base_url: &str, path: &str, token: &str) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}{}", base_url, path))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    // DELETE 204 may have empty body
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

/// Create admin state with real SQLite DB and configurable db_available flag.
async fn create_db_admin_state_with_availability(
    tc: &TestConfig,
    db_available: Option<Arc<AtomicBool>>,
) -> (AdminState, tempfile::TempDir) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_avail.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let state = AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: create_test_jwt_manager(tc),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    (state, temp_dir)
}

#[tokio::test]
async fn test_batch_create_consumers_and_proxies() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({
        "consumers": [
            {"id": "c1", "username": "user1", "credentials": {}},
            {"id": "c2", "username": "user2", "credentials": {}},
            {"id": "c3", "username": "user3", "credentials": {}}
        ],
        "proxies": [
            {"id": "p1", "listen_path": "/a", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true},
            {"id": "p2", "listen_path": "/b", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "Batch create failed: {:?}", body);
    assert_eq!(body["created"]["consumers"], 3);
    assert_eq!(body["created"]["proxies"], 2);
    assert_eq!(body["created"]["plugin_configs"], 0);
    assert_eq!(body["created"]["upstreams"], 0);

    // Verify resources exist via individual GET
    let (status, _body, _) = admin_get(&base_url, "/consumers/c1", &token).await;
    assert_eq!(status, 200);

    let (status, _body, _) = admin_get(&base_url, "/proxies/p1", &token).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn test_batch_create_plugin_configs() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // First create a proxy for the plugin to reference
    let proxy_batch = json!({
        "proxies": [
            {"id": "bp1", "listen_path": "/bp1", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &proxy_batch).await;
    assert_eq!(status, 201);

    // Now batch create plugin configs
    let plugin_batch = json!({
        "plugin_configs": [
            {"id": "pc1", "plugin_name": "key_auth", "scope": "proxy", "proxy_id": "bp1", "enabled": true, "config": {"key_location": "header:X-API-Key"}},
            {"id": "pc2", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}}
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &plugin_batch).await;
    assert_eq!(status, 201, "Batch plugin create failed: {:?}", body);
    assert_eq!(body["created"]["plugin_configs"], 2);

    let (status, proxy_body, _) = admin_get(&base_url, "/proxies/bp1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(proxy_body["plugins"][0]["plugin_config_id"], "pc1");
}

#[tokio::test]
async fn test_batch_create_proxy_and_proxy_plugin_association_same_request() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({
        "proxies": [
            {
                "id": "assoc-proxy",
                "listen_path": "/assoc",
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": 8080,
                "strip_listen_path": true,
                "plugins": [{"plugin_config_id": "assoc-pc"}]
            }
        ],
        "plugin_configs": [
            {
                "id": "assoc-pc",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "assoc-proxy",
                "enabled": true,
                "config": {"key_location": "header:X-API-Key"}
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "Batch create failed: {:?}", body);
    assert_eq!(body["created"]["proxies"], 1);
    assert_eq!(body["created"]["plugin_configs"], 1);

    let (status, proxy_body, _) = admin_get(&base_url, "/proxies/assoc-proxy", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(proxy_body["plugins"][0]["plugin_config_id"], "assoc-pc");
}

#[tokio::test]
async fn test_batch_create_read_only_rejected() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({"consumers": [{"id": "c1", "username": "u1"}]});
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 403);
    assert!(body["error"].as_str().unwrap().contains("read-only"));
}

#[tokio::test]
async fn test_batch_create_empty_request() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Empty batch — all zero counts
    let (status, body) = admin_post(&base_url, "/batch", &token, &json!({})).await;
    assert_eq!(status, 201);
    assert_eq!(body["created"]["proxies"], 0);
    assert_eq!(body["created"]["consumers"], 0);
    assert_eq!(body["created"]["plugin_configs"], 0);
    assert_eq!(body["created"]["upstreams"], 0);
}

// ---- Backup & Restore Tests ----

#[tokio::test]
async fn test_backup_returns_full_config() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Seed some data via batch
    let seed = json!({
        "consumers": [
            {"id": "bc1", "username": "backup_user1", "credentials": {}},
            {"id": "bc2", "username": "backup_user2", "credentials": {}}
        ],
        "upstreams": [
            {"id": "bu1", "name": "backup_upstream", "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]}
        ],
        "proxies": [
            {"id": "bp1", "listen_path": "/backup1", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true, "upstream_id": "bu1"}
        ],
        "plugin_configs": [
            {"id": "bpc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201);

    // Backup
    let (status, body, data_source) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(data_source.as_deref(), Some("database"));

    // Verify counts
    assert_eq!(body["counts"]["consumers"], 2);
    assert_eq!(body["counts"]["upstreams"], 1);
    assert_eq!(body["counts"]["proxies"], 1);
    assert_eq!(body["counts"]["plugin_configs"], 1);

    // Verify actual data
    assert_eq!(body["proxies"].as_array().unwrap().len(), 1);
    assert_eq!(body["consumers"].as_array().unwrap().len(), 2);
    assert_eq!(body["upstreams"].as_array().unwrap().len(), 1);
    assert_eq!(body["plugin_configs"].as_array().unwrap().len(), 1);

    // Verify metadata
    assert!(body["exported_at"].is_string());
    assert_eq!(body["version"], "1");
}

#[tokio::test]
async fn test_backup_empty_config() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["counts"]["proxies"], 0);
    assert_eq!(body["counts"]["consumers"], 0);
    assert_eq!(body["counts"]["plugin_configs"], 0);
    assert_eq!(body["counts"]["upstreams"], 0);
}

#[tokio::test]
async fn test_backup_resource_filter() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Seed data with all resource types
    let seed = json!({
        "consumers": [
            {"id": "fc1", "username": "filter_user", "credentials": {}}
        ],
        "upstreams": [
            {"id": "fu1", "name": "filter_upstream", "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]}
        ],
        "proxies": [
            {"id": "fp1", "listen_path": "/filter", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ],
        "plugin_configs": [
            {"id": "fpc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201);

    // Backup only proxies and upstreams
    let (status, body, _) =
        admin_get(&base_url, "/backup?resources=proxies,upstreams", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["counts"]["proxies"], 1);
    assert_eq!(body["counts"]["upstreams"], 1);
    assert_eq!(body["counts"]["consumers"], 0);
    assert_eq!(body["counts"]["plugin_configs"], 0);
    assert!(body["proxies"].as_array().unwrap().len() == 1);
    assert!(body["consumers"].as_array().unwrap().is_empty());

    // Backup only consumers
    let (status, body, _) = admin_get(&base_url, "/backup?resources=consumers", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["counts"]["consumers"], 1);
    assert_eq!(body["counts"]["proxies"], 0);
}

#[tokio::test]
async fn test_restore_requires_confirm() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Without ?confirm=true
    let (status, body) = admin_post(&base_url, "/restore", &token, &json!({})).await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().unwrap().contains("confirm=true"));
}

#[tokio::test]
async fn test_restore_rejects_invalid_plugin_config_before_delete() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [
            {"id": "restore-keep", "listen_path": "/keep", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);

    let restore_payload = json!({
        "proxies": [
            {"id": "restore-new", "listen_path": "/new", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ],
        "plugin_configs": [{
            "id": "bad-mrd",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy",
            "proxy_id": "restore-new",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_tls": {"verify_server_cert": false}
                    }
                }]
            }
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(
        status, 400,
        "Invalid plugin restore should fail: {:?}",
        body
    );
    let errors = body["validation_errors"]
        .as_array()
        .expect("validation errors");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap_or("").contains("mesh_route_dispatch")),
        "expected plugin validation error: {:?}",
        body
    );

    let (status, _, _) = admin_get(&base_url, "/proxies/restore-keep", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "restore validation must happen before destructive delete"
    );
}

#[tokio::test]
async fn test_restore_replaces_all_config() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Seed initial data
    let seed = json!({
        "consumers": [
            {"id": "old_c1", "username": "old_user", "credentials": {}},
        ],
        "proxies": [
            {"id": "old_p1", "listen_path": "/old", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201);

    // Restore with new data
    let restore_payload = json!({
        "consumers": [
            {"id": "new_c1", "username": "new_user1", "credentials": {}},
            {"id": "new_c2", "username": "new_user2", "credentials": {}}
        ],
        "proxies": [
            {"id": "new_p1", "listen_path": "/new1", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true},
            {"id": "new_p2", "listen_path": "/new2", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;
    assert_eq!(status, 200, "Restore failed: {:?}", body);
    assert_eq!(body["restored"]["consumers"], 2);
    assert_eq!(body["restored"]["proxies"], 2);

    // Verify old data is gone
    let (status, _, _) = admin_get(&base_url, "/consumers/old_c1", &token).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    let (status, _, _) = admin_get(&base_url, "/proxies/old_p1", &token).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);

    // Verify new data exists
    let (status, _, _) = admin_get(&base_url, "/consumers/new_c1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, _, _) = admin_get(&base_url, "/proxies/new_p1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_backup_then_restore_roundtrip() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Seed data
    let seed = json!({
        "consumers": [
            {"id": "rt_c1", "username": "roundtrip_user", "credentials": {}},
        ],
        "upstreams": [
            {"id": "rt_u1", "name": "roundtrip_upstream", "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]}
        ],
        "proxies": [
            {"id": "rt_p1", "listen_path": "/roundtrip", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ],
        "plugin_configs": [
            {"id": "rt_pc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201);

    // Backup
    let (status, backup, _) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);

    // Wipe by restoring empty config
    let (status, _) = admin_post(&base_url, "/restore?confirm=true", &token, &json!({})).await;
    assert_eq!(status, 200);

    // Verify wiped
    let (status, check, _) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(check["counts"]["proxies"], 0);

    // Restore from backup
    let (status, body) = admin_post(&base_url, "/restore?confirm=true", &token, &backup).await;
    assert_eq!(status, 200, "Roundtrip restore failed: {:?}", body);
    assert_eq!(body["restored"]["consumers"], 1);
    assert_eq!(body["restored"]["upstreams"], 1);
    assert_eq!(body["restored"]["proxies"], 1);
    assert_eq!(body["restored"]["plugin_configs"], 1);

    // Verify data is back
    let (status, _, _) = admin_get(&base_url, "/consumers/rt_c1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, _, _) = admin_get(&base_url, "/proxies/rt_p1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_backup_then_restore_roundtrip_with_proxy_plugin_association() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [
            {
                "id": "assoc-rt-proxy",
                "listen_path": "/assoc-rt",
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": 8080,
                "strip_listen_path": true,
                "plugins": [{"plugin_config_id": "assoc-rt-pc"}]
            }
        ],
        "plugin_configs": [
            {
                "id": "assoc-rt-pc",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "assoc-rt-proxy",
                "enabled": true,
                "config": {"key_location": "header:X-API-Key"}
            }
        ]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed batch failed: {:?}", body);

    let (status, backup, _) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);

    let (status, body) = admin_post(&base_url, "/restore?confirm=true", &token, &backup).await;
    assert_eq!(status, 200, "Roundtrip restore failed: {:?}", body);
    assert_eq!(body["restored"]["proxies"], 1);
    assert_eq!(body["restored"]["plugin_configs"], 1);

    let (status, proxy_body, _) = admin_get(&base_url, "/proxies/assoc-rt-proxy", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(proxy_body["plugins"][0]["plugin_config_id"], "assoc-rt-pc");
}

#[tokio::test]
async fn test_restore_read_only_rejected() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_post(&base_url, "/restore?confirm=true", &token, &json!({})).await;
    assert_eq!(status, 403);
    assert!(body["error"].as_str().unwrap().contains("read-only"));
}

#[tokio::test]
async fn test_batch_create_proxies_persists_hosts() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({
        "proxies": [
            {
                "id": "hosts_p1",
                "listen_path": "/hosts-test",
                "hosts": ["api.example.com", "*.staging.example.com"],
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": 8080,
                "strip_listen_path": true
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "Batch create failed: {:?}", body);
    assert_eq!(body["created"]["proxies"], 1);

    // Verify hosts field was persisted by reading the proxy back
    let (status, proxy_body, _) = admin_get(&base_url, "/proxies/hosts_p1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let hosts = proxy_body["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0], "api.example.com");
    assert_eq!(hosts[1], "*.staging.example.com");
}

#[tokio::test]
async fn test_batch_create_upstreams_persists_service_discovery() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({
        "upstreams": [
            {
                "id": "sd_u1",
                "name": "sd-upstream",
                "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}],
                "service_discovery": {
                    "provider": "dns_sd",
                    "dns_sd": {"service_name": "_http._tcp.local", "poll_interval_seconds": 60},
                    "default_weight": 5
                }
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 201, "Batch create failed: {:?}", body);
    assert_eq!(body["created"]["upstreams"], 1);

    // Verify service_discovery was persisted
    let (status, upstream_body, _) = admin_get(&base_url, "/upstreams/sd_u1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let sd = &upstream_body["service_discovery"];
    assert!(!sd.is_null(), "service_discovery should be persisted");
    assert_eq!(sd["provider"], "dns_sd");
    assert_eq!(sd["dns_sd"]["service_name"], "_http._tcp.local");
    assert_eq!(sd["dns_sd"]["poll_interval_seconds"], 60);
    assert_eq!(sd["default_weight"], 5);
}

#[tokio::test]
async fn test_restore_hashes_consumer_secrets() {
    // `hash_basic_auth_password` (in `src/config/types.rs`) reads
    // `FERRUM_BASIC_AUTH_HMAC_SECRET` from the environment via
    // `resolve_ferrum_var`. The previous single-process libtest run
    // happened to inherit this from whatever test happened to set it
    // first; under nextest's process-per-test model (now used by the
    // sharded `test-integration` job) every test starts with a clean
    // env, so the restore handler errors with the "must be set" message
    // and the assertion below trips on the bubbled-up error string.
    // Set it explicitly here — the value is irrelevant beyond being
    // ≥32 chars; we only assert that the plaintext password was hashed
    // out of the credential, not the hash value itself.
    //
    // SAFETY: this test owns its own admin server, started below after
    // the env var is in place, so no other thread is reading the
    // environment at the moment of mutation.
    unsafe {
        std::env::set_var(
            "FERRUM_BASIC_AUTH_HMAC_SECRET",
            "ferrum-test-basic-auth-hmac-secret-32chars-or-more-aaaaaaaaaa",
        );
    }

    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Restore with a consumer that has a plaintext basicauth password
    let restore_payload = json!({
        "consumers": [
            {
                "id": "hash_c1",
                "username": "hash_user",
                "credentials": {
                    "basicauth": [{
                        "username": "hash_user",
                        "password": "my_secret_password"
                    }]
                }
            }
        ]
    });

    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;
    assert_eq!(status, 200, "Restore failed: {:?}", body);
    assert_eq!(body["restored"]["consumers"], 1);

    // Read the consumer back and verify the password was hashed
    // (the plaintext "password" key should be removed, replaced by "password_hash")
    let (status, consumer_body, _) = admin_get(&base_url, "/consumers/hash_c1", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let creds = &consumer_body["credentials"]["basicauth"][0];
    // The API redacts password_hash, but the plaintext "password" key should NOT be present
    assert!(
        creds.get("password").is_none() || creds["password"].is_null(),
        "Plaintext password should be removed after hashing, got: {:?}",
        creds
    );
}

// ============================================================================
// Upstream Cached Config Fallback Tests
// ============================================================================

#[tokio::test]
async fn test_list_upstreams_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/upstreams", &token).await;

    assert_eq!(status, 200);
    let upstreams = body["data"]
        .as_array()
        .expect("Should return envelope data array of upstreams");
    assert_eq!(upstreams.len(), 2);
    assert_eq!(upstreams[0]["id"], "upstream-1");
    assert_eq!(upstreams[1]["id"], "upstream-2");
    assert_eq!(
        data_source.as_deref(),
        Some("cached"),
        "Should indicate data is from cache"
    );
}

#[tokio::test]
async fn test_get_upstream_by_id_falls_back_to_cached_config() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/upstreams/upstream-2", &token).await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], "upstream-2");
    assert_eq!(body["name"], "backend-pool-2");
    assert_eq!(data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn test_get_upstream_not_found_in_cache() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/upstreams/nonexistent", &token).await;

    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_list_upstreams_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/upstreams", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No database and no cached config")
    );
}

#[tokio::test]
async fn test_get_upstream_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/upstreams/any-id", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No database and no cached config")
    );
}

// ============================================================================
// Upstream CRUD with Real SQLite DB
// ============================================================================

#[tokio::test]
async fn test_upstream_crud_create_and_read() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "id": "crud-u1",
        "name": "test-upstream",
        "targets": [
            {"host": "10.0.0.1", "port": 8080, "weight": 100},
            {"host": "10.0.0.2", "port": 8080, "weight": 50}
        ],
        "algorithm": "round_robin"
    });

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201, "Create upstream failed: {:?}", body);

    // Read it back
    let (status, body, _) = admin_get(&base_url, "/upstreams/crud-u1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], "crud-u1");
    assert_eq!(body["name"], "test-upstream");
    let targets = body["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["host"], "10.0.0.1");
    assert_eq!(targets[1]["host"], "10.0.0.2");

    // List should include it
    let (status, body, _) = admin_get(&base_url, "/upstreams", &token).await;
    assert_eq!(status, 200);
    let upstreams = body["data"].as_array().unwrap();
    assert_eq!(upstreams.len(), 1);
    assert_eq!(upstreams[0]["id"], "crud-u1");
}

#[tokio::test]
async fn test_upstream_crud_update() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Create
    let upstream = json!({
        "id": "upd-u1",
        "name": "original-upstream",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    // Update with new targets and name
    let updated = json!({
        "id": "upd-u1",
        "name": "updated-upstream",
        "targets": [
            {"host": "10.0.0.5", "port": 9090, "weight": 200},
            {"host": "10.0.0.6", "port": 9090, "weight": 300}
        ],
        "algorithm": "least_connections"
    });
    let (status, body) = admin_put(&base_url, "/upstreams/upd-u1", &token, &updated).await;
    assert_eq!(status, 200, "Update upstream failed: {:?}", body);

    // Verify update
    let (status, body, _) = admin_get(&base_url, "/upstreams/upd-u1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "updated-upstream");
    let targets = body["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["host"], "10.0.0.5");
}

#[tokio::test]
async fn test_upstream_crud_delete() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Create
    let upstream = json!({
        "id": "del-u1",
        "name": "delete-me",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    // Delete
    let (status, _) = admin_delete(&base_url, "/upstreams/del-u1", &token).await;
    assert_eq!(status, 204);

    // Verify gone
    let (status, _, _) = admin_get(&base_url, "/upstreams/del-u1", &token).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_upstream_delete_referenced_by_proxy_returns_409() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Create upstream
    let upstream = json!({
        "id": "ref-u1",
        "name": "referenced-upstream",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    // Create proxy referencing the upstream
    let proxy = json!({
        "id": "ref-p1",
        "listen_path": "/ref-test",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
        "strip_listen_path": true,
        "upstream_id": "ref-u1"
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create proxy failed: {:?}", body);

    // Attempt to delete upstream — should be blocked with 409
    let (status, body) = admin_delete(&base_url, "/upstreams/ref-u1", &token).await;
    assert_eq!(
        status, 409,
        "Should return 409 CONFLICT when upstream is referenced by proxy: {:?}",
        body
    );
    assert!(
        body["error"].as_str().unwrap_or("").contains("referenced"),
        "Error should mention upstream is referenced: {:?}",
        body
    );
}

#[tokio::test]
async fn test_upstream_delete_referenced_by_mesh_route_dispatch_returns_409() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "id": "mrd-ref-u1",
        "name": "mrd-referenced-upstream",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    let proxy = json!({
        "id": "mrd-ref-p1",
        "listen_path": "/mrd-ref-test",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
        "strip_listen_path": true
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create proxy failed: {:?}", body);

    let plugin = json!({
        "id": "mrd-ref-plugin",
        "plugin_name": "mesh_route_dispatch",
        "scope": "proxy",
        "proxy_id": "mrd-ref-p1",
        "enabled": true,
        "config": {
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "mrd-ref-u1"}
            }]
        }
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;
    assert_eq!(status, 201, "Create plugin failed: {:?}", body);

    let (status, body) = admin_delete(&base_url, "/upstreams/mrd-ref-u1", &token).await;
    assert_eq!(
        status, 409,
        "Should return 409 CONFLICT when upstream is referenced by mesh_route_dispatch: {:?}",
        body
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("mesh_route_dispatch"),
        "Error should mention mesh_route_dispatch reference: {:?}",
        body
    );
}

#[tokio::test]
async fn test_upstream_update_rejects_removing_referenced_subset() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "id": "subset-u1",
        "name": "subset-upstream",
        "targets": [
            {"host": "10.0.0.1", "port": 8080, "weight": 100, "tags": {"version": "stable"}},
            {"host": "10.0.0.2", "port": 8080, "weight": 100, "tags": {"version": "canary"}}
        ],
        "subsets": [
            {"name": "stable", "labels": {"version": "stable"}},
            {"name": "canary", "labels": {"version": "canary"}}
        ]
    });
    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201, "Create upstream failed: {:?}", body);

    let proxy = json!({
        "id": "subset-p1",
        "listen_path": "/subset-test",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
        "strip_listen_path": true,
        "upstream_id": "subset-u1",
        "upstream_subset": "canary"
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create proxy failed: {:?}", body);

    let updated = json!({
        "id": "subset-u1",
        "name": "subset-upstream",
        "targets": [
            {"host": "10.0.0.1", "port": 8080, "weight": 100, "tags": {"version": "stable"}},
            {"host": "10.0.0.2", "port": 8080, "weight": 100, "tags": {"version": "canary"}}
        ],
        "subsets": [
            {"name": "stable", "labels": {"version": "stable"}}
        ]
    });
    let (status, body) = admin_put(&base_url, "/upstreams/subset-u1", &token, &updated).await;
    assert_eq!(
        status, 400,
        "Should reject removing a subset referenced by a proxy: {:?}",
        body
    );
    let error = body["error"].as_str().unwrap_or("");
    assert!(
        error.contains("cannot remove subset 'canary'") && error.contains("subset-p1"),
        "Error should identify the referenced subset and proxy: {:?}",
        body
    );
}

// ============================================================================
// DB Outage Write Blocking Tests (503 via db_available flag)
// ============================================================================

#[tokio::test]
async fn test_create_proxy_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "listen_path": "/blocked",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_create_consumer_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let consumer = json!({"username": "blocked-user"});
    let (status, body) = admin_post(&base_url, "/consumers", &token, &consumer).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_create_upstream_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "name": "blocked-upstream",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_create_plugin_config_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let plugin = json!({
        "plugin_name": "rate_limiting",
        "scope": "global",
        "enabled": true,
        "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_update_proxy_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "id": "any-id",
        "listen_path": "/any",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
    });
    let (status, body) = admin_put(&base_url, "/proxies/any-id", &token, &proxy).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_delete_upstream_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_delete(&base_url, "/upstreams/any-id", &token).await;
    assert_eq!(
        status, 503,
        "Should return 503 when DB unavailable: {:?}",
        body
    );
}

// ============================================================================
// Backup Cached Config Fallback Tests
// ============================================================================

#[tokio::test]
async fn test_backup_falls_back_to_cached_config_when_no_db() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/backup", &token).await;

    assert_eq!(status, 200);
    assert_eq!(body["source"], "cached");
    assert_eq!(
        data_source.as_deref(),
        Some("cached"),
        "X-Data-Source header should be 'cached'"
    );
    assert_eq!(body["counts"]["proxies"], 2);
    assert_eq!(body["counts"]["consumers"], 1);
    assert_eq!(body["counts"]["upstreams"], 2);
    assert_eq!(body["counts"]["plugin_configs"], 1);
}

#[tokio::test]
async fn test_backup_no_db_no_cache_returns_503() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/backup", &token).await;

    assert_eq!(status, 503);
    assert!(
        body["error"].as_str().unwrap().contains("No database"),
        "Error should mention no database: {:?}",
        body
    );
}

// ============================================================================
// Write Operations with No DB Returns 503
// ============================================================================

#[tokio::test]
async fn test_create_proxy_returns_503_when_no_db() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "listen_path": "/no-db",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 503, "Should return 503 when no DB: {:?}", body);
    assert!(body["error"].as_str().unwrap().contains("No database"));
}

#[tokio::test]
async fn test_create_upstream_returns_503_when_no_db() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "name": "no-db-upstream",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 503, "Should return 503 when no DB: {:?}", body);
    assert!(body["error"].as_str().unwrap().contains("No database"));
}

// ============================================================================
// DB Recovery Transition Test
// ============================================================================

#[tokio::test]
async fn test_db_recovery_allows_writes_after_outage() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag.clone())).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // DB is down — writes should be blocked
    let proxy = json!({
        "id": "recovery-p1",
        "listen_path": "/recovery",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
        "strip_listen_path": true,
    });
    let (status, _) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 503, "Writes should be blocked while DB is down");

    // Simulate DB recovery
    db_flag.store(true, Ordering::Relaxed);

    // Writes should now succeed
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(
        status, 201,
        "Writes should work after DB recovery: {:?}",
        body
    );

    // Verify the proxy was created
    let (status, body, _) = admin_get(&base_url, "/proxies/recovery-p1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], "recovery-p1");
}

// ============================================================================
// Cached config reflects upstream updates
// ============================================================================

#[tokio::test]
async fn test_cached_config_reflects_upstream_updates() {
    let tc = TestConfig::default();
    let cached = Arc::new(ArcSwap::new(Arc::new(
        create_test_gateway_config_with_upstreams(),
    )));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(cached.clone()),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Initial read: 2 upstreams
    let (status, body, _) = admin_get(&base_url, "/upstreams", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 2);

    // Simulate config update (e.g., from polling loop)
    let mut updated_config = create_test_gateway_config_with_upstreams();
    updated_config
        .upstreams
        .push(create_test_upstream("upstream-3", "backend-pool-3"));
    cached.store(Arc::new(updated_config));

    // Read again: should see 3 upstreams now
    let (status, body, _) = admin_get(&base_url, "/upstreams", &token).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["data"].as_array().unwrap().len(),
        3,
        "Updated cached config should be reflected immediately"
    );
}

// ============================================================================
// Proxy & Consumer CRUD with Real SQLite DB (extended coverage)
// ============================================================================

#[tokio::test]
async fn test_proxy_invalid_association_does_not_fall_back_and_put_repairs() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("invalid_assoc.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let ts = Utc::now().to_rfc3339();
    let pool = db.pool();

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES ('proxy-1', 'ferrum', 'db proxy', '[]', '/api/v1', 'http', 'db.example.com', 8080, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy insert must succeed");
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES ('global-invalid', 'ferrum', 'cors', '{}', 'global', NULL, 1, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("global plugin insert must succeed");
    sqlx::query(
        "INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES ('proxy-1', 'global-invalid')",
    )
    .execute(&pool)
    .await
    .expect("invalid association insert must succeed");

    let state = db_admin_state(&tc, db, Some(create_test_gateway_config()));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/proxies/proxy-1", &token).await;
    assert_eq!(
        status, 503,
        "invalid association should not fall back to cached proxy: {body:?}"
    );
    assert_eq!(data_source, None);
    assert_eq!(
        body["error"].as_str(),
        Some("Database unavailable — operation failed")
    );

    let repaired = json!({
        "id": "proxy-1",
        "name": "repaired proxy",
        "listen_path": "/api/v1",
        "backend_scheme": "http",
        "backend_host": "repaired.example.com",
        "backend_port": 8081,
        "strip_listen_path": true
    });
    let (status, body) = admin_put(&base_url, "/proxies/proxy-1", &token, &repaired).await;
    assert_eq!(
        status, 200,
        "PUT without the invalid association should repair proxy_plugins: {body:?}"
    );

    let (status, body, data_source) = admin_get(&base_url, "/proxies/proxy-1", &token).await;
    assert_eq!(status, 200, "repaired proxy should read from DB: {body:?}");
    assert_eq!(data_source, None);
    assert_eq!(body["backend_host"], "repaired.example.com");
    assert_eq!(
        body["plugins"].as_array().map(|plugins| plugins.len()),
        Some(0)
    );
}

#[tokio::test]
async fn test_proxy_get_namespace_miss_does_not_validate_other_namespace_associations() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("namespace_miss_invalid_assoc.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let ts = Utc::now().to_rfc3339();
    let pool = db.pool();

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES ('other-proxy', 'other', 'other proxy', '[]', '/api/v1', 'http', 'other.example.com', 8080, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("other namespace proxy insert must succeed");
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES ('other-global-invalid', 'other', 'cors', '{}', 'global', NULL, 1, ?, ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("other namespace global plugin insert must succeed");
    sqlx::query(
        "INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES ('other-proxy', 'other-global-invalid')",
    )
    .execute(&pool)
    .await
    .expect("invalid other namespace association insert must succeed");

    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/proxies/other-proxy", &token).await;
    assert_eq!(
        status, 404,
        "default namespace GET should not validate a proxy from another namespace: {body:?}"
    );
    assert_eq!(data_source, None);
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("not found")),
        "namespace miss should be reported as not found, got: {body:?}"
    );
}

#[tokio::test]
async fn test_proxy_crud_create_update_delete() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Create
    let proxy = json!({
        "id": "crud-proxy-1",
        "name": "My Proxy",
        "listen_path": "/crud-proxy",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 9999,
        "strip_listen_path": true,
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create proxy failed: {:?}", body);

    // Read
    let (status, body, _) = admin_get(&base_url, "/proxies/crud-proxy-1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "My Proxy");
    assert_eq!(body["listen_path"], "/crud-proxy");

    // Update
    let updated = json!({
        "id": "crud-proxy-1",
        "name": "Updated Proxy",
        "listen_path": "/crud-proxy-updated",
        "backend_scheme": "http",
        "backend_host": "new-host.example.com",
        "backend_port": 7777,
        "strip_listen_path": false,
    });
    let (status, body) = admin_put(&base_url, "/proxies/crud-proxy-1", &token, &updated).await;
    assert_eq!(status, 200, "Update proxy failed: {:?}", body);

    // Verify update
    let (status, body, _) = admin_get(&base_url, "/proxies/crud-proxy-1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "Updated Proxy");
    assert_eq!(body["listen_path"], "/crud-proxy-updated");
    assert_eq!(body["backend_host"], "new-host.example.com");
    assert_eq!(body["backend_port"], 7777);

    // Delete
    let (status, _) = admin_delete(&base_url, "/proxies/crud-proxy-1", &token).await;
    assert_eq!(status, 204);

    // Verify gone
    let (status, _, _) = admin_get(&base_url, "/proxies/crud-proxy-1", &token).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_consumer_crud_create_update_delete() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Create
    let consumer = json!({
        "id": "crud-consumer-1",
        "username": "crud_user",
        "custom_id": "crud-custom-1",
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &consumer).await;
    assert_eq!(status, 201, "Create consumer failed: {:?}", body);

    // Read
    let (status, body, _) = admin_get(&base_url, "/consumers/crud-consumer-1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["username"], "crud_user");
    assert_eq!(body["custom_id"], "crud-custom-1");

    // Update
    let updated = json!({
        "id": "crud-consumer-1",
        "username": "updated_user",
        "custom_id": "updated-custom-1",
    });
    let (status, body) = admin_put(&base_url, "/consumers/crud-consumer-1", &token, &updated).await;
    assert_eq!(status, 200, "Update consumer failed: {:?}", body);

    // Verify update
    let (status, body, _) = admin_get(&base_url, "/consumers/crud-consumer-1", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["username"], "updated_user");

    // Delete
    let (status, _) = admin_delete(&base_url, "/consumers/crud-consumer-1", &token).await;
    assert_eq!(status, 204);

    // Verify gone
    let (status, _, _) = admin_get(&base_url, "/consumers/crud-consumer-1", &token).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_create_consumer_rejects_custom_id_collision_with_existing_username() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let alice = json!({
        "id": "collision-c1",
        "username": "alice"
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &alice).await;
    assert_eq!(status, 201, "Create consumer failed: {:?}", body);

    let colliding = json!({
        "id": "collision-c2",
        "username": "bob",
        "custom_id": "alice"
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &colliding).await;
    assert_eq!(status, 409, "Expected conflict, got: {:?}", body);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("conflicts with username")
    );
}

#[tokio::test]
async fn test_update_consumer_rejects_empty_username() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let consumer = json!({
        "id": "empty-user-c1",
        "username": "valid-user"
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &consumer).await;
    assert_eq!(status, 201, "Create consumer failed: {:?}", body);

    let updated = json!({
        "id": "empty-user-c1",
        "username": "   "
    });
    let (status, body) = admin_put(&base_url, "/consumers/empty-user-c1", &token, &updated).await;
    assert_eq!(status, 400, "Expected validation error, got: {:?}", body);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("username must not be empty")
    );
}

#[tokio::test]
async fn test_stream_proxy_admin_shape_preserved_across_get_and_backup() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "id": "stream-shape-proxy",
        "backend_scheme": "tcp",
        "backend_host": "localhost",
        "backend_port": 5432,
        "listen_port": 19010,
        "response_body_mode": "stream"
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create stream proxy failed: {:?}", body);

    let (status, proxy_body, _) = admin_get(&base_url, "/proxies/stream-shape-proxy", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    // Stream proxies MUST NOT have listen_path set — the admin API serializes
    // Option<String> None as null.
    assert!(
        proxy_body["listen_path"].is_null(),
        "Stream proxy listen_path should be null, got {:?}",
        proxy_body["listen_path"]
    );

    let (status, backup, _) = admin_get(&base_url, "/backup", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let proxy_entry = backup["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proxy| proxy["id"] == "stream-shape-proxy")
        .unwrap();
    assert!(
        proxy_entry["listen_path"].is_null(),
        "Backup stream proxy listen_path should be null, got {:?}",
        proxy_entry["listen_path"]
    );
}

// ============================================================================
// Health Endpoint with DB Availability Info
// ============================================================================

#[tokio::test]
async fn test_health_endpoint_shows_db_availability() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let cached = Arc::new(ArcSwap::new(Arc::new(create_test_gateway_config())));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: Some(cached),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: Some(db_flag.clone()),
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["cached_config"]["available"], true);

    // Simulate DB going down
    db_flag.store(false, Ordering::Relaxed);

    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Health returns 200 but status is "degraded" when DB is unavailable
    assert_eq!(
        body["status"], "degraded",
        "Status should be 'degraded' when DB is down but gateway is operational"
    );
}

// ============================================================================
// Batch Operations During DB Outage
// ============================================================================

#[tokio::test]
async fn test_batch_create_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let batch = json!({
        "proxies": [
            {"id": "batch-blocked", "listen_path": "/blocked", "backend_scheme": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 503,
        "Batch should be blocked when DB unavailable: {:?}",
        body
    );
}

#[tokio::test]
async fn test_restore_returns_503_when_db_unavailable() {
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_post(
        &base_url,
        "/restore?confirm=true",
        &token,
        &json!({"proxies": []}),
    )
    .await;
    assert_eq!(
        status, 503,
        "Restore should be blocked when DB unavailable: {:?}",
        body
    );
}

// ============================================================================
// Upstream Duplicate ID and Name Uniqueness Tests
// ============================================================================

#[tokio::test]
async fn test_upstream_duplicate_id_returns_409() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "id": "dup-u1",
        "name": "first",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    // Same ID again
    let upstream2 = json!({
        "id": "dup-u1",
        "name": "second",
        "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
    });
    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream2).await;
    assert_eq!(status, 409, "Duplicate ID should return 409: {:?}", body);
}

#[tokio::test]
async fn test_upstream_duplicate_name_returns_409() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let upstream = json!({
        "id": "name-u1",
        "name": "same-name",
        "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
    });
    let (status, _) = admin_post(&base_url, "/upstreams", &token, &upstream).await;
    assert_eq!(status, 201);

    // Different ID but same name
    let upstream2 = json!({
        "id": "name-u2",
        "name": "same-name",
        "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
    });
    let (status, body) = admin_post(&base_url, "/upstreams", &token, &upstream2).await;
    assert_eq!(status, 409, "Duplicate name should return 409: {:?}", body);
}

// ---- Cluster Status Endpoint Tests ----

#[tokio::test]
async fn test_cluster_endpoint_requires_auth() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    // No auth header -> 401
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/cluster", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_cluster_endpoint_cp_mode_empty_registry() {
    let tc = TestConfig::default();
    let registry = std::sync::Arc::new(ferrum_edge::grpc::cp_server::DpNodeRegistry::new());
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: Some(registry),
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "cp");
    assert_eq!(body["connected_data_planes"], 0);
    assert!(body["data_planes"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_cluster_endpoint_cp_mode_with_connected_dps() {
    let tc = TestConfig::default();
    let registry = std::sync::Arc::new(ferrum_edge::grpc::cp_server::DpNodeRegistry::new());

    // Simulate two connected DPs
    registry.insert(ferrum_edge::grpc::cp_server::DpNodeInfo {
        node_id: "dp-node-1".to_string(),
        version: "0.9.0".to_string(),
        namespace: "ferrum".to_string(),
        connected_at: Utc::now(),
        last_update_at: Utc::now(),
    });
    registry.insert(ferrum_edge::grpc::cp_server::DpNodeInfo {
        node_id: "dp-node-2".to_string(),
        version: "0.9.0".to_string(),
        namespace: "staging".to_string(),
        connected_at: Utc::now(),
        last_update_at: Utc::now(),
    });

    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: Some(registry),
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "cp");
    assert_eq!(body["connected_data_planes"], 2);
    let dps = body["data_planes"].as_array().unwrap();
    assert_eq!(dps.len(), 2);
    // Each DP should have expected fields
    for dp in dps {
        assert!(dp["node_id"].is_string());
        assert_eq!(dp["status"], "online");
        assert!(dp["connected_at"].is_string());
        assert!(dp["last_sync_at"].is_string());
    }
}

#[tokio::test]
async fn test_cluster_endpoint_cp_mode_with_connected_mesh_nodes() {
    let tc = TestConfig::default();
    let registry = std::sync::Arc::new(ferrum_edge::grpc::mesh_registry::MeshNodeRegistry::new());
    let connected_at = Utc::now();
    let last_heartbeat_at = connected_at + chrono::Duration::seconds(30);
    let last_update_at = connected_at + chrono::Duration::seconds(60);

    registry.insert(ferrum_edge::grpc::mesh_registry::MeshNodeInfo {
        node_id: "mesh-node-1".to_string(),
        version: "0.9.0".to_string(),
        namespace: "ferrum".to_string(),
        connected_at,
        last_heartbeat_at,
        last_update_at,
    });

    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: Some(registry),
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "cp");
    assert_eq!(body["connected_mesh_nodes"], 1);
    let mesh_nodes = body["mesh_nodes"].as_array().unwrap();
    assert_eq!(mesh_nodes.len(), 1);
    assert_eq!(mesh_nodes[0]["node_id"], "mesh-node-1");
    assert_eq!(
        mesh_nodes[0]["last_heartbeat_at"],
        last_heartbeat_at.to_rfc3339()
    );
    assert_eq!(mesh_nodes[0]["last_sync_at"], last_update_at.to_rfc3339());
}

#[tokio::test]
async fn test_cluster_endpoint_dp_mode_connected() {
    let tc = TestConfig::default();
    let now = Utc::now();
    let conn_state = std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(
        ferrum_edge::grpc::dp_client::DpCpConnectionState {
            connected: true,
            cp_url: "http://cp:50051".to_string(),
            is_primary: true,
            last_config_received_at: Some(now),
            connected_since: Some(now),
        },
    )));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "dp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(conn_state),
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "dp");
    assert_eq!(body["control_plane"]["status"], "online");
    assert_eq!(body["control_plane"]["url"], "http://cp:50051");
    assert!(body["control_plane"]["connected_since"].is_string());
    assert!(body["control_plane"]["last_config_received_at"].is_string());
}

#[tokio::test]
async fn test_cluster_endpoint_dp_mode_disconnected() {
    let tc = TestConfig::default();
    let conn_state = std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(
        ferrum_edge::grpc::dp_client::DpCpConnectionState::new_disconnected("http://cp:50051"),
    )));
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "dp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(conn_state),
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "dp");
    assert_eq!(body["control_plane"]["status"], "offline");
    assert!(body["control_plane"]["connected_since"].is_null());
    assert!(body["control_plane"]["last_config_received_at"].is_null());
}

#[tokio::test]
async fn test_cluster_endpoint_database_mode() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "database");
    assert!(body["message"].is_string());
}
