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
        audience: None,
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
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
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
        let _ = serve_admin_on_listener(
            listener,
            state_clone,
            shutdown_rx_clone,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    // Liveness/readiness are unauthenticated, but the detailed cached_config
    // diagnostics require auth — present a valid admin token.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .header(
            "authorization",
            format!("Bearer {}", generate_test_token(&tc)),
        )
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .header(
            "authorization",
            format!("Bearer {}", generate_test_token(&tc)),
        )
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: Some(startup_ready.clone()),
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(cached.clone()),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_pagination_test_config(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
    // An omitted limit reports the server default (100), not the result count.
    assert_eq!(body["pagination"]["limit"], 100);
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
    assert_eq!(body["pagination"]["offset"], 2);
    assert_eq!(body["pagination"]["limit"], 2);
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
async fn test_list_offset_width_is_independent_of_target_pointer_size() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // One past u32::MAX must remain a valid backend-safe offset even on a
    // 32-bit target. An in-memory collection cannot reach it, so the explicit
    // policy is an empty page with the requested offset preserved.
    let (status, body, _) =
        admin_get(&base_url, "/proxies?offset=4294967296&limit=10", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["pagination"]["offset"], 4_294_967_296u64);
    assert_eq!(body["pagination"]["limit"], 10);
    assert_eq!(body["pagination"]["total"], 5);
}

#[tokio::test]
async fn malformed_pagination_is_ignored_by_non_paginated_routes() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/backup?limit=abc", &token).await;
    assert_eq!(status, 200, "backup must ignore limit: {body:?}");
    assert_eq!(body["counts"]["proxies"], 5);

    let (status, body, _) = admin_get(&base_url, "/cluster?offset=-1", &token).await;
    assert_eq!(status, 200, "cluster must ignore offset: {body:?}");
    assert_eq!(body["mode"], "test");
}

// ---- /namespaces pagination tests ----

/// Admin state backed by a real (SQLite) database seeded with one upstream
/// per namespace, so `GET /namespaces` takes the database-paginated path
/// instead of the cached-config fallback.
async fn create_seeded_db_admin_state(
    tc: &TestConfig,
    db_url: &str,
    namespaces: &[&str],
) -> AdminState {
    let store = ferrum_edge::config::db_loader::DatabaseStore::connect_with_pool_config(
        "sqlite",
        db_url,
        ferrum_edge::config::db_loader::DbPoolConfig::default(),
    )
    .await
    .expect("connect sqlite store");
    for namespace in namespaces {
        sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
            .bind(format!("{namespace}-upstream"))
            .bind(namespace)
            .bind(format!("{namespace}-name"))
            .execute(&store.pool())
            .await
            .unwrap();
    }
    AdminState {
        db: Some(Arc::new(store)),
        jwt_manager: create_test_jwt_manager(tc),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

fn namespaces_db_url(dir: &tempfile::TempDir) -> String {
    let db_path = dir.path().join("namespaces.db");
    format!("sqlite:{}?mode=rwc", db_path.to_string_lossy())
}

#[tokio::test]
async fn test_list_namespaces_returns_paginated_envelope() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_url = namespaces_db_url(&temp_dir);
    let state = create_seeded_db_admin_state(&tc, &db_url, &["zeta", "alpha", "middle"]).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/namespaces", &token).await;
    assert_eq!(status, 200);
    let data = body["data"].as_array().expect("namespaces data array");
    let names: Vec<&str> = data.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(names, ["alpha", "middle", "zeta"]);
    assert_eq!(body["pagination"]["offset"], 0);
    assert_eq!(body["pagination"]["limit"], 100);
    assert_eq!(body["pagination"]["total"], 3);
}

#[tokio::test]
async fn test_list_namespaces_with_pagination() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_url = namespaces_db_url(&temp_dir);
    let state = create_seeded_db_admin_state(&tc, &db_url, &["zeta", "alpha", "middle"]).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/namespaces?limit=2&offset=2", &token).await;
    assert_eq!(status, 200);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0], "zeta");
    assert_eq!(body["pagination"]["offset"], 2);
    assert_eq!(body["pagination"]["limit"], 2);
    assert_eq!(body["pagination"]["total"], 3);

    // An offset beyond the total is a valid empty page, not an error.
    let (status, body, _) = admin_get(&base_url, "/namespaces?offset=100&limit=10", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["pagination"]["total"], 3);

    // `0` keeps the documented "server default" meaning.
    let (status, body, _) = admin_get(&base_url, "/namespaces?limit=0", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["pagination"]["limit"], 100);
    assert_eq!(body["data"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_list_namespaces_malformed_pagination_rejected() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_url = namespaces_db_url(&temp_dir);
    let state = create_seeded_db_admin_state(&tc, &db_url, &["alpha"]).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/namespaces?limit=abc", &token).await;
    assert_eq!(status, 400, "malformed limit must be rejected: {body:?}");

    let (status, body, _) = admin_get(&base_url, "/namespaces?offset=-1", &token).await;
    assert_eq!(status, 400, "negative offset must be rejected: {body:?}");
}

#[tokio::test]
async fn test_list_namespaces_cached_config_branch_paginates_in_memory() {
    let tc = TestConfig::default();
    let mut config = create_pagination_test_config();
    config.known_namespaces = vec![
        "ferrum".to_string(),
        "prod".to_string(),
        "staging".to_string(),
    ];
    let mut state = create_pagination_admin_state(&tc);
    state.cached_config = Some(Arc::new(ArcSwap::new(Arc::new(config))));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/namespaces?limit=2", &token).await;
    assert_eq!(status, 200);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(body["pagination"]["limit"], 2);
    assert_eq!(body["pagination"]["total"], 3);

    let (status, body, _) = admin_get(&base_url, "/namespaces?limit=abc", &token).await;
    assert_eq!(
        status, 400,
        "the cached-config branch shares the route's pagination contract: {body:?}"
    );
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

    let (status, body, _) =
        admin_get(&base_url, "/proxies?limit=18446744073709551615", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["pagination"]["limit"], 1000);
}

#[tokio::test]
async fn test_malformed_pagination_is_rejected_with_400() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (query, expected_message) in [
        (
            "/proxies?limit=abc",
            "Invalid limit pagination parameter: must be a non-negative integer",
        ),
        (
            "/proxies?limit=-1",
            "Invalid limit pagination parameter: must be a non-negative integer",
        ),
        (
            "/proxies?offset=abc",
            "Invalid offset pagination parameter: must be a non-negative integer",
        ),
        (
            "/proxies?offset=-1",
            "Invalid offset pagination parameter: must be a non-negative integer",
        ),
        (
            "/proxies?limit=18446744073709551616",
            "Invalid limit pagination parameter: exceeds the maximum supported value",
        ),
        // i64::MAX + 1 wrapped negative under the old `as i64` cast and became
        // an enormous MongoDB u64 skip.
        (
            "/proxies?offset=9223372036854775808",
            "Invalid offset pagination parameter: exceeds the maximum supported value",
        ),
    ] {
        let (status, body, _) = admin_get(&base_url, query, &token).await;
        assert_eq!(status, 400, "{query} must be rejected: {body:?}");
        assert_eq!(body["error"], expected_message, "wrong error for {query}");
    }
}

#[tokio::test]
async fn test_malformed_pagination_does_not_preempt_authentication() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;

    // Pagination is validated only after the admin JWT gate, so an
    // unauthenticated caller still gets 401 rather than a 400 that would leak
    // input validation ahead of authentication.
    let (status, body, _) = admin_get(&base_url, "/proxies?limit=abc", "not-a-valid-token").await;
    assert_eq!(status, 401, "unauthenticated caller must get 401: {body:?}");
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
        metrics_auth: Default::default(),
        cached_config: cached_config.map(|config| Arc::new(ArcSwap::new(Arc::new(config)))),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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

#[tokio::test]
async fn transaction_log_schema_admin_rejects_unknown_closed_object_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, expected_path) in [
        (
            "unknown-outer",
            json!({"schemas": {"audit": {}}, "strict": true}),
            "config.strict",
        ),
        (
            "unknown-derived",
            json!({
                "schemas": {"audit": {"derived_fields": [
                    {"name": "outcome", "kind": "outcome", "from": "status"}
                ]}}
            }),
            "derived_fields[0].from",
        ),
        (
            "unknown-metadata",
            json!({
                "schemas": {"audit": {"metadata": {
                    "mode": "flatten", "on_collison": "overwrite"
                }}}
            }),
            "metadata.on_collison",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "transaction_log_schema",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;
        assert_eq!(status, 400, "unknown key was admitted: {body:?}");
        assert!(
            body.to_string().contains(expected_path),
            "error did not identify {expected_path}: {body:?}"
        );
    }
}

#[tokio::test]
async fn transaction_log_schema_crud_validates_the_prospective_database_graph() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let schema = json!({
        "id": "schema-owner",
        "plugin_name": "transaction_log_schema",
        "scope": "global",
        "enabled": true,
        "config": {"schemas": {"audit": {"summary_type": "both"}}}
    });
    let logger = json!({
        "id": "schema-consumer",
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": true,
        "config": {"schema_ref": "audit"}
    });

    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &schema).await;
    assert_eq!(status, 201, "schema create failed: {body:?}");
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &logger).await;
    assert_eq!(
        status, 201,
        "the DB schema must resolve before any live-registry reload: {body:?}"
    );

    let duplicate = json!({
        "id": "duplicate-schema-owner",
        "plugin_name": "transaction_log_schema",
        "scope": "global",
        "enabled": true,
        "config": {"schemas": {"audit": {}}}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &duplicate).await;
    assert_eq!(status, 400, "duplicate schema name was admitted: {body:?}");
    assert!(body.to_string().contains("registered more than once"));

    let mut renamed = schema.clone();
    renamed["config"] = json!({"schemas": {"renamed": {}}});
    let (status, body) =
        admin_put(&base_url, "/plugins/config/schema-owner", &token, &renamed).await;
    assert_eq!(status, 400, "dangling rename was admitted: {body:?}");
    assert!(body.to_string().contains("unknown schema 'audit'"));

    let (status, body) = admin_delete(&base_url, "/plugins/config/schema-owner", &token).await;
    assert_eq!(status, 400, "dangling delete was admitted: {body:?}");
    assert!(body.to_string().contains("unknown schema 'audit'"));
}

#[tokio::test]
async fn disabled_schema_graph_plugins_defer_graph_validation_but_not_egress_screening() {
    let tc = TestConfig::default();
    let (mut state, _dir) = create_db_admin_state(&tc).await;
    state.backend_allow_ips = ferrum_edge::config::BackendEgressPolicy::from_env(
        ferrum_edge::config::BackendAllowIps::Both,
        "",
        "",
        true,
    )
    .expect("default deny policy is valid");
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let disabled = json!({
        "id": "disabled-schema-ref-crud",
        "plugin_name": "rate_limiting",
        "scope": "global",
        "enabled": false,
        "config": {
            "window_seconds": 60,
            "max_requests": 10,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "schema_ref": "missing"
        }
    });

    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &disabled).await;
    assert_eq!(
        status, 201,
        "disabled direct CRUD must defer construction and graph validation: {body:?}"
    );

    let mut batch_plugin = disabled;
    batch_plugin["id"] = json!("disabled-schema-ref-batch");
    let (status, body) = admin_post(
        &base_url,
        "/batch",
        &token,
        &json!({"plugin_configs": [batch_plugin]}),
    )
    .await;
    assert_eq!(
        status, 201,
        "disabled batch config must defer construction and graph validation: {body:?}"
    );

    let denied = json!({
        "id": "disabled-denied-egress-crud",
        "plugin_name": "rate_limiting",
        "scope": "global",
        "enabled": false,
        "config": {
            "window_seconds": 60,
            "max_requests": 10,
            "sync_mode": "redis",
            "redis_url": "redis://169.254.169.254:6379/0",
            "schema_ref": "missing"
        }
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &denied).await;
    assert_eq!(
        status, 400,
        "disabled direct CRUD must retain literal egress screening: {body:?}"
    );
    assert!(
        body.to_string()
            .contains("redis_url IP 169.254.169.254 denied"),
        "unexpected direct CRUD denial: {body:?}"
    );

    let mut denied_batch = denied;
    denied_batch["id"] = json!("disabled-denied-egress-batch");
    let (status, body) = admin_post(
        &base_url,
        "/batch",
        &token,
        &json!({"plugin_configs": [denied_batch]}),
    )
    .await;
    assert_eq!(
        status, 400,
        "disabled batch config must retain literal egress screening: {body:?}"
    );
    assert!(
        body.to_string()
            .contains("redis_url IP 169.254.169.254 denied"),
        "unexpected batch denial: {body:?}"
    );
}

#[tokio::test]
async fn transaction_log_schema_batch_and_restore_are_definition_order_independent() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let logger = json!({
        "id": "ordered-logger",
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": true,
        "config": {"schema_ref": "ordered"}
    });
    let schema = json!({
        "id": "ordered-schema",
        "plugin_name": "transaction_log_schema",
        "scope": "global",
        "enabled": true,
        "config": {"schemas": {"ordered": {}}}
    });

    let (status, body) = admin_post(
        &base_url,
        "/batch",
        &token,
        &json!({"plugin_configs": [logger, schema]}),
    )
    .await;
    assert_eq!(status, 201, "definition-last batch failed: {body:?}");

    let restore_logger = json!({
        "id": "restore-logger",
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": true,
        "config": {"schema_ref": "restored"}
    });
    let restore_schema = json!({
        "id": "restore-schema",
        "plugin_name": "transaction_log_schema",
        "scope": "global",
        "enabled": true,
        "config": {"schemas": {"restored": {}}}
    });
    let (status, body) = admin_post(
        &base_url,
        "/restore?confirm=true",
        &token,
        &json!({"plugin_configs": [restore_logger, restore_schema]}),
    )
    .await;
    assert_eq!(status, 200, "definition-last restore failed: {body:?}");

    let invalid_restore = json!({
        "plugin_configs": [{
            "id": "dangling-restore-logger",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {"schema_ref": "missing"}
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &invalid_restore).await;
    assert_eq!(status, 400, "dangling restore was admitted: {body:?}");
    assert!(body.to_string().contains("unknown schema 'missing'"));

    let (status, _, _) = admin_get(&base_url, "/plugins/config/restore-schema", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "invalid restore must leave the prior graph intact"
    );
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
async fn test_batch_create_rejects_hmac_secret_reused_by_persisted_consumer() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let shared_secret = "batch-shared-hmac-secret-at-least-32-characters";

    let existing = json!({
        "id": "existing-hmac-consumer",
        "username": "alice",
        "credentials": {"hmac_auth": [{"secret": shared_secret}]}
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &existing).await;
    assert_eq!(status, 201, "consumer seed should succeed: {body:?}");

    let conflicting_batch = json!({
        "consumers": [{
            "id": "batch-hmac-consumer",
            "username": "bob",
            "credentials": {"hmac_auth": [{"secret": shared_secret}]}
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &conflicting_batch).await;

    assert_eq!(status, 400, "batch HMAC reuse must be rejected: {body:?}");
    assert!(
        body["validation_errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|error| error.contains("Duplicate hmac_auth shared secret"))))
    );
    assert!(
        !body.to_string().contains(shared_secret),
        "validation response must not disclose the shared secret"
    );
}

#[tokio::test]
async fn non_hmac_credential_update_revalidates_retained_hmac_credentials() {
    let tc = TestConfig::default();
    let (state, temp_dir) = create_db_admin_state(&tc).await;
    let db_path = temp_dir.path().join("test_batch.db");
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let shared_secret = "retained-hmac-secret-at-least-32-characters";
    let owner = json!({
        "id": "retained-hmac-owner",
        "username": "alice",
        "credentials": {"hmac_auth": [{"secret": shared_secret}]}
    });
    let stale = json!({
        "id": "retained-hmac-stale",
        "username": "bob",
        "credentials": {"hmac_auth": [{
            "secret": "original-hmac-secret-at-least-32-characters"
        }]}
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &owner).await;
    assert_eq!(status, 201, "HMAC owner seed failed: {body:?}");
    let (status, body) = admin_post(&base_url, "/consumers", &token, &stale).await;
    assert_eq!(status, 201, "stale consumer seed failed: {body:?}");

    // Simulate a legacy/out-of-band row whose HMAC credential no longer agrees
    // with its datastore index entry. A non-HMAC mutation still rewrites the
    // complete Consumer and must detect this collision before persistence.
    let db_url = format!("sqlite:{}?mode=rw", db_path.to_string_lossy());
    let pool = sqlx::SqlitePool::connect(&db_url)
        .await
        .expect("connect raw SQLite pool");
    sqlx::query("UPDATE consumers SET credentials = ? WHERE namespace = ? AND id = ?")
        .bind(json!({"hmac_auth": [{"secret": shared_secret}]}).to_string())
        .bind("ferrum")
        .bind("retained-hmac-stale")
        .execute(&pool)
        .await
        .expect("inject stale HMAC credential");

    let (status, body) = admin_put(
        &base_url,
        "/consumers/retained-hmac-stale/credentials/keyauth",
        &token,
        &json!([{"key": "new-keyauth-credential"}]),
    )
    .await;

    assert_eq!(
        status, 409,
        "retained HMAC collision was not rejected: {body:?}"
    );
    assert!(
        body.to_string()
            .contains("Duplicate hmac_auth shared secret"),
        "collision must be reported by candidate validation, not the datastore backstop: {body:?}"
    );
    assert!(
        !body.to_string().contains(shared_secret),
        "collision response must not disclose the HMAC secret"
    );
    let (status, consumer, _) =
        admin_get(&base_url, "/consumers/retained-hmac-stale", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        consumer["credentials"].get("keyauth").is_none(),
        "rejected non-HMAC mutation must not be persisted"
    );
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
async fn prometheus_plugin_crud_rejects_a_second_enabled_registry_owner() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let first = json!({
        "id": "prometheus-owner",
        "plugin_name": "prometheus_metrics",
        "scope": "global",
        "enabled": true,
        "config": {}
    });

    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &first).await;
    assert_eq!(status, 201, "first owner should be admitted: {body:?}");

    let (status, body) = admin_put(
        &base_url,
        "/plugins/config/prometheus-owner",
        &token,
        &first,
    )
    .await;
    assert_eq!(
        status, 200,
        "in-place owner update should be admitted: {body:?}"
    );

    let disabled = json!({
        "id": "prometheus-disabled",
        "plugin_name": "prometheus_metrics",
        "scope": "global",
        "enabled": false,
        "config": {}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &disabled).await;
    assert_eq!(
        status, 201,
        "disabled config should not compete for ownership: {body:?}"
    );

    let mut enabled = disabled.clone();
    enabled["enabled"] = json!(true);
    let (status, body) = admin_put(
        &base_url,
        "/plugins/config/prometheus-disabled",
        &token,
        &enabled,
    )
    .await;
    assert_eq!(
        status, 409,
        "enabling a second owner must conflict: {body:?}"
    );
    assert!(body["error"].as_str().unwrap_or("").contains("at most one"));

    let third = json!({
        "id": "prometheus-second-create",
        "plugin_name": "prometheus_metrics",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &third).await;
    assert_eq!(
        status, 409,
        "creating a second owner must conflict: {body:?}"
    );

    let response = reqwest::Client::new()
        .post(format!("{base_url}/plugins/config"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Ferrum-Namespace", "other-tenant")
        .json(&json!({
            "id": "prometheus-other-namespace",
            "plugin_name": "prometheus_metrics",
            "scope": "global",
            "enabled": true,
            "config": {}
        }))
        .send()
        .await
        .expect("cross-namespace create request");
    assert_eq!(
        response.status().as_u16(),
        409,
        "the process-wide registry owner must be unique across namespaces"
    );
}

#[tokio::test]
async fn prometheus_plugin_batch_rejects_duplicate_and_existing_owners() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let duplicate_batch = json!({
        "plugin_configs": [
            {"id": "prometheus-batch-a", "plugin_name": "prometheus_metrics", "scope": "global", "enabled": true, "config": {}},
            {"id": "prometheus-batch-b", "plugin_name": "prometheus_metrics", "scope": "global", "enabled": true, "config": {}}
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &duplicate_batch).await;
    assert_eq!(status, 400, "same-batch owners must be rejected: {body:?}");
    assert!(
        body["validation_errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|error| error.contains("at most one"))))
    );

    let owner = json!({
        "id": "prometheus-existing-owner",
        "plugin_name": "prometheus_metrics",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &owner).await;
    assert_eq!(status, 201, "owner seed should succeed: {body:?}");

    let existing_conflict = json!({
        "plugin_configs": [
            {"id": "prometheus-batch-new", "plugin_name": "prometheus_metrics", "scope": "global", "enabled": true, "config": {}}
        ]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &existing_conflict).await;
    assert_eq!(
        status, 400,
        "batch must reject a persisted owner conflict: {body:?}"
    );
    assert!(
        body["validation_errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|error| error.contains("already owns"))))
    );
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_jwt_auth_policy_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, unknown_key) in [
        (
            "jwt-audience-typo",
            json!({"audience": ["payments-api"]}),
            "audience",
        ),
        (
            "jwt-issuer-typo",
            json!({"expected_issue": "https://issuer.example"}),
            "expected_issue",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "jwt_auth",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(status, 400, "unknown jwt_auth key was admitted: {body}");
        assert!(
            body.to_string()
                .contains(&format!("jwt_auth: unknown config key '{unknown_key}'")),
            "unexpected admin validation response: {body}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_load_testing_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let plugin = json!({
        "id": "load-testing-typo",
        "plugin_name": "load_testing",
        "scope": "global",
        "enabled": true,
        "config": {
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 5,
            "duration_seconds": 10,
            "request_timeot_ms": 5000,
            "gateway_adresses": ["https://10.0.0.2:8443"]
        }
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

    assert_eq!(status, 400, "unknown load_testing key was admitted: {body}");
    let body_text = body.to_string();
    assert!(
        body_text.contains("unknown configuration key"),
        "unexpected admin validation response: {body}"
    );
    assert!(
        body_text.contains("config.gateway_adresses") || body_text.contains("gateway_adresses"),
        "admin response must name gateway_adresses: {body}"
    );
    assert!(
        body_text.contains("config.request_timeot_ms") || body_text.contains("request_timeot_ms"),
        "admin response must name request_timeot_ms: {body}"
    );
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_compression_config_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, needle) in [
        (
            "compression-length-typo",
            json!({"min_content_lenght": 4096}),
            "config.min_content_lenght",
        ),
        (
            "compression-gzip-typo",
            json!({"gzip_leveel": 1}),
            "config.gzip_leveel",
        ),
        (
            "compression-accept-typo",
            json!({"remove_accept_encodng": false}),
            "config.remove_accept_encodng",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "compression",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(status, 400, "unknown compression key was admitted: {body}");
        assert!(
            body.to_string().contains(needle),
            "unexpected admin validation response: {body}"
        );
        assert!(
            body.to_string().contains("unknown configuration key"),
            "admin error must use unknown-key wording: {body}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_proxy_alerts_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, needle) in [
        (
            "proxy-alerts-enabled-typo",
            json!({
                "enabledd": false,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "config.enabledd",
        ),
        (
            "proxy-alerts-rule-cross-variant",
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "threshold_count": 10,
                    "channels": ["ops"]
                }]
            }),
            "rules[0].threshold_count",
        ),
        (
            "proxy-alerts-channel-typo",
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x",
                        "channel_overide": "#alerts"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "channels.ops.channel_overide",
        ),
        (
            "proxy-alerts-enabled-wrong-type",
            json!({
                "enabled": "false",
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'enabled' must be a boolean",
        ),
        (
            "proxy-alerts-max-concurrent-zero",
            json!({
                "max_concurrent_dispatches": 0,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'max_concurrent_dispatches' must be >= 1",
        ),
        (
            "proxy-alerts-min-request-count-wrong-type",
            json!({
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "min_request_count": "100",
                    "channels": ["ops"]
                }]
            }),
            "'min_request_count' must be an unsigned integer",
        ),
        (
            "proxy-alerts-quiet-hours-null",
            json!({
                "quiet_hours_utc": null,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"]
                }]
            }),
            "'quiet_hours_utc' must be an array",
        ),
        (
            "proxy-alerts-unused-default-resolved-window-out-of-range",
            json!({
                "default_resolved_window_seconds": 4,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "channels": ["ops"],
                    "recovery": {"resolved_window_seconds": 300}
                }]
            }),
            "'default_resolved_window_seconds' must be in [5, 86400]",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "proxy_alerts",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(
            status, 400,
            "invalid proxy_alerts config was admitted: {body}"
        );
        assert!(
            body.to_string().contains(needle),
            "unexpected admin validation response for {needle}: {body}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_mesh_route_dispatch_nested_policy_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config) in [
        (
            "mesh-route-reject-typo",
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"}
                }],
                "reject_unmtached": true
            }),
        ),
        (
            "mesh-route-retry-typo",
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {"max_retry": 2}
                }]
            }),
        ),
        (
            "mesh-route-backend-tls-typo",
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "api.internal",
                        "backend_port": 443,
                        "backend_tls": {"client_certpath": "/tls/client.pem"}
                    }
                }]
            }),
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "mesh_route_dispatch",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(
            status, 400,
            "unknown mesh_route_dispatch nested key was admitted: {body}"
        );
        assert!(
            body.to_string().contains("unknown field"),
            "unexpected admin validation response: {body}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_malformed_correlation_id_configs() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, expected_error) in [
        (
            "correlation-non-object",
            json!([]),
            "correlation_id: config must be a JSON object",
        ),
        (
            "correlation-unknown-key",
            json!({"echo_downsteam": false}),
            "correlation_id: unknown config field(s): echo_downsteam",
        ),
        (
            "correlation-managed-header",
            json!({"header_name": "Content-Length"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-internal-grpc-web-marker",
            json!({"header_name": "X-Grpc-Web-Mode"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-internal-compression-marker",
            json!({"header_name": "X-Ferrum-Original-Content-Encoding"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-early-data-marker",
            json!({"header_name": "Early-Data"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-traceparent",
            json!({"header_name": "Traceparent"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-tracestate",
            json!({"header_name": "Tracestate"}),
            "correlation_id: 'header_name' is protocol-managed",
        ),
        (
            "correlation-credential-header",
            json!({"header_name": "Authorization"}),
            "correlation_id: 'header_name' is protocol-managed or security-sensitive",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "correlation_id",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(
            status, 400,
            "malformed correlation config was admitted: {body}"
        );
        assert!(
            body.to_string().contains(expected_error),
            "unexpected admin validation response: {body}"
        );
    }
}

#[tokio::test]
async fn batch_admission_rejects_duplicate_effective_correlation_headers() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let candidate = json!({
        "proxies": [{
            "id": "duplicate-correlation-proxy",
            "listen_path": "/duplicate-correlation",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "duplicate-correlation-first"},
                {"plugin_config_id": "duplicate-correlation-second"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "duplicate-correlation-first",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "duplicate-correlation-proxy",
                "enabled": true,
                "config": {}
            },
            {
                "id": "duplicate-correlation-second",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "duplicate-correlation-proxy",
                "enabled": true,
                "priority_override": 75,
                "config": {"header_name": " X-Request-ID "}
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &candidate).await;

    assert_eq!(
        status, 400,
        "duplicate correlation writers were admitted: {body}"
    );
    assert!(
        body.to_string().contains("duplicate effective header_name"),
        "unexpected duplicate-correlation admission response: {body}"
    );
}

#[tokio::test]
async fn batch_admission_rejects_equal_effective_correlation_priorities() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let candidate = json!({
        "proxies": [{
            "id": "equal-correlation-priority-proxy",
            "listen_path": "/equal-correlation-priority",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "equal-correlation-priority-first"},
                {"plugin_config_id": "equal-correlation-priority-second"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "equal-correlation-priority-first",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "equal-correlation-priority-proxy",
                "enabled": true,
                "config": {"header_name": "x-internal-request-id"}
            },
            {
                "id": "equal-correlation-priority-second",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "equal-correlation-priority-proxy",
                "enabled": true,
                "config": {"header_name": "x-external-request-id"}
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &candidate).await;

    assert_eq!(
        status, 400,
        "equal correlation priorities were admitted: {body}"
    );
    assert!(
        body.to_string().contains("duplicate effective priority 50"),
        "unexpected correlation-priority admission response: {body}"
    );
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_ai_prompt_compressor_policy_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (index, (unknown_key, config)) in [
        ("compress_role", json!({"compress_role": ["system"]})),
        ("target_rato", json!({"target_rato": 0.9})),
        ("min_content_token", json!({"min_content_token": 10})),
        ("max_scan_byte", json!({"max_scan_byte": 4096})),
        ("preserve_tags", json!({"preserve_tags": "keep"})),
    ]
    .into_iter()
    .enumerate()
    {
        let plugin = json!({
            "id": format!("prompt-compressor-typo-{index}"),
            "plugin_name": "ai_prompt_compressor",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(status, 400, "unknown compressor key was admitted: {body}");
        assert!(
            body.to_string().contains(&format!(
                "ai_prompt_compressor: unknown config field(s): {unknown_key}"
            )),
            "unexpected admin validation response: {body}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_ai_stream_router_policy_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for (id, config, needle) in [
        (
            "stream-router-enabled-typo",
            json!({
                "enabeld": false,
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"]
                }]
            }),
            "config.enabeld",
        ),
        (
            "stream-router-provider-typo",
            json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"],
                    "inherit_backend_tl": true
                }]
            }),
            "config.providers[0].inherit_backend_tl",
        ),
        (
            "stream-router-fallback-typo",
            json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"]
                }],
                "fallback": {"max_attemps": 3}
            }),
            "config.fallback.max_attemps",
        ),
    ] {
        let plugin = json!({
            "id": id,
            "plugin_name": "ai_stream_router",
            "scope": "global",
            "enabled": true,
            "config": config
        });
        let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;

        assert_eq!(
            status, 400,
            "unknown ai_stream_router key was admitted: {body}"
        );
        let body_text = body.to_string();
        assert!(
            body_text.contains("unknown configuration key"),
            "unexpected admin validation response: {body_text}"
        );
        assert!(
            body_text.contains(needle),
            "admin response missing {needle}: {body_text}"
        );
    }
}

#[tokio::test]
async fn test_admin_create_rejects_unknown_adaptive_concurrency_policy_keys() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let plugin = json!({
        "id": "adaptive-limit-typo",
        "plugin_name": "adaptive_concurrency",
        "scope": "global",
        "enabled": true,
        "config": {"max_limt": 32}
    });

    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;
    assert_eq!(status, 400, "unknown adaptive key was admitted: {body}");
    assert!(
        body.to_string()
            .contains("adaptive_concurrency: unknown config key 'max_limt'"),
        "unexpected admin validation response: {body}"
    );
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
async fn plugin_delete_rejects_revealing_global_body_transformer_beside_hmac() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let seed = json!({
        "proxies": [{
            "id": "delete-shadow-proxy",
            "listen_path": "/delete-shadow",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "delete-shadow-hmac"},
                {"plugin_config_id": "delete-shadow-scoped-transformer"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "delete-shadow-global-transformer",
                "plugin_name": "request_transformer",
                "scope": "global",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "gateway",
                    "value": "ferrum"
                }]}
            },
            {
                "id": "delete-shadow-scoped-transformer",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "delete-shadow-proxy",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Gateway",
                    "value": "ferrum"
                }]}
            },
            {
                "id": "delete-shadow-hmac",
                "plugin_name": "hmac_auth",
                "scope": "proxy",
                "proxy_id": "delete-shadow-proxy",
                "enabled": true,
                "config": {"clock_skew_seconds": 300}
            }
        ]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(
        status, 201,
        "safe shadowed composition seed failed: {body:?}"
    );

    let (status, body) = admin_delete(
        &base_url,
        "/plugins/config/delete-shadow-scoped-transformer",
        &token,
    )
    .await;

    assert_eq!(status, 400, "unsafe plugin deletion was admitted: {body:?}");
    assert!(
        body.to_string()
            .contains("hmac_auth cannot be combined with request-body transformer"),
        "unexpected deletion validation response: {body:?}"
    );
    let (status, _, _) = admin_get(
        &base_url,
        "/plugins/config/delete-shadow-scoped-transformer",
        &token,
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "rejected deletion must retain the shadowing plugin"
    );
}

#[tokio::test]
async fn hmac_composition_admission_is_namespace_scoped() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let client = reqwest::Client::new();
    let tenant_a = client
        .post(format!("{base_url}/plugins/config"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Ferrum-Namespace", "tenant-a")
        .json(&json!({
            "id": "tenant-a-global-hmac",
            "plugin_name": "hmac_auth",
            "scope": "global",
            "enabled": true,
            "config": {"clock_skew_seconds": 300}
        }))
        .send()
        .await
        .expect("create tenant-a HMAC plugin");
    assert_eq!(tenant_a.status(), reqwest::StatusCode::CREATED);

    let tenant_b = client
        .post(format!("{base_url}/plugins/config"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Ferrum-Namespace", "tenant-b")
        .json(&json!({
            "id": "tenant-b-global-transformer",
            "plugin_name": "request_transformer",
            "scope": "global",
            "enabled": true,
            "config": {"rules": [{
                "operation": "add",
                "target": "body",
                "key": "gateway",
                "value": "ferrum"
            }]}
        }))
        .send()
        .await
        .expect("create tenant-b request transformer");
    let status = tenant_b.status();
    let body: Value = tenant_b.json().await.expect("tenant-b response body");

    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "plugins in distinct runtime namespace slices must not conflict: {body:?}"
    );
}

#[tokio::test]
async fn admin_rejects_custom_request_body_transformer_beside_hmac() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let batch = json!({
        "proxies": [{
            "id": "custom-transform-proxy",
            "listen_path": "/custom-transform",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "custom-transform-hmac"},
                {"plugin_config_id": "custom-transform-plugin"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "custom-transform-hmac",
                "plugin_name": "hmac_auth",
                "scope": "proxy",
                "proxy_id": "custom-transform-proxy",
                "enabled": true,
                "config": {"clock_skew_seconds": 300}
            },
            {
                "id": "custom-transform-plugin",
                "plugin_name": "example_plugin",
                "scope": "proxy",
                "proxy_id": "custom-transform-proxy",
                "enabled": true,
                "config": {"request_body_prefix": "custom:"}
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;

    assert_eq!(
        status, 400,
        "custom body transformer was admitted: {body:?}"
    );
    assert!(
        body.to_string().contains("example_plugin"),
        "composition error must identify the custom transformer: {body:?}"
    );
}

#[tokio::test]
async fn admin_rejects_custom_only_correlation_collision_before_persistence() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let batch = json!({
        "proxies": [{
            "id": "custom-correlation-proxy",
            "listen_path": "/custom-correlation",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "custom-correlation-first"},
                {"plugin_config_id": "custom-correlation-second"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "custom-correlation-first",
                "plugin_name": "example_plugin",
                "scope": "proxy",
                "proxy_id": "custom-correlation-proxy",
                "enabled": true,
                "config": {"correlation_header_name": "x-custom-correlation-id"}
            },
            {
                "id": "custom-correlation-second",
                "plugin_name": "example_plugin",
                "scope": "proxy",
                "proxy_id": "custom-correlation-proxy",
                "enabled": true,
                "priority_override": 5001,
                "config": {"correlation_header_name": " X-Custom-Correlation-ID "}
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;

    assert_eq!(
        status, 400,
        "custom correlation collision was admitted: {body:?}"
    );
    assert!(
        body["validation_errors"].as_array().is_some_and(|errors| {
            errors.iter().filter_map(Value::as_str).any(|error| {
                error.contains("duplicate effective header_name \"x-custom-correlation-id\"")
            })
        }),
        "unexpected custom correlation admission response: {body:?}"
    );
    for id in ["custom-correlation-first", "custom-correlation-second"] {
        let (status, _, _) = admin_get(&base_url, &format!("/plugins/config/{id}"), &token).await;
        assert_eq!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "rejected custom correlation config {id} was persisted"
        );
    }
    let (status, _, _) = admin_get(&base_url, "/proxies/custom-correlation-proxy", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "rejected custom correlation proxy was persisted"
    );
}

#[tokio::test]
async fn admin_rejects_reserved_custom_correlation_claim_before_persistence() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let batch = json!({
        "proxies": [{
            "id": "reserved-custom-correlation-proxy",
            "listen_path": "/reserved-custom-correlation",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "reserved-custom-correlation"}]
        }],
        "plugin_configs": [{
            "id": "reserved-custom-correlation",
            "plugin_name": "example_plugin",
            "scope": "proxy",
            "proxy_id": "reserved-custom-correlation-proxy",
            "enabled": true,
            "config": {"correlation_header_name": " AuThOrIzAtIoN "}
        }]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;

    assert_eq!(status, 400, "reserved custom claim was admitted: {body:?}");
    assert!(
        body["validation_errors"].as_array().is_some_and(|errors| {
            errors.iter().filter_map(Value::as_str).any(|error| {
                error.contains("effective header_name \"authorization\"")
                    && error.contains("plugin \"example_plugin\"")
                    && error.contains("protocol Http")
                    && error.contains("reserved")
            })
        }),
        "unexpected reserved custom correlation admission response: {body:?}"
    );
    let (status, _, _) = admin_get(
        &base_url,
        "/plugins/config/reserved-custom-correlation",
        &token,
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "rejected reserved custom correlation config was persisted"
    );
    let (status, _, _) = admin_get(
        &base_url,
        "/proxies/reserved-custom-correlation-proxy",
        &token,
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "rejected reserved custom correlation proxy was persisted"
    );
}

#[tokio::test]
async fn admin_allows_custom_correlation_owners_on_disjoint_protocols() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let batch = json!({
        "proxies": [{
            "id": "disjoint-correlation-proxy",
            "listen_path": "/disjoint-correlation",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "disjoint-correlation-http"},
                {"plugin_config_id": "disjoint-correlation-tcp"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "disjoint-correlation-http",
                "plugin_name": "example_plugin",
                "scope": "proxy",
                "proxy_id": "disjoint-correlation-proxy",
                "enabled": true,
                "config": {"correlation_header_name": "x-custom-correlation-id"}
            },
            {
                "id": "disjoint-correlation-tcp",
                "plugin_name": "example_plugin",
                "scope": "proxy",
                "proxy_id": "disjoint-correlation-proxy",
                "enabled": true,
                "config": {
                    "correlation_header_name": " X-Custom-Correlation-ID ",
                    "protocol": "tcp"
                }
            }
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "disjoint custom correlation owners were rejected: {body:?}"
    );
    for id in ["disjoint-correlation-http", "disjoint-correlation-tcp"] {
        let (status, _, _) = admin_get(&base_url, &format!("/plugins/config/{id}"), &token).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "admitted custom correlation config {id} was not persisted"
        );
    }
    let (status, _, _) = admin_get(&base_url, "/proxies/disjoint-correlation-proxy", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "admitted custom correlation proxy was not persisted"
    );
}

#[tokio::test]
async fn restore_rejects_hmac_request_body_transformer_before_delete() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let seed = json!({
        "proxies": [{
            "id": "restore-composition-keep",
            "listen_path": "/restore-composition-keep",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "restore preservation seed failed: {body:?}");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-composition-new",
            "listen_path": "/restore-composition-new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true,
            "plugins": [
                {"plugin_config_id": "restore-composition-hmac"},
                {"plugin_config_id": "restore-composition-transformer"}
            ]
        }],
        "plugin_configs": [
            {
                "id": "restore-composition-hmac",
                "plugin_name": "hmac_auth",
                "scope": "proxy",
                "proxy_id": "restore-composition-new",
                "enabled": true,
                "config": {"clock_skew_seconds": 300}
            },
            {
                "id": "restore-composition-transformer",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "restore-composition-new",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "gateway",
                    "value": "ferrum"
                }]}
            }
        ]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 400, "unsafe restore was admitted: {body:?}");
    assert!(
        body["validation_errors"]
            .as_array()
            .is_some_and(|errors| errors
                .iter()
                .any(|error| error.as_str().is_some_and(|error| error
                    .contains("hmac_auth cannot be combined with request-body transformer")))),
        "unexpected restore validation response: {body:?}"
    );
    let (status, _, _) = admin_get(&base_url, "/proxies/restore-composition-keep", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "restore validation must run before destructive deletion"
    );
}

#[tokio::test]
async fn restore_prometheus_owner_conflicts_only_with_other_namespaces() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let owner = json!({
        "id": "restore-prometheus-existing",
        "plugin_name": "prometheus_metrics",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &owner).await;
    assert_eq!(status, 201, "owner seed should succeed: {body:?}");

    let restore_payload = json!({
        "plugin_configs": [{
            "id": "restore-prometheus-incoming",
            "plugin_name": "prometheus_metrics",
            "scope": "global",
            "enabled": true,
            "config": {}
        }]
    });
    let response = reqwest::Client::new()
        .post(format!("{base_url}/restore?confirm=true"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Ferrum-Namespace", "restore-other-tenant")
        .json(&restore_payload)
        .send()
        .await
        .expect("cross-namespace restore request");
    assert_eq!(
        response.status().as_u16(),
        400,
        "restore must reject an owner in another namespace"
    );
    let body: Value = response.json().await.expect("restore conflict body");
    assert!(
        body["validation_errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| error
                .as_str()
                .is_some_and(|error| error.contains("another namespace"))))
    );

    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;
    assert_eq!(
        status, 200,
        "restoring the current namespace replaces its prior owner: {body:?}"
    );
}

#[tokio::test]
async fn test_restore_rolls_back_prior_config_after_mid_import_failure() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_rollback.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [{
            "id": "restore-keep",
            "listen_path": "/keep",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);

    sqlx::query(
        "CREATE TRIGGER fail_restore_proxy BEFORE INSERT ON proxies \
         WHEN NEW.id = 'restore-fail' \
         BEGIN SELECT RAISE(FAIL, 'injected restore persistence failure'); END",
    )
    .execute(&pool)
    .await
    .expect("Failed to install restore fault-injection trigger");

    let restore_payload = json!({
        "consumers": [{
            "id": "restore-partial-consumer",
            "username": "partial-user",
            "credentials": {}
        }],
        "proxies": [{
            "id": "restore-fail",
            "listen_path": "/new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 500, "Failed restore response: {:?}", body);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("prior config retained"),
        "rollback response must confirm retention: {:?}",
        body
    );

    let (status, _, _) = admin_get(&base_url, "/proxies/restore-keep", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the prior known-good proxy must survive a failed restore"
    );
    let (status, _, _) = admin_get(&base_url, "/consumers/restore-partial-consumer", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "resources committed before the injected failure must be removed"
    );
}

/// Rollback must faithfully replay the raw pre-restore snapshot even when it
/// contains a legacy/out-of-band mTLS DNS ambiguity. Normal admission rejects
/// this state, but applying that new validation to the compensating replay
/// would first delete the namespace and then make its prior state unrecoverable.
#[tokio::test]
async fn restore_rollback_replays_preexisting_ambiguous_mtls_dns_snapshot() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_mtls_dns_rollback.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "consumers": [
            {
                "id": "restore-dns-upper",
                "username": "restore-dns-upper",
                "credentials": {
                    "mtls_auth": [{"identity": "API.Example.COM"}]
                }
            },
            {
                "id": "restore-dns-lower",
                "username": "restore-dns-lower",
                "credentials": {
                    "mtls_auth": [{"identity": "other.example.com"}]
                }
            }
        ],
        "plugin_configs": [{
            "id": "restore-dns-policy",
            "plugin_name": "mtls_auth",
            "scope": "global",
            "enabled": true,
            "config": {"cert_field": "san_dns"}
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "mTLS DNS rollback seed failed: {body:?}");

    // Simulate a pre-fix or out-of-band row. Exact credential uniqueness still
    // permits this case variant; the active san_dns policy makes the resulting
    // runtime snapshot ambiguous. The restore snapshot intentionally uses the
    // raw, non-validating loader so it can preserve this prior durable state.
    let ambiguous_credentials = json!({
        "mtls_auth": [{"identity": "api.example.com"}]
    });
    sqlx::query("UPDATE consumers SET credentials = ? WHERE namespace = ? AND id = ?")
        .bind(ambiguous_credentials.to_string())
        .bind("ferrum")
        .bind("restore-dns-lower")
        .execute(&pool)
        .await
        .expect("Failed to inject the pre-existing DNS ambiguity");

    sqlx::query(
        "CREATE TRIGGER fail_restore_mtls_dns BEFORE INSERT ON proxies \
         WHEN NEW.id = 'restore-dns-fail' \
         BEGIN SELECT RAISE(FAIL, 'injected restore persistence failure'); END",
    )
    .execute(&pool)
    .await
    .expect("Failed to install mTLS DNS restore fault trigger");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-dns-fail",
            "listen_path": "/new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;
    assert_eq!(status, 500, "fault-injected restore unexpectedly succeeded");
    assert_eq!(
        body["rollback"].as_str(),
        Some("completed"),
        "raw ambiguous snapshot must remain rollback-capable: {body:?}"
    );

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id, credentials FROM consumers WHERE namespace = ? ORDER BY id")
            .bind("ferrum")
            .fetch_all(&pool)
            .await
            .expect("Failed to inspect replayed consumers");
    assert_eq!(rows.len(), 2);
    let restored_identities: Vec<String> = rows
        .iter()
        .map(|(_, credentials)| {
            serde_json::from_str::<Value>(credentials).unwrap()["mtls_auth"][0]["identity"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        restored_identities,
        vec!["api.example.com".to_string(), "API.Example.COM".to_string(),],
        "rollback must replay the exact prior credential casing"
    );
    let plugin_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM plugin_configs WHERE namespace = ? AND id = ?")
            .bind("ferrum")
            .bind("restore-dns-policy")
            .fetch_one(&pool)
            .await
            .expect("Failed to inspect replayed mTLS policy");
    assert_eq!(
        plugin_count, 1,
        "rollback must restore the active DNS policy"
    );
    let failed_proxy_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE namespace = ? AND id = ?")
            .bind("ferrum")
            .bind("restore-dns-fail")
            .fetch_one(&pool)
            .await
            .expect("Failed to inspect partial restore cleanup");
    assert_eq!(failed_proxy_count, 0);
}

/// Restore must remain usable to REPAIR a namespace whose existing config is
/// already invalid/unloadable. The rollback snapshot is taken with a
/// NON-VALIDATING raw load (`load_namespace_snapshot`), so an invalid-but-present
/// config (here: a corrupt regex listen_path that the VALIDATING
/// `load_full_config` would reject) still snapshots successfully — the repair
/// proceeds AND rollback stays available. The restore succeeds, so rollback is
/// not exercised here; the point is that stricter `load_full_config` validation
/// no longer suppresses the snapshot. Contrast with
/// `test_restore_aborts_when_snapshot_cannot_be_loaded`, where a genuine DB
/// failure (not invalid content) aborts the restore.
#[tokio::test]
async fn test_restore_repairs_namespace_with_unloadable_prior_config() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_repair.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [{
            "id": "restore-corrupt",
            "listen_path": "/keep",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);

    // Corrupt the existing config directly so the VALIDATING `load_full_config`
    // would reject it: an unbalanced character class is an invalid regex
    // listen_path, which that loader treats as fatal. The rollback snapshot now
    // uses the NON-VALIDATING `load_namespace_snapshot`, which tolerates this and
    // still captures the prior rows. Admin validation would never accept this, so
    // we inject it below the API.
    sqlx::query("UPDATE proxies SET listen_path = '~[unclosed' WHERE id = 'restore-corrupt'")
        .execute(&pool)
        .await
        .expect("Failed to corrupt existing proxy listen_path");

    // A valid replacement payload — restore should repair the namespace.
    let restore_payload = json!({
        "proxies": [{
            "id": "restore-repaired",
            "listen_path": "/repaired",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(
        status, 200,
        "restore must repair a namespace whose prior config could not be snapshotted: {:?}",
        body
    );

    // The corrupt proxy is gone and the repaired proxy is present.
    let (status, _, _) = admin_get(&base_url, "/proxies/restore-corrupt", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "the unloadable prior proxy must be replaced"
    );
    let (status, _, _) = admin_get(&base_url, "/proxies/restore-repaired", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the restored proxy must be present after a repair restore"
    );
}

/// A restore MUST NOT delete the prior config when it cannot even snapshot it
/// for rollback due to a genuine database failure (as opposed to an
/// invalid-but-present config, which still snapshots — see
/// `test_restore_repairs_namespace_with_unloadable_prior_config`). Here we
/// simulate a transient DB outage by closing the pool before restore runs: the
/// snapshot load fails, so the restore aborts with `503` and never issues the
/// destructive delete. The prior config survives intact.
#[tokio::test]
async fn test_restore_aborts_when_snapshot_cannot_be_loaded() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_snapshot_fail.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [{
            "id": "restore-survivor",
            "listen_path": "/survivor",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);

    // Simulate a transient database outage: close the shared pool so every
    // subsequent query — including the rollback snapshot load — fails. This is a
    // genuine connectivity failure, NOT an invalid-but-present config.
    pool.close().await;

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-should-not-apply",
            "listen_path": "/nope",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(
        status, 503,
        "restore must abort with 503 when the prior config cannot be snapshotted: {:?}",
        body
    );
    assert_eq!(body["failure_class"].as_str(), Some("connectivity"));
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT be deleted")
            || body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("NOT deleted"),
        "abort error must state the existing config was not deleted: {:?}",
        body
    );

    // Verify via a FRESH connection to the same SQLite file that the prior config
    // was NOT wiped — the destructive delete must never have run.
    let verify_db =
        DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
            .expect("Failed to reconnect for verification");
    let survivor = verify_db
        .get_proxy("ferrum", "restore-survivor")
        .await
        .expect("verification query failed");
    assert!(
        survivor.is_some(),
        "the prior proxy must survive an aborted restore (no delete ran)"
    );
    let should_not_exist = verify_db
        .get_proxy("ferrum", "restore-should-not-apply")
        .await
        .expect("verification query failed");
    assert!(
        should_not_exist.is_none(),
        "the restore payload must NOT have been applied when the restore aborted"
    );
}

/// A persisted row that cannot be decoded is a data-integrity failure, not a
/// transient database outage. Restore still fails closed before delete, but
/// operators receive a distinct status/class and the safe resource identity.
#[tokio::test]
async fn test_restore_surfaces_corrupt_snapshot_row_as_data_integrity() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_snapshot_corrupt.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [{
            "id": "restore-corrupt-row",
            "listen_path": "/survivor",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);
    sqlx::query("UPDATE proxies SET hosts = 'not-json' WHERE id = 'restore-corrupt-row'")
        .execute(&pool)
        .await
        .expect("Failed to corrupt proxy row");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-should-not-apply",
            "listen_path": "/replacement",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 500, "corrupt snapshot response: {:?}", body);
    assert_eq!(body["failure_class"].as_str(), Some("data_integrity"));
    let surfaced = body["restore_errors"][0].as_str().unwrap_or_default();
    assert!(surfaced.contains("proxy") && surfaced.contains("restore-corrupt-row"));

    let corrupt_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE id = 'restore-corrupt-row'")
            .fetch_one(&pool)
            .await
            .expect("Failed to verify retained corrupt row");
    let replacement_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE id = 'restore-should-not-apply'")
            .fetch_one(&pool)
            .await
            .expect("Failed to verify replacement absence");
    assert_eq!(
        corrupt_count, 1,
        "snapshot failure must not delete prior rows"
    );
    assert_eq!(replacement_count, 0, "restore import must not start");
}

/// `api_specs` are admin-only metadata outside `GatewayConfig`, so a config
/// rollback cannot restore them. A failed restore that rolls back must surface
/// how many specs the operator has to re-submit rather than silently dropping
/// them.
#[tokio::test]
async fn test_restore_reports_api_specs_not_restored_on_rollback() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_apispec.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();

    // Seed a proxy + its owning api_spec directly through the backend so the
    // namespace carries admin-only metadata before the restore.
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "spec-proxy",
        "namespace": "ferrum",
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": "/spec-proxy"
    }))
    .expect("proxy deserialization failed");
    let bundle = ferrum_edge::ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let content = b"minimal owned spec";
    let spec = ferrum_edge::config::types::ApiSpec {
        id: "spec-1".to_string(),
        namespace: "ferrum".to_string(),
        proxy_id: "spec-proxy".to_string(),
        spec_version: "3.1.0".to_string(),
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(content)
            .expect("compress failed"),
        content_encoding: "gzip".to_string(),
        uncompressed_size: content.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(content),
        title: Some("Test API".to_string()),
        info_version: Some("1.0.0".to_string()),
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    db.submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("Failed to seed api_spec bundle");

    // Corrupt summary metadata that the item-listing path must deserialize.
    // Restore only needs the authoritative count, so this admin-only row must
    // not block the raw config snapshot or the repair operation.
    sqlx::query("UPDATE api_specs SET spec_format = 'corrupt' WHERE id = 'spec-1'")
        .execute(&pool)
        .await
        .expect("Failed to corrupt api_spec summary metadata");

    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Force the import phase to fail so the restore rolls back.
    sqlx::query(
        "CREATE TRIGGER fail_restore_apispec BEFORE INSERT ON proxies \
         WHEN NEW.id = 'restore-fail' \
         BEGIN SELECT RAISE(FAIL, 'injected restore persistence failure'); END",
    )
    .execute(&pool)
    .await
    .expect("Failed to install restore fault-injection trigger");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-fail",
            "listen_path": "/new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 500, "Failed restore response: {:?}", body);
    assert_eq!(
        body["rollback"].as_str(),
        Some("completed"),
        "config rollback should complete: {:?}",
        body
    );
    assert_eq!(
        body["api_specs_not_restored"].as_u64(),
        Some(1),
        "restore must report the api_specs it could not restore: {:?}",
        body
    );
    assert!(body.get("api_specs_lost").is_none());
    let note = body["api_specs_note"].as_str().unwrap_or_default();
    assert!(
        note.contains("POST /api-specs") && note.contains("GET /api-specs"),
        "restore must give a usable re-submit and current-list recovery path: {:?}",
        body
    );

    // The config resource itself was restored by rollback.
    let (status, _, _) = admin_get(&base_url, "/proxies/spec-proxy", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the spec-owned proxy must survive rollback as a plain resource"
    );
}

/// A rollback response reports the authoritative API spec count even when the
/// namespace contains more rows than the normal list page size.
#[tokio::test]
async fn test_restore_reports_authoritative_api_spec_count_beyond_page_size() {
    let total_specs = 501;

    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_apispec_trunc.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();

    // Seed enough specs (and their owning proxies) to exceed the normal list
    // page size. Bundles go straight through the backend.
    for i in 0..total_specs {
        let proxy: Proxy = serde_json::from_value(json!({
            "id": format!("spec-proxy-{i}"),
            "namespace": "ferrum",
            "backend_host": "backend.example.com",
            "backend_port": 443,
            "listen_path": format!("/spec-{i}")
        }))
        .expect("proxy deserialization failed");
        let bundle = ferrum_edge::ExtractedBundle {
            proxy,
            upstream: None,
            plugins: vec![],
        };
        let content = format!("minimal owned spec {i}");
        let content_bytes = content.as_bytes();
        let spec = ferrum_edge::config::types::ApiSpec {
            id: format!("spec-{i}"),
            namespace: "ferrum".to_string(),
            proxy_id: format!("spec-proxy-{i}"),
            spec_version: "3.1.0".to_string(),
            spec_format: ferrum_edge::config::types::SpecFormat::Json,
            spec_content: ferrum_edge::admin::spec_codec::compress_gzip(content_bytes)
                .expect("compress failed"),
            content_encoding: "gzip".to_string(),
            uncompressed_size: content_bytes.len() as u64,
            content_hash: ferrum_edge::admin::spec_codec::sha256_hex(content_bytes),
            title: Some(format!("Test API {i}")),
            info_version: Some("1.0.0".to_string()),
            description: None,
            contact_name: None,
            contact_email: None,
            license_name: None,
            license_identifier: None,
            tags: vec![],
            server_urls: vec![],
            operation_count: 0,
            resource_hash: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        db.submit_api_spec_bundle(&bundle, &spec)
            .await
            .expect("Failed to seed api_spec bundle");
    }

    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Force the import phase to fail so the restore rolls back and the api_specs
    // recovery report is produced.
    sqlx::query(
        "CREATE TRIGGER fail_restore_apispec_trunc BEFORE INSERT ON proxies \
         WHEN NEW.id = 'restore-fail' \
         BEGIN SELECT RAISE(FAIL, 'injected restore persistence failure'); END",
    )
    .execute(&pool)
    .await
    .expect("Failed to install restore fault-injection trigger");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-fail",
            "listen_path": "/new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 500, "Failed restore response: {:?}", body);
    assert_eq!(
        body["rollback"].as_str(),
        Some("completed"),
        "config rollback should complete: {:?}",
        body
    );
    // The authoritative total is reported without paginating identities.
    assert_eq!(
        body["api_specs_not_restored"].as_u64(),
        Some(total_specs as u64),
        "api_specs_not_restored must be the authoritative total: {:?}",
        body["api_specs_not_restored"]
    );
    assert!(body.get("api_specs_lost").is_none());
    let note = body["api_specs_note"].as_str().unwrap_or_default();
    assert!(note.contains("POST /api-specs") && note.contains("GET /api-specs"));
}

/// When `delete_all_resources` fails on an ATOMIC backend (SQL runs the clear in
/// one transaction), nothing was deleted, so the prior config is fully intact.
/// Restore must return `500` with `rollback: "not_needed"` and retain the prior
/// config WITHOUT invoking a second delete/import — a compensating re-clear would
/// be unnecessary and could delete `api_specs` or duplicate resources on a
/// transient error.
#[tokio::test]
async fn test_restore_atomic_delete_failure_retains_prior_config() {
    let tc = TestConfig::default();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_restore_delete_fail.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("Failed to connect to test database");
    let pool = db.pool();
    let state = db_admin_state(&tc, db, None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let seed = json!({
        "proxies": [{
            "id": "restore-keep",
            "listen_path": "/keep",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &seed).await;
    assert_eq!(status, 201, "Seed failed: {:?}", body);

    // Make the delete phase fail. On SQLite the clear is one transaction, so the
    // whole clear rolls back and the prior config is untouched.
    sqlx::query(
        "CREATE TRIGGER fail_restore_delete BEFORE DELETE ON proxies \
         WHEN OLD.id = 'restore-keep' \
         BEGIN SELECT RAISE(FAIL, 'injected delete failure'); END",
    )
    .execute(&pool)
    .await
    .expect("Failed to install delete fault-injection trigger");

    let restore_payload = json!({
        "proxies": [{
            "id": "restore-new",
            "listen_path": "/new",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 8080,
            "strip_listen_path": true
        }]
    });
    let (status, body) =
        admin_post(&base_url, "/restore?confirm=true", &token, &restore_payload).await;

    assert_eq!(status, 500, "Failed restore response: {:?}", body);
    // Atomic clear failure => no rollback attempted; prior config retained.
    assert_eq!(
        body["rollback"].as_str(),
        Some("not_needed"),
        "atomic delete failure must not trigger a rollback re-import: {:?}",
        body
    );
    // A second delete/import was NOT invoked, so there are no rollback errors.
    assert!(
        body["rollback_errors"].is_null(),
        "atomic delete failure must not run a compensating clear (no rollback_errors): {:?}",
        body
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("prior config was retained"),
        "response must confirm the prior config was retained: {:?}",
        body
    );

    // The prior proxy survived because the delete transaction rolled back.
    let (status, _, _) = admin_get(&base_url, "/proxies/restore-keep", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the prior proxy must survive a failed atomic delete"
    );
    // The restore payload's proxy must NOT have been imported — the import phase
    // never ran because the clear failed and returned early.
    let (status, _, _) = admin_get(&base_url, "/proxies/restore-new", &token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "no import must occur when the atomic clear fails"
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
// Config-Validation Rejection Classification (issue #2158)
// ============================================================================

#[tokio::test]
async fn test_config_rejection_keeps_admin_writable_and_marks_health_degraded() {
    // A reachable backend that serves a validation-rejected snapshot must NOT
    // lock the admin API read-only: db_available stays true and admin writes
    // are the in-band repair path. The condition surfaces on authenticated
    // /health as config_rejected + degraded, and clears on the next good load.
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(true));
    let cfg_rejected = Arc::new(AtomicBool::new(true));
    let (mut state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    state.config_rejected = Some(cfg_rejected.clone());
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // (a) Admin write succeeds despite the standing validation rejection.
    let proxy = json!({
        "listen_path": "/repair-2158",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert!(
        (200..300).contains(&status),
        "config_rejected must not lock admin read-only (got {status}): {body:?}"
    );

    // Authenticated /health detail surfaces the degraded status + flag.
    let (health_status, health, _) = admin_get(&base_url, "/health", &token).await;
    assert_eq!(health_status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["config_rejected"], true);
    assert_eq!(health["admin_writes_enabled"], true);

    // Tiering: the boolean detail must NOT leak to unauthenticated probes.
    let client = reqwest::Client::new();
    let unauth: Value = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        unauth.get("config_rejected").is_none(),
        "config_rejected detail must be authenticated-only: {unauth:?}"
    );

    // (c) Lifecycle: an accepted load clears the flag and drops the detail.
    cfg_rejected.store(false, Ordering::Relaxed);
    let (_, health2, _) = admin_get(&base_url, "/health", &token).await;
    assert!(
        health2.get("config_rejected").is_none(),
        "config_rejected must clear once the rejection resolves: {health2:?}"
    );
    assert_eq!(health2["admin_writes_enabled"], true);
}

#[tokio::test]
async fn test_connectivity_failure_still_blocks_admin_writes_2158() {
    // Contrast with the validation-rejection case: a genuine connectivity
    // outage (db_available=false, no validation rejection) must still flip the
    // admin API read-only, preserving the fail-closed behavior.
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false));
    let (state, _dir) = create_db_admin_state_with_availability(&tc, Some(db_flag)).await;
    // config_rejected stays None — this is an outage, not a validation rejection.
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "listen_path": "/outage-2158",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080,
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(
        status, 503,
        "connectivity failure must still block admin writes: {body:?}"
    );
}

#[tokio::test]
async fn test_config_rejected_detail_suppressed_during_connectivity_outage_2158() {
    // Finding 3 (issue #2158): the stored config_rejected flag is deliberately
    // sticky and clears only on an accepted authoritative full reload. But once a
    // later connectivity outage sets db_available=false, admin writes are blocked
    // (admin_writes_enabled=false), so the writable in-band repair path that
    // config_rejected advertises no longer exists. The authenticated /health
    // detail must therefore SUPPRESS config_rejected while db_available=false —
    // keeping the two authenticated details mutually honest — without clearing
    // the sticky stored flag.
    let tc = TestConfig::default();
    let db_flag = Arc::new(AtomicBool::new(false)); // connectivity outage
    let cfg_rejected = Arc::new(AtomicBool::new(true)); // sticky prior rejection
    let (mut state, _dir) =
        create_db_admin_state_with_availability(&tc, Some(db_flag.clone())).await;
    state.config_rejected = Some(cfg_rejected.clone());
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (health_status, health, _) = admin_get(&base_url, "/health", &token).await;
    assert_eq!(health_status, reqwest::StatusCode::OK);
    assert_eq!(
        health["admin_writes_enabled"], false,
        "a connectivity outage must block admin writes: {health:?}"
    );
    assert!(
        health.get("config_rejected").is_none(),
        "config_rejected detail must be suppressed while db_available=false: {health:?}"
    );

    // The stored flag is only suppressed, not cleared: once the backend is
    // reachable again the detail re-appears (writes are back, repair path valid).
    db_flag.store(true, Ordering::Relaxed);
    let (_, health2, _) = admin_get(&base_url, "/health", &token).await;
    assert_eq!(health2["admin_writes_enabled"], true);
    assert_eq!(
        health2["config_rejected"], true,
        "the sticky rejection detail must re-surface once the backend is reachable: {health2:?}"
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
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(
            create_test_gateway_config_with_upstreams(),
        )))),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: Some(cached.clone()),
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
async fn test_consumer_put_preserves_basic_credentials_omitted_from_get_response() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let password_hash = format!("hmac_sha256:{}", "a".repeat(64));

    let consumer = json!({
        "id": "basic-roundtrip-consumer",
        "username": "basic_roundtrip_user",
        "credentials": {
            "basicauth": [{"password_hash": password_hash.clone()}]
        }
    });
    let (status, body) = admin_post(&base_url, "/consumers", &token, &consumer).await;
    assert_eq!(status, 201, "Create consumer failed: {:?}", body);

    let (status, mut roundtrip, _) =
        admin_get(&base_url, "/consumers/basic-roundtrip-consumer", &token).await;
    assert_eq!(status, 200);
    assert!(roundtrip["credentials"].get("basicauth").is_none());

    roundtrip["custom_id"] = json!("basic-roundtrip-custom-id");
    let (status, body) = admin_put(
        &base_url,
        "/consumers/basic-roundtrip-consumer",
        &token,
        &roundtrip,
    )
    .await;
    assert_eq!(status, 200, "Round-trip update failed: {:?}", body);

    let (status, backup, _) = admin_get(&base_url, "/backup?resources=consumers", &token).await;
    assert_eq!(status, 200);
    let stored = backup["consumers"]
        .as_array()
        .expect("backup consumers array")
        .iter()
        .find(|consumer| consumer["id"] == "basic-roundtrip-consumer")
        .expect("updated consumer in backup");
    assert_eq!(
        stored["credentials"]["basicauth"][0]["password_hash"].as_str(),
        Some(password_hash.as_str())
    );
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

#[tokio::test]
async fn tcp_connection_throttle_admin_rejects_udp_attachment_before_persistence() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let proxy = json!({
        "id": "udp-throttle-admin-proxy",
        "backend_scheme": "udp",
        "backend_host": "localhost",
        "backend_port": 5353,
        "listen_port": 19011
    });
    let (status, body) = admin_post(&base_url, "/proxies", &token, &proxy).await;
    assert_eq!(status, 201, "Create UDP proxy failed: {body:?}");

    // A scoped definition is dormant until the proxy association exists.
    let plugin = json!({
        "id": "udp-throttle-admin-plugin",
        "plugin_name": "tcp_connection_throttle",
        "scope": "proxy",
        "proxy_id": "udp-throttle-admin-proxy",
        "enabled": true,
        "config": {"max_connections_per_key": 1}
    });
    let (status, body) = admin_post(&base_url, "/plugins/config", &token, &plugin).await;
    assert_eq!(status, 201, "Create dormant throttle failed: {body:?}");

    let attached = json!({
        "id": "udp-throttle-admin-proxy",
        "backend_scheme": "udp",
        "backend_host": "localhost",
        "backend_port": 5353,
        "listen_port": 19011,
        "plugins": [{"plugin_config_id": "udp-throttle-admin-plugin"}]
    });
    let (status, body) = admin_put(
        &base_url,
        "/proxies/udp-throttle-admin-proxy",
        &token,
        &attached,
    )
    .await;
    assert_eq!(
        status, 400,
        "UDP throttle attachment was persisted: {body:?}"
    );
    assert!(body.to_string().contains("only TCP/TCP+TLS is supported"));

    let (status, persisted, _) =
        admin_get(&base_url, "/proxies/udp-throttle-admin-proxy", &token).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(
        persisted["plugins"]
            .as_array()
            .is_some_and(|plugins| plugins.is_empty()),
        "rejected attachment changed the persisted proxy: {persisted:?}"
    );
}

#[tokio::test]
async fn tcp_connection_throttle_batch_rejects_udp_attachment() {
    let tc = TestConfig::default();
    let (state, _dir) = create_db_admin_state(&tc).await;
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let batch = json!({
        "proxies": [{
            "id": "udp-throttle-batch-proxy",
            "backend_scheme": "udp",
            "backend_host": "localhost",
            "backend_port": 5354,
            "listen_port": 19012,
            "plugins": [{"plugin_config_id": "udp-throttle-batch-plugin"}]
        }],
        "plugin_configs": [{
            "id": "udp-throttle-batch-plugin",
            "plugin_name": "tcp_connection_throttle",
            "scope": "proxy",
            "proxy_id": "udp-throttle-batch-proxy",
            "enabled": true,
            "config": {"max_connections_per_key": 1}
        }]
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(status, 400, "UDP throttle batch was persisted: {body:?}");
    assert!(body.to_string().contains("only TCP/TCP+TLS is supported"));
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
        metrics_auth: Default::default(),
        cached_config: Some(cached),
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: Some(db_flag.clone()),
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_test_admin(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", base_url))
        .header(
            "authorization",
            format!("Bearer {}", generate_test_token(&tc)),
        )
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: Some(registry),
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: Some(registry),
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: Some(registry),
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "dp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(conn_state),
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "dp".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: Some(conn_state),
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: std::sync::Arc::new(
            ferrum_edge::proxy::client_ip::TrustedProxies::none(),
        ),
        cached_db_health: std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(None))),
        db_health_refresh: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/cluster", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body["mode"], "database");
    assert!(body["message"].is_string());
}

// ---- Pagination is validated before the shared request-body read ----

fn generate_test_token_with_role(config: &TestConfig, role: &str) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

/// Send a request carrying `body_len` bytes, past the admin 1 MiB body cap.
async fn admin_request_with_body(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    token: Option<&str>,
    body_len: usize,
) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, format!("{}{}", base_url, path))
        .body(vec![b'x'; body_len]);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {}", token));
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!(null));
    (status, body)
}

const OVERSIZED_BODY: usize = 2 * 1024 * 1024;

/// A paginated GET must resolve `limit`/`offset` from the request line before
/// the shared `Limited::collect` body read. Otherwise an oversized (and wholly
/// unused) GET body turns the documented malformed-pagination `400` into a
/// `413`, after buffering up to the cap on a read endpoint.
#[tokio::test]
async fn malformed_pagination_on_get_list_precedes_body_buffering() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    for path in [
        "/proxies?limit=abc",
        "/consumers?offset=-1",
        "/plugins/config?limit=1.5",
        "/upstreams?offset=18446744073709551616",
    ] {
        let (status, body) = admin_request_with_body(
            reqwest::Method::GET,
            &base_url,
            path,
            Some(&token),
            OVERSIZED_BODY,
        )
        .await;
        assert_eq!(
            status, 400,
            "{path} must return the pagination 400 without buffering the body: {body:?}"
        );
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("must be")
                || body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("maximum supported value"),
            "{path} must report the pagination error, not a body error: {body:?}"
        );
    }

    // Well-formed pagination on the same route still succeeds; only the
    // malformed case short-circuits ahead of the body read.
    let (status, body, _) = admin_get(&base_url, "/proxies?limit=2", &token).await;
    assert_eq!(status, 200, "valid pagination unaffected: {body:?}");
    assert_eq!(body["data"].as_array().unwrap().len(), 2);

    // Body handling for mutation routes is unchanged: an oversized POST body is
    // still rejected with 413 by the shared reader.
    let (status, body) = admin_request_with_body(
        reqwest::Method::POST,
        &base_url,
        "/proxies?limit=abc",
        Some(&token),
        OVERSIZED_BODY,
    )
    .await;
    assert_eq!(
        status, 413,
        "mutation routes keep the shared body cap: {body:?}"
    );
}

/// `/audit` narrows the shared `i64` offset to the audit store's `u32`. That
/// route-specific ceiling has to be replayed in the pre-body gate too, or an
/// offset the handler would reject with `400` instead buffers an unused body
/// and returns `413`.
#[tokio::test]
async fn audit_offset_ceiling_precedes_body_buffering() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // u32::MAX + 1: inside the shared parser's range, outside the audit store's.
    let (status, body) = admin_request_with_body(
        reqwest::Method::GET,
        &base_url,
        "/audit?offset=4294967296",
        Some(&token),
        OVERSIZED_BODY,
    )
    .await;
    assert_eq!(
        status, 400,
        "audit offset ceiling must precede the body read: {body:?}"
    );
    assert_eq!(
        body["error"], "Audit offset exceeds supported range",
        "pre-body rejection must reuse the handler's message: {body:?}"
    );

    // Without a body the same request reports the identical error, so the two
    // paths through `audit_pagination_offset` cannot diverge.
    let (status, body, _) = admin_get(&base_url, "/audit?offset=4294967296", &token).await;
    assert_eq!(status, 400, "no-body audit offset: {body:?}");
    assert_eq!(body["error"], "Audit offset exceeds supported range");

    // The bound is exact: `u32::MAX` is still accepted, so the oversized body
    // reaches the shared reader and its `413` — proving the `400` above came
    // from the ceiling, not from a blanket rejection of the route.
    let (status, body) = admin_request_with_body(
        reqwest::Method::GET,
        &base_url,
        "/audit?offset=4294967295",
        Some(&token),
        OVERSIZED_BODY,
    )
    .await;
    assert_eq!(
        status, 413,
        "u32::MAX offset is in range and must not be pre-rejected: {body:?}"
    );

    // Unrelated list routes keep the wider `i64` contract: the same offset is a
    // valid request beyond the collection, not a `400`.
    let (status, body, _) = admin_get(&base_url, "/proxies?offset=4294967296", &token).await;
    assert_eq!(
        status, 200,
        "the audit ceiling must not narrow other routes: {body:?}"
    );
    assert!(
        body["data"].as_array().unwrap().is_empty(),
        "offset beyond the collection returns an empty page: {body:?}"
    );
}

/// The pre-body pagination gate must not reorder the security checks ahead of
/// it: an unauthenticated caller still gets `401` and an under-privileged one
/// still gets `403`, even when the pagination is malformed.
#[tokio::test]
async fn pre_body_pagination_never_preempts_authentication_or_rbac() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let viewer = generate_test_token_with_role(&tc, "viewer");

    // No credentials at all -> 401, never the pagination 400.
    let (status, body) = admin_request_with_body(
        reqwest::Method::GET,
        &base_url,
        "/proxies?limit=abc",
        None,
        OVERSIZED_BODY,
    )
    .await;
    assert_eq!(
        status, 401,
        "unauthenticated malformed pagination must stay 401: {body:?}"
    );

    // Authenticated but under-privileged on routes whose arm gates on a role
    // before parsing pagination -> 403, never the pagination 400.
    for path in [
        "/audit?limit=abc",
        "/admin/tls/inventory?limit=abc",
        "/admin/tls/certificates?offset=-1",
    ] {
        let (status, body) = admin_request_with_body(
            reqwest::Method::GET,
            &base_url,
            path,
            Some(&viewer),
            OVERSIZED_BODY,
        )
        .await;
        assert_eq!(
            status, 403,
            "{path} must return 403 before pagination validation: {body:?}"
        );
    }

    // `/live` stays unauthenticated and minimal regardless of query garbage.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/live?limit=abc", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({"status": "ok"}));
}
