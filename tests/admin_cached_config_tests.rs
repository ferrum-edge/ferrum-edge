//! Admin API Cached Config Fallback Tests
//!
//! Tests that the admin API serves config from the in-memory cache when
//! the database is unavailable (resilience during data source outages).

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_gateway::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    start_admin_listener,
};
use ferrum_gateway::config::types::{
    AuthMode, BackendProtocol, Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

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
            jwt_issuer: "test-ferrum-gateway".to_string(),
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
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn create_test_proxy(id: &str, listen_path: &str, host: &str, port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("Test Proxy {}", id)),
        hosts: vec![],
        listen_path: listen_path.to_string(),
        backend_protocol: BackendProtocol::Http,
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
            username: "alice".to_string(),
            custom_id: Some("alice-custom".to_string()),
            credentials: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        plugin_configs: vec![PluginConfig {
            id: "plugin-cfg-1".to_string(),
            plugin_name: "rate_limiting".to_string(),
            config: json!({"rate": 100}),
            scope: PluginScope::Global,
            enabled: true,
            proxy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        upstreams: vec![],
        loaded_at: Utc::now(),
    }
}

/// Start an admin server with the given state on a random port, returns the base URL.
async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Bind to get the actual port
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    let state_clone = state.clone();
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = start_admin_listener(actual_addr, state_clone, shutdown_rx_clone).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (format!("http://{}", actual_addr), shutdown_tx)
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
        admin_restore_max_body_size_mib: 100,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/proxies", &token).await;

    assert_eq!(status, 200);
    let proxies = body.as_array().expect("Should return array of proxies");
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
        admin_restore_max_body_size_mib: 100,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/consumers", &token).await;

    assert_eq!(status, 200);
    let consumers = body.as_array().expect("Should return array of consumers");
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
        admin_restore_max_body_size_mib: 100,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, data_source) = admin_get(&base_url, "/plugins/config", &token).await;

    assert_eq!(status, 200);
    let plugins = body
        .as_array()
        .expect("Should return array of plugin configs");
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
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
        admin_restore_max_body_size_mib: 100,
    };
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    // Initial read: 2 proxies
    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 2);

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
        body.as_array().unwrap().len(),
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
            username: format!("user-{}", i),
            custom_id: None,
            credentials: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        plugin_configs.push(PluginConfig {
            id: format!("plugin-cfg-{}", i),
            plugin_name: "rate_limiting".to_string(),
            config: json!({"rate": 100}),
            scope: PluginScope::Global,
            enabled: true,
            proxy_id: None,
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
        admin_restore_max_body_size_mib: 100,
    }
}

#[tokio::test]
async fn test_list_proxies_without_pagination_returns_plain_array() {
    let tc = TestConfig::default();
    let state = create_pagination_admin_state(&tc);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body, _) = admin_get(&base_url, "/proxies", &token).await;
    assert_eq!(status, 200);
    // Without pagination params, should be a plain array
    assert!(
        body.is_array(),
        "Should return plain array without pagination params"
    );
    assert_eq!(body.as_array().unwrap().len(), 5);
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

use ferrum_gateway::config::db_loader::DatabaseStore;

async fn create_db_admin_state(tc: &TestConfig) -> (AdminState, tempfile::TempDir) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_batch.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db =
        DatabaseStore::connect_with_tls_config("sqlite", &db_url, false, None, None, None, false)
            .await
            .expect("Failed to connect to test database");
    let state = AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: create_test_jwt_manager(tc),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_restore_max_body_size_mib: 100,
    };
    (state, temp_dir)
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
            {"id": "p1", "listen_path": "/a", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true},
            {"id": "p2", "listen_path": "/b", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
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
            {"id": "bp1", "listen_path": "/bp1", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ]
    });
    let (status, _) = admin_post(&base_url, "/batch", &token, &proxy_batch).await;
    assert_eq!(status, 201);

    // Now batch create plugin configs
    let plugin_batch = json!({
        "plugin_configs": [
            {"id": "pc1", "plugin_name": "key_auth", "scope": "proxy", "proxy_id": "bp1", "enabled": true, "config": {"key_location": "header:X-API-Key"}},
            {"id": "pc2", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"rate": 100, "per": "second"}}
        ]
    });

    let (status, body) = admin_post(&base_url, "/batch", &token, &plugin_batch).await;
    assert_eq!(status, 201, "Batch plugin create failed: {:?}", body);
    assert_eq!(body["created"]["plugin_configs"], 2);
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
        admin_restore_max_body_size_mib: 100,
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
            {"id": "bp1", "listen_path": "/backup1", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true, "upstream_id": "bu1"}
        ],
        "plugin_configs": [
            {"id": "bpc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"rate": 100, "per": "second"}}
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
            {"id": "fp1", "listen_path": "/filter", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ],
        "plugin_configs": [
            {"id": "fpc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"rate": 100, "per": "second"}}
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
            {"id": "old_p1", "listen_path": "/old", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
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
            {"id": "new_p1", "listen_path": "/new1", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true},
            {"id": "new_p2", "listen_path": "/new2", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
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
            {"id": "rt_p1", "listen_path": "/roundtrip", "backend_protocol": "http", "backend_host": "localhost", "backend_port": 8080, "strip_listen_path": true}
        ],
        "plugin_configs": [
            {"id": "rt_pc1", "plugin_name": "rate_limiting", "scope": "global", "enabled": true, "config": {"rate": 50, "per": "second"}}
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
async fn test_restore_read_only_rejected() {
    let tc = TestConfig::default();
    let state = AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(&tc),
        cached_config: None,
        proxy_state: None,
        mode: "test".to_string(),
        read_only: true,
        admin_restore_max_body_size_mib: 100,
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
                "backend_protocol": "http",
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
                    "basicauth": {
                        "username": "hash_user",
                        "password": "my_secret_password"
                    }
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
    let creds = &consumer_body["credentials"]["basicauth"];
    // The API redacts password_hash, but the plaintext "password" key should NOT be present
    assert!(
        creds.get("password").is_none() || creds["password"].is_null(),
        "Plaintext password should be removed after hashing, got: {:?}",
        creds
    );
}
