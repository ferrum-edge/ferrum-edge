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
