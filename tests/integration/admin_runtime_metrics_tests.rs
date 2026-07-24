//! Admin API runtime metrics endpoint.
//!
//! Verifies that `GET /metrics/runtime` is exposed only through the
//! standard admin JWT gate and returns the combined runtime JSON shape.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::runtime_metrics::{LogLevel, PoolKind};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-runtime-metrics-32chars".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn admin_state_with_runtime_metrics(jwt: JwtManager) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let env_config = EnvConfig {
        runtime_metrics_cache_ttl_ms: 0,
        status_counts_max_entries: 128,
        ..Default::default()
    };

    let dns_cache = DnsCache::new(DnsConfig::default());
    let (proxy_state, _health_check_handles) =
        ProxyState::new(cfg, dns_cache, env_config, None, None).expect("proxy state");

    proxy_state.request_count.store(2, Ordering::Relaxed);
    proxy_state.status_counts.insert(200, AtomicU64::new(2));
    proxy_state
        .windowed_metrics
        .requests_per_second
        .store(2, Ordering::Relaxed);
    proxy_state
        .windowed_metrics
        .status_codes_per_second
        .insert(200, AtomicU64::new(2));

    seed_runtime_counters();

    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "test".to_string(),
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
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
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

fn seed_runtime_counters() {
    let metrics = ferrum_edge::runtime_metrics::global();
    metrics.record_transaction(&TransactionSummary {
        proxy_id: Some("runtime-metrics-proxy".to_string()),
        response_status_code: 502,
        error_class: Some(ErrorClass::TlsError),
        ..TransactionSummary::default()
    });
    metrics.record_dns_hit();
    metrics.record_dns_miss();
    metrics.record_pool_handshake(PoolKind::HttpReqwest);
    metrics.record_log(LogLevel::Warn, "proxy");
}

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

async fn wait_for_admin_ready(addr: SocketAddr) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", addr);
}

async fn admin_request_unauth(base_url: &str) -> (reqwest::StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", base_url, "/metrics/runtime"))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn admin_request_with_token(base_url: &str, token: &str) -> (reqwest::StatusCode, Value) {
    admin_request_with_authorization(base_url, &format!("Bearer {}", token)).await
}

async fn admin_request_with_authorization(
    base_url: &str,
    authorization: &str,
) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", base_url, "/metrics/runtime"))
        .header("authorization", authorization)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn runtime_metrics_endpoint_accepts_case_insensitive_bearer_scheme() {
    let tc = TestConfig::default();
    let state = admin_state_with_runtime_metrics(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);
    let auth_header = format!("bearer {token}");

    let (status, body) = admin_request_with_authorization(&base_url, &auth_header).await;

    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert_eq!(body["mode"].as_str(), Some("test"));
}

#[tokio::test]
async fn runtime_metrics_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = admin_state_with_runtime_metrics(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let (status, body) = admin_request_unauth(&base_url).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 without bearer; body: {body}"
    );
}

#[tokio::test]
async fn runtime_metrics_endpoint_returns_seeded_json_shape() {
    let tc = TestConfig::default();
    let state = admin_state_with_runtime_metrics(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_request_with_token(&base_url, &token).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");

    assert_eq!(body["mode"].as_str(), Some("test"));
    assert!(body["timestamp"].as_str().is_some(), "timestamp: {body}");
    assert_eq!(body["http"]["total_requests"].as_u64(), Some(2));
    assert_eq!(
        body["http"]["status_codes"]["totals"]["200"].as_u64(),
        Some(2)
    );
    assert_eq!(body["http"]["requests_per_second_1s"].as_u64(), Some(2));

    assert!(
        body["errors"]["by_class"]["tls_error"]["http"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "seeded tls_error counter missing: {body}"
    );
    assert!(
        body["errors"]["by_proxy"]["runtime-metrics-proxy"]["tls_error"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "seeded proxy error counter missing: {body}"
    );
    assert!(
        body["dns"]["lookups_total"].as_u64().unwrap_or(0) >= 2,
        "seeded DNS counters missing: {body}"
    );
    assert!(
        body["connections"]["pool_handshakes_total"]["http_reqwest"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "seeded pool counter missing: {body}"
    );
    assert!(
        body["logs"]["by_level"]["warn"].as_u64().unwrap_or(0) >= 1,
        "seeded log counter missing: {body}"
    );
    assert!(body["logs"]["sinks"]["stdout"].is_null());
    assert!(body["logs"]["sinks"]["stderr"].is_null());
    assert_eq!(body["overload"]["level"].as_str(), Some("normal"));
}
