//! Admin API — Backend Capability Registry Endpoints
//!
//! Verifies that `GET /backend-capabilities` and
//! `POST /backend-capabilities/refresh` are permanently exposed under
//! the standard admin JWT auth — no env-var gate, no mode special-case.
//!
//! These endpoints serve operator-facing protocol-classification
//! introspection (see `docs/admin_api.md` and `openapi.yaml`). They run
//! against an in-process admin listener (no gateway binary) so the test
//! lives in the integration test suite, not the functional one.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::backend_capabilities::{
    BackendCapabilityRecord, ProtocolSupport, capability_key_for_proxy_target,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

/// JWT config for tests. The admin handlers are JWT-gated regardless of
/// any env flag, so this exercises the only auth path operators use.
#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api-32chars".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

/// Build an `AdminState` whose `proxy_state` has a `BackendCapabilityRegistry`
/// pre-populated with one classified entry the test can assert on.
fn admin_state_with_capability_registry(jwt: JwtManager) -> AdminState {
    // ProxyState owns the registry. Construct via the same path as
    // production; we don't need a real backend or DB.
    let cfg = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let dns_cache = DnsCache::new(DnsConfig::default());
    let proxy_state = ProxyState::new(cfg, dns_cache, env_config, None).expect("proxy state");

    // Seed one capability entry — h2_tls=Unsupported, h1=Supported (the
    // post-ALPN-downgrade shape). The exact key value isn't asserted by
    // the test; we only assert the entry's presence + classifications.
    let dummy_proxy = make_minimal_proxy("seed-proxy");
    let key = capability_key_for_proxy_target(&dummy_proxy, None);
    let mut record = BackendCapabilityRecord::default();
    record.plain_http.h1 = ProtocolSupport::Supported;
    record.plain_http.h2_tls = ProtocolSupport::Unsupported;
    record.plain_http.h3 = ProtocolSupport::Unknown;
    record.grpc_transport.h2_tls = ProtocolSupport::Unsupported;
    record.last_probe_error = Some("seeded by test".to_string());
    proxy_state.backend_capabilities.upsert(key, record);

    AdminState {
        db: None,
        jwt_manager: jwt,
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "test".to_string(),
        read_only: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        cp_connection_state: None,
    }
}

fn make_minimal_proxy(id: &str) -> ferrum_edge::config::types::Proxy {
    use ferrum_edge::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
    };
    let now = Utc::now();
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Https),
        dispatch_kind: DispatchKind::from(BackendScheme::Https),
        backend_host: "backend.test".to_string(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default_verify(),
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
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: now,
        updated_at: now,
    }
}

/// Spawn an admin listener on `127.0.0.1:0` and return its base URL.
///
/// The bind happens here; the pre-bound listener is moved into the spawned
/// task without ever being dropped. That removes the bind→drop→rebind race
/// where, under parallel test load, another process could grab the port
/// between `drop(listener)` and the listener task re-binding — turning
/// regression tests into connection-refused panics. Readiness is detected
/// by a TCP probe rather than a fixed sleep, so a slow startup also cannot
/// race the first request.
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
/// Replaces the previous fixed 50 ms sleep, which could fire before the
/// accept loop was ready under load. 200 attempts × 10 ms = 2 s budget,
/// well above any realistic in-process startup time.
async fn wait_for_admin_ready(addr: SocketAddr) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", addr);
}

async fn admin_request_unauth(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
) -> (reqwest::StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .request(method, format!("{}{}", base_url, path))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn admin_request_with_token(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    token: &str,
) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .request(method, format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn get_backend_capabilities_returns_401_without_token() {
    let tc = TestConfig::default();
    let state = admin_state_with_capability_registry(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let (status, body) =
        admin_request_unauth(reqwest::Method::GET, &base_url, "/backend-capabilities").await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 without bearer; body: {body}"
    );
}

#[tokio::test]
async fn post_backend_capabilities_refresh_returns_401_without_token() {
    let tc = TestConfig::default();
    let state = admin_state_with_capability_registry(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let (status, body) = admin_request_unauth(
        reqwest::Method::POST,
        &base_url,
        "/backend-capabilities/refresh",
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 without bearer; body: {body}"
    );
}

#[tokio::test]
async fn get_backend_capabilities_returns_200_with_valid_token_and_no_env_flag() {
    // Critical regression assertion: NO `FERRUM_EXPOSE_*` env var is set
    // anywhere in this test, yet the endpoint must respond 200. The
    // endpoint is permanently exposed under the standard admin JWT auth
    // path — verifying that here ensures a future refactor cannot
    // accidentally re-introduce a feature flag without breaking this test.
    let tc = TestConfig::default();
    let state = admin_state_with_capability_registry(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_request_with_token(
        reqwest::Method::GET,
        &base_url,
        "/backend-capabilities",
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");

    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "seeded one entry; body: {body}");

    let entry = &entries[0];
    assert!(entry["key"].is_string(), "entry missing key: {entry}");
    assert_eq!(entry["plain_http"]["h1"].as_str(), Some("supported"));
    assert_eq!(entry["plain_http"]["h2_tls"].as_str(), Some("unsupported"));
    assert_eq!(entry["plain_http"]["h3"].as_str(), Some("unknown"));
    assert_eq!(
        entry["grpc_transport"]["h2_tls"].as_str(),
        Some("unsupported")
    );
    assert_eq!(
        entry["last_probe_error"].as_str(),
        Some("seeded by test"),
        "last_probe_error should round-trip the seeded message"
    );
    assert!(
        entry["last_probe_at_unix_secs"].is_number(),
        "missing timestamp: {entry}"
    );
}

#[tokio::test]
async fn post_backend_capabilities_refresh_returns_200_with_valid_token() {
    let tc = TestConfig::default();
    let state = admin_state_with_capability_registry(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let token = generate_test_token(&tc);

    let (status, body) = admin_request_with_token(
        reqwest::Method::POST,
        &base_url,
        "/backend-capabilities/refresh",
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert_eq!(
        body["status"].as_str(),
        Some("refreshed"),
        "expected refresh acknowledgement; body: {body}"
    );
}

#[tokio::test]
async fn get_backend_capabilities_rejects_invalid_token() {
    let tc = TestConfig::default();
    let state = admin_state_with_capability_registry(create_test_jwt_manager(&tc));
    let (base_url, _shutdown) = start_test_admin(state).await;

    // Invalid token: signed with a different secret.
    let now = Utc::now();
    let claims = json!({
        "iss": tc.jwt_issuer,
        "sub": "attacker",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret("a-completely-different-secret".as_bytes());
    let bad_token = encode(&header, &claims, &key).unwrap();

    let (status, _body) = admin_request_with_token(
        reqwest::Method::GET,
        &base_url,
        "/backend-capabilities",
        &bad_token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}
