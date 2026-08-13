//! Admin Upstream/Proxy reverse-write admission for plain-HTTPS backend-TLS-SNI
//! destinations when an effective request-body-buffering plugin is already
//! persisted in the DB.
//!
//! An SNI override no longer requires the direct-H2 pool: the reqwest HTTP/1.1
//! dial carries the server name in the URL authority with the real target
//! pinned on the resolver, so a buffering (or retrying, or `pool_enable_http2:
//! false`) association beside an SNI override is a representable configuration
//! and must be **admitted**. These tests pin that the reverse-write gate stays
//! removed — including with a missing or deliberately stale `cached_config`,
//! which is where a resurrected screener would take its plugin view from.
//! Genuinely unrepresentable dials still fail closed at runtime (the `502`
//! `backend_tls_sni_requires_direct_h2`), not at admission.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::GatewayConfig;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-upstream-proxy-sni-admission".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn make_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn make_token(config: &TestConfig) -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .unwrap()
}

fn stale_empty_cached_config() -> Option<Arc<ArcSwap<GatewayConfig>>> {
    // Deliberately empty plugin list: the cache a resurrected SNI screener
    // would read from disagrees with the DB-persisted buffering plugin, so a
    // write admitted here is admitted on policy rather than on a cache miss.
    Some(Arc::new(ArcSwap::from_pointee(GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    })))
}

async fn build_admin_state(
    tc: &TestConfig,
    cached_config: Option<Arc<ArcSwap<GatewayConfig>>>,
) -> (AdminState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("upstream_proxy_sni_admission.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("DB connect must succeed");

    let state = AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: make_jwt_manager(tc),
        metrics_auth: Default::default(),
        cached_config,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: None,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    };
    (state, tmp)
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
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
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin server at {} never became ready", actual);
}

async fn admin_post(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

async fn admin_put(base_url: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

fn err_string(body: &Value) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn plain_upstream(id: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
        "algorithm": "round_robin",
    })
}

fn sni_upstream(id: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "targets": [{"host": "backend.mesh.internal", "port": 443, "weight": 100}],
        "algorithm": "round_robin",
        "backend_tls_sni": "backend.mesh.internal",
    })
}

fn https_proxy_with_plugins(id: &str, upstream_id: &str, plugin_ids: &[&str]) -> Value {
    json!({
        "id": id,
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": 8443,
        "strip_listen_path": true,
        "upstream_id": upstream_id,
        "plugins": plugin_ids
            .iter()
            .map(|plugin_id| json!({ "plugin_config_id": plugin_id }))
            .collect::<Vec<_>>(),
    })
}

/// A write that combines an SNI override with an effective request-body
/// buffering association must be admitted, and must not be refused with the
/// retired direct-H2 diagnostic.
fn assert_sni_buffering_admitted(status: u16, body: &Value) {
    let err = err_string(body);
    assert!(
        !err.contains("backend TLS SNI"),
        "the retired direct-H2 SNI admission gate must not reject this write: {err}"
    );
    assert_eq!(
        status, 200,
        "SNI + buffering is representable on the HTTP/1.1 dial: {body:?}"
    );
}

async fn seed_plain_upstream_with_associated_buffering(
    base_url: &str,
    token: &str,
    upstream_id: &str,
    proxy_id: &str,
    plugin_id: &str,
) {
    let (status, body) =
        admin_post(base_url, "/upstreams", token, &plain_upstream(upstream_id)).await;
    assert_eq!(status, 201, "plain upstream seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins(proxy_id, upstream_id, &[plugin_id])
        ],
        "plugin_configs": [{
            "id": plugin_id,
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(base_url, "/batch", token, &batch).await;
    assert_eq!(
        status, 201,
        "proxy + buffering plugin seed failed: {body:?}"
    );
}

#[tokio::test]
async fn upstream_write_admits_sni_when_associated_buffering_and_cached_config_none() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, None).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_upstream_with_associated_buffering(
        &base_url,
        &token,
        "plain-up",
        "p-sni",
        "grpc-web-1",
    )
    .await;

    let (status, body) = admin_put(
        &base_url,
        "/upstreams/plain-up",
        &token,
        &sni_upstream("plain-up"),
    )
    .await;
    assert_sni_buffering_admitted(status, &body);
}

#[tokio::test]
async fn upstream_write_admits_sni_when_associated_buffering_and_cached_config_stale() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, stale_empty_cached_config()).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_upstream_with_associated_buffering(
        &base_url,
        &token,
        "plain-up",
        "p-sni",
        "grpc-web-1",
    )
    .await;

    let (status, body) = admin_put(
        &base_url,
        "/upstreams/plain-up",
        &token,
        &sni_upstream("plain-up"),
    )
    .await;
    assert_sni_buffering_admitted(status, &body);
}

#[tokio::test]
async fn proxy_write_admits_sni_upstream_when_associated_buffering_and_cached_config_none() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, None).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Proxy-scoped plugin configs require the proxy to exist first, so seed the
    // buffering association against a plain upstream, then retarget onto SNI.
    seed_plain_upstream_with_associated_buffering(
        &base_url,
        &token,
        "plain-up",
        "p-sni",
        "grpc-web-1",
    )
    .await;

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(status, 201, "SNI upstream seed failed: {body:?}");

    let (status, body) = admin_put(
        &base_url,
        "/proxies/p-sni",
        &token,
        &https_proxy_with_plugins("p-sni", "sni-up", &["grpc-web-1"]),
    )
    .await;
    assert_sni_buffering_admitted(status, &body);
}

#[tokio::test]
async fn proxy_write_admits_sni_upstream_when_associated_buffering_and_cached_config_stale() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, stale_empty_cached_config()).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    seed_plain_upstream_with_associated_buffering(
        &base_url,
        &token,
        "plain-up",
        "p-sni",
        "grpc-web-1",
    )
    .await;

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(status, 201, "SNI upstream seed failed: {body:?}");

    let (status, body) = admin_put(
        &base_url,
        "/proxies/p-sni",
        &token,
        &https_proxy_with_plugins("p-sni", "sni-up", &["grpc-web-1"]),
    )
    .await;
    assert_sni_buffering_admitted(status, &body);
}

#[tokio::test]
async fn upstream_write_admits_sni_when_associated_plugin_does_not_buffer() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, None).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) =
        admin_post(&base_url, "/upstreams", &token, &plain_upstream("plain-up")).await;
    assert_eq!(status, 201, "plain upstream seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["stdout-1"])
        ],
        "plugin_configs": [{
            "id": "stdout-1",
            "plugin_name": "stdout_logging",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "proxy + non-buffering plugin seed failed: {body:?}"
    );

    let (status, body) = admin_put(
        &base_url,
        "/upstreams/plain-up",
        &token,
        &sni_upstream("plain-up"),
    )
    .await;
    assert_eq!(
        status, 200,
        "non-buffering association must admit SNI upstream write: {body:?}"
    );
}

#[tokio::test]
async fn proxy_write_admits_sni_upstream_when_associated_plugin_does_not_buffer() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc, stale_empty_cached_config()).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) =
        admin_post(&base_url, "/upstreams", &token, &plain_upstream("plain-up")).await;
    assert_eq!(status, 201, "plain upstream seed failed: {body:?}");

    let batch = json!({
        "proxies": [
            https_proxy_with_plugins("p-sni", "plain-up", &["stdout-1"])
        ],
        "plugin_configs": [{
            "id": "stdout-1",
            "plugin_name": "stdout_logging",
            "scope": "proxy",
            "proxy_id": "p-sni",
            "enabled": true,
            "config": {},
        }],
    });
    let (status, body) = admin_post(&base_url, "/batch", &token, &batch).await;
    assert_eq!(
        status, 201,
        "proxy + non-buffering plugin seed failed: {body:?}"
    );

    let (status, body) = admin_post(&base_url, "/upstreams", &token, &sni_upstream("sni-up")).await;
    assert_eq!(status, 201, "SNI upstream seed failed: {body:?}");

    let (status, body) = admin_put(
        &base_url,
        "/proxies/p-sni",
        &token,
        &https_proxy_with_plugins("p-sni", "sni-up", &["stdout-1"]),
    )
    .await;
    assert_eq!(
        status, 200,
        "non-buffering association must admit SNI proxy write: {body:?}"
    );
}
