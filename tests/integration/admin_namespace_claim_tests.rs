//! Per-namespace admin tenancy enforcement (issue #2120, option B).
//!
//! When `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`
//! (`AdminState.admin_require_namespace_claim`), namespace-scoped admin routes
//! require the admin JWT to carry an `ns` claim (single string or array of
//! strings — the same shapes as the CP↔DP gRPC plane) authorizing the
//! `X-Ferrum-Namespace` value. Global admin surfaces stay unaffected, and the
//! flag-off default preserves pre-existing behavior (namespace header is a
//! routing selector only).

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

const JWT_SECRET: &str = "namespace-claim-test-secret-key-0000000000";
const JWT_ISSUER: &str = "ferrum-edge-ns-claim-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

/// Mint an admin JWT; `ns` is injected verbatim when provided so tests can
/// exercise string, array, and malformed claim shapes.
fn admin_token_with_ns(ns: Option<Value>) -> String {
    let now = chrono::Utc::now();
    let mut claims = json!({
        "iss": JWT_ISSUER,
        "sub": "ns-claim-test",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

/// Admin state without a DB: reads serve from the cached config, which is all
/// the tenancy gate needs (the 403 fires before any handler dispatch).
fn admin_state(require_namespace_claim: bool) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Arc::new(MetricsAuthPolicy::default()),
        proxy_state: None,
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())))),
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: require_namespace_claim,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
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

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{actual}"), shutdown_tx)
}

async fn get_with(base: &str, path: &str, token: &str, namespace: Option<&str>) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(ns) = namespace {
        req = req.header("X-Ferrum-Namespace", ns);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn flag_off_token_without_ns_claim_reaches_any_namespace() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let token = admin_token_with_ns(None);

    let (status, _) = get_with(&base, "/proxies", &token, None).await;
    assert_eq!(status, 200, "default namespace must be reachable");

    let (status, _) = get_with(&base, "/proxies", &token, Some("prod")).await;
    assert_eq!(status, 200, "flag off: any namespace is a routing selector");
}

#[tokio::test]
async fn flag_on_token_without_ns_claim_is_rejected_on_scoped_routes() {
    let (base, _sd) = start_admin(admin_state(true)).await;
    let token = admin_token_with_ns(None);

    let (status, body) = get_with(&base, "/proxies", &token, Some("prod")).await;
    assert_eq!(status, 403);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM"),
        "error should explain the missing ns claim: {body}"
    );

    // The default namespace is also denied — tenancy intent must be explicit.
    let (status, _) = get_with(&base, "/consumers", &token, None).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn flag_on_ns_claim_authorizes_only_listed_namespaces() {
    let (base, _sd) = start_admin(admin_state(true)).await;
    let token = admin_token_with_ns(Some(json!(["staging", "ferrum"])));

    let (status, _) = get_with(&base, "/proxies", &token, Some("staging")).await;
    assert_eq!(status, 200);

    // Default namespace `ferrum` is in the claim set.
    let (status, _) = get_with(&base, "/proxies", &token, None).await;
    assert_eq!(status, 200);

    let (status, body) = get_with(&base, "/proxies", &token, Some("prod")).await;
    assert_eq!(status, 403);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not authorize namespace 'prod'"),
        "error should name the denied namespace: {body}"
    );
}

#[tokio::test]
async fn flag_on_single_string_ns_claim_is_accepted() {
    let (base, _sd) = start_admin(admin_state(true)).await;
    let token = admin_token_with_ns(Some(json!("staging")));

    let (status, _) = get_with(&base, "/upstreams", &token, Some("staging")).await;
    assert_eq!(status, 200);

    let (status, _) = get_with(&base, "/upstreams", &token, Some("ferrum")).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn flag_on_write_routes_are_denied_before_dispatch() {
    // The issue #2120 scenario: a staging-scoped operator token must not be
    // able to address prod via POST /restore + X-Ferrum-Namespace: prod. The
    // tenancy gate fires before role/read-only/body handling.
    let (base, _sd) = start_admin(admin_state(true)).await;
    let token = admin_token_with_ns(Some(json!("staging")));

    let resp = reqwest::Client::new()
        .post(format!("{base}/restore?confirm=true"))
        .bearer_auth(&token)
        .header("X-Ferrum-Namespace", "prod")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn flag_on_global_routes_do_not_require_ns_claim() {
    let (base, _sd) = start_admin(admin_state(true)).await;
    let token = admin_token_with_ns(None);

    // `GET /plugins` lists plugin *types* — global metadata, not tenant data.
    let (status, _) = get_with(&base, "/plugins", &token, None).await;
    assert_eq!(status, 200);

    // Observability stays reachable regardless of tenancy claims.
    let resp = reqwest::Client::new()
        .get(format!("{base}/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn malformed_ns_claim_rejects_token_at_authentication() {
    let (base, _sd) = start_admin(admin_state(true)).await;

    for bad in [json!(42), json!([1, "prod"]), json!(""), json!([""])] {
        let token = admin_token_with_ns(Some(bad.clone()));
        let (status, _) = get_with(&base, "/proxies", &token, None).await;
        assert_eq!(status, 401, "malformed ns claim {bad} must fail closed");
    }
}
