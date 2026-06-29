//! Admin observability endpoint authorization tests.
//!
//! Covers the hardened defaults for the observability surfaces:
//! - `/live` is always unauthenticated and returns only `{"status":"ok"}`.
//! - `/health` is reachable unauthenticated but exposes only `status`+`ready`;
//!   the detailed diagnostics (mode, DB, cached-config counts) require auth.
//! - `/metrics` returns `401` by default and succeeds with a valid admin JWT,
//!   a matching metrics bearer token, or an allowlisted client CIDR.
//!
//! Detailed `/overload` tiering needs a live `ProxyState` and is covered E2E in
//! `tests/functional/functional_admin_observability_test.rs`.

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

const JWT_SECRET: &str = "observability-auth-test-secret-key-000000";
const JWT_ISSUER: &str = "ferrum-edge-obs-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "obs-test",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

/// Build an admin state with the given metrics-auth policy. No DB / proxy state
/// is wired — these tests only exercise `/live`, `/health`, and `/metrics`.
fn admin_state(metrics_auth: MetricsAuthPolicy) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Arc::new(metrics_auth),
        proxy_state: None,
        cached_config: None,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
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

#[tokio::test]
async fn live_endpoint_is_unauthenticated_and_minimal() {
    let (base, _sd) = start_admin(admin_state(MetricsAuthPolicy::default())).await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    // Exactly `{"status":"ok"}` — no operational internals.
    assert_eq!(body, json!({"status": "ok"}));
}

#[tokio::test]
async fn health_unauthenticated_omits_detailed_fields() {
    let (base, _sd) = start_admin(admin_state(MetricsAuthPolicy::default())).await;

    // Unauthenticated: only status + ready, nothing operational.
    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert!(body.get("ready").is_some(), "ready present: {body}");
    for leaked in [
        "mode",
        "timestamp",
        "cached_config",
        "database",
        "admin_writes_enabled",
    ] {
        assert!(
            body.get(leaked).is_none(),
            "unauthenticated /health must not expose `{leaked}`: {body}"
        );
    }

    // Authenticated: detailed diagnostics are present.
    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .header("Authorization", format!("Bearer {}", admin_token()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body.get("mode").and_then(|v| v.as_str()), Some("file"));
    assert!(body.get("cached_config").is_some(), "detailed body: {body}");
}

#[tokio::test]
async fn metrics_requires_auth_by_default() {
    let (base, _sd) = start_admin(admin_state(MetricsAuthPolicy::default())).await;

    // No credential → 401.
    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        401,
        "/metrics must be 401 without auth by default"
    );

    // Valid admin JWT → 200 Prometheus text.
    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .header("Authorization", format!("Bearer {}", admin_token()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("text/plain"))
    );
}

#[tokio::test]
async fn metrics_accepts_dedicated_bearer_token() {
    let policy = MetricsAuthPolicy {
        allowed_cidrs: TrustedProxies::none(),
        bearer_token: Some("super-secret-scrape-token".to_string()),
    };
    let (base, _sd) = start_admin(admin_state(policy)).await;

    // Correct metrics token → 200.
    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .header("Authorization", "Bearer super-secret-scrape-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Wrong token → 401.
    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn metrics_allows_allowlisted_cidr_unauthenticated() {
    // Loopback is allowlisted, so an unauthenticated scrape from 127.0.0.1
    // (the test client) is permitted.
    let policy = MetricsAuthPolicy {
        allowed_cidrs: TrustedProxies::parse("127.0.0.1/32,::1"),
        bearer_token: None,
    };
    let (base, _sd) = start_admin(admin_state(policy)).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "allowlisted loopback should scrape without a credential"
    );
}
