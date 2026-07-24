//! File-mode SIGHUP reload observability (issue #2979).
//!
//! Rejected load/validation/apply must raise `config_rejected` so authenticated
//! `/health` reports degraded; Applied/Unchanged clears it. File mode leaves
//! `db_available` unset so the health gate treats it as reachable.

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::admin::{AdminState, MetricsAuthPolicy, serve_admin_on_listener};
use ferrum_edge::modes::file::{
    record_file_mode_reload_apply_outcome, record_file_mode_reload_load_failure,
};
use ferrum_edge::proxy::ConfigApplyOutcome;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn test_jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "file-mode-reload-observability-secret!!".into(),
        issuer: "ferrum-edge".into(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn mint_token() -> String {
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": "ferrum-edge",
        "sub": "operator",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::hours(1)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"file-mode-reload-observability-secret!!"),
    )
    .expect("mint token")
}

fn file_mode_admin_state(config_rejected: Arc<AtomicBool>) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: test_jwt_manager(),
        proxy_state: None,
        cached_config: None,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: Some(Arc::new(AtomicBool::new(true))),
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: Some(config_rejected),
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        metrics_auth: Arc::new(MetricsAuthPolicy::default()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state_clone,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn get_health(base: &str, token: Option<&str>) -> Value {
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{base}/health"));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    req.send()
        .await
        .expect("health request")
        .json()
        .await
        .expect("health json")
}

#[test]
fn test_file_mode_reload_helpers_set_and_clear_config_rejected() {
    let flag = AtomicBool::new(false);

    record_file_mode_reload_load_failure(&anyhow::anyhow!("parse failed"), &flag);
    assert!(flag.load(Ordering::Relaxed));

    record_file_mode_reload_apply_outcome(&ConfigApplyOutcome::Applied, &flag);
    assert!(!flag.load(Ordering::Relaxed));

    record_file_mode_reload_apply_outcome(
        &ConfigApplyOutcome::Rejected {
            errors: vec!["invalid".into()],
        },
        &flag,
    );
    assert!(flag.load(Ordering::Relaxed));

    record_file_mode_reload_apply_outcome(&ConfigApplyOutcome::Unchanged, &flag);
    assert!(!flag.load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_file_mode_rejected_reload_degrades_authenticated_health_and_recovers() {
    let flag = Arc::new(AtomicBool::new(false));
    let state = file_mode_admin_state(flag.clone());
    let (base, _shutdown) = start_admin(state).await;
    let token = mint_token();

    // Healthy baseline: no config_rejected detail.
    let health = get_health(&base, Some(&token)).await;
    assert_ne!(health.get("status"), Some(&json!("degraded")));
    assert!(health.get("config_rejected").is_none());

    // Simulate a rejected SIGHUP load (parse / validation failure).
    record_file_mode_reload_load_failure(&anyhow::anyhow!("invalid yaml"), &flag);
    let degraded = get_health(&base, Some(&token)).await;
    assert_eq!(degraded["status"], "degraded");
    assert_eq!(degraded["config_rejected"], true);

    // Unauthenticated probes must not see the detail field.
    let unauth = get_health(&base, None).await;
    assert!(unauth.get("config_rejected").is_none());

    // A later Applied reload clears degradation.
    record_file_mode_reload_apply_outcome(&ConfigApplyOutcome::Applied, &flag);
    let recovered = get_health(&base, Some(&token)).await;
    assert!(recovered.get("config_rejected").is_none());
    assert_ne!(recovered.get("status"), Some(&json!("degraded")));
}
