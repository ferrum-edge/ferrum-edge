//! Localized mesh file / stock-xDS policy reload → admin `/health` observability
//! (issue #3776).
//!
//! A failed reload must raise the shared `config_rejected` signal, keep the
//! last-good slice/policy, surface authenticated `/health` as `degraded` +
//! `config_rejected: true`, redact the boolean from unauthenticated probes, and
//! clear only after the exact current recovery is accepted by the proxy apply
//! lifecycle (not on provisional install / channel send).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

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
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::config_consumer::file_source::{
    MeshLocalReloadApply, MeshLocalSourceRecovery, apply_mesh_file_reload_candidate,
    load_mesh_slice_from_file,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
    StockPolicySnapshot, apply_stock_policy_reload_candidate,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSliceRequest;
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

const ADMIN_JWT_SECRET: &str = "mesh-local-reload-observability-secret-32b";
const ADMIN_JWT_ISSUER: &str = "ferrum-edge-test";

const VALID_MESH_YAML: &str = r#"
version: "1"
mesh:
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
"#;

const VALID_STOCK_POLICY_YAML: &str = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;

fn write_temp(ext: &str, content: &str) -> tempfile::TempPath {
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{ext}"))
        .tempfile()
        .expect("create temp mesh config");
    file.write_all(content.as_bytes())
        .expect("write temp mesh config");
    file.into_temp_path()
}

fn request() -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "mesh-reload-obs".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    }
}

fn mint_admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": ADMIN_JWT_ISSUER,
        "sub": "mesh-reload-operator",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ADMIN_JWT_SECRET.as_bytes()),
    )
    .expect("encode admin JWT")
}

fn build_mesh_admin_state(config_rejected: Arc<AtomicBool>) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    };
    let env_config = EnvConfig {
        namespace: "ferrum".to_string(),
        mesh_config_protocol: "file".to_string(),
        ..EnvConfig::default()
    };
    let (proxy_state, _handles) = ProxyState::new(
        cfg,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state");

    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ADMIN_JWT_SECRET.to_string(),
            issuer: ADMIN_JWT_ISSUER.to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "mesh".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: None,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: Some(config_rejected),
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: Some(MeshRuntimeState::new()),
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

async fn start_test_admin(state: AdminState) -> (u16, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
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
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    (port, shutdown_tx)
}

async fn get_health(port: u16, token: Option<&str>) -> (reqwest::StatusCode, Value) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest");
    let mut req = client.get(format!("http://127.0.0.1:{port}/health"));
    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.expect("GET /health");
    let status = resp.status();
    let body = resp.json().await.expect("/health JSON");
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_file_reload_rejection_surfaces_authenticated_health_and_clears() {
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request()).expect("initial load");
    let state = MeshRuntimeState::new();
    state.install_slice(slice.clone());

    let flag = Arc::new(AtomicBool::new(false));
    let recovery = MeshLocalSourceRecovery::new(flag.clone());
    let admin = build_mesh_admin_state(flag.clone());
    let (port, shutdown) = start_test_admin(admin).await;
    let token = mint_admin_token();

    let (status, health) = get_health(port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert!(health.get("config_rejected").is_none());

    let rejected = apply_mesh_file_reload_candidate(
        &state,
        &recovery,
        load_mesh_slice_from_file(
            std::path::Path::new("/nonexistent/mesh-reload.yaml"),
            request(),
        ),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert!(
        state
            .snapshot()
            .as_ref()
            .as_ref()
            .unwrap()
            .content_eq(&slice),
        "failed reload must retain last-good slice"
    );

    let (status, health) = get_health(port, Some(&token)).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["config_rejected"], true);

    let (_, unauth) = get_health(port, None).await;
    assert!(
        unauth.get("config_rejected").is_none(),
        "config_rejected must stay authenticated-only: {unauth:?}"
    );

    let submitted = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert!(matches!(
        submitted,
        MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
    ));
    assert!(
        recovery.is_rejected(),
        "valid candidate pending proxy accept must remain degraded"
    );
    let (_, health) = get_health(port, Some(&token)).await;
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["config_rejected"], true);

    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());

    let (_, health) = get_health(port, Some(&token)).await;
    assert_eq!(health["status"], "ok");
    assert!(health.get("config_rejected").is_none());

    let _ = shutdown.send(true);
}

#[test]
fn stock_policy_reload_rejection_raises_and_recovery_clears_only_after_proxy() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::load_stock_policy_baseline;
    use ferrum_edge::modes::mesh::slice::MeshSlice;

    let path = write_temp("yaml", VALID_STOCK_POLICY_YAML);
    let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
    let (tx, _rx) =
        tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));

    let rejected = apply_stock_policy_reload_candidate(
        &tx,
        &recovery,
        load_stock_policy_baseline(std::path::Path::new("/nonexistent/stock-policy.yaml")),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert_eq!(tx.borrow().mesh(), &baseline);

    let recovered = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline.clone()));
    assert_eq!(recovered, MeshLocalReloadApply::Unchanged);
    assert!(
        recovery.is_rejected(),
        "policy channel send must not clear config_rejected"
    );

    let bound = MeshSlice {
        version: "stock-obs-recovery".to_string(),
        ..MeshSlice::default()
    };
    let epoch = recovery.pending_epoch();
    recovery.bind_installed_slice_if_policy_recovery(epoch, &bound);
    recovery.note_proxy_apply_success(&bound);
    assert!(!recovery.is_rejected());

    let mut changed = baseline.clone();
    changed.peer_authentications.clear();
    let applied = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(changed.clone()));
    assert_eq!(applied, MeshLocalReloadApply::Applied);
    // No prior rejection: sticky flag stays clear, but pending is still set for
    // the new recovery epoch until proxy accept (idempotent clear).
    assert_eq!(tx.borrow().mesh(), &changed);
}
