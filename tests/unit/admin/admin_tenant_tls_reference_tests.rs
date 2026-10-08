//! Namespace-scoped operators cannot point backend TLS material outside their
//! namespace.
//!
//! Where the JWT `ns` claim is an authorization boundary, the control plane
//! loads backend TLS references on write and every data plane later loads them
//! with its own credentials. An `operator` scoped to one namespace must
//! therefore not be able to name another namespace's Kubernetes Secret, a
//! secret-manager or managed store, or a file on the gateway's filesystem —
//! and the refusal must not depend on whether that material exists.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "tenant-tls-reference-test-secret-key-0000";
const JWT_ISSUER: &str = "ferrum-edge-tenant-tls-reference-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn operator_token(namespaces: &[&str]) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "tenant-a-operator",
        "role": "operator",
        "ns": namespaces,
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

async fn sqlite_store(temp_dir: &TempDir, file: &str) -> Arc<dyn DatabaseBackend> {
    let db_path = temp_dir.path().join(file);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store connects and migrates");
    Arc::new(store)
}

/// A multi-tenant control plane: writable Admin, `ns` claim enforced.
fn tenant_control_plane_state(db: Arc<dyn DatabaseBackend>) -> AdminState {
    AdminState {
        db: Some(db),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: true,
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
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
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
        runtime_config_apply: None,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
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
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn post(base: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Ferrum-Namespace", "tenant-a")
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

fn upstream_with(field: &str, value: &str) -> Value {
    let mut body = json!({
        "id": "u-partner",
        "name": "partner",
        "targets": [{"host": "127.0.0.1", "port": 8443, "weight": 100}],
        "algorithm": "round_robin",
    });
    body[field] = json!(value);
    body
}

fn proxy_with(field: &str, value: &str) -> Value {
    let mut body = json!({
        "id": "p-partner",
        "listen_path": "/partner",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": 8443,
    });
    body[field] = json!(value);
    body
}

#[tokio::test]
async fn namespace_scoped_operator_cannot_reference_material_outside_its_namespace() {
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "tenant_tls_reference.db").await;
    let (base, _shutdown) = start_admin(tenant_control_plane_state(db)).await;
    let token = operator_token(&["tenant-a"]);

    let cases = [
        (
            "backend_tls_server_ca_cert_path",
            "k8s://tenant-b/db-mtls#ca.crt",
            "namespace of the resource",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "vault://secret/data/tenant-b#ca",
            "secret-manager",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "managed://ca-bundles/platform#ca",
            "secret-manager",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "/etc/ferrum/platform/ca.pem",
            "gateway filesystem",
        ),
    ];
    for (field, value, reason) in cases {
        for (path, body) in [
            ("/upstreams", upstream_with(field, value)),
            ("/proxies", proxy_with(field, value)),
        ] {
            let (status, response) = post(&base, path, &token, &body).await;
            assert_eq!(status, 400, "{path} {value} must be refused: {response}");
            let error = response["error"].as_str().unwrap_or_default();
            assert!(
                error.contains(field) && error.contains(reason),
                "{path} {value} must be refused before any load ({reason:?}): {error}"
            );
            assert!(
                !error.contains(value) && !error.contains("tenant-b"),
                "the refusal must not echo the reference: {error}"
            );
        }
    }
}
