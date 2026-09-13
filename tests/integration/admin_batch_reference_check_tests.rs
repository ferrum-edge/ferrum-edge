//! `POST /batch` reference-check HTTP classification (issue #4377).
//!
//! A database failure while validating `plugin_config.proxy_id` must return
//! 503 with the shared redacted `db_error_response` body. A genuine miss still
//! returns 400 with the unchanged namespace-predicated wording from #2122.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::set_batch_reference_check_fault_for_test;
use ferrum_edge::{
    admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    },
    config::db_loader::{DatabaseStore, DbPoolConfig},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-batch-ref-check-32ch";
const JWT_ISSUER: &str = "test-ferrum-edge";
const RAW_DB_DETAIL: &str =
    "postgres://ferrum:s3cr3t-dsn-password@db.internal:5432/ferrum_prod pool exhausted";

struct BatchRefFaultGuard {
    namespace: String,
}

impl Drop for BatchRefFaultGuard {
    fn drop(&mut self) {
        set_batch_reference_check_fault_for_test(&self.namespace, None);
    }
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "batch-ref-check-admin",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 4,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("batch-ref-check-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state(db: DatabaseStore) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
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
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
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
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual);
}

async fn post_ns(base: &str, path: &str, namespace: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(admin_token())
        .header("X-Ferrum-Namespace", namespace)
        .json(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

fn plugin_referencing_proxy(plugin_id: &str, proxy_id: &str) -> Value {
    json!({
        "plugin_configs": [{
            "id": plugin_id,
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "limits": [{"scope": "default", "requests_per_minute": 60}],
            },
        }],
    })
}

/// A batch that reaches `check_upstream_exists` (the first #4379 reference
/// lookup) without submitting a plugin graph, consumer credentials, or an
/// mTLS-compat participant, so none of the earlier #4527 candidate-validation
/// sites can shadow the reference-lookup classification under test.
fn proxy_referencing_upstream(proxy_id: &str, upstream_id: &str) -> Value {
    json!({
        "proxies": [{
            "id": proxy_id,
            "listen_path": format!("/{proxy_id}"),
            "backend_scheme": "http",
            "upstream_id": upstream_id,
        }],
    })
}

#[tokio::test]
async fn batch_missing_proxy_reference_is_400_with_unchanged_wording() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = "batch-ref-missing";
    let plugin_id = "pc-missing";
    let proxy_id = "no-such-proxy";

    let (status, body) = post_ns(
        &base,
        "/batch",
        namespace,
        &plugin_referencing_proxy(plugin_id, proxy_id),
    )
    .await;

    assert_eq!(
        status, 400,
        "a genuine miss must stay a client validation error: {body:?}"
    );
    assert_eq!(body["error"], "Batch validation failed");
    let expected = format!(
        "PluginConfig '{plugin_id}' references proxy_id '{proxy_id}' \
         that does not exist in namespace '{namespace}'"
    );
    let errors = body["validation_errors"]
        .as_array()
        .expect("validation_errors array");
    let found = errors.iter().any(|item| item.as_str() == Some(&expected));
    assert!(
        found,
        "missing proxy must keep the issue #2122 wording {expected:?}; got {errors:?}"
    );
}

#[tokio::test]
async fn batch_reference_check_backend_failure_is_503_and_redacted() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = format!("batch-ref-db-fail-{}", uuid::Uuid::new_v4());
    set_batch_reference_check_fault_for_test(&namespace, Some(RAW_DB_DETAIL));
    let _guard = BatchRefFaultGuard {
        namespace: namespace.clone(),
    };

    let (status, body) = post_ns(
        &base,
        "/batch",
        &namespace,
        &proxy_referencing_upstream("proxy-db-fail", "upstream-db-fail"),
    )
    .await;

    assert_eq!(
        status, 503,
        "a reference-check backend failure must be retryable: {body:?}"
    );
    assert_eq!(
        body["error"], "Database unavailable — operation failed",
        "503 must reuse the redacted db_error_response shape: {body:?}"
    );
    assert!(
        body.get("validation_errors").is_none(),
        "DB failures must not be reported as Batch validation failed: {body:?}"
    );
    let rendered = body.to_string();
    for sentinel in [
        "s3cr3t-dsn-password",
        "db.internal:5432",
        "ferrum_prod",
        RAW_DB_DETAIL,
        "Batch validation failed",
    ] {
        assert!(
            !rendered.contains(sentinel),
            "503 body leaked persistence sentinel {sentinel:?}: {rendered}"
        );
    }
}

/// Issue #4527: the plugin-graph candidate validation runs *before* the first
/// `batch_reference_lookup`, so for any batch carrying plugin configs a
/// database outage was answered with `400 "Batch validation failed"` — telling
/// a Terraform/GitOps caller the payload was malformed and must not be retried.
/// It must return the same retryable, redacted 503.
#[tokio::test]
async fn batch_plugin_graph_candidate_db_failure_is_503_and_redacted() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = format!("batch-candidate-db-fail-{}", uuid::Uuid::new_v4());
    set_batch_reference_check_fault_for_test(&namespace, Some(RAW_DB_DETAIL));
    let _guard = BatchRefFaultGuard {
        namespace: namespace.clone(),
    };

    // Non-empty `plugin_configs` makes `batch_submits_plugin_graph` true, which
    // is the exact condition issue #4377 documented.
    let (status, body) = post_ns(
        &base,
        "/batch",
        &namespace,
        &plugin_referencing_proxy("pc-candidate-db-fail", "proxy-candidate-db-fail"),
    )
    .await;

    assert_eq!(
        status, 503,
        "a candidate-validation database failure must be retryable: {body:?}"
    );
    assert_eq!(
        body["error"], "Database unavailable — operation failed",
        "503 must reuse the redacted db_error_response shape: {body:?}"
    );
    assert!(
        body.get("validation_errors").is_none(),
        "DB failures must not be reported as Batch validation failed: {body:?}"
    );
    let rendered = body.to_string();
    for sentinel in [
        "s3cr3t-dsn-password",
        "db.internal:5432",
        "ferrum_prod",
        RAW_DB_DETAIL,
        "Batch validation failed",
    ] {
        assert!(
            !rendered.contains(sentinel),
            "503 body leaked persistence sentinel {sentinel:?}: {rendered}"
        );
    }
}

/// The 503 classification must not swallow genuine payload problems: with no
/// fault armed, the same plugin-config payload still returns the unchanged 400.
#[tokio::test]
async fn batch_plugin_graph_genuine_miss_stays_400_without_a_fault() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = format!("batch-candidate-no-fault-{}", uuid::Uuid::new_v4());

    let (status, body) = post_ns(
        &base,
        "/batch",
        &namespace,
        &plugin_referencing_proxy("pc-no-fault", "proxy-no-fault"),
    )
    .await;

    assert_eq!(
        status, 400,
        "an unarmed namespace must keep the client validation error: {body:?}"
    );
    assert_eq!(body["error"], "Batch validation failed");
    assert!(
        body["validation_errors"].is_array(),
        "400 must still enumerate the payload problems: {body:?}"
    );
}
