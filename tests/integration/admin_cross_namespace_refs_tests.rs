//! Cross-namespace reference rejection tests.
//!
//! Background: namespaces are the primary tenant-isolation boundary. The DB
//! polling path filters every resource by `namespace`, but the admin API's
//! reference checks (`check_upstream_exists`, `check_proxy_exists`,
//! `validate_proxy_plugin_associations`) historically did NOT filter by
//! namespace. That gap admitted configs that referenced resources in other
//! namespaces — they passed admin validation but then silently failed at
//! runtime with 502 (the polling path can't see the cross-namespace target).
//!
//! These tests exercise the admin API end-to-end against a real SQLite store
//! to confirm:
//!
//!   1. A proxy in namespace `B` referencing an `upstream_id` that lives in
//!      namespace `A` is rejected with 400. Since lookups became
//!      namespace-predicated (issue #2122 DB-M1), the diagnostic reports the
//!      target as missing in the caller's namespace instead of disclosing
//!      which namespace owns it.
//!   2. A proxy in namespace `B` whose `plugins[]` association points at a
//!      `plugin_config` that lives in namespace `A` is rejected with 400.
//!   3. A `plugin_config` in namespace `B` whose `proxy_id` points at a proxy
//!      that lives in namespace `A` is rejected with 400.
//!   4. Same-namespace references continue to succeed (regression guard).

use crate::scaffolding::port_registry::TestSocket;

use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::BatchConfigWriteMode;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, LoadBalancerAlgorithm, PluginAssociation,
    PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

const NAMESPACE_A: &str = "tenant-a";
const NAMESPACE_B: &str = "tenant-b";

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-cross-namespace-refs".to_string(),
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

async fn build_admin_state(tc: &TestConfig) -> (AdminState, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("cross_ns_refs.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("DB connect must succeed");

    let state = AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: make_jwt_manager(tc),
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
        runtime_config_apply: None,
    };
    (state, tmp)
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
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

/// POST with `X-Ferrum-Namespace` so the admin scopes the request to that
/// tenant. Returns `(status, body)`.
async fn ns_post(
    base_url: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: &Value,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .header("X-Ferrum-Namespace", namespace)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

fn upstream_payload(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "targets": [{"host": "127.0.0.1", "port": 8080, "weight": 100}],
        "algorithm": "round_robin",
    })
}

fn proxy_with_upstream(id: &str, listen_path: &str, upstream_id: &str) -> Value {
    json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true,
        "upstream_id": upstream_id,
    })
}

fn plain_proxy(id: &str, listen_path: &str) -> Value {
    json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true,
    })
}

fn proxy_scoped_plugin(id: &str, proxy_id: &str) -> Value {
    json!({
        "id": id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "config": {
            "limits": [{"scope": "default", "requests_per_minute": 60}],
        },
        "enabled": true,
    })
}

fn mesh_route_dispatch_plugin(id: &str, proxy_id: &str, upstream_id: &str) -> Value {
    json!({
        "id": id,
        "plugin_name": "mesh_route_dispatch",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "config": {
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": upstream_id},
            }],
        },
        "enabled": true,
    })
}

fn err_string(body: &Value) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ── upstream_id reference ────────────────────────────────────────────────────

#[tokio::test]
async fn cross_namespace_upstream_reference_is_rejected() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Seed the upstream in namespace A.
    let (status, body) = ns_post(
        &base_url,
        "/upstreams",
        NAMESPACE_A,
        &token,
        &upstream_payload("up-shared", "shared"),
    )
    .await;
    assert_eq!(status, 201, "seed upstream in A failed: {:?}", body);

    // Try to create a proxy in namespace B that references the namespace-A upstream.
    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_B,
        &token,
        &proxy_with_upstream("p-b-1", "/api", "up-shared"),
    )
    .await;
    assert_eq!(
        status, 400,
        "cross-namespace upstream ref must be rejected (got {}): {:?}",
        status, body
    );
    let err = err_string(&body);
    // Lookups are namespace-predicated (issue #2122 DB-M1): a resource in
    // another namespace reports as missing in the caller's namespace, so the
    // rejection no longer discloses which namespace owns the resource.
    assert!(
        err.contains("does not exist") && err.contains("up-shared") && err.contains(NAMESPACE_B),
        "error must report the upstream as missing in the caller's namespace; got: {}",
        err
    );
}

#[tokio::test]
async fn same_namespace_upstream_reference_is_accepted() {
    // Regression guard: the namespace filter must NOT block legitimate
    // same-namespace references.
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, _) = ns_post(
        &base_url,
        "/upstreams",
        NAMESPACE_A,
        &token,
        &upstream_payload("up-a", "a-pool"),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &proxy_with_upstream("p-a-1", "/api", "up-a"),
    )
    .await;
    assert_eq!(
        status, 201,
        "same-namespace ref must succeed (got {}): {:?}",
        status, body
    );
}

#[tokio::test]
async fn missing_upstream_reports_does_not_exist_not_cross_namespace() {
    // When the upstream genuinely doesn't exist anywhere, the error says
    // "does not exist" — the same shape a cross-namespace reference now
    // yields, since lookups are namespace-predicated (issue #2122 DB-M1).
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &proxy_with_upstream("p-a-1", "/api", "totally-missing"),
    )
    .await;
    assert_eq!(status, 400, "missing upstream must 400: {:?}", body);
    let err = err_string(&body);
    assert!(
        err.contains("does not exist") && !err.contains("Cross-namespace"),
        "missing upstream should report 'does not exist', not cross-namespace; got: {}",
        err
    );
}

// ── plugin_config.proxy_id reference ─────────────────────────────────────────

#[tokio::test]
async fn cross_namespace_plugin_config_proxy_reference_is_rejected() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Seed a proxy in namespace A.
    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &plain_proxy("p-a-shared", "/api-a"),
    )
    .await;
    assert_eq!(status, 201, "seed proxy in A failed: {:?}", body);

    // Try to create a proxy-scoped plugin_config in namespace B targeting
    // the namespace-A proxy.
    let (status, body) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_B,
        &token,
        &proxy_scoped_plugin("pc-b-1", "p-a-shared"),
    )
    .await;
    assert_eq!(
        status, 400,
        "cross-namespace plugin_config.proxy_id must be rejected (got {}): {:?}",
        status, body
    );
    let err = err_string(&body);
    // Namespace-predicated lookup: the namespace-A proxy reports as missing
    // in namespace B (no cross-tenant disclosure).
    assert!(
        err.contains("does not exist") && err.contains("p-a-shared") && err.contains(NAMESPACE_B),
        "error must report the proxy as missing in the caller's namespace; got: {}",
        err
    );
}

#[tokio::test]
async fn same_namespace_plugin_config_proxy_reference_is_accepted() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, _) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &plain_proxy("p-a-1", "/api-a"),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_A,
        &token,
        &proxy_scoped_plugin("pc-a-1", "p-a-1"),
    )
    .await;
    assert_eq!(
        status, 201,
        "same-namespace plugin_config ref must succeed (got {}): {:?}",
        status, body
    );
}

// ── mesh_route_dispatch destination.upstream_id ─────────────────────────────

#[tokio::test]
async fn mesh_route_dispatch_missing_destination_upstream_is_rejected() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &plain_proxy("p-a-route", "/route"),
    )
    .await;
    assert_eq!(status, 201, "seed proxy failed: {:?}", body);

    let (status, body) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_A,
        &token,
        &mesh_route_dispatch_plugin("pc-route", "p-a-route", "missing-upstream"),
    )
    .await;
    assert_eq!(
        status, 400,
        "missing mesh_route_dispatch destination upstream must be rejected: {:?}",
        body
    );
    let err = err_string(&body);
    assert!(
        err.contains("mesh_route_dispatch") && err.contains("missing-upstream"),
        "error must mention plugin type and upstream id; got: {}",
        err
    );
}

#[tokio::test]
async fn mesh_route_dispatch_cross_namespace_destination_upstream_is_rejected() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = ns_post(
        &base_url,
        "/upstreams",
        NAMESPACE_A,
        &token,
        &upstream_payload("up-shared", "shared"),
    )
    .await;
    assert_eq!(status, 201, "seed upstream in A failed: {:?}", body);

    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_B,
        &token,
        &plain_proxy("p-b-route", "/route"),
    )
    .await;
    assert_eq!(status, 201, "seed proxy in B failed: {:?}", body);

    let (status, body) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_B,
        &token,
        &mesh_route_dispatch_plugin("pc-b-route", "p-b-route", "up-shared"),
    )
    .await;
    assert_eq!(
        status, 400,
        "cross-namespace mesh_route_dispatch destination upstream must be rejected: {:?}",
        body
    );
    let err = err_string(&body);
    // Namespace-predicated lookup: the namespace-A upstream reports as
    // missing in namespace B (no cross-tenant disclosure).
    assert!(
        err.contains("does not exist") && err.contains("up-shared"),
        "error must report the destination upstream as missing; got: {}",
        err
    );
}

#[tokio::test]
async fn mesh_route_dispatch_same_namespace_destination_upstream_is_accepted() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let (status, body) = ns_post(
        &base_url,
        "/upstreams",
        NAMESPACE_A,
        &token,
        &upstream_payload("up-a-route", "route-pool"),
    )
    .await;
    assert_eq!(status, 201, "seed upstream failed: {:?}", body);

    let (status, body) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &plain_proxy("p-a-route", "/route"),
    )
    .await;
    assert_eq!(status, 201, "seed proxy failed: {:?}", body);

    let (status, body) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_A,
        &token,
        &mesh_route_dispatch_plugin("pc-a-route", "p-a-route", "up-a-route"),
    )
    .await;
    assert_eq!(
        status, 201,
        "same-namespace mesh_route_dispatch destination upstream should succeed: {:?}",
        body
    );
}

// ── proxy plugin associations ────────────────────────────────────────────────

#[tokio::test]
async fn cross_namespace_proxy_plugin_association_is_rejected() {
    // A proxy in namespace B that lists a `plugins[]` association referencing
    // a plugin_config in namespace A must be rejected. This is the
    // `validate_proxy_plugin_associations` path (separate from the
    // plugin_config.proxy_id check exercised above).
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Seed a proxy + a proxy-scoped plugin_config in namespace A.
    let (status, _) = ns_post(
        &base_url,
        "/proxies",
        NAMESPACE_A,
        &token,
        &plain_proxy("p-a-host", "/api-a"),
    )
    .await;
    assert_eq!(status, 201);

    let (status, _) = ns_post(
        &base_url,
        "/plugins/config",
        NAMESPACE_A,
        &token,
        &proxy_scoped_plugin("pc-a-shared", "p-a-host"),
    )
    .await;
    assert_eq!(status, 201);

    // Try to create a proxy in namespace B that lists pc-a-shared in
    // its `plugins[]` association list. The plugin_config lives in
    // namespace A; admin must reject this.
    let cross_ns_proxy = json!({
        "id": "p-b-bad",
        "listen_path": "/api-b",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true,
        "plugins": [
            { "plugin_config_id": "pc-a-shared" },
        ],
    });
    let (status, body) = ns_post(&base_url, "/proxies", NAMESPACE_B, &token, &cross_ns_proxy).await;
    assert_eq!(
        status, 400,
        "cross-namespace plugins[] association must be rejected (got {}): {:?}",
        status, body
    );
    let err = err_string(&body);
    assert!(
        err.contains("pc-a-shared"),
        "error must mention the offending plugin_config id; got: {}",
        err
    );
}

// ── batch endpoint ───────────────────────────────────────────────────────────

#[tokio::test]
async fn batch_cross_namespace_upstream_reference_is_rejected() {
    // The batch endpoint runs its own reference checks (separate from the
    // single-resource CRUD path); make sure it also enforces namespace
    // isolation.
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    // Seed in namespace A.
    let (status, _) = ns_post(
        &base_url,
        "/upstreams",
        NAMESPACE_A,
        &token,
        &upstream_payload("up-shared", "shared"),
    )
    .await;
    assert_eq!(status, 201);

    // Submit a batch in namespace B that references the namespace-A upstream
    // (and does NOT include the upstream in the same batch — otherwise the
    // intra-batch check short-circuits before hitting the DB).
    let batch = json!({
        "proxies": [
            {
                "id": "p-b-batch",
                "listen_path": "/api",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 8080,
                "strip_listen_path": true,
                "upstream_id": "up-shared",
            },
        ],
    });
    let (status, body) = ns_post(&base_url, "/batch", NAMESPACE_B, &token, &batch).await;
    assert_eq!(
        status, 400,
        "batch cross-namespace upstream ref must be rejected (got {}): {:?}",
        status, body
    );
    let errors = body
        .get("validation_errors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let joined = errors
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        joined.contains("up-shared")
            && joined.contains("does not exist")
            && joined.contains(NAMESPACE_B),
        "batch error must report the upstream as missing in the caller's namespace; got: {}",
        joined
    );
}

#[tokio::test]
async fn batch_mesh_route_dispatch_missing_destination_upstream_is_rejected() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let batch = json!({
        "proxies": [{
            "id": "p-batch-route",
            "listen_path": "/route",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 8080,
            "strip_listen_path": true,
        }],
        "plugin_configs": [
            mesh_route_dispatch_plugin("pc-batch-route", "p-batch-route", "missing-upstream"),
        ],
    });
    let (status, body) = ns_post(&base_url, "/batch", NAMESPACE_A, &token, &batch).await;
    assert_eq!(
        status, 400,
        "batch mesh_route_dispatch missing upstream must be rejected: {:?}",
        body
    );
    let errors = body
        .get("validation_errors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let joined = errors
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        joined.contains("mesh_route_dispatch") && joined.contains("missing-upstream"),
        "batch error must mention plugin type and upstream id; got: {}",
        joined
    );
}

#[tokio::test]
async fn batch_mesh_route_dispatch_destination_can_reference_batch_upstream() {
    let tc = TestConfig::default();
    let (state, _tmp) = build_admin_state(&tc).await;
    let (base_url, _shutdown) = start_admin(state).await;
    let token = make_token(&tc);

    let batch = json!({
        "upstreams": [
            upstream_payload("up-batch-route", "route-pool"),
        ],
        "proxies": [{
            "id": "p-batch-route",
            "listen_path": "/route",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 8080,
            "strip_listen_path": true,
        }],
        "plugin_configs": [
            mesh_route_dispatch_plugin("pc-batch-route", "p-batch-route", "up-batch-route"),
        ],
    });
    let (status, body) = ns_post(&base_url, "/batch", NAMESPACE_A, &token, &batch).await;
    assert_eq!(
        status, 201,
        "batch mesh_route_dispatch should accept upstreams created in the same batch: {:?}",
        body
    );
}

// ── store-level mesh_route_dispatch upstream-reference lookup ────────────────
//
// Admission rejects cross-namespace mesh_route_dispatch writes, but the store
// delete path must still namespace-predicate its reference scan so a legacy or
// direct DB row cannot block another tenant's upstream delete.

async fn sqlite_store_for_store_level_tests() -> (DatabaseStore, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("cross_ns_store_refs.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, tmp)
}

async fn seed_store_upstream(store: &DatabaseStore, namespace: &str, id: &str, ts: &str) {
    sqlx::query(
        "INSERT INTO upstreams \
         (id, namespace, name, targets, algorithm, created_at, updated_at) \
         VALUES (?, ?, ?, '[{\"host\":\"127.0.0.1\",\"port\":8080,\"weight\":100}]', 'round_robin', ?, ?)",
    )
    .bind(id)
    .bind(namespace)
    .bind(format!("{id}-name"))
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("upstream insert must succeed");
}

async fn seed_store_proxy(store: &DatabaseStore, namespace: &str, id: &str, ts: &str) {
    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES (?, ?, ?, '[]', '/route', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind(id)
    .bind(namespace)
    .bind(format!("{id}-name"))
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("proxy insert must succeed");
}

async fn seed_store_mesh_route_dispatch(
    store: &DatabaseStore,
    namespace: &str,
    plugin_id: &str,
    proxy_id: &str,
    upstream_id: &str,
    ts: &str,
) {
    let config = format!(
        r#"{{"rules":[{{"match":{{"methods":["GET"]}},"destination":{{"upstream_id":"{upstream_id}"}}}}]}}"#
    );
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, ?, 'mesh_route_dispatch', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind(plugin_id)
    .bind(namespace)
    .bind(config)
    .bind(proxy_id)
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("mesh_route_dispatch insert must succeed");
}

async fn upstream_exists(store: &DatabaseStore, namespace: &str, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM upstreams WHERE id = ? AND namespace = ?")
        .bind(id)
        .bind(namespace)
        .fetch_one(&store.pool())
        .await
        .expect("upstream count must succeed")
        > 0
}

#[tokio::test]
async fn mesh_route_dispatch_store_cross_namespace_ref_does_not_block_upstream_delete() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    let ts = chrono::Utc::now().to_rfc3339();
    let shared_upstream_id = "up-shared-store";

    seed_store_upstream(&store, NAMESPACE_A, shared_upstream_id, &ts).await;
    seed_store_proxy(&store, NAMESPACE_B, "p-b-store-route", &ts).await;
    seed_store_mesh_route_dispatch(
        &store,
        NAMESPACE_B,
        "pc-b-store-route",
        "p-b-store-route",
        shared_upstream_id,
        &ts,
    )
    .await;

    let deleted = store
        .delete_upstream(NAMESPACE_A, shared_upstream_id)
        .await
        .expect("namespace A upstream delete must succeed despite cross-namespace plugin row");
    assert!(deleted, "upstream in namespace A must be deleted");
    assert!(
        !upstream_exists(&store, NAMESPACE_A, shared_upstream_id).await,
        "deleted upstream must not remain in namespace A"
    );
}

#[tokio::test]
async fn mesh_route_dispatch_store_same_namespace_ref_blocks_upstream_delete() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    let ts = chrono::Utc::now().to_rfc3339();
    let upstream_id = "up-a-store-route";

    seed_store_upstream(&store, NAMESPACE_A, upstream_id, &ts).await;
    seed_store_proxy(&store, NAMESPACE_A, "p-a-store-route", &ts).await;
    seed_store_mesh_route_dispatch(
        &store,
        NAMESPACE_A,
        "pc-a-store-route",
        "p-a-store-route",
        upstream_id,
        &ts,
    )
    .await;

    let err = store
        .delete_upstream(NAMESPACE_A, upstream_id)
        .await
        .expect_err("same-namespace mesh_route_dispatch reference must block delete");
    let message = err.to_string();
    assert!(
        message.contains("mesh_route_dispatch") && message.contains("pc-a-store-route"),
        "delete error must name the referring plugin; got: {message}"
    );
    assert!(
        upstream_exists(&store, NAMESPACE_A, upstream_id).await,
        "blocked upstream must remain in namespace A"
    );
}

#[test]
fn mongo_mesh_route_dispatch_upstream_ref_lookup_filters_by_namespace() {
    let source = include_str!("../../src/config/mongo_store.rs");
    let find_start = source
        .find("async fn find_mesh_route_dispatch_upstream_ref_opt_session(")
        .expect("Mongo mesh_route_dispatch upstream lookup");
    let find_body = &source[find_start..];
    let next_fn = find_body
        .find("async fn find_access_control_consumer_ref_opt_session(")
        .expect("access_control lookup following mesh_route_dispatch lookup");
    let find_body = &find_body[..next_fn];

    assert!(
        find_body.contains("\"namespace\": namespace,"),
        "Mongo mesh_route_dispatch upstream-reference lookup must filter by namespace"
    );
    assert_eq!(
        find_body.matches("\"namespace\": namespace,").count(),
        2,
        "Mongo lookup must namespace-predicate both session branches"
    );
}

// ============================================================================
// Issue #4627 — durable identity is `(namespace, id)`
//
// Before this fix `proxies`, `upstreams`, `plugin_configs`, and `api_specs`
// used the bare `id` as their sole SQL primary key (and as the bare MongoDB
// `_id`), while every admin existence check was namespace-scoped. One tenant
// could therefore reserve a conventional id — `payments`, `auth`, `default` —
// and permanently deny it to every other tenant, and the difference between a
// validation failure, a successful create, and a duplicate-key persistence
// failure was a cross-tenant existence oracle.
//
// These tests run against a real SQLite store because `DatabaseStore` is the
// shared implementation behind every SQL dialect.
// ============================================================================

fn ns_upstream(namespace: &str, id: &str) -> Upstream {
    Upstream {
        labels: Default::default(),
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: None,
        targets: vec![UpstreamTarget {
            host: "127.0.0.1".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn ns_plugin_config(namespace: &str, id: &str, scope: PluginScope) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: "stdout_logging".to_string(),
        config: json!({}),
        scope,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn ns_proxy(namespace: &str, id: &str, listen_path: &str) -> Proxy {
    Proxy {
        labels: Default::default(),
        id: id.to_string(),
        namespace: namespace.to_string(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
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
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: Vec::new(),
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

/// Build the identical `(upstream, plugin_config, proxy)` graph in `namespace`,
/// using the SAME bare ids in every tenant.
async fn seed_identical_graph(store: &DatabaseStore, namespace: &str) {
    store
        .create_upstream(&ns_upstream(namespace, "payments"))
        .await
        .unwrap_or_else(|e| panic!("upstream create in {namespace} must succeed: {e}"));
    store
        .create_plugin_config(&ns_plugin_config(
            namespace,
            "auth",
            PluginScope::ProxyGroup,
        ))
        .await
        .unwrap_or_else(|e| panic!("plugin create in {namespace} must succeed: {e}"));
    let mut proxy = ns_proxy(namespace, "edge", "/edge");
    proxy.upstream_id = Some("payments".to_string());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "auth".to_string(),
    }];
    store
        .create_proxy(&proxy)
        .await
        .unwrap_or_else(|e| panic!("proxy create in {namespace} must succeed: {e}"));
}

/// Everything that identifies a namespace's persisted graph, in a form two
/// snapshots can be compared with. `loaded_at` is deliberately excluded: it is
/// the load timestamp, not tenant state.
fn config_fingerprint(config: &GatewayConfig) -> String {
    let mut proxies = config.proxies.clone();
    proxies.sort_by(|a, b| a.id.cmp(&b.id));
    let mut plugin_configs = config.plugin_configs.clone();
    plugin_configs.sort_by(|a, b| a.id.cmp(&b.id));
    let mut upstreams = config.upstreams.clone();
    upstreams.sort_by(|a, b| a.id.cmp(&b.id));
    serde_json::to_string(&json!({
        "proxies": proxies,
        "plugin_configs": plugin_configs,
        "upstreams": upstreams,
    }))
    .expect("config fingerprint must serialize")
}

#[tokio::test(flavor = "multi_thread")]
async fn two_namespaces_own_the_same_bare_resource_ids_independently() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;

    // The pre-#4627 schema failed the SECOND tenant here on a global primary
    // key, even though its own namespace had no such id.
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    for namespace in [NAMESPACE_A, NAMESPACE_B] {
        let upstream = store
            .get_upstream(namespace, "payments")
            .await
            .expect("upstream read must succeed")
            .expect("upstream must exist in its own namespace");
        assert_eq!(upstream.namespace, namespace);

        let plugin = store
            .get_plugin_config(namespace, "auth")
            .await
            .expect("plugin read must succeed")
            .expect("plugin must exist in its own namespace");
        assert_eq!(plugin.namespace, namespace);

        let proxy = store
            .get_proxy(namespace, "edge")
            .await
            .expect("proxy read must succeed")
            .expect("proxy must exist in its own namespace");
        assert_eq!(proxy.namespace, namespace);
        assert_eq!(proxy.upstream_id.as_deref(), Some("payments"));
        assert_eq!(
            proxy
                .plugins
                .iter()
                .map(|assoc| assoc.plugin_config_id.as_str())
                .collect::<Vec<_>>(),
            vec!["auth"],
            "each tenant's junction rows must resolve to its own plugin config"
        );

        let full = store
            .load_full_config(namespace)
            .await
            .expect("full load must succeed");
        assert_eq!(full.proxies.len(), 1);
        assert_eq!(full.upstreams.len(), 1);
        assert_eq!(full.plugin_configs.len(), 1);
        for owner in full
            .proxies
            .iter()
            .map(|p| p.namespace.as_str())
            .chain(full.upstreams.iter().map(|u| u.namespace.as_str()))
            .chain(full.plugin_configs.iter().map(|p| p.namespace.as_str()))
        {
            assert_eq!(owner, namespace, "full load must not cross tenants");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_same_id_graph_leaves_the_other_namespace_byte_for_byte_unchanged() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    let before = config_fingerprint(
        &store
            .load_full_config(NAMESPACE_B)
            .await
            .expect("baseline load"),
    );

    assert!(
        store
            .delete_proxy(NAMESPACE_A, "edge")
            .await
            .expect("proxy delete must succeed")
    );
    // `delete_proxy` also sweeps tenant A's now-unreferenced proxy_group plugin
    // and orphaned upstream; whatever it left is removed explicitly so the
    // namespace ends empty either way.
    store
        .delete_plugin_config(NAMESPACE_A, "auth")
        .await
        .expect("plugin delete must not error");
    store
        .delete_upstream(NAMESPACE_A, "payments")
        .await
        .expect("upstream delete must not error");

    let after = config_fingerprint(
        &store
            .load_full_config(NAMESPACE_B)
            .await
            .expect("post-delete load"),
    );
    assert_eq!(
        before, after,
        "deleting tenant A's same-id graph must leave tenant B untouched"
    );

    let empty = store
        .load_full_config(NAMESPACE_A)
        .await
        .expect("emptied namespace must still load");
    assert!(empty.proxies.is_empty());
    assert!(empty.plugin_configs.is_empty());
    assert!(empty.upstreams.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_config_delete_does_not_detach_a_same_id_plugin_in_another_namespace() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    assert!(
        store
            .delete_plugin_config(NAMESPACE_A, "auth")
            .await
            .expect("plugin delete must succeed")
    );

    let a_proxy = store
        .get_proxy(NAMESPACE_A, "edge")
        .await
        .expect("tenant A proxy must still read")
        .expect("tenant A proxy must survive its plugin delete");
    assert!(
        a_proxy.plugins.is_empty(),
        "tenant A's own association must be removed with its plugin config"
    );

    let b_proxy = store
        .get_proxy(NAMESPACE_B, "edge")
        .await
        .expect("tenant B proxy must read")
        .expect("tenant B proxy must exist");
    assert_eq!(
        b_proxy
            .plugins
            .iter()
            .map(|assoc| assoc.plugin_config_id.as_str())
            .collect::<Vec<_>>(),
        vec!["auth"],
        "a plugin delete in one tenant must not unbind the same-id plugin in another"
    );
    assert!(
        store
            .get_plugin_config(NAMESPACE_B, "auth")
            .await
            .expect("tenant B plugin must read")
            .is_some(),
        "tenant B's plugin config must survive"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_group_orphan_cleanup_only_reaps_the_deleting_namespaces_plugin() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    // Deleting the only proxy that referenced the proxy_group plugin runs the
    // orphan sweep; it must scan only the deleting tenant's junction rows.
    assert!(
        store
            .delete_proxy(NAMESPACE_A, "edge")
            .await
            .expect("proxy delete must succeed")
    );

    assert!(
        store
            .get_plugin_config(NAMESPACE_A, "auth")
            .await
            .expect("tenant A plugin read must succeed")
            .is_none(),
        "tenant A's now-orphaned proxy_group plugin must be reaped"
    );
    assert!(
        store
            .get_plugin_config(NAMESPACE_B, "auth")
            .await
            .expect("tenant B plugin read must succeed")
            .is_some(),
        "tenant B's same-id proxy_group plugin is still referenced and must survive"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn incremental_delta_removals_are_keyed_on_namespace_and_id() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    let a_cursor = store
        .latest_change_sequence(NAMESPACE_A)
        .await
        .expect("tenant A cursor");
    let b_cursor = store
        .latest_change_sequence(NAMESPACE_B)
        .await
        .expect("tenant B cursor");

    assert!(
        store
            .delete_proxy(NAMESPACE_A, "edge")
            .await
            .expect("proxy delete must succeed")
    );

    let a_delta = store
        .load_incremental_config(NAMESPACE_A, a_cursor)
        .await
        .expect("tenant A delta must load");
    assert!(
        a_delta
            .removed_proxy_ids
            .iter()
            .any(|key| key.namespace == NAMESPACE_A && key.id == "edge"),
        "tenant A's delta must carry the namespace-qualified removal"
    );

    let b_delta = store
        .load_incremental_config(NAMESPACE_B, b_cursor)
        .await
        .expect("tenant B delta must load");
    assert!(
        b_delta.removed_proxy_ids.is_empty(),
        "a same-id delete in another tenant must not appear as a removal here: {:?}",
        b_delta.removed_proxy_ids
    );
    assert!(
        b_delta.added_or_modified_proxies.is_empty(),
        "tenant B saw no mutation and must receive an empty proxy delta"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn clearing_one_namespace_leaves_the_same_id_resources_in_the_other() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    seed_identical_graph(&store, NAMESPACE_A).await;
    seed_identical_graph(&store, NAMESPACE_B).await;

    let before = config_fingerprint(
        &store
            .load_full_config(NAMESPACE_B)
            .await
            .expect("baseline load"),
    );

    // The restore path's clear step, and the cascade behind DELETE /namespaces.
    store
        .delete_all_resources(NAMESPACE_A, &BatchConfigWriteMode::Admission)
        .await
        .expect("namespace clear must succeed");

    let cleared = store
        .load_full_config(NAMESPACE_A)
        .await
        .expect("cleared namespace must load");
    assert!(cleared.proxies.is_empty());
    assert!(cleared.plugin_configs.is_empty());
    assert!(cleared.upstreams.is_empty());

    let after = config_fingerprint(
        &store
            .load_full_config(NAMESPACE_B)
            .await
            .expect("post-clear load"),
    );
    assert_eq!(
        before, after,
        "clearing one tenant must leave the other byte-for-byte unchanged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_same_id_creates_succeed_across_namespaces_and_admit_one_within_one() {
    let (store, _tmp) = sqlite_store_for_store_level_tests().await;
    let store = Arc::new(store);

    // Different namespaces, same bare id: BOTH must land.
    let cross =
        {
            let a = Arc::clone(&store);
            let b = Arc::clone(&store);
            let left = tokio::spawn(async move {
                a.create_upstream(&ns_upstream(NAMESPACE_A, "shared")).await
            });
            let right = tokio::spawn(async move {
                b.create_upstream(&ns_upstream(NAMESPACE_B, "shared")).await
            });
            (
                left.await.expect("task A must not panic"),
                right.await.expect("task B must not panic"),
            )
        };
    assert!(
        cross.0.is_ok() && cross.1.is_ok(),
        "same bare id in two namespaces must both persist: {:?} / {:?}",
        cross.0.as_ref().err().map(ToString::to_string),
        cross.1.as_ref().err().map(ToString::to_string)
    );
    for namespace in [NAMESPACE_A, NAMESPACE_B] {
        assert!(
            store
                .get_upstream(namespace, "shared")
                .await
                .expect("read must succeed")
                .is_some()
        );
    }

    // Same namespace, same id: exactly one may land.
    let same = {
        let a = Arc::clone(&store);
        let b = Arc::clone(&store);
        let left =
            tokio::spawn(async move { a.create_upstream(&ns_upstream(NAMESPACE_A, "solo")).await });
        let right =
            tokio::spawn(async move { b.create_upstream(&ns_upstream(NAMESPACE_A, "solo")).await });
        (
            left.await.expect("task A must not panic"),
            right.await.expect("task B must not panic"),
        )
    };
    let admitted = usize::from(same.0.is_ok()) + usize::from(same.1.is_ok());
    assert_eq!(
        admitted, 1,
        "concurrent same-namespace creates of one id must admit exactly one"
    );
}
