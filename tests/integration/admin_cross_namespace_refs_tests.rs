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

use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
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
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
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
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
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
