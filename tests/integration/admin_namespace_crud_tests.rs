//! Admin API first-class namespace CRUD (issue #3955).
//!
//! Covers create/get/list, malformed update bodies, Unicode description
//! bounds, rename (resources move, target collision, derived-only tenants,
//! historical audit history follows the tenant while namespace_at_event is
//! retained), delete (empty, occupied, confirmed cascade over every occupancy
//! and ancillary surface), protection of the
//! effective configured namespace from both delete and rename-away, the
//! last-remaining-namespace invariant under concurrent deletes, commit-boundary
//! lease loss, late-step rollback, file-mode 403s, and the
//! `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` gate the registry handlers apply to
//! the path/body name themselves (list filtering plus per-name 403s, including
//! a rename's target name).

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::lock_namespace_registry_admission_for_test;
use ferrum_edge::_test_support::{NamespaceRegistryPhase, set_namespace_registry_fault_for_test};
use ferrum_edge::admin::{
    AdminState,
    audit::{AuditEvent, AuditListFilter},
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::batch_atomicity::{
    NamespaceAdmissionLeaseHold, NamespaceConfigAdmissionLeaseRef,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::namespace_registry::MAX_NAMESPACE_DESCRIPTION_CHARS;
use ferrum_edge::config::types::GatewayConfig;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-namespace-crud-32ch";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn token_with_role(role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "namespace-admin",
        "role": role,
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
    .expect("token encodes")
}

fn admin_token() -> String {
    token_with_role("admin")
}

/// Mint an admin JWT carrying an `ns` claim verbatim, so the namespace-claim
/// gate can be exercised with both the single-string and the array shapes.
fn admin_token_with_ns(ns: Value) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "namespace-admin",
        "role": "admin",
        "ns": ns,
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
    .expect("token encodes")
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 4,
        min_connections: 0,
        acquire_timeout_seconds: 10,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    make_store_at(dir, &format!("ns-admin-{}", uuid::Uuid::new_v4())).await
}

async fn make_store_at(dir: &TempDir, name: &str) -> DatabaseStore {
    let db_path = dir.path().join(format!("{name}.db"));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

/// A store whose *effective configured namespace* is not `ferrum`, mirroring a
/// deployment that set `FERRUM_NAMESPACE`. The value is applied through the
/// same startup setter `src/modes/database.rs` uses, so the protection path is
/// exercised without touching the process environment.
async fn make_store_serving(dir: &TempDir, namespace: &str) -> DatabaseStore {
    make_store_protecting(dir, &[namespace]).await
}

/// A store configured to serve several namespaces, mirroring a control plane
/// with `FERRUM_CP_NAMESPACES=a,b` (`CpScope::Set`). The set is applied through
/// the same startup setter `src/modes/control_plane.rs` uses, so protection is
/// exercised without touching the process environment.
async fn make_store_protecting(dir: &TempDir, namespaces: &[&str]) -> DatabaseStore {
    let mut store = make_store(dir).await;
    apply_protected_namespaces(&mut store, namespaces);
    store
}

fn apply_protected_namespaces(store: &mut DatabaseStore, namespaces: &[&str]) {
    let owned: Vec<String> = namespaces.iter().map(|name| name.to_string()).collect();
    store.set_protected_namespaces(&owned);
}

fn admin_state(db: DatabaseStore) -> AdminState {
    admin_state_from_arc(Arc::new(db))
}

fn admin_state_from_arc(db: Arc<dyn DatabaseBackend>) -> AdminState {
    AdminState {
        db: Some(db),
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

/// `admin_state_from_arc` with `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` on. The
/// registry routes are NOT selected by `X-Ferrum-Namespace`, so each handler
/// applies the claim to the path/body name itself.
fn claim_enforcing_state(db: Arc<dyn DatabaseBackend>) -> AdminState {
    AdminState {
        admin_require_namespace_claim: true,
        ..admin_state_from_arc(db)
    }
}

fn file_mode_state() -> AdminState {
    // Struct-update form, not `let mut config = Default::default()` + field
    // assignment: the latter is `clippy::field_reassign_with_default`.
    let config = GatewayConfig {
        known_namespaces: vec!["ferrum".to_string(), "file-only".to_string()],
        ..GatewayConfig::default()
    };
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(config)))),
        proxy_state: None,
        mode: "file".to_string(),
        read_only: true,
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
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr parses");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr)
        .await
        .expect("bind");
    let actual = listener.local_addr().expect("local addr");
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
            return (format!("http://{actual}"), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {actual} never became ready");
}

async fn send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("request succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn send_in_namespace(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    namespace: &str,
    body: Option<Value>,
) -> u16 {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Ferrum-Namespace", namespace);
    if let Some(body) = body {
        request = request.json(&body);
    }
    request
        .send()
        .await
        .expect("request succeeds")
        .status()
        .as_u16()
}

async fn seed_upstream(store: &DatabaseStore, namespace: &str, id: &str) {
    sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
        .bind(id)
        .bind(namespace)
        .bind(format!("{id}-name"))
        .execute(&store.pool())
        .await
        .unwrap();
}

async fn count_rows(store: &DatabaseStore, sql: &str, namespace: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .bind(namespace)
        .fetch_one(&store.pool())
        .await
        .unwrap()
}

async fn count_registry_rows(store: &DatabaseStore) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM namespaces")
        .fetch_one(&store.pool())
        .await
        .unwrap()
}

async fn registry_row_exists(store: &DatabaseStore, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM namespaces WHERE name = ?")
        .bind(name)
        .fetch_one(&store.pool())
        .await
        .unwrap()
        > 0
}

/// Drop the canonical `ferrum` registry row so a test can create an exact
/// two-namespace world. The one-time compatibility backfill seeds `ferrum` on
/// first connect; with no resources under it the name then genuinely no longer
/// exists, and a later reconnect must not resurrect it.
async fn drop_default_registry_row(store: &DatabaseStore) {
    sqlx::query("DELETE FROM namespaces WHERE name = 'ferrum'")
        .execute(&store.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn create_get_list_and_reject_duplicates_and_invalid_names() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "staging", "description": "pre-prod"})),
    )
    .await;
    assert_eq!(status, 201, "create empty tenant: {body:?}");
    assert_eq!(body["name"], "staging");
    assert_eq!(body["description"], "pre-prod");
    assert!(body["created_at"].as_str().is_some());
    assert!(body["updated_at"].as_str().is_some());

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/staging",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "get created tenant: {body:?}");
    assert_eq!(body["name"], "staging");
    assert_eq!(body["description"], "pre-prod");

    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &token, None).await;
    assert_eq!(status, 200);
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        names.contains(&"ferrum") && names.contains(&"staging"),
        "list stays string[] and includes registry names: {names:?}"
    );

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "staging"})),
    )
    .await;
    assert_eq!(status, 409, "duplicate registry name: {body:?}");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "bad name"})),
    )
    .await;
    assert_eq!(status, 400, "invalid name: {body:?}");

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "too-wordy", "description": over_limit})),
    )
    .await;
    assert_eq!(status, 400, "over-limit description on create: {body:?}");
    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/too-wordy",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "a rejected create must not persist anything");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "typed", "description": 5})),
    )
    .await;
    assert_eq!(status, 400, "wrong-typed description on create: {body:?}");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token_with_role("operator"),
        Some(json!({"name": "ops-denied"})),
    )
    .await;
    assert_eq!(status, 403, "operator cannot create: {body:?}");
}

#[tokio::test]
async fn update_rejects_malformed_fields_without_mutating() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant", "description": "keep me"})),
    )
    .await;
    assert_eq!(status, 201);

    // Every one of these is a 400 with nothing mutated. A non-string
    // `description` must NOT be read as "clear it".
    for body in [
        json!({"description": {}}),
        json!({"description": []}),
        json!({"description": 42}),
        json!({"description": true}),
        json!({"name": null}),
        json!({"name": 7}),
        json!({"name": ["other"]}),
        json!({"name": "bad name"}),
    ] {
        let (status, response) = send(
            reqwest::Method::PUT,
            &base,
            "/namespaces/tenant",
            &token,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, 400, "malformed update {body:?} -> {response:?}");
    }

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["description"], "keep me",
        "no rejected update may have touched the stored description"
    );

    // Omitted description leaves it alone; explicit null clears it.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant",
        &token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["description"], "keep me");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant",
        &token,
        Some(json!({"description": null})),
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert!(
        body.get("description").is_none() || body["description"].is_null(),
        "explicit null clears: {body:?}"
    );
}

#[tokio::test]
async fn update_description_respects_unicode_character_bounds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "unicode"})),
    )
    .await;
    assert_eq!(status, 201);

    // `maxLength` is Unicode scalar values: 1024 four-byte characters is over
    // 4 KiB of UTF-8 and must still be accepted.
    let at_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(at_limit.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": at_limit})),
    )
    .await;
    assert_eq!(status, 200, "multibyte description at the limit: {body:?}");
    assert_eq!(
        body["description"].as_str().unwrap().chars().count(),
        MAX_NAMESPACE_DESCRIPTION_CHARS
    );

    let over_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": over_limit})),
    )
    .await;
    assert_eq!(status, 400, "one character over the limit: {body:?}");

    // Trailing whitespace is trimmed before the length rule applies, so an
    // otherwise-at-limit value padded with spaces is still accepted.
    let padded = format!("  {}  ", "é".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS));
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": padded})),
    )
    .await;
    assert_eq!(
        status, 200,
        "trim happens before the length check: {body:?}"
    );
}

#[tokio::test]
async fn rename_moves_resources_and_rejects_target_collision() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();
    let labels = json!({"provisioned-by":"ferrum-foundry", "team":"platform"});

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant-a"})),
    )
    .await;
    assert_eq!(status, 201, "create tenant-a: {body:?}");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "tenant-a",
        Some(json!({
            "id": "up-a",
            "labels": labels.clone(),
            "name": "up-a-name",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201, "create upstream in tenant-a");

    for (path, mut body) in [
        ("/consumers", json!({"id":"consumer-a", "username":"alice"})),
        (
            "/proxies",
            json!({"id":"proxy-a", "listen_path":"/labels-rename", "backend_host":"example.com", "backend_port":80}),
        ),
        (
            "/plugins/config",
            json!({"id":"plugin-a", "plugin_name":"cors", "scope":"global", "enabled":false, "config":{}}),
        ),
    ] {
        body["labels"] = labels.clone();
        let status = send_in_namespace(
            reqwest::Method::POST,
            &base,
            path,
            &token,
            "tenant-a",
            Some(body),
        )
        .await;
        assert_eq!(status, 201, "create {path} in tenant-a");
    }

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        &token,
        Some(json!({"name": "tenant-b", "description": "moved"})),
    )
    .await;
    assert_eq!(status, 200, "rename: {body:?}");
    assert_eq!(body["name"], "tenant-b");
    assert_eq!(body["description"], "moved");

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-a",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "old name is gone: {body:?}");

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-b",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "new name exists: {body:?}");

    let (status, body) = send(reqwest::Method::GET, &base, "/upstreams/up-a", &token, None).await;
    // Default X-Ferrum-Namespace is ferrum; the moved upstream lives in tenant-b.
    assert_eq!(
        status, 404,
        "upstream is not in default namespace: {body:?}"
    );

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-a",
        &token,
        "tenant-b",
        None,
    )
    .await;
    assert_eq!(status, 200, "upstream moved with the tenant");

    for path in [
        "/upstreams/up-a",
        "/consumers/consumer-a",
        "/proxies/proxy-a",
        "/plugins/config/plugin-a",
    ] {
        let response = reqwest::Client::new()
            .get(format!("{base}{path}"))
            .bearer_auth(&token)
            .header("X-Ferrum-Namespace", "tenant-b")
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, 200, "{path}: {body:?}");
        assert_eq!(body["labels"], labels, "labels moved with {path}");
    }

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "taken"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-b",
        &token,
        Some(json!({"name": "taken"})),
    )
    .await;
    assert_eq!(status, 409, "rename onto an existing name: {body:?}");

    // The refused rename must have changed nothing on either side.
    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-b",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "source survives a refused rename");
    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-a",
        &token,
        "tenant-b",
        None,
    )
    .await;
    assert_eq!(status, 200, "resources survive a refused rename");
}

#[tokio::test]
async fn derived_only_namespace_can_be_renamed_and_described() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    // A namespace that exists ONLY because a resource was written under it —
    // no registry row at all. This is the pre-#3955 shape every existing
    // deployment has.
    seed_upstream(&store, "implicit", "up-implicit").await;
    assert!(!registry_row_exists(&store, "implicit").await);
    let store = Arc::new(store);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    // A description-only update materializes the registry row.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/implicit",
        &token,
        Some(json!({"description": "materialized"})),
    )
    .await;
    assert_eq!(status, 200, "derived-only description update: {body:?}");
    assert_eq!(body["description"], "materialized");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/implicit",
        &token,
        Some(json!({"name": "explicit"})),
    )
    .await;
    assert_eq!(status, 200, "derived-only rename: {body:?}");
    assert_eq!(body["name"], "explicit");
    assert_eq!(
        body["description"], "materialized",
        "an omitted description survives a rename"
    );

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-implicit",
        &token,
        "explicit",
        None,
    )
    .await;
    assert_eq!(status, 200, "resources moved with the derived tenant");

    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/implicit",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "old derived name is gone");
}

#[tokio::test]
async fn delete_empty_ok_non_empty_conflicts_unless_confirmed() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    seed_upstream(&store, "occupied", "up-occupied").await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "empty-tenant"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/empty-tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/empty-tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/occupied",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 409, "non-empty without confirm: {body:?}");

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-occupied",
        &token,
        "occupied",
        None,
    )
    .await;
    assert_eq!(status, 200, "a refused delete removes nothing");

    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/occupied?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "the effective configured namespace cannot be deleted: {body:?}"
    );
}

#[tokio::test]
async fn confirmed_cascade_removes_every_occupancy_and_ancillary_surface() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "doomed",
        Some(json!({
            "id": "up-doomed",
            "name": "up-doomed-name",
            "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201, "seed upstream");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/proxies",
        &token,
        "doomed",
        Some(json!({
            "id": "px-doomed",
            "listen_path": "/doomed",
            "backend_scheme": "http",
            "backend_host": "10.0.0.2",
            "backend_port": 8080,
            "strip_listen_path": true
        })),
    )
    .await;
    assert_eq!(status, 201, "seed proxy");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/consumers",
        &token,
        "doomed",
        Some(json!({"id": "cons-doomed", "username": "doomed-user", "credentials": {}})),
    )
    .await;
    assert_eq!(status, 201, "seed consumer");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/plugins/config",
        &token,
        "doomed",
        Some(json!({
            "id": "pl-doomed",
            "plugin_name": "correlation_id",
            "scope": "proxy",
            "proxy_id": "px-doomed",
            "config": {}
        })),
    )
    .await;
    assert_eq!(status, 201, "seed plugin config");

    // Surfaces with no admin write endpoint: seeded directly so the cascade is
    // proved against the real row shapes.
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO gateway_trust_bundles \
         (namespace, id, trust_domain, bundle, revision, updated_by, created_at, updated_at) \
         VALUES ('doomed', 'tb-doomed', 'doomed.local', '[]', 1, 'test', ?, ?)",
    )
    .bind(&now)
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO api_specs \
         (id, namespace, proxy_id, spec_version, spec_format, spec_content, content_encoding, \
          uncompressed_size, content_hash, tags, server_urls, operation_count, resource_hash, \
          created_at, updated_at) \
         VALUES ('spec-doomed', 'doomed', 'px-doomed', '3.0.0', 'json', X'00', 'gzip', 1, \
                 'hash', '[]', '[]', 0, '', ?, ?)",
    )
    .bind(&now)
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO proxy_route_locks (namespace, route_key_hash, created_at) \
         VALUES ('doomed', 'stale-bucket', ?)",
    )
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/doomed?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204, "confirmed cascade: {body:?}");

    for sql in [
        "SELECT COUNT(*) FROM proxies WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumers WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumer_identity_index WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumer_credential_index WHERE namespace = ?",
        "SELECT COUNT(*) FROM plugin_configs WHERE namespace = ?",
        "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
        "SELECT COUNT(*) FROM api_specs WHERE namespace = ?",
        "SELECT COUNT(*) FROM gateway_trust_bundles WHERE namespace = ?",
        "SELECT COUNT(*) FROM proxy_route_locks WHERE namespace = ?",
        "SELECT COUNT(*) FROM namespaces WHERE name = ?",
    ] {
        assert_eq!(
            count_rows(&store, sql, "doomed").await,
            0,
            "cascade must clear: {sql}"
        );
    }

    // Polling tombstones are deliberately RETAINED so a gateway serving the
    // deleted namespace converges instead of silently keeping stale config.
    assert!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM config_changes WHERE namespace = ? AND operation = 'delete'",
            "doomed",
        )
        .await
            > 0,
        "the cascade must leave delete tombstones for pollers"
    );

    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/doomed",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn effective_configured_namespace_is_protected_from_delete_and_rename() {
    let dir = TempDir::new().unwrap();
    // This gateway serves `tenant-prod`, NOT `ferrum`. The protection must
    // follow the resolved configuration, not the hardcoded default.
    let store = Arc::new(make_store_serving(&dir, "tenant-prod").await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant-prod", "description": "live"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/tenant-prod",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "configured namespace cannot be deleted: {body:?}"
    );

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-prod",
        &token,
        Some(json!({"name": "tenant-prod-renamed"})),
    )
    .await;
    assert_eq!(
        status, 409,
        "a rename is a removal of the old name: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "tenant-prod").await
            && !registry_row_exists(&store, "tenant-prod-renamed").await,
        "the refused rename must not have created the target"
    );

    // Description-only updates of the protected namespace stay allowed.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-prod",
        &token,
        Some(json!({"description": "still live"})),
    )
    .await;
    assert_eq!(status, 200, "description-only update is allowed: {body:?}");
    assert_eq!(body["description"], "still live");

    // `ferrum` is NOT this process's namespace, so it is an ordinary tenant.
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 204,
        "a non-configured `ferrum` is deletable: {body:?}"
    );
}

#[tokio::test]
async fn deleted_canonical_ferrum_is_not_resurrected_by_later_compatibility_pass() {
    let dir = TempDir::new().unwrap();
    let store_name = "ns-ferrum-not-resurrected";
    let store = Arc::new({
        let mut store = make_store_at(&dir, store_name).await;
        apply_protected_namespaces(&mut store, &["tenant-prod"]);
        store
    });
    let (base, shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant-prod"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 204,
        "a non-configured `ferrum` is deletable: {body:?}"
    );
    assert!(
        !registry_row_exists(store.as_ref(), "ferrum").await,
        "delete must have removed the canonical registry row"
    );

    let _ = shutdown.send(true);
    drop(store);

    let store = {
        let mut store = make_store_at(&dir, store_name).await;
        apply_protected_namespaces(&mut store, &["tenant-prod"]);
        store
    };
    assert!(
        registry_row_exists(&store, "tenant-prod").await,
        "the remaining registry row must survive reconnect"
    );
    assert!(
        !registry_row_exists(&store, "ferrum").await,
        "a later connect/migrate compatibility pass must not resurrect deleted ferrum"
    );
    let listed = store.list_namespaces().await.unwrap();
    assert!(
        !listed.iter().any(|item| item == "ferrum"),
        "GET /namespaces must not resurrect deleted ferrum: {listed:?}"
    );
}

#[tokio::test]
async fn concurrent_deletes_cannot_remove_the_last_namespace() {
    let dir = TempDir::new().unwrap();
    // No namespace of this name exists, so neither `alpha` nor `beta` is
    // protected as the configured namespace and the last-remaining invariant
    // is the only thing standing between the two deletes and an empty world.
    let store = Arc::new(make_store_serving(&dir, "not-present").await);
    drop_default_registry_row(&store).await;
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    for name in ["alpha", "beta"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &token,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    let (base_a, base_b) = (base.clone(), base.clone());
    let (token_a, token_b) = (token.clone(), token.clone());
    let first = tokio::spawn(async move {
        send(
            reqwest::Method::DELETE,
            &base_a,
            "/namespaces/alpha",
            &token_a,
            None,
        )
        .await
    });
    let second = tokio::spawn(async move {
        send(
            reqwest::Method::DELETE,
            &base_b,
            "/namespaces/beta",
            &token_b,
            None,
        )
        .await
    });
    let (first, second) = (first.await.unwrap(), second.await.unwrap());

    let statuses = [first.0, second.0];
    assert!(
        statuses.contains(&204),
        "exactly one delete should succeed: {statuses:?}"
    );
    assert!(
        statuses.contains(&409),
        "the other must be refused as the last remaining namespace: {statuses:?} \
         ({:?} / {:?})",
        first.1,
        second.1
    );

    assert_eq!(
        count_registry_rows(&store).await,
        1,
        "the registry must never be emptied by concurrent deletes"
    );
}

#[tokio::test]
async fn a_late_transaction_failure_rolls_the_whole_tenant_back() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "rollback",
        Some(json!({
            "id": "up-rollback",
            "name": "up-rollback-name",
            "targets": [{"host": "10.0.0.3", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/rollback",
        &token,
        Some(json!({"description": "registered"})),
    )
    .await;
    assert_eq!(status, 200);

    // Trip AFTER the resource rows, the guard rows, and the registry row have
    // all been written inside the transaction. A happy-path test can never
    // reach this step.
    set_namespace_registry_fault_for_test(
        "rollback",
        Some(NamespaceRegistryPhase::LastNamespaceCheck),
    );
    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/rollback?confirm=true",
        &token,
        None,
    )
    .await;
    set_namespace_registry_fault_for_test("rollback", None);
    assert_eq!(status, 500, "an injected late failure is a server error");

    assert!(
        registry_row_exists(&store, "rollback").await,
        "the registry row must be rolled back"
    );
    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "rollback"
        )
        .await,
        1,
        "cascade-deleted resources must be rolled back"
    );

    // Without the fault the same request succeeds, proving the rollback was
    // the fault and not a broken code path.
    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/rollback?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(!registry_row_exists(&store, "rollback").await);
}

#[tokio::test]
async fn a_lost_admission_lease_fails_closed_at_the_commit_boundary() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "leased"})),
    )
    .await;
    assert_eq!(status, 201);

    // Handler path: a lease reported lost at the commit gate is the retryable
    // fail-closed 503, and nothing is deleted.
    set_namespace_registry_fault_for_test("leased", Some(NamespaceRegistryPhase::LeaseLost));
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/leased",
        &token,
        None,
    )
    .await;
    set_namespace_registry_fault_for_test("leased", None);
    assert_eq!(status, 503, "lost lease is retryable: {body:?}");
    assert_eq!(body["rollback"], "not_needed");
    assert!(registry_row_exists(&store, "leased").await);

    // Backend path with a REAL but wrong lease identity: the commit-boundary
    // re-verification must refuse it even though the caller holds the local
    // guards, and nothing may become durable.
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["leased"])
        .await
        .expect("registry admission");
    let mut holds = admission.holds();
    // Corrupt exactly the affected namespace's lease, leaving the global
    // registry lease genuinely held.
    let stolen = NamespaceAdmissionLeaseHold {
        key: "leased",
        lease: NamespaceConfigAdmissionLeaseRef {
            owner: "some-other-writer",
            generation: 1,
        },
    };
    for hold in holds.iter_mut() {
        if hold.key == "leased" {
            *hold = stolen;
        }
    }
    let error = store
        .delete_namespace("leased", true, &holds)
        .await
        .expect_err("a stolen lease must abort the commit");
    assert!(
        ferrum_edge::config::db_backend::is_batch_admission_lease_lost(&error),
        "expected a typed lease-lost error, got: {error}"
    );
    drop(admission);
    assert!(
        registry_row_exists(&store, "leased").await,
        "an unverified write must never become durable"
    );
}

#[tokio::test]
async fn file_mode_writes_are_forbidden() {
    let (base, _shutdown) = start_admin(file_mode_state()).await;
    let token = admin_token();

    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &token, None).await;
    assert_eq!(status, 200);
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(names, ["ferrum", "file-only"]);

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/file-only",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["name"], "file-only");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "new-file-ns"})),
    )
    .await;
    assert_eq!(status, 403, "file-mode create: {body:?}");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/file-only",
        &token,
        Some(json!({"description": "nope"})),
    )
    .await;
    assert_eq!(status, 403, "file-mode update: {body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/file-only",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 403, "file-mode delete: {body:?}");
}

#[tokio::test]
async fn store_create_rename_delete_round_trip() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let now = Utc::now();
    let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
        "direct".to_string(),
        Some("via store".to_string()),
        now,
    );

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["direct"])
        .await
        .expect("registry admission");
    store
        .create_namespace(&record, &admission.holds())
        .await
        .unwrap();
    drop(admission);
    assert!(store.namespace_name_in_use("direct").await.unwrap());
    assert!(!store.namespace_has_resources("direct").await.unwrap());

    seed_upstream(&store, "direct", "up-direct").await;
    assert!(store.namespace_has_resources("direct").await.unwrap());

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["direct", "renamed"])
        .await
        .expect("registry admission");
    let updated = store
        .update_namespace(
            "direct",
            "renamed",
            Some(Some("moved".into())),
            &admission.holds(),
        )
        .await
        .unwrap();
    drop(admission);
    assert_eq!(updated.name, "renamed");
    assert!(!store.namespace_name_in_use("direct").await.unwrap());
    assert!(store.namespace_name_in_use("renamed").await.unwrap());

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["renamed"])
        .await
        .expect("registry admission");
    let err = store
        .delete_namespace("renamed", false, &admission.holds())
        .await
        .unwrap_err();
    assert!(
        ferrum_edge::config::namespace_registry::is_namespace_registry_error(&err).is_some(),
        "unconfirmed occupied delete is a typed 409: {err}"
    );
    assert!(
        store
            .delete_namespace("renamed", true, &admission.holds())
            .await
            .unwrap()
    );
    drop(admission);
    assert!(!store.namespace_name_in_use("renamed").await.unwrap());
}

#[tokio::test]
async fn namespace_rename_moves_historical_audit_namespace() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let now = Utc::now();
    let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
        "hist-a".to_string(),
        None,
        now,
    );

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["hist-a"])
        .await
        .expect("registry admission");
    store
        .create_namespace(&record, &admission.holds())
        .await
        .unwrap();
    drop(admission);

    seed_upstream(&store, "hist-a", "up-hist").await;
    store
        .insert_audit_event(&AuditEvent {
            id: "hist-event-1".to_string(),
            ts: now,
            actor: "namespace-admin".to_string(),
            action: "update".to_string(),
            resource_type: "upstream".to_string(),
            resource_id: "up-hist".to_string(),
            namespace: "hist-a".to_string(),
            namespace_at_event: "hist-a".to_string(),
            source_address: String::new(),
            request_id: String::new(),
            outcome: "success".to_string(),
            diff: json!({ "after": { "id": "up-hist" } }),
        })
        .await
        .unwrap();

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["hist-a", "hist-b"])
        .await
        .expect("registry admission");
    store
        .update_namespace("hist-a", "hist-b", None, &admission.holds())
        .await
        .unwrap();
    drop(admission);

    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "hist-a"
        )
        .await,
        0,
        "live resource rows must move with the tenant"
    );
    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "hist-b"
        )
        .await,
        1,
        "live resource rows must land under the new name"
    );

    let historical = store
        .list_audit_events(
            "hist-a",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        historical.total, 0,
        "old namespace must not expose the renamed tenant's audit history"
    );

    let renamed = store
        .list_audit_events(
            "hist-b",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        renamed.total, 1,
        "historical audit_events must follow the renamed tenant"
    );
    assert_eq!(renamed.items[0].id, "hist-event-1");
    assert_eq!(renamed.items[0].namespace, "hist-b");
    assert_eq!(
        renamed.items[0].namespace_at_event, "hist-a",
        "namespace_at_event must keep the namespace recorded when the event was written"
    );
}

#[tokio::test]
async fn last_registry_row_cannot_disappear_behind_a_derived_only_name() {
    // Race this invariant prevents: delete registered A while derived-only B
    // still has one resource; concurrently ordinary DELETE removes B's last
    // resource. If last-remaining counted the GET union, A's delete would
    // observe B and commit, then B's resource delete would leave zero names.
    // Registry-row authority cannot race with writers outside the global lease.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store_serving(&dir, "not-present").await);
    drop_default_registry_row(&store).await;
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(status, 201, "create the sole registry row: {body:?}");
    seed_upstream(&store, "ghost", "up-ghost").await;
    assert!(
        !registry_row_exists(&store, "ghost").await,
        "ordinary resource writes must not insert a registry row"
    );

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces?limit=100",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        names.contains(&"alpha") && names.contains(&"ghost"),
        "GET remains registry ∪ derived names: {body:?}"
    );

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/alpha",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "the last registry row must survive even while a derived-only name has \
         resources: {body:?}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("last remaining"),
        "typed last-remaining refusal: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "alpha").await,
        "the last registry row must still be durable"
    );
}

#[tokio::test]
async fn namespace_rename_fails_closed_on_a_target_mtls_dns_restore_fence() {
    // `alpha` sorts before `zeta`, so a rename zeta→alpha locks the target
    // first. A restore owner on alpha must reject the rename. Locking only
    // the source would write resources into the fenced target.
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store.clone())).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "zeta" })),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    sqlx::query(
        "INSERT INTO mtls_dns_admission_locks (namespace, updated_at, restore_owner) \
         VALUES (?, ?, ?)",
    )
    .bind("alpha")
    .bind(Utc::now().to_rfc3339())
    .bind("restore-owner-uuid")
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/zeta",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(
        status, 503,
        "target restore fence must fail closed: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "zeta").await && !registry_row_exists(&store, "alpha").await,
        "the refused rename must not have created the target"
    );
}

#[tokio::test]
async fn namespace_rename_fails_closed_on_a_source_mtls_dns_restore_fence() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store.clone())).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    sqlx::query(
        "INSERT INTO mtls_dns_admission_locks (namespace, updated_at, restore_owner) \
         VALUES (?, ?, ?)",
    )
    .bind("alpha")
    .bind(Utc::now().to_rfc3339())
    .bind("restore-owner-uuid")
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/alpha",
        &token,
        Some(json!({ "name": "zeta" })),
    )
    .await;
    assert_eq!(
        status, 503,
        "source restore fence must fail closed: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "alpha").await && !registry_row_exists(&store, "zeta").await,
        "the refused rename must not have created the target"
    );
}

#[tokio::test]
async fn update_rejects_empty_or_non_object_bodies() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();
    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "tenant", "description": "keep" })),
    )
    .await;
    assert_eq!(status, 201);

    for raw in ["", "null", "[]", "42", "\"tenant\""] {
        let response = reqwest::Client::new()
            .request(reqwest::Method::PUT, format!("{base}/namespaces/tenant"))
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .body(raw.to_string())
            .send()
            .await
            .expect("request succeeds");
        assert_eq!(
            response.status().as_u16(),
            400,
            "non-object PUT body {raw:?} must be 400"
        );
    }

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["description"], "keep");
}

#[tokio::test]
async fn corrupt_registry_row_is_not_served_as_plausible_detail() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    sqlx::query("UPDATE namespaces SET created_at = 'not-a-timestamp' WHERE name = 'ferrum'")
        .execute(&store.pool())
        .await
        .unwrap();
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 500, "corrupt timestamps must fail closed: {body:?}");
    let error = body["error"].as_str().unwrap_or("");
    assert!(
        error.contains(ferrum_edge::config::namespace_registry::NamespaceRegistryCorrupt::MESSAGE),
        "client must see the static corrupt message: {body:?}"
    );
    assert!(
        !error.contains("not-a-timestamp") && !error.contains("ferrum"),
        "raw corrupt values must not be echoed: {body:?}"
    );
}

// ── Protected namespace set (issue #3955 review) ────────────────────────────

async fn clear_backfill_marker(store: &DatabaseStore) {
    sqlx::query("DELETE FROM _ferrum_schema_compat WHERE name = ?")
        .bind(ferrum_edge::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID)
        .execute(&store.pool())
        .await
        .unwrap();
}

async fn backfill_marker_present(store: &DatabaseStore) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _ferrum_schema_compat WHERE name = ?")
        .bind(ferrum_edge::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID)
        .fetch_one(&store.pool())
        .await
        .unwrap()
        > 0
}

/// Free the global registry admission key deterministically.
///
/// Admin handlers release their lease from a `Drop`-spawned task, so a test
/// that must observe the NEXT startup taking that key cannot depend on when
/// that task happens to run. Expiring the row is exactly what the lease's own
/// release statement does, and it needs no sleep or poll.
async fn expire_global_registry_lease(store: &DatabaseStore) {
    sqlx::query("UPDATE config_admission_locks SET expires_at = 0 WHERE namespace = ?")
        .bind(ferrum_edge::config::namespace_registry::NAMESPACE_REGISTRY_ADMISSION_KEY)
        .execute(&store.pool())
        .await
        .unwrap();
}

fn protected_reason_is_static(body: &Value) {
    use ferrum_edge::config::namespace_registry::NamespaceRegistryError as RegistryError;
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(RegistryError::PROTECTED_CONFIGURED_NAMESPACE),
        "the 409 must carry the fixed protected reason: {body:?}"
    );
}

/// `FERRUM_CP_NAMESPACES=tenant-a,tenant-b` resolves to `CpScope::Set`, and the
/// CP keeps polling BOTH names for the life of the process. Deleting or
/// renaming either one away would leave the control plane polling a namespace
/// that no longer exists and its DPs converging to empty configuration, so
/// every explicitly configured name is protected — not only `FERRUM_NAMESPACE`.
#[tokio::test]
async fn cp_scope_set_protects_every_explicitly_configured_namespace() {
    let dir = TempDir::new().unwrap();
    // `reserved` is configured but has never been created — protection guards
    // REMOVAL of a configured name, it does not reserve the name as a target.
    let store = Arc::new(
        make_store_protecting(&dir, &["tenant-a", "tenant-b", "ferrum", "reserved"]).await,
    );
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    for name in ["tenant-a", "tenant-b", "spare", "spare-two"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &token,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    for name in ["tenant-a", "tenant-b", "ferrum"] {
        let (status, body) = send(
            reqwest::Method::DELETE,
            &base,
            &format!("/namespaces/{name}"),
            &token,
            None,
        )
        .await;
        assert_eq!(
            status, 409,
            "{name} must be protected from delete: {body:?}"
        );
        protected_reason_is_static(&body);
        assert!(
            registry_row_exists(store.as_ref(), name).await,
            "{name} must still exist after a refused delete"
        );

        let (status, body) = send(
            reqwest::Method::PUT,
            &base,
            &format!("/namespaces/{name}"),
            &token,
            Some(json!({ "name": format!("{name}-renamed") })),
        )
        .await;
        assert_eq!(
            status, 409,
            "{name} must be protected from rename-away: {body:?}"
        );
        protected_reason_is_static(&body);
        assert!(
            !registry_row_exists(store.as_ref(), &format!("{name}-renamed")).await,
            "a refused rename must not materialize the target name"
        );

        // Description-only updates stay allowed for a protected namespace.
        let (status, body) = send(
            reqwest::Method::PUT,
            &base,
            &format!("/namespaces/{name}"),
            &token,
            Some(json!({ "description": "still editable" })),
        )
        .await;
        assert_eq!(
            status, 200,
            "a description-only update of {name} must stay allowed: {body:?}"
        );
        assert_eq!(body["description"], "still editable");
        assert_eq!(body["name"], name);
    }

    // Target-name creation semantics are unchanged: renaming INTO a configured
    // but currently vacant name is allowed, exactly as `POST /namespaces` for
    // that name would be.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/spare",
        &token,
        Some(json!({ "name": "reserved" })),
    )
    .await;
    assert_eq!(
        status, 200,
        "renaming into a configured but vacant name stays allowed: {body:?}"
    );
    assert_eq!(body["name"], "reserved");

    // ...and once it exists under that configured name, it is protected.
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/reserved",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "a configured name is protected once it exists: {body:?}"
    );
    protected_reason_is_static(&body);

    // An unconfigured tenant is still fully removable.
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/spare-two",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 204,
        "an unconfigured tenant deletes freely: {body:?}"
    );
}

/// `FERRUM_CP_NAMESPACES=*` (`CpScope::All`) discovers namespaces dynamically,
/// so it must NOT freeze every discovered name. Only `FERRUM_NAMESPACE` is
/// protected; every other tenant stays removable.
#[tokio::test]
async fn cp_scope_all_protects_only_the_configured_default_namespace() {
    let dir = TempDir::new().unwrap();
    // What `src/modes/control_plane.rs` computes for `CpScope::All`:
    // `explicit_namespaces()` is `None`, so the set is FERRUM_NAMESPACE alone.
    let store = Arc::new(make_store_protecting(&dir, &["tenant-home"]).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    for name in ["tenant-home", "discovered-a", "discovered-b"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &token,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/tenant-home",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 409, "FERRUM_NAMESPACE stays protected: {body:?}");
    protected_reason_is_static(&body);

    for name in ["discovered-a", "discovered-b"] {
        let (status, body) = send(
            reqwest::Method::PUT,
            &base,
            &format!("/namespaces/{name}"),
            &token,
            Some(json!({ "name": format!("{name}-moved") })),
        )
        .await;
        assert_eq!(
            status, 200,
            "a dynamically discovered namespace stays renamable under CpScope::All: {body:?}"
        );
        let (status, body) = send(
            reqwest::Method::DELETE,
            &base,
            &format!("/namespaces/{name}-moved"),
            &token,
            None,
        )
        .await;
        assert_eq!(
            status, 204,
            "a dynamically discovered namespace stays deletable under CpScope::All: {body:?}"
        );
    }
}

/// The handler precheck is only a better message. The same predicate must hold
/// inside the committing SQL transaction, so a caller that reaches the backend
/// directly — a different admin surface, or a racing request that passed the
/// precheck before the store was configured — still cannot remove a configured
/// namespace.
#[tokio::test]
async fn sql_backend_refuses_protected_namespaces_without_the_handler_precheck() {
    let dir = TempDir::new().unwrap();
    let store: Arc<dyn DatabaseBackend> =
        Arc::new(make_store_protecting(&dir, &["tenant-a", "tenant-b"]).await);

    for name in ["tenant-a", "tenant-b"] {
        let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
            name.to_string(),
            None,
            Utc::now(),
        );
        let admission = lock_namespace_registry_admission_for_test(store.clone(), &[name])
            .await
            .expect("registry admission");
        store
            .create_namespace(&record, &admission.holds())
            .await
            .expect("create");
        drop(admission);
    }

    for name in ["tenant-a", "tenant-b"] {
        let admission = lock_namespace_registry_admission_for_test(store.clone(), &[name])
            .await
            .expect("registry admission");
        let error = store
            .delete_namespace(name, true, &admission.holds())
            .await
            .expect_err("the backend itself must refuse a configured namespace");
        let registry_error =
            ferrum_edge::config::namespace_registry::is_namespace_registry_error(&error)
                .expect("typed registry error");
        assert!(
            matches!(
                registry_error,
                ferrum_edge::config::namespace_registry::NamespaceRegistryError::Protected { .. }
            ),
            "expected a typed protection refusal, got {error}"
        );
        drop(admission);

        let renamed = format!("{name}-renamed");
        let admission =
            lock_namespace_registry_admission_for_test(store.clone(), &[name, renamed.as_str()])
                .await
                .expect("registry admission");
        let error = store
            .update_namespace(name, &renamed, None, &admission.holds())
            .await
            .expect_err("the backend itself must refuse a rename-away");
        assert!(
            ferrum_edge::config::namespace_registry::is_namespace_registry_error(&error).is_some(),
            "expected a typed protection refusal, got {error}"
        );
        drop(admission);
    }

    // Nothing was mutated by either refusal.
    for name in ["tenant-a", "tenant-b"] {
        assert!(store.get_namespace(name).await.unwrap().is_some());
        assert!(
            store
                .get_namespace(&format!("{name}-renamed"))
                .await
                .unwrap()
                .is_none()
        );
    }
}

// ── One-time compatibility backfill serialization (issue #3955 review) ──────

/// The compatibility pass takes the SAME global registry admission lease every
/// live create/rename/delete takes. While that lease is held elsewhere the pass
/// must defer instead of reading derived names next to a concurrent mutation —
/// and it must leave the completion marker absent so a later startup retries.
#[tokio::test]
async fn namespace_registry_backfill_defers_while_the_global_registry_lease_is_held() {
    let dir = TempDir::new().unwrap();
    let store_name = "ns-backfill-deferred";
    let store: Arc<dyn DatabaseBackend> = Arc::new(make_store_at(&dir, store_name).await);

    // A derived-only tenant the next compatibility pass would seed.
    {
        let sql_store = make_store_at(&dir, store_name).await;
        seed_upstream(&sql_store, "derived-tenant", "up-derived").await;
        clear_backfill_marker(&sql_store).await;
        assert!(!registry_row_exists(&sql_store, "derived-tenant").await);
    }

    // Hold the global registry key exactly the way a live mutation does.
    let admission = lock_namespace_registry_admission_for_test(store.clone(), &["derived-tenant"])
        .await
        .expect("registry admission");

    let contended = make_store_at(&dir, store_name).await;
    assert!(
        !registry_row_exists(&contended, "derived-tenant").await,
        "the compatibility pass must not seed while the global registry lease is held elsewhere"
    );
    assert!(
        !backfill_marker_present(&contended).await,
        "a deferred pass must leave the completion marker absent so a later startup retries"
    );
    drop(admission);
}

/// A pass that crashed before recording completion leaves the marker absent, so
/// the next startup retries the same idempotent inserts — and a namespace that
/// was deliberately deleted in between is NOT resurrected, because it is no
/// longer a derived name.
#[tokio::test]
async fn namespace_registry_backfill_retries_after_a_crash_without_resurrecting_deletes() {
    let dir = TempDir::new().unwrap();
    let store_name = "ns-backfill-crash-retry";
    let store = Arc::new({
        let mut store = make_store_at(&dir, store_name).await;
        apply_protected_namespaces(&mut store, &["keeper"]);
        store
    });
    let (base, shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    for name in ["keeper", "doomed"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &token,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/doomed",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204, "delete an empty tenant: {body:?}");
    assert!(!registry_row_exists(store.as_ref(), "doomed").await);

    // Simulate a compatibility pass that crashed before its marker landed, and
    // a derived-only tenant that only the retry can materialize.
    seed_upstream(store.as_ref(), "late-derived", "up-late").await;
    clear_backfill_marker(store.as_ref()).await;
    // The DELETE handler releases its admission lease from a Drop-spawned task;
    // expire the global key outright so the reconnect below deterministically
    // acquires it instead of racing that task.
    expire_global_registry_lease(store.as_ref()).await;
    let _ = shutdown.send(true);
    drop(store);

    let retried = make_store_at(&dir, store_name).await;
    assert!(
        backfill_marker_present(&retried).await,
        "the retry must record completion"
    );
    assert!(
        registry_row_exists(&retried, "late-derived").await,
        "the retry must seed pre-existing derived names"
    );
    assert!(
        registry_row_exists(&retried, "keeper").await,
        "an existing registry row survives the retry"
    );
    assert!(
        !registry_row_exists(&retried, "doomed").await,
        "a deleted namespace must not be resurrected by a later compatibility pass"
    );
}

/// Backfill-then-delete: once the pass has materialized a derived name, an
/// ordinary confirmed delete removes it for good and no later pass brings it
/// back (the completion marker is durable, and the name is no longer derived).
#[tokio::test]
async fn namespace_registry_backfill_then_delete_is_not_undone_by_a_later_pass() {
    let dir = TempDir::new().unwrap();
    let store_name = "ns-backfill-then-delete";
    let store = Arc::new({
        let mut store = make_store_at(&dir, store_name).await;
        apply_protected_namespaces(&mut store, &["anchor"]);
        store
    });
    seed_upstream(store.as_ref(), "seeded-tenant", "up-seeded").await;
    clear_backfill_marker(store.as_ref()).await;
    drop(store);

    let store = Arc::new({
        let mut store = make_store_at(&dir, store_name).await;
        apply_protected_namespaces(&mut store, &["anchor"]);
        store
    });
    assert!(
        registry_row_exists(store.as_ref(), "seeded-tenant").await,
        "the compatibility pass must materialize the derived name"
    );
    let (base, shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "anchor" })),
    )
    .await;
    assert_eq!(status, 201, "keep a second registry row: {body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/seeded-tenant?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204, "confirmed cascade delete: {body:?}");
    assert!(!registry_row_exists(store.as_ref(), "seeded-tenant").await);

    let _ = shutdown.send(true);
    drop(store);

    let reconnected = make_store_at(&dir, store_name).await;
    assert!(
        !registry_row_exists(&reconnected, "seeded-tenant").await,
        "a later compatibility pass must not resurrect a confirmed delete"
    );
    let listed = reconnected.list_namespaces().await.unwrap();
    assert!(
        !listed.iter().any(|item| item == "seeded-tenant"),
        "GET /namespaces must not resurrect a confirmed delete: {listed:?}"
    );
}

/// The compatibility pass verifies AND locks the global registry lease row as
/// the FIRST statement of its transaction, at the generation it just acquired.
///
/// A predecessor that crashed leaves an expired lease row behind at some
/// earlier generation. Acquisition steals it and bumps `generation`; the
/// start-of-pass pin must verify that NEW generation against the database's own
/// clock. A pin bound to the wrong generation, or one whose placeholders are
/// mis-ordered for the dialect, would defer every pass forever and never seed.
/// Fully deterministic: the stale row is written directly, with no sleep and no
/// timing race.
#[tokio::test]
async fn namespace_registry_backfill_pins_the_lease_generation_it_acquired() {
    let dir = TempDir::new().unwrap();
    let store_name = "ns-backfill-lease-pin";
    let registry_key = ferrum_edge::config::namespace_registry::NAMESPACE_REGISTRY_ADMISSION_KEY;
    {
        let store = make_store_at(&dir, store_name).await;
        seed_upstream(&store, "pinned-tenant", "up-pinned").await;
        clear_backfill_marker(&store).await;
        sqlx::query(
            "INSERT INTO config_admission_locks (namespace, owner, expires_at, generation) \
             VALUES (?, 'crashed-predecessor', 0, 7) \
             ON CONFLICT (namespace) DO UPDATE SET \
             owner = 'crashed-predecessor', expires_at = 0, generation = 7",
        )
        .bind(registry_key)
        .execute(&store.pool())
        .await
        .unwrap();
    }

    let retried = make_store_at(&dir, store_name).await;
    assert!(
        backfill_marker_present(&retried).await,
        "a pass that stole an expired lease must still commit"
    );
    assert!(
        registry_row_exists(&retried, "pinned-tenant").await,
        "the derived name must be seeded under the newly acquired generation"
    );
    let generation = sqlx::query_scalar::<_, i64>(
        "SELECT generation FROM config_admission_locks WHERE namespace = ?",
    )
    .bind(registry_key)
    .fetch_one(&retried.pool())
    .await
    .unwrap();
    assert!(
        generation > 7,
        "stealing an expired lease must bump the generation the pin verifies: {generation}"
    );
}

/// A database that aborts the committing transaction as a serialization
/// failure or deadlock victim (PostgreSQL `40001` / `40P01`, or MySQL's `40001`
/// deadlock victim) committed nothing, so the endpoint must answer the
/// documented retryable `503` — not a `500`.
///
/// The real abort needs two racing PostgreSQL transactions plus the independent
/// 30-second admission renewer, which no deterministic test can stage. This
/// drives the already-classified typed conflict through the same commit-boundary
/// gate the real abort surfaces at; the SQLSTATE classification itself is
/// covered by `tests/unit/config/db_loader_tests.rs`.
#[tokio::test]
async fn a_database_aborted_transaction_is_a_retryable_503_not_a_500() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "conflicted", "description": "before"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    for (method, path, payload) in [
        (
            reqwest::Method::DELETE,
            "/namespaces/conflicted".to_string(),
            None,
        ),
        (
            reqwest::Method::PUT,
            "/namespaces/conflicted".to_string(),
            Some(json!({"name": "conflicted-renamed"})),
        ),
    ] {
        set_namespace_registry_fault_for_test(
            "conflicted",
            Some(NamespaceRegistryPhase::TransactionConflict),
        );
        let mut request = reqwest::Client::new()
            .request(method.clone(), format!("{base}{path}"))
            .bearer_auth(&token);
        if let Some(payload) = &payload {
            request = request.json(payload);
        }
        let response = request.send().await.expect("request succeeds");
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
        set_namespace_registry_fault_for_test("conflicted", None);

        assert_eq!(
            status, 503,
            "{method} must report a database-aborted transaction as retryable: {body:?}"
        );
        assert_eq!(
            retry_after.as_deref(),
            Some("1"),
            "{method} must carry Retry-After: 1"
        );
        assert_eq!(
            body["rollback"], "not_needed",
            "{method} aborted before commit, so there is nothing to roll back"
        );
        assert_eq!(
            body["error"],
            ferrum_edge::config::namespace_registry::NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE,
            "{method} must return the fixed redacted message"
        );

        // Redaction: no SQLSTATE, driver text, relation name, or statement.
        let rendered = body.to_string();
        for leak in [
            "40001",
            "40P01",
            "SQLSTATE",
            "config_admission_locks",
            "FOR UPDATE",
            "serialization",
            "deadlock",
        ] {
            assert!(
                !rendered.contains(leak),
                "the {method} response leaked driver/schema detail ({leak}): {rendered}"
            );
        }
    }

    // Nothing was applied by either refusal.
    assert!(registry_row_exists(&store, "conflicted").await);
    assert!(!registry_row_exists(&store, "conflicted-renamed").await);
    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/conflicted",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["description"], "before");
}

#[tokio::test]
async fn namespace_claim_gate_filters_the_list_and_denies_unclaimed_names() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(claim_enforcing_state(store.clone())).await;
    let broad = admin_token_with_ns(json!(["tenant-a", "tenant-b"]));
    let narrow = admin_token_with_ns(json!("tenant-b"));
    let no_claim = admin_token();

    for name in ["tenant-a", "tenant-b"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &broad,
            Some(json!({"name": name})),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    // The list is a global surface, so it is FILTERED to the claim, never 403.
    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &narrow, None).await;
    assert_eq!(status, 200, "claim-filtered list: {body:?}");
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(names, ["tenant-b"], "list must be filtered to the ns claim");

    // A token with no `ns` claim sees an empty list rather than every tenant.
    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &no_claim, None).await;
    assert_eq!(status, 200, "no-claim list is empty, not 403: {body:?}");
    assert!(
        body["data"].as_array().unwrap().is_empty(),
        "a token with no ns claim must not see any registry name: {body:?}"
    );

    // Per-name routes deny a name the token cannot address.
    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-a",
        &narrow,
        None,
    )
    .await;
    assert_eq!(status, 403, "GET of an unclaimed name: {body:?}");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &narrow,
        Some(json!({"name": "tenant-c"})),
    )
    .await;
    assert_eq!(status, 403, "create of an unclaimed name: {body:?}");
    assert!(
        !registry_row_exists(&store, "tenant-c").await,
        "a denied create must not persist anything"
    );

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/tenant-a",
        &narrow,
        None,
    )
    .await;
    assert_eq!(status, 403, "delete of an unclaimed name: {body:?}");
    assert!(
        registry_row_exists(&store, "tenant-a").await,
        "a denied delete must not remove the row"
    );
}

#[tokio::test]
async fn namespace_rename_requires_the_claim_for_the_target_name_too() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(claim_enforcing_state(store.clone())).await;
    let broad = admin_token_with_ns(json!(["tenant-a", "tenant-b"]));
    let source_only = admin_token_with_ns(json!("tenant-a"));

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &broad,
        Some(json!({"name": "tenant-a"})),
    )
    .await;
    assert_eq!(status, 201, "create the source tenant: {body:?}");

    // Authorized for the current name only. A rename moves the whole tenant
    // into a namespace this token may not address, so it must be refused.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        &source_only,
        Some(json!({"name": "tenant-b"})),
    )
    .await;
    assert_eq!(status, 403, "rename must also check the target: {body:?}");
    assert!(
        registry_row_exists(&store, "tenant-a").await,
        "a denied rename must leave the source row in place"
    );
    assert!(
        !registry_row_exists(&store, "tenant-b").await,
        "a denied rename must not materialize the target row"
    );

    // A description-only update of the claimed name stays allowed.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        &source_only,
        Some(json!({"description": "still mine"})),
    )
    .await;
    assert_eq!(status, 200, "description-only update: {body:?}");
    assert_eq!(body["description"], "still mine");

    // With both names claimed the rename is admitted.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        &broad,
        Some(json!({"name": "tenant-b"})),
    )
    .await;
    assert_eq!(status, 200, "rename with both names claimed: {body:?}");
    assert_eq!(body["name"], "tenant-b");
    assert!(!registry_row_exists(&store, "tenant-a").await);
    assert!(registry_row_exists(&store, "tenant-b").await);
}
