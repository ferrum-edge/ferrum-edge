//! Regression tests for SQL proxy/plugin association loading.
//!
//! Proxy/plugin associations carry security and policy plugins. SQL loaders
//! must fail closed when the junction-table query or row decoding fails, and
//! admin reads must not serialize incomplete association graphs.

use crate::scaffolding::port_registry::TestSocket;

use chrono::Utc;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("proxy_plugin_assoc_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

async fn seed_proxy_with_plugin(store: &DatabaseStore) {
    let pool = store.pool();
    let ts = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES (?, 'ferrum', 'edge', '[\"example.com\"]', '/', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy insert must succeed");

    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-1")
    .bind(r#"{"key_location":"header:X-API-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("plugin insert must succeed");

    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-1")
    .execute(&pool)
    .await
    .expect("association insert must succeed");

    sqlx::query(
        "INSERT INTO config_changes (namespace, resource_type, resource_id, operation, created_at) \
         VALUES ('ferrum', 'plugin_config', 'plugin-1', 'upsert', ?), \
                ('ferrum', 'proxy', 'proxy-1', 'upsert', ?)",
    )
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("change-log seed must succeed");
}

/// Inject the pre-#4627 corrupt shape: a proxy-scoped plugin config in
/// namespace `other` pointing at `ferrum`'s `proxy-1`, plus a junction row
/// binding them.
///
/// The composite foreign keys `(namespace, proxy_id) -> proxies(namespace, id)`
/// and `(namespace, plugin_config_id) -> plugin_configs(namespace, id)` refuse
/// both rows now, so enforcement is disabled for the injection. The loader's
/// own fail-closed validation is what these tests exercise.
async fn inject_cross_namespace_plugin_association(store: &DatabaseStore) {
    let ts = Utc::now().to_rfc3339();
    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'other', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-other")
    .bind(r#"{"key_location":"header:X-Secret-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&mut *conn)
    .await
    .expect("cross-namespace plugin insert must succeed with enforcement off");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-other")
    .execute(&mut *conn)
    .await
    .expect("cross-namespace association insert must succeed with enforcement off");
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await
        .unwrap();
}

/// Issue #4627: the schema itself now refuses a cross-tenant attachment.
#[tokio::test(flavor = "multi_thread")]
async fn composite_foreign_keys_refuse_cross_namespace_plugin_attachment() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    let plugin_error = sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'other', 'key_auth', ?, 'proxy', ?, 1, ?, ?)",
    )
    .bind("plugin-other")
    .bind(r#"{"key_location":"header:X-Secret-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect_err("a plugin config must not attach to a proxy in another namespace");
    assert!(
        plugin_error
            .to_string()
            .to_lowercase()
            .contains("foreign key"),
        "expected a composite FK refusal, got: {plugin_error}"
    );

    // A junction row can never join tenants either: its single `namespace`
    // column feeds BOTH foreign keys.
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'other', 'key_auth', ?, 'global', NULL, 1, ?, ?)",
    )
    .bind("plugin-other")
    .bind(r#"{"key_location":"header:X-Secret-Key"}"#)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("a global plugin config in another namespace is legitimate");

    let junction_error = sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-other")
    .execute(&pool)
    .await
    .expect_err("a junction row must not bind across namespaces");
    assert!(
        junction_error
            .to_string()
            .to_lowercase()
            .contains("foreign key"),
        "expected a composite FK refusal, got: {junction_error}"
    );
}

async fn drop_proxy_plugins_table(store: &DatabaseStore) {
    sqlx::query("DROP TABLE proxy_plugins")
        .execute(&store.pool())
        .await
        .expect("drop proxy_plugins must succeed");
}

async fn drop_plugin_configs_table(store: &DatabaseStore) {
    let pool = store.pool();
    let mut conn = pool
        .acquire()
        .await
        .expect("connection acquisition must succeed");
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .expect("foreign key disabling must succeed");
    sqlx::query("DROP TABLE plugin_configs")
        .execute(&mut *conn)
        .await
        .expect("drop plugin_configs must succeed");
}

fn error_text<T>(result: Result<T, anyhow::Error>) -> String {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(err) => err.to_string(),
    }
}

fn assert_association_error_context(message: &str, operation: &str) {
    assert!(
        message.contains(&format!("operation={operation}")),
        "error should include operation context, got: {message}"
    );
    assert!(
        message.contains("resource=proxy_plugins"),
        "error should identify proxy_plugins, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_association_loading_remains_unchanged() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let full = store
        .load_full_config("ferrum")
        .await
        .expect("full load must succeed");
    let proxy = full
        .proxies
        .iter()
        .find(|proxy| proxy.id == "proxy-1")
        .expect("proxy must be present");
    assert_eq!(proxy.plugins.len(), 1);
    assert_eq!(proxy.plugins[0].plugin_config_id, "plugin-1");

    let incremental = store
        .load_incremental_config("ferrum", 0)
        .await
        .expect("incremental load must succeed");
    let incremental_proxy = incremental
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "proxy-1")
        .expect("incremental proxy must be present");
    assert_eq!(incremental_proxy.plugins.len(), 1);
    assert_eq!(incremental_proxy.plugins[0].plugin_config_id, "plugin-1");

    let admin_proxy = store
        .get_proxy("ferrum", "proxy-1")
        .await
        .expect("admin get_proxy must succeed")
        .expect("proxy must exist");
    assert_eq!(admin_proxy.plugins.len(), 1);
    assert_eq!(admin_proxy.plugins[0].plugin_config_id, "plugin-1");

    let page = store
        .list_proxies_paginated("ferrum", 25, 0)
        .await
        .expect("admin list_proxies must succeed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].plugins.len(), 1);
    assert_eq!(page.items[0].plugins[0].plugin_config_id, "plugin-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_load_association_query_failure_rejects_candidate() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    drop_proxy_plugins_table(&store).await;

    let message = error_text(store.load_full_config("ferrum").await);
    assert_association_error_context(&message, "load_full_config");
    assert!(
        !message.contains("X-API-Key"),
        "association errors must not include plugin credential material: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn incremental_association_query_failure_rejects_delta() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let baseline = store
        .load_full_config("ferrum")
        .await
        .expect("baseline full load must succeed");
    assert_eq!(baseline.proxies.len(), 1);

    drop_proxy_plugins_table(&store).await;

    let message = error_text(store.load_incremental_config("ferrum", 0).await);
    assert_association_error_context(&message, "load_incremental_config");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_association_row_rejects_candidate_instead_of_being_skipped() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, X'FF')",
    )
        .bind("proxy-1")
        .execute(&mut *conn)
        .await
        .unwrap();

    let message = error_text(store.load_full_config("ferrum").await);
    assert_association_error_context(&message, "load_full_config");
    assert!(
        message.contains("proxy_id=proxy-1") && message.contains("column=plugin_config_id"),
        "decode error should include safe row context, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_invalid_association_rejects_the_full_snapshot() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    store
        .load_full_config("ferrum")
        .await
        .expect("valid baseline must load before injecting invalid association");

    // Since issue #4627 the composite foreign keys make this shape
    // structurally impossible, so the corrupt rows are injected with
    // enforcement disabled. The loader must still fail closed on them.
    inject_cross_namespace_plugin_association(&store).await;

    let error = store
        .load_full_config("ferrum")
        .await
        .expect_err("invalid association must reject the full snapshot");
    assert!(
        ferrum_edge::_test_support::is_config_validation_rejection(&error),
        "invalid runtime association must be classified as a reachable validation rejection"
    );
    let message = error.to_string();
    assert_association_error_context(&message, "load_full_config");
    assert!(
        message.contains("plugin-other"),
        "invalid association should identify the safe plugin id, got: {message}"
    );
    assert!(
        !message.contains("X-Secret-Key"),
        "invalid association error must not expose plugin config values: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_fail_closed_on_association_query_failure() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    drop_proxy_plugins_table(&store).await;

    let get_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_wrap_plugin_config_lookup_failures_as_association_errors() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;
    drop_plugin_configs_table(&store).await;

    let get_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(
        get_message.contains("failed to load plugin_config references"),
        "plugin_config lookup failure should be wrapped as association context, got: {get_message}"
    );

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(
        list_message.contains("failed to load plugin_config references"),
        "paginated plugin_config lookup failure should be wrapped as association context, got: {list_message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_incomplete_cross_namespace_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    // Since issue #4627 the composite foreign keys make this shape
    // structurally impossible, so the corrupt rows are injected with
    // enforcement disabled. The loader must still fail closed on them.
    inject_cross_namespace_plugin_association(&store).await;

    let get_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-other"));
    assert!(!get_message.contains("X-Secret-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-other"));
    assert!(!list_message.contains("X-Secret-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_global_plugin_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'global', ?, 1, ?, ?)",
    )
    .bind("plugin-global")
    .bind(r#"{"key_location":"header:X-Global-Key"}"#)
    .bind(Option::<String>::None)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("global plugin insert must succeed");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-global")
    .execute(&pool)
    .await
    .expect("global association insert must succeed");

    let get_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-global"));
    assert!(!get_message.contains("X-Global-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-global"));
    assert!(!list_message.contains("X-Global-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_proxy_reads_reject_proxy_group_plugin_with_proxy_id() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'proxy_group', ?, 1, ?, ?)",
    )
    .bind("plugin-group-corrupt")
    .bind(r#"{"key_location":"header:X-Group-Key"}"#)
    .bind("proxy-1")
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("proxy-group plugin insert must succeed");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-group-corrupt")
    .execute(&pool)
    .await
    .expect("proxy-group association insert must succeed");

    let get_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&get_message, "get_proxy");
    assert!(get_message.contains("plugin-group-corrupt"));
    assert!(!get_message.contains("X-Group-Key"));

    let list_message = error_text(store.list_proxies_paginated("ferrum", 25, 0).await);
    assert_association_error_context(&list_message, "list_proxies_paginated");
    assert!(list_message.contains("plugin-group-corrupt"));
    assert!(!list_message.contains("X-Group-Key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_write_precheck_can_repair_invalid_associations() {
    let (store, _temp_dir) = sqlite_store().await;
    seed_proxy_with_plugin(&store).await;

    let ts = Utc::now().to_rfc3339();
    let pool = store.pool();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, 'global', ?, 1, ?, ?)",
    )
    .bind("plugin-global")
    .bind(r#"{"key_location":"header:X-Global-Key"}"#)
    .bind(Option::<String>::None)
    .bind(&ts)
    .bind(&ts)
    .execute(&pool)
    .await
    .expect("global plugin insert must succeed");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES ('ferrum', ?, ?)",
    )
    .bind("proxy-1")
    .bind("plugin-global")
    .execute(&pool)
    .await
    .expect("global association insert must succeed");

    let read_message = error_text(store.get_proxy("ferrum", "proxy-1").await);
    assert_association_error_context(&read_message, "get_proxy");
    assert!(read_message.contains("plugin-global"));

    let mut repair_proxy = store
        .get_proxy_for_write("ferrum", "proxy-1")
        .await
        .expect("write precheck get must succeed")
        .expect("proxy must exist");
    repair_proxy
        .plugins
        .retain(|assoc| assoc.plugin_config_id != "plugin-global");
    store
        .update_proxy(&repair_proxy)
        .await
        .expect("update should repair proxy_plugins rows");

    let repaired = store
        .get_proxy("ferrum", "proxy-1")
        .await
        .expect("repaired proxy read must succeed")
        .expect("proxy must still exist");
    assert_eq!(repaired.plugins.len(), 1);
    assert_eq!(repaired.plugins[0].plugin_config_id, "plugin-1");
}

// ---------------------------------------------------------------------------
// Admin write path attaches the proxy association (issue #4611)
//
// `docs/plugins.md` states the runtime rule: a proxy-scoped plugin config
// applies only when the target proxy lists it in `plugins`; `proxy_id` alone
// never attaches it. Database mode used to answer `201`/`200` for a
// `scope: "proxy"` write while leaving `proxy_plugins` untouched, so
// `GET /proxies/{id}` reported `plugins: []` and the runtime never applied the
// config. Both sides must now move in the same transaction.
// ---------------------------------------------------------------------------

use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::plugin_cache::PluginCache;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::sync::Arc;

const ATTACH_JWT_SECRET: &str = "test-secret-key-for-plugin-attach-tests";
const ATTACH_NAMESPACE: &str = "ferrum";

async fn attach_admin(store: Arc<DatabaseStore>) -> (String, tokio::sync::watch::Sender<bool>) {
    let state = AdminState {
        db: Some(store),
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ATTACH_JWT_SECRET.to_string(),
            issuer: "test-ferrum-edge".to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }),
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

    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
            return (format!("http://{}", addr), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin server at {} never became ready", addr);
}

fn attach_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": "test-ferrum-edge",
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ATTACH_JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn admin_call(
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{}{}", base_url, path))
        .bearer_auth(attach_token())
        .header("X-Ferrum-Namespace", ATTACH_NAMESPACE);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.expect("admin request must complete");
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

fn attach_proxy_payload(id: &str, listen_path: &str) -> Value {
    json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "strip_listen_path": true,
    })
}

fn attach_plugin_payload(id: &str, proxy_id: Option<&str>) -> Value {
    let mut payload = json!({
        "id": id,
        "plugin_name": "request_transformer",
        "scope": if proxy_id.is_some() { "proxy" } else { "global" },
        "config": { "rules": [{
            "operation": "add",
            "target": "header",
            "key": "x-ferrum-attach",
            "value": "1",
        }] },
        "enabled": true,
    });
    if let Some(proxy_id) = proxy_id {
        payload["proxy_id"] = json!(proxy_id);
    }
    payload
}

/// Ids the proxy currently lists, as `GET /proxies/{id}` renders them.
fn association_ids(proxy_body: &Value) -> Vec<String> {
    proxy_body["plugins"]
        .as_array()
        .map(|associations| {
            associations
                .iter()
                .filter_map(|association| {
                    association["plugin_config_id"].as_str().map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Returns the store, the tempdir, the admin base URL, and the shutdown sender
/// — the caller must hold the last two alive for the duration of the test.
type AttachFixture = (
    Arc<DatabaseStore>,
    TempDir,
    String,
    tokio::sync::watch::Sender<bool>,
);

async fn attach_fixture() -> AttachFixture {
    let (store, temp_dir) = sqlite_store().await;
    let store = Arc::new(store);
    let (base_url, shutdown) = attach_admin(store.clone()).await;
    let (status, body) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/proxies",
        Some(&attach_proxy_payload("proxy-attach-1", "/attach-1")),
    )
    .await;
    assert_eq!(status, 201, "proxy create must succeed: {:?}", body);
    (store, temp_dir, base_url, shutdown)
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_scoped_plugin_create_writes_the_proxy_association() {
    let (store, _temp_dir, base_url, _shutdown) = attach_fixture().await;

    let before = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-1")
        .await
        .expect("proxy read must succeed")
        .expect("proxy must exist");

    let (status, body) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/plugins/config",
        Some(&attach_plugin_payload(
            "pc-attach-1",
            Some("proxy-attach-1"),
        )),
    )
    .await;
    assert_eq!(
        status, 201,
        "proxy-scoped plugin create must succeed: {:?}",
        body
    );

    let (status, proxy_body) = admin_call(
        reqwest::Method::GET,
        &base_url,
        "/proxies/proxy-attach-1",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        association_ids(&proxy_body),
        vec!["pc-attach-1".to_string()],
        "201 must mean attached: GET /proxies must list the config"
    );

    // The poll/CP broadcast contract: the proxy's own `updated_at` advances so
    // the change is republished, not just the plugin_config row's.
    let after = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-1")
        .await
        .expect("proxy read must succeed")
        .expect("proxy must exist");
    assert!(
        after.updated_at > before.updated_at,
        "attaching must advance the proxy's updated_at ({} -> {})",
        before.updated_at,
        after.updated_at
    );

    // The incremental poll republishes the proxy carrying the association, so
    // a running gateway picks the attachment up on its next cycle.
    let delta = store
        .load_incremental_config(ATTACH_NAMESPACE, 0)
        .await
        .expect("incremental load must succeed");
    let republished = delta
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "proxy-attach-1")
        .expect("the touched proxy must be republished");
    assert_eq!(republished.plugins.len(), 1);
    assert_eq!(republished.plugins[0].plugin_config_id, "pc-attach-1");

    // And the resulting generation actually applies the plugin to the proxy.
    let config = store
        .load_full_config(ATTACH_NAMESPACE)
        .await
        .expect("full load must succeed");
    let cache = PluginCache::new(&config).expect("plugin cache must build");
    assert!(
        !cache
            .get_plugins(ATTACH_NAMESPACE, "proxy-attach-1")
            .is_empty(),
        "the attached plugin must be applied to the proxy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_scoped_plugin_update_rehomes_the_association() {
    let (store, _temp_dir, base_url, _shutdown) = attach_fixture().await;

    let (status, body) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/proxies",
        Some(&attach_proxy_payload("proxy-attach-2", "/attach-2")),
    )
    .await;
    assert_eq!(status, 201, "second proxy create must succeed: {:?}", body);

    let (status, _) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/plugins/config",
        Some(&attach_plugin_payload(
            "pc-attach-1",
            Some("proxy-attach-1"),
        )),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = admin_call(
        reqwest::Method::PUT,
        &base_url,
        "/plugins/config/pc-attach-1",
        Some(&attach_plugin_payload(
            "pc-attach-1",
            Some("proxy-attach-2"),
        )),
    )
    .await;
    assert_eq!(status, 200, "re-homing update must succeed: {:?}", body);

    let first = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-1")
        .await
        .expect("first proxy read must succeed")
        .expect("first proxy must exist");
    assert!(
        first.plugins.is_empty(),
        "the previous proxy must lose the association"
    );
    let second = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-2")
        .await
        .expect("second proxy read must succeed")
        .expect("second proxy must exist");
    assert_eq!(second.plugins.len(), 1);
    assert_eq!(second.plugins[0].plugin_config_id, "pc-attach-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_scope_change_away_from_proxy_detaches_the_association() {
    let (store, _temp_dir, base_url, _shutdown) = attach_fixture().await;

    let (status, _) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/plugins/config",
        Some(&attach_plugin_payload(
            "pc-attach-1",
            Some("proxy-attach-1"),
        )),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = admin_call(
        reqwest::Method::PUT,
        &base_url,
        "/plugins/config/pc-attach-1",
        Some(&attach_plugin_payload("pc-attach-1", None)),
    )
    .await;
    assert_eq!(status, 200, "scope change must succeed: {:?}", body);

    let proxy = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-1")
        .await
        .expect("proxy read must succeed")
        .expect("proxy must exist");
    assert!(
        proxy.plugins.is_empty(),
        "a global-scoped config must not stay associated with a proxy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_config_delete_detaches_the_association() {
    let (store, _temp_dir, base_url, _shutdown) = attach_fixture().await;

    let (status, _) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/plugins/config",
        Some(&attach_plugin_payload(
            "pc-attach-1",
            Some("proxy-attach-1"),
        )),
    )
    .await;
    assert_eq!(status, 201);

    let (status, body) = admin_call(
        reqwest::Method::DELETE,
        &base_url,
        "/plugins/config/pc-attach-1",
        None,
    )
    .await;
    assert!(
        status == 200 || status == 204,
        "delete must succeed (got {}): {:?}",
        status,
        body
    );

    let proxy = store
        .get_proxy(ATTACH_NAMESPACE, "proxy-attach-1")
        .await
        .expect("proxy read must succeed")
        .expect("proxy must exist");
    assert!(
        proxy.plugins.is_empty(),
        "deleting the config must remove every association"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_scoped_plugin_for_a_missing_proxy_is_still_rejected() {
    let (_store, _temp_dir, base_url, _shutdown) = attach_fixture().await;

    let (status, body) = admin_call(
        reqwest::Method::POST,
        &base_url,
        "/plugins/config",
        Some(&attach_plugin_payload("pc-attach-1", Some("proxy-missing"))),
    )
    .await;
    assert_eq!(status, 400, "unknown proxy_id must be rejected: {:?}", body);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not exist in namespace"),
        "existing diagnostic shape must be preserved: {:?}",
        body
    );
}
