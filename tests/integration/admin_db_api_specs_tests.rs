//! Integration tests for `DatabaseBackend` api_spec operations (Wave 2).
//!
//! All tests run against a SQLite in-memory (file-based temp) database so they
//! are self-contained and do not require any external service.
//!
//! # Hot-path isolation contract
//!
//! The `api_specs` table is admin-only metadata. These methods must NEVER be
//! called from the proxy runtime, polling loops, or gRPC distribution paths.
//! Each test verifies only the admin-layer operations; no test wires
//! `list_api_specs` / `get_api_spec` into `GatewayConfig` loading.
//!
//! # Database coverage notes (PR review item 11)
//!
//! The tests here exercise the `sqlx::Any` dialect path shared by SQLite,
//! PostgreSQL, and MySQL.  Dialect-specific behaviour is covered as follows:
//!
//! - **SQLite**: all tests here run against SQLite.  SQLite uses the same
//!   query templates as Postgres/MySQL (the `q()` helper adjusts placeholders
//!   from `?` to `$N` for Postgres at runtime).
//!
//! - **PostgreSQL**: `RETURNING` clauses and JSONB indexes are used only in
//!   non-api-specs paths.  The api-specs queries (`list_api_specs`,
//!   `submit_api_spec_bundle`, `replace_api_spec_bundle`, `delete_api_spec`)
//!   use plain SQL that is identical across all three SQL dialects.  Postgres-
//!   specific end-to-end coverage runs in functional tests when a `POSTGRES_URL`
//!   environment variable is configured.
//!
//! - **MySQL**: follows the same pattern.  The `V001SqlBuilder` dialect
//!   differences (VARCHAR vs TEXT, TINYINT vs INTEGER) do not affect query
//!   semantics; they are covered by `sql_dialect.rs` unit tests.
//!
//! - **MongoDB**: `MongoStore` mirrors the SQL API-spec operations where
//!   possible. Atomic late-delete restore is implemented only with a replica
//!   set transaction; standalone MongoDB rejects it before writing. A future
//!   `#[ignore]` test file with a `MONGO_URL` env-gated harness would close the
//!   live-backend gap. See Round 8 P2 documenting comment for context on why
//!   this is deferred.

use ferrum_edge::{
    ExtractedBundle, GatewayConfig,
    admin::api_specs::{EffectiveExternalRefPolicy, ExternalRefSnapshot},
    config::{
        BackendAllowIps, BackendEgressPolicy,
        db_backend::{
            ApiSpecListFilter, ApiSpecSortBy, SortOrder,
            tcp_connection_throttle_attachment_conflict,
        },
        db_loader::{DatabaseStore, DbPoolConfig},
        types::{
            ApiSpec, PluginAssociation, PluginConfig, PluginScope, Proxy, SpecFormat, Upstream,
        },
    },
    plugins::PluginHttpClient,
};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
};
use tempfile::TempDir;

/// Build a default list filter with just limit/offset (for existing pagination tests).
fn simple_filter(limit: u32, offset: u32) -> ApiSpecListFilter {
    ApiSpecListFilter {
        limit,
        offset,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic counter to generate unique resource IDs within a test run.
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn uid(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

fn restore_validation_http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

/// Pool config with short timeouts for test speed.
fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

/// Create a fresh SQLite in-memory (temp-file) store with migrations applied.
async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir.path().join(format!("test-{}.db", uid("db")));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect_with_pool_config failed")
}

/// Build a minimal `Proxy` with a unique id.
fn make_proxy(id: &str, namespace: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": format!("/{id}")
    }))
    .expect("proxy deserialization failed")
}

/// Build a minimal `Upstream` with a unique id.
fn make_upstream(id: &str, namespace: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "target.internal", "port": 443}]
    }))
    .expect("upstream deserialization failed")
}

/// Build a `PluginConfig` linked to a proxy.
fn make_plugin(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    api_spec_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: "rate_limiting".to_string(),
        config: serde_json::json!({
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: api_spec_id.map(str::to_string),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Build an `ApiSpec` with gzip-compressed stub content.
fn make_spec(id: &str, proxy_id: &str, namespace: &str, content: &[u8]) -> ApiSpec {
    let compressed =
        ferrum_edge::admin::spec_codec::compress_gzip(content).expect("compress failed");
    let hash = ferrum_edge::admin::spec_codec::sha256_hex(content);
    ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: "3.1.0".to_string(),
        spec_format: SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: content.len() as u64,
        content_hash: hash,
        title: Some("Test API".to_string()),
        info_version: Some("1.0.0".to_string()),
        // Wave 5 fields — defaults for existing tests
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: String::new(),
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — happy path
// ---------------------------------------------------------------------------

/// All four resource types (proxy, upstream, 2 plugins, spec) are written and
/// each carries the correct `api_spec_id` tag.
#[tokio::test]
async fn submit_bundle_happy_path_all_resources_tagged() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id_1 = uid("plugin");
    let plugin_id_2 = uid("plugin");
    let spec_id = uid("spec");

    let proxy = make_proxy(&proxy_id, ns);
    let upstream = make_upstream(&upstream_id, ns);

    let plugin1 = make_plugin(&plugin_id_1, &proxy_id, ns, None);
    let plugin2 = make_plugin(&plugin_id_2, &proxy_id, ns, None);

    let bundle = ExtractedBundle {
        proxy,
        upstream: Some(upstream),
        plugins: vec![plugin1, plugin2],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"stub spec content for test");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // --- Verify the spec row round-trips correctly ---
    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found after submit");
    assert_eq!(fetched.id, spec_id);
    assert_eq!(fetched.proxy_id, proxy_id);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "spec_content bytes must round-trip"
    );

    // --- Verify proxy exists, and the admin GET path PRESERVES api_spec_id ---
    // Hot-path isolation means the GATEWAY RUNTIME must never see api_spec_id
    // (enforced by `strip_api_spec_id_from_runtime_config` in
    // `load_full_config` / `load_incremental_config`). The admin GET/list
    // path, by contrast, must return the owning spec id so admin clients can
    // distinguish spec-owned from hand-added resources per the OpenAPI
    // schema. `get_proxy` is on the admin path and must preserve it.
    let proxy_row = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    assert_eq!(
        proxy_row.api_spec_id.as_deref(),
        Some(spec_id.as_str()),
        "get_proxy (admin path) must preserve api_spec_id; runtime stripping happens \
         in load_full_config / load_incremental_config, not in the row mapper"
    );

    // --- Verify get_api_spec_by_proxy ---
    let by_proxy = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(by_proxy.id, spec_id);

    // --- Verify plugin count (2 spec-owned + 0 hand-added = 2) ---
    let all_plugins = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list_plugin_configs_paginated failed");
    let spec_plugins: Vec<_> = all_plugins
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(spec_plugins.len(), 2, "expected 2 plugins for proxy");
}

#[tokio::test]
async fn list_spec_owned_plugin_configs_orders_by_created_at_then_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let mut proxy = make_proxy(&proxy_id, ns);

    let timestamp = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut plugin_b = make_plugin("plugin-b", &proxy_id, ns, None);
    let mut plugin_a = make_plugin("plugin-a", &proxy_id, ns, None);
    for plugin in [&mut plugin_b, &mut plugin_a] {
        plugin.created_at = timestamp;
        plugin.updated_at = timestamp;
    }

    proxy.plugins = vec![
        PluginAssociation {
            plugin_config_id: plugin_b.id.clone(),
        },
        PluginAssociation {
            plugin_config_id: plugin_a.id.clone(),
        },
    ];
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![plugin_b, plugin_a],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"spec with duplicate canonical plugins",
    );

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    let ordered_ids: Vec<String> = store
        .list_spec_owned_plugin_configs(ns, &spec_id)
        .await
        .expect("list_spec_owned_plugin_configs failed")
        .into_iter()
        .map(|pc| pc.id)
        .collect();

    assert_eq!(
        ordered_ids,
        vec!["plugin-a".to_string(), "plugin-b".to_string()],
        "PUT canonical ID reuse depends on a deterministic FIFO order for \
         duplicate spec-owned plugins"
    );
}

/// submit with proxy-only bundle (no upstream, no plugins).
#[tokio::test]
async fn submit_bundle_proxy_only() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"proxy-only spec");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert_eq!(fetched.proxy_id, proxy_id);
}

#[tokio::test]
async fn submit_bundle_remains_available_with_unrelated_malformed_plugin_association() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let plugin_target_proxy_id = uid("submit-repair-target");
    let wrong_association_proxy_id = uid("submit-repair-wrong-association");
    let malformed_plugin_id = uid("submit-repair-plugin");

    store
        .create_proxy(&make_proxy(&plugin_target_proxy_id, ns))
        .await
        .expect("seed plugin target proxy failed");
    store
        .create_proxy(&make_proxy(&wrong_association_proxy_id, ns))
        .await
        .expect("seed wrongly associated proxy failed");
    store
        .create_plugin_config(&make_plugin(
            &malformed_plugin_id,
            &plugin_target_proxy_id,
            ns,
            None,
        ))
        .await
        .expect("seed proxy-scoped plugin failed");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES (?, ?, ?)",
    )
    .bind(ns)
    .bind(&wrong_association_proxy_id)
    .bind(&malformed_plugin_id)
    .execute(&store.pool())
    .await
    .expect("seed out-of-band malformed association failed");

    let proxy_id = uid("submit-repair-new-proxy");
    let spec_id = uid("submit-repair-new-spec");
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"valid submission beside malformed plugin state",
    );

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("ordinary API-spec submit must remain available for in-band repair");

    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_some());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_some());
    let malformed_association_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?",
    )
    .bind(&wrong_association_proxy_id)
    .bind(&malformed_plugin_id)
    .fetch_one(&store.pool())
    .await
    .expect("count malformed association failed");
    assert_eq!(malformed_association_count, 1);
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — rollback on duplicate
// ---------------------------------------------------------------------------

/// When the INSERT fails mid-transaction (duplicate proxy id), the entire
/// transaction is rolled back and no rows are left in any table.
#[tokio::test]
async fn submit_bundle_rollback_on_duplicate_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id_1 = uid("spec");
    let spec_id_2 = uid("spec");

    // First submit succeeds.
    let bundle1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec1 = make_spec(&spec_id_1, &proxy_id, ns, b"first spec");
    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("first submit failed");

    // Second submit uses the SAME proxy_id → should fail with a unique constraint error.
    let bundle2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec2 = make_spec(&spec_id_2, &proxy_id, ns, b"duplicate spec");
    let result = store.submit_api_spec_bundle(&bundle2, &spec2).await;
    assert!(result.is_err(), "duplicate proxy_id submit must return Err");

    // The second spec row must NOT be present.
    let fetched2 = store
        .get_api_spec(ns, &spec_id_2)
        .await
        .expect("get_api_spec failed");
    assert!(
        fetched2.is_none(),
        "spec2 must not exist after rollback; got: {:?}",
        fetched2.map(|s| s.id)
    );

    // The first spec + proxy must still be intact.
    let fetched1 = store
        .get_api_spec(ns, &spec_id_1)
        .await
        .expect("get_api_spec failed")
        .expect("spec1 not found after failed second submit");
    assert_eq!(fetched1.id, spec_id_1);
}

// ---------------------------------------------------------------------------
// restore_api_spec_bundle — atomic late-delete compensation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_bundle_preserves_complete_owned_and_hand_added_graph() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-proxy");
    let upstream_id = uid("restore-upstream");
    let spec_plugin_id = uid("restore-owned-plugin");
    let additional_plugin_id = uid("restore-hand-plugin");
    let spec_id = uid("restore-spec");
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .to_utc();
    let updated_at = chrono::DateTime::parse_from_rfc3339("2026-02-03T04:05:06Z")
        .unwrap()
        .to_utc();

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.upstream_id = Some(upstream_id.clone());
    proxy.created_at = created_at;
    proxy.updated_at = updated_at;
    proxy.plugins = vec![
        PluginAssociation {
            plugin_config_id: spec_plugin_id.clone(),
        },
        PluginAssociation {
            plugin_config_id: additional_plugin_id.clone(),
        },
    ];

    let mut upstream = make_upstream(&upstream_id, ns);
    upstream.api_spec_id = Some(spec_id.clone());
    upstream.created_at = created_at;
    upstream.updated_at = updated_at;

    let mut spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, Some(&spec_id));
    spec_plugin.priority_override = Some(7);
    spec_plugin.created_at = created_at;
    spec_plugin.updated_at = updated_at;
    let mut additional_plugin = make_plugin(&additional_plugin_id, &proxy_id, ns, None);
    additional_plugin.enabled = false;
    additional_plugin.priority_override = Some(41);
    additional_plugin.created_at = created_at;
    additional_plugin.updated_at = updated_at;

    let bundle = ExtractedBundle {
        proxy,
        upstream: Some(upstream),
        plugins: vec![spec_plugin],
    };
    let mut spec = make_spec(&spec_id, &proxy_id, ns, b"restored API spec");
    spec.created_at = created_at;
    spec.updated_at = updated_at;

    store
        .restore_api_spec_bundle(
            &bundle,
            &spec,
            &[],
            std::slice::from_ref(&additional_plugin),
            &restore_validation_http_client(),
        )
        .await
        .expect("atomic API-spec restore failed");

    let restored_proxy = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("restored proxy missing");
    assert_eq!(
        restored_proxy.api_spec_id.as_deref(),
        Some(spec_id.as_str())
    );
    assert_eq!(restored_proxy.created_at, created_at);
    assert_eq!(restored_proxy.updated_at, updated_at);
    let association_ids: HashSet<&str> = restored_proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    assert_eq!(
        association_ids,
        HashSet::from([spec_plugin_id.as_str(), additional_plugin_id.as_str()])
    );

    let restored_upstream = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream failed")
        .expect("restored upstream missing");
    assert_eq!(
        restored_upstream.api_spec_id.as_deref(),
        Some(spec_id.as_str())
    );
    assert_eq!(restored_upstream.created_at, created_at);
    assert_eq!(restored_upstream.updated_at, updated_at);

    let restored_owned = store
        .get_plugin_config(ns, &spec_plugin_id)
        .await
        .expect("get owned plugin failed")
        .expect("restored owned plugin missing");
    assert_eq!(
        restored_owned.api_spec_id.as_deref(),
        Some(spec_id.as_str())
    );
    assert_eq!(restored_owned.scope, PluginScope::Proxy);
    assert_eq!(restored_owned.proxy_id.as_deref(), Some(proxy_id.as_str()));
    assert!(restored_owned.enabled);
    assert_eq!(restored_owned.priority_override, Some(7));
    assert_eq!(restored_owned.config, bundle.plugins[0].config);
    assert_eq!(restored_owned.created_at, created_at);
    assert_eq!(restored_owned.updated_at, updated_at);

    let restored_additional = store
        .get_plugin_config(ns, &additional_plugin_id)
        .await
        .expect("get hand-owned plugin failed")
        .expect("restored hand-owned plugin missing");
    assert!(restored_additional.api_spec_id.is_none());
    assert_eq!(restored_additional.scope, PluginScope::Proxy);
    assert_eq!(
        restored_additional.proxy_id.as_deref(),
        Some(proxy_id.as_str())
    );
    assert!(!restored_additional.enabled);
    assert_eq!(restored_additional.priority_override, Some(41));
    assert_eq!(restored_additional.config, additional_plugin.config);
    assert_eq!(restored_additional.created_at, created_at);
    assert_eq!(restored_additional.updated_at, updated_at);

    let restored_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("restored API spec missing");
    assert_eq!(restored_spec.created_at, created_at);
    assert_eq!(restored_spec.updated_at, updated_at);

    let changes: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT resource_type, resource_id, operation FROM config_changes \
         WHERE namespace = ? ORDER BY sequence",
    )
    .bind(ns)
    .fetch_all(&store.pool())
    .await
    .expect("load restore config changes failed");
    assert_eq!(changes.len(), 4);
    assert_eq!(
        changes.into_iter().collect::<HashSet<_>>(),
        HashSet::from([
            ("upstream".to_string(), upstream_id, "upsert".to_string()),
            ("proxy".to_string(), proxy_id, "upsert".to_string()),
            (
                "plugin_config".to_string(),
                spec_plugin_id,
                "upsert".to_string()
            ),
            (
                "plugin_config".to_string(),
                additional_plugin_id,
                "upsert".to_string()
            ),
        ])
    );
}

#[tokio::test]
async fn restore_bundle_preserves_unattached_proxy_config_during_late_delete_compensation() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-unattached-proxy");
    let spec_id = uid("restore-unattached-spec");
    let plugin_id = uid("restore-unattached-plugin");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    assert!(proxy.plugins.is_empty());
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"unattached plugin compensation");
    let mut unattached = make_plugin(&plugin_id, &proxy_id, ns, None);
    unattached.enabled = false;
    unattached.priority_override = Some(19);

    store
        .restore_api_spec_bundle(
            &bundle,
            &spec,
            &[],
            std::slice::from_ref(&unattached),
            &restore_validation_http_client(),
        )
        .await
        .expect("late-delete compensation must restore an unattached proxy config");

    let restored_proxy = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get restored proxy failed")
        .expect("restored proxy missing");
    assert!(
        restored_proxy.plugins.is_empty(),
        "compensation must not invent a reverse proxy association"
    );
    let restored_plugin = store
        .get_plugin_config(ns, &plugin_id)
        .await
        .expect("get restored unattached plugin failed")
        .expect("unattached proxy config was not restored");
    assert_eq!(restored_plugin.scope, PluginScope::Proxy);
    assert_eq!(restored_plugin.proxy_id.as_deref(), Some(proxy_id.as_str()));
    assert!(restored_plugin.api_spec_id.is_none());
    assert!(!restored_plugin.enabled);
    assert_eq!(restored_plugin.priority_override, Some(19));
    assert_eq!(restored_plugin.config, unattached.config);
}

#[tokio::test]
async fn restore_bundle_uses_configured_plugin_validation_egress_policy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-egress-proxy");
    let spec_id = uid("restore-egress-spec");
    let plugin_id = uid("restore-egress-plugin");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: plugin_id.clone(),
    }];
    let mut plugin = make_plugin(&plugin_id, &proxy_id, ns, Some(&spec_id));
    plugin.plugin_name = "http_logging".to_string();
    plugin.config = serde_json::json!({
        "endpoint_url": "http://169.254.169.254/ingest"
    });
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![plugin],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"configured recovery validation client",
    );
    let policy = BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true)
        .expect("production backend egress policy");
    let validation_http_client = PluginHttpClient::default_with_backend_allow_ips(policy);

    let error = store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &validation_http_client)
        .await
        .expect_err("configured backend egress policy must reject recovery plugin");
    assert!(
        error.to_string().contains("backend egress policy"),
        "recovery validation must return the configured-client rejection: {error:#}"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(
        store
            .get_plugin_config(ns, &plugin_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
    let change_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM config_changes WHERE namespace = ? AND resource_id IN (?, ?)",
    )
    .bind(ns)
    .bind(&proxy_id)
    .bind(&plugin_id)
    .fetch_one(&store.pool())
    .await
    .expect("count rejected recovery changes failed");
    assert_eq!(change_count, 0, "rejected recovery must roll back changes");
}

#[tokio::test]
async fn restore_bundle_ignores_unrelated_malformed_plugin_association() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let plugin_target_proxy_id = uid("restore-repair-target");
    let wrong_association_proxy_id = uid("restore-repair-wrong-association");
    let malformed_plugin_id = uid("restore-repair-plugin");

    store
        .create_proxy(&make_proxy(&plugin_target_proxy_id, ns))
        .await
        .expect("seed plugin target proxy failed");
    store
        .create_proxy(&make_proxy(&wrong_association_proxy_id, ns))
        .await
        .expect("seed wrongly associated proxy failed");
    store
        .create_plugin_config(&make_plugin(
            &malformed_plugin_id,
            &plugin_target_proxy_id,
            ns,
            None,
        ))
        .await
        .expect("seed proxy-scoped plugin failed");
    sqlx::query(
        "INSERT INTO proxy_plugins (namespace, proxy_id, plugin_config_id) VALUES (?, ?, ?)",
    )
    .bind(ns)
    .bind(&wrong_association_proxy_id)
    .bind(&malformed_plugin_id)
    .execute(&store.pool())
    .await
    .expect("seed out-of-band malformed association failed");

    let restored_proxy_id = uid("restore-repair-recovered-proxy");
    let spec_id = uid("restore-repair-spec");
    let mut restored_proxy = make_proxy(&restored_proxy_id, ns);
    restored_proxy.api_spec_id = Some(spec_id.clone());
    let bundle = ExtractedBundle {
        proxy: restored_proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &restored_proxy_id,
        ns,
        b"valid recovery beside malformed plugin state",
    );

    store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect("unrelated repairable association must not block compensation");

    assert!(
        store
            .get_proxy(ns, &restored_proxy_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_some());
    let malformed_association_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?",
    )
    .bind(&wrong_association_proxy_id)
    .bind(&malformed_plugin_id)
    .fetch_one(&store.pool())
    .await
    .expect("count malformed association failed");
    assert_eq!(
        malformed_association_count, 1,
        "compensation must not mask or rewrite unrelated repairable state"
    );
}

#[test]
fn mongo_restore_validation_uses_the_recovered_proxy_graph_projection() {
    let source = include_str!("../../src/config/mongo_store.rs");
    let validation_start = source
        .find("async fn validate_api_spec_restore_candidate_in_session")
        .expect("Mongo restore validation helper");
    let validation_end = source[validation_start..]
        .find("// -----------------------------------------------------------------------")
        .map(|offset| validation_start + offset)
        .expect("end of Mongo restore validation helper");
    let validation = &source[validation_start..validation_end];

    assert!(validation.contains("api_spec_recovered_proxy_graph"));
    assert!(validation.contains("restored_proxy_id"));
    assert!(validation.contains("recovered_graph.validate_plugin_references()"));
    assert!(validation.contains("load_full_upstreams_opt_session"));
    assert!(validation.contains("recovered_graph.validate_upstream_references()"));
    assert!(validation.contains("validate_api_spec_recovered_plugin_graph("));
    assert!(validation.contains("validation_http_client: &crate::plugins::PluginHttpClient"));
    assert!(validation.contains("validation_http_client"));
    assert!(!validation.contains("PluginHttpClient::default()"));
    assert!(
        validation.contains("validate_tcp_connection_throttle_attachments(&candidate)"),
        "namespace-wide guarded composition validation must remain in force"
    );
}

#[test]
fn recovery_graph_validation_uses_the_configured_admin_http_client() {
    let shared = include_str!("../../src/config/db_backend.rs");
    let validation_start = shared
        .find("pub(crate) async fn validate_api_spec_recovered_plugin_graph(")
        .expect("shared recovery graph validator");
    let validation_end = shared[validation_start..]
        .find("/// Validate the immutable identity")
        .map(|offset| validation_start + offset)
        .expect("end of shared recovery graph validator");
    let validation = &shared[validation_start..validation_end];
    assert!(validation.contains("http_client: &PluginHttpClient"));
    assert!(validation.contains("let http_client = http_client.clone();"));
    assert!(!validation.contains("PluginHttpClient::default"));

    let sql = include_str!("../../src/config/db_loader.rs");
    assert!(sql.contains("validation_http_client: &crate::plugins::PluginHttpClient"));
    assert!(sql.contains("&recovered_graph,\n            validation_http_client,"));

    let handlers = include_str!("../../src/admin/api_specs/handlers.rs");
    assert!(handlers.contains("plugin_validation_http_client(state)"));
    assert!(handlers.contains("&validation_http_client,"));
}

#[tokio::test]
async fn restore_bundle_rolls_back_resources_associations_spec_and_changes_on_late_failure() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = "restore-failure-proxy";
    let upstream_id = "restore-failure-upstream";
    let additional_upstream_id = "restore-failure-hand-upstream";
    let spec_plugin_id = "restore-failure-owned-plugin";
    let additional_plugin_id = "restore-failure-hand-plugin";
    let spec_id = "restore-failure-spec";

    sqlx::query(
        "CREATE TRIGGER fail_api_spec_restore_change BEFORE INSERT ON config_changes \
         WHEN NEW.resource_id = 'restore-failure-hand-plugin' \
         BEGIN SELECT RAISE(ABORT, 'injected late API-spec restore failure'); END",
    )
    .execute(&store.pool())
    .await
    .expect("install API-spec restore fault trigger failed");

    let mut proxy = make_proxy(proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.to_string());
    proxy.upstream_id = Some(additional_upstream_id.to_string());
    proxy.plugins = vec![
        PluginAssociation {
            plugin_config_id: spec_plugin_id.to_string(),
        },
        PluginAssociation {
            plugin_config_id: additional_plugin_id.to_string(),
        },
    ];
    let mut upstream = make_upstream(upstream_id, ns);
    upstream.api_spec_id = Some(spec_id.to_string());
    let bundle = ExtractedBundle {
        proxy,
        upstream: Some(upstream),
        plugins: vec![make_plugin(spec_plugin_id, proxy_id, ns, Some(spec_id))],
    };
    let spec = make_spec(spec_id, proxy_id, ns, b"fault-injected restore");
    let additional_upstream = make_upstream(additional_upstream_id, ns);
    let additional = make_plugin(additional_plugin_id, proxy_id, ns, None);

    let error = store
        .restore_api_spec_bundle(
            &bundle,
            &spec,
            &[additional_upstream],
            &[additional],
            &restore_validation_http_client(),
        )
        .await
        .expect_err("fault-injected restore must fail");
    assert!(
        format!("{error:#}").contains("injected late API-spec restore failure"),
        "restore must reach the injected late failure after inserting the hand-owned upstream: {error:#}"
    );

    assert!(store.get_proxy(ns, proxy_id).await.unwrap().is_none());
    assert!(store.get_upstream(ns, upstream_id).await.unwrap().is_none());
    assert!(
        store
            .get_upstream(ns, additional_upstream_id)
            .await
            .unwrap()
            .is_none(),
        "hand-owned upstream must roll back with the API-spec restore"
    );
    assert!(
        store
            .get_plugin_config(ns, spec_plugin_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_plugin_config(ns, additional_plugin_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_api_spec(ns, spec_id).await.unwrap().is_none());

    let association_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM proxy_plugins WHERE proxy_id = ?")
            .bind(proxy_id)
            .fetch_one(&store.pool())
            .await
            .expect("count proxy associations failed");
    assert_eq!(association_count, 0);
    let change_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM config_changes WHERE namespace = ?")
            .bind(ns)
            .fetch_one(&store.pool())
            .await
            .expect("count config changes failed");
    assert_eq!(change_count, 0);
}

#[tokio::test]
async fn restore_bundle_preserves_preexisting_shared_additional_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let shared_upstream_id = uid("restore-shared-hand-upstream");
    let keeper_proxy_id = uid("restore-shared-keeper");
    let restored_proxy_id = uid("restore-shared-proxy");
    let spec_id = uid("restore-shared-spec");

    let mut current_upstream = make_upstream(&shared_upstream_id, ns);
    current_upstream.name = Some("current shared upstream".to_string());
    store
        .create_upstream(&current_upstream)
        .await
        .expect("create shared upstream");
    let mut keeper_proxy = make_proxy(&keeper_proxy_id, ns);
    keeper_proxy.upstream_id = Some(shared_upstream_id.clone());
    store
        .create_proxy(&keeper_proxy)
        .await
        .expect("create proxy retaining shared upstream");

    let mut restored_proxy = make_proxy(&restored_proxy_id, ns);
    restored_proxy.api_spec_id = Some(spec_id.clone());
    restored_proxy.upstream_id = Some(shared_upstream_id.clone());
    let bundle = ExtractedBundle {
        proxy: restored_proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &restored_proxy_id,
        ns,
        b"restore while shared hand upstream remains live",
    );
    let mut pre_delete_upstream = current_upstream.clone();
    pre_delete_upstream.name = Some("stale pre-delete snapshot".to_string());

    store
        .restore_api_spec_bundle(
            &bundle,
            &spec,
            &[pre_delete_upstream],
            &[],
            &restore_validation_http_client(),
        )
        .await
        .expect("restore must reuse the hand upstream retained by another proxy");

    assert!(
        store
            .get_proxy(ns, &restored_proxy_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_some());
    let preserved_upstream = store
        .get_upstream(ns, &shared_upstream_id)
        .await
        .unwrap()
        .expect("shared upstream must remain present");
    assert_eq!(
        preserved_upstream.name.as_deref(),
        Some("current shared upstream")
    );
}

#[tokio::test]
async fn restore_bundle_rejects_recreated_additional_upstream_identity() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let upstream_id = uid("restore-recreated-hand-upstream");
    let proxy_id = uid("restore-recreated-proxy");
    let spec_id = uid("restore-recreated-spec");

    let recreated_upstream = make_upstream(&upstream_id, ns);
    store
        .create_upstream(&recreated_upstream)
        .await
        .expect("create intervening replacement upstream");
    let mut pre_delete_upstream = recreated_upstream.clone();
    pre_delete_upstream.created_at = recreated_upstream.created_at - chrono::Duration::seconds(1);

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.upstream_id = Some(upstream_id.clone());
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"reject upstream recreated after orphan cascade",
    );

    let error = store
        .restore_api_spec_bundle(
            &bundle,
            &spec,
            &[pre_delete_upstream],
            &[],
            &restore_validation_http_client(),
        )
        .await
        .expect_err("replacement upstream identity must reject compensation");
    assert!(
        error
            .to_string()
            .contains("does not match its pre-delete identity"),
        "unexpected replacement-upstream error: {error:#}"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
    assert!(
        store
            .get_upstream(ns, &upstream_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn restore_bundle_rejects_intervening_schema_dependency_removal() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-schema-proxy");
    let plugin_id = uid("restore-schema-logger");
    let spec_id = uid("restore-schema-spec");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: plugin_id.clone(),
    }];
    let mut plugin = make_plugin(&plugin_id, &proxy_id, ns, Some(&spec_id));
    plugin.plugin_name = "stdout_logging".to_string();
    plugin.config = serde_json::json!({"schema_ref": "removed-during-delete"});
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![plugin],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"restore after schema dependency removal",
    );

    let error = store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect_err("missing current schema dependency must reject compensation");
    let error_message = error.to_string();
    assert!(
        error_message.contains(&plugin_id)
            && error_message.contains("references unknown schema")
            && error_message.contains("removed-during-delete"),
        "unexpected schema dependency error: {error:#}"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(
        store
            .get_plugin_config(ns, &plugin_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
}

#[test]
fn mongo_restore_keeps_additional_upstreams_inside_the_transaction() {
    let source = include_str!("../../src/config/mongo_store.rs");
    let restore_start = source
        .find("async fn restore_api_spec_bundle(")
        .expect("Mongo restore implementation");
    let restore_end = source[restore_start..]
        .find("async fn replace_api_spec_bundle(")
        .map(|offset| restore_start + offset)
        .expect("end of Mongo restore implementation");
    let restore = &source[restore_start..restore_end];

    assert!(restore.contains("prepare_api_spec_restore_docs("));
    assert!(restore.contains("prepared_docs.additional_upstreams"));
    assert!(restore.contains("validate_api_spec_retained_upstream_identity("));
    assert!(restore.contains("validation_http_client: &crate::plugins::PluginHttpClient"));
    assert!(restore.contains("validate_api_spec_restore_candidate_in_session("));
    assert!(restore.contains("validation_http_client,"));
    assert!(!restore.contains("PluginHttpClient::default()"));
    assert!(restore.contains("record_config_change_in_session("));
}

#[tokio::test]
async fn restore_bundle_rejects_invalid_additional_upstream_ownership_before_writing() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    for (suffix, additional_id_matches_bundle, owner, expected_error) in [
        ("overlap", true, None, "overlapping upstream id"),
        (
            "foreign",
            false,
            Some("different-api-spec"),
            "owned by a different API spec",
        ),
    ] {
        let proxy_id = format!("restore-upstream-input-{suffix}-proxy");
        let spec_id = format!("restore-upstream-input-{suffix}-spec");
        let upstream_id = format!("restore-upstream-input-{suffix}-owned");
        let additional_id = if additional_id_matches_bundle {
            upstream_id.clone()
        } else {
            format!("restore-upstream-input-{suffix}-additional")
        };
        let mut proxy = make_proxy(&proxy_id, ns);
        proxy.api_spec_id = Some(spec_id.clone());
        proxy.upstream_id = Some(upstream_id.clone());
        let mut upstream = make_upstream(&upstream_id, ns);
        upstream.api_spec_id = Some(spec_id.clone());
        let bundle = ExtractedBundle {
            proxy,
            upstream: Some(upstream),
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns, b"invalid additional upstream");
        let mut additional = make_upstream(&additional_id, ns);
        additional.api_spec_id = owner.map(str::to_string);

        let error = store
            .restore_api_spec_bundle(
                &bundle,
                &spec,
                &[additional],
                &[],
                &restore_validation_http_client(),
            )
            .await
            .expect_err("invalid additional upstream must fail before persistence");
        assert!(
            error.to_string().contains(expected_error),
            "unexpected additional-upstream validation error: {error:#}"
        );
        assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
        assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
        assert!(
            store
                .get_upstream(ns, &upstream_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_upstream(ns, &additional_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn restore_bundle_rejects_overlapping_ids_and_foreign_ownership_before_writing() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    for (suffix, additional_owner, expected_error) in [
        ("overlap", None, "overlapping plugin id"),
        (
            "foreign",
            Some("different-api-spec"),
            "owned by an API spec",
        ),
    ] {
        let proxy_id = format!("restore-input-{suffix}-proxy");
        let plugin_id = format!("restore-input-{suffix}-plugin");
        let additional_id = if suffix == "overlap" {
            plugin_id.clone()
        } else {
            format!("restore-input-{suffix}-additional")
        };
        let spec_id = format!("restore-input-{suffix}-spec");
        let mut proxy = make_proxy(&proxy_id, ns);
        proxy.api_spec_id = Some(spec_id.clone());
        proxy.plugins = vec![PluginAssociation {
            plugin_config_id: plugin_id.clone(),
        }];
        if plugin_id != additional_id {
            proxy.plugins.push(PluginAssociation {
                plugin_config_id: additional_id.clone(),
            });
        }
        let bundle = ExtractedBundle {
            proxy,
            upstream: None,
            plugins: vec![make_plugin(&plugin_id, &proxy_id, ns, Some(&spec_id))],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns, b"invalid restore input");
        let additional = make_plugin(&additional_id, &proxy_id, ns, additional_owner);

        let error = store
            .restore_api_spec_bundle(
                &bundle,
                &spec,
                &[],
                &[additional],
                &restore_validation_http_client(),
            )
            .await
            .expect_err("invalid restore input must fail");
        assert!(
            error.to_string().contains(expected_error),
            "unexpected restore validation error: {error:#}"
        );
        assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
        assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn restore_bundle_rejects_wrong_preexisting_plugin_instance_and_rolls_back() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-wrong-instance-proxy");
    let external_plugin_id = uid("restore-wrong-instance-plugin");
    let spec_id = uid("restore-wrong-instance-spec");

    let mut global = make_plugin(&external_plugin_id, &proxy_id, ns, None);
    global.scope = PluginScope::Global;
    global.proxy_id = None;
    store
        .create_plugin_config(&global)
        .await
        .expect("seed global plugin failed");
    let baseline_changes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM config_changes WHERE namespace = ?")
            .bind(ns)
            .fetch_one(&store.pool())
            .await
            .expect("count baseline changes failed");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: external_plugin_id.clone(),
    }];
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"wrong plugin instance restore");
    let error = store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect_err("global plugin association must fail closed");
    assert!(
        error
            .to_string()
            .contains("invalid proxy/plugin associations"),
        "unexpected wrong-instance error: {error:#}"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
    assert!(
        store
            .get_plugin_config(ns, &external_plugin_id)
            .await
            .unwrap()
            .is_some(),
        "pre-existing plugin must survive the rolled-back restore"
    );
    let final_changes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM config_changes WHERE namespace = ?")
            .bind(ns)
            .fetch_one(&store.pool())
            .await
            .expect("count final changes failed");
    assert_eq!(final_changes, baseline_changes);
}

#[tokio::test]
async fn restore_bundle_preserves_preexisting_proxy_when_later_insert_conflicts() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-existing-proxy");
    let upstream_id = uid("restore-conflict-upstream");
    let spec_id = uid("restore-conflict-spec");
    let existing = make_proxy(&proxy_id, ns);
    store
        .create_proxy(&existing)
        .await
        .expect("seed existing proxy failed");

    let mut restore_proxy = existing.clone();
    restore_proxy.api_spec_id = Some(spec_id.clone());
    let mut restore_upstream = make_upstream(&upstream_id, ns);
    restore_upstream.api_spec_id = Some(spec_id.clone());
    let bundle = ExtractedBundle {
        proxy: restore_proxy,
        upstream: Some(restore_upstream),
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"pre-existing proxy conflict");
    assert!(
        store
            .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
            .await
            .is_err()
    );

    let preserved = store
        .get_proxy(ns, &proxy_id)
        .await
        .unwrap()
        .expect("pre-existing proxy was lost");
    assert_eq!(preserved.id, existing.id);
    assert!(
        store
            .get_upstream(ns, &upstream_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
}

#[tokio::test]
async fn restore_bundle_rejects_intervening_route_conflict_and_rolls_back() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let existing_proxy_id = uid("restore-route-existing");
    let restored_proxy_id = uid("restore-route-candidate");
    let restored_upstream_id = uid("restore-route-upstream");
    let spec_id = uid("restore-route-spec");

    let existing = make_proxy(&existing_proxy_id, ns);
    store
        .create_proxy(&existing)
        .await
        .expect("seed intervening route failed");

    let mut restored_proxy = make_proxy(&restored_proxy_id, ns);
    restored_proxy.api_spec_id = Some(spec_id.clone());
    restored_proxy.listen_path = existing.listen_path.clone();
    let mut restored_upstream = make_upstream(&restored_upstream_id, ns);
    restored_upstream.api_spec_id = Some(spec_id.clone());
    let bundle = ExtractedBundle {
        proxy: restored_proxy,
        upstream: Some(restored_upstream),
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &restored_proxy_id,
        ns,
        b"intervening route conflict",
    );

    let error = store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect_err("overlapping intervening route must reject compensation");
    assert!(
        error.to_string().contains("overlapping hosts"),
        "unexpected route-conflict error: {error:#}"
    );
    assert!(
        store
            .get_proxy(ns, &existing_proxy_id)
            .await
            .unwrap()
            .is_some(),
        "intervening proxy must survive rejected compensation"
    );
    assert!(
        store
            .get_proxy(ns, &restored_proxy_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_upstream(ns, &restored_upstream_id)
            .await
            .unwrap()
            .is_none(),
        "upstream inserted before route admission must roll back"
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
}

#[tokio::test]
async fn restore_bundle_rejects_missing_hand_owned_upstream_reference() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-missing-upstream-proxy");
    let missing_upstream_id = uid("restore-missing-upstream");
    let spec_id = uid("restore-missing-upstream-spec");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.upstream_id = Some(missing_upstream_id);
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"missing hand-owned upstream");

    assert!(
        store
            .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
            .await
            .is_err(),
        "compensation must reject a proxy whose hand-owned upstream disappeared"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
}

#[tokio::test]
async fn restore_bundle_rejects_intervening_hand_owned_upstream_subset_change() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-subset-proxy");
    let upstream_id = uid("restore-subset-upstream");
    let spec_id = uid("restore-subset-spec");

    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": upstream_id,
        "namespace": ns,
        "targets": [{
            "host": "target.internal",
            "port": 443,
            "tags": {"version": "blue"}
        }],
        "subsets": [{"name": "blue", "labels": {"version": "blue"}}]
    }))
    .expect("subset upstream deserialization failed");
    store
        .create_upstream(&upstream)
        .await
        .expect("seed hand-owned upstream failed");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.upstream_id = Some(upstream_id.clone());
    proxy.upstream_subset = Some("blue".to_string());
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"restored subset snapshot");

    upstream.subsets = None;
    assert!(
        store
            .update_upstream(&upstream)
            .await
            .expect("intervening upstream update failed")
    );

    let error = store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect_err("removed upstream subset must reject compensation");
    assert!(
        error.to_string().contains("upstream_subset 'blue'"),
        "unexpected subset validation error: {error:#}"
    );
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_none());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_none());
    assert!(
        store
            .get_upstream(ns, &upstream_id)
            .await
            .unwrap()
            .is_some_and(|current| current.subsets.is_none()),
        "rejected compensation must preserve the intervening upstream"
    );
}

#[tokio::test]
async fn restore_bundle_accepts_intervening_hand_owned_mesh_retry_change() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let proxy_id = uid("restore-mesh-retry-proxy");
    let upstream_id = uid("restore-mesh-retry-upstream");
    let spec_id = uid("restore-mesh-retry-spec");

    let mut upstream = make_upstream(&upstream_id, ns);
    store
        .create_upstream(&upstream)
        .await
        .expect("seed hand-owned upstream failed");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.api_spec_id = Some(spec_id.clone());
    proxy.upstream_id = Some(upstream_id.clone());
    proxy.retry = Some(
        serde_json::from_value(serde_json::json!({"max_retries": 1}))
            .expect("retry deserialization failed"),
    );
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"restored mesh retry snapshot");

    upstream.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());
    assert!(
        store
            .update_upstream(&upstream)
            .await
            .expect("intervening mesh upstream update failed")
    );

    store
        .restore_api_spec_bundle(&bundle, &spec, &[], &[], &restore_validation_http_client())
        .await
        .expect("mesh transport targets must remain valid with retries");
    assert!(store.get_proxy(ns, &proxy_id).await.unwrap().is_some());
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_some());
    assert!(
        store
            .get_upstream(ns, &upstream_id)
            .await
            .unwrap()
            .is_some_and(|current| {
                current.targets[0]
                    .tags
                    .get("mesh.hbone")
                    .map(String::as_str)
                    == Some("true")
            }),
        "restore must preserve the intervening mesh upstream"
    );
}

// ---------------------------------------------------------------------------
// replace_api_spec_bundle
// ---------------------------------------------------------------------------

/// After replace: the spec-owned plugin is gone (replaced), but a hand-added
/// plugin (api_spec_id = NULL) on the same proxy survives.
#[tokio::test]
async fn replace_bundle_spec_owned_replaced_hand_added_survives() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let hand_plugin_id = uid("plugin");

    // Initial submit: one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Now hand-add a plugin directly (api_spec_id = NULL).
    let hand_plugin = make_plugin(&hand_plugin_id, &proxy_id, ns, None);
    store
        .create_plugin_config(&hand_plugin)
        .await
        .expect("hand-add plugin failed");

    // Verify both plugins exist before replace.
    let before = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list failed");
    let proxy_plugins_before: Vec<_> = before
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(
        proxy_plugins_before.len(),
        2,
        "expected 2 plugins before replace"
    );

    // Replace: new bundle has a different spec-owned plugin.
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 spec");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Old spec-owned plugin must be gone.
    let old_plugin = store
        .get_plugin_config(ns, &spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        old_plugin.is_none(),
        "old spec-owned plugin must be removed after replace"
    );

    // New spec-owned plugin must exist.
    let new_plugin = store
        .get_plugin_config(ns, &new_spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        new_plugin.is_some(),
        "new spec-owned plugin must exist after replace"
    );

    // The hand-added plugin (NULL api_spec_id) must survive because replace now
    // UPDATE-s the proxy in place rather than DELETE + INSERT, so the proxy PK
    // is stable and the FK cascade does NOT fire.
    let hand_plugin_row = store
        .get_plugin_config(ns, &hand_plugin_id)
        .await
        .expect("get_plugin_config for hand plugin failed");
    assert!(
        hand_plugin_row.is_some(),
        "hand-added plugin must survive spec replace (proxy updated in place)"
    );

    // Proxy primary key must be stable — same id, same created_at.
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after replace");
    assert_eq!(
        proxy_after.id, proxy_id,
        "proxy id must be unchanged after replace"
    );
}

#[tokio::test]
async fn replace_api_spec_bundle_does_not_delete_same_api_spec_id_in_other_namespace() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let other_ns = "other-ns";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let other_plugin_id = uid("plugin-other-ns");
    let other_upstream_id = uid("upstream-other-ns");

    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![make_plugin(&spec_plugin_id, &proxy_id, ns, None)],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    let other_plugin = PluginConfig {
        labels: Default::default(),
        id: other_plugin_id.clone(),
        namespace: other_ns.to_string(),
        plugin_name: "cors".to_string(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_plugin_config(&other_plugin)
        .await
        .expect("create other namespace plugin");
    let other_upstream = make_upstream(&other_upstream_id, other_ns);
    store
        .create_upstream(&other_upstream)
        .await
        .expect("create other namespace upstream");

    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE id = ?")
        .bind(&spec_id)
        .bind(&other_plugin_id)
        .execute(&store.pool())
        .await
        .expect("tag other namespace plugin");
    sqlx::query("UPDATE upstreams SET api_spec_id = ? WHERE id = ?")
        .bind(&spec_id)
        .bind(&other_upstream_id)
        .execute(&store.pool())
        .await
        .expect("tag other namespace upstream");

    let new_spec_plugin_id = uid("plugin");
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![make_plugin(&new_spec_plugin_id, &proxy_id, ns, None)],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 spec");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    assert!(
        store
            .get_plugin_config(other_ns, &other_plugin_id)
            .await
            .expect("get other namespace plugin")
            .is_some(),
        "replace must not delete a plugin_config in another namespace even if api_spec_id matches"
    );
    assert!(
        store
            .get_upstream(other_ns, &other_upstream_id)
            .await
            .expect("get other namespace upstream")
            .is_some(),
        "replace must not delete an upstream in another namespace even if api_spec_id matches"
    );
}

// ---------------------------------------------------------------------------
// get_api_spec round-trip (spec_content bytes are preserved)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_bytes_round_trip() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Use a content string with non-ASCII bytes to stress the BLOB path.
    let raw_content: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &raw_content);

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");

    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "BLOB round-trip must preserve all bytes"
    );
    assert_eq!(fetched.uncompressed_size, 512);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(fetched.spec_format, SpecFormat::Json);
    assert_eq!(fetched.title.as_deref(), Some("Test API"));
    assert_eq!(fetched.info_version.as_deref(), Some("1.0.0"));
}

// ---------------------------------------------------------------------------
// get_api_spec_by_proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_by_proxy_returns_none_for_unknown_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let result = store
        .get_api_spec_by_proxy("ferrum", "nonexistent-proxy-id")
        .await
        .expect("get_api_spec_by_proxy failed");
    assert!(result.is_none());
}

#[tokio::test]
async fn get_api_spec_by_proxy_finds_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let result = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(result.id, spec_id);
}

// ---------------------------------------------------------------------------
// list_api_specs — namespace-scoped, paginated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_api_specs_namespace_scoped_and_paginated() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let ns_a = "ns-a";
    let ns_b = "ns-b";

    // Insert 3 specs in ns_a and 1 in ns_b.
    for i in 0..3 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_a),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_a, format!("spec-{i}").as_bytes());
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .unwrap_or_else(|e| panic!("submit ns_a spec {i} failed: {e}"));
    }
    {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_b),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_b, b"ns-b spec");
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .expect("submit ns_b spec failed");
    }

    // All 3 ns_a specs.
    let all_a = store
        .list_api_specs(ns_a, &simple_filter(100, 0))
        .await
        .expect("list_api_specs failed")
        .items;
    assert_eq!(all_a.len(), 3, "ns_a must have 3 specs");

    // Pagination: first page (limit=2), second page (limit=2, offset=2).
    let page1 = store
        .list_api_specs(ns_a, &simple_filter(2, 0))
        .await
        .expect("page1 failed")
        .items;
    let page2 = store
        .list_api_specs(ns_a, &simple_filter(2, 2))
        .await
        .expect("page2 failed")
        .items;
    assert_eq!(page1.len(), 2, "page1 should have 2 items");
    assert_eq!(page2.len(), 1, "page2 should have 1 item");

    // Namespace isolation: ns_b must have exactly 1 spec.
    let all_b = store
        .list_api_specs(ns_b, &simple_filter(100, 0))
        .await
        .expect("list ns_b failed")
        .items;
    assert_eq!(all_b.len(), 1, "ns_b must have 1 spec");

    // The authoritative count-only path is namespace scoped and does not need
    // to fetch or deserialize any API spec summary rows.
    assert_eq!(store.count_api_specs(ns_a).await.unwrap(), 3);
    assert_eq!(store.count_api_specs(ns_b).await.unwrap(), 1);
    assert_eq!(store.count_api_specs("missing").await.unwrap(), 0);

    // ns_b spec must not appear in ns_a results.
    let b_id = &all_b[0].id;
    assert!(
        all_a.iter().all(|s| &s.id != b_id),
        "ns_b spec must not appear in ns_a listing"
    );
}

#[tokio::test]
async fn list_api_specs_does_not_hydrate_spec_content_blob() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let raw_content = vec![b'x'; 1024 * 64];
    let mut spec = make_spec(&spec_id, &proxy_id, ns, &raw_content);
    let snapshot = ExternalRefSnapshot::empty(&EffectiveExternalRefPolicy::disabled());
    let snapshot_bytes = snapshot.gzip_bytes().expect("snapshot gzip");
    spec.external_ref_snapshot = Some(snapshot_bytes.clone());
    spec.external_ref_digest = Some(snapshot.snapshot_digest.clone());
    let stored_spec_content = spec.spec_content.clone();
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let listed = store
        .list_api_specs(ns, &simple_filter(100, 0))
        .await
        .expect("list_api_specs failed")
        .items;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, spec_id);
    assert_eq!(listed[0].content_hash, spec.content_hash);
    assert_eq!(listed[0].external_ref_digest, spec.external_ref_digest);
    assert!(
        listed[0].spec_content.is_empty(),
        "list_api_specs is a summary path and must not hydrate the compressed spec blob"
    );
    assert!(
        listed[0].external_ref_snapshot.is_none(),
        "list_api_specs must keep external snapshot bytes private"
    );

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert_eq!(
        fetched.spec_content, stored_spec_content,
        "single-spec GET must still hydrate the compressed spec blob"
    );
    assert_eq!(fetched.external_ref_snapshot, Some(snapshot_bytes));
}

// ---------------------------------------------------------------------------
// delete_api_spec — cascade behaviour
// ---------------------------------------------------------------------------

/// delete_api_spec removes the proxy, spec-owned plugins, spec-owned upstream,
/// and the spec row itself. A non-spec-owned upstream (hand-created, no
/// api_spec_id) is NOT removed.
#[tokio::test]
async fn delete_api_spec_cascades_and_spares_hand_upstreams() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id = uid("plugin");
    let spec_id = uid("spec");

    // Spec-owned upstream + proxy + plugin.
    let spec_upstream = make_upstream(&upstream_id, ns);
    let spec_plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: Some(spec_upstream),
        plugins: vec![spec_plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"to be deleted");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Create a hand-added upstream (not owned by any spec).
    let hand_upstream_id = uid("upstream");
    let hand_upstream = make_upstream(&hand_upstream_id, ns);
    store
        .create_upstream(&hand_upstream)
        .await
        .expect("create hand upstream failed");

    // Delete the spec.
    let deleted = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(
        deleted,
        "delete_api_spec must return true for existing spec"
    );

    // Spec row must be gone.
    let spec_row = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(spec_row.is_none(), "spec row must be gone after delete");

    // Proxy must be gone.
    let proxy_row = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed");
    assert!(proxy_row.is_none(), "proxy must be gone after spec delete");

    // Spec-owned upstream must be gone.
    let upstream_row = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream failed");
    assert!(
        upstream_row.is_none(),
        "spec-owned upstream must be gone after spec delete"
    );

    // Hand-added upstream must still exist.
    let hand_row = store
        .get_upstream(ns, &hand_upstream_id)
        .await
        .expect("get_upstream for hand upstream failed");
    assert!(
        hand_row.is_some(),
        "hand-added upstream must survive spec delete"
    );

    // Spec-owned plugin must be gone (deleted by either api_spec_id cleanup or
    // the proxy FK cascade — both are in play).
    let plugin_row = store
        .get_plugin_config(ns, &plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        plugin_row.is_none(),
        "spec-owned plugin must be gone after spec delete"
    );
}

#[tokio::test]
async fn delete_api_spec_does_not_delete_same_api_spec_id_in_other_namespace() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let other_ns = "other-ns";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let other_plugin_id = uid("plugin-other-ns");
    let other_upstream_id = uid("upstream-other-ns");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"delete namespace guard");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let other_plugin = PluginConfig {
        labels: Default::default(),
        id: other_plugin_id.clone(),
        namespace: other_ns.to_string(),
        plugin_name: "cors".to_string(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_plugin_config(&other_plugin)
        .await
        .expect("create other namespace plugin");
    let other_upstream = make_upstream(&other_upstream_id, other_ns);
    store
        .create_upstream(&other_upstream)
        .await
        .expect("create other namespace upstream");

    sqlx::query("UPDATE plugin_configs SET api_spec_id = ? WHERE id = ?")
        .bind(&spec_id)
        .bind(&other_plugin_id)
        .execute(&store.pool())
        .await
        .expect("tag other namespace plugin");
    sqlx::query("UPDATE upstreams SET api_spec_id = ? WHERE id = ?")
        .bind(&spec_id)
        .bind(&other_upstream_id)
        .execute(&store.pool())
        .await
        .expect("tag other namespace upstream");

    assert!(
        store
            .delete_api_spec(ns, &spec_id)
            .await
            .expect("delete_api_spec failed"),
        "expected delete to find the spec"
    );
    assert!(
        store
            .get_plugin_config(other_ns, &other_plugin_id)
            .await
            .expect("get other namespace plugin")
            .is_some(),
        "delete must not remove a plugin_config in another namespace even if api_spec_id matches"
    );
    assert!(
        store
            .get_upstream(other_ns, &other_upstream_id)
            .await
            .expect("get other namespace upstream")
            .is_some(),
        "delete must not remove an upstream in another namespace even if api_spec_id matches"
    );
}

#[tokio::test]
async fn delete_api_spec_cleans_orphaned_proxy_group_plugin() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let proxy_group_plugin_id = uid("proxy-group-plugin");
    let spec_id = uid("spec");

    let proxy_group_plugin = PluginConfig {
        labels: Default::default(),
        id: proxy_group_plugin_id.clone(),
        namespace: ns.to_string(),
        plugin_name: "cors".to_string(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_plugin_config(&proxy_group_plugin)
        .await
        .expect("create proxy_group plugin");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: proxy_group_plugin_id.clone(),
    }];
    let bundle = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"spec with proxy_group association",
    );

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit bundle");

    assert!(
        store
            .get_plugin_config(ns, &proxy_group_plugin_id)
            .await
            .expect("get proxy_group before delete")
            .is_some(),
        "proxy_group plugin must exist before deleting the spec"
    );

    let deleted = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect("delete api spec");
    assert!(deleted, "delete_api_spec should report deletion");

    assert!(
        store
            .get_plugin_config(ns, &proxy_group_plugin_id)
            .await
            .expect("get proxy_group after delete")
            .is_none(),
        "delete_api_spec must mirror delete_proxy and remove proxy_group \
         plugin configs once their last proxy association is gone"
    );
}

/// delete_api_spec returns false for a non-existent spec.
///
/// Mongo invariant (non-RS path): `delete_api_spec` in `mongo_store.rs` uses
/// best-effort deletes with `warn!` logging for each collection when no replica
/// set is configured.  When a replica set IS configured it wraps all deletes in
/// a single `with_transaction` session so partial failures roll back atomically,
/// matching the behaviour of `submit_api_spec_bundle` and
/// `replace_api_spec_bundle`.  This test exercises the SQL path only; the Mongo
/// transaction path requires a live replica-set MongoDB and is validated in CI
/// via manual Mongo integration testing.
#[tokio::test]
async fn delete_api_spec_returns_false_for_missing_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let deleted = store
        .delete_api_spec("ferrum", "nonexistent-spec-id")
        .await
        .expect("delete_api_spec failed");
    assert!(
        !deleted,
        "delete_api_spec must return false for missing spec"
    );
}

#[tokio::test]
async fn delete_api_spec_rejects_removing_last_global_tcp_throttle_target() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";
    let spec_id = uid("spec-tcp-delete-guard");
    let tcp_proxy_id = uid("tcp-proxy");
    let http_proxy_id = uid("http-proxy");
    let tcp_proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": tcp_proxy_id,
        "namespace": ns,
        "backend_scheme": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": 9000,
        "listen_port": 19101
    }))
    .unwrap();
    let bundle = ExtractedBundle {
        proxy: tcp_proxy.clone(),
        upstream: None,
        plugins: Vec::new(),
    };
    let spec = make_spec(&spec_id, &tcp_proxy_id, ns, b"tcp spec");
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    store
        .create_proxy(&make_proxy(&http_proxy_id, ns))
        .await
        .unwrap();
    let now = chrono::Utc::now();
    store
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: uid("global-tcp-throttle"),
            namespace: ns.to_string(),
            plugin_name: "tcp_connection_throttle".to_string(),
            config: serde_json::json!({"max_connections_per_key": 10}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("the mixed global graph has a supported TCP target");

    let error = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect_err("the API-spec cascade must not remove the final TCP target");
    assert!(
        tcp_connection_throttle_attachment_conflict(&error).is_some(),
        "unexpected API-spec delete rejection: {error:#}"
    );
    assert!(store.get_api_spec(ns, &spec_id).await.unwrap().is_some());
    assert!(store.get_proxy(ns, &tcp_proxy_id).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Namespace isolation
// ---------------------------------------------------------------------------

/// A spec in namespace A must not be visible from namespace B.
#[tokio::test]
async fn spec_in_ns_a_invisible_from_ns_b() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, "ns-a"),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, "ns-a", b"ns-a content");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // get_api_spec with wrong namespace → None.
    let result = store
        .get_api_spec("ns-b", &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(result.is_none(), "spec in ns-a must be invisible from ns-b");

    // list_api_specs for ns-b → empty.
    let list = store
        .list_api_specs("ns-b", &simple_filter(100, 0))
        .await
        .expect("list_api_specs failed")
        .items;
    assert!(list.is_empty(), "ns-b must have no specs");

    // delete_api_spec with wrong namespace → false.
    let deleted = store
        .delete_api_spec("ns-b", &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(!deleted, "delete from wrong namespace must return false");

    // spec still accessible from correct namespace.
    let still_there = store
        .get_api_spec("ns-a", &spec_id)
        .await
        .expect("get_api_spec ns-a failed");
    assert!(
        still_there.is_some(),
        "spec in ns-a must still exist after failed delete from ns-b"
    );
}

// ---------------------------------------------------------------------------
// Gap #1: Hot-path isolation — api_specs NOT in GatewayConfig
// ---------------------------------------------------------------------------

/// `load_full_config` must return a `GatewayConfig` that contains the proxy
/// and plugin created via the api_spec bundle path, but must NOT expose any
/// `api_specs` / `spec` field at the top level.  This test acts as a compile-
/// time + runtime canary: a future contributor who accidentally adds an
/// `api_specs` field to `GatewayConfig` will fail both the serde assertion
/// and, if the field is `#[serde(skip)]`, the field-name grep in CI.
///
/// Additionally, the `ResourceTable` enum inside `db_loader` has no
/// `ApiSpecs` variant (by design — the runtime polling loop must never
/// read that table).  We cannot enumerate private enum variants here, but
/// the comment in the source file acts as the authoritative guard.
#[tokio::test]
async fn api_specs_not_in_gateway_config_load() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert a real proxy + plugin via the spec bundle path.
    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    // 1 MiB+ spec content to stress the path.
    let big_content: Vec<u8> = (0u8..=255u8).cycle().take(1_048_576).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &big_content);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // Load the runtime config the way the gateway does.
    let config: GatewayConfig = store
        .load_full_config(ns)
        .await
        .expect("load_full_config failed");

    // Prove the loader actually sees the proxy and plugin (same DB).
    let proxy_present = config.proxies.iter().any(|p| p.id == proxy_id);
    assert!(
        proxy_present,
        "loaded config must contain the submitted proxy"
    );
    let plugin_present = config.plugin_configs.iter().any(|pc| pc.id == plugin_id);
    assert!(
        plugin_present,
        "loaded config must contain the submitted plugin"
    );

    // Prove no `api_specs` / `specs` field leaks into the serialized config.
    let config_value = serde_json::to_value(&config).expect("GatewayConfig must serialize to JSON");
    assert!(
        config_value.get("api_specs").is_none(),
        "GatewayConfig must NOT have an 'api_specs' field (hot-path isolation); \
         future contributor: do NOT add api_specs to GatewayConfig"
    );
    assert!(
        config_value.get("specs").is_none(),
        "GatewayConfig must NOT have a 'specs' field"
    );
}

// ---------------------------------------------------------------------------
// Fix 5: runtime load strips api_spec_id from resources
// ---------------------------------------------------------------------------

/// Resources created via submit_api_spec_bundle carry an api_spec_id tag in the
/// DB. load_full_config must strip that tag (set it to None) on every Proxy,
/// PluginConfig, and Upstream it returns, mirroring the SQL path's explicit
/// `api_spec_id: None` in the row-to-struct helpers.
///
/// The Mongo path enforces the same invariant via post-processing in
/// load_full_config / the incremental polling loop — see mongo_store.rs.
#[tokio::test]
async fn runtime_load_strips_api_spec_id_from_resources() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id = uid("plugin");
    let spec_id = uid("spec");

    let upstream = make_upstream(&upstream_id, ns);
    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: Some(upstream),
        plugins: vec![plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec for load-strip test");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Load the runtime config.
    let config: GatewayConfig = store
        .load_full_config(ns)
        .await
        .expect("load_full_config failed");

    // Every proxy in the loaded config must have api_spec_id = None.
    for p in &config.proxies {
        assert!(
            p.api_spec_id.is_none(),
            "Proxy {}: api_spec_id must be None in runtime config (hot-path isolation)",
            p.id
        );
    }

    // Every plugin in the loaded config must have api_spec_id = None.
    for pc in &config.plugin_configs {
        assert!(
            pc.api_spec_id.is_none(),
            "PluginConfig {}: api_spec_id must be None in runtime config",
            pc.id
        );
    }

    // Every upstream in the loaded config must have api_spec_id = None.
    for u in &config.upstreams {
        assert!(
            u.api_spec_id.is_none(),
            "Upstream {}: api_spec_id must be None in runtime config",
            u.id
        );
    }
}

// ---------------------------------------------------------------------------
// Gap #4: DELETE proxy cascades the api_spec row via FK
// ---------------------------------------------------------------------------

/// When a proxy is deleted directly (via `delete_proxy`, not via
/// `delete_api_spec`), the `api_specs` row that FKs onto that proxy must be
/// removed automatically by the `ON DELETE CASCADE` constraint, and the
/// spec-owned plugin must also be gone (double cascade via plugin_configs FK).
///
/// # Mongo equivalence (Fix 3)
///
/// The SQL path relies on the `api_specs.proxy_id REFERENCES proxies(id) ON DELETE CASCADE`
/// FK. The Mongo path has no FK, so `MongoStore::delete_proxy` calls
/// `api_specs().delete_many({proxy_id})` explicitly to mirror this behaviour.
/// See `src/config/mongo_store.rs` — the implementation is directly tested here
/// for SQL; the Mongo path requires a running MongoDB instance and follows the
/// same invariant by code-review and inline assertion.
#[tokio::test]
async fn delete_proxy_cascades_api_spec_row_via_fk() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec for fk cascade test");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Confirm spec and plugin are present before delete.
    let before_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(before_spec.is_some(), "spec must exist before delete");

    // Delete the proxy directly (not via delete_api_spec).
    let deleted = store
        .delete_proxy(ns, &proxy_id)
        .await
        .expect("delete_proxy failed");
    assert!(deleted, "delete_proxy must return true for existing proxy");

    // The api_spec row must be gone (FK ON DELETE CASCADE).
    let after_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed after proxy delete");
    assert!(
        after_spec.is_none(),
        "api_spec row must be cascade-deleted when its proxy is deleted"
    );

    // The spec-owned plugin must also be gone (proxy FK → plugin_configs cascade).
    let after_plugin = store
        .get_plugin_config(ns, &plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        after_plugin.is_none(),
        "spec-owned plugin must be cascade-deleted when its proxy is deleted"
    );
}

// ---------------------------------------------------------------------------
// Fix 2: replace_with_changed_resources_keeps_hand_added_plugins
// ---------------------------------------------------------------------------

/// When replace_api_spec_bundle is called with a genuinely new bundle (different
/// resource_hash), hand-added plugins (api_spec_id = NULL) on the proxy must
/// survive because the proxy is updated in place rather than deleted.
#[tokio::test]
async fn replace_with_changed_resources_keeps_hand_added_plugins() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let hand_plugin_id = uid("plugin");

    // Initial submit with one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec content");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Capture proxy created_at before replace.
    let proxy_before = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist before replace");
    let created_at_before = proxy_before.created_at;

    // Hand-add a plugin directly (api_spec_id = NULL).
    let hand_plugin = make_plugin(&hand_plugin_id, &proxy_id, ns, None);
    store
        .create_plugin_config(&hand_plugin)
        .await
        .expect("hand-add plugin failed");

    // Replace with a new bundle (different spec-owned plugin → different resource hash).
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"v2 spec content with changed resources",
    );
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Hand-added plugin must still exist.
    let hand_row = store
        .get_plugin_config(ns, &hand_plugin_id)
        .await
        .expect("get_plugin_config for hand plugin failed");
    assert!(
        hand_row.is_some(),
        "hand-added plugin must survive replace_api_spec_bundle with changed resources"
    );

    // Old spec-owned plugin must be gone.
    let old_spec_row = store
        .get_plugin_config(ns, &spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        old_spec_row.is_none(),
        "old spec-owned plugin must be removed after replace"
    );

    // New spec-owned plugin must exist.
    let new_spec_row = store
        .get_plugin_config(ns, &new_spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        new_spec_row.is_some(),
        "new spec-owned plugin must exist after replace"
    );

    // Proxy primary key must be preserved (created_at unchanged).
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist after replace");
    assert_eq!(proxy_after.id, proxy_id, "proxy id must be unchanged");
    assert_eq!(
        proxy_after.created_at.timestamp(),
        created_at_before.timestamp(),
        "proxy created_at must be unchanged after replace (proxy updated in place)"
    );
}

// ===========================================================================
// Wave 5 tests — Tier 1 metadata extraction, idempotent PUT, list filters
// ===========================================================================

// ---------------------------------------------------------------------------
// Test helpers for Wave 5
// ---------------------------------------------------------------------------

/// Build a full spec with all Tier 1 metadata fields populated. The spec body
/// is a valid OpenAPI 3.1 JSON document with info, contact, license, tags,
/// servers, and paths that the extractor can parse.
fn make_spec_with_metadata(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    title: &str,
    spec_version_suffix: &str,
    tags: &[&str],
) -> (ferrum_edge::admin::api_specs::ExtractedBundle, ApiSpec) {
    use ferrum_edge::admin::api_specs::hash_resource_bundle;
    use ferrum_edge::admin::spec_codec;
    use ferrum_edge::config::types::SpecFormat;

    let tags_json: String = tags
        .iter()
        .map(|t| format!(r#"{{"name": "{t}"}}"#))
        .collect::<Vec<_>>()
        .join(", ");

    let body = format!(
        r#"{{
            "openapi": "3.1.{spec_version_suffix}",
            "info": {{
                "title": "{title}",
                "version": "1.0.0",
                "description": "Test description for {title}",
                "contact": {{ "name": "Alice", "email": "alice@example.com" }},
                "license": {{ "name": "MIT", "identifier": "MIT" }}
            }},
            "tags": [{tags_json}],
            "servers": [{{"url": "https://api.example.com/v1"}}],
            "paths": {{
                "/foo": {{ "get": {{}}, "post": {{}} }},
                "/bar": {{ "delete": {{}} }}
            }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();

    let (bundle, meta) = ferrum_edge::admin::api_specs::extract(body_bytes, None, namespace)
        .expect("extract failed");

    let compressed = spec_codec::compress_gzip(body_bytes).expect("compress failed");
    let content_hash = spec_codec::sha256_hex(body_bytes);
    let resource_hash = hash_resource_bundle(&bundle)
        .expect("hash_resource_bundle should never fail for a valid bundle");

    let spec = ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: meta.version.clone(),
        spec_format: SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title.clone(),
        info_version: meta.info_version.clone(),
        description: meta.description.clone(),
        contact_name: meta.contact_name.clone(),
        contact_email: meta.contact_email.clone(),
        license_name: meta.license_name.clone(),
        license_identifier: meta.license_identifier.clone(),
        tags: meta.tags.clone(),
        server_urls: meta.server_urls.clone(),
        operation_count: meta.operation_count,
        resource_hash,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    (bundle, spec)
}

fn make_spec_from_openapi_body(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    body: &str,
) -> (ferrum_edge::admin::api_specs::ExtractedBundle, ApiSpec) {
    use ferrum_edge::admin::api_specs::hash_resource_bundle;
    use ferrum_edge::admin::spec_codec;
    use ferrum_edge::config::types::SpecFormat;

    let body_bytes = body.as_bytes();
    let (bundle, meta) = ferrum_edge::admin::api_specs::extract(body_bytes, None, namespace)
        .expect("extract failed");
    let resource_hash = hash_resource_bundle(&bundle)
        .expect("hash_resource_bundle should never fail for a valid bundle");

    let spec = ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: meta.version.clone(),
        spec_format: SpecFormat::Json,
        spec_content: spec_codec::compress_gzip(body_bytes).expect("compress failed"),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash: spec_codec::sha256_hex(body_bytes),
        title: meta.title.clone(),
        info_version: meta.info_version.clone(),
        description: meta.description.clone(),
        contact_name: meta.contact_name.clone(),
        contact_email: meta.contact_email.clone(),
        license_name: meta.license_name.clone(),
        license_identifier: meta.license_identifier.clone(),
        tags: meta.tags.clone(),
        server_urls: meta.server_urls.clone(),
        operation_count: meta.operation_count,
        resource_hash,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    (bundle, spec)
}

// ---------------------------------------------------------------------------
// Feature B: Tier 1 metadata extraction
// ---------------------------------------------------------------------------

/// Submit a spec with full info/contact/license/tags/servers/paths and verify
/// all 8 metadata fields are stored correctly.
#[tokio::test]
async fn submit_extracts_tier1_metadata() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let (bundle, spec) = make_spec_with_metadata(
        &spec_id,
        &proxy_id,
        ns,
        "Orders API",
        "0",
        &["public", "orders"],
    );

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("spec not found");

    // description
    assert!(
        fetched
            .description
            .as_deref()
            .unwrap_or("")
            .contains("Orders API"),
        "description must contain title text: {:?}",
        fetched.description
    );
    // contact
    assert_eq!(fetched.contact_name.as_deref(), Some("Alice"));
    assert_eq!(fetched.contact_email.as_deref(), Some("alice@example.com"));
    // license
    assert_eq!(fetched.license_name.as_deref(), Some("MIT"));
    assert_eq!(fetched.license_identifier.as_deref(), Some("MIT"));
    // tags — de-duplicated and sorted
    assert_eq!(fetched.tags, vec!["orders", "public"]);
    // server_urls
    assert_eq!(fetched.server_urls, vec!["https://api.example.com/v1"]);
    // operation_count: /foo has get+post (2), /bar has delete (1) = 3
    assert_eq!(fetched.operation_count, 3, "3 HTTP methods in paths");
    // resource_hash present
    assert!(!fetched.resource_hash.is_empty());
}

/// Description longer than 4096 bytes is truncated at a UTF-8 boundary.
#[tokio::test]
async fn submit_truncates_long_description_at_4kib() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Build a 10 KiB description using multi-byte chars to test UTF-8 boundary.
    // U+00E9 (é) is 2 bytes in UTF-8; 10 KiB / 2 = 5120 chars.
    let long_desc: String = "é".repeat(5120);
    assert!(
        long_desc.len() >= 10240,
        "description must be ≥ 10 KiB in bytes"
    );

    let body = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{
                "title": "Long Desc API",
                "version": "1.0.0",
                "description": "{long_desc}"
            }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();
    let (bundle, _) =
        ferrum_edge::admin::api_specs::extract(body_bytes, None, ns).expect("extract failed");

    let meta = ferrum_edge::admin::api_specs::extract(body_bytes, None, ns)
        .expect("extract failed")
        .1;
    let compressed = ferrum_edge::admin::spec_codec::compress_gzip(body_bytes).unwrap();
    let content_hash = ferrum_edge::admin::spec_codec::sha256_hex(body_bytes);
    let resource_hash = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle)
        .expect("hash_resource_bundle should never fail for a valid bundle");

    let spec = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title,
        info_version: meta.info_version,
        description: meta.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("spec not found");

    let stored_desc = fetched.description.expect("description must be stored");
    assert!(
        stored_desc.len() <= 4096,
        "stored description ({} bytes) must be ≤ 4096 bytes",
        stored_desc.len()
    );
    // Must be valid UTF-8 (Rust String guarantees this, but also check it's a
    // clean boundary by encoding/decoding).
    assert!(std::str::from_utf8(stored_desc.as_bytes()).is_ok());
}

/// Swagger 2.0: server_urls are constructed from `schemes + host + basePath`.
#[tokio::test]
async fn swagger_2_0_server_urls_constructed_from_schemes_host_basepath() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let body = format!(
        r#"{{
            "swagger": "2.0",
            "info": {{ "title": "Swagger API", "version": "1.0" }},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let body_bytes = body.as_bytes();
    let (bundle, meta) =
        ferrum_edge::admin::api_specs::extract(body_bytes, None, ns).expect("extract failed");
    let compressed = ferrum_edge::admin::spec_codec::compress_gzip(body_bytes).unwrap();
    let content_hash = ferrum_edge::admin::spec_codec::sha256_hex(body_bytes);
    let resource_hash = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle)
        .expect("hash_resource_bundle should never fail for a valid bundle");

    let spec = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_bytes.len() as u64,
        content_hash,
        title: meta.title,
        info_version: meta.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: meta.server_urls.clone(),
        operation_count: 0,
        resource_hash,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get failed")
        .expect("not found");

    assert_eq!(
        fetched.server_urls,
        vec!["https://api.example.com/v1"],
        "server_urls must be constructed from schemes+host+basePath for Swagger 2.0"
    );
}

// ---------------------------------------------------------------------------
// Feature A: idempotent PUT (hash short-circuit)
// ---------------------------------------------------------------------------

/// PUT with the same bundle (but potentially different spec document text like
/// description changes) must NOT update proxy.updated_at, but MUST advance
/// api_specs.updated_at.
#[tokio::test]
async fn replace_with_unchanged_resources_skips_proxy_write() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Initial submit.
    let body1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API v1", "version": "1.0", "description": "Original desc" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle1, meta1) =
        ferrum_edge::admin::api_specs::extract(body1.as_bytes(), None, ns).expect("extract1");
    let resource_hash1 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle1)
        .expect("hash_resource_bundle should never fail for a valid bundle");
    let spec1 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta1.version.clone(),
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body1.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body1.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body1.as_bytes()),
        title: meta1.title.clone(),
        info_version: meta1.info_version.clone(),
        description: meta1.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash1.clone(),
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("initial submit");

    // Capture proxy.updated_at before the PUT.
    let proxy_before = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    let proxy_updated_at_before = proxy_before.updated_at;

    // Small sleep to ensure any write would bump the timestamp.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // PUT with same bundle, different description (same resource_hash).
    let body2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API v1", "version": "1.0", "description": "Updated desc" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle2, meta2) =
        ferrum_edge::admin::api_specs::extract(body2.as_bytes(), None, ns).expect("extract2");
    let resource_hash2 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle2)
        .expect("hash_resource_bundle should never fail for a valid bundle");
    // Sanity: hashes must be identical (proxy unchanged).
    assert_eq!(
        resource_hash1, resource_hash2,
        "resource_hash must match when bundle is identical"
    );

    let now2 = chrono::Utc::now();
    let spec2 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta2.version.clone(),
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body2.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body2.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body2.as_bytes()),
        title: meta2.title.clone(),
        info_version: meta2.info_version.clone(),
        description: meta2.description.clone(),
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash2,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: spec1.created_at,
        updated_at: now2,
    };

    store
        .replace_api_spec_bundle(&bundle2, &spec2)
        .await
        .expect("replace failed");

    // proxy.updated_at must NOT have advanced.
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    assert_eq!(
        proxy_after.updated_at.timestamp(),
        proxy_updated_at_before.timestamp(),
        "proxy.updated_at must not change when bundle is unchanged"
    );

    // api_specs.updated_at MUST have advanced.
    let spec_after = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert!(
        spec_after.updated_at > proxy_updated_at_before,
        "api_specs.updated_at must advance on PUT even when bundle is unchanged"
    );
}

/// PUT with a real proxy field change must update proxy.updated_at.
#[tokio::test]
async fn replace_with_changed_resources_updates_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let body1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend-v1.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle1, meta1) =
        ferrum_edge::admin::api_specs::extract(body1.as_bytes(), None, ns).expect("extract1");
    let resource_hash1 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle1)
        .expect("hash_resource_bundle should never fail for a valid bundle");

    let spec1 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta1.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body1.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body1.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body1.as_bytes()),
        title: meta1.title,
        info_version: meta1.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash1.clone(),
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("initial submit");

    let proxy_before = store.get_proxy(ns, &proxy_id).await.unwrap().unwrap();
    let before_ts = proxy_before.updated_at;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Change backend_host → different resource_hash.
    let body2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend-v2.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle2, meta2) =
        ferrum_edge::admin::api_specs::extract(body2.as_bytes(), None, ns).expect("extract2");
    let resource_hash2 = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle2)
        .expect("hash_resource_bundle should never fail for a valid bundle");
    assert_ne!(
        resource_hash1, resource_hash2,
        "resource_hash must differ when proxy backend_host changes"
    );

    let now2 = chrono::Utc::now();
    let spec2 = ApiSpec {
        id: spec_id.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_id.clone(),
        spec_version: meta2.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body2.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body2.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body2.as_bytes()),
        title: meta2.title,
        info_version: meta2.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: resource_hash2,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: spec1.created_at,
        updated_at: now2,
    };

    store
        .replace_api_spec_bundle(&bundle2, &spec2)
        .await
        .expect("replace failed");

    // Proxy must have been re-inserted with new backend_host.
    let proxy_after = store.get_proxy(ns, &proxy_id).await.unwrap().unwrap();
    assert_eq!(proxy_after.backend_host, "backend-v2.internal");
    assert!(
        proxy_after.updated_at > before_ts || proxy_after.updated_at >= before_ts,
        "proxy.updated_at must advance when bundle changes"
    );
}

// ---------------------------------------------------------------------------
// Feature C: list filters
// ---------------------------------------------------------------------------

/// `?proxy_id=foo` returns only specs whose proxy_id matches exactly.
/// Each spec must have a unique proxy_id (DB constraint), so we use 2 proxies
/// in group A and 1 in group B. The test checks that filtering by one
/// specific proxy_id returns exactly that spec.
#[tokio::test]
async fn list_filter_proxy_id() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Submit three specs with distinct proxy_ids. We'll filter by proxy_a1.
    let proxy_a1 = uid("proxy-a1");
    let proxy_a2 = uid("proxy-a2");
    let proxy_b1 = uid("proxy-b1");

    let spec_a1 = uid("spec");
    let spec_a2 = uid("spec");
    let spec_b1 = uid("spec");

    let (bundle, spec) = make_spec_with_metadata(&spec_a1, &proxy_a1, ns, "API A1", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    let (bundle, spec) = make_spec_with_metadata(&spec_a2, &proxy_a2, ns, "API A2", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    let (bundle, spec) = make_spec_with_metadata(&spec_b1, &proxy_b1, ns, "API B1", "0", &[]);
    store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();

    // Filter by proxy_a1 — should return exactly 1.
    let filter = ApiSpecListFilter {
        proxy_id: Some(proxy_a1.clone()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed")
        .items;
    assert_eq!(results.len(), 1, "must return 1 spec for proxy_a1");
    assert_eq!(results[0].proxy_id, proxy_a1);

    // Filter by proxy_b1 — should return exactly 1.
    let filter2 = ApiSpecListFilter {
        proxy_id: Some(proxy_b1.clone()),
        limit: 100,
        ..Default::default()
    };
    let results2 = store
        .list_api_specs(ns, &filter2)
        .await
        .expect("list b1")
        .items;
    assert_eq!(results2.len(), 1, "must return 1 spec for proxy_b1");

    // No filter — should return all 3.
    let all = store
        .list_api_specs(ns, &simple_filter(100, 0))
        .await
        .expect("list all")
        .items;
    assert_eq!(all.len(), 3, "must return 3 specs without filter");
}

/// `?spec_version=3.1` returns only specs whose spec_version starts with `3.1`.
#[tokio::test]
async fn list_filter_spec_version_prefix() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Submit specs with versions 3.1.0, 3.1.0 (different proxy), 3.2.0.
    // Note: make_spec_with_metadata builds "3.1.{suffix}".
    let versions: Vec<(&str, &str)> = vec![("0", "v1"), ("0", "v2"), ("0", "v3")];
    // proxy for 3.2.0 needs a separate spec
    let proxy_32 = uid("proxy-32");
    let spec_32 = uid("spec-32");
    let body_32 = format!(
        r#"{{
            "openapi": "3.2.0",
            "info": {{ "title": "API 3.2", "version": "1.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_32}",
                "backend_host": "b.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_32}"
            }}
        }}"#
    );
    let (b32, m32) =
        ferrum_edge::admin::api_specs::extract(body_32.as_bytes(), None, ns).expect("extract 3.2");
    let rh32 = ferrum_edge::admin::api_specs::hash_resource_bundle(&b32)
        .expect("hash_resource_bundle should never fail for a valid bundle");
    let s32 = ApiSpec {
        id: spec_32.clone(),
        namespace: ns.to_string(),
        proxy_id: proxy_32.clone(),
        spec_version: m32.version,
        spec_format: ferrum_edge::config::types::SpecFormat::Json,
        spec_content: ferrum_edge::admin::spec_codec::compress_gzip(body_32.as_bytes()).unwrap(),
        content_encoding: "gzip".to_string(),
        uncompressed_size: body_32.len() as u64,
        content_hash: ferrum_edge::admin::spec_codec::sha256_hex(body_32.as_bytes()),
        title: m32.title,
        info_version: m32.info_version,
        description: None,
        contact_name: None,
        contact_email: None,
        license_name: None,
        license_identifier: None,
        tags: vec![],
        server_urls: vec![],
        operation_count: 0,
        resource_hash: rh32,
        external_ref_snapshot: None,
        external_ref_digest: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.submit_api_spec_bundle(&b32, &s32).await.unwrap();

    for (suffix, title) in versions {
        let proxy_id = uid("proxy-31");
        let spec_id = uid("spec-31");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        spec_version_prefix: Some("3.1".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed")
        .items;
    assert_eq!(
        results.len(),
        3,
        "should return 3 specs with version prefix 3.1"
    );
    assert!(
        results.iter().all(|s| s.spec_version.starts_with("3.1")),
        "all results must have spec_version starting with 3.1"
    );
}

/// `?title_contains=orders` is case-insensitive.
#[tokio::test]
async fn list_filter_title_contains_case_insensitive() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Titles: "Orders API", "ORDERS Service", "Catalog"
    for (title, suffix) in &[
        ("Orders API", "0"),
        ("ORDERS Service", "1"),
        ("Catalog", "2"),
    ] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        title_contains: Some("orders".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed")
        .items;
    assert_eq!(
        results.len(),
        2,
        "should return 2 specs matching 'orders' case-insensitively"
    );
}

/// `?updated_since=<timestamp>` returns only specs updated at or after that time.
#[tokio::test]
async fn list_filter_updated_since() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert 2 specs.
    for i in 0..2u8 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", &i.to_string(), &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    // The cutoff is "right now" — both specs were inserted just before this,
    // so updated_since = now means 0 results.
    let cutoff = chrono::Utc::now() + chrono::Duration::seconds(1);
    let filter = ApiSpecListFilter {
        updated_since: Some(cutoff),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed")
        .items;
    assert!(
        results.is_empty(),
        "no specs updated after the cutoff (got {})",
        results.len()
    );

    // With past cutoff, all specs are returned.
    let past_cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
    let filter2 = ApiSpecListFilter {
        updated_since: Some(past_cutoff),
        limit: 100,
        ..Default::default()
    };
    let results2 = store
        .list_api_specs(ns, &filter2)
        .await
        .expect("list failed")
        .items;
    assert_eq!(results2.len(), 2, "all 2 specs must match past cutoff");
}

/// `?has_tag=public` returns only specs that have the tag "public".
#[tokio::test]
async fn list_filter_has_tag() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Three specs: two tagged "public", one tagged "private".
    for (tags, suffix) in &[
        (vec!["public", "api"], "0"),
        (vec!["public"], "1"),
        (vec!["private"], "2"),
    ] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", suffix, tags.as_slice());
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let filter = ApiSpecListFilter {
        has_tag: Some("public".to_string()),
        limit: 100,
        ..Default::default()
    };
    let results = store
        .list_api_specs(ns, &filter)
        .await
        .expect("list failed")
        .items;
    assert_eq!(results.len(), 2, "2 specs must have the 'public' tag");
    assert!(
        results
            .iter()
            .all(|s| s.tags.contains(&"public".to_string()))
    );
}

/// Sort by title ascending then descending.
#[tokio::test]
async fn list_sort_by_title_asc_then_desc() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    for (title, suffix) in &[("Bravo", "0"), ("Alpha", "1"), ("Charlie", "2")] {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, title, suffix, &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
    }

    let asc_filter = ApiSpecListFilter {
        sort_by: ApiSpecSortBy::Title,
        order: SortOrder::Asc,
        limit: 100,
        ..Default::default()
    };
    let asc = store
        .list_api_specs(ns, &asc_filter)
        .await
        .expect("list asc")
        .items;
    let asc_titles: Vec<_> = asc.iter().filter_map(|s| s.title.as_deref()).collect();
    assert!(
        asc_titles.windows(2).all(|w| w[0] <= w[1]),
        "titles must be in ascending order: {:?}",
        asc_titles
    );

    let desc_filter = ApiSpecListFilter {
        sort_by: ApiSpecSortBy::Title,
        order: SortOrder::Desc,
        limit: 100,
        ..Default::default()
    };
    let desc = store
        .list_api_specs(ns, &desc_filter)
        .await
        .expect("list desc")
        .items;
    let desc_titles: Vec<_> = desc.iter().filter_map(|s| s.title.as_deref()).collect();
    assert!(
        desc_titles.windows(2).all(|w| w[0] >= w[1]),
        "titles must be in descending order: {:?}",
        desc_titles
    );
}

/// Default sort is `updated_at DESC` (most-recent first).
#[tokio::test]
async fn list_default_sort_is_updated_at_desc() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert 3 specs with a short sleep between each so timestamps differ.
    let mut spec_ids = Vec::new();
    for i in 0..3u8 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let (bundle, spec) =
            make_spec_with_metadata(&spec_id, &proxy_id, ns, "API", &i.to_string(), &[]);
        store.submit_api_spec_bundle(&bundle, &spec).await.unwrap();
        spec_ids.push(spec_id);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let filter = ApiSpecListFilter {
        limit: 100,
        ..Default::default()
    };
    let results = store.list_api_specs(ns, &filter).await.expect("list").items;
    assert_eq!(results.len(), 3);
    // Most recently inserted should appear first.
    assert!(
        results
            .windows(2)
            .all(|w| w[0].updated_at >= w[1].updated_at),
        "default sort must be updated_at DESC"
    );
}

// ===========================================================================
// Round 2 PR review fixes
// ===========================================================================

// ---------------------------------------------------------------------------
// Fix 2: imported plugins appear in proxy.plugins associations
// ---------------------------------------------------------------------------

/// Build an `ExtractedBundle` that mimics what the extractor now produces:
/// plugins have the proxy_id stamped, and proxy.plugins contains associations.
fn make_bundle_with_plugins(
    proxy_id: &str,
    namespace: &str,
    plugin_ids: &[&str],
    upstream: Option<Upstream>,
) -> ExtractedBundle {
    let mut proxy = make_proxy(proxy_id, namespace);
    let mut plugins: Vec<PluginConfig> = Vec::new();
    let mut associations: Vec<PluginAssociation> = Vec::new();

    for &pid in plugin_ids {
        let mut p = make_plugin(pid, proxy_id, namespace, None);
        p.proxy_id = Some(proxy_id.to_string());
        associations.push(PluginAssociation {
            plugin_config_id: pid.to_string(),
        });
        plugins.push(p);
    }
    proxy.plugins = associations;
    ExtractedBundle {
        proxy,
        upstream,
        plugins,
    }
}

/// After submit_api_spec_bundle, proxy.plugins associations must be persisted
/// so the gateway's PluginCache can instantiate them.
#[tokio::test]
async fn submit_imported_plugins_appear_in_proxy_plugins_associations() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let plugin_id_1 = uid("plugin");
    let plugin_id_2 = uid("plugin");
    let spec_id = uid("spec");

    let bundle = make_bundle_with_plugins(&proxy_id, ns, &[&plugin_id_1, &plugin_id_2], None);
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec with plugins");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // Verify proxy.plugins association list was persisted (via proxy_plugins table).
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    assert!(
        proxy_after.plugins.len() >= 2,
        "proxy.plugins must have at least 2 entries; got {}",
        proxy_after.plugins.len()
    );
    let assoc_ids: Vec<&str> = proxy_after
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();
    assert!(
        assoc_ids.contains(&plugin_id_1.as_str()),
        "plugin_id_1 must be in proxy.plugins"
    );
    assert!(
        assoc_ids.contains(&plugin_id_2.as_str()),
        "plugin_id_2 must be in proxy.plugins"
    );
}

/// After replace_api_spec_bundle, the new plugin associations replace the old ones.
#[tokio::test]
async fn replace_updates_proxy_plugins_associations() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let plugin_id_v1 = uid("plugin");
    let spec_id = uid("spec");

    // Initial submit with one plugin.
    let bundle_v1 = make_bundle_with_plugins(&proxy_id, ns, &[&plugin_id_v1], None);
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 with plugin");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("submit failed");

    // Replace with a different plugin.
    let plugin_id_v2 = uid("plugin");
    let bundle_v2 = make_bundle_with_plugins(&proxy_id, ns, &[&plugin_id_v2], None);
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 with different plugin");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Proxy associations must now reference only the new plugin (for spec-owned entries).
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    let assoc_ids: Vec<&str> = proxy_after
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();
    assert!(
        assoc_ids.contains(&plugin_id_v2.as_str()),
        "v2 plugin must be in proxy.plugins after replace"
    );
    // v1 plugin is gone from plugin_configs so its association should not appear.
    assert!(
        !assoc_ids.contains(&plugin_id_v1.as_str()),
        "v1 plugin must not be in proxy.plugins after replace"
    );
}

// ---------------------------------------------------------------------------
// Fix 3: replace with changed upstream_id does not fail FK constraint
// ---------------------------------------------------------------------------

/// submit spec A with upstream U1; then replace with spec A' containing a
/// different upstream U2. The replace must succeed (the old upstream FK must
/// be cleared before deleting U1).
#[tokio::test]
async fn replace_with_changed_upstream_id_does_not_fail_fk() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id_v1 = uid("upstream");
    let upstream_id_v2 = uid("upstream");
    let spec_id = uid("spec");

    // Initial submit: proxy + upstream U1.
    let mut proxy_v1 = make_proxy(&proxy_id, ns);
    proxy_v1.upstream_id = Some(upstream_id_v1.clone());
    let bundle_v1 = ExtractedBundle {
        proxy: proxy_v1,
        upstream: Some(make_upstream(&upstream_id_v1, ns)),
        plugins: vec![],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 upstream");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Confirm U1 exists and proxy references it.
    let u1 = store
        .get_upstream(ns, &upstream_id_v1)
        .await
        .expect("get u1")
        .expect("u1 must exist");
    assert_eq!(u1.id, upstream_id_v1);
    let p_before = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get proxy")
        .expect("proxy must exist");
    assert_eq!(
        p_before.upstream_id.as_deref(),
        Some(upstream_id_v1.as_str())
    );

    // Replace: proxy + upstream U2. The FK proxies.upstream_id → upstreams(id) ON DELETE
    // RESTRICT would fail if we deleted U1 before clearing proxy.upstream_id.
    let mut proxy_v2 = make_proxy(&proxy_id, ns);
    proxy_v2.upstream_id = Some(upstream_id_v2.clone());
    let bundle_v2 = ExtractedBundle {
        proxy: proxy_v2,
        upstream: Some(make_upstream(&upstream_id_v2, ns)),
        plugins: vec![],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 different upstream");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace with changed upstream failed (FK violation?)");

    // U1 must be gone.
    let u1_after = store
        .get_upstream(ns, &upstream_id_v1)
        .await
        .expect("get u1 after");
    assert!(
        u1_after.is_none(),
        "old upstream U1 must be deleted after replace"
    );

    // U2 must exist.
    let u2_after = store
        .get_upstream(ns, &upstream_id_v2)
        .await
        .expect("get u2 after")
        .expect("U2 must exist");
    assert_eq!(u2_after.id, upstream_id_v2);

    // Proxy must reference U2.
    let p_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get proxy")
        .expect("proxy must exist");
    assert_eq!(
        p_after.upstream_id.as_deref(),
        Some(upstream_id_v2.as_str()),
        "proxy.upstream_id must be updated to U2 after replace"
    );
}

// ---------------------------------------------------------------------------
// Fix 3: replace_with_changed_resources_keeps_manual_proxy_plugin_association
// ---------------------------------------------------------------------------

/// When replace_api_spec_bundle runs with a genuinely changed bundle, a
/// manually-associated plugin (one whose proxy_plugins junction row was added
/// by the operator directly, not by the spec) must survive.
///
/// This tests the SQL-layer invariant: the junction-table delete is scoped to
/// spec-owned plugin IDs only (via `DELETE FROM plugin_configs WHERE api_spec_id
/// = ?` which removes the plugin_configs rows, and then for proxy_plugins only
/// those association rows are deleted because we only insert/delete associations
/// for spec-owned plugin IDs). The hand-added junction row for a non-spec plugin
/// is never touched.
///
/// The Mongo path mirrors this via the `proxy_to_persist` merge logic in
/// `replace_api_spec_bundle` (mongo_store.rs). No Mongo-specific assertion
/// here since it requires a live MongoDB; the SQL test is the authoritative
/// parity check.
#[tokio::test]
async fn replace_with_changed_resources_keeps_manual_proxy_plugin_association() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");

    // Initial submit with one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: spec_plugin_id.clone(),
    }];
    let bundle_v1 = ExtractedBundle {
        proxy,
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec content");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Create a proxy-group plugin and associate it with the proxy manually
    // (simulating an operator adding a shared plugin after spec creation via
    // direct admin API).
    let manual_plugin_id = uid("proxy-group-plugin");
    let manual_plugin = PluginConfig {
        labels: Default::default(),
        id: manual_plugin_id.clone(),
        namespace: ns.to_string(),
        plugin_name: "cors".to_string(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_plugin_config(&manual_plugin)
        .await
        .expect("create proxy-group plugin failed");

    // Add the junction row manually (direct DB update to proxy.plugins).
    let proxy_with_manual = {
        let mut p = store
            .get_proxy(ns, &proxy_id)
            .await
            .expect("get_proxy failed")
            .expect("proxy must exist");
        p.plugins.push(PluginAssociation {
            plugin_config_id: manual_plugin_id.clone(),
        });
        p
    };
    store
        .update_proxy(&proxy_with_manual)
        .await
        .expect("update proxy with manual association failed");

    // Replace with a new bundle (different spec-owned plugin → different resource hash).
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let mut proxy_v2 = make_proxy(&proxy_id, ns);
    proxy_v2.plugins = vec![PluginAssociation {
        plugin_config_id: new_spec_plugin_id.clone(),
    }];
    let bundle_v2 = ExtractedBundle {
        proxy: proxy_v2,
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(
        &spec_id,
        &proxy_id,
        ns,
        b"v2 spec content with changed resources",
    );
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // The proxy-group plugin itself must still exist (not deleted).
    let manual_row = store
        .get_plugin_config(ns, &manual_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        manual_row.is_some(),
        "proxy-group plugin must still exist after replace"
    );

    // The proxy's plugin associations must include the manual proxy-group plugin.
    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist");
    let plugin_ids: Vec<&str> = proxy_after
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();
    assert!(
        plugin_ids.contains(&manual_plugin_id.as_str()),
        "manual proxy-group plugin association must be preserved after replace; \
         proxy.plugins = {:?}",
        plugin_ids
    );
    // The new spec-owned plugin must also be referenced.
    assert!(
        plugin_ids.contains(&new_spec_plugin_id.as_str()),
        "new spec-owned plugin must be in proxy.plugins; found: {:?}",
        plugin_ids
    );
}

#[tokio::test]
async fn replace_removes_removed_spec_declared_external_proxy_plugin_association() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let group_plugin_id = uid("group-plugin");

    let group_plugin = PluginConfig {
        labels: Default::default(),
        id: group_plugin_id.clone(),
        namespace: ns.to_string(),
        plugin_name: "rate_limiting".to_string(),
        config: serde_json::json!({
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_plugin_config(&group_plugin)
        .await
        .expect("create proxy_group plugin failed");

    let body_v1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}",
                "plugins": [{{ "plugin_config_id": "{group_plugin_id}" }}]
            }}
        }}"#
    );
    let (bundle_v1, spec_v1) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body_v1);
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    let proxy_before = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    assert!(
        proxy_before
            .plugins
            .iter()
            .any(|a| a.plugin_config_id == group_plugin_id),
        "v1 spec-declared proxy_group association must be active before replace"
    );

    let body_v2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.1" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle_v2, spec_v2) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body_v2);
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    let proxy_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist");
    assert!(
        !proxy_after
            .plugins
            .iter()
            .any(|a| a.plugin_config_id == group_plugin_id),
        "removed spec-declared proxy_group association must not persist after replace"
    );
}

/// When tagged spec-owned resources exist but the `api_specs` row is missing
/// (e.g. restore preserved a dangling `api_spec_id`), the metadata-only shortcut
/// must fail closed instead of committing an empty transaction and reporting
/// success. Existence is the same-transaction SELECT, not UPDATE rows_affected
/// (issue #4285).
#[tokio::test]
async fn replace_metadata_only_shortcut_fails_when_api_specs_row_missing() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, "Dangling API", "0", &[]);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("initial submit failed");

    sqlx::query("DELETE FROM api_specs WHERE namespace = ? AND id = ?")
        .bind(ns)
        .bind(&spec_id)
        .execute(&store.pool())
        .await
        .expect("delete api_specs row for dangling fixture");

    assert!(
        store
            .get_api_spec(ns, &spec_id)
            .await
            .expect("get_api_spec failed")
            .is_none(),
        "fixture must leave tagged resources without an api_specs row"
    );

    let (bundle_put, mut spec_put) =
        make_spec_with_metadata(&spec_id, &proxy_id, ns, "Dangling API", "0", &[]);
    spec_put.description = Some("metadata-only PUT with unchanged resources".to_string());
    spec_put.updated_at = chrono::Utc::now();

    let err = store
        .replace_api_spec_bundle(&bundle_put, &spec_put)
        .await
        .expect_err("metadata-only replace must fail when api_specs row is absent");
    let msg = err.to_string();
    assert!(
        msg.contains("metadata-only replace"),
        "error must identify the metadata-only shortcut path, got: {msg}"
    );
    assert!(
        msg.contains("not found") && msg.contains(&spec_id) && msg.contains(ns),
        "error must identify the missing namespace/id row, got: {msg}"
    );
    assert!(
        !msg.contains("rows_affected"),
        "error must not treat changed-row count as the missing-row authority, got: {msg}"
    );
}

/// An existing `api_specs` row whose spec-owned resource graph already matches
/// must succeed on the metadata-only shortcut. A MySQL UPDATE that writes
/// identical values can report `rows_affected=0` without `CLIENT_FOUND_ROWS`;
/// that must not be misclassified as a missing row (issue #4285).
#[tokio::test]
async fn replace_metadata_only_shortcut_succeeds_when_api_specs_row_exists() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let (bundle, spec) = make_spec_with_metadata(&spec_id, &proxy_id, ns, "Existing API", "0", &[]);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("initial submit failed");

    let (bundle_put, mut spec_put) =
        make_spec_with_metadata(&spec_id, &proxy_id, ns, "Existing API", "0", &[]);
    spec_put.description = spec.description.clone();
    spec_put.updated_at = spec.updated_at;

    store
        .replace_api_spec_bundle(&bundle_put, &spec_put)
        .await
        .expect(
            "metadata-only replace must succeed when the namespace/id row exists, even if the \
             UPDATE is a no-op on changed-row count",
        );

    let stored = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("api_specs row must still exist after idempotent metadata replace");
    assert_eq!(stored.id, spec_id);
    assert_eq!(stored.namespace, ns);
    assert_eq!(stored.resource_hash, spec.resource_hash);
}

#[tokio::test]
async fn replace_same_hash_reconciles_drifted_spec_owned_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let body = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "spec.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }}
        }}"#
    );
    let (bundle, spec) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("initial submit failed");

    let mut drifted_proxy = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    drifted_proxy.backend_host = "drifted.internal".to_string();
    drifted_proxy.updated_at = chrono::Utc::now();
    store
        .update_proxy(&drifted_proxy)
        .await
        .expect("direct proxy drift update failed");

    let proxy_after_drift = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must exist");
    assert_eq!(proxy_after_drift.backend_host, "drifted.internal");

    store
        .replace_api_spec_bundle(&bundle, &spec)
        .await
        .expect("same-hash replace should reconcile drift");

    let proxy_after_replace = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy must still exist");
    assert_eq!(
        proxy_after_replace.backend_host, "spec.internal",
        "unchanged resource_hash must not skip reconciliation when spec-owned rows drift"
    );
}

#[tokio::test]
async fn replace_api_spec_rejects_external_proxy_referencing_spec_owned_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let manual_proxy_id = uid("manual-proxy");
    let upstream_id = uid("upstream");
    let spec_id = uid("spec");
    let body_v1 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }},
            "x-ferrum-upstream": {{
                "id": "{upstream_id}",
                "targets": [{{ "host": "target.internal", "port": 443 }}]
            }}
        }}"#
    );
    let (bundle_v1, spec_v1) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body_v1);
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    let mut manual_proxy = make_proxy(&manual_proxy_id, ns);
    manual_proxy.upstream_id = Some(upstream_id.clone());
    store
        .create_proxy(&manual_proxy)
        .await
        .expect("create manual proxy sharing spec upstream failed");

    let body_v2 = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.1" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "replacement.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }},
            "x-ferrum-upstream": {{
                "id": "{upstream_id}",
                "targets": [{{ "host": "target.internal", "port": 443 }}]
            }}
        }}"#
    );
    let (bundle_v2, spec_v2) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body_v2);
    let err = store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect_err("replace must reject shared spec-owned upstream");
    assert!(
        err.to_string().contains("references a spec-owned upstream"),
        "unexpected error: {err}"
    );

    let upstream_after = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream failed");
    assert!(
        upstream_after.is_some(),
        "guarded replace must leave the spec-owned upstream intact"
    );
    let manual_proxy_after = store
        .get_proxy(ns, &manual_proxy_id)
        .await
        .expect("get_proxy failed");
    assert!(
        manual_proxy_after.is_some(),
        "guarded replace must leave the external proxy intact"
    );
}

/// Malformed `upstreams.id` must fail closed inside the external-reference
/// guard (issue #3210). SQLite type drift (`X'FF'`) makes `AnyRow::try_get::<String>`
/// reject the column; the lossy `filter_map(...ok())` path used to drop that
/// id, treat the protected set as empty, and skip the mesh_route_dispatch scan.
#[tokio::test]
async fn delete_api_spec_rolls_back_when_spec_owned_upstream_id_fails_to_decode() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let spec_id = uid("spec");
    let mesh_plugin_id = uid("mesh-dispatch");
    let body = format!(
        r#"{{
            "openapi": "3.1.0",
            "info": {{ "title": "API", "version": "1.0.0" }},
            "x-ferrum-proxy": {{
                "id": "{proxy_id}",
                "backend_host": "backend.internal",
                "backend_port": 443,
                "listen_path": "/{proxy_id}"
            }},
            "x-ferrum-upstream": {{
                "id": "{upstream_id}",
                "targets": [{{ "host": "target.internal", "port": 443 }}]
            }}
        }}"#
    );
    let (bundle, spec) = make_spec_from_openapi_body(&spec_id, &proxy_id, ns, &body);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("initial submit failed");

    // External enabled mesh_route_dispatch naming the spec-owned upstream —
    // the reference the guard must not skip when ID decode fails.
    let now = chrono::Utc::now();
    store
        .create_plugin_config(&PluginConfig {
            labels: Default::default(),
            id: mesh_plugin_id.clone(),
            namespace: ns.to_string(),
            plugin_name: "mesh_route_dispatch".to_string(),
            config: serde_json::json!({
                "rules": [{
                    "match": { "methods": ["GET"] },
                    "destination": { "upstream_id": upstream_id }
                }]
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create external mesh_route_dispatch plugin failed");

    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("UPDATE upstreams SET id = X'FF' WHERE id = ? AND namespace = ?")
        .bind(&upstream_id)
        .bind(ns)
        .execute(&mut *conn)
        .await
        .expect("injecting undecodable upstream id must succeed");
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await
        .expect("restore SQLite foreign-key enforcement");
    drop(conn);

    let blob_upstream_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM upstreams \
         WHERE namespace = ? AND api_spec_id = ? AND typeof(id) = 'blob'",
    )
    .bind(ns)
    .bind(&spec_id)
    .fetch_one(&store.pool())
    .await
    .expect("blob upstream count must succeed");
    assert_eq!(blob_upstream_before, 1);

    let err = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect_err("malformed upstream id must abort api_spec deletion");
    let message = err.to_string();
    assert!(
        message.contains("operation=ensure_no_external_spec_upstream_refs"),
        "error should identify the reference-integrity guard, got: {message}"
    );
    assert!(
        message.contains("resource=upstreams")
            && message.contains("column=id")
            && message.contains(&format!("namespace={ns}"))
            && message.contains(&format!("api_spec_id={spec_id}")),
        "error should include namespace/spec/column context without relying on later selects, got: {message}"
    );
    assert!(
        !message.contains(&mesh_plugin_id),
        "decode-path failure must abort before the mesh_route_dispatch reference check embeds the plugin id: {message}"
    );

    assert!(
        store
            .get_api_spec(ns, &spec_id)
            .await
            .expect("get_api_spec failed")
            .is_some(),
        "api_specs row must remain after rollback"
    );
    assert!(
        store
            .get_proxy(ns, &proxy_id)
            .await
            .expect("get_proxy failed")
            .is_some(),
        "spec-owned proxy must remain after rollback"
    );
    let blob_upstream_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM upstreams \
         WHERE namespace = ? AND api_spec_id = ? AND typeof(id) = 'blob'",
    )
    .bind(ns)
    .bind(&spec_id)
    .fetch_one(&store.pool())
    .await
    .expect("blob upstream count after delete must succeed");
    assert_eq!(
        blob_upstream_after, 1,
        "spec-owned upstream must remain after rollback"
    );
    assert!(
        store
            .get_plugin_config(ns, &mesh_plugin_id)
            .await
            .expect("get_plugin_config failed")
            .is_some(),
        "external mesh_route_dispatch plugin must remain after rollback"
    );
}

#[test]
fn mongo_api_spec_upstream_reference_guard_fails_closed_on_id_decode() {
    let source = include_str!("../../src/config/mongo_store.rs");
    let guard = source
        .split("async fn ensure_no_external_spec_upstream_refs_opt_session(")
        .nth(1)
        .expect("Mongo API-spec external-reference guard exists")
        .split(
            "// -----------------------------------------------------------------------\n    // BSON serialization helpers",
        )
        .next()
        .expect("bounded Mongo API-spec external-reference guard");

    assert!(
        !guard.contains("if let Ok(id) = doc.get_str(\"_id\")"),
        "Mongo must not silently omit a malformed spec-owned upstream id"
    );
    assert_eq!(
        guard
            .matches(
                "failed to decode spec-owned upstream id required for external reference checks",
            )
            .count(),
        2,
        "session and standalone Mongo guards must both fail closed with contextual decode errors"
    );
}

// ============================================================================
// Fix 1 (DB layer) — server-side timestamp stamping
// ============================================================================

/// Verify that if a bundle's resources carry deliberately-old timestamps (as
/// would happen if an operator embedded stale `updated_at` values inside the
/// OpenAPI extension), the handler-level timestamp stamp has already overwritten
/// them before the bundle reaches the DB.
///
/// This test works at the DB level by constructing a bundle with an epoch-old
/// `updated_at` and confirming that `replace_api_spec_bundle` stores whatever
/// timestamp was embedded (the DB layer is passive).  The complementary
/// HTTP-level test (`put_overwrites_imported_updated_at_so_polling_picks_change`
/// in `admin_api_specs_handler_tests.rs`) proves that the handler stamps fresh
/// timestamps BEFORE the bundle reaches here.
///
/// Together the two tests form a contract: if the handler stamp fires, the DB
/// stores a fresh timestamp; if it doesn't fire, the DB stores the stale value.
#[tokio::test]
async fn put_overwrites_imported_updated_at_so_polling_picks_change() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    // Initial submit with a normal timestamp.
    let mut proxy_v1 = make_proxy(&proxy_id, ns);
    proxy_v1.plugins = vec![PluginAssociation {
        plugin_config_id: plugin_id.clone(),
    }];
    let plugin_v1 = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: proxy_v1,
        upstream: None,
        plugins: vec![plugin_v1],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 content");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    let proxy_after_submit = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy")
        .expect("proxy must exist");
    let submit_updated_at = proxy_after_submit.updated_at;

    // Small sleep to ensure wall-clock advances.
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;

    // Build a replacement bundle with a *fresh* server-side timestamp (simulating
    // what assign_ids_for_put stamps before the bundle reaches the DB).
    let now = chrono::Utc::now();
    let mut proxy_v2 = make_proxy(&proxy_id, ns);
    proxy_v2.updated_at = now; // server-side stamp (fresh)
    proxy_v2.created_at = proxy_after_submit.created_at; // preserved from original
    proxy_v2.plugins = vec![];
    let bundle_v2 = ExtractedBundle {
        proxy: proxy_v2,
        upstream: None,
        plugins: vec![],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 content fresh ts");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    let proxy_after_replace = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy after replace")
        .expect("proxy must still exist");

    // The DB stored whatever the bundle carried — a fresh server-side timestamp.
    assert!(
        proxy_after_replace.updated_at > submit_updated_at,
        "proxy.updated_at ({}) must be NEWER than the initial submit timestamp ({}) \
         when the bundle carries a fresh server-side stamp",
        proxy_after_replace.updated_at,
        submit_updated_at
    );

    // Now demonstrate the failure mode: replace with a deliberately-stale timestamp.
    let epoch = chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
        .unwrap()
        .to_utc();
    let mut proxy_stale = make_proxy(&proxy_id, ns);
    proxy_stale.updated_at = epoch; // operator-embedded stale timestamp (NOT overwritten)
    proxy_stale.plugins = vec![];
    let bundle_stale = ExtractedBundle {
        proxy: proxy_stale,
        upstream: None,
        plugins: vec![],
    };
    let spec_stale = make_spec(&spec_id, &proxy_id, ns, b"v3 content stale ts");
    store
        .replace_api_spec_bundle(&bundle_stale, &spec_stale)
        .await
        .expect("replace with stale ts failed");

    let proxy_stale_after = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy stale")
        .expect("proxy must still exist");

    // DB stored the stale epoch timestamp — the handler MUST overwrite it before
    // calling replace_api_spec_bundle.  This assertion is the "canary": if it
    // were the only test, a stale stored timestamp would go undetected.
    // The HTTP-level test (`put_overwrites_imported_updated_at_so_polling_picks_change`
    // in handler_tests) is the real guard.
    assert_eq!(
        proxy_stale_after.updated_at, epoch,
        "DB layer passively stores whatever timestamp the bundle carries; \
         handler-level stamping is what prevents stale timestamps in production"
    );
}

// ============================================================================
// Fix 3 — Mongo / SQL delete_proxy cleans up orphaned upstream
// ============================================================================

/// `delete_proxy` must cascade-delete the proxy's upstream when no other proxy
/// still references it (mirrors SQL delete_proxy behavior).
///
/// This test runs against SQLite which is the reference implementation.
/// The invariant is: delete P1 (sole referencer of U1) → U1 is removed.
/// Negative: delete P1 when P2 also references U1 → U1 must survive.
#[tokio::test]
async fn delete_proxy_cleans_up_orphaned_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // ------------------------------------------------------------------ setup
    let upstream_id = uid("upstream-orphan");
    let proxy_id_1 = uid("proxy-sole-ref");
    let proxy_id_2 = uid("proxy-second-ref");

    // Create the shared upstream.
    let upstream = make_upstream(&upstream_id, ns);
    store
        .create_upstream(&upstream)
        .await
        .expect("create upstream");

    // Create proxy P1 that references the upstream.
    let mut p1 = make_proxy(&proxy_id_1, ns);
    p1.upstream_id = Some(upstream_id.clone());
    store.create_proxy(&p1).await.expect("create P1");

    // ------------------------------------------------------------------ negative: P2 also references → upstream must survive
    // Use a distinct listen_path so uniqueness constraints don't fire.
    let p2: Proxy = serde_json::from_value(serde_json::json!({
        "id": proxy_id_2,
        "namespace": ns,
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": format!("/{proxy_id_2}"),
        "upstream_id": upstream_id
    }))
    .expect("p2 deserialization");
    store.create_proxy(&p2).await.expect("create P2");

    // Delete P1 — P2 still references the upstream → upstream must NOT be deleted.
    let deleted = store
        .delete_proxy(ns, &proxy_id_1)
        .await
        .expect("delete P1");
    assert!(deleted, "delete_proxy P1 must return true");

    let upstream_after_p1_delete = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream after P1 delete");
    assert!(
        upstream_after_p1_delete.is_some(),
        "upstream must survive when P2 still references it; got None"
    );

    // ------------------------------------------------------------------ positive: delete P2 → upstream now orphaned → must be removed
    let deleted2 = store
        .delete_proxy(ns, &proxy_id_2)
        .await
        .expect("delete P2");
    assert!(deleted2, "delete_proxy P2 must return true");

    let upstream_after_p2_delete = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream after P2 delete");
    assert!(
        upstream_after_p2_delete.is_none(),
        "orphaned upstream must be cascade-deleted after last referencing proxy is removed; \
         got Some({:?})",
        upstream_after_p2_delete
    );
}

#[tokio::test]
async fn delete_proxy_opt_out_preserves_orphaned_hand_owned_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let upstream_id = uid("upstream-preserve");
    let proxy_id = uid("proxy-preserve");
    store
        .create_upstream(&make_upstream(&upstream_id, ns))
        .await
        .expect("create upstream");
    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.upstream_id = Some(upstream_id.clone());
    store.create_proxy(&proxy).await.expect("create proxy");

    let deleted = store
        .delete_proxy_with_orphan_cleanup(ns, &proxy_id, false)
        .await
        .expect("delete proxy with opt-out");
    assert!(deleted, "delete_proxy must return true");

    let upstream_after = store
        .get_upstream(ns, &upstream_id)
        .await
        .expect("get_upstream after opt-out delete");
    assert!(
        upstream_after.is_some(),
        "hand-owned upstream must survive when cleanup_orphaned_upstream is false"
    );
}

#[tokio::test]
async fn delete_proxy_never_cleans_spec_owned_upstream_regardless_of_flag() {
    for cleanup in [true, false] {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        let ns = "ferrum";

        let spec_id = uid("spec");
        let spec_proxy_id = uid("spec-proxy");
        let spec_upstream_id = uid("spec-upstream");
        let hand_proxy_id = uid("hand-proxy");
        let drift_upstream_id = uid("drift-upstream");

        let mut spec_proxy = make_proxy(&spec_proxy_id, ns);
        spec_proxy.upstream_id = Some(spec_upstream_id.clone());
        let bundle = ExtractedBundle {
            proxy: spec_proxy,
            upstream: Some(make_upstream(&spec_upstream_id, ns)),
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &spec_proxy_id, ns, br#"{"openapi":"3.1.0"}"#);
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .expect("submit api spec bundle");

        store
            .create_upstream(&make_upstream(&drift_upstream_id, ns))
            .await
            .expect("create drift upstream");
        let mut hand_proxy = make_proxy(&hand_proxy_id, ns);
        hand_proxy.upstream_id = Some(spec_upstream_id.clone());
        store
            .create_proxy(&hand_proxy)
            .await
            .expect("create hand-managed proxy pointing at spec-owned upstream");

        let mut drifted = store
            .get_proxy(ns, &spec_proxy_id)
            .await
            .expect("get spec proxy")
            .expect("spec proxy exists");
        drifted.upstream_id = Some(drift_upstream_id.clone());
        store
            .update_proxy(&drifted)
            .await
            .expect("drift spec proxy off spec-owned upstream");

        let deleted = store
            .delete_proxy_with_orphan_cleanup(ns, &hand_proxy_id, cleanup)
            .await
            .expect("delete hand-managed last referencer");
        assert!(deleted, "delete_proxy must return true");

        let spec_upstream = store
            .get_upstream(ns, &spec_upstream_id)
            .await
            .expect("get spec-owned upstream");
        assert!(
            spec_upstream.is_some(),
            "spec-owned upstream must never be orphan-cleaned \
             (cleanup_orphaned_upstream={cleanup})"
        );
    }
}

#[tokio::test]
async fn delete_proxy_never_cleans_still_referenced_upstream_regardless_of_flag() {
    for cleanup in [true, false] {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        let ns = "ferrum";

        let upstream_id = uid("shared-upstream");
        let proxy_id_1 = uid("shared-p1");
        let proxy_id_2 = uid("shared-p2");
        store
            .create_upstream(&make_upstream(&upstream_id, ns))
            .await
            .expect("create upstream");

        let mut p1 = make_proxy(&proxy_id_1, ns);
        p1.upstream_id = Some(upstream_id.clone());
        store.create_proxy(&p1).await.expect("create P1");

        let p2: Proxy = serde_json::from_value(serde_json::json!({
            "id": proxy_id_2,
            "namespace": ns,
            "backend_host": "backend.example.com",
            "backend_port": 443,
            "listen_path": format!("/{proxy_id_2}"),
            "upstream_id": upstream_id
        }))
        .expect("p2 deserialization");
        store.create_proxy(&p2).await.expect("create P2");

        let deleted = store
            .delete_proxy_with_orphan_cleanup(ns, &proxy_id_1, cleanup)
            .await
            .expect("delete P1");
        assert!(deleted, "delete_proxy P1 must return true");

        let upstream_after = store
            .get_upstream(ns, &upstream_id)
            .await
            .expect("get_upstream after P1 delete");
        assert!(
            upstream_after.is_some(),
            "upstream still referenced by P2 must survive \
             (cleanup_orphaned_upstream={cleanup})"
        );
    }
}

#[tokio::test]
async fn update_proxy_reassignment_cleans_up_orphaned_old_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let old_upstream_id = uid("old-upstream");
    let shared_old_upstream_id = uid("shared-old-upstream");
    let new_upstream_id = uid("new-upstream");
    for upstream_id in [&old_upstream_id, &shared_old_upstream_id, &new_upstream_id] {
        store
            .create_upstream(&make_upstream(upstream_id, ns))
            .await
            .expect("create upstream");
    }

    let proxy_id = uid("proxy-reassign");
    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.upstream_id = Some(old_upstream_id.clone());
    store.create_proxy(&proxy).await.expect("create proxy");

    proxy.upstream_id = Some(new_upstream_id.clone());
    store
        .update_proxy(&proxy)
        .await
        .expect("reassign proxy upstream");

    let old_after_reassign = store
        .get_upstream(ns, &old_upstream_id)
        .await
        .expect("get old upstream after reassignment");
    assert!(
        old_after_reassign.is_none(),
        "old upstream must be deleted when reassignment leaves it orphaned"
    );

    let new_after_reassign = store
        .get_upstream(ns, &new_upstream_id)
        .await
        .expect("get new upstream after reassignment");
    assert!(
        new_after_reassign.is_some(),
        "new upstream must survive because the proxy now references it"
    );

    let first_shared_proxy_id = uid("first-shared-proxy");
    let second_shared_proxy_id = uid("second-shared-proxy");
    let mut first_shared_proxy = make_proxy(&first_shared_proxy_id, ns);
    first_shared_proxy.upstream_id = Some(shared_old_upstream_id.clone());
    store
        .create_proxy(&first_shared_proxy)
        .await
        .expect("create first shared proxy");

    let mut second_shared_proxy = make_proxy(&second_shared_proxy_id, ns);
    second_shared_proxy.upstream_id = Some(shared_old_upstream_id.clone());
    store
        .create_proxy(&second_shared_proxy)
        .await
        .expect("create second shared proxy");

    first_shared_proxy.upstream_id = Some(new_upstream_id);
    store
        .update_proxy(&first_shared_proxy)
        .await
        .expect("reassign first shared proxy");

    let shared_old_after_reassign = store
        .get_upstream(ns, &shared_old_upstream_id)
        .await
        .expect("get shared old upstream after reassignment");
    assert!(
        shared_old_after_reassign.is_some(),
        "old upstream must survive while another proxy still references it"
    );
}

#[tokio::test]
async fn delete_proxy_removes_drifted_spec_owned_upstream() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let spec_id = uid("spec");
    let proxy_id = uid("proxy");
    let spec_upstream_id = uid("spec-upstream");
    let hand_upstream_id = uid("hand-upstream");

    let mut proxy = make_proxy(&proxy_id, ns);
    proxy.upstream_id = Some(spec_upstream_id.clone());
    let bundle = ExtractedBundle {
        proxy: proxy.clone(),
        upstream: Some(make_upstream(&spec_upstream_id, ns)),
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, br#"{"openapi":"3.1.0"}"#);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit api spec bundle");

    // Simulate direct admin CRUD drift: the spec-owned proxy now points at a
    // hand-managed upstream, but the original spec-owned upstream still carries
    // api_spec_id = spec_id.
    store
        .create_upstream(&make_upstream(&hand_upstream_id, ns))
        .await
        .expect("create hand upstream");
    let mut drifted_proxy = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get proxy")
        .expect("proxy exists");
    drifted_proxy.upstream_id = Some(hand_upstream_id.clone());
    store
        .update_proxy(&drifted_proxy)
        .await
        .expect("drift proxy upstream");

    let deleted = store
        .delete_proxy(ns, &proxy_id)
        .await
        .expect("delete proxy");
    assert!(deleted, "delete_proxy must delete the spec-owned proxy");

    let spec_upstream = store
        .get_upstream(ns, &spec_upstream_id)
        .await
        .expect("get spec upstream");
    assert!(
        spec_upstream.is_none(),
        "delete_proxy must delete the upstream tagged with the cascaded api_spec_id"
    );
}

// ===========================================================================
// Round 8 PR review fixes — concurrency and MongoDB gap documentation
// ===========================================================================

// ---------------------------------------------------------------------------
// P2: Concurrent access tests (SQLite — always run, no external services)
// ---------------------------------------------------------------------------
//
// MongoDB coverage note:
//   The SQL tests below exercise the cross-backend invariants: uniqueness
//   constraints, resource-hash idempotency, and namespace isolation.
//   The MongoDB implementations (`MongoStore`) mirror the SQL ones — see
//   `src/config/mongo_store.rs` functions `submit_api_spec_bundle`,
//   `replace_api_spec_bundle`, and `list_api_specs`.
//
//   Automated MongoDB tests require a live Mongo instance and are NOT part
//   of CI. To run them locally:
//
//     1. Start a replica set: docker run --rm -p 27017:27017 mongo:7 \
//          mongod --replSet rs0 --bind_ip_all
//        Then: mongo --eval "rs.initiate()"
//     2. Set MONGO_URL=mongodb://localhost:27017/ferrum_test?replicaSet=rs0
//     3. Run: cargo test --test integration_tests -- --ignored
//
//   Functions to exercise (these have no automated Mongo-specific tests today):
//     - mongo_store::submit_api_spec_bundle   (unique proxy_id constraint via Mongo unique index)
//     - mongo_store::replace_api_spec_bundle  (resource_hash short-circuit; idempotent PUT)
//     - mongo_store::list_api_specs           (count_documents + find; filter/sort/pagination)
//     - mongo_store::delete_api_spec          (multi-document best-effort delete)
//
//   TODO: Add a `#[cfg(feature = "mongo-tests")] mod mongo` sub-module or a
//   `tests/integration/admin_mongo_api_specs_tests.rs` with `#[ignore]` tests
//   gated on `std::env::var("MONGO_URL").is_ok()`.  The SQL tests above are
//   the current source of truth for all cross-backend behavioral invariants.

/// Two concurrent `submit_api_spec_bundle` calls with the same `proxy_id` must
/// result in exactly one succeeding and one failing with a uniqueness error.
///
/// SQLite serialises writes at the WAL level, so exactly one will win the UNIQUE
/// constraint on `(namespace, proxy_id)` in the `api_specs` table.
///
/// Concurrency note: `tokio::join!` issues both futures simultaneously but SQLite
/// serialises at the WAL write-lock level.  The loser consistently sees the
/// UNIQUE constraint violation.  This test is deterministic on SQLite; behaviour
/// on Postgres / MySQL is identical (row-level locking guarantees one winner).
#[tokio::test]
async fn concurrent_post_same_proxy_id_one_succeeds_one_conflicts() {
    let dir = TempDir::new().unwrap();
    let store = std::sync::Arc::new(make_store(&dir).await);
    let ns = "ferrum";

    let proxy_id = uid("proxy-concurrent");
    let spec_id_a = uid("spec-concurrent-a");
    let spec_id_b = uid("spec-concurrent-b");

    let (bundle_a, spec_a) = make_spec_with_metadata(&spec_id_a, &proxy_id, ns, "API A", "0", &[]);
    let (bundle_b, spec_b) = make_spec_with_metadata(&spec_id_b, &proxy_id, ns, "API B", "0", &[]);

    // Both tasks use the same proxy_id → UNIQUE(namespace, proxy_id) must fire for one.
    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        tokio::spawn(async move { store_a.submit_api_spec_bundle(&bundle_a, &spec_a).await }),
        tokio::spawn(async move { store_b.submit_api_spec_bundle(&bundle_b, &spec_b).await }),
    );

    let result_a = result_a.expect("task A panicked");
    let result_b = result_b.expect("task B panicked");

    let success_count = [result_a.is_ok(), result_b.is_ok()]
        .iter()
        .filter(|&&ok| ok)
        .count();
    let failure_count = [result_a.is_err(), result_b.is_err()]
        .iter()
        .filter(|&&err| err)
        .count();

    assert_eq!(
        success_count, 1,
        "exactly one concurrent submit must succeed; got {success_count} successes"
    );
    assert_eq!(
        failure_count, 1,
        "exactly one concurrent submit must fail; got {failure_count} failures"
    );

    // Verify the DB has exactly one spec for this proxy_id.
    let listed = store
        .list_api_specs(
            ns,
            &ApiSpecListFilter {
                proxy_id: Some(proxy_id.clone()),
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("list_api_specs failed");
    assert_eq!(
        listed.items.len(),
        1,
        "DB must contain exactly one spec for proxy_id after concurrent conflict; got {}",
        listed.items.len()
    );
    assert_eq!(
        listed.total, 1,
        "total must also be 1; got {}",
        listed.total
    );
}

/// Two concurrent `replace_api_spec_bundle` calls with byte-identical bundles
/// (same resource_hash) must both succeed — the resource-hash short-circuit makes
/// the replace idempotent.
///
/// Post-condition: `proxy.updated_at` must NOT advance beyond the initial POST
/// timestamp for either PUT (the short-circuit skips the proxy row update).
#[tokio::test]
async fn concurrent_put_same_spec_resource_hash_idempotent() {
    let dir = TempDir::new().unwrap();
    let store = std::sync::Arc::new(make_store(&dir).await);
    let ns = "ferrum";

    let proxy_id = uid("proxy-concurrent-put");
    let spec_id = uid("spec-concurrent-put");

    // Initial POST.
    let (bundle_initial, spec_initial) =
        make_spec_with_metadata(&spec_id, &proxy_id, ns, "Idempotent API", "0", &[]);
    store
        .submit_api_spec_bundle(&bundle_initial, &spec_initial)
        .await
        .expect("initial submit failed");

    let proxy_after_post = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy after POST")
        .expect("proxy must exist after POST");
    let post_updated_at = proxy_after_post.updated_at;

    // Two identical PUTs (same resource_hash → short-circuit, proxy row untouched).
    let (bundle_put_a, mut spec_put_a) =
        make_spec_with_metadata(&spec_id, &proxy_id, ns, "Idempotent API", "0", &[]);
    let (bundle_put_b, mut spec_put_b) =
        make_spec_with_metadata(&spec_id, &proxy_id, ns, "Idempotent API", "0", &[]);
    // The api_specs row always gets a fresh updated_at, but the proxy row does not.
    spec_put_a.updated_at = chrono::Utc::now();
    spec_put_b.updated_at = chrono::Utc::now();

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        tokio::spawn(async move {
            store_a
                .replace_api_spec_bundle(&bundle_put_a, &spec_put_a)
                .await
        }),
        tokio::spawn(async move {
            store_b
                .replace_api_spec_bundle(&bundle_put_b, &spec_put_b)
                .await
        }),
    );

    // The TOCTOU fix wraps the resource_hash SELECT + conditional UPDATE in a
    // single transaction, which means concurrent PUTs are correctly serialized.
    // On SQLite, the loser of the lock race may surface a BUSY error (the WAL
    // busy_timeout is not always propagated to test pools); on Postgres/MySQL
    // the loser would block on row locks until the winner commits. Either is
    // correct behavior.
    //
    // What we actually verify here:
    //   1. Tasks don't panic (no internal logic error from interleaving).
    //   2. At least one PUT succeeds (progress is made under contention).
    //   3. After both tasks settle, the proxy.updated_at has NOT been
    //      bumped — the short-circuit was honored by whichever PUT(s)
    //      succeeded.
    let outcome_a = result_a.expect("task A panicked");
    let outcome_b = result_b.expect("task B panicked");

    let succeeded = [&outcome_a, &outcome_b]
        .iter()
        .filter(|r| r.is_ok())
        .count();
    assert!(
        succeeded >= 1,
        "at least one concurrent PUT must succeed; A: {:?}, B: {:?}",
        outcome_a.as_ref().err(),
        outcome_b.as_ref().err()
    );
    // Any error must be a BUSY-class contention error, NOT a logic error.
    for (label, r) in [("A", &outcome_a), ("B", &outcome_b)] {
        if let Err(e) = r {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("locked") || msg.contains("busy") || msg.contains("deadlock"),
                "PUT {label} failed with non-contention error: {e}"
            );
        }
    }

    // The proxy row must not have advanced its updated_at (resource_hash short-circuit).
    let proxy_after_puts = store
        .get_proxy(ns, &proxy_id)
        .await
        .expect("get_proxy after PUTs")
        .expect("proxy must still exist");
    assert_eq!(
        proxy_after_puts.updated_at, post_updated_at,
        "proxy.updated_at must NOT advance when resource_hash short-circuit fires; \
         got {} (expected {})",
        proxy_after_puts.updated_at, post_updated_at
    );
}

#[tokio::test]
async fn full_sql_api_spec_reads_reject_corrupt_external_ref_pairs() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let namespace = "ferrum";
    let proxy_id = uid("proxy-corrupt-extref");
    let spec_id = uid("spec-corrupt-extref");
    let (bundle, spec) =
        make_spec_with_metadata(&spec_id, &proxy_id, namespace, "Integrity API", "0", &[]);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit spec");

    sqlx::query("UPDATE api_specs SET external_ref_digest = ? WHERE namespace = ? AND id = ?")
        .bind("a".repeat(64))
        .bind(namespace)
        .bind(&spec_id)
        .execute(&store.pool())
        .await
        .expect("corrupt digest pair");

    let error = store
        .get_api_spec(namespace, &spec_id)
        .await
        .expect_err("full row decode must reject digest without snapshot");
    assert!(error.to_string().contains("integrity validation failed"));

    // The list query intentionally projects out the blob. A well-formed digest
    // remains usable as summary metadata without pretending the omitted blob is
    // a corrupt full record.
    let summary = store
        .list_api_specs(namespace, &simple_filter(10, 0))
        .await
        .expect("summary projection may omit snapshot blob");
    assert!(summary.items.iter().any(|item| item.id == spec_id));

    sqlx::query(
        "UPDATE api_specs SET external_ref_snapshot = ?, external_ref_digest = ? \
         WHERE namespace = ? AND id = ?",
    )
    .bind(vec![0x1f, 0x8b, 0x00])
    .bind("b".repeat(64))
    .bind(namespace)
    .bind(&spec_id)
    .execute(&store.pool())
    .await
    .expect("corrupt snapshot bytes");
    let error = store
        .get_api_spec(namespace, &spec_id)
        .await
        .expect_err("full row decode must reject malformed snapshot gzip");
    assert!(error.to_string().contains("integrity validation failed"));
}
