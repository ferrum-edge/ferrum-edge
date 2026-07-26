//! Regression tests for fail-closed SQL row decoding during config mutations.
//!
//! Destructive admin mutations must abort and roll back when a selected row
//! required for follow-on invalidation/cleanup cannot be decoded. Silently
//! skipping malformed rows would commit a partial mutation (issues #3209 and
//! #3221). Coverage uses SQLite type drift (`X'FF'` blobs) against the shared
//! `AnyRow`/`try_get::<String>` path used by PostgreSQL, MySQL, and SQLite.

use chrono::Utc;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use sqlx::Row;
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mutation_decode_fail_closed.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

async fn insert_proxy(store: &DatabaseStore, id: &str, updated_at: &str) {
    sqlx::query(
        "INSERT INTO proxies \
         (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, backend_port, created_at, updated_at) \
         VALUES (?, 'ferrum', ?, '[\"example.com\"]', '/', 'http', '127.0.0.1', 8080, ?, ?)",
    )
    .bind(id)
    .bind(format!("proxy-{id}"))
    .bind(updated_at)
    .bind(updated_at)
    .execute(&store.pool())
    .await
    .expect("proxy insert must succeed");
}

async fn insert_plugin(
    store: &DatabaseStore,
    id: &str,
    scope: &str,
    proxy_id: Option<&str>,
    config: &str,
    ts: &str,
) {
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (?, 'ferrum', 'key_auth', ?, ?, ?, 1, ?, ?)",
    )
    .bind(id)
    .bind(config)
    .bind(scope)
    .bind(proxy_id)
    .bind(ts)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("plugin insert must succeed");
}

async fn insert_association(store: &DatabaseStore, proxy_id: &str, plugin_config_id: &str) {
    sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
        .bind(proxy_id)
        .bind(plugin_config_id)
        .execute(&store.pool())
        .await
        .expect("association insert must succeed");
}

async fn seed_change(
    store: &DatabaseStore,
    resource_type: &str,
    resource_id: &str,
    operation: &str,
    ts: &str,
) {
    sqlx::query(
        "INSERT INTO config_changes \
         (namespace, resource_type, resource_id, operation, created_at) \
         VALUES ('ferrum', ?, ?, ?, ?)",
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(operation)
    .bind(ts)
    .execute(&store.pool())
    .await
    .expect("config_changes seed must succeed");
}

async fn proxy_updated_at(store: &DatabaseStore, id: &str) -> String {
    sqlx::query_scalar("SELECT updated_at FROM proxies WHERE id = ? AND namespace = 'ferrum'")
        .bind(id)
        .fetch_one(&store.pool())
        .await
        .expect("proxy updated_at must be readable")
}

async fn count_plugins(store: &DatabaseStore, id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM plugin_configs WHERE id = ? AND namespace = 'ferrum'",
    )
    .bind(id)
    .fetch_one(&store.pool())
    .await
    .expect("plugin count must succeed")
}

async fn count_associations(store: &DatabaseStore, plugin_config_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM proxy_plugins WHERE plugin_config_id = ?")
        .bind(plugin_config_id)
        .fetch_one(&store.pool())
        .await
        .expect("association count must succeed")
}

async fn count_proxies(store: &DatabaseStore, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE id = ? AND namespace = 'ferrum'")
        .bind(id)
        .fetch_one(&store.pool())
        .await
        .expect("proxy count must succeed")
}

async fn count_blob_scoped_plugins(store: &DatabaseStore) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM plugin_configs \
         WHERE namespace = 'ferrum' AND scope = 'proxy_group' AND typeof(id) = 'blob'",
    )
    .fetch_one(&store.pool())
    .await
    .expect("blob plugin count must succeed")
}

async fn change_log_snapshot(store: &DatabaseStore) -> Vec<(i64, String, String, String)> {
    let rows = sqlx::query(
        "SELECT sequence, resource_type, resource_id, operation \
         FROM config_changes WHERE namespace = 'ferrum' ORDER BY sequence",
    )
    .fetch_all(&store.pool())
    .await
    .expect("config_changes snapshot must succeed");
    rows.into_iter()
        .map(|row| {
            (
                row.get::<i64, _>("sequence"),
                row.get::<String, _>("resource_type"),
                row.get::<String, _>("resource_id"),
                row.get::<String, _>("operation"),
            )
        })
        .collect()
}

fn assert_safe_decode_error(message: &str, operation: &str, column: &str) {
    assert!(
        message.contains(&format!("operation={operation}")),
        "error should include operation context, got: {message}"
    );
    assert!(
        message.contains(&format!("column={column}")),
        "error should identify the failing column, got: {message}"
    );
    assert!(
        !message.contains("X-API-Key") && !message.contains("X-Orphan-Key"),
        "decode errors must not expose plugin credential material: {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_plugin_config_rolls_back_when_association_proxy_id_fails_to_decode() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_proxy(&store, "proxy-1", &ts).await;
    insert_plugin(
        &store,
        "plugin-1",
        "proxy",
        Some("proxy-1"),
        r#"{"key_location":"header:X-API-Key"}"#,
        &ts,
    )
    .await;
    insert_association(&store, "proxy-1", "plugin-1").await;
    seed_change(&store, "plugin_config", "plugin-1", "upsert", &ts).await;
    seed_change(&store, "proxy", "proxy-1", "upsert", &ts).await;

    let updated_before = proxy_updated_at(&store, "proxy-1").await;
    let changes_before = change_log_snapshot(&store).await;
    assert_eq!(count_plugins(&store, "plugin-1").await, 1);
    assert_eq!(count_associations(&store, "plugin-1").await, 1);

    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("UPDATE proxy_plugins SET proxy_id = X'FF' WHERE plugin_config_id = ?")
        .bind("plugin-1")
        .execute(&mut *conn)
        .await
        .expect("injecting undecodable proxy_id must succeed");
    drop(conn);

    let err = store
        .delete_plugin_config("ferrum", "plugin-1")
        .await
        .expect_err("malformed association proxy_id must abort plugin deletion");
    let message = err.to_string();
    assert_safe_decode_error(&message, "delete_plugin_config", "proxy_id");
    assert!(
        message.contains("resource=proxy_plugins"),
        "error should identify proxy_plugins, got: {message}"
    );

    assert_eq!(
        count_plugins(&store, "plugin-1").await,
        1,
        "plugin_configs row must remain after rollback"
    );
    assert_eq!(
        count_associations(&store, "plugin-1").await,
        1,
        "proxy_plugins junction row must remain after rollback"
    );
    assert_eq!(
        proxy_updated_at(&store, "proxy-1").await,
        updated_before,
        "proxies.updated_at must be unchanged when invalidation decode fails"
    );
    assert_eq!(
        change_log_snapshot(&store).await,
        changes_before,
        "config_changes must be unchanged when plugin deletion rolls back"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_proxy_rolls_back_when_orphaned_proxy_group_metadata_fails_to_decode() {
    let (store, _temp_dir) = sqlite_store().await;
    let ts = Utc::now().to_rfc3339();

    insert_proxy(&store, "proxy-1", &ts).await;
    seed_change(&store, "proxy", "proxy-1", "upsert", &ts).await;

    // Pre-existing orphaned proxy_group plugin whose id cannot decode as String.
    // Parent proxy deletion invokes cleanup and must fail closed rather than
    // silently retaining the orphan while reporting success (issue #3221).
    let mut conn = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO plugin_configs \
         (id, namespace, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) \
         VALUES (X'FF', 'ferrum', 'key_auth', ?, 'proxy_group', NULL, 1, ?, ?)",
    )
    .bind(r#"{"key_location":"header:X-Orphan-Key"}"#)
    .bind(&ts)
    .bind(&ts)
    .execute(&mut *conn)
    .await
    .expect("injecting undecodable orphan plugin id must succeed");
    drop(conn);

    let changes_before = change_log_snapshot(&store).await;
    assert_eq!(count_blob_scoped_plugins(&store).await, 1);
    assert_eq!(count_proxies(&store, "proxy-1").await, 1);

    let err = store
        .delete_proxy("ferrum", "proxy-1")
        .await
        .expect_err("malformed orphan metadata must abort the parent proxy deletion");
    let message = err.to_string();
    assert_safe_decode_error(&message, "cleanup_orphaned_proxy_group_plugins", "id");
    assert!(
        message.contains("resource=plugin_configs"),
        "error should identify plugin_configs, got: {message}"
    );

    assert_eq!(
        count_proxies(&store, "proxy-1").await,
        1,
        "parent proxy deletion must roll back when orphan decode fails"
    );
    assert_eq!(
        count_blob_scoped_plugins(&store).await,
        1,
        "undecodable orphan must remain untouched after rollback"
    );
    assert_eq!(
        change_log_snapshot(&store).await,
        changes_before,
        "config_changes must be unchanged when orphan cleanup aborts the parent mutation"
    );
}
