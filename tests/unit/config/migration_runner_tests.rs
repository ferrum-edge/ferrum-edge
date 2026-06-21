//! Tests for database migration runner

use ferrum_edge::config::migrations::MigrationRunner;
use sqlx::Row;

/// Create a single-connection SQLite in-memory pool for testing.
/// With SQLite in-memory databases, each connection gets a separate DB,
/// so we must limit the pool to 1 connection to ensure all queries hit
/// the same in-memory database.
async fn test_pool() -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// Query sqlite_master for all index names in the database.
async fn get_index_names(pool: &sqlx::AnyPool) -> Vec<String> {
    let rows: Vec<sqlx::any::AnyRow> =
        sqlx::query("SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name")
            .fetch_all(pool)
            .await
            .unwrap();
    rows.iter()
        .map(|r| r.try_get::<String, _>("name").unwrap())
        .collect()
}

/// Compound and junction-table indexes created by V001.
const EXPECTED_INDEX_NAMES: &[&str] = &[
    "idx_proxy_plugins_plugin_config_id",
    "idx_consumer_credential_index_consumer_id",
    "idx_proxies_ns_updated",
    "idx_consumers_ns_updated",
    "idx_plugin_configs_ns_updated",
    "idx_upstreams_ns_updated",
    "idx_audit_events_namespace_ts_id",
    // Sequence indexes for durable incremental-poll change tracking.
    "idx_config_changes_ns_sequence",
    "idx_config_changes_sequence",
    "idx_plugin_configs_scope_id",
];

#[tokio::test]
async fn test_migration_runner_fresh_database() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let applied = runner.run_pending().await.unwrap();

    // V1 should be applied on a fresh database.
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[0].name, "initial_schema");

    // Running again should apply nothing
    let applied_again = runner.run_pending().await.unwrap();
    assert!(applied_again.is_empty());

    // Verify that V001 creates the expected indexes
    let index_names = get_index_names(&pool).await;
    for expected in EXPECTED_INDEX_NAMES {
        assert!(
            index_names.iter().any(|n| n == expected),
            "Expected index '{}' to exist after V001 migration, found: {:?}",
            expected,
            index_names
        );
    }
}

/// Returns true if a table with the given name exists in the SQLite database.
async fn table_exists(pool: &sqlx::AnyPool, table: &str) -> bool {
    let rows: Vec<sqlx::any::AnyRow> =
        sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table)
            .fetch_all(pool)
            .await
            .unwrap();
    !rows.is_empty()
}

/// Regression test for the route-lock compatibility pass.
///
/// `proxy_route_locks` was folded into the V001 baseline after databases could
/// already have V001 recorded in `_ferrum_migrations`. The migration loop skips
/// V001 once version 1 is tracked, so without an idempotent compatibility pass
/// the table would never be created on those databases — and the proxy
/// persistence path writes to it on every create/update/batch/API-spec write,
/// so each write would fail with a missing-table error.
///
/// This simulates such a database by applying V001, dropping `proxy_route_locks`
/// (leaving the V001 record intact, exactly as a pre-fold database looks), then
/// re-running `run_pending()` and asserting the table is restored and writable.
#[tokio::test]
async fn test_run_pending_restores_route_lock_table_on_existing_v001_db() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Fresh apply records V001 and creates proxy_route_locks.
    runner.run_pending().await.unwrap();
    assert!(table_exists(&pool, "proxy_route_locks").await);

    // Simulate a database that recorded V001 *before* proxy_route_locks was
    // folded in: the V001 record stays, but the table is gone.
    sqlx::query("DROP TABLE proxy_route_locks")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!table_exists(&pool, "proxy_route_locks").await);

    // The migration loop skips already-tracked V001, but the idempotent
    // compatibility pass must recreate the table.
    let applied = runner.run_pending().await.unwrap();
    assert!(
        applied.is_empty(),
        "V001 is already tracked, so no migration should be newly applied"
    );
    assert!(
        table_exists(&pool, "proxy_route_locks").await,
        "run_pending must restore proxy_route_locks on an existing V001 database"
    );

    // The restored table must accept the route-lock insert the persistence
    // path performs.
    sqlx::query(
        "INSERT INTO proxy_route_locks (namespace, route_key_hash, created_at) \
         VALUES ('ferrum', 'deadbeef', '2025-01-01T00:00:00Z')",
    )
    .execute(&pool)
    .await
    .expect("restored proxy_route_locks must be writable");
}

#[tokio::test]
async fn test_run_pending_restores_config_change_indexes_on_existing_v001_db() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    runner.run_pending().await.unwrap();
    sqlx::query("DROP INDEX idx_config_changes_ns_sequence")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP INDEX idx_config_changes_sequence")
        .execute(&pool)
        .await
        .unwrap();
    let index_names = get_index_names(&pool).await;
    assert!(!index_names.iter().any(|n| n == "idx_config_changes_ns_sequence"));
    assert!(!index_names.iter().any(|n| n == "idx_config_changes_sequence"));

    let applied = runner.run_pending().await.unwrap();
    assert!(
        applied.is_empty(),
        "V001 is already tracked, so no migration should be newly applied"
    );
    let index_names = get_index_names(&pool).await;
    assert!(
        index_names.iter().any(|n| n == "idx_config_changes_ns_sequence"),
        "compatibility pass must restore idx_config_changes_ns_sequence"
    );
    assert!(
        index_names.iter().any(|n| n == "idx_config_changes_sequence"),
        "compatibility pass must restore idx_config_changes_sequence"
    );
}

/// Incremental polling reads durable change records after the last accepted
/// sequence cursor. The `(namespace, sequence)` index must support the range
/// scan and ordering so polling cost follows retained changes, not total
/// runtime resource count.
#[tokio::test]
async fn test_v001_config_changes_poll_uses_sequence_index() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    let rows: Vec<sqlx::any::AnyRow> = sqlx::query(
        "EXPLAIN QUERY PLAN \
         SELECT sequence, resource_type, resource_id, operation, created_at \
         FROM config_changes \
         WHERE namespace = ? AND sequence > ? \
         ORDER BY sequence ASC",
    )
    .bind("ferrum")
    .bind(42_i64)
    .fetch_all(&pool)
    .await
    .unwrap();
    let plan: String = rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("detail").ok())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        plan.contains("idx_config_changes_ns_sequence"),
        "incremental change poll should use idx_config_changes_ns_sequence, got plan: {plan}"
    );
}

#[tokio::test]
async fn test_v001_schema_includes_upstream_backend_tls_identity_fields() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    sqlx::query(
        "INSERT INTO upstreams \
         (id, name, targets, algorithm, backend_tls_sni, backend_tls_san_allow_list, created_at, updated_at) \
         VALUES ('tls-upstream', 'tls', '[]', 'round_robin', ?, ?, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')",
    )
    .bind("reviews.mesh.internal")
    .bind("[\"reviews.mesh.internal\"]")
    .execute(&pool)
    .await
    .expect("INSERT with backend TLS identity fields should succeed");

    let row = sqlx::query(
        "SELECT backend_tls_sni, backend_tls_san_allow_list FROM upstreams WHERE id = 'tls-upstream'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let sni: String = row.try_get("backend_tls_sni").unwrap();
    let sans: String = row.try_get("backend_tls_san_allow_list").unwrap();
    assert_eq!(sni, "reviews.mesh.internal");
    assert_eq!(sans, "[\"reviews.mesh.internal\"]");
}

#[tokio::test]
async fn test_migration_runner_rejects_existing_untracked_schema() {
    let pool = test_pool().await;

    // Simulate a pre-migration database by creating the tables directly.
    // A real pre-migration DB has all five tables; this should fail instead
    // of trying to bootstrap over an untracked schema.
    sqlx::query(
        "CREATE TABLE upstreams (id TEXT PRIMARY KEY, namespace TEXT NOT NULL DEFAULT 'ferrum', name TEXT, targets TEXT NOT NULL DEFAULT '[]', algorithm TEXT NOT NULL DEFAULT 'round_robin', hash_on TEXT, hash_on_cookie_config TEXT, health_checks TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE consumers (id TEXT PRIMARY KEY, namespace TEXT NOT NULL DEFAULT 'ferrum', username TEXT NOT NULL, custom_id TEXT, credentials TEXT NOT NULL DEFAULT '{}', acl_groups TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE proxies (id TEXT PRIMARY KEY, namespace TEXT NOT NULL DEFAULT 'ferrum', name TEXT, hosts TEXT NOT NULL DEFAULT '[]', listen_path TEXT, backend_scheme TEXT NOT NULL DEFAULT 'https', backend_host TEXT NOT NULL, backend_port INTEGER NOT NULL DEFAULT 80, backend_path TEXT, strip_listen_path INTEGER NOT NULL DEFAULT 1, preserve_host_header INTEGER NOT NULL DEFAULT 0, backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000, backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000, backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000, upstream_id TEXT REFERENCES upstreams(id), auth_mode TEXT NOT NULL DEFAULT 'single', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE plugin_configs (id TEXT PRIMARY KEY, namespace TEXT NOT NULL DEFAULT 'ferrum', plugin_name TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}', scope TEXT NOT NULL DEFAULT 'global', proxy_id TEXT REFERENCES proxies(id) ON DELETE CASCADE, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE proxy_plugins (proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE, plugin_config_id TEXT NOT NULL REFERENCES plugin_configs(id) ON DELETE CASCADE, PRIMARY KEY (proxy_id, plugin_config_id))"
    )
    .execute(&pool)
    .await
    .unwrap();

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let err = runner
        .run_pending()
        .await
        .expect_err("existing untracked schemas must not be bootstrapped");
    let msg = err.to_string();
    assert!(
        msg.contains("api_spec_id") || msg.contains("duplicate") || msg.contains("already exists"),
        "expected V1 to fail against the untracked old schema, got: {msg}"
    );

    // No bootstrap marker is inserted, so all migrations are still pending.
    let status = runner.status().await.unwrap();
    assert!(status.applied.is_empty());
    assert_eq!(status.pending.len(), 1);
    assert_eq!(status.pending[0].version, 1);
}

#[tokio::test]
async fn test_migration_status() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Before running: V1 should be pending.
    let status = runner.status().await.unwrap();
    assert!(status.applied.is_empty());
    assert_eq!(status.pending.len(), 1);

    // Run migrations
    runner.run_pending().await.unwrap();

    // After running: V1 should be applied.
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert!(status.pending.is_empty());
}

#[tokio::test]
async fn test_v001_accepts_full_rfc3339_timestamps() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let applied = runner.run_pending().await.unwrap();

    // V1 should be applied on a fresh database.
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 1);

    // Verify the schema accepts a full nanosecond-precision RFC 3339 timestamp
    // (35 chars, the maximum chrono produces)
    let long_ts = "2024-01-15T12:34:56.123456789+00:00";
    sqlx::query(
        "INSERT INTO proxies (id, name, listen_path, backend_host, backend_port, hosts, created_at, updated_at) VALUES ('ts-test', 'ts', '/ts', 'localhost', 8080, '[]', ?, ?)"
    )
    .bind(long_ts)
    .bind(long_ts)
    .execute(&pool)
    .await
    .expect("INSERT with 35-char RFC 3339 timestamp should succeed");

    let row = sqlx::query("SELECT created_at FROM proxies WHERE id = 'ts-test'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let val: String = sqlx::Row::try_get(&row, "created_at").unwrap();
    assert_eq!(val, long_ts);
}

#[tokio::test]
async fn test_v001_schema_includes_tcp_idle_timeout_seconds() {
    let pool = test_pool().await;

    // Run V1 migration
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    // Verify the tcp_idle_timeout_seconds column exists by inserting a row that uses it
    sqlx::query(
        "INSERT INTO proxies (id, name, listen_path, backend_host, backend_port, hosts, tcp_idle_timeout_seconds, created_at, updated_at) VALUES ('test-proxy', 'test', '/test', 'localhost', 8080, '[]', 120, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')"
    )
    .execute(&pool)
    .await
    .expect("INSERT with tcp_idle_timeout_seconds should succeed");

    // Read it back
    let row: (i64,) =
        sqlx::query_as("SELECT tcp_idle_timeout_seconds FROM proxies WHERE id = 'test-proxy'")
            .fetch_one(&pool)
            .await
            .expect("Should be able to read tcp_idle_timeout_seconds");

    assert_eq!(row.0, 120);
}

#[tokio::test]
async fn test_v001_tcp_idle_timeout_seconds_nullable() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    // Insert without tcp_idle_timeout_seconds — should default to NULL
    sqlx::query(
        "INSERT INTO proxies (id, name, listen_path, backend_host, backend_port, hosts, created_at, updated_at) VALUES ('test-null', 'test-null', '/null', 'localhost', 8080, '[]', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')"
    )
    .execute(&pool)
    .await
    .expect("INSERT without tcp_idle_timeout_seconds should succeed (nullable column)");

    // Verify the value is NULL
    let row = sqlx::query("SELECT tcp_idle_timeout_seconds FROM proxies WHERE id = 'test-null'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let val: Option<i64> = sqlx::Row::try_get(&row, "tcp_idle_timeout_seconds").ok();
    assert!(
        val.is_none(),
        "tcp_idle_timeout_seconds should be NULL when not specified"
    );
}

#[tokio::test]
async fn test_v001_schema_includes_acl_groups_column() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    // Insert a consumer without specifying acl_groups — should default to '[]'
    sqlx::query(
        "INSERT INTO consumers (id, username, credentials, created_at, updated_at) VALUES ('c1', 'alice', '{}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')"
    )
    .execute(&pool)
    .await
    .expect("INSERT without acl_groups should succeed (defaults to '[]')");

    let row = sqlx::query("SELECT acl_groups FROM consumers WHERE id = 'c1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let val: String = sqlx::Row::try_get(&row, "acl_groups").unwrap();
    assert_eq!(val, "[]");

    // Insert with explicit acl_groups
    sqlx::query(
        r#"INSERT INTO consumers (id, username, credentials, acl_groups, created_at, updated_at) VALUES ('c2', 'bob', '{}', '["engineering","platform"]', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')"#
    )
    .execute(&pool)
    .await
    .expect("INSERT with acl_groups should succeed");

    let row = sqlx::query("SELECT acl_groups FROM consumers WHERE id = 'c2'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let val: String = sqlx::Row::try_get(&row, "acl_groups").unwrap();
    let groups: Vec<String> = serde_json::from_str(&val).unwrap();
    assert_eq!(groups, vec!["engineering", "platform"]);
}
