//! Tests for database migration runner

use ferrum_edge::config::migrations::MigrationRunner;

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

#[tokio::test]
async fn test_migration_runner_fresh_database() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let applied = runner.run_pending().await.unwrap();

    // V1 should be applied on a fresh database
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[0].name, "initial_schema");

    // Running again should apply nothing
    let applied_again = runner.run_pending().await.unwrap();
    assert!(applied_again.is_empty());
}

#[tokio::test]
async fn test_migration_runner_bootstrap_existing_db() {
    let pool = test_pool().await;

    // Simulate a pre-migration database by creating the core tables directly
    // (as V1 would have created them, so V2+ migrations can alter them)
    sqlx::query(
        "CREATE TABLE proxies (id TEXT PRIMARY KEY, name TEXT, listen_path TEXT NOT NULL UNIQUE, backend_protocol TEXT NOT NULL DEFAULT 'http', backend_host TEXT NOT NULL, backend_port INTEGER NOT NULL DEFAULT 80, backend_path TEXT, strip_listen_path INTEGER NOT NULL DEFAULT 1, preserve_host_header INTEGER NOT NULL DEFAULT 0, backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000, backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000, backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000, backend_tls_client_cert_path TEXT, backend_tls_client_key_path TEXT, backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1, backend_tls_server_ca_cert_path TEXT, dns_override TEXT, dns_cache_ttl_seconds INTEGER, auth_mode TEXT NOT NULL DEFAULT 'single', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE upstreams (id TEXT PRIMARY KEY, name TEXT, targets TEXT NOT NULL DEFAULT '[]', algorithm TEXT NOT NULL DEFAULT 'round_robin', hash_on TEXT, hash_on_cookie_config TEXT, health_checks TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let applied = runner.run_pending().await.unwrap();

    // V1 should NOT be applied (bootstrapped instead)
    assert!(applied.is_empty());

    // Check that V1 (bootstrapped) is recorded
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert_eq!(status.applied[0].version, 1);
    assert!(status.pending.is_empty());
}

#[tokio::test]
async fn test_migration_status() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Before running: everything should be pending
    let status = runner.status().await.unwrap();
    assert!(status.applied.is_empty());
    assert_eq!(status.pending.len(), 1);

    // Run migrations
    runner.run_pending().await.unwrap();

    // After running: everything should be applied
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert!(status.pending.is_empty());
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
