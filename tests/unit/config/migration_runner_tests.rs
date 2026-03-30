//! Tests for database migration runner

use ferrum_gateway::config::migrations::MigrationRunner;

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

    // V1 + V2 should be applied on a fresh database
    assert_eq!(applied.len(), 2);
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[0].name, "initial_schema");
    assert_eq!(applied[1].version, 2);
    assert_eq!(applied[1].name, "hash_on_cookie_config");

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
        "CREATE TABLE upstreams (id TEXT PRIMARY KEY, name TEXT, targets TEXT NOT NULL DEFAULT '[]', algorithm TEXT NOT NULL DEFAULT 'round_robin', hash_on TEXT, health_checks TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    .execute(&pool)
    .await
    .unwrap();

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    let applied = runner.run_pending().await.unwrap();

    // V1 should NOT be applied (bootstrapped instead), but V2 should be applied
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 2);
    assert_eq!(applied[0].name, "hash_on_cookie_config");

    // Check that V1 (bootstrapped) + V2 (applied) are recorded
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 2);
    assert_eq!(status.applied[0].version, 1);
    assert_eq!(status.applied[1].version, 2);
    assert!(status.pending.is_empty());
}

#[tokio::test]
async fn test_migration_status() {
    let pool = test_pool().await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Before running: everything should be pending
    let status = runner.status().await.unwrap();
    assert!(status.applied.is_empty());
    assert_eq!(status.pending.len(), 2);

    // Run migrations
    runner.run_pending().await.unwrap();

    // After running: everything should be applied
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 2);
    assert!(status.pending.is_empty());
}
