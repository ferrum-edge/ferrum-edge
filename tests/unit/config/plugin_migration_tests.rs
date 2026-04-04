//! Tests for custom plugin database migration support

use ferrum_edge::config::migrations::{CustomPluginMigration, MigrationRunner};

/// Create a single-connection SQLite in-memory pool for testing.
async fn test_pool() -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// Helper to run core migrations first (required for a valid database state).
async fn setup_core_migrations(pool: &sqlx::AnyPool) {
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();
}

// ---------------------------------------------------------------------------
// Database-specific SQL selection
// ---------------------------------------------------------------------------

#[test]
fn test_sql_for_db_default() {
    let m = CustomPluginMigration {
        version: 1,
        name: "test",
        checksum: "test_checksum",
        sql: "CREATE TABLE t (id TEXT)",
        sql_postgres: None,
        sql_mysql: None,
    };

    // SQLite uses default
    assert_eq!(m.sql_for_db("sqlite"), "CREATE TABLE t (id TEXT)");
    // PostgreSQL uses default when no override
    assert_eq!(m.sql_for_db("postgres"), "CREATE TABLE t (id TEXT)");
    // MySQL uses default when no override
    assert_eq!(m.sql_for_db("mysql"), "CREATE TABLE t (id TEXT)");
}

#[test]
fn test_sql_for_db_postgres_override() {
    let m = CustomPluginMigration {
        version: 1,
        name: "test",
        checksum: "test_checksum",
        sql: "CREATE TABLE t (id TEXT, data TEXT)",
        sql_postgres: Some("CREATE TABLE t (id TEXT, data JSONB)"),
        sql_mysql: None,
    };

    assert_eq!(
        m.sql_for_db("postgres"),
        "CREATE TABLE t (id TEXT, data JSONB)"
    );
    // SQLite still uses default
    assert_eq!(
        m.sql_for_db("sqlite"),
        "CREATE TABLE t (id TEXT, data TEXT)"
    );
    // MySQL still uses default
    assert_eq!(m.sql_for_db("mysql"), "CREATE TABLE t (id TEXT, data TEXT)");
}

#[test]
fn test_sql_for_db_mysql_override() {
    let m = CustomPluginMigration {
        version: 1,
        name: "test",
        checksum: "test_checksum",
        sql: "CREATE TABLE t (id TEXT PRIMARY KEY)",
        sql_postgres: None,
        sql_mysql: Some("CREATE TABLE t (id VARCHAR(255) PRIMARY KEY)"),
    };

    assert_eq!(
        m.sql_for_db("mysql"),
        "CREATE TABLE t (id VARCHAR(255) PRIMARY KEY)"
    );
    assert_eq!(
        m.sql_for_db("sqlite"),
        "CREATE TABLE t (id TEXT PRIMARY KEY)"
    );
    assert_eq!(
        m.sql_for_db("postgres"),
        "CREATE TABLE t (id TEXT PRIMARY KEY)"
    );
}

#[test]
fn test_sql_for_db_both_overrides() {
    let m = CustomPluginMigration {
        version: 1,
        name: "test",
        checksum: "test_checksum",
        sql: "CREATE TABLE t (ts TEXT)",
        sql_postgres: Some("CREATE TABLE t (ts TIMESTAMPTZ)"),
        sql_mysql: Some("CREATE TABLE t (ts DATETIME(3))"),
    };

    assert_eq!(m.sql_for_db("sqlite"), "CREATE TABLE t (ts TEXT)");
    assert_eq!(m.sql_for_db("postgres"), "CREATE TABLE t (ts TIMESTAMPTZ)");
    assert_eq!(m.sql_for_db("mysql"), "CREATE TABLE t (ts DATETIME(3))");
}

#[test]
fn test_sql_for_db_unknown_type_uses_default() {
    let m = CustomPluginMigration {
        version: 1,
        name: "test",
        checksum: "test_checksum",
        sql: "CREATE TABLE t (id TEXT)",
        sql_postgres: Some("CREATE TABLE t (id TEXT) -- pg"),
        sql_mysql: Some("CREATE TABLE t (id TEXT) -- mysql"),
    };

    // Unknown db type falls through to default sql
    assert_eq!(m.sql_for_db("cockroachdb"), "CREATE TABLE t (id TEXT)");
}

// ---------------------------------------------------------------------------
// run_plugin_pending — basic execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_migrations_fresh_database() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "test_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_test_table",
            checksum: "v1_test_abc123",
            sql: "CREATE TABLE IF NOT EXISTS test_plugin_data (id TEXT PRIMARY KEY, value TEXT NOT NULL)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].plugin_name, "test_plugin");
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[0].name, "create_test_table");

    // Verify the table was actually created
    sqlx::query("INSERT INTO test_plugin_data (id, value) VALUES ('k1', 'v1')")
        .execute(&pool)
        .await
        .expect("Table should exist after migration");
}

#[tokio::test]
async fn test_plugin_migrations_idempotent() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "test_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_table",
            checksum: "v1_chk",
            sql: "CREATE TABLE IF NOT EXISTS idempotent_test (id TEXT PRIMARY KEY)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    // First run applies
    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 1);

    // Second run skips (already applied)
    let applied_again = runner.run_plugin_pending(&migrations).await.unwrap();
    assert!(applied_again.is_empty());
}

#[tokio::test]
async fn test_plugin_migrations_multiple_versions() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "multi_ver",
        vec![
            CustomPluginMigration {
                version: 1,
                name: "create_table",
                checksum: "v1_chk",
                sql: "CREATE TABLE IF NOT EXISTS multi_ver_data (id TEXT PRIMARY KEY, value TEXT)",
                sql_postgres: None,
                sql_mysql: None,
            },
            CustomPluginMigration {
                version: 2,
                name: "add_index",
                checksum: "v2_chk",
                sql: "CREATE INDEX IF NOT EXISTS idx_multi_ver_value ON multi_ver_data (value)",
                sql_postgres: None,
                sql_mysql: None,
            },
        ],
    )];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 2);
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[1].version, 2);
}

#[tokio::test]
async fn test_plugin_migrations_incremental_apply() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Apply V1 first
    let v1_only = vec![(
        "incr_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "v1",
            checksum: "v1_chk",
            sql: "CREATE TABLE IF NOT EXISTS incr_data (id TEXT PRIMARY KEY)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let applied = runner.run_plugin_pending(&v1_only).await.unwrap();
    assert_eq!(applied.len(), 1);

    // Now add V2
    let v1_and_v2 = vec![(
        "incr_plugin",
        vec![
            CustomPluginMigration {
                version: 1,
                name: "v1",
                checksum: "v1_chk",
                sql: "CREATE TABLE IF NOT EXISTS incr_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            },
            CustomPluginMigration {
                version: 2,
                name: "v2",
                checksum: "v2_chk",
                sql: "ALTER TABLE incr_data ADD COLUMN extra TEXT",
                sql_postgres: None,
                sql_mysql: None,
            },
        ],
    )];

    let applied = runner.run_plugin_pending(&v1_and_v2).await.unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 2);
}

// ---------------------------------------------------------------------------
// Multi-statement SQL execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_migration_multi_statement_sql() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![(
        "multi_stmt",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_table_and_index",
            checksum: "v1_multi",
            sql: r#"
                CREATE TABLE IF NOT EXISTS multi_stmt_data (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    value TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_multi_stmt_category ON multi_stmt_data (category)
            "#,
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 1);

    // Verify both the table and index were created
    sqlx::query("INSERT INTO multi_stmt_data (id, category, value) VALUES ('k1', 'cat1', 'v1')")
        .execute(&pool)
        .await
        .expect("Table should exist");

    // The index should be usable (query exercises it)
    sqlx::query("SELECT id FROM multi_stmt_data WHERE category = 'cat1'")
        .fetch_one(&pool)
        .await
        .expect("Index should be usable");
}

#[tokio::test]
async fn test_plugin_migration_trailing_semicolons_and_whitespace() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // SQL with trailing semicolons and extra whitespace — should not cause errors
    let migrations = vec![(
        "whitespace",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_table",
            checksum: "v1_ws",
            sql: "  CREATE TABLE IF NOT EXISTS ws_test (id TEXT PRIMARY KEY)  ;  ;  ",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();
    assert_eq!(applied.len(), 1);
}

// ---------------------------------------------------------------------------
// Multiple plugins with independent version spaces
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_plugins_independent_versions() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let migrations = vec![
        (
            "plugin_a",
            vec![
                CustomPluginMigration {
                    version: 1,
                    name: "create_a_table",
                    checksum: "a_v1",
                    sql: "CREATE TABLE IF NOT EXISTS plugin_a_data (id TEXT PRIMARY KEY)",
                    sql_postgres: None,
                    sql_mysql: None,
                },
                CustomPluginMigration {
                    version: 2,
                    name: "add_a_column",
                    checksum: "a_v2",
                    sql: "ALTER TABLE plugin_a_data ADD COLUMN extra TEXT",
                    sql_postgres: None,
                    sql_mysql: None,
                },
            ],
        ),
        (
            "plugin_b",
            vec![CustomPluginMigration {
                version: 1,
                name: "create_b_table",
                checksum: "b_v1",
                sql: "CREATE TABLE IF NOT EXISTS plugin_b_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            }],
        ),
    ];

    let applied = runner.run_plugin_pending(&migrations).await.unwrap();

    // plugin_a V1, plugin_a V2, plugin_b V1
    assert_eq!(applied.len(), 3);
    assert_eq!(applied[0].plugin_name, "plugin_a");
    assert_eq!(applied[0].version, 1);
    assert_eq!(applied[1].plugin_name, "plugin_a");
    assert_eq!(applied[1].version, 2);
    assert_eq!(applied[2].plugin_name, "plugin_b");
    assert_eq!(applied[2].version, 1);
}

// ---------------------------------------------------------------------------
// Checksum mismatch detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_migration_checksum_mismatch_warns_but_continues() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    // Apply V1 with original checksum
    let migrations_v1 = vec![(
        "chk_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_table",
            checksum: "original_checksum",
            sql: "CREATE TABLE IF NOT EXISTS chk_data (id TEXT PRIMARY KEY)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];
    runner.run_plugin_pending(&migrations_v1).await.unwrap();

    // Now run with a different checksum for V1 + a new V2
    // This should warn about the checksum mismatch but still apply V2
    let migrations_v1_modified = vec![(
        "chk_plugin",
        vec![
            CustomPluginMigration {
                version: 1,
                name: "create_table",
                checksum: "modified_checksum",
                sql: "CREATE TABLE IF NOT EXISTS chk_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            },
            CustomPluginMigration {
                version: 2,
                name: "add_column",
                checksum: "v2_checksum",
                sql: "ALTER TABLE chk_data ADD COLUMN value TEXT",
                sql_postgres: None,
                sql_mysql: None,
            },
        ],
    )];

    // Should not error — mismatch is a warning, not a failure
    let applied = runner
        .run_plugin_pending(&migrations_v1_modified)
        .await
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].version, 2);
}

// ---------------------------------------------------------------------------
// plugin_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_status_shows_applied_and_pending() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let all_migrations = vec![(
        "status_plugin",
        vec![
            CustomPluginMigration {
                version: 1,
                name: "v1",
                checksum: "v1_chk",
                sql: "CREATE TABLE IF NOT EXISTS status_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            },
            CustomPluginMigration {
                version: 2,
                name: "v2",
                checksum: "v2_chk",
                sql: "ALTER TABLE status_data ADD COLUMN extra TEXT",
                sql_postgres: None,
                sql_mysql: None,
            },
        ],
    )];

    // Before running: both should be pending
    let status = runner.plugin_status(&all_migrations).await.unwrap();
    assert!(status.applied.is_empty());
    assert_eq!(status.pending.len(), 2);
    assert_eq!(status.pending[0].plugin_name, "status_plugin");
    assert_eq!(status.pending[0].version, 1);
    assert_eq!(status.pending[1].version, 2);

    // Apply V1 only
    let v1_only = vec![(
        "status_plugin",
        vec![CustomPluginMigration {
            version: 1,
            name: "v1",
            checksum: "v1_chk",
            sql: "CREATE TABLE IF NOT EXISTS status_data (id TEXT PRIMARY KEY)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];
    runner.run_plugin_pending(&v1_only).await.unwrap();

    // After V1: one applied, one pending
    let status = runner.plugin_status(&all_migrations).await.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert_eq!(status.applied[0].version, 1);
    assert_eq!(status.pending.len(), 1);
    assert_eq!(status.pending[0].version, 2);
}

#[tokio::test]
async fn test_plugin_status_empty_when_no_plugins() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let empty: Vec<(&str, Vec<CustomPluginMigration>)> = vec![];
    let status = runner.plugin_status(&empty).await.unwrap();
    assert!(status.applied.is_empty());
    assert!(status.pending.is_empty());
}

#[tokio::test]
async fn test_run_plugin_pending_empty_is_noop() {
    let pool = test_pool().await;
    setup_core_migrations(&pool).await;

    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let empty: Vec<(&str, Vec<CustomPluginMigration>)> = vec![];
    let applied = runner.run_plugin_pending(&empty).await.unwrap();
    assert!(applied.is_empty());
}
