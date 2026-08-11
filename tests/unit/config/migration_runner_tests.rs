//! Tests for database migration runner

use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::migrations::{
    AppliedMigrationHistory, AppliedMigrationHistoryEntry, CustomPluginMigration,
    DeclaredMigrationHistory, DeclaredMigrationHistoryEntry, MigrationHistoryIntegrityError,
    MigrationHistoryIntegrityKind, MigrationHistoryIntegrityReason, MigrationHistoryNamespace,
    MigrationRunner, validate_migration_history_integrity,
};
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
    "idx_proxies_ns_id",
    "idx_consumers_ns_id",
    "idx_plugin_configs_ns_id",
    "idx_upstreams_ns_id",
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

/// Regression test for the audit_events compatibility pass.
///
/// `audit_events` was folded into the V001 baseline after databases could
/// already have V001 recorded in `_ferrum_migrations`. The migration loop skips
/// V001 once version 1 is tracked, so without an idempotent compatibility pass
/// the table and its indexes would never be created on those databases.
#[tokio::test]
async fn test_run_pending_restores_audit_events_table_on_existing_v001_db() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    runner.run_pending().await.unwrap();
    assert!(table_exists(&pool, "audit_events").await);

    sqlx::query("DROP TABLE audit_events")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!table_exists(&pool, "audit_events").await);

    let applied = runner.run_pending().await.unwrap();
    assert!(
        applied.is_empty(),
        "V001 is already tracked, so no migration should be newly applied"
    );
    assert!(
        table_exists(&pool, "audit_events").await,
        "run_pending must restore audit_events on an existing V001 database"
    );

    let index_names = get_index_names(&pool).await;
    for index_name in [
        "idx_audit_events_namespace_ts_id",
        "idx_audit_events_actor",
        "idx_audit_events_resource_type",
    ] {
        assert!(
            index_names.iter().any(|n| n == index_name),
            "compatibility pass must restore {index_name}"
        );
    }

    sqlx::query(
        "INSERT INTO audit_events \
         (id, ts, actor, action, resource_type, resource_id, namespace, \
          source_address, request_id, outcome, diff) \
         VALUES ('event-1', '2026-01-01T00:00:00Z', 'admin', 'backup', \
                 'backup', 'export', 'ferrum', '127.0.0.1', 'request-1', \
                 'success', '{}')",
    )
    .execute(&pool)
    .await
    .expect("restored audit_events must be writable");
}

#[tokio::test]
async fn test_run_pending_adds_audit_context_columns_on_existing_v001_db() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    runner.run_pending().await.unwrap();
    for column in ["source_address", "request_id", "outcome"] {
        let sql = format!("ALTER TABLE audit_events DROP COLUMN {column}");
        sqlx::query(&sql).execute(&pool).await.unwrap();
    }

    let applied = runner.run_pending().await.unwrap();
    assert!(applied.is_empty(), "V001 must remain already applied");

    sqlx::query(
        "INSERT INTO audit_events \
         (id, ts, actor, action, resource_type, resource_id, namespace, \
          source_address, request_id, outcome, diff) \
         VALUES ('event-1', '2026-01-01T00:00:00Z', 'admin', 'backup', \
                 'backup', 'export', 'ferrum', '127.0.0.1', 'request-1', \
                 'success', '{}')",
    )
    .execute(&pool)
    .await
    .expect("upgraded audit_events must accept context-aware audit inserts");

    let row = sqlx::query(
        "SELECT source_address, request_id, outcome FROM audit_events WHERE id = 'event-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row.try_get::<String, _>("source_address").unwrap(),
        "127.0.0.1"
    );
    assert_eq!(row.try_get::<String, _>("request_id").unwrap(), "request-1");
    assert_eq!(row.try_get::<String, _>("outcome").unwrap(), "success");
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
    assert!(
        !index_names
            .iter()
            .any(|n| n == "idx_config_changes_ns_sequence")
    );
    assert!(
        !index_names
            .iter()
            .any(|n| n == "idx_config_changes_sequence")
    );

    let applied = runner.run_pending().await.unwrap();
    assert!(
        applied.is_empty(),
        "V001 is already tracked, so no migration should be newly applied"
    );
    let index_names = get_index_names(&pool).await;
    assert!(
        index_names
            .iter()
            .any(|n| n == "idx_config_changes_ns_sequence"),
        "compatibility pass must restore idx_config_changes_ns_sequence"
    );
    assert!(
        index_names
            .iter()
            .any(|n| n == "idx_config_changes_sequence"),
        "compatibility pass must restore idx_config_changes_sequence"
    );
}

#[tokio::test]
async fn test_run_pending_restores_full_load_indexes_on_existing_v001_db() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    runner.run_pending().await.unwrap();
    for index_name in [
        "idx_proxies_ns_id",
        "idx_consumers_ns_id",
        "idx_plugin_configs_ns_id",
        "idx_upstreams_ns_id",
    ] {
        let drop_sql = format!("DROP INDEX {index_name}");
        sqlx::query(&drop_sql).execute(&pool).await.unwrap();
    }
    let index_names = get_index_names(&pool).await;
    for index_name in [
        "idx_proxies_ns_id",
        "idx_consumers_ns_id",
        "idx_plugin_configs_ns_id",
        "idx_upstreams_ns_id",
    ] {
        assert!(
            !index_names.iter().any(|n| n == index_name),
            "{index_name} should be absent after DROP INDEX"
        );
    }

    let applied = runner.run_pending().await.unwrap();
    assert!(
        applied.is_empty(),
        "V001 is already tracked, so no migration should be newly applied"
    );
    let index_names = get_index_names(&pool).await;
    for index_name in [
        "idx_proxies_ns_id",
        "idx_consumers_ns_id",
        "idx_plugin_configs_ns_id",
        "idx_upstreams_ns_id",
    ] {
        assert!(
            index_names.iter().any(|n| n == index_name),
            "compatibility pass must restore {index_name}"
        );
    }
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
    runner
        .run_pending()
        .await
        .expect_err("existing untracked schemas must not be bootstrapped");

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
    assert!(
        !table_exists(&pool, "_ferrum_migrations").await,
        "status must not create the core migration tracking table"
    );

    // Run migrations
    runner.run_pending().await.unwrap();

    // After running: V1 should be applied.
    let status = runner.status().await.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert!(status.pending.is_empty());
}

#[tokio::test]
async fn test_v001_checksum_is_content_derived_sha256() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool, "sqlite".to_string());

    let applied = runner.run_pending().await.unwrap();
    let checksum = &applied[0].checksum;
    assert!(checksum.starts_with("sha256:"));
    assert_eq!(checksum.len(), "sha256:".len() + 64);
    assert_ne!(checksum, "v001_initial_schema");
}

fn declared_history(
    namespace: MigrationHistoryNamespace,
    migrations: &[(i64, &str)],
) -> DeclaredMigrationHistory {
    DeclaredMigrationHistory {
        namespace,
        migrations: migrations
            .iter()
            .map(|(version, checksum)| DeclaredMigrationHistoryEntry {
                version: *version,
                checksum: (*checksum).to_string(),
            })
            .collect(),
    }
}

fn applied_history(
    namespace: MigrationHistoryNamespace,
    migrations: &[(i64, &str)],
) -> AppliedMigrationHistory {
    AppliedMigrationHistory {
        namespace,
        migrations: migrations
            .iter()
            .map(|(version, checksum)| AppliedMigrationHistoryEntry {
                version: *version,
                checksum: (*checksum).to_string(),
            })
            .collect(),
    }
}

#[test]
fn history_integrity_validation_is_shared_by_every_sql_adapter() {
    let plugin_namespace = MigrationHistoryNamespace::CustomPlugin("audit_plugin".to_string());
    let declarations = vec![
        declared_history(
            MigrationHistoryNamespace::Core,
            &[(1, "core-1"), (2, "core-2")],
        ),
        declared_history(
            plugin_namespace.clone(),
            &[(3, "plugin-3"), (4, "plugin-4")],
        ),
    ];
    let valid_prefix = vec![
        applied_history(MigrationHistoryNamespace::Core, &[(1, "core-1")]),
        applied_history(plugin_namespace.clone(), &[(3, "plugin-3")]),
    ];

    for backend in ["sqlite", "postgres", "mysql"] {
        validate_migration_history_integrity(backend, &declarations, &valid_prefix)
            .expect("a valid prefix with a pending suffix must remain valid");

        for (namespace, version, stored_checksum) in [
            (MigrationHistoryNamespace::Core, 1, "stored-core"),
            (plugin_namespace.clone(), 3, "stored-plugin"),
        ] {
            let drift = vec![applied_history(
                namespace.clone(),
                &[(version, stored_checksum)],
            )];
            let error = validate_migration_history_integrity(backend, &declarations, &drift)
                .expect_err("checksum drift must fail closed");
            assert_eq!(error.backend, backend);
            assert_eq!(error.namespace, namespace);
            assert_eq!(
                error.kind(),
                MigrationHistoryIntegrityKind::ChecksumMismatch
            );
        }
    }
}

#[test]
fn shared_history_integrity_rejects_unknown_missing_and_ambiguous_sequences() {
    let plugin_namespace = MigrationHistoryNamespace::CustomPlugin("audit_plugin".to_string());
    let declarations = vec![
        declared_history(
            MigrationHistoryNamespace::Core,
            &[(1, "core-1"), (2, "core-2")],
        ),
        declared_history(
            plugin_namespace.clone(),
            &[(3, "plugin-3"), (4, "plugin-4")],
        ),
    ];

    for history in [
        applied_history(MigrationHistoryNamespace::Core, &[(99, "unknown")]),
        applied_history(plugin_namespace.clone(), &[(99, "unknown")]),
    ] {
        let error = validate_migration_history_integrity("sqlite", &declarations, &[history])
            .expect_err("an unknown applied version must fail closed");
        assert_eq!(
            error.kind(),
            MigrationHistoryIntegrityKind::UnknownAppliedVersion
        );
    }

    for history in [
        applied_history(MigrationHistoryNamespace::Core, &[(2, "core-2")]),
        applied_history(plugin_namespace.clone(), &[(4, "plugin-4")]),
    ] {
        let error = validate_migration_history_integrity("sqlite", &declarations, &[history])
            .expect_err("a later applied version cannot hide a missing prefix entry");
        assert_eq!(
            error.kind(),
            MigrationHistoryIntegrityKind::MissingAppliedVersion
        );
    }

    let duplicate_core_version = vec![declared_history(
        MigrationHistoryNamespace::Core,
        &[(1, "first"), (1, "duplicate")],
    )];
    let error = validate_migration_history_integrity("sqlite", &duplicate_core_version, &[])
        .expect_err("duplicate core declaration IDs must be rejected");
    assert_eq!(
        error.kind(),
        MigrationHistoryIntegrityKind::DuplicateDeclaredVersion
    );

    let duplicate_plugin_namespace = vec![
        declared_history(plugin_namespace.clone(), &[(1, "first")]),
        declared_history(plugin_namespace, &[(2, "second")]),
    ];
    let error = validate_migration_history_integrity("sqlite", &duplicate_plugin_namespace, &[])
        .expect_err("duplicate plugin namespace declarations must be rejected");
    assert_eq!(
        error.kind(),
        MigrationHistoryIntegrityKind::DuplicateDeclaredNamespace
    );

    for (declaration, expected_kind) in [
        (
            declared_history(MigrationHistoryNamespace::Core, &[(0, "zero")]),
            MigrationHistoryIntegrityKind::NonPositiveDeclaredVersion,
        ),
        (
            declared_history(
                MigrationHistoryNamespace::Core,
                &[(i64::from(i32::MAX) + 1, "out-of-range")],
            ),
            MigrationHistoryIntegrityKind::DeclaredVersionOutOfRange,
        ),
        (
            declared_history(
                MigrationHistoryNamespace::Core,
                &[(2, "second"), (1, "first")],
            ),
            MigrationHistoryIntegrityKind::UnorderedDeclaredVersions,
        ),
    ] {
        let error = validate_migration_history_integrity("sqlite", &[declaration], &[])
            .expect_err("invalid declaration ordering must fail closed");
        assert_eq!(error.kind(), expected_kind);
    }
    assert_eq!(
        MigrationHistoryIntegrityKind::DeclaredVersionOutOfRange.as_str(),
        "declared_version_out_of_range"
    );

    let duplicate_applied = applied_history(
        MigrationHistoryNamespace::Core,
        &[(1, "core-1"), (1, "core-1")],
    );
    let error = validate_migration_history_integrity("sqlite", &declarations, &[duplicate_applied])
        .expect_err("duplicate applied history rows must fail closed");
    assert_eq!(
        error.kind(),
        MigrationHistoryIntegrityKind::DuplicateAppliedVersion
    );
}

#[test]
fn integrity_error_display_is_single_line_escaped_bounded_and_keeps_raw_fields() {
    let backend = "sqlite\nbackend\u{1b}".repeat(1000);
    let plugin_name = "audit\rplugin\u{7}".repeat(1000);
    let stored_checksum = format!("stored\n\u{1b}{}", "x".repeat(100_000));
    let expected_checksum = format!("expected\t{}", "y".repeat(100_000));
    let error = MigrationHistoryIntegrityError {
        backend: backend.clone(),
        namespace: MigrationHistoryNamespace::CustomPlugin(plugin_name.clone()),
        reason: MigrationHistoryIntegrityReason::ChecksumMismatch {
            version: 7,
            stored_checksum: stored_checksum.clone(),
            expected_checksum: expected_checksum.clone(),
        },
    };

    let rendered = error.to_string();
    assert!(!rendered.contains('\n'));
    assert!(!rendered.contains('\r'));
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\u{7}'));
    assert!(rendered.contains("kind=checksum_mismatch"));
    assert!(rendered.contains("namespace=custom-plugin"));
    assert!(rendered.contains("version=7"));
    assert!(rendered.contains("\\n"));
    assert!(rendered.contains("\\u{1b}"));
    assert!(
        rendered.len() < 700,
        "every string field must remain bounded"
    );

    assert_eq!(error.backend, backend);
    assert_eq!(
        error.namespace,
        MigrationHistoryNamespace::CustomPlugin(plugin_name)
    );
    match error.reason {
        MigrationHistoryIntegrityReason::ChecksumMismatch {
            stored_checksum: raw_stored,
            expected_checksum: raw_expected,
            ..
        } => {
            assert_eq!(raw_stored, stored_checksum);
            assert_eq!(raw_expected, expected_checksum);
        }
        other => panic!("unexpected integrity reason: {other:?}"),
    }
}

#[test]
fn integrity_error_remains_typed_through_anyhow_context() {
    for (applied, expected_kind) in [
        (
            applied_history(MigrationHistoryNamespace::Core, &[(1, "stored")]),
            MigrationHistoryIntegrityKind::ChecksumMismatch,
        ),
        (
            applied_history(MigrationHistoryNamespace::Core, &[(99, "unknown")]),
            MigrationHistoryIntegrityKind::UnknownAppliedVersion,
        ),
    ] {
        let error = validate_migration_history_integrity(
            "sqlite",
            &[declared_history(
                MigrationHistoryNamespace::Core,
                &[(1, "expected")],
            )],
            &[applied],
        )
        .expect_err("invalid history must fail");
        let wrapped = anyhow::Error::new(error).context("automatic startup migration failed");

        assert!(wrapped.is::<MigrationHistoryIntegrityError>());
        assert_eq!(
            wrapped
                .downcast_ref::<MigrationHistoryIntegrityError>()
                .expect("typed source must remain in the error chain")
                .kind(),
            expected_kind
        );
    }
}

#[tokio::test]
async fn core_checksum_drift_blocks_status_and_compatibility_writes() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();

    sqlx::query("UPDATE _ferrum_migrations SET checksum = ? WHERE version = 1")
        .bind("stored-core-checksum")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE proxy_route_locks")
        .execute(&pool)
        .await
        .unwrap();

    let before = sqlx::query(
        "SELECT name, applied_at, checksum, execution_time_ms FROM _ferrum_migrations WHERE version = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let before = (
        before.try_get::<String, _>("name").unwrap(),
        before.try_get::<String, _>("applied_at").unwrap(),
        before.try_get::<String, _>("checksum").unwrap(),
        before.try_get::<i32, _>("execution_time_ms").unwrap(),
    );

    let status_error = runner
        .status()
        .await
        .expect_err("status must return a blocking error on core drift");
    assert!(status_error.is::<MigrationHistoryIntegrityError>());

    let apply_error = runner
        .run_pending()
        .await
        .expect_err("automatic core migration must fail on drift");
    let integrity_error = apply_error
        .downcast_ref::<MigrationHistoryIntegrityError>()
        .expect("error must retain structured integrity metadata");
    assert_eq!(integrity_error.backend, "sqlite");
    assert_eq!(integrity_error.namespace, MigrationHistoryNamespace::Core);
    match &integrity_error.reason {
        MigrationHistoryIntegrityReason::ChecksumMismatch {
            version,
            stored_checksum,
            expected_checksum,
        } => {
            assert_eq!(*version, 1);
            assert_eq!(stored_checksum, "stored-core-checksum");
            assert!(expected_checksum.starts_with("sha256:"));
        }
        other => panic!("unexpected integrity reason: {other:?}"),
    }
    assert!(!apply_error.to_string().contains("CREATE TABLE"));
    assert!(
        !table_exists(&pool, "proxy_route_locks").await,
        "V001 compatibility work must not run after integrity refusal"
    );

    let after = sqlx::query(
        "SELECT name, applied_at, checksum, execution_time_ms FROM _ferrum_migrations WHERE version = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let after = (
        after.try_get::<String, _>("name").unwrap(),
        after.try_get::<String, _>("applied_at").unwrap(),
        after.try_get::<String, _>("checksum").unwrap(),
        after.try_get::<i32, _>("execution_time_ms").unwrap(),
    );
    assert_eq!(after, before, "integrity refusal must not rewrite history");
}

#[tokio::test]
async fn unknown_applied_core_version_blocks_compatibility_schema_and_history_writes() {
    let pool = test_pool().await;
    sqlx::query(
        "CREATE TABLE _ferrum_migrations (\
         version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL, \
         checksum TEXT NOT NULL, execution_time_ms INTEGER NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO _ferrum_migrations \
         (version, name, applied_at, checksum, execution_time_ms) \
         VALUES (99, 'unknown', '2026-01-01T00:00:00Z', 'unknown-core-checksum', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());

    let status_error = runner
        .status()
        .await
        .expect_err("core status must reject an unknown applied version");
    assert_eq!(
        status_error
            .downcast_ref::<MigrationHistoryIntegrityError>()
            .expect("status refusal must remain typed")
            .kind(),
        MigrationHistoryIntegrityKind::UnknownAppliedVersion
    );

    let apply_error = runner
        .run_pending()
        .await
        .expect_err("core migration must reject an unknown applied version");
    assert!(apply_error.is::<MigrationHistoryIntegrityError>());
    assert!(
        !table_exists(&pool, "proxy_route_locks").await,
        "V001 compatibility work must not run after integrity refusal"
    );
    assert!(
        !table_exists(&pool, "proxies").await,
        "V001 schema work must remain pending"
    );
    let row = sqlx::query("SELECT version, checksum FROM _ferrum_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.try_get::<i32, _>("version").unwrap(), 99);
    assert_eq!(
        row.try_get::<String, _>("checksum").unwrap(),
        "unknown-core-checksum"
    );
}

#[tokio::test]
async fn core_checksum_drift_blocks_later_plugin_migration() {
    let pool = test_pool().await;
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();
    sqlx::query("UPDATE _ferrum_migrations SET checksum = ? WHERE version = 1")
        .bind("drift-before-plugin")
        .execute(&pool)
        .await
        .unwrap();
    let pending_plugin = vec![(
        "pending_after_core",
        vec![CustomPluginMigration {
            version: 1,
            name: "create_pending_after_core",
            checksum: "pending-v1",
            sql: "CREATE TABLE pending_after_core_data (id TEXT PRIMARY KEY)",
            sql_postgres: None,
            sql_mysql: None,
        }],
    )];

    runner
        .run_all_pending(&pending_plugin)
        .await
        .expect_err("core drift must block all later plugin work");

    assert!(
        !table_exists(&pool, "pending_after_core_data").await,
        "later plugin schema must remain pending"
    );
    assert!(
        !table_exists(&pool, "_ferrum_plugin_migrations").await,
        "preflight refusal must happen before creating plugin history"
    );
    let row = sqlx::query("SELECT checksum FROM _ferrum_migrations WHERE version = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        row.try_get::<String, _>("checksum").unwrap(),
        "drift-before-plugin"
    );
}

#[tokio::test]
async fn database_store_startup_surfaces_core_checksum_drift() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("startup_checksum_drift.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .unwrap();
    let runner = MigrationRunner::new(pool.clone(), "sqlite".to_string());
    runner.run_pending().await.unwrap();
    sqlx::query("UPDATE _ferrum_migrations SET checksum = ? WHERE version = 1")
        .bind("startup-stored-checksum")
        .execute(&pool)
        .await
        .unwrap();

    let error =
        match DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
            .await
        {
            Ok(_) => panic!("automatic database startup must refuse checksum drift"),
            Err(error) => error,
        };
    assert!(error.is::<MigrationHistoryIntegrityError>());

    let row = sqlx::query("SELECT checksum FROM _ferrum_migrations WHERE version = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        row.try_get::<String, _>("checksum").unwrap(),
        "startup-stored-checksum"
    );
}

#[tokio::test]
async fn concurrent_sqlite_runners_serialize_and_loser_skips_tracking_insert() {
    sqlx::any::install_default_drivers();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent_migrations.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let pool_one = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .unwrap();
    let pool_two = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .unwrap();
    let runner_one = MigrationRunner::new(pool_one.clone(), "sqlite".to_string());
    let runner_two = MigrationRunner::new(pool_two.clone(), "sqlite".to_string());

    let (first, second) = tokio::join!(runner_one.run_pending(), runner_two.run_pending());
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(
        first.len() + second.len(),
        1,
        "exactly one process-equivalent runner should apply V001"
    );

    let row = sqlx::query("SELECT COUNT(*) AS count FROM _ferrum_migrations")
        .fetch_one(&pool_one)
        .await
        .unwrap();
    let count: i64 = row.try_get("count").unwrap();
    assert_eq!(count, 1, "the tracking insert must not race or duplicate");
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
