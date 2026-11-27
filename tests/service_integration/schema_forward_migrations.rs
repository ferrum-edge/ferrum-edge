//! Forward-only core schema migrations on every supported SQL backend.
//!
//! From 1.0.0 onward the `V001` baseline is frozen and schema changes ship as
//! `V002`+ forward migrations. Ferrum ships no `V002` yet, so these tests
//! register a test-only `V002` through the `test-support` seam and drive it
//! through the production `MigrationRunner` and the exact `migrate status` /
//! `migrate up` report code, against SQLite (in memory), PostgreSQL 17, and
//! MySQL 8.4 containers:
//!
//! - a database at `V001` records the committed golden `V001` identity;
//! - `status` reports `V002` pending, `up` applies it, `status` then reports it
//!   applied, and a second `up` is a no-op;
//! - a `V002` whose tracking row is lost re-runs idempotently (MySQL tolerates
//!   only the structured duplicate-index error);
//! - an edited `V002` (checksum drift on an applied migration) is fatal;
//! - a binary that does not know `V002` (a downgrade) refuses the database;
//! - drift on the frozen `V001` row remains fatal.

use std::time::Duration;

use ferrum_edge::_test_support::{
    migration_runner_with_test_migrations_for_test, sql_migrate_status_report_for_test,
    sql_migrate_up_report_for_test,
};
use ferrum_edge::config::migrations::v001_initial_schema::V001_BASELINE_CHECKSUM;
use ferrum_edge::config::migrations::{
    MigrationHistoryIntegrityError, MigrationHistoryIntegrityReason, MigrationRunner, SqlMigration,
};
use sqlx::Row;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::containers::{BoxError, fail_in_ci_else_skip, start_within_deadline};
use super::common::host_ports::{allocate_host_port, retry_on_host_port_collision};

/// The test-only forward migration. Re-runnable on every dialect.
const TEST_V002: SqlMigration = SqlMigration {
    version: 2,
    name: "test_forward_v002",
    postgres: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id TEXT PRIMARY KEY, note TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_ferrum_test_forward_v002_note ON ferrum_test_forward_v002 (note)",
    ],
    mysql: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id VARCHAR(64) NOT NULL PRIMARY KEY, note VARCHAR(255) NOT NULL)",
        "CREATE INDEX idx_ferrum_test_forward_v002_note ON ferrum_test_forward_v002 (note)",
    ],
    sqlite: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id TEXT PRIMARY KEY, note TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_ferrum_test_forward_v002_note ON ferrum_test_forward_v002 (note)",
    ],
};

/// The same version with edited SQL: what an in-place edit of a shipped
/// migration looks like to a database that already applied the original.
const TEST_V002_EDITED: SqlMigration = SqlMigration {
    postgres: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id TEXT PRIMARY KEY, note TEXT)",
    ],
    mysql: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id VARCHAR(64) NOT NULL PRIMARY KEY, note VARCHAR(255))",
    ],
    sqlite: &[
        "CREATE TABLE IF NOT EXISTS ferrum_test_forward_v002 (id TEXT PRIMARY KEY, note TEXT)",
    ],
    ..TEST_V002
};

fn integrity_reason(error: &anyhow::Error) -> MigrationHistoryIntegrityReason {
    error
        .downcast_ref::<MigrationHistoryIntegrityError>()
        .unwrap_or_else(|| panic!("expected a migration-history integrity error, got: {error:#}"))
        .reason
        .clone()
}

async fn tracked_checksum(pool: &sqlx::AnyPool, version: i32) -> Option<String> {
    let sql = if version == 1 {
        "SELECT checksum FROM _ferrum_migrations WHERE version = 1"
    } else {
        "SELECT checksum FROM _ferrum_migrations WHERE version = 2"
    };
    sqlx::query(sql)
        .fetch_optional(pool)
        .await
        .expect("read tracking row")
        .map(|row| row.try_get::<String, _>("checksum").expect("checksum text"))
}

async fn forward_table_ids(pool: &sqlx::AnyPool) -> Vec<String> {
    sqlx::query("SELECT id FROM ferrum_test_forward_v002 ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("V002 table must exist")
        .iter()
        .map(|row| row.try_get::<String, _>("id").expect("id text"))
        .collect()
}

/// The complete forward-path contract for one backend. `pool` must point at an
/// empty database.
async fn exercise_forward_path(pool: &sqlx::AnyPool, db_type: &str) {
    // A release at V001: only the shipped declarations.
    let shipped = MigrationRunner::new(pool.clone(), db_type.to_string());
    let applied = shipped.run_pending().await.expect("V001 applies");
    assert_eq!(applied.len(), 1, "{db_type}: a fresh database applies V001");
    assert_eq!(
        tracked_checksum(pool, 1).await.as_deref(),
        Some(V001_BASELINE_CHECKSUM),
        "{db_type}: V001 must record the committed golden identity"
    );

    // A later binary that adds V002.
    let forward =
        migration_runner_with_test_migrations_for_test(pool.clone(), db_type, vec![TEST_V002]);
    let status = sql_migrate_status_report_for_test(&forward, &[])
        .await
        .expect("status before V002");
    assert!(
        status.contains("  V1: initial_schema (applied: ")
            && status.contains(&format!("checksum: {V001_BASELINE_CHECKSUM})")),
        "{db_type}: status must list V001 as applied:\n{status}"
    );
    assert!(
        status.contains("Pending migrations:\n  V2: test_forward_v002"),
        "{db_type}: status must report V002 pending:\n{status}"
    );

    let up = sql_migrate_up_report_for_test(&forward, &[])
        .await
        .expect("up applies V002");
    assert!(
        up.starts_with("Applied 1 migration(s):\n  V2: test_forward_v002 ("),
        "{db_type}: up must apply exactly V002:\n{up}"
    );
    assert_eq!(
        tracked_checksum(pool, 2).await,
        Some(TEST_V002.checksum()),
        "{db_type}: V002 records its canonical checksum"
    );
    sqlx::query("INSERT INTO ferrum_test_forward_v002 (id, note) VALUES ('row-1', 'forward')")
        .execute(pool)
        .await
        .expect("V002 schema is usable");

    let status = sql_migrate_status_report_for_test(&forward, &[])
        .await
        .expect("status after V002");
    assert!(
        status.contains("  V2: test_forward_v002 (applied: ")
            && status.contains("Pending migrations: (none — schema is up to date)"),
        "{db_type}: status must report V002 applied and nothing pending:\n{status}"
    );
    let up_again = sql_migrate_up_report_for_test(&forward, &[])
        .await
        .expect("second up");
    assert_eq!(
        up_again, "Database schema is up to date. No migrations applied.",
        "{db_type}: a second up is a no-op"
    );

    // A lost tracking row (crash between DDL and the insert) re-runs V002.
    sqlx::query("DELETE FROM _ferrum_migrations WHERE version = 2")
        .execute(pool)
        .await
        .expect("drop V002 tracking row");
    let rerun = forward
        .run_pending()
        .await
        .expect("V002 re-runs idempotently");
    assert_eq!(rerun.len(), 1, "{db_type}: V002 re-applied once");
    assert_eq!(
        forward_table_ids(pool).await,
        vec!["row-1".to_string()],
        "{db_type}: the re-run must not touch existing data"
    );

    // Editing an applied migration is checksum drift: fatal for status and up.
    let edited = migration_runner_with_test_migrations_for_test(
        pool.clone(),
        db_type,
        vec![TEST_V002_EDITED],
    );
    for error in [
        sql_migrate_status_report_for_test(&edited, &[])
            .await
            .expect_err("edited V002 must fail status"),
        sql_migrate_up_report_for_test(&edited, &[])
            .await
            .expect_err("edited V002 must fail up"),
    ] {
        match integrity_reason(&error) {
            MigrationHistoryIntegrityReason::ChecksumMismatch {
                version,
                stored_checksum,
                expected_checksum,
            } => {
                assert_eq!(version, 2);
                assert_eq!(stored_checksum, TEST_V002.checksum());
                assert_eq!(expected_checksum, TEST_V002_EDITED.checksum());
            }
            other => panic!("{db_type}: expected V002 checksum drift, got {other:?}"),
        }
    }

    // An older binary that does not know V002 (binary downgrade) is refused by
    // status, explicit up, and the startup path, with a clear diagnostic.
    for error in [
        shipped.status().await.expect_err("downgrade status"),
        shipped.run_pending().await.expect_err("downgrade up"),
        shipped
            .run_pending_with_plugin_history(&[])
            .await
            .expect_err("downgrade startup"),
    ] {
        assert_eq!(
            integrity_reason(&error),
            MigrationHistoryIntegrityReason::UnknownAppliedVersion { version: 2 },
            "{db_type}: an unknown future migration must be refused"
        );
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("kind=unknown_applied_version")
                && rendered.contains("namespace=core")
                && rendered.contains("version=2"),
            "{db_type}: downgrade refusal must name the unknown version: {rendered}"
        );
    }
    assert_eq!(
        tracked_checksum(pool, 2).await,
        Some(TEST_V002.checksum()),
        "{db_type}: refusals never rewrite history"
    );

    // Drift on the frozen baseline row stays fatal for the forward binary too.
    sqlx::query("UPDATE _ferrum_migrations SET checksum = 'sha256:tampered' WHERE version = 1")
        .execute(pool)
        .await
        .expect("tamper V001 row");
    let error = sql_migrate_status_report_for_test(&forward, &[])
        .await
        .expect_err("V001 drift must fail");
    match integrity_reason(&error) {
        MigrationHistoryIntegrityReason::ChecksumMismatch {
            version,
            expected_checksum,
            ..
        } => {
            assert_eq!(version, 1);
            assert_eq!(expected_checksum, V001_BASELINE_CHECKSUM);
        }
        other => panic!("{db_type}: expected V001 checksum drift, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_schema_forward_migration_contract() {
    sqlx::any::install_default_drivers();
    // One connection: every in-memory SQLite connection is its own database.
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("sqlite pool");
    exercise_forward_path(&pool, "sqlite").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_schema_forward_migration_contract() {
    let fixture = match super::mysql::start_mysql().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "mysql_schema_forward_migration_contract",
                "MySQL 8.4",
                &error,
            );
            return;
        }
    };
    exercise_forward_path(&fixture.pool, "mysql").await;
}

struct PostgresFixture {
    _container: ContainerAsync<GenericImage>,
    pool: sqlx::AnyPool,
}

async fn start_postgres() -> Result<PostgresFixture, BoxError> {
    const PASSWORD: &str = "ferrum-postgres-test-password";
    let (container, port) = retry_on_host_port_collision(|| async {
        let host_port = allocate_host_port()?;
        let container = start_within_deadline("PostgreSQL", || {
            GenericImage::new("postgres", "17")
                .with_exposed_port(5432.tcp())
                .with_mapped_port(host_port, 5432.tcp())
                .with_env_var("POSTGRES_USER", "ferrum")
                .with_env_var("POSTGRES_PASSWORD", PASSWORD)
                .with_env_var("POSTGRES_DB", "ferrum")
                .start()
        })
        .await?;
        Ok((container, host_port))
    })
    .await?;
    let url = format!("postgres://ferrum:{PASSWORD}@127.0.0.1:{port}/ferrum");

    sqlx::any::install_default_drivers();
    // Prove the published mapping from the host before any assertion. The
    // image's init server restarts once, so require a working query.
    let started = tokio::time::Instant::now();
    let mut last_error = String::new();
    for _ in 0..120 {
        match sqlx::any::AnyPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url)
            .await
        {
            Ok(pool) => match sqlx::query("SELECT 1").fetch_one(&pool).await {
                Ok(_) => {
                    return Ok(PostgresFixture {
                        _container: container,
                        pool,
                    });
                }
                Err(error) => last_error = error.to_string(),
            },
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "PostgreSQL connect readiness not reached (elapsed {:.1}s): {last_error}",
        started.elapsed().as_secs_f64()
    )
    .into())
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_schema_forward_migration_contract() {
    let fixture = match start_postgres().await {
        Ok(fixture) => fixture,
        Err(error) => {
            fail_in_ci_else_skip(
                "postgres_schema_forward_migration_contract",
                "PostgreSQL 17",
                &error,
            );
            return;
        }
    };
    exercise_forward_path(&fixture.pool, "postgres").await;
}
