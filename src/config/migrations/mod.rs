pub mod v001_initial_schema;

use chrono::Utc;
use sqlx::any::AnyRow;
use sqlx::{AnyPool, Row};
use std::time::Instant;
use tracing::{info, warn};

/// Trait that all database migrations implement.
///
/// Because async trait methods with `&self` are not yet object-safe in stable Rust,
/// we use a concrete dispatch approach: each migration struct implements `up()` directly,
/// and the runner calls it via the `run_migration_up` helper.
pub trait Migration: Send + Sync {
    fn version(&self) -> i64;
    fn name(&self) -> &str;
    fn checksum(&self) -> &str;
}

/// Record of a migration that was applied.
#[derive(Debug, Clone)]
pub struct MigrationRecord {
    pub version: i64,
    pub name: String,
    pub applied_at: String,
    pub checksum: String,
    pub execution_time_ms: i64,
}

/// Summary of migration status.
#[derive(Debug)]
pub struct MigrationStatus {
    pub applied: Vec<MigrationRecord>,
    pub pending: Vec<PendingMigration>,
}

/// A migration that has not yet been applied.
#[derive(Debug)]
pub struct PendingMigration {
    pub version: i64,
    pub name: String,
}

/// Runs versioned database migrations with tracking.
pub struct MigrationRunner {
    pool: AnyPool,
    db_type: String,
}

impl MigrationRunner {
    pub fn new(pool: AnyPool, db_type: String) -> Self {
        Self { pool, db_type }
    }

    /// Build the ordered list of all known migrations.
    fn all_migrations(&self) -> Vec<Box<dyn MigrationEntry>> {
        vec![Box::new(MigrationEntryV001(
            v001_initial_schema::V001InitialSchema,
        ))]
    }

    /// Ensure the `_ferrum_migrations` tracking table exists.
    ///
    /// MySQL's `TEXT` type is reported as `BLOB` by the `Any` driver, which
    /// prevents `try_get::<String>()`. Use `VARCHAR` for MySQL compatibility.
    async fn ensure_tracking_table(&self) -> Result<(), anyhow::Error> {
        let sql = if self.db_type == "mysql" {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at VARCHAR(50) NOT NULL,
                checksum VARCHAR(255) NOT NULL,
                execution_time_ms INTEGER NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL,
                execution_time_ms INTEGER NOT NULL
            )
            "#
        };
        sqlx::query(sql).execute(&self.pool).await?;
        Ok(())
    }

    /// Detect pre-migration databases and bootstrap the tracking table.
    ///
    /// If the `proxies` table exists but `_ferrum_migrations` is empty,
    /// this is a database created before the migration system was added.
    /// Mark V1 (initial_schema) as already applied.
    async fn bootstrap_if_needed(&self) -> Result<(), anyhow::Error> {
        // Check if any migrations are already recorded
        let rows: Vec<AnyRow> = sqlx::query("SELECT version FROM _ferrum_migrations")
            .fetch_all(&self.pool)
            .await?;
        if !rows.is_empty() {
            return Ok(());
        }

        // Check if the proxies table exists (pre-migration database)
        let table_exists = self.table_exists("proxies").await?;
        if !table_exists {
            // Fresh database — let normal migration flow handle everything
            return Ok(());
        }

        // Pre-migration database detected — mark V1 as applied
        info!("Detected pre-migration database. Bootstrapping migration tracking for V1.");
        let now = Utc::now().to_rfc3339();
        let v1 = v001_initial_schema::V001InitialSchema;
        let insert_sql = Self::migration_insert_sql(&self.db_type);
        sqlx::query(&insert_sql)
            .bind(v1.version())
            .bind(v1.name())
            .bind(&now)
            .bind(v1.checksum())
            .bind(0i64)
            .execute(&self.pool)
            .await?;

        info!("Bootstrapped: V1 ({}) marked as applied", v1.name());
        Ok(())
    }

    /// Check if a table exists in the database, dispatching per db_type.
    ///
    /// PostgreSQL uses `$1` for bind parameters (the `?` placeholder is
    /// ambiguous because PostgreSQL reserves `?` as a JSON operator).
    async fn table_exists(&self, table_name: &str) -> Result<bool, anyhow::Error> {
        let sql = match self.db_type.as_str() {
            "postgres" => {
                "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename = $1"
            }
            "mysql" => {
                "SELECT table_name FROM information_schema.tables WHERE table_name = ? AND table_schema = DATABASE()"
            }
            _ => {
                // SQLite
                "SELECT name FROM sqlite_master WHERE type='table' AND name = ?"
            }
        };

        let rows: Vec<AnyRow> = sqlx::query(sql)
            .bind(table_name)
            .fetch_all(&self.pool)
            .await?;

        Ok(!rows.is_empty())
    }

    /// Return the migration INSERT statement with the correct bind parameter
    /// syntax for the target database. PostgreSQL uses `$N`, MySQL/SQLite use `?`.
    fn migration_insert_sql(db_type: &str) -> String {
        if db_type == "postgres" {
            "INSERT INTO _ferrum_migrations (version, name, applied_at, checksum, execution_time_ms) VALUES ($1, $2, $3, $4, $5)".to_string()
        } else {
            "INSERT INTO _ferrum_migrations (version, name, applied_at, checksum, execution_time_ms) VALUES (?, ?, ?, ?, ?)".to_string()
        }
    }

    /// Get all applied migration versions from the tracking table.
    async fn applied_versions(&self) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        let rows: Vec<AnyRow> =
            sqlx::query("SELECT version, name, applied_at, checksum, execution_time_ms FROM _ferrum_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await?;

        let mut records = Vec::new();
        for row in rows {
            records.push(MigrationRecord {
                version: row.try_get::<i32, _>("version")? as i64,
                name: row.try_get("name")?,
                applied_at: row.try_get("applied_at")?,
                checksum: row.try_get("checksum")?,
                execution_time_ms: row.try_get::<i32, _>("execution_time_ms")? as i64,
            });
        }
        Ok(records)
    }

    /// Run all pending migrations in order. Returns the list of newly applied migrations.
    pub async fn run_pending(&self) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        self.ensure_tracking_table().await?;
        self.bootstrap_if_needed().await?;

        let applied = self.applied_versions().await?;
        let applied_versions: Vec<i64> = applied.iter().map(|r| r.version).collect();

        // Validate checksums of applied migrations
        let all_migrations = self.all_migrations();
        for record in &applied {
            if let Some(migration) = all_migrations
                .iter()
                .find(|m| m.version() == record.version)
                && migration.checksum() != record.checksum
            {
                warn!(
                    "Migration V{} ({}) checksum mismatch: expected '{}', found '{}' in database. \
                     This may indicate the migration source was modified after being applied.",
                    record.version,
                    record.name,
                    migration.checksum(),
                    record.checksum
                );
            }
        }

        let mut newly_applied = Vec::new();

        for migration in &all_migrations {
            if applied_versions.contains(&migration.version()) {
                continue;
            }

            info!(
                "Applying migration V{}: {}",
                migration.version(),
                migration.name()
            );

            let start = Instant::now();
            migration.run_up(&self.pool, &self.db_type).await?;
            let elapsed_ms = start.elapsed().as_millis() as i64;

            let now = Utc::now().to_rfc3339();
            let insert_sql = Self::migration_insert_sql(&self.db_type);
            sqlx::query(&insert_sql)
                .bind(migration.version() as i32)
                .bind(migration.name())
                .bind(&now)
                .bind(migration.checksum())
                .bind(elapsed_ms as i32)
                .execute(&self.pool)
                .await?;

            let record = MigrationRecord {
                version: migration.version(),
                name: migration.name().to_string(),
                applied_at: now,
                checksum: migration.checksum().to_string(),
                execution_time_ms: elapsed_ms,
            };

            info!(
                "Applied migration V{}: {} ({}ms)",
                record.version, record.name, record.execution_time_ms
            );

            newly_applied.push(record);
        }

        Ok(newly_applied)
    }

    /// Get current migration status (applied and pending).
    pub async fn status(&self) -> Result<MigrationStatus, anyhow::Error> {
        self.ensure_tracking_table().await?;

        let applied = self.applied_versions().await?;
        let applied_versions: Vec<i64> = applied.iter().map(|r| r.version).collect();

        let all_migrations = self.all_migrations();
        let pending: Vec<PendingMigration> = all_migrations
            .iter()
            .filter(|m| !applied_versions.contains(&m.version()))
            .map(|m| PendingMigration {
                version: m.version(),
                name: m.name().to_string(),
            })
            .collect();

        Ok(MigrationStatus { applied, pending })
    }
}

// --------------------------------------------------------------------------
// MigrationEntry wrapper — bridges the Migration trait with async up() calls
// --------------------------------------------------------------------------

/// Internal trait that combines Migration metadata with the ability to run the migration.
/// This avoids the need for async methods in the Migration trait (which aren't object-safe).
trait MigrationEntry: Send + Sync {
    fn version(&self) -> i64;
    fn name(&self) -> &str;
    fn checksum(&self) -> &str;
    fn run_up<'a>(
        &'a self,
        pool: &'a AnyPool,
        db_type: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;
}

/// Wrapper for V001InitialSchema.
struct MigrationEntryV001(v001_initial_schema::V001InitialSchema);

impl MigrationEntry for MigrationEntryV001 {
    fn version(&self) -> i64 {
        self.0.version()
    }
    fn name(&self) -> &str {
        self.0.name()
    }
    fn checksum(&self) -> &str {
        self.0.checksum()
    }
    fn run_up<'a>(
        &'a self,
        pool: &'a AnyPool,
        db_type: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>
    {
        Box::pin(self.0.up(pool, db_type))
    }
}
