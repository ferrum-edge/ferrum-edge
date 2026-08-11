pub(crate) mod mysql_collation_probe;
pub(crate) mod sql_dialect;
pub(crate) mod sql_statements;
pub mod v001_initial_schema;

#[allow(unused_imports)] // Re-exported for external unit tests / public API consumers.
pub use mysql_collation_probe::{
    IdentityBearingColumn, LiveColumnCollation, LiveTableCollation,
    REQUIRED_MYSQL_IDENTITY_COLLATION, StaleCollationFinding, find_stale_column_collations,
    find_stale_table_collations, format_affected_columns_summary, identity_bearing_columns,
    inspect_mysql_identity_collations, merge_stale_collation_findings,
    remediation_alter_statements, warn_stale_mysql_identity_collations,
};
pub use sql_statements::split_plugin_migration_statements;

use chrono::Utc;
use sqlx::any::AnyRow;
use sqlx::pool::PoolConnection;
use sqlx::{Any, AnyConnection, AnyPool, Connection, Row};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const POSTGRES_MIGRATION_LOCK_ID: i64 = 0x4645_5252_554D_4D47;
const MYSQL_MIGRATION_LOCK_NAME: &str = "ferrum-edge:migrations";
const MIGRATION_LOCK_WAIT_WARNING_INTERVAL: Duration = Duration::from_secs(30);
const POSTGRES_MIGRATION_LOCK_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const SQLITE_MIGRATION_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// One cross-process migration lock held on a dedicated database connection.
///
/// PostgreSQL advisory locks and MySQL named locks are session-scoped. SQLite
/// has no advisory-lock primitive, so `BEGIN IMMEDIATE` holds the file's write
/// reservation for the entire migration and tracking-row update. Keeping all
/// migration work on this same connection is required for the SQLite lock to
/// serialize competing processes rather than deadlock against our own pool.
struct MigrationConnectionLock {
    connection: PoolConnection<Any>,
    db_type: String,
    active: bool,
}

impl MigrationConnectionLock {
    async fn acquire(pool: &AnyPool, db_type: &str) -> Result<Self, anyhow::Error> {
        let connection = pool.acquire().await?;
        // Install the close-on-drop guard before the first lock statement is
        // awaited. If this future is cancelled after the server grants a
        // session lock (or starts the SQLite transaction), the connection is
        // closed instead of returning to the pool while still holding it.
        let mut migration_lock = Self {
            connection,
            db_type: db_type.to_string(),
            active: true,
        };
        migration_lock.acquire_on_connection().await?;
        Ok(migration_lock)
    }

    async fn acquire_on_connection(&mut self) -> Result<(), anyhow::Error> {
        let wait_started = Instant::now();
        let mut last_wait_warning = Instant::now();

        match self.db_type.as_str() {
            "postgres" => loop {
                let row = sqlx::query("SELECT pg_try_advisory_lock($1) AS migration_lock_acquired")
                    .bind(POSTGRES_MIGRATION_LOCK_ID)
                    .fetch_one(&mut *self.connection)
                    .await?;
                if row.try_get::<bool, _>("migration_lock_acquired")? {
                    break;
                }
                warn_if_migration_lock_waiting("postgres", wait_started, &mut last_wait_warning);
                tokio::time::sleep(POSTGRES_MIGRATION_LOCK_RETRY_INTERVAL).await;
            },
            "mysql" => loop {
                let row = sqlx::query(
                    "SELECT CAST(GET_LOCK(?, 30) AS SIGNED) AS migration_lock_acquired",
                )
                .bind(MYSQL_MIGRATION_LOCK_NAME)
                .fetch_one(&mut *self.connection)
                .await?;
                match row.try_get::<Option<i64>, _>("migration_lock_acquired")? {
                    Some(1) => break,
                    Some(0) => warn_if_migration_lock_waiting(
                        "mysql",
                        wait_started,
                        &mut last_wait_warning,
                    ),
                    _ => {
                        anyhow::bail!("MySQL GET_LOCK returned NULL for the Ferrum migration lock")
                    }
                }
            },
            "sqlite" => {
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(&mut *self.connection)
                    .await?;
                sqlx::query("PRAGMA busy_timeout = 5000")
                    .execute(&mut *self.connection)
                    .await?;
                loop {
                    match sqlx::query("BEGIN IMMEDIATE")
                        .execute(&mut *self.connection)
                        .await
                    {
                        Ok(_) => break,
                        Err(error) if is_sqlite_lock_contention(&error) => {
                            warn_if_migration_lock_waiting(
                                "sqlite",
                                wait_started,
                                &mut last_wait_warning,
                            );
                            tokio::time::sleep(SQLITE_MIGRATION_LOCK_RETRY_INTERVAL).await;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            other => anyhow::bail!("Unsupported database type for migrations: {other}"),
        }
        Ok(())
    }

    fn connection(&mut self) -> &mut AnyConnection {
        &mut self.connection
    }

    async fn finish(mut self, commit: bool) -> Result<(), anyhow::Error> {
        match self.db_type.as_str() {
            "postgres" => {
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(POSTGRES_MIGRATION_LOCK_ID)
                    .execute(&mut *self.connection)
                    .await?;
            }
            "mysql" => {
                let row = sqlx::query(
                    "SELECT CAST(RELEASE_LOCK(?) AS SIGNED) AS migration_lock_released",
                )
                .bind(MYSQL_MIGRATION_LOCK_NAME)
                .fetch_one(&mut *self.connection)
                .await?;
                if row.try_get::<Option<i64>, _>("migration_lock_released")? != Some(1) {
                    anyhow::bail!("MySQL RELEASE_LOCK did not release the Ferrum migration lock");
                }
            }
            "sqlite" => {
                let statement = if commit { "COMMIT" } else { "ROLLBACK" };
                sqlx::query(statement)
                    .execute(&mut *self.connection)
                    .await?;
            }
            _ => {}
        }
        self.active = false;
        Ok(())
    }
}

fn warn_if_migration_lock_waiting(
    db_type: &str,
    wait_started: Instant,
    last_warning: &mut Instant,
) {
    if last_warning.elapsed() >= MIGRATION_LOCK_WAIT_WARNING_INTERVAL {
        warn!(
            database_type = db_type,
            waited_seconds = wait_started.elapsed().as_secs(),
            "Still waiting for the cross-process migration lock"
        );
        *last_warning = Instant::now();
    }
}

impl Drop for MigrationConnectionLock {
    fn drop(&mut self) {
        if self.active {
            // Session-scoped locks must never leak back into the pool if the
            // migration future is cancelled, panics, or lock cleanup fails.
            // Closing releases PostgreSQL/MySQL locks and rolls back an
            // unfinished SQLite transaction at the server boundary.
            self.connection.close_on_drop();
        }
    }
}

fn is_sqlite_lock_contention(error: &sqlx::Error) -> bool {
    let Some(database_error) = error.as_database_error() else {
        return false;
    };
    database_error
        .code()
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| matches!(code & 0xff, 5 | 6))
        || database_error.message().contains("database is locked")
        || database_error.message().contains("database is busy")
}

fn finish_locked_operation<T>(
    operation: Result<T, anyhow::Error>,
    release: Result<(), anyhow::Error>,
) -> Result<T, anyhow::Error> {
    match (operation, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(release_error)) => Err(release_error),
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Err(operation_error), Err(release_error)) => Err(operation_error.context(format!(
            "migration lock cleanup also failed: {release_error}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Custom plugin migration support
// ---------------------------------------------------------------------------

/// A database migration declared by a custom plugin.
///
/// Custom plugins define migrations inline using this struct. Each migration
/// has a version number (scoped to the plugin), a name, a checksum for
/// tamper detection, and SQL statements for each supported database.
///
/// # Example
///
/// ```ignore
/// pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
///     vec![
///         CustomPluginMigration {
///             version: 1,
///             name: "create_audit_log",
///             checksum: "v1_create_audit_log_a1b2c3",
///             sql: "CREATE TABLE IF NOT EXISTS audit_log (
///                 id TEXT PRIMARY KEY,
///                 timestamp TEXT NOT NULL,
///                 action TEXT NOT NULL
///             )",
///             sql_postgres: None,
///             sql_mysql: None,
///         },
///     ]
/// }
/// ```
pub struct CustomPluginMigration {
    /// Migration version number, scoped per plugin. Must be positive and
    /// monotonically increasing within each plugin.
    pub version: i64,
    /// Human-readable migration name (e.g., "create_audit_log").
    pub name: &'static str,
    /// Unique checksum for tamper detection. Convention: `v{N}_{name}_{short_hash}`.
    pub checksum: &'static str,
    /// Default SQL used for all databases unless overridden by a db-specific field.
    /// Must be compatible with PostgreSQL, MySQL, and SQLite when no overrides are set.
    pub sql: &'static str,
    /// PostgreSQL-specific SQL override. When `Some`, used instead of `sql` for PostgreSQL.
    pub sql_postgres: Option<&'static str>,
    /// MySQL-specific SQL override. When `Some`, used instead of `sql` for MySQL.
    pub sql_mysql: Option<&'static str>,
}

/// Whether a MySQL statement failure is a benign missing-index error (1091).
///
/// MySQL implicitly commits around index DDL. A custom-plugin migration can
/// therefore pair `DROP INDEX` with `CREATE INDEX` to reconstruct an exact,
/// plugin-owned index definition on every retry. Only the structured server
/// code for a missing key is tolerated, and only on the drop half of that
/// pair; creation failures remain fatal rather than blessing an unknown index.
pub fn mysql_drop_index_missing_is_benign(statement: &str, error_number: Option<u16>) -> bool {
    let mut words = statement.split_whitespace();
    let is_drop_index = matches!(
        (words.next(), words.next()),
        (Some(drop), Some(index))
            if drop.eq_ignore_ascii_case("DROP") && index.eq_ignore_ascii_case("INDEX")
    );
    is_drop_index && error_number == Some(1091)
}

fn map_plugin_statement_result<T>(
    db_type: &str,
    statement: &str,
    result: Result<T, sqlx::Error>,
) -> Result<(), sqlx::Error> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let missing_index_is_benign = {
                let error_number = e
                    .as_database_error()
                    .and_then(|database_error| {
                        database_error.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                    })
                    .map(sqlx::mysql::MySqlDatabaseError::number);
                db_type == "mysql" && mysql_drop_index_missing_is_benign(statement, error_number)
            };
            if missing_index_is_benign {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

impl CustomPluginMigration {
    /// Returns the SQL appropriate for the given database type.
    pub fn sql_for_db(&self, db_type: &str) -> &str {
        match db_type {
            "postgres" => self.sql_postgres.unwrap_or(self.sql),
            "mysql" => self.sql_mysql.unwrap_or(self.sql),
            _ => self.sql,
        }
    }
}

/// Record of a custom plugin migration that was applied.
#[derive(Debug, Clone)]
pub struct PluginMigrationRecord {
    pub plugin_name: String,
    pub version: i64,
    pub name: String,
    pub applied_at: String,
    pub checksum: String,
    pub execution_time_ms: i64,
}

/// Summary of custom plugin migration status.
#[derive(Debug)]
pub struct PluginMigrationStatus {
    pub applied: Vec<PluginMigrationRecord>,
    pub pending: Vec<PendingPluginMigration>,
}

/// A custom plugin migration that has not yet been applied.
#[derive(Debug)]
pub struct PendingPluginMigration {
    pub plugin_name: String,
    pub version: i64,
    pub name: String,
}

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

/// The migration-history namespace whose integrity could not be established.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MigrationHistoryNamespace {
    Core,
    CustomPlugin(String),
}

/// Stable classification for migration-history integrity failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationHistoryIntegrityKind {
    DuplicateDeclaredNamespace,
    NonPositiveDeclaredVersion,
    DeclaredVersionOutOfRange,
    DuplicateDeclaredVersion,
    UnorderedDeclaredVersions,
    DuplicateAppliedNamespace,
    DuplicateAppliedVersion,
    UnknownAppliedNamespace,
    UnknownAppliedVersion,
    MissingAppliedVersion,
    ChecksumMismatch,
}

impl MigrationHistoryIntegrityKind {
    /// Stable fixed-cardinality label for metrics, audit records, and APIs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateDeclaredNamespace => "duplicate_declared_namespace",
            Self::NonPositiveDeclaredVersion => "non_positive_declared_version",
            Self::DeclaredVersionOutOfRange => "declared_version_out_of_range",
            Self::DuplicateDeclaredVersion => "duplicate_declared_version",
            Self::UnorderedDeclaredVersions => "unordered_declared_versions",
            Self::DuplicateAppliedNamespace => "duplicate_applied_namespace",
            Self::DuplicateAppliedVersion => "duplicate_applied_version",
            Self::UnknownAppliedNamespace => "unknown_applied_namespace",
            Self::UnknownAppliedVersion => "unknown_applied_version",
            Self::MissingAppliedVersion => "missing_applied_version",
            Self::ChecksumMismatch => "checksum_mismatch",
        }
    }
}

/// Structured reason and raw metadata for a migration-history integrity error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationHistoryIntegrityReason {
    DuplicateDeclaredNamespace,
    NonPositiveDeclaredVersion {
        version: i64,
    },
    DeclaredVersionOutOfRange {
        version: i64,
        max_supported_version: i64,
    },
    DuplicateDeclaredVersion {
        version: i64,
    },
    UnorderedDeclaredVersions {
        previous_version: i64,
        version: i64,
    },
    DuplicateAppliedNamespace,
    DuplicateAppliedVersion {
        version: i64,
    },
    UnknownAppliedNamespace,
    UnknownAppliedVersion {
        version: i64,
    },
    MissingAppliedVersion {
        expected_version: i64,
        observed_version: i64,
    },
    ChecksumMismatch {
        version: i64,
        stored_checksum: String,
        expected_checksum: String,
    },
}

impl MigrationHistoryIntegrityReason {
    pub fn kind(&self) -> MigrationHistoryIntegrityKind {
        match self {
            Self::DuplicateDeclaredNamespace => {
                MigrationHistoryIntegrityKind::DuplicateDeclaredNamespace
            }
            Self::NonPositiveDeclaredVersion { .. } => {
                MigrationHistoryIntegrityKind::NonPositiveDeclaredVersion
            }
            Self::DeclaredVersionOutOfRange { .. } => {
                MigrationHistoryIntegrityKind::DeclaredVersionOutOfRange
            }
            Self::DuplicateDeclaredVersion { .. } => {
                MigrationHistoryIntegrityKind::DuplicateDeclaredVersion
            }
            Self::UnorderedDeclaredVersions { .. } => {
                MigrationHistoryIntegrityKind::UnorderedDeclaredVersions
            }
            Self::DuplicateAppliedNamespace => {
                MigrationHistoryIntegrityKind::DuplicateAppliedNamespace
            }
            Self::DuplicateAppliedVersion { .. } => {
                MigrationHistoryIntegrityKind::DuplicateAppliedVersion
            }
            Self::UnknownAppliedNamespace => MigrationHistoryIntegrityKind::UnknownAppliedNamespace,
            Self::UnknownAppliedVersion { .. } => {
                MigrationHistoryIntegrityKind::UnknownAppliedVersion
            }
            Self::MissingAppliedVersion { .. } => {
                MigrationHistoryIntegrityKind::MissingAppliedVersion
            }
            Self::ChecksumMismatch { .. } => MigrationHistoryIntegrityKind::ChecksumMismatch,
        }
    }
}

/// A blocking failure to prove that applied migrations are an exact prefix of
/// the binary's unambiguous ordered declarations.
///
/// Raw values remain available in the structured fields for programmatic
/// handling. Human-facing formatting is deliberately limited to safe migration
/// metadata and never includes database URLs, SQL, or connection details.
#[derive(Debug)]
pub struct MigrationHistoryIntegrityError {
    pub backend: String,
    pub namespace: MigrationHistoryNamespace,
    pub reason: MigrationHistoryIntegrityReason,
}

impl MigrationHistoryIntegrityError {
    pub fn kind(&self) -> MigrationHistoryIntegrityKind {
        self.reason.kind()
    }
}

/// Each string field in an integrity diagnostic is rendered as at most 128
/// escaped characters plus a `...` truncation marker. This keeps diagnostics
/// single-line and bounded even when a tracking table contains hostile TEXT.
const INTEGRITY_DIAGNOSTIC_FIELD_MAX_ESCAPED_CHARS: usize = 128;

struct BoundedIntegrityDiagnosticField<'a>(&'a str);

/// Render hostile migration-ledger text as one bounded, escaped field.
pub(crate) fn bounded_migration_diagnostic_field(value: &str) -> impl fmt::Display + '_ {
    BoundedIntegrityDiagnosticField(value)
}

impl fmt::Display for BoundedIntegrityDiagnosticField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = 0;
        for character in self.0.chars() {
            let escaped = character.escape_default();
            let escaped_len = escaped.clone().count();
            if rendered + escaped_len > INTEGRITY_DIAGNOSTIC_FIELD_MAX_ESCAPED_CHARS {
                return f.write_str("...");
            }
            for escaped_character in escaped {
                f.write_char(escaped_character)?;
            }
            rendered += escaped_len;
        }
        Ok(())
    }
}

impl fmt::Display for MigrationHistoryIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "migration history integrity check failed: kind={} backend=\"{}\"",
            self.kind().as_str(),
            BoundedIntegrityDiagnosticField(&self.backend)
        )?;
        match &self.namespace {
            MigrationHistoryNamespace::Core => f.write_str(" namespace=core")?,
            MigrationHistoryNamespace::CustomPlugin(plugin_name) => write!(
                f,
                " namespace=custom-plugin plugin=\"{}\"",
                BoundedIntegrityDiagnosticField(plugin_name)
            )?,
        }
        match &self.reason {
            MigrationHistoryIntegrityReason::DuplicateDeclaredNamespace
            | MigrationHistoryIntegrityReason::DuplicateAppliedNamespace
            | MigrationHistoryIntegrityReason::UnknownAppliedNamespace => Ok(()),
            MigrationHistoryIntegrityReason::NonPositiveDeclaredVersion { version }
            | MigrationHistoryIntegrityReason::DuplicateDeclaredVersion { version }
            | MigrationHistoryIntegrityReason::DuplicateAppliedVersion { version }
            | MigrationHistoryIntegrityReason::UnknownAppliedVersion { version } => {
                write!(f, " version={version}")
            }
            MigrationHistoryIntegrityReason::DeclaredVersionOutOfRange {
                version,
                max_supported_version,
            } => write!(
                f,
                " version={version} max_supported_version={max_supported_version}"
            ),
            MigrationHistoryIntegrityReason::UnorderedDeclaredVersions {
                previous_version,
                version,
            } => write!(f, " previous_version={previous_version} version={version}"),
            MigrationHistoryIntegrityReason::MissingAppliedVersion {
                expected_version,
                observed_version,
            } => write!(
                f,
                " expected_version={expected_version} observed_version={observed_version}"
            ),
            MigrationHistoryIntegrityReason::ChecksumMismatch {
                version,
                stored_checksum,
                expected_checksum,
            } => write!(
                f,
                " version={version} stored_checksum=\"{}\" expected_checksum=\"{}\"",
                BoundedIntegrityDiagnosticField(stored_checksum),
                BoundedIntegrityDiagnosticField(expected_checksum)
            ),
        }
    }
}

impl std::error::Error for MigrationHistoryIntegrityError {}

/// One migration expected by the current binary.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredMigrationHistoryEntry {
    pub version: i64,
    pub checksum: String,
}

/// The ordered migration declarations for one core or plugin namespace.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredMigrationHistory {
    pub namespace: MigrationHistoryNamespace,
    pub migrations: Vec<DeclaredMigrationHistoryEntry>,
}

/// One database tracking row used by the shared history validator.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigrationHistoryEntry {
    pub version: i64,
    pub checksum: String,
}

/// The ordered applied rows for one core or plugin namespace.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigrationHistory {
    pub namespace: MigrationHistoryNamespace,
    pub migrations: Vec<AppliedMigrationHistoryEntry>,
}

fn integrity_error(
    backend: &str,
    namespace: &MigrationHistoryNamespace,
    reason: MigrationHistoryIntegrityReason,
) -> MigrationHistoryIntegrityError {
    MigrationHistoryIntegrityError {
        backend: backend.to_string(),
        namespace: namespace.clone(),
        reason,
    }
}

/// Validate declaration integrity and prove that every applied namespace is an
/// exact checksum-matching prefix of the current binary's ordered sequence.
///
/// This public seam lets external adapter tests exercise the same model used by
/// the core and custom-plugin runners without executing migration SQL.
#[doc(hidden)]
pub fn validate_migration_history_integrity(
    backend: &str,
    declarations: &[DeclaredMigrationHistory],
    applied_histories: &[AppliedMigrationHistory],
) -> Result<(), MigrationHistoryIntegrityError> {
    let mut declared_namespaces = HashSet::new();
    for declaration in declarations {
        if !declared_namespaces.insert(&declaration.namespace) {
            return Err(integrity_error(
                backend,
                &declaration.namespace,
                MigrationHistoryIntegrityReason::DuplicateDeclaredNamespace,
            ));
        }

        let mut versions = HashSet::new();
        let mut previous_version = None;
        for migration in &declaration.migrations {
            if migration.version <= 0 {
                return Err(integrity_error(
                    backend,
                    &declaration.namespace,
                    MigrationHistoryIntegrityReason::NonPositiveDeclaredVersion {
                        version: migration.version,
                    },
                ));
            }
            if migration.version > i64::from(i32::MAX) {
                return Err(integrity_error(
                    backend,
                    &declaration.namespace,
                    MigrationHistoryIntegrityReason::DeclaredVersionOutOfRange {
                        version: migration.version,
                        max_supported_version: i64::from(i32::MAX),
                    },
                ));
            }
            if !versions.insert(migration.version) {
                return Err(integrity_error(
                    backend,
                    &declaration.namespace,
                    MigrationHistoryIntegrityReason::DuplicateDeclaredVersion {
                        version: migration.version,
                    },
                ));
            }
            if let Some(previous_version) = previous_version
                && migration.version < previous_version
            {
                return Err(integrity_error(
                    backend,
                    &declaration.namespace,
                    MigrationHistoryIntegrityReason::UnorderedDeclaredVersions {
                        previous_version,
                        version: migration.version,
                    },
                ));
            }
            previous_version = Some(migration.version);
        }
    }

    let mut applied_namespaces = HashSet::new();
    for applied in applied_histories {
        if !applied_namespaces.insert(&applied.namespace) {
            return Err(integrity_error(
                backend,
                &applied.namespace,
                MigrationHistoryIntegrityReason::DuplicateAppliedNamespace,
            ));
        }

        let Some(declaration) = declarations
            .iter()
            .find(|declaration| declaration.namespace == applied.namespace)
        else {
            return Err(integrity_error(
                backend,
                &applied.namespace,
                MigrationHistoryIntegrityReason::UnknownAppliedNamespace,
            ));
        };

        let mut applied_versions = HashSet::new();
        for migration in &applied.migrations {
            if !applied_versions.insert(migration.version) {
                return Err(integrity_error(
                    backend,
                    &applied.namespace,
                    MigrationHistoryIntegrityReason::DuplicateAppliedVersion {
                        version: migration.version,
                    },
                ));
            }
        }

        for (index, applied_migration) in applied.migrations.iter().enumerate() {
            let Some(declared_migration) = declaration.migrations.get(index) else {
                return Err(integrity_error(
                    backend,
                    &applied.namespace,
                    MigrationHistoryIntegrityReason::UnknownAppliedVersion {
                        version: applied_migration.version,
                    },
                ));
            };

            if applied_migration.version != declared_migration.version {
                let reason = if declaration
                    .migrations
                    .iter()
                    .any(|migration| migration.version == applied_migration.version)
                {
                    MigrationHistoryIntegrityReason::MissingAppliedVersion {
                        expected_version: declared_migration.version,
                        observed_version: applied_migration.version,
                    }
                } else {
                    MigrationHistoryIntegrityReason::UnknownAppliedVersion {
                        version: applied_migration.version,
                    }
                };
                return Err(integrity_error(backend, &applied.namespace, reason));
            }

            if applied_migration.checksum != declared_migration.checksum {
                return Err(integrity_error(
                    backend,
                    &applied.namespace,
                    MigrationHistoryIntegrityReason::ChecksumMismatch {
                        version: applied_migration.version,
                        stored_checksum: applied_migration.checksum.clone(),
                        expected_checksum: declared_migration.checksum.clone(),
                    },
                ));
            }
        }
    }

    Ok(())
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
        // During build-out, schema additions are folded into V001 rather than
        // carried as upgrade migrations.
        vec![Box::new(MigrationEntryV001(
            v001_initial_schema::V001InitialSchema,
        ))]
    }

    /// Ensure the `_ferrum_migrations` tracking table exists.
    ///
    /// MySQL's `TEXT` type is reported as `BLOB` by the `Any` driver, which
    /// prevents `try_get::<String>()`. Use `VARCHAR` for MySQL compatibility.
    async fn ensure_tracking_table(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        let sql = if self.db_type == "mysql" {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at VARCHAR(64) NOT NULL,
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
        sqlx::query(sql).execute(&mut *connection).await?;
        Ok(())
    }

    async fn tracking_table_exists(
        &self,
        connection: &mut AnyConnection,
        plugin_tracking: bool,
    ) -> Result<bool, anyhow::Error> {
        let table = if plugin_tracking {
            "_ferrum_plugin_migrations"
        } else {
            "_ferrum_migrations"
        };
        let sql = match self.db_type.as_str() {
            "postgres" => format!(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = '{table}' LIMIT 1"
            ),
            "mysql" => format!(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '{table}' LIMIT 1"
            ),
            "sqlite" => format!(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{table}' LIMIT 1"
            ),
            other => anyhow::bail!("Unsupported database type for migrations: {other}"),
        };
        Ok(sqlx::query(&sql)
            .fetch_optional(&mut *connection)
            .await?
            .is_some())
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
    async fn applied_versions(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        let rows: Vec<AnyRow> =
            sqlx::query("SELECT version, name, applied_at, checksum, execution_time_ms FROM _ferrum_migrations ORDER BY version")
                .fetch_all(&mut *connection)
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

    fn core_history_declaration(
        all_migrations: &[Box<dyn MigrationEntry>],
    ) -> DeclaredMigrationHistory {
        DeclaredMigrationHistory {
            namespace: MigrationHistoryNamespace::Core,
            migrations: all_migrations
                .iter()
                .map(|migration| DeclaredMigrationHistoryEntry {
                    version: migration.version(),
                    checksum: migration.checksum().to_string(),
                })
                .collect(),
        }
    }

    fn plugin_history_declarations(
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Vec<DeclaredMigrationHistory> {
        plugin_migrations
            .iter()
            .map(|(plugin_name, migrations)| DeclaredMigrationHistory {
                namespace: MigrationHistoryNamespace::CustomPlugin((*plugin_name).to_string()),
                migrations: migrations
                    .iter()
                    .map(|migration| DeclaredMigrationHistoryEntry {
                        version: migration.version,
                        checksum: migration.checksum.to_string(),
                    })
                    .collect(),
            })
            .collect()
    }

    fn core_applied_history(applied: &[MigrationRecord]) -> AppliedMigrationHistory {
        AppliedMigrationHistory {
            namespace: MigrationHistoryNamespace::Core,
            migrations: applied
                .iter()
                .map(|record| AppliedMigrationHistoryEntry {
                    version: record.version,
                    checksum: record.checksum.clone(),
                })
                .collect(),
        }
    }

    fn plugin_applied_histories(applied: &[PluginMigrationRecord]) -> Vec<AppliedMigrationHistory> {
        let mut histories: Vec<AppliedMigrationHistory> = Vec::new();
        let mut history_indexes: HashMap<&str, usize> = HashMap::new();
        for record in applied {
            if let Some(&history_index) = history_indexes.get(record.plugin_name.as_str()) {
                histories[history_index]
                    .migrations
                    .push(AppliedMigrationHistoryEntry {
                        version: record.version,
                        checksum: record.checksum.clone(),
                    });
            } else {
                let history_index = histories.len();
                history_indexes.insert(record.plugin_name.as_str(), history_index);
                histories.push(AppliedMigrationHistory {
                    namespace: MigrationHistoryNamespace::CustomPlugin(record.plugin_name.clone()),
                    migrations: vec![AppliedMigrationHistoryEntry {
                        version: record.version,
                        checksum: record.checksum.clone(),
                    }],
                });
            }
        }
        histories
    }

    fn validate_core_history(
        &self,
        applied: &[MigrationRecord],
        all_migrations: &[Box<dyn MigrationEntry>],
    ) -> Result<(), anyhow::Error> {
        let declarations = vec![Self::core_history_declaration(all_migrations)];
        let applied_histories = vec![Self::core_applied_history(applied)];
        validate_migration_history_integrity(&self.db_type, &declarations, &applied_histories)?;
        Ok(())
    }

    fn validate_plugin_history(
        &self,
        applied: &[PluginMigrationRecord],
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<(), anyhow::Error> {
        let declarations = Self::plugin_history_declarations(plugin_migrations);
        let applied_histories = Self::plugin_applied_histories(applied);
        validate_migration_history_integrity(&self.db_type, &declarations, &applied_histories)?;
        Ok(())
    }

    #[allow(dead_code)] // core-only helper for run_pending; production uses validate_known_history_locked
    async fn validate_core_history_locked(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        let all_migrations = self.all_migrations();
        let declarations = vec![Self::core_history_declaration(&all_migrations)];
        validate_migration_history_integrity(&self.db_type, &declarations, &[])?;
        let applied = if self.tracking_table_exists(connection, false).await? {
            self.applied_versions(connection).await?
        } else {
            Vec::new()
        };
        let applied_histories = vec![Self::core_applied_history(&applied)];
        validate_migration_history_integrity(&self.db_type, &declarations, &applied_histories)?;
        Ok(())
    }

    async fn validate_known_history_locked(
        &self,
        connection: &mut AnyConnection,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<(), anyhow::Error> {
        let all_migrations = self.all_migrations();
        let mut declarations = vec![Self::core_history_declaration(&all_migrations)];
        declarations.extend(Self::plugin_history_declarations(plugin_migrations));

        // Declaration ambiguity is rejected before inspecting database history.
        // This preflight runs under the same cross-process lock as migration
        // work and before any tracking table, compatibility, schema, or history
        // write can occur.
        validate_migration_history_integrity(&self.db_type, &declarations, &[])?;

        let core_applied = if self.tracking_table_exists(connection, false).await? {
            self.applied_versions(connection).await?
        } else {
            Vec::new()
        };
        let plugin_applied = if self.tracking_table_exists(connection, true).await? {
            self.applied_plugin_versions(connection).await?
        } else {
            Vec::new()
        };
        let mut applied_histories = vec![Self::core_applied_history(&core_applied)];
        applied_histories.extend(Self::plugin_applied_histories(&plugin_applied));
        validate_migration_history_integrity(&self.db_type, &declarations, &applied_histories)?;

        Ok(())
    }

    /// Run pending core migrations after validating core history only.
    ///
    /// This helper is intentionally core-only. Production startup uses
    /// [`Self::run_pending_with_plugin_history`] for combined validation.
    #[allow(dead_code)] // exercised via external migration tests; production uses run_pending_with_plugin_history
    pub async fn run_pending(&self) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        let mut migration_lock =
            MigrationConnectionLock::acquire(&self.pool, &self.db_type).await?;
        let operation = async {
            self.validate_core_history_locked(migration_lock.connection())
                .await?;
            self.run_pending_locked(migration_lock.connection()).await
        }
        .await;
        let release = migration_lock.finish(operation.is_ok()).await;
        finish_locked_operation(operation, release)
    }

    /// Validate complete core and plugin history before applying pending core work.
    ///
    /// Startup uses this combined path even when automatic plugin migration
    /// application is disabled or no plugins are currently compiled, so orphan,
    /// missing, duplicate, unknown, or drifted plugin history cannot be hidden
    /// by successful core migration or V001 compatibility work.
    pub async fn run_pending_with_plugin_history(
        &self,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        let mut migration_lock =
            MigrationConnectionLock::acquire(&self.pool, &self.db_type).await?;
        let operation = async {
            self.validate_known_history_locked(migration_lock.connection(), plugin_migrations)
                .await?;
            self.run_pending_locked(migration_lock.connection()).await
        }
        .await;
        let release = migration_lock.finish(operation.is_ok()).await;
        finish_locked_operation(operation, release)
    }

    /// Validate all known history, then apply core and plugin migrations under
    /// one cross-process lock. No migration work starts until both histories
    /// pass the complete sequence-integrity check.
    pub async fn run_all_pending(
        &self,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<(Vec<MigrationRecord>, Vec<PluginMigrationRecord>), anyhow::Error> {
        let mut migration_lock =
            MigrationConnectionLock::acquire(&self.pool, &self.db_type).await?;
        let operation = async {
            self.validate_known_history_locked(migration_lock.connection(), plugin_migrations)
                .await?;
            let core = self.run_pending_locked(migration_lock.connection()).await?;
            let plugins = if plugin_migrations.is_empty() {
                Vec::new()
            } else {
                self.run_plugin_pending_locked(plugin_migrations, migration_lock.connection())
                    .await?
            };
            Ok((core, plugins))
        }
        .await;
        let release = migration_lock.finish(operation.is_ok()).await;
        finish_locked_operation(operation, release)
    }

    async fn run_pending_locked(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<Vec<MigrationRecord>, anyhow::Error> {
        self.ensure_tracking_table(connection).await?;

        // This read deliberately happens only after acquiring the cross-process
        // lock. A process that waited for another replica therefore observes
        // the winner's committed tracking rows and skips them cleanly.
        let applied = self.applied_versions(connection).await?;
        let applied_versions: Vec<i64> = applied.iter().map(|r| r.version).collect();

        let all_migrations = self.all_migrations();
        self.validate_core_history(&applied, &all_migrations)?;

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
            migration.run_up(connection, &self.db_type).await?;
            let elapsed_ms = start.elapsed().as_millis() as i64;

            let now = Utc::now().to_rfc3339();
            let insert_sql = Self::migration_insert_sql(&self.db_type);
            sqlx::query(&insert_sql)
                .bind(migration.version() as i32)
                .bind(migration.name())
                .bind(&now)
                .bind(migration.checksum())
                .bind(elapsed_ms as i32)
                .execute(&mut *connection)
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

        // Idempotent compatibility pass for tables folded into the V001
        // baseline after some databases already recorded V001. The loop above
        // skips V001 once version 1 is tracked, so a newly folded-in table
        // (e.g. `proxy_route_locks`, which the proxy persistence path writes to
        // unconditionally) would otherwise be missing on existing databases.
        // This runs after every `run_pending()` and idempotently creates folded-in
        // tables/indexes and adds folded-in columns, so it is a no-op on fresh
        // databases that just applied V001 in full.
        sql_dialect::V001SqlBuilder::new(&self.db_type)
            .ensure_compatibility_tables(connection)
            .await?;

        // MySQL-only: warn when upgraded deployments still carry a non-
        // utf8mb4_0900_bin identity collation. Warn-and-continue (never refuse
        // startup) — matching the pending-plugin-migration posture. No-op on
        // PostgreSQL / SQLite; MongoDB never reaches MigrationRunner.
        mysql_collation_probe::warn_stale_mysql_identity_collations(connection, &self.db_type)
            .await;

        Ok(newly_applied)
    }

    /// Get core migration status after validating core history only.
    ///
    /// Combined operator status paths must also call [`Self::plugin_status`].
    pub async fn status(&self) -> Result<MigrationStatus, anyhow::Error> {
        let mut connection = self.pool.acquire().await?;
        let applied = if self.tracking_table_exists(&mut connection, false).await? {
            self.applied_versions(&mut connection).await?
        } else {
            Vec::new()
        };
        let applied_versions: Vec<i64> = applied.iter().map(|r| r.version).collect();

        let all_migrations = self.all_migrations();
        self.validate_core_history(&applied, &all_migrations)?;
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

    // -----------------------------------------------------------------------
    // Custom plugin migration support
    // -----------------------------------------------------------------------

    /// Ensure the `_ferrum_plugin_migrations` tracking table exists.
    ///
    /// This table is separate from `_ferrum_migrations` so that core gateway
    /// migrations and custom plugin migrations have independent version spaces.
    /// The composite primary key `(plugin_name, version)` allows each plugin
    /// to maintain its own migration sequence.
    async fn ensure_plugin_tracking_table(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        let sql = if self.db_type == "mysql" {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_plugin_migrations (
                plugin_name VARCHAR(255) NOT NULL,
                version INTEGER NOT NULL,
                name VARCHAR(255) NOT NULL,
                applied_at VARCHAR(64) NOT NULL,
                checksum VARCHAR(255) NOT NULL,
                execution_time_ms INTEGER NOT NULL,
                PRIMARY KEY (plugin_name, version)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_plugin_migrations (
                plugin_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL,
                execution_time_ms INTEGER NOT NULL,
                PRIMARY KEY (plugin_name, version)
            )
            "#
        };
        sqlx::query(sql).execute(&mut *connection).await?;
        Ok(())
    }

    /// Return the INSERT statement for the plugin migration tracking table.
    fn plugin_migration_insert_sql(db_type: &str) -> String {
        if db_type == "postgres" {
            "INSERT INTO _ferrum_plugin_migrations (plugin_name, version, name, applied_at, checksum, execution_time_ms) VALUES ($1, $2, $3, $4, $5, $6)".to_string()
        } else {
            "INSERT INTO _ferrum_plugin_migrations (plugin_name, version, name, applied_at, checksum, execution_time_ms) VALUES (?, ?, ?, ?, ?, ?)".to_string()
        }
    }

    /// Get all applied plugin migration records.
    async fn applied_plugin_versions(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<Vec<PluginMigrationRecord>, anyhow::Error> {
        let rows: Vec<AnyRow> =
            sqlx::query("SELECT plugin_name, version, name, applied_at, checksum, execution_time_ms FROM _ferrum_plugin_migrations ORDER BY plugin_name, version")
                .fetch_all(&mut *connection)
                .await?;

        let mut records = Vec::new();
        for row in rows {
            records.push(PluginMigrationRecord {
                plugin_name: row.try_get("plugin_name")?,
                version: row.try_get::<i32, _>("version")? as i64,
                name: row.try_get("name")?,
                applied_at: row.try_get("applied_at")?,
                checksum: row.try_get("checksum")?,
                execution_time_ms: row.try_get::<i32, _>("execution_time_ms")? as i64,
            });
        }
        Ok(records)
    }

    /// Run all pending custom plugin migrations.
    ///
    /// `plugin_migrations` is a list of `(plugin_name, migrations)` tuples,
    /// typically collected from the build-script-generated registry via
    /// `crate::custom_plugins::collect_all_custom_plugin_migrations()`.
    ///
    /// Each plugin's migrations are applied in version order. Migrations are
    /// tracked per-plugin in `_ferrum_plugin_migrations` with a composite
    /// `(plugin_name, version)` key.
    pub async fn run_plugin_pending(
        &self,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<Vec<PluginMigrationRecord>, anyhow::Error> {
        let mut migration_lock =
            MigrationConnectionLock::acquire(&self.pool, &self.db_type).await?;
        let operation = async {
            self.validate_known_history_locked(migration_lock.connection(), plugin_migrations)
                .await?;
            if plugin_migrations.is_empty() {
                Ok(Vec::new())
            } else {
                self.run_plugin_pending_locked(plugin_migrations, migration_lock.connection())
                    .await
            }
        }
        .await;
        let release = migration_lock.finish(operation.is_ok()).await;
        finish_locked_operation(operation, release)
    }

    async fn run_plugin_pending_locked(
        &self,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
        connection: &mut AnyConnection,
    ) -> Result<Vec<PluginMigrationRecord>, anyhow::Error> {
        self.ensure_plugin_tracking_table(connection).await?;

        // Re-read only after the cross-process lock is held so a waiter sees
        // and skips every tracking row committed by the winner.
        let applied = self.applied_plugin_versions(connection).await?;
        self.validate_plugin_history(&applied, plugin_migrations)?;
        let mut newly_applied = Vec::new();

        for (plugin_name, migrations) in plugin_migrations {
            let plugin_applied: Vec<&PluginMigrationRecord> = applied
                .iter()
                .filter(|r| r.plugin_name == *plugin_name)
                .collect();
            let applied_versions: Vec<i64> = plugin_applied.iter().map(|r| r.version).collect();

            for migration in migrations {
                if applied_versions.contains(&migration.version) {
                    continue;
                }

                info!(
                    "Applying plugin '{}' migration V{}: {}",
                    plugin_name, migration.version, migration.name
                );

                let sql = migration.sql_for_db(&self.db_type);
                let start = Instant::now();

                // Fail-closed: parse the full migration body into statement
                // boundaries before executing statement one. Classification and
                // execution share this exact split.
                let statements =
                    split_plugin_migration_statements(sql, &self.db_type).map_err(|err| {
                        anyhow::anyhow!(
                            "plugin '{}' migration V{} ({}): {}",
                            plugin_name,
                            migration.version,
                            migration.name,
                            err
                        )
                    })?;
                let non_transactional =
                    sql_statements::statements_require_non_transactional_postgres(
                        &self.db_type,
                        &statements,
                    );
                let now;
                if non_transactional {
                    // PostgreSQL online DDL such as CREATE INDEX CONCURRENTLY
                    // cannot run in an explicit transaction. Execute every
                    // statement successfully before writing the tracking row.
                    for statement in &statements {
                        map_plugin_statement_result(
                            &self.db_type,
                            statement,
                            sqlx::query(statement).execute(&mut *connection).await,
                        )?;
                    }
                    now = Utc::now().to_rfc3339();
                    let elapsed_ms = start.elapsed().as_millis() as i64;
                    let insert_sql = Self::plugin_migration_insert_sql(&self.db_type);
                    sqlx::query(&insert_sql)
                        .bind(*plugin_name)
                        .bind(migration.version as i32)
                        .bind(migration.name)
                        .bind(&now)
                        .bind(migration.checksum)
                        .bind(elapsed_ms as i32)
                        .execute(&mut *connection)
                        .await?;
                } else if self.db_type == "sqlite" {
                    // The cross-process SQLite lock is itself a
                    // `BEGIN IMMEDIATE` transaction. Execute body + tracking
                    // directly on that connection; `finish(true)` commits the
                    // complete locked operation and `finish(false)` rolls it
                    // back on any error.
                    for statement in &statements {
                        map_plugin_statement_result(
                            &self.db_type,
                            statement,
                            sqlx::query(statement).execute(&mut *connection).await,
                        )?;
                    }
                    now = Utc::now().to_rfc3339();
                    let elapsed_ms = start.elapsed().as_millis() as i64;
                    let insert_sql = Self::plugin_migration_insert_sql(&self.db_type);
                    sqlx::query(&insert_sql)
                        .bind(*plugin_name)
                        .bind(migration.version as i32)
                        .bind(migration.name)
                        .bind(&now)
                        .bind(migration.checksum)
                        .bind(elapsed_ms as i32)
                        .execute(&mut *connection)
                        .await?;
                } else if self.db_type == "mysql" {
                    // MySQL implicitly commits around DDL
                    // (https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html),
                    // so statements + tracking are NOT one atomic unit. Execute
                    // each statement with structured missing-index (1091)
                    // tolerance for DROP INDEX, then insert the tracking row.
                    // Paired DROP/CREATE statements can therefore reconstruct
                    // an exact plugin-owned index after any partial DDL retry.
                    for statement in &statements {
                        map_plugin_statement_result(
                            "mysql",
                            statement,
                            sqlx::query(statement).execute(&mut *connection).await,
                        )?;
                    }
                    now = Utc::now().to_rfc3339();
                    let elapsed_ms = start.elapsed().as_millis() as i64;
                    let insert_sql = Self::plugin_migration_insert_sql(&self.db_type);
                    sqlx::query(&insert_sql)
                        .bind(*plugin_name)
                        .bind(migration.version as i32)
                        .bind(migration.name)
                        .bind(&now)
                        .bind(migration.checksum)
                        .bind(elapsed_ms as i32)
                        .execute(&mut *connection)
                        .await?;
                } else {
                    // PostgreSQL transactional path: statements and tracking
                    // remain atomic in one transaction on the lock session.
                    let mut tx = connection.begin().await?;
                    for statement in &statements {
                        map_plugin_statement_result(
                            &self.db_type,
                            statement,
                            sqlx::query(statement).execute(&mut *tx).await,
                        )?;
                    }
                    now = Utc::now().to_rfc3339();
                    let elapsed_ms = start.elapsed().as_millis() as i64;
                    let insert_sql = Self::plugin_migration_insert_sql(&self.db_type);
                    sqlx::query(&insert_sql)
                        .bind(*plugin_name)
                        .bind(migration.version as i32)
                        .bind(migration.name)
                        .bind(&now)
                        .bind(migration.checksum)
                        .bind(elapsed_ms as i32)
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                }

                let elapsed_ms = start.elapsed().as_millis() as i64;

                let record = PluginMigrationRecord {
                    plugin_name: plugin_name.to_string(),
                    version: migration.version,
                    name: migration.name.to_string(),
                    applied_at: now,
                    checksum: migration.checksum.to_string(),
                    execution_time_ms: elapsed_ms,
                };

                info!(
                    "Applied plugin '{}' migration V{}: {} ({}ms)",
                    plugin_name, record.version, record.name, record.execution_time_ms
                );

                newly_applied.push(record);
            }
        }

        Ok(newly_applied)
    }

    /// Get custom-plugin status after validating complete core and plugin history.
    pub async fn plugin_status(
        &self,
        plugin_migrations: &[(&str, Vec<CustomPluginMigration>)],
    ) -> Result<PluginMigrationStatus, anyhow::Error> {
        let mut connection = self.pool.acquire().await?;
        let all_migrations = self.all_migrations();
        let mut declarations = vec![Self::core_history_declaration(&all_migrations)];
        declarations.extend(Self::plugin_history_declarations(plugin_migrations));
        validate_migration_history_integrity(&self.db_type, &declarations, &[])?;

        let core_applied = if self.tracking_table_exists(&mut connection, false).await? {
            self.applied_versions(&mut connection).await?
        } else {
            Vec::new()
        };
        let applied = if self.tracking_table_exists(&mut connection, true).await? {
            self.applied_plugin_versions(&mut connection).await?
        } else {
            Vec::new()
        };
        let mut applied_histories = vec![Self::core_applied_history(&core_applied)];
        applied_histories.extend(Self::plugin_applied_histories(&applied));
        validate_migration_history_integrity(&self.db_type, &declarations, &applied_histories)?;

        let mut pending = Vec::new();
        for (plugin_name, migrations) in plugin_migrations {
            let applied_versions: Vec<i64> = applied
                .iter()
                .filter(|r| r.plugin_name == *plugin_name)
                .map(|r| r.version)
                .collect();

            for migration in migrations {
                if !applied_versions.contains(&migration.version) {
                    pending.push(PendingPluginMigration {
                        plugin_name: plugin_name.to_string(),
                        version: migration.version,
                        name: migration.name.to_string(),
                    });
                }
            }
        }

        Ok(PluginMigrationStatus { applied, pending })
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
        connection: &'a mut AnyConnection,
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
        connection: &'a mut AnyConnection,
        db_type: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>
    {
        Box::pin(self.0.up(connection, db_type))
    }
}
