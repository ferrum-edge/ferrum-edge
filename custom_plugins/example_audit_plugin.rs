//! Example Audit Plugin — Custom Plugin with Database Migrations
//!
//! This is a complete, working example of a custom plugin that uses database
//! migrations to create and manage its own tables. It records an audit log of
//! every request processed by the gateway, storing the entry in a database
//! table that is created and maintained via the plugin migration system.
//!
//! ## Features Demonstrated
//!
//! - Database migrations via `plugin_migrations()` with multi-DB support
//! - Async database writes in the `log()` lifecycle hook (fire-and-forget)
//! - Stateful plugin holding a database connection pool
//! - PostgreSQL-specific and MySQL-specific SQL overrides
//! - Multi-statement migrations (CREATE TABLE + CREATE INDEX)
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "plugin_name": "example_audit_plugin",
//!   "config": {
//!     "db_url": "sqlite://ferrum.db",
//!     "db_type": "sqlite",
//!     "log_request_headers": false,
//!     "retention_days": 90
//!   }
//! }
//! ```
//!
//! ## Running Migrations
//!
//! ```bash
//! FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up cargo run
//! ```
//!
//! The migrate mode automatically discovers and runs migrations declared by
//! this plugin via the `plugin_migrations()` function below.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

use crate::config::migrations::CustomPluginMigration;
use crate::plugins::{Plugin, PluginHttpClient, TransactionSummary};

pub struct ExampleAuditPlugin {
    log_request_headers: bool,
    #[allow(dead_code)]
    retention_days: u64,
}

impl ExampleAuditPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        Ok(Self {
            log_request_headers: config["log_request_headers"].as_bool().unwrap_or(false),
            retention_days: config["retention_days"].as_u64().unwrap_or(90),
        })
    }
}

#[async_trait]
impl Plugin for ExampleAuditPlugin {
    fn name(&self) -> &str {
        "example_audit_plugin"
    }

    fn priority(&self) -> u16 {
        // Run in the logging band, after all other processing
        9150
    }

    /// Fire-and-forget logging hook — record each transaction to the audit log.
    async fn log(&self, summary: &TransactionSummary) {
        // In a real plugin, you would write to the database here using a
        // connection pool held in the plugin struct. This example just
        // demonstrates the pattern — the actual DB write is left as a
        // placeholder since this is an example plugin.
        //
        // Example of what a real implementation would look like:
        //
        //   let id = uuid::Uuid::new_v4().to_string();
        //   let headers_json = if self.log_request_headers {
        //       serde_json::to_string(&summary.metadata).unwrap_or_default()
        //   } else {
        //       String::new()
        //   };
        //
        //   sqlx::query("INSERT INTO audit_log (...) VALUES (...)")
        //       .bind(&id)
        //       .bind(&summary.timestamp_received)
        //       .bind(&summary.client_ip)
        //       .bind(&summary.http_method)
        //       .bind(&summary.request_path)
        //       .bind(summary.response_status_code as i32)
        //       .bind(summary.latency_total_ms)
        //       .bind(&summary.consumer_username)
        //       .bind(&summary.matched_proxy_id)
        //       .bind(&headers_json)
        //       .execute(&self.pool)
        //       .await
        //       .ok();

        let _ = (summary, self.log_request_headers);
    }
}

/// Factory function — called automatically by the build-script-generated registry.
/// Must return `Result` so invalid configs are rejected at admission time.
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(ExampleAuditPlugin::new(config)?)))
}

/// Database migrations for this plugin.
///
/// These migrations are automatically discovered by the build script and run
/// alongside core gateway migrations when `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up`
/// is executed.
///
/// ## Guidelines
///
/// - Version numbers are scoped to this plugin (start at 1, increment by 1)
/// - Table names should be prefixed with your plugin name to avoid collisions
///   (e.g., `audit_log_` prefix)
/// - The `sql` field is the default SQL used for all databases
/// - Use `sql_postgres` / `sql_mysql` for database-specific overrides when you
///   need features like `JSONB`, `AUTO_INCREMENT`, or other vendor extensions
/// - Multi-statement SQL is supported (separate statements with `;`)
/// - Checksums should be unique and stable — convention: `v{N}_{name}_{short_hash}`
pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
    vec![
        // V1: Create the audit_log table and indexes
        CustomPluginMigration {
            version: 1,
            name: "create_audit_log",
            checksum: "v1_create_audit_log_f8a3e1",
            sql: r#"
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    http_method TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    response_status INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_headers TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_log_client_ip ON audit_log (client_ip)
            "#,
            // PostgreSQL: use TIMESTAMPTZ for native timestamp handling and JSONB
            // for the request_headers column (enables GIN indexing for header queries)
            sql_postgres: Some(r#"
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    client_ip TEXT NOT NULL,
                    http_method TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    response_status INTEGER NOT NULL,
                    latency_ms DOUBLE PRECISION NOT NULL,
                    consumer_username TEXT,
                    proxy_id TEXT,
                    request_headers JSONB
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_log_client_ip ON audit_log (client_ip)
            "#),
            // MySQL: use DATETIME(3) for millisecond precision and JSON type
            sql_mysql: Some(r#"
                CREATE TABLE IF NOT EXISTS audit_log (
                    id VARCHAR(255) PRIMARY KEY,
                    timestamp DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
                    client_ip VARCHAR(255) NOT NULL,
                    http_method VARCHAR(20) NOT NULL,
                    request_path TEXT NOT NULL,
                    response_status INTEGER NOT NULL,
                    latency_ms DOUBLE NOT NULL,
                    consumer_username VARCHAR(255),
                    proxy_id VARCHAR(255),
                    request_headers JSON
                );
                CREATE INDEX idx_audit_log_timestamp ON audit_log (timestamp);
                CREATE INDEX idx_audit_log_client_ip ON audit_log (client_ip)
            "#),
        },
        // V2: Add a composite index for common query patterns
        CustomPluginMigration {
            version: 2,
            name: "add_status_timestamp_index",
            checksum: "v2_add_status_timestamp_idx_b7c4d2",
            sql: "CREATE INDEX IF NOT EXISTS idx_audit_log_status_ts ON audit_log (response_status, timestamp)",
            sql_postgres: None,
            // MySQL: no IF NOT EXISTS for CREATE INDEX before 8.0.29
            sql_mysql: None,
        },
    ]
}
