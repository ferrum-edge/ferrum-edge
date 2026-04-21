//! Dialect-specific SQL text for the V001 initial schema migration.
//!
//! MySQL intentionally diverges from the SQLite/Postgres-style schema in a few
//! places:
//! - strict mode forbids defaults on `TEXT`/`BLOB`, so MySQL uses bounded
//!   `VARCHAR(N)` columns for primary keys and other fields that need defaults
//! - timestamp columns stay as `VARCHAR(50)` because sqlx's `Any` driver does
//!   not round-trip MySQL `DATETIME` values into the string-based config layer
//!
//! The proxy schema also intentionally omits a unique index on
//! `(namespace, listen_path)`: path uniqueness is host-scoped, so only
//! namespace/name and namespace/listen_port constraints belong in V001.

use sqlx::AnyPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDialect {
    Postgres,
    MySql,
    Sqlite,
}

/// Small dialect-aware SQL helper for V001.
///
/// The helper keeps the migration logic conservative: it only encapsulates the
/// SQL text and the MySQL duplicate-index tolerance that already existed in the
/// migration, without trying to normalize the schema across databases.
pub(super) struct V001SqlBuilder {
    dialect: SqlDialect,
}

impl V001SqlBuilder {
    pub(super) fn new(db_type: &str) -> Self {
        let dialect = match db_type {
            "mysql" => SqlDialect::MySql,
            "sqlite" => SqlDialect::Sqlite,
            _ => SqlDialect::Postgres,
        };

        Self { dialect }
    }

    pub(super) async fn apply(&self, pool: &AnyPool) -> Result<(), anyhow::Error> {
        self.enable_sqlite_foreign_keys(pool).await?;
        self.create_tables(pool).await?;
        self.create_indexes(pool).await?;
        self.create_unique_indexes(pool).await?;
        Ok(())
    }

    async fn enable_sqlite_foreign_keys(&self, pool: &AnyPool) -> Result<(), anyhow::Error> {
        if self.is_sqlite() {
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(pool)
                .await?;
        }

        Ok(())
    }

    async fn create_tables(&self, pool: &AnyPool) -> Result<(), anyhow::Error> {
        for sql in [
            self.create_upstreams_sql(),
            self.create_consumers_sql(),
            self.create_proxies_sql(),
            self.create_plugin_configs_sql(),
            self.create_proxy_plugins_sql(),
        ] {
            sqlx::query(sql).execute(pool).await?;
        }

        Ok(())
    }

    async fn create_indexes(&self, pool: &AnyPool) -> Result<(), anyhow::Error> {
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_proxies_upstream_id ON proxies (upstream_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_proxy_id ON plugin_configs (proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_plugin_config_id ON proxy_plugins (plugin_config_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxies_updated_at ON proxies (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_updated_at ON consumers (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_updated_at ON plugin_configs (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_updated_at ON upstreams (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_proxies_namespace ON proxies (namespace)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_namespace ON consumers (namespace)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_namespace ON plugin_configs (namespace)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_namespace ON upstreams (namespace)",
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_updated ON proxies (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_updated ON consumers (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_updated ON plugin_configs (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_updated ON upstreams (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_scope ON plugin_configs (namespace, scope)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_plugin_name ON plugin_configs (namespace, plugin_name)",
        ];

        for idx_sql in indexes {
            self.execute_index_sql(pool, idx_sql).await?;
        }

        Ok(())
    }

    async fn create_unique_indexes(&self, pool: &AnyPool) -> Result<(), anyhow::Error> {
        self.execute_index_sql(pool, self.unique_listen_port_sql())
            .await?;

        for idx_sql in self.namespace_unique_index_sqls() {
            self.execute_index_sql(pool, idx_sql).await?;
        }

        Ok(())
    }

    async fn execute_index_sql(&self, pool: &AnyPool, idx_sql: &str) -> Result<(), anyhow::Error> {
        if self.is_mysql() {
            // MySQL < 8.0.29 does not support CREATE INDEX IF NOT EXISTS, so we
            // strip the clause and ignore duplicate-key errors, matching the
            // previous migration behavior.
            let mysql_sql = idx_sql.replace("IF NOT EXISTS ", "");
            match sqlx::query(&mysql_sql).execute(pool).await {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    // Error 1061: Duplicate key name (index already exists)
                    if !msg.contains("1061") {
                        return Err(e.into());
                    }
                }
            }
        } else {
            sqlx::query(idx_sql).execute(pool).await?;
        }

        Ok(())
    }

    fn is_mysql(&self) -> bool {
        matches!(self.dialect, SqlDialect::MySql)
    }

    fn is_sqlite(&self) -> bool {
        matches!(self.dialect, SqlDialect::Sqlite)
    }

    fn create_upstreams_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id VARCHAR(255) PRIMARY KEY,
                namespace VARCHAR(255) NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255),
                targets TEXT NOT NULL,
                algorithm VARCHAR(50) NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                hash_on_cookie_config TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                backend_tls_client_cert_path VARCHAR(2048),
                backend_tls_client_key_path VARCHAR(2048),
                backend_tls_verify_server_cert TINYINT NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path VARCHAR(2048),
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                name TEXT,
                targets TEXT NOT NULL DEFAULT '[]',
                algorithm TEXT NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                hash_on_cookie_config TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_consumers_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id VARCHAR(255) PRIMARY KEY,
                namespace VARCHAR(255) NOT NULL DEFAULT 'ferrum',
                username VARCHAR(255) NOT NULL,
                custom_id VARCHAR(255),
                credentials TEXT NOT NULL,
                acl_groups VARCHAR(8192) NOT NULL DEFAULT '[]',
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                username TEXT NOT NULL,
                custom_id TEXT,
                credentials TEXT NOT NULL DEFAULT '{}',
                acl_groups TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_proxies_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id VARCHAR(255) PRIMARY KEY,
                namespace VARCHAR(255) NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255),
                hosts TEXT NOT NULL,
                listen_path VARCHAR(500),
                backend_scheme VARCHAR(16) NOT NULL DEFAULT 'https',
                backend_prefer_h3 TINYINT NOT NULL DEFAULT 0,
                backend_host VARCHAR(255) NOT NULL,
                backend_port INTEGER NOT NULL DEFAULT 80,
                backend_path TEXT,
                strip_listen_path INTEGER NOT NULL DEFAULT 1,
                preserve_host_header INTEGER NOT NULL DEFAULT 0,
                backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
                backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                dns_override TEXT,
                dns_cache_ttl_seconds INTEGER,
                auth_mode VARCHAR(20) NOT NULL DEFAULT 'single',
                upstream_id VARCHAR(255),
                circuit_breaker TEXT,
                retry TEXT,
                response_body_mode VARCHAR(50) NOT NULL DEFAULT 'stream',

                pool_idle_timeout_seconds INTEGER,
                pool_enable_http_keep_alive INTEGER,
                pool_enable_http2 INTEGER,
                pool_tcp_keepalive_seconds INTEGER,
                pool_http2_keep_alive_interval_seconds INTEGER,
                pool_http2_keep_alive_timeout_seconds INTEGER,
                pool_http2_initial_stream_window_size INTEGER,
                pool_http2_initial_connection_window_size INTEGER,
                pool_http2_adaptive_window INTEGER,
                pool_http2_max_frame_size INTEGER,
                pool_http2_max_concurrent_streams INTEGER,
                pool_http3_connections_per_backend INTEGER,
                listen_port INTEGER,
                frontend_tls INTEGER NOT NULL DEFAULT 0,
                passthrough INTEGER NOT NULL DEFAULT 0,
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                tcp_idle_timeout_seconds INTEGER,
                allowed_methods TEXT,
                allowed_ws_origins TEXT,
                udp_max_response_amplification_factor REAL,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                CONSTRAINT fk_proxies_upstream FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE RESTRICT,
                CONSTRAINT chk_proxies_backend_port CHECK (backend_port >= 0 AND backend_port <= 65535),
                CONSTRAINT chk_proxies_listen_port CHECK (listen_port IS NULL OR (listen_port >= 1 AND listen_port <= 65535)),
                CONSTRAINT chk_proxies_connect_timeout CHECK (backend_connect_timeout_ms > 0),
                CONSTRAINT chk_proxies_read_timeout CHECK (backend_read_timeout_ms > 0),
                CONSTRAINT chk_proxies_write_timeout CHECK (backend_write_timeout_ms > 0)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                name TEXT,
                hosts TEXT NOT NULL DEFAULT '[]',
                listen_path TEXT,
                backend_scheme TEXT NOT NULL DEFAULT 'https',
                backend_prefer_h3 INTEGER NOT NULL DEFAULT 0,
                backend_host TEXT NOT NULL,
                backend_port INTEGER NOT NULL DEFAULT 80,
                backend_path TEXT,
                strip_listen_path INTEGER NOT NULL DEFAULT 1,
                preserve_host_header INTEGER NOT NULL DEFAULT 0,
                backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
                backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                dns_override TEXT,
                dns_cache_ttl_seconds INTEGER,
                auth_mode TEXT NOT NULL DEFAULT 'single',
                upstream_id TEXT REFERENCES upstreams(id) ON DELETE RESTRICT,
                circuit_breaker TEXT,
                retry TEXT,
                response_body_mode TEXT NOT NULL DEFAULT 'stream',

                pool_idle_timeout_seconds INTEGER,
                pool_enable_http_keep_alive INTEGER,
                pool_enable_http2 INTEGER,
                pool_tcp_keepalive_seconds INTEGER,
                pool_http2_keep_alive_interval_seconds INTEGER,
                pool_http2_keep_alive_timeout_seconds INTEGER,
                pool_http2_initial_stream_window_size INTEGER,
                pool_http2_initial_connection_window_size INTEGER,
                pool_http2_adaptive_window INTEGER,
                pool_http2_max_frame_size INTEGER,
                pool_http2_max_concurrent_streams INTEGER,
                pool_http3_connections_per_backend INTEGER,
                listen_port INTEGER,
                frontend_tls INTEGER NOT NULL DEFAULT 0,
                passthrough INTEGER NOT NULL DEFAULT 0,
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                tcp_idle_timeout_seconds INTEGER,
                allowed_methods TEXT,
                allowed_ws_origins TEXT,
                udp_max_response_amplification_factor REAL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (backend_port >= 0 AND backend_port <= 65535),
                CHECK (listen_port IS NULL OR (listen_port >= 1 AND listen_port <= 65535)),
                CHECK (backend_connect_timeout_ms > 0),
                CHECK (backend_read_timeout_ms > 0),
                CHECK (backend_write_timeout_ms > 0)
            )
            "#
        }
    }

    fn create_plugin_configs_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id VARCHAR(255) PRIMARY KEY,
                namespace VARCHAR(255) NOT NULL DEFAULT 'ferrum',
                plugin_name VARCHAR(255) NOT NULL,
                config TEXT NOT NULL,
                scope VARCHAR(50) NOT NULL DEFAULT 'global',
                proxy_id VARCHAR(255),
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                CONSTRAINT fk_plugin_configs_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                plugin_name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                scope TEXT NOT NULL DEFAULT 'global',
                proxy_id TEXT REFERENCES proxies(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_proxy_plugins_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id VARCHAR(255) NOT NULL,
                plugin_config_id VARCHAR(255) NOT NULL,
                PRIMARY KEY (proxy_id, plugin_config_id),
                CONSTRAINT fk_proxy_plugins_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE,
                CONSTRAINT fk_proxy_plugins_plugin FOREIGN KEY (plugin_config_id) REFERENCES plugin_configs(id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                plugin_config_id TEXT NOT NULL REFERENCES plugin_configs(id) ON DELETE CASCADE,
                PRIMARY KEY (proxy_id, plugin_config_id)
            )
            "#
        }
    }

    fn unique_listen_port_sql(&self) -> &'static str {
        if self.is_mysql() {
            "CREATE UNIQUE INDEX idx_proxies_unique_listen_port ON proxies (namespace, listen_port)"
        } else {
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_unique_listen_port ON proxies (namespace, listen_port) WHERE listen_port IS NOT NULL"
        }
    }

    fn namespace_unique_index_sqls(&self) -> &'static [&'static str] {
        if self.is_mysql() {
            &[
                "CREATE UNIQUE INDEX idx_proxies_namespace_name ON proxies (namespace, name)",
                "CREATE UNIQUE INDEX idx_consumers_namespace_username ON consumers (namespace, username)",
                "CREATE UNIQUE INDEX idx_consumers_namespace_custom_id ON consumers (namespace, custom_id)",
                "CREATE UNIQUE INDEX idx_upstreams_namespace_name ON upstreams (namespace, name)",
            ]
        } else {
            &[
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_namespace_name ON proxies (namespace, name) WHERE name IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_consumers_namespace_username ON consumers (namespace, username)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_consumers_namespace_custom_id ON consumers (namespace, custom_id) WHERE custom_id IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_upstreams_namespace_name ON upstreams (namespace, name) WHERE name IS NOT NULL",
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SqlDialect, V001SqlBuilder};

    #[test]
    fn test_mysql_builder_uses_mysql_table_sql() {
        let builder = V001SqlBuilder::new("mysql");
        assert!(matches!(builder.dialect, SqlDialect::MySql));
        assert!(
            builder
                .create_upstreams_sql()
                .contains("id VARCHAR(255) PRIMARY KEY")
        );
        assert!(
            builder
                .unique_listen_port_sql()
                .contains("CREATE UNIQUE INDEX idx_proxies_unique_listen_port")
        );
    }

    #[test]
    fn test_sqlite_builder_uses_sqlite_specific_behavior() {
        let builder = V001SqlBuilder::new("sqlite");
        assert!(matches!(builder.dialect, SqlDialect::Sqlite));
        assert!(
            builder
                .create_upstreams_sql()
                .contains("DEFAULT CURRENT_TIMESTAMP")
        );
        assert!(
            builder
                .unique_listen_port_sql()
                .contains("WHERE listen_port IS NOT NULL")
        );
    }

    #[test]
    fn test_postgres_builder_uses_partial_unique_indexes() {
        let builder = V001SqlBuilder::new("postgres");
        assert!(matches!(builder.dialect, SqlDialect::Postgres));
        assert!(
            builder
                .namespace_unique_index_sqls()
                .iter()
                .any(|sql| sql.contains("WHERE name IS NOT NULL"))
        );
    }
}
