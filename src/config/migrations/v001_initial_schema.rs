use sqlx::AnyPool;

use super::Migration;

/// V1: Initial schema — creates the baseline tables.
/// This matches the original inline schema from db_loader.rs.
pub struct V001InitialSchema;

impl Migration for V001InitialSchema {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "initial_schema"
    }

    fn checksum(&self) -> &str {
        "v001_initial_schema_fk_constraints_indexes_full_proxy_fields_updated_at_indexes"
    }
}

impl V001InitialSchema {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        // Enable foreign key enforcement for SQLite (off by default)
        if db_type == "sqlite" {
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(pool)
                .await?;
        }

        // Upstreams must be created first (referenced by proxies)
        let create_upstreams = r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                targets TEXT NOT NULL DEFAULT '[]',
                algorithm TEXT NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                health_checks TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        let create_consumers = r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                custom_id TEXT UNIQUE,
                credentials TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        // Proxies reference upstreams via FK
        let create_proxies = r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                listen_path TEXT NOT NULL UNIQUE,
                backend_protocol TEXT NOT NULL DEFAULT 'http',
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
                pool_max_idle_per_host INTEGER,
                pool_idle_timeout_seconds INTEGER,
                pool_enable_http_keep_alive INTEGER,
                pool_enable_http2 INTEGER,
                pool_tcp_keepalive_seconds INTEGER,
                pool_http2_keep_alive_interval_seconds INTEGER,
                pool_http2_keep_alive_timeout_seconds INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        // Plugin configs reference proxies via FK (proxy-scoped plugins cascade on proxy delete)
        let create_plugin_configs = r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id TEXT PRIMARY KEY,
                plugin_name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                scope TEXT NOT NULL DEFAULT 'global',
                proxy_id TEXT REFERENCES proxies(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        // Junction table with FKs to both proxies and plugin_configs
        let create_proxy_plugins = r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                plugin_config_id TEXT NOT NULL REFERENCES plugin_configs(id) ON DELETE CASCADE,
                PRIMARY KEY (proxy_id, plugin_config_id)
            )
        "#;

        sqlx::query(create_upstreams).execute(pool).await?;
        sqlx::query(create_consumers).execute(pool).await?;
        sqlx::query(create_proxies).execute(pool).await?;
        sqlx::query(create_plugin_configs).execute(pool).await?;
        sqlx::query(create_proxy_plugins).execute(pool).await?;

        // Indexes on foreign key columns for query performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_proxies_upstream_id ON proxies (upstream_id)")
            .execute(pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_proxy_id ON plugin_configs (proxy_id)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_plugin_config_id ON proxy_plugins (plugin_config_id)",
        )
        .execute(pool)
        .await?;

        // Indexes on updated_at columns for incremental polling queries
        // (SELECT * FROM X WHERE updated_at > ? uses index scan instead of full table scan)
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_proxies_updated_at ON proxies (updated_at)")
            .execute(pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_consumers_updated_at ON consumers (updated_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_updated_at ON plugin_configs (updated_at)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_upstreams_updated_at ON upstreams (updated_at)",
        )
        .execute(pool)
        .await?;

        Ok(())
    }
}
