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
        "v001_initial_schema_a1b2c3d4"
    }
}

impl V001InitialSchema {
    pub async fn up(&self, pool: &AnyPool, _db_type: &str) -> Result<(), anyhow::Error> {
        let create_proxies = r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                name TEXT,
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        let create_consumers = r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                custom_id TEXT,
                credentials TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        let create_plugin_configs = r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id TEXT PRIMARY KEY,
                plugin_name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                scope TEXT NOT NULL DEFAULT 'global',
                proxy_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        let create_proxy_plugins = r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id TEXT NOT NULL,
                plugin_config_id TEXT NOT NULL,
                PRIMARY KEY (proxy_id, plugin_config_id)
            )
        "#;

        let create_upstreams = r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id TEXT PRIMARY KEY,
                name TEXT,
                targets TEXT NOT NULL DEFAULT '[]',
                algorithm TEXT NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                health_checks TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        sqlx::query(create_proxies).execute(pool).await?;
        sqlx::query(create_consumers).execute(pool).await?;
        sqlx::query(create_plugin_configs).execute(pool).await?;
        sqlx::query(create_proxy_plugins).execute(pool).await?;
        sqlx::query(create_upstreams).execute(pool).await?;

        Ok(())
    }
}
