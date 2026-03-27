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
        "v001_initial_schema_fk_constraints_indexes_full_proxy_fields_updated_at_indexes_mysql_compat_hosts_service_discovery"
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

        // MySQL strict mode forbids DEFAULT values on TEXT/BLOB columns, so
        // MySQL uses VARCHAR(N) for columns that need defaults, and TEXT columns
        // that held JSON defaults use explicit non-null constraints instead (the
        // application always provides these values on INSERT).
        //
        // Timestamp columns use VARCHAR(50) instead of DATETIME because sqlx's
        // Any driver cannot map MySQL's Datetime type to String. The application
        // always provides RFC3339 values via bind params. MySQL also requires
        // explicit FK constraint syntax.
        let is_mysql = db_type == "mysql";

        // Upstreams must be created first (referenced by proxies)
        let create_upstreams = if is_mysql {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) UNIQUE,
                targets TEXT NOT NULL,
                algorithm VARCHAR(50) NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                targets TEXT NOT NULL DEFAULT '[]',
                algorithm TEXT NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        };

        let create_consumers = if is_mysql {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id VARCHAR(255) PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                custom_id VARCHAR(255) UNIQUE,
                credentials TEXT NOT NULL,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                custom_id TEXT UNIQUE,
                credentials TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        };

        // Proxies reference upstreams via FK
        let create_proxies = if is_mysql {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) UNIQUE,
                hosts TEXT NOT NULL,
                listen_path VARCHAR(500) NOT NULL,
                backend_protocol VARCHAR(20) NOT NULL DEFAULT 'http',
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
                pool_max_idle_per_host INTEGER,
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
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                CONSTRAINT fk_proxies_upstream FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE RESTRICT
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                hosts TEXT NOT NULL DEFAULT '[]',
                listen_path TEXT NOT NULL,
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
                pool_http2_initial_stream_window_size INTEGER,
                pool_http2_initial_connection_window_size INTEGER,
                pool_http2_adaptive_window INTEGER,
                pool_http2_max_frame_size INTEGER,
                pool_http2_max_concurrent_streams INTEGER,
                pool_http3_connections_per_backend INTEGER,
                listen_port INTEGER,
                frontend_tls INTEGER NOT NULL DEFAULT 0,
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        };

        // Plugin configs reference proxies via FK (proxy-scoped plugins cascade on proxy delete)
        let create_plugin_configs = if is_mysql {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id VARCHAR(255) PRIMARY KEY,
                plugin_name VARCHAR(255) NOT NULL,
                config TEXT NOT NULL,
                scope VARCHAR(50) NOT NULL DEFAULT 'global',
                proxy_id VARCHAR(255),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                CONSTRAINT fk_plugin_configs_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
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
            "#
        };

        // Junction table with FKs to both proxies and plugin_configs
        let create_proxy_plugins = if is_mysql {
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
        };

        sqlx::query(create_upstreams).execute(pool).await?;
        sqlx::query(create_consumers).execute(pool).await?;
        sqlx::query(create_proxies).execute(pool).await?;
        sqlx::query(create_plugin_configs).execute(pool).await?;
        sqlx::query(create_proxy_plugins).execute(pool).await?;

        // Indexes on foreign key columns for query performance.
        // MySQL < 8.0.29 does not support CREATE INDEX IF NOT EXISTS, so we
        // use a helper that catches "index already exists" errors on MySQL.
        let indexes = &[
            "CREATE INDEX IF NOT EXISTS idx_proxies_upstream_id ON proxies (upstream_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_proxy_id ON plugin_configs (proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_plugin_config_id ON proxy_plugins (plugin_config_id)",
            // Indexes on updated_at columns for incremental polling queries
            "CREATE INDEX IF NOT EXISTS idx_proxies_updated_at ON proxies (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_updated_at ON consumers (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_updated_at ON plugin_configs (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_updated_at ON upstreams (updated_at)",
        ];

        for idx_sql in indexes {
            if is_mysql {
                // MySQL: strip "IF NOT EXISTS" and tolerate duplicate key errors
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
        }

        Ok(())
    }
}
