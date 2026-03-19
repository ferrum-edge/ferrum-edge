use crate::config::types::{
    AuthMode, BackendProtocol, Consumer, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use chrono::Utc;
use sqlx::{AnyPool, any::AnyPoolOptions, any::AnyRow};
use sqlx::Row;
use tracing::{error, info};

/// Database configuration store.
#[derive(Clone)]
pub struct DatabaseStore {
    pool: AnyPool,
    db_type: String,
}

impl DatabaseStore {
    /// Connect to the database and run migrations.
    #[allow(dead_code)]
    pub async fn connect(db_type: &str, db_url: &str) -> Result<Self, anyhow::Error> {
        Self::connect_with_tls_config(
            db_type,
            db_url,
            false,
            None,
            None,
            None,
            false,
        )
        .await
    }

    /// Connect to the database with optional TLS configuration and run migrations.
    pub async fn connect_with_tls_config(
        db_type: &str,
        db_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<Self, anyhow::Error> {
        // Install all drivers
        sqlx::any::install_default_drivers();

        // Construct TLS-aware connection URL
        let final_url = if tls_enabled && (db_type == "postgres" || db_type == "mysql") {
            Self::build_tls_connection_url(
                db_url,
                db_type,
                tls_ca_cert_path,
                tls_client_cert_path,
                tls_client_key_path,
                tls_insecure,
            )?
        } else {
            db_url.to_string()
        };

        let pool = AnyPoolOptions::new()
            .max_connections(10)
            .connect(&final_url)
            .await?;

        let store = Self {
            pool,
            db_type: db_type.to_string(),
        };

        store.run_migrations().await?;

        info!("Database connected and migrations applied (type={}, tls_enabled={})", db_type, tls_enabled);
        Ok(store)
    }

    /// Build a TLS-aware connection URL for Postgres and MySQL.
    fn build_tls_connection_url(
        base_url: &str,
        db_type: &str,
        ca_cert_path: Option<&str>,
        client_cert_path: Option<&str>,
        client_key_path: Option<&str>,
        insecure: bool,
    ) -> Result<String, anyhow::Error> {
        let mut url = base_url.to_string();

        // Add a separator if the URL doesn't already have query parameters
        let separator = if url.contains('?') { '&' } else { '?' };

        match db_type {
            "postgres" => {
                if insecure {
                    url.push_str(&format!("{}sslmode=require", separator));
                } else {
                    url.push_str(&format!("{}sslmode=require", separator));
                    if let Some(ca_path) = ca_cert_path {
                        url.push_str(&format!("&sslrootcert={}", ca_path));
                    }
                    if let Some(cert_path) = client_cert_path {
                        url.push_str(&format!("&sslcert={}", cert_path));
                    }
                    if let Some(key_path) = client_key_path {
                        url.push_str(&format!("&sslkey={}", key_path));
                    }
                }
            }
            "mysql" => {
                if insecure {
                    url.push_str(&format!("{}ssl-mode=REQUIRED", separator));
                } else {
                    url.push_str(&format!("{}ssl-mode=REQUIRED", separator));
                    if let Some(ca_path) = ca_cert_path {
                        url.push_str(&format!("&ssl-ca={}", ca_path));
                    }
                    if let Some(cert_path) = client_cert_path {
                        url.push_str(&format!("&ssl-client-cert={}", cert_path));
                    }
                    if let Some(key_path) = client_key_path {
                        url.push_str(&format!("&ssl-client-key={}", key_path));
                    }
                }
            }
            _ => {
                // SQLite and others don't use network TLS
                info!("TLS configuration not supported for database type: {}", db_type);
            }
        }

        Ok(url)
    }

    /// Run schema migrations.
    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
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

        sqlx::query(create_proxies).execute(&self.pool).await?;
        sqlx::query(create_consumers).execute(&self.pool).await?;
        sqlx::query(create_plugin_configs)
            .execute(&self.pool)
            .await?;
        sqlx::query(create_proxy_plugins)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Load the full gateway configuration from the database.
    pub async fn load_full_config(&self) -> Result<GatewayConfig, anyhow::Error> {
        let proxies = self.load_proxies().await?;
        let consumers = self.load_consumers().await?;
        let plugin_configs = self.load_plugin_configs().await?;

        let config = GatewayConfig {
            proxies,
            consumers,
            plugin_configs,
            loaded_at: Utc::now(),
        };

        if let Err(dupes) = config.validate_unique_listen_paths() {
            for msg in &dupes {
                error!("{}", msg);
            }
            anyhow::bail!("Database has duplicate listen_path values");
        }

        Ok(config)
    }

    async fn load_proxies(&self) -> Result<Vec<Proxy>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM proxies")
            .fetch_all(&self.pool)
            .await?;

        let mut proxies = Vec::new();
        for row in rows {
            let id: String = row.try_get("id")?;

            // Load proxy plugin associations
            let assoc_rows: Vec<AnyRow> =
                sqlx::query("SELECT plugin_config_id FROM proxy_plugins WHERE proxy_id = ?")
                    .bind(&id)
                    .fetch_all(&self.pool)
                    .await
                    .unwrap_or_default();

            let plugins: Vec<PluginAssociation> = assoc_rows
                .iter()
                .map(|r| PluginAssociation {
                    plugin_config_id: r.try_get("plugin_config_id").unwrap_or_default(),
                })
                .collect();

            let proto_str: String = row.try_get("backend_protocol").unwrap_or("http".into());
            let auth_mode_str: String = row.try_get("auth_mode").unwrap_or("single".into());

            proxies.push(Proxy {
                id,
                name: row.try_get("name").ok(),
                listen_path: row.try_get("listen_path")?,
                backend_protocol: parse_protocol(&proto_str),
                backend_host: row.try_get("backend_host")?,
                backend_port: row
                    .try_get::<i32, _>("backend_port")
                    .map(|v| v as u16)
                    .unwrap_or(80),
                backend_path: row.try_get("backend_path").ok(),
                strip_listen_path: row.try_get::<i32, _>("strip_listen_path").unwrap_or(1) != 0,
                preserve_host_header: row
                    .try_get::<i32, _>("preserve_host_header")
                    .unwrap_or(0)
                    != 0,
                backend_connect_timeout_ms: row
                    .try_get::<i64, _>("backend_connect_timeout_ms")
                    .unwrap_or(5000) as u64,
                backend_read_timeout_ms: row
                    .try_get::<i64, _>("backend_read_timeout_ms")
                    .unwrap_or(30000) as u64,
                backend_write_timeout_ms: row
                    .try_get::<i64, _>("backend_write_timeout_ms")
                    .unwrap_or(30000) as u64,
                backend_tls_client_cert_path: row.try_get("backend_tls_client_cert_path").ok(),
                backend_tls_client_key_path: row.try_get("backend_tls_client_key_path").ok(),
                backend_tls_verify_server_cert: row
                    .try_get::<i32, _>("backend_tls_verify_server_cert")
                    .unwrap_or(1)
                    != 0,
                backend_tls_server_ca_cert_path: row
                    .try_get("backend_tls_server_ca_cert_path")
                    .ok(),
                dns_override: row.try_get("dns_override").ok(),
                dns_cache_ttl_seconds: row
                    .try_get::<i64, _>("dns_cache_ttl_seconds")
                    .ok()
                    .map(|v| v as u64),
                auth_mode: parse_auth_mode(&auth_mode_str),
                plugins,
                // Connection pooling settings - None to use global defaults
                pool_max_idle_per_host: None,
                pool_idle_timeout_seconds: None,
                pool_enable_http_keep_alive: None,
                pool_enable_http2: None,
                pool_tcp_keepalive_seconds: None,
                pool_http2_keep_alive_interval_seconds: None,
                pool_http2_keep_alive_timeout_seconds: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }

        Ok(proxies)
    }

    async fn load_consumers(&self) -> Result<Vec<Consumer>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM consumers")
            .fetch_all(&self.pool)
            .await?;

        let mut consumers = Vec::new();
        for row in rows {
            let creds_str: String = row.try_get("credentials").unwrap_or("{}".into());
            let credentials = serde_json::from_str(&creds_str).unwrap_or_default();

            consumers.push(Consumer {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                custom_id: row.try_get("custom_id").ok(),
                credentials,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }

        Ok(consumers)
    }

    async fn load_plugin_configs(&self) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM plugin_configs")
            .fetch_all(&self.pool)
            .await?;

        let mut configs = Vec::new();
        for row in rows {
            let config_str: String = row.try_get("config").unwrap_or("{}".into());
            let config_val = serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null);
            let scope_str: String = row.try_get("scope").unwrap_or("global".into());

            configs.push(PluginConfig {
                id: row.try_get("id")?,
                plugin_name: row.try_get("plugin_name")?,
                config: config_val,
                scope: if scope_str == "proxy" {
                    PluginScope::Proxy
                } else {
                    PluginScope::Global
                },
                proxy_id: row.try_get("proxy_id").ok(),
                enabled: row.try_get::<i32, _>("enabled").unwrap_or(1) != 0,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }

        Ok(configs)
    }

    // ---- CRUD for Admin API ----

    pub async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        sqlx::query(
            "INSERT INTO proxies (id, name, listen_path, backend_protocol, backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, auth_mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&proxy.id)
        .bind(&proxy.name)
        .bind(&proxy.listen_path)
        .bind(proxy.backend_protocol.to_string())
        .bind(&proxy.backend_host)
        .bind(proxy.backend_port as i32)
        .bind(&proxy.backend_path)
        .bind(if proxy.strip_listen_path { 1i32 } else { 0 })
        .bind(if proxy.preserve_host_header { 1i32 } else { 0 })
        .bind(proxy.backend_connect_timeout_ms as i64)
        .bind(proxy.backend_read_timeout_ms as i64)
        .bind(proxy.backend_write_timeout_ms as i64)
        .bind(match proxy.auth_mode { AuthMode::Multi => "multi", _ => "single" })
        .bind(proxy.created_at.to_rfc3339())
        .bind(proxy.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE proxies SET name=?, listen_path=?, backend_protocol=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, auth_mode=?, updated_at=? WHERE id=?"
        )
        .bind(&proxy.name)
        .bind(&proxy.listen_path)
        .bind(proxy.backend_protocol.to_string())
        .bind(&proxy.backend_host)
        .bind(proxy.backend_port as i32)
        .bind(&proxy.backend_path)
        .bind(if proxy.strip_listen_path { 1i32 } else { 0 })
        .bind(if proxy.preserve_host_header { 1i32 } else { 0 })
        .bind(proxy.backend_connect_timeout_ms as i64)
        .bind(proxy.backend_read_timeout_ms as i64)
        .bind(proxy.backend_write_timeout_ms as i64)
        .bind(match proxy.auth_mode { AuthMode::Multi => "multi", _ => "single" })
        .bind(Utc::now().to_rfc3339())
        .bind(&proxy.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        let result = sqlx::query("DELETE FROM proxies WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        let proxies = self.load_proxies().await?;
        Ok(proxies.into_iter().find(|p| p.id == id))
    }

    pub async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        sqlx::query(
            "INSERT INTO consumers (id, username, custom_id, credentials, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&consumer.id)
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(consumer.created_at.to_rfc3339())
        .bind(consumer.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        sqlx::query(
            "UPDATE consumers SET username=?, custom_id=?, credentials=?, updated_at=? WHERE id=?"
        )
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(Utc::now().to_rfc3339())
        .bind(&consumer.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_consumer(&self, id: &str) -> Result<bool, anyhow::Error> {
        let result = sqlx::query("DELETE FROM consumers WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_consumer(&self, id: &str) -> Result<Option<Consumer>, anyhow::Error> {
        let consumers = self.load_consumers().await?;
        Ok(consumers.into_iter().find(|c| c.id == id))
    }

    pub async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::Global => "global",
        };
        sqlx::query(
            "INSERT INTO plugin_configs (id, plugin_name, config, scope, proxy_id, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&pc.id)
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(pc.created_at.to_rfc3339())
        .bind(pc.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::Global => "global",
        };
        sqlx::query(
            "UPDATE plugin_configs SET plugin_name=?, config=?, scope=?, proxy_id=?, enabled=?, updated_at=? WHERE id=?"
        )
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(Utc::now().to_rfc3339())
        .bind(&pc.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error> {
        let result = sqlx::query("DELETE FROM plugin_configs WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error> {
        let configs = self.load_plugin_configs().await?;
        Ok(configs.into_iter().find(|c| c.id == id))
    }

    pub async fn check_listen_path_unique(
        &self,
        listen_path: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query("SELECT id FROM proxies WHERE listen_path = ? AND id != ?")
                .bind(listen_path)
                .bind(eid)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query("SELECT id FROM proxies WHERE listen_path = ?")
                .bind(listen_path)
                .fetch_all(&self.pool)
                .await?
        };
        Ok(rows.is_empty())
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn db_type(&self) -> &str {
        &self.db_type
    }
}

fn parse_protocol(s: &str) -> BackendProtocol {
    match s.to_lowercase().as_str() {
        "https" => BackendProtocol::Https,
        "ws" => BackendProtocol::Ws,
        "wss" => BackendProtocol::Wss,
        "grpc" => BackendProtocol::Grpc,
        _ => BackendProtocol::Http,
    }
}

fn parse_auth_mode(s: &str) -> AuthMode {
    match s.to_lowercase().as_str() {
        "multi" => AuthMode::Multi,
        _ => AuthMode::Single,
    }
}
