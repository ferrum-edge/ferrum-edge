use crate::config::types::{
    AuthMode, BackendProtocol, Consumer, GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm,
    PluginAssociation, PluginConfig, PluginScope, Proxy, Upstream, UpstreamTarget,
};
use chrono::Utc;
use sqlx::Row;
use sqlx::{AnyPool, any::AnyPoolOptions, any::AnyRow};
use tracing::{debug, error, info, warn};

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
        Self::connect_with_tls_config(db_type, db_url, false, None, None, None, false).await
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

        // Enable foreign key enforcement for SQLite (off by default)
        if db_type == "sqlite" {
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&pool)
                .await?;
        }

        let store = Self {
            pool,
            db_type: db_type.to_string(),
        };

        store.run_migrations().await?;

        info!(
            "Database connected and migrations applied (type={}, tls_enabled={})",
            db_type, tls_enabled
        );
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
                    // sslmode=require: encrypts but does NOT verify the server certificate
                    url.push_str(&format!("{}sslmode=require", separator));
                } else {
                    // sslmode=verify-full: encrypts AND verifies the server certificate
                    url.push_str(&format!("{}sslmode=verify-full", separator));
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
                    // REQUIRED: encrypts but does NOT verify the server certificate
                    url.push_str(&format!("{}ssl-mode=REQUIRED", separator));
                } else {
                    // VERIFY_IDENTITY: encrypts AND verifies the server certificate
                    url.push_str(&format!("{}ssl-mode=VERIFY_IDENTITY", separator));
                    if let Some(ca_path) = ca_cert_path {
                        url.push_str(&format!("&ssl-ca={}", ca_path));
                    }
                    if let Some(cert_path) = client_cert_path {
                        url.push_str(&format!("&ssl-cert={}", cert_path));
                    }
                    if let Some(key_path) = client_key_path {
                        url.push_str(&format!("&ssl-key={}", key_path));
                    }
                }
            }
            _ => {
                // SQLite and others don't use network TLS
                info!(
                    "TLS configuration not supported for database type: {}",
                    db_type
                );
            }
        }

        Ok(url)
    }

    /// Run versioned schema migrations using the MigrationRunner.
    ///
    /// This replaces the old inline `CREATE TABLE IF NOT EXISTS` approach with
    /// a tracked, versioned migration system. Existing databases are automatically
    /// detected and bootstrapped into the new system.
    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        use crate::config::migrations::MigrationRunner;

        let runner = MigrationRunner::new(self.pool.clone(), self.db_type.clone());
        let applied = runner.run_pending().await?;

        if applied.is_empty() {
            info!("Database schema is up to date");
        } else {
            for m in &applied {
                info!(
                    "Applied migration V{}: {} ({}ms)",
                    m.version, m.name, m.execution_time_ms
                );
            }
        }

        Ok(())
    }

    /// Load the full gateway configuration from the database.
    pub async fn load_full_config(&self) -> Result<GatewayConfig, anyhow::Error> {
        let proxies = self.load_proxies().await?;
        let consumers = self.load_consumers().await?;
        let plugin_configs = self.load_plugin_configs().await?;
        let upstreams = self.load_upstreams().await?;

        let config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            consumers,
            plugin_configs,
            upstreams,
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

        // Batch-load all proxy_plugins in one query (eliminates N+1)
        let assoc_rows: Vec<AnyRow> =
            match sqlx::query("SELECT proxy_id, plugin_config_id FROM proxy_plugins")
                .fetch_all(&self.pool)
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    error!("Failed to load proxy_plugins associations: {}", e);
                    Vec::new()
                }
            };

        let mut plugins_by_proxy: std::collections::HashMap<String, Vec<PluginAssociation>> =
            std::collections::HashMap::new();
        for r in &assoc_rows {
            let proxy_id: String = r.try_get("proxy_id").unwrap_or_default();
            let plugin_config_id: String = r.try_get("plugin_config_id").unwrap_or_default();
            plugins_by_proxy
                .entry(proxy_id)
                .or_default()
                .push(PluginAssociation { plugin_config_id });
        }

        let mut proxies = Vec::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            proxies.push(row_to_proxy(&row, id, plugins)?);
        }

        Ok(proxies)
    }

    async fn load_consumers(&self) -> Result<Vec<Consumer>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM consumers")
            .fetch_all(&self.pool)
            .await?;

        let mut consumers = Vec::new();
        for row in rows {
            consumers.push(row_to_consumer(&row)?);
        }

        Ok(consumers)
    }

    async fn load_plugin_configs(&self) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM plugin_configs")
            .fetch_all(&self.pool)
            .await?;

        let mut configs = Vec::new();
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }

        Ok(configs)
    }

    // ---- CRUD for Admin API ----

    pub async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        sqlx::query(
            "INSERT INTO proxies (id, name, listen_path, backend_protocol, backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, auth_mode, upstream_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
        .bind(&proxy.upstream_id)
        .bind(proxy.created_at.to_rfc3339())
        .bind(proxy.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Persist plugin associations in the junction table
        for assoc in &proxy.plugins {
            sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
                .bind(&proxy.id)
                .bind(&assoc.plugin_config_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    pub async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE proxies SET name=?, listen_path=?, backend_protocol=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, auth_mode=?, upstream_id=?, updated_at=? WHERE id=?"
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
        .bind(&proxy.upstream_id)
        .bind(Utc::now().to_rfc3339())
        .bind(&proxy.id)
        .execute(&self.pool)
        .await?;

        // Update plugin associations: remove old, insert new
        sqlx::query("DELETE FROM proxy_plugins WHERE proxy_id = ?")
            .bind(&proxy.id)
            .execute(&self.pool)
            .await?;

        for assoc in &proxy.plugins {
            sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
                .bind(&proxy.id)
                .bind(&assoc.plugin_config_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    pub async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        // Look up the proxy's upstream_id before deleting so we can cascade-delete
        // the upstream if it becomes orphaned.
        let upstream_id: Option<String> =
            sqlx::query("SELECT upstream_id FROM proxies WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .and_then(|row| row.try_get::<String, _>("upstream_id").ok());

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query("DELETE FROM proxy_plugins WHERE proxy_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM proxies WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Ok(false);
        }

        // If the proxy had an upstream, check if it's now orphaned and delete it
        if let Some(ref uid) = upstream_id
            && !self.is_upstream_referenced(uid).await?
        {
            info!("Cascade-deleting orphaned upstream {}", uid);
            sqlx::query("DELETE FROM upstreams WHERE id = ?")
                .bind(uid)
                .execute(&self.pool)
                .await?;
        }

        Ok(true)
    }

    pub async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query("SELECT * FROM proxies WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let assoc_rows: Vec<AnyRow> =
            match sqlx::query("SELECT plugin_config_id FROM proxy_plugins WHERE proxy_id = ?")
                .bind(id)
                .fetch_all(&self.pool)
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    error!("Failed to load plugin associations for proxy {}: {}", id, e);
                    Vec::new()
                }
            };

        let plugins: Vec<PluginAssociation> = assoc_rows
            .iter()
            .filter_map(|r| {
                r.try_get::<String, _>("plugin_config_id")
                    .ok()
                    .map(|plugin_config_id| PluginAssociation { plugin_config_id })
            })
            .collect();

        Ok(Some(row_to_proxy(&row, id.to_string(), plugins)?))
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
            "UPDATE consumers SET username=?, custom_id=?, credentials=?, updated_at=? WHERE id=?",
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
        let row: Option<AnyRow> = sqlx::query("SELECT * FROM consumers WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_consumer(&r)?)),
            None => Ok(None),
        }
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
        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query("DELETE FROM proxy_plugins WHERE plugin_config_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query("DELETE FROM plugin_configs WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query("SELECT * FROM plugin_configs WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_plugin_config(&r)?)),
            None => Ok(None),
        }
    }

    // ---- Upstream CRUD ----

    async fn load_upstreams(&self) -> Result<Vec<Upstream>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM upstreams")
            .fetch_all(&self.pool)
            .await?;

        let mut upstreams = Vec::new();
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }

        Ok(upstreams)
    }

    pub async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        // algo_json is quoted like "\"round_robin\"", strip the quotes
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(
            "INSERT INTO upstreams (id, name, targets, algorithm, hash_on, health_checks, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&upstream.id)
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&health_checks_json)
        .bind(upstream.created_at.to_rfc3339())
        .bind(upstream.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(
            "UPDATE upstreams SET name=?, targets=?, algorithm=?, hash_on=?, health_checks=?, updated_at=? WHERE id=?"
        )
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&health_checks_json)
        .bind(Utc::now().to_rfc3339())
        .bind(&upstream.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete an upstream only if it is not referenced by any proxy.
    /// Returns `Err` if the upstream is still in use.
    pub async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
        if self.is_upstream_referenced(id).await? {
            anyhow::bail!(
                "Upstream {} is referenced by one or more proxies and cannot be deleted",
                id
            );
        }

        let result = sqlx::query("DELETE FROM upstreams WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Check if any proxy references this upstream via upstream_id.
    pub async fn is_upstream_referenced(&self, upstream_id: &str) -> Result<bool, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1")
            .bind(upstream_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(!rows.is_empty())
    }

    /// When a proxy changes its upstream_id, clean up the old upstream if it
    /// became orphaned (no other proxies reference it).
    pub async fn cleanup_orphaned_upstream(
        &self,
        old_upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        if !self.is_upstream_referenced(old_upstream_id).await? {
            info!(
                "Cleaning up orphaned upstream {} after proxy reassignment",
                old_upstream_id
            );
            sqlx::query("DELETE FROM upstreams WHERE id = ?")
                .bind(old_upstream_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn get_upstream(&self, id: &str) -> Result<Option<Upstream>, anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query("SELECT * FROM upstreams WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_upstream(&r)?)),
            None => Ok(None),
        }
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
        "grpcs" => BackendProtocol::Grpcs,
        "h3" => BackendProtocol::H3,
        _ => BackendProtocol::Http,
    }
}

fn parse_auth_mode(s: &str) -> AuthMode {
    match s.to_lowercase().as_str() {
        "multi" => AuthMode::Multi,
        _ => AuthMode::Single,
    }
}

/// Parse a proxy row into a Proxy struct (shared by load_proxies and get_proxy).
fn row_to_proxy(
    row: &AnyRow,
    id: String,
    plugins: Vec<PluginAssociation>,
) -> Result<Proxy, anyhow::Error> {
    let proto_str: String = row.try_get("backend_protocol").unwrap_or("http".into());
    let auth_mode_str: String = row.try_get("auth_mode").unwrap_or("single".into());

    Ok(Proxy {
        id,
        name: row.try_get("name").ok(),
        listen_path: row.try_get("listen_path")?,
        backend_protocol: parse_protocol(&proto_str),
        backend_host: row.try_get("backend_host")?,
        backend_port: row
            .try_get::<i32, _>("backend_port")
            .map(|v| v.clamp(0, 65535) as u16)
            .unwrap_or(80),
        backend_path: row.try_get("backend_path").ok(),
        strip_listen_path: row.try_get::<i32, _>("strip_listen_path").unwrap_or(1) != 0,
        preserve_host_header: row.try_get::<i32, _>("preserve_host_header").unwrap_or(0) != 0,
        backend_connect_timeout_ms: row
            .try_get::<i64, _>("backend_connect_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(5000),
        backend_read_timeout_ms: row
            .try_get::<i64, _>("backend_read_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(30000),
        backend_write_timeout_ms: row
            .try_get::<i64, _>("backend_write_timeout_ms")
            .map(|v| v.max(0) as u64)
            .unwrap_or(30000),
        backend_tls_client_cert_path: row.try_get("backend_tls_client_cert_path").ok(),
        backend_tls_client_key_path: row.try_get("backend_tls_client_key_path").ok(),
        backend_tls_verify_server_cert: row
            .try_get::<i32, _>("backend_tls_verify_server_cert")
            .unwrap_or(1)
            != 0,
        backend_tls_server_ca_cert_path: row.try_get("backend_tls_server_ca_cert_path").ok(),
        dns_override: row.try_get("dns_override").ok(),
        dns_cache_ttl_seconds: row
            .try_get::<i64, _>("dns_cache_ttl_seconds")
            .ok()
            .map(|v| v as u64),
        auth_mode: parse_auth_mode(&auth_mode_str),
        plugins,
        upstream_id: row.try_get::<String, _>("upstream_id").ok(),
        circuit_breaker: None,
        retry: None,
        response_body_mode: crate::config::types::ResponseBodyMode::default(),
        pool_max_idle_per_host: None,
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a consumer row into a Consumer struct.
fn row_to_consumer(row: &AnyRow) -> Result<Consumer, anyhow::Error> {
    let creds_str: String = row.try_get("credentials").unwrap_or("{}".into());
    let credentials = serde_json::from_str(&creds_str).unwrap_or_else(|e| {
        warn!("Failed to parse credentials JSON for consumer: {}", e);
        std::collections::HashMap::new()
    });

    Ok(Consumer {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        custom_id: row.try_get("custom_id").ok(),
        credentials,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a plugin_config row into a PluginConfig struct.
fn row_to_plugin_config(row: &AnyRow) -> Result<PluginConfig, anyhow::Error> {
    let config_str: String = row.try_get("config").unwrap_or("{}".into());
    let config_val = serde_json::from_str(&config_str).unwrap_or_else(|e| {
        warn!("Failed to parse plugin config JSON: {}", e);
        serde_json::Value::Null
    });
    let scope_str: String = row.try_get("scope").unwrap_or("global".into());

    Ok(PluginConfig {
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
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse an upstream row into an Upstream struct.
fn row_to_upstream(row: &AnyRow) -> Result<Upstream, anyhow::Error> {
    let targets_str: String = row.try_get("targets").unwrap_or("[]".into());
    let targets: Vec<UpstreamTarget> = serde_json::from_str(&targets_str).unwrap_or_default();

    let algo_str: String = row.try_get("algorithm").unwrap_or("round_robin".into());
    let algorithm: LoadBalancerAlgorithm =
        serde_json::from_value(serde_json::Value::String(algo_str)).unwrap_or_default();

    let health_checks: Option<HealthCheckConfig> = row
        .try_get::<String, _>("health_checks")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    Ok(Upstream {
        id: row.try_get("id")?,
        name: row.try_get("name").ok(),
        targets,
        algorithm,
        hash_on: row.try_get("hash_on").ok(),
        health_checks,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a datetime column from a database row, falling back to `Utc::now()` if
/// the column is missing or the value cannot be parsed. Database stores timestamps
/// as RFC 3339 strings or SQLite `CURRENT_TIMESTAMP` format.
fn parse_datetime_column(row: &AnyRow, column: &str) -> chrono::DateTime<Utc> {
    row.try_get::<String, _>(column)
        .ok()
        .and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
                .or_else(|| {
                    // SQLite CURRENT_TIMESTAMP format: "YYYY-MM-DD HH:MM:SS"
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                        .map(|ndt| ndt.and_utc())
                        .ok()
                })
        })
        .unwrap_or_else(|| {
            debug!(
                "Could not parse '{}' column, falling back to Utc::now()",
                column
            );
            Utc::now()
        })
}
