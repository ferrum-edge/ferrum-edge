use crate::config::types::{
    AuthMode, BackendProtocol, CircuitBreakerConfig, Consumer, GatewayConfig, HealthCheckConfig,
    LoadBalancerAlgorithm, PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode,
    RetryConfig, Upstream, UpstreamTarget,
};
use chrono::{DateTime, Duration, Utc};
use sqlx::Executor;
use sqlx::Row;
use sqlx::{AnyPool, any::AnyPoolOptions, any::AnyRow};
use std::collections::HashSet;
use tracing::{debug, error, info, warn};

/// Result of an incremental config poll.
///
/// Contains only the resources that changed since the last poll, plus IDs of
/// resources that were deleted. The polling loop uses this to apply surgical
/// updates without loading the entire database.
pub struct IncrementalResult {
    pub added_or_modified_proxies: Vec<Proxy>,
    pub removed_proxy_ids: Vec<String>,
    pub added_or_modified_consumers: Vec<Consumer>,
    pub removed_consumer_ids: Vec<String>,
    pub added_or_modified_plugin_configs: Vec<PluginConfig>,
    pub removed_plugin_config_ids: Vec<String>,
    pub added_or_modified_upstreams: Vec<Upstream>,
    pub removed_upstream_ids: Vec<String>,
    /// Timestamp to use as `since` for the next incremental poll.
    pub poll_timestamp: DateTime<Utc>,
}

impl IncrementalResult {
    /// True when nothing changed — skip all cache work.
    pub fn is_empty(&self) -> bool {
        self.added_or_modified_proxies.is_empty()
            && self.removed_proxy_ids.is_empty()
            && self.added_or_modified_consumers.is_empty()
            && self.removed_consumer_ids.is_empty()
            && self.added_or_modified_plugin_configs.is_empty()
            && self.removed_plugin_config_ids.is_empty()
            && self.added_or_modified_upstreams.is_empty()
            && self.removed_upstream_ids.is_empty()
    }
}

/// Database configuration store.
#[derive(Clone)]
pub struct DatabaseStore {
    pool: AnyPool,
    db_type: String,
}

impl DatabaseStore {
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

        let is_sqlite = db_type == "sqlite";
        let pool = AnyPoolOptions::new()
            .max_connections(10)
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    // Enable foreign key enforcement on every SQLite connection
                    // (PRAGMA is per-connection, not persistent across pool connections)
                    if is_sqlite {
                        conn.execute("PRAGMA foreign_keys = ON").await?;
                    }
                    Ok(())
                })
            })
            .connect(&final_url)
            .await?;

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
            info!("Applied {} migration(s)", applied.len());
        }

        Ok(())
    }

    /// Load the full gateway configuration from the database.
    pub async fn load_full_config(&self) -> Result<GatewayConfig, anyhow::Error> {
        let proxies = self.load_proxies().await?;
        let consumers = self.load_consumers().await?;
        let plugin_configs = self.load_plugin_configs().await?;
        let upstreams = self.load_upstreams().await?;

        let mut config = GatewayConfig {
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

        // Validate stream proxy (TCP/UDP) configuration
        if let Err(errors) = config.validate_stream_proxies() {
            for msg in &errors {
                error!("{}", msg);
            }
            anyhow::bail!(
                "Database configuration validation failed: {} stream proxy error(s) found",
                errors.len()
            );
        }

        // Normalize stream proxy listen_paths to synthetic values (__tcp:PORT, __udp:PORT)
        config.normalize_stream_proxy_paths();

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
            let proxy_id: String = match r.try_get("proxy_id") {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to read proxy_id from proxy_plugins row: {}", e);
                    continue;
                }
            };
            let plugin_config_id: String = match r.try_get("plugin_config_id") {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Failed to read plugin_config_id from proxy_plugins row (proxy_id={}): {}",
                        proxy_id, e
                    );
                    continue;
                }
            };
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
        let circuit_breaker_json = proxy
            .circuit_breaker
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let retry_json = proxy
            .retry
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let response_body_mode_str = match proxy.response_body_mode {
            ResponseBodyMode::Buffer => "buffer",
            ResponseBodyMode::Stream => "stream",
        };

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO proxies (id, name, listen_path, backend_protocol, backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, circuit_breaker, retry, response_body_mode, pool_max_idle_per_host, pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, pool_http2_keep_alive_timeout_seconds, listen_port, frontend_tls, udp_idle_timeout_seconds, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
        .bind(&proxy.backend_tls_client_cert_path)
        .bind(&proxy.backend_tls_client_key_path)
        .bind(if proxy.backend_tls_verify_server_cert { 1i32 } else { 0 })
        .bind(&proxy.backend_tls_server_ca_cert_path)
        .bind(&proxy.dns_override)
        .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
        .bind(match proxy.auth_mode { AuthMode::Multi => "multi", _ => "single" })
        .bind(&proxy.upstream_id)
        .bind(&circuit_breaker_json)
        .bind(&retry_json)
        .bind(response_body_mode_str)
        .bind(proxy.pool_max_idle_per_host.map(|v| v as i64))
        .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_enable_http_keep_alive.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
        .bind(proxy.listen_port.map(|v| v as i32))
        .bind(if proxy.frontend_tls { 1i32 } else { 0 })
        .bind(proxy.udp_idle_timeout_seconds as i64)
        .bind(proxy.created_at.to_rfc3339())
        .bind(proxy.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;

        // Persist plugin associations in the junction table
        for assoc in &proxy.plugins {
            sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
                .bind(&proxy.id)
                .bind(&assoc.plugin_config_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    pub async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        let circuit_breaker_json = proxy
            .circuit_breaker
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let retry_json = proxy
            .retry
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let response_body_mode_str = match proxy.response_body_mode {
            ResponseBodyMode::Buffer => "buffer",
            ResponseBodyMode::Stream => "stream",
        };

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "UPDATE proxies SET name=?, listen_path=?, backend_protocol=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, dns_override=?, dns_cache_ttl_seconds=?, auth_mode=?, upstream_id=?, circuit_breaker=?, retry=?, response_body_mode=?, pool_max_idle_per_host=?, pool_idle_timeout_seconds=?, pool_enable_http_keep_alive=?, pool_enable_http2=?, pool_tcp_keepalive_seconds=?, pool_http2_keep_alive_interval_seconds=?, pool_http2_keep_alive_timeout_seconds=?, listen_port=?, frontend_tls=?, udp_idle_timeout_seconds=?, updated_at=? WHERE id=?"
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
        .bind(&proxy.backend_tls_client_cert_path)
        .bind(&proxy.backend_tls_client_key_path)
        .bind(if proxy.backend_tls_verify_server_cert { 1i32 } else { 0 })
        .bind(&proxy.backend_tls_server_ca_cert_path)
        .bind(&proxy.dns_override)
        .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
        .bind(match proxy.auth_mode { AuthMode::Multi => "multi", _ => "single" })
        .bind(&proxy.upstream_id)
        .bind(&circuit_breaker_json)
        .bind(&retry_json)
        .bind(response_body_mode_str)
        .bind(proxy.pool_max_idle_per_host.map(|v| v as i64))
        .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_enable_http_keep_alive.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
        .bind(proxy.listen_port.map(|v| v as i32))
        .bind(if proxy.frontend_tls { 1i32 } else { 0 })
        .bind(proxy.udp_idle_timeout_seconds as i64)
        .bind(Utc::now().to_rfc3339())
        .bind(&proxy.id)
        .execute(&mut *tx)
        .await?;

        // Update plugin associations: remove old, insert new
        sqlx::query("DELETE FROM proxy_plugins WHERE proxy_id = ?")
            .bind(&proxy.id)
            .execute(&mut *tx)
            .await?;

        for assoc in &proxy.plugins {
            sqlx::query("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)")
                .bind(&proxy.id)
                .bind(&assoc.plugin_config_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    pub async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        let mut tx = self.pool.begin().await?;

        // Look up the proxy's upstream_id before deleting so we can cascade-delete
        // the upstream if it becomes orphaned.
        let upstream_id: Option<String> =
            sqlx::query("SELECT upstream_id FROM proxies WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| row.try_get::<String, _>("upstream_id").ok());

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query("DELETE FROM proxy_plugins WHERE proxy_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query("DELETE FROM proxies WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        // If the proxy had an upstream, check if it's now orphaned and delete it
        if let Some(ref uid) = upstream_id {
            let ref_rows: Vec<AnyRow> =
                sqlx::query("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1")
                    .bind(uid)
                    .fetch_all(&mut *tx)
                    .await?;
            if ref_rows.is_empty() {
                info!("Cascade-deleting orphaned upstream {}", uid);
                sqlx::query("DELETE FROM upstreams WHERE id = ?")
                    .bind(uid)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;

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
            .filter_map(|r| match r.try_get::<String, _>("plugin_config_id") {
                Ok(plugin_config_id) => Some(PluginAssociation { plugin_config_id }),
                Err(e) => {
                    warn!("Failed to read plugin_config_id for proxy {}: {}", id, e);
                    None
                }
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
        let mut tx = self.pool.begin().await?;

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query("DELETE FROM proxy_plugins WHERE plugin_config_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM plugin_configs WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

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
    /// Uses a transaction to prevent race conditions between the reference
    /// check and the delete.
    pub async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
        let mut tx = self.pool.begin().await?;

        // Check reference within the transaction to prevent races
        let ref_rows: Vec<AnyRow> =
            sqlx::query("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        if !ref_rows.is_empty() {
            tx.rollback().await?;
            anyhow::bail!(
                "Upstream {} is referenced by one or more proxies and cannot be deleted",
                id
            );
        }

        let result = sqlx::query("DELETE FROM upstreams WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(result.rows_affected() > 0)
    }

    /// When a proxy changes its upstream_id, clean up the old upstream if it
    /// became orphaned (no other proxies reference it).
    /// Uses a transaction to prevent race conditions between check and delete.
    pub async fn cleanup_orphaned_upstream(
        &self,
        old_upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        let mut tx = self.pool.begin().await?;

        let ref_rows: Vec<AnyRow> =
            sqlx::query("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1")
                .bind(old_upstream_id)
                .fetch_all(&mut *tx)
                .await?;

        if ref_rows.is_empty() {
            info!(
                "Cleaning up orphaned upstream {} after proxy reassignment",
                old_upstream_id
            );
            sqlx::query("DELETE FROM upstreams WHERE id = ?")
                .bind(old_upstream_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

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

    /// Check if a proxy name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_proxy_name_unique(
        &self,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query("SELECT id FROM proxies WHERE name = ? AND id != ?")
                .bind(name)
                .bind(eid)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query("SELECT id FROM proxies WHERE name = ?")
                .bind(name)
                .fetch_all(&self.pool)
                .await?
        };
        Ok(rows.is_empty())
    }

    /// Check if an upstream name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_upstream_name_unique(
        &self,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query("SELECT id FROM upstreams WHERE name = ? AND id != ?")
                .bind(name)
                .bind(eid)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query("SELECT id FROM upstreams WHERE name = ?")
                .bind(name)
                .fetch_all(&self.pool)
                .await?
        };
        Ok(rows.is_empty())
    }

    /// Check if a keyauth API key is unique across all consumers.
    /// Returns `true` if the key is unique (no conflicts found).
    ///
    /// Since the API key is stored inside the credentials JSON blob,
    /// this loads all consumers and checks in application code.
    pub async fn check_keyauth_key_unique(
        &self,
        api_key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT id, credentials FROM consumers")
            .fetch_all(&self.pool)
            .await?;

        for row in &rows {
            let id: String = row.try_get("id")?;
            if let Some(eid) = exclude_consumer_id
                && id == eid
            {
                continue;
            }
            let creds_str: String = row.try_get("credentials").unwrap_or_else(|e| {
                warn!(
                    "Failed to read credentials column for consumer {}: {}",
                    id, e
                );
                String::new()
            });
            if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&creds_str)
                && let Some(key) = creds
                    .get("keyauth")
                    .and_then(|k| k.get("key"))
                    .and_then(|k| k.as_str())
                && key == api_key
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check if an upstream with the given ID exists.
    /// Returns `true` if the upstream exists.
    pub async fn check_upstream_exists(&self, upstream_id: &str) -> Result<bool, anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query("SELECT id FROM upstreams WHERE id = ?")
            .bind(upstream_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    // ---- Incremental Polling ----

    /// Load only resources that changed since `since`, and detect deletions by
    /// comparing current DB IDs against the caller's known ID sets.
    ///
    /// This replaces `load_full_config()` for subsequent polls after the initial
    /// full load, reducing DB I/O from 4 full table scans to 4 indexed
    /// `WHERE updated_at > ?` queries plus 4 lightweight `SELECT id` queries.
    pub async fn load_incremental_config(
        &self,
        since: DateTime<Utc>,
        known_proxy_ids: &HashSet<String>,
        known_consumer_ids: &HashSet<String>,
        known_plugin_config_ids: &HashSet<String>,
        known_upstream_ids: &HashSet<String>,
    ) -> Result<IncrementalResult, anyhow::Error> {
        let poll_timestamp = Utc::now();

        // Subtract 1 second safety margin to handle boundary writes
        let since_safe = since - Duration::seconds(1);
        let since_str = since_safe.to_rfc3339();

        // Fetch changed rows (indexed scan via updated_at index)
        let changed_proxies = self.load_proxies_since(&since_str).await?;
        let changed_consumers = self.load_consumers_since(&since_str).await?;
        let changed_plugin_configs = self.load_plugin_configs_since(&since_str).await?;
        let changed_upstreams = self.load_upstreams_since(&since_str).await?;

        // Fetch current IDs (lightweight — one TEXT column per table)
        let current_proxy_ids = self.load_table_ids("proxies").await?;
        let current_consumer_ids = self.load_table_ids("consumers").await?;
        let current_plugin_config_ids = self.load_table_ids("plugin_configs").await?;
        let current_upstream_ids = self.load_table_ids("upstreams").await?;

        // Detect deletions: IDs we knew about that no longer exist
        let removed_proxy_ids = diff_removed(known_proxy_ids, &current_proxy_ids);
        let removed_consumer_ids = diff_removed(known_consumer_ids, &current_consumer_ids);
        let removed_plugin_config_ids =
            diff_removed(known_plugin_config_ids, &current_plugin_config_ids);
        let removed_upstream_ids = diff_removed(known_upstream_ids, &current_upstream_ids);

        let result = IncrementalResult {
            added_or_modified_proxies: changed_proxies,
            removed_proxy_ids,
            added_or_modified_consumers: changed_consumers,
            removed_consumer_ids,
            added_or_modified_plugin_configs: changed_plugin_configs,
            removed_plugin_config_ids,
            added_or_modified_upstreams: changed_upstreams,
            removed_upstream_ids,
            poll_timestamp,
        };

        if result.is_empty() {
            debug!("Incremental poll: no changes detected");
        } else {
            info!(
                "Incremental poll: {} proxies, {} consumers, {} plugins, {} upstreams changed; {} proxies, {} consumers, {} plugins, {} upstreams removed",
                result.added_or_modified_proxies.len(),
                result.added_or_modified_consumers.len(),
                result.added_or_modified_plugin_configs.len(),
                result.added_or_modified_upstreams.len(),
                result.removed_proxy_ids.len(),
                result.removed_consumer_ids.len(),
                result.removed_plugin_config_ids.len(),
                result.removed_upstream_ids.len(),
            );
        }

        Ok(result)
    }

    /// Load proxies modified since `since_str` (RFC 3339 timestamp).
    async fn load_proxies_since(&self, since_str: &str) -> Result<Vec<Proxy>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM proxies WHERE updated_at > ?")
            .bind(since_str)
            .fetch_all(&self.pool)
            .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Batch-load proxy_plugins only for the changed proxy IDs
        let changed_ids: HashSet<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect();

        let assoc_rows: Vec<AnyRow> =
            sqlx::query("SELECT proxy_id, plugin_config_id FROM proxy_plugins")
                .fetch_all(&self.pool)
                .await
                .unwrap_or_default();

        let mut plugins_by_proxy: std::collections::HashMap<String, Vec<PluginAssociation>> =
            std::collections::HashMap::new();
        for r in &assoc_rows {
            if let Ok(proxy_id) = r.try_get::<String, _>("proxy_id")
                && changed_ids.contains(&proxy_id)
                && let Ok(plugin_config_id) = r.try_get::<String, _>("plugin_config_id")
            {
                plugins_by_proxy
                    .entry(proxy_id)
                    .or_default()
                    .push(PluginAssociation { plugin_config_id });
            }
        }

        let mut proxies = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            proxies.push(row_to_proxy(row, id, plugins)?);
        }

        Ok(proxies)
    }

    /// Load consumers modified since `since_str`.
    async fn load_consumers_since(&self, since_str: &str) -> Result<Vec<Consumer>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM consumers WHERE updated_at > ?")
            .bind(since_str)
            .fetch_all(&self.pool)
            .await?;

        let mut consumers = Vec::with_capacity(rows.len());
        for row in rows {
            consumers.push(row_to_consumer(&row)?);
        }
        Ok(consumers)
    }

    /// Load plugin configs modified since `since_str`.
    async fn load_plugin_configs_since(
        &self,
        since_str: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM plugin_configs WHERE updated_at > ?")
            .bind(since_str)
            .fetch_all(&self.pool)
            .await?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }
        Ok(configs)
    }

    /// Load upstreams modified since `since_str`.
    async fn load_upstreams_since(&self, since_str: &str) -> Result<Vec<Upstream>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query("SELECT * FROM upstreams WHERE updated_at > ?")
            .bind(since_str)
            .fetch_all(&self.pool)
            .await?;

        let mut upstreams = Vec::with_capacity(rows.len());
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }
        Ok(upstreams)
    }

    /// Load all IDs from a table (lightweight — one TEXT column, no deserialization).
    async fn load_table_ids(&self, table: &str) -> Result<HashSet<String>, anyhow::Error> {
        // Table name is a compile-time constant from the caller, not user input.
        let sql = format!("SELECT id FROM {}", table);
        let rows: Vec<AnyRow> = sqlx::query(&sql).fetch_all(&self.pool).await?;

        let mut ids = HashSet::with_capacity(rows.len());
        for row in rows {
            if let Ok(id) = row.try_get::<String, _>("id") {
                ids.insert(id);
            }
        }
        Ok(ids)
    }

    /// Extract known IDs from a full config (used to seed the incremental poller).
    pub fn extract_known_ids(
        config: &GatewayConfig,
    ) -> (
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
    ) {
        let proxy_ids: HashSet<String> = config.proxies.iter().map(|p| p.id.clone()).collect();
        let consumer_ids: HashSet<String> = config.consumers.iter().map(|c| c.id.clone()).collect();
        let plugin_config_ids: HashSet<String> = config
            .plugin_configs
            .iter()
            .map(|pc| pc.id.clone())
            .collect();
        let upstream_ids: HashSet<String> = config.upstreams.iter().map(|u| u.id.clone()).collect();
        (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids)
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn db_type(&self) -> &str {
        &self.db_type
    }
}

/// IDs in `known` that are not in `current` (i.e., deleted resources).
fn diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
    known.difference(current).cloned().collect()
}

fn parse_protocol(s: &str) -> BackendProtocol {
    match s.to_lowercase().as_str() {
        "https" => BackendProtocol::Https,
        "ws" => BackendProtocol::Ws,
        "wss" => BackendProtocol::Wss,
        "grpc" => BackendProtocol::Grpc,
        "grpcs" => BackendProtocol::Grpcs,
        "h3" => BackendProtocol::H3,
        "tcp" => BackendProtocol::Tcp,
        "tcp_tls" => BackendProtocol::TcpTls,
        "udp" => BackendProtocol::Udp,
        "dtls" => BackendProtocol::Dtls,
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
    // Clone id for use in warning messages (the original is moved into the Proxy struct).
    let pid = id.clone();
    let proto_str: String = row.try_get("backend_protocol").unwrap_or_else(|e| {
        warn!(
            "Proxy {}: failed to read backend_protocol, defaulting to http: {}",
            pid, e
        );
        "http".into()
    });
    let auth_mode_str: String = row.try_get("auth_mode").unwrap_or_else(|e| {
        warn!(
            "Proxy {}: failed to read auth_mode, defaulting to single: {}",
            pid, e
        );
        "single".into()
    });

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
        circuit_breaker: row
            .try_get::<String, _>("circuit_breaker")
            .ok()
            .and_then(|s| {
                serde_json::from_str::<CircuitBreakerConfig>(&s)
                    .map_err(|e| {
                        warn!("Proxy {}: failed to parse circuit_breaker JSON: {}", pid, e);
                        e
                    })
                    .ok()
            }),
        retry: row.try_get::<String, _>("retry").ok().and_then(|s| {
            serde_json::from_str::<RetryConfig>(&s)
                .map_err(|e| {
                    warn!("Proxy {}: failed to parse retry JSON: {}", pid, e);
                    e
                })
                .ok()
        }),
        response_body_mode: row
            .try_get::<String, _>("response_body_mode")
            .ok()
            .map(|s| match s.as_str() {
                "buffer" => ResponseBodyMode::Buffer,
                _ => ResponseBodyMode::Stream,
            })
            .unwrap_or_default(),
        pool_max_idle_per_host: row
            .try_get::<i64, _>("pool_max_idle_per_host")
            .ok()
            .map(|v| v as usize),
        pool_idle_timeout_seconds: row
            .try_get::<i64, _>("pool_idle_timeout_seconds")
            .ok()
            .map(|v| v as u64),
        pool_enable_http_keep_alive: row
            .try_get::<i32, _>("pool_enable_http_keep_alive")
            .ok()
            .map(|v| v != 0),
        pool_enable_http2: row
            .try_get::<i32, _>("pool_enable_http2")
            .ok()
            .map(|v| v != 0),
        pool_tcp_keepalive_seconds: row
            .try_get::<i64, _>("pool_tcp_keepalive_seconds")
            .ok()
            .map(|v| v as u64),
        pool_http2_keep_alive_interval_seconds: row
            .try_get::<i64, _>("pool_http2_keep_alive_interval_seconds")
            .ok()
            .map(|v| v as u64),
        pool_http2_keep_alive_timeout_seconds: row
            .try_get::<i64, _>("pool_http2_keep_alive_timeout_seconds")
            .ok()
            .map(|v| v as u64),
        listen_port: row
            .try_get::<i32, _>("listen_port")
            .ok()
            .map(|v| v.clamp(0, 65535) as u16),
        frontend_tls: row.try_get::<i32, _>("frontend_tls").unwrap_or(0) != 0,
        udp_idle_timeout_seconds: row
            .try_get::<i64, _>("udp_idle_timeout_seconds")
            .map(|v| v.max(0) as u64)
            .unwrap_or(60),
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a consumer row into a Consumer struct.
fn row_to_consumer(row: &AnyRow) -> Result<Consumer, anyhow::Error> {
    let creds_str: String = row.try_get("credentials").unwrap_or_else(|e| {
        warn!("Failed to read credentials column for consumer: {}", e);
        "{}".into()
    });
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
    let config_str: String = row.try_get("config").unwrap_or_else(|e| {
        warn!("Failed to read plugin config column: {}", e);
        "{}".into()
    });
    let config_val = serde_json::from_str(&config_str).unwrap_or_else(|e| {
        warn!("Failed to parse plugin config JSON: {}", e);
        serde_json::Value::Null
    });
    let scope_str: String = row.try_get("scope").unwrap_or_else(|e| {
        warn!(
            "Failed to read plugin scope column, defaulting to global: {}",
            e
        );
        "global".into()
    });

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
    let targets_str: String = row.try_get("targets").unwrap_or_else(|e| {
        warn!("Failed to read upstream targets column: {}", e);
        "[]".into()
    });
    let targets: Vec<UpstreamTarget> = serde_json::from_str(&targets_str).unwrap_or_else(|e| {
        warn!("Failed to parse upstream targets JSON: {}", e);
        Vec::new()
    });

    let algo_str: String = row.try_get("algorithm").unwrap_or_else(|e| {
        warn!(
            "Failed to read upstream algorithm column, defaulting to round_robin: {}",
            e
        );
        "round_robin".into()
    });
    let algorithm: LoadBalancerAlgorithm =
        serde_json::from_value(serde_json::Value::String(algo_str)).unwrap_or_default();

    let health_checks: Option<HealthCheckConfig> = row
        .try_get::<String, _>("health_checks")
        .ok()
        .and_then(|s| {
            serde_json::from_str(&s)
                .map_err(|e| {
                    warn!("Failed to parse upstream health_checks JSON: {}", e);
                    e
                })
                .ok()
        });

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
