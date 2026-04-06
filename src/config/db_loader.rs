//! Database config loader with incremental polling.
//!
//! **Incremental polling strategy** (two-phase):
//! 1. **Change detection**: Indexed `WHERE updated_at > ?` queries on 4 tables to
//!    fetch only rows modified since the last poll. A 1-second safety margin on the
//!    timestamp prevents missing boundary writes due to clock skew or in-flight commits.
//! 2. **Deletion detection**: Lightweight `SELECT id` queries on all 4 tables, diffed
//!    against the poller's known ID sets to find removed rows.
//!
//! On startup, a full `SELECT *` seeds the initial config and known ID sets.
//! If an incremental poll fails for any reason, the loop falls back to a full
//! reload and re-seeds. Known ID sets are only updated after successful apply.
//!
//! **Key implementation details**:
//! - Postgres `?` → `$N` placeholder rewrite via `q()` method (sqlx `Any` uses `?`)
//! - `>500` IN-clause threshold switches to full-table fetch + in-memory filter
//! - `ArcSwap`-based pool swap enables zero-downtime DNS re-resolution on failover
//! - Batch chunking (`BATCH_CHUNK_SIZE`) for large imports to stay within DB limits

use crate::config::types::{
    AuthMode, BackendProtocol, CircuitBreakerConfig, Consumer, GatewayConfig, HealthCheckConfig,
    LoadBalancerAlgorithm, PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode,
    RetryConfig, ServiceDiscoveryConfig, Upstream, UpstreamTarget,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::Executor;
use sqlx::Row;
use sqlx::{AnyPool, any::AnyPoolOptions, any::AnyRow};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

// Re-export trait types so existing `use crate::config::db_loader::{IncrementalResult, ...}` works.
#[allow(unused_imports)]
pub use crate::config::db_backend::{
    DatabaseBackend, IncrementalResult, PaginatedResult, extract_db_hostname, extract_known_ids,
    redact_url,
};

struct PluginConfigRef {
    id: String,
    scope: PluginScope,
    proxy_id: Option<String>,
}

/// Database connection pool tuning parameters.
///
/// These are exposed via `FERRUM_DB_POOL_*` environment variables and applied
/// to all SQLx pools (primary, failover, and read replica).
#[derive(Debug, Clone)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    /// Maximum time (seconds) to wait for a new TCP connection to the database
    /// server. Default: 10. Applies per connection attempt — separate from
    /// `acquire_timeout_seconds` which covers the full pool checkout (wait +
    /// connect). 0 = no explicit timeout (falls back to OS TCP timeout).
    pub connect_timeout_seconds: u64,
    /// Maximum execution time (seconds) for any single SQL statement. Default:
    /// 30. Set via `SET statement_timeout` (PostgreSQL) or
    /// `SET SESSION max_execution_time` (MySQL) on every new connection.
    /// Prevents runaway queries from holding connections indefinitely.
    /// 0 = disabled (no per-statement timeout). Ignored for SQLite.
    pub statement_timeout_seconds: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 10,
            statement_timeout_seconds: 30,
        }
    }
}

/// Database configuration store.
///
/// The inner pool is wrapped in `ArcSwap` so it can be atomically replaced
/// when DNS re-resolution detects that the database FQDN now points to a
/// different IP. All readers (query methods, transactions) take a cheap
/// `Arc` clone of the current pool, so in-flight queries finish on the old
/// pool while new queries go to the freshly connected one.
#[derive(Clone)]
pub struct DatabaseStore {
    pool: Arc<ArcSwap<AnyPool>>,
    read_replica_pool: Option<Arc<ArcSwap<AnyPool>>>,
    db_type: String,
    failover_urls: Vec<String>,
    pool_config: DbPoolConfig,
    slow_query_threshold_ms: Option<u64>,
    cert_expiry_warning_days: u64,
    backend_allow_ips: crate::config::BackendAllowIps,
}

impl DatabaseStore {
    /// Rewrite `?` placeholders to `$N` for PostgreSQL.
    ///
    /// The `sqlx::Any` driver does not automatically translate `?` bind
    /// parameters to PostgreSQL's `$1`, `$2`, ... syntax. PostgreSQL reserves
    /// `?` as a JSON "exists" operator, so unescaped `?` in a query string
    /// causes a parse error.
    ///
    /// This method is a no-op for MySQL and SQLite (which use `?` natively).
    fn q(&self, sql: &str) -> String {
        if self.db_type != "postgres" {
            return sql.to_string();
        }
        let mut result = String::with_capacity(sql.len() + 16);
        let mut n = 0u32;
        for ch in sql.chars() {
            if ch == '?' {
                n += 1;
                result.push('$');
                // Inline u32 formatting to avoid format!() overhead
                let s = n.to_string();
                result.push_str(&s);
            } else {
                result.push(ch);
            }
        }
        result
    }

    // set_slow_query_threshold, set_cert_expiry_warning_days, and
    // set_backend_allow_ips are implemented via the DatabaseBackend trait.

    /// Log a warning if the elapsed time since `start` exceeds the configured
    /// slow query threshold. No-op when the threshold is disabled.
    fn check_slow_query(&self, operation: &str, start: Instant) {
        if let Some(threshold_ms) = self.slow_query_threshold_ms {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            if elapsed_ms > threshold_ms {
                warn!(
                    "Slow database query: {} took {}ms (threshold: {}ms)",
                    operation, elapsed_ms, threshold_ms
                );
            }
        }
    }

    /// Build `AnyPoolOptions` from the stored pool configuration.
    ///
    /// Used by all pool creation paths (initial connect, reconnect, read replica)
    /// to ensure consistent tuning from `FERRUM_DB_POOL_*` env vars.
    fn build_pool_options(&self) -> AnyPoolOptions {
        Self::build_pool_options_from_config(&self.pool_config, &self.db_type)
    }

    /// Build `AnyPoolOptions` from a given pool configuration.
    fn build_pool_options_from_config(config: &DbPoolConfig, db_type: &str) -> AnyPoolOptions {
        let is_sqlite = db_type == "sqlite";
        let is_postgres = db_type == "postgres";
        let is_mysql = db_type == "mysql";
        let statement_timeout_seconds = config.statement_timeout_seconds;

        AnyPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(std::time::Duration::from_secs(
                config.acquire_timeout_seconds,
            ))
            .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_seconds))
            // Force connection cycling so new TCP connections re-resolve DNS.
            // Defence-in-depth alongside the explicit DnsCache-based reconnect.
            .max_lifetime(std::time::Duration::from_secs(config.max_lifetime_seconds))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    // Enable foreign key enforcement on every SQLite connection
                    // (PRAGMA is per-connection, not persistent across pool connections)
                    if is_sqlite {
                        conn.execute("PRAGMA foreign_keys = ON").await?;
                    }
                    // Set per-statement timeout on network databases to prevent
                    // runaway queries from holding connections indefinitely.
                    if statement_timeout_seconds > 0 {
                        if is_postgres {
                            // PostgreSQL statement_timeout is in milliseconds
                            let sql = format!(
                                "SET statement_timeout = '{}'",
                                statement_timeout_seconds * 1000
                            );
                            conn.execute(sql.as_str()).await?;
                        } else if is_mysql {
                            // MySQL max_execution_time is in milliseconds
                            let sql = format!(
                                "SET SESSION max_execution_time = {}",
                                statement_timeout_seconds * 1000
                            );
                            conn.execute(sql.as_str()).await?;
                        }
                    }
                    Ok(())
                })
            })
    }

    /// Append `connect_timeout` to a database URL for PostgreSQL and MySQL.
    ///
    /// This sets the driver-level TCP connect timeout — separate from
    /// `acquire_timeout` which covers waiting for a pool slot + connecting.
    /// SQLite is local I/O so connect timeout is not applicable.
    fn append_connect_timeout(url: &str, db_type: &str, timeout_seconds: u64) -> String {
        if timeout_seconds == 0 || db_type == "sqlite" {
            return url.to_string();
        }
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{}{}connect_timeout={}", url, separator, timeout_seconds)
    }

    /// Connect to the database with optional TLS configuration and run migrations.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_tls_config(
        db_type: &str,
        db_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        // Install all drivers
        sqlx::any::install_default_drivers();

        // Construct TLS-aware connection URL
        let mut final_url = if tls_enabled && (db_type == "postgres" || db_type == "mysql") {
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

        // Append driver-level connect timeout to the URL
        final_url =
            Self::append_connect_timeout(&final_url, db_type, pool_config.connect_timeout_seconds);

        let pool = Self::build_pool_options_from_config(&pool_config, db_type)
            .connect(&final_url)
            .await?;

        let store = Self {
            pool: Arc::new(ArcSwap::from_pointee(pool)),
            read_replica_pool: None,
            db_type: db_type.to_string(),
            failover_urls: Vec::new(),
            pool_config,
            slow_query_threshold_ms: None,
            cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
            backend_allow_ips: crate::config::BackendAllowIps::Both,
        };

        store.run_migrations().await?;

        info!(
            "Database connected and migrations applied (type={}, tls_enabled={}, max_connections={}, min_connections={})",
            db_type,
            tls_enabled,
            store.pool_config.max_connections,
            store.pool_config.min_connections
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

        let runner = MigrationRunner::new(self.pool(), self.db_type.clone());
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
        let start = Instant::now();
        // Capture timestamp before queries so the incremental polling safety
        // margin covers the full load duration.
        let loaded_at = Utc::now();
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
            loaded_at,
        };

        // Normalize canonical in-memory fields before validation.
        config.normalize_fields();

        // Validate all field-level constraints (lengths, ranges, nested configs).
        // Warn-only since data already exists in the database.
        if let Err(errors) = config.validate_all_fields_with_ip_policy(
            self.cert_expiry_warning_days,
            &self.backend_allow_ips,
        ) {
            for msg in &errors {
                warn!("{}", msg);
            }
        }

        // Validate host entry format
        if let Err(errors) = config.validate_hosts() {
            for msg in &errors {
                warn!("{}", msg);
            }
        }

        // Validate regex listen_paths compile correctly
        if let Err(errors) = config.validate_regex_listen_paths() {
            for msg in &errors {
                error!("{}", msg);
            }
            anyhow::bail!("Database has invalid regex listen_path(s)");
        }

        if let Err(dupes) = config.validate_unique_listen_paths() {
            for msg in &dupes {
                error!("{}", msg);
            }
            anyhow::bail!("Database has conflicting host+listen_path combinations");
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

        // Defense-in-depth: validate consumer identity and credential uniqueness.
        // The database schema has UNIQUE constraints, but if data was imported or
        // the schema was modified, duplicates could exist. Log warnings instead of
        // failing startup so the gateway can still serve with the DB's data.
        if let Err(errors) = config.validate_unique_consumer_identities() {
            for msg in &errors {
                warn!("{}", msg);
            }
        }
        if let Err(errors) = config.validate_unique_consumer_credentials() {
            for msg in &errors {
                warn!("{}", msg);
            }
        }

        if let Err(errors) = config.validate_upstream_references() {
            for msg in &errors {
                error!("{}", msg);
            }
            anyhow::bail!("Database has invalid upstream reference(s)");
        }

        if let Err(errors) = config.validate_plugin_references() {
            for msg in &errors {
                error!("{}", msg);
            }
            anyhow::bail!("Database has invalid plugin reference(s)");
        }

        // Validate each plugin config by instantiating the plugin.
        // Warn-only since data already exists in the database.
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if let Err(err) = crate::plugins::validate_plugin_config(&pc.plugin_name, &pc.config) {
                warn!("Plugin '{}' (id={}): {}", pc.plugin_name, pc.id, err);
            }
        }

        self.check_slow_query("load_full_config", start);
        Ok(config)
    }

    async fn load_proxies(&self) -> Result<Vec<Proxy>, anyhow::Error> {
        let start = Instant::now();

        // Batch-load all proxy_plugins in one query (eliminates N+1).
        // This table is lightweight (two TEXT columns, no JSON) so a single
        // unbounded fetch is fine even at scale.
        let assoc_rows: Vec<AnyRow> =
            match sqlx::query("SELECT proxy_id, plugin_config_id FROM proxy_plugins")
                .fetch_all(&self.rpool())
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

        // Load proxies in chunks to avoid unbounded SELECT * at scale.
        let mut proxies = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> =
                sqlx::query(&self.q("SELECT * FROM proxies ORDER BY id LIMIT ? OFFSET ?"))
                    .bind(Self::FULL_LOAD_PAGE_SIZE)
                    .bind(offset)
                    .fetch_all(&self.rpool())
                    .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id")?;
                let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
                proxies.push(row_to_proxy(&row, id, plugins)?);
            }
            if (fetched as i64) < Self::FULL_LOAD_PAGE_SIZE {
                break;
            }
            offset += Self::FULL_LOAD_PAGE_SIZE;
        }

        self.check_slow_query("load_proxies", start);
        Ok(proxies)
    }

    async fn load_consumers(&self) -> Result<Vec<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let mut consumers = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> =
                sqlx::query(&self.q("SELECT * FROM consumers ORDER BY id LIMIT ? OFFSET ?"))
                    .bind(Self::FULL_LOAD_PAGE_SIZE)
                    .bind(offset)
                    .fetch_all(&self.rpool())
                    .await?;
            let fetched = rows.len();
            for row in rows {
                consumers.push(row_to_consumer(&row)?);
            }
            if (fetched as i64) < Self::FULL_LOAD_PAGE_SIZE {
                break;
            }
            offset += Self::FULL_LOAD_PAGE_SIZE;
        }

        self.check_slow_query("load_consumers", start);
        Ok(consumers)
    }

    async fn load_plugin_configs(&self) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let mut configs = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> =
                sqlx::query(&self.q("SELECT * FROM plugin_configs ORDER BY id LIMIT ? OFFSET ?"))
                    .bind(Self::FULL_LOAD_PAGE_SIZE)
                    .bind(offset)
                    .fetch_all(&self.rpool())
                    .await?;
            let fetched = rows.len();
            for row in rows {
                configs.push(row_to_plugin_config(&row)?);
            }
            if (fetched as i64) < Self::FULL_LOAD_PAGE_SIZE {
                break;
            }
            offset += Self::FULL_LOAD_PAGE_SIZE;
        }

        self.check_slow_query("load_plugin_configs", start);
        Ok(configs)
    }

    // ---- CRUD for Admin API ----

    pub async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        let start = Instant::now();
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

        let mut tx = self.pool().begin().await?;

        let hosts_json = serde_json::to_string(&proxy.hosts)?;

        sqlx::query(
            &self.q("INSERT INTO proxies (id, name, hosts, listen_path, backend_protocol, backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, circuit_breaker, retry, response_body_mode, pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, pool_http2_initial_connection_window_size, pool_http2_adaptive_window, pool_http2_max_frame_size, pool_http2_max_concurrent_streams, pool_http3_connections_per_backend, listen_port, frontend_tls, passthrough, udp_idle_timeout_seconds, tcp_idle_timeout_seconds, allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&proxy.id)
        .bind(&proxy.name)
        .bind(&hosts_json)
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
        .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_enable_http_keep_alive.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_stream_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_connection_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_adaptive_window.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
        .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
        .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
        .bind(proxy.listen_port.map(|v| v as i32))
        .bind(if proxy.frontend_tls { 1i32 } else { 0 })
        .bind(if proxy.passthrough { 1i32 } else { 0 })
        .bind(proxy.udp_idle_timeout_seconds as i64)
        .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.allowed_methods.as_ref().map(serde_json::to_string).transpose()?)
        .bind(if proxy.allowed_ws_origins.is_empty() { None } else { Some(serde_json::to_string(&proxy.allowed_ws_origins)?) })
        .bind(proxy.udp_max_response_amplification_factor.map(|v| v as f64))
        .bind(proxy.created_at.to_rfc3339())
        .bind(proxy.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;

        // Persist plugin associations in the junction table
        for assoc in &proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        self.check_slow_query("create_proxy", start);
        Ok(())
    }

    pub async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        let start = Instant::now();
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

        let mut tx = self.pool().begin().await?;

        let hosts_json = serde_json::to_string(&proxy.hosts)?;

        sqlx::query(
            &self.q("UPDATE proxies SET name=?, hosts=?, listen_path=?, backend_protocol=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, dns_override=?, dns_cache_ttl_seconds=?, auth_mode=?, upstream_id=?, circuit_breaker=?, retry=?, response_body_mode=?, pool_idle_timeout_seconds=?, pool_enable_http_keep_alive=?, pool_enable_http2=?, pool_tcp_keepalive_seconds=?, pool_http2_keep_alive_interval_seconds=?, pool_http2_keep_alive_timeout_seconds=?, pool_http2_initial_stream_window_size=?, pool_http2_initial_connection_window_size=?, pool_http2_adaptive_window=?, pool_http2_max_frame_size=?, pool_http2_max_concurrent_streams=?, pool_http3_connections_per_backend=?, listen_port=?, frontend_tls=?, passthrough=?, udp_idle_timeout_seconds=?, tcp_idle_timeout_seconds=?, allowed_methods=?, allowed_ws_origins=?, udp_max_response_amplification_factor=?, updated_at=? WHERE id=?")
        )
        .bind(&proxy.name)
        .bind(&hosts_json)
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
        .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_enable_http_keep_alive.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_stream_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_initial_connection_window_size.map(|v| v as i64))
        .bind(proxy.pool_http2_adaptive_window.map(|v| if v { 1i32 } else { 0 }))
        .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
        .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
        .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
        .bind(proxy.listen_port.map(|v| v as i32))
        .bind(if proxy.frontend_tls { 1i32 } else { 0 })
        .bind(if proxy.passthrough { 1i32 } else { 0 })
        .bind(proxy.udp_idle_timeout_seconds as i64)
        .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
        .bind(proxy.allowed_methods.as_ref().map(serde_json::to_string).transpose()?)
        .bind(if proxy.allowed_ws_origins.is_empty() { None } else { Some(serde_json::to_string(&proxy.allowed_ws_origins)?) })
        .bind(proxy.udp_max_response_amplification_factor.map(|v| v as f64))
        .bind(Utc::now().to_rfc3339())
        .bind(&proxy.id)
        .execute(&mut *tx)
        .await?;

        // Update plugin associations: remove old, insert new
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id = ?"))
            .bind(&proxy.id)
            .execute(&mut *tx)
            .await?;

        for assoc in &proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        self.check_slow_query("update_proxy", start);
        Ok(())
    }

    pub async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        // Look up the proxy's upstream_id before deleting so we can cascade-delete
        // the upstream if it becomes orphaned.
        let upstream_id: Option<String> =
            sqlx::query(&self.q("SELECT upstream_id FROM proxies WHERE id = ?"))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| row.try_get::<String, _>("upstream_id").ok());

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query(&self.q("DELETE FROM proxies WHERE id = ?"))
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
                sqlx::query(&self.q("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1"))
                    .bind(uid)
                    .fetch_all(&mut *tx)
                    .await?;
            if ref_rows.is_empty() {
                info!("Cascade-deleting orphaned upstream {}", uid);
                sqlx::query(&self.q("DELETE FROM upstreams WHERE id = ?"))
                    .bind(uid)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;

        self.check_slow_query("delete_proxy", start);
        Ok(true)
    }

    pub async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT * FROM proxies WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool())
            .await?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let assoc_rows: Vec<AnyRow> = match sqlx::query(
            &self.q("SELECT plugin_config_id FROM proxy_plugins WHERE proxy_id = ?"),
        )
        .bind(id)
        .fetch_all(&self.pool())
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

        let mut proxy = row_to_proxy(&row, id.to_string(), plugins)?;
        proxy.normalize_fields();
        self.check_slow_query("get_proxy", start);
        Ok(Some(proxy))
    }

    pub async fn check_proxy_exists(&self, proxy_id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT id FROM proxies WHERE id = ?"))
            .bind(proxy_id)
            .fetch_optional(&self.pool())
            .await?;
        self.check_slow_query("check_proxy_exists", start);
        Ok(row.is_some())
    }

    pub async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
        sqlx::query(
            &self.q("INSERT INTO consumers (id, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&consumer.id)
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(&acl_groups_json)
        .bind(consumer.created_at.to_rfc3339())
        .bind(consumer.updated_at.to_rfc3339())
        .execute(&self.pool())
        .await?;

        self.check_slow_query("create_consumer", start);
        Ok(())
    }

    pub async fn update_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let creds_json = serde_json::to_string(&consumer.credentials)?;
        let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
        sqlx::query(&self.q(
            "UPDATE consumers SET username=?, custom_id=?, credentials=?, acl_groups=?, updated_at=? WHERE id=?",
        ))
        .bind(&consumer.username)
        .bind(&consumer.custom_id)
        .bind(&creds_json)
        .bind(&acl_groups_json)
        .bind(Utc::now().to_rfc3339())
        .bind(&consumer.id)
        .execute(&self.pool())
        .await?;

        self.check_slow_query("update_consumer", start);
        Ok(())
    }

    pub async fn delete_consumer(&self, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let result = sqlx::query(&self.q("DELETE FROM consumers WHERE id = ?"))
            .bind(id)
            .execute(&self.pool())
            .await?;
        self.check_slow_query("delete_consumer", start);
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_consumer(&self, id: &str) -> Result<Option<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT * FROM consumers WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool())
            .await?;

        let result = match row {
            Some(r) => {
                let mut consumer = row_to_consumer(&r)?;
                consumer.normalize_fields();
                Ok(Some(consumer))
            }
            None => Ok(None),
        };
        self.check_slow_query("get_consumer", start);
        result
    }

    pub async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::Global => "global",
        };
        sqlx::query(
            &self.q("INSERT INTO plugin_configs (id, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&pc.id)
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(pc.priority_override.map(|v| v as i32))
        .bind(pc.created_at.to_rfc3339())
        .bind(pc.updated_at.to_rfc3339())
        .execute(&self.pool())
        .await?;

        self.check_slow_query("create_plugin_config", start);
        Ok(())
    }

    pub async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let config_json = serde_json::to_string(&pc.config)?;
        let scope_str = match pc.scope {
            PluginScope::Proxy => "proxy",
            PluginScope::Global => "global",
        };
        sqlx::query(
            &self.q("UPDATE plugin_configs SET plugin_name=?, config=?, scope=?, proxy_id=?, enabled=?, priority_override=?, updated_at=? WHERE id=?")
        )
        .bind(&pc.plugin_name)
        .bind(&config_json)
        .bind(scope_str)
        .bind(&pc.proxy_id)
        .bind(if pc.enabled { 1i32 } else { 0 })
        .bind(pc.priority_override.map(|v| v as i32))
        .bind(Utc::now().to_rfc3339())
        .bind(&pc.id)
        .execute(&self.pool())
        .await?;

        self.check_slow_query("update_plugin_config", start);
        Ok(())
    }

    pub async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        // Clean up junction table (defense in depth alongside ON DELETE CASCADE)
        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE plugin_config_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(&self.q("DELETE FROM plugin_configs WHERE id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        self.check_slow_query("delete_plugin_config", start);
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT * FROM plugin_configs WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool())
            .await?;

        let result = match row {
            Some(r) => {
                let mut plugin_config = row_to_plugin_config(&r)?;
                plugin_config.normalize_fields();
                Ok(Some(plugin_config))
            }
            None => Ok(None),
        };
        self.check_slow_query("get_plugin_config", start);
        result
    }

    // ---- Upstream CRUD ----

    async fn load_upstreams(&self) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let mut upstreams = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> =
                sqlx::query(&self.q("SELECT * FROM upstreams ORDER BY id LIMIT ? OFFSET ?"))
                    .bind(Self::FULL_LOAD_PAGE_SIZE)
                    .bind(offset)
                    .fetch_all(&self.rpool())
                    .await?;
            let fetched = rows.len();
            for row in rows {
                upstreams.push(row_to_upstream(&row)?);
            }
            if (fetched as i64) < Self::FULL_LOAD_PAGE_SIZE {
                break;
            }
            offset += Self::FULL_LOAD_PAGE_SIZE;
        }

        self.check_slow_query("load_upstreams", start);
        Ok(upstreams)
    }

    // ---- Paginated list queries for Admin API ----

    /// List proxies with database-level LIMIT/OFFSET pagination.
    pub async fn list_proxies_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        let start = Instant::now();

        let count_row = sqlx::query("SELECT COUNT(*) AS cnt FROM proxies")
            .fetch_one(&self.rpool())
            .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM proxies ORDER BY id LIMIT ? OFFSET ?"))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.rpool())
                .await?;

        // Batch-load proxy_plugins for only the proxies in this page
        let proxy_ids: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect();

        let mut plugins_by_proxy: std::collections::HashMap<String, Vec<PluginAssociation>> =
            std::collections::HashMap::new();
        if !proxy_ids.is_empty() {
            let placeholders = std::iter::repeat_n("?", proxy_ids.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = self.q(&format!(
                "SELECT proxy_id, plugin_config_id FROM proxy_plugins WHERE proxy_id IN ({})",
                placeholders
            ));
            let mut query = sqlx::query(&sql);
            for id in &proxy_ids {
                query = query.bind(id);
            }
            match query.fetch_all(&self.rpool()).await {
                Ok(assoc_rows) => {
                    for r in &assoc_rows {
                        if let (Ok(pid), Ok(pcid)) = (
                            r.try_get::<String, _>("proxy_id"),
                            r.try_get::<String, _>("plugin_config_id"),
                        ) {
                            plugins_by_proxy
                                .entry(pid)
                                .or_default()
                                .push(PluginAssociation {
                                    plugin_config_id: pcid,
                                });
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to load proxy_plugins for paginated list: {}", e);
                }
            }
        }

        let mut proxies = Vec::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            proxies.push(row_to_proxy(&row, id, plugins)?);
        }

        self.check_slow_query("list_proxies_paginated", start);
        Ok(PaginatedResult {
            items: proxies,
            total,
        })
    }

    /// List consumers with database-level LIMIT/OFFSET pagination.
    pub async fn list_consumers_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        let start = Instant::now();

        let count_row = sqlx::query("SELECT COUNT(*) AS cnt FROM consumers")
            .fetch_one(&self.rpool())
            .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM consumers ORDER BY id LIMIT ? OFFSET ?"))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.rpool())
                .await?;

        let mut consumers = Vec::new();
        for row in rows {
            consumers.push(row_to_consumer(&row)?);
        }

        self.check_slow_query("list_consumers_paginated", start);
        Ok(PaginatedResult {
            items: consumers,
            total,
        })
    }

    /// List plugin configs with database-level LIMIT/OFFSET pagination.
    pub async fn list_plugin_configs_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        let start = Instant::now();

        let count_row = sqlx::query("SELECT COUNT(*) AS cnt FROM plugin_configs")
            .fetch_one(&self.rpool())
            .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM plugin_configs ORDER BY id LIMIT ? OFFSET ?"))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.rpool())
                .await?;

        let mut configs = Vec::new();
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }

        self.check_slow_query("list_plugin_configs_paginated", start);
        Ok(PaginatedResult {
            items: configs,
            total,
        })
    }

    /// List upstreams with database-level LIMIT/OFFSET pagination.
    pub async fn list_upstreams_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        let start = Instant::now();

        let count_row = sqlx::query("SELECT COUNT(*) AS cnt FROM upstreams")
            .fetch_one(&self.rpool())
            .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams ORDER BY id LIMIT ? OFFSET ?"))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.rpool())
                .await?;

        let mut upstreams = Vec::new();
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }

        self.check_slow_query("list_upstreams_paginated", start);
        Ok(PaginatedResult {
            items: upstreams,
            total,
        })
    }

    pub async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        // algo_json is quoted like "\"round_robin\"", strip the quotes
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let service_discovery_json = upstream
            .service_discovery
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(
            &self.q("INSERT INTO upstreams (id, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&upstream.id)
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(upstream.created_at.to_rfc3339())
        .bind(upstream.updated_at.to_rfc3339())
        .execute(&self.pool())
        .await?;

        self.check_slow_query("create_upstream", start);
        Ok(())
    }

    pub async fn update_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let targets_json = serde_json::to_string(&upstream.targets)?;
        let algo_json = serde_json::to_string(&upstream.algorithm)?;
        let algo_str = algo_json.trim_matches('"');
        let health_checks_json = upstream
            .health_checks
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let service_discovery_json = upstream
            .service_discovery
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(
            &self.q("UPDATE upstreams SET name=?, targets=?, algorithm=?, hash_on=?, hash_on_cookie_config=?, health_checks=?, service_discovery=?, updated_at=? WHERE id=?")
        )
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(Utc::now().to_rfc3339())
        .bind(&upstream.id)
        .execute(&self.pool())
        .await?;

        self.check_slow_query("update_upstream", start);
        Ok(())
    }

    /// Delete an upstream only if it is not referenced by any proxy.
    /// Returns `Err` if the upstream is still in use.
    /// Uses a transaction to prevent race conditions between the reference
    /// check and the delete.
    pub async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        // Check reference within the transaction to prevent races
        let ref_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1"))
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

        let result = sqlx::query(&self.q("DELETE FROM upstreams WHERE id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        self.check_slow_query("delete_upstream", start);
        Ok(result.rows_affected() > 0)
    }

    /// When a proxy changes its upstream_id, clean up the old upstream if it
    /// became orphaned (no other proxies reference it).
    /// Uses a transaction to prevent race conditions between check and delete.
    pub async fn cleanup_orphaned_upstream(
        &self,
        old_upstream_id: &str,
    ) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        let ref_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1"))
                .bind(old_upstream_id)
                .fetch_all(&mut *tx)
                .await?;

        if ref_rows.is_empty() {
            info!(
                "Cleaning up orphaned upstream {} after proxy reassignment",
                old_upstream_id
            );
            sqlx::query(&self.q("DELETE FROM upstreams WHERE id = ?"))
                .bind(old_upstream_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        self.check_slow_query("cleanup_orphaned_upstream", start);
        Ok(())
    }

    pub async fn get_upstream(&self, id: &str) -> Result<Option<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT * FROM upstreams WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool())
            .await?;

        let result = match row {
            Some(r) => Ok(Some(row_to_upstream(&r)?)),
            None => Ok(None),
        };
        self.check_slow_query("get_upstream", start);
        result
    }

    /// Check if a proxy's (hosts, listen_path) combination is unique.
    ///
    /// Two proxies may share the same `listen_path` if their `hosts` sets are
    /// completely disjoint. Returns `true` if no conflict is found.
    pub async fn check_listen_path_unique(
        &self,
        listen_path: &str,
        hosts: &[String],
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(&self.q("SELECT id, hosts FROM proxies \
                 WHERE listen_path = ? \
                   AND backend_protocol NOT IN ('tcp', 'tcp_tls', 'udp', 'dtls') \
                   AND id != ?"))
            .bind(listen_path)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id, hosts FROM proxies \
                 WHERE listen_path = ? \
                   AND backend_protocol NOT IN ('tcp', 'tcp_tls', 'udp', 'dtls')"))
            .bind(listen_path)
            .fetch_all(&self.pool())
            .await?
        };

        self.check_slow_query("check_listen_path_unique", start);

        // No other proxy with this listen_path — unique
        if rows.is_empty() {
            return Ok(true);
        }

        // Check if any existing proxy's hosts overlap with the new hosts
        for row in &rows {
            let existing_hosts: Vec<String> = row
                .try_get::<String, _>("hosts")
                .ok()
                .and_then(|s| match serde_json::from_str(&s) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        warn!("Failed to parse hosts JSON during uniqueness check: {}", e);
                        None
                    }
                })
                .unwrap_or_default();

            if crate::config::types::hosts_overlap(hosts, &existing_hosts) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check if a proxy name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_proxy_name_unique(
        &self,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE name = ? AND id != ?"))
                .bind(name)
                .bind(eid)
                .fetch_all(&self.pool())
                .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE name = ?"))
                .bind(name)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_proxy_name_unique", start);
        Ok(rows.is_empty())
    }

    /// Check if an upstream name is unique (when present).
    /// Returns `true` if the name is unique (no conflicts found).
    pub async fn check_upstream_name_unique(
        &self,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE name = ? AND id != ?"))
                .bind(name)
                .bind(eid)
                .fetch_all(&self.pool())
                .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE name = ?"))
                .bind(name)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_upstream_name_unique", start);
        Ok(rows.is_empty())
    }

    /// Check that a consumer username/custom_id combination does not collide
    /// with another consumer's username/custom_id namespace.
    pub async fn check_consumer_identity_unique(
        &self,
        username: &str,
        custom_id: Option<&str>,
        exclude_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        let start = Instant::now();
        let (sql, binds): (String, Vec<&str>) = match custom_id {
            Some(custom_id) => (
                self.q("SELECT id, username, custom_id FROM consumers \
                     WHERE (username = ? OR custom_id = ? OR username = ? OR custom_id = ?)"),
                vec![username, custom_id, custom_id, username],
            ),
            None => (
                self.q("SELECT id, username, custom_id FROM consumers \
                     WHERE (username = ? OR custom_id = ?)"),
                vec![username, username],
            ),
        };

        let sql = if exclude_id.is_some() {
            format!("{} AND id != ?", sql)
        } else {
            sql
        };

        let mut query = sqlx::query(&sql);
        for value in binds {
            query = query.bind(value);
        }
        if let Some(exclude_id) = exclude_id {
            query = query.bind(exclude_id);
        }

        let rows = query.fetch_all(&self.pool()).await?;
        for row in rows {
            let id: String = row.try_get("id")?;
            let existing_username: String = row.try_get("username")?;
            let existing_custom_id: Option<String> = row.try_get("custom_id").ok();

            if existing_username == username {
                return Ok(Some(format!(
                    "A consumer with username '{}' already exists (consumer '{}')",
                    username, id
                )));
            }
            if existing_custom_id.as_deref() == Some(username) {
                return Ok(Some(format!(
                    "Consumer username '{}' conflicts with custom_id of consumer '{}'",
                    username, id
                )));
            }

            if let Some(custom_id) = custom_id {
                if existing_custom_id.as_deref() == Some(custom_id) {
                    return Ok(Some(format!(
                        "A consumer with custom_id '{}' already exists (consumer '{}')",
                        custom_id, id
                    )));
                }
                if existing_username == custom_id {
                    return Ok(Some(format!(
                        "Consumer custom_id '{}' conflicts with username of consumer '{}'",
                        custom_id, id
                    )));
                }
            }
        }

        self.check_slow_query("check_consumer_identity_unique", start);
        Ok(None)
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
        let start = Instant::now();
        let rows: Vec<AnyRow> = sqlx::query("SELECT id, credentials FROM consumers")
            .fetch_all(&self.pool())
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

        self.check_slow_query("check_keyauth_key_unique", start);
        Ok(true)
    }

    /// Check that an mTLS identity is not already used by another consumer.
    ///
    /// mTLS identities are stored inside the credentials JSON blob, so there is
    /// no database-level UNIQUE constraint — this application-level check is
    /// the only enforcement.
    ///
    /// Returns `true` if the identity is unique (safe to insert/update).
    pub async fn check_mtls_identity_unique(
        &self,
        mtls_identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = sqlx::query("SELECT id, credentials FROM consumers")
            .fetch_all(&self.pool())
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
                && let Some(identity) = creds
                    .get("mtls_auth")
                    .and_then(|m| m.get("identity"))
                    .and_then(|i| i.as_str())
                && identity == mtls_identity
            {
                return Ok(false);
            }
        }

        self.check_slow_query("check_mtls_identity_unique", start);
        Ok(true)
    }

    /// Check if a listen_port is unique across all stream proxies.
    /// Returns `true` if the port is unique (no conflicts found).
    pub async fn check_listen_port_unique(
        &self,
        port: u16,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE listen_port = ? AND id != ?"))
                .bind(port as i32)
                .bind(eid)
                .fetch_all(&self.pool())
                .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE listen_port = ?"))
                .bind(port as i32)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_listen_port_unique", start);
        Ok(rows.is_empty())
    }

    /// Check if an upstream with the given ID exists.
    /// Returns `true` if the upstream exists.
    pub async fn check_upstream_exists(&self, upstream_id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> = sqlx::query(&self.q("SELECT id FROM upstreams WHERE id = ?"))
            .bind(upstream_id)
            .fetch_optional(&self.pool())
            .await?;
        self.check_slow_query("check_upstream_exists", start);
        Ok(row.is_some())
    }

    /// Validate that a proxy's plugin associations reference existing
    /// proxy-scoped plugin configs targeted at the same proxy, and that the
    /// resolved plugin names remain unique for that proxy.
    pub async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        associations: &[PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> {
        if associations.is_empty() {
            return Ok(Vec::new());
        }

        let mut requested_ids = Vec::with_capacity(associations.len());
        let mut seen_assoc_ids: HashSet<&str> = HashSet::new();
        let mut errors = Vec::new();

        for assoc in associations {
            if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                errors.push(format!(
                    "Proxy '{}' references plugin_config '{}' more than once",
                    proxy_id, assoc.plugin_config_id
                ));
            } else {
                requested_ids.push(assoc.plugin_config_id.clone());
            }
        }

        let plugin_refs = self.load_plugin_config_refs(&requested_ids).await?;

        for assoc in associations {
            match plugin_refs.get(assoc.plugin_config_id.as_str()) {
                Some(plugin) => {
                    if plugin.scope != PluginScope::Proxy {
                        errors.push(format!(
                            "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped plugin configs",
                            proxy_id, plugin.id
                        ));
                        continue;
                    }
                    if plugin.proxy_id.as_deref() != Some(proxy_id) {
                        errors.push(format!(
                            "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                            proxy_id,
                            plugin.id,
                            plugin.proxy_id.as_deref().unwrap_or("<none>")
                        ));
                    }
                }
                None => errors.push(format!(
                    "Proxy '{}' references non-existent plugin_config '{}'",
                    proxy_id, assoc.plugin_config_id
                )),
            }
        }

        Ok(errors)
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
        let start = Instant::now();
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

        self.check_slow_query("load_incremental_config", start);
        Ok(result)
    }

    /// Load proxies modified since `since_str` (RFC 3339 timestamp).
    async fn load_proxies_since(&self, since_str: &str) -> Result<Vec<Proxy>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(&self.q("SELECT * FROM proxies WHERE updated_at > ?"))
            .bind(since_str)
            .fetch_all(&self.rpool())
            .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Batch-load proxy_plugins only for the changed proxy IDs
        let changed_ids: HashSet<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect();

        let mut plugins_by_proxy: std::collections::HashMap<String, Vec<PluginAssociation>> =
            std::collections::HashMap::new();

        if !changed_ids.is_empty() {
            let changed_id_list: Vec<&str> = changed_ids.iter().map(|s| s.as_str()).collect();

            let assoc_rows: Vec<AnyRow> = if changed_id_list.len() > 500 {
                // Too many IDs for an IN clause — fetch all and filter in memory
                match sqlx::query("SELECT proxy_id, plugin_config_id FROM proxy_plugins")
                    .fetch_all(&self.rpool())
                    .await
                {
                    Ok(all_rows) => all_rows
                        .into_iter()
                        .filter(|r| {
                            r.try_get::<String, _>("proxy_id")
                                .map(|id| changed_ids.contains(&id))
                                .unwrap_or(false)
                        })
                        .collect(),
                    Err(e) => {
                        warn!(
                            "Failed to fetch proxy_plugins for incremental update: {}. \
                             Plugin associations may be stale until next full reload.",
                            e
                        );
                        Vec::new()
                    }
                }
            } else {
                // Build parameterized IN clause for targeted fetch
                let placeholders: String = changed_id_list
                    .iter()
                    .map(|_| "?")
                    .collect::<Vec<_>>()
                    .join(", ");
                let sql = self.q(&format!(
                    "SELECT proxy_id, plugin_config_id FROM proxy_plugins WHERE proxy_id IN ({})",
                    placeholders
                ));
                let mut query = sqlx::query(&sql);
                for id in &changed_id_list {
                    query = query.bind(*id);
                }
                match query.fetch_all(&self.rpool()).await {
                    Ok(rows) => rows,
                    Err(e) => {
                        warn!(
                            "Failed to fetch proxy_plugins for incremental update: {}. \
                             Plugin associations may be stale until next full reload.",
                            e
                        );
                        Vec::new()
                    }
                }
            };

            for r in &assoc_rows {
                if let Ok(proxy_id) = r.try_get::<String, _>("proxy_id")
                    && let Ok(plugin_config_id) = r.try_get::<String, _>("plugin_config_id")
                {
                    plugins_by_proxy
                        .entry(proxy_id)
                        .or_default()
                        .push(PluginAssociation { plugin_config_id });
                }
            }
        }

        let mut proxies = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.try_get("id")?;
            let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
            proxies.push(row_to_proxy(row, id, plugins)?);
        }

        self.check_slow_query("load_proxies_since", start);
        Ok(proxies)
    }

    /// Load consumers modified since `since_str`.
    async fn load_consumers_since(&self, since_str: &str) -> Result<Vec<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM consumers WHERE updated_at > ?"))
                .bind(since_str)
                .fetch_all(&self.rpool())
                .await?;

        let mut consumers = Vec::with_capacity(rows.len());
        for row in rows {
            consumers.push(row_to_consumer(&row)?);
        }
        self.check_slow_query("load_consumers_since", start);
        Ok(consumers)
    }

    /// Load plugin configs modified since `since_str`.
    async fn load_plugin_configs_since(
        &self,
        since_str: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM plugin_configs WHERE updated_at > ?"))
                .bind(since_str)
                .fetch_all(&self.rpool())
                .await?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }
        self.check_slow_query("load_plugin_configs_since", start);
        Ok(configs)
    }

    /// Load upstreams modified since `since_str`.
    async fn load_upstreams_since(&self, since_str: &str) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams WHERE updated_at > ?"))
                .bind(since_str)
                .fetch_all(&self.rpool())
                .await?;

        let mut upstreams = Vec::with_capacity(rows.len());
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }
        self.check_slow_query("load_upstreams_since", start);
        Ok(upstreams)
    }

    /// Load all IDs from a table (lightweight — one TEXT column, no deserialization).
    async fn load_table_ids(&self, table: &str) -> Result<HashSet<String>, anyhow::Error> {
        let start = Instant::now();
        // Table name is a compile-time constant from the caller, not user input.
        let sql = format!("SELECT id FROM {}", table);
        let rows: Vec<AnyRow> = sqlx::query(&sql).fetch_all(&self.rpool()).await?;

        let mut ids = HashSet::with_capacity(rows.len());
        for row in rows {
            if let Ok(id) = row.try_get::<String, _>("id") {
                ids.insert(id);
            }
        }
        self.check_slow_query(&format!("load_table_ids({})", table), start);
        Ok(ids)
    }

    async fn load_plugin_config_refs(
        &self,
        ids: &[String],
    ) -> Result<std::collections::HashMap<String, PluginConfigRef>, anyhow::Error> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let placeholders = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = self.q(&format!(
            "SELECT id, scope, proxy_id FROM plugin_configs WHERE id IN ({})",
            placeholders
        ));

        let mut query = sqlx::query(&sql);
        for id in ids {
            query = query.bind(id);
        }

        let rows = query.fetch_all(&self.pool()).await?;
        let mut plugin_refs = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id")?;
            let scope = match row.try_get::<String, _>("scope")?.as_str() {
                "proxy" => PluginScope::Proxy,
                _ => PluginScope::Global,
            };
            plugin_refs.insert(
                id.clone(),
                PluginConfigRef {
                    id,
                    scope,
                    proxy_id: row.try_get("proxy_id").ok(),
                },
            );
        }

        Ok(plugin_refs)
    }

    /// Extract known IDs from a full config (used to seed the incremental poller).
    ///
    /// Delegates to [`crate::config::db_backend::extract_known_ids`].
    #[allow(dead_code)]
    pub fn extract_known_ids(
        config: &GatewayConfig,
    ) -> (
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
    ) {
        crate::config::db_backend::extract_known_ids(config)
    }

    /// Maximum records per database transaction for batch operations.
    /// Keeps transaction WAL/redo log size manageable and reduces lock hold time.
    const BATCH_CHUNK_SIZE: usize = 1000;

    /// Maximum rows fetched per query during full config loading.
    /// Prevents unbounded `SELECT *` from hitting statement timeouts or causing
    /// memory spikes at scale (100k+ rows). Raw `AnyRow` buffers are freed
    /// between chunks, so peak memory is proportional to chunk size, not table size.
    const FULL_LOAD_PAGE_SIZE: i64 = 5000;

    /// Batch-create multiple proxies, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    #[allow(dead_code)]
    pub async fn batch_create_proxies(&self, proxies: &[Proxy]) -> Result<usize, anyhow::Error> {
        self.batch_create_proxies_internal(proxies, true).await
    }

    pub async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
    ) -> Result<usize, anyhow::Error> {
        self.batch_create_proxies_internal(proxies, false).await
    }

    async fn batch_create_proxies_internal(
        &self,
        proxies: &[Proxy],
        attach_plugins: bool,
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if proxies.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in proxies.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self
                .batch_create_proxies_chunk(chunk, attach_plugins)
                .await?;
        }
        self.check_slow_query("batch_create_proxies", start);
        Ok(total)
    }

    /// Insert a single chunk of proxies in one transaction.
    async fn batch_create_proxies_chunk(
        &self,
        proxies: &[Proxy],
        attach_plugins: bool,
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let insert_sql = self.q("INSERT INTO proxies (id, name, hosts, listen_path, backend_protocol, backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, circuit_breaker, retry, response_body_mode, pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, pool_http2_initial_connection_window_size, pool_http2_adaptive_window, pool_http2_max_frame_size, pool_http2_max_concurrent_streams, pool_http3_connections_per_backend, listen_port, frontend_tls, passthrough, udp_idle_timeout_seconds, tcp_idle_timeout_seconds, allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");

        for proxy in proxies {
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
            let hosts_json = serde_json::to_string(&proxy.hosts)?;

            sqlx::query(&insert_sql)
                .bind(&proxy.id)
                .bind(&proxy.name)
                .bind(&hosts_json)
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
                .bind(if proxy.backend_tls_verify_server_cert {
                    1i32
                } else {
                    0
                })
                .bind(&proxy.backend_tls_server_ca_cert_path)
                .bind(&proxy.dns_override)
                .bind(proxy.dns_cache_ttl_seconds.map(|v| v as i64))
                .bind(match proxy.auth_mode {
                    AuthMode::Multi => "multi",
                    _ => "single",
                })
                .bind(&proxy.upstream_id)
                .bind(&circuit_breaker_json)
                .bind(&retry_json)
                .bind(response_body_mode_str)
                .bind(proxy.pool_idle_timeout_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .pool_enable_http_keep_alive
                        .map(|v| if v { 1i32 } else { 0 }),
                )
                .bind(proxy.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
                .bind(proxy.pool_tcp_keepalive_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .pool_http2_keep_alive_interval_seconds
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_keep_alive_timeout_seconds
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_initial_stream_window_size
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_initial_connection_window_size
                        .map(|v| v as i64),
                )
                .bind(
                    proxy
                        .pool_http2_adaptive_window
                        .map(|v| if v { 1i32 } else { 0 }),
                )
                .bind(proxy.pool_http2_max_frame_size.map(|v| v as i64))
                .bind(proxy.pool_http2_max_concurrent_streams.map(|v| v as i64))
                .bind(proxy.pool_http3_connections_per_backend.map(|v| v as i64))
                .bind(proxy.listen_port.map(|v| v as i32))
                .bind(if proxy.frontend_tls { 1i32 } else { 0 })
                .bind(if proxy.passthrough { 1i32 } else { 0 })
                .bind(proxy.udp_idle_timeout_seconds as i64)
                .bind(proxy.tcp_idle_timeout_seconds.map(|v| v as i64))
                .bind(
                    proxy
                        .allowed_methods
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                )
                .bind(if proxy.allowed_ws_origins.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&proxy.allowed_ws_origins)?)
                })
                .bind(
                    proxy
                        .udp_max_response_amplification_factor
                        .map(|v| v as f64),
                )
                .bind(proxy.created_at.to_rfc3339())
                .bind(proxy.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;

            if attach_plugins {
                for assoc in &proxy.plugins {
                    sqlx::query(&assoc_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }

        let count = proxies.len();
        tx.commit().await?;
        Ok(count)
    }

    pub async fn batch_attach_proxy_plugins(&self, proxies: &[Proxy]) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        if proxies.is_empty() {
            return Ok(());
        }

        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");
        for chunk in proxies.chunks(Self::BATCH_CHUNK_SIZE) {
            let mut tx = self.pool().begin().await?;
            for proxy in chunk {
                for assoc in &proxy.plugins {
                    sqlx::query(&assoc_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            tx.commit().await?;
        }

        self.check_slow_query("batch_attach_proxy_plugins", start);
        Ok(())
    }

    /// Batch-create multiple consumers, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    pub async fn batch_create_consumers(
        &self,
        consumers: &[Consumer],
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if consumers.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in consumers.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_consumers_chunk(chunk).await?;
        }
        self.check_slow_query("batch_create_consumers", start);
        Ok(total)
    }

    /// Insert a single chunk of consumers in one transaction.
    async fn batch_create_consumers_chunk(
        &self,
        consumers: &[Consumer],
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let sql = self.q("INSERT INTO consumers (id, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)");

        for consumer in consumers {
            let creds_json = serde_json::to_string(&consumer.credentials)?;
            let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
            sqlx::query(&sql)
                .bind(&consumer.id)
                .bind(&consumer.username)
                .bind(&consumer.custom_id)
                .bind(&creds_json)
                .bind(&acl_groups_json)
                .bind(consumer.created_at.to_rfc3339())
                .bind(consumer.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }

        let count = consumers.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Batch-create multiple plugin configs, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    pub async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if configs.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in configs.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_plugin_configs_chunk(chunk).await?;
        }
        self.check_slow_query("batch_create_plugin_configs", start);
        Ok(total)
    }

    /// Insert a single chunk of plugin configs in one transaction.
    async fn batch_create_plugin_configs_chunk(
        &self,
        configs: &[PluginConfig],
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let sql = self.q("INSERT INTO plugin_configs (id, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

        for pc in configs {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                PluginScope::Proxy => "proxy",
                PluginScope::Global => "global",
            };
            sqlx::query(&sql)
                .bind(&pc.id)
                .bind(&pc.plugin_name)
                .bind(&config_json)
                .bind(scope_str)
                .bind(&pc.proxy_id)
                .bind(if pc.enabled { 1i32 } else { 0 })
                .bind(pc.priority_override.map(|v| v as i32))
                .bind(pc.created_at.to_rfc3339())
                .bind(pc.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }

        let count = configs.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Batch-create multiple upstreams, chunked into transactions of
    /// [`BATCH_CHUNK_SIZE`] for large-scale imports.
    pub async fn batch_create_upstreams(
        &self,
        upstreams: &[Upstream],
    ) -> Result<usize, anyhow::Error> {
        let start = Instant::now();
        if upstreams.is_empty() {
            return Ok(0);
        }
        let mut total = 0usize;
        for chunk in upstreams.chunks(Self::BATCH_CHUNK_SIZE) {
            total += self.batch_create_upstreams_chunk(chunk).await?;
        }
        self.check_slow_query("batch_create_upstreams", start);
        Ok(total)
    }

    /// Insert a single chunk of upstreams in one transaction.
    async fn batch_create_upstreams_chunk(
        &self,
        upstreams: &[Upstream],
    ) -> Result<usize, anyhow::Error> {
        let mut tx = self.pool().begin().await?;
        let sql = self.q("INSERT INTO upstreams (id, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        for upstream in upstreams {
            let targets_json = serde_json::to_string(&upstream.targets)?;
            let algo_json = serde_json::to_string(&upstream.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let hash_on_cookie_config_json = upstream
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let health_checks_json = upstream
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = upstream
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            sqlx::query(&sql)
                .bind(&upstream.id)
                .bind(&upstream.name)
                .bind(&targets_json)
                .bind(algo_str)
                .bind(&upstream.hash_on)
                .bind(&hash_on_cookie_config_json)
                .bind(&health_checks_json)
                .bind(&service_discovery_json)
                .bind(upstream.created_at.to_rfc3339())
                .bind(upstream.updated_at.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }

        let count = upstreams.len();
        tx.commit().await?;
        Ok(count)
    }

    /// Delete all resources from all tables in a single transaction.
    ///
    /// Deletion order respects foreign key constraints:
    /// 1. proxy_plugins (junction table)
    /// 2. plugin_configs (may reference proxies)
    /// 3. proxies (may reference upstreams)
    /// 4. consumers
    /// 5. upstreams
    pub async fn delete_all_resources(&self) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        sqlx::query("DELETE FROM proxy_plugins")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM plugin_configs")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM proxies").execute(&mut *tx).await?;
        sqlx::query("DELETE FROM consumers")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM upstreams")
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        self.check_slow_query("delete_all_resources", start);
        Ok(())
    }

    /// Get a snapshot of the current connection pool.
    ///
    /// Returns an owned clone (cheap — `AnyPool` is `Arc`-based internally).
    /// The returned handle remains valid even if `reconnect()` swaps the pool.
    pub fn pool(&self) -> AnyPool {
        (**self.pool.load()).clone()
    }

    #[allow(dead_code)]
    pub fn db_type_str(&self) -> &str {
        &self.db_type
    }

    /// Atomically replace the connection pool with a freshly connected one.
    ///
    /// Called by the DB polling loop when DnsCache detects that the database
    /// FQDN now resolves to a different set of IPs. The old pool is closed
    /// gracefully in the background — in-flight queries complete normally.
    pub async fn reconnect(
        &self,
        db_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        let mut final_url =
            if tls_enabled && (self.db_type == "postgres" || self.db_type == "mysql") {
                Self::build_tls_connection_url(
                    db_url,
                    &self.db_type,
                    tls_ca_cert_path,
                    tls_client_cert_path,
                    tls_client_key_path,
                    tls_insecure,
                )?
            } else {
                db_url.to_string()
            };

        final_url = Self::append_connect_timeout(
            &final_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        );

        let new_pool = self.build_pool_options().connect(&final_url).await?;

        // Atomic swap — readers that already loaded the old pool keep using it.
        let old_pool = self.pool.swap(Arc::new(new_pool));
        info!(
            "Database pool reconnected (db_type={}). Old pool closing in background.",
            self.db_type
        );

        // Close old pool gracefully in the background so in-flight queries
        // finish without blocking the polling loop.
        tokio::spawn(async move {
            old_pool.close().await;
        });

        Ok(())
    }

    /// Extract the hostname from a database URL, if it contains one.
    ///
    /// Delegates to [`crate::config::db_backend::extract_db_hostname`].
    #[allow(dead_code)]
    pub fn extract_db_hostname(db_url: &str) -> Option<String> {
        crate::config::db_backend::extract_db_hostname(db_url)
    }

    /// Connect to the primary database, trying failover URLs if the primary fails.
    ///
    /// Tries the primary URL first. If it fails and failover URLs are provided,
    /// tries each in order. The first successful connection is used. Migrations
    /// are run on the connected database.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_failover(
        db_type: &str,
        primary_url: &str,
        failover_urls: &[String],
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        match Self::connect_with_tls_config(
            db_type,
            primary_url,
            tls_enabled,
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_insecure,
            pool_config.clone(),
        )
        .await
        {
            Ok(mut store) => {
                store.failover_urls = failover_urls.to_vec();
                Ok(store)
            }
            Err(primary_err) => {
                if failover_urls.is_empty() {
                    return Err(primary_err);
                }
                warn!(
                    "Primary database connection failed: {}. Trying {} failover URL(s)...",
                    primary_err,
                    failover_urls.len()
                );
                for (i, url) in failover_urls.iter().enumerate() {
                    match Self::connect_with_tls_config(
                        db_type,
                        url,
                        tls_enabled,
                        tls_ca_cert_path,
                        tls_client_cert_path,
                        tls_client_key_path,
                        tls_insecure,
                        pool_config.clone(),
                    )
                    .await
                    {
                        Ok(mut store) => {
                            info!(
                                "Connected to failover database #{} ({})",
                                i + 1,
                                Self::redact_url(url)
                            );
                            store.failover_urls = failover_urls.to_vec();
                            return Ok(store);
                        }
                        Err(e) => {
                            warn!(
                                "Failover database #{} ({}) failed: {}",
                                i + 1,
                                Self::redact_url(url),
                                e
                            );
                        }
                    }
                }
                Err(anyhow::anyhow!(
                    "All database URLs failed. Primary: {}. Tried {} failover URL(s).",
                    primary_err,
                    failover_urls.len()
                ))
            }
        }
    }

    /// Connect a read replica pool for config polling.
    ///
    /// The read replica pool uses the same connection settings (max_connections,
    /// max_lifetime) as the primary. Migrations are NOT run on the replica.
    pub async fn connect_read_replica(
        &mut self,
        replica_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        let mut final_url =
            if tls_enabled && (self.db_type == "postgres" || self.db_type == "mysql") {
                Self::build_tls_connection_url(
                    replica_url,
                    &self.db_type,
                    tls_ca_cert_path,
                    tls_client_cert_path,
                    tls_client_key_path,
                    tls_insecure,
                )?
            } else {
                replica_url.to_string()
            };

        final_url = Self::append_connect_timeout(
            &final_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        );

        let pool = self.build_pool_options().connect(&final_url).await?;

        self.read_replica_pool = Some(Arc::new(ArcSwap::from_pointee(pool)));
        info!(
            "Read replica connected (db_type={}, url={})",
            self.db_type,
            Self::redact_url(replica_url)
        );
        Ok(())
    }

    /// Get a snapshot of the read replica pool, falling back to the primary.
    ///
    /// Used by config polling (load_full_config, load_incremental_config) to
    /// offload read traffic from the primary. If no read replica is configured
    /// or the replica pool has been closed, returns the primary pool.
    fn rpool(&self) -> AnyPool {
        if let Some(ref rp) = self.read_replica_pool {
            (**rp.load()).clone()
        } else {
            self.pool()
        }
    }

    /// Atomically replace the read replica pool with a freshly connected one.
    ///
    /// Called by the DB polling loop when DnsCache detects that the read replica
    /// FQDN now resolves to a different set of IPs.
    pub async fn reconnect_read_replica(
        &self,
        replica_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error> {
        let rp = match &self.read_replica_pool {
            Some(rp) => rp,
            None => return Ok(()), // no replica configured
        };

        sqlx::any::install_default_drivers();

        let mut final_url =
            if tls_enabled && (self.db_type == "postgres" || self.db_type == "mysql") {
                Self::build_tls_connection_url(
                    replica_url,
                    &self.db_type,
                    tls_ca_cert_path,
                    tls_client_cert_path,
                    tls_client_key_path,
                    tls_insecure,
                )?
            } else {
                replica_url.to_string()
            };

        final_url = Self::append_connect_timeout(
            &final_url,
            &self.db_type,
            self.pool_config.connect_timeout_seconds,
        );

        let new_pool = self.build_pool_options().connect(&final_url).await?;

        let old_pool = rp.swap(Arc::new(new_pool));
        info!(
            "Read replica pool reconnected (db_type={}). Old pool closing in background.",
            self.db_type
        );

        tokio::spawn(async move {
            old_pool.close().await;
        });

        Ok(())
    }

    /// Try to reconnect to any available database URL (primary first, then failover).
    ///
    /// Called by the polling loop when the current connection is failing.
    /// Returns the URL that succeeded, or an error if all failed.
    pub async fn try_failover_reconnect(
        &self,
        primary_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<String, anyhow::Error> {
        // Try primary first
        if self
            .reconnect(
                primary_url,
                tls_enabled,
                tls_ca_cert_path,
                tls_client_cert_path,
                tls_client_key_path,
                tls_insecure,
            )
            .await
            .is_ok()
        {
            info!("Reconnected to primary database");
            return Ok(primary_url.to_string());
        }

        // Try failover URLs in order
        for (i, url) in self.failover_urls.iter().enumerate() {
            if self
                .reconnect(
                    url,
                    tls_enabled,
                    tls_ca_cert_path,
                    tls_client_cert_path,
                    tls_client_key_path,
                    tls_insecure,
                )
                .await
                .is_ok()
            {
                info!(
                    "Reconnected to failover database #{} ({})",
                    i + 1,
                    Self::redact_url(url)
                );
                return Ok(url.clone());
            }
            warn!(
                "Failover database #{} ({}) reconnect failed",
                i + 1,
                Self::redact_url(url)
            );
        }

        Err(anyhow::anyhow!(
            "All database URLs failed during reconnect ({} failover URL(s) tried)",
            self.failover_urls.len()
        ))
    }

    /// Redact credentials from a database URL for safe logging.
    ///
    /// Delegates to [`crate::config::db_backend::redact_url`].
    pub fn redact_url(url: &str) -> String {
        crate::config::db_backend::redact_url(url)
    }

    /// Returns true if a read replica pool is configured.
    #[allow(dead_code)] // Public API for tests and future consumers
    pub fn has_read_replica_pool(&self) -> bool {
        self.read_replica_pool.is_some()
    }
}

// ---------------------------------------------------------------------------
// DatabaseBackend trait implementation for sqlx-backed DatabaseStore
// ---------------------------------------------------------------------------

#[async_trait]
impl DatabaseBackend for DatabaseStore {
    async fn health_check(&self) -> Result<(), anyhow::Error> {
        sqlx::query("SELECT 1").fetch_one(&self.pool()).await?;
        Ok(())
    }

    fn db_type(&self) -> &str {
        &self.db_type
    }

    fn has_read_replica(&self) -> bool {
        self.has_read_replica_pool()
    }

    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>) {
        self.slow_query_threshold_ms = threshold_ms;
    }

    fn set_cert_expiry_warning_days(&mut self, days: u64) {
        self.cert_expiry_warning_days = days;
    }

    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendAllowIps) {
        self.backend_allow_ips = policy;
    }

    async fn load_full_config(&self) -> Result<GatewayConfig, anyhow::Error> {
        DatabaseStore::load_full_config(self).await
    }

    async fn load_incremental_config(
        &self,
        since: DateTime<Utc>,
        known_proxy_ids: &HashSet<String>,
        known_consumer_ids: &HashSet<String>,
        known_plugin_config_ids: &HashSet<String>,
        known_upstream_ids: &HashSet<String>,
    ) -> Result<IncrementalResult, anyhow::Error> {
        DatabaseStore::load_incremental_config(
            self,
            since,
            known_proxy_ids,
            known_consumer_ids,
            known_plugin_config_ids,
            known_upstream_ids,
        )
        .await
    }

    async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        DatabaseStore::create_proxy(self, proxy).await
    }

    async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
        DatabaseStore::update_proxy(self, proxy).await
    }

    async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_proxy(self, id).await
    }

    async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        DatabaseStore::get_proxy(self, id).await
    }

    async fn check_proxy_exists(&self, proxy_id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_exists(self, proxy_id).await
    }

    async fn list_proxies_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        DatabaseStore::list_proxies_paginated(self, limit, offset).await
    }

    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        DatabaseStore::create_consumer(self, consumer).await
    }

    async fn update_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
        DatabaseStore::update_consumer(self, consumer).await
    }

    async fn delete_consumer(&self, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_consumer(self, id).await
    }

    async fn get_consumer(&self, id: &str) -> Result<Option<Consumer>, anyhow::Error> {
        DatabaseStore::get_consumer(self, id).await
    }

    async fn list_consumers_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        DatabaseStore::list_consumers_paginated(self, limit, offset).await
    }

    async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        DatabaseStore::create_plugin_config(self, pc).await
    }

    async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
        DatabaseStore::update_plugin_config(self, pc).await
    }

    async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_plugin_config(self, id).await
    }

    async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error> {
        DatabaseStore::get_plugin_config(self, id).await
    }

    async fn list_plugin_configs_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        DatabaseStore::list_plugin_configs_paginated(self, limit, offset).await
    }

    async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        DatabaseStore::create_upstream(self, upstream).await
    }

    async fn update_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
        DatabaseStore::update_upstream(self, upstream).await
    }

    async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_upstream(self, id).await
    }

    async fn get_upstream(&self, id: &str) -> Result<Option<Upstream>, anyhow::Error> {
        DatabaseStore::get_upstream(self, id).await
    }

    async fn cleanup_orphaned_upstream(&self, upstream_id: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::cleanup_orphaned_upstream(self, upstream_id).await
    }

    async fn list_upstreams_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        DatabaseStore::list_upstreams_paginated(self, limit, offset).await
    }

    async fn check_listen_path_unique(
        &self,
        listen_path: &str,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_path_unique(self, listen_path, hosts, exclude_proxy_id).await
    }

    async fn check_proxy_name_unique(
        &self,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_name_unique(self, name, exclude_proxy_id).await
    }

    async fn check_upstream_name_unique(
        &self,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_name_unique(self, name, exclude_upstream_id).await
    }

    async fn check_consumer_identity_unique(
        &self,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        DatabaseStore::check_consumer_identity_unique(
            self,
            username,
            custom_id,
            exclude_consumer_id,
        )
        .await
    }

    async fn check_keyauth_key_unique(
        &self,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_keyauth_key_unique(self, key, exclude_consumer_id).await
    }

    async fn check_mtls_identity_unique(
        &self,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_mtls_identity_unique(self, identity, exclude_consumer_id).await
    }

    async fn check_listen_port_unique(
        &self,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_port_unique(self, port, exclude_proxy_id).await
    }

    async fn check_upstream_exists(&self, upstream_id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_exists(self, upstream_id).await
    }

    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::validate_proxy_plugin_associations(self, proxy_id, plugins).await
    }

    async fn batch_create_proxies(&self, proxies: &[Proxy]) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_proxies(self, proxies).await
    }

    async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_proxies_without_plugins(self, proxies).await
    }

    async fn batch_attach_proxy_plugins(&self, proxies: &[Proxy]) -> Result<(), anyhow::Error> {
        DatabaseStore::batch_attach_proxy_plugins(self, proxies).await
    }

    async fn batch_create_consumers(&self, consumers: &[Consumer]) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_consumers(self, consumers).await
    }

    async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
    ) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_plugin_configs(self, configs).await
    }

    async fn batch_create_upstreams(&self, upstreams: &[Upstream]) -> Result<usize, anyhow::Error> {
        DatabaseStore::batch_create_upstreams(self, upstreams).await
    }

    async fn delete_all_resources(&self) -> Result<(), anyhow::Error> {
        DatabaseStore::delete_all_resources(self).await
    }

    async fn reconnect(
        &self,
        db_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect(
            self,
            db_url,
            tls_enabled,
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_insecure,
        )
        .await
    }

    async fn reconnect_read_replica(
        &self,
        replica_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect_read_replica(
            self,
            replica_url,
            tls_enabled,
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_insecure,
        )
        .await
    }

    async fn try_failover_reconnect(
        &self,
        primary_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<String, anyhow::Error> {
        DatabaseStore::try_failover_reconnect(
            self,
            primary_url,
            tls_enabled,
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_insecure,
        )
        .await
    }

    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        DatabaseStore::run_migrations(self).await
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

    let hosts: Vec<String> = row
        .try_get::<String, _>("hosts")
        .ok()
        .and_then(|s| match serde_json::from_str(&s) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("Proxy {}: failed to parse hosts JSON '{}': {}", pid, s, e);
                None
            }
        })
        .unwrap_or_default();

    Ok(Proxy {
        id,
        name: row.try_get("name").ok(),
        hosts,
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
        pool_http2_initial_stream_window_size: row
            .try_get::<i64, _>("pool_http2_initial_stream_window_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_initial_connection_window_size: row
            .try_get::<i64, _>("pool_http2_initial_connection_window_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_adaptive_window: row
            .try_get::<i32, _>("pool_http2_adaptive_window")
            .ok()
            .map(|v| v != 0),
        pool_http2_max_frame_size: row
            .try_get::<i64, _>("pool_http2_max_frame_size")
            .ok()
            .map(|v| v as u32),
        pool_http2_max_concurrent_streams: row
            .try_get::<i64, _>("pool_http2_max_concurrent_streams")
            .ok()
            .map(|v| v as u32),
        pool_http3_connections_per_backend: row
            .try_get::<i64, _>("pool_http3_connections_per_backend")
            .ok()
            .map(|v| v.max(1) as usize),
        listen_port: row
            .try_get::<i32, _>("listen_port")
            .ok()
            .map(|v| v.clamp(0, 65535) as u16),
        frontend_tls: row.try_get::<i32, _>("frontend_tls").unwrap_or(0) != 0,
        passthrough: row.try_get::<i32, _>("passthrough").unwrap_or(0) != 0,
        udp_idle_timeout_seconds: row
            .try_get::<i64, _>("udp_idle_timeout_seconds")
            .map(|v| v.max(0) as u64)
            .unwrap_or(60),
        tcp_idle_timeout_seconds: row
            .try_get::<i64, _>("tcp_idle_timeout_seconds")
            .ok()
            .map(|v| v.max(0) as u64),
        allowed_methods: row
            .try_get::<String, _>("allowed_methods")
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok()),
        allowed_ws_origins: row
            .try_get::<String, _>("allowed_ws_origins")
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default(),
        udp_max_response_amplification_factor: row
            .try_get::<f64, _>("udp_max_response_amplification_factor")
            .ok()
            .map(|v| v as f32),
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

    let acl_groups_str: String = row.try_get("acl_groups").unwrap_or_else(|_| "[]".into());
    let acl_groups: Vec<String> = serde_json::from_str(&acl_groups_str).unwrap_or_else(|e| {
        warn!("Failed to parse acl_groups JSON for consumer: {}", e);
        Vec::new()
    });

    Ok(Consumer {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        custom_id: row.try_get("custom_id").ok(),
        credentials,
        acl_groups,
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
        priority_override: row
            .try_get::<Option<i32>, _>("priority_override")
            .ok()
            .flatten()
            .map(|v| v as u16),
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
        serde_json::from_value(serde_json::Value::String(algo_str.clone())).unwrap_or_else(|e| {
            warn!(
                "Failed to parse upstream algorithm '{}', defaulting to round_robin: {}",
                algo_str, e
            );
            LoadBalancerAlgorithm::default()
        });

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

    let service_discovery: Option<ServiceDiscoveryConfig> = row
        .try_get::<String, _>("service_discovery")
        .ok()
        .and_then(|s| {
            serde_json::from_str(&s)
                .map_err(|e| {
                    warn!("Failed to parse upstream service_discovery JSON: {}", e);
                    e
                })
                .ok()
        });

    let hash_on_cookie_config: Option<crate::config::types::HashOnCookieConfig> = row
        .try_get::<String, _>("hash_on_cookie_config")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    Ok(Upstream {
        id: row.try_get("id")?,
        name: row.try_get("name").ok(),
        targets,
        algorithm,
        hash_on: row.try_get("hash_on").ok(),
        hash_on_cookie_config,
        health_checks,
        service_discovery,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_connect_timeout_postgres_no_existing_params() {
        let url = "postgres://user:pass@localhost/mydb";
        let result = DatabaseStore::append_connect_timeout(url, "postgres", 10);
        assert_eq!(
            result,
            "postgres://user:pass@localhost/mydb?connect_timeout=10"
        );
    }

    #[test]
    fn test_append_connect_timeout_postgres_with_existing_params() {
        let url = "postgres://user:pass@localhost/mydb?sslmode=require";
        let result = DatabaseStore::append_connect_timeout(url, "postgres", 15);
        assert_eq!(
            result,
            "postgres://user:pass@localhost/mydb?sslmode=require&connect_timeout=15"
        );
    }

    #[test]
    fn test_append_connect_timeout_mysql() {
        let url = "mysql://user:pass@localhost/mydb";
        let result = DatabaseStore::append_connect_timeout(url, "mysql", 5);
        assert_eq!(result, "mysql://user:pass@localhost/mydb?connect_timeout=5");
    }

    #[test]
    fn test_append_connect_timeout_sqlite_skipped() {
        let url = "sqlite://mydb.sqlite";
        let result = DatabaseStore::append_connect_timeout(url, "sqlite", 10);
        assert_eq!(result, "sqlite://mydb.sqlite");
    }

    #[test]
    fn test_append_connect_timeout_zero_disabled() {
        let url = "postgres://user:pass@localhost/mydb";
        let result = DatabaseStore::append_connect_timeout(url, "postgres", 0);
        assert_eq!(result, "postgres://user:pass@localhost/mydb");
    }

    #[test]
    fn test_db_pool_config_default() {
        let config = DbPoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.acquire_timeout_seconds, 30);
        assert_eq!(config.idle_timeout_seconds, 600);
        assert_eq!(config.max_lifetime_seconds, 300);
        assert_eq!(config.connect_timeout_seconds, 10);
        assert_eq!(config.statement_timeout_seconds, 30);
    }

    // -----------------------------------------------------------------------
    // diff_removed — deletion detection for incremental polling
    // -----------------------------------------------------------------------

    #[test]
    fn test_diff_removed_empty_sets() {
        let known = HashSet::new();
        let current = HashSet::new();
        let removed = diff_removed(&known, &current);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_diff_removed_no_deletions() {
        let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let current: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let removed = diff_removed(&known, &current);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_diff_removed_all_deleted() {
        let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let current = HashSet::new();
        let mut removed = diff_removed(&known, &current);
        removed.sort();
        assert_eq!(removed, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_diff_removed_partial_deletion() {
        let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let current: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
        let removed = diff_removed(&known, &current);
        assert_eq!(removed, vec!["b"]);
    }

    #[test]
    fn test_diff_removed_current_has_new_ids() {
        // New IDs in current that are not in known should not appear in removed
        let known: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let current: HashSet<String> = ["a", "b", "d", "e"].iter().map(|s| s.to_string()).collect();
        let removed = diff_removed(&known, &current);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_diff_removed_known_empty_current_has_items() {
        let known = HashSet::new();
        let current: HashSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
        let removed = diff_removed(&known, &current);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_diff_removed_mixed_additions_and_deletions() {
        let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let current: HashSet<String> = ["b", "d", "e"].iter().map(|s| s.to_string()).collect();
        let mut removed = diff_removed(&known, &current);
        removed.sort();
        assert_eq!(removed, vec!["a", "c"]);
    }

    // -----------------------------------------------------------------------
    // parse_protocol — backend protocol string parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_protocol_known_values() {
        assert!(matches!(parse_protocol("http"), BackendProtocol::Http));
        assert!(matches!(parse_protocol("https"), BackendProtocol::Https));
        assert!(matches!(parse_protocol("ws"), BackendProtocol::Ws));
        assert!(matches!(parse_protocol("wss"), BackendProtocol::Wss));
        assert!(matches!(parse_protocol("grpc"), BackendProtocol::Grpc));
        assert!(matches!(parse_protocol("grpcs"), BackendProtocol::Grpcs));
        assert!(matches!(parse_protocol("h3"), BackendProtocol::H3));
        assert!(matches!(parse_protocol("tcp"), BackendProtocol::Tcp));
        assert!(matches!(parse_protocol("tcp_tls"), BackendProtocol::TcpTls));
        assert!(matches!(parse_protocol("udp"), BackendProtocol::Udp));
        assert!(matches!(parse_protocol("dtls"), BackendProtocol::Dtls));
    }

    #[test]
    fn test_parse_protocol_case_insensitive() {
        assert!(matches!(parse_protocol("HTTPS"), BackendProtocol::Https));
        assert!(matches!(parse_protocol("Grpc"), BackendProtocol::Grpc));
        assert!(matches!(parse_protocol("H3"), BackendProtocol::H3));
        assert!(matches!(parse_protocol("TCP_TLS"), BackendProtocol::TcpTls));
    }

    #[test]
    fn test_parse_protocol_unknown_defaults_to_http() {
        assert!(matches!(parse_protocol("ftp"), BackendProtocol::Http));
        assert!(matches!(parse_protocol(""), BackendProtocol::Http));
        assert!(matches!(parse_protocol("nonsense"), BackendProtocol::Http));
    }

    // -----------------------------------------------------------------------
    // parse_auth_mode — auth mode string parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_auth_mode_known_values() {
        assert!(matches!(parse_auth_mode("single"), AuthMode::Single));
        assert!(matches!(parse_auth_mode("multi"), AuthMode::Multi));
    }

    #[test]
    fn test_parse_auth_mode_case_insensitive() {
        assert!(matches!(parse_auth_mode("MULTI"), AuthMode::Multi));
        assert!(matches!(parse_auth_mode("Single"), AuthMode::Single));
    }

    #[test]
    fn test_parse_auth_mode_unknown_defaults_to_single() {
        assert!(matches!(parse_auth_mode("unknown"), AuthMode::Single));
        assert!(matches!(parse_auth_mode(""), AuthMode::Single));
    }
}
