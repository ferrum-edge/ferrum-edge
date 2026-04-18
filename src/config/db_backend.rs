//! Database backend trait — abstracts config storage for SQL (sqlx) and NoSQL (MongoDB) backends.
//!
//! All database operations needed by the admin API, operating modes, and config
//! polling are defined here. Each backend (sqlx, MongoDB) provides its own
//! implementation. The trait is object-safe so it can be used as `Arc<dyn DatabaseBackend>`.

use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

/// Result of an incremental config poll.
///
/// Contains only the resources that changed since the last poll, plus IDs of
/// resources that were deleted. The polling loop uses this to apply surgical
/// updates without loading the entire database.
///
/// Serializable for CP-to-DP gRPC delta broadcasts.
#[derive(serde::Serialize, serde::Deserialize)]
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

/// Result of a paginated database query.
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: i64,
}

/// Connection pool statistics for observability.
///
/// Exposed via the admin `/status` endpoint to help operators tune pool settings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DbPoolStats {
    /// Current number of connections managed by the pool (idle + active).
    pub size: u32,
    /// Number of idle connections available for checkout.
    pub idle: u32,
    /// Number of connections currently checked out (in-use).
    pub active: u32,
    /// Maximum configured connections (`FERRUM_DB_POOL_MAX_CONNECTIONS`).
    pub max_connections: u32,
    /// Minimum configured idle connections (`FERRUM_DB_POOL_MIN_CONNECTIONS`).
    pub min_connections: u32,
    /// Read replica pool stats, if a replica is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_replica: Option<Box<DbPoolStatsInner>>,
}

/// Inner pool stats (used for read replicas to avoid infinite nesting).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DbPoolStatsInner {
    pub size: u32,
    pub idle: u32,
    pub active: u32,
}

/// Unified database backend trait.
///
/// This trait defines all operations needed by the admin API, operating modes,
/// and config polling. Concrete implementations exist for:
/// - `DatabaseStore` (sqlx) — PostgreSQL, MySQL, SQLite
/// - `MongoStore` (mongodb) — MongoDB
///
/// Connection lifecycle (connect, reconnect, failover) is NOT in the trait
/// because construction is inherently backend-specific. The trait covers only
/// operations on an already-connected store.
#[allow(dead_code)] // Some methods are only used through dyn dispatch or by MongoDB backend
#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    // -----------------------------------------------------------------------
    // Health & metadata
    // -----------------------------------------------------------------------

    /// Run a lightweight health check (e.g. `SELECT 1` for SQL, `ping` for MongoDB).
    async fn health_check(&self) -> Result<(), anyhow::Error>;

    /// Return the database type identifier (e.g. "postgres", "mysql", "sqlite", "mongodb").
    fn db_type(&self) -> &str;

    /// Returns true if a read replica is configured.
    fn has_read_replica(&self) -> bool;

    /// Return connection pool statistics for observability.
    ///
    /// Returns `None` when the backend does not expose pool internals
    /// (e.g. MongoDB, whose driver manages pooling internally).
    fn pool_stats(&self) -> Option<DbPoolStats> {
        None
    }

    // -----------------------------------------------------------------------
    // Settings (mutable — called once at startup before sharing via Arc)
    // -----------------------------------------------------------------------

    /// Set the slow query threshold (in milliseconds).
    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>);

    /// Set the certificate expiry warning threshold (days before expiration).
    fn set_cert_expiry_warning_days(&mut self, days: u64);

    /// Set the backend IP allowlist policy for SSRF protection.
    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendAllowIps);

    // -----------------------------------------------------------------------
    // Full config loading
    // -----------------------------------------------------------------------

    /// Load the full gateway configuration from the database.
    async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Incremental polling
    // -----------------------------------------------------------------------

    /// Load only resources changed since `since`, plus detect deletions.
    async fn load_incremental_config(
        &self,
        namespace: &str,
        since: DateTime<Utc>,
        known_proxy_ids: &HashSet<String>,
        known_consumer_ids: &HashSet<String>,
        known_plugin_config_ids: &HashSet<String>,
        known_upstream_ids: &HashSet<String>,
    ) -> Result<IncrementalResult, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Proxy CRUD
    // -----------------------------------------------------------------------

    async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error>;
    async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error>;
    async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error>;
    async fn check_proxy_exists(&self, proxy_id: &str) -> Result<bool, anyhow::Error>;
    async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Consumer CRUD
    // -----------------------------------------------------------------------

    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error>;
    async fn update_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error>;
    async fn delete_consumer(&self, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_consumer(&self, id: &str) -> Result<Option<Consumer>, anyhow::Error>;
    async fn list_consumers_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Plugin config CRUD
    // -----------------------------------------------------------------------

    async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error>;
    async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error>;
    async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error>;
    async fn list_plugin_configs_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Upstream CRUD
    // -----------------------------------------------------------------------

    async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error>;
    async fn update_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error>;
    async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_upstream(&self, id: &str) -> Result<Option<Upstream>, anyhow::Error>;
    async fn cleanup_orphaned_upstream(&self, upstream_id: &str) -> Result<(), anyhow::Error>;
    async fn list_upstreams_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Validation queries
    // -----------------------------------------------------------------------

    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: &str,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error>;

    async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_upstream_exists(&self, upstream_id: &str) -> Result<bool, anyhow::Error>;

    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Batch operations
    // -----------------------------------------------------------------------

    async fn batch_create_proxies(&self, proxies: &[Proxy]) -> Result<usize, anyhow::Error>;
    async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
    ) -> Result<usize, anyhow::Error>;
    async fn batch_attach_proxy_plugins(&self, proxies: &[Proxy]) -> Result<(), anyhow::Error>;
    async fn batch_create_consumers(&self, consumers: &[Consumer]) -> Result<usize, anyhow::Error>;
    async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
    ) -> Result<usize, anyhow::Error>;
    async fn batch_create_upstreams(&self, upstreams: &[Upstream]) -> Result<usize, anyhow::Error>;
    async fn delete_all_resources(&self, namespace: &str) -> Result<(), anyhow::Error>;

    // -----------------------------------------------------------------------
    // Connection lifecycle (called from polling loops)
    // -----------------------------------------------------------------------

    /// Atomically replace the connection pool with a freshly connected one.
    async fn reconnect(
        &self,
        db_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error>;

    /// Atomically replace the read replica pool with a freshly connected one.
    async fn reconnect_read_replica(
        &self,
        replica_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<(), anyhow::Error>;

    /// Try to reconnect to any available database URL (primary first, then failover).
    async fn try_failover_reconnect(
        &self,
        primary_url: &str,
        tls_enabled: bool,
        tls_ca_cert_path: Option<&str>,
        tls_client_cert_path: Option<&str>,
        tls_client_key_path: Option<&str>,
        tls_insecure: bool,
    ) -> Result<String, anyhow::Error>;

    /// Run schema migrations (SQL) or ensure indexes/collections exist (MongoDB).
    async fn run_migrations(&self) -> Result<(), anyhow::Error>;

    /// If the backend has pending migrations deferred from offline bootstrap,
    /// try to apply them now. Returns `Ok(true)` if migrations were run, or
    /// `Ok(false)` if nothing was pending (the normal case). `Err` means the
    /// database is still unreachable or the migration itself failed; the
    /// caller should leave the "pending" state unchanged.
    ///
    /// Call this anywhere an outcome-agnostic migration check is cheap: at
    /// startup after offline bootstrap, on each polling-loop success, and
    /// at the end of `reconnect()`. Implementations must be idempotent —
    /// concurrent calls should not run migrations twice.
    ///
    /// The default implementation is a no-op for backends that don't have
    /// an offline-bootstrap / lazy-pool concept (e.g., MongoDB).
    async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    /// Return all distinct namespaces across all resource tables.
    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error>;
}

/// Extract known IDs from a full config (used to seed the incremental poller).
///
/// This is a pure function on `GatewayConfig`, independent of any backend.
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

/// Extract the hostname from a database URL, if it contains one.
///
/// Returns `None` for SQLite URLs (file-based, no network host) or
/// if the host portion is already an IP address literal.
pub fn extract_db_hostname(db_url: &str) -> Option<String> {
    let parsed = url::Url::parse(db_url).ok()?;

    let scheme = parsed.scheme().to_lowercase();
    if scheme.contains("sqlite") {
        return None;
    }

    let host = parsed.host_str()?;

    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(host.to_string())
}

/// Redact credentials from a database URL for safe logging.
pub fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            if !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
            }
            parsed.to_string()
        }
        Err(_) => "<invalid-url>".to_string(),
    }
}
