//! Database backend trait — abstracts config storage for SQL (sqlx) and NoSQL (MongoDB) backends.
//!
//! All database operations needed by the admin API, operating modes, and config
//! polling are defined here. Each backend (sqlx, MongoDB) provides its own
//! implementation. The trait is object-safe so it can be used as `Arc<dyn DatabaseBackend>`.

use crate::config::types::{ApiSpec, Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use std::collections::HashSet;

/// User-facing proxy route conflict message shared by preflight and persistence checks.
pub const PROXY_ROUTE_CONFLICT_ERROR: &str =
    "A proxy with overlapping hosts and listen_path already exists";

// ---------------------------------------------------------------------------
// ApiSpec list filter types (Wave 5)
// ---------------------------------------------------------------------------

/// Sort column for `list_api_specs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApiSpecSortBy {
    /// `updated_at` — default, most recent first.
    #[default]
    UpdatedAt,
    Title,
    OperationCount,
    CreatedAt,
}

/// Sort direction for `list_api_specs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    /// Descending — default (most recent first for timestamps).
    #[default]
    Desc,
    Asc,
}

/// Filter parameters for `list_api_specs`.
#[derive(Debug, Clone)]
pub struct ApiSpecListFilter {
    /// Exact match on `proxy_id`.
    pub proxy_id: Option<String>,
    /// Prefix match on `spec_version` (e.g. `"3.1"` matches `"3.1.0"`, `"3.1.1"`).
    pub spec_version_prefix: Option<String>,
    /// Case-insensitive substring match on `title`.
    pub title_contains: Option<String>,
    /// `updated_at >= ?`
    pub updated_since: Option<DateTime<Utc>>,
    /// Exact tag membership (tag name must appear in the stored JSON array).
    pub has_tag: Option<String>,
    /// Column to sort by (default: `UpdatedAt`).
    pub sort_by: ApiSpecSortBy,
    /// Sort direction (default: `Desc`).
    pub order: SortOrder,
    /// Maximum number of rows to return (default 50, max 200).
    pub limit: u32,
    /// Row offset for pagination (default 0).
    pub offset: u32,
}

impl Default for ApiSpecListFilter {
    fn default() -> Self {
        Self {
            proxy_id: None,
            spec_version_prefix: None,
            title_contains: None,
            updated_since: None,
            has_tag: None,
            sort_by: ApiSpecSortBy::default(),
            order: SortOrder::default(),
            limit: 50,
            offset: 0,
        }
    }
}

/// Result of an incremental config poll.
///
/// Contains only the resources that changed since the last poll, plus IDs of
/// resources that were deleted. The polling loop uses this to apply surgical
/// updates without loading the entire database.
///
/// Serializable for CP-to-DP gRPC delta broadcasts.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    /// Read replica pool stats, if a configured admin-read replica is active.
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

/// Result of a narrow gateway trust-bundle poll.
#[allow(dead_code)] // `Unchanged` is for backends with a narrow change detector.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayTrustBundlePoll {
    /// The backend knows the authoritative trust-bundle source has not changed.
    Unchanged,
    /// The backend has the current authoritative value. `None` explicitly clears
    /// previously delivered CP trust material.
    Current(Option<Box<crate::modes::mesh::config::TrustBundleSet>>),
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

    /// Returns true if a configured read replica currently has an active pool.
    fn read_replica_available(&self) -> bool {
        self.has_read_replica()
    }

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

    /// Set the maximum rows fetched per query during full config loading.
    /// Only meaningful for SQL backends; MongoDB uses cursor-based loading.
    fn set_full_load_page_size(&mut self, page_size: u64);

    /// Set the certificate expiry warning threshold (days before expiration).
    fn set_cert_expiry_warning_days(&mut self, days: u64);

    /// Set the backend IP allowlist policy for SSRF protection.
    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendAllowIps);

    // -----------------------------------------------------------------------
    // Full config loading
    // -----------------------------------------------------------------------

    /// Load the full gateway configuration from the database.
    async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error>;

    /// Poll gateway-to-mesh trust bundles from the authoritative config source.
    ///
    /// This must stay narrow: the common empty incremental-poll path calls it so
    /// trust-bundle-only changes can be detected without reloading all gateway
    /// resources.
    async fn load_gateway_trust_bundles(
        &self,
        namespace: &str,
    ) -> Result<GatewayTrustBundlePoll, anyhow::Error>;

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
    /// Load an existing proxy for write prechecks/audit without rejecting
    /// repairable proxy-plugin reference corruption. Backends that store
    /// associations inline can use the normal read path.
    async fn get_proxy_for_write(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
        self.get_proxy(id).await
    }
    /// Check whether a proxy with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace, so
    /// admin-side reference checks cannot be satisfied by a row that lives
    /// in a different namespace.
    async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error>;
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

    /// Returns `true` when the `(listen_path, hosts)` combination does not
    /// conflict with any existing proxy in `namespace`.
    ///
    /// Conflict semantics:
    /// - `Some(path) + non-empty hosts` — conflict with any existing proxy with
    ///   the same `listen_path` AND overlapping hosts (empty hosts on the
    ///   existing row counts as catch-all and overlaps with everything).
    /// - `Some(path) + empty hosts` — conflict with any existing proxy with the
    ///   same `listen_path` regardless of hosts.
    /// - `None + non-empty hosts` (host-only proxy) — conflict with any
    ///   existing proxy that has `listen_path IS NULL` AND overlapping hosts.
    /// - `None + empty hosts` — rejected upstream of this call in
    ///   `validate_fields_inner`. Defensive implementations should return an
    ///   error or `Ok(false)` here.
    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
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
        consumer_id: &str,
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

    /// Check whether an upstream with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace, so a
    /// proxy in namespace A cannot reference an upstream that actually lives
    /// in namespace B (which would silently 502 at runtime).
    async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error>;

    /// Validate that a proxy's plugin association list references existing
    /// plugin configs. Plugin configs are looked up only within `namespace`
    /// — references to plugin_configs in other namespaces are rejected as
    /// non-existent so cross-namespace pollution is impossible.
    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
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
    ///
    /// The URL must be the effective URL produced by `EnvConfig`, including any
    /// database TLS parameters derived from `FERRUM_DB_TLS_MODE`.
    async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error>;

    /// Atomically replace the admin-read replica pool with a freshly connected one.
    async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error>;

    /// Try to reconnect to any available database URL (primary first, then failover).
    async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error>;

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

    /// Return the list of custom-plugin migrations that have not yet been
    /// applied to the database. Used at startup to warn operators when a
    /// gateway upgrade brings in new plugin schema changes that have not yet
    /// been applied.
    ///
    /// The default implementation returns an empty list — appropriate for
    /// backends that do not support SQL-based plugin migrations (e.g.,
    /// MongoDB; per the docs, `CustomPluginMigration` is SQL-only and
    /// MongoDB plugins create collections/indexes inside `create_plugin()`).
    async fn pending_plugin_migrations(
        &self,
        _plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PendingPluginMigration>, anyhow::Error> {
        Ok(Vec::new())
    }

    /// Apply all pending custom-plugin migrations. Used by the opt-in
    /// `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true` startup path so operators
    /// can ship a binary upgrade with bundled plugin schema changes without
    /// running a separate `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up`
    /// step.
    ///
    /// The default implementation is a no-op for backends that do not
    /// support SQL-based plugin migrations (e.g., MongoDB).
    async fn apply_plugin_migrations(
        &self,
        _plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PluginMigrationRecord>, anyhow::Error> {
        Ok(Vec::new())
    }

    /// Return all distinct namespaces across all resource tables for admin reads.
    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error>;

    /// Return all distinct namespaces using the authoritative primary read path.
    ///
    /// Runtime config polling uses this when `FERRUM_CP_NAMESPACES=*` so namespace
    /// discovery cannot lag behind primary resource reads.
    async fn list_namespaces_authoritative(&self) -> Result<Vec<String>, anyhow::Error> {
        self.list_namespaces().await
    }

    // -----------------------------------------------------------------------
    // ApiSpec CRUD (admin-only — NEVER call from polling loops, gRPC
    // distribution, or GatewayConfig loading. Hot-path isolation is critical.)
    // -----------------------------------------------------------------------

    /// Atomically insert the api_spec row plus all bundle resources.
    ///
    /// Insertion order: upstream (optional) → proxy → plugin_configs → api_spec.
    /// All four resource kinds are tagged with `api_spec_id = spec.id`.
    ///
    /// Returns `Err` if any unique constraint is violated (e.g. duplicate proxy
    /// id or duplicate `(namespace, proxy_id)` on api_specs). Wave 3 handlers
    /// map constraint violations to HTTP 409.
    async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error>;

    /// Atomically replace an existing api spec identified by `spec.id`.
    ///
    /// Deletes the spec-owned resources (those whose `api_spec_id = spec.id`),
    /// then inserts the new bundle in their place, and updates the api_spec row.
    /// Resources not owned by the spec (e.g. hand-added plugins whose
    /// `api_spec_id` is NULL) are left untouched.
    async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error>;

    /// Fetch a single ApiSpec by namespace + id.
    async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error>;

    /// Fetch the ApiSpec that owns a given proxy (by proxy_id), if any.
    async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error>;

    /// List ApiSpecs in a namespace, with filtering, sorting, and pagination.
    ///
    /// This is a summary path: implementations must not hydrate the
    /// `spec_content` blob for each row. Returned items carry empty
    /// `spec_content`; callers that need the original document must use
    /// `get_api_spec` or `get_api_spec_by_proxy`.
    ///
    /// Default sort is `updated_at DESC` (most recent first).
    /// `filter.limit` and `filter.offset` drive pagination.
    /// The returned [`PaginatedResult`] includes a `total` count of all matching
    /// rows (ignoring limit/offset) so callers can build "showing X of Y" UI.
    async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &ApiSpecListFilter,
    ) -> Result<PaginatedResult<ApiSpec>, anyhow::Error>;

    /// Delete an ApiSpec and all resources it owns.
    ///
    /// Deletion order: spec-owned plugin_configs and upstreams (manual cleanup
    /// because the `api_spec_id` back-links are not FK-enforced), then the
    /// proxy (whose FK cascade also removes the api_specs row). Returns `true`
    /// if a spec was found and deleted.
    async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;

    /// List the plugin configs owned by a specific api spec (tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to resolve existing spec-owned plugin IDs so
    /// re-submitted specs with empty plugin IDs can reuse them rather than
    /// minting fresh UUIDs every time.
    ///
    /// Admin-only. NEVER call from polling loops, gRPC distribution, or
    /// GatewayConfig loading.
    async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::PluginConfig>, anyhow::Error>;

    /// List upstreams owned by a specific api spec (tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to resolve the existing spec-owned upstream
    /// independently from the mutable proxy.upstream_id pointer, which regular
    /// admin CRUD can change.
    ///
    /// Admin-only. NEVER call from polling loops, gRPC distribution, or
    /// GatewayConfig loading.
    async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::Upstream>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Admin audit log (admin-only — runtime config loading and proxy hot paths
    // must never read this table/collection).
    // -----------------------------------------------------------------------

    async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error>;

    async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error>;
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
    let parsed = match url::Url::parse(db_url) {
        Ok(parsed) => parsed,
        Err(_) => return extract_mongodb_multi_host_hostname(db_url),
    };

    let scheme = parsed.scheme().to_lowercase();
    if scheme.contains("sqlite") {
        return None;
    }

    let host = parsed.host_str()?;

    // MongoDB seed lists without explicit ports (e.g.
    // `mongodb://user:pass@mongo1,mongo2/ferrum`) are accepted by `url` as a
    // single comma-joined host. Re-route through the multi-host extractor so
    // DNS rotation tracks the first seed host instead of an unresolvable
    // combined authority.
    if host.contains(',') {
        return extract_mongodb_multi_host_hostname(db_url);
    }

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
            if parsed.password().is_some() && parsed.set_password(Some("***")).is_err() {
                return "<invalid-url>".to_string();
            }
            if !parsed.username().is_empty() && parsed.set_username("***").is_err() {
                return "<invalid-url>".to_string();
            }
            if let Some(query) = parsed.query() {
                // Redact via the shared option-aware scrubber rather than
                // `query_pairs()`, which only splits on `&` and would leak
                // credentials carried in MongoDB `;`-separated options or in
                // `authMechanismProperties` token lists.
                let redacted_query = redact_query_string(query);
                parsed.set_query(Some(&redacted_query));
            }
            parsed.to_string()
        }
        Err(_) => redact_mongodb_multi_host_url(url).unwrap_or_else(|| "<invalid-url>".to_string()),
    }
}

/// Redact configured database URLs if a driver error includes them verbatim.
pub fn redact_error_text(error: impl std::fmt::Display, urls: &[&str]) -> String {
    let mut text = error.to_string();
    for url in urls {
        text = text.replace(url, &redact_url(url));
    }
    text
}

fn extract_mongodb_multi_host_hostname(db_url: &str) -> Option<String> {
    let authority = mongodb_multi_host_authority(db_url)?;
    let hosts = strip_mongodb_userinfo(authority);
    let first_host = hosts.split(',').next()?.trim();
    if first_host.is_empty() {
        return None;
    }

    let host = if let Some(rest) = first_host.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        first_host.split(':').next().unwrap_or(first_host)
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(host.to_string())
}

fn redact_mongodb_multi_host_url(raw_url: &str) -> Option<String> {
    let scheme_len = mongodb_multi_host_scheme_len(raw_url)?;
    let rest = &raw_url[scheme_len..];
    let authority_end = rest
        .find(|ch| ['/', '?', '#'].contains(&ch))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if !authority.contains(',') {
        return None;
    }

    let redacted_authority = if let Some(at) = authority.rfind('@') {
        format!("***@{}", &authority[at + 1..])
    } else {
        authority.to_string()
    };
    let suffix = redact_url_suffix_query(&rest[authority_end..]);
    Some(format!(
        "{}{}{}",
        &raw_url[..scheme_len],
        redacted_authority,
        suffix
    ))
}

fn mongodb_multi_host_authority(db_url: &str) -> Option<&str> {
    let scheme_len = mongodb_multi_host_scheme_len(db_url)?;
    let rest = &db_url[scheme_len..];
    let authority_end = rest
        .find(|ch| ['/', '?', '#'].contains(&ch))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    authority.contains(',').then_some(authority)
}

fn mongodb_multi_host_scheme_len(db_url: &str) -> Option<usize> {
    const MONGODB_SCHEME: &str = "mongodb://";
    db_url
        .get(..MONGODB_SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(MONGODB_SCHEME))
        .map(str::len)
}

fn strip_mongodb_userinfo(authority: &str) -> &str {
    authority
        .rfind('@')
        .map(|at| &authority[at + 1..])
        .unwrap_or(authority)
}

fn redact_url_suffix_query(suffix: &str) -> String {
    let Some(query_start) = suffix.find('?') else {
        return suffix.to_string();
    };
    let (before_query, query_and_fragment) = suffix.split_at(query_start + 1);
    let (query, fragment) = match query_and_fragment.find('#') {
        Some(fragment_start) => query_and_fragment.split_at(fragment_start),
        None => (query_and_fragment, ""),
    };
    let redacted_query = redact_query_string(query);
    format!("{before_query}{redacted_query}{fragment}")
}

/// Redact credential-bearing values from a URL query string.
///
/// Splits on both `&` and `;`. MongoDB documents `;` as an accepted option
/// separator, and `url`'s `form_urlencoded` parser only splits on `&`, so a
/// `;`-joined option such as `replicaSet=rs0;password=secret` would otherwise be
/// treated as a single non-sensitive `replicaSet` value and leak the password.
/// Re-serialization normalizes the separator to `&`, which every driver accepts.
fn redact_query_string(query: &str) -> String {
    query
        .split(['&', ';'])
        .filter(|option| !option.is_empty())
        .map(redact_query_option)
        .collect::<Vec<_>>()
        .join("&")
}

/// Redact a single `name[=value]` query option according to its key.
fn redact_query_option(option: &str) -> String {
    let (key, value) = match option.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (option, None),
    };

    let Some(value) = value else {
        return key.to_string();
    };

    let decoded_key = percent_decode_str(key).decode_utf8_lossy();
    let decoded_key = decoded_key.as_ref();

    if is_sensitive_url_query_key(decoded_key) {
        return format!("{key}=***");
    }

    // MongoDB's `authMechanismProperties` carries a comma-separated list of
    // `NAME:VALUE` properties; with MONGODB-AWS the AWS session token rides in
    // `AWS_SESSION_TOKEN:<secret>`. The key itself is not sensitive, so redact
    // any credential-bearing property value within it while keeping benign
    // properties (e.g. `CANONICALIZE_HOST_NAME:true`) for observability. Query
    // parameter names must be matched after percent-decoding so encoded aliases
    // such as `authMechanismPropert%69es` cannot bypass nested redaction.
    if normalize_query_key(decoded_key) == "authmechanismproperties" {
        return format!("{key}={}", redact_mechanism_properties(value));
    }

    format!("{key}={value}")
}

/// Redact credential-bearing properties inside a MongoDB
/// `authMechanismProperties` value (`NAME:VALUE` pairs separated by `,`).
fn redact_mechanism_properties(value: &str) -> String {
    value
        .split(',')
        .map(|property| match property.split_once(':') {
            Some((name, _)) if is_sensitive_url_query_key(name) => format!("{name}:***"),
            _ => property.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn is_sensitive_url_query_key(key: &str) -> bool {
    // Callers pass percent-decoded key names so encoded sensitive aliases such
    // as `pass%77ord` are matched using their semantic query-parameter name.
    // Exact (separator-insensitive) matches for credential-bearing keys that do
    // not contain one of the `SENSITIVE_SUBSTRINGS` below. Compared against the
    // normalized key, so `api_key`, `api-key`, and `apiKey` all match `apikey`.
    const SENSITIVE_KEYS: &[&str] = &[
        "apikey",
        "key",
        "pass",
        "privatekey",
        "sslkey",
        "user",
        "username",
    ];

    // Driver query parameters frequently embed credentials under
    // option-specific aliases (e.g. MongoDB's `tlsCertificateKeyFilePassword`,
    // PostgreSQL's `sslpassword`, OAuth-style `client_secret`/`access_token`).
    // Matching these credential-bearing substrings after normalization keeps
    // such aliases redacted even when they are not in the exact-key list. Only
    // unambiguously secret substrings are listed; path or identifier options
    // like `tlsCertificateKeyFile` (a file path) must not be matched here, so
    // `key`/`user` are intentionally excluded from the substring set.
    const SENSITIVE_SUBSTRINGS: &[&str] = &["password", "passwd", "secret", "token", "credential"];

    let normalized = normalize_query_key(key);
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| normalized == *sensitive)
        || SENSITIVE_SUBSTRINGS
            .iter()
            .any(|sensitive| normalized.contains(sensitive))
}

/// Normalize a query-parameter key for sensitivity matching: lowercase and
/// strip `-`/`_`/`.` separators so aliases like `client-secret`, `client_secret`,
/// and `clientSecret` all compare equal.
fn normalize_query_key(key: &str) -> String {
    key.chars()
        .filter(|ch| !matches!(ch, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}
