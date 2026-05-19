//! Database config loader with incremental polling.
//!
//! **Incremental polling strategy** (two-phase):
//! 1. **Change detection**: Indexed `WHERE updated_at >= ?` queries on 4 tables to
//!    fetch only rows modified since the last poll. A 1-second safety margin on the
//!    timestamp prevents missing boundary writes due to clock skew or in-flight commits.
//!    The `>=` (inclusive) ensures rows written at exactly the boundary are never missed;
//!    duplicates from the overlap are harmless because the incremental result is merged by ID.
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
    AuthMode, BackendScheme, CircuitBreakerConfig, Consumer, DispatchKind, GatewayConfig,
    HealthCheckConfig, LoadBalancerAlgorithm, PluginAssociation, PluginConfig, PluginScope, Proxy,
    ResponseBodyMode, RetryConfig, ServiceDiscoveryConfig, Upstream, UpstreamTarget,
};
use crate::config::validation_pipeline::{ValidationAction, ValidationPipeline};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
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
    ApiSpecListFilter, ApiSpecSortBy, DatabaseBackend, GatewayTrustBundlePoll, IncrementalResult,
    PaginatedResult, SortOrder, extract_db_hostname, extract_known_ids, redact_url,
};

struct PluginConfigRef {
    id: String,
    scope: PluginScope,
    proxy_id: Option<String>,
}

fn mesh_route_dispatch_references_upstream_id(plugin: &PluginConfig, upstream_id: &str) -> bool {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return false;
    }
    MeshRouteDispatchConfig::from_value(&plugin.config)
        .is_ok_and(|config| config.references_upstream_id(upstream_id))
}

fn mesh_route_dispatch_referenced_upstream(
    plugin: &PluginConfig,
    upstream_ids: &HashSet<String>,
) -> Option<String> {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return None;
    }
    let config = MeshRouteDispatchConfig::from_value(&plugin.config).ok()?;
    config
        .rules
        .iter()
        .filter_map(|rule| rule.destination.upstream_id.as_deref())
        .find(|upstream_id| upstream_ids.contains(*upstream_id))
        .map(ToOwned::to_owned)
}

fn upstream_backend_tls_san_allow_list_json(
    upstream: &Upstream,
) -> Result<Option<String>, anyhow::Error> {
    if upstream.backend_tls_san_allow_list.is_empty() {
        Ok(None)
    } else {
        serde_json::to_string(&upstream.backend_tls_san_allow_list)
            .map(Some)
            .map_err(Into::into)
    }
}

fn declared_proxy_plugin_association_ids_from_spec(
    spec: &crate::config::types::ApiSpec,
) -> Result<HashSet<String>, anyhow::Error> {
    if spec.content_encoding != "gzip" {
        warn!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id, spec.content_encoding
        );
        return Ok(HashSet::new());
    }
    let cap = usize::try_from(spec.uncompressed_size).unwrap_or(usize::MAX);
    let body = match crate::admin::spec_codec::decompress_gzip_capped(&spec.spec_content, cap) {
        Ok(body) => body,
        Err(e) => {
            warn!(
                "failed to decompress stored api_spec '{}' proxy plugin associations: {}",
                spec.id, e
            );
            return Ok(HashSet::new());
        }
    };
    let ids = match crate::admin::api_specs::extract_declared_proxy_plugin_association_ids(
        &body,
        Some(spec.spec_format),
    ) {
        Ok(ids) => ids,
        Err(e) => {
            warn!(
                "failed to parse stored api_spec '{}' proxy plugin associations: {}",
                spec.id, e
            );
            return Ok(HashSet::new());
        }
    };
    Ok(ids.into_iter().collect())
}

fn store_canonical_resource_hash(
    bundle: &crate::admin::api_specs::ExtractedBundle,
) -> Result<String, anyhow::Error> {
    let mut proxy = bundle.proxy.clone();
    proxy.normalize_fields();
    let upstream = bundle.upstream.clone().map(|mut upstream| {
        upstream.normalize_fields();
        upstream
    });
    let mut plugins = bundle.plugins.clone();
    for plugin in &mut plugins {
        plugin.normalize_fields();
    }
    crate::admin::api_specs::hash_resource_bundle(&crate::admin::api_specs::ExtractedBundle {
        proxy,
        upstream,
        plugins,
    })
}

/// Identifies a resource table for lightweight `SELECT id` queries.
///
/// Used by `load_table_ids()` to eliminate dynamic table-name interpolation
/// and make SQL injection impossible by construction.
#[derive(Clone, Copy)]
enum ResourceTable {
    Proxies,
    Consumers,
    PluginConfigs,
    Upstreams,
}

impl ResourceTable {
    /// Static SQL for loading IDs — no format!() needed.
    const fn select_ids_sql(self) -> &'static str {
        match self {
            Self::Proxies => "SELECT id FROM proxies WHERE namespace = ?",
            Self::Consumers => "SELECT id FROM consumers WHERE namespace = ?",
            Self::PluginConfigs => "SELECT id FROM plugin_configs WHERE namespace = ?",
            Self::Upstreams => "SELECT id FROM upstreams WHERE namespace = ?",
        }
    }

    /// Label for slow-query logging.
    const fn load_ids_label(self) -> &'static str {
        match self {
            Self::Proxies => "load_table_ids(proxies)",
            Self::Consumers => "load_table_ids(consumers)",
            Self::PluginConfigs => "load_table_ids(plugin_configs)",
            Self::Upstreams => "load_table_ids(upstreams)",
        }
    }
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
    /// 30, max 3600 (clamped at `EnvConfig` parse time). Set via
    /// `SET statement_timeout` (PostgreSQL) or `SET SESSION max_execution_time`
    /// (MySQL) on every new connection. Prevents runaway queries from holding
    /// connections indefinitely. 0 = disabled (no per-statement timeout).
    /// Ignored for SQLite.
    pub statement_timeout_seconds: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 32,
            min_connections: 1,
            acquire_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 10,
            statement_timeout_seconds: 30,
        }
    }
}

/// Build the `SET` SQL for per-statement timeouts, or `None` when disabled.
///
/// Returns:
/// - PostgreSQL: `SET statement_timeout = <ms>` (unquoted numeric)
/// - MySQL: `SET SESSION max_execution_time = <ms>`
/// - SQLite / `timeout_seconds == 0`: `None`
///
/// The caller is responsible for clamping `timeout_seconds` before calling
/// (enforced at `EnvConfig` parse time, 0..=3600).
pub(crate) fn statement_timeout_sql(
    timeout_seconds: u64,
    is_postgres: bool,
    is_mysql: bool,
) -> Option<String> {
    if timeout_seconds == 0 {
        return None;
    }
    let timeout_ms = timeout_seconds * 1000;
    if is_postgres {
        Some(format!("SET statement_timeout = {timeout_ms}"))
    } else if is_mysql {
        Some(format!("SET SESSION max_execution_time = {timeout_ms}"))
    } else {
        None
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
    /// Maximum rows fetched per query during full config loading.
    /// Configurable via `FERRUM_DB_FULL_LOAD_PAGE_SIZE`. Default: 10000.
    full_load_page_size: i64,
    cert_expiry_warning_days: u64,
    backend_allow_ips: crate::config::BackendAllowIps,
    /// Set to `true` when the store was created via
    /// [`DatabaseStore::connect_offline_with_pool_config`] — the lazy pool
    /// never ran migrations because the DB was unreachable at startup.
    /// Cleared once migrations succeed against a recovered DB. `reconnect()`
    /// checks this flag and runs migrations on the first successful reconnect
    /// so the polling loop does not loop forever on a missing schema.
    /// Shared via `Arc<AtomicBool>` so all clones of the store observe the
    /// same cleared-state after recovery.
    migrations_pending: Arc<std::sync::atomic::AtomicBool>,
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
                    // SQLite per-connection PRAGMAs (not persistent across pool
                    // connections — must be set on every checkout).
                    if is_sqlite {
                        conn.execute("PRAGMA foreign_keys = ON").await?;
                        // WAL mode dramatically improves concurrent read/write
                        // performance. Unlike other PRAGMAs this persists on the
                        // database file, but setting it per-connection is a harmless
                        // no-op once applied and ensures it is always enabled even
                        // after a fresh database creation.
                        conn.execute("PRAGMA journal_mode = WAL").await?;
                        // Without busy_timeout, concurrent writes immediately fail
                        // with SQLITE_BUSY. 5 000 ms gives the WAL writer time to
                        // finish before returning an error.
                        conn.execute("PRAGMA busy_timeout = 5000").await?;
                    }
                    // Set per-statement timeout on network databases to prevent
                    // runaway queries from holding connections indefinitely.
                    //
                    // Safety: `statement_timeout_seconds` is a `u64` parsed from
                    // `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` and clamped to
                    // 0..=3600 at `EnvConfig` parse time, so the `format!()`
                    // interpolation always produces a plain integer literal.
                    // `SET` commands do not support `$1`/`?` parameterized
                    // placeholders in sqlx, hence the string interpolation.
                    if let Some(sql) =
                        statement_timeout_sql(statement_timeout_seconds, is_postgres, is_mysql)
                    {
                        conn.execute(sql.as_str()).await?;
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
    pub(crate) fn append_connect_timeout(url: &str, db_type: &str, timeout_seconds: u64) -> String {
        if timeout_seconds == 0 || db_type == "sqlite" {
            return url.to_string();
        }
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{}{}connect_timeout={}", url, separator, timeout_seconds)
    }

    /// Connect to the database with the provided pool configuration and run migrations.
    pub async fn connect_with_pool_config(
        db_type: &str,
        db_url: &str,
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        // Install all drivers
        sqlx::any::install_default_drivers();

        let final_url =
            Self::append_connect_timeout(db_url, db_type, pool_config.connect_timeout_seconds);

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
            full_load_page_size: Self::DEFAULT_FULL_LOAD_PAGE_SIZE,
            cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
            backend_allow_ips: crate::config::BackendAllowIps::Both,
            migrations_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        store.run_migrations().await?;

        info!(
            "Database connected and migrations applied (type={}, max_connections={}, min_connections={})",
            db_type, store.pool_config.max_connections, store.pool_config.min_connections
        );
        Ok(store)
    }

    /// Construct a `DatabaseStore` with a lazy pool — no TCP connection is
    /// opened and no migrations run. The first query will trigger connection
    /// (and may fail). Use this only as a bootstrap fallback when eager
    /// connection has failed but a backup config is being loaded from disk:
    /// the gateway serves from cached config while the background polling
    /// loop retries the pool until the DB becomes reachable again.
    ///
    /// `failover_urls` is stored on the returned `DatabaseStore` so that the
    /// polling loop's `try_failover_reconnect()` call can probe each URL in
    /// order — a primary that stays down should not prevent recovery when a
    /// configured failover DB is healthy.
    ///
    /// The returned store has `migrations_pending=true`. The first successful
    /// `reconnect()` (primary or failover) will run migrations, because a DB
    /// that comes back with a fresh or outdated schema must be brought up to
    /// the expected version before the polling loop can read from it.
    pub fn connect_offline_with_pool_config(
        db_type: &str,
        db_url: &str,
        failover_urls: &[String],
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        sqlx::any::install_default_drivers();

        let final_url =
            Self::append_connect_timeout(db_url, db_type, pool_config.connect_timeout_seconds);

        // `connect_lazy` does not attempt a connection — the pool is ready to
        // hand out connections on first query. Migrations are deferred until
        // the database becomes reachable and the polling loop drives a
        // successful `reconnect()`.
        let pool =
            Self::build_pool_options_from_config(&pool_config, db_type).connect_lazy(&final_url)?;

        Ok(Self {
            pool: Arc::new(ArcSwap::from_pointee(pool)),
            read_replica_pool: None,
            db_type: db_type.to_string(),
            failover_urls: failover_urls.to_vec(),
            pool_config,
            slow_query_threshold_ms: None,
            full_load_page_size: Self::DEFAULT_FULL_LOAD_PAGE_SIZE,
            cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
            backend_allow_ips: crate::config::BackendAllowIps::Both,
            migrations_pending: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
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

    /// If `migrations_pending` is set (only true for offline-bootstrapped
    /// stores), try to run migrations now. Returns `Ok(true)` if migrations
    /// were actually executed, `Ok(false)` if nothing was pending.
    ///
    /// Uses a CAS from `true → false` so concurrent callers don't run
    /// migrations twice: whichever caller wins the CAS is the designated
    /// runner. On failure, the flag is restored so the next caller retries.
    ///
    /// This is the canonical entry point for clearing the deferred-migration
    /// state. Call it:
    /// - At startup right after offline bootstrap (so the startup path
    ///   doesn't wait for the first polling tick to catch up).
    /// - At the end of `reconnect()` (for the failover-reconnect path).
    /// - On each successful polling-loop query (for the case where the lazy
    ///   pool happened to connect on the first query and `reconnect()` never
    ///   fired — otherwise the flag would stay `true` indefinitely).
    pub async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        use std::sync::atomic::Ordering;

        // Only one caller wins the CAS and runs migrations; the rest see
        // `Ok(false)` and return early. Acquire on success ensures we see
        // the constructor's write of `true`; Release on the clear ensures
        // other CPUs observe post-migration state after we complete.
        if self
            .migrations_pending
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }

        info!("Applying deferred migrations after backup-bootstrap recovery");
        match self.run_migrations().await {
            Ok(()) => {
                info!("Deferred migrations applied — database ready for polling");
                Ok(true)
            }
            Err(e) => {
                // Restore the flag so the next caller retries. Without this,
                // a transient migration failure would silently skip forever.
                self.migrations_pending.store(true, Ordering::Release);
                Err(e)
            }
        }
    }

    /// Load the full gateway configuration from the database.
    pub async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
        let start = Instant::now();
        // Capture timestamp before queries so the incremental polling safety
        // margin covers the full load duration.
        let loaded_at = Utc::now();
        let proxies = self.load_proxies(namespace).await?;
        let consumers = self.load_consumers(namespace).await?;
        let plugin_configs = self.load_plugin_configs(namespace).await?;
        let upstreams = self.load_upstreams(namespace).await?;

        let mut config = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            consumers,
            plugin_configs,
            upstreams,
            loaded_at,
            known_namespaces: Vec::new(),
            ..Default::default()
        };

        ValidationPipeline::new(&mut config)
            .normalize_fields()
            .resolve_upstream_tls()
            .validate_all_fields_with_ip_policy(
                self.cert_expiry_warning_days,
                &self.backend_allow_ips,
                ValidationAction::Warn,
            )
            .validate_hosts(ValidationAction::Warn)
            .validate_regex_listen_paths(ValidationAction::FatalStatic(
                "Database has invalid regex listen_path(s)",
            ))
            .validate_unique_listen_paths(ValidationAction::FatalStatic(
                "Database has conflicting host+listen_path combinations",
            ))
            .validate_stream_proxies(ValidationAction::FatalCount(
                "Database configuration validation failed: {} stream proxy error(s) found",
            ))
            .validate_unique_consumer_identities(ValidationAction::Warn)
            .validate_unique_consumer_credentials(ValidationAction::Warn)
            .validate_upstream_references(ValidationAction::FatalStatic(
                "Database has invalid upstream reference(s)",
            ))
            .validate_mesh_route_dispatch_references(ValidationAction::FatalStatic(
                "Database has invalid mesh_route_dispatch upstream reference(s)",
            ))
            .validate_plugin_references(ValidationAction::FatalStatic(
                "Database has invalid plugin reference(s)",
            ))
            .validate_plugin_configs(ValidationAction::Warn)
            .validate_plugin_file_dependencies(ValidationAction::Warn)
            .run()?;

        // Hot-path isolation: strip api_spec_id from runtime config. The row
        // mappers preserve api_spec_id so admin GET/list paths can serialise
        // it; here we ensure the gateway's in-memory `GatewayConfig` does
        // not carry the ownership tag (the runtime never reads it, and CP
        // gRPC broadcasts must not leak it to DPs). Mirrors the strip done
        // by Mongo's `load_full_config`. See the cross-backend invariant
        // test `runtime_load_strips_api_spec_id_from_resources`.
        strip_api_spec_id_from_runtime_config(&mut config);

        self.check_slow_query("load_full_config", start);
        Ok(config)
    }

    async fn load_proxies(&self, namespace: &str) -> Result<Vec<Proxy>, anyhow::Error> {
        let start = Instant::now();

        // Batch-load proxy_plugins for proxies in this namespace (eliminates N+1).
        let assoc_rows: Vec<AnyRow> =
            match sqlx::query(&self.q("SELECT pp.proxy_id, pp.plugin_config_id FROM proxy_plugins pp INNER JOIN proxies p ON pp.proxy_id = p.id WHERE p.namespace = ?"))
                .bind(namespace)
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
            let rows: Vec<AnyRow> = sqlx::query(
                &self.q("SELECT * FROM proxies WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
            )
            .bind(namespace)
            .bind(self.full_load_page_size)
            .bind(offset)
            .fetch_all(&self.rpool())
            .await?;
            let fetched = rows.len();
            for row in rows {
                let id: String = row.try_get("id")?;
                let plugins = plugins_by_proxy.remove(&id).unwrap_or_default();
                proxies.push(row_to_proxy(&row, id, plugins)?);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
            offset += self.full_load_page_size;
        }

        self.check_slow_query("load_proxies", start);
        Ok(proxies)
    }

    async fn load_consumers(&self, namespace: &str) -> Result<Vec<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let mut consumers = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> = sqlx::query(
                &self.q("SELECT * FROM consumers WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
            )
            .bind(namespace)
            .bind(self.full_load_page_size)
            .bind(offset)
            .fetch_all(&self.rpool())
            .await?;
            let fetched = rows.len();
            for row in rows {
                consumers.push(row_to_consumer(&row)?);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
            offset += self.full_load_page_size;
        }

        self.check_slow_query("load_consumers", start);
        Ok(consumers)
    }

    async fn load_plugin_configs(
        &self,
        namespace: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let mut configs = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> = sqlx::query(&self.q(
                "SELECT * FROM plugin_configs WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?",
            ))
            .bind(namespace)
            .bind(self.full_load_page_size)
            .bind(offset)
            .fetch_all(&self.rpool())
            .await?;
            let fetched = rows.len();
            for row in rows {
                configs.push(row_to_plugin_config(&row)?);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
            offset += self.full_load_page_size;
        }

        self.check_slow_query("load_plugin_configs", start);
        Ok(configs)
    }

    // ---- Proxy INSERT SQL helpers ----
    //
    // The column list for a proxy INSERT appears in three places:
    //   1. `create_proxy`           — direct admin POST /proxies
    //   2. `batch_create_proxies_chunk` — bulk import
    //   3. `submit_api_spec_bundle` — spec-owned INSERT (adds `api_spec_id` column)
    //
    // Sites 1 and 2 share `PROXY_INSERT_SQL` (no api_spec_id).
    // Site 3 uses `PROXY_INSERT_WITH_SPEC_SQL` (adds api_spec_id before created_at).
    //
    // IMPORTANT: when adding a new column to `proxies`, update BOTH constants and
    // the corresponding `.bind()` chains in all three call sites.  The direct-admin
    // `update_proxy` (also in this file) and `replace_api_spec_bundle` UPDATE paths
    // are separate SQL strings and must be updated independently.
    //
    // NOTE: `submit_api_spec_bundle` uses a literal multi-line query string with
    // `\` continuation rather than this const because it adds the `api_spec_id`
    // column.  The `replace_api_spec_bundle` path uses UPDATE so it is out of scope.
    // ── Drift-prevention contract for proxy INSERT call sites ────────────────
    //
    // The 45-column proxy column list is canonical and shared by THREE INSERT
    // sites and ONE UPDATE site. When you add a new column to the `proxies`
    // table, it must be added — in the same position — to ALL of:
    //
    //   1. PROXY_INSERT_SQL                         (direct admin path)
    //   2. create_proxy() bind chain                (this file, ~line 790)
    //   3. submit_api_spec_bundle() proxy INSERT    (this file, ~line 3387)
    //   4. update_proxy() SET clause + bind chain   (this file, ~line 919)
    //   5. PROXY_INSERT_PLACEHOLDER_COUNT below     (drift catcher)
    //   6. PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT below
    //
    // The two `proxy_insert_sql_*_count_matches_bind_count` tests below count
    // `?` placeholders in the SQL and assert against the constants here. If
    // you forget to update the placeholder count, the test fails and points
    // at the exact discrepancy. If you update the constant but forget to
    // bind, sqlx returns "wrong number of parameters" at execute time.
    //
    // We chose this drift-catcher pattern over a fully-generic
    // `bind_proxy_base_columns` helper because the sqlx::Any generic makes
    // such helpers verbose without meaningful runtime benefit.

    /// Number of `?` placeholders in `PROXY_INSERT_SQL` (no api_spec_id).
    /// 47 base columns + `created_at` + `updated_at` = 49.
    ///
    /// Used only by the drift-catcher tests in `proxy_insert_sql_drift_tests`;
    /// kept available outside `#[cfg(test)]` so it remains a visible
    /// drift-prevention anchor when reading the SQL definition.
    #[allow(dead_code)]
    pub(crate) const PROXY_INSERT_PLACEHOLDER_COUNT: usize = 49;

    /// Number of `?` placeholders in the `submit_api_spec_bundle` proxy
    /// INSERT statement (which adds `api_spec_id` between
    /// `udp_max_response_amplification_factor` and `created_at`).
    /// 49 base + 1 (api_spec_id) = 50.
    #[allow(dead_code)]
    pub(crate) const PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT: usize = 50;

    /// Proxy INSERT SQL without `api_spec_id` (direct admin path and bulk import).
    ///
    /// Note: the `?` placeholder is rewritten to `$N` for PostgreSQL by `self.q()`.
    /// Any new column must be appended in the same position in `PROXY_INSERT_SQL`
    /// and the corresponding `.bind()` chain — see the drift-prevention contract
    /// block above.
    const PROXY_INSERT_SQL: &'static str = "\
        INSERT INTO proxies (id, namespace, name, hosts, listen_path, backend_scheme, \
         backend_host, backend_port, backend_path, strip_listen_path, preserve_host_header, \
         backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, \
         backend_tls_client_cert_path, backend_tls_client_key_path, \
         backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, \
         dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, \
         circuit_breaker, retry, response_body_mode, \
         pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, \
         pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, \
         pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, \
         pool_http2_initial_connection_window_size, pool_http2_adaptive_window, \
         pool_http2_max_frame_size, pool_http2_max_concurrent_streams, \
         pool_http3_connections_per_backend, pool_max_requests_per_connection, \
         listen_port, frontend_tls, passthrough, \
         udp_idle_timeout_seconds, tcp_idle_timeout_seconds, \
         allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, \
         upstream_subset, \
         created_at, updated_at) \
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                ?, ?, ?, ?)";

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

        sqlx::query(&self.q(Self::PROXY_INSERT_SQL))
            .bind(&proxy.id)
            .bind(&proxy.namespace)
            .bind(&proxy.name)
            .bind(&hosts_json)
            .bind(&proxy.listen_path)
            .bind(proxy.effective_scheme().to_scheme_str())
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
            .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
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
            .bind(&proxy.upstream_subset)
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
            &self.q("UPDATE proxies SET name=?, hosts=?, listen_path=?, backend_scheme=?, backend_host=?, backend_port=?, backend_path=?, strip_listen_path=?, preserve_host_header=?, backend_connect_timeout_ms=?, backend_read_timeout_ms=?, backend_write_timeout_ms=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, dns_override=?, dns_cache_ttl_seconds=?, auth_mode=?, upstream_id=?, upstream_subset=?, circuit_breaker=?, retry=?, response_body_mode=?, pool_idle_timeout_seconds=?, pool_enable_http_keep_alive=?, pool_enable_http2=?, pool_tcp_keepalive_seconds=?, pool_http2_keep_alive_interval_seconds=?, pool_http2_keep_alive_timeout_seconds=?, pool_http2_initial_stream_window_size=?, pool_http2_initial_connection_window_size=?, pool_http2_adaptive_window=?, pool_http2_max_frame_size=?, pool_http2_max_concurrent_streams=?, pool_http3_connections_per_backend=?, pool_max_requests_per_connection=?, listen_port=?, frontend_tls=?, passthrough=?, udp_idle_timeout_seconds=?, tcp_idle_timeout_seconds=?, allowed_methods=?, allowed_ws_origins=?, udp_max_response_amplification_factor=?, updated_at=? WHERE id=?")
        )
        .bind(&proxy.name)
        .bind(&hosts_json)
        .bind(&proxy.listen_path)
        .bind(proxy.effective_scheme().to_scheme_str())
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
        .bind(&proxy.upstream_subset)
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
        .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
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

        // Clean up orphaned proxy_group plugin configs (no remaining associations)
        self.cleanup_orphaned_proxy_group_plugins(&mut tx).await?;

        tx.commit().await?;

        self.check_slow_query("update_proxy", start);
        Ok(())
    }

    pub async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        // Look up the proxy's current upstream_id before deleting so we can
        // cascade-delete that upstream if it becomes orphaned. Also capture the
        // api_spec row, if this proxy owns one, before the FK cascade removes it.
        let proxy_row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT upstream_id FROM proxies WHERE id = ?"))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(proxy_row) = proxy_row else {
            tx.rollback().await?;
            self.check_slow_query("delete_proxy", start);
            return Ok(false);
        };
        let upstream_id: Option<String> = proxy_row.try_get::<String, _>("upstream_id").ok();

        let spec_row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id, namespace FROM api_specs WHERE proxy_id = ?"))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let spec_owner: Option<(String, String)> = spec_row
            .as_ref()
            .map(|row| Ok::<_, anyhow::Error>((row.try_get("id")?, row.try_get("namespace")?)))
            .transpose()?;
        if let Some((ref spec_id, ref namespace)) = spec_owner {
            self.ensure_no_external_spec_upstream_refs_tx(&mut tx, namespace, spec_id, id)
                .await?;
        }

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
            self.check_slow_query("delete_proxy", start);
            return Ok(false);
        }

        // Clean up orphaned proxy_group plugin configs (no remaining associations)
        self.cleanup_orphaned_proxy_group_plugins(&mut tx).await?;

        // If this was a spec-owned proxy, delete every upstream tagged with the
        // spec id, not only the proxy's current upstream_id. Direct admin CRUD
        // can drift the pointer away from the original spec-owned upstream.
        if let Some((ref spec_id, ref namespace)) = spec_owner {
            sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
                .bind(spec_id)
                .bind(namespace)
                .execute(&mut *tx)
                .await?;
        }

        // If the proxy had an upstream, check if it's now orphaned and delete it
        if let Some(ref uid) = upstream_id {
            let ref_rows: Vec<AnyRow> =
                sqlx::query(&self.q("SELECT id FROM proxies WHERE upstream_id = ? LIMIT 1"))
                    .bind(uid)
                    .fetch_all(&mut *tx)
                    .await?;
            let dispatch_ref = if ref_rows.is_empty() {
                self.find_mesh_route_dispatch_upstream_ref_tx(&mut tx, uid)
                    .await?
            } else {
                None
            };
            if ref_rows.is_empty() && dispatch_ref.is_none() {
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

    /// Delete proxy_group-scoped plugin configs that have no remaining proxy
    /// associations in the proxy_plugins junction table. Called within a
    /// transaction after proxy deletion or proxy update (which may remove
    /// associations).
    async fn cleanup_orphaned_proxy_group_plugins(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<(), anyhow::Error> {
        let orphaned_ids: Vec<String> = sqlx::query(&self.q(
            "SELECT pc.id FROM plugin_configs pc \
                 WHERE pc.scope = 'proxy_group' \
                 AND NOT EXISTS (SELECT 1 FROM proxy_plugins pp WHERE pp.plugin_config_id = pc.id)",
        ))
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .filter_map(|row| row.try_get::<String, _>("id").ok())
        .collect();

        for id in &orphaned_ids {
            info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
            sqlx::query(&self.q("DELETE FROM plugin_configs WHERE id = ?"))
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }

        Ok(())
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

    /// Check whether a proxy with the given ID exists in `namespace`.
    ///
    /// The `namespace` filter is required: admin-API callers must scope
    /// reference checks to the requesting tenant's namespace so that, for
    /// example, a `plugin_config.proxy_id` cannot point at a proxy that lives
    /// in a different namespace (such a config would never load at runtime
    /// because the polling path filters by namespace).
    pub async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM proxies WHERE id = ? AND namespace = ?"))
                .bind(proxy_id)
                .bind(namespace)
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
            &self.q("INSERT INTO consumers (id, namespace, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&consumer.id)
        .bind(&consumer.namespace)
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
            PluginScope::ProxyGroup => "proxy_group",
            PluginScope::Global => "global",
        };
        sqlx::query(
            &self.q("INSERT INTO plugin_configs (id, namespace, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&pc.id)
        .bind(&pc.namespace)
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
            PluginScope::ProxyGroup => "proxy_group",
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

    async fn load_upstreams(&self, namespace: &str) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let mut upstreams = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let rows: Vec<AnyRow> = sqlx::query(
                &self.q("SELECT * FROM upstreams WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
            )
            .bind(namespace)
            .bind(self.full_load_page_size)
            .bind(offset)
            .fetch_all(&self.rpool())
            .await?;
            let fetched = rows.len();
            for row in rows {
                upstreams.push(row_to_upstream(&row)?);
            }
            if (fetched as i64) < self.full_load_page_size {
                break;
            }
            offset += self.full_load_page_size;
        }

        self.check_slow_query("load_upstreams", start);
        Ok(upstreams)
    }

    // ---- Paginated list queries for Admin API ----

    /// List proxies with database-level LIMIT/OFFSET pagination.
    pub async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM proxies WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(&self.rpool())
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM proxies WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM consumers WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(&self.rpool())
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM consumers WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM plugin_configs WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(&self.rpool())
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self
                .q("SELECT * FROM plugin_configs WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        let start = Instant::now();

        let count_row =
            sqlx::query(&self.q("SELECT COUNT(*) AS cnt FROM upstreams WHERE namespace = ?"))
                .bind(namespace)
                .fetch_one(&self.rpool())
                .await?;
        let total: i64 = count_row.try_get("cnt")?;

        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM upstreams WHERE namespace = ? ORDER BY id LIMIT ? OFFSET ?"),
        )
        .bind(namespace)
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

        let subsets_json = upstream
            .subsets
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(upstream)?;

        sqlx::query(
            &self.q("INSERT INTO upstreams (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, subsets, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, backend_tls_sni, backend_tls_san_allow_list, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        )
        .bind(&upstream.id)
        .bind(&upstream.namespace)
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(&subsets_json)
        .bind(&upstream.backend_tls_client_cert_path)
        .bind(&upstream.backend_tls_client_key_path)
        .bind(upstream.backend_tls_verify_server_cert as i32)
        .bind(&upstream.backend_tls_server_ca_cert_path)
        .bind(&upstream.backend_tls_sni)
        .bind(&backend_tls_san_allow_list_json)
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
        let subsets_json = upstream
            .subsets
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let hash_on_cookie_config_json = upstream
            .hash_on_cookie_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(upstream)?;

        sqlx::query(
            &self.q("UPDATE upstreams SET name=?, targets=?, algorithm=?, hash_on=?, hash_on_cookie_config=?, health_checks=?, service_discovery=?, subsets=?, backend_tls_client_cert_path=?, backend_tls_client_key_path=?, backend_tls_verify_server_cert=?, backend_tls_server_ca_cert_path=?, backend_tls_sni=?, backend_tls_san_allow_list=?, updated_at=? WHERE id=?")
        )
        .bind(&upstream.name)
        .bind(&targets_json)
        .bind(algo_str)
        .bind(&upstream.hash_on)
        .bind(&hash_on_cookie_config_json)
        .bind(&health_checks_json)
        .bind(&service_discovery_json)
        .bind(&subsets_json)
        .bind(&upstream.backend_tls_client_cert_path)
        .bind(&upstream.backend_tls_client_key_path)
        .bind(upstream.backend_tls_verify_server_cert as i32)
        .bind(&upstream.backend_tls_server_ca_cert_path)
        .bind(&upstream.backend_tls_sni)
        .bind(&backend_tls_san_allow_list_json)
        .bind(Utc::now().to_rfc3339())
        .bind(&upstream.id)
        .execute(&self.pool())
        .await?;

        self.check_slow_query("update_upstream", start);
        Ok(())
    }

    async fn mesh_route_dispatch_plugin_configs_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM plugin_configs WHERE plugin_name = ? AND enabled != 0"),
        )
        .bind("mesh_route_dispatch")
        .fetch_all(&mut **tx)
        .await?;

        let mut plugins = Vec::with_capacity(rows.len());
        for row in &rows {
            plugins.push(row_to_plugin_config(row)?);
        }
        Ok(plugins)
    }

    async fn find_mesh_route_dispatch_upstream_ref_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        upstream_id: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error> {
        let plugins = self.mesh_route_dispatch_plugin_configs_tx(tx).await?;
        Ok(plugins
            .into_iter()
            .find(|plugin| mesh_route_dispatch_references_upstream_id(plugin, upstream_id)))
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
        if let Some(plugin) = self
            .find_mesh_route_dispatch_upstream_ref_tx(&mut tx, id)
            .await?
        {
            tx.rollback().await?;
            anyhow::bail!(
                "Upstream {} is referenced by mesh_route_dispatch plugin_config '{}' and cannot be deleted",
                id,
                plugin.id
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

        let dispatch_ref = if ref_rows.is_empty() {
            self.find_mesh_route_dispatch_upstream_ref_tx(&mut tx, old_upstream_id)
                .await?
        } else {
            None
        };

        if ref_rows.is_empty() && dispatch_ref.is_none() {
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
    /// See `DatabaseBackend::check_listen_path_unique` for the full conflict
    /// semantics. In short: `Some(path)` candidates are uniqueness-keyed by
    /// `(namespace, listen_path)` + host overlap; `None` (host-only) candidates
    /// are uniqueness-keyed by `(namespace, listen_path IS NULL)` + host
    /// overlap. `None + empty hosts` is rejected by the caller — returned
    /// `Ok(false)` defensively here.
    pub async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        // Defensive: None + empty hosts has no meaningful uniqueness scope.
        // validate_fields_inner rejects this at admission time; we still guard
        // so the DB layer never accepts a "match everything" proxy if a caller
        // slips past validation.
        if listen_path.is_none() && hosts.is_empty() {
            return Ok(false);
        }

        let start = Instant::now();
        let base_filter = "namespace = ? \
              AND backend_scheme NOT IN ('tcp', 'tcps', 'udp', 'dtls')";
        let path_filter = if listen_path.is_some() {
            "listen_path = ?"
        } else {
            "listen_path IS NULL"
        };

        let rows: Vec<AnyRow> = match (exclude_id, listen_path) {
            (Some(eid), Some(path)) => sqlx::query(&self.q(&format!(
                "SELECT id, hosts FROM proxies WHERE {base_filter} AND {path_filter} AND id != ?"
            )))
            .bind(namespace)
            .bind(path)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?,
            (Some(eid), None) => sqlx::query(&self.q(&format!(
                "SELECT id, hosts FROM proxies WHERE {base_filter} AND {path_filter} AND id != ?"
            )))
            .bind(namespace)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?,
            (None, Some(path)) => {
                sqlx::query(&self.q(&format!(
                    "SELECT id, hosts FROM proxies WHERE {base_filter} AND {path_filter}"
                )))
                .bind(namespace)
                .bind(path)
                .fetch_all(&self.pool())
                .await?
            }
            (None, None) => {
                sqlx::query(&self.q(&format!(
                    "SELECT id, hosts FROM proxies WHERE {base_filter} AND {path_filter}"
                )))
                .bind(namespace)
                .fetch_all(&self.pool())
                .await?
            }
        };

        self.check_slow_query("check_listen_path_unique", start);

        // No other proxy with this listen_path bucket — unique
        if rows.is_empty() {
            return Ok(true);
        }

        // `Some(path) + empty hosts` is a catch-all for the path — any existing
        // row in this bucket is a conflict regardless of its hosts.
        if listen_path.is_some() && hosts.is_empty() {
            return Ok(false);
        }

        // Otherwise check if any existing proxy's hosts overlap with the new hosts
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
        namespace: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q("SELECT id FROM proxies WHERE namespace = ? AND name = ? AND id != ?"),
            )
            .bind(namespace)
            .bind(name)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE namespace = ? AND name = ?"))
                .bind(namespace)
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
        namespace: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q("SELECT id FROM upstreams WHERE namespace = ? AND name = ? AND id != ?"),
            )
            .bind(namespace)
            .bind(name)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE namespace = ? AND name = ?"))
                .bind(namespace)
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
        namespace: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        let start = Instant::now();
        let (sql, binds): (String, Vec<&str>) = match custom_id {
            Some(custom_id) => (
                self.q("SELECT id, username, custom_id FROM consumers \
                     WHERE namespace = ? AND (username = ? OR custom_id = ? OR username = ? OR custom_id = ?)"),
                vec![namespace, username, custom_id, custom_id, username],
            ),
            None => (
                self.q("SELECT id, username, custom_id FROM consumers \
                     WHERE namespace = ? AND (username = ? OR custom_id = ?)"),
                vec![namespace, username, username],
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
        namespace: &str,
        api_key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT id, credentials FROM consumers WHERE namespace = ?"))
                .bind(namespace)
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
            if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&creds_str) {
                let found = creds
                    .get("keyauth")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|arr| {
                        arr.iter().any(|obj| {
                            obj.get("key")
                                .and_then(|k| k.as_str())
                                .is_some_and(|k| k == api_key)
                        })
                    });
                if found {
                    return Ok(false);
                }
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
        namespace: &str,
        mtls_identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT id, credentials FROM consumers WHERE namespace = ?"))
                .bind(namespace)
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
            if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&creds_str) {
                let found = creds
                    .get("mtls_auth")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|arr| {
                        arr.iter().any(|obj| {
                            obj.get("identity")
                                .and_then(|i| i.as_str())
                                .is_some_and(|i| i == mtls_identity)
                        })
                    });
                if found {
                    return Ok(false);
                }
            }
        }

        self.check_slow_query("check_mtls_identity_unique", start);
        Ok(true)
    }

    /// Check if a listen_port is unique across all stream proxies.
    /// Returns `true` if the port is unique (no conflicts found).
    pub async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = if let Some(eid) = exclude_id {
            sqlx::query(
                &self.q(
                    "SELECT id FROM proxies WHERE namespace = ? AND listen_port = ? AND id != ?",
                ),
            )
            .bind(namespace)
            .bind(port as i32)
            .bind(eid)
            .fetch_all(&self.pool())
            .await?
        } else {
            sqlx::query(&self.q("SELECT id FROM proxies WHERE namespace = ? AND listen_port = ?"))
                .bind(namespace)
                .bind(port as i32)
                .fetch_all(&self.pool())
                .await?
        };
        self.check_slow_query("check_listen_port_unique", start);
        Ok(rows.is_empty())
    }

    /// Check if an upstream with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace.
    ///
    /// The `namespace` filter is mandatory: cross-namespace references would
    /// pass admin validation but silently 502 at runtime because the proxy
    /// load path filters upstreams by namespace.
    pub async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        let start = Instant::now();
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT id FROM upstreams WHERE id = ? AND namespace = ?"))
                .bind(upstream_id)
                .bind(namespace)
                .fetch_optional(&self.pool())
                .await?;
        self.check_slow_query("check_upstream_exists", start);
        Ok(row.is_some())
    }

    /// Validate that a proxy's plugin associations reference existing
    /// proxy-scoped plugin configs targeted at the same proxy, and that the
    /// resolved plugin names remain unique for that proxy.
    ///
    /// Plugin configs are resolved only within `namespace`. References to
    /// plugin_configs in a different namespace surface as
    /// `non-existent plugin_config '<id>'` errors so admin validation
    /// cannot admit cross-namespace pollution.
    pub async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
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

        let plugin_refs = self
            .load_plugin_config_refs(&requested_ids, namespace)
            .await?;

        for assoc in associations {
            match plugin_refs.get(assoc.plugin_config_id.as_str()) {
                Some(plugin) => match plugin.scope {
                    PluginScope::Global => {
                        errors.push(format!(
                            "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped or proxy_group-scoped plugin configs",
                            proxy_id, plugin.id
                        ));
                        continue;
                    }
                    PluginScope::Proxy => {
                        if plugin.proxy_id.as_deref() != Some(proxy_id) {
                            errors.push(format!(
                                "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                proxy_id,
                                plugin.id,
                                plugin.proxy_id.as_deref().unwrap_or("<none>")
                            ));
                        }
                    }
                    PluginScope::ProxyGroup => {
                        // ProxyGroup plugins have no proxy_id — any proxy can
                        // reference them via its plugins association list.
                    }
                },
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
    /// `WHERE updated_at >= ?` queries plus 4 lightweight `SELECT id` queries.
    pub async fn load_incremental_config(
        &self,
        namespace: &str,
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
        let changed_proxies = self.load_proxies_since(namespace, &since_str).await?;
        let changed_consumers = self.load_consumers_since(namespace, &since_str).await?;
        let changed_plugin_configs = self
            .load_plugin_configs_since(namespace, &since_str)
            .await?;
        let changed_upstreams = self.load_upstreams_since(namespace, &since_str).await?;

        // Fetch current IDs (lightweight — one TEXT column per table)
        let current_proxy_ids = self
            .load_table_ids(namespace, ResourceTable::Proxies)
            .await?;
        let current_consumer_ids = self
            .load_table_ids(namespace, ResourceTable::Consumers)
            .await?;
        let current_plugin_config_ids = self
            .load_table_ids(namespace, ResourceTable::PluginConfigs)
            .await?;
        let current_upstream_ids = self
            .load_table_ids(namespace, ResourceTable::Upstreams)
            .await?;

        // Detect deletions: IDs we knew about that no longer exist
        let removed_proxy_ids = diff_removed(known_proxy_ids, &current_proxy_ids);
        let removed_consumer_ids = diff_removed(known_consumer_ids, &current_consumer_ids);
        let removed_plugin_config_ids =
            diff_removed(known_plugin_config_ids, &current_plugin_config_ids);
        let removed_upstream_ids = diff_removed(known_upstream_ids, &current_upstream_ids);

        let mut result = IncrementalResult {
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

        // Hot-path isolation: strip api_spec_id from every loaded resource
        // before the polling loop applies the delta. Mirrors the
        // load_full_config strip and matches the Mongo incremental path.
        for p in &mut result.added_or_modified_proxies {
            p.api_spec_id = None;
        }
        for u in &mut result.added_or_modified_upstreams {
            u.api_spec_id = None;
        }
        for pc in &mut result.added_or_modified_plugin_configs {
            pc.api_spec_id = None;
        }

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
    async fn load_proxies_since(
        &self,
        namespace: &str,
        since_str: &str,
    ) -> Result<Vec<Proxy>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM proxies WHERE namespace = ? AND updated_at >= ?"))
                .bind(namespace)
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
    async fn load_consumers_since(
        &self,
        namespace: &str,
        since_str: &str,
    ) -> Result<Vec<Consumer>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM consumers WHERE namespace = ? AND updated_at >= ?"))
                .bind(namespace)
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
        namespace: &str,
        since_str: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM plugin_configs WHERE namespace = ? AND updated_at >= ?"),
        )
        .bind(namespace)
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
    async fn load_upstreams_since(
        &self,
        namespace: &str,
        since_str: &str,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = Instant::now();
        let rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams WHERE namespace = ? AND updated_at >= ?"))
                .bind(namespace)
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

    /// Load all IDs from a resource table (lightweight — one TEXT column, no
    /// deserialization). The table is selected via [`ResourceTable`] to ensure
    /// only known tables are queried — no dynamic string interpolation.
    async fn load_table_ids(
        &self,
        namespace: &str,
        table: ResourceTable,
    ) -> Result<HashSet<String>, anyhow::Error> {
        let start = Instant::now();
        let sql = self.q(table.select_ids_sql());
        let rows: Vec<AnyRow> = sqlx::query(&sql)
            .bind(namespace)
            .fetch_all(&self.rpool())
            .await?;

        let mut ids = HashSet::with_capacity(rows.len());
        for row in rows {
            if let Ok(id) = row.try_get::<String, _>("id") {
                ids.insert(id);
            }
        }
        self.check_slow_query(table.load_ids_label(), start);
        Ok(ids)
    }

    /// Load `(id, scope, proxy_id)` for each plugin_config ID **within
    /// `namespace`**. Rows whose namespace does not match are filtered out
    /// at the SQL layer, so callers using the result map to validate
    /// references will report rows in other namespaces as missing.
    async fn load_plugin_config_refs(
        &self,
        ids: &[String],
        namespace: &str,
    ) -> Result<std::collections::HashMap<String, PluginConfigRef>, anyhow::Error> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let placeholders = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = self.q(&format!(
            "SELECT id, scope, proxy_id FROM plugin_configs WHERE namespace = ? AND id IN ({})",
            placeholders
        ));

        let mut query = sqlx::query(&sql);
        query = query.bind(namespace);
        for id in ids {
            query = query.bind(id);
        }

        let rows = query.fetch_all(&self.pool()).await?;
        let mut plugin_refs = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id")?;
            let scope = match row.try_get::<String, _>("scope")?.as_str() {
                "proxy" => PluginScope::Proxy,
                "proxy_group" => PluginScope::ProxyGroup,
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

    /// Fallback page size used only when no runtime override has been set
    /// via `set_full_load_page_size()`. Matches the default for
    /// `FERRUM_DB_FULL_LOAD_PAGE_SIZE`.
    const DEFAULT_FULL_LOAD_PAGE_SIZE: i64 = 10_000;

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
        let insert_sql = self.q(Self::PROXY_INSERT_SQL);
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
                .bind(&proxy.namespace)
                .bind(&proxy.name)
                .bind(&hosts_json)
                .bind(&proxy.listen_path)
                .bind(proxy.effective_scheme().to_scheme_str())
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
                .bind(proxy.pool_max_requests_per_connection.map(|v| v as i64))
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
                .bind(&proxy.upstream_subset)
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

        let assoc_exists_sql = self
            .q("SELECT 1 FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ? LIMIT 1");
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");
        for chunk in proxies.chunks(Self::BATCH_CHUNK_SIZE) {
            let mut tx = self.pool().begin().await?;
            let mut seen = HashSet::new();
            for proxy in chunk {
                for assoc in &proxy.plugins {
                    if !seen.insert((proxy.id.as_str(), assoc.plugin_config_id.as_str())) {
                        continue;
                    }
                    let already_attached = sqlx::query(&assoc_exists_sql)
                        .bind(&proxy.id)
                        .bind(&assoc.plugin_config_id)
                        .fetch_optional(&mut *tx)
                        .await?
                        .is_some();
                    if already_attached {
                        continue;
                    }
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
        let sql = self.q("INSERT INTO consumers (id, namespace, username, custom_id, credentials, acl_groups, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

        for consumer in consumers {
            let creds_json = serde_json::to_string(&consumer.credentials)?;
            let acl_groups_json = serde_json::to_string(&consumer.acl_groups)?;
            sqlx::query(&sql)
                .bind(&consumer.id)
                .bind(&consumer.namespace)
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
        let sql = self.q("INSERT INTO plugin_configs (id, namespace, plugin_name, config, scope, proxy_id, enabled, priority_override, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        let assoc_sql =
            self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)");

        for pc in configs {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                PluginScope::Proxy => "proxy",
                PluginScope::ProxyGroup => "proxy_group",
                PluginScope::Global => "global",
            };
            sqlx::query(&sql)
                .bind(&pc.id)
                .bind(&pc.namespace)
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

            if pc.scope == PluginScope::Proxy
                && let Some(proxy_id) = pc.proxy_id.as_deref()
            {
                sqlx::query(&assoc_sql)
                    .bind(proxy_id)
                    .bind(&pc.id)
                    .execute(&mut *tx)
                    .await?;
            }
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
        let sql = self.q("INSERT INTO upstreams (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, health_checks, service_discovery, subsets, backend_tls_client_cert_path, backend_tls_client_key_path, backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, backend_tls_sni, backend_tls_san_allow_list, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

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
            let subsets_json = upstream
                .subsets
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json =
                upstream_backend_tls_san_allow_list_json(upstream)?;
            sqlx::query(&sql)
                .bind(&upstream.id)
                .bind(&upstream.namespace)
                .bind(&upstream.name)
                .bind(&targets_json)
                .bind(algo_str)
                .bind(&upstream.hash_on)
                .bind(&hash_on_cookie_config_json)
                .bind(&health_checks_json)
                .bind(&service_discovery_json)
                .bind(&subsets_json)
                .bind(&upstream.backend_tls_client_cert_path)
                .bind(&upstream.backend_tls_client_key_path)
                .bind(upstream.backend_tls_verify_server_cert as i32)
                .bind(&upstream.backend_tls_server_ca_cert_path)
                .bind(&upstream.backend_tls_sni)
                .bind(&backend_tls_san_allow_list_json)
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
    pub async fn delete_all_resources(&self, namespace: &str) -> Result<(), anyhow::Error> {
        let start = Instant::now();
        let mut tx = self.pool().begin().await?;

        sqlx::query(&self.q("DELETE FROM proxy_plugins WHERE proxy_id IN (SELECT id FROM proxies WHERE namespace = ?)"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        // Delete api_specs BEFORE proxies: the FK cascade (proxy_id → proxies ON
        // DELETE CASCADE) would handle it, but explicit deletion is clearer and
        // matches the Mongo path.  Also ensures cleanup even if FK enforcement is
        // disabled (e.g. SQLite PRAGMA foreign_keys=OFF in recovery scenarios).
        sqlx::query(&self.q("DELETE FROM api_specs WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM proxies WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM consumers WHERE namespace = ?"))
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&self.q("DELETE FROM upstreams WHERE namespace = ?"))
            .bind(namespace)
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
    pub async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        let final_url = Self::append_connect_timeout(
            db_url,
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

        // If this store was bootstrapped via `connect_offline_with_pool_config`
        // (backup-file startup with an unreachable DB), migrations never ran.
        // Now that the pool is reconnected to a live DB, run them before
        // returning so the polling loop finds tables at the expected schema.
        // The helper uses a CAS so concurrent callers don't run migrations
        // twice, and restores the flag on failure so a transient error
        // doesn't silently skip migrations forever.
        self.maybe_apply_deferred_migrations().await?;

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
    pub async fn connect_with_failover(
        db_type: &str,
        primary_url: &str,
        failover_urls: &[String],
        pool_config: DbPoolConfig,
    ) -> Result<Self, anyhow::Error> {
        match Self::connect_with_pool_config(db_type, primary_url, pool_config.clone()).await {
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
                    match Self::connect_with_pool_config(db_type, url, pool_config.clone()).await {
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
    pub async fn connect_read_replica(&mut self, replica_url: &str) -> Result<(), anyhow::Error> {
        sqlx::any::install_default_drivers();

        let final_url = Self::append_connect_timeout(
            replica_url,
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
    pub async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error> {
        let rp = match &self.read_replica_pool {
            Some(rp) => rp,
            None => return Ok(()), // no replica configured
        };

        sqlx::any::install_default_drivers();

        let final_url = Self::append_connect_timeout(
            replica_url,
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
    pub async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> {
        // Try primary first
        if self.reconnect(primary_url).await.is_ok() {
            info!("Reconnected to primary database");
            return Ok(primary_url.to_string());
        }

        // Try failover URLs in order
        for (i, url) in self.failover_urls.iter().enumerate() {
            if self.reconnect(url).await.is_ok() {
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

    /// Return all distinct namespaces across all resource tables.
    pub async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
        let start = Instant::now();
        let sql = "SELECT DISTINCT namespace FROM proxies \
                   UNION SELECT DISTINCT namespace FROM consumers \
                   UNION SELECT DISTINCT namespace FROM plugin_configs \
                   UNION SELECT DISTINCT namespace FROM upstreams \
                   ORDER BY 1";
        let rows: Vec<AnyRow> = sqlx::query(sql).fetch_all(&self.rpool()).await?;
        let mut namespaces = Vec::with_capacity(rows.len());
        for row in rows {
            if let Ok(ns) = row.try_get::<String, _>("namespace") {
                namespaces.push(ns);
            }
        }
        self.check_slow_query("list_namespaces", start);
        Ok(namespaces)
    }

    // -----------------------------------------------------------------------
    // ApiSpec operations — admin-only, never called from the hot proxy path.
    //
    // IMPORTANT: Do NOT call these from db_loader polling loops, GatewayConfig
    // loading, or gRPC distribution paths. The api_specs table is pure admin
    // metadata; the gateway runtime never reads it.
    // -----------------------------------------------------------------------

    /// Atomically insert all bundle resources + the api_spec row.
    ///
    /// Insertion order (respects FK dependencies):
    ///   1. upstream (optional) — no FK on proxies
    ///   2. proxy — depends on upstream FK
    ///   3. plugin_configs — depend on proxy FK
    ///   4. api_specs — depends on proxy FK (ON DELETE CASCADE)
    ///
    /// Each resource is tagged with `api_spec_id = spec.id` so that a later
    /// `replace_api_spec_bundle` / `delete_api_spec` can identify spec-owned
    /// rows via `WHERE api_spec_id = ?`.
    pub async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        use crate::config::types::{AuthMode, ResponseBodyMode};

        let mut tx = self.pool().begin().await?;

        // 1. INSERT upstream (if present), tagged with api_spec_id.
        if let Some(u) = &bundle.upstream {
            let targets_json = serde_json::to_string(&u.targets)?;
            let algo_json = serde_json::to_string(&u.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let health_checks_json = u
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = u
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let subsets_json = u.subsets.as_ref().map(serde_json::to_string).transpose()?;
            let hash_on_cookie_config_json = u
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(u)?;

            sqlx::query(&self.q("INSERT INTO upstreams \
                 (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, \
                  health_checks, service_discovery, subsets, backend_tls_client_cert_path, \
                  backend_tls_client_key_path, backend_tls_verify_server_cert, \
                  backend_tls_server_ca_cert_path, backend_tls_sni, \
                  backend_tls_san_allow_list, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&u.id)
            .bind(&u.namespace)
            .bind(&u.name)
            .bind(&targets_json)
            .bind(algo_str)
            .bind(&u.hash_on)
            .bind(&hash_on_cookie_config_json)
            .bind(&health_checks_json)
            .bind(&service_discovery_json)
            .bind(&subsets_json)
            .bind(&u.backend_tls_client_cert_path)
            .bind(&u.backend_tls_client_key_path)
            .bind(u.backend_tls_verify_server_cert as i32)
            .bind(&u.backend_tls_server_ca_cert_path)
            .bind(&u.backend_tls_sni)
            .bind(&backend_tls_san_allow_list_json)
            .bind(&spec.id)
            .bind(u.created_at.to_rfc3339())
            .bind(u.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // 2. INSERT proxy, tagged with api_spec_id.
        //
        // This SQL differs from `Self::PROXY_INSERT_SQL` only by the addition of
        // the `api_spec_id` column before `created_at`.  When adding a new column
        // to `proxies`, update BOTH this query AND `Self::PROXY_INSERT_SQL` (and
        // the corresponding `.bind()` chains in `create_proxy`, `batch_create_proxies_chunk`,
        // and the `replace_api_spec_bundle` UPDATE path).
        {
            let p = &bundle.proxy;
            let hosts_json = serde_json::to_string(&p.hosts)?;
            let circuit_breaker_json = p
                .circuit_breaker
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let retry_json = p.retry.as_ref().map(serde_json::to_string).transpose()?;
            let response_body_mode_str = match p.response_body_mode {
                ResponseBodyMode::Buffer => "buffer",
                ResponseBodyMode::Stream => "stream",
            };

            sqlx::query(&self.q("INSERT INTO proxies \
                 (id, namespace, name, hosts, listen_path, backend_scheme, backend_host, \
                  backend_port, backend_path, strip_listen_path, preserve_host_header, \
                  backend_connect_timeout_ms, backend_read_timeout_ms, backend_write_timeout_ms, \
                  backend_tls_client_cert_path, backend_tls_client_key_path, \
                  backend_tls_verify_server_cert, backend_tls_server_ca_cert_path, \
                  dns_override, dns_cache_ttl_seconds, auth_mode, upstream_id, upstream_subset, \
                  circuit_breaker, retry, response_body_mode, \
                  pool_idle_timeout_seconds, pool_enable_http_keep_alive, pool_enable_http2, \
                  pool_tcp_keepalive_seconds, pool_http2_keep_alive_interval_seconds, \
                  pool_http2_keep_alive_timeout_seconds, pool_http2_initial_stream_window_size, \
                  pool_http2_initial_connection_window_size, pool_http2_adaptive_window, \
                  pool_http2_max_frame_size, pool_http2_max_concurrent_streams, \
                  pool_http3_connections_per_backend, pool_max_requests_per_connection, \
                  listen_port, frontend_tls, passthrough, \
                  udp_idle_timeout_seconds, tcp_idle_timeout_seconds, \
                  allowed_methods, allowed_ws_origins, udp_max_response_amplification_factor, \
                  api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                         ?, ?, ?, ?, ?)"))
            .bind(&p.id)
            .bind(&p.namespace)
            .bind(&p.name)
            .bind(&hosts_json)
            .bind(&p.listen_path)
            .bind(p.effective_scheme().to_scheme_str())
            .bind(&p.backend_host)
            .bind(p.backend_port as i32)
            .bind(&p.backend_path)
            .bind(if p.strip_listen_path { 1i32 } else { 0 })
            .bind(if p.preserve_host_header { 1i32 } else { 0 })
            .bind(p.backend_connect_timeout_ms as i64)
            .bind(p.backend_read_timeout_ms as i64)
            .bind(p.backend_write_timeout_ms as i64)
            .bind(&p.backend_tls_client_cert_path)
            .bind(&p.backend_tls_client_key_path)
            .bind(if p.backend_tls_verify_server_cert {
                1i32
            } else {
                0
            })
            .bind(&p.backend_tls_server_ca_cert_path)
            .bind(&p.dns_override)
            .bind(p.dns_cache_ttl_seconds.map(|v| v as i64))
            .bind(match p.auth_mode {
                AuthMode::Multi => "multi",
                _ => "single",
            })
            .bind(&p.upstream_id)
            .bind(&p.upstream_subset)
            .bind(&circuit_breaker_json)
            .bind(&retry_json)
            .bind(response_body_mode_str)
            .bind(p.pool_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.pool_enable_http_keep_alive
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
            .bind(p.pool_tcp_keepalive_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
            .bind(p.pool_http2_initial_stream_window_size.map(|v| v as i64))
            .bind(
                p.pool_http2_initial_connection_window_size
                    .map(|v| v as i64),
            )
            .bind(
                p.pool_http2_adaptive_window
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_http2_max_frame_size.map(|v| v as i64))
            .bind(p.pool_http2_max_concurrent_streams.map(|v| v as i64))
            .bind(p.pool_http3_connections_per_backend.map(|v| v as i64))
            .bind(p.pool_max_requests_per_connection.map(|v| v as i64))
            .bind(p.listen_port.map(|v| v as i32))
            .bind(if p.frontend_tls { 1i32 } else { 0 })
            .bind(if p.passthrough { 1i32 } else { 0 })
            .bind(p.udp_idle_timeout_seconds as i64)
            .bind(p.tcp_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.allowed_methods
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(if p.allowed_ws_origins.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&p.allowed_ws_origins)?)
            })
            .bind(p.udp_max_response_amplification_factor.map(|v| v as f64))
            .bind(&spec.id)
            .bind(p.created_at.to_rfc3339())
            .bind(p.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;

            // NOTE: proxy_plugins junction rows are inserted AFTER plugin_configs
            // below (step 3) to satisfy the FK: plugin_config_id REFERENCES
            // plugin_configs(id). Inserting them here would violate that FK because
            // the plugin_configs rows don't exist yet.
        }

        // 3. INSERT plugin_configs, tagged with api_spec_id.
        for pc in &bundle.plugins {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                crate::config::types::PluginScope::Proxy => "proxy",
                crate::config::types::PluginScope::ProxyGroup => "proxy_group",
                crate::config::types::PluginScope::Global => "global",
            };
            sqlx::query(&self.q("INSERT INTO plugin_configs \
                 (id, namespace, plugin_name, config, scope, proxy_id, enabled, \
                  priority_override, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&pc.id)
            .bind(&pc.namespace)
            .bind(&pc.plugin_name)
            .bind(&config_json)
            .bind(scope_str)
            .bind(&pc.proxy_id)
            .bind(if pc.enabled { 1i32 } else { 0 })
            .bind(pc.priority_override.map(|v| v as i32))
            .bind(&spec.id)
            .bind(pc.created_at.to_rfc3339())
            .bind(pc.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // 3b. INSERT proxy_plugins junction rows — AFTER plugin_configs so the
        //     plugin_config_id FK is satisfied.
        {
            let p = &bundle.proxy;
            for assoc in &p.plugins {
                sqlx::query(
                    &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
                )
                .bind(&p.id)
                .bind(&assoc.plugin_config_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // 4. INSERT api_specs row.
        self.insert_api_spec_tx(&mut tx, spec).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Atomically replace a spec: delete spec-owned resources, re-insert from
    /// the new bundle, then update the api_specs row in place.
    pub async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        use crate::config::types::{AuthMode, ResponseBodyMode};

        // --- Resource no-op shortcut (Wave 5 Feature A) -----------------------
        // Compare the current spec-owned resource graph to the incoming bundle
        // inside the SAME transaction as any subsequent write. If they already
        // match, only the api_specs metadata row is updated; proxy/upstream/plugin
        // tables are left untouched. Because this reads the live resources, direct
        // admin CRUD drift forces the full replace path even when the submitted
        // spec's resource_hash matches the stored metadata.
        let mut tx = self.pool().begin().await?;

        let existing_spec: Option<crate::config::types::ApiSpec> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(&spec.namespace)
                .bind(&spec.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(|row| row_to_api_spec(&row))
                .transpose()?;
        let previous_declared_assoc_ids = existing_spec
            .as_ref()
            .map(declared_proxy_plugin_association_ids_from_spec)
            .transpose()?
            .unwrap_or_default();
        let desired_resource_hash = store_canonical_resource_hash(bundle)?;

        let current_resource_hash = if !spec.resource_hash.is_empty() {
            self.current_api_spec_resource_hash_tx(
                &mut tx,
                bundle,
                spec,
                &previous_declared_assoc_ids,
            )
            .await?
        } else {
            None
        };
        if !spec.resource_hash.is_empty()
            && current_resource_hash.as_deref() == Some(desired_resource_hash.as_str())
        {
            // Bundle is unchanged — only update the api_specs metadata row.
            let tags_json = serde_json::to_string(&spec.tags).unwrap_or_else(|_| "[]".to_string());
            let server_urls_json =
                serde_json::to_string(&spec.server_urls).unwrap_or_else(|_| "[]".to_string());
            let spec_format_str = match spec.spec_format {
                crate::config::types::SpecFormat::Json => "json",
                crate::config::types::SpecFormat::Yaml => "yaml",
            };
            sqlx::query(&self.q("UPDATE api_specs SET \
                 spec_content = ?, content_encoding = ?, content_hash = ?, \
                 uncompressed_size = ?, resource_hash = ?, \
                 spec_format = ?, spec_version = ?, title = ?, info_version = ?, \
                 description = ?, contact_name = ?, contact_email = ?, \
                 license_name = ?, license_identifier = ?, \
                 tags = ?, server_urls = ?, operation_count = ?, \
                 updated_at = ? \
                 WHERE namespace = ? AND id = ?"))
            .bind(&spec.spec_content)
            .bind(&spec.content_encoding)
            .bind(&spec.content_hash)
            .bind(spec.uncompressed_size as i64)
            .bind(&spec.resource_hash)
            .bind(spec_format_str)
            .bind(&spec.spec_version)
            .bind(&spec.title)
            .bind(&spec.info_version)
            .bind(&spec.description)
            .bind(&spec.contact_name)
            .bind(&spec.contact_email)
            .bind(&spec.license_name)
            .bind(&spec.license_identifier)
            .bind(&tags_json)
            .bind(&server_urls_json)
            .bind(spec.operation_count as i64)
            .bind(spec.updated_at.to_rfc3339())
            .bind(&spec.namespace)
            .bind(&spec.id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(());
        }
        // Resource graph mismatch — fall through to the full replace path. The
        // same `tx` wraps the rest of the operation; opening another `begin()`
        // would double-nest and is redundant.

        self.ensure_no_external_spec_upstream_refs_tx(
            &mut tx,
            &spec.namespace,
            &spec.id,
            &spec.proxy_id,
        )
        .await?;

        // Delete only spec-owned plugin_configs. Hand-added plugins (api_spec_id IS NULL)
        // are intentionally preserved. The proxy itself is updated in place (not deleted)
        // so FK cascades do not wipe hand-added plugins.
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE api_spec_id = ? AND namespace = ?"))
            .bind(&spec.id)
            .bind(&spec.namespace)
            .execute(&mut *tx)
            .await?;

        // Fix 3: proxies.upstream_id FK is ON DELETE RESTRICT (not SET NULL).
        // We must clear proxy.upstream_id BEFORE deleting the old upstream row,
        // otherwise the DELETE violates the FK and rolls back the transaction.
        sqlx::query(&self.q("UPDATE proxies SET upstream_id = NULL \
                 WHERE id = ? AND api_spec_id = ? AND namespace = ?"))
        .bind(&spec.proxy_id)
        .bind(&spec.id)
        .bind(&spec.namespace)
        .execute(&mut *tx)
        .await?;

        // Now safe to delete spec-owned upstreams — no proxy references them.
        sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
            .bind(&spec.id)
            .bind(&spec.namespace)
            .execute(&mut *tx)
            .await?;

        // Insert the new upstream (if present).
        if let Some(u) = &bundle.upstream {
            let targets_json = serde_json::to_string(&u.targets)?;
            let algo_json = serde_json::to_string(&u.algorithm)?;
            let algo_str = algo_json.trim_matches('"');
            let health_checks_json = u
                .health_checks
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let service_discovery_json = u
                .service_discovery
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let subsets_json = u.subsets.as_ref().map(serde_json::to_string).transpose()?;
            let hash_on_cookie_config_json = u
                .hash_on_cookie_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let backend_tls_san_allow_list_json = upstream_backend_tls_san_allow_list_json(u)?;

            sqlx::query(&self.q("INSERT INTO upstreams \
                 (id, namespace, name, targets, algorithm, hash_on, hash_on_cookie_config, \
                  health_checks, service_discovery, subsets, backend_tls_client_cert_path, \
                  backend_tls_client_key_path, backend_tls_verify_server_cert, \
                  backend_tls_server_ca_cert_path, backend_tls_sni, \
                  backend_tls_san_allow_list, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&u.id)
            .bind(&u.namespace)
            .bind(&u.name)
            .bind(&targets_json)
            .bind(algo_str)
            .bind(&u.hash_on)
            .bind(&hash_on_cookie_config_json)
            .bind(&health_checks_json)
            .bind(&service_discovery_json)
            .bind(&subsets_json)
            .bind(&u.backend_tls_client_cert_path)
            .bind(&u.backend_tls_client_key_path)
            .bind(u.backend_tls_verify_server_cert as i32)
            .bind(&u.backend_tls_server_ca_cert_path)
            .bind(&u.backend_tls_sni)
            .bind(&backend_tls_san_allow_list_json)
            .bind(&spec.id)
            .bind(u.created_at.to_rfc3339())
            .bind(u.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // UPDATE proxy in place (preserves the primary key and created_at, so
        // hand-added plugins whose proxy_id FK points at this row are unaffected).
        {
            let p = &bundle.proxy;
            let hosts_json = serde_json::to_string(&p.hosts)?;
            let circuit_breaker_json = p
                .circuit_breaker
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let retry_json = p.retry.as_ref().map(serde_json::to_string).transpose()?;
            let response_body_mode_str = match p.response_body_mode {
                ResponseBodyMode::Buffer => "buffer",
                ResponseBodyMode::Stream => "stream",
            };

            sqlx::query(&self.q("UPDATE proxies SET \
                 namespace = ?, name = ?, hosts = ?, listen_path = ?, backend_scheme = ?, \
                 backend_host = ?, backend_port = ?, backend_path = ?, \
                 strip_listen_path = ?, preserve_host_header = ?, \
                 backend_connect_timeout_ms = ?, backend_read_timeout_ms = ?, \
                 backend_write_timeout_ms = ?, \
                 backend_tls_client_cert_path = ?, backend_tls_client_key_path = ?, \
                 backend_tls_verify_server_cert = ?, backend_tls_server_ca_cert_path = ?, \
                 dns_override = ?, dns_cache_ttl_seconds = ?, auth_mode = ?, upstream_id = ?, \
                 upstream_subset = ?, \
                 circuit_breaker = ?, retry = ?, response_body_mode = ?, \
                 pool_idle_timeout_seconds = ?, pool_enable_http_keep_alive = ?, \
                 pool_enable_http2 = ?, pool_tcp_keepalive_seconds = ?, \
                 pool_http2_keep_alive_interval_seconds = ?, \
                 pool_http2_keep_alive_timeout_seconds = ?, \
                 pool_http2_initial_stream_window_size = ?, \
                 pool_http2_initial_connection_window_size = ?, \
                 pool_http2_adaptive_window = ?, pool_http2_max_frame_size = ?, \
                 pool_http2_max_concurrent_streams = ?, \
                 pool_http3_connections_per_backend = ?, \
                 pool_max_requests_per_connection = ?, \
                 listen_port = ?, frontend_tls = ?, passthrough = ?, \
                 udp_idle_timeout_seconds = ?, tcp_idle_timeout_seconds = ?, \
                 allowed_methods = ?, allowed_ws_origins = ?, \
                 udp_max_response_amplification_factor = ?, \
                 api_spec_id = ?, updated_at = ? \
                 WHERE id = ? AND namespace = ?"))
            .bind(&p.namespace)
            .bind(&p.name)
            .bind(&hosts_json)
            .bind(&p.listen_path)
            .bind(p.effective_scheme().to_scheme_str())
            .bind(&p.backend_host)
            .bind(p.backend_port as i32)
            .bind(&p.backend_path)
            .bind(if p.strip_listen_path { 1i32 } else { 0 })
            .bind(if p.preserve_host_header { 1i32 } else { 0 })
            .bind(p.backend_connect_timeout_ms as i64)
            .bind(p.backend_read_timeout_ms as i64)
            .bind(p.backend_write_timeout_ms as i64)
            .bind(&p.backend_tls_client_cert_path)
            .bind(&p.backend_tls_client_key_path)
            .bind(if p.backend_tls_verify_server_cert {
                1i32
            } else {
                0
            })
            .bind(&p.backend_tls_server_ca_cert_path)
            .bind(&p.dns_override)
            .bind(p.dns_cache_ttl_seconds.map(|v| v as i64))
            .bind(match p.auth_mode {
                AuthMode::Multi => "multi",
                _ => "single",
            })
            .bind(&p.upstream_id)
            .bind(&p.upstream_subset)
            .bind(&circuit_breaker_json)
            .bind(&retry_json)
            .bind(response_body_mode_str)
            .bind(p.pool_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.pool_enable_http_keep_alive
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_enable_http2.map(|v| if v { 1i32 } else { 0 }))
            .bind(p.pool_tcp_keepalive_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_interval_seconds.map(|v| v as i64))
            .bind(p.pool_http2_keep_alive_timeout_seconds.map(|v| v as i64))
            .bind(p.pool_http2_initial_stream_window_size.map(|v| v as i64))
            .bind(
                p.pool_http2_initial_connection_window_size
                    .map(|v| v as i64),
            )
            .bind(
                p.pool_http2_adaptive_window
                    .map(|v| if v { 1i32 } else { 0 }),
            )
            .bind(p.pool_http2_max_frame_size.map(|v| v as i64))
            .bind(p.pool_http2_max_concurrent_streams.map(|v| v as i64))
            .bind(p.pool_http3_connections_per_backend.map(|v| v as i64))
            .bind(p.pool_max_requests_per_connection.map(|v| v as i64))
            .bind(p.listen_port.map(|v| v as i32))
            .bind(if p.frontend_tls { 1i32 } else { 0 })
            .bind(if p.passthrough { 1i32 } else { 0 })
            .bind(p.udp_idle_timeout_seconds as i64)
            .bind(p.tcp_idle_timeout_seconds.map(|v| v as i64))
            .bind(
                p.allowed_methods
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            )
            .bind(if p.allowed_ws_origins.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&p.allowed_ws_origins)?)
            })
            .bind(p.udp_max_response_amplification_factor.map(|v| v as f64))
            .bind(&spec.id)
            .bind(p.updated_at.to_rfc3339())
            // WHERE clause — match by primary key
            .bind(&p.id)
            .bind(&p.namespace)
            .execute(&mut *tx)
            .await?;
        }

        // Insert new spec-owned plugin_configs.
        for pc in &bundle.plugins {
            let config_json = serde_json::to_string(&pc.config)?;
            let scope_str = match pc.scope {
                crate::config::types::PluginScope::Proxy => "proxy",
                crate::config::types::PluginScope::ProxyGroup => "proxy_group",
                crate::config::types::PluginScope::Global => "global",
            };
            sqlx::query(&self.q("INSERT INTO plugin_configs \
                 (id, namespace, plugin_name, config, scope, proxy_id, enabled, \
                  priority_override, api_spec_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            .bind(&pc.id)
            .bind(&pc.namespace)
            .bind(&pc.plugin_name)
            .bind(&config_json)
            .bind(scope_str)
            .bind(&pc.proxy_id)
            .bind(if pc.enabled { 1i32 } else { 0 })
            .bind(pc.priority_override.map(|v| v as i32))
            .bind(&spec.id)
            .bind(pc.created_at.to_rfc3339())
            .bind(pc.updated_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        // Rebuild the proxy_plugins junction table for this proxy. Associations
        // declared in the previous spec are removed when absent from the new
        // document; truly hand-added associations remain untouched.
        let desired_assoc_ids: HashSet<String> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.clone())
            .collect();
        for previous_id in &previous_declared_assoc_ids {
            if !desired_assoc_ids.contains(previous_id) {
                sqlx::query(
                    &self
                        .q("DELETE FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?"),
                )
                .bind(&bundle.proxy.id)
                .bind(previous_id)
                .execute(&mut *tx)
                .await?;
            }
        }
        for assoc in &bundle.proxy.plugins {
            sqlx::query(
                &self.q("DELETE FROM proxy_plugins WHERE proxy_id = ? AND plugin_config_id = ?"),
            )
            .bind(&bundle.proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }
        // Re-insert — plugin_configs rows now exist (inserted above), so FK is satisfied.
        for assoc in &bundle.proxy.plugins {
            sqlx::query(
                &self.q("INSERT INTO proxy_plugins (proxy_id, plugin_config_id) VALUES (?, ?)"),
            )
            .bind(&bundle.proxy.id)
            .bind(&assoc.plugin_config_id)
            .execute(&mut *tx)
            .await?;
        }
        self.cleanup_orphaned_proxy_group_plugins(&mut tx).await?;

        // Update the api_specs row (no CASCADE delete needed since proxy survives).
        let tags_json = serde_json::to_string(&spec.tags).unwrap_or_else(|_| "[]".to_string());
        let server_urls_json =
            serde_json::to_string(&spec.server_urls).unwrap_or_else(|_| "[]".to_string());
        let spec_format_str = match spec.spec_format {
            crate::config::types::SpecFormat::Json => "json",
            crate::config::types::SpecFormat::Yaml => "yaml",
        };
        sqlx::query(&self.q("UPDATE api_specs SET \
             proxy_id = ?, spec_content = ?, content_encoding = ?, content_hash = ?, \
             uncompressed_size = ?, \
             spec_format = ?, spec_version = ?, title = ?, info_version = ?, \
             description = ?, contact_name = ?, contact_email = ?, \
             license_name = ?, license_identifier = ?, \
             tags = ?, server_urls = ?, operation_count = ?, resource_hash = ?, \
             updated_at = ? \
             WHERE namespace = ? AND id = ?"))
        .bind(&spec.proxy_id)
        .bind(&spec.spec_content)
        .bind(&spec.content_encoding)
        .bind(&spec.content_hash)
        .bind(spec.uncompressed_size as i64)
        .bind(spec_format_str)
        .bind(&spec.spec_version)
        .bind(&spec.title)
        .bind(&spec.info_version)
        .bind(&spec.description)
        .bind(&spec.contact_name)
        .bind(&spec.contact_email)
        .bind(&spec.license_name)
        .bind(&spec.license_identifier)
        .bind(&tags_json)
        .bind(&server_urls_json)
        .bind(spec.operation_count as i64)
        .bind(&spec.resource_hash)
        .bind(spec.updated_at.to_rfc3339())
        .bind(&spec.namespace)
        .bind(&spec.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn current_api_spec_resource_hash_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
        previous_declared_assoc_ids: &HashSet<String>,
    ) -> Result<Option<String>, anyhow::Error> {
        let plugin_rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM plugin_configs ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(&spec.namespace)
        .bind(&spec.id)
        .fetch_all(&mut **tx)
        .await?;
        let mut plugins = Vec::with_capacity(plugin_rows.len());
        for row in &plugin_rows {
            let mut plugin = row_to_plugin_config(row)?;
            plugin.normalize_fields();
            plugins.push(plugin);
        }

        let spec_owned_plugin_ids: HashSet<String> =
            plugins.iter().map(|pc| pc.id.clone()).collect();
        let desired_assoc_ids: HashSet<String> = bundle
            .proxy
            .plugins
            .iter()
            .map(|assoc| assoc.plugin_config_id.clone())
            .collect();
        let mut relevant_assoc_ids = spec_owned_plugin_ids.clone();
        relevant_assoc_ids.extend(previous_declared_assoc_ids.iter().cloned());
        relevant_assoc_ids.extend(desired_assoc_ids.iter().cloned());

        let assoc_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT plugin_config_id FROM proxy_plugins WHERE proxy_id = ?"))
                .bind(&spec.proxy_id)
                .fetch_all(&mut **tx)
                .await?;
        let mut current_relevant_assoc_ids = HashSet::new();
        for row in &assoc_rows {
            if let Ok(id) = row.try_get::<String, _>("plugin_config_id")
                && relevant_assoc_ids.contains(&id)
            {
                current_relevant_assoc_ids.insert(id);
            }
        }
        if current_relevant_assoc_ids != desired_assoc_ids {
            return Ok(None);
        }

        let proxy_row: Option<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM proxies WHERE id = ? AND namespace = ? AND api_spec_id = ?"),
        )
        .bind(&spec.proxy_id)
        .bind(&spec.namespace)
        .bind(&spec.id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(proxy_row) = proxy_row else {
            return Ok(None);
        };
        let desired_assocs: Vec<PluginAssociation> = bundle
            .proxy
            .plugins
            .iter()
            .filter(|assoc| current_relevant_assoc_ids.contains(&assoc.plugin_config_id))
            .cloned()
            .collect();
        let mut proxy = row_to_proxy(&proxy_row, spec.proxy_id.clone(), desired_assocs)?;
        proxy.normalize_fields();

        let upstream_rows: Vec<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM upstreams WHERE namespace = ? AND api_spec_id = ?"))
                .bind(&spec.namespace)
                .bind(&spec.id)
                .fetch_all(&mut **tx)
                .await?;
        if upstream_rows.len() > 1 {
            return Ok(None);
        }
        let upstream =
            upstream_rows
                .first()
                .map(row_to_upstream)
                .transpose()?
                .map(|mut upstream| {
                    upstream.normalize_fields();
                    upstream
                });

        let current = crate::admin::api_specs::ExtractedBundle {
            proxy,
            upstream,
            plugins,
        };
        crate::admin::api_specs::hash_resource_bundle(&current).map(Some)
    }

    async fn ensure_no_external_spec_upstream_refs_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        namespace: &str,
        spec_id: &str,
        spec_proxy_id: &str,
    ) -> Result<(), anyhow::Error> {
        let row: Option<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT p.id AS proxy_id, p.upstream_id AS upstream_id ",
            "FROM proxies p ",
            "INNER JOIN upstreams u ON p.upstream_id = u.id ",
            "WHERE u.namespace = ? AND u.api_spec_id = ? AND p.id <> ? ",
            "LIMIT 1"
        )))
        .bind(namespace)
        .bind(spec_id)
        .bind(spec_proxy_id)
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = row {
            let proxy_id = row
                .try_get::<String, _>("proxy_id")
                .unwrap_or_else(|_| "<unknown>".to_string());
            let upstream_id = row
                .try_get::<String, _>("upstream_id")
                .unwrap_or_else(|_| "<unknown>".to_string());
            anyhow::bail!(
                "proxy '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                 detach it before replacing or deleting the API spec",
                proxy_id,
                upstream_id,
                spec_id
            );
        }

        let upstream_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT id FROM upstreams WHERE namespace = ? AND api_spec_id = ?"),
        )
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&mut **tx)
        .await?;
        let spec_upstream_ids: HashSet<String> = upstream_rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect();
        if spec_upstream_ids.is_empty() {
            return Ok(());
        }

        let plugin_rows: Vec<AnyRow> = sqlx::query(
            &self.q("SELECT * FROM plugin_configs WHERE plugin_name = ? AND enabled != 0"),
        )
        .bind("mesh_route_dispatch")
        .fetch_all(&mut **tx)
        .await?;
        for row in &plugin_rows {
            let plugin = row_to_plugin_config(row)?;
            if plugin.api_spec_id.as_deref() == Some(spec_id) {
                continue;
            }
            if let Some(upstream_id) =
                mesh_route_dispatch_referenced_upstream(&plugin, &spec_upstream_ids)
            {
                anyhow::bail!(
                    "mesh_route_dispatch plugin_config '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                     detach it before replacing or deleting the API spec",
                    plugin.id,
                    upstream_id,
                    spec_id
                );
            }
        }

        Ok(())
    }

    /// Insert the api_specs row inside an existing transaction.
    async fn insert_api_spec_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        let spec_format_str = match spec.spec_format {
            crate::config::types::SpecFormat::Json => "json",
            crate::config::types::SpecFormat::Yaml => "yaml",
        };
        let tags_json = serde_json::to_string(&spec.tags).unwrap_or_else(|_| "[]".to_string());
        let server_urls_json =
            serde_json::to_string(&spec.server_urls).unwrap_or_else(|_| "[]".to_string());
        sqlx::query(&self.q("INSERT INTO api_specs \
             (id, namespace, proxy_id, spec_version, spec_format, spec_content, \
              content_encoding, uncompressed_size, content_hash, title, info_version, \
              description, contact_name, contact_email, license_name, license_identifier, \
              tags, server_urls, operation_count, resource_hash, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
        .bind(&spec.id)
        .bind(&spec.namespace)
        .bind(&spec.proxy_id)
        .bind(&spec.spec_version)
        .bind(spec_format_str)
        .bind(&spec.spec_content)
        .bind(&spec.content_encoding)
        .bind(spec.uncompressed_size as i64)
        .bind(&spec.content_hash)
        .bind(&spec.title)
        .bind(&spec.info_version)
        .bind(&spec.description)
        .bind(&spec.contact_name)
        .bind(&spec.contact_email)
        .bind(&spec.license_name)
        .bind(&spec.license_identifier)
        .bind(&tags_json)
        .bind(&server_urls_json)
        .bind(spec.operation_count as i64)
        .bind(&spec.resource_hash)
        .bind(spec.created_at.to_rfc3339())
        .bind(spec.updated_at.to_rfc3339())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Fetch a single ApiSpec by namespace + id.
    pub async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(namespace)
                .bind(id)
                .fetch_optional(&self.pool())
                .await?;
        match row {
            Some(r) => Ok(Some(row_to_api_spec(&r)?)),
            None => Ok(None),
        }
    }

    /// Fetch the ApiSpec that owns a given proxy_id.
    pub async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT * FROM api_specs WHERE namespace = ? AND proxy_id = ?"))
                .bind(namespace)
                .bind(proxy_id)
                .fetch_optional(&self.pool())
                .await?;
        match row {
            Some(r) => Ok(Some(row_to_api_spec(&r)?)),
            None => Ok(None),
        }
    }

    /// List ApiSpecs in a namespace with optional filtering, sorting, and pagination.
    ///
    /// Returns a [`PaginatedResult`] that includes the filtered `total` row count
    /// (ignoring limit/offset) so callers can build "showing X of Y" UI.
    /// The count query uses the same WHERE conditions as the data query; both
    /// are issued against the read pool and run sequentially on a single
    /// connection from that pool.
    pub async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &crate::config::db_backend::ApiSpecListFilter,
    ) -> Result<
        crate::config::db_backend::PaginatedResult<crate::config::types::ApiSpec>,
        anyhow::Error,
    > {
        use crate::config::db_backend::{ApiSpecSortBy, PaginatedResult, SortOrder};

        // Build WHERE clause dynamically.
        // We collect bind values as strings/i64 in order to use sqlx's typed bind API.
        // All column references are whitelisted — no user input goes into the SQL template.
        //
        // Note: the COUNT and data queries run sequentially without a shared
        // transaction, so `total` can be stale relative to `items` if a
        // concurrent write lands between them.  Standard pagination trade-off;
        // wrapping both in a transaction would serialize all list calls.
        let mut conditions: Vec<&'static str> = vec!["namespace = ?"];
        let mut proxy_id_val: Option<String> = None;
        let mut spec_version_val: Option<String> = None;
        let mut title_contains_val: Option<String> = None;
        let mut updated_since_val: Option<String> = None;
        let mut has_tag_val: Option<String> = None;

        if filter.proxy_id.is_some() {
            conditions.push("proxy_id = ?");
            proxy_id_val = filter.proxy_id.clone();
        }
        if let Some(ref prefix) = filter.spec_version_prefix {
            conditions.push("spec_version LIKE ?");
            spec_version_val = Some(format!("{prefix}%"));
        }
        if let Some(ref substr) = filter.title_contains {
            // LOWER() + LIKE for case-insensitive substring.
            conditions.push("LOWER(title) LIKE ?");
            title_contains_val = Some(format!("%{}%", substr.to_lowercase()));
        }
        if let Some(ref since) = filter.updated_since {
            conditions.push("updated_at >= ?");
            updated_since_val = Some(since.to_rfc3339());
        }
        if let Some(ref tag) = filter.has_tag {
            // Tags are stored as a JSON text array e.g. `["foo","bar"]`.
            // We match with LIKE `%"tag_name"%` — this correctly handles the JSON
            // quote-wrapping without requiring JSON functions (cross-dialect).
            //
            // SAFETY-CRITICAL CROSS-FILE INVARIANT:
            // The bare LIKE pattern here has NO ESCAPE clause.  It is safe ONLY
            // because tag names containing `"`, `%`, `_`, or `\` are rejected
            // at extract time via `ExtractError::InvalidTagName` in
            // src/admin/api_specs/extractor.rs (tag validation section).
            // Note: `_` is the SQL LIKE single-character wildcard — without
            // rejecting it, `?has_tag=api_v1` would falsely match `apixv1`.
            // If you ever relax that extractor whitelist, you MUST switch this
            // query to use `LIKE ... ESCAPE '\\'` and pre-escape the tag value
            // before binding it — otherwise `%`, `_`, or `\` in a tag name
            // would turn into a wildcard or escape token, producing false
            // positives.
            //
            // MongoDB uses native array membership (`filter_doc.insert("tags", tag)`)
            // with a multikey index and is unaffected by this pattern.
            conditions.push(r#"tags LIKE ?"#);
            has_tag_val = Some(format!("%\"{}\"", tag) + "%");
        }

        let where_clause = conditions.join(" AND ");

        // --- COUNT query (same WHERE, no ORDER BY / LIMIT / OFFSET) ----------
        let count_sql = self.q(&format!(
            "SELECT COUNT(*) AS cnt FROM api_specs WHERE {where_clause}"
        ));
        let mut count_query = sqlx::query(&count_sql).bind(namespace);
        if let Some(ref v) = proxy_id_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = spec_version_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = title_contains_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = updated_since_val {
            count_query = count_query.bind(v);
        }
        if let Some(ref v) = has_tag_val {
            count_query = count_query.bind(v);
        }
        let count_row = count_query.fetch_one(&self.rpool()).await?;
        let total: i64 = count_row.try_get("cnt")?;

        // --- Data query (ORDER BY + LIMIT + OFFSET) --------------------------
        // Whitelist the ORDER BY column to prevent injection.
        let order_col = match filter.sort_by {
            ApiSpecSortBy::UpdatedAt => "updated_at",
            ApiSpecSortBy::Title => "title",
            ApiSpecSortBy::OperationCount => "operation_count",
            ApiSpecSortBy::CreatedAt => "created_at",
        };
        let order_dir = match filter.order {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        };

        let sql = self.q(&format!(
            "SELECT id, namespace, proxy_id, spec_version, spec_format, \
             content_encoding, uncompressed_size, content_hash, title, \
             info_version, description, contact_name, contact_email, \
             license_name, license_identifier, tags, server_urls, \
             operation_count, created_at, updated_at \
             FROM api_specs WHERE {where_clause} \
             ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?"
        ));

        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(ref v) = proxy_id_val {
            query = query.bind(v);
        }
        if let Some(ref v) = spec_version_val {
            query = query.bind(v);
        }
        if let Some(ref v) = title_contains_val {
            query = query.bind(v);
        }
        if let Some(ref v) = updated_since_val {
            query = query.bind(v);
        }
        if let Some(ref v) = has_tag_val {
            query = query.bind(v);
        }
        let rows: Vec<AnyRow> = query
            .bind(filter.limit as i64)
            .bind(filter.offset as i64)
            .fetch_all(&self.rpool())
            .await?;
        let mut specs = Vec::with_capacity(rows.len());
        for row in &rows {
            specs.push(row_to_api_spec_summary(row)?);
        }
        Ok(PaginatedResult {
            items: specs,
            total,
        })
    }

    /// Delete an ApiSpec and all resources it owns.
    ///
    /// The api_spec row has FK `proxy_id REFERENCES proxies(id) ON DELETE CASCADE`,
    /// so deleting the proxy cascades to remove the api_specs row and the
    /// proxy-scoped plugin_configs (via plugin_configs.proxy_id FK). Upstreams
    /// have no FK to proxies, so they are cleaned up manually by api_spec_id.
    pub async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        let mut tx = self.pool().begin().await?;

        // Find the proxy_id for this spec.
        let row: Option<AnyRow> =
            sqlx::query(&self.q("SELECT proxy_id FROM api_specs WHERE namespace = ? AND id = ?"))
                .bind(namespace)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(false);
        };

        let proxy_id: String = row.try_get("proxy_id")?;

        self.ensure_no_external_spec_upstream_refs_tx(&mut tx, namespace, id, &proxy_id)
            .await?;

        // Delete spec-owned plugin_configs by api_spec_id (belt-and-suspenders;
        // the proxy FK cascade below would handle proxy-scoped ones, but
        // being explicit ensures correctness even if FK enforcement is disabled).
        sqlx::query(&self.q("DELETE FROM plugin_configs WHERE api_spec_id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Delete the proxy. FK ON DELETE CASCADE on api_specs.proxy_id removes
        // the api_specs row. FK ON DELETE CASCADE on plugin_configs.proxy_id
        // removes any remaining proxy-scoped plugins.
        sqlx::query(&self.q("DELETE FROM proxies WHERE id = ? AND namespace = ?"))
            .bind(&proxy_id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Deleting the proxy removes proxy_plugins junction rows via FK
        // cascade. If a spec-associated proxy was the last proxy referencing a
        // proxy_group plugin, mirror delete_proxy() and remove that now-orphaned
        // shared plugin config inside the same transaction.
        self.cleanup_orphaned_proxy_group_plugins(&mut tx).await?;

        // Delete spec-owned upstream (no FK cascade on this path).
        sqlx::query(&self.q("DELETE FROM upstreams WHERE api_spec_id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        // Defensive explicit delete of the api_specs row in case the FK
        // cascade did not fire (e.g. SQLite with foreign_keys OFF).
        sqlx::query(&self.q("DELETE FROM api_specs WHERE id = ? AND namespace = ?"))
            .bind(id)
            .bind(namespace)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// List plugin configs owned by `spec_id` (i.e., tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to reuse existing plugin IDs rather than
    /// minting fresh UUIDs on every re-submit of a spec with empty plugin IDs.
    /// Admin-only — NEVER call from polling loops or GatewayConfig loading.
    pub async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        let start = std::time::Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM plugin_configs ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&self.pool())
        .await?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            configs.push(row_to_plugin_config(&row)?);
        }
        self.check_slow_query("list_spec_owned_plugin_configs", start);
        Ok(configs)
    }

    /// List upstreams owned by `spec_id` (i.e., tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to reuse the previous spec-owned upstream ID
    /// even when direct admin CRUD drifted the proxy's upstream pointer.
    /// Admin-only — NEVER call from polling loops or GatewayConfig loading.
    pub async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        let start = std::time::Instant::now();
        let rows: Vec<AnyRow> = sqlx::query(&self.q(concat!(
            "SELECT * FROM upstreams ",
            "WHERE namespace = ? AND api_spec_id = ? ",
            "ORDER BY created_at ASC, id ASC"
        )))
        .bind(namespace)
        .bind(spec_id)
        .fetch_all(&self.pool())
        .await?;

        let mut upstreams = Vec::with_capacity(rows.len());
        for row in rows {
            upstreams.push(row_to_upstream(&row)?);
        }
        self.check_slow_query("list_spec_owned_upstreams", start);
        Ok(upstreams)
    }

    pub async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error> {
        let start = std::time::Instant::now();
        let diff = serde_json::to_string(&event.diff)?;
        sqlx::query(&self.q("INSERT INTO audit_events \
             (id, ts, actor, action, resource_type, resource_id, namespace, diff) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"))
        .bind(&event.id)
        .bind(audit_ts_string(&event.ts))
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&event.namespace)
        .bind(diff)
        .execute(&self.pool())
        .await?;
        self.check_slow_query("insert_audit_event", start);
        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
        let start = std::time::Instant::now();
        let mut conditions: Vec<&'static str> = vec!["namespace = ?"];

        if filter.actor.is_some() {
            conditions.push("actor = ?");
        }
        if filter.action.is_some() {
            conditions.push("action = ?");
        }
        if filter.resource_type.is_some() {
            conditions.push("resource_type = ?");
        }
        if filter.resource_id.is_some() {
            conditions.push("resource_id = ?");
        }
        if filter.start.is_some() {
            conditions.push("ts >= ?");
        }
        if filter.end.is_some() {
            conditions.push("ts <= ?");
        }

        let where_clause = conditions.join(" AND ");
        let count_sql = self.q(&format!(
            "SELECT COUNT(*) AS cnt FROM audit_events WHERE {where_clause}"
        ));
        let mut count_query = sqlx::query(&count_sql).bind(namespace);
        if let Some(ref value) = filter.actor {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.action {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.resource_type {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.resource_id {
            count_query = count_query.bind(value);
        }
        if let Some(ref value) = filter.start {
            count_query = count_query.bind(audit_ts_string(value));
        }
        if let Some(ref value) = filter.end {
            count_query = count_query.bind(audit_ts_string(value));
        }
        let total: i64 = count_query.fetch_one(&self.rpool()).await?.try_get("cnt")?;

        let sql = self.q(&format!(
            "SELECT id, ts, actor, action, resource_type, resource_id, namespace, diff \
             FROM audit_events WHERE {where_clause} \
             ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        ));
        let mut query = sqlx::query(&sql).bind(namespace);
        if let Some(ref value) = filter.actor {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.action {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.resource_type {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.resource_id {
            query = query.bind(value);
        }
        if let Some(ref value) = filter.start {
            query = query.bind(audit_ts_string(value));
        }
        if let Some(ref value) = filter.end {
            query = query.bind(audit_ts_string(value));
        }
        let rows = query
            .bind(filter.limit as i64)
            .bind(filter.offset as i64)
            .fetch_all(&self.rpool())
            .await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(row_to_audit_event(row)?);
        }
        self.check_slow_query("list_audit_events", start);
        Ok(PaginatedResult { items, total })
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

    fn pool_stats(&self) -> Option<crate::config::db_backend::DbPoolStats> {
        let primary = self.pool.load();
        let size = primary.size();
        let idle = primary.num_idle() as u32;

        let replica = self.read_replica_pool.as_ref().map(|rp| {
            let rp = rp.load();
            Box::new(crate::config::db_backend::DbPoolStatsInner {
                size: rp.size(),
                idle: rp.num_idle() as u32,
                active: rp.size().saturating_sub(rp.num_idle() as u32),
            })
        });

        Some(crate::config::db_backend::DbPoolStats {
            size,
            idle,
            active: size.saturating_sub(idle),
            max_connections: self.pool_config.max_connections,
            min_connections: self.pool_config.min_connections,
            read_replica: replica,
        })
    }

    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>) {
        self.slow_query_threshold_ms = threshold_ms;
    }

    fn set_full_load_page_size(&mut self, page_size: u64) {
        self.full_load_page_size = page_size as i64;
    }

    fn set_cert_expiry_warning_days(&mut self, days: u64) {
        self.cert_expiry_warning_days = days;
    }

    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendAllowIps) {
        self.backend_allow_ips = policy;
    }

    async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
        DatabaseStore::load_full_config(self, namespace).await
    }

    async fn load_gateway_trust_bundles(
        &self,
        _namespace: &str,
    ) -> Result<GatewayTrustBundlePoll, anyhow::Error> {
        // SQL backends do not have a dedicated top-level GatewayConfig storage
        // shape today, so preserve whatever trust material the initial config
        // load supplied instead of clearing it on the first empty poll.
        Ok(GatewayTrustBundlePoll::Unchanged)
    }

    async fn load_incremental_config(
        &self,
        namespace: &str,
        since: DateTime<Utc>,
        known_proxy_ids: &HashSet<String>,
        known_consumer_ids: &HashSet<String>,
        known_plugin_config_ids: &HashSet<String>,
        known_upstream_ids: &HashSet<String>,
    ) -> Result<IncrementalResult, anyhow::Error> {
        DatabaseStore::load_incremental_config(
            self,
            namespace,
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

    async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_exists(self, proxy_id, namespace).await
    }

    async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
        DatabaseStore::list_proxies_paginated(self, namespace, limit, offset).await
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
        DatabaseStore::list_consumers_paginated(self, namespace, limit, offset).await
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
        DatabaseStore::list_plugin_configs_paginated(self, namespace, limit, offset).await
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
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
        DatabaseStore::list_upstreams_paginated(self, namespace, limit, offset).await
    }

    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_path_unique(
            self,
            namespace,
            listen_path,
            hosts,
            exclude_proxy_id,
        )
        .await
    }

    async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_proxy_name_unique(self, namespace, name, exclude_proxy_id).await
    }

    async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_name_unique(self, namespace, name, exclude_upstream_id).await
    }

    async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> {
        DatabaseStore::check_consumer_identity_unique(
            self,
            namespace,
            username,
            custom_id,
            exclude_consumer_id,
        )
        .await
    }

    async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_keyauth_key_unique(self, namespace, key, exclude_consumer_id).await
    }

    async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_mtls_identity_unique(self, namespace, identity, exclude_consumer_id)
            .await
    }

    async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_listen_port_unique(self, namespace, port, exclude_proxy_id).await
    }

    async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> {
        DatabaseStore::check_upstream_exists(self, upstream_id, namespace).await
    }

    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::validate_proxy_plugin_associations(self, proxy_id, namespace, plugins).await
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

    async fn delete_all_resources(&self, namespace: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::delete_all_resources(self, namespace).await
    }

    async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect(self, db_url).await
    }

    async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error> {
        DatabaseStore::reconnect_read_replica(self, replica_url).await
    }

    async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> {
        DatabaseStore::try_failover_reconnect(self, primary_url).await
    }

    async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        DatabaseStore::run_migrations(self).await
    }

    async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        DatabaseStore::maybe_apply_deferred_migrations(self).await
    }

    async fn pending_plugin_migrations(
        &self,
        plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PendingPluginMigration>, anyhow::Error> {
        if plugin_migrations.is_empty() {
            return Ok(Vec::new());
        }
        let runner =
            crate::config::migrations::MigrationRunner::new(self.pool(), self.db_type.clone());
        let status = runner.plugin_status(plugin_migrations).await?;
        Ok(status.pending)
    }

    async fn apply_plugin_migrations(
        &self,
        plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PluginMigrationRecord>, anyhow::Error> {
        if plugin_migrations.is_empty() {
            return Ok(Vec::new());
        }
        let runner =
            crate::config::migrations::MigrationRunner::new(self.pool(), self.db_type.clone());
        runner.run_plugin_pending(plugin_migrations).await
    }

    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
        DatabaseStore::list_namespaces(self).await
    }

    async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::submit_api_spec_bundle(self, bundle, spec).await
    }

    async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::replace_api_spec_bundle(self, bundle, spec).await
    }

    async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        DatabaseStore::get_api_spec(self, namespace, id).await
    }

    async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<crate::config::types::ApiSpec>, anyhow::Error> {
        DatabaseStore::get_api_spec_by_proxy(self, namespace, proxy_id).await
    }

    async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &crate::config::db_backend::ApiSpecListFilter,
    ) -> Result<
        crate::config::db_backend::PaginatedResult<crate::config::types::ApiSpec>,
        anyhow::Error,
    > {
        DatabaseStore::list_api_specs(self, namespace, filter).await
    }

    async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
        DatabaseStore::delete_api_spec(self, namespace, id).await
    }

    async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<PluginConfig>, anyhow::Error> {
        DatabaseStore::list_spec_owned_plugin_configs(self, namespace, spec_id).await
    }

    async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<Upstream>, anyhow::Error> {
        DatabaseStore::list_spec_owned_upstreams(self, namespace, spec_id).await
    }

    async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error> {
        DatabaseStore::insert_audit_event(self, event).await
    }

    async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
        DatabaseStore::list_audit_events(self, namespace, filter).await
    }
}

/// IDs in `known` that are not in `current` (i.e., deleted resources).
pub(crate) fn diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
    known.difference(current).cloned().collect()
}

/// Parse a stored backend scheme string into the canonical 6-variant
/// `BackendScheme`.
pub(crate) fn parse_scheme(s: &str) -> Result<BackendScheme, String> {
    match s.to_lowercase().as_str() {
        "http" => Ok(BackendScheme::Http),
        "https" => Ok(BackendScheme::Https),
        "tcp" => Ok(BackendScheme::Tcp),
        "tcps" => Ok(BackendScheme::Tcps),
        "udp" => Ok(BackendScheme::Udp),
        "dtls" => Ok(BackendScheme::Dtls),
        _ => Err(format!(
            "unsupported backend_scheme '{s}' (expected one of: http, https, tcp, tcps, udp, dtls)"
        )),
    }
}

pub(crate) fn parse_auth_mode(s: &str) -> AuthMode {
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
    // Clone id for use in error messages (the original is moved into the Proxy struct).
    let pid = id.clone();
    let scheme_str: String = row
        .try_get::<String, _>("backend_scheme")
        .map_err(|e| anyhow::anyhow!("Proxy {}: failed to read backend_scheme: {}", pid, e))?;
    let backend_scheme =
        parse_scheme(&scheme_str).map_err(|e| anyhow::anyhow!("Proxy {}: {}", pid, e))?;
    let auth_mode_str: String = row
        .try_get("auth_mode")
        .map_err(|e| anyhow::anyhow!("Proxy {}: failed to read auth_mode: {}", pid, e))?;

    let hosts_str: String = row
        .try_get::<String, _>("hosts")
        .unwrap_or_else(|_| "[]".into());
    let hosts: Vec<String> = serde_json::from_str(&hosts_str).map_err(|e| {
        anyhow::anyhow!(
            "Proxy {}: failed to parse hosts JSON '{}': {}",
            pid,
            hosts_str,
            e
        )
    })?;

    Ok(Proxy {
        id,
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| crate::config::types::default_namespace()),
        name: row.try_get("name").ok(),
        hosts,
        // Propagate decode errors — silently defaulting to None would turn a
        // malformed listen_path into a host-only proxy and change routing
        // behavior. `Option<String>` already represents SQL NULL, so `?` is
        // safe for the expected nullable case and fails fast on real errors.
        listen_path: row.try_get::<Option<String>, _>("listen_path")?,
        backend_scheme: Some(backend_scheme),
        // `dispatch_kind` is populated by `GatewayConfig::normalize_fields()`
        // once the full config is loaded. Seed it here from the row values so
        // single-row reads (e.g., `get_proxy`) still return a usable Proxy
        // even when no normalization pass runs.
        dispatch_kind: DispatchKind::from(backend_scheme),
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
        circuit_breaker: match row.try_get::<String, _>("circuit_breaker") {
            Ok(s) => Some(
                serde_json::from_str::<CircuitBreakerConfig>(&s).map_err(|e| {
                    anyhow::anyhow!("Proxy {}: failed to parse circuit_breaker JSON: {}", pid, e)
                })?,
            ),
            Err(_) => None,
        },
        retry: match row.try_get::<String, _>("retry") {
            Ok(s) => Some(serde_json::from_str::<RetryConfig>(&s).map_err(|e| {
                anyhow::anyhow!("Proxy {}: failed to parse retry JSON: {}", pid, e)
            })?),
            Err(_) => None,
        },
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
        pool_max_requests_per_connection: row
            .try_get::<i64, _>("pool_max_requests_per_connection")
            .ok()
            .map(|v| v.max(0) as u64),
        upstream_subset: row.try_get::<String, _>("upstream_subset").ok(),
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
        allowed_methods: match row.try_get::<String, _>("allowed_methods") {
            Ok(s) => Some(serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!("Proxy {}: failed to parse allowed_methods JSON: {}", pid, e)
            })?),
            Err(_) => None,
        },
        allowed_ws_origins: match row.try_get::<String, _>("allowed_ws_origins") {
            Ok(s) => serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Proxy {}: failed to parse allowed_ws_origins JSON: {}",
                    pid,
                    e
                )
            })?,
            Err(_) => Vec::new(),
        },
        udp_max_response_amplification_factor: row
            .try_get::<f64, _>("udp_max_response_amplification_factor")
            .ok()
            .map(|v| v as f32),
        // api_spec_id: PRESERVE here. This row mapper is shared between
        // admin GET/list paths (which need the real owning spec id to
        // serialise per the OpenAPI schema) and the runtime config loader
        // (which must NOT see it). The runtime callers
        // `load_full_config` / `load_incremental_config` strip it
        // explicitly via `strip_api_spec_id_from_runtime_config(&mut cfg)`
        // before returning — see Wave 1A's hot-path isolation invariant.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        resolved_tls: Default::default(),
        // Populated by `GatewayConfig::resolve_dispatch_port_overrides()` after
        // upstreams are loaded and any mesh DR overrides applied.
        dispatch_port_overrides: None,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse a consumer row into a Consumer struct.
fn row_to_consumer(row: &AnyRow) -> Result<Consumer, anyhow::Error> {
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let creds_str: String = row.try_get("credentials").map_err(|e| {
        anyhow::anyhow!(
            "Consumer {}: failed to read credentials column: {}",
            id_preview,
            e
        )
    })?;
    let credentials = serde_json::from_str(&creds_str).map_err(|e| {
        anyhow::anyhow!(
            "Consumer {}: failed to parse credentials JSON: {}",
            id_preview,
            e
        )
    })?;

    let acl_groups_str: String = row.try_get("acl_groups").unwrap_or_else(|_| "[]".into());
    let acl_groups: Vec<String> = serde_json::from_str(&acl_groups_str).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse acl_groups JSON for consumer: {} (raw: {})",
            e,
            acl_groups_str
        )
    })?;

    Ok(Consumer {
        id: row.try_get("id")?,
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| crate::config::types::default_namespace()),
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
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let config_str: String = row.try_get("config").map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to read config column: {}",
            id_preview,
            e
        )
    })?;
    let config_val = serde_json::from_str(&config_str).map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to parse config JSON: {}",
            id_preview,
            e
        )
    })?;
    let scope_str: String = row.try_get("scope").map_err(|e| {
        anyhow::anyhow!(
            "PluginConfig {}: failed to read scope column: {}",
            id_preview,
            e
        )
    })?;

    Ok(PluginConfig {
        id: row.try_get("id")?,
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| crate::config::types::default_namespace()),
        plugin_name: row.try_get("plugin_name")?,
        config: config_val,
        scope: match scope_str.as_str() {
            "proxy" => PluginScope::Proxy,
            "proxy_group" => PluginScope::ProxyGroup,
            _ => PluginScope::Global,
        },
        proxy_id: row.try_get("proxy_id").ok(),
        enabled: row.try_get::<i32, _>("enabled").unwrap_or(1) != 0,
        priority_override: row
            .try_get::<Option<i32>, _>("priority_override")
            .ok()
            .flatten()
            .map(|v| v as u16),
        // See row_to_proxy for the rationale: preserve here so admin reads
        // get the real owning spec id; runtime callers strip via
        // strip_api_spec_id_from_runtime_config.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Parse an upstream row into an Upstream struct.
fn row_to_upstream(row: &AnyRow) -> Result<Upstream, anyhow::Error> {
    let id_preview: String = row
        .try_get("id")
        .unwrap_or_else(|_| "<unknown>".to_string());
    let targets_str: String = row.try_get("targets").map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to read targets column: {}",
            id_preview,
            e
        )
    })?;
    let targets: Vec<UpstreamTarget> = serde_json::from_str(&targets_str).map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to parse targets JSON: {}",
            id_preview,
            e
        )
    })?;

    let algo_str: String = row.try_get("algorithm").map_err(|e| {
        anyhow::anyhow!(
            "Upstream {}: failed to read algorithm column: {}",
            id_preview,
            e
        )
    })?;
    let algorithm: LoadBalancerAlgorithm =
        serde_json::from_value(serde_json::Value::String(algo_str.clone())).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse algorithm '{}': {}",
                id_preview,
                algo_str,
                e
            )
        })?;

    let health_checks: Option<HealthCheckConfig> = match row.try_get::<String, _>("health_checks") {
        Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse health_checks JSON: {}",
                id_preview,
                e
            )
        })?),
        Err(_) => None,
    };

    let service_discovery: Option<ServiceDiscoveryConfig> =
        match row.try_get::<String, _>("service_discovery") {
            Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Upstream {}: failed to parse service_discovery JSON: {}",
                    id_preview,
                    e
                )
            })?),
            Err(_) => None,
        };

    let hash_on_cookie_config: Option<crate::config::types::HashOnCookieConfig> = row
        .try_get::<String, _>("hash_on_cookie_config")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    // Parse backend TLS fields
    let backend_tls_verify_server_cert: bool = row
        .try_get::<i32, _>("backend_tls_verify_server_cert")
        .map(|v| v != 0)
        .unwrap_or(true);

    let subsets = match row.try_get::<String, _>("subsets") {
        Ok(s) => Some(serde_json::from_str(&s).map_err(|e| {
            anyhow::anyhow!(
                "Upstream {}: failed to parse subsets JSON: {}",
                id_preview,
                e
            )
        })?),
        Err(_) => None,
    };

    let backend_tls_san_allow_list =
        match row.try_get::<Option<String>, _>("backend_tls_san_allow_list") {
            Ok(Some(s)) => serde_json::from_str::<Vec<String>>(&s).map_err(|e| {
                anyhow::anyhow!(
                    "Upstream {}: failed to parse backend_tls_san_allow_list JSON: {}",
                    id_preview,
                    e
                )
            })?,
            Ok(None) => Vec::new(),
            Err(e) => return Err(e.into()),
        };
    let backend_tls_sni: Option<String> = row.try_get("backend_tls_sni")?;

    Ok(Upstream {
        id: row.try_get("id")?,
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| crate::config::types::default_namespace()),
        name: row.try_get("name").ok(),
        targets,
        algorithm,
        hash_on: row.try_get("hash_on").ok(),
        hash_on_cookie_config,
        health_checks,
        service_discovery,
        subsets,
        // Per-port overrides are populated in-memory by the mesh apply
        // pipeline (`apply_destination_rules`); they are not persisted to SQL
        // backends today, so SQL rows always start with an empty map.
        port_overrides: std::collections::HashMap::new(),
        // `source_locality` is projected at mesh slice apply by
        // `project_mesh_source_locality` from the workload's locality; SQL
        // backends do not persist it (no column), and `Upstream::validate_fields`
        // rejects operator writes via the admin API. SQL rows always start `None`.
        source_locality: None,
        locality_lb_setting: None,
        backend_tls_client_cert_path: row.try_get("backend_tls_client_cert_path").ok(),
        backend_tls_client_key_path: row.try_get("backend_tls_client_key_path").ok(),
        backend_tls_verify_server_cert,
        backend_tls_server_ca_cert_path: row.try_get("backend_tls_server_ca_cert_path").ok(),
        backend_tls_sni,
        backend_tls_san_allow_list,
        // Per-subset TLS overlays are derived state populated by mesh
        // `apply_destination_rules`; SQL backends do not persist them, so SQL
        // rows always start with an empty map.
        resolved_subset_tls: std::collections::HashMap::new(),
        // See row_to_proxy for the rationale: preserve here so admin reads
        // get the real owning spec id; runtime callers strip via
        // strip_api_spec_id_from_runtime_config.
        api_spec_id: row
            .try_get::<Option<String>, _>("api_spec_id")
            .ok()
            .flatten(),
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

/// Strip `api_spec_id` from every resource in a `GatewayConfig` so the
/// gateway runtime never observes the ownership tag.
///
/// The row mappers (`row_to_proxy`, `row_to_upstream`, `row_to_plugin_config`)
/// PRESERVE `api_spec_id` so admin GET/list paths can serialise it per the
/// OpenAPI schema. The runtime callers (`load_full_config`,
/// `load_incremental_config`) call this helper before returning to enforce
/// the hot-path isolation invariant: api_specs is admin-only metadata,
/// CP gRPC broadcasts must not leak ownership tags to DPs, and the
/// polling delta path keys off resource fields that should not include
/// admin metadata.
///
/// Mirror of the Mongo path's strip in `MongoStore::load_full_config` /
/// `MongoStore::load_incremental_config`.
pub(crate) fn strip_api_spec_id_from_runtime_config(config: &mut GatewayConfig) {
    for p in &mut config.proxies {
        p.api_spec_id = None;
    }
    for u in &mut config.upstreams {
        u.api_spec_id = None;
    }
    for pc in &mut config.plugin_configs {
        pc.api_spec_id = None;
    }
}

/// Parse an api_specs row into an [`ApiSpec`] struct.
///
/// This function is used exclusively by the admin-layer api_spec methods.
/// It must NEVER be called from runtime polling paths.
fn row_to_api_spec(row: &AnyRow) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    // spec_content is stored as BLOB/BYTEA — sqlx returns Vec<u8>.
    let spec_content: Vec<u8> = row.try_get("spec_content")?;
    row_to_api_spec_with_content(row, spec_content)
}

/// Parse an api_specs list row into an [`ApiSpec`] summary.
///
/// The list endpoint must not pull the compressed `spec_content` blob for
/// every row. Keep `spec_content` empty here; full document retrieval goes
/// through [`row_to_api_spec`].
fn row_to_api_spec_summary(row: &AnyRow) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    row_to_api_spec_with_content(row, Vec::new())
}

fn row_to_api_spec_with_content(
    row: &AnyRow,
    spec_content: Vec<u8>,
) -> Result<crate::config::types::ApiSpec, anyhow::Error> {
    use crate::config::types::{ApiSpec, SpecFormat};

    let spec_format_str: String = row.try_get("spec_format")?;
    let spec_format = match spec_format_str.as_str() {
        "json" => SpecFormat::Json,
        _ => SpecFormat::Yaml,
    };
    let uncompressed_size: i64 = row.try_get("uncompressed_size")?;

    // Wave 5: parse JSON-text arrays for tags / server_urls.
    let tags: Vec<String> = row
        .try_get::<String, _>("tags")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let server_urls: Vec<String> = row
        .try_get::<String, _>("server_urls")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let operation_count: u32 = row
        .try_get::<i64, _>("operation_count")
        .map(|v| v.clamp(0, u32::MAX as i64) as u32)
        .unwrap_or(0);
    let resource_hash: String = row
        .try_get::<String, _>("resource_hash")
        .unwrap_or_default();

    Ok(ApiSpec {
        id: row.try_get("id")?,
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| crate::config::types::default_namespace()),
        proxy_id: row.try_get("proxy_id")?,
        spec_version: row.try_get("spec_version")?,
        spec_format,
        spec_content,
        content_encoding: row
            .try_get::<String, _>("content_encoding")
            .unwrap_or_else(|_| "gzip".to_string()),
        uncompressed_size: uncompressed_size.max(0) as u64,
        content_hash: row.try_get("content_hash")?,
        title: row.try_get("title").ok().flatten(),
        info_version: row.try_get("info_version").ok().flatten(),
        description: row.try_get("description").ok().flatten(),
        contact_name: row.try_get("contact_name").ok().flatten(),
        contact_email: row.try_get("contact_email").ok().flatten(),
        license_name: row.try_get("license_name").ok().flatten(),
        license_identifier: row.try_get("license_identifier").ok().flatten(),
        tags,
        server_urls,
        operation_count,
        resource_hash,
        created_at: parse_datetime_column(row, "created_at"),
        updated_at: parse_datetime_column(row, "updated_at"),
    })
}

fn row_to_audit_event(row: &AnyRow) -> Result<crate::admin::audit::AuditEvent, anyhow::Error> {
    let id: String = row.try_get("id")?;
    let diff_raw: String = row.try_get("diff")?;
    let diff = serde_json::from_str(&diff_raw).unwrap_or_else(|e| {
        warn!(
            audit_event_id = %id,
            error = %e,
            "Audit event diff column is not valid JSON; returning empty diff"
        );
        serde_json::json!({})
    });
    Ok(crate::admin::audit::AuditEvent {
        id,
        ts: parse_datetime_column(row, "ts"),
        actor: row.try_get("actor")?,
        action: row.try_get("action")?,
        resource_type: row.try_get("resource_type")?,
        resource_id: row.try_get("resource_id")?,
        namespace: row.try_get("namespace")?,
        diff,
    })
}

fn audit_ts_string(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Nanos, true)
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
mod proxy_insert_sql_drift_tests {
    //! Drift-catcher tests for the proxy INSERT call sites.
    //!
    //! See the "Drift-prevention contract for proxy INSERT call sites"
    //! comment block in [`DatabaseStore::PROXY_INSERT_PLACEHOLDER_COUNT`]
    //! for the contract these tests enforce.
    //!
    //! When you add a column to `proxies`:
    //!   1. Bump `PROXY_INSERT_PLACEHOLDER_COUNT` by 1.
    //!   2. Bump `PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT` by 1.
    //!   3. Add the column + `?` placeholder + `.bind()` to all four sites
    //!      listed in the contract block.
    //!   4. Re-run these tests; they verify the SQL placeholder counts match
    //!      the constants. If the bind chain is missing a column, sqlx will
    //!      surface "wrong number of parameters" at execute time (caught by
    //!      the existing integration tests).
    use super::{DatabaseStore, audit_ts_string};

    #[test]
    fn audit_ts_string_is_fixed_width_and_lexically_ordered() {
        let base = chrono::DateTime::parse_from_rfc3339("2026-05-18T03:00:00Z")
            .expect("base timestamp")
            .with_timezone(&chrono::Utc);
        let later = base + chrono::Duration::milliseconds(100);

        assert_eq!(audit_ts_string(&base), "2026-05-18T03:00:00.000000000Z");
        assert_eq!(audit_ts_string(&later), "2026-05-18T03:00:00.100000000Z");
        assert!(audit_ts_string(&base) < audit_ts_string(&later));
    }

    #[test]
    fn proxy_insert_sql_placeholder_count_matches_const() {
        let placeholders = DatabaseStore::PROXY_INSERT_SQL.matches('?').count();
        assert_eq!(
            placeholders,
            DatabaseStore::PROXY_INSERT_PLACEHOLDER_COUNT,
            "PROXY_INSERT_SQL `?` placeholder count drifted from \
             PROXY_INSERT_PLACEHOLDER_COUNT — see the drift-prevention \
             contract comment block in db_loader.rs",
        );
    }

    /// The `submit_api_spec_bundle` INSERT is built inline (it carries an
    /// extra `api_spec_id` column), so we mirror its SQL skeleton here and
    /// assert the same `?` count contract. If the inline SQL in
    /// `submit_api_spec_bundle` drifts, edit BOTH this fixture and the
    /// `PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT` constant.
    #[test]
    fn submit_api_spec_bundle_proxy_insert_placeholder_count_matches_const() {
        // VALUES list has one `?` per column; we lifted this row count from
        // the actual INSERT in submit_api_spec_bundle. Update if columns
        // change there.
        let values_clause = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                                     ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                                     ?, ?, ?, ?, ?)";
        let placeholders = values_clause.matches('?').count();
        assert_eq!(
            placeholders,
            DatabaseStore::PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT,
            "submit_api_spec_bundle proxy INSERT placeholder count must match \
             PROXY_INSERT_WITH_API_SPEC_ID_PLACEHOLDER_COUNT — see drift-prevention contract",
        );
    }
}
