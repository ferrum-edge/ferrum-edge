//! MongoDB config store — NoSQL backend implementing [`DatabaseBackend`].
//!
//! Provides the same config persistence semantics as the sqlx-backed
//! `DatabaseStore` but uses MongoDB collections instead of SQL tables:
//!
//! | SQL Table | MongoDB Collection |
//! |-----------|--------------------|
//! | `proxies` | `proxies` |
//! | `consumers` | `consumers` |
//! | `plugin_configs` | `plugin_configs` |
//! | `upstreams` | `upstreams` |
//!
//! **Document model**: Each document is a direct BSON serialization of the
//! domain type (`Proxy`, `Consumer`, etc.) with `_id` set to the resource's
//! `id` field. Plugin associations are embedded in the proxy document's
//! `plugins` array (no junction table needed — unlike the relational model).
//!
//! **Incremental polling**: Uses `updated_at` timestamp queries (same strategy
//! as the SQL backend). MongoDB change streams are a future enhancement that
//! requires a replica set.
//!
//! **Index creation**: The `run_migrations()` method creates indexes instead of
//! running SQL migrations. `createIndex` is idempotent **only when the full
//! index spec (keys + options) matches**; if the keys match but options differ
//! (e.g. a new `partialFilterExpression`), MongoDB raises
//! `IndexOptionsConflict` (server error 85). Where this baseline ships a
//! changed-option index over a previously-shipped one, `run_migrations()`
//! detects the conflict, drops the legacy index, and recreates with the new
//! options. See the api_specs `(namespace, proxy_id)` unique index for the
//! pattern.

#[allow(dead_code)] // MongoStore is wired up in mode dispatch (database.rs, control_plane.rs)
mod inner {
    use crate::config::db_backend::{
        ApiSpecListFilter, ApiSpecSortBy, DatabaseBackend, GatewayTrustBundlePoll,
        IncrementalResult, PaginatedResult, SortOrder,
    };
    use crate::config::types::{
        ApiSpec, Consumer, GatewayConfig, PluginAssociation, PluginConfig, Proxy, Upstream,
    };
    use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;
    use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use mongodb::bson::{
        Binary, Bson, DateTime as BsonDateTime, Document, doc, spec::BinarySubtype,
    };
    use mongodb::options::{
        ClientOptions, FindOptions, IndexOptions, ReadPreference, SelectionCriteria, Tls,
        TlsOptions,
    };
    use mongodb::{Client, ClientSession, Collection, Database, IndexModel};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tracing::{debug, error, info, warn};
    // regex::escape is used for safe MongoDB $regex pattern construction in list filters.
    use regex::escape as regex_escape;

    // MongoDB server error codes used by the index-upgrade logic in
    // `run_migrations`. Source: src/mongo/db/operation_exit_code.idl (server)
    // and https://www.mongodb.com/docs/manual/reference/error-codes/.
    const MONGO_ERR_INDEX_NOT_FOUND: i32 = 27;
    const MONGO_ERR_INDEX_ALREADY_EXISTS: i32 = 68;
    const MONGO_ERR_INDEX_OPTIONS_CONFLICT: i32 = 85;
    const MONGO_ERR_INDEX_KEY_SPECS_CONFLICT: i32 = 86;

    /// Build an ordering-safe `$gte` lower bound for the string-typed
    /// `updated_at` field.
    ///
    /// Resource `updated_at` values are persisted as RFC 3339 strings via
    /// chrono's serde impl, which uses `SecondsFormat::AutoSi`: it emits a
    /// `Z`-suffixed string with **variable** fractional precision (no fraction
    /// for whole seconds, otherwise 3/6/9 digits). Plain RFC 3339 string
    /// comparison is therefore not chronologically faithful at the sub-second
    /// boundary — `.` (0x2E) sorts before `Z` (0x5A), so a whole-second bound
    /// like `2025-06-15T15:06:40Z` lexicographically *excludes* the
    /// chronologically-newer `2025-06-15T15:06:40.123Z`.
    ///
    /// To keep `$gte` correct across all stored fractional widths, floor the
    /// bound to its whole second and emit it with no fractional part and no
    /// zone suffix (`%Y-%m-%dT%H:%M:%S`). Such a string is a prefix of every
    /// AutoSi representation of that same second (and of any later instant), so
    /// it lexicographically precedes them all and the boundary second is fully
    /// included. Instants strictly before the bound's second still sort lower
    /// and remain excluded. A sub-second bound is rounded down to the start of
    /// its second — over-inclusive by at most one second, the same safe
    /// direction as the incremental poll's explicit 1s margin (never drop
    /// newer rows).
    fn mongo_updated_at_lower_bound(ts: DateTime<Utc>) -> String {
        ts.format("%Y-%m-%dT%H:%M:%S").to_string()
    }

    fn is_mongo_command_error_with_code(err: &mongodb::error::Error, code: i32) -> bool {
        matches!(
            err.kind.as_ref(),
            mongodb::error::ErrorKind::Command(cmd) if cmd.code == code
        )
    }

    fn is_index_options_conflict(err: &mongodb::error::Error) -> bool {
        is_mongo_command_error_with_code(err, MONGO_ERR_INDEX_OPTIONS_CONFLICT)
            || is_mongo_command_error_with_code(err, MONGO_ERR_INDEX_KEY_SPECS_CONFLICT)
    }

    fn is_index_not_found(err: &mongodb::error::Error) -> bool {
        is_mongo_command_error_with_code(err, MONGO_ERR_INDEX_NOT_FOUND)
    }

    fn is_index_already_exists(err: &mongodb::error::Error) -> bool {
        is_mongo_command_error_with_code(err, MONGO_ERR_INDEX_ALREADY_EXISTS)
    }

    fn mesh_route_dispatch_references_upstream_id(
        plugin: &PluginConfig,
        upstream_id: &str,
    ) -> bool {
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

    /// Connection settings captured at startup so `reconnect()` and
    /// `try_failover_reconnect()` can rebuild the underlying `Client` against
    /// a different URL without changing any other client behavior.
    ///
    /// Stored alongside the live `Client` in `MongoStore` because the typed
    /// `ClientOptions` are URL-derived — when failover swaps the URL, every
    /// non-URL setting (database name, app name, replica set, auth mechanism,
    /// timeouts) must be re-applied identically. Without this struct,
    /// `reconnect()` would have no way to rebuild the client.
    #[derive(Clone, Debug)]
    pub(super) struct MongoConnSettings {
        pub database_name: String,
        pub app_name: Option<String>,
        pub replica_set: Option<String>,
        pub auth_mechanism: Option<String>,
        pub server_selection_timeout_secs: u64,
        pub connect_timeout_secs: u64,
        pub tls_enabled: bool,
        pub tls_ca_cert_path: Option<String>,
        pub tls_client_cert_path: Option<String>,
        pub tls_client_key_path: Option<String>,
        pub tls_insecure: bool,
    }

    /// Decide whether multi-document transactions are available based on the
    /// effective replica set name (after any explicit override has been
    /// applied to `ClientOptions::repl_set_name`).
    fn resolve_replica_set_configured(repl_set_name: Option<&str>) -> bool {
        matches!(repl_set_name, Some(name) if !name.is_empty())
    }

    /// Step labels for the standalone-mongod (no-replica-set) `delete_proxy`
    /// path, in execution order. Documented as data so the order can be
    /// regression-tested without a running MongoDB server.
    pub(super) const DELETE_PROXY_SEQUENTIAL_ORDER: &[&str] = &[
        "delete_proxy_document",
        "delete_proxy_scoped_plugin_configs",
        "cleanup_orphaned_proxy_group_plugins",
    ];

    /// Step labels for the standalone-mongod (no-replica-set)
    /// `replace_api_spec_bundle` delete phase, in execution order. The proxy
    /// document is removed first so any later partial failure leaves no live
    /// route with missing plugin/upstream dependencies.
    pub(super) const REPLACE_API_SPEC_STANDALONE_DELETE_ORDER: &[&str] = &[
        "delete_proxy_document",
        "delete_spec_owned_plugin_configs",
        "delete_spec_owned_upstreams",
        "delete_api_spec_document",
    ];

    /// Step labels for the standalone-mongod (no-replica-set)
    /// `delete_api_spec` path, in execution order. The proxy document is removed
    /// first for the same runtime-safety reason as `delete_proxy`.
    pub(super) const DELETE_API_SPEC_STANDALONE_ORDER: &[&str] = &[
        "delete_proxy_document",
        "delete_spec_owned_plugin_configs",
        "delete_proxy_scoped_plugin_configs",
        "cleanup_orphaned_proxy_group_plugins",
        "delete_spec_owned_upstreams",
        "delete_api_spec_document",
    ];

    /// Step labels for standalone-mongod api-spec bundle inserts/reinserts.
    /// Dependency documents are created before the proxy document so polling can
    /// never observe a live proxy that points at missing plugin/upstream docs.
    pub(super) const API_SPEC_STANDALONE_INSERT_ORDER: &[&str] = &[
        "insert_upstream_document",
        "insert_plugin_config_documents",
        "insert_proxy_document",
        "insert_api_spec_document",
    ];

    /// Step labels for compensating rollback after a partial standalone insert.
    /// The proxy is removed before plugin/upstream dependencies so rollback
    /// failures preserve a runtime-safe route if the proxy cannot be deleted.
    pub(super) const COMPENSATE_BUNDLE_INSERT_ORDER: &[&str] = &[
        "delete_api_spec_document",
        "delete_proxy_document",
        "delete_plugin_config_documents",
        "delete_upstream_document",
    ];

    /// Step labels for the standalone-mongod (no-replica-set) `update_proxy`
    /// path, in execution order. Cleanup runs after the replace because the
    /// new proxy.plugins array determines which proxy_group plugin_configs
    /// are still referenced.
    pub(super) const UPDATE_PROXY_SEQUENTIAL_ORDER: &[&str] = &[
        "replace_proxy_document",
        "cleanup_orphaned_proxy_group_plugins",
    ];

    /// MongoDB-backed config store.
    ///
    /// Implements [`DatabaseBackend`] to provide a NoSQL alternative to the
    /// sqlx-backed `DatabaseStore`. Uses the official `mongodb` Rust driver.
    ///
    /// **Failover & reconnect**: `client` and `db` are wrapped in
    /// `Arc<ArcSwap<...>>` so [`Self::try_failover_reconnect`] can atomically
    /// replace the underlying `Client` when the primary URL is unreachable
    /// and a configured failover URL is healthy. Readers that already loaded
    /// the old client keep using it (commands in flight complete normally),
    /// then drop their reference and pick up the new one on the next call.
    /// This mirrors the `Arc<ArcSwap<AnyPool>>` pattern used by the sqlx
    /// `DatabaseStore` for the same reason — without it, every "failover"
    /// attempt would just ping the dead client and the gateway would never
    /// recover for standalone (non-replica-set) MongoDB deployments.
    #[derive(Clone)]
    pub struct MongoStore {
        // The live client. Held only so it gets dropped when swapped out;
        // every collection access goes through `db()`, which loads from
        // `db` directly (the `Database` handle internally references the
        // current client).
        client: Arc<ArcSwap<Client>>,
        db: Arc<ArcSwap<Database>>,
        // Settings captured at startup so failover rebuilds use identical
        // ClientOptions for every non-URL field.
        conn_settings: MongoConnSettings,
        db_type_str: String,
        slow_query_threshold_ms: Option<u64>,
        cert_expiry_warning_days: u64,
        backend_allow_ips: crate::config::BackendAllowIps,
        failover_urls: Vec<String>,
        replica_set_configured: Arc<AtomicBool>,
    }

    impl MongoStore {
        /// Connect to MongoDB using the provided connection string.
        ///
        /// The connection string follows the standard MongoDB URI format:
        /// `mongodb://[username:password@]host[:port]/[database][?options]`
        ///
        /// **TLS/mTLS configuration**: When `tls_enabled` is true, TLS is configured
        /// programmatically via `TlsOptions` using the canonical database TLS env vars:
        /// - `FERRUM_DB_TLS_CA_CERT_PATH` → `TlsOptions::ca_file_path`
        /// - `FERRUM_DB_TLS_CLIENT_CERT_PATH` → `TlsOptions::cert_key_file_path`
        ///   when supplied alone as a combined PEM; combined with
        ///   `FERRUM_DB_TLS_CLIENT_KEY_PATH` into a temp PEM when supplied as
        ///   separate cert/key files (MongoDB requires a single file)
        /// - `FERRUM_DB_TLS_MODE=require` → `TlsOptions::allow_invalid_certificates`
        ///
        /// TLS can also be configured directly via connection string options
        /// (`tls=true&tlsCAFile=...`), which takes precedence over the programmatic
        /// config when both are set.
        #[allow(clippy::too_many_arguments)]
        pub async fn connect(
            mongo_url: &str,
            database_name: &str,
            app_name: Option<&str>,
            replica_set: Option<&str>,
            auth_mechanism: Option<&str>,
            server_selection_timeout_secs: u64,
            connect_timeout_secs: u64,
            tls_enabled: bool,
            tls_ca_cert_path: Option<&str>,
            tls_client_cert_path: Option<&str>,
            tls_client_key_path: Option<&str>,
            tls_insecure: bool,
        ) -> Result<Self, anyhow::Error> {
            let conn_settings = MongoConnSettings {
                database_name: database_name.to_string(),
                app_name: app_name.map(str::to_string),
                replica_set: replica_set.map(str::to_string),
                auth_mechanism: auth_mechanism.map(str::to_string),
                server_selection_timeout_secs,
                connect_timeout_secs,
                tls_enabled,
                tls_ca_cert_path: tls_ca_cert_path.map(str::to_string),
                tls_client_cert_path: tls_client_cert_path.map(str::to_string),
                tls_client_key_path: tls_client_key_path.map(str::to_string),
                tls_insecure,
            };

            let (client, db, replica_set_configured) = Self::build_client_and_db(
                mongo_url,
                &conn_settings,
                tls_enabled,
                tls_ca_cert_path,
                tls_client_cert_path,
                tls_client_key_path,
                tls_insecure,
            )
            .await?;

            if !replica_set_configured {
                warn!(
                    "MongoDB connected without a replica set (FERRUM_MONGO_REPLICA_SET is unset). \
                     Multi-document writes (proxy delete/update, api_spec submit/replace) will \
                     fall back to compensating rollback instead of transactions, leaving a small \
                     window where partial failure can orphan documents until the polling cycle \
                     cleans them. Configure FERRUM_MONGO_REPLICA_SET to enable transactions."
                );
            }

            Ok(Self {
                client: Arc::new(ArcSwap::from_pointee(client)),
                db: Arc::new(ArcSwap::from_pointee(db)),
                conn_settings,
                db_type_str: "mongodb".to_string(),
                slow_query_threshold_ms: None,
                cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
                backend_allow_ips: crate::config::BackendAllowIps::Both,
                failover_urls: Vec::new(),
                replica_set_configured: Arc::new(AtomicBool::new(replica_set_configured)),
            })
        }

        /// Build a `Client` + `Database` from a URL plus the captured
        /// connection settings, applying TLS if requested. Verifies
        /// connectivity with a `ping` before returning so callers can
        /// distinguish "URL parse / config error" from "URL is down".
        ///
        /// Used by both [`Self::connect`] (initial connect) and
        /// [`DatabaseBackend::reconnect`] (failover) so the two paths
        /// can never diverge on how `ClientOptions` are built.
        async fn build_client_and_db(
            mongo_url: &str,
            settings: &MongoConnSettings,
            tls_enabled: bool,
            tls_ca_cert_path: Option<&str>,
            tls_client_cert_path: Option<&str>,
            tls_client_key_path: Option<&str>,
            tls_insecure: bool,
        ) -> Result<(Client, Database, bool), anyhow::Error> {
            let mut client_options = ClientOptions::parse(mongo_url).await?;
            if client_options.selection_criteria.is_some() {
                warn!(
                    "MongoDB readPreference from FERRUM_DB_URL is ignored; authoritative config reads use primary"
                );
            }
            client_options.selection_criteria =
                Some(SelectionCriteria::ReadPreference(ReadPreference::Primary));

            if let Some(name) = &settings.app_name {
                client_options.app_name = Some(name.clone());
            }
            if let Some(rs) = &settings.replica_set {
                client_options.repl_set_name = Some(rs.clone());
            }
            let replica_set_configured =
                resolve_replica_set_configured(client_options.repl_set_name.as_deref());
            if let Some(mechanism) = &settings.auth_mechanism {
                client_options
                    .credential
                    .get_or_insert_with(Default::default)
                    .mechanism = Some(mechanism.parse().map_err(|e| {
                    anyhow::anyhow!("Invalid MongoDB auth mechanism '{}': {}", mechanism, e)
                })?);
            }
            client_options.server_selection_timeout =
                Some(Duration::from_secs(settings.server_selection_timeout_secs));
            client_options.connect_timeout =
                Some(Duration::from_secs(settings.connect_timeout_secs));

            // Configure TLS via the canonical database TLS env vars.
            // Only set programmatic TLS if the connection string doesn't already
            // include TLS options (connection string takes precedence).
            if tls_enabled && client_options.tls.is_none() {
                let ca = tls_ca_cert_path
                    .map(|ca_path| {
                        Self::materialize_tls_source_to_file(
                            ca_path,
                            MaterialKind::CaBundle,
                            "ferrum-mongo-ca-",
                        )
                    })
                    .transpose()?;

                // MongoDB requires client cert + key in a single combined PEM file.
                // If the user provides separate cert and key files, combine them
                // into a temp file. If only cert is provided, assume it already
                // contains the key (combined PEM).
                let cert_key = match (tls_client_cert_path, tls_client_key_path) {
                    (Some(cert_path), Some(key_path)) => {
                        Some(Self::combine_cert_key_pem(cert_path, key_path)?)
                    }
                    (Some(cert_path), None) => Some(Self::materialize_tls_source_to_file(
                        cert_path,
                        MaterialKind::Cert,
                        "ferrum-mongo-client-",
                    )?),
                    _ => None,
                };

                // Build TlsOptions using the typed-state builder. Each method
                // consumes the builder, so we chain conditionally.
                let tls_opts = Self::build_tls_options(ca, cert_key, tls_insecure);

                client_options.tls = Some(Tls::Enabled(tls_opts));
                info!(
                    "MongoDB TLS enabled (ca={}, client_cert={}, insecure={})",
                    tls_ca_cert_path
                        .map(|value| CertSource::parse(value, MaterialKind::CaBundle).source_id())
                        .unwrap_or_else(|| "system-roots".to_string()),
                    tls_client_cert_path
                        .map(|value| CertSource::parse(value, MaterialKind::Cert).source_id())
                        .unwrap_or_else(|| "none".to_string()),
                    tls_insecure
                );
            }

            let client = Client::with_options(client_options)?;
            let db = client.database(&settings.database_name);

            // Verify connectivity
            db.run_command(doc! { "ping": 1 }).await.map_err(|e| {
                anyhow::anyhow!(
                    "MongoDB connectivity check failed (database='{}'): {}",
                    settings.database_name,
                    e
                )
            })?;

            info!(
                "MongoDB connected (database='{}', url={}, replica_set={})",
                settings.database_name,
                crate::config::db_backend::redact_url(mongo_url),
                replica_set_configured
            );

            Ok((client, db, replica_set_configured))
        }

        /// Combine separate PEM cert and key sources into a single temporary file.
        ///
        /// The MongoDB Rust driver requires client cert + key in a single PEM file
        /// (`TlsOptions::cert_key_file_path`). The gateway's `FERRUM_DB_TLS_*` env
        /// vars use separate sources (matching the PostgreSQL/MySQL convention).
        /// This helper reads both sources and writes a combined PEM to a securely
        /// created temp file with restrictive permissions.
        fn combine_cert_key_pem(cert_path: &str, key_path: &str) -> Result<PathBuf, anyhow::Error> {
            let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
            let key_source = CertSource::parse(key_path, MaterialKind::Key);
            let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB client cert: {}", e))?;
            let key_material = load_material_blocking(&key_source, MaterialKind::Key)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB client key: {}", e))?;

            // Write combined PEM to a securely-created temp file. `tempfile`
            // creates files with restrictive permissions and random names,
            // avoiding predictable-path and world-readable key leakage risks.
            let mut combined = Vec::with_capacity(
                cert_material.bytes.expose_secret().len()
                    + key_material.bytes.expose_secret().len()
                    + 1,
            );
            combined.extend_from_slice(cert_material.bytes.expose_secret());
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(key_material.bytes.expose_secret());
            let temp_file = tempfile::Builder::new()
                .prefix("ferrum-mongo-client-")
                .suffix(".pem")
                .tempfile()
                .map_err(|e| anyhow::anyhow!("Failed to create temp PEM file: {}", e))?;
            let (_file, combined_path) = temp_file.keep().map_err(|e| {
                anyhow::anyhow!(
                    "Failed to persist combined MongoDB client PEM '{}': {}",
                    e.file.path().display(),
                    e.error
                )
            })?;
            std::fs::write(&combined_path, combined).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write combined MongoDB client PEM to '{}': {}",
                    combined_path.display(),
                    e
                )
            })?;

            info!(
                "Combined MongoDB client cert ({}) + key ({}) into {}",
                cert_material.source_id,
                key_material.source_id,
                combined_path.display()
            );
            Ok(combined_path)
        }

        fn materialize_tls_source_to_file(
            source_value: &str,
            kind: MaterialKind,
            temp_prefix: &str,
        ) -> Result<PathBuf, anyhow::Error> {
            let source = CertSource::parse(source_value, kind);
            if let Some(path) = source.as_file_path() {
                return Ok(path);
            }

            let material = load_material_blocking(&source, kind)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB TLS material: {}", e))?;
            let temp_file = tempfile::Builder::new()
                .prefix(temp_prefix)
                .suffix(".pem")
                .tempfile()
                .map_err(|e| anyhow::anyhow!("Failed to create temp PEM file: {}", e))?;
            let (_file, material_path) = temp_file.keep().map_err(|e| {
                anyhow::anyhow!(
                    "Failed to persist MongoDB TLS PEM '{}': {}",
                    e.file.path().display(),
                    e.error
                )
            })?;
            std::fs::write(&material_path, material.bytes.expose_secret()).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write MongoDB TLS PEM to '{}': {}",
                    material_path.display(),
                    e
                )
            })?;

            info!(
                "Materialized MongoDB TLS source {} into {}",
                material.source_id,
                material_path.display()
            );
            Ok(material_path)
        }

        /// Build `TlsOptions` from the individual components.
        ///
        /// The MongoDB `TlsOptions` builder uses a typed-state pattern where each
        /// method consumes the builder and returns a new type. This makes conditional
        /// chaining impossible, so we handle the 8 possible combinations explicitly.
        fn build_tls_options(
            ca: Option<PathBuf>,
            cert_key: Option<PathBuf>,
            insecure: bool,
        ) -> TlsOptions {
            // Use the typed-state builder for each combination of options.
            // Each arm builds the complete option set matching what's provided.
            match (ca, cert_key, insecure) {
                (Some(ca_path), Some(ck_path), true) => TlsOptions::builder()
                    .ca_file_path(ca_path)
                    .cert_key_file_path(ck_path)
                    .allow_invalid_certificates(true)
                    .build(),
                (Some(ca_path), Some(ck_path), false) => TlsOptions::builder()
                    .ca_file_path(ca_path)
                    .cert_key_file_path(ck_path)
                    .build(),
                (Some(ca_path), None, true) => TlsOptions::builder()
                    .ca_file_path(ca_path)
                    .allow_invalid_certificates(true)
                    .build(),
                (Some(ca_path), None, false) => TlsOptions::builder().ca_file_path(ca_path).build(),
                (None, Some(ck_path), true) => TlsOptions::builder()
                    .cert_key_file_path(ck_path)
                    .allow_invalid_certificates(true)
                    .build(),
                (None, Some(ck_path), false) => {
                    TlsOptions::builder().cert_key_file_path(ck_path).build()
                }
                (None, None, true) => TlsOptions::builder()
                    .allow_invalid_certificates(true)
                    .build(),
                (None, None, false) => TlsOptions::builder().build(),
            }
        }

        /// Connect with failover URLs (same pattern as SQL backend).
        #[allow(clippy::too_many_arguments)]
        pub async fn connect_with_failover(
            primary_url: &str,
            database_name: &str,
            app_name: Option<&str>,
            replica_set: Option<&str>,
            auth_mechanism: Option<&str>,
            server_selection_timeout_secs: u64,
            connect_timeout_secs: u64,
            tls_enabled: bool,
            tls_ca_cert_path: Option<&str>,
            tls_client_cert_path: Option<&str>,
            tls_client_key_path: Option<&str>,
            tls_insecure: bool,
            failover_urls: &[String],
        ) -> Result<Self, anyhow::Error> {
            match Self::connect(
                primary_url,
                database_name,
                app_name,
                replica_set,
                auth_mechanism,
                server_selection_timeout_secs,
                connect_timeout_secs,
                tls_enabled,
                tls_ca_cert_path,
                tls_client_cert_path,
                tls_client_key_path,
                tls_insecure,
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
                        "Primary MongoDB connection failed: {}. Trying {} failover URL(s)...",
                        primary_err,
                        failover_urls.len()
                    );
                    for (i, url) in failover_urls.iter().enumerate() {
                        match Self::connect(
                            url,
                            database_name,
                            app_name,
                            replica_set,
                            auth_mechanism,
                            server_selection_timeout_secs,
                            connect_timeout_secs,
                            tls_enabled,
                            tls_ca_cert_path,
                            tls_client_cert_path,
                            tls_client_key_path,
                            tls_insecure,
                        )
                        .await
                        {
                            Ok(mut store) => {
                                info!(
                                    "Connected to failover MongoDB #{} ({})",
                                    i + 1,
                                    crate::config::db_backend::redact_url(url)
                                );
                                store.failover_urls = failover_urls.to_vec();
                                return Ok(store);
                            }
                            Err(e) => {
                                warn!(
                                    "Failover MongoDB #{} ({}) failed: {}",
                                    i + 1,
                                    crate::config::db_backend::redact_url(url),
                                    e
                                );
                            }
                        }
                    }
                    Err(anyhow::anyhow!(
                        "All MongoDB URLs failed. Primary: {}. Tried {} failover URL(s).",
                        primary_err,
                        failover_urls.len()
                    ))
                }
            }
        }

        // -------------------------------------------------------------------
        // Collection accessors
        // -------------------------------------------------------------------

        /// Snapshot of the current `Database` handle. Cheap clone (the driver's
        /// `Database` is internally Arc-based) so callers can hold the handle
        /// across awaits without blocking concurrent `reconnect()` swaps.
        fn db(&self) -> Database {
            (**self.db.load()).clone()
        }

        fn proxies(&self) -> Collection<Document> {
            self.db().collection("proxies")
        }

        fn consumers(&self) -> Collection<Document> {
            self.db().collection("consumers")
        }

        fn plugin_configs(&self) -> Collection<Document> {
            self.db().collection("plugin_configs")
        }

        fn upstreams(&self) -> Collection<Document> {
            self.db().collection("upstreams")
        }

        fn api_specs(&self) -> Collection<Document> {
            self.db().collection("api_specs")
        }

        fn audit_events(&self) -> Collection<Document> {
            self.db().collection("audit_events")
        }

        // -------------------------------------------------------------------
        // Internal helpers
        // -------------------------------------------------------------------

        fn check_slow_query(&self, operation: &str, start: std::time::Instant) {
            if let Some(threshold_ms) = self.slow_query_threshold_ms {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                if elapsed_ms > threshold_ms {
                    warn!(
                        "Slow MongoDB query: {} took {}ms (threshold: {}ms)",
                        operation, elapsed_ms, threshold_ms
                    );
                }
            }
        }

        /// Count `api_specs` rows that the floored `updated_at` prefilter
        /// over-matched: those in the boundary second `[floor(since), since)`
        /// whose exact `updated_at` is chronologically `< since`.
        ///
        /// `base_filter` is the caller's full list filter (namespace plus any
        /// proxy_id/tag/etc. predicates) including the floored `updated_at`
        /// `$gte`; this restricts the scan to the same logical set. The
        /// `updated_at` predicate is then narrowed to the single boundary
        /// second so only that window is fetched (one second of resource
        /// writes, normally empty). Only the `updated_at` field is projected.
        async fn count_updated_before_in_boundary_second(
            &self,
            base_filter: &Document,
            since: DateTime<Utc>,
        ) -> Result<i64, anyhow::Error> {
            // Restrict to `[floor(since), floor(since)+1s)` — the only window
            // the whole-second floor can over-include.
            let floor = mongo_updated_at_lower_bound(since);
            let next = mongo_updated_at_lower_bound(since + chrono::Duration::seconds(1));
            let mut filter = base_filter.clone();
            filter.insert("updated_at", doc! { "$gte": &floor, "$lt": &next });

            let options = FindOptions::builder()
                .projection(doc! { "_id": 0, "updated_at": 1 })
                .build();
            let mut cursor = self.api_specs().find(filter).with_options(options).await?;
            let mut overage: i64 = 0;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                // Parse the stored RFC 3339 string exactly (faithful across
                // every AutoSi fractional width) and apply `< since`.
                if let Ok(raw) = doc.get_str("updated_at")
                    && let Ok(parsed) = DateTime::parse_from_rfc3339(raw)
                    && parsed.with_timezone(&Utc) < since
                {
                    overage += 1;
                }
            }
            Ok(overage)
        }

        /// Delete proxy_group-scoped plugin configs that are no longer referenced
        /// by any proxy's embedded `plugins` array. Called after proxy deletion or
        /// update (which may remove associations).
        async fn cleanup_orphaned_proxy_group_plugins(&self) -> Result<(), anyhow::Error> {
            self.cleanup_orphaned_proxy_group_plugins_opt_session(None)
                .await
        }

        /// Same as [`Self::cleanup_orphaned_proxy_group_plugins`] but optionally
        /// participates in a `ClientSession`-scoped transaction.
        async fn cleanup_orphaned_proxy_group_plugins_opt_session(
            &self,
            session: Option<&mut ClientSession>,
        ) -> Result<(), anyhow::Error> {
            if let Some(s) = session {
                let mut cursor = self
                    .plugin_configs()
                    .find(doc! { "scope": "proxy_group" })
                    .projection(doc! { "_id": 1 })
                    .session(&mut *s)
                    .await?;
                let mut group_ids: Vec<String> = Vec::new();
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current()?;
                    if let Ok(id) = doc.get_str("_id") {
                        group_ids.push(id.to_string());
                    }
                }
                drop(cursor);

                for id in &group_ids {
                    let count = self
                        .proxies()
                        .count_documents(doc! { "plugins.plugin_config_id": id })
                        .session(&mut *s)
                        .await?;
                    if count == 0 {
                        info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
                        self.plugin_configs()
                            .delete_one(doc! { "_id": id })
                            .session(&mut *s)
                            .await?;
                    }
                }
                return Ok(());
            }

            // Find all proxy_group-scoped plugin config IDs
            let mut cursor = self
                .plugin_configs()
                .find(doc! { "scope": "proxy_group" })
                .projection(doc! { "_id": 1 })
                .await?;
            let mut group_ids: Vec<String> = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("_id") {
                    group_ids.push(id.to_string());
                }
            }

            for id in &group_ids {
                // Check if any proxy still references this plugin config
                let count = self
                    .proxies()
                    .count_documents(doc! { "plugins.plugin_config_id": id })
                    .await?;
                if count == 0 {
                    info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
                    self.plugin_configs().delete_one(doc! { "_id": id }).await?;
                }
            }

            Ok(())
        }

        async fn find_mesh_route_dispatch_upstream_ref_opt_session(
            &self,
            session: Option<&mut ClientSession>,
            upstream_id: &str,
        ) -> Result<Option<PluginConfig>, anyhow::Error> {
            if let Some(s) = session {
                let mut cursor = self
                    .plugin_configs()
                    .find(doc! { "plugin_name": "mesh_route_dispatch", "enabled": true })
                    .session(&mut *s)
                    .await?;
                while cursor.advance(&mut *s).await? {
                    let plugin = doc_to_plugin_config(cursor.deserialize_current()?)?;
                    if mesh_route_dispatch_references_upstream_id(&plugin, upstream_id) {
                        return Ok(Some(plugin));
                    }
                }
            } else {
                let mut cursor = self
                    .plugin_configs()
                    .find(doc! { "plugin_name": "mesh_route_dispatch", "enabled": true })
                    .await?;
                while cursor.advance().await? {
                    let plugin = doc_to_plugin_config(cursor.deserialize_current()?)?;
                    if mesh_route_dispatch_references_upstream_id(&plugin, upstream_id) {
                        return Ok(Some(plugin));
                    }
                }
            }
            Ok(None)
        }

        async fn current_api_spec_resource_hash(
            &self,
            bundle: &crate::admin::api_specs::ExtractedBundle,
            spec: &ApiSpec,
            previous_declared_assoc_ids: &HashSet<String>,
        ) -> Result<Option<String>, anyhow::Error> {
            let mut plugin_cursor = self
                .plugin_configs()
                .find(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                .await?;
            let mut plugins = Vec::new();
            while plugin_cursor.advance().await? {
                let mut plugin = doc_to_plugin_config(plugin_cursor.deserialize_current()?)?;
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

            let proxy_doc = self
                .proxies()
                .find_one(
                    doc! { "_id": &spec.proxy_id, "namespace": &spec.namespace, "api_spec_id": &spec.id },
                )
                .await?;
            let Some(proxy_doc) = proxy_doc else {
                return Ok(None);
            };
            let mut proxy = doc_to_proxy(proxy_doc)?;
            proxy.normalize_fields();
            let current_relevant_assoc_ids: HashSet<String> = proxy
                .plugins
                .iter()
                .filter_map(|assoc| {
                    if relevant_assoc_ids.contains(&assoc.plugin_config_id) {
                        Some(assoc.plugin_config_id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            if current_relevant_assoc_ids != desired_assoc_ids {
                return Ok(None);
            }
            proxy.plugins = bundle
                .proxy
                .plugins
                .iter()
                .filter(|assoc| current_relevant_assoc_ids.contains(&assoc.plugin_config_id))
                .cloned()
                .collect();

            let mut upstream_cursor = self
                .upstreams()
                .find(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                .await?;
            let mut upstreams = Vec::new();
            while upstream_cursor.advance().await? {
                let mut upstream = doc_to_upstream(upstream_cursor.deserialize_current()?)?;
                upstream.normalize_fields();
                upstreams.push(upstream);
            }
            if upstreams.len() > 1 {
                return Ok(None);
            }

            let current = crate::admin::api_specs::ExtractedBundle {
                proxy,
                upstream: upstreams.into_iter().next(),
                plugins,
            };
            crate::admin::api_specs::hash_resource_bundle(&current).map(Some)
        }

        async fn ensure_no_external_spec_upstream_refs(
            &self,
            namespace: &str,
            spec_id: &str,
            spec_proxy_id: &str,
        ) -> Result<(), anyhow::Error> {
            self.ensure_no_external_spec_upstream_refs_opt_session(
                None,
                namespace,
                spec_id,
                spec_proxy_id,
            )
            .await
        }

        async fn ensure_no_external_spec_upstream_refs_opt_session(
            &self,
            session: Option<&mut ClientSession>,
            namespace: &str,
            spec_id: &str,
            spec_proxy_id: &str,
        ) -> Result<(), anyhow::Error> {
            if let Some(s) = session {
                let mut upstream_ids = Vec::new();
                let mut upstream_cursor = self
                    .upstreams()
                    .find(doc! { "api_spec_id": spec_id, "namespace": namespace })
                    .projection(doc! { "_id": 1 })
                    .session(&mut *s)
                    .await?;
                while upstream_cursor.advance(&mut *s).await? {
                    let doc = upstream_cursor.deserialize_current()?;
                    if let Ok(id) = doc.get_str("_id") {
                        upstream_ids.push(id.to_string());
                    }
                }
                drop(upstream_cursor);

                if upstream_ids.is_empty() {
                    return Ok(());
                }

                let filter = doc! {
                    "upstream_id": { "$in": &upstream_ids },
                    "_id": { "$ne": spec_proxy_id },
                };
                let external = self
                    .proxies()
                    .find_one(filter)
                    .projection(doc! { "_id": 1, "upstream_id": 1 })
                    .session(&mut *s)
                    .await?;
                if let Some(doc) = external {
                    let proxy_id = doc.get_str("_id").unwrap_or("<unknown>");
                    let upstream_id = doc.get_str("upstream_id").unwrap_or("<unknown>");
                    anyhow::bail!(
                        "proxy '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                         detach it before replacing or deleting the API spec",
                        proxy_id,
                        upstream_id,
                        spec_id
                    );
                }

                let spec_upstream_ids: HashSet<String> = upstream_ids.iter().cloned().collect();
                let mut plugin_cursor = self
                    .plugin_configs()
                    .find(doc! { "plugin_name": "mesh_route_dispatch", "enabled": true })
                    .session(&mut *s)
                    .await?;
                while plugin_cursor.advance(&mut *s).await? {
                    let plugin = doc_to_plugin_config(plugin_cursor.deserialize_current()?)?;
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
            } else {
                let mut upstream_ids = Vec::new();
                let mut upstream_cursor = self
                    .upstreams()
                    .find(doc! { "api_spec_id": spec_id, "namespace": namespace })
                    .projection(doc! { "_id": 1 })
                    .await?;
                while upstream_cursor.advance().await? {
                    let doc = upstream_cursor.deserialize_current()?;
                    if let Ok(id) = doc.get_str("_id") {
                        upstream_ids.push(id.to_string());
                    }
                }

                if upstream_ids.is_empty() {
                    return Ok(());
                }

                let filter = doc! {
                    "upstream_id": { "$in": &upstream_ids },
                    "_id": { "$ne": spec_proxy_id },
                };
                let external = self
                    .proxies()
                    .find_one(filter)
                    .projection(doc! { "_id": 1, "upstream_id": 1 })
                    .await?;
                if let Some(doc) = external {
                    let proxy_id = doc.get_str("_id").unwrap_or("<unknown>");
                    let upstream_id = doc.get_str("upstream_id").unwrap_or("<unknown>");
                    anyhow::bail!(
                        "proxy '{}' references a spec-owned upstream '{}' from api_spec '{}'; \
                         detach it before replacing or deleting the API spec",
                        proxy_id,
                        upstream_id,
                        spec_id
                    );
                }

                let spec_upstream_ids: HashSet<String> = upstream_ids.iter().cloned().collect();
                let mut plugin_cursor = self
                    .plugin_configs()
                    .find(doc! { "plugin_name": "mesh_route_dispatch", "enabled": true })
                    .await?;
                while plugin_cursor.advance().await? {
                    let plugin = doc_to_plugin_config(plugin_cursor.deserialize_current()?)?;
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
            }

            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // BSON serialization helpers
    // -----------------------------------------------------------------------

    /// Strip explicit `null` values for fields that participate in unique
    /// + sparse compound indexes.
    ///
    /// MongoDB's sparse indexes skip documents where the indexed field is
    /// **absent**, but they DO index documents where the field is explicitly
    /// set to `null`. Under `unique: true`, two documents in the same
    /// namespace with `{listen_port: null}` (or `{name: null}`, etc.) both
    /// land on the same index entry and the second insert fails with
    /// `E11000 duplicate key error`.
    ///
    /// The domain structs use `Option<T>` without `skip_serializing_if`, so
    /// `None` serializes to BSON `Null`. Stripping these fields from the
    /// document before insert restores sparse-index semantics while keeping
    /// JSON admin-API responses (which read `name`/`listen_port`/`custom_id`
    /// via serde) unchanged.
    ///
    /// Only the fields listed here need stripping. Other `Option` fields
    /// either participate in non-unique indexes (no conflict) or have no
    /// index at all.
    fn strip_null_fields(doc: &mut Document, fields: &[&str]) {
        for field in fields {
            if matches!(doc.get(*field), Some(Bson::Null)) {
                doc.remove(*field);
            }
        }
    }

    fn declared_proxy_plugin_association_ids_from_spec(
        spec: &ApiSpec,
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

    /// Convert a domain `Proxy` into a BSON `Document` for storage.
    fn proxy_to_doc(proxy: &Proxy) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(proxy)?;
        // Use the proxy's id as the MongoDB _id
        doc.insert("_id", proxy.id.as_str());
        // `name` and `listen_port` both participate in unique+sparse
        // compound indexes (`{namespace, name}` and
        // `{namespace, listen_port}`). Two HTTP proxies in the same
        // namespace both have `listen_port: None` — without stripping,
        // the second insert would fail with a duplicate-null-key error.
        strip_null_fields(&mut doc, &["name", "listen_port"]);
        Ok(doc)
    }

    /// Convert a BSON `Document` back into a domain `Proxy`.
    ///
    /// All admin resource types use `#[serde(deny_unknown_fields)]`, so every
    /// `doc_to_*` helper strips MongoDB's `_id` before deserialization.
    fn doc_to_proxy(mut doc: Document) -> Result<Proxy, anyhow::Error> {
        doc.remove("_id");
        let proxy: Proxy = mongodb::bson::from_document(doc)?;
        Ok(proxy)
    }

    /// Convert a domain `Consumer` into a BSON `Document`.
    fn consumer_to_doc(consumer: &Consumer) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(consumer)?;
        doc.insert("_id", consumer.id.as_str());
        // `custom_id` participates in the `{namespace, custom_id}` unique+
        // sparse index. Strip when absent for the same reason as Proxy above.
        strip_null_fields(&mut doc, &["custom_id"]);
        Ok(doc)
    }

    fn doc_to_consumer(mut doc: Document) -> Result<Consumer, anyhow::Error> {
        doc.remove("_id");
        Ok(mongodb::bson::from_document(doc)?)
    }

    /// Convert a domain `PluginConfig` into a BSON `Document`.
    fn plugin_config_to_doc(pc: &PluginConfig) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(pc)?;
        doc.insert("_id", pc.id.as_str());
        Ok(doc)
    }

    fn doc_to_plugin_config(mut doc: Document) -> Result<PluginConfig, anyhow::Error> {
        doc.remove("_id");
        Ok(mongodb::bson::from_document(doc)?)
    }

    /// Convert a domain `Upstream` into a BSON `Document`.
    fn upstream_to_doc(upstream: &Upstream) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(upstream)?;
        doc.insert("_id", upstream.id.as_str());
        // `name` participates in the `{namespace, name}` unique+sparse index.
        // Upstreams without a name must omit the field so multiple nameless
        // upstreams in the same namespace don't collide on a shared null key.
        strip_null_fields(&mut doc, &["name"]);
        Ok(doc)
    }

    fn doc_to_upstream(mut doc: Document) -> Result<Upstream, anyhow::Error> {
        doc.remove("_id");
        Ok(mongodb::bson::from_document(doc)?)
    }

    /// Convert an [`ApiSpec`] into a BSON `Document` for storage.
    ///
    /// `spec_content` (gzip bytes) serializes as BSON Binary. The document
    /// size limit is ~16 MiB; callers must check before insert.
    ///
    /// Wave 5: `tags` and `server_urls` are stored as native BSON arrays.
    fn api_spec_to_doc(spec: &ApiSpec) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(spec)?;
        doc.insert("_id", spec.id.as_str());
        doc.insert(
            "spec_content",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: spec.spec_content.clone(),
            }),
        );
        Ok(doc)
    }

    fn audit_event_to_doc(
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(event)?;
        doc.insert("_id", event.id.as_str());
        doc.insert("diff", serde_json::to_string(&event.diff)?);
        doc.insert(
            "ts",
            Bson::DateTime(BsonDateTime::from_millis(event.ts.timestamp_millis())),
        );
        Ok(doc)
    }

    fn doc_to_audit_event(
        mut doc: Document,
    ) -> Result<crate::admin::audit::AuditEvent, anyhow::Error> {
        doc.remove("_id");
        match doc.remove("ts") {
            Some(Bson::DateTime(ts)) => {
                let ts = DateTime::<Utc>::from_timestamp_millis(ts.timestamp_millis())
                    .ok_or_else(|| anyhow::anyhow!("audit event ts is outside chrono range"))?;
                doc.insert("ts", ts.to_rfc3339());
            }
            Some(other) => {
                doc.insert("ts", other);
            }
            None => {}
        }
        let diff = match doc.remove("diff") {
            Some(Bson::String(diff_json)) => Some(serde_json::from_str(&diff_json)?),
            Some(other) => {
                doc.insert("diff", other);
                None
            }
            None => Some(serde_json::Value::Object(serde_json::Map::new())),
        };
        if diff.is_some() {
            doc.insert("diff", Bson::Document(Document::new()));
        }

        let mut event: crate::admin::audit::AuditEvent = mongodb::bson::from_document(doc)?;
        if let Some(diff) = diff {
            event.diff = diff;
        }
        Ok(event)
    }

    fn doc_to_api_spec(mut doc: Document) -> Result<ApiSpec, anyhow::Error> {
        doc.remove("_id");
        let spec_content = match doc.remove("spec_content") {
            Some(Bson::Binary(binary)) => binary.bytes,
            Some(Bson::Array(values)) => {
                let mut bytes = Vec::with_capacity(values.len());
                for value in values {
                    let byte = match value {
                        Bson::Int32(v) if (0..=u8::MAX as i32).contains(&v) => v as u8,
                        Bson::Int64(v) if (0..=u8::MAX as i64).contains(&v) => v as u8,
                        other => {
                            anyhow::bail!(
                                "api_specs.spec_content array contains non-byte value: {:?}",
                                other
                            );
                        }
                    };
                    bytes.push(byte);
                }
                bytes
            }
            Some(other) => {
                anyhow::bail!(
                    "api_specs.spec_content has unexpected BSON type: {:?}",
                    other
                );
            }
            None => anyhow::bail!("api_specs.spec_content missing"),
        };

        // Let serde populate the rest of the struct, then restore the bytes
        // from the BSON Binary above. This avoids materializing a huge BSON
        // integer array just to satisfy Vec<u8> deserialization.
        doc.insert("spec_content", Bson::Array(Vec::new()));
        let mut spec: ApiSpec = mongodb::bson::from_document(doc)?;
        spec.spec_content = spec_content;
        Ok(spec)
    }

    fn doc_to_api_spec_summary(mut doc: Document) -> Result<ApiSpec, anyhow::Error> {
        doc.insert(
            "spec_content",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: Vec::new(),
            }),
        );
        doc_to_api_spec(doc)
    }

    struct PreparedApiSpecBundleDocs {
        upstream: Option<(String, Document)>,
        plugins: Vec<(String, Document)>,
        proxy: (String, Document),
        spec: Document,
    }

    fn prepare_api_spec_bundle_docs(
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<PreparedApiSpecBundleDocs, anyhow::Error> {
        let upstream = bundle
            .upstream
            .as_ref()
            .map(|u| {
                let mut doc = upstream_to_doc(u)?;
                doc.insert("api_spec_id", spec.id.as_str());
                Ok::<_, anyhow::Error>((u.id.clone(), doc))
            })
            .transpose()?;

        let mut plugins = Vec::with_capacity(bundle.plugins.len());
        for pc in &bundle.plugins {
            let mut doc = plugin_config_to_doc(pc)?;
            doc.insert("api_spec_id", spec.id.as_str());
            plugins.push((pc.id.clone(), doc));
        }

        let mut proxy_doc = proxy_to_doc(&bundle.proxy)?;
        proxy_doc.insert("api_spec_id", spec.id.as_str());
        let spec_doc = api_spec_to_doc(spec)?;

        Ok(PreparedApiSpecBundleDocs {
            upstream,
            plugins,
            proxy: (bundle.proxy.id.clone(), proxy_doc),
            spec: spec_doc,
        })
    }

    // -----------------------------------------------------------------------
    // DatabaseBackend trait implementation
    // -----------------------------------------------------------------------

    #[async_trait]
    impl DatabaseBackend for MongoStore {
        async fn health_check(&self) -> Result<(), anyhow::Error> {
            self.db().run_command(doc! { "ping": 1 }).await?;
            Ok(())
        }

        fn db_type(&self) -> &str {
            // Strip the "+rs" suffix (used internally to detect replica-set capability)
            // so the admin API always sees "mongodb" as the db_type.
            if self.db_type_str.starts_with("mongodb") {
                "mongodb"
            } else {
                &self.db_type_str
            }
        }

        fn has_read_replica(&self) -> bool {
            // MongoDB driver handles read preference internally via connection string
            false
        }

        fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>) {
            self.slow_query_threshold_ms = threshold_ms;
        }

        fn set_full_load_page_size(&mut self, _page_size: u64) {
            // No-op: MongoDB uses cursor-based loading, not SQL pagination.
        }

        fn set_cert_expiry_warning_days(&mut self, days: u64) {
            self.cert_expiry_warning_days = days;
        }

        fn set_backend_allow_ips(&mut self, policy: crate::config::BackendAllowIps) {
            self.backend_allow_ips = policy;
        }

        async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
            let start = std::time::Instant::now();
            let loaded_at = Utc::now();
            let ns_filter = doc! { "namespace": namespace };

            // Load all collections scoped to namespace.
            // api_spec_id is admin-only metadata; the gateway runtime must never see it.
            // Strip it to None on every resource the runtime will use, mirroring
            // the SQL path's explicit `api_spec_id: None` in row_to_proxy / row_to_upstream
            // / row_to_plugin_config. Do NOT strip on write paths or admin-read paths.
            let mut proxies = Vec::new();
            let mut cursor = self.proxies().find(ns_filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut p = doc_to_proxy(doc)?;
                p.api_spec_id = None;
                proxies.push(p);
            }

            let mut consumers = Vec::new();
            let mut cursor = self.consumers().find(ns_filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                consumers.push(doc_to_consumer(doc)?);
            }

            let mut plugin_configs = Vec::new();
            let mut cursor = self.plugin_configs().find(ns_filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut pc = doc_to_plugin_config(doc)?;
                pc.api_spec_id = None;
                plugin_configs.push(pc);
            }

            let mut upstreams = Vec::new();
            let mut cursor = self.upstreams().find(ns_filter).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut u = doc_to_upstream(doc)?;
                u.api_spec_id = None;
                upstreams.push(u);
            }

            self.check_slow_query("load_full_config", start);

            info!(
                "MongoDB loaded config (namespace='{}'): {} proxies, {} consumers, {} plugins, {} upstreams",
                namespace,
                proxies.len(),
                consumers.len(),
                plugin_configs.len(),
                upstreams.len()
            );

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
            config.resolve_upstream_tls();

            // Defense in depth — Mongo `load_full_config` does not run the
            // SQL-side `ValidationPipeline`, so a row written directly into
            // the proxy collection with an encoded-slash listen_path would
            // otherwise reach `ProxyState::validate_full_config()` as the
            // only guard. Reject here as well so a Mongo-backed CP broadcast
            // can never carry the bypass shape downstream.
            if let Err(errors) = config.validate_listen_path_encodings() {
                for msg in &errors {
                    error!("MongoDB config rejected — {}", msg);
                }
                anyhow::bail!("MongoDB has listen_path(s) containing encoded slashes");
            }

            Ok(config)
        }

        async fn load_gateway_trust_bundles(
            &self,
            _namespace: &str,
        ) -> Result<GatewayTrustBundlePoll, anyhow::Error> {
            // Mongo backends currently persist gateway resources as separate
            // collections and do not store top-level GatewayConfig trust
            // bundles. Preserve whatever trust material the initial config load
            // supplied instead of clearing it on the first empty poll.
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
            let start = std::time::Instant::now();
            let poll_timestamp = Utc::now();

            // Safety margin: 1 second before `since` to avoid missing boundary writes.
            // Resource `updated_at` values are stored as variable-precision
            // RFC 3339 strings (chrono `AutoSi`), so use a whole-second-floor
            // lower bound that orders correctly against every fractional width.
            // See `mongo_updated_at_lower_bound`.
            //
            // Unlike `list_api_specs`, the poll path *wants* the floored bound's
            // over-inclusion: re-emitting an already-known row is idempotent and
            // the explicit 1s margin above already over-includes by design, so
            // no exact `>= since` post-filter is applied here.
            let since_with_margin = since - chrono::Duration::seconds(1);
            let since_str = mongo_updated_at_lower_bound(since_with_margin);
            let filter = doc! { "namespace": namespace, "updated_at": { "$gte": &since_str } };

            // Load changed resources.
            // Strip api_spec_id on every resource for the same reason as load_full_config:
            // api_spec_id is admin-only metadata and must not reach the gateway runtime.
            let mut added_or_modified_proxies = Vec::new();
            let mut cursor = self.proxies().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut p = doc_to_proxy(doc)?;
                p.api_spec_id = None;
                added_or_modified_proxies.push(p);
            }

            let mut added_or_modified_consumers = Vec::new();
            let mut cursor = self.consumers().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                added_or_modified_consumers.push(doc_to_consumer(doc)?);
            }

            let mut added_or_modified_plugin_configs = Vec::new();
            let mut cursor = self.plugin_configs().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut pc = doc_to_plugin_config(doc)?;
                pc.api_spec_id = None;
                added_or_modified_plugin_configs.push(pc);
            }

            let mut added_or_modified_upstreams = Vec::new();
            let mut cursor = self.upstreams().find(filter).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let mut u = doc_to_upstream(doc)?;
                u.api_spec_id = None;
                added_or_modified_upstreams.push(u);
            }

            // Detect deletions by loading current IDs (scoped to namespace) and diffing against known sets
            let ns_filter = doc! { "namespace": namespace };
            let current_proxy_ids = self
                .load_collection_ids_filtered("proxies", ns_filter.clone())
                .await?;
            let current_consumer_ids = self
                .load_collection_ids_filtered("consumers", ns_filter.clone())
                .await?;
            let current_plugin_config_ids = self
                .load_collection_ids_filtered("plugin_configs", ns_filter.clone())
                .await?;
            let current_upstream_ids = self
                .load_collection_ids_filtered("upstreams", ns_filter)
                .await?;

            let removed_proxy_ids = diff_removed(known_proxy_ids, &current_proxy_ids);
            let removed_consumer_ids = diff_removed(known_consumer_ids, &current_consumer_ids);
            let removed_plugin_config_ids =
                diff_removed(known_plugin_config_ids, &current_plugin_config_ids);
            let removed_upstream_ids = diff_removed(known_upstream_ids, &current_upstream_ids);

            self.check_slow_query("load_incremental_config", start);

            Ok(IncrementalResult {
                added_or_modified_proxies,
                removed_proxy_ids,
                added_or_modified_consumers,
                removed_consumer_ids,
                added_or_modified_plugin_configs,
                removed_plugin_config_ids,
                added_or_modified_upstreams,
                removed_upstream_ids,
                poll_timestamp,
            })
        }

        // -------------------------------------------------------------------
        // Proxy CRUD
        // -------------------------------------------------------------------

        async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let doc = proxy_to_doc(proxy)?;
            self.proxies().insert_one(doc).await?;
            self.check_slow_query("create_proxy", start);
            Ok(())
        }

        async fn update_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            // Preserve api_spec_id: the incoming Proxy from the admin CRUD
            // endpoint has api_spec_id: None (stripped in normalize()), but
            // the stored document may carry an ownership tag from a spec
            // import.  SQL is safe because its UPDATE excludes api_spec_id.
            //
            // The api_specs collection is the source of truth for ownership.
            // Inject that tag into the replacement document before writing so
            // the method cannot succeed with an untagged spec-owned proxy.
            let mut doc = proxy_to_doc(proxy)?;

            if self.replica_set_configured.load(Ordering::Acquire) {
                let mut session = self.client.load().start_session().await?;
                session
                    .start_transaction()
                    .and_run((self, &proxy.id, doc), |s, (this, id, doc)| {
                        Box::pin(async move {
                            let mut doc = doc.clone();
                            if let Some(spec_doc) = this
                                .api_specs()
                                .find_one(mongodb::bson::doc! { "proxy_id": *id })
                                .session(&mut *s)
                                .await?
                            {
                                let sid = spec_doc.get_str("_id").map_err(|e| {
                                    mongodb::error::Error::custom(format!(
                                        "api_spec for proxy {} is missing _id: {}",
                                        *id, e
                                    ))
                                })?;
                                doc.insert("api_spec_id", sid);
                            }
                            this.proxies()
                                .replace_one(mongodb::bson::doc! { "_id": *id }, doc)
                                .session(&mut *s)
                                .await?;
                            this.cleanup_orphaned_proxy_group_plugins_opt_session(Some(s))
                                .await
                                .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                            Ok(())
                        })
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("update_proxy transaction failed: {}", e))?;
            } else {
                if let Some(spec_doc) = self
                    .api_specs()
                    .find_one(doc! { "proxy_id": &proxy.id })
                    .await?
                {
                    let sid = spec_doc.get_str("_id").map_err(|e| {
                        anyhow::anyhow!("api_spec for proxy {} is missing _id: {}", proxy.id, e)
                    })?;
                    doc.insert("api_spec_id", sid);
                }
                self.proxies()
                    .replace_one(doc! { "_id": &proxy.id }, doc)
                    .await?;
                self.cleanup_orphaned_proxy_group_plugins().await?;
            }

            self.check_slow_query("update_proxy", start);
            Ok(())
        }

        async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();

            if self.replica_set_configured.load(Ordering::Acquire) {
                let mut session = self.client.load().start_session().await?;
                let deleted = session
                    .start_transaction()
                    .and_run((self, id.to_string()), |s, (this, id)| {
                        Box::pin(async move {
                            // Capture upstream_id before deleting the proxy.
                            let proxy_doc = this
                                .proxies()
                                .find_one(mongodb::bson::doc! { "_id": id.as_str() })
                                .session(&mut *s)
                                .await?;
                            let upstream_id_to_check: Option<String> =
                                proxy_doc.as_ref().and_then(|doc| {
                                    doc.get_str("upstream_id").ok().map(str::to_string)
                                });
                            if proxy_doc.is_none() {
                                return Ok(false);
                            }

                            let spec_owner: Option<(String, String)> = this
                                .api_specs()
                                .find_one(mongodb::bson::doc! { "proxy_id": id.as_str() })
                                .session(&mut *s)
                                .await?
                                .map(|doc| {
                                    let sid =
                                        doc.get_str("_id").map(str::to_string).map_err(|e| {
                                            mongodb::error::Error::custom(format!(
                                                "api_spec for proxy {} is missing _id: {}",
                                                id, e
                                            ))
                                        })?;
                                    let namespace = doc
                                        .get_str("namespace")
                                        .map(str::to_string)
                                        .unwrap_or_else(|_| {
                                            crate::config::types::default_namespace()
                                        });
                                    Ok::<_, mongodb::error::Error>((sid, namespace))
                                })
                                .transpose()?;
                            if let Some((ref sid, ref namespace)) = spec_owner {
                                this.ensure_no_external_spec_upstream_refs_opt_session(
                                    Some(&mut *s),
                                    namespace,
                                    sid,
                                    id,
                                )
                                .await
                                .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                            }

                            this.plugin_configs()
                                .delete_many(mongodb::bson::doc! { "proxy_id": id.as_str() })
                                .session(&mut *s)
                                .await?;
                            let result = this
                                .proxies()
                                .delete_one(mongodb::bson::doc! { "_id": id.as_str() })
                                .session(&mut *s)
                                .await?;

                            if result.deleted_count > 0 {
                                // Cascade api_specs + spec-owned upstreams.
                                if let Some((ref sid, ref namespace)) = spec_owner {
                                    this.api_specs()
                                        .delete_one(mongodb::bson::doc! {
                                            "_id": sid.as_str(),
                                            "namespace": namespace.as_str(),
                                        })
                                        .session(&mut *s)
                                        .await?;
                                    this.upstreams()
                                        .delete_many(mongodb::bson::doc! {
                                            "api_spec_id": sid.as_str(),
                                            "namespace": namespace.as_str(),
                                        })
                                        .session(&mut *s)
                                        .await?;
                                }
                                // Cascade-delete orphaned upstream.
                                if let Some(ref uid) = upstream_id_to_check {
                                    let still_referenced = this
                                        .proxies()
                                        .count_documents(
                                            mongodb::bson::doc! { "upstream_id": uid.as_str() },
                                        )
                                        .session(&mut *s)
                                        .await?
                                        > 0;
                                    let dispatch_ref = if !still_referenced {
                                        this.find_mesh_route_dispatch_upstream_ref_opt_session(
                                            Some(&mut *s),
                                            uid,
                                        )
                                        .await
                                        .map_err(|e| mongodb::error::Error::custom(e.to_string()))?
                                    } else {
                                        None
                                    };
                                    if !still_referenced && dispatch_ref.is_none() {
                                        let _ = this
                                            .upstreams()
                                            .delete_one(mongodb::bson::doc! { "_id": uid.as_str() })
                                            .session(&mut *s)
                                            .await;
                                    }
                                }
                            }

                            this.cleanup_orphaned_proxy_group_plugins_opt_session(Some(s))
                                .await
                                .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                            Ok(result.deleted_count > 0)
                        })
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("delete_proxy transaction failed: {}", e))?;
                self.check_slow_query("delete_proxy", start);
                return Ok(deleted);
            }

            // Non-replica-set best-effort path.
            let proxy_doc = self.proxies().find_one(doc! { "_id": id }).await?;
            let upstream_id_to_check: Option<String> = proxy_doc
                .as_ref()
                .and_then(|doc| doc.get_str("upstream_id").ok().map(str::to_string));
            if proxy_doc.is_none() {
                self.check_slow_query("delete_proxy", start);
                return Ok(false);
            }
            let spec_owner: Option<(String, String)> =
                match self.api_specs().find_one(doc! { "proxy_id": id }).await? {
                    Some(doc) => {
                        let sid = doc.get_str("_id").map(str::to_string).map_err(|e| {
                            anyhow::anyhow!("api_spec for proxy {} is missing _id: {}", id, e)
                        })?;
                        let namespace = doc
                            .get_str("namespace")
                            .map(str::to_string)
                            .unwrap_or_else(|_| crate::config::types::default_namespace());
                        Some((sid, namespace))
                    }
                    None => None,
                };
            if let Some((ref sid, ref namespace)) = spec_owner {
                self.ensure_no_external_spec_upstream_refs(namespace, sid, id)
                    .await?;
            }

            let result = self.proxies().delete_one(doc! { "_id": id }).await?;
            if result.deleted_count > 0 {
                self.plugin_configs()
                    .delete_many(doc! { "proxy_id": id })
                    .await?;
                let _ = self.api_specs().delete_one(doc! { "proxy_id": id }).await;
                if let Some((ref sid, ref namespace)) = spec_owner {
                    let _ = self
                        .upstreams()
                        .delete_many(doc! { "api_spec_id": sid, "namespace": namespace })
                        .await;
                }
                if let Some(ref uid) = upstream_id_to_check {
                    let still_referenced = self
                        .proxies()
                        .count_documents(doc! { "upstream_id": uid })
                        .await?
                        > 0;
                    let dispatch_ref = if !still_referenced {
                        self.find_mesh_route_dispatch_upstream_ref_opt_session(None, uid)
                            .await?
                    } else {
                        None
                    };
                    if !still_referenced && dispatch_ref.is_none() {
                        info!("Cascade-deleting orphaned upstream {}", uid);
                        let _ = self.upstreams().delete_one(doc! { "_id": uid }).await;
                    }
                }
            }
            self.cleanup_orphaned_proxy_group_plugins().await?;
            self.check_slow_query("delete_proxy", start);
            Ok(result.deleted_count > 0)
        }

        async fn get_proxy(&self, id: &str) -> Result<Option<Proxy>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self.proxies().find_one(doc! { "_id": id }).await?;
            self.check_slow_query("get_proxy", start);
            match result {
                Some(doc) => Ok(Some(doc_to_proxy(doc)?)),
                None => Ok(None),
            }
        }

        async fn check_proxy_exists(
            &self,
            proxy_id: &str,
            namespace: &str,
        ) -> Result<bool, anyhow::Error> {
            // Namespace filter is mandatory: a proxy_id that exists in another
            // namespace must NOT satisfy the reference check, otherwise admin
            // would admit a config that fails to resolve at runtime.
            let count = self
                .proxies()
                .count_documents(doc! { "_id": proxy_id, "namespace": namespace })
                .await?;
            Ok(count > 0)
        }

        async fn list_proxies_paginated(
            &self,
            namespace: &str,
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
            let start = std::time::Instant::now();
            let ns_filter = doc! { "namespace": namespace };
            let total = self.proxies().count_documents(ns_filter.clone()).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self.proxies().find(ns_filter).with_options(options).await?;
            let mut items = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                items.push(doc_to_proxy(doc)?);
            }
            self.check_slow_query("list_proxies_paginated", start);
            Ok(PaginatedResult { items, total })
        }

        // -------------------------------------------------------------------
        // Consumer CRUD
        // -------------------------------------------------------------------

        async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let doc = consumer_to_doc(consumer)?;
            self.consumers().insert_one(doc).await?;
            self.check_slow_query("create_consumer", start);
            Ok(())
        }

        async fn update_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let doc = consumer_to_doc(consumer)?;
            self.consumers()
                .replace_one(doc! { "_id": &consumer.id }, doc)
                .await?;
            self.check_slow_query("update_consumer", start);
            Ok(())
        }

        async fn delete_consumer(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self.consumers().delete_one(doc! { "_id": id }).await?;
            self.check_slow_query("delete_consumer", start);
            Ok(result.deleted_count > 0)
        }

        async fn get_consumer(&self, id: &str) -> Result<Option<Consumer>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self.consumers().find_one(doc! { "_id": id }).await?;
            self.check_slow_query("get_consumer", start);
            match result {
                Some(doc) => Ok(Some(doc_to_consumer(doc)?)),
                None => Ok(None),
            }
        }

        async fn list_consumers_paginated(
            &self,
            namespace: &str,
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
            let start = std::time::Instant::now();
            let ns_filter = doc! { "namespace": namespace };
            let total = self.consumers().count_documents(ns_filter.clone()).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self
                .consumers()
                .find(ns_filter)
                .with_options(options)
                .await?;
            let mut items = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                items.push(doc_to_consumer(doc)?);
            }
            self.check_slow_query("list_consumers_paginated", start);
            Ok(PaginatedResult { items, total })
        }

        // -------------------------------------------------------------------
        // Plugin config CRUD
        // -------------------------------------------------------------------

        async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let doc = plugin_config_to_doc(pc)?;
            self.plugin_configs().insert_one(doc).await?;
            self.check_slow_query("create_plugin_config", start);
            Ok(())
        }

        async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            // Preserve api_spec_id by carrying it into the replacement document.
            // Returning an error is safer than silently detaching spec ownership.
            let mut doc = plugin_config_to_doc(pc)?;
            let existing_doc = self
                .plugin_configs()
                .find_one(doc! { "_id": &pc.id })
                .await?;
            let existing_spec_id = match existing_doc.as_ref().and_then(|d| d.get("api_spec_id")) {
                Some(Bson::String(s)) if !s.is_empty() => Some(s.clone()),
                Some(Bson::Null) | None => None,
                Some(other) => {
                    anyhow::bail!(
                        "plugin_config {} has non-string api_spec_id ownership tag: {:?}",
                        pc.id,
                        other
                    );
                }
            };
            if let Some(sid) = existing_spec_id {
                doc.insert("api_spec_id", sid);
            }
            self.plugin_configs()
                .replace_one(doc! { "_id": &pc.id }, doc)
                .await?;
            self.check_slow_query("update_plugin_config", start);
            Ok(())
        }

        async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            self.proxies()
                .update_many(
                    doc! { "plugins.plugin_config_id": id },
                    doc! {
                        "$pull": { "plugins": { "plugin_config_id": id } },
                        "$set": { "updated_at": Utc::now().to_rfc3339() },
                    },
                )
                .await?;
            let result = self.plugin_configs().delete_one(doc! { "_id": id }).await?;
            self.check_slow_query("delete_plugin_config", start);
            Ok(result.deleted_count > 0)
        }

        async fn get_plugin_config(&self, id: &str) -> Result<Option<PluginConfig>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self.plugin_configs().find_one(doc! { "_id": id }).await?;
            self.check_slow_query("get_plugin_config", start);
            match result {
                Some(doc) => Ok(Some(doc_to_plugin_config(doc)?)),
                None => Ok(None),
            }
        }

        async fn list_plugin_configs_paginated(
            &self,
            namespace: &str,
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
            let start = std::time::Instant::now();
            let ns_filter = doc! { "namespace": namespace };
            let total = self
                .plugin_configs()
                .count_documents(ns_filter.clone())
                .await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self
                .plugin_configs()
                .find(ns_filter)
                .with_options(options)
                .await?;
            let mut items = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                items.push(doc_to_plugin_config(doc)?);
            }
            self.check_slow_query("list_plugin_configs_paginated", start);
            Ok(PaginatedResult { items, total })
        }

        // -------------------------------------------------------------------
        // Upstream CRUD
        // -------------------------------------------------------------------

        async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let doc = upstream_to_doc(upstream)?;
            self.upstreams().insert_one(doc).await?;
            self.check_slow_query("create_upstream", start);
            Ok(())
        }

        async fn update_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            // Preserve api_spec_id by carrying it into the replacement document.
            // Returning an error is safer than silently detaching spec ownership.
            let mut doc = upstream_to_doc(upstream)?;
            let existing_doc = self
                .upstreams()
                .find_one(doc! { "_id": &upstream.id })
                .await?;
            let existing_spec_id = match existing_doc.as_ref().and_then(|d| d.get("api_spec_id")) {
                Some(Bson::String(s)) if !s.is_empty() => Some(s.clone()),
                Some(Bson::Null) | None => None,
                Some(other) => {
                    anyhow::bail!(
                        "upstream {} has non-string api_spec_id ownership tag: {:?}",
                        upstream.id,
                        other
                    );
                }
            };
            if let Some(sid) = existing_spec_id {
                doc.insert("api_spec_id", sid);
            }
            self.upstreams()
                .replace_one(doc! { "_id": &upstream.id }, doc)
                .await?;
            self.check_slow_query("update_upstream", start);
            Ok(())
        }

        async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let proxy_refs = self
                .proxies()
                .count_documents(doc! { "upstream_id": id })
                .await?;
            if proxy_refs > 0 {
                anyhow::bail!(
                    "Upstream {} is referenced by one or more proxies and cannot be deleted",
                    id
                );
            }
            if let Some(plugin) = self
                .find_mesh_route_dispatch_upstream_ref_opt_session(None, id)
                .await?
            {
                anyhow::bail!(
                    "Upstream {} is referenced by mesh_route_dispatch plugin_config '{}' and cannot be deleted",
                    id,
                    plugin.id
                );
            }
            let result = self.upstreams().delete_one(doc! { "_id": id }).await?;
            self.check_slow_query("delete_upstream", start);
            Ok(result.deleted_count > 0)
        }

        async fn get_upstream(&self, id: &str) -> Result<Option<Upstream>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self.upstreams().find_one(doc! { "_id": id }).await?;
            self.check_slow_query("get_upstream", start);
            match result {
                Some(doc) => Ok(Some(doc_to_upstream(doc)?)),
                None => Ok(None),
            }
        }

        async fn cleanup_orphaned_upstream(&self, upstream_id: &str) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            // Check if any proxy still references this upstream
            let count = self
                .proxies()
                .count_documents(doc! { "upstream_id": upstream_id })
                .await?;
            let dispatch_ref = if count == 0 {
                self.find_mesh_route_dispatch_upstream_ref_opt_session(None, upstream_id)
                    .await?
            } else {
                None
            };
            if count == 0 && dispatch_ref.is_none() {
                self.upstreams()
                    .delete_one(doc! { "_id": upstream_id })
                    .await?;
                debug!("Cleaned up orphaned upstream: {}", upstream_id);
            }
            self.check_slow_query("cleanup_orphaned_upstream", start);
            Ok(())
        }

        async fn list_upstreams_paginated(
            &self,
            namespace: &str,
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
            let start = std::time::Instant::now();
            let ns_filter = doc! { "namespace": namespace };
            let total = self.upstreams().count_documents(ns_filter.clone()).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self
                .upstreams()
                .find(ns_filter)
                .with_options(options)
                .await?;
            let mut items = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                items.push(doc_to_upstream(doc)?);
            }
            self.check_slow_query("list_upstreams_paginated", start);
            Ok(PaginatedResult { items, total })
        }

        // -------------------------------------------------------------------
        // Validation queries
        // -------------------------------------------------------------------

        async fn check_listen_path_unique(
            &self,
            namespace: &str,
            listen_path: Option<&str>,
            hosts: &[String],
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            // Defensive: `None` listen_path + empty hosts is rejected by
            // validate_fields_inner. Guard so the DB layer never admits
            // a "match everything" proxy if a caller slips past validation.
            if listen_path.is_none() && hosts.is_empty() {
                return Ok(false);
            }

            // Filter on namespace + listen_path bucket (same path for path
            // proxies, `null` for host-only proxies). Mongo's equality-to-null
            // matches both a missing field and a literal null. Do NOT try to
            // match hosts server-side with `$in` — that catches exact-string
            // overlaps only and misses wildcard-to-exact or wildcard-to-wildcard
            // overlaps that `hosts_overlap` must recognize. Fetch candidates
            // and run the full overlap check in Rust (typically ≤ a handful
            // of rows per bucket).
            //
            // Exclude stream proxies (tcp/tcp_tls/udp/dtls) from the query —
            // they also serialize `listen_path` as null, and they commonly
            // have empty `hosts` (which `hosts_overlap` treats as catch-all).
            // Without this exclusion, a host-only HTTP create/update can be
            // falsely rejected whenever any stream proxy exists in the
            // namespace. Stream proxies have their own uniqueness check
            // (`check_listen_port_unique`). Matches the sqlx impl.
            let mut filter = match listen_path {
                Some(path) => doc! { "namespace": namespace, "listen_path": path },
                None => doc! { "namespace": namespace, "listen_path": null },
            };
            filter.insert(
                "backend_scheme",
                doc! { "$nin": ["tcp", "tcps", "udp", "dtls"] },
            );
            if let Some(id) = exclude_proxy_id {
                filter.insert("_id", doc! { "$ne": id });
            }

            // `Some(path) + empty hosts` is a catch-all for the path — any
            // existing proxy in this bucket conflicts regardless of hosts.
            if listen_path.is_some() && hosts.is_empty() {
                let count = self.proxies().count_documents(filter).await?;
                return Ok(count == 0);
            }

            // Otherwise iterate candidates and check host overlap in Rust so
            // wildcard semantics (e.g. `*.example.com` overlapping with
            // `api.example.com`) are detected correctly.
            let mut cursor = self
                .proxies()
                .find(filter)
                .projection(doc! { "_id": 1, "hosts": 1 })
                .await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let existing_hosts: Vec<String> = doc
                    .get_array("hosts")
                    .ok()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                if crate::config::types::hosts_overlap(hosts, &existing_hosts) {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        async fn check_proxy_name_unique(
            &self,
            namespace: &str,
            name: &str,
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "namespace": namespace, "name": name };
            if let Some(id) = exclude_proxy_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.proxies().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_upstream_name_unique(
            &self,
            namespace: &str,
            name: &str,
            exclude_upstream_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "namespace": namespace, "name": name };
            if let Some(id) = exclude_upstream_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.upstreams().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_consumer_identity_unique(
            &self,
            namespace: &str,
            consumer_id: &str,
            username: &str,
            custom_id: Option<&str>,
            exclude_consumer_id: Option<&str>,
        ) -> Result<Option<String>, anyhow::Error> {
            let mut candidates = vec![
                Bson::String(consumer_id.to_string()),
                Bson::String(username.to_string()),
            ];
            if let Some(custom_id) = custom_id {
                candidates.push(Bson::String(custom_id.to_string()));
            }
            let mut filter = doc! {
                "namespace": namespace,
                "$or": [
                    { "_id": { "$in": candidates.clone() } },
                    { "username": { "$in": candidates.clone() } },
                    { "custom_id": { "$in": candidates } },
                ],
            };
            if let Some(id) = exclude_consumer_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let result = self.consumers().find_one(filter).await?;
            match result {
                Some(doc) => {
                    let conflict_id = doc.get_str("_id").unwrap_or("unknown").to_string();
                    Ok(Some(conflict_id))
                }
                None => Ok(None),
            }
        }

        async fn check_keyauth_key_unique(
            &self,
            namespace: &str,
            key: &str,
            exclude_consumer_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! {
                "namespace": namespace,
                "credentials.keyauth": { "$elemMatch": { "key": key } }
            };
            if let Some(id) = exclude_consumer_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.consumers().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_mtls_identity_unique(
            &self,
            namespace: &str,
            identity: &str,
            exclude_consumer_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! {
                "namespace": namespace,
                "credentials.mtls_auth": { "$elemMatch": { "identity": identity } }
            };
            if let Some(id) = exclude_consumer_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.consumers().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_listen_port_unique(
            &self,
            namespace: &str,
            port: u16,
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "namespace": namespace, "listen_port": port as i32 };
            if let Some(id) = exclude_proxy_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.proxies().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_upstream_exists(
            &self,
            upstream_id: &str,
            namespace: &str,
        ) -> Result<bool, anyhow::Error> {
            // Namespace filter is mandatory: see [`check_proxy_exists`].
            let count = self
                .upstreams()
                .count_documents(doc! { "_id": upstream_id, "namespace": namespace })
                .await?;
            Ok(count > 0)
        }

        async fn validate_proxy_plugin_associations(
            &self,
            _proxy_id: &str,
            namespace: &str,
            plugins: &[PluginAssociation],
        ) -> Result<Vec<String>, anyhow::Error> {
            // Plugin configs in a different namespace must surface as missing
            // so admin validation cannot let a proxy bind to a plugin_config
            // that lives outside its namespace.
            let mut missing = Vec::new();
            for assoc in plugins {
                let count = self
                    .plugin_configs()
                    .count_documents(doc! {
                        "_id": &assoc.plugin_config_id,
                        "namespace": namespace,
                    })
                    .await?;
                if count == 0 {
                    missing.push(assoc.plugin_config_id.clone());
                }
            }
            Ok(missing)
        }

        // -------------------------------------------------------------------
        // Batch operations
        // -------------------------------------------------------------------

        async fn batch_create_proxies(&self, proxies: &[Proxy]) -> Result<usize, anyhow::Error> {
            if proxies.is_empty() {
                return Ok(0);
            }
            let docs: Vec<Document> = proxies.iter().map(proxy_to_doc).collect::<Result<_, _>>()?;
            let result = self.proxies().insert_many(docs).ordered(false).await?;
            Ok(result.inserted_ids.len())
        }

        async fn batch_create_proxies_without_plugins(
            &self,
            proxies: &[Proxy],
        ) -> Result<usize, anyhow::Error> {
            // In MongoDB, plugins are embedded in the proxy document, so this
            // is the same as batch_create_proxies. The distinction only matters
            // for the SQL backend where plugin associations are in a junction table.
            self.batch_create_proxies(proxies).await
        }

        async fn batch_attach_proxy_plugins(
            &self,
            _proxies: &[Proxy],
        ) -> Result<(), anyhow::Error> {
            // No-op for MongoDB — plugins are embedded in the proxy document.
            // The SQL backend uses this to populate the proxy_plugins junction table.
            Ok(())
        }

        async fn batch_create_consumers(
            &self,
            consumers: &[Consumer],
        ) -> Result<usize, anyhow::Error> {
            if consumers.is_empty() {
                return Ok(0);
            }
            let docs: Vec<Document> = consumers
                .iter()
                .map(consumer_to_doc)
                .collect::<Result<_, _>>()?;
            let result = self.consumers().insert_many(docs).ordered(false).await?;
            Ok(result.inserted_ids.len())
        }

        async fn batch_create_plugin_configs(
            &self,
            configs: &[PluginConfig],
        ) -> Result<usize, anyhow::Error> {
            if configs.is_empty() {
                return Ok(0);
            }
            let docs: Vec<Document> = configs
                .iter()
                .map(plugin_config_to_doc)
                .collect::<Result<_, _>>()?;
            let result = self
                .plugin_configs()
                .insert_many(docs)
                .ordered(false)
                .await?;
            Ok(result.inserted_ids.len())
        }

        async fn batch_create_upstreams(
            &self,
            upstreams: &[Upstream],
        ) -> Result<usize, anyhow::Error> {
            if upstreams.is_empty() {
                return Ok(0);
            }
            let docs: Vec<Document> = upstreams
                .iter()
                .map(upstream_to_doc)
                .collect::<Result<_, _>>()?;
            let result = self.upstreams().insert_many(docs).ordered(false).await?;
            Ok(result.inserted_ids.len())
        }

        async fn delete_all_resources(&self, namespace: &str) -> Result<(), anyhow::Error> {
            let ns_filter = doc! { "namespace": namespace };
            self.plugin_configs().delete_many(ns_filter.clone()).await?;
            self.proxies().delete_many(ns_filter.clone()).await?;
            self.consumers().delete_many(ns_filter.clone()).await?;
            self.upstreams().delete_many(ns_filter.clone()).await?;
            // Clear api_specs so restore doesn't leave orphaned spec metadata
            // pointing to proxies that no longer exist.
            self.api_specs().delete_many(ns_filter).await?;
            info!("All MongoDB resources deleted (namespace='{}')", namespace);
            Ok(())
        }

        // -------------------------------------------------------------------
        // Connection lifecycle
        // -------------------------------------------------------------------

        async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
            // Build a fresh Client + Database against the requested URL using
            // the captured connection settings. `build_client_and_db` runs a
            // ping before returning, so on `Ok` we know the new client can
            // actually talk to MongoDB. On `Err` the swap is skipped and the
            // existing (possibly degraded) client stays in place — same
            // contract as `DatabaseStore::reconnect` for sqlx.
            let (new_client, new_db, replica_set_configured) = Self::build_client_and_db(
                db_url,
                &self.conn_settings,
                self.conn_settings.tls_enabled,
                self.conn_settings.tls_ca_cert_path.as_deref(),
                self.conn_settings.tls_client_cert_path.as_deref(),
                self.conn_settings.tls_client_key_path.as_deref(),
                self.conn_settings.tls_insecure,
            )
            .await?;

            // Atomic swap. Readers that already loaded the old `Database`
            // handle keep using it (in-flight commands complete); the next
            // call to `db()` picks up the new handle. Old client is held
            // briefly here, then dropped — the driver closes idle
            // connections in the background.
            let _old_db = self.db.swap(Arc::new(new_db));
            let _old_client = self.client.swap(Arc::new(new_client));
            self.replica_set_configured
                .store(replica_set_configured, Ordering::Release);

            info!(
                "MongoDB client reconnected to {} (replica_set={})",
                crate::config::db_backend::redact_url(db_url),
                replica_set_configured
            );
            Ok(())
        }

        async fn reconnect_read_replica(&self, _replica_url: &str) -> Result<(), anyhow::Error> {
            // MongoDB uses one authoritative client and forces primary reads
            // for the config store. There is no separate admin-read replica
            // pool to reconnect.
            Ok(())
        }

        async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> {
            // Try primary first. `reconnect()` rebuilds the underlying
            // `Client` against the primary URL and pings it; on success
            // the swap is committed and the gateway is back on the
            // primary.
            if self.reconnect(primary_url).await.is_ok() {
                info!(
                    "Reconnected to primary MongoDB ({})",
                    crate::config::db_backend::redact_url(primary_url)
                );
                return Ok(primary_url.to_string());
            }

            // Try failover URLs in order. The first one that successfully
            // pings wins; subsequent URLs are not tried until the next
            // failover-reconnect cycle.
            for (i, url) in self.failover_urls.iter().enumerate() {
                if self.reconnect(url).await.is_ok() {
                    info!(
                        "Reconnected to failover MongoDB #{} ({})",
                        i + 1,
                        crate::config::db_backend::redact_url(url)
                    );
                    return Ok(url.clone());
                }
                warn!(
                    "Failover MongoDB #{} ({}) reconnect failed",
                    i + 1,
                    crate::config::db_backend::redact_url(url)
                );
            }

            Err(anyhow::anyhow!(
                "All MongoDB URLs failed during reconnect ({} failover URL(s) tried)",
                self.failover_urls.len()
            ))
        }

        async fn run_migrations(&self) -> Result<(), anyhow::Error> {
            // MongoDB doesn't use SQL migrations. Instead, ensure indexes exist.
            // createIndex is idempotent — no-op if the index already exists.

            // proxies indexes — uniqueness scoped to namespace
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "name": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "name": { "$type": "string" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            self.proxies()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "upstream_id": 1 })
                        .build(),
                )
                .await?;
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "plugins.plugin_config_id": 1 })
                        .build(),
                )
                .await?;
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "listen_port": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "listen_port": { "$type": "number" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            // Intentionally NO unique index on (namespace, listen_path). Path
            // uniqueness is host-scoped: two HTTP proxies may share a
            // listen_path if their `hosts` lists do not overlap. A plain
            // unique index would reject valid host-partitioned routes before
            // the host-overlap check in `check_listen_path_unique` runs.
            // Uniqueness is enforced at the application layer instead.
            //
            // No standalone {namespace} index: the {namespace, updated_at}
            // compound below covers namespace-only lookups via the
            // leading-column rule.
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Covering index for the incremental-poll deletion diff. Each poll
            // runs `find({ namespace }, { _id: 1 })` on these four collections
            // to detect deletions (see `load_collection_ids_filtered`). Unlike
            // InnoDB, MongoDB does not carry `_id` in secondary indexes, so the
            // `{namespace, updated_at}` index above would force a FETCH per
            // matched document just to read `_id`. A `{namespace, _id}` index
            // makes the query covered (IXSCAN only, no FETCH). Mirrors the SQL
            // `(namespace, id)` covering indexes in `sql_dialect.rs`.
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "_id": 1 })
                        .build(),
                )
                .await?;

            // consumers indexes — uniqueness scoped to namespace
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "username": 1 })
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "custom_id": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "custom_id": { "$type": "string" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "credentials.keyauth.key": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "credentials.keyauth.key": { "$type": "string" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "credentials.mtls_auth.identity": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "credentials.mtls_auth.identity": { "$type": "string" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            // No standalone {namespace} index — covered by {namespace, updated_at} below.
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Covering index for the deletion diff — see proxies above.
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "_id": 1 })
                        .build(),
                )
                .await?;

            // plugin_configs indexes
            self.plugin_configs()
                .create_index(IndexModel::builder().keys(doc! { "proxy_id": 1 }).build())
                .await?;
            self.plugin_configs()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            // No standalone {namespace} index — covered by {namespace, updated_at} below.
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Covering index for the deletion diff — see proxies above.
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "_id": 1 })
                        .build(),
                )
                .await?;
            // Compound indexes for common admin API query patterns (V003)
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "scope": 1 })
                        .build(),
                )
                .await?;
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "scope": 1, "_id": 1 })
                        .build(),
                )
                .await?;
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "plugin_name": 1 })
                        .build(),
                )
                .await?;
            // Cold-path index for cross-namespace mesh_route_dispatch lookups in
            // `find_mesh_route_dispatch_upstream_ref_opt_session` and
            // `ensure_no_external_spec_upstream_refs_opt_session`. Both query
            // `{plugin_name: "mesh_route_dispatch", enabled: true}` across all
            // namespaces (upstream IDs are globally unique, so a cross-namespace
            // reference is real and must be caught). The partial filter halves
            // index size and write amplification in deployments with many
            // disabled plugin_configs.
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "plugin_name": 1, "enabled": 1 })
                        .options(
                            IndexOptions::builder()
                                .partial_filter_expression(doc! { "enabled": true })
                                .build(),
                        )
                        .build(),
                )
                .await?;

            // Sparse index on api_spec_id for cascade queries (delete/replace by
            // spec ownership).  Most plugin_configs have api_spec_id: null, so
            // sparse avoids indexing the majority of documents.
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "api_spec_id": 1 })
                        .options(IndexOptions::builder().sparse(true).build())
                        .build(),
                )
                .await?;

            // upstreams indexes — uniqueness scoped to namespace
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "name": 1 })
                        .options(
                            IndexOptions::builder()
                                .unique(true)
                                .partial_filter_expression(doc! {
                                    "name": { "$type": "string" }
                                })
                                .build(),
                        )
                        .build(),
                )
                .await?;
            self.upstreams()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            // No standalone {namespace} index — covered by {namespace, updated_at} below.
            // Sparse index on api_spec_id — mirrors plugin_configs above.
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "api_spec_id": 1 })
                        .options(IndexOptions::builder().sparse(true).build())
                        .build(),
                )
                .await?;
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Covering index for the deletion diff — see proxies above.
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "_id": 1 })
                        .build(),
                )
                .await?;

            // api_specs indexes (admin-only; runtime never reads this collection).
            // Unique (namespace, proxy_id) mirrors the SQL unique index and prevents
            // a second spec from claiming ownership of an already-spec-owned proxy.
            // Partial filter mirrors the sparse-unique pattern used for
            // (namespace, name), (namespace, custom_id), and (namespace, listen_port)
            // elsewhere — guards against the null-collision case if a future doc
            // is ever inserted without a proxy_id. SQL is safe via NOT NULL.
            //
            // Upgrade path: the previous V001 baseline created the same-keyed
            // index with `unique(true)` only. MongoDB raises
            // IndexOptionsConflict (code 85) when keys match but options
            // differ, so a plain `create_index` fails on upgrade. Drop the
            // legacy index on conflict and recreate — fresh DBs skip the
            // branch, upgraded DBs take it exactly once. IndexNotFound on
            // drop and IndexAlreadyExists on recreate are both tolerated to
            // make the path safe under concurrent multi-instance startup.
            let api_specs_unique = IndexModel::builder()
                .keys(doc! { "namespace": 1, "proxy_id": 1 })
                .options(
                    IndexOptions::builder()
                        .unique(true)
                        .partial_filter_expression(doc! {
                            "proxy_id": { "$type": "string" }
                        })
                        .build(),
                )
                .build();
            match self
                .api_specs()
                .create_index(api_specs_unique.clone())
                .await
            {
                Ok(_) => {}
                Err(e) if is_index_options_conflict(&e) => {
                    warn!(
                        "MongoDB api_specs (namespace, proxy_id) unique index exists \
                         without partialFilterExpression. Dropping the legacy index and \
                         recreating with the new options — one-time upgrade step."
                    );
                    match self.api_specs().drop_index("namespace_1_proxy_id_1").await {
                        Ok(_) => {}
                        Err(drop_err) if is_index_not_found(&drop_err) => {}
                        Err(drop_err) => {
                            return Err(anyhow::anyhow!(
                                "Failed to drop legacy api_specs (namespace, proxy_id) index \
                                 during upgrade: {drop_err}. Run \
                                 `db.api_specs.dropIndex(\"namespace_1_proxy_id_1\")` \
                                 manually and restart."
                            ));
                        }
                    }
                    match self.api_specs().create_index(api_specs_unique).await {
                        Ok(_) => {}
                        Err(create_err) if is_index_already_exists(&create_err) => {}
                        Err(create_err) => return Err(create_err.into()),
                    }
                }
                Err(e) => return Err(e.into()),
            }
            self.api_specs()
                .create_index(IndexModel::builder().keys(doc! { "proxy_id": 1 }).build())
                .await?;
            self.api_specs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Wave 5 indexes — spec_version filter, operation_count/created_at sorting,
            // and tags multikey index for has_tag membership filter.
            self.api_specs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "spec_version": 1 })
                        .build(),
                )
                .await?;
            self.api_specs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "operation_count": 1 })
                        .build(),
                )
                .await?;
            self.api_specs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "created_at": -1 })
                        .build(),
                )
                .await?;
            self.api_specs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "tags": 1 })
                        .build(),
                )
                .await?;

            // audit_events indexes (admin-only mutation log).
            self.audit_events()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "ts": -1 })
                        .build(),
                )
                .await?;
            self.audit_events()
                .create_index(IndexModel::builder().keys(doc! { "actor": 1 }).build())
                .await?;
            self.audit_events()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "action": 1 })
                        .build(),
                )
                .await?;
            self.audit_events()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "resource_type": 1 })
                        .build(),
                )
                .await?;
            self.audit_events()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "resource_id": 1 })
                        .build(),
                )
                .await?;

            info!("MongoDB indexes ensured");
            Ok(())
        }

        async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> {
            let mut all_namespaces = HashSet::new();

            // Collect distinct namespaces from all 4 collections
            for ns in self.distinct_namespaces("proxies").await? {
                all_namespaces.insert(ns);
            }
            for ns in self.distinct_namespaces("consumers").await? {
                all_namespaces.insert(ns);
            }
            for ns in self.distinct_namespaces("plugin_configs").await? {
                all_namespaces.insert(ns);
            }
            for ns in self.distinct_namespaces("upstreams").await? {
                all_namespaces.insert(ns);
            }

            let mut result: Vec<String> = all_namespaces.into_iter().collect();
            result.sort();
            Ok(result)
        }

        async fn list_namespaces_authoritative(&self) -> Result<Vec<String>, anyhow::Error> {
            self.list_namespaces().await
        }

        // -------------------------------------------------------------------
        // ApiSpec operations — admin-only.
        //
        // IMPORTANT: Do NOT call these from db_loader polling loops,
        // GatewayConfig loading, or gRPC distribution paths.
        //
        // BSON 16 MiB size check: the pre-flight check measures only the
        // api_specs document (which contains the gzip-compressed spec
        // content).  Bundle-side documents (proxy, upstream, plugin_configs)
        // are assumed individually small — a single Proxy/Upstream/
        // PluginConfig serializes to a few KB of BSON at most.  If a future
        // change embeds large binary payloads in those types, add per-doc
        // size checks here.
        // -------------------------------------------------------------------

        async fn submit_api_spec_bundle(
            &self,
            bundle: &crate::admin::api_specs::ExtractedBundle,
            spec: &ApiSpec,
        ) -> Result<(), anyhow::Error> {
            // Pre-flight size check: BSON document limit is 16 MiB.
            // Measure the actual serialized BSON size rather than estimating
            // with a hardcoded overhead constant.
            let spec_doc = api_spec_to_doc(spec)?;
            let bson_bytes = mongodb::bson::to_vec(&spec_doc)?;
            if bson_bytes.len() > 15 * 1024 * 1024 {
                anyhow::bail!(
                    "MongoDB document limit exceeded: serialized spec is {} bytes \
                     (limit ~15 MiB); use a SQL backend for large specs",
                    bson_bytes.len()
                );
            }

            if self.replica_set_configured() {
                // With a replica set: use a multi-document transaction.
                let mut session = self.client.load().start_session().await?;
                session.start_transaction().await?;

                if let Some(u) = &bundle.upstream {
                    let mut doc = upstream_to_doc(u)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.upstreams()
                        .insert_one(doc)
                        .session(&mut session)
                        .await?;
                }

                {
                    let mut doc = proxy_to_doc(&bundle.proxy)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.proxies().insert_one(doc).session(&mut session).await?;
                }

                for pc in &bundle.plugins {
                    let mut doc = plugin_config_to_doc(pc)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.plugin_configs()
                        .insert_one(doc)
                        .session(&mut session)
                        .await?;
                }

                let spec_doc = api_spec_to_doc(spec)?;
                self.api_specs()
                    .insert_one(spec_doc)
                    .session(&mut session)
                    .await?;
                self.cleanup_orphaned_proxy_group_plugins_opt_session(Some(&mut session))
                    .await?;

                session.commit_transaction().await?;
            } else {
                // No replica set: best-effort with compensating rollback on failure.
                // Track inserted document IDs for cleanup.
                let mut inserted_upstream: Option<String> = None;
                let mut inserted_proxy: Option<String> = None;
                let mut inserted_plugins: Vec<String> = Vec::new();
                let mut inserted_spec: bool = false;

                let result: Result<(), anyhow::Error> = async {
                    if let Some(u) = &bundle.upstream {
                        let mut doc = upstream_to_doc(u)?;
                        doc.insert("api_spec_id", spec.id.as_str());
                        self.upstreams().insert_one(doc).await?;
                        inserted_upstream = Some(u.id.clone());
                    }

                    for pc in &bundle.plugins {
                        let mut doc = plugin_config_to_doc(pc)?;
                        doc.insert("api_spec_id", spec.id.as_str());
                        self.plugin_configs().insert_one(doc).await?;
                        inserted_plugins.push(pc.id.clone());
                    }

                    {
                        let mut doc = proxy_to_doc(&bundle.proxy)?;
                        doc.insert("api_spec_id", spec.id.as_str());
                        self.proxies().insert_one(doc).await?;
                        inserted_proxy = Some(bundle.proxy.id.clone());
                    }

                    let spec_doc = api_spec_to_doc(spec)?;
                    self.api_specs().insert_one(spec_doc).await?;
                    inserted_spec = true;

                    Ok(())
                }
                .await;

                if let Err(e) = result {
                    // Compensating deletes — best-effort, log failures as warnings.
                    self.compensate_bundle_insert(
                        &inserted_upstream,
                        &inserted_proxy,
                        &inserted_plugins,
                        inserted_spec.then_some(spec.id.as_str()),
                    )
                    .await;
                    return Err(e);
                }
            }

            Ok(())
        }

        async fn replace_api_spec_bundle(
            &self,
            bundle: &crate::admin::api_specs::ExtractedBundle,
            spec: &ApiSpec,
        ) -> Result<(), anyhow::Error> {
            // Pre-flight size check: measure actual BSON size before either
            // the metadata-only short-circuit or the full replace path.  Both
            // paths write the api_specs document, so both must return the
            // handler's friendly 413 classification instead of raw MongoDB
            // document-limit errors.
            let spec_doc_check = api_spec_to_doc(spec)?;
            let bson_bytes = mongodb::bson::to_vec(&spec_doc_check)?;
            if bson_bytes.len() > 15 * 1024 * 1024 {
                anyhow::bail!(
                    "MongoDB document limit exceeded: serialized spec is {} bytes \
                     (limit ~15 MiB); use a SQL backend for large specs",
                    bson_bytes.len()
                );
            }

            let existing_spec_doc = self
                .api_specs()
                .find_one(doc! { "_id": &spec.id, "namespace": &spec.namespace })
                .await?;
            let existing_spec: Option<ApiSpec> = existing_spec_doc
                .as_ref()
                .map(|doc| doc_to_api_spec(doc.clone()))
                .transpose()?;
            let previous_declared_assoc_ids = existing_spec
                .as_ref()
                .map(declared_proxy_plugin_association_ids_from_spec)
                .transpose()?
                .unwrap_or_default();
            let desired_resource_hash = store_canonical_resource_hash(bundle)?;

            // --- Resource no-op shortcut (Wave 5 Feature A) ------------------
            // If the current spec-owned resource graph already matches the
            // incoming bundle, only update the api_specs document metadata. The
            // live-resource check prevents direct admin CRUD drift from pinning
            // stale runtime config behind unchanged spec metadata.
            if !spec.resource_hash.is_empty()
                && self
                    .current_api_spec_resource_hash(bundle, spec, &previous_declared_assoc_ids)
                    .await?
                    .as_deref()
                    == Some(desired_resource_hash.as_str())
            {
                // Only update metadata fields on the spec doc.
                self.api_specs()
                    .replace_one(
                        doc! { "_id": &spec.id, "namespace": &spec.namespace },
                        spec_doc_check,
                    )
                    .await?;
                return Ok(());
            }

            self.ensure_no_external_spec_upstream_refs(&spec.namespace, &spec.id, &spec.proxy_id)
                .await?;

            // Fix 3 (Mongo): Preserve manual proxy.plugins associations added
            // after spec creation (e.g. a global rate-limit plugin associated
            // via the direct admin API). The SQL path is correct because it only
            // deletes spec-owned junction rows and the proxy is updated in-place.
            // Mongo deletes and re-inserts the entire proxy doc, which loses any
            // associations not in the bundle. The fix:
            //
            // 1. Collect spec-owned plugin IDs for THIS spec (about to be replaced).
            // 2. Read the existing proxy doc's `plugins` array.
            // 3. Keep associations whose plugin_config_id is NOT in the spec-owned set
            //    (these are manual associations the operator added separately).
            // 4. Merge: manual associations + new bundle's spec-extracted associations.
            //
            // See the SQL parity test `replace_with_changed_resources_keeps_manual_proxy_plugin_association`
            // in admin_db_api_specs_tests.rs for the invariant being maintained.
            let proxy_to_persist: std::borrow::Cow<'_, crate::admin::api_specs::ExtractedBundle> = {
                // 1. Spec-owned plugin IDs currently in the DB.
                let old_spec_plugin_ids: std::collections::HashSet<String> = {
                    let mut cursor = self
                        .plugin_configs()
                        .find(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                        .await?;
                    let mut ids = std::collections::HashSet::new();
                    while cursor.advance().await? {
                        let d = cursor.deserialize_current()?;
                        if let Ok(id) = d.get_str("_id") {
                            ids.insert(id.to_string());
                        }
                    }
                    ids
                };

                // 2. Existing proxy doc (may be absent on first replace or orphaned).
                let existing_proxy_doc = self
                    .proxies()
                    .find_one(doc! { "_id": &spec.proxy_id, "namespace": &spec.namespace })
                    .await?;

                if let Some(existing_doc) = existing_proxy_doc {
                    // 3. Manual associations = existing plugins not in spec-owned set.
                    let existing_proxy = doc_to_proxy(existing_doc)?;
                    let new_spec_plugin_ids: std::collections::HashSet<&str> = bundle
                        .proxy
                        .plugins
                        .iter()
                        .map(|a| a.plugin_config_id.as_str())
                        .collect();

                    let preserved: Vec<crate::config::types::PluginAssociation> = existing_proxy
                        .plugins
                        .into_iter()
                        .filter(|a| {
                            // Keep manual associations: not spec-owned AND not already
                            // in the new bundle's plugin list (avoid duplicates).
                            !old_spec_plugin_ids.contains(&a.plugin_config_id)
                                && !previous_declared_assoc_ids.contains(&a.plugin_config_id)
                                && !new_spec_plugin_ids.contains(a.plugin_config_id.as_str())
                        })
                        .collect();

                    if preserved.is_empty() {
                        // No manual associations — use bundle as-is.
                        std::borrow::Cow::Borrowed(bundle)
                    } else {
                        // 4. Merge: manual (preserved) + new spec-extracted.
                        let mut proxy_clone = bundle.proxy.clone();
                        let mut merged = preserved;
                        merged.extend(bundle.proxy.plugins.iter().cloned());
                        proxy_clone.plugins = merged;
                        std::borrow::Cow::Owned(crate::admin::api_specs::ExtractedBundle {
                            proxy: proxy_clone,
                            upstream: bundle.upstream.clone(),
                            plugins: bundle.plugins.clone(),
                        })
                    }
                } else {
                    std::borrow::Cow::Borrowed(bundle)
                }
            };
            let effective_bundle: &crate::admin::api_specs::ExtractedBundle = &proxy_to_persist;

            if self.replica_set_configured() {
                let mut session = self.client.load().start_session().await?;
                session.start_transaction().await?;

                self.ensure_no_external_spec_upstream_refs_opt_session(
                    Some(&mut session),
                    &spec.namespace,
                    &spec.id,
                    &spec.proxy_id,
                )
                .await?;

                // Delete spec-owned resources (leaf-first).
                self.plugin_configs()
                    .delete_many(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                    .session(&mut session)
                    .await?;
                self.proxies()
                    .delete_one(doc! { "_id": &spec.proxy_id, "namespace": &spec.namespace })
                    .session(&mut session)
                    .await?;
                self.upstreams()
                    .delete_many(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                    .session(&mut session)
                    .await?;
                // The api_specs doc itself.
                self.api_specs()
                    .delete_one(doc! { "_id": &spec.id, "namespace": &spec.namespace })
                    .session(&mut session)
                    .await?;

                // Re-insert with the effective bundle (manual associations preserved).
                if let Some(u) = &effective_bundle.upstream {
                    let mut doc = upstream_to_doc(u)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.upstreams()
                        .insert_one(doc)
                        .session(&mut session)
                        .await?;
                }
                {
                    let mut doc = proxy_to_doc(&effective_bundle.proxy)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.proxies().insert_one(doc).session(&mut session).await?;
                }
                for pc in &effective_bundle.plugins {
                    let mut doc = plugin_config_to_doc(pc)?;
                    doc.insert("api_spec_id", spec.id.as_str());
                    self.plugin_configs()
                        .insert_one(doc)
                        .session(&mut session)
                        .await?;
                }
                let spec_doc = api_spec_to_doc(spec)?;
                self.api_specs()
                    .insert_one(spec_doc)
                    .session(&mut session)
                    .await?;
                self.cleanup_orphaned_proxy_group_plugins_opt_session(Some(&mut session))
                    .await?;

                session.commit_transaction().await?;
            } else {
                // No replica set: best-effort delete then re-insert with
                // compensating rollback on re-insert failure.
                //
                // Build every replacement document and preflight primary-key
                // ownership before the destructive delete phase. Otherwise a
                // user-supplied upstream/plugin id that collides with a
                // hand-managed document would not fail until after the old
                // proxy has already been removed.
                let prepared_docs = prepare_api_spec_bundle_docs(effective_bundle, spec)?;
                self.ensure_api_spec_standalone_replace_ids_available(&prepared_docs, spec)
                    .await?;

                // PARTIAL-STATE WINDOW: after the deletes below succeed and
                // before all re-inserts complete, the spec's proxy/upstream/
                // plugins temporarily do not exist.  Traffic to those routes
                // will see 404 / no-route until the re-insert finishes or the
                // next polling cycle picks up the inconsistency.  The unavoidable
                // window is documented in docs/api_specs.md §Atomicity.  To
                // eliminate this risk, configure FERRUM_MONGO_REPLICA_SET.
                //
                // "Rollback" here means: if a re-insert fails partway through,
                // we attempt to delete any documents that WERE successfully
                // inserted so we don't leave a partial new state.  The old data
                // is already gone at this point; the compensating deletes at
                // least leave the spec empty rather than half-populated.
                // Operators should re-submit the spec to recover.

                // Delete the live proxy first and fail closed if that cannot
                // happen. Later cleanup failures may leave orphans, but no live
                // route will point at missing dependencies.
                if let Err(e) = self
                    .proxies()
                    .delete_one(doc! { "_id": &spec.proxy_id, "namespace": &spec.namespace })
                    .await
                {
                    return Err(anyhow::anyhow!(
                        "replace_api_spec_bundle: failed to delete proxy {} for spec {} before \
                         dependency cleanup: {}",
                        spec.proxy_id,
                        spec.id,
                        e
                    ));
                }

                if let Err(e) = self
                    .plugin_configs()
                    .delete_many(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                    .await
                {
                    warn!(
                        "replace_api_spec_bundle: failed to delete spec-owned plugin_configs for \
                         spec {}: {}",
                        spec.id, e
                    );
                }
                if let Err(e) = self
                    .upstreams()
                    .delete_many(doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace })
                    .await
                {
                    warn!(
                        "replace_api_spec_bundle: failed to delete spec-owned upstreams for \
                         spec {}: {}",
                        spec.id, e
                    );
                }
                if let Err(e) = self
                    .api_specs()
                    .delete_one(doc! { "_id": &spec.id, "namespace": &spec.namespace })
                    .await
                {
                    warn!(
                        "replace_api_spec_bundle: failed to delete api_spec row {}: {}",
                        spec.id, e
                    );
                }

                // Re-insert new bundle with manual associations preserved.
                // Track inserted IDs so we can compensate on partial failure.
                let mut inserted_upstream_id: Option<String> = None;
                let mut inserted_proxy_id: Option<String> = None;
                let mut inserted_plugin_ids: Vec<String> = Vec::new();
                let mut inserted_spec_id: Option<&str> = None;

                let insert_result: Result<(), anyhow::Error> = async {
                    if let Some((upstream_id, upstream_doc)) = &prepared_docs.upstream {
                        self.upstreams().insert_one(upstream_doc.clone()).await?;
                        inserted_upstream_id = Some(upstream_id.clone());
                    }
                    for (plugin_id, plugin_doc) in &prepared_docs.plugins {
                        self.plugin_configs().insert_one(plugin_doc.clone()).await?;
                        inserted_plugin_ids.push(plugin_id.clone());
                    }
                    {
                        let (proxy_id, proxy_doc) = &prepared_docs.proxy;
                        self.proxies().insert_one(proxy_doc.clone()).await?;
                        inserted_proxy_id = Some(proxy_id.clone());
                    }
                    self.api_specs()
                        .insert_one(prepared_docs.spec.clone())
                        .await?;
                    inserted_spec_id = Some(spec.id.as_str());
                    Ok(())
                }
                .await;

                if let Err(e) = insert_result {
                    // Re-insert failed partway through.  Attempt to undo whatever
                    // DID get inserted so we leave an empty state rather than a
                    // partial one.  Old data is already gone; re-submit to recover.
                    warn!(
                        "replace_api_spec_bundle: re-insert failed for spec {}; \
                         attempting compensating rollback of partial inserts. \
                         Re-submit the spec to restore it. Error: {}",
                        spec.id, e
                    );
                    self.compensate_bundle_insert(
                        &inserted_upstream_id,
                        &inserted_proxy_id,
                        &inserted_plugin_ids,
                        inserted_spec_id,
                    )
                    .await;
                    return Err(e);
                }
                self.cleanup_orphaned_proxy_group_plugins().await?;
            }

            Ok(())
        }

        async fn get_api_spec(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<Option<ApiSpec>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .api_specs()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            self.check_slow_query("get_api_spec", start);
            match result {
                Some(doc) => Ok(Some(doc_to_api_spec(doc)?)),
                None => Ok(None),
            }
        }

        async fn get_api_spec_by_proxy(
            &self,
            namespace: &str,
            proxy_id: &str,
        ) -> Result<Option<ApiSpec>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .api_specs()
                .find_one(doc! { "proxy_id": proxy_id, "namespace": namespace })
                .await?;
            self.check_slow_query("get_api_spec_by_proxy", start);
            match result {
                Some(doc) => Ok(Some(doc_to_api_spec(doc)?)),
                None => Ok(None),
            }
        }

        async fn list_api_specs(
            &self,
            namespace: &str,
            filter: &ApiSpecListFilter,
        ) -> Result<PaginatedResult<ApiSpec>, anyhow::Error> {
            let start = std::time::Instant::now();

            // Build filter document
            let mut filter_doc = doc! { "namespace": namespace };
            if let Some(ref pid) = filter.proxy_id {
                filter_doc.insert("proxy_id", pid.as_str());
            }
            if let Some(ref prefix) = filter.spec_version_prefix {
                // prefix match via regex
                filter_doc.insert(
                    "spec_version",
                    doc! { "$regex": format!("^{}", regex_escape(prefix)) },
                );
            }
            if let Some(ref substr) = filter.title_contains {
                filter_doc.insert(
                    "title",
                    doc! { "$regex": regex_escape(substr), "$options": "i" },
                );
            }
            if let Some(ref since) = filter.updated_since {
                // `updated_at` is a variable-precision RFC 3339 string
                // (chrono `AutoSi`), so no single lexicographic `$gte` bound is
                // chronologically faithful at the sub-second boundary. Use the
                // whole-second-floor bound as an index *prefilter* only: it
                // includes every row that is chronologically `>= since` (never
                // drops newer rows) at the cost of also matching rows in the
                // boundary second `[floor(since), since)`. The exact
                // `updated_at >= since` predicate (the documented/trait
                // semantics, matching the SQL backend) is then re-applied in
                // app code below against the parsed `DateTime`. See
                // `mongo_updated_at_lower_bound`.
                filter_doc.insert(
                    "updated_at",
                    doc! { "$gte": mongo_updated_at_lower_bound(*since) },
                );
            }
            if let Some(ref tag) = filter.has_tag {
                // Native array membership query (multikey index used).
                // Unlike SQL, MongoDB uses a real array field and multikey
                // index — no LIKE pattern needed, and characters like `"`, `%`,
                // `\` in tag names are matched literally and do not cause
                // false positives.
                filter_doc.insert("tags", tag.as_str());
            }

            // --- COUNT query (same filter, no pagination) --------------------
            let prefilter_total =
                self.api_specs().count_documents(filter_doc.clone()).await? as i64;

            // The floored `updated_at` prefilter is over-inclusive only when
            // `updated_since` carries a sub-second component: it then also
            // matches rows in the boundary second `[floor(since), since)`.
            // Count those spurious rows exactly so `total` reflects the
            // documented `updated_at >= since` semantics. The boundary window
            // is at most one second of resource writes (typically empty), so
            // this is a small, index-bounded scan that fetches only timestamps.
            let boundary_overage = match filter.updated_since {
                Some(since) if since.timestamp_subsec_nanos() != 0 => {
                    self.count_updated_before_in_boundary_second(&filter_doc, since)
                        .await?
                }
                _ => 0,
            };
            let total = prefilter_total - boundary_overage;

            // --- Data query (sort + skip + limit) ----------------------------
            // Sort document
            let sort_field = match filter.sort_by {
                ApiSpecSortBy::UpdatedAt => "updated_at",
                ApiSpecSortBy::Title => "title",
                ApiSpecSortBy::OperationCount => "operation_count",
                ApiSpecSortBy::CreatedAt => "created_at",
            };
            let sort_dir: i32 = match filter.order {
                SortOrder::Asc => 1,
                SortOrder::Desc => -1,
            };

            // The floored `updated_at` prefilter over-includes the boundary
            // second `[floor(since), since)` ONLY when `updated_since` carries a
            // sub-second component (a whole-second floor is exact). The exact
            // `updated_at >= since` predicate is faithful across every AutoSi
            // fractional width, but it can only be applied in app code on the
            // parsed `DateTime` — it has no ordering-faithful string `$gte` form.
            //
            // Pagination must therefore see the *kept* rows, not the raw
            // prefilter rows. If we let Mongo `.skip()/.limit()` the
            // over-inclusive set and post-filtered afterwards, a dropped
            // boundary row would consume a page slot (under-filling the page,
            // hiding valid rows past the limit) and shift `next_offset`,
            // producing duplicates on the next page. So when (and only when) the
            // boundary post-filter can fire, paginate app-side over the kept
            // rows; otherwise keep the efficient server-side skip/limit. This
            // matches the SQL backend, which applies the exact `updated_at >= ?`
            // predicate before `LIMIT/OFFSET`.
            let exact_postfilter_since = match filter.updated_since {
                Some(since) if since.timestamp_subsec_nanos() != 0 => Some(since),
                _ => None,
            };

            // Push skip/limit to Mongo only when no boundary over-inclusion is
            // possible. When the exact post-filter can fire (sub-second `since`),
            // leave skip/limit unset (`None`) and paginate app-side over kept
            // rows below, so dropped boundary rows never consume a page slot.
            let (mongo_skip, mongo_limit) = if exact_postfilter_since.is_some() {
                (None, None)
            } else {
                (Some(filter.offset as u64), Some(filter.limit as i64))
            };
            let options = mongodb::options::FindOptions::builder()
                .sort(doc! { sort_field: sort_dir })
                .skip(mongo_skip)
                .limit(mongo_limit)
                .projection(doc! { "spec_content": 0, "resource_hash": 0 })
                .build();
            let mut cursor = self
                .api_specs()
                .find(filter_doc)
                .with_options(options)
                .await?;

            let mut specs = Vec::new();
            if let Some(since) = exact_postfilter_since {
                // App-side pagination over kept rows.
                let offset = filter.offset as u64;
                let limit = filter.limit as usize;
                let mut kept_seen: u64 = 0;
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current()?;
                    let spec = doc_to_api_spec_summary(doc)?;
                    // Drop boundary-second rows the floored prefilter over-matched.
                    if spec.updated_at < since {
                        continue;
                    }
                    // Skip the first `offset` kept rows, then collect `limit`.
                    if kept_seen < offset {
                        kept_seen += 1;
                        continue;
                    }
                    if specs.len() >= limit {
                        // Enough kept rows for this page; stop scanning early.
                        break;
                    }
                    specs.push(spec);
                }
            } else {
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current()?;
                    specs.push(doc_to_api_spec_summary(doc)?);
                }
            }
            self.check_slow_query("list_api_specs", start);
            Ok(PaginatedResult {
                items: specs,
                total,
            })
        }

        async fn list_spec_owned_plugin_configs(
            &self,
            namespace: &str,
            spec_id: &str,
        ) -> Result<Vec<crate::config::types::PluginConfig>, anyhow::Error> {
            let start = std::time::Instant::now();
            let options = FindOptions::builder()
                .sort(doc! { "created_at": 1, "_id": 1 })
                .build();
            let mut cursor = self
                .plugin_configs()
                .find(doc! { "namespace": namespace, "api_spec_id": spec_id })
                .with_options(options)
                .await?;
            let mut configs = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_plugin_config(doc) {
                    Ok(pc) => {
                        // Preserve api_spec_id: this is an admin-read path used
                        // by the PUT handler for ownership resolution.  Runtime
                        // paths strip via strip_api_spec_id_from_runtime_config.
                        configs.push(pc);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "list_spec_owned_plugin_configs: skipping malformed doc: {}",
                            e
                        );
                    }
                }
            }
            self.check_slow_query("list_spec_owned_plugin_configs", start);
            Ok(configs)
        }

        async fn list_spec_owned_upstreams(
            &self,
            namespace: &str,
            spec_id: &str,
        ) -> Result<Vec<crate::config::types::Upstream>, anyhow::Error> {
            let start = std::time::Instant::now();
            let options = FindOptions::builder()
                .sort(doc! { "created_at": 1, "_id": 1 })
                .build();
            let mut cursor = self
                .upstreams()
                .find(doc! { "namespace": namespace, "api_spec_id": spec_id })
                .with_options(options)
                .await?;
            let mut upstreams = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_upstream(doc) {
                    Ok(upstream) => upstreams.push(upstream),
                    Err(e) => {
                        tracing::warn!("list_spec_owned_upstreams: skipping malformed doc: {}", e);
                    }
                }
            }
            self.check_slow_query("list_spec_owned_upstreams", start);
            Ok(upstreams)
        }

        async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();

            // Check existence first (namespace-scoped).
            let existing = self
                .api_specs()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;

            if existing.is_none() {
                self.check_slow_query("delete_api_spec", start);
                return Ok(false);
            }

            // Determine the proxy_id before deleting.
            let proxy_id: Option<String> = existing
                .as_ref()
                .and_then(|d| d.get_str("proxy_id").ok())
                .map(str::to_string);

            self.ensure_no_external_spec_upstream_refs(
                namespace,
                id,
                proxy_id.as_deref().unwrap_or(""),
            )
            .await?;

            if self.replica_set_configured() {
                // With a replica set: use a multi-document transaction so that a
                // partial failure does not leave orphaned proxy/upstream/plugin rows.
                // Mirrors `submit_api_spec_bundle` and `replace_api_spec_bundle`.
                let mut session = self.client.load().start_session().await?;
                session.start_transaction().await?;

                self.ensure_no_external_spec_upstream_refs_opt_session(
                    Some(&mut session),
                    namespace,
                    id,
                    proxy_id.as_deref().unwrap_or(""),
                )
                .await?;

                // 1. Spec-owned plugin_configs.
                self.plugin_configs()
                    .delete_many(doc! { "api_spec_id": id, "namespace": namespace })
                    .session(&mut session)
                    .await?;
                // 2. All plugin_configs attached to the proxy (catches proxy-scoped
                //    plugins that were added after spec creation and are not tagged
                //    with api_spec_id).
                if let Some(ref pid) = proxy_id {
                    self.plugin_configs()
                        .delete_many(doc! { "proxy_id": pid, "namespace": namespace })
                        .session(&mut session)
                        .await?;
                    self.proxies()
                        .delete_one(doc! { "_id": pid, "namespace": namespace })
                        .session(&mut session)
                        .await?;
                }
                self.cleanup_orphaned_proxy_group_plugins_opt_session(Some(&mut session))
                    .await?;
                // 3. Spec-owned upstreams.
                self.upstreams()
                    .delete_many(doc! { "api_spec_id": id, "namespace": namespace })
                    .session(&mut session)
                    .await?;
                // 4. The spec row itself.
                self.api_specs()
                    .delete_one(doc! { "_id": id, "namespace": namespace })
                    .session(&mut session)
                    .await?;

                session.commit_transaction().await?;
            } else {
                // No replica set: best-effort deletes.  Log failures as warnings so
                // operators can detect partial-delete orphans; the function still
                // returns Ok(true) so the caller knows the spec was found and the
                // attempt was made.  Production MongoDB deployments should use a
                // replica set (see FERRUM_MONGO_REPLICA_SET).
                if let Some(ref pid) = proxy_id {
                    self.proxies()
                        .delete_one(doc! { "_id": pid, "namespace": namespace })
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "delete_api_spec: failed to delete proxy {} for spec {} before \
                                 dependency cleanup: {}",
                                pid,
                                id,
                                e
                            )
                        })?;
                }
                if let Err(e) = self
                    .plugin_configs()
                    .delete_many(doc! { "api_spec_id": id, "namespace": namespace })
                    .await
                {
                    warn!(
                        "delete_api_spec: failed to delete spec-owned plugin_configs for \
                         spec {}: {}",
                        id, e
                    );
                }
                if let Some(ref pid) = proxy_id {
                    let cleanup_result = self
                        .plugin_configs()
                        .delete_many(doc! { "proxy_id": pid, "namespace": namespace })
                        .await;
                    if let Err(e) = cleanup_result {
                        warn!(
                            "delete_api_spec: failed to delete proxy-scoped plugin_configs for \
                             proxy {}: {}",
                            pid, e
                        );
                    }
                }
                if let Err(e) = self.cleanup_orphaned_proxy_group_plugins().await {
                    warn!(
                        "delete_api_spec: failed to cleanup orphaned proxy_group plugins \
                         after deleting spec {}: {}",
                        id, e
                    );
                }
                if let Err(e) = self
                    .upstreams()
                    .delete_many(doc! { "api_spec_id": id, "namespace": namespace })
                    .await
                {
                    warn!(
                        "delete_api_spec: failed to delete spec-owned upstreams for spec {}: {}",
                        id, e
                    );
                }
                // The spec row deletion is the one we must succeed on — if this fails
                // the spec appears to still exist, which is worse than an orphan.
                self.api_specs()
                    .delete_one(doc! { "_id": id, "namespace": namespace })
                    .await?;
            }

            self.check_slow_query("delete_api_spec", start);
            Ok(true)
        }

        async fn insert_audit_event(
            &self,
            event: &crate::admin::audit::AuditEvent,
        ) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            self.audit_events()
                .insert_one(audit_event_to_doc(event)?)
                .await?;
            self.check_slow_query("insert_audit_event", start);
            Ok(())
        }

        async fn list_audit_events(
            &self,
            namespace: &str,
            filter: &crate::admin::audit::AuditListFilter,
        ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut filter_doc = doc! { "namespace": namespace };
            if let Some(ref value) = filter.actor {
                filter_doc.insert("actor", value.as_str());
            }
            if let Some(ref value) = filter.action {
                filter_doc.insert("action", value.as_str());
            }
            if let Some(ref value) = filter.resource_type {
                filter_doc.insert("resource_type", value.as_str());
            }
            if let Some(ref value) = filter.resource_id {
                filter_doc.insert("resource_id", value.as_str());
            }
            if let Some(ts_range) = audit_ts_range_filter(filter) {
                filter_doc.insert("ts", ts_range);
            }

            let total = self
                .audit_events()
                .count_documents(filter_doc.clone())
                .await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "ts": -1, "_id": -1 })
                .skip(Some(filter.offset as u64))
                .limit(Some(filter.limit as i64))
                .build();
            let mut cursor = self
                .audit_events()
                .find(filter_doc)
                .with_options(options)
                .await?;
            let mut items = Vec::new();
            while cursor.advance().await? {
                items.push(doc_to_audit_event(cursor.deserialize_current()?)?);
            }
            self.check_slow_query("list_audit_events", start);
            Ok(PaginatedResult { items, total })
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn audit_ts_range_filter(filter: &crate::admin::audit::AuditListFilter) -> Option<Document> {
        let mut ts_range = Document::new();
        if let Some(value) = filter.start.as_ref() {
            ts_range.insert("$gte", audit_ts_bound(value));
        }
        if let Some(value) = filter.end.as_ref() {
            ts_range.insert("$lte", audit_ts_bound(value));
        }
        if ts_range.is_empty() {
            None
        } else {
            Some(ts_range)
        }
    }

    fn audit_ts_bound(value: &DateTime<Utc>) -> Bson {
        Bson::DateTime(BsonDateTime::from_millis(value.timestamp_millis()))
    }

    impl MongoStore {
        /// Load all `_id` values from a collection (for deletion detection).
        #[allow(dead_code)]
        async fn load_collection_ids(
            &self,
            collection_name: &str,
        ) -> Result<HashSet<String>, anyhow::Error> {
            self.load_collection_ids_filtered(collection_name, doc! {})
                .await
        }

        /// Load `_id` values from a collection matching a filter (for namespace-scoped deletion detection).
        async fn load_collection_ids_filtered(
            &self,
            collection_name: &str,
            filter: Document,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let collection: Collection<Document> = self.db().collection(collection_name);
            let options = FindOptions::builder().projection(doc! { "_id": 1 }).build();
            let mut cursor = collection.find(filter).with_options(options).await?;
            let mut ids = HashSet::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("_id") {
                    ids.insert(id.to_string());
                }
            }
            Ok(ids)
        }

        /// Collect distinct namespace values from a single collection.
        async fn distinct_namespaces(
            &self,
            collection_name: &str,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let collection: Collection<Document> = self.db().collection(collection_name);
            let values = collection.distinct("namespace", doc! {}).await?;
            let mut namespaces = HashSet::new();
            for val in values {
                if let Some(s) = val.as_str() {
                    namespaces.insert(s.to_string());
                }
            }
            Ok(namespaces)
        }

        /// Returns `true` when a MongoDB replica set was configured at `connect()` time.
        ///
        /// The official `mongodb` Rust driver does not expose `repl_set_name` as a
        /// `Client` method. Instead, the `MongoStore` constructor and reconnect
        /// path update this atomic from the effective `ClientOptions::repl_set_name`.
        /// API-spec writes use this helper to decide whether multi-document
        /// transactions are available. Without a replica set, MongoDB does not
        /// support transactions (server-side error on `start_transaction`).
        ///
        /// Detection is env-var-based only (`FERRUM_MONGO_REPLICA_SET`).  A
        /// user pointing at an actual replica set without setting the env var
        /// silently falls into the compensating-delete path.  A startup
        /// `hello` probe could detect the mismatch and warn, but the env var
        /// is the documented contract and false-negative is safe (just slower
        /// and less atomic).
        fn replica_set_configured(&self) -> bool {
            self.replica_set_configured.load(Ordering::Acquire)
        }

        async fn ensure_api_spec_standalone_replace_ids_available(
            &self,
            prepared: &PreparedApiSpecBundleDocs,
            spec: &ApiSpec,
        ) -> Result<(), anyhow::Error> {
            let (proxy_id, _) = &prepared.proxy;
            Self::ensure_document_id_available_for_api_spec_replace(
                self.proxies(),
                "proxy",
                proxy_id,
                &spec.namespace,
                &spec.id,
            )
            .await?;

            if let Some((upstream_id, _)) = &prepared.upstream {
                Self::ensure_document_id_available_for_api_spec_replace(
                    self.upstreams(),
                    "upstream",
                    upstream_id,
                    &spec.namespace,
                    &spec.id,
                )
                .await?;
            }

            let mut seen_plugin_ids = HashSet::new();
            for (plugin_id, _) in &prepared.plugins {
                if !seen_plugin_ids.insert(plugin_id.as_str()) {
                    anyhow::bail!(
                        "duplicate key preflight: plugin_config id '{}' appears more than once in api_spec '{}' replacement bundle",
                        plugin_id,
                        spec.id
                    );
                }
                Self::ensure_document_id_available_for_api_spec_replace(
                    self.plugin_configs(),
                    "plugin_config",
                    plugin_id,
                    &spec.namespace,
                    &spec.id,
                )
                .await?;
            }

            Ok(())
        }

        async fn ensure_document_id_available_for_api_spec_replace(
            collection: Collection<Document>,
            resource_type: &str,
            id: &str,
            namespace: &str,
            spec_id: &str,
        ) -> Result<(), anyhow::Error> {
            let existing = collection
                .find_one(doc! { "_id": id })
                .projection(doc! { "api_spec_id": 1, "namespace": 1 })
                .await?;
            if let Some(doc) = existing {
                let same_spec = doc.get_str("api_spec_id").ok() == Some(spec_id)
                    && doc.get_str("namespace").ok() == Some(namespace);
                if !same_spec {
                    let owner = doc.get_str("api_spec_id").unwrap_or("<none>");
                    let owner_namespace = doc.get_str("namespace").unwrap_or("<unknown>");
                    anyhow::bail!(
                        "duplicate key preflight: {} id '{}' already exists in namespace '{}' owned by api_spec '{}'; cannot replace api_spec '{}'",
                        resource_type,
                        id,
                        owner_namespace,
                        owner,
                        spec_id
                    );
                }
            }
            Ok(())
        }

        /// Attempt to delete all documents inserted so far in a best-effort
        /// compensating rollback. Errors are logged as warnings (the original
        /// insert error is what the caller returns).
        async fn compensate_bundle_insert(
            &self,
            upstream_id: &Option<String>,
            proxy_id: &Option<String>,
            plugin_ids: &[String],
            spec_id: Option<&str>,
        ) {
            if let Some(sid) = spec_id
                && let Err(e) = self.api_specs().delete_one(doc! { "_id": sid }).await
            {
                warn!(
                    "compensate_bundle_insert: failed to delete api_spec {}: {}",
                    sid, e
                );
            }
            if let Some(pid) = proxy_id
                && let Err(e) = self.proxies().delete_one(doc! { "_id": pid }).await
            {
                warn!(
                    "compensate_bundle_insert: failed to delete proxy {}; \
                     leaving inserted dependencies in place to avoid a live proxy \
                     with dangling references: {}",
                    pid, e
                );
                return;
            }
            for pid in plugin_ids {
                if let Err(e) = self.plugin_configs().delete_one(doc! { "_id": pid }).await {
                    warn!(
                        "compensate_bundle_insert: failed to delete plugin_config {}: {}",
                        pid, e
                    );
                }
            }
            if let Some(uid) = upstream_id
                && let Err(e) = self.upstreams().delete_one(doc! { "_id": uid }).await
            {
                warn!(
                    "compensate_bundle_insert: failed to delete upstream {}: {}",
                    uid, e
                );
            }
        }
    }

    /// IDs in `known` that are not in `current` (i.e., deleted resources).
    fn diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
        known.difference(current).cloned().collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashSet;

        #[test]
        fn audit_ts_range_filter_uses_bson_datetimes() {
            let start = DateTime::parse_from_rfc3339("2026-05-18T01:00:00Z")
                .expect("start timestamp")
                .with_timezone(&Utc);
            let end = DateTime::parse_from_rfc3339("2026-05-18T02:00:00Z")
                .expect("end timestamp")
                .with_timezone(&Utc);
            let filter = crate::admin::audit::AuditListFilter {
                start: Some(start),
                end: Some(end),
                ..Default::default()
            };

            let range = audit_ts_range_filter(&filter).expect("timestamp range");

            assert_eq!(
                range.get("$gte"),
                Some(&Bson::DateTime(BsonDateTime::from_millis(
                    start.timestamp_millis()
                )))
            );
            assert_eq!(
                range.get("$lte"),
                Some(&Bson::DateTime(BsonDateTime::from_millis(
                    end.timestamp_millis()
                )))
            );
        }

        /// How a `DateTime<Utc>` is actually persisted into `updated_at`:
        /// chrono's serde impl (`SecondsFormat::AutoSi`). Mirrors what
        /// `bson::to_document` writes for resource/api-spec docs, so the bound
        /// tests below compare against the real stored bytes.
        fn stored_updated_at(ts: DateTime<Utc>) -> String {
            serde_json::to_string(&ts)
                .expect("serialize timestamp")
                .trim_matches('"')
                .to_string()
        }

        #[test]
        fn mongo_updated_at_lower_bound_floors_to_whole_second() {
            let whole = DateTime::parse_from_rfc3339("2026-05-18T01:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc);
            let fractional = DateTime::parse_from_rfc3339("2026-05-18T01:00:00.123Z")
                .expect("timestamp")
                .with_timezone(&Utc);

            assert_eq!(mongo_updated_at_lower_bound(whole), "2026-05-18T01:00:00");
            assert_eq!(
                mongo_updated_at_lower_bound(fractional),
                "2026-05-18T01:00:00"
            );
            // No zone suffix or fractional part — it must be a prefix of every
            // AutoSi stored representation of the same (or a later) second.
            assert!(!mongo_updated_at_lower_bound(fractional).ends_with('Z'));
            assert!(!mongo_updated_at_lower_bound(fractional).contains('.'));
        }

        #[test]
        fn mongo_updated_at_lower_bound_includes_same_second_sub_second_rows() {
            // Regression: `GET /api-specs?updated_since=...T01:00:00Z` must not
            // omit a row stored at `...T01:00:00.123Z`. A naive `Z`-suffixed
            // bound excludes it because `.` (0x2E) sorts before `Z` (0x5A).
            let bound_instant = DateTime::parse_from_rfc3339("2026-05-18T01:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc);
            let bound = mongo_updated_at_lower_bound(bound_instant);

            // Stored values at or after the bound, across every AutoSi width.
            for stored_instant in [
                "2026-05-18T01:00:00Z",           // exact second, no fraction
                "2026-05-18T01:00:00.123Z",       // millis
                "2026-05-18T01:00:00.123456Z",    // micros
                "2026-05-18T01:00:00.000000001Z", // nanos
                "2026-05-18T01:00:01Z",           // next second
                "2026-05-18T01:01:00.5Z",         // later minute, fractional
            ] {
                let stored = stored_updated_at(
                    DateTime::parse_from_rfc3339(stored_instant)
                        .expect("stored timestamp")
                        .with_timezone(&Utc),
                );
                assert!(
                    stored.as_str() >= bound.as_str(),
                    "stored {stored} must be >= bound {bound} (chronologically >= bound)"
                );
            }

            // Strictly-earlier instants must remain excluded.
            for stored_instant in [
                "2026-05-18T00:59:59.999999999Z",
                "2026-05-18T00:59:59Z",
                "2026-05-17T23:59:59.5Z",
            ] {
                let stored = stored_updated_at(
                    DateTime::parse_from_rfc3339(stored_instant)
                        .expect("stored timestamp")
                        .with_timezone(&Utc),
                );
                assert!(
                    stored.as_str() < bound.as_str(),
                    "stored {stored} must be < bound {bound} (chronologically < bound)"
                );
            }
        }

        // Mirrors the exact `updated_at >= since` post-filter that
        // `list_api_specs` re-applies after the floored index prefilter, plus
        // the bounded boundary-second overage count. The floored `$gte` bound
        // matches every chronologically-`>= since` row but over-includes rows
        // in `[floor(since), since)`; these helpers reproduce the decision the
        // store makes on parsed timestamps (faithful across AutoSi widths).
        fn parse_stored(stored: &str) -> DateTime<Utc> {
            DateTime::parse_from_rfc3339(stored)
                .expect("stored timestamp")
                .with_timezone(&Utc)
        }
        fn in_boundary_window(stored: &str, since: DateTime<Utc>) -> bool {
            // `[floor(since), floor(since)+1s)` — the only over-included window.
            let lo = mongo_updated_at_lower_bound(since);
            let hi = mongo_updated_at_lower_bound(since + chrono::Duration::seconds(1));
            let s = stored_updated_at(parse_stored(stored));
            s.as_str() >= lo.as_str() && s.as_str() < hi.as_str()
        }

        #[test]
        fn list_api_specs_exact_updated_since_semantics() {
            // Finding: `GET /api-specs?updated_since=2026-05-18T01:00:00.900Z`
            // must NOT return/count a spec stored at `2026-05-18T01:00:00.100Z`
            // even though the floored prefilter (`...T01:00:00`) matches it.
            let since = parse_stored("2026-05-18T01:00:00.900Z");

            // Spurious boundary-second row: prefilter-matched but `< since`.
            let earlier = "2026-05-18T01:00:00.100Z";
            assert!(in_boundary_window(earlier, since));
            assert!(
                parse_stored(earlier) < since,
                "earlier row must be excluded by the exact post-filter"
            );

            // Same-instant and later rows are retained.
            for kept in [
                "2026-05-18T01:00:00.900Z",    // exact boundary
                "2026-05-18T01:00:00.900001Z", // just after, micros
                "2026-05-18T01:00:01Z",        // next second
            ] {
                assert!(
                    parse_stored(kept) >= since,
                    "row {kept} must be retained (chronologically >= since)"
                );
            }

            // Whole-second `since`: the floor is already exact, so the boundary
            // window holds nothing `< since` and no overage is subtracted.
            let whole = parse_stored("2026-05-18T01:00:00Z");
            assert_eq!(whole.timestamp_subsec_nanos(), 0);
            assert!(in_boundary_window("2026-05-18T01:00:00.000000001Z", whole));
            assert!(
                parse_stored("2026-05-18T01:00:00.000000001Z") >= whole,
                "with whole-second since, same-second sub-second rows are kept"
            );
        }

        #[test]
        fn list_api_specs_sub_second_since_paginates_over_kept_rows() {
            // Finding: with a sub-second `updated_since`, the exact post-filter
            // runs AFTER Mongo skip/limit, so a dropped boundary-second row would
            // consume a page slot — under-filling the page and shifting
            // `next_offset` into duplicates. The fix paginates app-side over the
            // *kept* rows. This test models that app-side loop against the same
            // sorted prefilter set the store scans.
            let since = parse_stored("2026-05-18T01:00:00.500Z");

            // Sorted (updated_at ASC) prefilter set: the floored `$gte` matches
            // every row at/after `...T01:00:00`. Two boundary rows are `< since`
            // and must be dropped without consuming page slots.
            let prefilter_sorted = [
                "2026-05-18T01:00:00.100Z", // boundary, dropped (< since)
                "2026-05-18T01:00:00.400Z", // boundary, dropped (< since)
                "2026-05-18T01:00:00.500Z", // kept[0] (== since)
                "2026-05-18T01:00:00.700Z", // kept[1]
                "2026-05-18T01:00:01.000Z", // kept[2]
                "2026-05-18T01:00:02.000Z", // kept[3]
                "2026-05-18T01:00:03.000Z", // kept[4]
            ];

            // App-side pagination identical to the store: drop `< since`, skip
            // `offset` kept rows, then collect up to `limit` kept rows.
            let page = |offset: u64, limit: usize| -> Vec<String> {
                let mut kept_seen: u64 = 0;
                let mut out: Vec<String> = Vec::new();
                for stored in prefilter_sorted {
                    if parse_stored(stored) < since {
                        continue;
                    }
                    if kept_seen < offset {
                        kept_seen += 1;
                        continue;
                    }
                    if out.len() >= limit {
                        break;
                    }
                    out.push(stored.to_string());
                }
                out
            };

            // Page 1 (offset 0, limit 2) must be FULL with kept rows — the two
            // dropped boundary rows do not steal slots.
            let p1 = page(0, 2);
            assert_eq!(
                p1,
                vec![
                    "2026-05-18T01:00:00.500Z".to_string(),
                    "2026-05-18T01:00:00.700Z".to_string(),
                ],
                "first page must be filled from kept rows only"
            );

            // `next_offset` = offset + items.len() = 2 (handler computation).
            // Page 2 must continue WITHOUT repeating page-1 rows.
            let p2 = page(2, 2);
            assert_eq!(
                p2,
                vec![
                    "2026-05-18T01:00:01.000Z".to_string(),
                    "2026-05-18T01:00:02.000Z".to_string(),
                ],
                "second page must not duplicate first-page rows"
            );

            // Final page drains the remainder, no overlap.
            let p3 = page(4, 2);
            assert_eq!(
                p3,
                vec!["2026-05-18T01:00:03.000Z".to_string()],
                "tail page returns only the final kept row"
            );

            // Exactly 5 kept rows total across non-overlapping pages.
            assert_eq!(p1.len() + p2.len() + p3.len(), 5);
        }

        #[test]
        fn audit_event_to_doc_stores_ts_as_bson_datetime() {
            let ts = DateTime::parse_from_rfc3339("2026-05-18T01:00:00.123Z")
                .expect("timestamp")
                .with_timezone(&Utc);
            let event = crate::admin::audit::AuditEvent {
                id: "audit-1".to_string(),
                ts,
                actor: "operator".to_string(),
                action: "update".to_string(),
                resource_type: "proxy".to_string(),
                resource_id: "proxy-1".to_string(),
                namespace: "ferrum".to_string(),
                diff: serde_json::json!({
                    "changed": true,
                    "after": {
                        "config": {
                            "$api_key": "[REDACTED]",
                            "nested.value": true
                        }
                    }
                }),
            };

            let doc = audit_event_to_doc(&event).expect("audit event document");

            assert_eq!(
                doc.get("ts"),
                Some(&Bson::DateTime(BsonDateTime::from_millis(
                    ts.timestamp_millis()
                )))
            );
            assert!(
                matches!(doc.get("diff"), Some(Bson::String(_))),
                "Mongo audit diff must be stored as opaque JSON text"
            );

            let round_trip = doc_to_audit_event(doc).expect("audit event round-trips");
            assert_eq!(round_trip.ts.timestamp_millis(), ts.timestamp_millis());
            assert_eq!(round_trip.diff, event.diff);
        }

        // -------------------------------------------------------------------
        // diff_removed tests
        // -------------------------------------------------------------------

        #[test]
        fn diff_removed_empty_sets() {
            let known = HashSet::new();
            let current = HashSet::new();
            let removed = diff_removed(&known, &current);
            assert!(removed.is_empty(), "no removals when both sets are empty");
        }

        #[test]
        fn diff_removed_no_deletions() {
            let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
            let current: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
            let removed = diff_removed(&known, &current);
            assert!(removed.is_empty(), "no removals when sets are identical");
        }

        #[test]
        fn diff_removed_all_deleted() {
            let known: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
            let current = HashSet::new();
            let mut removed = diff_removed(&known, &current);
            removed.sort();
            assert_eq!(removed, vec!["a", "b", "c"]);
        }

        #[test]
        fn diff_removed_partial_deletion() {
            let known: HashSet<String> =
                ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
            let current: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
            let mut removed = diff_removed(&known, &current);
            removed.sort();
            assert_eq!(removed, vec!["b", "d"]);
        }

        #[test]
        fn diff_removed_current_has_new_ids() {
            // New IDs in current that are not in known should NOT appear in removed
            let known: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
            let current: HashSet<String> =
                ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
            let removed = diff_removed(&known, &current);
            assert!(
                removed.is_empty(),
                "additions in current should not appear as removals"
            );
        }

        #[test]
        fn api_spec_doc_stores_spec_content_as_bson_binary() {
            let now = chrono::Utc::now();
            let spec = ApiSpec {
                id: "spec-1".to_string(),
                namespace: "ferrum".to_string(),
                proxy_id: "proxy-1".to_string(),
                spec_version: "3.1.0".to_string(),
                spec_format: crate::config::types::SpecFormat::Json,
                spec_content: vec![0, 1, 2, 253, 254, 255],
                content_encoding: "gzip".to_string(),
                uncompressed_size: 128,
                content_hash: "a".repeat(64),
                title: Some("Example".to_string()),
                info_version: Some("1.0.0".to_string()),
                description: None,
                contact_name: None,
                contact_email: None,
                license_name: None,
                license_identifier: None,
                tags: vec!["api".to_string()],
                server_urls: vec!["https://api.example.com".to_string()],
                operation_count: 3,
                resource_hash: "b".repeat(64),
                created_at: now,
                updated_at: now,
            };

            let doc = api_spec_to_doc(&spec).expect("api_spec_to_doc");
            assert!(
                matches!(doc.get("spec_content"), Some(Bson::Binary(_))),
                "spec_content must be BSON Binary, not an integer array"
            );

            let restored = doc_to_api_spec(doc).expect("doc_to_api_spec");
            assert_eq!(restored.spec_content, spec.spec_content);
            assert_eq!(restored.tags, spec.tags);
            assert_eq!(restored.server_urls, spec.server_urls);
        }

        #[test]
        fn api_spec_summary_doc_allows_projected_out_spec_content() {
            let now = chrono::Utc::now();
            let spec = ApiSpec {
                id: "spec-summary".to_string(),
                namespace: "ferrum".to_string(),
                proxy_id: "proxy-summary".to_string(),
                spec_version: "3.1.0".to_string(),
                spec_format: crate::config::types::SpecFormat::Yaml,
                spec_content: vec![1, 2, 3, 4],
                content_encoding: "gzip".to_string(),
                uncompressed_size: 256,
                content_hash: "c".repeat(64),
                title: Some("Summary".to_string()),
                info_version: Some("1.0.0".to_string()),
                description: Some("metadata only".to_string()),
                contact_name: None,
                contact_email: None,
                license_name: None,
                license_identifier: None,
                tags: vec!["public".to_string()],
                server_urls: vec!["https://api.example.com".to_string()],
                operation_count: 7,
                resource_hash: "d".repeat(64),
                created_at: now,
                updated_at: now,
            };

            let mut doc = api_spec_to_doc(&spec).expect("api_spec_to_doc");
            doc.remove("spec_content");
            doc.remove("resource_hash");

            let summary = doc_to_api_spec_summary(doc).expect("doc_to_api_spec_summary");
            assert_eq!(summary.id, spec.id);
            assert_eq!(summary.content_hash, spec.content_hash);
            assert_eq!(summary.title, spec.title);
            assert_eq!(summary.tags, spec.tags);
            assert!(summary.spec_content.is_empty());
            assert!(summary.resource_hash.is_empty());
        }

        #[test]
        fn diff_removed_single_deletion() {
            let known: HashSet<String> = ["proxy-1", "proxy-2", "proxy-3"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let current: HashSet<String> = ["proxy-1", "proxy-3"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let removed = diff_removed(&known, &current);
            assert_eq!(removed, vec!["proxy-2"]);
        }

        #[test]
        fn diff_removed_known_empty_current_has_ids() {
            let known = HashSet::new();
            let current: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
            let removed = diff_removed(&known, &current);
            assert!(removed.is_empty(), "nothing to remove when known is empty");
        }

        // -------------------------------------------------------------------
        // BSON round-trip serialization tests
        // -------------------------------------------------------------------

        #[test]
        fn proxy_bson_round_trip() {
            let now = chrono::Utc::now();
            let proxy = Proxy {
                id: "test-proxy".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: Some("My Proxy".to_string()),
                hosts: vec!["example.com".to_string()],
                listen_path: Some("/api".to_string()),
                backend_scheme: Some(crate::config::types::BackendScheme::Https),
                dispatch_kind: crate::config::types::DispatchKind::from(
                    crate::config::types::BackendScheme::Https,
                ),
                backend_host: "backend.internal".to_string(),
                backend_port: 8443,
                backend_path: Some("/v2".to_string()),
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: crate::config::types::AuthMode::Single,
                plugins: vec![],
                pool_idle_timeout_seconds: None,
                pool_enable_http_keep_alive: None,
                pool_enable_http2: None,
                pool_tcp_keepalive_seconds: None,
                pool_http2_keep_alive_interval_seconds: None,
                pool_http2_keep_alive_timeout_seconds: None,
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: crate::config::types::ResponseBodyMode::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                created_at: now,
                updated_at: now,
            };

            let doc = proxy_to_doc(&proxy).expect("proxy_to_doc should succeed");
            // Verify _id was set
            assert_eq!(doc.get_str("_id").unwrap(), "test-proxy");

            let restored = doc_to_proxy(doc).expect("doc_to_proxy should succeed");
            assert_eq!(restored.id, proxy.id);
            assert_eq!(restored.name, proxy.name);
            assert_eq!(restored.hosts, proxy.hosts);
            assert_eq!(restored.listen_path, proxy.listen_path);
            assert_eq!(restored.backend_host, proxy.backend_host);
            assert_eq!(restored.backend_port, proxy.backend_port);
            assert_eq!(restored.backend_path, proxy.backend_path);
            assert_eq!(restored.strip_listen_path, proxy.strip_listen_path);
        }

        #[test]
        fn consumer_bson_round_trip() {
            let now = chrono::Utc::now();
            let consumer = Consumer {
                id: "consumer-1".to_string(),
                namespace: crate::config::types::default_namespace(),
                username: "alice".to_string(),
                custom_id: Some("ext-alice".to_string()),
                credentials: std::collections::HashMap::new(),
                acl_groups: vec!["group-a".to_string(), "group-b".to_string()],
                created_at: now,
                updated_at: now,
            };

            let doc = consumer_to_doc(&consumer).expect("consumer_to_doc should succeed");
            assert_eq!(doc.get_str("_id").unwrap(), "consumer-1");

            let restored = doc_to_consumer(doc).expect("doc_to_consumer should succeed");
            assert_eq!(restored.id, consumer.id);
            assert_eq!(restored.username, consumer.username);
            assert_eq!(restored.custom_id, consumer.custom_id);
            assert_eq!(restored.acl_groups, consumer.acl_groups);
        }

        #[test]
        fn plugin_config_bson_round_trip() {
            let now = chrono::Utc::now();
            let pc = PluginConfig {
                id: "plugin-1".to_string(),
                namespace: crate::config::types::default_namespace(),
                plugin_name: "rate_limiting".to_string(),
                enabled: true,
                config: serde_json::json!({
                    "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
                }),
                scope: crate::config::types::PluginScope::Proxy,
                proxy_id: Some("proxy-1".to_string()),
                priority_override: Some(500),
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            };

            let doc = plugin_config_to_doc(&pc).expect("plugin_config_to_doc should succeed");
            assert_eq!(doc.get_str("_id").unwrap(), "plugin-1");

            let restored = doc_to_plugin_config(doc).expect("doc_to_plugin_config should succeed");
            assert_eq!(restored.id, pc.id);
            assert_eq!(restored.plugin_name, pc.plugin_name);
            assert_eq!(restored.enabled, pc.enabled);
            assert_eq!(restored.proxy_id, pc.proxy_id);
            assert_eq!(restored.priority_override, pc.priority_override);
        }

        #[test]
        fn upstream_bson_round_trip() {
            let now = chrono::Utc::now();
            let upstream = Upstream {
                id: "upstream-1".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: Some("my-upstream".to_string()),
                algorithm: crate::config::types::LoadBalancerAlgorithm::RoundRobin,
                targets: vec![crate::config::types::UpstreamTarget {
                    host: "target1.example.com".to_string(),
                    port: 8080,
                    service_port_policy_key: None,
                    weight: 100,
                    tags: std::collections::HashMap::new(),
                    locality: None,
                    path: None,
                }],
                health_checks: None,
                hash_on: None,
                hash_on_cookie_config: None,
                service_discovery: None,
                subsets: None,
                port_overrides: std::collections::HashMap::new(),
                source_locality: None,
                locality_lb_strict: false,
                locality_lb_setting: None,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                backend_tls_sni: Some("reviews.mesh.internal".to_string()),
                backend_tls_san_allow_list: vec![
                    "reviews.mesh.internal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                ],
                resolved_subset_tls: std::collections::HashMap::new(),
                dispatch_port_override_fallback: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            };

            let doc = upstream_to_doc(&upstream).expect("upstream_to_doc should succeed");
            assert_eq!(doc.get_str("_id").unwrap(), "upstream-1");

            let restored = doc_to_upstream(doc).expect("doc_to_upstream should succeed");
            assert_eq!(restored.id, upstream.id);
            assert_eq!(restored.name, upstream.name);
            assert_eq!(restored.targets.len(), 1);
            assert_eq!(restored.targets[0].host, "target1.example.com");
            assert_eq!(restored.targets[0].port, 8080);
            assert_eq!(restored.targets[0].weight, 100);
            assert_eq!(
                restored.backend_tls_sni.as_deref(),
                Some("reviews.mesh.internal")
            );
            assert_eq!(
                restored.backend_tls_san_allow_list,
                vec![
                    "reviews.mesh.internal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                ]
            );
        }

        #[test]
        fn proxy_to_doc_sets_id_field() {
            let now = chrono::Utc::now();
            let proxy = Proxy {
                id: "unique-id-123".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/".to_string()),
                backend_scheme: Some(crate::config::types::BackendScheme::Http),
                dispatch_kind: crate::config::types::DispatchKind::from(
                    crate::config::types::BackendScheme::Http,
                ),
                backend_host: "localhost".to_string(),
                backend_port: 80,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: crate::config::types::AuthMode::Single,
                plugins: vec![],
                pool_idle_timeout_seconds: None,
                pool_enable_http_keep_alive: None,
                pool_enable_http2: None,
                pool_tcp_keepalive_seconds: None,
                pool_http2_keep_alive_interval_seconds: None,
                pool_http2_keep_alive_timeout_seconds: None,
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: crate::config::types::ResponseBodyMode::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                created_at: now,
                updated_at: now,
            };
            let doc = proxy_to_doc(&proxy).unwrap();
            // The _id should be set to the proxy id
            assert_eq!(doc.get_str("_id").unwrap(), "unique-id-123");
            // The original id field should also be present (BSON serialization includes it)
            assert_eq!(doc.get_str("id").unwrap(), "unique-id-123");
        }

        #[test]
        fn run_migrations_declares_proxy_plugin_cleanup_indexes() {
            let source = include_str!("mongo_store.rs");
            assert!(
                source.contains(r#""plugins.plugin_config_id": 1"#),
                "MongoDB must index proxy plugin associations for orphan cleanup"
            );
            assert!(
                source.contains(r#""scope": 1, "_id": 1"#),
                "MongoDB must have a scope-leading plugin_configs index for proxy_group cleanup"
            );
        }

        #[test]
        fn run_migrations_declares_unique_consumer_credential_indexes() {
            let source = include_str!("mongo_store.rs");
            assert!(
                source.contains(r#""credentials.keyauth.key": 1"#)
                    && source.contains(r#""credentials.mtls_auth.identity": 1"#)
                    && source.contains(".unique(true)"),
                "MongoDB must enforce keyauth and mTLS credential uniqueness with indexes"
            );
        }

        /// Regression guard for the MongoDB unique+sparse index on
        /// `{namespace, name}` and `{namespace, listen_port}`. MongoDB treats
        /// explicit `null` as a valid indexed value, so two HTTP proxies in
        /// the same namespace (both `name: None`, both `listen_port: None`)
        /// would collide with `E11000 duplicate key error`. `proxy_to_doc`
        /// strips these fields so the sparse index actually skips them.
        #[test]
        fn proxy_to_doc_strips_null_sparse_index_fields() {
            let now = chrono::Utc::now();
            let proxy = Proxy {
                id: "http-proxy".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: None,        // must NOT appear in the document
                listen_port: None, // must NOT appear in the document
                hosts: vec![],
                listen_path: Some("/".to_string()),
                backend_scheme: Some(crate::config::types::BackendScheme::Http),
                dispatch_kind: crate::config::types::DispatchKind::from(
                    crate::config::types::BackendScheme::Http,
                ),
                backend_host: "localhost".to_string(),
                backend_port: 80,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: crate::config::types::AuthMode::Single,
                plugins: vec![],
                pool_idle_timeout_seconds: None,
                pool_enable_http_keep_alive: None,
                pool_enable_http2: None,
                pool_tcp_keepalive_seconds: None,
                pool_http2_keep_alive_interval_seconds: None,
                pool_http2_keep_alive_timeout_seconds: None,
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: crate::config::types::ResponseBodyMode::default(),
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                created_at: now,
                updated_at: now,
            };
            let doc = proxy_to_doc(&proxy).unwrap();
            assert!(
                doc.get("name").is_none(),
                "`name` must be absent (not null) when Proxy.name is None: {:?}",
                doc.get("name")
            );
            assert!(
                doc.get("listen_port").is_none(),
                "`listen_port` must be absent (not null) when Proxy.listen_port is None: {:?}",
                doc.get("listen_port")
            );
            // But a present name should survive round-trip.
            let mut with_name = proxy.clone();
            with_name.name = Some("my-proxy".to_string());
            let doc2 = proxy_to_doc(&with_name).unwrap();
            assert_eq!(doc2.get_str("name").unwrap(), "my-proxy");
        }

        #[test]
        fn consumer_to_doc_strips_null_custom_id() {
            let now = chrono::Utc::now();
            let consumer = Consumer {
                id: "c-1".to_string(),
                namespace: crate::config::types::default_namespace(),
                username: "alice".to_string(),
                custom_id: None, // must NOT appear in the document
                credentials: std::collections::HashMap::new(),
                acl_groups: vec![],
                created_at: now,
                updated_at: now,
            };
            let doc = consumer_to_doc(&consumer).unwrap();
            assert!(
                doc.get("custom_id").is_none(),
                "`custom_id` must be absent when Consumer.custom_id is None"
            );
        }

        #[test]
        fn upstream_to_doc_strips_null_name() {
            let now = chrono::Utc::now();
            let upstream = Upstream {
                id: "u-1".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: None, // must NOT appear in the document
                targets: vec![],
                algorithm: crate::config::types::LoadBalancerAlgorithm::RoundRobin,
                hash_on: None,
                hash_on_cookie_config: None,
                health_checks: None,
                service_discovery: None,
                subsets: None,
                port_overrides: std::collections::HashMap::new(),
                source_locality: None,
                locality_lb_strict: false,
                locality_lb_setting: None,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                backend_tls_sni: None,
                backend_tls_san_allow_list: Vec::new(),
                resolved_subset_tls: std::collections::HashMap::new(),
                dispatch_port_override_fallback: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            };
            let doc = upstream_to_doc(&upstream).unwrap();
            assert!(
                doc.get("name").is_none(),
                "`name` must be absent when Upstream.name is None"
            );
        }

        #[test]
        fn consumer_with_credentials_round_trip() {
            let now = chrono::Utc::now();
            let mut credentials = std::collections::HashMap::new();
            credentials.insert(
                "key_auth".to_string(),
                serde_json::json!({"key": "my-api-key-123"}),
            );
            credentials.insert(
                "basic_auth".to_string(),
                serde_json::json!({"username": "alice", "password_hash": "abc123"}),
            );

            let consumer = Consumer {
                id: "consumer-with-creds".to_string(),
                namespace: crate::config::types::default_namespace(),
                username: "alice".to_string(),
                custom_id: None,
                credentials,
                acl_groups: vec![],
                created_at: now,
                updated_at: now,
            };

            let doc = consumer_to_doc(&consumer).unwrap();
            let restored = doc_to_consumer(doc).unwrap();
            assert_eq!(restored.credentials.len(), 2);
            assert!(restored.credentials.contains_key("key_auth"));
            assert!(restored.credentials.contains_key("basic_auth"));
        }

        #[test]
        fn proxy_with_plugin_associations_round_trip() {
            let now = chrono::Utc::now();
            let proxy = Proxy {
                id: "proxy-with-plugins".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/test".to_string()),
                backend_scheme: Some(crate::config::types::BackendScheme::Http),
                dispatch_kind: crate::config::types::DispatchKind::from(
                    crate::config::types::BackendScheme::Http,
                ),
                backend_host: "backend.local".to_string(),
                backend_port: 8080,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: crate::config::types::AuthMode::Single,
                plugins: vec![
                    PluginAssociation {
                        plugin_config_id: "plugin-a".to_string(),
                    },
                    PluginAssociation {
                        plugin_config_id: "plugin-b".to_string(),
                    },
                ],
                pool_idle_timeout_seconds: None,
                pool_enable_http_keep_alive: None,
                pool_enable_http2: None,
                pool_tcp_keepalive_seconds: None,
                pool_http2_keep_alive_interval_seconds: None,
                pool_http2_keep_alive_timeout_seconds: None,
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                upstream_id: Some("my-upstream".to_string()),
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: crate::config::types::ResponseBodyMode::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                created_at: now,
                updated_at: now,
            };

            let doc = proxy_to_doc(&proxy).unwrap();
            let restored = doc_to_proxy(doc).unwrap();
            assert_eq!(restored.plugins.len(), 2);
            assert_eq!(restored.plugins[0].plugin_config_id, "plugin-a");
            assert_eq!(restored.plugins[1].plugin_config_id, "plugin-b");
            assert_eq!(restored.upstream_id, Some("my-upstream".to_string()));
        }

        // -------------------------------------------------------------------
        // Failover reconnect tests
        //
        // These tests exercise the runtime client-replacement path
        // introduced when `try_failover_reconnect` was promoted from a
        // no-op ping into an actual `Client` rebuild + atomic swap. Earlier
        // versions ignored the URL parameter and just pinged the (already
        // dead) primary, so failover never actually happened for
        // standalone MongoDB deployments.
        //
        // We build a `MongoStore` whose `db` and `client` ArcSwaps point at
        // a `Client` constructed against a non-routable URL. `Client::with_options`
        // does NOT connect (the driver is lazy — the first command triggers
        // the real handshake), so this works without a live MongoDB.
        // -------------------------------------------------------------------

        /// Construct a `MongoStore` directly without going through `connect()`,
        /// bypassing the startup ping. The resulting store has a Client that
        /// will fail on any real command, but its ArcSwap pointers are valid
        /// — which is all the failover tests need to verify the swap path.
        fn make_test_store(failover_urls: Vec<String>) -> MongoStore {
            let settings = MongoConnSettings {
                database_name: "test".to_string(),
                app_name: None,
                replica_set: None,
                auth_mechanism: None,
                server_selection_timeout_secs: 1,
                connect_timeout_secs: 1,
                tls_enabled: false,
                tls_ca_cert_path: None,
                tls_client_cert_path: None,
                tls_client_key_path: None,
                tls_insecure: false,
            };
            // Build a client against a non-routable URL. `Client::with_options`
            // is lazy — no connection is attempted here.
            let opts = mongodb::options::ClientOptions::builder()
                .hosts(vec![])
                .build();
            let client = mongodb::Client::with_options(opts)
                .expect("Client::with_options should accept empty hosts");
            let db = client.database(&settings.database_name);
            MongoStore {
                client: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(client)),
                db: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(db)),
                conn_settings: settings,
                db_type_str: "mongodb".to_string(),
                slow_query_threshold_ms: None,
                cert_expiry_warning_days: 30,
                backend_allow_ips: crate::config::BackendAllowIps::Both,
                failover_urls,
                replica_set_configured: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                    false,
                )),
            }
        }

        /// Both primary and every failover URL are unroutable — `try_failover_reconnect`
        /// must surface a final error and not silently report success.
        ///
        /// Regression guard: the pre-fix implementation called `reconnect()` for
        /// every URL, which only pinged the existing client. If the existing
        /// client happened to be alive at that moment, every "failover" attempt
        /// reported success even though no actual rebuild had taken place.
        #[tokio::test(flavor = "current_thread")]
        async fn try_failover_reconnect_returns_err_when_all_urls_unroutable() {
            // 240.0.0.1 is in the reserved 240/4 block — no host will ever
            // route to it, so `ClientOptions::parse` succeeds but the
            // subsequent ping inside `build_client_and_db` fails fast
            // (bounded by `server_selection_timeout_secs = 1`).
            let store = make_test_store(vec![
                "mongodb://240.0.0.1:27017/test".to_string(),
                "mongodb://240.0.0.2:27017/test".to_string(),
            ]);

            let result = store
                .try_failover_reconnect("mongodb://240.0.0.3:27017/test")
                .await;

            assert!(
                result.is_err(),
                "try_failover_reconnect must return Err when every URL is unreachable, \
                 not silently succeed by pinging the cached client"
            );
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("All MongoDB URLs failed"),
                "expected 'All MongoDB URLs failed' in error, got: {}",
                err
            );
            assert!(
                err.contains("2 failover URL(s) tried"),
                "expected error to mention failover-url count, got: {}",
                err
            );
        }

        /// Empty failover list and unroutable primary — error must mention
        /// zero failovers tried (proves we didn't hallucinate attempts).
        #[tokio::test(flavor = "current_thread")]
        async fn try_failover_reconnect_no_failovers_returns_clean_err() {
            let store = make_test_store(vec![]);
            let result = store
                .try_failover_reconnect("mongodb://240.0.0.1:27017/test")
                .await;

            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("0 failover URL(s) tried"),
                "expected error to report zero failovers, got: {}",
                err
            );
        }

        /// White-box check that successful `reconnect()` actually replaces
        /// the underlying `Client` and `Database` handles. Earlier code held
        /// `client: Client` and `db: Database` directly and the trait's
        /// `&self` receiver made replacement impossible — every "reconnect"
        /// just pinged the old client, so a genuinely-down standalone
        /// MongoDB deployment would never recover.
        ///
        /// We can't run a real reconnect without a live MongoDB, so this
        /// test simulates a successful rebuild by directly swapping new
        /// Client + Database handles into the ArcSwap fields and verifies
        /// `db()` returns the new handle. If somebody re-introduces a
        /// `client: Client` / `db: Database` field (or makes `db()` return
        /// the original startup handle), this test fails to compile or
        /// returns the wrong namespace.
        #[tokio::test(flavor = "current_thread")]
        async fn db_accessor_reflects_swapped_handle() {
            let store = make_test_store(vec![]);

            // Build a "fresh" client+db pretending failover succeeded.
            let opts = mongodb::options::ClientOptions::builder()
                .hosts(vec![])
                .build();
            let new_client = mongodb::Client::with_options(opts).unwrap();
            let new_db = new_client.database("after_failover");

            // Confirm the accessor sees the original namespace before the swap.
            assert_eq!(store.db().name(), "test");

            // Swap in the new handles (mirrors what `reconnect()` does on success).
            store.db.store(std::sync::Arc::new(new_db));
            store.client.store(std::sync::Arc::new(new_client));

            // Accessor must now return the swapped handle. If it kept a
            // captured copy of the original `db` field (the pre-fix bug),
            // this assertion fails.
            assert_eq!(
                store.db().name(),
                "after_failover",
                "db() must reflect the swapped handle — collection accessors \
                 (proxies/consumers/plugin_configs/upstreams) all flow through \
                 db(), so a stale handle would mean every read still goes to \
                 the dead primary even after a successful reconnect"
            );
        }

        // -------------------------------------------------------------------
        // Replica-set / transactional-path detection
        // -------------------------------------------------------------------

        #[test]
        fn resolve_replica_set_configured_none_means_standalone() {
            assert!(!resolve_replica_set_configured(None));
        }

        #[test]
        fn resolve_replica_set_configured_empty_string_treated_as_unset() {
            assert!(!resolve_replica_set_configured(Some("")));
        }

        #[test]
        fn resolve_replica_set_configured_named_replica_set_enables_transactions() {
            assert!(resolve_replica_set_configured(Some("rs0")));
            assert!(resolve_replica_set_configured(Some("ferrum-cluster")));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn api_spec_replica_set_helper_uses_atomic_state() {
            let store = make_test_store(vec![]);

            assert!(
                !store.replica_set_configured(),
                "fresh test store should default to standalone MongoDB semantics"
            );

            store.replica_set_configured.store(true, Ordering::Release);

            assert!(
                store.replica_set_configured(),
                "API-spec transaction branch detection must follow the atomic \
                 replica-set state updated by connect/reconnect, not db_type_str"
            );
            assert_eq!(
                store.db_type_str, "mongodb",
                "db_type_str intentionally remains the backend name and must not \
                 be the replica-set source of truth"
            );
        }

        // -------------------------------------------------------------------
        // delete_proxy / update_proxy / api-spec step-order regression guards
        // -------------------------------------------------------------------

        #[test]
        fn delete_proxy_sequential_order_proxy_first() {
            assert_eq!(
                DELETE_PROXY_SEQUENTIAL_ORDER,
                &[
                    "delete_proxy_document",
                    "delete_proxy_scoped_plugin_configs",
                    "cleanup_orphaned_proxy_group_plugins",
                ],
                "delete_proxy must delete the proxy document BEFORE its plugin_configs \
                 so a partial failure can't leave a dangling-reference proxy in the DB"
            );
        }

        #[test]
        fn delete_proxy_sequential_order_first_step_is_proxy() {
            assert_eq!(
                DELETE_PROXY_SEQUENTIAL_ORDER.first().copied(),
                Some("delete_proxy_document"),
                "delete_proxy MUST start by removing the proxy document"
            );
        }

        #[test]
        fn delete_proxy_standalone_implementation_deletes_proxy_before_plugins() {
            let source = include_str!("mongo_store.rs");
            let standalone_start = source
                .find("// Non-replica-set best-effort path.")
                .expect("standalone delete_proxy marker");
            let standalone_path = &source[standalone_start..];
            let proxy_delete = standalone_path
                .find("let result = self.proxies().delete_one")
                .expect("standalone proxy delete call");
            let plugin_cleanup = standalone_path
                .find("self.plugin_configs()")
                .expect("standalone plugin config cleanup call");
            assert!(
                proxy_delete < plugin_cleanup,
                "standalone delete_proxy must delete the proxy document before \
                 proxy-scoped plugin_configs so partial failure leaves a \
                 runtime-safe database shape"
            );
        }

        #[test]
        fn update_proxy_sequential_order_replace_then_cleanup() {
            assert_eq!(
                UPDATE_PROXY_SEQUENTIAL_ORDER,
                &[
                    "replace_proxy_document",
                    "cleanup_orphaned_proxy_group_plugins",
                ],
                "update_proxy must replace the proxy document BEFORE cleaning up \
                 orphan proxy_group plugin_configs so the cleanup observes the new \
                 plugins.plugin_config_id references"
            );
        }

        #[test]
        fn replace_api_spec_standalone_delete_order_proxy_first() {
            assert_eq!(
                REPLACE_API_SPEC_STANDALONE_DELETE_ORDER,
                &[
                    "delete_proxy_document",
                    "delete_spec_owned_plugin_configs",
                    "delete_spec_owned_upstreams",
                    "delete_api_spec_document",
                ],
                "standalone replace_api_spec_bundle must delete the proxy before \
                 dependencies so partial failures leave no live dangling route"
            );
        }

        #[test]
        fn replace_api_spec_standalone_implementation_deletes_proxy_before_plugins() {
            let source = include_str!("mongo_store.rs");
            let standalone_start = source
                .find("// Delete the live proxy first and fail closed if that cannot")
                .expect("standalone replace_api_spec delete marker");
            let standalone_path = &source[standalone_start..];
            let proxy_delete = standalone_path
                .find("self\n                    .proxies()\n                    .delete_one")
                .expect("standalone replace proxy delete call");
            let plugin_cleanup = standalone_path
                .find(
                    "self\n                    .plugin_configs()\n                    .delete_many",
                )
                .expect("standalone replace plugin cleanup call");
            assert!(
                proxy_delete < plugin_cleanup,
                "standalone replace_api_spec_bundle must remove the proxy before \
                 deleting plugin_configs"
            );
        }

        #[test]
        fn replace_api_spec_standalone_preflights_ids_before_destructive_delete() {
            let source = include_str!("mongo_store.rs");
            let standalone_start = source
                .find("// Build every replacement document and preflight primary-key")
                .expect("standalone replace_api_spec preflight marker");
            let standalone_path = &source[standalone_start..];
            let prepare = standalone_path
                .find("let prepared_docs = prepare_api_spec_bundle_docs")
                .expect("standalone replace must build replacement docs before delete");
            let preflight = standalone_path
                .find("ensure_api_spec_standalone_replace_ids_available")
                .expect("standalone replace must preflight replacement ids before delete");
            let proxy_delete = standalone_path
                .find("self\n                    .proxies()\n                    .delete_one")
                .expect("standalone replace proxy delete call");
            assert!(
                prepare < preflight && preflight < proxy_delete,
                "standalone replace_api_spec_bundle must build replacement docs \
                 and preflight id ownership before deleting the live proxy"
            );
        }

        #[test]
        fn delete_api_spec_standalone_order_proxy_first() {
            assert_eq!(
                DELETE_API_SPEC_STANDALONE_ORDER,
                &[
                    "delete_proxy_document",
                    "delete_spec_owned_plugin_configs",
                    "delete_proxy_scoped_plugin_configs",
                    "cleanup_orphaned_proxy_group_plugins",
                    "delete_spec_owned_upstreams",
                    "delete_api_spec_document",
                ],
                "standalone delete_api_spec must delete the proxy before \
                 plugin cleanup so partial failures stay runtime-safe"
            );
        }

        #[test]
        fn delete_api_spec_standalone_implementation_deletes_proxy_before_plugins() {
            let source = include_str!("mongo_store.rs");
            let delete_api_spec_start = source
                .find("async fn delete_api_spec(&self, namespace: &str, id: &str)")
                .expect("delete_api_spec function");
            let standalone_start = source[delete_api_spec_start..]
                .find("// No replica set: best-effort deletes.")
                .map(|idx| delete_api_spec_start + idx)
                .expect("standalone delete_api_spec marker");
            let standalone_path = &source[standalone_start..];
            let proxy_delete = standalone_path
                .find("self.proxies()\n                        .delete_one")
                .expect("standalone delete_api_spec proxy delete call");
            let plugin_cleanup = standalone_path
                .find(
                    "self\n                    .plugin_configs()\n                    .delete_many",
                )
                .expect("standalone delete_api_spec plugin cleanup call");
            assert!(
                proxy_delete < plugin_cleanup,
                "standalone delete_api_spec must remove the proxy before \
                 deleting plugin_configs"
            );
        }

        #[test]
        fn api_spec_standalone_insert_order_dependencies_before_proxy() {
            assert_eq!(
                API_SPEC_STANDALONE_INSERT_ORDER,
                &[
                    "insert_upstream_document",
                    "insert_plugin_config_documents",
                    "insert_proxy_document",
                    "insert_api_spec_document",
                ],
                "standalone api-spec bundle writes must create dependencies before \
                 the proxy document becomes pollable"
            );
        }

        #[test]
        fn submit_api_spec_standalone_implementation_inserts_plugins_before_proxy() {
            let source = include_str!("mongo_store.rs");
            let standalone_start = source
                .find("// No replica set: best-effort with compensating rollback on failure.")
                .expect("standalone submit_api_spec marker");
            let standalone_path = &source[standalone_start..];
            let plugin_insert = standalone_path
                .find("self.plugin_configs().insert_one(doc).await")
                .expect("standalone submit plugin insert");
            let proxy_insert = standalone_path
                .find("self.proxies().insert_one(doc).await")
                .expect("standalone submit proxy insert");
            assert!(
                plugin_insert < proxy_insert,
                "standalone submit_api_spec_bundle must insert plugin_configs before \
                 the proxy so a partial insert cannot expose a proxy with missing plugins"
            );
        }

        #[test]
        fn replace_api_spec_standalone_reinsert_implementation_inserts_plugins_before_proxy() {
            let source = include_str!("mongo_store.rs");
            let reinsert_start = source
                .find("// Re-insert new bundle with manual associations preserved.")
                .expect("standalone replace_api_spec reinsert marker");
            let reinsert_path = &source[reinsert_start..];
            let plugin_insert = reinsert_path
                .find("self.plugin_configs().insert_one(doc).await")
                .expect("standalone replace plugin insert");
            let proxy_insert = reinsert_path
                .find("self.proxies().insert_one(doc).await")
                .expect("standalone replace proxy insert");
            assert!(
                plugin_insert < proxy_insert,
                "standalone replace_api_spec_bundle must reinsert plugin_configs before \
                 the proxy so a partial reinsert cannot expose a proxy with missing plugins"
            );
        }

        #[test]
        fn compensate_bundle_insert_order_proxy_before_dependencies() {
            assert_eq!(
                COMPENSATE_BUNDLE_INSERT_ORDER,
                &[
                    "delete_api_spec_document",
                    "delete_proxy_document",
                    "delete_plugin_config_documents",
                    "delete_upstream_document",
                ],
                "compensating rollback must remove the proxy before dependencies"
            );
        }

        #[test]
        fn compensate_bundle_insert_implementation_deletes_proxy_before_plugins() {
            let source = include_str!("mongo_store.rs");
            let compensate_start = source
                .find("async fn compensate_bundle_insert(")
                .expect("compensate_bundle_insert function");
            let compensate_path = &source[compensate_start..];
            let proxy_delete = compensate_path
                .find("self.proxies().delete_one")
                .expect("compensating proxy delete");
            let plugin_delete = compensate_path
                .find("self.plugin_configs().delete_one")
                .expect("compensating plugin delete");
            assert!(
                proxy_delete < plugin_delete,
                "compensating rollback must delete the proxy before plugin_configs"
            );
        }

        #[test]
        fn delete_proxy_guards_external_spec_upstream_refs_before_spec_upstream_delete() {
            let source = include_str!("mongo_store.rs");
            let delete_proxy_start = source
                .find("async fn delete_proxy(&self, id: &str)")
                .expect("delete_proxy function");
            let delete_proxy_body = &source[delete_proxy_start..];
            let guard = delete_proxy_body
                .find("ensure_no_external_spec_upstream_refs")
                .expect("delete_proxy guard call");
            let upstream_delete = delete_proxy_body
                .find("\"api_spec_id\": sid")
                .expect("delete_proxy spec-owned upstream delete");
            assert!(
                guard < upstream_delete,
                "delete_proxy must guard external references before deleting \
                 upstreams tagged with the spec id"
            );
        }

        #[test]
        fn update_paths_preserve_api_spec_id_in_replacement_doc() {
            let source = include_str!("mongo_store.rs");
            let update_proxy_start = source
                .find("async fn update_proxy(&self, proxy: &Proxy)")
                .expect("update_proxy function");
            let update_proxy_body = &source[update_proxy_start..];
            let insert_tag = update_proxy_body
                .find("doc.insert(\"api_spec_id\", sid);")
                .expect("update_proxy must insert api_spec_id into replacement doc");
            let replace = update_proxy_body
                .find(".replace_one")
                .expect("update_proxy replace_one call");
            assert!(
                insert_tag < replace,
                "update_proxy must carry api_spec_id into the replacement document \
                 before replace_one, not restore it afterward"
            );

            let update_plugin_start = source
                .find("async fn update_plugin_config(&self, pc: &PluginConfig)")
                .expect("update_plugin_config function");
            let update_plugin_body = &source[update_plugin_start..];
            assert!(
                update_plugin_body
                    .find("doc.insert(\"api_spec_id\", sid);")
                    .is_some(),
                "update_plugin_config must preserve api_spec_id in the replacement doc"
            );

            let update_upstream_start = source
                .find("async fn update_upstream(&self, upstream: &Upstream)")
                .expect("update_upstream function");
            let update_upstream_body = &source[update_upstream_start..];
            assert!(
                update_upstream_body
                    .find("doc.insert(\"api_spec_id\", sid);")
                    .is_some(),
                "update_upstream must preserve api_spec_id in the replacement doc"
            );
        }
    }
}

pub use inner::MongoStore;
