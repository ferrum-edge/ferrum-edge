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
//! `id` field. Consumers are the exception: their `_id` is the composite
//! `"{namespace}:{id}"` (see [`consumer_doc_id`]) so consumer ids are unique
//! per namespace rather than globally. Plugin associations are embedded in
//! the proxy document's `plugins` array (no junction table needed — unlike
//! the relational model).
//!
//! **Full loads and incremental polling**: Replica-set full loads use a
//! snapshot transaction so the runtime config is read from one multi-collection
//! view. Standalone deployments cannot provide multi-collection snapshots, so
//! they use sequential primary reads and only reject inconsistencies caught by
//! the runtime load validation path. Replica-set incremental polling reads
//! durable `config_changes` documents after the accepted sequence cursor and
//! point-loads changed resource IDs, except that consumer changes force a full
//! reload to rehydrate any runtime-quarantined credentials. Standalone
//! deployments force full reloads for every change because resource writes and
//! change records are not transactionally coupled.
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
        ApiSpecListFilter, ApiSpecSortBy, BatchConfigWriteMode, DatabaseBackend,
        DeleteAllResourcesError, DeleteMode, FullConfigLoadPurpose, IncrementalResult,
        MtlsDnsAdmissionUnavailable, MtlsDnsIdentityConflict, NamespaceConfigAdmissionLeaseBackend,
        NamespaceResourceCounts, NamespacedResourceId, PROXY_ROUTE_CONFLICT_ERROR, PaginatedResult,
        SnapshotDataIntegrityError, SortOrder, TcpConnectionThrottleAttachmentConflict,
    };
    use crate::config::db_loader::{credential_value_hash, proxy_route_key_hash};
    use crate::config::types::{
        ApiSpec, Consumer, GatewayConfig, PluginAssociation, PluginConfig, PluginScope, Proxy,
        Upstream,
    };
    use crate::config::validation_pipeline::{
        ValidationAction, collect_rejecting_runtime_config_errors,
        validate_plugin_file_dependencies_off_thread,
    };
    use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;
    use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
    use anyhow::Context;
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use dashmap::DashMap;
    use mongodb::bson::{
        Binary, Bson, DateTime as BsonDateTime, Document, doc, spec::BinarySubtype,
    };
    use mongodb::options::{
        ClientOptions, FindOptions, IndexOptions, ReadConcern, ReadPreference, ReturnDocument,
        SelectionCriteria, Tls, TlsOptions, WriteConcern,
    };
    use mongodb::{Client, ClientSession, Collection, Database, IndexModel};
    use std::collections::HashSet;
    use std::future::Future;
    use std::io::Write;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tracing::{debug, error, info, warn};
    use uuid::Uuid;
    use zeroize::Zeroizing;
    // regex::escape is used for safe MongoDB $regex pattern construction in list filters.
    use regex::escape as regex_escape;

    // MongoDB server error codes used by the index-upgrade logic in
    // `run_migrations`. Source: src/mongo/db/operation_exit_code.idl (server)
    // and https://www.mongodb.com/docs/manual/reference/error-codes/.
    const MONGO_ERR_INDEX_NOT_FOUND: i32 = 27;
    const MONGO_ERR_NAMESPACE_EXISTS: i32 = 48;
    const MONGO_ERR_INDEX_ALREADY_EXISTS: i32 = 68;
    const MONGO_ERR_INDEX_OPTIONS_CONFLICT: i32 = 85;
    const MONGO_ERR_INDEX_KEY_SPECS_CONFLICT: i32 = 86;
    const MONGO_ERR_DUPLICATE_KEY: i32 = 11_000;
    const CHANGE_LOG_BATCH_LIMIT: i64 = 10_000;
    const CHANGE_LOG_RETAIN_PER_NAMESPACE: u64 = 100_000;
    const MONGO_MIGRATION_LOCK_ID: &str = "global";
    const MONGO_MIGRATION_LEASE_DURATION: Duration = Duration::from_secs(120);
    const MONGO_MIGRATION_LEASE_DURATION_MILLIS: i64 =
        MONGO_MIGRATION_LEASE_DURATION.as_millis() as i64;
    const MONGO_MIGRATION_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(30);
    const MONGO_MIGRATION_LEASE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
    const CONFIG_ADMISSION_LEASE_DURATION_MILLIS: i64 = 120_000;
    const MONGO_ADMISSION_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(120);
    const HMAC_SECRET_HASHES_FIELD: &str = "_ferrum_hmac_secret_hashes";
    // Dedicated migration-lease pool size. Lease upkeep only issues tiny
    // update_one/delete_one operations, so a couple of connections is ample
    // while keeping the lease client fully isolated from the migration-work
    // pool that may be saturated by a long-running create_index.
    const MONGO_MIGRATION_LEASE_POOL_SIZE: u32 = 2;

    #[derive(Clone, Copy)]
    struct ConfigChangeWrite<'a> {
        namespace: &'a str,
        resource_type: &'a str,
        resource_id: &'a str,
        operation: &'a str,
    }

    /// Proxy fields needed by the transactional admission guards
    /// (route-bucket lock + uniqueness re-check + upstream reference guard),
    /// extracted once so transaction closures don't clone the whole `Proxy`.
    #[derive(Clone)]
    struct ProxyWriteGuardParams {
        namespace: String,
        listen_path: Option<String>,
        hosts: Vec<String>,
        /// Stream schemes (tcp/tcps/udp/dtls) skip route-bucket enforcement —
        /// they route on `listen_port` and have `check_listen_port_unique`.
        is_stream: bool,
        upstream_id: Option<String>,
    }

    impl ProxyWriteGuardParams {
        fn from_proxy(proxy: &Proxy) -> Self {
            Self {
                namespace: proxy.namespace.clone(),
                listen_path: proxy.listen_path.clone(),
                hosts: proxy.hosts.clone(),
                is_stream: proxy.effective_scheme().is_stream(),
                upstream_id: proxy.upstream_id.clone(),
            }
        }
    }

    /// One proxy in a (namespace, listen_path) route bucket, as needed by the
    /// standalone post-write route reconciliation.
    struct RouteBucketCandidate {
        id: String,
        hosts: Vec<String>,
        created_at: String,
    }

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

    fn is_namespace_exists(err: &mongodb::error::Error) -> bool {
        is_mongo_command_error_with_code(err, MONGO_ERR_NAMESPACE_EXISTS)
    }

    fn is_index_already_exists(err: &mongodb::error::Error) -> bool {
        is_mongo_command_error_with_code(err, MONGO_ERR_INDEX_ALREADY_EXISTS)
    }

    fn is_duplicate_key(err: &mongodb::error::Error) -> bool {
        if is_mongo_command_error_with_code(err, MONGO_ERR_DUPLICATE_KEY) {
            return true;
        }
        match err.kind.as_ref() {
            mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                write_error,
            )) if write_error.code == MONGO_ERR_DUPLICATE_KEY => true,
            mongodb::error::ErrorKind::InsertMany(insert_error) => {
                insert_error.write_errors.as_deref().is_some_and(|errors| {
                    errors
                        .iter()
                        .any(|write_error| write_error.code == MONGO_ERR_DUPLICATE_KEY)
                })
            }
            _ => false,
        }
    }

    /// Recognize an AWS DocumentDB rejection of an aggregation-pipeline-form
    /// update (an `update` supplied as an array of stages).
    ///
    /// DocumentDB is documented as MongoDB-compatible and supports aggregation
    /// *queries*, but it does NOT implement pipeline-form `findOneAndUpdate` /
    /// `updateOne`. When the primary `$$NOW` acquire pipeline is issued, a
    /// DocumentDB backend rejects the command up-front — before any lock
    /// document is touched — either as an unsupported feature or as a type/parse
    /// error because the update value is an array rather than an object.
    ///
    /// This check runs ONLY on the first acquire attempt in pipeline mode. A
    /// false positive merely moves that lease to the fully functional classic
    /// client-time path, while a false negative prevents DocumentDB migrations
    /// from starting at all, so matching is deliberately moderately broad while
    /// remaining restricted to Command errors that reference the update shape.
    /// Connectivity and duplicate-key contention use other ErrorKind/code paths
    /// and cannot trigger this capability fallback. A genuine MongoDB server
    /// accepts the pipeline and never reaches here.
    fn is_pipeline_update_unsupported(err: &mongodb::error::Error) -> bool {
        let mongodb::error::ErrorKind::Command(command_error) = err.kind.as_ref() else {
            return false;
        };
        let message = command_error.message.to_ascii_lowercase();
        let says_unsupported = message.contains("not supported") || message.contains("unsupported");
        let references_update = message.contains("update")
            || message.contains("pipeline")
            || message.contains("aggregation");
        let names_pipeline_form = message.contains("pipeline")
            || message.contains("aggregation")
            || (message.contains("update") && message.contains("array"));
        let names_value_type = message.contains("object") || message.contains("array");
        let says_type_error = message.contains("must be")
            || message.contains("expected")
            || message.contains("wrong type")
            || message.contains("badvalue")
            || message.contains("typemismatch");
        let has_pipeline_type_or_parse_code = matches!(command_error.code, 2 | 9 | 14);

        (says_unsupported && names_pipeline_form)
            || (references_update
                && ((says_type_error && names_value_type) || has_pipeline_type_or_parse_code))
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
        /// Explicit `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` override.
        /// `None` preserves the URI `serverSelectionTimeoutMS` value (or the
        /// driver default when the URI omits it).
        pub server_selection_timeout_secs: Option<u64>,
        /// Explicit `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` override.
        /// `None` preserves the URI `connectTimeoutMS` value (or the driver
        /// default when the URI omits it).
        pub connect_timeout_secs: Option<u64>,
        pub tls_enabled: bool,
        pub tls_ca_cert_path: Option<String>,
        pub tls_client_cert_path: Option<String>,
        pub tls_client_key_path: Option<String>,
        pub tls_insecure: bool,
    }

    /// Apply explicit Ferrum timeout overrides onto parsed `ClientOptions`.
    ///
    /// URI-parsed timeout values survive when the corresponding env override is
    /// unset (`None`). Only an explicitly supplied `FERRUM_MONGO_*_TIMEOUT_SECONDS`
    /// value replaces the URI/driver setting — mirroring `app_name` /
    /// `repl_set_name` precedence.
    pub(crate) fn apply_mongo_timeout_overrides(
        client_options: &mut ClientOptions,
        server_selection_timeout_secs: Option<u64>,
        connect_timeout_secs: Option<u64>,
    ) {
        if let Some(secs) = server_selection_timeout_secs {
            client_options.server_selection_timeout = Some(Duration::from_secs(secs));
        }
        if let Some(secs) = connect_timeout_secs {
            client_options.connect_timeout = Some(Duration::from_secs(secs));
        }
    }

    /// Decide whether multi-document transactions are available based on the
    /// effective replica set name (after any explicit override has been
    /// applied to `ClientOptions::repl_set_name`).
    fn resolve_replica_set_configured(repl_set_name: Option<&str>) -> bool {
        matches!(repl_set_name, Some(name) if !name.is_empty())
    }

    struct MaterializedTlsPath {
        path: PathBuf,
        temp_path: Option<tempfile::TempPath>,
    }

    struct MongoConnectionBundle {
        client: Client,
        db: Database,
        // Reusable small-pool client for migration and admission lease upkeep.
        // It uses the same materialized TLS/read-preference options as the
        // primary client but cannot be starved by long-running datastore work.
        lease_client: Client,
        // Own generated TLS PEM files for exactly as long as this driver
        // client can open new sockets using their paths.
        _tls_temp_paths: Vec<tempfile::TempPath>,
    }

    /// How a renewable MongoDB migration lease stamps expiry timestamps.
    ///
    /// A lease picks its mode once, on the FIRST acquire attempt, and keeps it
    /// for its whole lifecycle so acquire, renew, and release stay consistent.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RenewableLeaseMode {
        /// Real MongoDB. Acquire/renew via aggregation-pipeline updates that
        /// evaluate expiry and stamp timestamps from MongoDB SERVER time
        /// (`$$NOW`), so client clock skew can never stomp an active lease.
        ServerTimePipeline,
        /// AWS DocumentDB fallback. DocumentDB is documented as MongoDB-
        /// compatible but does NOT support aggregation-pipeline-form updates, so
        /// acquire/renew use classic operator updates stamped from the CLIENT
        /// clock (`BsonDateTime::now()`). This reintroduces client-clock-skew
        /// sensitivity to the lease; that degradation is accepted ONLY for
        /// DocumentDB, where server-time updates are unavailable.
        ClientTimeClassic,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MongoLockMode {
        RenewableLease(RenewableLeaseMode),
        /// Security-sensitive admission mutex. It has no expiry and cannot be
        /// taken from a paused owner: only that owner's explicit release
        /// removes the document. A crashed owner therefore leaves a lock that
        /// must be removed by an operator after verifying the process is gone.
        UntilExplicitRelease,
    }

    /// Whether dropping a durable admission guard may remove its lock.
    ///
    /// A guard starts before any protected write exists, so cancellation while
    /// validating may clean up. Once a MongoDB mutation has been dispatched,
    /// an error or cancelled future cannot prove whether the server committed
    /// it; that state must retain both the datastore fence and the connection
    /// generation pin. Only an explicit `release()` call declares the outcome
    /// settled and authorizes owner-qualified cleanup (including a Drop retry).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DurableAdmissionMutationState {
        NotStarted,
        InFlightOrUncertain,
        Settled,
    }

    fn durable_admission_drop_must_retain(
        mode: MongoLockMode,
        state: DurableAdmissionMutationState,
    ) -> bool {
        mode == MongoLockMode::UntilExplicitRelease
            && state == DurableAdmissionMutationState::InFlightOrUncertain
    }

    /// Whether a returned MongoDB error leaves a dispatched write's durable
    /// outcome unknowable. Transaction errors labelled transient are
    /// definitive aborts unless the commit-result label is also present;
    /// standalone network/write-concern failures remain fail-closed.
    fn mongo_error_outcome_is_uncertain(error: &mongodb::error::Error) -> bool {
        if error.contains_label("UnknownTransactionCommitResult") {
            return true;
        }
        if error.contains_label("TransientTransactionError")
            || error.contains_label("NoWritesPerformed")
        {
            return false;
        }
        if error.contains_label("RetryableWriteError") {
            return true;
        }
        match error.kind.as_ref() {
            mongodb::error::ErrorKind::Io(_)
            | mongodb::error::ErrorKind::ConnectionPoolCleared { .. }
            | mongodb::error::ErrorKind::InvalidResponse { .. }
            | mongodb::error::ErrorKind::Shutdown => true,
            mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteConcernError(
                _,
            )) => true,
            mongodb::error::ErrorKind::InsertMany(error) => error.write_concern_error.is_some(),
            mongodb::error::ErrorKind::BulkWrite(error) => !error.write_concern_errors.is_empty(),
            _ => false,
        }
    }

    fn mongo_mutation_outcome_is_uncertain(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<mongodb::error::Error>()
                .is_some_and(mongo_error_outcome_is_uncertain)
        })
    }

    /// A connection bundle paired with the read side of the store's
    /// generation barrier. Keeping this value alive prevents reconnect or
    /// failover from swapping the bundle out from under a protected mutation.
    struct MongoAdmissionConnectionPin {
        connection: Arc<MongoConnectionBundle>,
        _generation_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    }

    /// Store-held pin for one multi-step admission operation. Every guarded
    /// read and write borrows the same owner and exact connection bundle.
    struct MongoPersistentAdmissionPin {
        namespace: String,
        pin: MongoAdmissionConnectionPin,
        uncertain_outcome: Arc<AtomicBool>,
    }

    struct MongoLockGuard {
        // Collection handle bound to the reusable DEDICATED lease client/pool,
        // deliberately separate from the store's work pool so acquire, renew,
        // release, and Drop cleanup cannot be starved by a long operation.
        collection: Collection<Document>,
        lock_id: String,
        label: &'static str,
        owner: String,
        // The update mode chosen at acquisition, carried so release/diagnostics
        // stay consistent with how acquire/renew stamped the lock and so
        // security-sensitive lock deletion requests majority acknowledgement.
        mode: MongoLockMode,
        stop_tx: Option<tokio::sync::watch::Sender<bool>>,
        renew_task: Option<tokio::task::JoinHandle<()>>,
        valid: Arc<AtomicBool>,
        released: bool,
        mutation_state: DurableAdmissionMutationState,
        // A guarded operation borrows the outer admission guard and must never
        // delete it when the individual batch finishes.
        delete_on_release: bool,
        // Read side of the connection-generation barrier. Ordinary admission
        // guards own it directly. Multi-step guards transfer it into
        // `MongoStore::persistent_admission_pins` between guarded operations.
        connection_generation_guard: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
        // If an in-flight mutation future is cancelled or errors, Drop moves
        // the generation pin here instead of releasing it. That keeps this
        // process from reconnecting around the fail-closed datastore fence.
        retained_admission_pins: Arc<DashMap<String, MongoAdmissionConnectionPin>>,
        // Borrowed guards set this flag if cancellation or an uncertain Mongo
        // error prevents an explicit outcome settlement. The outer owner then
        // refuses release and keeps its datastore fence and generation pin.
        persistent_outcome_uncertain: Option<Arc<AtomicBool>>,
        // Keeps the live connection bundle — and the generated TLS PEM temp
        // files it owns — alive for as long as the reusable lease client may
        // open new sockets, including the best-effort Drop cleanup task.
        _connection: Arc<MongoConnectionBundle>,
    }

    impl MongoLockGuard {
        fn mark_mutation_started(&mut self) {
            if self.mode == MongoLockMode::UntilExplicitRelease {
                self.mutation_state = DurableAdmissionMutationState::InFlightOrUncertain;
            }
        }

        async fn run_mutation<T, F>(&mut self, mutation: F) -> Result<T, anyhow::Error>
        where
            F: Future<Output = Result<T, anyhow::Error>>,
        {
            self.mark_mutation_started();
            match mutation.await {
                Ok(value) => Ok(value),
                Err(error) if mongo_mutation_outcome_is_uncertain(&error) => Err(error),
                Err(error) => {
                    // A definitive server rejection or transaction abort cannot
                    // commit later. Settle and release now instead of orphaning
                    // a non-expiring fence for an operation known not to be in
                    // flight. Cleanup failure still retains the pin in Drop.
                    self.release().await?;
                    Err(error)
                }
            }
        }

        fn into_persistent_owner(
            mut self,
        ) -> Result<(String, MongoAdmissionConnectionPin), anyhow::Error> {
            let generation_guard = self.connection_generation_guard.take().ok_or_else(|| {
                anyhow::anyhow!(
                    "MongoDB {} guard '{}' has no connection-generation pin",
                    self.label,
                    self.lock_id
                )
            })?;
            self.released = true;
            Ok((
                self.owner.clone(),
                MongoAdmissionConnectionPin {
                    connection: self._connection.clone(),
                    _generation_guard: generation_guard,
                },
            ))
        }

        async fn release(&mut self) -> Result<(), anyhow::Error> {
            if self.mode == MongoLockMode::UntilExplicitRelease {
                // Calling release is the only declaration that the protected
                // mutation has a settled outcome. A failed cleanup can now be
                // retried safely without reopening an uncertain-write race.
                self.mutation_state = DurableAdmissionMutationState::Settled;
            }
            if !self.delete_on_release {
                self.released = true;
                return Ok(());
            }
            if let Some(stop_tx) = self.stop_tx.take() {
                let _ = stop_tx.send(true);
            }
            if let Some(renew_task) = self.renew_task.take() {
                let label = self.label;
                renew_task.await.map_err(|error| {
                    anyhow::anyhow!("MongoDB {label} lease renewal task failed: {error}")
                })?;
            }

            // Every release is owner-qualified. Security-sensitive admission
            // locks additionally require majority acknowledgement so an
            // election cannot revive stale ownership.
            debug!(
                "Releasing MongoDB {} lease '{}' (mode={:?})",
                self.label, self.lock_id, self.mode
            );
            let delete = self.collection.delete_one(doc! {
                "_id": &self.lock_id,
                "owner": &self.owner,
            });
            let result = match self.mode {
                MongoLockMode::RenewableLease(_) => delete.await,
                MongoLockMode::UntilExplicitRelease => {
                    delete.write_concern(WriteConcern::majority()).await
                }
            };
            let result = match result {
                Ok(result) => result,
                Err(error) if self.mode == MongoLockMode::UntilExplicitRelease => {
                    // The protected mutation is already committed at every
                    // admission call site. Report cleanup trouble loudly and
                    // let Drop retry, but do not turn durable success into a
                    // false failed response that suppresses hooks/audit.
                    error!(
                        "MongoDB {} lock '{}' cleanup failed after a committed operation: {}",
                        self.label, self.lock_id, error
                    );
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            self.released = true;
            if !self.valid.load(Ordering::Acquire) {
                anyhow::bail!(
                    "MongoDB {} lease '{}' expired or was lost while the operation ran",
                    self.label,
                    self.lock_id
                );
            }
            if result.deleted_count != 1 {
                if self.mode == MongoLockMode::UntilExplicitRelease {
                    error!(
                        "MongoDB {} lock '{}' cleanup did not match its owner after a committed operation",
                        self.label, self.lock_id
                    );
                    return Ok(());
                }
                anyhow::bail!(
                    "MongoDB {} lease '{}' release did not match the owning document",
                    self.label,
                    self.lock_id
                );
            }
            Ok(())
        }
    }

    impl Drop for MongoLockGuard {
        fn drop(&mut self) {
            if self.released {
                return;
            }
            if !self.delete_on_release {
                if durable_admission_drop_must_retain(self.mode, self.mutation_state)
                    && let Some(uncertain) = &self.persistent_outcome_uncertain
                {
                    uncertain.store(true, Ordering::Release);
                    error!(
                        "Retaining outer MongoDB {} guard '{}' because a borrowed mutation outcome is uncertain",
                        self.label, self.lock_id
                    );
                }
                return;
            }
            if durable_admission_drop_must_retain(self.mode, self.mutation_state) {
                let retained_key = format!("{}:{}", self.lock_id, self.owner);
                if let Some(generation_guard) = self.connection_generation_guard.take() {
                    let _ = self.retained_admission_pins.insert(
                        retained_key,
                        MongoAdmissionConnectionPin {
                            connection: self._connection.clone(),
                            _generation_guard: generation_guard,
                        },
                    );
                }
                error!(
                    "Retaining MongoDB {} lock '{}' and its connection generation because the protected mutation outcome is uncertain; verify the write outcome and restart this admin process before manually removing the owner-qualified lock",
                    self.label, self.lock_id
                );
                return;
            }
            if let Some(stop_tx) = self.stop_tx.take() {
                let _ = stop_tx.send(true);
            }

            let collection = self.collection.clone();
            let lock_id = self.lock_id.clone();
            let owner = self.owner.clone();
            let renew_task = self.renew_task.take();
            let majority = self.mode == MongoLockMode::UntilExplicitRelease;
            // Keep the bundle (and its TLS temp files) alive for the whole
            // best-effort cleanup so the dedicated lease client can still open
            // a socket even if the store's bundle was already swapped/dropped.
            let connection = self._connection.clone();
            let connection_generation_guard = self.connection_generation_guard.take();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let _cleanup_task = runtime.spawn(async move {
                    let _connection = connection;
                    // Keep the generation stable only while this final retry
                    // is running. Its protected mutation is settled, so even
                    // a failed retry must release the local pin and leave the
                    // durable owner-qualified document as the fail-closed
                    // operator-recovery fence.
                    let _connection_generation_guard = connection_generation_guard;
                    if let Some(renew_task) = renew_task {
                        let _ = renew_task.await;
                    }
                    let delete = collection.delete_one(doc! {
                        "_id": &lock_id,
                        "owner": &owner,
                    });
                    let _ = if majority {
                        delete.write_concern(WriteConcern::majority()).await
                    } else {
                        delete.await
                    };
                });
            }
        }
    }

    impl MongoConnectionBundle {
        fn new(
            client: Client,
            db: Database,
            lease_client: Client,
            tls_temp_paths: Vec<tempfile::TempPath>,
        ) -> Self {
            Self {
                client,
                db,
                lease_client,
                _tls_temp_paths: tls_temp_paths,
            }
        }
    }

    struct MongoDatabaseHandle {
        db: Database,
        _connection: Arc<MongoConnectionBundle>,
    }

    impl Deref for MongoDatabaseHandle {
        type Target = Database;

        fn deref(&self) -> &Self::Target {
            &self.db
        }
    }

    struct MongoCollectionHandle {
        collection: Collection<Document>,
        // Keep this handle in scope for cursor-producing finds; cursors can
        // issue getMore calls after the initial find future completes.
        _connection: Arc<MongoConnectionBundle>,
    }

    impl Deref for MongoCollectionHandle {
        type Target = Collection<Document>;

        fn deref(&self) -> &Self::Target {
            &self.collection
        }
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
    /// **Failover & reconnect**: the live `Client`, `Database`, and generated
    /// TLS PEM guards are wrapped in one `ArcSwap` bundle so
    /// [`Self::try_failover_reconnect`] can atomically replace the underlying
    /// client when the primary URL is unreachable and a configured failover URL
    /// is healthy. Readers that already loaded the old bundle keep using it
    /// (commands in flight complete normally), then drop their reference and
    /// pick up the new one on the next call. This mirrors the
    /// `Arc<ArcSwap<AnyPool>>` pattern used by the sqlx `DatabaseStore` for the
    /// same reason — without it, every "failover" attempt would just ping the
    /// dead client and the gateway would never recover for standalone
    /// (non-replica-set) MongoDB deployments.
    #[derive(Clone)]
    pub struct MongoStore {
        // The live client, database handle, and any generated TLS PEM paths.
        // Swapping the bundle as one Arc keeps files present while an old
        // client can still open sockets, then removes them when the final old
        // bundle reference is dropped.
        connection: Arc<ArcSwap<MongoConnectionBundle>>,
        // Admission operations hold the read side from lock acquisition
        // through validation, mutation, and owner-qualified release. A
        // reconnect must take the write side before swapping `connection`, so
        // one protected operation can never straddle MongoDB generations.
        connection_generation: Arc<tokio::sync::RwLock<()>>,
        // Multi-step admission guards outlive an individual trait call. Their owner
        // token indexes the exact connection bundle and generation pin that
        // every clear/replay batch must borrow until explicit release.
        persistent_admission_pins: Arc<DashMap<String, MongoPersistentAdmissionPin>>,
        // An uncertain mutation deliberately leaks neither availability nor
        // safety silently: retain its connection pin for this process's
        // lifetime, log operator recovery guidance, and leave the durable
        // owner-qualified fence in MongoDB.
        retained_admission_pins: Arc<DashMap<String, MongoAdmissionConnectionPin>>,
        // Settings captured at startup so failover rebuilds use identical
        // ClientOptions for every non-URL field.
        conn_settings: MongoConnSettings,
        db_type_str: String,
        slow_query_threshold_ms: Option<u64>,
        cert_expiry_warning_days: u64,
        backend_allow_ips: crate::config::BackendEgressPolicy,
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
        /// TLS can alternatively be configured directly via connection string
        /// options (`tls=true&tlsCAFile=...`) when `FERRUM_DB_TLS_MODE` is
        /// unset. Mixing the two sources is rejected so URI options cannot
        /// silently override the canonical environment policy.
        #[allow(clippy::too_many_arguments)]
        pub async fn connect(
            mongo_url: &str,
            database_name: &str,
            app_name: Option<&str>,
            replica_set: Option<&str>,
            auth_mechanism: Option<&str>,
            server_selection_timeout_secs: Option<u64>,
            connect_timeout_secs: Option<u64>,
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

            let (connection, replica_set_configured) = Self::build_connection_bundle(
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
                     window where partial failure may require operator reconciliation. Atomic \
                     late API-spec delete compensation is unavailable and fails before writing. \
                     Configure FERRUM_MONGO_REPLICA_SET to enable transactions."
                );
            }

            Ok(Self {
                connection: Arc::new(ArcSwap::from_pointee(connection)),
                connection_generation: Arc::new(tokio::sync::RwLock::new(())),
                persistent_admission_pins: Arc::new(DashMap::new()),
                retained_admission_pins: Arc::new(DashMap::new()),
                conn_settings,
                db_type_str: "mongodb".to_string(),
                slow_query_threshold_ms: None,
                cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
                backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
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
        async fn build_connection_bundle(
            mongo_url: &str,
            settings: &MongoConnSettings,
            tls_enabled: bool,
            tls_ca_cert_path: Option<&str>,
            tls_client_cert_path: Option<&str>,
            tls_client_key_path: Option<&str>,
            tls_insecure: bool,
        ) -> Result<(MongoConnectionBundle, bool), anyhow::Error> {
            let mut client_options = ClientOptions::parse(mongo_url).await?;
            if (tls_enabled
                || tls_ca_cert_path.is_some()
                || tls_client_cert_path.is_some()
                || tls_client_key_path.is_some()
                || tls_insecure)
                && client_options.tls.is_some()
            {
                anyhow::bail!(
                    "MongoDB URI TLS options conflict with FERRUM_DB_TLS_MODE; configure TLS in exactly one source"
                );
            }
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
            apply_mongo_timeout_overrides(
                &mut client_options,
                settings.server_selection_timeout_secs,
                settings.connect_timeout_secs,
            );

            // Configure TLS via the canonical database TLS env vars. URI TLS
            // settings were rejected above whenever the canonical mode is set.
            let mut tls_temp_paths: Vec<tempfile::TempPath> = Vec::new();
            if tls_enabled {
                let ca = tls_ca_cert_path
                    .map(|ca_path| {
                        Self::materialize_tls_source_to_file(
                            ca_path,
                            MaterialKind::CaBundle,
                            "ferrum-mongo-ca-",
                        )
                    })
                    .transpose()?;
                let ca_path = ca.as_ref().map(|ca| ca.path.clone());
                if let Some(ca) = ca
                    && let Some(temp_path) = ca.temp_path
                {
                    tls_temp_paths.push(temp_path);
                }

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
                let cert_key_path = cert_key.as_ref().map(|cert_key| cert_key.path.clone());
                if let Some(cert_key) = cert_key
                    && let Some(temp_path) = cert_key.temp_path
                {
                    tls_temp_paths.push(temp_path);
                }

                // Build TlsOptions using the typed-state builder. Each method
                // consumes the builder, so we chain conditionally.
                let tls_opts = Self::build_tls_options(ca_path, cert_key_path, tls_insecure);

                client_options.tls = Some(Tls::Enabled(tls_opts));
                info!(
                    "MongoDB TLS enabled (ca={}, client_cert={}, insecure={})",
                    tls_ca_cert_path
                        .map(|value| {
                            CertSource::parse(value, MaterialKind::CaBundle).redacted_source_id()
                        })
                        .unwrap_or_else(|| "system-roots".to_string()),
                    tls_client_cert_path
                        .map(|value| {
                            CertSource::parse(value, MaterialKind::Cert).redacted_source_id()
                        })
                        .unwrap_or_else(|| "none".to_string()),
                    tls_insecure
                );
            }

            // Build one reusable, independently capped lease-upkeep pool from
            // the fully materialized effective options. Reusing this client is
            // important for the per-write admission lease: constructing a new
            // driver client and pool for every admin mutation would create
            // avoidable connection churn.
            let client = Client::with_options(client_options.clone())?;
            let mut lease_options = client_options;
            lease_options.max_pool_size = Some(MONGO_MIGRATION_LEASE_POOL_SIZE);
            // Never let a URL-derived minPoolSize exceed the capped max (which
            // would fail client construction) or eagerly warm this upkeep pool.
            lease_options.min_pool_size = None;
            let lease_client = Client::with_options(lease_options)?;
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

            Ok((
                MongoConnectionBundle::new(client, db, lease_client, tls_temp_paths),
                replica_set_configured,
            ))
        }

        /// Combine separate PEM cert and key sources into a single temporary file.
        ///
        /// The MongoDB Rust driver requires client cert + key in a single PEM file
        /// (`TlsOptions::cert_key_file_path`). The gateway's `FERRUM_DB_TLS_*` env
        /// vars use separate sources (matching the PostgreSQL/MySQL convention).
        /// This helper reads both sources and writes a combined PEM to a securely
        /// created temp file with restrictive permissions.
        fn combine_cert_key_pem(
            cert_path: &str,
            key_path: &str,
        ) -> Result<MaterializedTlsPath, anyhow::Error> {
            let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
            let key_source = CertSource::parse(key_path, MaterialKind::Key);
            let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB client cert: {}", e))?;
            let key_material = load_material_blocking(&key_source, MaterialKind::Key)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB client key: {}", e))?;

            // Write combined PEM to a securely-created temp file. `tempfile`
            // creates files with restrictive permissions and random names,
            // avoiding predictable-path and world-readable key leakage risks.
            let mut combined = Zeroizing::new(Vec::with_capacity(
                cert_material.bytes.expose_secret().len()
                    + key_material.bytes.expose_secret().len()
                    + 1,
            ));
            combined.extend_from_slice(cert_material.bytes.expose_secret());
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(key_material.bytes.expose_secret());
            let materialized = Self::write_owned_temp_pem(
                "ferrum-mongo-client-",
                combined.as_slice(),
                "combined MongoDB client PEM",
            )?;

            info!(
                "Combined MongoDB client cert ({}) + key ({}) into owned temporary PEM",
                cert_material.display_source_id, key_material.display_source_id
            );
            Ok(materialized)
        }

        fn materialize_tls_source_to_file(
            source_value: &str,
            kind: MaterialKind,
            temp_prefix: &str,
        ) -> Result<MaterializedTlsPath, anyhow::Error> {
            let source = CertSource::parse(source_value, kind);
            if let Some(path) = source.as_file_path() {
                return Ok(MaterializedTlsPath {
                    path,
                    temp_path: None,
                });
            }

            let material = load_material_blocking(&source, kind)
                .map_err(|e| anyhow::anyhow!("Failed to load MongoDB TLS material: {}", e))?;
            let materialized = Self::write_owned_temp_pem(
                temp_prefix,
                material.bytes.expose_secret(),
                "MongoDB TLS PEM",
            )?;

            info!(
                "Materialized MongoDB TLS source {} into owned temporary PEM",
                material.display_source_id
            );
            Ok(materialized)
        }

        fn write_owned_temp_pem(
            temp_prefix: &str,
            contents: &[u8],
            label: &str,
        ) -> Result<MaterializedTlsPath, anyhow::Error> {
            let mut temp_file = tempfile::Builder::new()
                .prefix(temp_prefix)
                .suffix(".pem")
                .tempfile()
                .map_err(|e| anyhow::anyhow!("Failed to create temporary {label}: {e}"))?;
            temp_file.as_file_mut().write_all(contents).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write temporary {label} '{}': {e}",
                    temp_file.path().display()
                )
            })?;
            temp_file.as_file_mut().flush().map_err(|e| {
                anyhow::anyhow!(
                    "Failed to flush temporary {label} '{}': {e}",
                    temp_file.path().display()
                )
            })?;
            Self::set_private_file_permissions(temp_file.path(), label)?;
            let path = temp_file.path().to_path_buf();
            let temp_path = temp_file.into_temp_path();
            Ok(MaterializedTlsPath {
                path,
                temp_path: Some(temp_path),
            })
        }

        #[cfg(unix)]
        fn set_private_file_permissions(path: &Path, label: &str) -> Result<(), anyhow::Error> {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to inspect permissions for temporary {label} '{}': {e}",
                        path.display()
                    )
                })?
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to set private permissions on temporary {label} '{}': {e}",
                    path.display()
                )
            })
        }

        #[cfg(not(unix))]
        fn set_private_file_permissions(_path: &Path, _label: &str) -> Result<(), anyhow::Error> {
            Ok(())
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
            server_selection_timeout_secs: Option<u64>,
            connect_timeout_secs: Option<u64>,
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

        /// Snapshot of the current connection bundle. Holding this `Arc`
        /// keeps generated TLS PEM guards alive for any driver handle cloned
        /// from it.
        fn connection(&self) -> Arc<MongoConnectionBundle> {
            self.connection.load_full()
        }

        fn install_reconnected_bundle(
            &self,
            new_connection: MongoConnectionBundle,
            replica_set_configured: bool,
        ) -> Result<(), anyhow::Error> {
            // Never swap generations while an admission guard is validating,
            // mutating, cleaning up, or spanning a restore rollback. In
            // particular, an uncertain write retains a read pin indefinitely;
            // reconnect must fail fast rather than wait forever or route later
            // writes around its fail-closed fence.
            let _generation_guard = self.connection_generation.try_write().map_err(|_| {
                anyhow::anyhow!(
                    "MongoDB reconnect deferred while an mTLS DNS admission operation pins the current connection generation"
                )
            })?;
            let _old_connection = self.connection.swap(Arc::new(new_connection));
            self.replica_set_configured
                .store(replica_set_configured, Ordering::Release);
            Ok(())
        }

        /// Aggregation-pipeline update that takes or holds a renewable lease.
        /// using MongoDB SERVER time (`$$NOW`). Clock skew on the connecting
        /// client can never enter the expiry comparison: the server both
        /// evaluates whether the existing lease is expired and stamps the new
        /// expiry/renewal timestamps in a single consistent `$$NOW` snapshot.
        /// The lease is (re)claimed only when it is missing, server-expired, or
        /// already owned by us; otherwise every field is left untouched so an
        /// active owner is never stomped.
        fn server_time_lease_acquire_pipeline(owner: &str, duration_millis: i64) -> Vec<Document> {
            vec![
                doc! {
                    "$set": {
                        "_ferrum_same_owner": { "$eq": [ "$owner", owner ] },
                        "_ferrum_claimable": {
                            "$or": [
                                { "$eq": [ { "$type": "$expires_at" }, "missing" ] },
                                { "$lte": [ "$expires_at", "$$NOW" ] },
                                { "$eq": [ "$owner", owner ] },
                            ],
                        },
                    },
                },
                doc! {
                    "$set": {
                        "owner": { "$cond": [ "$_ferrum_claimable", owner, "$owner" ] },
                        "expires_at": {
                            "$cond": [
                                "$_ferrum_claimable",
                                { "$add": [ "$$NOW", duration_millis ] },
                                "$expires_at",
                            ],
                        },
                        "generation": {
                            "$cond": [
                                "$_ferrum_claimable",
                                {
                                    "$cond": [
                                        "$_ferrum_same_owner",
                                        { "$ifNull": [ "$generation", 1_i64 ] },
                                        { "$add": [ { "$ifNull": [ "$generation", 0_i64 ] }, 1_i64 ] },
                                    ],
                                },
                                "$generation",
                            ],
                        },
                        "updated_at": {
                            "$cond": [ "$_ferrum_claimable", "$$NOW", "$updated_at" ],
                        },
                        "created_at": { "$ifNull": [ "$created_at", "$$NOW" ] },
                    },
                },
                doc! { "$unset": [ "_ferrum_claimable", "_ferrum_same_owner" ] },
            ]
        }

        fn migration_lease_acquire_pipeline(owner: &str) -> Vec<Document> {
            vec![
                doc! {
                    "$set": {
                        "_ferrum_claimable": {
                            "$or": [
                                { "$eq": [ { "$type": "$expires_at" }, "missing" ] },
                                { "$lte": [ "$expires_at", "$$NOW" ] },
                                { "$eq": [ "$owner", owner ] },
                            ],
                        },
                    },
                },
                doc! {
                    "$set": {
                        "owner": { "$cond": [ "$_ferrum_claimable", owner, "$owner" ] },
                        "expires_at": {
                            "$cond": [
                                "$_ferrum_claimable",
                                { "$add": [ "$$NOW", MONGO_MIGRATION_LEASE_DURATION_MILLIS ] },
                                "$expires_at",
                            ],
                        },
                        "updated_at": {
                            "$cond": [ "$_ferrum_claimable", "$$NOW", "$updated_at" ],
                        },
                        "created_at": { "$ifNull": [ "$created_at", "$$NOW" ] },
                    },
                },
                doc! { "$unset": "_ferrum_claimable" },
            ]
        }

        /// Aggregation-pipeline update that renews a lease with a fresh
        /// server-time (`$$NOW`) expiry. The owner match stays in the query
        /// filter so a renewal that no longer owns the lock matches nothing.
        fn server_time_lease_renew_pipeline(duration_millis: i64) -> Vec<Document> {
            vec![doc! {
                "$set": {
                    "expires_at": { "$add": [ "$$NOW", duration_millis ] },
                    "updated_at": "$$NOW",
                },
            }]
        }

        async fn lease_server_time(&self) -> Result<BsonDateTime, anyhow::Error> {
            let response = self.lease_db().run_command(doc! { "hello": 1 }).await?;
            response
                .get_datetime("localTime")
                .cloned()
                .map_err(|error| {
                    anyhow::anyhow!("MongoDB hello response omitted localTime: {error}")
                })
        }

        /// The migration-lease duration in milliseconds (exposed for tests that
        /// assert the classic acquire/renew builders stamp `now + duration`).
        pub(crate) fn migration_lease_duration_millis() -> i64 {
            MONGO_MIGRATION_LEASE_DURATION_MILLIS
        }

        pub(crate) fn pipeline_update_unsupported_for_test(error: &mongodb::error::Error) -> bool {
            is_pipeline_update_unsupported(error)
        }

        /// Client-time expiry (`now + lease duration`) as a BSON `DateTime`, so
        /// the classic DocumentDB fallback writes the same BSON type the
        /// server-time (`$$NOW`) pipeline produces.
        fn classic_lease_expiry(client_now: BsonDateTime) -> BsonDateTime {
            BsonDateTime::from_millis(
                client_now.timestamp_millis() + MONGO_MIGRATION_LEASE_DURATION_MILLIS,
            )
        }

        /// Classic (non-pipeline) acquire FILTER for the DocumentDB fallback.
        ///
        /// Matches the lock when it is missing (`expires_at` absent), expired by
        /// the CLIENT clock, or already owned by us. Combined with an upsert, a
        /// lock held by another owner with an unexpired `expires_at` matches
        /// nothing, so the upsert attempts an insert on the existing `_id` and
        /// fails with a duplicate-key error the acquire loop treats as
        /// contention (retry) — mirroring the pipeline path.
        pub(crate) fn migration_lease_acquire_filter_classic(
            owner: &str,
            client_now: BsonDateTime,
        ) -> Document {
            Self::lease_acquire_filter_classic(MONGO_MIGRATION_LOCK_ID, owner, client_now)
        }

        fn lease_acquire_filter_classic(
            lock_id: &str,
            owner: &str,
            client_now: BsonDateTime,
        ) -> Document {
            doc! {
                "_id": lock_id,
                "$or": [
                    { "expires_at": { "$exists": false } },
                    { "expires_at": { "$lte": client_now } },
                    { "owner": owner },
                ],
            }
        }

        /// Classic (non-pipeline) acquire UPDATE for the DocumentDB fallback.
        ///
        /// Stamps the new owner plus a client-clock expiry/renewal, and sets
        /// `created_at` only on insert. Client-time stamping carries the
        /// accepted clock-skew degradation documented on
        /// [`RenewableLeaseMode::ClientTimeClassic`].
        pub(crate) fn migration_lease_acquire_update_classic(
            owner: &str,
            client_now: BsonDateTime,
        ) -> Document {
            doc! {
                "$set": {
                    "owner": owner,
                    "expires_at": Self::classic_lease_expiry(client_now),
                    "updated_at": client_now,
                },
                "$setOnInsert": { "created_at": client_now },
            }
        }

        /// Classic (non-pipeline) renew UPDATE for the DocumentDB fallback. The
        /// owner match stays in the query filter (`{_id, owner}`) so a renewal
        /// that no longer owns the lock matches nothing, unchanged from the
        /// pipeline path.
        pub(crate) fn migration_lease_renew_update_classic(client_now: BsonDateTime) -> Document {
            doc! {
                "$set": {
                    "expires_at": Self::classic_lease_expiry(client_now),
                    "updated_at": client_now,
                },
            }
        }

        /// Acquire filter for the non-expiring mTLS DNS admission mutex.
        /// Deliberately absent: any expiry/takeover clause. A retry may match
        /// its own owner after an uncertain response, but another owner can
        /// only observe duplicate-key contention on the fixed namespace `_id`.
        pub(crate) fn mtls_dns_admission_lock_filter(namespace: &str, owner: &str) -> Document {
            doc! {
                "_id": namespace,
                "$or": [
                    { "owner": { "$exists": false } },
                    { "owner": owner },
                ],
            }
        }

        /// Update for the non-expiring admission mutex. `$unset` removes any
        /// accidentally supplied expiry so lock ownership can never transfer
        /// merely because an admin process pauses.
        pub(crate) fn mtls_dns_admission_lock_update(
            owner: &str,
            client_now: BsonDateTime,
        ) -> Document {
            doc! {
                "$set": {
                    "owner": owner,
                    "updated_at": client_now,
                },
                "$unset": { "expires_at": "" },
                "$setOnInsert": { "created_at": client_now },
            }
        }

        pub(crate) fn mtls_dns_admission_drop_must_retain_for_test(
            mutation_started: bool,
            outcome_settled: bool,
        ) -> bool {
            let state = if outcome_settled {
                DurableAdmissionMutationState::Settled
            } else if mutation_started {
                DurableAdmissionMutationState::InFlightOrUncertain
            } else {
                DurableAdmissionMutationState::NotStarted
            };
            durable_admission_drop_must_retain(MongoLockMode::UntilExplicitRelease, state)
        }

        async fn acquire_migration_lease(&self) -> Result<MongoLockGuard, anyhow::Error> {
            self.acquire_renewable_lease(
                "_ferrum_migration_locks",
                MONGO_MIGRATION_LOCK_ID,
                "migration",
            )
            .await
        }

        async fn acquire_mtls_dns_admission_lease(
            &self,
            namespace: &str,
        ) -> Result<MongoLockGuard, anyhow::Error> {
            self.acquire_mtls_dns_admission_lease_for_mode(
                namespace,
                &BatchConfigWriteMode::Admission,
            )
            .await
        }

        async fn acquire_mtls_dns_admission_lease_for_mode(
            &self,
            namespace: &str,
            mode: &BatchConfigWriteMode,
        ) -> Result<MongoLockGuard, anyhow::Error> {
            self.acquire_durable_admission_lock(
                "mtls_dns_admission_locks",
                namespace,
                "mTLS DNS admission",
                mode.guard_owner(),
            )
            .await
        }

        async fn acquire_mtls_dns_admission_leases<'a>(
            &self,
            namespaces: impl IntoIterator<Item = &'a str>,
        ) -> Result<Vec<MongoLockGuard>, anyhow::Error> {
            self.acquire_mtls_dns_admission_leases_for_mode(
                namespaces,
                &BatchConfigWriteMode::Admission,
            )
            .await
        }

        async fn acquire_mtls_dns_admission_leases_for_mode<'a>(
            &self,
            namespaces: impl IntoIterator<Item = &'a str>,
            mode: &BatchConfigWriteMode,
        ) -> Result<Vec<MongoLockGuard>, anyhow::Error> {
            let mut namespaces: Vec<&str> = namespaces.into_iter().collect();
            namespaces.sort_unstable();
            namespaces.dedup();
            let mut leases = Vec::with_capacity(namespaces.len());
            for namespace in namespaces {
                leases.push(
                    self.acquire_mtls_dns_admission_lease_for_mode(namespace, mode)
                        .await?,
                );
            }
            Ok(leases)
        }

        async fn release_mtls_dns_admission_leases(
            leases: &mut Vec<MongoLockGuard>,
        ) -> Result<(), anyhow::Error> {
            while let Some(mut lease) = leases.pop() {
                lease.release().await?;
            }
            Ok(())
        }

        fn mark_mtls_dns_mutations_started(leases: &mut [MongoLockGuard]) {
            for lease in leases {
                lease.mark_mutation_started();
            }
        }

        async fn run_mtls_dns_mutations<T, F>(
            leases: &mut Vec<MongoLockGuard>,
            mutation: F,
        ) -> Result<T, anyhow::Error>
        where
            F: Future<Output = Result<T, anyhow::Error>>,
        {
            Self::mark_mtls_dns_mutations_started(leases);
            match mutation.await {
                Ok(value) => Ok(value),
                Err(error) if mongo_mutation_outcome_is_uncertain(&error) => Err(error),
                Err(error) => {
                    Self::release_mtls_dns_admission_leases(leases).await?;
                    Err(error)
                }
            }
        }

        async fn validate_mtls_dns_candidate<F>(
            &self,
            namespace: &str,
            mutate: F,
        ) -> Result<(), anyhow::Error>
        where
            F: Fn(&mut GatewayConfig),
        {
            self.validate_mtls_dns_candidate_with_mode(namespace, mutate, false, false)
                .await
        }

        async fn validate_plugin_graph_admission_candidate<F>(
            &self,
            namespace: &str,
            mutate: F,
        ) -> Result<(), anyhow::Error>
        where
            F: Fn(&mut GatewayConfig),
        {
            self.validate_mtls_dns_candidate_with_mode(namespace, mutate, false, true)
                .await
        }

        async fn validate_mtls_dns_repair_delete_candidate<F>(
            &self,
            namespace: &str,
            mutate: F,
        ) -> Result<(), anyhow::Error>
        where
            F: Fn(&mut GatewayConfig),
        {
            self.validate_mtls_dns_candidate_with_mode(namespace, mutate, true, false)
                .await
        }

        async fn validate_plugin_graph_repair_delete_candidate<F>(
            &self,
            namespace: &str,
            mutate: F,
        ) -> Result<(), anyhow::Error>
        where
            F: Fn(&mut GatewayConfig),
        {
            self.validate_mtls_dns_candidate_with_mode(namespace, mutate, true, true)
                .await
        }

        async fn validate_mtls_dns_candidate_with_mode<F>(
            &self,
            namespace: &str,
            mutate: F,
            allow_existing_conflicts: bool,
            validate_plugin_graph: bool,
        ) -> Result<(), anyhow::Error>
        where
            F: Fn(&mut GatewayConfig),
        {
            // Most mutations cannot affect DNS-derived identities. Load the
            // policy graph first and avoid decoding every consumer unless an
            // enabled effective san_dns policy exists after the mutation.
            let mut policy_candidate = self.load_mtls_dns_policy_candidate(namespace).await?;
            mutate(&mut policy_candidate);
            policy_candidate.normalize_fields();
            if validate_plugin_graph {
                crate::plugin_cache::validate_tcp_connection_throttle_attachments(
                    &policy_candidate,
                )
                .map_err(|errors| {
                    anyhow::Error::new(TcpConnectionThrottleAttachmentConflict::new(errors))
                })?;
            }
            if !policy_candidate.has_effective_mtls_dns_identity_policy() {
                return Ok(());
            }

            let mut candidate =
                <Self as DatabaseBackend>::load_namespace_snapshot(self, namespace).await?;
            let prior_conflicts = if allow_existing_conflicts {
                candidate.mtls_dns_identity_conflicts()
            } else {
                Default::default()
            };
            mutate(&mut candidate);
            candidate.normalize_fields();
            if allow_existing_conflicts
                && !candidate.introduces_new_mtls_dns_identity_conflict(&prior_conflicts)
            {
                return Ok(());
            }
            match candidate.validate_unique_mtls_dns_identities() {
                Ok(()) if allow_existing_conflicts => {
                    Err(anyhow::Error::new(MtlsDnsIdentityConflict::new(vec![
                        "Mutation would introduce a new mTLS DNS identity ambiguity".to_string(),
                    ])))
                }
                Ok(()) => Ok(()),
                Err(errors) => Err(anyhow::Error::new(MtlsDnsIdentityConflict::new(errors))),
            }
        }

        async fn load_mtls_dns_policy_candidate(
            &self,
            namespace: &str,
        ) -> Result<GatewayConfig, anyhow::Error> {
            let loaded_at = Utc::now();
            let (proxies, plugin_configs) = if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                session
                    .start_transaction()
                    .read_concern(ReadConcern::snapshot())
                    .write_concern(WriteConcern::majority())
                    .await?;

                let loaded = async {
                    let proxies = self
                        .load_full_proxies_opt_session(
                            namespace,
                            Some((connection.as_ref(), &mut session)),
                            true,
                        )
                        .await?;
                    let plugin_configs = self
                        .load_full_plugin_configs_opt_session(
                            namespace,
                            Some((connection.as_ref(), &mut session)),
                            true,
                        )
                        .await?;
                    Ok::<_, anyhow::Error>((proxies, plugin_configs))
                }
                .await;

                match loaded {
                    Ok(resources) => {
                        session.commit_transaction().await?;
                        resources
                    }
                    Err(error) => {
                        let _ = session.abort_transaction().await;
                        return Err(error);
                    }
                }
            } else {
                (
                    self.load_full_proxies_opt_session(namespace, None, true)
                        .await?,
                    self.load_full_plugin_configs_opt_session(namespace, None, true)
                        .await?,
                )
            };

            let mut candidate = GatewayConfig {
                version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
                proxies,
                plugin_configs,
                loaded_at,
                ..Default::default()
            };
            candidate.normalize_fields();
            Ok(candidate)
        }

        async fn acquire_durable_admission_lock(
            &self,
            collection_name: &str,
            lock_id: &str,
            label: &'static str,
            guard_owner: Option<&str>,
        ) -> Result<MongoLockGuard, anyhow::Error> {
            // A TTL lease is not a write fence on standalone MongoDB: a paused
            // process could resume after expiry and write concurrently with a
            // successor. Admission therefore uses a durable mutex document
            // that another process can never reclaim. This deliberately trades
            // automatic crash recovery for fail-closed uniqueness. Acquisition
            // is bounded so an orphan produces an actionable error instead of
            // hanging an admin request forever.
            let owner = guard_owner
                .map(str::to_string)
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let lock_id = lock_id.to_string();
            let (connection, connection_generation_guard, persistent_outcome_uncertain) =
                if guard_owner.is_some() {
                    let persistent_pin = self
                        .persistent_admission_pins
                        .get(&owner)
                        .ok_or_else(|| {
                            anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(format!(
                                "MongoDB {label} guard '{lock_id}' is not active in this admin process"
                            ))
                        })?;
                    if persistent_pin.namespace != lock_id {
                        return Err(anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(
                            "MongoDB mTLS DNS admission guard belongs to a different namespace",
                        ));
                    }
                    if persistent_pin.uncertain_outcome.load(Ordering::Acquire) {
                        return Err(anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(
                            "MongoDB mTLS DNS admission guard retained because a prior protected mutation outcome is uncertain",
                        ));
                    }
                    (
                        persistent_pin.pin.connection.clone(),
                        None,
                        Some(persistent_pin.uncertain_outcome.clone()),
                    )
                } else {
                    let generation_guard = self.connection_generation.clone().read_owned().await;
                    (self.connection(), Some(generation_guard), None)
                };
            let collection = connection
                .lease_client
                .database(connection.db.name())
                .collection::<Document>(collection_name);

            if guard_owner.is_some() {
                let client_now = BsonDateTime::now();
                let document = collection
                    .find_one_and_update(
                        doc! { "_id": &lock_id, "owner": &owner },
                        doc! { "$set": { "updated_at": client_now } },
                    )
                    .return_document(ReturnDocument::After)
                    .write_concern(WriteConcern::majority())
                    .await?;
                if document
                    .as_ref()
                    .and_then(|document| document.get_str("owner").ok())
                    != Some(owner.as_str())
                {
                    return Err(anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(
                        "MongoDB mTLS DNS admission guard is not owned by this operation",
                    ));
                }
                return Ok(MongoLockGuard {
                    collection,
                    lock_id,
                    label,
                    owner,
                    mode: MongoLockMode::UntilExplicitRelease,
                    stop_tx: None,
                    renew_task: None,
                    valid: Arc::new(AtomicBool::new(true)),
                    released: false,
                    mutation_state: DurableAdmissionMutationState::NotStarted,
                    delete_on_release: false,
                    connection_generation_guard,
                    retained_admission_pins: self.retained_admission_pins.clone(),
                    persistent_outcome_uncertain,
                    _connection: connection,
                });
            }
            let deadline = tokio::time::Instant::now() + MONGO_ADMISSION_LOCK_WAIT_TIMEOUT;

            loop {
                let client_now = BsonDateTime::now();
                let result = collection
                    .find_one_and_update(
                        Self::mtls_dns_admission_lock_filter(&lock_id, &owner),
                        Self::mtls_dns_admission_lock_update(&owner, client_now),
                    )
                    .upsert(true)
                    .return_document(ReturnDocument::After)
                    .write_concern(WriteConcern::majority())
                    .await;

                match result {
                    Ok(Some(document))
                        if document.get_str("owner").ok() == Some(owner.as_str()) =>
                    {
                        return Ok(MongoLockGuard {
                            collection,
                            lock_id,
                            label,
                            owner,
                            mode: MongoLockMode::UntilExplicitRelease,
                            stop_tx: None,
                            renew_task: None,
                            valid: Arc::new(AtomicBool::new(true)),
                            released: false,
                            mutation_state: DurableAdmissionMutationState::NotStarted,
                            delete_on_release: true,
                            connection_generation_guard,
                            retained_admission_pins: self.retained_admission_pins.clone(),
                            persistent_outcome_uncertain,
                            _connection: connection,
                        });
                    }
                    Ok(_) => {}
                    Err(error) if is_duplicate_key(&error) => {}
                    Err(error) => return Err(error.into()),
                }

                if tokio::time::Instant::now() >= deadline {
                    return Err(
                        anyhow::Error::new(MtlsDnsAdmissionUnavailable).context(format!(
                            "MongoDB {label} lock '{lock_id}' remained held for {} seconds; \
                         admission locks do not expire because reclaiming one could permit a \
                         stale writer, so verify the prior owner is stopped before removing the \
                         lock document",
                            MONGO_ADMISSION_LOCK_WAIT_TIMEOUT.as_secs()
                        )),
                    );
                }
                tokio::time::sleep(MONGO_MIGRATION_LEASE_RETRY_INTERVAL).await;
            }
        }

        async fn acquire_renewable_lease(
            &self,
            collection_name: &str,
            lock_id: &str,
            label: &'static str,
        ) -> Result<MongoLockGuard, anyhow::Error> {
            // Lease upkeep uses the connection bundle's reusable dedicated
            // pool. This isolates tiny acquire/renew/release commands from the
            // datastore work pool without constructing a new driver client for
            // every admission attempt.
            let connection = self.connection();
            let collection = connection
                .lease_client
                .database(connection.db.name())
                .collection::<Document>(collection_name);
            let owner = Uuid::new_v4().to_string();
            let lock_id = lock_id.to_string();

            // Start in server-time (`$$NOW`) pipeline mode, the skew-immune
            // primary path for real MongoDB. Only the FIRST acquire attempt may
            // probe the backend: if that pipeline update is rejected as
            // unsupported (AWS DocumentDB), switch to the classic client-time
            // mode for this lease's whole lifecycle and retry immediately.
            let mut mode = RenewableLeaseMode::ServerTimePipeline;
            let mut first_attempt = true;
            loop {
                let result = match mode {
                    RenewableLeaseMode::ServerTimePipeline => {
                        collection
                            .find_one_and_update(
                                doc! { "_id": &lock_id },
                                Self::migration_lease_acquire_pipeline(&owner),
                            )
                            .upsert(true)
                            .return_document(ReturnDocument::After)
                            .await
                    }
                    RenewableLeaseMode::ClientTimeClassic => {
                        let client_now = BsonDateTime::now();
                        collection
                            .find_one_and_update(
                                Self::lease_acquire_filter_classic(&lock_id, &owner, client_now),
                                Self::migration_lease_acquire_update_classic(&owner, client_now),
                            )
                            .upsert(true)
                            .return_document(ReturnDocument::After)
                            .await
                    }
                };

                let was_first_attempt = first_attempt;
                first_attempt = false;
                match result {
                    // Acquire only writes our owner when the lease was
                    // claimable; a returned document owned by someone else means
                    // a still-valid lease we must wait on.
                    Ok(Some(document))
                        if document.get_str("owner").ok() == Some(owner.as_str()) =>
                    {
                        break;
                    }
                    Ok(_) => {}
                    Err(error) if is_duplicate_key(&error) => {}
                    // DocumentDB rejects the aggregation-pipeline update up-front
                    // (before touching the lock), detected only on the first
                    // attempt. Permanently switch this lease to the classic
                    // client-time path and retry immediately: the lock state is
                    // unchanged, so this is a capability fallback, not backoff.
                    Err(error)
                        if was_first_attempt
                            && mode == RenewableLeaseMode::ServerTimePipeline
                            && is_pipeline_update_unsupported(&error) =>
                    {
                        warn!(
                            "MongoDB rejected the aggregation-pipeline {}-lease update \
                             (AWS DocumentDB-compatible backend); falling back to the classic \
                             client-time lease for this operation: {error}",
                            label
                        );
                        mode = RenewableLeaseMode::ClientTimeClassic;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
                tokio::time::sleep(MONGO_MIGRATION_LEASE_RETRY_INTERVAL).await;
            }

            let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
            let renew_collection = collection.clone();
            let renew_owner = owner.clone();
            let renew_lock_id = lock_id.clone();
            let renew_label = label;
            let valid = Arc::new(AtomicBool::new(true));
            let renew_valid = valid.clone();
            let renew_task = tokio::spawn(async move {
                let mut valid_until = tokio::time::Instant::now() + MONGO_MIGRATION_LEASE_DURATION;
                loop {
                    tokio::select! {
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(MONGO_MIGRATION_LEASE_RENEW_INTERVAL) => {}
                    }

                    loop {
                        // Renew with the SAME mode the lease acquired under so a
                        // DocumentDB lease never re-sends the unsupported
                        // pipeline. The owner filter is identical in both modes.
                        let renew_filter = doc! {
                            "_id": &renew_lock_id,
                            "owner": &renew_owner,
                        };
                        let renewal = match mode {
                            RenewableLeaseMode::ServerTimePipeline => {
                                renew_collection
                                    .update_one(
                                        renew_filter,
                                        MongoStore::server_time_lease_renew_pipeline(
                                            MONGO_MIGRATION_LEASE_DURATION_MILLIS,
                                        ),
                                    )
                                    .await
                            }
                            RenewableLeaseMode::ClientTimeClassic => {
                                renew_collection
                                    .update_one(
                                        renew_filter,
                                        MongoStore::migration_lease_renew_update_classic(
                                            BsonDateTime::now(),
                                        ),
                                    )
                                    .await
                            }
                        };
                        match renewal {
                            Ok(result) if result.matched_count == 1 => {
                                valid_until =
                                    tokio::time::Instant::now() + MONGO_MIGRATION_LEASE_DURATION;
                                break;
                            }
                            Ok(_) => {
                                renew_valid.store(false, Ordering::Release);
                                error!(
                                    "MongoDB {} lease renewal lost the owning lock document",
                                    renew_label
                                );
                                return;
                            }
                            Err(error) => {
                                if tokio::time::Instant::now()
                                    + MONGO_MIGRATION_LEASE_RETRY_INTERVAL
                                    >= valid_until
                                {
                                    renew_valid.store(false, Ordering::Release);
                                    error!(
                                        "MongoDB {} lease expired after renewal failures: {}",
                                        renew_label, error
                                    );
                                    return;
                                }
                                debug!(
                                    "MongoDB {} lease renewal failed; retrying before expiry: {}",
                                    renew_label, error
                                );
                                tokio::select! {
                                    changed = stop_rx.changed() => {
                                        if changed.is_err() || *stop_rx.borrow() {
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(MONGO_MIGRATION_LEASE_RETRY_INTERVAL) => {}
                                }
                            }
                        }
                    }
                }
            });

            Ok(MongoLockGuard {
                collection,
                lock_id,
                label,
                owner,
                mode: MongoLockMode::RenewableLease(mode),
                stop_tx: Some(stop_tx),
                renew_task: Some(renew_task),
                valid,
                released: false,
                mutation_state: DurableAdmissionMutationState::NotStarted,
                delete_on_release: true,
                connection_generation_guard: None,
                retained_admission_pins: self.retained_admission_pins.clone(),
                persistent_outcome_uncertain: None,
                _connection: connection,
            })
        }

        /// Snapshot of the current `Database` handle, tied to the bundle that
        /// owns any generated TLS files it may need for new sockets.
        fn db(&self) -> MongoDatabaseHandle {
            let connection = self.connection();
            MongoDatabaseHandle {
                db: connection.db.clone(),
                _connection: connection,
            }
        }

        /// Snapshot of the dedicated lease `Database` handle. Lease acquisition,
        /// renewal, release, and supporting server-time reads must not queue
        /// behind ordinary datastore traffic.
        fn lease_db(&self) -> MongoDatabaseHandle {
            let connection = self.connection();
            let db = connection.lease_client.database(connection.db.name());
            MongoDatabaseHandle {
                db,
                _connection: connection,
            }
        }

        fn collection(&self, name: &str) -> MongoCollectionHandle {
            let connection = self.connection();
            MongoCollectionHandle {
                collection: connection.db.collection(name),
                _connection: connection,
            }
        }

        fn proxies(&self) -> MongoCollectionHandle {
            self.collection("proxies")
        }

        fn consumers(&self) -> MongoCollectionHandle {
            self.collection("consumers")
        }

        fn plugin_configs(&self) -> MongoCollectionHandle {
            self.collection("plugin_configs")
        }

        fn upstreams(&self) -> MongoCollectionHandle {
            self.collection("upstreams")
        }

        fn api_specs(&self) -> MongoCollectionHandle {
            self.collection("api_specs")
        }

        fn audit_events(&self) -> MongoCollectionHandle {
            self.collection("audit_events")
        }

        fn config_changes(&self) -> MongoCollectionHandle {
            self.collection("config_changes")
        }

        fn config_change_counters(&self) -> MongoCollectionHandle {
            self.collection("config_change_counters")
        }

        fn config_admission_locks(&self) -> MongoCollectionHandle {
            let lease_db = self.lease_db();
            MongoCollectionHandle {
                collection: lease_db.collection("config_admission_locks"),
                _connection: lease_db._connection,
            }
        }

        /// Merged consumer identity keyspace (id ∪ username ∪ custom_id per
        /// namespace). Documents are `{_id: "{namespace}:{value}", namespace,
        /// identity_value, consumer_id}` — `_id` uniqueness is the atomic
        /// guard against two consumers claiming the same identity value.
        fn consumer_identity_index(&self) -> MongoCollectionHandle {
            self.collection("consumer_identity_index")
        }

        /// Per-(namespace, route-bucket) lock documents keyed by
        /// `"{namespace}:{route_key_hash}"`. The Mongo analogue of the SQL
        /// backend's `proxy_route_locks` `SELECT ... FOR UPDATE` row.
        fn proxy_route_locks(&self) -> MongoCollectionHandle {
            self.collection("proxy_route_locks")
        }

        /// Per-(namespace, upstream) guard documents keyed by
        /// `"{namespace}:{upstream_id}"`. Written in-session by proxy
        /// create/update transactions that reference the upstream and by
        /// `delete_upstream`'s transaction, so a concurrent create-referencing
        /// transaction and the delete transaction write-conflict and serialize.
        fn upstream_ref_guards(&self) -> MongoCollectionHandle {
            self.collection("upstream_ref_guards")
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

        async fn next_config_change_sequence(&self) -> Result<u64, anyhow::Error> {
            let doc = self
                .config_change_counters()
                .find_one_and_update(
                    doc! { "_id": "global" },
                    doc! { "$inc": { "sequence": 1_i64 } },
                )
                .upsert(true)
                .return_document(ReturnDocument::After)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("MongoDB config change counter update returned no document")
                })?;
            Self::config_change_sequence_from_counter_doc(&doc)
        }

        async fn reserve_config_change_sequences(
            &self,
            count: usize,
        ) -> Result<u64, anyhow::Error> {
            if count == 0 {
                anyhow::bail!("cannot reserve zero MongoDB config change sequences");
            }
            let count = i64::try_from(count).map_err(|_| {
                anyhow::anyhow!("MongoDB config change batch exceeds i64 sequence range")
            })?;
            let doc = self
                .config_change_counters()
                .find_one_and_update(
                    doc! { "_id": "global" },
                    doc! { "$inc": { "sequence": count } },
                )
                .upsert(true)
                .return_document(ReturnDocument::After)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("MongoDB config change counter update returned no document")
                })?;
            Self::config_change_sequence_from_counter_doc(&doc)
        }

        async fn next_config_change_sequence_in_session(
            &self,
            session: &mut ClientSession,
        ) -> mongodb::error::Result<u64> {
            let doc = self
                .config_change_counters()
                .find_one_and_update(
                    doc! { "_id": "global" },
                    doc! { "$inc": { "sequence": 1_i64 } },
                )
                .upsert(true)
                .return_document(ReturnDocument::After)
                .session(&mut *session)
                .await?
                .ok_or_else(|| {
                    mongodb::error::Error::custom(
                        "MongoDB config change counter update returned no document",
                    )
                })?;
            Self::config_change_sequence_from_counter_doc(&doc)
                .map_err(|e| mongodb::error::Error::custom(e.to_string()))
        }

        fn config_change_sequence_from_counter_doc(doc: &Document) -> Result<u64, anyhow::Error> {
            match doc.get("sequence") {
                Some(Bson::Int64(value)) if *value >= 0 => Ok(*value as u64),
                Some(Bson::Int32(value)) if *value >= 0 => Ok(*value as u64),
                other => anyhow::bail!(
                    "MongoDB config change counter has invalid sequence: {:?}",
                    other
                ),
            }
        }

        fn config_change_retention_doc_id(namespace: &str) -> String {
            format!("retention:{namespace}")
        }

        fn config_change_doc(
            sequence: u64,
            namespace: &str,
            resource_type: &str,
            resource_id: &str,
            operation: &str,
        ) -> Document {
            doc! {
                "sequence": sequence as i64,
                "namespace": namespace,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "operation": operation,
                "created_at": Utc::now().to_rfc3339(),
            }
        }

        async fn record_config_change(
            &self,
            namespace: &str,
            resource_type: &str,
            resource_id: &str,
            operation: &str,
        ) -> Result<(), anyhow::Error> {
            let sequence = self.next_config_change_sequence().await?;
            let doc =
                Self::config_change_doc(sequence, namespace, resource_type, resource_id, operation);
            self.config_changes().insert_one(doc).await?;
            self.compact_config_changes(namespace).await?;
            Ok(())
        }

        async fn record_config_changes_batch(
            &self,
            changes: &[ConfigChangeWrite<'_>],
        ) -> Result<(), anyhow::Error> {
            if changes.is_empty() {
                return Ok(());
            }
            let latest_sequence = self.reserve_config_change_sequences(changes.len()).await?;
            let count = changes.len() as u64;
            let first_sequence = latest_sequence.checked_sub(count - 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "MongoDB config change sequence reservation underflowed for {} changes",
                    changes.len()
                )
            })?;
            let created_at = Utc::now().to_rfc3339();
            let docs: Vec<Document> = changes
                .iter()
                .enumerate()
                .map(|(idx, change)| {
                    doc! {
                        "sequence": (first_sequence + idx as u64) as i64,
                        "namespace": change.namespace,
                        "resource_type": change.resource_type,
                        "resource_id": change.resource_id,
                        "operation": change.operation,
                        "created_at": created_at.clone(),
                    }
                })
                .collect();
            self.config_changes().insert_many(docs).await?;

            let namespaces: HashSet<&str> = changes.iter().map(|change| change.namespace).collect();
            for namespace in namespaces {
                self.compact_config_changes(namespace).await?;
            }

            Ok(())
        }

        async fn record_config_change_in_session(
            &self,
            session: &mut ClientSession,
            namespace: &str,
            resource_type: &str,
            resource_id: &str,
            operation: &str,
        ) -> mongodb::error::Result<()> {
            let sequence = self.next_config_change_sequence_in_session(session).await?;
            let doc =
                Self::config_change_doc(sequence, namespace, resource_type, resource_id, operation);
            self.config_changes()
                .insert_one(doc)
                .session(&mut *session)
                .await?;
            Ok(())
        }

        async fn compact_config_changes_best_effort(&self, namespace: &str) {
            if let Err(e) = self.compact_config_changes(namespace).await {
                warn!(
                    "MongoDB config change compaction failed for namespace '{}': {}",
                    namespace, e
                );
            }
        }

        async fn rollback_standalone_created_document(
            &self,
            collection_name: &str,
            namespace: &str,
            resource_type: &str,
            resource_id: &str,
            change_error: &anyhow::Error,
        ) -> bool {
            match self
                .collection(collection_name)
                .delete_one(doc! { "_id": resource_id })
                .await
            {
                Ok(result) if result.deleted_count > 0 => {
                    warn!(
                        "Rolled back MongoDB standalone {} create for id '{}' in namespace '{}' after config_changes write failed: {}",
                        resource_type, resource_id, namespace, change_error
                    );
                    true
                }
                Ok(_) => {
                    warn!(
                        "MongoDB standalone {} create for id '{}' in namespace '{}' failed to record config_changes, but rollback confirmed no inserted document remains: {}",
                        resource_type, resource_id, namespace, change_error
                    );
                    true
                }
                Err(rollback_err) => {
                    warn!(
                        "MongoDB standalone {} create for id '{}' in namespace '{}' failed to record config_changes and rollback failed: {}; original error: {}",
                        resource_type, resource_id, namespace, rollback_err, change_error
                    );
                    false
                }
            }
        }

        async fn rollback_standalone_created_documents(
            &self,
            collection_name: &str,
            resource_type: &str,
            resource_ids: &[&str],
            change_error: &anyhow::Error,
        ) -> HashSet<String> {
            if resource_ids.is_empty() {
                return HashSet::new();
            }

            let mut confirmed_absent = HashSet::with_capacity(resource_ids.len());
            for chunk in resource_ids.chunks(500) {
                let id_values: Vec<Bson> = chunk
                    .iter()
                    .map(|resource_id| Bson::String((*resource_id).to_string()))
                    .collect();
                match self
                    .collection(collection_name)
                    .delete_many(doc! { "_id": { "$in": id_values } })
                    .await
                {
                    Ok(result) => {
                        // A successful delete_many confirms that every ID in
                        // this chunk is absent when the operation completes,
                        // including IDs that were already absent.
                        confirmed_absent
                            .extend(chunk.iter().map(|resource_id| (*resource_id).to_string()));
                        debug!(
                            "MongoDB standalone {} batch rollback deleted {} documents from a {}-ID chunk",
                            resource_type,
                            result.deleted_count,
                            chunk.len()
                        );
                    }
                    Err(rollback_err) => {
                        warn!(
                            "MongoDB standalone {} batch create failed to record config_changes and rollback failed after confirming {} of {} inserted documents absent: {}; original error: {}",
                            resource_type,
                            confirmed_absent.len(),
                            resource_ids.len(),
                            rollback_err,
                            change_error
                        );
                        return confirmed_absent;
                    }
                }
            }

            warn!(
                "Rolled back MongoDB standalone {} batch create after config_changes write failed; confirmed {} of {} inserted documents absent: {}",
                resource_type,
                confirmed_absent.len(),
                resource_ids.len(),
                change_error
            );
            confirmed_absent
        }

        fn resource_ids_without_failed_insert_indices<'a>(
            resource_ids: &'a [&'a str],
            failed_indices: &HashSet<usize>,
        ) -> Vec<&'a str> {
            resource_ids
                .iter()
                .enumerate()
                .filter_map(|(idx, resource_id)| {
                    if failed_indices.contains(&idx) {
                        None
                    } else {
                        Some(*resource_id)
                    }
                })
                .collect()
        }

        fn rollback_ids_for_unordered_insert_error<'a>(
            resource_ids: &'a [&'a str],
            err: &mongodb::error::Error,
        ) -> Vec<&'a str> {
            let mongodb::error::ErrorKind::InsertMany(insert_error) = err.kind.as_ref() else {
                return Vec::new();
            };
            let failed_indices: HashSet<usize> = insert_error
                .write_errors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|write_error| write_error.index)
                .collect();
            Self::resource_ids_without_failed_insert_indices(resource_ids, &failed_indices)
        }

        async fn rollback_standalone_updated_document(
            &self,
            collection_name: &str,
            resource_type: &str,
            resource_id: &str,
            previous_doc: Option<Document>,
            change_error: &anyhow::Error,
        ) -> bool {
            let Some(previous_doc) = previous_doc else {
                warn!(
                    "MongoDB standalone {} update for id '{}' failed to record config_changes, \
                     but no previous document was available to restore: {}",
                    resource_type, resource_id, change_error
                );
                return false;
            };
            match self
                .collection(collection_name)
                .replace_one(doc! { "_id": resource_id }, previous_doc)
                .await
            {
                Ok(result) if result.matched_count > 0 => {
                    warn!(
                        "Restored MongoDB standalone {} update for id '{}' after config_changes write failed: {}",
                        resource_type, resource_id, change_error
                    );
                    true
                }
                Ok(_) => {
                    warn!(
                        "MongoDB standalone {} update for id '{}' failed to record config_changes, but rollback found no document to restore: {}",
                        resource_type, resource_id, change_error
                    );
                    false
                }
                Err(rollback_err) => {
                    warn!(
                        "MongoDB standalone {} update for id '{}' failed to record config_changes and rollback failed: {}; original error: {}",
                        resource_type, resource_id, rollback_err, change_error
                    );
                    false
                }
            }
        }

        async fn compact_config_changes(&self, namespace: &str) -> Result<(), anyhow::Error> {
            let latest = self.latest_change_sequence(namespace).await?;
            if latest <= CHANGE_LOG_RETAIN_PER_NAMESPACE {
                return Ok(());
            }
            let cutoff = latest - CHANGE_LOG_RETAIN_PER_NAMESPACE;
            let retained_doc = self
                .config_changes()
                .find_one(doc! {
                    "namespace": namespace,
                    "sequence": { "$lte": cutoff as i64 },
                })
                .sort(doc! { "sequence": -1 })
                .await?;
            let retained_sequence = match retained_doc.as_ref().and_then(|doc| doc.get("sequence"))
            {
                Some(Bson::Int64(value)) if *value > 0 => Some(*value),
                Some(Bson::Int32(value)) if *value > 0 => Some(*value as i64),
                Some(other) => anyhow::bail!(
                    "MongoDB config_changes row has invalid sequence: {:?}",
                    other
                ),
                None => None,
            };
            if let Some(retained_sequence) = retained_sequence {
                self.config_change_counters()
                    .update_one(
                        doc! { "_id": Self::config_change_retention_doc_id(namespace) },
                        doc! {
                            "$max": { "retained_sequence": retained_sequence },
                            "$set": { "updated_at": Utc::now().to_rfc3339() },
                        },
                    )
                    .upsert(true)
                    .await?;
            }
            self.config_changes()
                .delete_many(doc! {
                    "namespace": namespace,
                    "sequence": { "$lte": cutoff as i64 },
                })
                .await?;
            Ok(())
        }

        async fn ensure_change_cursor_available(
            &self,
            namespace: &str,
            after_sequence: u64,
        ) -> Result<(), anyhow::Error> {
            let doc = self
                .config_change_counters()
                .find_one(doc! { "_id": Self::config_change_retention_doc_id(namespace) })
                .await?;
            if let Some(doc) = doc {
                let retained_sequence = match doc.get("retained_sequence") {
                    Some(Bson::Int64(value)) if *value >= 0 => *value as u64,
                    Some(Bson::Int32(value)) if *value >= 0 => *value as u64,
                    other => anyhow::bail!(
                        "MongoDB config change retention row has invalid sequence: {:?}",
                        other
                    ),
                };
                if after_sequence < retained_sequence {
                    anyhow::bail!(
                        "config change cursor {} for namespace '{}' is behind retained sequence {}",
                        after_sequence,
                        namespace,
                        retained_sequence
                    );
                }
            }
            Ok(())
        }

        async fn load_change_ids(
            &self,
            collection: MongoCollectionHandle,
            namespace: &str,
            ids: &[String],
        ) -> Result<Vec<Document>, anyhow::Error> {
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let mut docs = Vec::new();
            for chunk in ids.chunks(500) {
                let id_values: Vec<Bson> = chunk.iter().cloned().map(Bson::String).collect();
                let mut cursor = collection
                    .find(doc! { "namespace": namespace, "_id": { "$in": id_values } })
                    .await?;
                while cursor.advance().await? {
                    docs.push(cursor.deserialize_current()?);
                }
            }
            Ok(docs)
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
            let api_specs = self.api_specs();
            let mut cursor = api_specs.find(filter).with_options(options).await?;
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
        async fn cleanup_orphaned_proxy_group_plugins(
            &self,
            namespace: &str,
        ) -> Result<Vec<(String, String)>, anyhow::Error> {
            self.cleanup_orphaned_proxy_group_plugins_opt_session(namespace, None)
                .await
        }

        /// Same as [`Self::cleanup_orphaned_proxy_group_plugins`] but optionally
        /// participates in a `ClientSession`-scoped transaction.
        async fn cleanup_orphaned_proxy_group_plugins_opt_session(
            &self,
            namespace: &str,
            session: Option<&mut ClientSession>,
        ) -> Result<Vec<(String, String)>, anyhow::Error> {
            if let Some(s) = session {
                let plugin_configs = self.plugin_configs();
                let mut cursor = plugin_configs
                    .find(doc! { "scope": "proxy_group", "namespace": namespace })
                    .projection(doc! { "_id": 1, "namespace": 1 })
                    .session(&mut *s)
                    .await?;
                let mut group_plugins: Vec<(String, String)> = Vec::new();
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current()?;
                    if let Ok(id) = doc.get_str("_id") {
                        let namespace = doc
                            .get_str("namespace")
                            .map(str::to_string)
                            .unwrap_or_else(|_| crate::config::types::default_namespace());
                        group_plugins.push((id.to_string(), namespace));
                    }
                }
                drop(cursor);

                let mut deleted = Vec::new();
                for (id, namespace) in &group_plugins {
                    let count = self
                        .proxies()
                        .count_documents(doc! {
                            "namespace": namespace,
                            "plugins.plugin_config_id": id,
                        })
                        .session(&mut *s)
                        .await?;
                    if count == 0 {
                        info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
                        let result = self
                            .plugin_configs()
                            .delete_one(doc! { "_id": id, "namespace": namespace })
                            .session(&mut *s)
                            .await?;
                        if result.deleted_count > 0 {
                            deleted.push((id.clone(), namespace.clone()));
                        }
                    }
                }
                return Ok(deleted);
            }

            // Find all proxy_group-scoped plugin config IDs
            let plugin_configs = self.plugin_configs();
            let mut cursor = plugin_configs
                .find(doc! { "scope": "proxy_group", "namespace": namespace })
                .projection(doc! { "_id": 1, "namespace": 1 })
                .await?;
            let mut group_plugins: Vec<(String, String)> = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("_id") {
                    let namespace = doc
                        .get_str("namespace")
                        .map(str::to_string)
                        .unwrap_or_else(|_| crate::config::types::default_namespace());
                    group_plugins.push((id.to_string(), namespace));
                }
            }

            let mut deleted = Vec::new();
            for (id, namespace) in &group_plugins {
                // Check if any proxy still references this plugin config
                let count = self
                    .proxies()
                    .count_documents(doc! {
                        "namespace": namespace,
                        "plugins.plugin_config_id": id,
                    })
                    .await?;
                if count == 0 {
                    info!("Cascade-deleting orphaned proxy_group plugin config {}", id);
                    let result = self
                        .plugin_configs()
                        .delete_one(doc! { "_id": id, "namespace": namespace })
                        .await?;
                    if result.deleted_count > 0 {
                        deleted.push((id.clone(), namespace.clone()));
                    }
                }
            }

            Ok(deleted)
        }

        async fn find_mesh_route_dispatch_upstream_ref_opt_session(
            &self,
            session: Option<&mut ClientSession>,
            upstream_id: &str,
        ) -> Result<Option<PluginConfig>, anyhow::Error> {
            if let Some(s) = session {
                let plugin_configs = self.plugin_configs();
                let mut cursor = plugin_configs
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
                let plugin_configs = self.plugin_configs();
                let mut cursor = plugin_configs
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

        // -------------------------------------------------------------------
        // Proxy admission guards (route uniqueness + upstream references)
        // -------------------------------------------------------------------

        /// Take the per-(namespace, route-bucket) admission lock inside a
        /// transaction by upserting a lock document with a fresh nonce.
        ///
        /// This is the Mongo analogue of the SQL backend's
        /// `SELECT ... FOR UPDATE` lock row (`lock_proxy_route_bucket_tx`):
        /// two concurrent transactions writing the same lock document raise a
        /// WriteConflict, which the driver's `and_run` retry loop resolves by
        /// aborting and re-running one of them — serializing all admission
        /// checks for the same route bucket.
        async fn lock_proxy_route_bucket_in_session(
            &self,
            session: &mut ClientSession,
            namespace: &str,
            listen_path: Option<&str>,
        ) -> mongodb::error::Result<()> {
            let route_key_hash = proxy_route_key_hash(listen_path);
            self.proxy_route_locks()
                .update_one(
                    doc! { "_id": format!("{namespace}:{route_key_hash}") },
                    doc! {
                        "$set": {
                            "nonce": Uuid::new_v4().to_string(),
                            "updated_at": Utc::now().to_rfc3339(),
                        }
                    },
                )
                .upsert(true)
                .session(&mut *session)
                .await?;
            Ok(())
        }

        /// Session-aware variant of `check_listen_path_unique` — same
        /// candidate query and `hosts_overlap` logic, but every read runs on
        /// the caller's transaction session so it observes (and conflicts
        /// with) concurrent admissions serialized by the route-bucket lock.
        async fn check_listen_path_unique_in_session(
            &self,
            session: &mut ClientSession,
            namespace: &str,
            listen_path: Option<&str>,
            hosts: &[String],
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            if listen_path.is_none() && hosts.is_empty() {
                return Ok(false);
            }
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
            let proxies = self.proxies();
            let mut cursor = proxies
                .find(filter)
                .projection(doc! { "_id": 1, "hosts": 1 })
                .session(&mut *session)
                .await?;
            while cursor.advance(&mut *session).await? {
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

        /// Transaction-scoped proxy admission guards: route-bucket lock +
        /// uniqueness re-check, and (when the proxy references an upstream)
        /// the upstream reference guard + existence check.
        ///
        /// Mirrors the SQL backend's `ensure_proxy_route_unique_tx`: stream
        /// schemes (tcp/tcps/udp/dtls) skip route enforcement — they have
        /// their own `check_listen_port_unique` — and route conflicts surface
        /// as [`PROXY_ROUTE_CONFLICT_ERROR`] so the admin layer maps 409.
        async fn ensure_proxy_admission_guards_in_session(
            &self,
            session: &mut ClientSession,
            params: &ProxyWriteGuardParams,
            exclude_proxy_id: Option<&str>,
        ) -> mongodb::error::Result<()> {
            if !params.is_stream {
                self.lock_proxy_route_bucket_in_session(
                    &mut *session,
                    &params.namespace,
                    params.listen_path.as_deref(),
                )
                .await?;
                let unique = self
                    .check_listen_path_unique_in_session(
                        &mut *session,
                        &params.namespace,
                        params.listen_path.as_deref(),
                        &params.hosts,
                        exclude_proxy_id,
                    )
                    .await
                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                if !unique {
                    // Owned String payload — `mongodb::error::Error`'s Display
                    // only surfaces custom payloads that downcast to String,
                    // and the admin layer matches this substring for 409.
                    return Err(mongodb::error::Error::custom(
                        PROXY_ROUTE_CONFLICT_ERROR.to_string(),
                    ));
                }
            }
            if let Some(ref upstream_id) = params.upstream_id {
                // Guard doc: a concurrent `delete_upstream` transaction writes
                // the same document, so create-referencing and delete
                // write-conflict and serialize instead of racing.
                self.upstream_ref_guards()
                    .update_one(
                        doc! { "_id": format!("{}:{}", params.namespace, upstream_id) },
                        doc! {
                            "$set": {
                                "nonce": Uuid::new_v4().to_string(),
                                "updated_at": Utc::now().to_rfc3339(),
                            }
                        },
                    )
                    .upsert(true)
                    .session(&mut *session)
                    .await?;
                let exists = self
                    .upstreams()
                    .find_one(doc! {
                        "_id": upstream_id.as_str(),
                        "namespace": params.namespace.as_str(),
                    })
                    .projection(doc! { "_id": 1 })
                    .session(&mut *session)
                    .await?
                    .is_some();
                if !exists {
                    return Err(mongodb::error::Error::custom(format!(
                        "referenced upstream '{}' does not exist in namespace '{}'",
                        upstream_id, params.namespace
                    )));
                }
            }
            Ok(())
        }

        /// Standalone-path upstream existence check for proxy writes.
        async fn upstream_exists_in_namespace(
            &self,
            namespace: &str,
            upstream_id: &str,
        ) -> Result<bool, anyhow::Error> {
            let existing = self
                .upstreams()
                .find_one(doc! { "_id": upstream_id, "namespace": namespace })
                .projection(doc! { "_id": 1 })
                .await?;
            Ok(existing.is_some())
        }

        /// Fetch every proxy in the same (namespace, listen_path) route
        /// bucket, excluding stream schemes, with the fields needed for the
        /// standalone post-write reconciliation: `_id`, `hosts`, and the
        /// stored `created_at` string.
        async fn listen_path_bucket_candidates(
            &self,
            namespace: &str,
            listen_path: Option<&str>,
        ) -> Result<Vec<RouteBucketCandidate>, anyhow::Error> {
            let mut filter = match listen_path {
                Some(path) => doc! { "namespace": namespace, "listen_path": path },
                None => doc! { "namespace": namespace, "listen_path": null },
            };
            filter.insert(
                "backend_scheme",
                doc! { "$nin": ["tcp", "tcps", "udp", "dtls"] },
            );
            let proxies = self.proxies();
            let mut cursor = proxies
                .find(filter)
                .projection(doc! { "_id": 1, "hosts": 1, "created_at": 1 })
                .await?;
            let mut candidates = Vec::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                let Ok(id) = doc.get_str("_id") else {
                    continue;
                };
                let hosts: Vec<String> = doc
                    .get_array("hosts")
                    .ok()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let created_at = doc.get_str("created_at").unwrap_or_default().to_string();
                candidates.push(RouteBucketCandidate {
                    id: id.to_string(),
                    hosts,
                    created_at,
                });
            }
            Ok(candidates)
        }

        /// Deterministic loser-yield for the standalone proxy-route
        /// reconciliation: after writing its own document, a writer re-reads
        /// the route bucket and yields iff some conflicting document has a
        /// strictly smaller `(created_at, _id)` pair. `created_at` is a
        /// stored RFC 3339 string, so string comparison is deterministic and
        /// both racers reading the same committed documents reach the same
        /// verdict (chronological fidelity at sub-second precision is not
        /// required — only a total order is).
        ///
        /// This narrows the standalone TOCTOU to convergent post-write
        /// reconciliation: whichever racer observes the conflict deletes the
        /// losing document. A residual window remains when the loser's
        /// re-check runs before the winner's write lands; full serialization
        /// requires `FERRUM_MONGO_REPLICA_SET` (transactions + route-bucket
        /// lock docs).
        fn standalone_route_writer_should_yield(
            my_id: &str,
            my_hosts: &[String],
            candidates: &[RouteBucketCandidate],
        ) -> bool {
            let Some(me) = candidates.iter().find(|c| c.id == my_id) else {
                // Our own write is already gone (concurrent delete) — nothing
                // to yield.
                return false;
            };
            candidates.iter().any(|other| {
                other.id != my_id
                    && crate::config::types::hosts_overlap(my_hosts, &other.hosts)
                    && (other.created_at.as_str(), other.id.as_str())
                        < (me.created_at.as_str(), me.id.as_str())
            })
        }

        /// Standalone updates mutate a document that already owned its old
        /// route. After replacement, any overlapping route owned by another
        /// proxy makes the update yield and restore its previous document.
        /// This differs from create-vs-create ordering: an existing proxy's
        /// original `created_at` must not let a later route mutation displace
        /// a concurrently admitted create.
        fn standalone_route_update_has_conflict(
            my_id: &str,
            my_hosts: &[String],
            candidates: &[RouteBucketCandidate],
        ) -> bool {
            candidates.iter().any(|other| {
                other.id != my_id && crate::config::types::hosts_overlap(my_hosts, &other.hosts)
            })
        }

        // -------------------------------------------------------------------
        // Consumer identity index maintenance
        // -------------------------------------------------------------------

        /// Reserve identity docs for `values` inside a transaction using a
        /// preflight read-then-insert protocol: every requested value is read
        /// and validated BEFORE any potentially-aborting write, so stale
        /// same-owner reservations are adopted without ever relying on reads or
        /// repair writes after an E11000 in an already-failed transaction. See
        /// [`Self::preflight_reserve_consumer_identity_docs_in_session`].
        async fn insert_consumer_identity_docs_in_session(
            &self,
            session: &mut ClientSession,
            namespace: &str,
            consumer_id: &str,
            values: &[String],
        ) -> mongodb::error::Result<()> {
            if values.is_empty() {
                return Ok(());
            }
            self.preflight_reserve_consumer_identity_docs_in_session(
                session,
                &consumer_identity_index_docs(namespace, consumer_id, values),
            )
            .await
        }

        /// Preflight-reserve a set of `consumer_identity_index` candidate docs
        /// inside a transaction. Every candidate is read first — one batched
        /// `_id` `$in` read using the transaction's own read concern — and
        /// classified BEFORE any write:
        ///   - a same-owner reservation is adopted (skipped);
        ///   - a different-owner or malformed reservation fails closed as a
        ///     duplicate-key conflict — the "duplicate key" text maps to HTTP
        ///     409;
        ///   - only preflight-absent candidates are inserted.
        ///
        /// A duplicate key on the insert of a preflight-absent candidate means
        /// a concurrent writer committed the same reservation in the read→write
        /// window (or two candidates in this batch collide on one identity
        /// value). That aborts the transaction; the error is propagated WITHOUT
        /// any further reads or repair writes — the session is no longer usable
        /// and must never be treated as if it were. The convenient-transaction
        /// runner retries the whole closure on the resulting transient write
        /// conflict, and the retry's preflight then observes the now-committed
        /// reservation and either adopts it or fails closed. There is
        /// intentionally no post-E11000 recovery read/write in this
        /// already-failed transaction.
        async fn preflight_reserve_consumer_identity_docs_in_session(
            &self,
            session: &mut ClientSession,
            candidates: &[Document],
        ) -> mongodb::error::Result<()> {
            if candidates.is_empty() {
                return Ok(());
            }
            // Batched preflight read of every candidate reservation's current
            // owner, inside the transaction, before any write.
            let mut ids: Vec<Bson> = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                let doc_id = consumer_identity_field(candidate, "_id")?;
                ids.push(Bson::String(doc_id.to_string()));
            }
            let mut existing_owners = std::collections::HashMap::<String, String>::new();
            let mut cursor = self
                .consumer_identity_index()
                .find(doc! { "_id": { "$in": ids } })
                .session(&mut *session)
                .await?;
            while cursor.advance(&mut *session).await? {
                let existing = cursor.deserialize_current()?;
                let doc_id = consumer_identity_field(&existing, "_id")?;
                let owner = consumer_identity_field(&existing, "consumer_id")?;
                existing_owners.insert(doc_id.to_string(), owner.to_string());
            }
            drop(cursor);

            // Classify every candidate against the preflight snapshot. Only
            // preflight-absent candidates are inserted; a different owner or a
            // malformed reservation fails closed (409) with no write attempted.
            let mut to_insert: Vec<Document> = Vec::new();
            for candidate in candidates {
                let doc_id = consumer_identity_field(candidate, "_id")?;
                let consumer_id = consumer_identity_field(candidate, "consumer_id")?;
                match existing_owners.get(doc_id) {
                    Some(owner) => {
                        if owner.as_str() != consumer_id {
                            return Err(mongodb::error::Error::custom(format!(
                                "E11000 duplicate key error: consumer identity reservation \
                                 '{doc_id}' is reserved by consumer '{owner}'"
                            )));
                        }
                        // Same owner ⇒ adopt the existing reservation.
                    }
                    None => to_insert.push(candidate.clone()),
                }
            }
            if to_insert.is_empty() {
                return Ok(());
            }
            // Insert ONLY preflight-absent reservations. A duplicate key here is
            // a concurrent race in the read→write window (or an intra-batch
            // collision): it aborts the transaction and is propagated as-is. Do
            // not follow it with any session operation.
            self.consumer_identity_index()
                .insert_many(to_insert)
                .session(&mut *session)
                .await?;
            Ok(())
        }

        /// Delete this consumer's reservations for specific identity values
        /// inside a transaction. Filtered by `consumer_id` so a value that
        /// was already re-claimed by another consumer is never touched.
        async fn delete_consumer_identity_values_in_session(
            &self,
            session: &mut ClientSession,
            namespace: &str,
            consumer_id: &str,
            values: &[String],
        ) -> mongodb::error::Result<()> {
            if values.is_empty() {
                return Ok(());
            }
            let ids: Vec<Bson> = values
                .iter()
                .map(|value| Bson::String(consumer_identity_doc_id(namespace, value)))
                .collect();
            self.consumer_identity_index()
                .delete_many(doc! { "_id": { "$in": ids }, "consumer_id": consumer_id })
                .session(&mut *session)
                .await?;
            Ok(())
        }

        /// For an ORDERED `insert_many` failure, the number of leading
        /// documents that were actually inserted (everything before the first
        /// reported write-error index; later documents were never attempted).
        /// Unknown failures, including InsertMany errors without a reported
        /// write-error index, return `None`: cleanup cannot safely attribute
        /// any reservation to this attempt and must retain all of them.
        fn ordered_insert_inserted_prefix_len(err: &mongodb::error::Error) -> Option<usize> {
            let mongodb::error::ErrorKind::InsertMany(insert_error) = err.kind.as_ref() else {
                return None;
            };
            insert_error
                .write_errors
                .as_deref()?
                .iter()
                .map(|write_error| write_error.index)
                .min()
        }

        /// Standalone reserve-first: insert the identity reservations BEFORE
        /// writing the consumer document. A duplicate-key error is treated as
        /// success when every conflicting reservation is already owned by this
        /// consumer (orphaned same-owner retry / stale release). A different
        /// owner still bails after best-effort deleting (1) the verifiable
        /// ordered-insert prefix and (2) vacant reservations this adoption
        /// attempt inserted before failing — never pre-existing same-owner
        /// adoptions.
        ///
        /// On success, returns only the identity values **this attempt newly
        /// inserted**. Later write-path rollback must release that set alone —
        /// never adopted same-owner reservations whose provenance is unknown
        /// (they may belong to a live consumer or a prior durable orphan that
        /// another retry still needs).
        async fn reserve_consumer_identity_docs_standalone(
            &self,
            namespace: &str,
            consumer_id: &str,
            values: &[String],
        ) -> Result<Vec<String>, anyhow::Error> {
            if values.is_empty() {
                return Ok(Vec::new());
            }
            if let Err(err) = self
                .consumer_identity_index()
                .insert_many(consumer_identity_index_docs(namespace, consumer_id, values))
                .await
            {
                if is_duplicate_key(&err) {
                    match self
                        .ensure_consumer_identity_docs_owned(namespace, consumer_id, values)
                        .await
                    {
                        Ok(ensured_new) => {
                            let inserted_prefix = Self::ordered_insert_inserted_prefix_len(&err);
                            let mut newly_inserted =
                                ordered_insert_newly_inserted_prefix(values, inserted_prefix)
                                    .to_vec();
                            if inserted_prefix.is_none() {
                                warn!(
                                    "Retaining MongoDB consumer identity reservations for '{}' in \
                                     namespace '{}' that may have been inserted by a failed ordered \
                                     insert without a verifiable write-error index; rollback will \
                                     only release values newly inserted during same-owner adoption",
                                    consumer_id, namespace
                                );
                            }
                            for value in ensured_new {
                                if !newly_inserted.contains(&value) {
                                    newly_inserted.push(value);
                                }
                            }
                            return Ok(newly_inserted);
                        }
                        Err(adopt_err) => {
                            let inserted_prefix = Self::ordered_insert_inserted_prefix_len(&err);
                            if inserted_prefix.is_none() {
                                warn!(
                                    "Retaining MongoDB consumer identity reservations for '{}' in \
                                     namespace '{}' because the failed ordered insert did not report \
                                     a verifiable write-error index; still releasing vacant \
                                     reservations inserted during this adoption attempt",
                                    consumer_id, namespace
                                );
                            }
                            let to_release = consumer_identity_adoption_failure_release_values(
                                values,
                                inserted_prefix,
                                &adopt_err.newly_inserted,
                            );
                            self.release_consumer_identity_values_best_effort(
                                namespace,
                                consumer_id,
                                &to_release,
                            )
                            .await;
                            return Err(adopt_err.into_source());
                        }
                    }
                }
                if let Some(inserted) = Self::ordered_insert_inserted_prefix_len(&err) {
                    self.release_consumer_identity_values_best_effort(
                        namespace,
                        consumer_id,
                        &values[..inserted],
                    )
                    .await;
                } else {
                    warn!(
                        "Retaining MongoDB consumer identity reservations for '{}' in namespace \
                         '{}' because the failed ordered insert did not report a verifiable \
                         write-error index",
                        consumer_id, namespace
                    );
                }
                return Err(err.into());
            }
            Ok(values.to_vec())
        }

        /// Ensure every identity value is reserved by `consumer_id`.
        ///
        /// Used after an E11000 on `insert_many`: same-owner docs are adopted;
        /// vacant docs are inserted; a different owner is a conflict (message
        /// retains "duplicate key" so the admin layer maps to HTTP 409).
        ///
        /// On success, returns identity values this call newly inserted (safe
        /// to roll back). Adopted existing docs are omitted — their provenance
        /// is unknown. On failure, [`ConsumerIdentityEnsureOwnedError`] still
        /// carries the exact vacant inserts committed before the failure so
        /// callers can release that provenance.
        async fn ensure_consumer_identity_docs_owned(
            &self,
            namespace: &str,
            consumer_id: &str,
            values: &[String],
        ) -> Result<Vec<String>, ConsumerIdentityEnsureOwnedError> {
            let mut newly_inserted = Vec::new();
            for value in values {
                let doc_id = consumer_identity_doc_id(namespace, value);
                let existing = match self
                    .consumer_identity_index()
                    .find_one(doc! { "_id": &doc_id })
                    .await
                {
                    Ok(existing) => existing,
                    Err(err) => {
                        return Err(ConsumerIdentityEnsureOwnedError::new(
                            newly_inserted,
                            err.into(),
                        ));
                    }
                };
                match existing {
                    Some(existing) => {
                        let owner = match existing.get_str("consumer_id") {
                            Ok(owner) => owner,
                            Err(e) => {
                                return Err(ConsumerIdentityEnsureOwnedError::new(
                                    newly_inserted,
                                    anyhow::anyhow!(
                                        "consumer_identity_index doc '{}' missing consumer_id: {}",
                                        doc_id,
                                        e
                                    ),
                                ));
                            }
                        };
                        // Same owner ⇒ adopt the existing reservation (orphaned
                        // retry / stale release). A different owner is a conflict;
                        // the "duplicate key" text maps to HTTP 409. Live
                        // reservations are never stolen.
                        if owner != consumer_id {
                            return Err(ConsumerIdentityEnsureOwnedError::new(
                                newly_inserted,
                                anyhow::anyhow!(
                                    "E11000 duplicate key error: identity value '{}' in \
                                     namespace '{}' is reserved by consumer '{}'",
                                    value,
                                    namespace,
                                    owner
                                ),
                            ));
                        }
                    }
                    None => {
                        let doc = consumer_identity_index_doc(namespace, value, consumer_id);
                        if let Err(err) = self.consumer_identity_index().insert_one(doc).await {
                            if !is_duplicate_key(&err) {
                                return Err(ConsumerIdentityEnsureOwnedError::new(
                                    newly_inserted,
                                    err.into(),
                                ));
                            }
                            let existing = match self
                                .consumer_identity_index()
                                .find_one(doc! { "_id": &doc_id })
                                .await
                            {
                                Ok(existing) => existing,
                                Err(find_err) => {
                                    return Err(ConsumerIdentityEnsureOwnedError::new(
                                        newly_inserted,
                                        find_err.into(),
                                    ));
                                }
                            };
                            let Some(existing) = existing else {
                                return Err(ConsumerIdentityEnsureOwnedError::new(
                                    newly_inserted,
                                    err.into(),
                                ));
                            };
                            let owner = match existing.get_str("consumer_id") {
                                Ok(owner) => owner,
                                Err(e) => {
                                    return Err(ConsumerIdentityEnsureOwnedError::new(
                                        newly_inserted,
                                        anyhow::anyhow!(
                                            "consumer_identity_index doc '{}' missing \
                                             consumer_id: {}",
                                            doc_id,
                                            e
                                        ),
                                    ));
                                }
                            };
                            if owner != consumer_id {
                                return Err(ConsumerIdentityEnsureOwnedError::new(
                                    newly_inserted,
                                    anyhow::anyhow!(
                                        "E11000 duplicate key error: identity value '{}' in \
                                         namespace '{}' is reserved by consumer '{}'",
                                        value,
                                        namespace,
                                        owner
                                    ),
                                ));
                            }
                            // Lost the insert race to another same-owner writer —
                            // provenance unknown; do not mark rollback-safe.
                        } else {
                            newly_inserted.push(value.clone());
                        }
                    }
                }
            }
            Ok(newly_inserted)
        }

        // NOTE: There is intentionally NO startup/orphan reconcile that deletes
        // `consumer_identity_index` docs whose consumer point-read is absent.
        // The migration lease serializes migration runners only — not normal
        // consumer CRUD across serving nodes. A standalone reserve-first create
        // can commit the reservation and still be awaiting `consumers.insert_one`
        // while another node observes the consumer absent and would reclaim the
        // live reservation, leaving the delayed create unguarded. Automatic
        // different-owner reclamation would need attempt/generation identity,
        // bounded leases, atomic conditional takeover, and writer-side
        // verify/rollback; without that protocol, permanent conservative lockout
        // (healed by same-owner E11000 adoption or manual mongosh surgery) is
        // preferred over corrupting uniqueness.

        /// Best-effort compensation: delete identity reservations this call
        /// inserted. Filtered by `consumer_id` so reservations owned by other
        /// consumers (including the one that won a duplicate-key race) are
        /// never deleted.
        async fn release_consumer_identity_values_best_effort(
            &self,
            namespace: &str,
            consumer_id: &str,
            values: &[String],
        ) {
            if values.is_empty() {
                return;
            }
            let ids: Vec<Bson> = values
                .iter()
                .map(|value| Bson::String(consumer_identity_doc_id(namespace, value)))
                .collect();
            if let Err(err) = self
                .consumer_identity_index()
                .delete_many(doc! { "_id": { "$in": ids }, "consumer_id": consumer_id })
                .await
            {
                warn!(
                    "MongoDB best-effort consumer identity reservation rollback failed for \
                     consumer '{}' in namespace '{}': {}",
                    consumer_id, namespace, err
                );
            }
        }

        /// Release reservations only for identity docs **this attempt newly
        /// inserted**, and only when the owning consumer document's compensating
        /// delete was confirmed. Adopted same-owner reservations and docs for
        /// unverified rollback chunks are retained so a live consumer (or a
        /// durable orphan still needed by same-owner retry) cannot lose its
        /// uniqueness guard.
        async fn release_confirmed_batch_consumer_identity_docs_best_effort(
            &self,
            newly_inserted_identity_docs: &[Document],
            confirmed_absent_doc_ids: &HashSet<String>,
        ) {
            let docs_to_release: Vec<Document> = newly_inserted_identity_docs
                .iter()
                .filter(|doc| {
                    let Ok(namespace) = doc.get_str("namespace") else {
                        return false;
                    };
                    let Ok(consumer_id) = doc.get_str("consumer_id") else {
                        return false;
                    };
                    confirmed_absent_doc_ids.contains(&consumer_doc_id(namespace, consumer_id))
                })
                .cloned()
                .collect();
            self.release_consumer_identity_docs_best_effort(&docs_to_release)
                .await;
        }

        /// Best-effort deletion of specific identity-index documents
        /// (matched by both `_id` and `consumer_id`), used to release exactly
        /// the prefix an ordered batch reservation insert managed to commit.
        async fn release_consumer_identity_docs_best_effort(&self, docs: &[Document]) {
            for chunk in docs.chunks(500) {
                let clauses: Vec<Document> = chunk
                    .iter()
                    .filter_map(|doc| {
                        let id = doc.get_str("_id").ok()?;
                        let consumer_id = doc.get_str("consumer_id").ok()?;
                        Some(doc! { "_id": id, "consumer_id": consumer_id })
                    })
                    .collect();
                if clauses.is_empty() {
                    continue;
                }
                if let Err(err) = self
                    .consumer_identity_index()
                    .delete_many(doc! { "$or": clauses })
                    .await
                {
                    warn!(
                        "MongoDB best-effort batch consumer identity reservation rollback \
                         failed: {}",
                        err
                    );
                    return;
                }
            }
        }

        /// Load plain consumer `id` values (not the composite `_id`) matching
        /// a cold-path filter — change-log records carry plain resource ids.
        async fn load_consumer_plain_ids_filtered(
            &self,
            filter: Document,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let consumers = self.consumers();
            let options = FindOptions::builder().projection(doc! { "id": 1 }).build();
            let mut cursor = consumers.find(filter).with_options(options).await?;
            let mut ids = HashSet::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("id") {
                    ids.insert(id.to_string());
                }
            }
            Ok(ids)
        }

        async fn load_consumer_plain_ids_filtered_in_session(
            &self,
            session: &mut ClientSession,
            filter: Document,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let consumers = self.consumers();
            let mut cursor = consumers
                .find(filter)
                .projection(doc! { "id": 1 })
                .session(&mut *session)
                .await?;
            let mut ids = HashSet::new();
            while cursor.advance(&mut *session).await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("id") {
                    ids.insert(id.to_string());
                }
            }
            Ok(ids)
        }

        async fn current_api_spec_resource_hash(
            &self,
            bundle: &crate::admin::api_specs::ExtractedBundle,
            spec: &ApiSpec,
            previous_declared_assoc_ids: &HashSet<String>,
        ) -> Result<Option<String>, anyhow::Error> {
            let plugin_configs = self.plugin_configs();
            let mut plugin_cursor = plugin_configs
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

            let upstreams_collection = self.upstreams();
            let mut upstream_cursor = upstreams_collection
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
                let upstreams_collection = self.upstreams();
                let mut upstream_cursor = upstreams_collection
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
                let plugin_configs = self.plugin_configs();
                let mut plugin_cursor = plugin_configs
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
                let upstreams_collection = self.upstreams();
                let mut upstream_cursor = upstreams_collection
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
                let plugin_configs = self.plugin_configs();
                let mut plugin_cursor = plugin_configs
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

    /// Convert a paginated `offset` into MongoDB's unsigned `skip`.
    ///
    /// Admin callers bound `offset` to `0..=i64::MAX` in
    /// `admin::parse_pagination` before it ever reaches a store, so a negative
    /// value is unreachable here. This helper enforces that invariant at the
    /// call site anyway: a bare `offset as u64` would reinterpret a negative
    /// offset as an enormous skip, which is precisely the wraparound this
    /// pagination contract exists to prevent. Defense in depth for any future
    /// caller of the public `DatabaseBackend` trait.
    fn mongo_skip(offset: i64) -> u64 {
        debug_assert!(offset >= 0, "offset must be non-negative");
        offset.max(0) as u64
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

    /// Composite MongoDB `_id` for consumer documents: `"{namespace}:{id}"`.
    ///
    /// The namespace charset forbids `':'`, so the first `':'` is an
    /// unambiguous delimiter between namespace and id. Using a composite key
    /// makes consumer ids unique per namespace instead of globally (issue
    /// #2121). The serde-serialized `id` and `namespace` fields remain in the
    /// document — all reads strip `_id` before deserializing.
    fn consumer_doc_id(namespace: &str, id: &str) -> String {
        format!("{namespace}:{id}")
    }

    /// Composite `_id` for `consumer_identity_index` documents:
    /// `"{namespace}:{identity_value}"`. Same delimiter rationale as
    /// [`consumer_doc_id`].
    fn consumer_identity_doc_id(namespace: &str, value: &str) -> String {
        format!("{namespace}:{value}")
    }

    /// The identity values a consumer claims in the merged per-namespace
    /// identity keyspace: id ∪ username ∪ custom_id. Self-collisions within
    /// one consumer are allowed, so the set is deduped.
    fn consumer_identity_values(consumer: &Consumer) -> Vec<String> {
        let mut values = vec![consumer.id.clone(), consumer.username.clone()];
        if let Some(ref custom_id) = consumer.custom_id {
            values.push(custom_id.clone());
        }
        values.sort();
        values.dedup();
        values
    }

    fn consumer_identity_index_doc(namespace: &str, value: &str, consumer_id: &str) -> Document {
        doc! {
            "_id": consumer_identity_doc_id(namespace, value),
            "namespace": namespace,
            "identity_value": value,
            "consumer_id": consumer_id,
        }
    }

    fn consumer_identity_index_docs(
        namespace: &str,
        consumer_id: &str,
        values: &[String],
    ) -> Vec<Document> {
        values
            .iter()
            .map(|value| consumer_identity_index_doc(namespace, value, consumer_id))
            .collect()
    }

    /// Extract a required string field from a `consumer_identity_index`
    /// reservation candidate or stored document, mapping a missing or mistyped
    /// field to a transaction error instead of panicking. Used by the
    /// preflight replica-set reservation path.
    fn consumer_identity_field<'a>(
        doc: &'a Document,
        field: &str,
    ) -> mongodb::error::Result<&'a str> {
        doc.get_str(field).map_err(|_| {
            mongodb::error::Error::custom(format!(
                "consumer_identity_index reservation doc missing field '{field}'"
            ))
        })
    }

    /// Failure from [`MongoStore::ensure_consumer_identity_docs_owned`] that
    /// preserves vacant reservations this adoption attempt inserted before the
    /// failure. Callers must best-effort release `newly_inserted` (in addition
    /// to any verifiable ordered-insert prefix) and must never treat adopted
    /// pre-existing same-owner reservations as rollback-safe.
    ///
    /// Crate-internal only: the type is not exposed through any public or
    /// `_test_support` surface; failure provenance is exercised through the
    /// `consumer_identity_adoption_failure_release_values` helper and the
    /// standalone/batch reserve paths.
    #[derive(Debug)]
    struct ConsumerIdentityEnsureOwnedError {
        /// Exact identity values this ensure call newly inserted before failing.
        newly_inserted: Vec<String>,
        source: anyhow::Error,
    }

    impl ConsumerIdentityEnsureOwnedError {
        fn new(newly_inserted: Vec<String>, source: anyhow::Error) -> Self {
            Self {
                newly_inserted,
                source,
            }
        }

        /// Consume the error, returning the underlying source for propagation.
        fn into_source(self) -> anyhow::Error {
            self.source
        }
    }

    impl std::fmt::Display for ConsumerIdentityEnsureOwnedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.source)
        }
    }

    impl std::error::Error for ConsumerIdentityEnsureOwnedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source.source()
        }
    }

    /// Ordered `insert_many` E11000: only the prefix before `first_error_index`
    /// was inserted by this attempt. `None` means attribution is unknown —
    /// retain everything (return an empty rollback-safe slice).
    pub(crate) fn ordered_insert_newly_inserted_prefix<T>(
        values: &[T],
        first_error_index: Option<usize>,
    ) -> &[T] {
        match first_error_index {
            Some(i) if i <= values.len() => &values[..i],
            _ => &[],
        }
    }

    /// Failure-path release set after a partial ordered insert entered
    /// same-owner adoption and then failed.
    ///
    /// Includes (1) the verifiable ordered-insert prefix and (2) vacant
    /// reservations this adoption attempt inserted before failing. Unknown
    /// ordered-insert provenance (`None`) contributes nothing — those
    /// reservations are retained. Pre-existing same-owner adoptions must not
    /// appear in `adoption_newly_inserted`.
    pub(crate) fn consumer_identity_adoption_failure_release_values(
        ordered_values: &[String],
        ordered_first_error_index: Option<usize>,
        adoption_newly_inserted: &[String],
    ) -> Vec<String> {
        let mut out =
            ordered_insert_newly_inserted_prefix(ordered_values, ordered_first_error_index)
                .to_vec();
        for value in adoption_newly_inserted {
            if !out.contains(value) {
                out.push(value.clone());
            }
        }
        out
    }

    /// Convert a domain `Consumer` into a BSON `Document`.
    fn consumer_to_doc(consumer: &Consumer) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(consumer)?;
        // Composite `_id` ("{namespace}:{id}") — consumer ids are unique per
        // namespace, not globally. See `consumer_doc_id`.
        doc.insert("_id", consumer_doc_id(&consumer.namespace, &consumer.id));
        // `custom_id` participates in the `{namespace, custom_id}` unique+
        // sparse index. Strip when absent for the same reason as Proxy above.
        strip_null_fields(&mut doc, &["custom_id"]);
        // New writes carry a derived, deduplicated secret-hash projection for
        // the namespace-scoped unique multikey index. Legacy documents lack
        // this field, so adding the index does not make pre-existing duplicate
        // credentials block startup; snapshot admission still quarantines
        // those until an operator repairs them. Never index the raw secret.
        let mut hmac_secret_hashes: Vec<String> = consumer
            .credential_entries("hmac_auth")
            .into_iter()
            .filter_map(|entry| entry.get("secret").and_then(serde_json::Value::as_str))
            .map(credential_value_hash)
            .collect();
        hmac_secret_hashes.sort();
        hmac_secret_hashes.dedup();
        if !hmac_secret_hashes.is_empty() {
            doc.insert(HMAC_SECRET_HASHES_FIELD, hmac_secret_hashes);
        }
        Ok(doc)
    }

    fn doc_to_consumer(mut doc: Document) -> Result<Consumer, anyhow::Error> {
        doc.remove("_id");
        doc.remove(HMAC_SECRET_HASHES_FIELD);
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

    fn map_snapshot_document_error(
        snapshot: bool,
        resource_type: &'static str,
        resource_id: Option<String>,
        error: impl Into<anyhow::Error>,
    ) -> anyhow::Error {
        let error = error.into();
        if snapshot {
            anyhow::Error::new(SnapshotDataIntegrityError::new(
                resource_type,
                resource_id,
                error,
            ))
        } else {
            error
        }
    }

    fn decode_loaded_document<T>(
        doc: Document,
        snapshot: bool,
        resource_type: &'static str,
        decode: fn(Document) -> Result<T, anyhow::Error>,
    ) -> Result<T, anyhow::Error> {
        let resource_id = doc.get_str("_id").ok().map(str::to_string);
        decode(doc).map_err(|error| {
            map_snapshot_document_error(snapshot, resource_type, resource_id, error)
        })
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

    #[derive(Clone)]
    struct PreparedApiSpecBundleDocs {
        upstream: Option<(String, Document)>,
        additional_upstreams: Vec<(String, Document)>,
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
            additional_upstreams: Vec::new(),
            plugins,
            proxy: (bundle.proxy.id.clone(), proxy_doc),
            spec: spec_doc,
        })
    }

    fn prepare_api_spec_restore_docs(
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
        additional_upstreams: &[Upstream],
        additional_plugins: &[PluginConfig],
    ) -> Result<PreparedApiSpecBundleDocs, anyhow::Error> {
        let mut prepared = prepare_api_spec_bundle_docs(bundle, spec)?;
        prepared
            .additional_upstreams
            .reserve(additional_upstreams.len());
        for upstream in additional_upstreams {
            prepared
                .additional_upstreams
                .push((upstream.id.clone(), upstream_to_doc(upstream)?));
        }
        prepared.plugins.reserve(additional_plugins.len());
        for plugin in additional_plugins {
            prepared
                .plugins
                .push((plugin.id.clone(), plugin_config_to_doc(plugin)?));
        }
        Ok(prepared)
    }

    async fn validate_api_spec_restore_candidate_in_session(
        store: &MongoStore,
        connection: &MongoConnectionBundle,
        session: &mut ClientSession,
        namespace: &str,
        restored_proxy_id: &str,
        validation_http_client: &crate::plugins::PluginHttpClient,
    ) -> Result<(), anyhow::Error> {
        let proxies = store
            .load_full_proxies_opt_session(namespace, Some((connection, &mut *session)), true)
            .await?;
        let plugin_configs = store
            .load_full_plugin_configs_opt_session(
                namespace,
                Some((connection, &mut *session)),
                true,
            )
            .await?;
        let upstreams = store
            .load_full_upstreams_opt_session(namespace, Some((connection, &mut *session)), true)
            .await?;
        let mut candidate = GatewayConfig {
            version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
            proxies,
            plugin_configs,
            upstreams,
            loaded_at: Utc::now(),
            ..Default::default()
        };
        candidate.normalize_fields();
        let recovered_graph = crate::config::db_backend::api_spec_recovered_proxy_graph(
            candidate.clone(),
            restored_proxy_id,
        )?;
        if let Err(errors) = recovered_graph.validate_plugin_references() {
            anyhow::bail!(
                "restore_api_spec_bundle produced invalid proxy/plugin associations: {}",
                errors.join("; ")
            );
        }
        if let Err(errors) = recovered_graph.validate_upstream_references() {
            anyhow::bail!(
                "restore_api_spec_bundle produced invalid proxy/upstream references: {}",
                errors.join("; ")
            );
        }
        crate::config::db_backend::validate_api_spec_recovered_plugin_graph(
            &recovered_graph,
            validation_http_client,
        )
        .await?;
        crate::plugin_cache::validate_tcp_connection_throttle_attachments(&candidate).map_err(
            |errors| anyhow::Error::new(TcpConnectionThrottleAttachmentConflict::new(errors)),
        )?;
        if !candidate.has_effective_mtls_dns_identity_policy() {
            return Ok(());
        }
        candidate.consumers = store
            .load_full_consumers_opt_session(namespace, Some((connection, &mut *session)), true)
            .await?;
        candidate
            .validate_unique_mtls_dns_identities()
            .map_err(|errors| anyhow::Error::new(MtlsDnsIdentityConflict::new(errors)))
    }

    // -----------------------------------------------------------------------
    // DatabaseBackend trait implementation
    // -----------------------------------------------------------------------

    #[async_trait]
    impl NamespaceConfigAdmissionLeaseBackend for MongoStore {
        async fn try_acquire_namespace_config_admission_lease(
            &self,
            namespace: &str,
            owner: &str,
        ) -> Result<Option<u64>, anyhow::Error> {
            let collection = self.config_admission_locks();
            let result = collection
                .find_one_and_update(
                    doc! { "_id": namespace },
                    Self::server_time_lease_acquire_pipeline(
                        owner,
                        CONFIG_ADMISSION_LEASE_DURATION_MILLIS,
                    ),
                )
                .upsert(true)
                .return_document(ReturnDocument::After)
                .await;
            let result = match result {
                Err(error) if is_pipeline_update_unsupported(&error) => {
                    let now = self.lease_server_time().await?;
                    let expires_at = BsonDateTime::from_millis(
                        now.timestamp_millis() + CONFIG_ADMISSION_LEASE_DURATION_MILLIS,
                    );
                    let retained = collection
                        .find_one_and_update(
                            doc! { "_id": namespace, "owner": owner },
                            doc! {
                                "$set": {
                                    "expires_at": expires_at,
                                    "updated_at": now,
                                },
                            },
                        )
                        .return_document(ReturnDocument::After)
                        .await?;
                    if retained.is_some() {
                        Ok(retained)
                    } else {
                        collection
                            .find_one_and_update(
                                doc! {
                                    "_id": namespace,
                                    "$or": [
                                        { "expires_at": { "$exists": false } },
                                        { "expires_at": { "$lte": now } },
                                        { "owner": owner },
                                    ],
                                },
                                doc! {
                                    "$set": {
                                        "owner": owner,
                                        "expires_at": expires_at,
                                        "updated_at": now,
                                    },
                                    "$inc": { "generation": 1_i64 },
                                    "$setOnInsert": { "created_at": now },
                                },
                            )
                            .upsert(true)
                            .return_document(ReturnDocument::After)
                            .await
                    }
                }
                result => result,
            };
            match result {
                Ok(Some(document)) if document.get_str("owner").ok() == Some(owner) => {
                    let generation = document.get_i64("generation").map_err(anyhow::Error::new)?;
                    Ok(Some(u64::try_from(generation).map_err(|_| {
                        anyhow::anyhow!("namespace config admission generation is negative")
                    })?))
                }
                Ok(Some(_)) | Ok(None) => Ok(None),
                Err(error) if is_duplicate_key(&error) => Ok(None),
                Err(error) => Err(error.into()),
            }
        }

        async fn renew_namespace_config_admission_lease(
            &self,
            namespace: &str,
            owner: &str,
        ) -> Result<bool, anyhow::Error> {
            let collection = self.config_admission_locks();
            let result = collection
                .update_one(
                    doc! {
                        "_id": namespace,
                        "owner": owner,
                        "$expr": { "$gt": [ "$expires_at", "$$NOW" ] },
                    },
                    Self::server_time_lease_renew_pipeline(CONFIG_ADMISSION_LEASE_DURATION_MILLIS),
                )
                .await;
            let result = match result {
                Err(error) if is_pipeline_update_unsupported(&error) => {
                    let now = self.lease_server_time().await?;
                    let expires_at = BsonDateTime::from_millis(
                        now.timestamp_millis() + CONFIG_ADMISSION_LEASE_DURATION_MILLIS,
                    );
                    collection
                        .update_one(
                            doc! {
                                "_id": namespace,
                                "owner": owner,
                                "expires_at": { "$gt": now },
                            },
                            doc! {
                                "$set": {
                                    "expires_at": expires_at,
                                    "updated_at": now,
                                },
                            },
                        )
                        .await
                }
                result => result,
            }?;
            Ok(result.matched_count == 1)
        }

        async fn release_namespace_config_admission_lease(
            &self,
            namespace: &str,
            owner: &str,
        ) -> Result<bool, anyhow::Error> {
            let result = self
                .config_admission_locks()
                .update_one(
                    doc! { "_id": namespace, "owner": owner },
                    doc! { "$set": { "expires_at": BsonDateTime::from_millis(0) } },
                )
                .await?;
            Ok(result.matched_count == 1)
        }
    }

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

        fn set_backend_allow_ips(&mut self, policy: crate::config::BackendEgressPolicy) {
            self.backend_allow_ips = policy;
        }

        async fn load_full_config_for_purpose(
            &self,
            namespace: &str,
            purpose: FullConfigLoadPurpose,
        ) -> Result<GatewayConfig, anyhow::Error> {
            let start = std::time::Instant::now();
            let loaded_at = Utc::now();
            let (proxies, consumers, plugin_configs, upstreams) =
                if self.replica_set_configured.load(Ordering::Acquire) {
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    session
                        .start_transaction()
                        .read_concern(ReadConcern::snapshot())
                        .write_concern(WriteConcern::majority())
                        .await?;

                    let loaded = async {
                        let proxies = self
                            .load_full_proxies_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                false,
                            )
                            .await?;
                        let consumers = self
                            .load_full_consumers_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                false,
                            )
                            .await?;
                        let plugin_configs = self
                            .load_full_plugin_configs_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                false,
                            )
                            .await?;
                        let upstreams = self
                            .load_full_upstreams_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                false,
                            )
                            .await?;
                        Ok::<_, anyhow::Error>((proxies, consumers, plugin_configs, upstreams))
                    }
                    .await;

                    match loaded {
                        Ok(resources) => {
                            session.commit_transaction().await?;
                            resources
                        }
                        Err(error) => {
                            let _ = session.abort_transaction().await;
                            return Err(error);
                        }
                    }
                } else {
                    (
                        self.load_full_proxies_opt_session(namespace, None, false)
                            .await?,
                        self.load_full_consumers_opt_session(namespace, None, false)
                            .await?,
                        self.load_full_plugin_configs_opt_session(namespace, None, false)
                            .await?,
                        self.load_full_upstreams_opt_session(namespace, None, false)
                            .await?,
                    )
                };

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
            config.normalize_fields();
            config.resolve_upstream_tls();

            // Fail-closed consumer identity collisions (issue #2121): Mongo
            // `load_full_config` does not run the SQL-side
            // `ValidationPipeline`, so quarantine colliding consumers here
            // directly. First-loaded consumer wins; the
            // `consumer_identity_index` collection prevents NEW collisions
            // from being committed, this guard covers pre-existing rows.
            for message in config.quarantine_colliding_consumer_identities() {
                error!("MongoDB config: {}", message);
            }

            // Fail-closed hmac_auth secret policy: strip pre-existing or
            // out-of-band credentials with weak or cross-consumer duplicate
            // secrets before this snapshot can publish or broadcast. Admin
            // write-time validation rejects new violations; this guard covers
            // stored rows.
            for message in config.quarantine_invalid_hmac_credentials() {
                error!("MongoDB config: {}", message);
            }

            // Mongo does not run the SQL-side `ValidationPipeline`, but full
            // runtime loads must still fail closed on the same rejecting
            // validation contract used by SQL loads and CP updates. This
            // catches malformed routes, stream proxy shapes, dangling upstream
            // references, and invalid plugin associations before startup or
            // broadcast can build runtime caches from invalid collection data.
            let validation_errors = collect_rejecting_runtime_config_errors(&config);
            if !validation_errors.is_empty() {
                for msg in &validation_errors {
                    error!("MongoDB config rejected — {}", msg);
                }
                // Return a typed, downcast-discoverable rejection (not a bare
                // `bail!`) so the database-mode poll loop can tell this apart
                // from a connectivity failure: MongoDB was reachable, the
                // snapshot is merely invalid, so admin writes must stay enabled
                // as the in-band repair path (issue #2158). Runtime caches / CP
                // broadcast still fail closed because this is an `Err`.
                return Err(
                    crate::config::validation_pipeline::ConfigValidationRejection {
                        backend: "MongoDB",
                        errors: validation_errors,
                    }
                    .into_anyhow(),
                );
            }

            // Match relational database full-load semantics for node-local
            // plugin files. Warning-mode validation keeps an absent MMDB a
            // supported data-plane fallback, while the accepted generation
            // hands every successfully validated snapshot to the subsequent
            // plugin-cache build. This must run only after all rejecting
            // validation has passed so an invalid Mongo snapshot cannot leave
            // a claimable MMDB handoff behind.
            if purpose.loads_node_local_plugin_files() {
                config =
                    validate_plugin_file_dependencies_off_thread(config, ValidationAction::Warn)
                        .await?;
            }

            Ok(config)
        }

        async fn load_namespace_snapshot(
            &self,
            namespace: &str,
        ) -> Result<GatewayConfig, anyhow::Error> {
            // Rollback snapshot: load the current rows WITHOUT the fatal
            // `validate_listen_path_encodings` guard that `load_full_config`
            // applies. Restore uses this to repair an invalid-but-present
            // namespace, so such a config must still snapshot; only a genuine
            // MongoDB error surfaces as `Err`, letting the caller abort the
            // destructive clear instead of wiping an unrecoverable-but-intact
            // config. The `_opt_session` helpers already clear `api_spec_id`
            // (parity with `load_full_config`). A replica-set deployment reads
            // the snapshot inside a majority/snapshot transaction; standalone
            // reads directly from the primary.
            let start = std::time::Instant::now();
            let loaded_at = Utc::now();
            let (proxies, consumers, plugin_configs, upstreams) =
                if self.replica_set_configured.load(Ordering::Acquire) {
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    session
                        .start_transaction()
                        .read_concern(ReadConcern::snapshot())
                        .write_concern(WriteConcern::majority())
                        .await?;

                    let loaded = async {
                        let proxies = self
                            .load_full_proxies_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                true,
                            )
                            .await?;
                        let consumers = self
                            .load_full_consumers_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                true,
                            )
                            .await?;
                        let plugin_configs = self
                            .load_full_plugin_configs_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                true,
                            )
                            .await?;
                        let upstreams = self
                            .load_full_upstreams_opt_session(
                                namespace,
                                Some((connection.as_ref(), &mut session)),
                                true,
                            )
                            .await?;
                        Ok::<_, anyhow::Error>((proxies, consumers, plugin_configs, upstreams))
                    }
                    .await;

                    match loaded {
                        Ok(resources) => {
                            session.commit_transaction().await?;
                            resources
                        }
                        Err(error) => {
                            let _ = session.abort_transaction().await;
                            return Err(error);
                        }
                    }
                } else {
                    (
                        self.load_full_proxies_opt_session(namespace, None, true)
                            .await?,
                        self.load_full_consumers_opt_session(namespace, None, true)
                            .await?,
                        self.load_full_plugin_configs_opt_session(namespace, None, true)
                            .await?,
                        self.load_full_upstreams_opt_session(namespace, None, true)
                            .await?,
                    )
                };

            self.check_slow_query("load_namespace_snapshot", start);

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
            // Normalize like admission (parity with the SQL snapshot loader and
            // idempotent — rows were normalized when written). Deliberately skip
            // both the fatal validators and `resolve_upstream_tls`: the snapshot
            // exists only to be re-persisted on rollback, and `resolved_tls` is a
            // runtime-derived field that is never stored.
            config.normalize_fields();
            Ok(config)
        }

        async fn count_namespace_resources(
            &self,
            namespace: &str,
        ) -> Result<NamespaceResourceCounts, anyhow::Error> {
            let filter = doc! { "namespace": namespace };
            if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                session
                    .start_transaction()
                    .read_concern(ReadConcern::snapshot())
                    .write_concern(WriteConcern::majority())
                    .await?;
                let counts = NamespaceResourceCounts {
                    proxies: connection
                        .db
                        .collection::<Document>("proxies")
                        .count_documents(filter.clone())
                        .session(&mut session)
                        .await?,
                    consumers: connection
                        .db
                        .collection::<Document>("consumers")
                        .count_documents(filter.clone())
                        .session(&mut session)
                        .await?,
                    plugin_configs: connection
                        .db
                        .collection::<Document>("plugin_configs")
                        .count_documents(filter.clone())
                        .session(&mut session)
                        .await?,
                    upstreams: connection
                        .db
                        .collection::<Document>("upstreams")
                        .count_documents(filter.clone())
                        .session(&mut session)
                        .await?,
                    api_specs: connection
                        .db
                        .collection::<Document>("api_specs")
                        .count_documents(filter)
                        .session(&mut session)
                        .await?,
                };
                session.commit_transaction().await?;
                Ok(counts)
            } else {
                Ok(NamespaceResourceCounts {
                    proxies: self.proxies().count_documents(filter.clone()).await?,
                    consumers: self.consumers().count_documents(filter.clone()).await?,
                    plugin_configs: self
                        .plugin_configs()
                        .count_documents(filter.clone())
                        .await?,
                    upstreams: self.upstreams().count_documents(filter.clone()).await?,
                    api_specs: self.api_specs().count_documents(filter).await?,
                })
            }
        }

        async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> {
            let doc = self
                .config_changes()
                .find_one(doc! { "namespace": namespace })
                .sort(doc! { "sequence": -1 })
                .await?;
            let Some(doc) = doc else {
                return Ok(0);
            };
            match doc.get("sequence") {
                Some(Bson::Int64(value)) if *value >= 0 => Ok(*value as u64),
                Some(Bson::Int32(value)) if *value >= 0 => Ok(*value as u64),
                other => anyhow::bail!(
                    "MongoDB config_changes row has invalid sequence: {:?}",
                    other
                ),
            }
        }

        async fn load_incremental_config(
            &self,
            namespace: &str,
            after_sequence: u64,
        ) -> Result<IncrementalResult, anyhow::Error> {
            if !self.replica_set_configured() {
                anyhow::bail!(
                    "standalone MongoDB uses non-transactional config_changes writes; forcing full reload"
                );
            }
            let start = std::time::Instant::now();
            let poll_timestamp = Utc::now();
            self.ensure_change_cursor_available(namespace, after_sequence)
                .await?;
            let mut cursor = self
                .config_changes()
                .find(doc! {
                    "namespace": namespace,
                    "sequence": { "$gt": after_sequence as i64 },
                })
                .sort(doc! { "sequence": 1 })
                .limit(CHANGE_LOG_BATCH_LIMIT)
                .await?;
            let mut sequence_cursor = after_sequence;
            let mut proxy_ops = std::collections::HashMap::new();
            let mut consumer_ops = std::collections::HashMap::new();
            let mut plugin_config_ops = std::collections::HashMap::new();
            let mut upstream_ops = std::collections::HashMap::new();
            let mut change_count = 0_usize;
            while cursor.advance().await? {
                change_count += 1;
                let doc = cursor.deserialize_current()?;
                let sequence = match doc.get("sequence") {
                    Some(Bson::Int64(value)) if *value >= 0 => *value as u64,
                    Some(Bson::Int32(value)) if *value >= 0 => *value as u64,
                    _ => continue,
                };
                sequence_cursor = sequence_cursor.max(sequence);
                let resource_type = doc.get_str("resource_type").unwrap_or_default();
                let resource_id = doc.get_str("resource_id").unwrap_or_default().to_string();
                let operation = doc.get_str("operation").unwrap_or_default().to_string();
                if resource_id.is_empty() {
                    continue;
                }
                match resource_type {
                    "proxy" => {
                        proxy_ops.insert(resource_id, operation);
                    }
                    "consumer" => {
                        consumer_ops.insert(resource_id, operation);
                    }
                    "plugin_config" => {
                        plugin_config_ops.insert(resource_id, operation);
                    }
                    "upstream" => {
                        upstream_ops.insert(resource_id, operation);
                    }
                    _ => {}
                }
            }
            self.ensure_change_cursor_available(namespace, after_sequence)
                .await?;
            if change_count >= CHANGE_LOG_BATCH_LIMIT as usize {
                anyhow::bail!(
                    "MongoDB config change batch for namespace '{}' reached limit {}; forcing full reload",
                    namespace,
                    CHANGE_LOG_BATCH_LIMIT
                );
            }

            if !consumer_ops.is_empty() {
                return Err(anyhow::Error::new(
                    crate::config::db_backend::IncrementalFullReloadRequired::for_consumer_changes(
                        namespace,
                    ),
                ));
            }

            let split_ops =
                |ops: std::collections::HashMap<String, String>| -> (Vec<String>, Vec<String>) {
                    let mut upserts = Vec::new();
                    let mut deletes = Vec::new();
                    for (id, op) in ops {
                        if op == "delete" {
                            deletes.push(id);
                        } else {
                            upserts.push(id);
                        }
                    }
                    upserts.sort();
                    deletes.sort();
                    (upserts, deletes)
                };
            let (proxy_upserts, mut removed_proxy_ids) = split_ops(proxy_ops);
            let (consumer_upserts, mut removed_consumer_ids) = split_ops(consumer_ops);
            let (plugin_config_upserts, mut removed_plugin_config_ids) =
                split_ops(plugin_config_ops);
            let (upstream_upserts, mut removed_upstream_ids) = split_ops(upstream_ops);

            let mut added_or_modified_proxies = Vec::new();
            for doc in self
                .load_change_ids(self.proxies(), namespace, &proxy_upserts)
                .await?
            {
                let mut proxy = doc_to_proxy(doc)?;
                proxy.api_spec_id = None;
                added_or_modified_proxies.push(proxy);
            }
            let loaded_proxy_ids: HashSet<String> = added_or_modified_proxies
                .iter()
                .map(|proxy| proxy.id.clone())
                .collect();
            removed_proxy_ids.extend(
                proxy_upserts
                    .iter()
                    .filter(|id| !loaded_proxy_ids.contains(*id))
                    .cloned(),
            );

            let mut added_or_modified_consumers = Vec::new();
            // Consumer point-loads use the composite `_id`
            // ("{namespace}:{id}"); change-log records carry plain ids and
            // the namespace is in scope, so construct the composite keys here
            // to keep the `{namespace, _id}` index usable.
            let consumer_upsert_doc_ids: Vec<String> = consumer_upserts
                .iter()
                .map(|id| consumer_doc_id(namespace, id))
                .collect();
            for doc in self
                .load_change_ids(self.consumers(), namespace, &consumer_upsert_doc_ids)
                .await?
            {
                added_or_modified_consumers.push(doc_to_consumer(doc)?);
            }
            let loaded_consumer_ids: HashSet<String> = added_or_modified_consumers
                .iter()
                .map(|consumer| consumer.id.clone())
                .collect();
            removed_consumer_ids.extend(
                consumer_upserts
                    .iter()
                    .filter(|id| !loaded_consumer_ids.contains(*id))
                    .cloned(),
            );
            let removed_consumer_ids = removed_consumer_ids
                .into_iter()
                .map(|id| NamespacedResourceId::new(namespace, id))
                .collect();

            let mut added_or_modified_plugin_configs = Vec::new();
            for doc in self
                .load_change_ids(self.plugin_configs(), namespace, &plugin_config_upserts)
                .await?
            {
                let mut plugin = doc_to_plugin_config(doc)?;
                plugin.api_spec_id = None;
                added_or_modified_plugin_configs.push(plugin);
            }
            let loaded_plugin_config_ids: HashSet<String> = added_or_modified_plugin_configs
                .iter()
                .map(|plugin| plugin.id.clone())
                .collect();
            removed_plugin_config_ids.extend(
                plugin_config_upserts
                    .iter()
                    .filter(|id| !loaded_plugin_config_ids.contains(*id))
                    .cloned(),
            );

            let mut added_or_modified_upstreams = Vec::new();
            for doc in self
                .load_change_ids(self.upstreams(), namespace, &upstream_upserts)
                .await?
            {
                let mut upstream = doc_to_upstream(doc)?;
                upstream.api_spec_id = None;
                added_or_modified_upstreams.push(upstream);
            }
            let loaded_upstream_ids: HashSet<String> = added_or_modified_upstreams
                .iter()
                .map(|upstream| upstream.id.clone())
                .collect();
            removed_upstream_ids.extend(
                upstream_upserts
                    .iter()
                    .filter(|id| !loaded_upstream_ids.contains(*id))
                    .cloned(),
            );

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
                sequence_cursor,
                poll_timestamp,
            })
        }

        // -------------------------------------------------------------------
        // Proxy CRUD
        // -------------------------------------------------------------------

        async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease(&proxy.namespace)
                .await?;
            self.validate_plugin_graph_admission_candidate(&proxy.namespace, |candidate| {
                candidate.proxies.push(proxy.clone());
            })
            .await?;
            let doc = proxy_to_doc(proxy)?;
            let guard_params = ProxyWriteGuardParams::from_proxy(proxy);
            mtls_lease
                .run_mutation(async {
            if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                session
                    .start_transaction()
                    .and_run(
                        (
                            self,
                            doc,
                            proxy.namespace.clone(),
                            proxy.id.clone(),
                            guard_params,
                        ),
                        |s, (this, doc, namespace, id, guard_params)| {
                            Box::pin(async move {
                                // Route-bucket lock + uniqueness re-check +
                                // upstream reference guard, all in-session so
                                // concurrent admissions serialize (DB-H1/DB-H4).
                                this.ensure_proxy_admission_guards_in_session(
                                    &mut *s,
                                    guard_params,
                                    None,
                                )
                                .await?;
                                this.proxies()
                                    .insert_one(doc.clone())
                                    .session(&mut *s)
                                    .await?;
                                this.record_config_change_in_session(
                                    &mut *s,
                                    namespace.as_str(),
                                    "proxy",
                                    id.as_str(),
                                    "upsert",
                                )
                                .await?;
                                Ok(())
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("create_proxy transaction failed")?;
                self.compact_config_changes_best_effort(&proxy.namespace)
                    .await;
            } else {
                // Standalone (no transactions): pre-check the referenced
                // upstream, insert, then reconcile post-write. The pre+post
                // checks converge for every interleaving of a concurrent
                // create+delete pair — either this create observes the delete
                // and self-reverts, or `delete_upstream`'s post-delete
                // re-check observes this proxy and re-inserts the upstream.
                if let Some(ref upstream_id) = proxy.upstream_id
                    && !self
                        .upstream_exists_in_namespace(&proxy.namespace, upstream_id)
                        .await?
                {
                    anyhow::bail!(
                        "referenced upstream '{}' does not exist in namespace '{}'",
                        upstream_id,
                        proxy.namespace
                    );
                }
                self.proxies().insert_one(doc).await?;
                // Post-write route reconciliation (see
                // `standalone_route_writer_should_yield`): deterministic
                // loser-yield narrows the standalone TOCTOU; full
                // serialization requires FERRUM_MONGO_REPLICA_SET.
                if !guard_params.is_stream {
                    let candidates = self
                        .listen_path_bucket_candidates(
                            &proxy.namespace,
                            proxy.listen_path.as_deref(),
                        )
                        .await?;
                    if Self::standalone_route_writer_should_yield(
                        &proxy.id,
                        &proxy.hosts,
                        &candidates,
                    ) {
                        if let Err(err) = self
                            .proxies()
                            .delete_one(doc! { "_id": &proxy.id, "namespace": &proxy.namespace })
                            .await
                        {
                            warn!(
                                "MongoDB standalone proxy route-conflict self-revert failed \
                                 for '{}': {}",
                                proxy.id, err
                            );
                        }
                        anyhow::bail!(PROXY_ROUTE_CONFLICT_ERROR);
                    }
                }
                if let Some(ref upstream_id) = proxy.upstream_id
                    && !self
                        .upstream_exists_in_namespace(&proxy.namespace, upstream_id)
                        .await?
                {
                    if let Err(err) = self
                        .proxies()
                        .delete_one(doc! { "_id": &proxy.id, "namespace": &proxy.namespace })
                        .await
                    {
                        warn!(
                            "MongoDB standalone proxy upstream-vanished self-revert failed \
                             for '{}': {}",
                            proxy.id, err
                        );
                    }
                    anyhow::bail!(
                        "referenced upstream '{}' does not exist in namespace '{}'",
                        upstream_id,
                        proxy.namespace
                    );
                }
                if let Err(err) = self
                    .record_config_change(&proxy.namespace, "proxy", &proxy.id, "upsert")
                    .await
                {
                    self.rollback_standalone_created_document(
                        "proxies",
                        &proxy.namespace,
                        "proxy",
                        &proxy.id,
                        &err,
                    )
                    .await;
                    return Err(err);
                }
            }
            Ok(())
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("create_proxy", start);
            Ok(())
        }

        async fn update_proxy(&self, proxy: &Proxy) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease(&proxy.namespace)
                .await?;
            self.validate_plugin_graph_admission_candidate(&proxy.namespace, |candidate| {
                if let Some(existing) = candidate
                    .proxies
                    .iter_mut()
                    .find(|existing| existing.id == proxy.id)
                {
                    *existing = proxy.clone();
                }
            })
            .await?;
            // Preserve api_spec_id: the incoming Proxy from the admin CRUD
            // endpoint has api_spec_id: None (stripped in normalize()), but
            // the stored document may carry an ownership tag from a spec
            // import.  SQL is safe because its UPDATE excludes api_spec_id.
            //
            // The api_specs collection is the source of truth for ownership.
            // Inject that tag into the replacement document before writing so
            // the method cannot succeed with an untagged spec-owned proxy.
            let mut doc = proxy_to_doc(proxy)?;
            let guard_params = ProxyWriteGuardParams::from_proxy(proxy);
            let matched = mtls_lease
                .run_mutation(async {

            let use_replica_set = self.replica_set_configured.load(Ordering::Acquire);
            if use_replica_set {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let (matched, orphaned_proxy_group_plugin_deletes) = session
                    .start_transaction()
                    .and_run(
                        (self, &proxy.id, doc, proxy.namespace.clone(), guard_params),
                        |s, (this, id, doc, namespace, guard_params)| {
                            Box::pin(async move {
                                // Establish target existence before admission
                                // guards so a concurrent delete surfaces as a
                                // no-match update, not a route conflict.
                                if this
                                    .proxies()
                                    .find_one(doc! {
                                        "_id": *id,
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?
                                    .is_none()
                                {
                                    return Ok((false, Vec::<(String, String)>::new()));
                                }
                                // Route-bucket lock + uniqueness re-check +
                                // upstream reference guard, all in-session so
                                // concurrent admissions serialize (DB-H1/DB-H4).
                                this.ensure_proxy_admission_guards_in_session(
                                    &mut *s,
                                    guard_params,
                                    Some(id.as_str()),
                                )
                                .await?;
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
                                let replace_result = this
                                    .proxies()
                                    .replace_one(
                                        mongodb::bson::doc! {
                                            "_id": *id,
                                            "namespace": namespace.as_str(),
                                        },
                                        doc,
                                    )
                                    .session(&mut *s)
                                    .await?;
                                if replace_result.matched_count == 0 {
                                    // Phantom update: no document in this
                                    // namespace. Skip cleanup and DO NOT write
                                    // a config-change record — a concurrent
                                    // delete must surface as not-found, not as
                                    // an upsert change (DB-M4). The lock/guard
                                    // upserts that commit are inert metadata.
                                    return Ok((false, Vec::<(String, String)>::new()));
                                }
                                let orphaned = this
                                    .cleanup_orphaned_proxy_group_plugins_opt_session(
                                        namespace.as_str(),
                                        Some(&mut *s),
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                                this.record_config_change_in_session(
                                    &mut *s,
                                    namespace.as_str(),
                                    "proxy",
                                    id.as_str(),
                                    "upsert",
                                )
                                .await?;
                                for (plugin_id, namespace) in &orphaned {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "plugin_config",
                                        plugin_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                Ok((true, orphaned))
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("update_proxy transaction failed")?;
                if matched {
                    self.compact_config_changes_best_effort(&proxy.namespace)
                        .await;
                    for (_, namespace) in &orphaned_proxy_group_plugin_deletes {
                        if namespace != &proxy.namespace {
                            self.compact_config_changes_best_effort(namespace).await;
                        }
                    }
                }
                return Ok(matched);
            }

            // Standalone (no transactions): pre-checks, replace, then
            // post-write reconciliation. This narrows the TOCTOU windows to
            // convergent post-write repair; full serialization requires
            // FERRUM_MONGO_REPLICA_SET.
            let previous_doc = self
                .proxies()
                .find_one(doc! { "_id": &proxy.id, "namespace": &proxy.namespace })
                .await?;
            let Some(previous_doc) = previous_doc else {
                return Ok(false);
            };
            let previous_upstream_id = previous_doc.get_str("upstream_id").ok().map(str::to_string);
            let upstream_ref_changed = proxy.upstream_id.is_some()
                && proxy.upstream_id.as_deref() != previous_upstream_id.as_deref();
            if upstream_ref_changed
                && let Some(ref upstream_id) = proxy.upstream_id
                && !self
                    .upstream_exists_in_namespace(&proxy.namespace, upstream_id)
                    .await?
            {
                anyhow::bail!(
                    "referenced upstream '{}' does not exist in namespace '{}'",
                    upstream_id,
                    proxy.namespace
                );
            }
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
            let replace_result = self
                .proxies()
                .replace_one(
                    doc! { "_id": &proxy.id, "namespace": &proxy.namespace },
                    doc,
                )
                .await?;
            if replace_result.matched_count == 0 {
                // Phantom update (concurrent delete): no config-change record.
                return Ok(false);
            }
            // Post-write route reconciliation: unlike two creates, an update
            // always yields to any conflicting route owner and restores its
            // previous document. The pre-existing proxy's original
            // `created_at` must not make its route mutation win.
            if !guard_params.is_stream {
                let candidates = self
                    .listen_path_bucket_candidates(&proxy.namespace, proxy.listen_path.as_deref())
                    .await?;
                if Self::standalone_route_update_has_conflict(&proxy.id, &proxy.hosts, &candidates)
                {
                    if let Err(err) = self
                        .proxies()
                        .replace_one(
                            doc! { "_id": &proxy.id, "namespace": &proxy.namespace },
                            previous_doc.clone(),
                        )
                        .await
                    {
                        warn!(
                            "MongoDB standalone proxy route-conflict restore failed for '{}': {}",
                            proxy.id, err
                        );
                    }
                    anyhow::bail!(PROXY_ROUTE_CONFLICT_ERROR);
                }
            }
            if upstream_ref_changed
                && let Some(ref upstream_id) = proxy.upstream_id
                && !self
                    .upstream_exists_in_namespace(&proxy.namespace, upstream_id)
                    .await?
            {
                if let Err(err) = self
                    .proxies()
                    .replace_one(
                        doc! { "_id": &proxy.id, "namespace": &proxy.namespace },
                        previous_doc.clone(),
                    )
                    .await
                {
                    warn!(
                        "MongoDB standalone proxy upstream-vanished restore failed for '{}': {}",
                        proxy.id, err
                    );
                }
                anyhow::bail!(
                    "referenced upstream '{}' does not exist in namespace '{}'",
                    upstream_id,
                    proxy.namespace
                );
            }
            if let Err(err) = self
                .record_config_change(&proxy.namespace, "proxy", &proxy.id, "upsert")
                .await
            {
                self.rollback_standalone_updated_document(
                    "proxies",
                    "proxy",
                    &proxy.id,
                    Some(previous_doc),
                    &err,
                )
                .await;
                return Err(err);
            }
            let orphaned_proxy_group_plugin_deletes =
                self.cleanup_orphaned_proxy_group_plugins(&proxy.namespace)
                    .await?;
            for (plugin_id, namespace) in orphaned_proxy_group_plugin_deletes {
                self.record_config_change(&namespace, "plugin_config", &plugin_id, "delete")
                    .await?;
            }

            Ok(true)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("update_proxy", start);
            Ok(matched)
        }

        async fn delete_proxy(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;
            self.validate_plugin_graph_repair_delete_candidate(namespace, |candidate| {
                candidate.proxies.retain(|proxy| proxy.id != id);
                candidate
                    .plugin_configs
                    .retain(|plugin| plugin.proxy_id.as_deref() != Some(id));
            })
            .await?;
            let deleted = mtls_lease
                .run_mutation(async {
            if self.replica_set_configured.load(Ordering::Acquire) {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let (
                    deleted,
                    proxy_namespace_for_changes,
                    spec_namespace_for_changes,
                    orphaned_proxy_group_plugin_deletes,
                ) = session
                    .start_transaction()
                    .and_run(
                        (self, namespace.to_string(), id.to_string()),
                        |s, (this, namespace, id)| {
                            Box::pin(async move {
                                // Capture upstream_id before deleting the proxy.
                                // Namespace-predicated so a cross-namespace admin
                                // call can never delete another namespace's proxy.
                                let proxy_doc = this
                                    .proxies()
                                    .find_one(mongodb::bson::doc! {
                                        "_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                let Some(proxy_doc) = proxy_doc else {
                                    return Ok((
                                        false,
                                        String::new(),
                                        None::<String>,
                                        Vec::<(String, String)>::new(),
                                    ));
                                };
                                let proxy_namespace_for_changes = namespace.clone();
                                let upstream_id_to_check: Option<String> =
                                    proxy_doc.get_str("upstream_id").ok().map(str::to_string);
                                let proxy_scoped_plugin_ids_for_changes = this
                                    .load_collection_ids_filtered_in_session(
                                        &mut *s,
                                        "plugin_configs",
                                        mongodb::bson::doc! { "proxy_id": id.as_str() },
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;

                                let spec_owner: Option<(String, String)> = this
                                    .api_specs()
                                    .find_one(mongodb::bson::doc! { "proxy_id": id.as_str() })
                                    .session(&mut *s)
                                    .await?
                                    .map(|doc| {
                                        let sid = doc.get_str("_id").map(str::to_string).map_err(
                                            |e| {
                                                mongodb::error::Error::custom(format!(
                                                    "api_spec for proxy {} is missing _id: {}",
                                                    id, e
                                                ))
                                            },
                                        )?;
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
                                let spec_upstream_ids_for_changes =
                                    if let Some((ref sid, ref namespace)) = spec_owner {
                                        this.load_collection_ids_filtered_in_session(
                                            &mut *s,
                                            "upstreams",
                                            mongodb::bson::doc! {
                                                "api_spec_id": sid.as_str(),
                                                "namespace": namespace.as_str(),
                                            },
                                        )
                                        .await
                                        .map_err(|e| mongodb::error::Error::custom(e.to_string()))?
                                    } else {
                                        HashSet::new()
                                    };

                                this.plugin_configs()
                                    .delete_many(mongodb::bson::doc! { "proxy_id": id.as_str() })
                                    .session(&mut *s)
                                    .await?;
                                let result = this
                                    .proxies()
                                    .delete_one(mongodb::bson::doc! {
                                        "_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;

                                let mut deleted_orphaned_upstream_id: Option<String> = None;
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
                                    // Generic proxy deletion owns ordinary
                                    // orphan cleanup. A spec-owned proxy can
                                    // drift to a hand-owned upstream, which
                                    // must survive deletion of the spec graph.
                                    if spec_owner.is_none()
                                        && let Some(ref uid) = upstream_id_to_check
                                    {
                                        let still_referenced = this
                                            .proxies()
                                            .count_documents(mongodb::bson::doc! {
                                                "upstream_id": uid.as_str()
                                            })
                                            .session(&mut *s)
                                            .await?
                                            > 0;
                                        let dispatch_ref = if !still_referenced {
                                            this.find_mesh_route_dispatch_upstream_ref_opt_session(
                                                Some(&mut *s),
                                                uid,
                                            )
                                            .await
                                            .map_err(
                                                |e| mongodb::error::Error::custom(e.to_string()),
                                            )?
                                        } else {
                                            None
                                        };
                                        if !still_referenced && dispatch_ref.is_none() {
                                            let upstream_delete = this
                                                .upstreams()
                                                .delete_one(mongodb::bson::doc! {
                                                    "_id": uid.as_str(),
                                                    "namespace": namespace.as_str(),
                                                })
                                                .session(&mut *s)
                                                .await?;
                                            if upstream_delete.deleted_count > 0 {
                                                deleted_orphaned_upstream_id = Some(uid.clone());
                                            }
                                        }
                                    }
                                }

                                let orphaned_proxy_group_plugin_deletes = this
                                    .cleanup_orphaned_proxy_group_plugins_opt_session(
                                        namespace.as_str(),
                                        Some(&mut *s),
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                                if result.deleted_count > 0 {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        proxy_namespace_for_changes.as_str(),
                                        "proxy",
                                        id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                    for plugin_id in proxy_scoped_plugin_ids_for_changes.iter() {
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            proxy_namespace_for_changes.as_str(),
                                            "plugin_config",
                                            plugin_id.as_str(),
                                            "delete",
                                        )
                                        .await?;
                                    }
                                    if let Some((_, namespace)) = spec_owner.as_ref() {
                                        for upstream_id in spec_upstream_ids_for_changes.iter() {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "upstream",
                                                upstream_id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                    }
                                    if let Some(upstream_id) = deleted_orphaned_upstream_id.as_ref()
                                    {
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            proxy_namespace_for_changes.as_str(),
                                            "upstream",
                                            upstream_id.as_str(),
                                            "delete",
                                        )
                                        .await?;
                                    }
                                    for (plugin_id, namespace) in
                                        &orphaned_proxy_group_plugin_deletes
                                    {
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "plugin_config",
                                            plugin_id.as_str(),
                                            "delete",
                                        )
                                        .await?;
                                    }
                                }
                                let spec_namespace_for_changes =
                                    spec_owner.as_ref().map(|(_, namespace)| namespace.clone());
                                Ok((
                                    result.deleted_count > 0,
                                    proxy_namespace_for_changes,
                                    spec_namespace_for_changes,
                                    orphaned_proxy_group_plugin_deletes,
                                ))
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("delete_proxy transaction failed")?;
                if deleted {
                    self.compact_config_changes_best_effort(&proxy_namespace_for_changes)
                        .await;
                    if let Some(ref namespace) = spec_namespace_for_changes
                        && namespace != &proxy_namespace_for_changes
                    {
                        self.compact_config_changes_best_effort(namespace).await;
                    }
                    for (_, namespace) in &orphaned_proxy_group_plugin_deletes {
                        if namespace != &proxy_namespace_for_changes {
                            self.compact_config_changes_best_effort(namespace).await;
                        }
                    }
                }
                return Ok(deleted);
            }

            let proxy_doc_for_changes = self
                .proxies()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            if proxy_doc_for_changes.is_none() {
                return Ok(false);
            };
            let proxy_namespace_for_changes = namespace.to_string();
            let proxy_scoped_plugin_ids_for_changes = self
                .load_collection_ids_filtered("plugin_configs", doc! { "proxy_id": id })
                .await?;
            let spec_owner_for_changes: Option<(String, String)> =
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
            let spec_upstream_ids_for_changes =
                if let Some((ref sid, ref namespace)) = spec_owner_for_changes {
                    self.load_collection_ids_filtered(
                        "upstreams",
                        doc! { "api_spec_id": sid, "namespace": namespace },
                    )
                    .await?
                } else {
                    HashSet::new()
                };

            // Non-replica-set best-effort path.
            let proxy_doc = self
                .proxies()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            let proxy_namespace = namespace.to_string();
            let upstream_id_to_check: Option<String> = proxy_doc
                .as_ref()
                .and_then(|doc| doc.get_str("upstream_id").ok().map(str::to_string));
            if proxy_doc.is_none() {
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

            let result = self
                .proxies()
                .delete_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            let mut deleted_spec_upstream_ids_for_changes = HashSet::new();
            let mut deleted_orphaned_upstream_id_for_changes = None;
            if result.deleted_count > 0 {
                self.plugin_configs()
                    .delete_many(doc! { "proxy_id": id })
                    .await?;
                let _ = self.api_specs().delete_one(doc! { "proxy_id": id }).await;
                if let Some((ref sid, ref namespace)) = spec_owner {
                    match self
                        .upstreams()
                        .delete_many(doc! { "api_spec_id": sid, "namespace": namespace })
                        .await
                    {
                        Ok(_) => {
                            deleted_spec_upstream_ids_for_changes =
                                spec_upstream_ids_for_changes.clone();
                        }
                        Err(e) => warn!(
                            "MongoDB best-effort upstream cascade delete failed for api_spec {}: {}",
                            sid, e
                        ),
                    }
                }
                if spec_owner.is_none()
                    && let Some(ref uid) = upstream_id_to_check
                {
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
                        match self
                            .upstreams()
                            .delete_one(doc! { "_id": uid, "namespace": namespace })
                            .await
                        {
                            Ok(delete_result) if delete_result.deleted_count > 0 => {
                                deleted_orphaned_upstream_id_for_changes = Some(uid.clone());
                            }
                            Ok(_) => {}
                            Err(e) => warn!(
                                "MongoDB best-effort orphan upstream delete failed for {}: {}",
                                uid, e
                            ),
                        }
                    }
                }
            }
            let orphaned_proxy_group_plugin_deletes =
                self.cleanup_orphaned_proxy_group_plugins(namespace).await?;
            if result.deleted_count > 0 {
                self.record_config_change(&proxy_namespace, "proxy", id, "delete")
                    .await?;
                for plugin_id in proxy_scoped_plugin_ids_for_changes {
                    self.record_config_change(
                        &proxy_namespace_for_changes,
                        "plugin_config",
                        &plugin_id,
                        "delete",
                    )
                    .await?;
                }
                if let Some((_, ref namespace)) = spec_owner_for_changes {
                    for upstream_id in deleted_spec_upstream_ids_for_changes {
                        self.record_config_change(namespace, "upstream", &upstream_id, "delete")
                            .await?;
                    }
                }
                if let Some(ref upstream_id) = deleted_orphaned_upstream_id_for_changes {
                    self.record_config_change(
                        &proxy_namespace_for_changes,
                        "upstream",
                        upstream_id,
                        "delete",
                    )
                    .await?;
                }
                for (plugin_id, namespace) in orphaned_proxy_group_plugin_deletes {
                    self.record_config_change(&namespace, "plugin_config", &plugin_id, "delete")
                        .await?;
                }
            }
            Ok(result.deleted_count > 0)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("delete_proxy", start);
            Ok(deleted)
        }

        async fn get_proxy(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<Option<Proxy>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .proxies()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
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
                .skip(Some(mongo_skip(offset)))
                .limit(Some(limit))
                .build();
            let proxies = self.proxies();
            let mut cursor = proxies.find(ns_filter).with_options(options).await?;
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
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease(&consumer.namespace)
                .await?;
            self.validate_mtls_dns_candidate(&consumer.namespace, |candidate| {
                if let Some(existing) = candidate
                    .consumers
                    .iter_mut()
                    .find(|existing| existing.id == consumer.id)
                {
                    *existing = consumer.clone();
                } else {
                    candidate.consumers.push(consumer.clone());
                }
            })
            .await?;
            let doc = consumer_to_doc(consumer)?;
            let identity_values = consumer_identity_values(consumer);
            mtls_lease
                .run_mutation(async {
            if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                session
                    .start_transaction()
                    .and_run(
                        (
                            self,
                            doc,
                            consumer.namespace.clone(),
                            consumer.id.clone(),
                            identity_values,
                        ),
                        |s, (this, doc, namespace, id, identity_values)| {
                            Box::pin(async move {
                                // Reserve the merged identity keyspace
                                // (id ∪ username ∪ custom_id) in the same
                                // transaction — a duplicate key means another
                                // consumer owns one of the values (409).
                                this.insert_consumer_identity_docs_in_session(
                                    &mut *s,
                                    namespace.as_str(),
                                    id.as_str(),
                                    identity_values,
                                )
                                .await?;
                                this.consumers()
                                    .insert_one(doc.clone())
                                    .session(&mut *s)
                                    .await?;
                                this.record_config_change_in_session(
                                    &mut *s,
                                    namespace.as_str(),
                                    "consumer",
                                    id.as_str(),
                                    "upsert",
                                )
                                .await?;
                                Ok(())
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("create_consumer transaction failed")?;
                self.compact_config_changes_best_effort(&consumer.namespace)
                    .await;
            } else {
                // Standalone: RESERVE FIRST. Inserting the identity docs
                // before the consumer makes the identity-index `_id` the
                // atomic admission guard — a duplicate key error (E11000,
                // "duplicate key") bails before the consumer is written.
                // Rollback releases only values this attempt newly inserted
                // (never adopted same-owner reservations of unknown provenance).
                let newly_inserted_identity_values = self
                    .reserve_consumer_identity_docs_standalone(
                        &consumer.namespace,
                        &consumer.id,
                        &identity_values,
                    )
                    .await?;
                // Release only values this attempt newly inserted — never adopted
                // same-owner reservations, whose provenance is unknown.
                let rollback_identity_values: &[String] = &newly_inserted_identity_values;
                if let Err(err) = self.consumers().insert_one(doc).await {
                    self.release_consumer_identity_values_best_effort(
                        &consumer.namespace,
                        &consumer.id,
                        rollback_identity_values,
                    )
                    .await;
                    return Err(err.into());
                }
                if let Err(err) = self
                    .record_config_change(&consumer.namespace, "consumer", &consumer.id, "upsert")
                    .await
                {
                    let rollback_confirmed = self
                        .rollback_standalone_created_document(
                            "consumers",
                            &consumer.namespace,
                            "consumer",
                            &consumer_doc_id(&consumer.namespace, &consumer.id),
                            &err,
                        )
                        .await;
                    if rollback_confirmed {
                        self.release_consumer_identity_values_best_effort(
                            &consumer.namespace,
                            &consumer.id,
                            rollback_identity_values,
                        )
                        .await;
                    } else {
                        warn!(
                            "Retaining MongoDB consumer identity reservations for '{}' in namespace '{}' because create rollback could not be verified",
                            consumer.id, consumer.namespace
                        );
                    }
                    return Err(err);
                }
            }
            Ok(())
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("create_consumer", start);
            Ok(())
        }

        async fn update_consumer(
            &self,
            consumer: &Consumer,
            mode: &BatchConfigWriteMode,
        ) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease_for_mode(&consumer.namespace, mode)
                .await?;
            self.validate_mtls_dns_candidate(&consumer.namespace, |candidate| {
                if let Some(existing) = candidate
                    .consumers
                    .iter_mut()
                    .find(|existing| existing.id == consumer.id)
                {
                    *existing = consumer.clone();
                }
            })
            .await?;
            let doc = consumer_to_doc(consumer)?;
            let new_identity_values = consumer_identity_values(consumer);
            let composite_id = consumer_doc_id(&consumer.namespace, &consumer.id);
            let matched = mtls_lease
                .run_mutation(async {
                    let matched = if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let matched =
                            session
                                .start_transaction()
                                .and_run(
                                    (
                                        self,
                                        doc,
                                        consumer.namespace.clone(),
                                        consumer.id.clone(),
                                        composite_id,
                                        new_identity_values,
                                    ),
                                    |s,
                                     (
                                        this,
                                        doc,
                                        namespace,
                                        id,
                                        composite_id,
                                        new_identity_values,
                                    )| {
                                        Box::pin(async move {
                                            // Read the previous consumer in-session to diff
                                            // the identity keyspace (id ∪ username ∪
                                            // custom_id).
                                            let previous = this
                                                .consumers()
                                                .find_one(doc! { "_id": composite_id.as_str() })
                                                .session(&mut *s)
                                                .await?;
                                            let Some(previous) = previous else {
                                                // Phantom update: no writes performed, no
                                                // config-change record (DB-M4).
                                                return Ok(false);
                                            };
                                            let previous_consumer = doc_to_consumer(previous)
                                                .map_err(|e| {
                                                    mongodb::error::Error::custom(e.to_string())
                                                })?;
                                            let old_values =
                                                consumer_identity_values(&previous_consumer);
                                            let replace_result = this
                                                .consumers()
                                                .replace_one(
                                                    doc! { "_id": composite_id.as_str() },
                                                    doc.clone(),
                                                )
                                                .session(&mut *s)
                                                .await?;
                                            if replace_result.matched_count == 0 {
                                                return Ok(false);
                                            }
                                            let added: Vec<String> = new_identity_values
                                                .iter()
                                                .filter(|value| !old_values.contains(value))
                                                .cloned()
                                                .collect();
                                            let removed: Vec<String> = old_values
                                                .iter()
                                                .filter(|value| {
                                                    !new_identity_values.contains(value)
                                                })
                                                .cloned()
                                                .collect();
                                            this.insert_consumer_identity_docs_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                id.as_str(),
                                                &added,
                                            )
                                            .await?;
                                            this.delete_consumer_identity_values_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                id.as_str(),
                                                &removed,
                                            )
                                            .await?;
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "consumer",
                                                id.as_str(),
                                                "upsert",
                                            )
                                            .await?;
                                            Ok(true)
                                        })
                                    },
                                )
                                .await
                                .map_err(anyhow::Error::new)
                                .context("update_consumer transaction failed")?;
                        if matched {
                            self.compact_config_changes_best_effort(&consumer.namespace)
                                .await;
                        }
                        matched
                    } else {
                        let previous_doc = self
                            .consumers()
                            .find_one(doc! { "_id": &composite_id })
                            .await?;
                        let Some(previous_doc) = previous_doc else {
                            return Ok(false);
                        };
                        let previous_consumer = doc_to_consumer(previous_doc.clone())?;
                        let old_values = consumer_identity_values(&previous_consumer);
                        let added: Vec<String> = new_identity_values
                            .iter()
                            .filter(|value| !old_values.contains(value))
                            .cloned()
                            .collect();
                        let removed: Vec<String> = old_values
                            .iter()
                            .filter(|value| !new_identity_values.contains(value))
                            .cloned()
                            .collect();
                        // Standalone: reserve the ADDED identity values first, then
                        // replace the consumer, then release the removed values. A
                        // duplicate key on the reservation (another consumer owns one
                        // of the values) bails before the consumer is touched.
                        // Failure rollback releases only values this attempt newly
                        // inserted — never adopted same-owner reservations.
                        let newly_inserted_identity_values = self
                            .reserve_consumer_identity_docs_standalone(
                                &consumer.namespace,
                                &consumer.id,
                                &added,
                            )
                            .await?;
                        // Release only values this attempt newly inserted — never
                        // adopted same-owner reservations of unknown provenance.
                        let rollback_identity_values: &[String] = &newly_inserted_identity_values;
                        let replace_result = match self
                            .consumers()
                            .replace_one(doc! { "_id": &composite_id }, doc)
                            .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                self.release_consumer_identity_values_best_effort(
                                    &consumer.namespace,
                                    &consumer.id,
                                    rollback_identity_values,
                                )
                                .await;
                                return Err(err.into());
                            }
                        };
                        if replace_result.matched_count == 0 {
                            // Phantom update (concurrent delete): release the
                            // reservations, no config-change record (DB-M4).
                            self.release_consumer_identity_values_best_effort(
                                &consumer.namespace,
                                &consumer.id,
                                rollback_identity_values,
                            )
                            .await;
                            return Ok(false);
                        }
                        if let Err(err) = self
                            .record_config_change(
                                &consumer.namespace,
                                "consumer",
                                &consumer.id,
                                "upsert",
                            )
                            .await
                        {
                            let rollback_confirmed = self
                                .rollback_standalone_updated_document(
                                    "consumers",
                                    "consumer",
                                    &composite_id,
                                    Some(previous_doc),
                                    &err,
                                )
                                .await;
                            if rollback_confirmed {
                                self.release_consumer_identity_values_best_effort(
                                    &consumer.namespace,
                                    &consumer.id,
                                    rollback_identity_values,
                                )
                                .await;
                            }
                            return Err(err);
                        }
                        // Removed values are released last so a change-record failure
                        // (which restores the previous consumer) never leaves the
                        // restored identities unreserved.
                        self.release_consumer_identity_values_best_effort(
                            &consumer.namespace,
                            &consumer.id,
                            &removed,
                        )
                        .await;
                        true
                    };
                    Ok(matched)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("update_consumer", start);
            Ok(matched)
        }

        async fn delete_consumer(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;
            self.validate_mtls_dns_repair_delete_candidate(namespace, |candidate| {
                candidate.consumers.retain(|consumer| consumer.id != id);
            })
            .await?;
            let composite_id = consumer_doc_id(namespace, id);
            let deleted = mtls_lease
                .run_mutation(async {
                    let deleted = if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let deleted = session
                            .start_transaction()
                            .and_run(
                                (self, id.to_string(), namespace.to_string(), composite_id),
                                |s, (this, id, namespace, composite_id)| {
                                    Box::pin(async move {
                                        let result = this
                                            .consumers()
                                            .delete_one(doc! { "_id": composite_id.as_str() })
                                            .session(&mut *s)
                                            .await?;
                                        if result.deleted_count > 0 {
                                            // Release the consumer's identity
                                            // reservations in the same transaction.
                                            this.consumer_identity_index()
                                                .delete_many(doc! {
                                                    "namespace": namespace.as_str(),
                                                    "consumer_id": id.as_str(),
                                                })
                                                .session(&mut *s)
                                                .await?;
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "consumer",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                        Ok(result.deleted_count > 0)
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("delete_consumer transaction failed")?;
                        if deleted {
                            self.compact_config_changes_best_effort(namespace).await;
                        }
                        deleted
                    } else {
                        let result = self
                            .consumers()
                            .delete_one(doc! { "_id": &composite_id })
                            .await?;
                        if result.deleted_count > 0 {
                            // Delete the consumer first, then its identity
                            // reservations. Best-effort: a failure here leaves
                            // orphaned reservations that 409 future claims of the
                            // same values until repaired, but the consumer delete
                            // itself already succeeded.
                            if let Err(err) = self
                                .consumer_identity_index()
                                .delete_many(doc! { "namespace": namespace, "consumer_id": id })
                                .await
                            {
                                warn!(
                                    "MongoDB standalone consumer identity index cleanup failed for \
                             consumer '{}' in namespace '{}': {}",
                                    id, namespace, err
                                );
                            }
                            self.record_config_change(namespace, "consumer", id, "delete")
                                .await?;
                        }
                        result.deleted_count > 0
                    };
                    Ok(deleted)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("delete_consumer", start);
            Ok(deleted)
        }

        async fn get_consumer(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<Option<Consumer>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .consumers()
                .find_one(doc! { "_id": consumer_doc_id(namespace, id) })
                .await?;
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
                .skip(Some(mongo_skip(offset)))
                .limit(Some(limit))
                .build();
            let consumers = self.consumers();
            let mut cursor = consumers.find(ns_filter).with_options(options).await?;
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
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(&pc.namespace).await?;
            self.validate_plugin_graph_admission_candidate(&pc.namespace, |candidate| {
                if let Some(existing) = candidate
                    .plugin_configs
                    .iter_mut()
                    .find(|existing| existing.id == pc.id)
                {
                    *existing = pc.clone();
                } else {
                    candidate.plugin_configs.push(pc.clone());
                }
            })
            .await?;
            let doc = plugin_config_to_doc(pc)?;
            mtls_lease
                .run_mutation(async {
                    if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let proxy_id = if pc.scope == PluginScope::Proxy {
                            pc.proxy_id.clone()
                        } else {
                            None
                        };
                        session
                            .start_transaction()
                            .and_run(
                                (self, doc, pc.namespace.clone(), pc.id.clone(), proxy_id),
                                |s, (this, doc, namespace, id, proxy_id)| {
                                    Box::pin(async move {
                                        this.plugin_configs()
                                            .insert_one(doc.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "plugin_config",
                                            id.as_str(),
                                            "upsert",
                                        )
                                        .await?;
                                        if let Some(proxy_id) = proxy_id.as_deref() {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "proxy",
                                                proxy_id,
                                                "upsert",
                                            )
                                            .await?;
                                        }
                                        Ok(())
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("create_plugin_config transaction failed")?;
                        self.compact_config_changes_best_effort(&pc.namespace).await;
                    } else {
                        self.plugin_configs().insert_one(doc).await?;
                        if let Err(err) = self
                            .record_config_change(&pc.namespace, "plugin_config", &pc.id, "upsert")
                            .await
                        {
                            self.rollback_standalone_created_document(
                                "plugin_configs",
                                &pc.namespace,
                                "plugin_config",
                                &pc.id,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                        if pc.scope == PluginScope::Proxy
                            && let Some(proxy_id) = pc.proxy_id.as_deref()
                            && let Err(err) = self
                                .record_config_change(&pc.namespace, "proxy", proxy_id, "upsert")
                                .await
                        {
                            self.rollback_standalone_created_document(
                                "plugin_configs",
                                &pc.namespace,
                                "plugin_config",
                                &pc.id,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    }
                    Ok(())
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("create_plugin_config", start);
            Ok(())
        }

        async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(&pc.namespace).await?;
            self.validate_plugin_graph_admission_candidate(&pc.namespace, |candidate| {
                if let Some(existing) = candidate
                    .plugin_configs
                    .iter_mut()
                    .find(|existing| existing.id == pc.id)
                {
                    *existing = pc.clone();
                }
            })
            .await?;
            // Preserve api_spec_id by carrying it into the replacement document.
            // Returning an error is safer than silently detaching spec ownership.
            let mut doc = plugin_config_to_doc(pc)?;
            let existing_doc = self
                .plugin_configs()
                .find_one(doc! { "_id": &pc.id, "namespace": &pc.namespace })
                .await?;
            if existing_doc.is_none() {
                // No document in this namespace — phantom update, no
                // config-change record (DB-M4).
                mtls_lease.release().await?;
                self.check_slow_query("update_plugin_config", start);
                return Ok(false);
            }
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
            let matched = mtls_lease
                .run_mutation(async {
                    if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let proxy_id = if pc.scope == PluginScope::Proxy {
                            pc.proxy_id.clone()
                        } else {
                            None
                        };
                        let matched = session
                            .start_transaction()
                            .and_run(
                                (self, doc, pc.namespace.clone(), pc.id.clone(), proxy_id),
                                |s, (this, doc, namespace, id, proxy_id)| {
                                    Box::pin(async move {
                                        let replace_result = this
                                            .plugin_configs()
                                            .replace_one(
                                                doc! {
                                                    "_id": id.as_str(),
                                                    "namespace": namespace.as_str(),
                                                },
                                                doc.clone(),
                                            )
                                            .session(&mut *s)
                                            .await?;
                                        if replace_result.matched_count == 0 {
                                            // Phantom update: no config-change record
                                            // (DB-M4).
                                            return Ok(false);
                                        }
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "plugin_config",
                                            id.as_str(),
                                            "upsert",
                                        )
                                        .await?;
                                        if let Some(proxy_id) = proxy_id.as_deref() {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "proxy",
                                                proxy_id,
                                                "upsert",
                                            )
                                            .await?;
                                        }
                                        Ok(true)
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("update_plugin_config transaction failed")?;
                        if matched {
                            self.compact_config_changes_best_effort(&pc.namespace).await;
                        }
                        return Ok(matched);
                    } else {
                        let replace_result = self
                            .plugin_configs()
                            .replace_one(doc! { "_id": &pc.id, "namespace": &pc.namespace }, doc)
                            .await?;
                        if replace_result.matched_count == 0 {
                            // Phantom update (concurrent delete): no config-change
                            // record (DB-M4).
                            return Ok(false);
                        }
                        let change_result: Result<(), anyhow::Error> = async {
                            self.record_config_change(
                                &pc.namespace,
                                "plugin_config",
                                &pc.id,
                                "upsert",
                            )
                            .await?;
                            if pc.scope == PluginScope::Proxy
                                && let Some(proxy_id) = pc.proxy_id.as_deref()
                            {
                                self.record_config_change(
                                    &pc.namespace,
                                    "proxy",
                                    proxy_id,
                                    "upsert",
                                )
                                .await?;
                            }
                            Ok(())
                        }
                        .await;
                        if let Err(err) = change_result {
                            self.rollback_standalone_updated_document(
                                "plugin_configs",
                                "plugin_config",
                                &pc.id,
                                existing_doc,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    }
                    Ok(true)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("update_plugin_config", start);
            Ok(matched)
        }

        async fn delete_plugin_config(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;
            self.validate_plugin_graph_repair_delete_candidate(namespace, |candidate| {
                candidate.plugin_configs.retain(|plugin| plugin.id != id);
                for proxy in &mut candidate.proxies {
                    proxy
                        .plugins
                        .retain(|association| association.plugin_config_id != id);
                }
            })
            .await?;
            let existing = self
                .plugin_configs()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            if existing.is_none() {
                // No document in this namespace — nothing to delete, and no
                // proxy associations to pull.
                mtls_lease.release().await?;
                self.check_slow_query("delete_plugin_config", start);
                return Ok(false);
            }
            let namespace = namespace.to_string();
            let mut affected_proxy_ids = Vec::new();
            let mut affected_cursor = self
                .proxies()
                .find(doc! { "plugins.plugin_config_id": id })
                .projection(doc! { "_id": 1 })
                .await?;
            while affected_cursor.advance().await? {
                let doc = affected_cursor.deserialize_current()?;
                if let Ok(proxy_id) = doc.get_str("_id") {
                    affected_proxy_ids.push(proxy_id.to_string());
                }
            }
            let deleted = mtls_lease
                .run_mutation(async {
                    let deleted = if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let deleted = session
                            .start_transaction()
                            .and_run(
                                (
                                    self,
                                    id.to_string(),
                                    namespace.clone(),
                                    affected_proxy_ids.clone(),
                                ),
                                |s, (this, id, namespace, affected_proxy_ids)| {
                                    Box::pin(async move {
                                        this.proxies()
                                    .update_many(
                                        doc! { "plugins.plugin_config_id": id.as_str() },
                                        doc! {
                                            "$pull": {
                                                "plugins": { "plugin_config_id": id.as_str() }
                                            },
                                            "$set": { "updated_at": Utc::now().to_rfc3339() },
                                        },
                                    )
                                    .session(&mut *s)
                                    .await?;
                                        let result = this
                                            .plugin_configs()
                                            .delete_one(doc! {
                                                "_id": id.as_str(),
                                                "namespace": namespace.as_str(),
                                            })
                                            .session(&mut *s)
                                            .await?;
                                        if result.deleted_count > 0 {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "plugin_config",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                            for proxy_id in affected_proxy_ids.iter() {
                                                this.record_config_change_in_session(
                                                    &mut *s,
                                                    namespace.as_str(),
                                                    "proxy",
                                                    proxy_id.as_str(),
                                                    "upsert",
                                                )
                                                .await?;
                                            }
                                        }
                                        Ok(result.deleted_count > 0)
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("delete_plugin_config transaction failed")?;
                        if deleted {
                            self.compact_config_changes_best_effort(&namespace).await;
                        }
                        deleted
                    } else {
                        self.proxies()
                            .update_many(
                                doc! { "plugins.plugin_config_id": id },
                                doc! {
                                    "$pull": { "plugins": { "plugin_config_id": id } },
                                    "$set": { "updated_at": Utc::now().to_rfc3339() },
                                },
                            )
                            .await?;
                        let result = self
                            .plugin_configs()
                            .delete_one(doc! { "_id": id, "namespace": &namespace })
                            .await?;
                        if result.deleted_count > 0 {
                            self.record_config_change(&namespace, "plugin_config", id, "delete")
                                .await?;
                            for proxy_id in affected_proxy_ids {
                                self.record_config_change(&namespace, "proxy", &proxy_id, "upsert")
                                    .await?;
                            }
                        }
                        result.deleted_count > 0
                    };
                    Ok(deleted)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("delete_plugin_config", start);
            Ok(deleted)
        }

        async fn get_plugin_config(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<Option<PluginConfig>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .plugin_configs()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
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
                .skip(Some(mongo_skip(offset)))
                .limit(Some(limit))
                .build();
            let plugin_configs = self.plugin_configs();
            let mut cursor = plugin_configs.find(ns_filter).with_options(options).await?;
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
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease(&upstream.namespace)
                .await?;
            mtls_lease
                .run_mutation(async {
                    if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        session
                            .start_transaction()
                            .and_run(
                                (self, doc, upstream.namespace.clone(), upstream.id.clone()),
                                |s, (this, doc, namespace, id)| {
                                    Box::pin(async move {
                                        this.upstreams()
                                            .insert_one(doc.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "upstream",
                                            id.as_str(),
                                            "upsert",
                                        )
                                        .await?;
                                        Ok(())
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("create_upstream transaction failed")?;
                        self.compact_config_changes_best_effort(&upstream.namespace)
                            .await;
                    } else {
                        self.upstreams().insert_one(doc).await?;
                        if let Err(err) = self
                            .record_config_change(
                                &upstream.namespace,
                                "upstream",
                                &upstream.id,
                                "upsert",
                            )
                            .await
                        {
                            self.rollback_standalone_created_document(
                                "upstreams",
                                &upstream.namespace,
                                "upstream",
                                &upstream.id,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    }
                    Ok(())
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("create_upstream", start);
            Ok(())
        }

        async fn update_upstream(&self, upstream: &Upstream) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            // Preserve api_spec_id by carrying it into the replacement document.
            // Returning an error is safer than silently detaching spec ownership.
            let mut doc = upstream_to_doc(upstream)?;
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease(&upstream.namespace)
                .await?;
            let existing_doc = self
                .upstreams()
                .find_one(doc! { "_id": &upstream.id, "namespace": &upstream.namespace })
                .await?;
            if existing_doc.is_none() {
                // No document in this namespace — phantom update, no
                // config-change record (DB-M4).
                mtls_lease.release().await?;
                self.check_slow_query("update_upstream", start);
                return Ok(false);
            }
            let existing_spec_id = match existing_doc.as_ref().and_then(|d| d.get("api_spec_id")) {
                Some(Bson::String(s)) if !s.is_empty() => Some(s.clone()),
                Some(Bson::Null) | None => None,
                Some(other) => {
                    mtls_lease.release().await?;
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
            let matched = mtls_lease
                .run_mutation(async {
                    if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        let matched = session
                            .start_transaction()
                            .and_run(
                                (self, doc, upstream.namespace.clone(), upstream.id.clone()),
                                |s, (this, doc, namespace, id)| {
                                    Box::pin(async move {
                                        let replace_result = this
                                            .upstreams()
                                            .replace_one(
                                                doc! {
                                                    "_id": id.as_str(),
                                                    "namespace": namespace.as_str(),
                                                },
                                                doc.clone(),
                                            )
                                            .session(&mut *s)
                                            .await?;
                                        if replace_result.matched_count == 0 {
                                            // Phantom update: no config-change record
                                            // (DB-M4).
                                            return Ok(false);
                                        }
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "upstream",
                                            id.as_str(),
                                            "upsert",
                                        )
                                        .await?;
                                        Ok(true)
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("update_upstream transaction failed")?;
                        if matched {
                            self.compact_config_changes_best_effort(&upstream.namespace)
                                .await;
                        }
                        Ok(matched)
                    } else {
                        let replace_result = self
                            .upstreams()
                            .replace_one(
                                doc! { "_id": &upstream.id, "namespace": &upstream.namespace },
                                doc,
                            )
                            .await?;
                        if replace_result.matched_count == 0 {
                            // Phantom update (concurrent delete): no config-change
                            // record (DB-M4).
                            return Ok(false);
                        }
                        if let Err(err) = self
                            .record_config_change(
                                &upstream.namespace,
                                "upstream",
                                &upstream.id,
                                "upsert",
                            )
                            .await
                        {
                            self.rollback_standalone_updated_document(
                                "upstreams",
                                "upstream",
                                &upstream.id,
                                existing_doc,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                        Ok(true)
                    }
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("update_upstream", start);
            Ok(matched)
        }

        async fn delete_upstream(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;
            let deleted = mtls_lease
                .run_mutation(async {
            let deleted = if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let deleted = session
                    .start_transaction()
                    .and_run(
                        (self, id.to_string(), namespace.to_string()),
                        |s, (this, id, namespace)| {
                            Box::pin(async move {
                                // Avoid creating a guard for a missing target.
                                // This read is inside the transaction so the
                                // following guard write still serializes with
                                // concurrent proxy admissions/deletes.
                                if this
                                    .upstreams()
                                    .find_one(doc! {
                                        "_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .projection(doc! { "_id": 1 })
                                    .session(&mut *s)
                                    .await?
                                    .is_none()
                                {
                                    return Ok(false);
                                }
                                // Write the same guard doc that proxy
                                // create/update transactions write when they
                                // reference this upstream, so a concurrent
                                // create-referencing transaction and this
                                // delete write-conflict and serialize (DB-H4).
                                // The upstream document itself is never
                                // modified — an unknown field would break
                                // deserialization elsewhere.
                                this.upstream_ref_guards()
                                    .update_one(
                                        doc! { "_id": format!("{}:{}", namespace, id) },
                                        doc! {
                                            "$set": {
                                                "nonce": Uuid::new_v4().to_string(),
                                                "updated_at": Utc::now().to_rfc3339(),
                                            }
                                        },
                                    )
                                    .upsert(true)
                                    .session(&mut *s)
                                    .await?;
                                // Reference checks run INSIDE the transaction
                                // so they cannot race a concurrent
                                // create-referencing transaction.
                                let proxy_refs = this
                                    .proxies()
                                    .count_documents(doc! { "upstream_id": id.as_str() })
                                    .session(&mut *s)
                                    .await?;
                                if proxy_refs > 0 {
                                    return Err(mongodb::error::Error::custom(format!(
                                        "Upstream {} is referenced by one or more proxies and cannot be deleted",
                                        id
                                    )));
                                }
                                if let Some(plugin) = this
                                    .find_mesh_route_dispatch_upstream_ref_opt_session(
                                        Some(&mut *s),
                                        id.as_str(),
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?
                                {
                                    return Err(mongodb::error::Error::custom(format!(
                                        "Upstream {} is referenced by mesh_route_dispatch plugin_config '{}' and cannot be deleted",
                                        id, plugin.id
                                    )));
                                }
                                let result = this
                                    .upstreams()
                                    .delete_one(doc! {
                                        "_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                if result.deleted_count > 0 {
                                    // The upstream is gone — drop its guard
                                    // doc so the collection doesn't accrete
                                    // entries for deleted upstreams.
                                    this.upstream_ref_guards()
                                        .delete_one(
                                            doc! { "_id": format!("{}:{}", namespace, id) },
                                        )
                                        .session(&mut *s)
                                        .await?;
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "upstream",
                                        id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                Ok(result.deleted_count > 0)
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("delete_upstream transaction failed")?;
                if deleted {
                    self.compact_config_changes_best_effort(namespace).await;
                }
                deleted
            } else {
                // Standalone pre-checks (best-effort, no transaction).
                // Verify the target in the requested namespace before scanning
                // references so a wrong-namespace delete remains a 404 and
                // does not disclose another namespace's relationships.
                // Capture the document now so a post-delete re-check can
                // restore it.
                let existing = self
                    .upstreams()
                    .find_one(doc! { "_id": id, "namespace": namespace })
                    .await?;
                let Some(existing) = existing else {
                    self.check_slow_query("delete_upstream", start);
                    return Ok(false);
                };
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
                let result = self
                    .upstreams()
                    .delete_one(doc! { "_id": id, "namespace": namespace })
                    .await?;
                if result.deleted_count == 0 {
                    self.check_slow_query("delete_upstream", start);
                    return Ok(false);
                }
                // Post-delete re-check: a proxy referencing this upstream may
                // have been created between the pre-check and the delete. If
                // one appeared, re-insert the captured document and bail.
                // Together with create_proxy's post-insert existence
                // re-check, these two post-write reconciliations converge for
                // every interleaving of a concurrent create+delete pair:
                // whichever write lands second observes the other and
                // self-reverts. Full serialization requires
                // FERRUM_MONGO_REPLICA_SET.
                let proxy_refs_after = self
                    .proxies()
                    .count_documents(doc! { "upstream_id": id })
                    .await?;
                if proxy_refs_after > 0 {
                    if let Err(err) = self.upstreams().insert_one(existing).await {
                        return Err(anyhow::Error::new(err).context(format!(
                            "MongoDB standalone delete_upstream could not restore '{}' after a late proxy reference",
                            id
                        )));
                    }
                    anyhow::bail!(
                        "Upstream {} is referenced by one or more proxies and cannot be deleted",
                        id
                    );
                }
                self.record_config_change(namespace, "upstream", id, "delete")
                    .await?;
                true
            };
            Ok(deleted)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("delete_upstream", start);
            Ok(deleted)
        }

        async fn get_upstream(
            &self,
            namespace: &str,
            id: &str,
        ) -> Result<Option<Upstream>, anyhow::Error> {
            let start = std::time::Instant::now();
            let result = self
                .upstreams()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;
            self.check_slow_query("get_upstream", start);
            match result {
                Some(doc) => Ok(Some(doc_to_upstream(doc)?)),
                None => Ok(None),
            }
        }

        async fn cleanup_orphaned_upstream(
            &self,
            namespace: &str,
            upstream_id: &str,
        ) -> Result<(), anyhow::Error> {
            let start = std::time::Instant::now();
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;
            let deleted_namespace = mtls_lease
                .run_mutation(async {
                    let deleted_namespace = if self.replica_set_configured() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        session
                            .start_transaction()
                            .and_run(
                                (self, namespace.to_string(), upstream_id.to_string()),
                                |s, (this, namespace, upstream_id)| {
                                    Box::pin(async move {
                                        let count = this
                                            .proxies()
                                            .count_documents(
                                                doc! { "upstream_id": upstream_id.as_str() },
                                            )
                                            .session(&mut *s)
                                            .await?;
                                        let mut deleted_namespace = None;
                                        if count == 0 {
                                            let dispatch_ref = this
                                                .find_mesh_route_dispatch_upstream_ref_opt_session(
                                                    Some(&mut *s),
                                                    upstream_id,
                                                )
                                                .await
                                                .map_err(|e| {
                                                    mongodb::error::Error::custom(e.to_string())
                                                })?;
                                            if dispatch_ref.is_none() {
                                                let result = this
                                                    .upstreams()
                                                    .delete_one(doc! {
                                                        "_id": upstream_id.as_str(),
                                                        "namespace": namespace.as_str(),
                                                    })
                                                    .session(&mut *s)
                                                    .await?;
                                                if result.deleted_count > 0 {
                                                    this.record_config_change_in_session(
                                                        &mut *s,
                                                        namespace.as_str(),
                                                        "upstream",
                                                        upstream_id.as_str(),
                                                        "delete",
                                                    )
                                                    .await?;
                                                    deleted_namespace = Some(namespace.clone());
                                                }
                                            }
                                        }
                                        Ok(deleted_namespace)
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("cleanup_orphaned_upstream transaction failed")?
                    } else {
                        let count = self
                            .proxies()
                            .count_documents(doc! { "upstream_id": upstream_id })
                            .await?;
                        let dispatch_ref = if count == 0 {
                            self.find_mesh_route_dispatch_upstream_ref_opt_session(
                                None,
                                upstream_id,
                            )
                            .await?
                        } else {
                            None
                        };
                        if count == 0 && dispatch_ref.is_none() {
                            let result = self
                                .upstreams()
                                .delete_one(doc! { "_id": upstream_id, "namespace": namespace })
                                .await?;
                            if result.deleted_count > 0 {
                                self.record_config_change(
                                    namespace,
                                    "upstream",
                                    upstream_id,
                                    "delete",
                                )
                                .await?;
                                Some(namespace.to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    Ok(deleted_namespace)
                })
                .await?;
            mtls_lease.release().await?;
            if let Some(namespace) = deleted_namespace {
                if self.replica_set_configured() {
                    self.compact_config_changes_best_effort(&namespace).await;
                }
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
                .skip(Some(mongo_skip(offset)))
                .limit(Some(limit))
                .build();
            let upstreams = self.upstreams();
            let mut cursor = upstreams.find(ns_filter).with_options(options).await?;
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
            let proxies = self.proxies();
            let mut cursor = proxies
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
            // Consumer `_id` is the composite "{namespace}:{id}", so identity
            // matching (and self-exclusion) must run against the plain `id`
            // field that serde keeps in the document.
            let mut filter = doc! {
                "namespace": namespace,
                "$or": [
                    { "id": { "$in": candidates.clone() } },
                    { "username": { "$in": candidates.clone() } },
                    { "custom_id": { "$in": candidates } },
                ],
            };
            if let Some(id) = exclude_consumer_id {
                filter.insert("id", doc! { "$ne": id });
            }
            let result = self.consumers().find_one(filter).await?;
            match result {
                Some(doc) => {
                    let conflict_id = doc.get_str("id").unwrap_or("unknown").to_string();
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
                // Consumer `_id` is composite ("{namespace}:{id}") — exclude
                // by the plain `id` field.
                filter.insert("id", doc! { "$ne": id });
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
                // Consumer `_id` is composite ("{namespace}:{id}") — exclude
                // by the plain `id` field.
                filter.insert("id", doc! { "$ne": id });
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

        async fn batch_create_proxies(
            &self,
            proxies: &[Proxy],
            mode: &BatchConfigWriteMode,
        ) -> Result<usize, anyhow::Error> {
            if proxies.is_empty() {
                return Ok(0);
            }
            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases_for_mode(
                    proxies.iter().map(|proxy| proxy.namespace.as_str()),
                    mode,
                )
                .await?;
            if mode.validates_mtls_dns() {
                let namespaces: HashSet<&str> = proxies
                    .iter()
                    .map(|proxy| proxy.namespace.as_str())
                    .collect();
                for namespace in namespaces {
                    self.validate_plugin_graph_admission_candidate(namespace, |candidate| {
                        candidate.proxies.extend(
                            proxies
                                .iter()
                                .filter(|proxy| proxy.namespace == namespace)
                                .cloned(),
                        );
                    })
                    .await?;
                }
            }
            let docs: Vec<Document> = proxies.iter().map(proxy_to_doc).collect::<Result<_, _>>()?;
            let count = Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                let count = if self.replica_set_configured() {
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    let changes: Vec<(String, String)> = proxies
                        .iter()
                        .map(|proxy| (proxy.namespace.clone(), proxy.id.clone()))
                        .collect();
                    let count = session
                        .start_transaction()
                        .and_run((self, docs, changes), |s, (this, docs, changes)| {
                            Box::pin(async move {
                                let result = this
                                    .proxies()
                                    .insert_many(docs.clone())
                                    .ordered(false)
                                    .session(&mut *s)
                                    .await?;
                                for (namespace, id) in changes.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "proxy",
                                        id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                Ok(result.inserted_ids.len())
                            })
                        })
                        .await
                        .map_err(anyhow::Error::new)
                        .context("batch_create_proxies transaction failed")?;
                    let namespaces: HashSet<String> = proxies
                        .iter()
                        .map(|proxy| proxy.namespace.clone())
                        .collect();
                    for namespace in namespaces {
                        self.compact_config_changes_best_effort(&namespace).await;
                    }
                    count
                } else {
                    let ids: Vec<&str> = proxies.iter().map(|proxy| proxy.id.as_str()).collect();
                    let result = match self.proxies().insert_many(docs).ordered(false).await {
                        Ok(result) => result,
                        Err(err) => {
                            let rollback_ids =
                                Self::rollback_ids_for_unordered_insert_error(&ids, &err);
                            let err = anyhow::Error::new(err);
                            self.rollback_standalone_created_documents(
                                "proxies",
                                "proxy",
                                &rollback_ids,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    };
                    let changes: Vec<ConfigChangeWrite<'_>> = proxies
                        .iter()
                        .map(|proxy| ConfigChangeWrite {
                            namespace: &proxy.namespace,
                            resource_type: "proxy",
                            resource_id: &proxy.id,
                            operation: "upsert",
                        })
                        .collect();
                    if let Err(err) = self.record_config_changes_batch(&changes).await {
                        self.rollback_standalone_created_documents("proxies", "proxy", &ids, &err)
                            .await;
                        return Err(err);
                    }
                    result.inserted_ids.len()
                };
                Ok(count)
            })
            .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
            Ok(count)
        }

        async fn batch_create_proxies_without_plugins(
            &self,
            proxies: &[Proxy],
            mode: &BatchConfigWriteMode,
        ) -> Result<usize, anyhow::Error> {
            // In MongoDB, plugins are embedded in the proxy document, so this
            // is the same as batch_create_proxies. The distinction only matters
            // for the SQL backend where plugin associations are in a junction table.
            self.batch_create_proxies(proxies, mode).await
        }

        async fn batch_attach_proxy_plugins(
            &self,
            _proxies: &[Proxy],
            _mode: &BatchConfigWriteMode,
        ) -> Result<(), anyhow::Error> {
            // No-op for MongoDB — plugins are embedded in the proxy document.
            // The SQL backend uses this to populate the proxy_plugins junction table.
            Ok(())
        }

        async fn batch_create_consumers(
            &self,
            consumers: &[Consumer],
            mode: &BatchConfigWriteMode,
        ) -> Result<usize, anyhow::Error> {
            if consumers.is_empty() {
                return Ok(0);
            }
            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases_for_mode(
                    consumers.iter().map(|consumer| consumer.namespace.as_str()),
                    mode,
                )
                .await?;
            if mode.validates_mtls_dns() {
                let namespaces: HashSet<&str> = consumers
                    .iter()
                    .map(|consumer| consumer.namespace.as_str())
                    .collect();
                for namespace in namespaces {
                    self.validate_mtls_dns_candidate(namespace, |candidate| {
                        candidate.consumers.extend(
                            consumers
                                .iter()
                                .filter(|consumer| consumer.namespace == namespace)
                                .cloned(),
                        );
                    })
                    .await?;
                }
            }
            let docs: Vec<Document> = consumers
                .iter()
                .map(consumer_to_doc)
                .collect::<Result<_, _>>()?;
            // Identity reservations for the whole batch. Two batch members
            // colliding with each other also collide here (duplicate `_id` on
            // the ordered insert).
            let identity_docs: Vec<Document> = consumers
                .iter()
                .flat_map(|consumer| {
                    consumer_identity_index_docs(
                        &consumer.namespace,
                        &consumer.id,
                        &consumer_identity_values(consumer),
                    )
                })
                .collect();
            let count = Self::run_mtls_dns_mutations(&mut mtls_leases, async {
            let count = if self.replica_set_configured() {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let changes: Vec<(String, String)> = consumers
                    .iter()
                    .map(|consumer| (consumer.namespace.clone(), consumer.id.clone()))
                    .collect();
                let count = session
                    .start_transaction()
                    .and_run(
                        (self, docs, changes, identity_docs),
                        |s, (this, docs, changes, identity_docs)| {
                            Box::pin(async move {
                                // Reserve the merged identity keyspace with a
                                // preflight read-then-insert (see
                                // preflight_reserve_consumer_identity_docs_in_session):
                                // every reservation is read and classified
                                // BEFORE any write. Same-owner reservations are
                                // adopted, a different owner or an intra-batch
                                // collision fails closed (409), and only
                                // preflight-absent reservations are inserted.
                                // No post-E11000 recovery runs in this
                                // transaction — a duplicate on the insert aborts
                                // it and the runner retries the closure.
                                this.preflight_reserve_consumer_identity_docs_in_session(
                                    &mut *s,
                                    identity_docs.as_slice(),
                                )
                                .await?;
                                let result = this
                                    .consumers()
                                    .insert_many(docs.clone())
                                    .ordered(false)
                                    .session(&mut *s)
                                    .await?;
                                for (namespace, id) in changes.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "consumer",
                                        id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                Ok(result.inserted_ids.len())
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("batch_create_consumers transaction failed")?;
                let namespaces: HashSet<String> = consumers
                    .iter()
                    .map(|consumer| consumer.namespace.clone())
                    .collect();
                for namespace in namespaces {
                    self.compact_config_changes_best_effort(&namespace).await;
                }
                count
            } else {
                // Standalone RESERVE FIRST: insert identity reservations for
                // the whole batch (ordered) before any consumer document. On
                // failure, best-effort delete (1) the verifiable ordered-insert
                // prefix and (2) vacant reservations this adoption attempt
                // inserted before failing — never pre-existing same-owner
                // adoptions. After a successful reserve (including same-owner
                // adoption), later consumer-write rollback releases only that
                // newly-inserted set — never adopted docs of unknown provenance.
                let mut newly_inserted_identity_docs: Vec<Document> = Vec::new();
                if let Err(err) = self
                    .consumer_identity_index()
                    .insert_many(identity_docs.clone())
                    .await
                {
                    if is_duplicate_key(&err) {
                        // Same-owner adoption across the batch: every doc must
                        // already be owned by its intended consumer_id (or be
                        // insertable). Cross-owner conflict still fails after
                        // releasing this call's ordered prefix plus vacant
                        // adoption inserts committed before the conflict.
                        let mut adopt_ok = true;
                        let mut adopt_err: Option<anyhow::Error> = None;
                        let mut ensured_new_docs: Vec<Document> = Vec::new();
                        for doc in &identity_docs {
                            let Ok(doc_id) = doc.get_str("_id") else {
                                adopt_ok = false;
                                adopt_err = Some(anyhow::anyhow!(
                                    "batch consumer identity reservation missing _id"
                                ));
                                break;
                            };
                            let Ok(consumer_id) = doc.get_str("consumer_id") else {
                                adopt_ok = false;
                                adopt_err = Some(anyhow::anyhow!(
                                    "batch consumer identity reservation '{}' missing consumer_id",
                                    doc_id
                                ));
                                break;
                            };
                            let Ok(namespace) = doc.get_str("namespace") else {
                                adopt_ok = false;
                                adopt_err = Some(anyhow::anyhow!(
                                    "batch consumer identity reservation '{}' missing namespace",
                                    doc_id
                                ));
                                break;
                            };
                            let Ok(identity_value) = doc.get_str("identity_value") else {
                                adopt_ok = false;
                                adopt_err = Some(anyhow::anyhow!(
                                    "batch consumer identity reservation '{}' missing identity_value",
                                    doc_id
                                ));
                                break;
                            };
                            match self
                                .ensure_consumer_identity_docs_owned(
                                    namespace,
                                    consumer_id,
                                    &[identity_value.to_string()],
                                )
                                .await
                            {
                                Ok(newly) => {
                                    if newly.iter().any(|value| value == identity_value) {
                                        ensured_new_docs.push(doc.clone());
                                    }
                                }
                                Err(e) => {
                                    // Single-value ensure: any vacant insert
                                    // committed inside this call before failure
                                    // is still on e.newly_inserted.
                                    for value in &e.newly_inserted {
                                        if value == identity_value {
                                            let already = ensured_new_docs.iter().any(|existing| {
                                                existing.get_str("_id").ok()
                                                    == doc.get_str("_id").ok()
                                            });
                                            if !already {
                                                ensured_new_docs.push(doc.clone());
                                            }
                                        }
                                    }
                                    adopt_ok = false;
                                    adopt_err = Some(e.into_source());
                                    break;
                                }
                            }
                        }
                        if !adopt_ok {
                            let inserted_prefix =
                                Self::ordered_insert_inserted_prefix_len(&err);
                            if inserted_prefix.is_none() {
                                warn!(
                                    "Retaining MongoDB batch consumer identity reservations because the \
                                     failed ordered insert did not report a verifiable write-error index; \
                                     still releasing vacant reservations inserted during this adoption \
                                     attempt"
                                );
                            }
                            let mut to_release: Vec<Document> =
                                ordered_insert_newly_inserted_prefix(
                                    &identity_docs,
                                    inserted_prefix,
                                )
                                .to_vec();
                            for doc in &ensured_new_docs {
                                let already = to_release.iter().any(|existing| {
                                    existing.get_str("_id").ok() == doc.get_str("_id").ok()
                                });
                                if !already {
                                    to_release.push(doc.clone());
                                }
                            }
                            self.release_consumer_identity_docs_best_effort(&to_release)
                                .await;
                            return Err(adopt_err.unwrap_or_else(|| err.into()));
                        }
                        let inserted_prefix = Self::ordered_insert_inserted_prefix_len(&err);
                        newly_inserted_identity_docs.extend(
                            ordered_insert_newly_inserted_prefix(&identity_docs, inserted_prefix)
                                .iter()
                                .cloned(),
                        );
                        if inserted_prefix.is_none() {
                            warn!(
                                "Retaining MongoDB batch consumer identity reservations that may have \
                                 been inserted by a failed ordered insert without a verifiable \
                                 write-error index; rollback will only release values newly inserted \
                                 during same-owner adoption"
                            );
                        }
                        for doc in ensured_new_docs {
                            let already = newly_inserted_identity_docs.iter().any(|existing| {
                                existing.get_str("_id").ok() == doc.get_str("_id").ok()
                            });
                            if !already {
                                newly_inserted_identity_docs.push(doc);
                            }
                        }
                    } else {
                        if let Some(inserted) = Self::ordered_insert_inserted_prefix_len(&err) {
                            self.release_consumer_identity_docs_best_effort(
                                &identity_docs[..inserted],
                            )
                            .await;
                        } else {
                            warn!(
                                "Retaining MongoDB batch consumer identity reservations because the \
                                 failed ordered insert did not report a verifiable write-error index"
                            );
                        }
                        return Err(err.into());
                    }
                } else {
                    newly_inserted_identity_docs = identity_docs.clone();
                }
                // Composite `_id`s ("{namespace}:{id}") for document-level
                // rollback; change-log records keep the plain resource ids.
                let doc_ids: Vec<String> = consumers
                    .iter()
                    .map(|consumer| consumer_doc_id(&consumer.namespace, &consumer.id))
                    .collect();
                let ids: Vec<&str> = doc_ids.iter().map(String::as_str).collect();
                let result = match self.consumers().insert_many(docs).ordered(false).await {
                    Ok(result) => result,
                    Err(err) => {
                        let rollback_ids =
                            Self::rollback_ids_for_unordered_insert_error(&ids, &err);
                        let err = anyhow::Error::new(err);
                        let confirmed_absent = self
                            .rollback_standalone_created_documents(
                                "consumers",
                                "consumer",
                                &rollback_ids,
                                &err,
                            )
                            .await;
                        self.release_confirmed_batch_consumer_identity_docs_best_effort(
                            &newly_inserted_identity_docs,
                            &confirmed_absent,
                        )
                        .await;
                        return Err(err);
                    }
                };
                let changes: Vec<ConfigChangeWrite<'_>> = consumers
                    .iter()
                    .map(|consumer| ConfigChangeWrite {
                        namespace: &consumer.namespace,
                        resource_type: "consumer",
                        resource_id: &consumer.id,
                        operation: "upsert",
                    })
                    .collect();
                if let Err(err) = self.record_config_changes_batch(&changes).await {
                    let confirmed_absent = self
                        .rollback_standalone_created_documents("consumers", "consumer", &ids, &err)
                        .await;
                    self.release_confirmed_batch_consumer_identity_docs_best_effort(
                        &newly_inserted_identity_docs,
                        &confirmed_absent,
                    )
                    .await;
                    return Err(err);
                }
                result.inserted_ids.len()
            };
            Ok(count)
                })
                .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
            Ok(count)
        }

        async fn batch_create_plugin_configs(
            &self,
            configs: &[PluginConfig],
            mode: &BatchConfigWriteMode,
        ) -> Result<usize, anyhow::Error> {
            if configs.is_empty() {
                return Ok(0);
            }
            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases_for_mode(
                    configs.iter().map(|config| config.namespace.as_str()),
                    mode,
                )
                .await?;
            if mode.validates_mtls_dns() {
                let namespaces: HashSet<&str> = configs
                    .iter()
                    .map(|config| config.namespace.as_str())
                    .collect();
                for namespace in namespaces {
                    self.validate_plugin_graph_admission_candidate(namespace, |candidate| {
                        candidate.plugin_configs.extend(
                            configs
                                .iter()
                                .filter(|config| config.namespace == namespace)
                                .cloned(),
                        );
                    })
                    .await?;
                }
            }
            let docs: Vec<Document> = configs
                .iter()
                .map(plugin_config_to_doc)
                .collect::<Result<_, _>>()?;
            let count = Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                let count = if self.replica_set_configured() {
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    let changes: Vec<(String, String)> = configs
                        .iter()
                        .map(|config| (config.namespace.clone(), config.id.clone()))
                        .collect();
                    let count = session
                        .start_transaction()
                        .and_run((self, docs, changes), |s, (this, docs, changes)| {
                            Box::pin(async move {
                                let result = this
                                    .plugin_configs()
                                    .insert_many(docs.clone())
                                    .ordered(false)
                                    .session(&mut *s)
                                    .await?;
                                for (namespace, id) in changes.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "plugin_config",
                                        id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                Ok(result.inserted_ids.len())
                            })
                        })
                        .await
                        .map_err(anyhow::Error::new)
                        .context("batch_create_plugin_configs transaction failed")?;
                    let namespaces: HashSet<String> = configs
                        .iter()
                        .map(|config| config.namespace.clone())
                        .collect();
                    for namespace in namespaces {
                        self.compact_config_changes_best_effort(&namespace).await;
                    }
                    count
                } else {
                    let ids: Vec<&str> = configs.iter().map(|config| config.id.as_str()).collect();
                    let result = match self.plugin_configs().insert_many(docs).ordered(false).await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            let rollback_ids =
                                Self::rollback_ids_for_unordered_insert_error(&ids, &err);
                            let err = anyhow::Error::new(err);
                            self.rollback_standalone_created_documents(
                                "plugin_configs",
                                "plugin_config",
                                &rollback_ids,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    };
                    let changes: Vec<ConfigChangeWrite<'_>> = configs
                        .iter()
                        .map(|config| ConfigChangeWrite {
                            namespace: &config.namespace,
                            resource_type: "plugin_config",
                            resource_id: &config.id,
                            operation: "upsert",
                        })
                        .collect();
                    if let Err(err) = self.record_config_changes_batch(&changes).await {
                        self.rollback_standalone_created_documents(
                            "plugin_configs",
                            "plugin_config",
                            &ids,
                            &err,
                        )
                        .await;
                        return Err(err);
                    }
                    result.inserted_ids.len()
                };
                Ok(count)
            })
            .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
            Ok(count)
        }

        async fn batch_create_upstreams(
            &self,
            upstreams: &[Upstream],
            mode: &BatchConfigWriteMode,
        ) -> Result<usize, anyhow::Error> {
            if upstreams.is_empty() {
                return Ok(0);
            }
            let docs: Vec<Document> = upstreams
                .iter()
                .map(upstream_to_doc)
                .collect::<Result<_, _>>()?;
            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases_for_mode(
                    upstreams.iter().map(|upstream| upstream.namespace.as_str()),
                    mode,
                )
                .await?;
            let count = Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                let count = if self.replica_set_configured() {
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    let changes: Vec<(String, String)> = upstreams
                        .iter()
                        .map(|upstream| (upstream.namespace.clone(), upstream.id.clone()))
                        .collect();
                    let count = session
                        .start_transaction()
                        .and_run((self, docs, changes), |s, (this, docs, changes)| {
                            Box::pin(async move {
                                let result = this
                                    .upstreams()
                                    .insert_many(docs.clone())
                                    .ordered(false)
                                    .session(&mut *s)
                                    .await?;
                                for (namespace, id) in changes.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "upstream",
                                        id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                Ok(result.inserted_ids.len())
                            })
                        })
                        .await
                        .map_err(anyhow::Error::new)
                        .context("batch_create_upstreams transaction failed")?;
                    let namespaces: HashSet<String> = upstreams
                        .iter()
                        .map(|upstream| upstream.namespace.clone())
                        .collect();
                    for namespace in namespaces {
                        self.compact_config_changes_best_effort(&namespace).await;
                    }
                    count
                } else {
                    let ids: Vec<&str> = upstreams
                        .iter()
                        .map(|upstream| upstream.id.as_str())
                        .collect();
                    let result = match self.upstreams().insert_many(docs).ordered(false).await {
                        Ok(result) => result,
                        Err(err) => {
                            let rollback_ids =
                                Self::rollback_ids_for_unordered_insert_error(&ids, &err);
                            let err = anyhow::Error::new(err);
                            self.rollback_standalone_created_documents(
                                "upstreams",
                                "upstream",
                                &rollback_ids,
                                &err,
                            )
                            .await;
                            return Err(err);
                        }
                    };
                    let changes: Vec<ConfigChangeWrite<'_>> = upstreams
                        .iter()
                        .map(|upstream| ConfigChangeWrite {
                            namespace: &upstream.namespace,
                            resource_type: "upstream",
                            resource_id: &upstream.id,
                            operation: "upsert",
                        })
                        .collect();
                    if let Err(err) = self.record_config_changes_batch(&changes).await {
                        self.rollback_standalone_created_documents(
                            "upstreams",
                            "upstream",
                            &ids,
                            &err,
                        )
                        .await;
                        return Err(err);
                    }
                    result.inserted_ids.len()
                };
                Ok(count)
            })
            .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
            Ok(count)
        }

        async fn delete_all_resources(
            &self,
            namespace: &str,
            write_mode: &BatchConfigWriteMode,
        ) -> Result<DeleteMode, DeleteAllResourcesError> {
            let mut mtls_lease = self
                .acquire_mtls_dns_admission_lease_for_mode(namespace, write_mode)
                .await
                .map_err(|source| {
                    let mode = if self.replica_set_configured() {
                        DeleteMode::Atomic
                    } else {
                        DeleteMode::NonAtomic
                    };
                    DeleteAllResourcesError::new(mode, source)
                })?;
            // Capture topology only after the guard pins its connection
            // generation. This value selects the implementation branch and is
            // returned on success or carried by an error, so reconnect cannot
            // make the request classify a different bundle than it mutates.
            let mode = if self.replica_set_configured() {
                DeleteMode::Atomic
            } else {
                DeleteMode::NonAtomic
            };
            let ns_filter = doc! { "namespace": namespace };
            let mutation_result = mtls_lease
                .run_mutation(async {
                    if mode.is_atomic() {
                        let connection = self.connection();
                        let mut session = connection.client.start_session().await?;
                        session
                            .start_transaction()
                            .and_run(
                                (self, namespace.to_string(), ns_filter.clone()),
                                |s, (this, namespace, ns_filter)| {
                                    Box::pin(async move {
                                        let proxy_ids = this
                                            .load_collection_ids_filtered_in_session(
                                                &mut *s,
                                                "proxies",
                                                ns_filter.clone(),
                                            )
                                            .await
                                            .map_err(|e| {
                                                mongodb::error::Error::custom(e.to_string())
                                            })?;
                                        // Consumers project the plain `id` field —
                                        // their `_id` is the composite
                                        // "{namespace}:{id}" and change-log records
                                        // carry plain resource ids.
                                        let consumer_ids = this
                                            .load_consumer_plain_ids_filtered_in_session(
                                                &mut *s,
                                                ns_filter.clone(),
                                            )
                                            .await
                                            .map_err(|e| {
                                                mongodb::error::Error::custom(e.to_string())
                                            })?;
                                        let plugin_config_ids = this
                                            .load_collection_ids_filtered_in_session(
                                                &mut *s,
                                                "plugin_configs",
                                                ns_filter.clone(),
                                            )
                                            .await
                                            .map_err(|e| {
                                                mongodb::error::Error::custom(e.to_string())
                                            })?;
                                        let upstream_ids = this
                                            .load_collection_ids_filtered_in_session(
                                                &mut *s,
                                                "upstreams",
                                                ns_filter.clone(),
                                            )
                                            .await
                                            .map_err(|e| {
                                                mongodb::error::Error::custom(e.to_string())
                                            })?;
                                        this.plugin_configs()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.proxies()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.consumers()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        // Namespace wipe releases every consumer
                                        // identity reservation in the namespace.
                                        this.consumer_identity_index()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.upstreams()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        this.api_specs()
                                            .delete_many(ns_filter.clone())
                                            .session(&mut *s)
                                            .await?;
                                        for id in &proxy_ids {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "proxy",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                        for id in &consumer_ids {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "consumer",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                        for id in &plugin_config_ids {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "plugin_config",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                        for id in &upstream_ids {
                                            this.record_config_change_in_session(
                                                &mut *s,
                                                namespace.as_str(),
                                                "upstream",
                                                id.as_str(),
                                                "delete",
                                            )
                                            .await?;
                                        }
                                        Ok(())
                                    })
                                },
                            )
                            .await
                            .map_err(anyhow::Error::new)
                            .context("delete_all_resources transaction failed")?;
                        self.compact_config_changes_best_effort(namespace).await;
                    } else {
                        let proxy_ids = self
                            .load_collection_ids_filtered("proxies", ns_filter.clone())
                            .await?;
                        // Plain `id` field — consumer `_id` is the composite
                        // "{namespace}:{id}" and change-log records carry plain ids.
                        let consumer_ids = self
                            .load_consumer_plain_ids_filtered(ns_filter.clone())
                            .await?;
                        let plugin_config_ids = self
                            .load_collection_ids_filtered("plugin_configs", ns_filter.clone())
                            .await?;
                        let upstream_ids = self
                            .load_collection_ids_filtered("upstreams", ns_filter.clone())
                            .await?;
                        self.plugin_configs().delete_many(ns_filter.clone()).await?;
                        self.proxies().delete_many(ns_filter.clone()).await?;
                        self.consumers().delete_many(ns_filter.clone()).await?;
                        // Namespace wipe releases every consumer identity reservation
                        // in the namespace.
                        self.consumer_identity_index()
                            .delete_many(ns_filter.clone())
                            .await?;
                        self.upstreams().delete_many(ns_filter.clone()).await?;
                        // Clear api_specs so restore doesn't leave orphaned spec metadata
                        // pointing to proxies that no longer exist.
                        self.api_specs().delete_many(ns_filter).await?;
                        for id in proxy_ids {
                            self.record_config_change(namespace, "proxy", &id, "delete")
                                .await?;
                        }
                        for id in consumer_ids {
                            self.record_config_change(namespace, "consumer", &id, "delete")
                                .await?;
                        }
                        for id in plugin_config_ids {
                            self.record_config_change(namespace, "plugin_config", &id, "delete")
                                .await?;
                        }
                        for id in upstream_ids {
                            self.record_config_change(namespace, "upstream", &id, "delete")
                                .await?;
                        }
                    }
                    Ok(mode)
                })
                .await;
            let mode = match mutation_result {
                Ok(mode) => mode,
                Err(source) => {
                    let error = if mongo_mutation_outcome_is_uncertain(&source) {
                        DeleteAllResourcesError::with_unknown_commit_result(mode, source)
                    } else {
                        DeleteAllResourcesError::new(mode, source)
                    };
                    return Err(error);
                }
            };
            let delete_error = |source: anyhow::Error| DeleteAllResourcesError::new(mode, source);
            mtls_lease.release().await.map_err(&delete_error)?;
            info!("All MongoDB resources deleted (namespace='{}')", namespace);
            Ok(mode)
        }

        async fn acquire_mtls_dns_admission_guard(
            &self,
            namespace: &str,
        ) -> Result<String, anyhow::Error> {
            let guard = self.acquire_mtls_dns_admission_lease(namespace).await?;
            let (owner, pin) = guard.into_persistent_owner()?;
            let _ = self.persistent_admission_pins.insert(
                owner.clone(),
                MongoPersistentAdmissionPin {
                    namespace: namespace.to_string(),
                    pin,
                    uncertain_outcome: Arc::new(AtomicBool::new(false)),
                },
            );
            Ok(owner)
        }

        async fn release_mtls_dns_admission_guard(
            &self,
            namespace: &str,
            guard_owner: &str,
        ) -> Result<(), anyhow::Error> {
            let connection = {
                let persistent_pin = self
                    .persistent_admission_pins
                    .get(guard_owner)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "MongoDB mTLS DNS admission guard is not active in this admin process for namespace '{namespace}'"
                        )
                    })?;
                if persistent_pin.namespace != namespace {
                    anyhow::bail!(
                        "MongoDB mTLS DNS admission guard belongs to a different namespace than '{namespace}'"
                    );
                }
                if persistent_pin.uncertain_outcome.load(Ordering::Acquire) {
                    anyhow::bail!(
                        "MongoDB mTLS DNS admission guard for namespace '{namespace}' retained because a protected mutation outcome is uncertain"
                    );
                }
                persistent_pin.pin.connection.clone()
            };
            let result = connection
                .lease_client
                .database(connection.db.name())
                .collection::<Document>("mtls_dns_admission_locks")
                .delete_one(doc! { "_id": namespace, "owner": guard_owner })
                .write_concern(WriteConcern::majority())
                .await;
            // The mutation outcome was checked as settled above. Drop the
            // process-local generation pin regardless of cleanup status; the
            // owner-qualified durable document remains the fail-closed fence
            // when the delete failed or its acknowledgement was lost.
            let _ = self.persistent_admission_pins.remove(guard_owner);
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    // Every borrowed mutation explicitly settled before this
                    // cleanup. Preserve its known response, surface cleanup
                    // status in the error log, and leave any durable fence for
                    // owner-qualified operator cleanup.
                    error!(
                        namespace = %namespace,
                        error = %error,
                        "MongoDB mTLS DNS admission guard cleanup failed after a settled operation"
                    );
                    return Ok(());
                }
            };
            if result.deleted_count != 1 {
                error!(
                    namespace = %namespace,
                    "MongoDB mTLS DNS admission guard cleanup did not match its owner after a settled operation"
                );
                return Ok(());
            }
            Ok(())
        }

        // -------------------------------------------------------------------
        // Connection lifecycle
        // -------------------------------------------------------------------

        async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> {
            // Build a fresh Client + Database against the requested URL using
            // the captured connection settings. `build_connection_bundle` runs a
            // ping before returning, so on `Ok` we know the new client can
            // actually talk to MongoDB. On `Err` the swap is skipped and the
            // existing (possibly degraded) client stays in place — same
            // contract as `DatabaseStore::reconnect` for sqlx.
            let (new_connection, replica_set_configured) = Self::build_connection_bundle(
                db_url,
                &self.conn_settings,
                self.conn_settings.tls_enabled,
                self.conn_settings.tls_ca_cert_path.as_deref(),
                self.conn_settings.tls_client_cert_path.as_deref(),
                self.conn_settings.tls_client_key_path.as_deref(),
                self.conn_settings.tls_insecure,
            )
            .await?;

            // Atomic swap. Readers that already loaded the old `Client` or
            // `Database` handle keep using it (in-flight commands complete);
            // the next call to `db()`/`client()` picks up the new handle. Any
            // generated TLS files are owned by the same bundle as the driver
            // client, so old files are deleted only after the final old bundle
            // reference is dropped.
            self.install_reconnected_bundle(new_connection, replica_set_configured)?;

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
            let mut migration_lease = self.acquire_migration_lease().await?;
            // Run every index/drop step inside a scoped future so a failure
            // part-way through still falls through to the lease release below.
            // Without this, an early `?` would exit `run_migrations` with the
            // lease still held, forcing other replicas to wait out the full
            // 120s lease window before they can migrate — the `Drop` path only
            // spawns a best-effort async cleanup that may never run when the
            // runtime is torn down in startup/migrate mode.
            let migration_result: Result<(), anyhow::Error> = async {
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
                // Supports incremental point-loads by namespace and changed IDs.
                // Deletions come from `config_changes`; normal polls no longer scan
                // full collection ID sets.
                self.proxies()
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! { "namespace": 1, "_id": 1 })
                            .build(),
                    )
                    .await?;

                // consumers indexes — uniqueness scoped to namespace.
                //
                // NOTE: the consumers collection's `_id` is the composite
                // "{namespace}:{id}" (see `consumer_doc_id`), so consumer *id*
                // uniqueness is per-namespace via `_id` itself — no extra index
                // needed. The username/custom_id unique indexes below stay as
                // secondary guards for their individual fields.
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
                // Namespace-scoped unique multikey index over the derived
                // secret-hash projection. One key is emitted per distinct
                // rotation entry, so another consumer cannot claim it while
                // repeated values within one document remain legal. Legacy
                // documents without the projection stay repairable instead of
                // making index creation fail on pre-existing duplicates.
                self.consumers()
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! { "namespace": 1, HMAC_SECRET_HASHES_FIELD: 1 })
                            .options(
                                IndexOptions::builder()
                                    .unique(true)
                                    .partial_filter_expression(doc! {
                                        HMAC_SECRET_HASHES_FIELD: { "$type": "string" }
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
                // Supports incremental point-loads by namespace and changed IDs.
                self.consumers()
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! { "namespace": 1, "_id": 1 })
                            .build(),
                    )
                    .await?;

                // consumer_identity_index — merged identity keyspace
                // (id ∪ username ∪ custom_id) per namespace. Documents are keyed
                // by `_id = "{namespace}:{identity_value}"`, so uniqueness needs
                // no extra index; the non-unique {namespace} index supports
                // namespace wipes (`delete_all_resources`) and per-consumer
                // cleanup filters.
                self.consumer_identity_index()
                    .create_index(IndexModel::builder().keys(doc! { "namespace": 1 }).build())
                    .await?;

                // Intentionally no automatic orphan reconcile of
                // `consumer_identity_index` against `consumers`. Point-read
                // consumer absence is not a uniqueness proof across serving
                // nodes (migration lease ≠ CRUD lock); reclaiming a live
                // reserve-first create would drop the durable uniqueness
                // guard. Crash orphans stay locked until same-owner E11000
                // adoption heals a retry of the same consumer id, or an
                // operator removes the reservation manually.

                // The guard collections are keyed purely by `_id`
                // (`{namespace}:{route_key_hash}`, `{namespace}:{upstream_id}`,
                // or the namespace itself) and need no secondary indexes. Some
                // are written from inside transactions, and MongoDB < 4.4 cannot
                // implicitly create a collection there, so create every guard
                // collection explicitly. NamespaceExists (code 48) is tolerated
                // for idempotent multi-instance startup.
                for lock_collection in [
                    "proxy_route_locks",
                    "upstream_ref_guards",
                    "mtls_dns_admission_locks",
                ] {
                    match self.db().create_collection(lock_collection).await {
                        Ok(()) => {}
                        Err(e) if is_namespace_exists(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }

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
                // Supports incremental point-loads by namespace and changed IDs.
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
                // Supports incremental point-loads by namespace and changed IDs.
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
                self.config_changes()
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! { "namespace": 1, "sequence": 1 })
                            .build(),
                    )
                    .await?;
                self.config_changes()
                    .create_index(IndexModel::builder().keys(doc! { "sequence": 1 }).build())
                    .await?;

                info!("MongoDB indexes ensured");
                Ok(())
            }
            .await;

            // Always release the lease — on success and on error — then surface
            // the combined outcome so a migration failure is not masked by a
            // release failure (and vice versa). Mirrors the SQL side's
            // run-body / capture-result / release / combine pattern.
            let release_result = migration_lease.release().await;
            match (migration_result, release_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(migration_err), Ok(())) => Err(migration_err),
                (Ok(()), Err(release_err)) => Err(release_err),
                (Err(migration_err), Err(release_err)) => Err(migration_err.context(format!(
                    "MongoDB migration lease release also failed: {release_err:#}"
                ))),
            }
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

        async fn list_namespaces_paginated(
            &self,
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<String>, anyhow::Error> {
            // MongoDB has no cross-collection union, so the distinct merge
            // stays in memory; namespace cardinality is operator-controlled
            // and bounded, and the page slice keeps the wire contract shared
            // with the SQL backends (ascending name order, exact total).
            let all = self.list_namespaces().await?;
            let total = all.len() as i64;
            let items = match usize::try_from(offset) {
                Ok(offset) => all
                    .into_iter()
                    .skip(offset)
                    .take(usize::try_from(limit).unwrap_or(usize::MAX))
                    .collect(),
                // A backend-safe offset can exceed `usize` on a 32-bit target;
                // that is a valid request beyond the collection — empty page.
                Err(_) => Vec::new(),
            };
            Ok(PaginatedResult { items, total })
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
            crate::config::db_backend::validate_api_spec_restore_inputs(
                bundle,
                spec,
                &[],
                &[],
                false,
            )?;
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

            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases(
                    std::iter::once(spec.namespace.as_str())
                        .chain(std::iter::once(bundle.proxy.namespace.as_str()))
                        .chain(
                            bundle
                                .plugins
                                .iter()
                                .map(|plugin| plugin.namespace.as_str()),
                        ),
                )
                .await?;
            let namespaces: HashSet<&str> = std::iter::once(spec.namespace.as_str())
                .chain(std::iter::once(bundle.proxy.namespace.as_str()))
                .chain(
                    bundle
                        .plugins
                        .iter()
                        .map(|plugin| plugin.namespace.as_str()),
                )
                .collect();
            for namespace in namespaces {
                self.validate_plugin_graph_admission_candidate(namespace, |candidate| {
                    if bundle.proxy.namespace == namespace {
                        candidate.proxies.push(bundle.proxy.clone());
                    }
                    candidate.plugin_configs.extend(
                        bundle
                            .plugins
                            .iter()
                            .filter(|plugin| plugin.namespace == namespace)
                            .cloned(),
                    );
                })
                .await?;
            }

            Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                let use_replica_set = self.replica_set_configured();
                let mut orphaned_proxy_group_plugin_deletes = Vec::new();
                if use_replica_set {
                    // With a replica set: use a multi-document transaction.
                    let connection = self.connection();
                    let mut session = connection.client.start_session().await?;
                    let prepared_docs = prepare_api_spec_bundle_docs(bundle, spec)?;
                    let mut upsert_changes: Vec<(String, &'static str, String)> = Vec::new();
                    if let Some(u) = &bundle.upstream {
                        upsert_changes.push((u.namespace.clone(), "upstream", u.id.clone()));
                    }
                    upsert_changes.push((
                        bundle.proxy.namespace.clone(),
                        "proxy",
                        bundle.proxy.id.clone(),
                    ));
                    for pc in &bundle.plugins {
                        upsert_changes.push((pc.namespace.clone(), "plugin_config", pc.id.clone()));
                    }
                    orphaned_proxy_group_plugin_deletes = session
                        .start_transaction()
                        .and_run(
                            (self, prepared_docs, upsert_changes, spec.namespace.clone()),
                            |s, (this, prepared_docs, upsert_changes, namespace)| {
                                Box::pin(async move {
                                    if let Some((_, doc)) = &prepared_docs.upstream {
                                        this.upstreams()
                                            .insert_one(doc.clone())
                                            .session(&mut *s)
                                            .await?;
                                    }
                                    this.proxies()
                                        .insert_one(prepared_docs.proxy.1.clone())
                                        .session(&mut *s)
                                        .await?;
                                    for (_, doc) in &prepared_docs.plugins {
                                        this.plugin_configs()
                                            .insert_one(doc.clone())
                                            .session(&mut *s)
                                            .await?;
                                    }
                                    this.api_specs()
                                        .insert_one(prepared_docs.spec.clone())
                                        .session(&mut *s)
                                        .await?;
                                    let orphaned = this
                                        .cleanup_orphaned_proxy_group_plugins_opt_session(
                                            namespace.as_str(),
                                            Some(&mut *s),
                                        )
                                        .await
                                        .map_err(|e| {
                                            mongodb::error::Error::custom(e.to_string())
                                        })?;
                                    for change in upsert_changes.iter() {
                                        let (namespace, resource_type, resource_id) = change;
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            resource_type,
                                            resource_id.as_str(),
                                            "upsert",
                                        )
                                        .await?;
                                    }
                                    for (plugin_id, namespace) in &orphaned {
                                        this.record_config_change_in_session(
                                            &mut *s,
                                            namespace.as_str(),
                                            "plugin_config",
                                            plugin_id.as_str(),
                                            "delete",
                                        )
                                        .await?;
                                    }
                                    Ok(orphaned)
                                })
                            },
                        )
                        .await
                        .map_err(anyhow::Error::new)
                        .context("submit_api_spec_bundle transaction failed")?;
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

                        if let Some(u) = &bundle.upstream {
                            self.record_config_change(&u.namespace, "upstream", &u.id, "upsert")
                                .await?;
                        }
                        self.record_config_change(
                            &bundle.proxy.namespace,
                            "proxy",
                            &bundle.proxy.id,
                            "upsert",
                        )
                        .await?;
                        for pc in &bundle.plugins {
                            self.record_config_change(
                                &pc.namespace,
                                "plugin_config",
                                &pc.id,
                                "upsert",
                            )
                            .await?;
                        }
                        for (plugin_id, namespace) in &orphaned_proxy_group_plugin_deletes {
                            self.record_config_change(
                                namespace,
                                "plugin_config",
                                plugin_id,
                                "delete",
                            )
                            .await?;
                        }

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
                    return Ok(());
                }

                let mut namespaces_to_compact = HashSet::new();
                if let Some(u) = &bundle.upstream {
                    namespaces_to_compact.insert(u.namespace.clone());
                }
                namespaces_to_compact.insert(bundle.proxy.namespace.clone());
                namespaces_to_compact.extend(bundle.plugins.iter().map(|pc| pc.namespace.clone()));
                namespaces_to_compact.extend(
                    orphaned_proxy_group_plugin_deletes
                        .iter()
                        .map(|(_, namespace)| namespace.clone()),
                );
                for namespace in namespaces_to_compact {
                    self.compact_config_changes_best_effort(&namespace).await;
                }

                Ok(())
            })
            .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
            Ok(())
        }

        async fn restore_api_spec_bundle(
            &self,
            bundle: &crate::admin::api_specs::ExtractedBundle,
            spec: &ApiSpec,
            additional_upstreams: &[Upstream],
            additional_plugins: &[PluginConfig],
            validation_http_client: &crate::plugins::PluginHttpClient,
        ) -> Result<(), anyhow::Error> {
            crate::config::db_backend::validate_api_spec_restore_inputs(
                bundle,
                spec,
                additional_upstreams,
                additional_plugins,
                true,
            )?;
            if !self.replica_set_configured() {
                anyhow::bail!(
                    "atomic API-spec restore requires MongoDB replica-set transactions; configure FERRUM_MONGO_REPLICA_SET"
                );
            }

            let spec_doc = api_spec_to_doc(spec)?;
            let bson_bytes = mongodb::bson::to_vec(&spec_doc)?;
            if bson_bytes.len() > 15 * 1024 * 1024 {
                anyhow::bail!(
                    "MongoDB document limit exceeded: serialized spec is {} bytes \
                     (limit ~15 MiB); use a SQL backend for large specs",
                    bson_bytes.len()
                );
            }

            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases(std::iter::once(spec.namespace.as_str()))
                .await?;
            self.validate_plugin_graph_admission_candidate(&spec.namespace, |candidate| {
                candidate.proxies.push(bundle.proxy.clone());
                candidate
                    .plugin_configs
                    .extend(bundle.plugins.iter().cloned());
                candidate
                    .plugin_configs
                    .extend(additional_plugins.iter().cloned());
            })
            .await?;

            Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let prepared_docs = prepare_api_spec_restore_docs(
                    bundle,
                    spec,
                    additional_upstreams,
                    additional_plugins,
                )?;
                let guard_params = ProxyWriteGuardParams::from_proxy(&bundle.proxy);
                let mut upsert_changes: Vec<(String, &'static str, String)> = Vec::new();
                if let Some(upstream) = &bundle.upstream {
                    upsert_changes.push((
                        upstream.namespace.clone(),
                        "upstream",
                        upstream.id.clone(),
                    ));
                }
                upsert_changes.push((
                    bundle.proxy.namespace.clone(),
                    "proxy",
                    bundle.proxy.id.clone(),
                ));
                for plugin in bundle.plugins.iter().chain(additional_plugins) {
                    upsert_changes.push((
                        plugin.namespace.clone(),
                        "plugin_config",
                        plugin.id.clone(),
                    ));
                }

                session
                    .start_transaction()
                    .and_run(
                        (
                            self,
                            connection,
                            prepared_docs,
                            guard_params,
                            upsert_changes,
                            spec.namespace.clone(),
                            bundle.proxy.id.clone(),
                            validation_http_client,
                        ),
                        |s,
                         (
                            this,
                            connection,
                            prepared_docs,
                            guard_params,
                            upsert_changes,
                            namespace,
                            restored_proxy_id,
                            validation_http_client,
                        )| {
                            Box::pin(async move {
                                if let Some((_, doc)) = &prepared_docs.upstream {
                                    this.upstreams()
                                        .insert_one(doc.clone())
                                        .session(&mut *s)
                                        .await?;
                                }
                                for (upstream_id, doc) in &prepared_docs.additional_upstreams {
                                    let upstream_namespace = doc
                                        .get_str("namespace")
                                        .map_err(|error| {
                                            mongodb::error::Error::custom(format!(
                                                "additional restore upstream {} is missing namespace: {}",
                                                upstream_id, error
                                            ))
                                        })?;
                                    let existing = this
                                        .upstreams()
                                        .find_one(mongodb::bson::doc! {
                                            "_id": upstream_id.as_str(),
                                            "namespace": upstream_namespace,
                                        })
                                        .session(&mut *s)
                                        .await?;
                                    if let Some(existing) = existing {
                                        let existing = doc_to_upstream(existing).map_err(|error| {
                                            mongodb::error::Error::custom(error.to_string())
                                        })?;
                                        let expected = doc_to_upstream(doc.clone()).map_err(
                                            |error| {
                                                mongodb::error::Error::custom(error.to_string())
                                            },
                                        )?;
                                        crate::config::db_backend::validate_api_spec_retained_upstream_identity(
                                            &expected,
                                            &existing,
                                        )
                                        .map_err(|error| {
                                            mongodb::error::Error::custom(error.to_string())
                                        })?;
                                        continue;
                                    }
                                    this.upstreams()
                                        .insert_one(doc.clone())
                                        .session(&mut *s)
                                        .await?;
                                    upsert_changes.push((
                                        upstream_namespace.to_string(),
                                        "upstream",
                                        upstream_id.clone(),
                                    ));
                                }
                                // Compensation may follow an intervening
                                // writer. Reapply the same in-session route
                                // uniqueness and upstream-reference guards as
                                // normal proxy creation before publishing the
                                // restored proxy.
                                this.ensure_proxy_admission_guards_in_session(
                                    &mut *s,
                                    guard_params,
                                    None,
                                )
                                .await?;
                                this.proxies()
                                    .insert_one(prepared_docs.proxy.1.clone())
                                    .session(&mut *s)
                                    .await?;
                                for (_, doc) in &prepared_docs.plugins {
                                    this.plugin_configs()
                                        .insert_one(doc.clone())
                                        .session(&mut *s)
                                        .await?;
                                }
                                this.api_specs()
                                    .insert_one(prepared_docs.spec.clone())
                                    .session(&mut *s)
                                    .await?;

                                validate_api_spec_restore_candidate_in_session(
                                    this,
                                    connection.as_ref(),
                                    &mut *s,
                                    namespace.as_str(),
                                    restored_proxy_id.as_str(),
                                    validation_http_client,
                                )
                                .await
                                .map_err(|error| {
                                    mongodb::error::Error::custom(error.to_string())
                                })?;

                                for (namespace, resource_type, resource_id) in upsert_changes.iter()
                                {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        resource_type,
                                        resource_id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                Ok(())
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("restore_api_spec_bundle transaction failed")?;

                self.compact_config_changes_best_effort(&spec.namespace)
                    .await;
                Ok(())
            })
            .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
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

            let mut mtls_leases = self
                .acquire_mtls_dns_admission_leases(
                    std::iter::once(spec.namespace.as_str())
                        .chain(std::iter::once(bundle.proxy.namespace.as_str()))
                        .chain(
                            bundle
                                .plugins
                                .iter()
                                .map(|plugin| plugin.namespace.as_str()),
                        ),
                )
                .await?;

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
                .map(
                    crate::admin::api_specs::declared_proxy_plugin_association_ids_from_stored_spec,
                )
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
                Self::run_mtls_dns_mutations(&mut mtls_leases, async {
                    let replace_result = self
                        .api_specs()
                        .replace_one(
                            doc! { "_id": &spec.id, "namespace": &spec.namespace },
                            spec_doc_check,
                        )
                        .await?;
                    // `replace_one` (no upsert) on the unique `{_id, namespace}`
                    // filter matches 0 or 1 doc. Zero means the spec was deleted
                    // (or the namespace predicate missed) between the hash check
                    // and this guarded write — never report that as a success.
                    if replace_result.matched_count != 1 {
                        anyhow::bail!(
                            "API spec document not found for id '{}' in namespace '{}' during \
                             metadata-only replace (matched_count={})",
                            spec.id,
                            spec.namespace,
                            replace_result.matched_count
                        );
                    }
                    Ok(())
                })
                .await?;
                Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
                return Ok(());
            }

            self.ensure_no_external_spec_upstream_refs(&spec.namespace, &spec.id, &spec.proxy_id)
                .await?;
            let old_spec_plugin_ids = self
                .load_collection_ids_filtered(
                    "plugin_configs",
                    doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace },
                )
                .await?;
            let old_spec_upstream_ids = self
                .load_collection_ids_filtered(
                    "upstreams",
                    doc! { "api_spec_id": &spec.id, "namespace": &spec.namespace },
                )
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
            let new_spec_plugin_ids: HashSet<String> = effective_bundle
                .plugins
                .iter()
                .map(|pc| pc.id.clone())
                .collect();
            let removed_replaced_plugin_config_ids: Vec<String> = old_spec_plugin_ids
                .iter()
                .filter(|id| !new_spec_plugin_ids.contains(*id))
                .cloned()
                .collect();
            let new_spec_upstream_ids: HashSet<String> = effective_bundle
                .upstream
                .iter()
                .map(|u| u.id.clone())
                .collect();
            let removed_replaced_upstream_ids: Vec<String> = old_spec_upstream_ids
                .iter()
                .filter(|id| !new_spec_upstream_ids.contains(*id))
                .cloned()
                .collect();

            let namespaces: HashSet<&str> = std::iter::once(spec.namespace.as_str())
                .chain(std::iter::once(effective_bundle.proxy.namespace.as_str()))
                .chain(
                    effective_bundle
                        .plugins
                        .iter()
                        .map(|plugin| plugin.namespace.as_str()),
                )
                .collect();
            for namespace in namespaces {
                self.validate_plugin_graph_admission_candidate(namespace, |candidate| {
                    candidate.plugin_configs.retain(|plugin| {
                        !old_spec_plugin_ids.contains(&plugin.id)
                            && !previous_declared_assoc_ids.contains(&plugin.id)
                    });
                    if effective_bundle.proxy.namespace == namespace {
                        if let Some(existing) = candidate
                            .proxies
                            .iter_mut()
                            .find(|proxy| proxy.id == effective_bundle.proxy.id)
                        {
                            *existing = effective_bundle.proxy.clone();
                        } else {
                            candidate.proxies.push(effective_bundle.proxy.clone());
                        }
                    }
                    candidate.plugin_configs.extend(
                        effective_bundle
                            .plugins
                            .iter()
                            .filter(|plugin| plugin.namespace == namespace)
                            .cloned(),
                    );
                })
                .await?;
            }

            Self::run_mtls_dns_mutations(&mut mtls_leases, async {
            let use_replica_set = self.replica_set_configured();
            let mut old_plugin_configs_deleted_for_changes = true;
            let mut old_upstreams_deleted_for_changes = true;
            let orphaned_proxy_group_plugin_deletes = if use_replica_set {
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                let prepared_docs = prepare_api_spec_bundle_docs(effective_bundle, spec)?;
                let mut upsert_changes: Vec<(String, &'static str, String)> = Vec::new();
                if let Some(u) = &effective_bundle.upstream {
                    upsert_changes.push((u.namespace.clone(), "upstream", u.id.clone()));
                }
                upsert_changes.push((
                    effective_bundle.proxy.namespace.clone(),
                    "proxy",
                    effective_bundle.proxy.id.clone(),
                ));
                for pc in &effective_bundle.plugins {
                    upsert_changes.push((pc.namespace.clone(), "plugin_config", pc.id.clone()));
                }
                session
                    .start_transaction()
                    .and_run(
                        (
                            self,
                            prepared_docs,
                            spec.namespace.clone(),
                            spec.id.clone(),
                            spec.proxy_id.clone(),
                            upsert_changes,
                            removed_replaced_plugin_config_ids.clone(),
                            removed_replaced_upstream_ids.clone(),
                        ),
                        |s,
                         (
                            this,
                            prepared_docs,
                            namespace,
                            spec_id,
                            proxy_id,
                            upsert_changes,
                            removed_plugin_ids,
                            removed_upstream_ids,
                        )| {
                            Box::pin(async move {
                                this.ensure_no_external_spec_upstream_refs_opt_session(
                                    Some(&mut *s),
                                    namespace.as_str(),
                                    spec_id.as_str(),
                                    proxy_id.as_str(),
                                )
                                .await
                                .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;

                                this.plugin_configs()
                                    .delete_many(doc! {
                                        "api_spec_id": spec_id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                this.proxies()
                                    .delete_one(doc! {
                                        "_id": proxy_id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                this.upstreams()
                                    .delete_many(doc! {
                                        "api_spec_id": spec_id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                this.api_specs()
                                    .delete_one(doc! {
                                        "_id": spec_id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;

                                if let Some((_, doc)) = &prepared_docs.upstream {
                                    this.upstreams()
                                        .insert_one(doc.clone())
                                        .session(&mut *s)
                                        .await?;
                                }
                                this.proxies()
                                    .insert_one(prepared_docs.proxy.1.clone())
                                    .session(&mut *s)
                                    .await?;
                                for (_, doc) in &prepared_docs.plugins {
                                    this.plugin_configs()
                                        .insert_one(doc.clone())
                                        .session(&mut *s)
                                        .await?;
                                }
                                this.api_specs()
                                    .insert_one(prepared_docs.spec.clone())
                                    .session(&mut *s)
                                    .await?;
                                let orphaned = this
                                    .cleanup_orphaned_proxy_group_plugins_opt_session(
                                        namespace.as_str(),
                                        Some(&mut *s),
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;

                                for change in upsert_changes.iter() {
                                    let (namespace, resource_type, resource_id) = change;
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        resource_type,
                                        resource_id.as_str(),
                                        "upsert",
                                    )
                                    .await?;
                                }
                                for plugin_id in removed_plugin_ids.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "plugin_config",
                                        plugin_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                for upstream_id in removed_upstream_ids.iter() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "upstream",
                                        upstream_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                for (plugin_id, namespace) in &orphaned {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "plugin_config",
                                        plugin_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                Ok(orphaned)
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("replace_api_spec_bundle transaction failed")?
            } else {
                // No replica set: best-effort delete then re-insert with
                // compensating rollback on re-insert failure.
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
                    return Err(anyhow::Error::new(e).context(format!(
                        "replace_api_spec_bundle: failed to delete proxy {} for spec {} before dependency cleanup",
                        spec.proxy_id, spec.id
                    )));
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
                    old_plugin_configs_deleted_for_changes = false;
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
                    old_upstreams_deleted_for_changes = false;
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
                self.cleanup_orphaned_proxy_group_plugins(&spec.namespace)
                    .await?
            };

            if use_replica_set {
                let mut namespaces_to_compact = HashSet::new();
                if let Some(u) = &effective_bundle.upstream {
                    namespaces_to_compact.insert(u.namespace.clone());
                }
                namespaces_to_compact.insert(effective_bundle.proxy.namespace.clone());
                namespaces_to_compact.extend(
                    effective_bundle
                        .plugins
                        .iter()
                        .map(|pc| pc.namespace.clone()),
                );
                if !removed_replaced_plugin_config_ids.is_empty()
                    || !removed_replaced_upstream_ids.is_empty()
                {
                    namespaces_to_compact.insert(spec.namespace.clone());
                }
                namespaces_to_compact.extend(
                    orphaned_proxy_group_plugin_deletes
                        .iter()
                        .map(|(_, namespace)| namespace.clone()),
                );
                for namespace in namespaces_to_compact {
                    self.compact_config_changes_best_effort(&namespace).await;
                }
                return Ok(());
            }

            if let Some(u) = &effective_bundle.upstream {
                self.record_config_change(&u.namespace, "upstream", &u.id, "upsert")
                    .await?;
            }
            self.record_config_change(
                &effective_bundle.proxy.namespace,
                "proxy",
                &effective_bundle.proxy.id,
                "upsert",
            )
            .await?;
            for pc in &effective_bundle.plugins {
                self.record_config_change(&pc.namespace, "plugin_config", &pc.id, "upsert")
                    .await?;
            }
            if old_plugin_configs_deleted_for_changes {
                for plugin_id in removed_replaced_plugin_config_ids {
                    self.record_config_change(
                        &spec.namespace,
                        "plugin_config",
                        &plugin_id,
                        "delete",
                    )
                    .await?;
                }
            }
            if old_upstreams_deleted_for_changes {
                for upstream_id in removed_replaced_upstream_ids {
                    self.record_config_change(&spec.namespace, "upstream", &upstream_id, "delete")
                        .await?;
                }
            }
            for (plugin_id, namespace) in orphaned_proxy_group_plugin_deletes {
                self.record_config_change(&namespace, "plugin_config", &plugin_id, "delete")
                    .await?;
            }

            Ok(())
                })
                .await?;
            Self::release_mtls_dns_admission_leases(&mut mtls_leases).await?;
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
            let api_specs = self.api_specs();
            let mut cursor = api_specs.find(filter_doc).with_options(options).await?;

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

        async fn count_api_specs(&self, namespace: &str) -> Result<u64, anyhow::Error> {
            let start = std::time::Instant::now();
            // MongoStore forces primary reads, so this count is authoritative.
            // count_documents does not fetch or deserialize matching items.
            let count = self
                .api_specs()
                .count_documents(doc! { "namespace": namespace })
                .await?;
            self.check_slow_query("count_api_specs", start);
            Ok(count)
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
            let plugin_configs = self.plugin_configs();
            let mut cursor = plugin_configs
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
            let upstreams = self.upstreams();
            let mut cursor = upstreams
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
            let mut mtls_lease = self.acquire_mtls_dns_admission_lease(namespace).await?;

            // Check existence first (namespace-scoped).
            let existing = self
                .api_specs()
                .find_one(doc! { "_id": id, "namespace": namespace })
                .await?;

            if existing.is_none() {
                mtls_lease.release().await?;
                self.check_slow_query("delete_api_spec", start);
                return Ok(false);
            }

            // Determine the proxy_id before deleting.
            let proxy_id: Option<String> = existing
                .as_ref()
                .and_then(|d| d.get_str("proxy_id").ok())
                .map(str::to_string);
            self.validate_plugin_graph_repair_delete_candidate(namespace, |candidate| {
                if let Some(proxy_id) = proxy_id.as_deref() {
                    candidate.proxies.retain(|proxy| proxy.id != proxy_id);
                    candidate
                        .plugin_configs
                        .retain(|plugin| plugin.proxy_id.as_deref() != Some(proxy_id));
                }
            })
            .await?;

            let use_replica_set = self.replica_set_configured();
            let (
                spec_plugin_config_ids,
                proxy_plugin_config_ids,
                mut deleted_upstream_ids,
                mut deleted_plugin_config_ids_for_changes,
            ) = if use_replica_set {
                (
                    HashSet::new(),
                    HashSet::new(),
                    HashSet::new(),
                    HashSet::new(),
                )
            } else {
                let spec_plugin_config_ids = self
                    .load_collection_ids_filtered(
                        "plugin_configs",
                        doc! { "api_spec_id": id, "namespace": namespace },
                    )
                    .await?;
                let mut deleted_plugin_config_ids = spec_plugin_config_ids.clone();
                let mut proxy_plugin_config_ids = HashSet::new();
                if let Some(ref pid) = proxy_id {
                    proxy_plugin_config_ids = self
                        .load_collection_ids_filtered(
                            "plugin_configs",
                            doc! { "proxy_id": pid, "namespace": namespace },
                        )
                        .await?;
                    for plugin_id in &proxy_plugin_config_ids {
                        if !deleted_plugin_config_ids.contains(plugin_id) {
                            deleted_plugin_config_ids.insert(plugin_id.clone());
                        }
                    }
                }
                let deleted_upstream_ids = self
                    .load_collection_ids_filtered(
                        "upstreams",
                        doc! { "api_spec_id": id, "namespace": namespace },
                    )
                    .await?;

                self.ensure_no_external_spec_upstream_refs(
                    namespace,
                    id,
                    proxy_id.as_deref().unwrap_or(""),
                )
                .await?;
                (
                    spec_plugin_config_ids,
                    proxy_plugin_config_ids,
                    deleted_upstream_ids,
                    HashSet::new(),
                )
            };
            let mut orphaned_proxy_group_plugin_deletes = Vec::new();
            let deleted = mtls_lease
                .run_mutation(async {
            if use_replica_set {
                // With a replica set: use a multi-document transaction so that a
                // partial failure does not leave orphaned proxy/upstream/plugin rows.
                // Mirrors `submit_api_spec_bundle` and `replace_api_spec_bundle`.
                let connection = self.connection();
                let mut session = connection.client.start_session().await?;
                orphaned_proxy_group_plugin_deletes = session
                    .start_transaction()
                    .and_run(
                        (
                            self,
                            namespace.to_string(),
                            id.to_string(),
                            proxy_id.clone(),
                        ),
                        |s, (this, namespace, id, proxy_id)| {
                            Box::pin(async move {
                                this.ensure_no_external_spec_upstream_refs_opt_session(
                                    Some(&mut *s),
                                    namespace.as_str(),
                                    id.as_str(),
                                    proxy_id.as_deref().unwrap_or(""),
                                )
                                .await
                                .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;

                                let spec_plugin_config_ids = this
                                    .load_collection_ids_filtered_in_session(
                                        &mut *s,
                                        "plugin_configs",
                                        doc! {
                                            "api_spec_id": id.as_str(),
                                            "namespace": namespace.as_str(),
                                        },
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                                let mut deleted_plugin_config_ids = spec_plugin_config_ids.clone();
                                if let Some(pid) = proxy_id.as_deref() {
                                    let proxy_plugin_config_ids = this
                                        .load_collection_ids_filtered_in_session(
                                            &mut *s,
                                            "plugin_configs",
                                            doc! {
                                                "proxy_id": pid,
                                                "namespace": namespace.as_str(),
                                            },
                                        )
                                        .await
                                        .map_err(|e| {
                                            mongodb::error::Error::custom(e.to_string())
                                        })?;
                                    for plugin_id in &proxy_plugin_config_ids {
                                        if !deleted_plugin_config_ids.contains(plugin_id) {
                                            deleted_plugin_config_ids.insert(plugin_id.clone());
                                        }
                                    }
                                }
                                let deleted_upstream_ids = this
                                    .load_collection_ids_filtered_in_session(
                                        &mut *s,
                                        "upstreams",
                                        doc! {
                                            "api_spec_id": id.as_str(),
                                            "namespace": namespace.as_str(),
                                        },
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;

                                this.plugin_configs()
                                    .delete_many(doc! {
                                        "api_spec_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                if let Some(pid) = proxy_id.as_deref() {
                                    this.plugin_configs()
                                        .delete_many(doc! {
                                            "proxy_id": pid,
                                            "namespace": namespace.as_str(),
                                        })
                                        .session(&mut *s)
                                        .await?;
                                    this.proxies()
                                        .delete_one(doc! {
                                            "_id": pid,
                                            "namespace": namespace.as_str(),
                                        })
                                        .session(&mut *s)
                                        .await?;
                                }
                                let orphaned = this
                                    .cleanup_orphaned_proxy_group_plugins_opt_session(
                                        namespace.as_str(),
                                        Some(&mut *s),
                                    )
                                    .await
                                    .map_err(|e| mongodb::error::Error::custom(e.to_string()))?;
                                this.upstreams()
                                    .delete_many(doc! {
                                        "api_spec_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;
                                this.api_specs()
                                    .delete_one(doc! {
                                        "_id": id.as_str(),
                                        "namespace": namespace.as_str(),
                                    })
                                    .session(&mut *s)
                                    .await?;

                                if let Some(pid) = proxy_id.as_deref() {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "proxy",
                                        pid,
                                        "delete",
                                    )
                                    .await?;
                                }
                                for plugin_id in &deleted_plugin_config_ids {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "plugin_config",
                                        plugin_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                for upstream_id in &deleted_upstream_ids {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        namespace.as_str(),
                                        "upstream",
                                        upstream_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                for (plugin_id, plugin_namespace) in &orphaned {
                                    this.record_config_change_in_session(
                                        &mut *s,
                                        plugin_namespace.as_str(),
                                        "plugin_config",
                                        plugin_id.as_str(),
                                        "delete",
                                    )
                                    .await?;
                                }
                                Ok(orphaned)
                            })
                        },
                    )
                    .await
                    .map_err(anyhow::Error::new)
                    .context("delete_api_spec transaction failed")?;
                self.compact_config_changes_best_effort(namespace).await;
                for (_, plugin_namespace) in &orphaned_proxy_group_plugin_deletes {
                    if plugin_namespace.as_str() != namespace {
                        self.compact_config_changes_best_effort(plugin_namespace)
                            .await;
                    }
                }
                return Ok(true);
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
                        .map_err(anyhow::Error::new)
                        .with_context(|| {
                            format!(
                                "delete_api_spec: failed to delete proxy {} for spec {} before dependency cleanup",
                                pid, id
                            )
                        })?;
                }
                match self
                    .plugin_configs()
                    .delete_many(doc! { "api_spec_id": id, "namespace": namespace })
                    .await
                {
                    Ok(_) => {
                        deleted_plugin_config_ids_for_changes
                            .extend(spec_plugin_config_ids.iter().cloned());
                    }
                    Err(e) => {
                        warn!(
                            "delete_api_spec: failed to delete spec-owned plugin_configs for \
                             spec {}: {}",
                            id, e
                        );
                    }
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
                    } else {
                        deleted_plugin_config_ids_for_changes
                            .extend(proxy_plugin_config_ids.iter().cloned());
                    }
                }
                match self.cleanup_orphaned_proxy_group_plugins(namespace).await {
                    Ok(deleted) => orphaned_proxy_group_plugin_deletes = deleted,
                    Err(e) => {
                        warn!(
                            "delete_api_spec: failed to cleanup orphaned proxy_group plugins \
                             after deleting spec {}: {}",
                            id, e
                        );
                    }
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
                    deleted_upstream_ids.clear();
                }
                // The spec row deletion is the one we must succeed on — if this fails
                // the spec appears to still exist, which is worse than an orphan.
                self.api_specs()
                    .delete_one(doc! { "_id": id, "namespace": namespace })
                    .await?;
            }

            if let Some(ref pid) = proxy_id {
                self.record_config_change(namespace, "proxy", pid, "delete")
                    .await?;
            }
            for plugin_id in deleted_plugin_config_ids_for_changes {
                self.record_config_change(namespace, "plugin_config", &plugin_id, "delete")
                    .await?;
            }
            for upstream_id in deleted_upstream_ids {
                self.record_config_change(namespace, "upstream", &upstream_id, "delete")
                    .await?;
            }
            for (plugin_id, plugin_namespace) in orphaned_proxy_group_plugin_deletes {
                self.record_config_change(&plugin_namespace, "plugin_config", &plugin_id, "delete")
                    .await?;
            }

            Ok(true)
                })
                .await?;
            mtls_lease.release().await?;
            self.check_slow_query("delete_api_spec", start);
            Ok(deleted)
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
            let audit_events = self.audit_events();
            let mut cursor = audit_events.find(filter_doc).with_options(options).await?;
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
        async fn load_full_proxies_opt_session(
            &self,
            namespace: &str,
            session: Option<(&MongoConnectionBundle, &mut ClientSession)>,
            snapshot: bool,
        ) -> Result<Vec<Proxy>, anyhow::Error> {
            let filter = doc! { "namespace": namespace };
            let mut proxies = Vec::new();

            if let Some((connection, s)) = session {
                let proxies_collection: Collection<Document> = connection.db.collection("proxies");
                let mut cursor = proxies_collection.find(filter).session(&mut *s).await?;
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "proxy", None, error)
                    })?;
                    let mut proxy = decode_loaded_document(doc, snapshot, "proxy", doc_to_proxy)?;
                    proxy.api_spec_id = None;
                    proxies.push(proxy);
                }
            } else {
                let proxies_collection = self.proxies();
                let mut cursor = proxies_collection.find(filter).await?;
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "proxy", None, error)
                    })?;
                    let mut proxy = decode_loaded_document(doc, snapshot, "proxy", doc_to_proxy)?;
                    proxy.api_spec_id = None;
                    proxies.push(proxy);
                }
            }

            Ok(proxies)
        }

        async fn load_full_consumers_opt_session(
            &self,
            namespace: &str,
            session: Option<(&MongoConnectionBundle, &mut ClientSession)>,
            snapshot: bool,
        ) -> Result<Vec<Consumer>, anyhow::Error> {
            let filter = doc! { "namespace": namespace };
            let mut consumers = Vec::new();

            if let Some((connection, s)) = session {
                let consumers_collection: Collection<Document> =
                    connection.db.collection("consumers");
                let mut cursor = consumers_collection
                    .find(filter)
                    .sort(doc! { "id": 1 })
                    .session(&mut *s)
                    .await?;
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "consumer", None, error)
                    })?;
                    consumers.push(decode_loaded_document(
                        doc,
                        snapshot,
                        "consumer",
                        doc_to_consumer,
                    )?);
                }
            } else {
                let consumers_collection = self.consumers();
                let mut cursor = consumers_collection
                    .find(filter)
                    .sort(doc! { "id": 1 })
                    .await?;
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "consumer", None, error)
                    })?;
                    consumers.push(decode_loaded_document(
                        doc,
                        snapshot,
                        "consumer",
                        doc_to_consumer,
                    )?);
                }
            }

            Ok(consumers)
        }

        async fn load_full_plugin_configs_opt_session(
            &self,
            namespace: &str,
            session: Option<(&MongoConnectionBundle, &mut ClientSession)>,
            snapshot: bool,
        ) -> Result<Vec<PluginConfig>, anyhow::Error> {
            let filter = doc! { "namespace": namespace };
            let mut plugin_configs = Vec::new();

            if let Some((connection, s)) = session {
                let plugin_configs_collection: Collection<Document> =
                    connection.db.collection("plugin_configs");
                let mut cursor = plugin_configs_collection
                    .find(filter)
                    .session(&mut *s)
                    .await?;
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "plugin_config", None, error)
                    })?;
                    let mut plugin_config = decode_loaded_document(
                        doc,
                        snapshot,
                        "plugin_config",
                        doc_to_plugin_config,
                    )?;
                    plugin_config.api_spec_id = None;
                    plugin_configs.push(plugin_config);
                }
            } else {
                let plugin_configs_collection = self.plugin_configs();
                let mut cursor = plugin_configs_collection.find(filter).await?;
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "plugin_config", None, error)
                    })?;
                    let mut plugin_config = decode_loaded_document(
                        doc,
                        snapshot,
                        "plugin_config",
                        doc_to_plugin_config,
                    )?;
                    plugin_config.api_spec_id = None;
                    plugin_configs.push(plugin_config);
                }
            }

            Ok(plugin_configs)
        }

        async fn load_full_upstreams_opt_session(
            &self,
            namespace: &str,
            session: Option<(&MongoConnectionBundle, &mut ClientSession)>,
            snapshot: bool,
        ) -> Result<Vec<Upstream>, anyhow::Error> {
            let filter = doc! { "namespace": namespace };
            let mut upstreams = Vec::new();

            if let Some((connection, s)) = session {
                let upstreams_collection: Collection<Document> =
                    connection.db.collection("upstreams");
                let mut cursor = upstreams_collection.find(filter).session(&mut *s).await?;
                while cursor.advance(&mut *s).await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "upstream", None, error)
                    })?;
                    let mut upstream =
                        decode_loaded_document(doc, snapshot, "upstream", doc_to_upstream)?;
                    upstream.api_spec_id = None;
                    upstreams.push(upstream);
                }
            } else {
                let upstreams_collection = self.upstreams();
                let mut cursor = upstreams_collection.find(filter).await?;
                while cursor.advance().await? {
                    let doc = cursor.deserialize_current().map_err(|error| {
                        map_snapshot_document_error(snapshot, "upstream", None, error)
                    })?;
                    let mut upstream =
                        decode_loaded_document(doc, snapshot, "upstream", doc_to_upstream)?;
                    upstream.api_spec_id = None;
                    upstreams.push(upstream);
                }
            }

            Ok(upstreams)
        }

        /// Load all `_id` values from a collection for cold-path bulk operations.
        #[allow(dead_code)]
        async fn load_collection_ids(
            &self,
            collection_name: &str,
        ) -> Result<HashSet<String>, anyhow::Error> {
            self.load_collection_ids_filtered(collection_name, doc! {})
                .await
        }

        /// Load `_id` values from a collection matching a cold-path filter.
        async fn load_collection_ids_filtered(
            &self,
            collection_name: &str,
            filter: Document,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let collection = self.collection(collection_name);
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

        async fn load_collection_ids_filtered_in_session(
            &self,
            session: &mut ClientSession,
            collection_name: &str,
            filter: Document,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let collection = self.collection(collection_name);
            let mut cursor = collection
                .find(filter)
                .projection(doc! { "_id": 1 })
                .session(&mut *session)
                .await?;
            let mut ids = HashSet::new();
            while cursor.advance(&mut *session).await? {
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
            let collection = self.collection(collection_name);
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
        /// Detection reads the effective `ClientOptions::repl_set_name`, which
        /// `ClientOptions::parse` populates from a URI `?replicaSet=...` option
        /// as well as from the `FERRUM_MONGO_REPLICA_SET` env var (applied as
        /// an override at `build_connection_bundle`). A user pointing at an
        /// actual replica set with `?replicaSet=rs0` in the URI is therefore
        /// recognized even without setting the env var, so transactions are
        /// not silently downgraded to the compensating-delete path.
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
            collection: MongoCollectionHandle,
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

    #[cfg(test)]
    mod tests {
        use super::*;

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
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
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
            // Consumer `_id` is the composite "{namespace}:{id}" so consumer
            // ids are unique per namespace (issue #2121).
            assert_eq!(
                doc.get_str("_id").unwrap(),
                format!("{}:consumer-1", crate::config::types::default_namespace())
            );

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
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
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
                    && source
                        .contains(r#".keys(doc! { "namespace": 1, HMAC_SECRET_HASHES_FIELD: 1 })"#)
                    && source.contains(".unique(true)"),
                "MongoDB must enforce keyauth, mTLS, and HMAC credential uniqueness with indexes"
            );
            assert!(
                !source.contains("drop_index(\"namespace_1_credentials.mtls_auth.identity_1\")"),
                "mTLS index setup must never drop the exact-match uniqueness backstop"
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
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
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
        fn consumer_to_doc_projects_deduplicated_hmac_hashes_and_round_trips() {
            let secret = "mongo-index-hmac-secret-at-least-32-characters";
            let mut credentials = std::collections::HashMap::new();
            credentials.insert(
                "hmac_auth".to_string(),
                serde_json::json!([{"secret": secret}, {"secret": secret}]),
            );
            let consumer = Consumer {
                id: "hmac-consumer".to_string(),
                namespace: "tenant-a".to_string(),
                username: "alice".to_string(),
                custom_id: None,
                credentials,
                acl_groups: vec![],
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            let doc = consumer_to_doc(&consumer).unwrap();
            let hashes = doc.get_array(HMAC_SECRET_HASHES_FIELD).unwrap();
            assert_eq!(hashes.len(), 1);
            assert_eq!(
                hashes[0].as_str(),
                Some(credential_value_hash(secret).as_str())
            );
            assert_ne!(hashes[0].as_str(), Some(secret));

            let restored = doc_to_consumer(doc).unwrap();
            assert_eq!(restored.credentials, consumer.credentials);
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
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
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
        // We build a `MongoStore` whose connection bundle points at a `Client`
        // constructed against a non-routable URL. `Client::with_options` does
        // NOT connect (the driver is lazy — the first command triggers the
        // real handshake), so this works without a live MongoDB.
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
                server_selection_timeout_secs: Some(1),
                connect_timeout_secs: Some(1),
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
            let client = mongodb::Client::with_options(opts.clone())
                .expect("Client::with_options should accept empty hosts");
            let lease_client = mongodb::Client::with_options(opts)
                .expect("lease Client::with_options should accept empty hosts");
            let db = client.database(&settings.database_name);
            let connection = MongoConnectionBundle::new(client, db, lease_client, Vec::new());
            MongoStore {
                connection: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(connection)),
                connection_generation: std::sync::Arc::new(tokio::sync::RwLock::new(())),
                persistent_admission_pins: std::sync::Arc::new(DashMap::new()),
                retained_admission_pins: std::sync::Arc::new(DashMap::new()),
                conn_settings: settings,
                db_type_str: "mongodb".to_string(),
                slow_query_threshold_ms: None,
                cert_expiry_warning_days: 30,
                backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
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
            // subsequent ping inside `build_connection_bundle` fails fast
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

        /// White-box check that successful `reconnect()` replaces the bundle,
        /// but cannot do so while admission pins the current generation.
        ///
        /// We can't run a real reconnect without a live MongoDB, so this
        /// test simulates a successful rebuild through the same install helper
        /// as `reconnect()`. This pins the security boundary as well as the
        /// accessor: validation and mutation must not straddle generations.
        #[tokio::test(flavor = "current_thread")]
        async fn admission_pin_blocks_swap_then_accessor_reflects_new_bundle() {
            let store = make_test_store(vec![]);

            let connection_bundle = |database_name: &str| {
                let opts = mongodb::options::ClientOptions::builder()
                    .hosts(vec![])
                    .build();
                let client = mongodb::Client::with_options(opts.clone()).unwrap();
                let lease_client = mongodb::Client::with_options(opts).unwrap();
                let db = client.database(database_name);
                MongoConnectionBundle::new(client, db, lease_client, Vec::new())
            };

            // Confirm the accessor sees the original namespace before the swap.
            assert_eq!(store.db().name(), "test");

            let admission_pin = store.connection_generation.clone().read_owned().await;
            let blocked = store
                .install_reconnected_bundle(connection_bundle("blocked_failover"), false)
                .expect_err("an admission pin must block reconnect/failover bundle replacement");
            assert!(blocked.to_string().contains("admission operation pins"));
            assert_eq!(store.db().name(), "test");
            drop(admission_pin);

            store
                .install_reconnected_bundle(connection_bundle("after_failover"), false)
                .expect("the bundle may swap after the admission generation pin is released");

            let guard_owner = "settled-owner".to_string();
            let generation_guard = store.connection_generation.clone().read_owned().await;
            let _ = store.persistent_admission_pins.insert(
                guard_owner.clone(),
                MongoPersistentAdmissionPin {
                    namespace: "ferrum".to_string(),
                    pin: MongoAdmissionConnectionPin {
                        connection: store.connection(),
                        _generation_guard: generation_guard,
                    },
                    uncertain_outcome: Arc::new(AtomicBool::new(false)),
                },
            );
            store
                .install_reconnected_bundle(connection_bundle("still_blocked"), false)
                .expect_err("a persistent admission pin must block bundle replacement");
            let _ = store.persistent_admission_pins.remove(&guard_owner);
            store
                .install_reconnected_bundle(connection_bundle("recovered_failover"), false)
                .expect("settled cleanup failure must release the local generation pin");

            // Accessor must now return the swapped handle. If it kept a
            // captured copy of the original `db` field (the pre-fix bug),
            // this assertion fails.
            assert_eq!(
                store.db().name(),
                "recovered_failover",
                "db() must reflect the swapped handle — collection accessors \
                 (proxies/consumers/plugin_configs/upstreams) all flow through \
                 db(), so a stale handle would mean every read still goes to \
                 the dead primary even after a successful reconnect"
            );
        }

        const TEST_CERT_PEM: &str =
            "-----BEGIN CERTIFICATE-----\nZmVycnVtLXRlc3QtY2VydA==\n-----END CERTIFICATE-----\n";
        const TEST_KEY_PEM: &str =
            "-----BEGIN PRIVATE KEY-----\nZmVycnVtLXRlc3Qta2V5\n-----END PRIVATE KEY-----\n";

        #[test]
        fn materialized_inline_tls_source_is_removed_when_guard_drops() {
            let materialized = MongoStore::materialize_tls_source_to_file(
                TEST_CERT_PEM,
                MaterialKind::Cert,
                "ferrum-mongo-test-cert-",
            )
            .expect("materialize inline cert");
            let path = materialized.path.clone();

            assert!(path.exists(), "owned temp cert should exist while guarded");
            assert!(
                materialized.temp_path.is_some(),
                "inline PEM materialization must own a temp guard"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path)
                    .expect("temp cert metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "temporary PEM permissions must be 0600");
            }

            drop(materialized);

            assert!(
                !path.exists(),
                "owned temp cert should be removed when the guard drops"
            );
        }

        #[test]
        fn path_tls_source_is_not_deleted_by_materialization_drop() {
            let mut source_file = tempfile::NamedTempFile::new().expect("source temp file");
            source_file
                .write_all(TEST_CERT_PEM.as_bytes())
                .expect("write source cert");
            let source_path = source_file.path().to_path_buf();
            let source_value = source_path.display().to_string();

            let materialized = MongoStore::materialize_tls_source_to_file(
                &source_value,
                MaterialKind::Cert,
                "ferrum-mongo-test-cert-",
            )
            .expect("materialize path cert");

            assert_eq!(materialized.path, source_path);
            assert!(
                materialized.temp_path.is_none(),
                "ordinary file paths are operator-owned, not generated temps"
            );
            drop(materialized);

            assert!(
                source_path.exists(),
                "operator-provided cert path must not be deleted"
            );
        }

        #[test]
        fn combined_client_pem_is_removed_when_guard_drops() {
            let materialized = MongoStore::combine_cert_key_pem(TEST_CERT_PEM, TEST_KEY_PEM)
                .expect("combine cert and key");
            let path = materialized.path.clone();
            let combined = std::fs::read_to_string(&path).expect("combined PEM content");

            assert!(combined.contains("BEGIN CERTIFICATE"));
            assert!(combined.contains("BEGIN PRIVATE KEY"));
            assert!(
                materialized.temp_path.is_some(),
                "combined client PEM must be guard-owned"
            );

            drop(materialized);

            assert!(
                !path.exists(),
                "combined client PEM should be removed when the guard drops"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn swapped_connection_keeps_old_temp_until_cursor_scope_guard_drops() {
            let materialized = MongoStore::materialize_tls_source_to_file(
                TEST_CERT_PEM,
                MaterialKind::Cert,
                "ferrum-mongo-test-held-",
            )
            .expect("materialize held temp");
            let MaterializedTlsPath { path, temp_path } = materialized;
            let temp_path = temp_path.expect("generated temp guard");

            let store = make_test_store(vec![]);
            let old_opts = mongodb::options::ClientOptions::builder()
                .hosts(vec![])
                .build();
            let old_client = mongodb::Client::with_options(old_opts.clone()).expect("old client");
            let old_lease_client =
                mongodb::Client::with_options(old_opts).expect("old lease client");
            let old_db = old_client.database("old_with_temp");
            store
                .connection
                .store(std::sync::Arc::new(MongoConnectionBundle::new(
                    old_client,
                    old_db,
                    old_lease_client,
                    vec![temp_path],
                )));

            let old_cursor_collection_guard = store.proxies();
            let new_opts = mongodb::options::ClientOptions::builder()
                .hosts(vec![])
                .build();
            let new_client = mongodb::Client::with_options(new_opts.clone()).expect("new client");
            let new_lease_client =
                mongodb::Client::with_options(new_opts).expect("new lease client");
            let new_db = new_client.database("new_without_temp");
            store
                .connection
                .store(std::sync::Arc::new(MongoConnectionBundle::new(
                    new_client,
                    new_db,
                    new_lease_client,
                    Vec::new(),
                )));

            assert!(
                path.exists(),
                "old temp PEM must remain while a cursor's collection guard holds the bundle"
            );
            drop(old_cursor_collection_guard);
            assert!(
                !path.exists(),
                "old temp PEM should be removed after the final old bundle handle drops"
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

        #[test]
        fn standalone_route_update_yields_to_any_conflicting_owner() {
            let candidates = vec![
                RouteBucketCandidate {
                    id: "existing-update".to_string(),
                    hosts: vec!["example.com".to_string()],
                    created_at: "2025-01-01T00:00:00Z".to_string(),
                },
                RouteBucketCandidate {
                    id: "concurrent-create".to_string(),
                    hosts: vec!["example.com".to_string()],
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                },
            ];

            assert!(MongoStore::standalone_route_update_has_conflict(
                "existing-update",
                &["example.com".to_string()],
                &candidates,
            ));
            assert!(
                !MongoStore::standalone_route_writer_should_yield(
                    "existing-update",
                    &["example.com".to_string()],
                    &candidates,
                ),
                "the update regression must not reuse create-vs-create created_at ordering",
            );
        }

        #[test]
        fn unknown_ordered_identity_insert_state_has_no_cleanup_prefix() {
            let error = mongodb::error::Error::custom("unknown insert state");
            assert_eq!(
                MongoStore::ordered_insert_inserted_prefix_len(&error),
                None,
                "non-InsertMany failures must retain reservations whose ownership is unknown",
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
                .find(".delete_one(doc! { \"_id\": id, \"namespace\": namespace })")
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
                .find("// No replica set: best-effort delete then re-insert")
                .expect("standalone replace_api_spec preflight marker");
            let standalone_path = &source[standalone_start..];
            let prepare = standalone_path
                .find("let prepared_docs = prepare_api_spec_bundle_docs")
                .expect("standalone replace must build replacement docs before delete");
            let preflight = standalone_path
                .find("ensure_api_spec_standalone_replace_ids_available")
                .expect("standalone replace must preflight replacement ids before delete");
            let proxy_delete = standalone_path
                .find(".proxies()\n                    .delete_one")
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
        fn unordered_insert_rollback_skips_failed_write_indices() {
            let resource_ids = vec!["proxy-a", "proxy-b", "proxy-c", "proxy-d"];
            let failed_indices = HashSet::from([1_usize, 3_usize]);

            assert_eq!(
                MongoStore::resource_ids_without_failed_insert_indices(
                    &resource_ids,
                    &failed_indices
                ),
                vec!["proxy-a", "proxy-c"],
                "unordered batch rollback must target only successful inserts"
            );
        }

        #[test]
        fn delete_proxy_guards_external_spec_upstream_refs_before_spec_upstream_delete() {
            let source = include_str!("mongo_store.rs");
            let delete_proxy_start = source
                .find("async fn delete_proxy(&self, namespace: &str, id: &str)")
                .expect("delete_proxy function");
            let delete_proxy_body = &source[delete_proxy_start..];
            let non_replica_start = delete_proxy_body
                .find("// Non-replica-set best-effort path.")
                .expect("delete_proxy non-replica path marker");
            let non_replica_path = &delete_proxy_body[non_replica_start..];
            let guard = non_replica_path
                .find("ensure_no_external_spec_upstream_refs(namespace, sid, id)")
                .expect("delete_proxy guard call");
            let upstream_delete = non_replica_path
                .find(".delete_many(doc! { \"api_spec_id\": sid, \"namespace\": namespace })")
                .expect("delete_proxy spec-owned upstream delete");
            assert!(
                guard < upstream_delete,
                "delete_proxy must guard external references before deleting \
                 upstreams tagged with the spec id"
            );
        }

        #[test]
        fn delete_upstream_standalone_checks_namespaced_target_before_references() {
            let source = include_str!("mongo_store.rs");
            let delete_start = source
                .find("async fn delete_upstream(&self, namespace: &str, id: &str)")
                .expect("delete_upstream function");
            let delete_body = &source[delete_start..];
            let standalone_start = delete_body
                .find("// Standalone pre-checks (best-effort, no transaction).")
                .expect("delete_upstream standalone marker");
            let standalone_path = &delete_body[standalone_start..];
            let target_lookup = standalone_path
                .find(".find_one(doc! { \"_id\": id, \"namespace\": namespace })")
                .expect("namespace-scoped upstream existence lookup");
            let proxy_refs = standalone_path
                .find(".count_documents(doc! { \"upstream_id\": id })")
                .expect("proxy reference check");
            let plugin_refs = standalone_path
                .find(".find_mesh_route_dispatch_upstream_ref_opt_session(None, id)")
                .expect("plugin reference check");

            assert!(
                target_lookup < proxy_refs && target_lookup < plugin_refs,
                "standalone delete_upstream must establish target existence in the requested \
                 namespace before scanning references"
            );
        }

        #[test]
        fn load_full_config_rejects_after_normalization_and_identity_quarantine() {
            let source = include_str!("mongo_store.rs");
            let load_start = source
                .find("async fn load_full_config_for_purpose(")
                .expect("Mongo purpose-aware full-config load function");
            let load_path = &source[load_start..];
            let snapshot_start = load_path
                .find("async fn load_namespace_snapshot(")
                .expect("load_namespace_snapshot following load_full_config");
            let load_body = &load_path[..snapshot_start];

            let normalize = load_body
                .find("config.normalize_fields();")
                .expect("load_full_config normalization");
            let quarantine = load_body
                .find("config.quarantine_colliding_consumer_identities()")
                .expect("load_full_config identity quarantine");
            let rejecting_validation = load_body
                .find("collect_rejecting_runtime_config_errors(&config)")
                .expect("load_full_config shared rejecting validation");
            let non_empty_guard = load_body
                .find("if !validation_errors.is_empty() {")
                .expect("load_full_config non-empty validation guard");
            let plugin_file_dependencies = load_body
                .find("validate_plugin_file_dependencies_off_thread(")
                .expect("load_full_config database-mode plugin file dependency validation");
            let runtime_file_guard = load_body
                .find("if purpose.loads_node_local_plugin_files() {")
                .expect("node-local plugin files must be gated by full-load purpose");
            let success = load_body
                .find("Ok(config)")
                .expect("load_full_config success return");

            // Brace-match the guard's block so the bail assertion is scoped
            // to it: a later unrelated bail must not satisfy this test if the
            // guard itself regresses to log-only. Format-string braces ({})
            // are balanced, so they do not skew the depth count.
            let mut depth = 0usize;
            let mut guard_end = None;
            for (offset, ch) in load_body[non_empty_guard..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            guard_end = Some(non_empty_guard + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let guard_block =
                &load_body[non_empty_guard..guard_end.expect("validation guard block must close")];

            assert!(
                normalize < quarantine && quarantine < rejecting_validation,
                "load_full_config must run shared rejecting validation after normalization and \
                 consumer identity quarantine"
            );
            assert!(
                rejecting_validation < non_empty_guard
                    && non_empty_guard < runtime_file_guard
                    && runtime_file_guard < plugin_file_dependencies
                    && plugin_file_dependencies < success,
                "the rejecting validation guard must sit between the shared validation call and \
                 runtime-only plugin file dependency generation, which must commit before the \
                 Ok(config) success return"
            );
            // The guard must fail closed by RETURNING a typed
            // `ConfigValidationRejection` (issue #2158) rather than merely
            // logging — a bare `anyhow::bail!` would be indistinguishable from
            // a connectivity failure to the database-mode poll loop.
            assert!(
                guard_block.contains("return Err(")
                    && guard_block.contains("ConfigValidationRejection")
                    && guard_block.contains("backend: \"MongoDB\"")
                    && guard_block.contains(".into_anyhow()"),
                "the non-empty rejecting validation guard itself must return a typed \
                 MongoDB ConfigValidationRejection, not merely log"
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
// Narrow crate-internal test seams (exposed only through `_test_support`): the
// timeout-precedence application and the identity reservation rollback/release
// accounting. Everything else stays module-private in `inner`.
#[allow(unused_imports)] // The binary target has no `_test_support` consumer.
pub(crate) use inner::{
    apply_mongo_timeout_overrides, consumer_identity_adoption_failure_release_values,
    ordered_insert_newly_inserted_prefix,
};
