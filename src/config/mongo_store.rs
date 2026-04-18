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
//! running SQL migrations. Indexes are idempotent (`createIndex` is a no-op if
//! the index already exists).

#[allow(dead_code)] // MongoStore is wired up in mode dispatch (database.rs, control_plane.rs)
mod inner {
    use crate::config::db_backend::{DatabaseBackend, IncrementalResult, PaginatedResult};
    use crate::config::types::{
        Consumer, GatewayConfig, PluginAssociation, PluginConfig, Proxy, Upstream,
    };
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use mongodb::bson::{Bson, Document, doc};
    use mongodb::options::{ClientOptions, FindOptions, IndexOptions, Tls, TlsOptions};
    use mongodb::{Client, Collection, Database, IndexModel};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::time::Duration;
    use tracing::{debug, info, warn};

    /// MongoDB-backed config store.
    ///
    /// Implements [`DatabaseBackend`] to provide a NoSQL alternative to the
    /// sqlx-backed `DatabaseStore`. Uses the official `mongodb` Rust driver.
    #[derive(Clone)]
    pub struct MongoStore {
        client: Client,
        db: Database,
        db_type_str: String,
        slow_query_threshold_ms: Option<u64>,
        cert_expiry_warning_days: u64,
        backend_allow_ips: crate::config::BackendAllowIps,
        failover_urls: Vec<String>,
    }

    impl MongoStore {
        /// Connect to MongoDB using the provided connection string.
        ///
        /// The connection string follows the standard MongoDB URI format:
        /// `mongodb://[username:password@]host[:port]/[database][?options]`
        ///
        /// **TLS/mTLS configuration**: When `tls_enabled` is true, TLS is configured
        /// programmatically via `TlsOptions` using the existing `FERRUM_DB_TLS_*`
        /// env vars:
        /// - `FERRUM_DB_TLS_CA_CERT_PATH` → `TlsOptions::ca_file_path`
        /// - `FERRUM_DB_TLS_CLIENT_CERT_PATH` → Combined with key into a temp PEM
        ///   for `TlsOptions::cert_key_file_path` (MongoDB requires a single file)
        /// - `FERRUM_DB_TLS_INSECURE` → `TlsOptions::allow_invalid_certificates`
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
            let mut client_options = ClientOptions::parse(mongo_url).await?;

            if let Some(name) = app_name {
                client_options.app_name = Some(name.to_string());
            }
            if let Some(rs) = replica_set {
                client_options.repl_set_name = Some(rs.to_string());
            }
            if let Some(mechanism) = auth_mechanism {
                client_options
                    .credential
                    .get_or_insert_with(Default::default)
                    .mechanism = Some(mechanism.parse().map_err(|e| {
                    anyhow::anyhow!("Invalid MongoDB auth mechanism '{}': {}", mechanism, e)
                })?);
            }
            client_options.server_selection_timeout =
                Some(Duration::from_secs(server_selection_timeout_secs));
            client_options.connect_timeout = Some(Duration::from_secs(connect_timeout_secs));

            // Configure TLS via the existing FERRUM_DB_TLS_* env vars.
            // Only set programmatic TLS if the connection string doesn't already
            // include TLS options (connection string takes precedence).
            if tls_enabled && client_options.tls.is_none() {
                let ca = tls_ca_cert_path.map(PathBuf::from);

                // MongoDB requires client cert + key in a single combined PEM file.
                // If the user provides separate cert and key files, combine them
                // into a temp file. If only cert is provided, assume it already
                // contains the key (combined PEM).
                let cert_key = match (tls_client_cert_path, tls_client_key_path) {
                    (Some(cert_path), Some(key_path)) => {
                        Some(Self::combine_cert_key_pem(cert_path, key_path)?)
                    }
                    (Some(cert_path), None) => Some(PathBuf::from(cert_path)),
                    _ => None,
                };

                // Build TlsOptions using the typed-state builder. Each method
                // consumes the builder, so we chain conditionally.
                let tls_opts = Self::build_tls_options(ca, cert_key, tls_insecure);

                client_options.tls = Some(Tls::Enabled(tls_opts));
                info!(
                    "MongoDB TLS enabled (ca={}, client_cert={}, insecure={})",
                    tls_ca_cert_path.unwrap_or("system-roots"),
                    tls_client_cert_path.unwrap_or("none"),
                    tls_insecure
                );
            }

            let client = Client::with_options(client_options)?;
            let db = client.database(database_name);

            // Verify connectivity
            db.run_command(doc! { "ping": 1 }).await.map_err(|e| {
                anyhow::anyhow!(
                    "MongoDB connectivity check failed (database='{}'): {}",
                    database_name,
                    e
                )
            })?;

            info!(
                "MongoDB connected (database='{}', url={})",
                database_name,
                crate::config::db_backend::redact_url(mongo_url)
            );

            Ok(Self {
                client,
                db,
                db_type_str: "mongodb".to_string(),
                slow_query_threshold_ms: None,
                cert_expiry_warning_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
                backend_allow_ips: crate::config::BackendAllowIps::Both,
                failover_urls: Vec::new(),
            })
        }

        /// Combine separate PEM cert and key files into a single temporary file.
        ///
        /// The MongoDB Rust driver requires client cert + key in a single PEM file
        /// (`TlsOptions::cert_key_file_path`). The gateway's `FERRUM_DB_TLS_*` env
        /// vars use separate files (matching the PostgreSQL/MySQL convention).
        /// This helper reads both files and writes a combined PEM to a temp file
        /// that persists for the lifetime of the process.
        fn combine_cert_key_pem(cert_path: &str, key_path: &str) -> Result<PathBuf, anyhow::Error> {
            let cert_data = std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!("Failed to read MongoDB client cert '{}': {}", cert_path, e)
            })?;
            let key_data = std::fs::read_to_string(key_path).map_err(|e| {
                anyhow::anyhow!("Failed to read MongoDB client key '{}': {}", key_path, e)
            })?;

            // Write combined PEM to a temp file. Use a PID-scoped deterministic path
            // so reconnect calls reuse the same file (no temp file leak) while multiple
            // gateway instances on the same host don't collide.
            let combined_path = std::env::temp_dir()
                .join(format!("ferrum-mongo-client-{}.pem", std::process::id()));
            let combined = format!("{}\n{}", cert_data.trim(), key_data.trim());
            std::fs::write(&combined_path, combined).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write combined MongoDB client PEM to '{}': {}",
                    combined_path.display(),
                    e
                )
            })?;

            info!(
                "Combined MongoDB client cert ({}) + key ({}) into {}",
                cert_path,
                key_path,
                combined_path.display()
            );
            Ok(combined_path)
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

        fn proxies(&self) -> Collection<Document> {
            self.db.collection("proxies")
        }

        fn consumers(&self) -> Collection<Document> {
            self.db.collection("consumers")
        }

        fn plugin_configs(&self) -> Collection<Document> {
            self.db.collection("plugin_configs")
        }

        fn upstreams(&self) -> Collection<Document> {
            self.db.collection("upstreams")
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

        /// Delete proxy_group-scoped plugin configs that are no longer referenced
        /// by any proxy's embedded `plugins` array. Called after proxy deletion or
        /// update (which may remove associations).
        async fn cleanup_orphaned_proxy_group_plugins(&self) -> Result<(), anyhow::Error> {
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
    fn doc_to_proxy(doc: Document) -> Result<Proxy, anyhow::Error> {
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

    fn doc_to_consumer(doc: Document) -> Result<Consumer, anyhow::Error> {
        Ok(mongodb::bson::from_document(doc)?)
    }

    /// Convert a domain `PluginConfig` into a BSON `Document`.
    fn plugin_config_to_doc(pc: &PluginConfig) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(pc)?;
        doc.insert("_id", pc.id.as_str());
        Ok(doc)
    }

    fn doc_to_plugin_config(doc: Document) -> Result<PluginConfig, anyhow::Error> {
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

    fn doc_to_upstream(doc: Document) -> Result<Upstream, anyhow::Error> {
        Ok(mongodb::bson::from_document(doc)?)
    }

    // -----------------------------------------------------------------------
    // DatabaseBackend trait implementation
    // -----------------------------------------------------------------------

    #[async_trait]
    impl DatabaseBackend for MongoStore {
        async fn health_check(&self) -> Result<(), anyhow::Error> {
            self.db.run_command(doc! { "ping": 1 }).await?;
            Ok(())
        }

        fn db_type(&self) -> &str {
            &self.db_type_str
        }

        fn has_read_replica(&self) -> bool {
            // MongoDB driver handles read preference internally via connection string
            false
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

        async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
            let start = std::time::Instant::now();
            let loaded_at = Utc::now();
            let ns_filter = doc! { "namespace": namespace };

            // Load all collections scoped to namespace
            let mut proxies = Vec::new();
            let mut cursor = self.proxies().find(ns_filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                proxies.push(doc_to_proxy(doc)?);
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
                plugin_configs.push(doc_to_plugin_config(doc)?);
            }

            let mut upstreams = Vec::new();
            let mut cursor = self.upstreams().find(ns_filter).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                upstreams.push(doc_to_upstream(doc)?);
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

            Ok(GatewayConfig {
                version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
                proxies,
                consumers,
                plugin_configs,
                upstreams,
                loaded_at,
                known_namespaces: Vec::new(),
            })
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
            // The `updated_at` field is stored as an RFC 3339 string (chrono serde),
            // which is lexicographically sortable, so $gt on strings works correctly.
            let since_with_margin = since - chrono::Duration::seconds(1);
            let since_str = since_with_margin.to_rfc3339();
            let filter = doc! { "namespace": namespace, "updated_at": { "$gt": &since_str } };

            // Load changed resources
            let mut added_or_modified_proxies = Vec::new();
            let mut cursor = self.proxies().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                added_or_modified_proxies.push(doc_to_proxy(doc)?);
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
                added_or_modified_plugin_configs.push(doc_to_plugin_config(doc)?);
            }

            let mut added_or_modified_upstreams = Vec::new();
            let mut cursor = self.upstreams().find(filter).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                added_or_modified_upstreams.push(doc_to_upstream(doc)?);
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
            let doc = proxy_to_doc(proxy)?;
            self.proxies()
                .replace_one(doc! { "_id": &proxy.id }, doc)
                .await?;
            // Clean up orphaned proxy_group plugin configs (update may remove associations)
            self.cleanup_orphaned_proxy_group_plugins().await?;
            self.check_slow_query("update_proxy", start);
            Ok(())
        }

        async fn delete_proxy(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
            // Also remove associated plugin_config entries scoped to this proxy
            self.plugin_configs()
                .delete_many(doc! { "proxy_id": id })
                .await?;
            let result = self.proxies().delete_one(doc! { "_id": id }).await?;
            // Clean up orphaned proxy_group plugin configs (no proxy references them)
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

        async fn check_proxy_exists(&self, proxy_id: &str) -> Result<bool, anyhow::Error> {
            let count = self
                .proxies()
                .count_documents(doc! { "_id": proxy_id })
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
            let doc = plugin_config_to_doc(pc)?;
            self.plugin_configs()
                .replace_one(doc! { "_id": &pc.id }, doc)
                .await?;
            self.check_slow_query("update_plugin_config", start);
            Ok(())
        }

        async fn delete_plugin_config(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
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
            let doc = upstream_to_doc(upstream)?;
            self.upstreams()
                .replace_one(doc! { "_id": &upstream.id }, doc)
                .await?;
            self.check_slow_query("update_upstream", start);
            Ok(())
        }

        async fn delete_upstream(&self, id: &str) -> Result<bool, anyhow::Error> {
            let start = std::time::Instant::now();
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
            if count == 0 {
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
            listen_path: &str,
            hosts: &[String],
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "namespace": namespace, "listen_path": listen_path };
            if let Some(id) = exclude_proxy_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            // Check for overlapping hosts (empty hosts = catch-all, always conflicts)
            if !hosts.is_empty() {
                filter.insert(
                    "$or",
                    vec![
                        doc! { "hosts": { "$size": 0 } },
                        doc! { "hosts": { "$in": hosts } },
                    ],
                );
            }
            let count = self.proxies().count_documents(filter).await?;
            Ok(count == 0)
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
            username: &str,
            custom_id: Option<&str>,
            exclude_consumer_id: Option<&str>,
        ) -> Result<Option<String>, anyhow::Error> {
            // Build OR filter for username or custom_id match
            let mut or_conditions = vec![doc! { "username": username }];
            if let Some(cid) = custom_id {
                or_conditions.push(doc! { "custom_id": cid });
            }
            let mut filter = doc! { "namespace": namespace, "$or": or_conditions };
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
            // Supports both single-object and array formats for keyauth credentials
            let mut filter = doc! {
                "namespace": namespace,
                "$or": [
                    { "credentials.keyauth.key": key },
                    { "credentials.keyauth": { "$elemMatch": { "key": key } } }
                ]
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
            // Supports both single-object and array formats for mtls_auth credentials
            let mut filter = doc! {
                "namespace": namespace,
                "$or": [
                    { "credentials.mtls_auth.identity": identity },
                    { "credentials.mtls_auth": { "$elemMatch": { "identity": identity } } }
                ]
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

        async fn check_upstream_exists(&self, upstream_id: &str) -> Result<bool, anyhow::Error> {
            let count = self
                .upstreams()
                .count_documents(doc! { "_id": upstream_id })
                .await?;
            Ok(count > 0)
        }

        async fn validate_proxy_plugin_associations(
            &self,
            _proxy_id: &str,
            plugins: &[PluginAssociation],
        ) -> Result<Vec<String>, anyhow::Error> {
            let mut missing = Vec::new();
            for assoc in plugins {
                let count = self
                    .plugin_configs()
                    .count_documents(doc! { "_id": &assoc.plugin_config_id })
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
            self.upstreams().delete_many(ns_filter).await?;
            info!("All MongoDB resources deleted (namespace='{}')", namespace);
            Ok(())
        }

        // -------------------------------------------------------------------
        // Connection lifecycle
        // -------------------------------------------------------------------

        async fn reconnect(
            &self,
            _db_url: &str,
            _tls_enabled: bool,
            _tls_ca_cert_path: Option<&str>,
            _tls_client_cert_path: Option<&str>,
            _tls_client_key_path: Option<&str>,
            _tls_insecure: bool,
        ) -> Result<(), anyhow::Error> {
            // MongoDB driver handles connection pooling and reconnection internally.
            // A full reconnect would require replacing the Client, which is complex
            // for an Arc-shared store. For now, verify the connection is alive.
            self.db
                .run_command(doc! { "ping": 1 })
                .await
                .map_err(|e| anyhow::anyhow!("MongoDB reconnect ping failed: {}", e))?;
            info!("MongoDB connection verified after reconnect request");
            Ok(())
        }

        async fn reconnect_read_replica(
            &self,
            _replica_url: &str,
            _tls_enabled: bool,
            _tls_ca_cert_path: Option<&str>,
            _tls_client_cert_path: Option<&str>,
            _tls_client_key_path: Option<&str>,
            _tls_insecure: bool,
        ) -> Result<(), anyhow::Error> {
            // MongoDB driver handles read preference routing internally via
            // the connection string (e.g., ?readPreference=secondaryPreferred).
            // No separate replica pool needed.
            Ok(())
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
                return Ok(primary_url.to_string());
            }

            // Try failover URLs
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
                        "Reconnected to failover MongoDB #{} ({})",
                        i + 1,
                        crate::config::db_backend::redact_url(url)
                    );
                    return Ok(url.clone());
                }
            }

            Err(anyhow::anyhow!("All MongoDB URLs failed during reconnect"))
        }

        async fn run_migrations(&self) -> Result<(), anyhow::Error> {
            // MongoDB doesn't use SQL migrations. Instead, ensure indexes exist.
            // createIndex is idempotent — no-op if the index already exists.

            // proxies indexes — uniqueness scoped to namespace
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "name": 1 })
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
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
                        .keys(doc! { "namespace": 1, "listen_port": 1 })
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            self.proxies()
                .create_index(IndexModel::builder().keys(doc! { "namespace": 1 }).build())
                .await?;
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
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
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            self.consumers()
                .create_index(IndexModel::builder().keys(doc! { "namespace": 1 }).build())
                .await?;
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
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
            self.plugin_configs()
                .create_index(IndexModel::builder().keys(doc! { "namespace": 1 }).build())
                .await?;
            self.plugin_configs()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
                        .build(),
                )
                .await?;
            // Compound indexes for common admin API query patterns (V002)
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
                        .keys(doc! { "namespace": 1, "plugin_name": 1 })
                        .build(),
                )
                .await?;

            // upstreams indexes — uniqueness scoped to namespace
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "name": 1 })
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            self.upstreams()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;
            self.upstreams()
                .create_index(IndexModel::builder().keys(doc! { "namespace": 1 }).build())
                .await?;
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "namespace": 1, "updated_at": 1 })
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
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

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
            let collection: Collection<Document> = self.db.collection(collection_name);
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
            let collection: Collection<Document> = self.db.collection(collection_name);
            let values = collection.distinct("namespace", doc! {}).await?;
            let mut namespaces = HashSet::new();
            for val in values {
                if let Some(s) = val.as_str() {
                    namespaces.insert(s.to_string());
                }
            }
            Ok(namespaces)
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
                listen_path: "/api".to_string(),
                backend_protocol: crate::config::types::BackendProtocol::Https,
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
                upstream_id: None,
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
                config: serde_json::json!({"window_seconds": 60, "max_requests": 100}),
                scope: crate::config::types::PluginScope::Proxy,
                proxy_id: Some("proxy-1".to_string()),
                priority_override: Some(500),
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
                    weight: 100,
                    tags: std::collections::HashMap::new(),
                    path: None,
                }],
                health_checks: None,
                hash_on: None,
                hash_on_cookie_config: None,
                service_discovery: None,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
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
        }

        #[test]
        fn proxy_to_doc_sets_id_field() {
            let now = chrono::Utc::now();
            let proxy = Proxy {
                id: "unique-id-123".to_string(),
                namespace: crate::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: "/".to_string(),
                backend_protocol: crate::config::types::BackendProtocol::Http,
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
                upstream_id: None,
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
                listen_path: "/".to_string(),
                backend_protocol: crate::config::types::BackendProtocol::Http,
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
                upstream_id: None,
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
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
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
                listen_path: "/test".to_string(),
                backend_protocol: crate::config::types::BackendProtocol::Http,
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
                upstream_id: Some("my-upstream".to_string()),
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
    }
}

pub use inner::MongoStore;
