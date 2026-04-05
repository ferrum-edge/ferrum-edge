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
    use mongodb::bson::{Document, doc};
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
    }

    // -----------------------------------------------------------------------
    // BSON serialization helpers
    // -----------------------------------------------------------------------

    /// Convert a domain `Proxy` into a BSON `Document` for storage.
    fn proxy_to_doc(proxy: &Proxy) -> Result<Document, anyhow::Error> {
        let mut doc = mongodb::bson::to_document(proxy)?;
        // Use the proxy's id as the MongoDB _id
        doc.insert("_id", proxy.id.as_str());
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

        async fn load_full_config(&self) -> Result<GatewayConfig, anyhow::Error> {
            let start = std::time::Instant::now();
            let loaded_at = Utc::now();

            // Load all collections
            let mut proxies = Vec::new();
            let mut cursor = self.proxies().find(doc! {}).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_proxy(doc) {
                    Ok(p) => proxies.push(p),
                    Err(e) => warn!("Failed to deserialize proxy document: {}", e),
                }
            }

            let mut consumers = Vec::new();
            let mut cursor = self.consumers().find(doc! {}).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_consumer(doc) {
                    Ok(c) => consumers.push(c),
                    Err(e) => warn!("Failed to deserialize consumer document: {}", e),
                }
            }

            let mut plugin_configs = Vec::new();
            let mut cursor = self.plugin_configs().find(doc! {}).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_plugin_config(doc) {
                    Ok(pc) => plugin_configs.push(pc),
                    Err(e) => warn!("Failed to deserialize plugin_config document: {}", e),
                }
            }

            let mut upstreams = Vec::new();
            let mut cursor = self.upstreams().find(doc! {}).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                match doc_to_upstream(doc) {
                    Ok(u) => upstreams.push(u),
                    Err(e) => warn!("Failed to deserialize upstream document: {}", e),
                }
            }

            self.check_slow_query("load_full_config", start);

            info!(
                "MongoDB loaded config: {} proxies, {} consumers, {} plugins, {} upstreams",
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
            })
        }

        async fn load_incremental_config(
            &self,
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
            let filter = doc! { "updated_at": { "$gt": &since_str } };

            // Load changed resources
            let mut added_or_modified_proxies = Vec::new();
            let mut cursor = self.proxies().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(p) = doc_to_proxy(doc) {
                    added_or_modified_proxies.push(p);
                }
            }

            let mut added_or_modified_consumers = Vec::new();
            let mut cursor = self.consumers().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(c) = doc_to_consumer(doc) {
                    added_or_modified_consumers.push(c);
                }
            }

            let mut added_or_modified_plugin_configs = Vec::new();
            let mut cursor = self.plugin_configs().find(filter.clone()).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(pc) = doc_to_plugin_config(doc) {
                    added_or_modified_plugin_configs.push(pc);
                }
            }

            let mut added_or_modified_upstreams = Vec::new();
            let mut cursor = self.upstreams().find(filter).await?;
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(u) = doc_to_upstream(doc) {
                    added_or_modified_upstreams.push(u);
                }
            }

            // Detect deletions by loading current IDs and diffing against known sets
            let current_proxy_ids = self.load_collection_ids("proxies").await?;
            let current_consumer_ids = self.load_collection_ids("consumers").await?;
            let current_plugin_config_ids = self.load_collection_ids("plugin_configs").await?;
            let current_upstream_ids = self.load_collection_ids("upstreams").await?;

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
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Proxy>, anyhow::Error> {
            let start = std::time::Instant::now();
            let total = self.proxies().count_documents(doc! {}).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self.proxies().find(doc! {}).with_options(options).await?;
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
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Consumer>, anyhow::Error> {
            let start = std::time::Instant::now();
            let total = self.consumers().count_documents(doc! {}).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self.consumers().find(doc! {}).with_options(options).await?;
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
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> {
            let start = std::time::Instant::now();
            let total = self.plugin_configs().count_documents(doc! {}).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self
                .plugin_configs()
                .find(doc! {})
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
            limit: i64,
            offset: i64,
        ) -> Result<PaginatedResult<Upstream>, anyhow::Error> {
            let start = std::time::Instant::now();
            let total = self.upstreams().count_documents(doc! {}).await? as i64;
            let options = FindOptions::builder()
                .sort(doc! { "_id": 1 })
                .skip(Some(offset as u64))
                .limit(Some(limit))
                .build();
            let mut cursor = self.upstreams().find(doc! {}).with_options(options).await?;
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
            listen_path: &str,
            hosts: &[String],
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "listen_path": listen_path };
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
            name: &str,
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "name": name };
            if let Some(id) = exclude_proxy_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.proxies().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_upstream_name_unique(
            &self,
            name: &str,
            exclude_upstream_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "name": name };
            if let Some(id) = exclude_upstream_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.upstreams().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_consumer_identity_unique(
            &self,
            username: &str,
            custom_id: Option<&str>,
            exclude_consumer_id: Option<&str>,
        ) -> Result<Option<String>, anyhow::Error> {
            // Build OR filter for username or custom_id match
            let mut or_conditions = vec![doc! { "username": username }];
            if let Some(cid) = custom_id {
                or_conditions.push(doc! { "custom_id": cid });
            }
            let mut filter = doc! { "$or": or_conditions };
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
            key: &str,
            exclude_consumer_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            // key_auth credentials are stored in credentials.key_auth.key
            let mut filter = doc! { "credentials.key_auth.key": key };
            if let Some(id) = exclude_consumer_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.consumers().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_mtls_identity_unique(
            &self,
            identity: &str,
            exclude_consumer_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "credentials.mtls.subject": identity };
            if let Some(id) = exclude_consumer_id {
                filter.insert("_id", doc! { "$ne": id });
            }
            let count = self.consumers().count_documents(filter).await?;
            Ok(count == 0)
        }

        async fn check_listen_port_unique(
            &self,
            port: u16,
            exclude_proxy_id: Option<&str>,
        ) -> Result<bool, anyhow::Error> {
            let mut filter = doc! { "listen_port": port as i32 };
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

        async fn delete_all_resources(&self) -> Result<(), anyhow::Error> {
            self.plugin_configs().delete_many(doc! {}).await?;
            self.proxies().delete_many(doc! {}).await?;
            self.consumers().delete_many(doc! {}).await?;
            self.upstreams().delete_many(doc! {}).await?;
            info!("All MongoDB resources deleted");
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

            // proxies indexes
            self.proxies()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "name": 1 })
                        .options(IndexOptions::builder().unique(true).build())
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
                        .keys(doc! { "listen_port": 1 })
                        .build(),
                )
                .await?;

            // consumers indexes
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "username": 1 })
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "custom_id": 1 })
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            self.consumers()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;

            // plugin_configs indexes
            self.plugin_configs()
                .create_index(IndexModel::builder().keys(doc! { "proxy_id": 1 }).build())
                .await?;
            self.plugin_configs()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;

            // upstreams indexes
            self.upstreams()
                .create_index(
                    IndexModel::builder()
                        .keys(doc! { "name": 1 })
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            self.upstreams()
                .create_index(IndexModel::builder().keys(doc! { "updated_at": 1 }).build())
                .await?;

            info!("MongoDB indexes ensured");
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    impl MongoStore {
        /// Load all `_id` values from a collection (for deletion detection).
        async fn load_collection_ids(
            &self,
            collection_name: &str,
        ) -> Result<HashSet<String>, anyhow::Error> {
            let collection: Collection<Document> = self.db.collection(collection_name);
            let options = FindOptions::builder().projection(doc! { "_id": 1 }).build();
            let mut cursor = collection.find(doc! {}).with_options(options).await?;
            let mut ids = HashSet::new();
            while cursor.advance().await? {
                let doc = cursor.deserialize_current()?;
                if let Ok(id) = doc.get_str("_id") {
                    ids.insert(id.to_string());
                }
            }
            Ok(ids)
        }
    }

    /// IDs in `known` that are not in `current` (i.e., deleted resources).
    fn diff_removed(known: &HashSet<String>, current: &HashSet<String>) -> Vec<String> {
        known.difference(current).cloned().collect()
    }
}

pub use inner::MongoStore;
