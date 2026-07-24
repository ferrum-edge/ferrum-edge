//! Dialect-specific SQL text for the V001 initial schema migration.
//!
//! MySQL intentionally diverges from the SQLite/Postgres-style schema in a few
//! places:
//! - strict mode forbids defaults on `TEXT`/`BLOB`, so MySQL uses bounded
//!   `VARCHAR(N)` columns for primary keys and other fields that need defaults
//! - timestamp columns use `VARCHAR(64)` (not native `DATETIME`) because sqlx's
//!   `Any` driver does not round-trip MySQL `DATETIME` values into the
//!   string-based config layer.  RFC 3339 nano-precision timestamps are at most
//!   35 chars; `VARCHAR(64)` provides comfortable headroom
//! - identifier / hostname VARCHAR columns use `COLLATE utf8mb4_bin` so
//!   uniqueness and ordering on `(namespace, name)` etc. is truly byte-exact
//!   (matching PostgreSQL `texteq` and SQLite BINARY), not merely accent-/
//!   case-sensitive UCA comparison. `utf8mb4_0900_as_cs` treats canonically
//!   equivalent Unicode sequences (NFC vs NFD) as equal, which diverges from
//!   the runtime's byte-keyed identity indexes. Hostnames are pre-normalized
//!   to ASCII-lowercase by `normalize_fields()`, so case-sensitivity is moot
//!   for those, but other identifiers benefit. Floor is MySQL 8.0+; the
//!   project test infra runs MySQL 8.
//! - columns whose code-side cap exceeds MySQL's `TEXT` (65,535 bytes) use
//!   `MEDIUMTEXT` (16 MiB): `plugin_configs.config` (1 MiB cap),
//!   `consumers.credentials` (64 KiB cap — off-by-one over `TEXT`),
//!   `consumers.acl_groups` (≈130 KiB worst case), `upstreams.targets`
//!   (1000 targets ≈ 200 KiB), `upstreams.backend_tls_san_allow_list`.
//!
//! The proxy schema also intentionally omits a unique index on
//! `(namespace, listen_path)`: path uniqueness is host-scoped, so only
//! namespace/name and namespace/listen_port constraints belong in V001.
//!
//! ## Foreign key constraints
//!
//! All six FK constraints are semantically identical across Postgres, MySQL,
//! and SQLite. The surface syntax differs — MySQL uses explicit
//! `CONSTRAINT <name> FOREIGN KEY (<cols>) REFERENCES ...` while Postgres and
//! SQLite use inline `<col> TYPE REFERENCES ...` for single-column FKs and
//! table-level `FOREIGN KEY (<cols>) REFERENCES ...` for composite FKs — but
//! the referenced tables, columns, ON DELETE actions, and nullability match
//! exactly:
//!
//! | Table                     | Column(s)                | References                | ON DELETE |
//! |---------------------------|--------------------------|---------------------------|-----------|
//! | proxies                   | upstream_id              | upstreams(id)             | RESTRICT  |
//! | plugin_configs            | proxy_id                 | proxies(id)               | CASCADE   |
//! | proxy_plugins             | proxy_id                 | proxies(id)               | CASCADE   |
//! | proxy_plugins             | plugin_config_id         | plugin_configs(id)        | CASCADE   |
//! | consumer_credential_index | (namespace, consumer_id) | consumers(namespace, id)  | CASCADE   |
//! | consumer_identity_index   | (namespace, consumer_id) | consumers(namespace, id)  | CASCADE   |
//!
//! `consumers` uses a composite `PRIMARY KEY (namespace, id)` (issue #2121):
//! consumer ids are unique per namespace, so the same id may exist in two
//! namespaces. Both consumer index tables therefore reference the composite
//! key.
//!
//! Named constraints on MySQL (e.g. `fk_proxies_upstream`) are cosmetic; they
//! aid `ALTER TABLE DROP CONSTRAINT` but do not change enforcement behavior.
//! The inline tests below regression-guard this cross-dialect consistency.

use sqlx::AnyConnection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDialect {
    Postgres,
    MySql,
    Sqlite,
}

/// Small dialect-aware SQL helper for V001.
///
/// The helper keeps the migration logic conservative: it only encapsulates the
/// SQL text and the MySQL duplicate-index tolerance that already existed in the
/// migration, without trying to normalize the schema across databases.
pub(super) struct V001SqlBuilder {
    dialect: SqlDialect,
}

impl V001SqlBuilder {
    pub(super) fn new(db_type: &str) -> Self {
        let dialect = match db_type {
            "mysql" => SqlDialect::MySql,
            "sqlite" => SqlDialect::Sqlite,
            _ => SqlDialect::Postgres,
        };

        Self { dialect }
    }

    pub(super) async fn apply(&self, connection: &mut AnyConnection) -> Result<(), anyhow::Error> {
        // MySQL auto-commits DDL, so a mid-V001 failure cannot be rolled back.
        // Keep every statement idempotent and only let MigrationRunner record
        // V001 after this full apply path returns successfully.
        self.enable_sqlite_foreign_keys(connection).await?;
        self.create_tables(connection).await?;
        self.create_indexes(connection).await?;
        self.create_unique_indexes(connection).await?;
        Ok(())
    }

    /// Idempotently ensure baseline tables that were folded into V001 *after*
    /// some databases had already recorded V001 in `_ferrum_migrations`.
    ///
    /// During build-out, schema additions are folded into the V001 baseline
    /// rather than carried as upgrade migrations (see the project build-out
    /// policy). The migration runner skips V001 entirely once version 1 is
    /// recorded, so a table added to V001 here would never be created on an
    /// already-initialized database — yet persistence writes compatibility
    /// tables such as `proxy_route_locks` and `config_admission_locks` on every
    /// guarded mutation. Re-running this idempotent `CREATE TABLE IF NOT EXISTS`
    /// pass on every startup guarantees those tables exist regardless of when
    /// V001 was recorded. Every statement here must be idempotent (no error on
    /// re-run) so the pass is safe on fresh databases that just applied V001.
    pub(super) async fn ensure_compatibility_tables(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(self.create_proxy_route_locks_sql())
            .execute(&mut *connection)
            .await?;
        sqlx::query(self.create_config_change_locks_sql())
            .execute(&mut *connection)
            .await?;
        sqlx::query(self.create_config_admission_locks_sql())
            .execute(&mut *connection)
            .await?;
        sqlx::query(self.create_config_change_retention_sql())
            .execute(&mut *connection)
            .await?;
        sqlx::query(self.create_config_changes_sql())
            .execute(&mut *connection)
            .await?;
        self.create_full_load_indexes(connection).await?;
        self.create_config_change_indexes(connection).await?;
        Ok(())
    }

    async fn enable_sqlite_foreign_keys(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        if self.is_sqlite() {
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&mut *connection)
                .await?;
        }

        Ok(())
    }

    async fn create_tables(&self, connection: &mut AnyConnection) -> Result<(), anyhow::Error> {
        for sql in [
            self.create_upstreams_sql(),
            self.create_consumers_sql(),
            self.create_consumer_credential_index_sql(),
            self.create_consumer_identity_index_sql(),
            self.create_proxies_sql(),
            self.create_proxy_route_locks_sql(),
            self.create_mtls_dns_admission_locks_sql(),
            self.create_plugin_configs_sql(),
            self.create_proxy_plugins_sql(),
            self.create_config_change_locks_sql(),
            self.create_config_admission_locks_sql(),
            self.create_config_change_retention_sql(),
            self.create_config_changes_sql(),
            // api_specs must come AFTER proxies (api_specs.proxy_id FKs
            // proxies(id) ON DELETE CASCADE, so the proxies table must exist
            // first).  The api_spec_id back-links on proxies/upstreams/
            // plugin_configs are application-managed (no FK constraint) — see
            // the comment block in create_api_specs_sql().  api_specs is
            // admin-only metadata; the gateway runtime never reads this table.
            self.create_api_specs_sql(),
            // audit_events is admin-only mutation history. It is not loaded into
            // GatewayConfig and is never touched by proxy/runtime hot paths.
            self.create_audit_events_sql(),
        ] {
            sqlx::query(sql).execute(&mut *connection).await?;
        }

        Ok(())
    }

    async fn create_indexes(&self, connection: &mut AnyConnection) -> Result<(), anyhow::Error> {
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_proxies_upstream_id ON proxies (upstream_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_proxy_id ON plugin_configs (proxy_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_plugin_config_id ON proxy_plugins (plugin_config_id)",
            "CREATE INDEX IF NOT EXISTS idx_proxies_updated_at ON proxies (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_updated_at ON consumers (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_updated_at ON plugin_configs (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_updated_at ON upstreams (updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_updated ON proxies (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_updated ON consumers (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumer_credential_index_consumer_id ON consumer_credential_index (consumer_id)",
            // Serves the per-consumer identity-row rewrite on consumer
            // update/delete and satisfies MySQL's FK-column index requirement
            // for the composite (namespace, consumer_id) foreign key.
            "CREATE INDEX IF NOT EXISTS idx_consumer_identity_index_consumer_id ON consumer_identity_index (namespace, consumer_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_updated ON plugin_configs (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_updated ON upstreams (namespace, updated_at)",
            // Full config loads use keyset pagination with
            // `WHERE namespace = ? AND id > ? ORDER BY id LIMIT ?`. The
            // `(namespace, updated_at)` compounds do not cover that access
            // pattern, so keep dedicated `(namespace, id)` indexes.
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_id ON proxies (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_id ON consumers (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_id ON plugin_configs (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_id ON upstreams (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_config_changes_ns_sequence ON config_changes (namespace, sequence)",
            "CREATE INDEX IF NOT EXISTS idx_config_changes_sequence ON config_changes (sequence)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_scope ON plugin_configs (namespace, scope)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_scope_id ON plugin_configs (scope, id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_plugin_name ON plugin_configs (namespace, plugin_name)",
            // Cold-path index for cross-namespace mesh_route_dispatch lookups in
            // `mesh_route_dispatch_plugin_configs_tx`. Upstream IDs are globally
            // unique PKs, so the cleanup helpers intentionally scan across
            // namespaces (a cross-namespace reference is real and must be
            // caught). MongoDB has a matching `{plugin_name, enabled}` partial
            // index with `partialFilterExpression: {enabled: true}`; the
            // SQL helper applies the same `WHERE enabled = 1` filter on
            // Postgres/SQLite (MySQL has no partial-index equivalent).
            self.mesh_route_dispatch_index_sql(),
            // Note: no standalone namespace index on api_specs — the compound
            // indexes below (namespace + updated_at / spec_version / etc.) all
            // have namespace as the leading column and serve namespace-only lookups.
            "CREATE INDEX IF NOT EXISTS idx_api_specs_namespace_updated_at ON api_specs (namespace, updated_at)",
            // Wave 5 indexes — for spec_version filter, title sort, operation_count sort, created_at sort
            "CREATE INDEX IF NOT EXISTS idx_api_specs_ns_spec_version ON api_specs (namespace, spec_version)",
            self.api_specs_title_index_sql(),
            "CREATE INDEX IF NOT EXISTS idx_api_specs_ns_operation_count ON api_specs (namespace, operation_count)",
            "CREATE INDEX IF NOT EXISTS idx_api_specs_ns_created_at ON api_specs (namespace, created_at)",
            // Back-link indexes: replace_api_spec_bundle and delete_api_spec
            // run WHERE api_spec_id = ? against these tables. Without indexes,
            // those queries are full-table scans that grow with overall config
            // volume, not spec count.
            "CREATE INDEX IF NOT EXISTS idx_proxies_api_spec_id ON proxies (api_spec_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_api_spec_id ON plugin_configs (api_spec_id)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_api_spec_id ON upstreams (api_spec_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_namespace_ts_id ON audit_events (namespace, ts, id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_resource_type ON audit_events (resource_type)",
        ];

        for idx_sql in indexes {
            self.execute_index_sql(connection, idx_sql).await?;
        }

        Ok(())
    }

    async fn create_unique_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        self.execute_index_sql(connection, self.unique_listen_port_sql())
            .await?;

        for idx_sql in self.namespace_unique_index_sqls() {
            self.execute_index_sql(connection, idx_sql).await?;
        }

        Ok(())
    }

    async fn create_config_change_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_config_changes_ns_sequence ON config_changes (namespace, sequence)",
            "CREATE INDEX IF NOT EXISTS idx_config_changes_sequence ON config_changes (sequence)",
        ] {
            self.execute_index_sql(connection, idx_sql).await?;
        }

        Ok(())
    }

    async fn create_full_load_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_id ON proxies (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_id ON consumers (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_id ON plugin_configs (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_id ON upstreams (namespace, id)",
        ] {
            self.execute_index_sql(connection, idx_sql).await?;
        }

        Ok(())
    }

    async fn execute_index_sql(
        &self,
        connection: &mut AnyConnection,
        idx_sql: &str,
    ) -> Result<(), anyhow::Error> {
        if self.is_mysql() {
            // MySQL does not reliably support CREATE INDEX IF NOT EXISTS, so we
            // strip the clause and ignore duplicate-key errors, matching the
            // previous migration behavior.
            let mysql_sql = idx_sql.replace("IF NOT EXISTS ", "");
            match sqlx::query(&mysql_sql).execute(&mut *connection).await {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string();
                    // Error 1061: Duplicate key name (index already exists)
                    if !msg.contains("1061") {
                        return Err(e.into());
                    }
                }
            }
        } else {
            sqlx::query(idx_sql).execute(&mut *connection).await?;
        }

        Ok(())
    }

    fn is_mysql(&self) -> bool {
        matches!(self.dialect, SqlDialect::MySql)
    }

    fn is_sqlite(&self) -> bool {
        matches!(self.dialect, SqlDialect::Sqlite)
    }

    fn api_specs_title_index_sql(&self) -> &'static str {
        if self.is_mysql() {
            // MySQL cannot index a TEXT column without a key length. The
            // extractor caps title at 1024 bytes; a 255-character prefix keeps
            // the namespace+title index comfortably inside InnoDB's common
            // utf8mb4 key length limits while preserving useful title sorting.
            "CREATE INDEX IF NOT EXISTS idx_api_specs_ns_title ON api_specs (namespace, title(255))"
        } else {
            "CREATE INDEX IF NOT EXISTS idx_api_specs_ns_title ON api_specs (namespace, title)"
        }
    }

    fn mesh_route_dispatch_index_sql(&self) -> &'static str {
        if self.is_mysql() {
            // MySQL lacks SQL-standard partial indexes; index every row.
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_plugin_name_enabled \
             ON plugin_configs (plugin_name, enabled)"
        } else {
            // Postgres and SQLite both support partial indexes. The
            // `mesh_route_dispatch_plugin_configs_tx` helper only ever asks
            // for `enabled != 0`, so filtering disabled rows out of the index
            // halves index size and write amplification in deployments with
            // many disabled plugin_configs — matching the MongoDB
            // `partialFilterExpression: {enabled: true}` companion index.
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_plugin_name_enabled \
             ON plugin_configs (plugin_name) WHERE enabled = 1"
        }
    }

    fn create_upstreams_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255) COLLATE utf8mb4_bin,
                targets MEDIUMTEXT NOT NULL,
                algorithm VARCHAR(50) NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                hash_on_cookie_config TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                subsets TEXT,
                backend_tls_client_cert_path VARCHAR(2048),
                backend_tls_client_key_path VARCHAR(2048),
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path VARCHAR(2048),
                backend_tls_sni VARCHAR(255) COLLATE utf8mb4_bin,
                backend_tls_san_allow_list MEDIUMTEXT,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                name TEXT,
                targets TEXT NOT NULL DEFAULT '[]',
                algorithm TEXT NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                hash_on_cookie_config TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                subsets TEXT,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                backend_tls_sni TEXT,
                backend_tls_san_allow_list TEXT,
                api_spec_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_consumers_sql(&self) -> &'static str {
        // Composite PRIMARY KEY (namespace, id): consumer ids are unique per
        // namespace (issue #2121), so the same id may exist in two namespaces.
        // Both consumer index tables FK the composite key.
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                username VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                custom_id VARCHAR(255) COLLATE utf8mb4_bin,
                credentials MEDIUMTEXT NOT NULL,
                acl_groups MEDIUMTEXT NOT NULL,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, id)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS consumers (
                id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                username TEXT NOT NULL,
                custom_id TEXT,
                credentials TEXT NOT NULL DEFAULT '{}',
                acl_groups TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id)
            )
            "#
        }
    }

    fn create_consumer_credential_index_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS consumer_credential_index (
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                credential_type VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                credential_hash VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                consumer_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                PRIMARY KEY (namespace, credential_type, credential_hash),
                CONSTRAINT fk_consumer_credential_index_consumer FOREIGN KEY (namespace, consumer_id) REFERENCES consumers(namespace, id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS consumer_credential_index (
                namespace TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                credential_hash TEXT NOT NULL,
                consumer_id TEXT NOT NULL,
                PRIMARY KEY (namespace, credential_type, credential_hash),
                FOREIGN KEY (namespace, consumer_id) REFERENCES consumers(namespace, id) ON DELETE CASCADE
            )
            "#
        }
    }

    fn create_consumer_identity_index_sql(&self) -> &'static str {
        // Persistence-level cross-field consumer identity uniqueness (issue
        // #2121): one row per identity value (id, username, custom_id) a
        // consumer claims within its namespace. The composite PK is the
        // enforcement — two consumers in one namespace cannot claim the same
        // identity value across *any* of those fields. Self-collisions (a
        // consumer whose custom_id equals its own id/username) are allowed;
        // the writer dedupes its own values before insert.
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS consumer_identity_index (
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                identity_value VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                consumer_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                created_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, identity_value),
                CONSTRAINT fk_consumer_identity_index_consumer FOREIGN KEY (namespace, consumer_id) REFERENCES consumers(namespace, id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS consumer_identity_index (
                namespace TEXT NOT NULL,
                identity_value TEXT NOT NULL,
                consumer_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, identity_value),
                FOREIGN KEY (namespace, consumer_id) REFERENCES consumers(namespace, id) ON DELETE CASCADE
            )
            "#
        }
    }

    fn create_proxies_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255) COLLATE utf8mb4_bin,
                hosts TEXT NOT NULL,
                listen_path VARCHAR(512),
                backend_scheme VARCHAR(16) NOT NULL DEFAULT 'https',
                backend_host VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                backend_port INTEGER NOT NULL DEFAULT 80,
                backend_path TEXT,
                strip_listen_path INTEGER NOT NULL DEFAULT 1,
                preserve_host_header INTEGER NOT NULL DEFAULT 0,
                backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
                backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                dns_override TEXT,
                dns_cache_ttl_seconds INTEGER,
                auth_mode VARCHAR(20) NOT NULL DEFAULT 'single',
                upstream_id VARCHAR(255) COLLATE utf8mb4_bin,
                upstream_subset VARCHAR(255) COLLATE utf8mb4_bin,
                circuit_breaker TEXT,
                retry TEXT,
                response_body_mode VARCHAR(50) NOT NULL DEFAULT 'stream',

                pool_idle_timeout_seconds INTEGER,
                pool_enable_http_keep_alive INTEGER,
                pool_enable_http2 INTEGER,
                pool_tcp_keepalive_seconds INTEGER,
                pool_http2_keep_alive_interval_seconds INTEGER,
                pool_http2_keep_alive_timeout_seconds INTEGER,
                pool_http2_initial_stream_window_size INTEGER,
                pool_http2_initial_connection_window_size INTEGER,
                pool_http2_adaptive_window INTEGER,
                pool_http2_max_frame_size INTEGER,
                pool_http2_max_concurrent_streams INTEGER,
                pool_http3_connections_per_backend INTEGER,
                pool_max_requests_per_connection INTEGER,
                listen_port INTEGER,
                frontend_tls INTEGER NOT NULL DEFAULT 0,
                passthrough INTEGER NOT NULL DEFAULT 0,
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                tcp_idle_timeout_seconds INTEGER,
                websocket_idle_timeout_seconds INTEGER,
                allowed_methods TEXT,
                allowed_ws_origins TEXT,
                udp_max_response_amplification_factor REAL,
                stream_proxy_protocol INTEGER,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                CONSTRAINT fk_proxies_upstream FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE RESTRICT,
                CONSTRAINT chk_proxies_backend_port CHECK (backend_port >= 0 AND backend_port <= 65535),
                CONSTRAINT chk_proxies_listen_port CHECK (listen_port IS NULL OR (listen_port >= 1 AND listen_port <= 65535)),
                CONSTRAINT chk_proxies_connect_timeout CHECK (backend_connect_timeout_ms > 0),
                CONSTRAINT chk_proxies_read_timeout CHECK (backend_read_timeout_ms >= 0),
                CONSTRAINT chk_proxies_write_timeout CHECK (backend_write_timeout_ms >= 0)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                name TEXT,
                hosts TEXT NOT NULL DEFAULT '[]',
                listen_path TEXT,
                backend_scheme TEXT NOT NULL DEFAULT 'https',
                backend_host TEXT NOT NULL,
                backend_port INTEGER NOT NULL DEFAULT 80,
                backend_path TEXT,
                strip_listen_path INTEGER NOT NULL DEFAULT 1,
                preserve_host_header INTEGER NOT NULL DEFAULT 0,
                backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
                backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_tls_client_cert_path TEXT,
                backend_tls_client_key_path TEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path TEXT,
                dns_override TEXT,
                dns_cache_ttl_seconds INTEGER,
                auth_mode TEXT NOT NULL DEFAULT 'single',
                upstream_id TEXT REFERENCES upstreams(id) ON DELETE RESTRICT,
                upstream_subset TEXT,
                circuit_breaker TEXT,
                retry TEXT,
                response_body_mode TEXT NOT NULL DEFAULT 'stream',

                pool_idle_timeout_seconds INTEGER,
                pool_enable_http_keep_alive INTEGER,
                pool_enable_http2 INTEGER,
                pool_tcp_keepalive_seconds INTEGER,
                pool_http2_keep_alive_interval_seconds INTEGER,
                pool_http2_keep_alive_timeout_seconds INTEGER,
                pool_http2_initial_stream_window_size INTEGER,
                pool_http2_initial_connection_window_size INTEGER,
                pool_http2_adaptive_window INTEGER,
                pool_http2_max_frame_size INTEGER,
                pool_http2_max_concurrent_streams INTEGER,
                pool_http3_connections_per_backend INTEGER,
                pool_max_requests_per_connection INTEGER,
                listen_port INTEGER,
                frontend_tls INTEGER NOT NULL DEFAULT 0,
                passthrough INTEGER NOT NULL DEFAULT 0,
                udp_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60,
                tcp_idle_timeout_seconds INTEGER,
                websocket_idle_timeout_seconds INTEGER,
                allowed_methods TEXT,
                allowed_ws_origins TEXT,
                udp_max_response_amplification_factor REAL,
                stream_proxy_protocol INTEGER,
                api_spec_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (backend_port >= 0 AND backend_port <= 65535),
                CHECK (listen_port IS NULL OR (listen_port >= 1 AND listen_port <= 65535)),
                CHECK (backend_connect_timeout_ms > 0),
                CHECK (backend_read_timeout_ms >= 0),
                CHECK (backend_write_timeout_ms >= 0)
            )
            "#
        }
    }

    fn create_plugin_configs_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                plugin_name VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                config MEDIUMTEXT NOT NULL,
                scope VARCHAR(50) NOT NULL DEFAULT 'global',
                proxy_id VARCHAR(255) COLLATE utf8mb4_bin,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                CONSTRAINT fk_plugin_configs_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                plugin_name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                scope TEXT NOT NULL DEFAULT 'global',
                proxy_id TEXT REFERENCES proxies(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                api_spec_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_proxy_route_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_route_locks (
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                route_key_hash VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                created_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, route_key_hash)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_route_locks (
                namespace TEXT NOT NULL,
                route_key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, route_key_hash)
            )
            "#
        }
    }

    /// One durable lock row per namespace for conditional DNS-identity
    /// admission. Consumer, plugin, and proxy-association writers lock this
    /// row in the same transaction that they persist their candidate, then
    /// validate the effective `san_dns` policy against that transaction's
    /// authoritative snapshot. This preserves exact semantics while no DNS
    /// policy is effective without leaving a cross-process TOCTOU window when
    /// one is enabled. `restore_owner` is a logical fence that persists across
    /// every transaction in a compensating restore replay.
    ///
    /// Build-out policy intentionally keeps this table in the current baseline
    /// only. It must not be added to `ensure_compatibility_tables` as an
    /// old-schema upgrade shim.
    fn create_mtls_dns_admission_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS mtls_dns_admission_locks (
                namespace VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                updated_at VARCHAR(64) NOT NULL,
                restore_owner VARCHAR(36) COLLATE utf8mb4_bin NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS mtls_dns_admission_locks (
                namespace TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                restore_owner TEXT NULL
            )
            "#
        }
    }

    fn create_proxy_plugins_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                plugin_config_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                PRIMARY KEY (proxy_id, plugin_config_id),
                CONSTRAINT fk_proxy_plugins_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE,
                CONSTRAINT fk_proxy_plugins_plugin FOREIGN KEY (plugin_config_id) REFERENCES plugin_configs(id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                plugin_config_id TEXT NOT NULL REFERENCES plugin_configs(id) ON DELETE CASCADE,
                PRIMARY KEY (proxy_id, plugin_config_id)
            )
            "#
        }
    }

    fn create_config_change_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS config_change_locks (
                lock_name VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
                updated_at VARCHAR(64) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS config_change_locks (
                lock_name TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL
            )
            "#
        }
    }

    fn create_config_admission_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS config_admission_locks (
                namespace VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                owner VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                expires_at BIGINT NOT NULL,
                generation BIGINT NOT NULL DEFAULT 1
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS config_admission_locks (
                namespace TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                generation BIGINT NOT NULL DEFAULT 1
            )
            "#
        }
    }

    fn create_config_change_retention_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS config_change_retention (
                namespace VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                retained_sequence BIGINT NOT NULL DEFAULT 0,
                updated_at VARCHAR(64) NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS config_change_retention (
                namespace TEXT PRIMARY KEY,
                retained_sequence BIGINT NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            "#
        }
    }

    fn create_config_changes_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS config_changes (
                sequence BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                resource_type VARCHAR(32) COLLATE utf8mb4_bin NOT NULL,
                resource_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                operation VARCHAR(16) COLLATE utf8mb4_bin NOT NULL,
                created_at VARCHAR(64) NOT NULL
            )
            "#
        } else if self.is_sqlite() {
            r#"
            CREATE TABLE IF NOT EXISTS config_changes (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS config_changes (
                sequence BIGSERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_api_specs_sql(&self) -> &'static str {
        // api_specs is admin-only metadata. The gateway runtime never reads
        // this table; it is excluded from db_loader.rs, GatewayConfig, and
        // all gRPC/CP distribution paths.
        //
        // FK: proxy_id → proxies(id) ON DELETE CASCADE so deleting the proxy
        //     (e.g., when a spec is purged) automatically removes the spec row.
        //
        // The api_spec_id columns on proxies, upstreams, and plugin_configs are
        // deliberately UNCONSTRAINED (no FK, no ON DELETE SET NULL).  Application
        // code in `delete_api_spec` (db_loader.rs and mongo_store.rs) handles
        // cleanup of spec-owned resources.  FK constraints were intentionally
        // omitted to:
        //   1. Keep MongoDB and SQL semantics identical without a Mongo FK concept.
        //   2. Avoid cross-table creation-ordering complexity on MySQL (which would
        //      require api_specs to exist before inserting proxies that reference it).
        // Manual DB operations that delete from api_specs directly must also clean
        // dependent rows by hand (WHERE api_spec_id = '<deleted-spec-id>').
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                proxy_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                spec_version VARCHAR(50) COLLATE utf8mb4_bin NOT NULL,
                spec_format VARCHAR(10) NOT NULL,
                spec_content LONGBLOB NOT NULL,
                content_encoding VARCHAR(50) NOT NULL DEFAULT 'gzip',
                uncompressed_size BIGINT NOT NULL,
                content_hash VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                title TEXT,
                info_version VARCHAR(255),
                description LONGTEXT,
                contact_name TEXT,
                contact_email TEXT,
                license_name TEXT,
                license_identifier TEXT,
                tags LONGTEXT NOT NULL,
                server_urls LONGTEXT NOT NULL,
                operation_count INTEGER NOT NULL DEFAULT 0,
                resource_hash VARCHAR(64) NOT NULL DEFAULT '',
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                CONSTRAINT fk_api_specs_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            )
            "#
        } else if self.is_sqlite() {
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                spec_version TEXT NOT NULL,
                spec_format TEXT NOT NULL,
                spec_content BLOB NOT NULL,
                content_encoding TEXT NOT NULL DEFAULT 'gzip',
                uncompressed_size BIGINT NOT NULL,
                content_hash TEXT NOT NULL,
                title TEXT,
                info_version TEXT,
                description TEXT,
                contact_name TEXT,
                contact_email TEXT,
                license_name TEXT,
                license_identifier TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                server_urls TEXT NOT NULL DEFAULT '[]',
                operation_count INTEGER NOT NULL DEFAULT 0,
                resource_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        } else {
            // PostgreSQL: BYTEA for binary data (BLOB is not a native PG type).
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
                spec_version TEXT NOT NULL,
                spec_format TEXT NOT NULL,
                spec_content BYTEA NOT NULL,
                content_encoding TEXT NOT NULL DEFAULT 'gzip',
                uncompressed_size BIGINT NOT NULL,
                content_hash TEXT NOT NULL,
                title TEXT,
                info_version TEXT,
                description TEXT,
                contact_name TEXT,
                contact_email TEXT,
                license_name TEXT,
                license_identifier TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                server_urls TEXT NOT NULL DEFAULT '[]',
                operation_count INTEGER NOT NULL DEFAULT 0,
                resource_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        }
    }

    fn create_audit_events_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY,
                ts VARCHAR(50) NOT NULL,
                actor VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                action VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
                resource_type VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
                resource_id VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_bin NOT NULL DEFAULT 'ferrum',
                diff LONGTEXT NOT NULL
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                diff TEXT NOT NULL
            )
            "#
        }
    }

    fn unique_listen_port_sql(&self) -> &'static str {
        if self.is_mysql() {
            "CREATE UNIQUE INDEX idx_proxies_unique_listen_port ON proxies (namespace, listen_port)"
        } else {
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_unique_listen_port ON proxies (namespace, listen_port) WHERE listen_port IS NOT NULL"
        }
    }

    fn namespace_unique_index_sqls(&self) -> &'static [&'static str] {
        if self.is_mysql() {
            &[
                "CREATE UNIQUE INDEX idx_proxies_namespace_name ON proxies (namespace, name)",
                "CREATE UNIQUE INDEX idx_consumers_namespace_username ON consumers (namespace, username)",
                "CREATE UNIQUE INDEX idx_consumers_namespace_custom_id ON consumers (namespace, custom_id)",
                "CREATE UNIQUE INDEX idx_upstreams_namespace_name ON upstreams (namespace, name)",
                "CREATE UNIQUE INDEX idx_api_specs_namespace_proxy_id ON api_specs (namespace, proxy_id)",
            ]
        } else {
            &[
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_namespace_name ON proxies (namespace, name) WHERE name IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_consumers_namespace_username ON consumers (namespace, username)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_consumers_namespace_custom_id ON consumers (namespace, custom_id) WHERE custom_id IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_upstreams_namespace_name ON upstreams (namespace, name) WHERE name IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_api_specs_namespace_proxy_id ON api_specs (namespace, proxy_id)",
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SqlDialect, V001SqlBuilder};

    #[test]
    fn test_mysql_builder_uses_mysql_table_sql() {
        let builder = V001SqlBuilder::new("mysql");
        assert!(matches!(builder.dialect, SqlDialect::MySql));
        assert!(
            builder
                .create_upstreams_sql()
                .contains("id VARCHAR(255) COLLATE utf8mb4_bin PRIMARY KEY")
        );
        assert!(
            builder
                .unique_listen_port_sql()
                .contains("CREATE UNIQUE INDEX idx_proxies_unique_listen_port")
        );
    }

    #[test]
    fn test_mysql_api_specs_title_index_uses_prefix_length() {
        let builder = V001SqlBuilder::new("mysql");
        assert!(
            builder.api_specs_title_index_sql().contains("title(255)"),
            "MySQL must use a prefix length when indexing api_specs.title TEXT"
        );
    }

    #[test]
    fn test_mysql_api_specs_metadata_columns_hold_extractor_caps() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_api_specs_sql();
        assert!(
            sql.contains("tags LONGTEXT NOT NULL"),
            "tags must not be capped at VARCHAR(8192); extractor caps can exceed that"
        );
        assert!(
            sql.contains("server_urls LONGTEXT NOT NULL"),
            "server_urls must not be capped at VARCHAR(8192); extractor caps can exceed that"
        );
    }

    #[test]
    fn test_mysql_upstreams_san_allow_list_column_holds_config_cap() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_upstreams_sql();
        assert!(
            sql.contains("backend_tls_san_allow_list MEDIUMTEXT"),
            "SAN allow-list JSON can exceed MySQL TEXT when every allowed entry is near the per-entry cap"
        );
    }

    #[test]
    fn test_mysql_upstreams_tls_verify_column_matches_reader_type() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_upstreams_sql();
        assert!(
            sql.contains("backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1"),
            "upstream TLS verify flag must match row_to_upstream's i32 reader"
        );
        assert!(
            !sql.contains("backend_tls_verify_server_cert TINYINT"),
            "upstream TLS verify flag must not use a narrower MySQL-only type"
        );
    }

    // ------------------------------------------------------------------
    // mesh_route_dispatch index — partial on Postgres/SQLite (matches
    // MongoDB's `partialFilterExpression: {enabled: true}`), full on
    // MySQL which lacks SQL-standard partial indexes.
    // ------------------------------------------------------------------

    #[test]
    fn test_mysql_mesh_route_dispatch_index_is_full() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.mesh_route_dispatch_index_sql();
        assert!(
            sql.contains("idx_plugin_configs_plugin_name_enabled"),
            "MySQL must still create the mesh_route_dispatch perf index"
        );
        assert!(
            sql.contains("(plugin_name, enabled)"),
            "MySQL has no partial-index support; the index must include enabled as a regular column"
        );
        assert!(
            !sql.contains("WHERE"),
            "MySQL cannot use a partial WHERE clause on a regular CREATE INDEX"
        );
    }

    #[test]
    fn test_postgres_mesh_route_dispatch_index_is_partial() {
        let builder = V001SqlBuilder::new("postgres");
        let sql = builder.mesh_route_dispatch_index_sql();
        assert!(
            sql.contains("idx_plugin_configs_plugin_name_enabled"),
            "Postgres must create the mesh_route_dispatch perf index"
        );
        assert!(
            sql.contains("(plugin_name)") && sql.contains("WHERE enabled = 1"),
            "Postgres should use a partial index keyed on plugin_name filtered by enabled = 1"
        );
    }

    #[test]
    fn test_sqlite_mesh_route_dispatch_index_is_partial() {
        let builder = V001SqlBuilder::new("sqlite");
        let sql = builder.mesh_route_dispatch_index_sql();
        assert!(
            sql.contains("idx_plugin_configs_plugin_name_enabled"),
            "SQLite must create the mesh_route_dispatch perf index"
        );
        assert!(
            sql.contains("(plugin_name)") && sql.contains("WHERE enabled = 1"),
            "SQLite should use a partial index keyed on plugin_name filtered by enabled = 1"
        );
    }

    // ------------------------------------------------------------------
    // Column-sizing regression tests for the V001 baseline.
    //
    // Code in `src/config/types.rs` enforces hard caps that exceed MySQL's
    // `TEXT` (65,535 bytes). The matching columns must be `MEDIUMTEXT` or
    // larger, otherwise valid payloads round-trip-fail with a truncation
    // error on MySQL.
    // ------------------------------------------------------------------

    #[test]
    fn test_mysql_plugin_configs_config_holds_one_mib_cap() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_plugin_configs_sql();
        assert!(
            sql.contains("config MEDIUMTEXT NOT NULL"),
            "MAX_PLUGIN_CONFIG_SIZE = 1 MiB exceeds MySQL TEXT (65,535 bytes); plugin_configs.config must be MEDIUMTEXT"
        );
    }

    #[test]
    fn test_mysql_consumers_credentials_holds_64kib_cap() {
        // MAX_CREDENTIALS_SIZE = 65_536 is exactly 1 byte over MySQL TEXT's
        // 65,535-byte ceiling. MEDIUMTEXT removes the off-by-one risk.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_consumers_sql();
        assert!(
            sql.contains("credentials MEDIUMTEXT NOT NULL"),
            "MAX_CREDENTIALS_SIZE = 65,536 is over MySQL TEXT (65,535); credentials must be MEDIUMTEXT"
        );
    }

    #[test]
    fn test_mysql_consumers_acl_groups_holds_worst_case_payload() {
        // 500 groups × 255 chars + JSON quoting ≈ 130 KiB worst case.
        // The previous VARCHAR(8192) silently truncated at scale.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_consumers_sql();
        assert!(
            sql.contains("acl_groups MEDIUMTEXT NOT NULL"),
            "ACL groups JSON worst case (~130 KiB) exceeds VARCHAR(8192) and MySQL TEXT; must be MEDIUMTEXT"
        );
        assert!(
            !sql.contains("VARCHAR(8192)"),
            "acl_groups must no longer use VARCHAR(8192)"
        );
    }

    #[test]
    fn test_mysql_upstreams_targets_holds_max_targets_payload() {
        // MAX_TARGETS_PER_UPSTREAM = 1000 with full TLS/SAN metadata exceeds
        // MySQL TEXT (65,535 bytes) at the upper bound.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_upstreams_sql();
        assert!(
            sql.contains("targets MEDIUMTEXT NOT NULL"),
            "upstreams.targets with MAX_TARGETS_PER_UPSTREAM = 1000 can exceed MySQL TEXT; must be MEDIUMTEXT"
        );
    }

    #[test]
    fn test_mysql_proxies_listen_path_has_headroom() {
        // MAX_LISTEN_PATH_LENGTH = 500; VARCHAR(512) gives headroom matching
        // the project's elsewhere-applied "1+ char buffer" convention.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_proxies_sql();
        assert!(
            sql.contains("listen_path VARCHAR(512)"),
            "listen_path should be VARCHAR(512) (MAX_LISTEN_PATH_LENGTH + headroom)"
        );
        assert!(
            !sql.contains("listen_path VARCHAR(500)"),
            "listen_path VARCHAR(500) has zero headroom over the code cap"
        );
    }

    #[test]
    fn test_proxy_route_lock_table_uses_compact_route_hash_key() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_proxy_route_locks_sql();
            assert!(
                sql.contains("proxy_route_locks"),
                "{dialect} must create the route-lock table"
            );
            assert!(
                sql.contains("route_key_hash"),
                "{dialect} must key route locks by the compact route hash"
            );
            assert!(
                sql.contains("PRIMARY KEY (namespace, route_key_hash)"),
                "{dialect} must serialize writers per namespace and route bucket"
            );
        }
    }

    #[test]
    fn test_mtls_dns_admission_lock_table_is_namespace_scoped() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_mtls_dns_admission_locks_sql();
            assert!(
                sql.contains("mtls_dns_admission_locks"),
                "{dialect} must create the mTLS DNS admission lock table"
            );
            assert!(
                sql.contains("namespace") && sql.contains("PRIMARY KEY"),
                "{dialect} must serialize mTLS DNS admission per namespace"
            );
            assert!(
                sql.contains("restore_owner"),
                "{dialect} must persist the whole-rollback guard owner"
            );
        }
    }

    // ------------------------------------------------------------------
    // Collation regression tests
    //
    // MySQL identifier and hostname VARCHAR columns must use explicit
    // `COLLATE utf8mb4_bin` so uniqueness on `(namespace, name)` and
    // similar is truly byte-exact (including NFC vs NFD), matching
    // PostgreSQL/SQLite and the runtime identity indexes. A UCA
    // collation such as `utf8mb4_0900_as_cs` is not byte-exact.
    // MySQL 8.0+ floor; the project test infra already runs MySQL 8
    // (tests/scripts/setup_db_tls.sh).
    // ------------------------------------------------------------------

    fn assert_columns_have_collation(sql: &str, table_label: &str, columns: &[&str]) {
        for col in columns {
            let needles = [
                format!("{col} VARCHAR(255) COLLATE utf8mb4_bin"),
                format!("{col} VARCHAR(50) COLLATE utf8mb4_bin"),
                format!("{col} VARCHAR(64) COLLATE utf8mb4_bin"),
                format!("{col} VARCHAR(36) COLLATE utf8mb4_bin"),
            ];
            assert!(
                needles.iter().any(|n| sql.contains(n)),
                "{table_label}.{col} must have an explicit COLLATE utf8mb4_bin clause"
            );
        }
        assert!(
            !sql.contains("utf8mb4_0900_as_cs"),
            "{table_label} must not keep the non-byte-exact utf8mb4_0900_as_cs collation"
        );
    }

    #[test]
    fn test_mysql_proxies_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_proxies_sql();
        assert_columns_have_collation(
            sql,
            "proxies",
            &[
                "id",
                "namespace",
                "name",
                "backend_host",
                "upstream_id",
                "upstream_subset",
                "api_spec_id",
            ],
        );
    }

    #[test]
    fn test_mysql_upstreams_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_upstreams_sql();
        assert_columns_have_collation(
            sql,
            "upstreams",
            &["id", "namespace", "name", "backend_tls_sni", "api_spec_id"],
        );
    }

    #[test]
    fn test_mysql_consumers_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_consumers_sql();
        assert_columns_have_collation(
            sql,
            "consumers",
            &["id", "namespace", "username", "custom_id"],
        );
    }

    #[test]
    fn test_mysql_consumer_credential_index_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_consumer_credential_index_sql();
        assert_columns_have_collation(
            sql,
            "consumer_credential_index",
            &[
                "namespace",
                "credential_type",
                "credential_hash",
                "consumer_id",
            ],
        );
    }

    #[test]
    fn test_mysql_consumer_identity_index_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_consumer_identity_index_sql();
        assert_columns_have_collation(
            sql,
            "consumer_identity_index",
            &["namespace", "identity_value", "consumer_id"],
        );
    }

    #[test]
    fn test_mysql_plugin_configs_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_plugin_configs_sql();
        assert_columns_have_collation(
            sql,
            "plugin_configs",
            &["id", "namespace", "plugin_name", "proxy_id", "api_spec_id"],
        );
    }

    #[test]
    fn test_mysql_api_specs_collation_on_identifier_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_api_specs_sql();
        assert_columns_have_collation(
            sql,
            "api_specs",
            &[
                "id",
                "namespace",
                "proxy_id",
                "content_hash",
                "spec_version",
            ],
        );
    }

    #[test]
    fn test_mysql_proxy_plugins_collation_on_fk_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_proxy_plugins_sql();
        assert_columns_have_collation(sql, "proxy_plugins", &["proxy_id", "plugin_config_id"]);
    }

    #[test]
    fn test_mysql_proxy_route_locks_collation_on_key_columns() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_proxy_route_locks_sql();
        assert_columns_have_collation(sql, "proxy_route_locks", &["namespace", "route_key_hash"]);
    }

    #[test]
    fn test_mysql_mtls_dns_admission_locks_collation_on_namespace() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_mtls_dns_admission_locks_sql();
        assert_columns_have_collation(
            sql,
            "mtls_dns_admission_locks",
            &["namespace", "restore_owner"],
        );
    }

    #[test]
    fn test_non_mysql_dialects_have_no_mysql_collation_clause() {
        for dialect in ["postgres", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            for sql in [
                builder.create_upstreams_sql(),
                builder.create_consumers_sql(),
                builder.create_consumer_credential_index_sql(),
                builder.create_consumer_identity_index_sql(),
                builder.create_proxies_sql(),
                builder.create_proxy_route_locks_sql(),
                builder.create_mtls_dns_admission_locks_sql(),
                builder.create_plugin_configs_sql(),
                builder.create_proxy_plugins_sql(),
                builder.create_api_specs_sql(),
            ] {
                assert!(
                    !sql.contains("utf8mb4_bin") && !sql.contains("utf8mb4_0900_as_cs"),
                    "{dialect} dialect must not carry MySQL-specific COLLATE clauses"
                );
            }
        }
    }

    #[test]
    fn test_sqlite_builder_uses_sqlite_specific_behavior() {
        let builder = V001SqlBuilder::new("sqlite");
        assert!(matches!(builder.dialect, SqlDialect::Sqlite));
        assert!(
            builder
                .create_upstreams_sql()
                .contains("DEFAULT CURRENT_TIMESTAMP")
        );
        assert!(
            builder
                .unique_listen_port_sql()
                .contains("WHERE listen_port IS NOT NULL")
        );
    }

    #[test]
    fn test_postgres_builder_uses_partial_unique_indexes() {
        let builder = V001SqlBuilder::new("postgres");
        assert!(matches!(builder.dialect, SqlDialect::Postgres));
        assert!(
            builder
                .namespace_unique_index_sqls()
                .iter()
                .any(|sql| sql.contains("WHERE name IS NOT NULL"))
        );
    }

    // ------------------------------------------------------------------
    // FK constraint consistency regression tests
    //
    // These verify that all three dialects define the same FK references
    // with the same ON DELETE actions, preventing accidental divergence
    // when editing one dialect branch but not the others.
    // ------------------------------------------------------------------

    /// Helper: checks that `sql` contains a REFERENCES clause pointing at
    /// `target_table(target_col)` with the given `on_delete` action.
    ///
    /// Works for both MySQL-style (`FOREIGN KEY (col) REFERENCES t(c)`)
    /// and inline-style (`col TYPE REFERENCES t(c)`).
    fn assert_fk_present(sql: &str, target_table: &str, target_col: &str, on_delete: &str) {
        let needle = format!("REFERENCES {target_table}({target_col}) ON DELETE {on_delete}");
        assert!(
            sql.contains(&needle),
            "expected FK clause '{}' not found in:\n{}",
            needle,
            sql
        );
    }

    #[test]
    fn test_fk_proxies_upstream_consistent_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_proxies_sql();
            assert_fk_present(sql, "upstreams", "id", "RESTRICT");
        }
    }

    #[test]
    fn test_fk_plugin_configs_proxy_consistent_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_plugin_configs_sql();
            assert_fk_present(sql, "proxies", "id", "CASCADE");
        }
    }

    #[test]
    fn test_fk_proxy_plugins_consistent_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_proxy_plugins_sql();
            // Both FKs in the junction table must be CASCADE
            assert_fk_present(sql, "proxies", "id", "CASCADE");
            assert_fk_present(sql, "plugin_configs", "id", "CASCADE");
        }
    }

    #[test]
    fn test_fk_consumer_index_tables_consistent_across_dialects() {
        // Both consumer index tables must FK the composite consumers PK
        // (namespace, id) with ON DELETE CASCADE in every dialect.
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            assert_fk_present(
                builder.create_consumer_credential_index_sql(),
                "consumers",
                "namespace, id",
                "CASCADE",
            );
            assert_fk_present(
                builder.create_consumer_identity_index_sql(),
                "consumers",
                "namespace, id",
                "CASCADE",
            );
        }
    }

    #[test]
    fn test_fk_count_matches_across_dialects() {
        // Every dialect must define exactly 6 FK references (counted by
        // occurrences of "REFERENCES" in the combined CREATE TABLE SQL):
        // the 4 proxy/plugin FKs plus the two composite consumer-index FKs.
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let all_sql = [
                builder.create_upstreams_sql(),
                builder.create_consumers_sql(),
                builder.create_consumer_credential_index_sql(),
                builder.create_consumer_identity_index_sql(),
                builder.create_proxies_sql(),
                builder.create_plugin_configs_sql(),
                builder.create_proxy_plugins_sql(),
            ]
            .join("\n");

            let count = all_sql.matches("REFERENCES").count();
            assert_eq!(
                count, 6,
                "{dialect} dialect has {count} FK REFERENCES clauses, expected 6"
            );
        }
    }

    // ------------------------------------------------------------------
    // Per-namespace consumer identity schema (issue #2121)
    // ------------------------------------------------------------------

    #[test]
    fn test_consumers_primary_key_is_composite_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_consumers_sql();
            assert!(
                sql.contains("PRIMARY KEY (namespace, id)"),
                "{dialect} consumers table must declare a composite PRIMARY KEY (namespace, id)"
            );
            assert!(
                !sql.contains("id TEXT PRIMARY KEY")
                    && !sql.contains("COLLATE utf8mb4_bin PRIMARY KEY"),
                "{dialect} consumers table must not keep a single-column id PRIMARY KEY"
            );
        }
    }

    #[test]
    fn test_consumer_identity_index_table_shape_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_consumer_identity_index_sql();
            assert!(
                sql.contains("consumer_identity_index"),
                "{dialect} must create the consumer_identity_index table"
            );
            assert!(
                sql.contains("PRIMARY KEY (namespace, identity_value)"),
                "{dialect} consumer_identity_index PK must be (namespace, identity_value) so \
                 cross-field identity collisions are rejected at persistence level"
            );
            for column in ["namespace", "identity_value", "consumer_id", "created_at"] {
                assert!(
                    sql.contains(column),
                    "{dialect} consumer_identity_index must carry the {column} column"
                );
            }
        }
    }
}
