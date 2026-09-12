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
//! - identifier / hostname VARCHAR columns use `COLLATE utf8mb4_0900_bin` so
//!   uniqueness and ordering on `(namespace, name)` etc. is truly byte-exact
//!   (matching PostgreSQL `texteq` and SQLite BINARY), not merely accent-/
//!   case-sensitive UCA comparison. `utf8mb4_0900_as_cs` treats canonically
//!   equivalent Unicode sequences (NFC vs NFD) as equal, while the older
//!   `utf8mb4_bin` has `PAD SPACE` semantics that ignore trailing spaces;
//!   both diverge from the runtime's byte-keyed identity indexes. Hostnames
//!   are pre-normalized to ASCII-lowercase by `normalize_fields()`, so
//!   case-sensitivity is moot for those, but other identifiers benefit.
//!   Floor is MySQL 8.0.17+ (`utf8mb4_0900_bin` was introduced then); the
//!   project test infra runs MySQL 8.4.
//! - columns whose code-side cap exceeds MySQL's `TEXT` (65,535 bytes) use
//!   `MEDIUMTEXT` (16 MiB): `plugin_configs.config` (1 MiB cap),
//!   `consumers.credentials` (64 KiB cap — off-by-one over `TEXT`),
//!   `consumers.acl_groups` (≈130 KiB worst case), `upstreams.targets`
//!   (1000 targets ≈ 200 KiB), `upstreams.backend_tls_san_allow_list`,
//!   the six proxy/upstream `backend_tls_*` material path/PEM columns
//!   (`MAX_TLS_INLINE_PEM_LENGTH` = 1 MiB), `upstreams.subsets` (uncapped
//!   label-set serialization), and `proxies.allowed_ws_origins` (uncapped
//!   admitted JSON), and `proxies.stream_match` (bounded matcher JSON).
//!
//! The proxy schema intentionally omits *unique* indexes on both
//! `(namespace, listen_path)` and `(namespace, listen_port)`: HTTP path
//! uniqueness is host-scoped, while multiple stream proxies may deliberately
//! form one validated SNI/L4 listener group on a port. Non-unique secondary
//! indexes cover both candidate scans under the namespace admission lease.
//! MySQL uses a
//! 255-character `listen_path` prefix because InnoDB appends the primary key to
//! secondary-index records; full namespace + path + primary-key columns can
//! exceed its 3072-byte key limit. The composite `PRIMARY KEY (namespace, id)`
//! does not change that budget: InnoDB only appends the clustered-index columns
//! a secondary index does not already carry, and every index whose length is
//! near the limit already leads with `namespace`. The query retains its full
//! `listen_path = ?` predicate, so prefix collisions are filtered correctly.
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
//! | Table                     | Column(s)                     | References                     | ON DELETE |
//! |---------------------------|-------------------------------|--------------------------------|-----------|
//! | proxies                   | (namespace, upstream_id)      | upstreams(namespace, id)       | RESTRICT  |
//! | plugin_configs            | (namespace, proxy_id)         | proxies(namespace, id)         | CASCADE   |
//! | proxy_plugins             | (namespace, proxy_id)         | proxies(namespace, id)         | CASCADE   |
//! | proxy_plugins             | (namespace, plugin_config_id) | plugin_configs(namespace, id)  | CASCADE   |
//! | api_specs                 | (namespace, proxy_id)         | proxies(namespace, id)         | CASCADE   |
//! | consumer_credential_index | (namespace, consumer_id)      | consumers(namespace, id)       | CASCADE   |
//! | consumer_identity_index   | (namespace, consumer_id)      | consumers(namespace, id)       | CASCADE   |
//!
//! ## Namespace-scoped resource identity
//!
//! `proxies`, `upstreams`, `plugin_configs`, `api_specs`, and `consumers` all
//! use a composite `PRIMARY KEY (namespace, id)`. `consumers` got there first
//! (issue #2121); the other four followed in issue #4627 so durable identity
//! matches `GatewayConfig::validate_unique_resource_ids`, which has always
//! permitted the same resource id in two tenants. Every relationship above is
//! therefore namespace-qualified: an association can never bind across
//! tenants, and one tenant cannot squat a bare id another tenant needs.
//!
//! `proxy_plugins` carries its own `namespace` column and a
//! `PRIMARY KEY (namespace, proxy_id, plugin_config_id)`. Both of its foreign
//! keys reuse that single column, so a junction row is structurally incapable
//! of joining a proxy in one namespace to a plugin config in another.
//!
//! Nullable child columns (`proxies.upstream_id`, `plugin_configs.proxy_id`)
//! keep the SQL default MATCH SIMPLE semantics: when any column of the child
//! key is NULL the constraint is not checked, which is exactly the
//! "unattached resource" case these columns model.
//!
//! Because `namespace` participates in every one of these keys, an in-place
//! `UPDATE <table> SET namespace = ?` can no longer be used to rename a
//! namespace — there is no ordering of such updates that keeps every
//! constraint satisfied. `DatabaseStore::rename_namespace_in_tx` copies the
//! rows parent-first under the new name and then deletes the old ones, the
//! same shape `consumers` and `gateway_trust_bundles` already used.
//!
//! Named constraints on MySQL (e.g. `fk_proxies_upstream`) are cosmetic; they
//! aid `ALTER TABLE DROP CONSTRAINT` but do not change enforcement behavior.
//! The inline tests below regression-guard this cross-dialect consistency.

use crate::config::db_loader::{
    CONFIG_ADMISSION_LEASE_DURATION_MILLIS, config_admission_lease_acquire_sql,
    config_admission_lease_now_sql, rewrite_query_placeholders,
};
use crate::config::namespace_registry::{
    NAMESPACE_REGISTRY_ADMISSION_KEY, NamespaceRegistryCorrupt, require_namespace_identity,
};
use sqlx::{AnyConnection, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDialect {
    Postgres,
    MySql,
    Sqlite,
}

/// Result of the shared pin / scan / seed / marker / proof sequence, before
/// the dialect-specific commit boundary is applied.
enum NamespacesRegistryBackfillOutcome {
    Apply,
    Defer,
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

    /// Idempotently reconcile baseline tables/indexes that were folded into
    /// V001 *after* some databases had already recorded V001 in
    /// `_ferrum_migrations`.
    ///
    /// During build-out, schema additions are folded into the V001 baseline
    /// rather than carried as upgrade migrations (see the project build-out
    /// policy). The migration runner skips V001 entirely once version 1 is
    /// recorded, so a table or changed baseline index here would never reach an
    /// already-initialized database. Re-running this idempotent reconciliation
    /// pass on every startup guarantees current baseline tables and indexes are
    /// present (and obsolete baseline constraints are absent) regardless of
    /// when V001 was recorded. Every statement here must tolerate re-run so the
    /// pass is safe on fresh databases that just applied V001.
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
        sqlx::query(self.create_audit_events_sql())
            .execute(&mut *connection)
            .await?;
        self.ensure_audit_event_context_columns(connection).await?;
        self.create_audit_event_indexes(connection).await?;
        self.remove_obsolete_listen_port_uniqueness(connection)
            .await?;
        self.create_full_load_indexes(connection).await?;
        self.create_config_change_indexes(connection).await?;
        self.ensure_namespaces_registry(connection).await?;
        Ok(())
    }

    async fn ensure_audit_event_context_columns(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        let columns = if self.is_mysql() {
            [
                (
                    "namespace_at_event",
                    "VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT ''",
                ),
                (
                    "source_address",
                    "VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT ''",
                ),
                (
                    "request_id",
                    "VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT ''",
                ),
                (
                    "outcome",
                    "VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT ''",
                ),
            ]
        } else {
            [
                ("namespace_at_event", "TEXT NOT NULL DEFAULT ''"),
                ("source_address", "TEXT NOT NULL DEFAULT ''"),
                ("request_id", "TEXT NOT NULL DEFAULT ''"),
                ("outcome", "TEXT NOT NULL DEFAULT ''"),
            ]
        };

        for (name, definition) in columns {
            if self.audit_event_column_exists(connection, name).await? {
                continue;
            }

            let sql = format!("ALTER TABLE audit_events ADD COLUMN {name} {definition}");
            if let Err(error) = sqlx::query(&sql).execute(&mut *connection).await {
                // Concurrent gateway startups can both observe an old schema.
                // Accept a racing ALTER only after confirming the column now exists.
                if !self.audit_event_column_exists(connection, name).await? {
                    return Err(error.into());
                }
            }
        }

        Ok(())
    }

    async fn audit_event_column_exists(
        &self,
        connection: &mut AnyConnection,
        column: &str,
    ) -> Result<bool, anyhow::Error> {
        if self.is_sqlite() {
            let rows = sqlx::query("PRAGMA table_info(audit_events)")
                .fetch_all(&mut *connection)
                .await?;
            return Ok(rows.iter().any(|row| {
                row.try_get::<String, _>("name")
                    .is_ok_and(|name| name == column)
            }));
        }

        Ok(sqlx::query(self.audit_event_column_exists_sql())
            .bind(column)
            .fetch_optional(&mut *connection)
            .await?
            .is_some())
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
            // gateway_trust_bundles is the authoritative namespace-keyed
            // gateway/mesh trust resource (issue #3727). It has no foreign keys
            // in either direction: trust is namespace-scoped, not proxy-scoped,
            // and must survive a full resource clear so a restore cannot
            // silently drop a namespace's roots.
            self.create_gateway_trust_bundles_sql(),
            // First-class namespace registry (issue #3955). Empty tenants can
            // exist before any resource row is written; GET /namespaces unions
            // this table with the derived resource-table names.
            self.create_namespaces_sql(),
            // One-time compatibility-state for folded-in baseline work such as
            // the namespace-registry backfill. Not a tenant table.
            self.create_schema_compat_sql(),
        ] {
            sqlx::query(sql).execute(&mut *connection).await?;
        }

        Ok(())
    }

    async fn create_indexes(&self, connection: &mut AnyConnection) -> Result<(), anyhow::Error> {
        let indexes = [
            // Relationship indexes lead with `namespace` because every
            // relationship key is `(namespace, id)` (issue #4627): they serve
            // the namespace-scoped reference scans AND satisfy MySQL's
            // requirement that a foreign key's referencing columns have an
            // index whose leftmost prefix is the FK column list.
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_upstream_id ON proxies (namespace, upstream_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_proxy_id ON plugin_configs (namespace, proxy_id)",
            // `proxy_plugins` PRIMARY KEY (namespace, proxy_id, plugin_config_id)
            // already covers the (namespace, proxy_id) foreign key; this index
            // covers the (namespace, plugin_config_id) one.
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_ns_plugin_config_id ON proxy_plugins (namespace, plugin_config_id)",
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
            // pattern. Since issue #4627 the four resource tables carry a
            // composite `PRIMARY KEY (namespace, id)` that already covers it,
            // but these explicit indexes are kept — matching the `consumers`
            // precedent from issue #2121 — so a database that recorded V001
            // before the composite keys were folded in still gets them from
            // the compatibility pass in `create_full_load_indexes`.
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_id ON proxies (namespace, id)",
            // Non-unique: host-overlap uniqueness stays application-enforced
            // under the route-bucket lock. This secondary index covers
            // `listen_path_candidate_sql` equality on `(namespace, listen_path)`.
            self.proxies_ns_listen_path_index_sql(),
            // Non-unique: stream-listener group validity is application-enforced
            // from the exact post-mutation namespace snapshot. Multiple SNI/L4
            // route rows may intentionally share this key.
            self.proxies_ns_listen_port_index_sql(),
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_id ON consumers (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_id ON plugin_configs (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_id ON upstreams (namespace, id)",
            "CREATE INDEX IF NOT EXISTS idx_config_changes_ns_sequence ON config_changes (namespace, sequence)",
            "CREATE INDEX IF NOT EXISTS idx_config_changes_sequence ON config_changes (sequence)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_scope ON plugin_configs (namespace, scope)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_scope_id ON plugin_configs (scope, id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_plugin_name ON plugin_configs (namespace, plugin_name)",
            // Cold-path index for the `mesh_route_dispatch` upstream-reference
            // lookups in `mesh_route_dispatch_plugin_configs_tx` and
            // `ensure_no_external_spec_upstream_refs_tx`. Since issue #4627 an
            // upstream id is only unique within its namespace, so those helpers
            // add a `namespace = ?` predicate on top of this index rather than
            // scanning every tenant. MongoDB has a matching
            // `{plugin_name, enabled}` partial
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
            // run WHERE namespace = ? AND api_spec_id = ? against these tables.
            // Without indexes, those queries are full-table scans that grow
            // with overall config volume, not spec count.
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_api_spec_id ON proxies (namespace, api_spec_id)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_api_spec_id ON plugin_configs (namespace, api_spec_id)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_api_spec_id ON upstreams (namespace, api_spec_id)",
        ];

        for idx_sql in indexes {
            self.execute_index_sql(connection, idx_sql).await?;
        }
        self.create_audit_event_indexes(connection).await?;

        Ok(())
    }

    async fn create_unique_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
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

    async fn create_audit_event_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        for idx_sql in self.audit_event_index_sqls() {
            self.execute_index_sql(connection, idx_sql).await?;
        }

        Ok(())
    }

    fn audit_event_index_sqls(&self) -> &'static [&'static str] {
        &[
            "CREATE INDEX IF NOT EXISTS idx_audit_events_namespace_ts_id ON audit_events (namespace, ts, id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor)",
            "CREATE INDEX IF NOT EXISTS idx_audit_events_resource_type ON audit_events (resource_type)",
        ]
    }

    async fn create_full_load_indexes(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_id ON proxies (namespace, id)",
            // Also run on the compatibility pass so databases that recorded
            // V001 before this secondary index was folded into the baseline
            // receive it without a new migration.
            self.proxies_ns_listen_path_index_sql(),
            self.proxies_ns_listen_port_index_sql(),
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

    /// Remove the former V001 uniqueness constraint before installing the
    /// non-unique listener-group lookup index. This stays in the idempotent
    /// baseline compatibility pass rather than introducing a new migration:
    /// build-out databases that already recorded V001 must not keep rejecting
    /// the shared SNI/L4 rows the current baseline admits.
    async fn remove_obsolete_listen_port_uniqueness(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        if self.is_mysql() {
            match sqlx::query("DROP INDEX idx_proxies_unique_listen_port ON proxies")
                .execute(&mut *connection)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    // MySQL error 1091: index does not exist. The compatibility
                    // pass runs on every startup, so absence is the steady state.
                    if !error.to_string().contains("1091") {
                        return Err(error.into());
                    }
                }
            }
        } else {
            sqlx::query("DROP INDEX IF EXISTS idx_proxies_unique_listen_port")
                .execute(&mut *connection)
                .await?;
        }
        Ok(())
    }

    fn is_mysql(&self) -> bool {
        matches!(self.dialect, SqlDialect::MySql)
    }

    fn is_sqlite(&self) -> bool {
        matches!(self.dialect, SqlDialect::Sqlite)
    }

    fn audit_event_column_exists_sql(&self) -> &'static str {
        if self.is_mysql() {
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'audit_events' \
             AND column_name = ?"
        } else {
            // Postgres native placeholders are $1..$n; a trailing `?` is parsed
            // as an incomplete operator and fails with "syntax error at end of input".
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'audit_events' \
             AND column_name = $1"
        }
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

    fn proxies_ns_listen_path_index_sql(&self) -> &'static str {
        match self.dialect {
            // InnoDB secondary-index records include the table's primary key.
            // namespace(255) + listen_path(255) + id(255) under utf8mb4 is
            // 3060 bytes, below the 3072-byte default-page limit. The full
            // equality predicate remains in the query as a residual filter.
            SqlDialect::MySql => {
                "CREATE INDEX IF NOT EXISTS idx_proxies_ns_listen_path ON proxies (namespace, listen_path(255))"
            }
            SqlDialect::Postgres | SqlDialect::Sqlite => {
                "CREATE INDEX IF NOT EXISTS idx_proxies_ns_listen_path ON proxies (namespace, listen_path)"
            }
        }
    }

    fn proxies_ns_listen_port_index_sql(&self) -> &'static str {
        "CREATE INDEX IF NOT EXISTS idx_proxies_ns_listen_port ON proxies (namespace, listen_port)"
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
                labels MEDIUMTEXT NOT NULL DEFAULT ('{}'),
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255) COLLATE utf8mb4_0900_bin,
                targets MEDIUMTEXT NOT NULL,
                algorithm VARCHAR(50) NOT NULL DEFAULT 'round_robin',
                hash_on TEXT,
                hash_on_cookie_config TEXT,
                health_checks TEXT,
                service_discovery TEXT,
                subsets MEDIUMTEXT,
                backend_tls_client_cert_path MEDIUMTEXT,
                backend_tls_client_key_path MEDIUMTEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path MEDIUMTEXT,
                backend_tls_sni VARCHAR(255) COLLATE utf8mb4_0900_bin,
                backend_tls_san_allow_list MEDIUMTEXT,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, id)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                labels TEXT NOT NULL DEFAULT ('{}'),
                id TEXT NOT NULL,
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
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id)
            )
            "#
        }
    }

    /// First-class namespace registry (issue #3955). `name` is the PRIMARY KEY
    /// and uses the same identifier collation as other tenant keys.
    fn create_namespaces_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS namespaces (
                name VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                description TEXT,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (name)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS namespaces (
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (name)
            )
            "#
        }
    }

    /// Idempotent create + one-time backfill for databases that recorded V001
    /// before the registry table was folded into the baseline.
    ///
    /// The first successful compatibility pass inserts every pre-existing
    /// derived namespace plus canonical `ferrum`, then durably marks the
    /// backfill complete in `_ferrum_schema_compat`. A failed or partial
    /// attempt leaves that marker absent so a later startup retries
    /// idempotently. Once the marker is present, later connect/migrate/
    /// reconnect/startup passes do not reseed deleted names or materialize
    /// newer derived-only names.
    async fn ensure_namespaces_registry(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(self.create_namespaces_sql())
            .execute(&mut *connection)
            .await?;
        sqlx::query(self.create_schema_compat_sql())
            .execute(&mut *connection)
            .await?;
        self.run_serialized_namespaces_registry_backfill(connection)
            .await
    }

    /// Run the one-time compatibility pass under the SAME global
    /// `!namespace-registry` admission lease every live create / rename /
    /// delete takes.
    ///
    /// Without that lease the pass reads derived names and inserts registry
    /// rows outside the authority live namespace CRUD serializes on, so a
    /// confirmed `DELETE /namespaces/{name}` could commit between the read and
    /// the insert and have its row resurrected before the completion marker
    /// landed. The lease is the whole fence: it is the first key in the
    /// established total lock order (global first, then affected names
    /// ascending), so taking only it can never invert that order or deadlock
    /// against a concurrent registry mutation. It is a datastore row, not a
    /// process-local mutex, so it serializes across gateway processes as well.
    ///
    /// Holding the lease is not by itself enough, because a lease can lapse:
    /// [`Self::backfill_namespaces_registry`] additionally verifies and LOCKS
    /// that row as the first statement of its transaction, so a competing
    /// acquisition cannot cross the derived-name scan even if the pass outruns
    /// the lease duration.
    ///
    /// A lease held elsewhere is not an error: the completion marker stays
    /// absent, which is exactly the crash-retry state, and the next
    /// connect / migrate / reconnect pass tries again.
    async fn run_serialized_namespaces_registry_backfill(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        // Unfenced fast path. On every startup after the first completed pass
        // this single SELECT is the entire cost of the backfill. It is only an
        // optimization: the authoritative check runs inside the fenced
        // transaction, so two processes cannot both seed.
        if self
            .namespaces_registry_backfill_completed(connection)
            .await?
        {
            return Ok(());
        }

        let owner = uuid::Uuid::new_v4().to_string();
        let Some(generation) = self
            .try_acquire_namespaces_registry_backfill_lease(connection, &owner)
            .await?
        else {
            tracing::info!(
                "Namespace registry compatibility backfill deferred: the global registry \
                 admission lease is held by another mutation; a later startup retries"
            );
            return Ok(());
        };

        // Always release, on success AND on error, so a failed pass cannot hold
        // the global registry key for the rest of its lease and stall live
        // namespace CRUD. Lease expiry stays the backstop for a hard crash.
        let backfill = self
            .backfill_namespaces_registry(connection, &owner, generation)
            .await;
        let release = self
            .release_namespaces_registry_backfill_lease(connection, &owner)
            .await;
        match (backfill, release) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(backfill_error), _) => Err(backfill_error),
            (Ok(()), Err(release_error)) => Err(release_error),
        }
    }

    /// Conditionally take the global registry admission lease.
    ///
    /// Returns the acquired generation, or `None` when an unexpired owner still
    /// holds it. The statement itself never steals an unexpired lease — it is
    /// the identical acquisition the runtime store uses for namespace
    /// admission, so both paths share one ownership rule.
    async fn try_acquire_namespaces_registry_backfill_lease(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
    ) -> Result<Option<i64>, anyhow::Error> {
        let acquire_sql = config_admission_lease_acquire_sql(self.db_type());
        sqlx::query(&acquire_sql)
            .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
            .bind(owner)
            .bind(CONFIG_ADMISSION_LEASE_DURATION_MILLIS)
            .execute(&mut *connection)
            .await?;

        let now = config_admission_lease_now_sql(self.db_type());
        let sql = self.q(&format!(
            "SELECT generation FROM config_admission_locks \
             WHERE namespace = ? AND owner = ? AND expires_at > {now}"
        ));
        let generation = sqlx::query_scalar::<_, i64>(&sql)
            .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
            .bind(owner)
            .fetch_optional(&mut *connection)
            .await;
        match generation {
            Ok(generation) => Ok(generation),
            Err(error) => {
                // The acquisition statement may already have taken the row, so
                // an ambiguous lookup must not leave the global registry key
                // owned for a full lease duration.
                self.release_namespaces_registry_backfill_lease(connection, owner)
                    .await?;
                Err(error.into())
            }
        }
    }

    async fn release_namespaces_registry_backfill_lease(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
    ) -> Result<(), anyhow::Error> {
        let sql = self.q("UPDATE config_admission_locks SET expires_at = 0 \
             WHERE namespace = ? AND owner = ?");
        sqlx::query(&sql)
            .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
            .bind(owner)
            .execute(&mut *connection)
            .await?;
        Ok(())
    }

    /// Verify AND transactionally pin the global registry lease row as the
    /// FIRST statement of the backfill transaction, before anything is scanned
    /// or inserted.
    ///
    /// This is the whole fence. Verification alone at the commit boundary is
    /// not enough: a competing acquirer could take the global key while the
    /// derived-name scan runs and commit a namespace delete, and the scan's
    /// pre-delete name set would then be inserted. Locking the row up front
    /// makes that impossible — every competing acquisition is a write to this
    /// exact row (`INSERT ... ON CONFLICT/DUPLICATE KEY UPDATE` on the
    /// `namespace` primary key), so it blocks until this transaction commits or
    /// rolls back and its mutation is strictly ordered after the pass.
    ///
    /// `FOR UPDATE` is the row lock on PostgreSQL and MySQL. SQLite has no
    /// `FOR UPDATE`, so the equivalent is to promote the deferred transaction
    /// to a **write** transaction here: a conditional `UPDATE` of the same row
    /// takes SQLite's single database writer lock for the rest of the
    /// transaction, which excludes every competing acquisition just as
    /// completely. The renewal it writes is also what keeps the post-commit
    /// lease view sane; correctness does not depend on it.
    ///
    /// A `false` return means the lease was already lost before any work
    /// started (stolen after expiry, or released), so the pass defers.
    async fn pin_namespaces_registry_backfill_lease(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<bool, anyhow::Error> {
        let now = config_admission_lease_now_sql(self.db_type());
        if self.is_sqlite() {
            let sql = self.q(&format!(
                "UPDATE config_admission_locks SET expires_at = {now} + ? \
                 WHERE namespace = ? AND owner = ? AND generation = ? AND expires_at > {now}"
            ));
            let pinned = sqlx::query(&sql)
                .bind(CONFIG_ADMISSION_LEASE_DURATION_MILLIS)
                .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
                .bind(owner)
                .bind(generation)
                .execute(&mut *connection)
                .await?
                .rows_affected();
            return Ok(pinned == 1);
        }
        let sql = self.q(&format!(
            "SELECT 1 FROM config_admission_locks \
             WHERE namespace = ? AND owner = ? AND generation = ? AND expires_at > {now} FOR UPDATE"
        ));
        Ok(sqlx::query(&sql)
            .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
            .bind(owner)
            .bind(generation)
            .fetch_optional(&mut *connection)
            .await?
            .is_some())
    }

    /// Commit-boundary proof that the pinned lease row is still this pass's
    /// own, at the same generation.
    ///
    /// Deliberately NOT predicated on `expires_at`. The row has been pinned by
    /// [`Self::pin_namespaces_registry_backfill_lease`] since before the
    /// derived-name scan, so no competing acquisition can have crossed it, and
    /// ordinary elapsed wall time under that lock is not lost ownership.
    /// Re-checking the TTL here would roll back an otherwise uncontended
    /// backfill that simply took longer than one lease duration — and it would
    /// do so on every retry, starving it forever. Owner and generation are the
    /// real proof: an ownership change is the only thing that can rewrite
    /// either, and nothing can rewrite them while the row is locked.
    ///
    /// `FOR UPDATE` is repeated so the pin is unambiguously still held on the
    /// statement that authorizes the commit; SQLite is still inside the write
    /// transaction the pin opened.
    async fn namespaces_registry_backfill_lease_held(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<bool, anyhow::Error> {
        let for_update = if self.is_sqlite() { "" } else { " FOR UPDATE" };
        let sql = self.q(&format!(
            "SELECT 1 FROM config_admission_locks \
             WHERE namespace = ? AND owner = ? AND generation = ?{for_update}"
        ));
        Ok(sqlx::query(&sql)
            .bind(NAMESPACE_REGISTRY_ADMISSION_KEY)
            .bind(owner)
            .bind(generation)
            .fetch_optional(&mut *connection)
            .await?
            .is_some())
    }

    /// Rewrite `?` placeholders for the active dialect, exactly as the runtime
    /// store does.
    fn q(&self, sql: &str) -> String {
        rewrite_query_placeholders(self.db_type(), sql)
    }

    fn db_type(&self) -> &'static str {
        match self.dialect {
            SqlDialect::Postgres => "postgres",
            SqlDialect::MySql => "mysql",
            SqlDialect::Sqlite => "sqlite",
        }
    }

    fn create_schema_compat_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_schema_compat (
                name VARCHAR(255) NOT NULL,
                completed_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (name)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS _ferrum_schema_compat (
                name TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                PRIMARY KEY (name)
            )
            "#
        }
    }

    async fn namespaces_registry_backfill_completed(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<bool, anyhow::Error> {
        let sql = if self.is_mysql() || self.is_sqlite() {
            "SELECT 1 FROM _ferrum_schema_compat WHERE name = ? LIMIT 1"
        } else {
            "SELECT 1 FROM _ferrum_schema_compat WHERE name = $1 LIMIT 1"
        };
        Ok(sqlx::query(sql)
            .bind(crate::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID)
            .fetch_optional(&mut *connection)
            .await?
            .is_some())
    }

    async fn mark_namespaces_registry_backfill_complete(
        &self,
        connection: &mut AnyConnection,
        completed_at: &str,
    ) -> Result<(), anyhow::Error> {
        let insert_marker = if self.is_mysql() {
            // Duplicate `name` is the only error this no-op UPDATE ignores.
            // `INSERT IGNORE` would also swallow truncation and other
            // integrity failures and could still write the completion marker.
            "INSERT INTO _ferrum_schema_compat (name, completed_at) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE name = _ferrum_schema_compat.name"
        } else if self.is_sqlite() {
            "INSERT INTO _ferrum_schema_compat (name, completed_at) VALUES (?, ?) \
             ON CONFLICT (name) DO NOTHING"
        } else {
            "INSERT INTO _ferrum_schema_compat (name, completed_at) VALUES ($1, $2) \
             ON CONFLICT (name) DO NOTHING"
        };
        sqlx::query(insert_marker)
            .bind(crate::config::namespace_registry::NAMESPACES_REGISTRY_BACKFILL_ID)
            .bind(completed_at)
            .execute(&mut *connection)
            .await?;
        Ok(())
    }

    /// The compatibility pass itself, fenced by `owner`/`generation` on the
    /// global registry admission lease.
    ///
    /// Everything the pass reads and writes — the lease pin, the authoritative
    /// completion check, the derived-name scan, the canonical `ferrum` seed,
    /// and the completion marker — lives inside one atomic unit, so a crash or
    /// an abort leaves the marker absent and the next startup retries the same
    /// idempotent statements. The marker is still written last so the ordering
    /// contract reads the same way it always did.
    ///
    /// PostgreSQL and MySQL commit that unit as ONE explicit transaction.
    /// SQLite cannot: `MigrationConnectionLock` already issued `BEGIN
    /// IMMEDIATE` on this same connection before `run_pending_locked` called
    /// `ensure_compatibility_tables`, and sqlx does not know about that raw
    /// BEGIN, so `connection.begin()` would emit another `BEGIN` and SQLite
    /// would fail with "cannot start a transaction within a transaction". The
    /// SQLite path therefore runs the identical sequence under a SAVEPOINT on
    /// the already-open migration transaction. `RELEASE SAVEPOINT` (success)
    /// or `ROLLBACK TO SAVEPOINT` (defer or failure) never `COMMIT`s or
    /// `ROLLBACK`s the outer `BEGIN IMMEDIATE`; that outer transaction remains
    /// the durable commit boundary via `MigrationConnectionLock::finish`.
    ///
    /// The lease row is verified and locked BEFORE the scan, not only at the
    /// commit boundary, so a competing acquirer cannot take the global key
    /// across the scan and commit a delete the scan's name set would then
    /// resurrect.
    async fn backfill_namespaces_registry(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<(), anyhow::Error> {
        if self.is_sqlite() {
            self.backfill_namespaces_registry_under_sqlite_savepoint(connection, owner, generation)
                .await
        } else {
            self.backfill_namespaces_registry_in_explicit_transaction(connection, owner, generation)
                .await
        }
    }

    /// PostgreSQL / MySQL: one explicit backfill transaction on a connection
    /// that is not already inside `BEGIN IMMEDIATE`.
    async fn backfill_namespaces_registry_in_explicit_transaction(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<(), anyhow::Error> {
        use sqlx::Connection;

        let mut tx = connection.begin().await?;
        match self
            .backfill_namespaces_registry_body(&mut tx, owner, generation)
            .await
        {
            Ok(NamespacesRegistryBackfillOutcome::Apply) => {
                tx.commit().await?;
                Ok(())
            }
            Ok(NamespacesRegistryBackfillOutcome::Defer) => {
                tx.rollback().await?;
                Ok(())
            }
            Err(error) => {
                if tx.rollback().await.is_err() {
                    return Err(error.context("namespace registry backfill rollback also failed"));
                }
                Err(error)
            }
        }
    }

    /// SQLite: run the backfill under a SAVEPOINT on the already-held
    /// `BEGIN IMMEDIATE` migration transaction. This must not call
    /// `connection.begin()`, `COMMIT`, or an unqualified `ROLLBACK`.
    async fn backfill_namespaces_registry_under_sqlite_savepoint(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<(), anyhow::Error> {
        sqlx::query("SAVEPOINT namespaces_registry_backfill")
            .execute(&mut *connection)
            .await?;
        match self
            .backfill_namespaces_registry_body(connection, owner, generation)
            .await
        {
            Ok(NamespacesRegistryBackfillOutcome::Apply) => {
                sqlx::query("RELEASE SAVEPOINT namespaces_registry_backfill")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            }
            Ok(NamespacesRegistryBackfillOutcome::Defer) => {
                self.rollback_sqlite_namespaces_registry_backfill_savepoint(connection)
                    .await
            }
            Err(error) => {
                if self
                    .rollback_sqlite_namespaces_registry_backfill_savepoint(connection)
                    .await
                    .is_err()
                {
                    return Err(
                        error.context("namespace registry backfill savepoint rollback also failed")
                    );
                }
                Err(error)
            }
        }
    }

    async fn rollback_sqlite_namespaces_registry_backfill_savepoint(
        &self,
        connection: &mut AnyConnection,
    ) -> Result<(), anyhow::Error> {
        sqlx::query("ROLLBACK TO SAVEPOINT namespaces_registry_backfill")
            .execute(&mut *connection)
            .await?;
        sqlx::query("RELEASE SAVEPOINT namespaces_registry_backfill")
            .execute(&mut *connection)
            .await?;
        Ok(())
    }

    /// Shared pin / scan / seed / marker / proof sequence. The caller supplies
    /// the atomic unit: an explicit transaction on PostgreSQL/MySQL, or a
    /// SAVEPOINT on the already-open SQLite migration transaction.
    async fn backfill_namespaces_registry_body(
        &self,
        connection: &mut AnyConnection,
        owner: &str,
        generation: i64,
    ) -> Result<NamespacesRegistryBackfillOutcome, anyhow::Error> {
        // Pin FIRST: the fence has to cover the scan, not just the commit.
        if !self
            .pin_namespaces_registry_backfill_lease(connection, owner, generation)
            .await?
        {
            tracing::warn!(
                "Namespace registry compatibility backfill did not start: the global registry \
                 admission lease was no longer held; a later startup retries"
            );
            return Ok(NamespacesRegistryBackfillOutcome::Defer);
        }

        // Authoritative completion check, inside the fence: two processes can
        // never both observe an absent marker and both seed.
        if self
            .namespaces_registry_backfill_completed(connection)
            .await?
        {
            return Ok(NamespacesRegistryBackfillOutcome::Defer);
        }

        let now = chrono::Utc::now().to_rfc3339();
        // Postgres native placeholders are `$1..$n`; a trailing `?` is a
        // syntax error. MySQL has no `ON CONFLICT` — the matching idempotent
        // insert is `ON DUPLICATE KEY UPDATE` of the primary key onto itself,
        // which ignores only that duplicate and surfaces every other error.
        // `INSERT IGNORE` is deliberately not used: it also downgrades
        // truncation and other integrity failures to warnings. SQLite accepts
        // `?` + `ON CONFLICT`.
        let insert_derived = if self.is_mysql() {
            "INSERT INTO namespaces (name, created_at, updated_at) \
             SELECT DISTINCT namespace, ?, ? FROM ( \
                 SELECT namespace FROM proxies \
                 UNION SELECT namespace FROM consumers \
                 UNION SELECT namespace FROM plugin_configs \
                 UNION SELECT namespace FROM upstreams \
                 UNION SELECT namespace FROM gateway_trust_bundles \
             ) AS ferrum_derived_namespaces \
             WHERE namespace IS NOT NULL \
             ON DUPLICATE KEY UPDATE name = namespaces.name"
        } else if self.is_sqlite() {
            "INSERT INTO namespaces (name, created_at, updated_at) \
             SELECT DISTINCT namespace, ?, ? FROM ( \
                 SELECT namespace FROM proxies \
                 UNION SELECT namespace FROM consumers \
                 UNION SELECT namespace FROM plugin_configs \
                 UNION SELECT namespace FROM upstreams \
                 UNION SELECT namespace FROM gateway_trust_bundles \
             ) AS ferrum_derived_namespaces \
             WHERE namespace IS NOT NULL \
             ON CONFLICT (name) DO NOTHING"
        } else {
            "INSERT INTO namespaces (name, created_at, updated_at) \
             SELECT DISTINCT namespace, $1, $2 FROM ( \
                 SELECT namespace FROM proxies \
                 UNION SELECT namespace FROM consumers \
                 UNION SELECT namespace FROM plugin_configs \
                 UNION SELECT namespace FROM upstreams \
                 UNION SELECT namespace FROM gateway_trust_bundles \
             ) AS ferrum_derived_namespaces \
             WHERE namespace IS NOT NULL \
             ON CONFLICT (name) DO NOTHING"
        };
        sqlx::query(insert_derived)
            .bind(&now)
            .bind(&now)
            .execute(&mut *connection)
            .await?;

        let insert_default = if self.is_mysql() {
            "INSERT INTO namespaces (name, created_at, updated_at) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE name = namespaces.name"
        } else if self.is_sqlite() {
            "INSERT INTO namespaces (name, created_at, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT (name) DO NOTHING"
        } else {
            "INSERT INTO namespaces (name, created_at, updated_at) VALUES ($1, $2, $3) \
             ON CONFLICT (name) DO NOTHING"
        };
        // The canonical `ferrum` row per issue #3955. Nothing else is seeded:
        // the backfill must not read the process environment, and a
        // deployment-specific `FERRUM_NAMESPACE` that has no resources yet is
        // created through `POST /namespaces`. Ordinary resource writes isolate
        // data under a derived name but do not insert a registry row. This
        // insert runs only on the first compatibility pass; later startups
        // see the completion marker and must not resurrect a deleted `ferrum`.
        sqlx::query(insert_default)
            .bind(crate::config::types::DEFAULT_NAMESPACE)
            .bind(&now)
            .bind(&now)
            .execute(&mut *connection)
            .await?;

        // Match MongoDB's in-transaction identity validation before recording
        // compatibility completion. Legacy resource rows can predate current
        // namespace admission, so copying an invalid derived name into the
        // registry and marking the pass complete would defer the corruption to
        // a later admin read. Keep the diagnostic redacted to the schema field
        // and let the caller roll the complete backfill transaction back.
        let registry_rows = sqlx::query("SELECT name FROM namespaces")
            .fetch_all(&mut *connection)
            .await?;
        for row in registry_rows {
            let name: String = row
                .try_get("name")
                .map_err(|_| NamespaceRegistryCorrupt::field("name"))?;
            require_namespace_identity(&name, &name, None)?;
        }

        // Marker last: it is the final write in the atomic unit, so an abort
        // or a crash leaves completion absent and the next serialized
        // compatibility pass retries the idempotent inserts. This must not be a
        // namespaces row — GET /namespaces would then list it as a tenant.
        self.mark_namespaces_registry_backfill_complete(connection, &now)
            .await?;

        // Commit-boundary fence, exactly like every live registry mutation: the
        // global lease must still be owned at the acquired generation. Under
        // the pin taken above only an ownership change can falsify that, and no
        // ownership change can happen while the row is locked — so this is a
        // proof, not a TTL race. A lost lease rolls the whole pass back with the
        // marker absent, so nothing is resurrected and a later startup retries.
        if !self
            .namespaces_registry_backfill_lease_held(connection, owner, generation)
            .await?
        {
            tracing::warn!(
                "Namespace registry compatibility backfill rolled back: the global registry \
                 admission lease was no longer held at the commit boundary; a later startup retries"
            );
            return Ok(NamespacesRegistryBackfillOutcome::Defer);
        }
        Ok(NamespacesRegistryBackfillOutcome::Apply)
    }

    /// Authoritative namespace-keyed gateway trust bundles (issue #3727).
    ///
    /// `namespace` is the PRIMARY KEY, not `(namespace, id)`: the resource is a
    /// singleton per namespace so the trust state a control plane projects into
    /// a namespace-scoped ConfigSync slice is never ambiguous. `id` stays a
    /// stable addressable identity for admin CRUD, and the primary key already
    /// covers every query shape the store issues (`WHERE namespace = ?` and
    /// `WHERE namespace = ? AND id = ?`), so no secondary index is created.
    ///
    /// `revision` is the optimistic-concurrency token. It is NOT a per-record
    /// counter: the store stamps it from `config_changes.sequence` inside the
    /// same transaction that writes `bundle`, so two admin replicas rotating
    /// concurrently cannot both believe they won, AND a record deleted and
    /// recreated never reuses a revision a stale client still holds. The column
    /// default exists only so the DDL is well-formed; every write supplies an
    /// explicit value.
    fn create_gateway_trust_bundles_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS gateway_trust_bundles (
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                trust_domain VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                bundle MEDIUMTEXT NOT NULL,
                revision BIGINT NOT NULL DEFAULT 1,
                updated_by VARCHAR(255) COLLATE utf8mb4_0900_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace)
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS gateway_trust_bundles (
                namespace TEXT NOT NULL,
                id TEXT NOT NULL,
                trust_domain TEXT NOT NULL,
                bundle TEXT NOT NULL,
                revision BIGINT NOT NULL DEFAULT 1,
                updated_by TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace)
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
                labels MEDIUMTEXT NOT NULL DEFAULT ('{}'),
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                username VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                custom_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
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
                labels TEXT NOT NULL DEFAULT ('{}'),
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                credential_type VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
                credential_hash VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
                consumer_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                identity_value VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                consumer_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
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
                labels MEDIUMTEXT NOT NULL DEFAULT ('{}'),
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                name VARCHAR(255) COLLATE utf8mb4_0900_bin,
                hosts TEXT NOT NULL,
                listen_path VARCHAR(512),
                backend_scheme VARCHAR(16) NOT NULL DEFAULT 'https',
                backend_host VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                backend_port INTEGER NOT NULL DEFAULT 80,
                backend_path TEXT,
                strip_listen_path INTEGER NOT NULL DEFAULT 1,
                preserve_host_header INTEGER NOT NULL DEFAULT 0,
                backend_connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
                backend_read_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_write_timeout_ms INTEGER NOT NULL DEFAULT 30000,
                backend_tls_client_cert_path MEDIUMTEXT,
                backend_tls_client_key_path MEDIUMTEXT,
                backend_tls_verify_server_cert INTEGER NOT NULL DEFAULT 1,
                backend_tls_server_ca_cert_path MEDIUMTEXT,
                dns_override TEXT,
                dns_cache_ttl_seconds INTEGER,
                auth_mode VARCHAR(20) NOT NULL DEFAULT 'single',
                upstream_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
                upstream_subset VARCHAR(255) COLLATE utf8mb4_0900_bin,
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
                allowed_ws_origins MEDIUMTEXT,
                udp_max_response_amplification_factor REAL,
                stream_proxy_protocol INTEGER,
                backend_proxy_protocol VARCHAR(16),
                stream_match MEDIUMTEXT,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, id),
                CONSTRAINT fk_proxies_upstream FOREIGN KEY (namespace, upstream_id) REFERENCES upstreams(namespace, id) ON DELETE RESTRICT,
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
                labels TEXT NOT NULL DEFAULT ('{}'),
                id TEXT NOT NULL,
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
                upstream_id TEXT,
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
                backend_proxy_protocol TEXT,
                stream_match TEXT,
                api_spec_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id),
                FOREIGN KEY (namespace, upstream_id) REFERENCES upstreams(namespace, id) ON DELETE RESTRICT,
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
                labels MEDIUMTEXT NOT NULL DEFAULT ('{}'),
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                plugin_name VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                config MEDIUMTEXT NOT NULL,
                scope VARCHAR(50) NOT NULL DEFAULT 'global',
                proxy_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                trigger_json MEDIUMTEXT DEFAULT NULL,
                api_spec_id VARCHAR(255) COLLATE utf8mb4_0900_bin,
                created_at VARCHAR(64) NOT NULL,
                updated_at VARCHAR(64) NOT NULL,
                PRIMARY KEY (namespace, id),
                CONSTRAINT fk_plugin_configs_proxy FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS plugin_configs (
                labels TEXT NOT NULL DEFAULT ('{}'),
                id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                plugin_name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                scope TEXT NOT NULL DEFAULT 'global',
                proxy_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority_override INTEGER DEFAULT NULL,
                trigger_json TEXT DEFAULT NULL,
                api_spec_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id),
                FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE
            )
            "#
        }
    }

    fn create_proxy_route_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_route_locks (
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                route_key_hash VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin PRIMARY KEY,
                updated_at VARCHAR(64) NOT NULL,
                restore_owner VARCHAR(36) COLLATE utf8mb4_0900_bin NULL
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                proxy_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                plugin_config_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                PRIMARY KEY (namespace, proxy_id, plugin_config_id),
                CONSTRAINT fk_proxy_plugins_proxy FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE,
                CONSTRAINT fk_proxy_plugins_plugin FOREIGN KEY (namespace, plugin_config_id) REFERENCES plugin_configs(namespace, id) ON DELETE CASCADE
            )
            "#
        } else {
            r#"
            CREATE TABLE IF NOT EXISTS proxy_plugins (
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                proxy_id TEXT NOT NULL,
                plugin_config_id TEXT NOT NULL,
                PRIMARY KEY (namespace, proxy_id, plugin_config_id),
                FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE,
                FOREIGN KEY (namespace, plugin_config_id) REFERENCES plugin_configs(namespace, id) ON DELETE CASCADE
            )
            "#
        }
    }

    fn create_config_change_locks_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS config_change_locks (
                lock_name VARCHAR(255) COLLATE utf8mb4_0900_bin PRIMARY KEY,
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin PRIMARY KEY,
                owner VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin PRIMARY KEY,
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
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                resource_type VARCHAR(32) COLLATE utf8mb4_0900_bin NOT NULL,
                resource_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                operation VARCHAR(16) COLLATE utf8mb4_0900_bin NOT NULL,
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
        // FK: (namespace, proxy_id) → proxies(namespace, id) ON DELETE CASCADE
        //     so deleting the proxy (e.g., when a spec is purged) automatically
        //     removes the spec row, and a spec can only ever describe a proxy in
        //     its own tenant (issue #4627).
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
        // dependent rows by hand
        // (WHERE namespace = '<ns>' AND api_spec_id = '<deleted-spec-id>').
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                proxy_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                spec_version VARCHAR(50) COLLATE utf8mb4_0900_bin NOT NULL,
                spec_format VARCHAR(10) NOT NULL,
                spec_content LONGBLOB NOT NULL,
                content_encoding VARCHAR(50) NOT NULL DEFAULT 'gzip',
                uncompressed_size BIGINT NOT NULL,
                content_hash VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
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
                external_ref_snapshot LONGBLOB NULL,
                external_ref_digest VARCHAR(64) COLLATE utf8mb4_0900_bin NULL,
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                PRIMARY KEY (namespace, id),
                CONSTRAINT fk_api_specs_proxy FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE
            )
            "#
        } else if self.is_sqlite() {
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                proxy_id TEXT NOT NULL,
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
                external_ref_snapshot BLOB NULL,
                external_ref_digest TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id),
                FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE
            )
            "#
        } else {
            // PostgreSQL: BYTEA for binary data (BLOB is not a native PG type).
            r#"
            CREATE TABLE IF NOT EXISTS api_specs (
                id TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'ferrum',
                proxy_id TEXT NOT NULL,
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
                external_ref_snapshot BYTEA NULL,
                external_ref_digest TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id),
                FOREIGN KEY (namespace, proxy_id) REFERENCES proxies(namespace, id) ON DELETE CASCADE
            )
            "#
        }
    }

    fn create_audit_events_sql(&self) -> &'static str {
        if self.is_mysql() {
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id VARCHAR(255) COLLATE utf8mb4_0900_bin PRIMARY KEY,
                ts VARCHAR(50) NOT NULL,
                actor VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                action VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
                resource_type VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL,
                resource_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
                namespace VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT 'ferrum',
                namespace_at_event VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT '',
                source_address VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT '',
                request_id VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT '',
                outcome VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL DEFAULT '',
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
                namespace_at_event TEXT NOT NULL DEFAULT '',
                source_address TEXT NOT NULL DEFAULT '',
                request_id TEXT NOT NULL DEFAULT '',
                outcome TEXT NOT NULL DEFAULT '',
                diff TEXT NOT NULL
            )
            "#
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
                .contains("id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL")
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
    fn test_audit_event_column_exists_sql_uses_dialect_placeholders() {
        let mysql_sql = V001SqlBuilder::new("mysql").audit_event_column_exists_sql();
        assert!(
            mysql_sql.contains("column_name = ?"),
            "MySQL information_schema probe must use `?` placeholders"
        );
        assert!(
            !mysql_sql.contains("$1"),
            "MySQL information_schema probe must not use Postgres `$1` placeholders"
        );

        let postgres_sql = V001SqlBuilder::new("postgres").audit_event_column_exists_sql();
        assert!(
            postgres_sql.contains("column_name = $1"),
            "Postgres information_schema probe must use `$1` placeholders"
        );
        assert!(
            !postgres_sql.contains("column_name = ?"),
            "Postgres information_schema probe must not leave a trailing `?` operator"
        );
    }

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
    fn test_mysql_upstreams_tls_material_and_subsets_hold_admitted_caps() {
        // MAX_TLS_INLINE_PEM_LENGTH = 1 MiB exceeds MySQL TEXT; subsets JSON
        // is uncapped at admission beyond per-label key/val length.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_upstreams_sql();
        for col in [
            "subsets MEDIUMTEXT",
            "backend_tls_client_cert_path MEDIUMTEXT",
            "backend_tls_client_key_path MEDIUMTEXT",
            "backend_tls_server_ca_cert_path MEDIUMTEXT",
        ] {
            assert!(
                sql.contains(col),
                "upstreams must use MEDIUMTEXT for {col} so admitted payloads are not truncated"
            );
        }
        assert!(
            !sql.contains("backend_tls_client_cert_path VARCHAR"),
            "upstream TLS material columns must not remain VARCHAR-capped"
        );
    }

    #[test]
    fn test_mysql_proxies_tls_material_and_ws_origins_hold_admitted_caps() {
        // Proxy TLS material shares MAX_TLS_INLINE_PEM_LENGTH = 1 MiB; prior
        // TEXT columns truncated at 65,535. allowed_ws_origins has no
        // admission size cap, so MEDIUMTEXT is the smallest existing-schema
        // fix that preserves uncapped admitted values.
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_proxies_sql();
        for col in [
            "backend_tls_client_cert_path MEDIUMTEXT",
            "backend_tls_client_key_path MEDIUMTEXT",
            "backend_tls_server_ca_cert_path MEDIUMTEXT",
            "allowed_ws_origins MEDIUMTEXT",
        ] {
            assert!(
                sql.contains(col),
                "proxies must use MEDIUMTEXT for {col} so admitted payloads are not truncated"
            );
        }
    }

    #[test]
    fn test_proxies_ns_listen_path_index_is_non_unique_and_dialect_safe() {
        // Covers listen_path_candidate_sql without weakening the host-overlap
        // uniqueness lease (which remains application-enforced).
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.proxies_ns_listen_path_index_sql();
            assert!(
                sql.contains("idx_proxies_ns_listen_path"),
                "{dialect} must name the listen_path secondary index consistently"
            );
            assert!(
                !sql.contains("UNIQUE"),
                "{dialect} must not add a unique lease on (namespace, listen_path)"
            );
            if dialect == "mysql" {
                assert!(
                    sql.contains("ON proxies (namespace, listen_path(255))"),
                    "MySQL must leave room for InnoDB's appended VARCHAR(255) primary key"
                );
            } else {
                assert!(
                    sql.contains("ON proxies (namespace, listen_path)"),
                    "{dialect} must index full (namespace, listen_path) columns"
                );
                assert!(
                    !sql.contains("listen_path("),
                    "{dialect} must not use a prefix length"
                );
            }
        }
    }

    #[test]
    fn test_proxies_ns_listen_port_index_is_non_unique() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.proxies_ns_listen_port_index_sql();
            assert!(
                sql.contains("idx_proxies_ns_listen_port"),
                "{dialect} must name the listen_port secondary index consistently"
            );
            assert!(
                !sql.contains("UNIQUE"),
                "{dialect} must allow validated SNI/L4 listener groups to share a port"
            );
            assert!(sql.contains("ON proxies (namespace, listen_port)"));
        }
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
    // `COLLATE utf8mb4_0900_bin` so uniqueness on `(namespace, name)` and similar
    // is truly byte-exact (matching PostgreSQL/SQLite and runtime HashMap
    // keys). A UCA collation such as `utf8mb4_0900_as_cs` is accent-/case-
    // sensitive but still folds NFC/NFD equivalents, and the older
    // `utf8mb4_bin` ignores trailing spaces under `PAD SPACE` semantics.
    // MySQL 8.0.17+ floor (`utf8mb4_0900_bin` introduced then); hosted
    // service-integration CI runs MySQL 8.4.
    // ------------------------------------------------------------------

    fn assert_columns_have_collation(sql: &str, table_label: &str, columns: &[&str]) {
        for col in columns {
            let needles = [
                format!("{col} VARCHAR(255) COLLATE utf8mb4_0900_bin"),
                format!("{col} VARCHAR(50) COLLATE utf8mb4_0900_bin"),
                format!("{col} VARCHAR(64) COLLATE utf8mb4_0900_bin"),
                format!("{col} VARCHAR(36) COLLATE utf8mb4_0900_bin"),
            ];
            assert!(
                needles.iter().any(|n| sql.contains(n)),
                "{table_label}.{col} must have an explicit COLLATE utf8mb4_0900_bin clause"
            );
        }
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
    fn test_mysql_namespaces_collation_on_name() {
        let builder = V001SqlBuilder::new("mysql");
        let sql = builder.create_namespaces_sql();
        assert_columns_have_collation(sql, "namespaces", &["name"]);
        assert!(sql.contains("PRIMARY KEY (name)"));
    }

    #[test]
    fn schema_compat_table_is_internal_and_keyed_by_name() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let sql = V001SqlBuilder::new(dialect).create_schema_compat_sql();
            assert!(
                sql.contains("CREATE TABLE IF NOT EXISTS _ferrum_schema_compat"),
                "{dialect} must fold the compatibility-state table into the baseline"
            );
            assert!(
                sql.contains("PRIMARY KEY (name)"),
                "{dialect} must key completion markers by name, not as a namespaces row"
            );
            assert!(
                !sql.contains("namespaces ("),
                "{dialect} must not store compatibility state in the tenant registry"
            );
        }
    }

    #[test]
    fn namespaces_registry_backfill_is_gated_by_schema_compat_marker() {
        let source = include_str!("sql_dialect.rs");
        let completed_start = source
            .find("async fn namespaces_registry_backfill_completed(")
            .expect("completion-check helper");
        let mark_start = source
            .find("async fn mark_namespaces_registry_backfill_complete(")
            .expect("completion-mark helper");
        let start = source
            .find("async fn backfill_namespaces_registry(")
            .expect("backfill helper");
        let completed_helper = &source[completed_start..mark_start];
        let mark_helper = &source[mark_start..start];
        let body = &source[start..];
        let end = body
            .find("\n    /// Authoritative namespace-keyed")
            .unwrap_or(body.len());
        let body = &body[..end];
        let completed_at = body
            .find("namespaces_registry_backfill_completed")
            .expect("completion check");
        let insert_at = body.find("insert_derived").expect("derived-name insert");
        let mark_at = body
            .find("mark_namespaces_registry_backfill_complete")
            .expect("completion mark");
        assert!(
            completed_at < insert_at,
            "a completed backfill must skip inserts:\n{body}"
        );
        assert!(
            insert_at < mark_at,
            "the marker must be written after the idempotent inserts so a crash retries:\n{body}"
        );
        for (name, helper) in [
            ("completion check", completed_helper),
            ("completion mark", mark_helper),
        ] {
            assert!(
                helper.contains("NAMESPACES_REGISTRY_BACKFILL_ID")
                    && helper.contains("_ferrum_schema_compat"),
                "{name} must use the internal compatibility table and marker ID:\n{helper}"
            );
        }
    }

    #[test]
    fn namespaces_registry_backfill_mysql_inserts_use_strict_duplicate_key_updates() {
        let source = include_str!("sql_dialect.rs");
        let start = source
            .find("async fn mark_namespaces_registry_backfill_complete(")
            .expect("completion-mark helper");
        let end = source[start..]
            .find("\n    /// Authoritative namespace-keyed")
            .map(|offset| start + offset)
            .unwrap_or(source.len());
        let backfill = &source[start..end];
        assert!(
            !backfill.contains("INSERT IGNORE INTO") && !backfill.contains("\"INSERT IGNORE"),
            "MySQL registry backfill must not use INSERT IGNORE; it swallows truncation and \
             other non-duplicate integrity errors:\n{backfill}"
        );
        assert!(
            backfill.contains("ON DUPLICATE KEY UPDATE name = _ferrum_schema_compat.name")
                && backfill
                    .matches("ON DUPLICATE KEY UPDATE name = namespaces.name")
                    .count()
                    == 2,
            "MySQL registry backfill must ignore only the intended duplicate primary key:\n\
             {backfill}"
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
        assert_columns_have_collation(
            sql,
            "proxy_plugins",
            &["namespace", "proxy_id", "plugin_config_id"],
        );
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
                    !sql.contains("utf8mb4_0900_bin") && !sql.contains("utf8mb4_0900_as_cs"),
                    "{dialect} dialect must not carry MySQL-specific COLLATE clauses"
                );
            }
        }
    }

    #[test]
    fn test_mysql_identity_columns_reject_uca_collation() {
        // Regression for #2994: UCA `utf8mb4_0900_as_cs` folds NFC/NFD and
        // diverges from PostgreSQL/SQLite/runtime byte keys.
        let builder = V001SqlBuilder::new("mysql");
        for (label, sql) in [
            ("consumers", builder.create_consumers_sql()),
            (
                "consumer_identity_index",
                builder.create_consumer_identity_index_sql(),
            ),
            ("proxies", builder.create_proxies_sql()),
            ("upstreams", builder.create_upstreams_sql()),
        ] {
            assert!(
                sql.contains("utf8mb4_0900_bin"),
                "{label} must use the NO PAD binary collation for byte-exact identity"
            );
            assert!(
                !sql.contains("utf8mb4_0900_as_cs"),
                "{label} must not use UCA utf8mb4_0900_as_cs (NFC/NFD fold)"
            );
            assert!(
                !sql.contains("COLLATE utf8mb4_bin"),
                "{label} must not use PAD SPACE utf8mb4_bin (trailing-space fold)"
            );
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
            assert_fk_present(sql, "upstreams", "namespace, id", "RESTRICT");
        }
    }

    #[test]
    fn test_fk_plugin_configs_proxy_consistent_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_plugin_configs_sql();
            assert_fk_present(sql, "proxies", "namespace, id", "CASCADE");
        }
    }

    #[test]
    fn test_fk_proxy_plugins_consistent_across_dialects() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            let sql = builder.create_proxy_plugins_sql();
            // Both FKs in the junction table must be namespace-qualified and
            // CASCADE, so a junction row cannot bind across tenants.
            assert_fk_present(sql, "proxies", "namespace, id", "CASCADE");
            assert_fk_present(sql, "plugin_configs", "namespace, id", "CASCADE");
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
        // Every dialect must define exactly 7 FK references (counted by
        // occurrences of "REFERENCES" in the combined CREATE TABLE SQL):
        // the 4 proxy/plugin FKs, the api_specs → proxies FK, and the two
        // composite consumer-index FKs.
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
                builder.create_api_specs_sql(),
            ]
            .join("\n");

            let count = all_sql.matches("REFERENCES").count();
            assert_eq!(
                count, 7,
                "{dialect} dialect has {count} FK REFERENCES clauses, expected 7"
            );
        }
    }

    /// Issue #4627: every namespaced resource table must key on
    /// `(namespace, id)` so the same bare id can exist in two tenants, and the
    /// junction table must carry the namespace in its own key.
    #[test]
    fn test_namespaced_resource_tables_use_composite_primary_keys() {
        for dialect in ["postgres", "mysql", "sqlite"] {
            let builder = V001SqlBuilder::new(dialect);
            for (table, sql) in [
                ("proxies", builder.create_proxies_sql()),
                ("upstreams", builder.create_upstreams_sql()),
                ("plugin_configs", builder.create_plugin_configs_sql()),
                ("api_specs", builder.create_api_specs_sql()),
            ] {
                assert!(
                    sql.contains("PRIMARY KEY (namespace, id)"),
                    "{dialect} {table} must declare a composite PRIMARY KEY (namespace, id)"
                );
                assert!(
                    !sql.contains("id TEXT PRIMARY KEY")
                        && !sql.contains("COLLATE utf8mb4_0900_bin PRIMARY KEY"),
                    "{dialect} {table} must not keep a single-column id PRIMARY KEY"
                );
            }

            let junction = builder.create_proxy_plugins_sql();
            assert!(
                junction.contains("PRIMARY KEY (namespace, proxy_id, plugin_config_id)"),
                "{dialect} proxy_plugins must key on (namespace, proxy_id, plugin_config_id)"
            );
            assert!(
                junction.contains("namespace"),
                "{dialect} proxy_plugins must carry a namespace column"
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
                    && !sql.contains("COLLATE utf8mb4_0900_bin PRIMARY KEY"),
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
