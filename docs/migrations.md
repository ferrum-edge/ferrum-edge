# Ferrum Edge Migration & Upgrade Guide

This document explains how Ferrum Edge handles upgrades between versions, including database schema migrations and configuration file migrations.

## Overview

Ferrum Edge uses a versioned migration system that:

- **Tracks applied database migrations** in a `_ferrum_migrations` table
- **Versions configuration files** with a `version` field
- **Auto-migrates on startup** (no manual intervention required for normal operation)
- **Provides a CLI mode** for operators who want explicit control

## Build-Out Schema Policy

Ferrum Edge is still in active build-out. During this phase, core database
schema changes are folded into the current baseline schema (`V001`) instead of
being added as new core schema migrations (`V002`, `V003`, etc.). Breaking
database-schema changes are acceptable during build-out, and compatibility
shims for legacy columns, fields, environment variables, config shapes, or
database values are not required unless explicitly requested.

Operationally, anyone running a build-out branch or recent `main` snapshot
should treat core schema changes as requiring a fresh database or an explicit
operator-managed rebuild of the affected tables. The versioned core migration
guide below documents the migration framework and the post-stabilization path;
it is not the default workflow for new core schema fields during build-out.
Custom plugin migrations still use the plugin migration system because plugin
storage is independently owned.

## Stability & Upgrade Contract

Ferrum Edge is in active build-out (crate version `0.9.x`, DB baseline `V001`).
This section states, in one place, what stability you can rely on across
branches and releases, when the schema freeze happens, and how breaking changes
are announced.

### What each channel guarantees

| Channel | What it is | Schema / config / API stability |
|---|---|---|
| `main` / build-out branches | Every push to `main` overwrites the `latest` prerelease image (see [ci_cd.md](ci_cd.md)). | **No cross-commit stability.** Core schema changes are folded into the `V001` baseline (see [Build-Out Schema Policy](#build-out-schema-policy)); breaking changes to schema, env vars, config shapes, and DB values are acceptable and are **not** shimmed. Treat any schema change as requiring a fresh database or an operator-managed rebuild. Do not run `latest` in production with data you cannot recreate. |
| Tagged release `vX.Y.Z` | A `v*` tag cuts a versioned GitHub Release + Docker tags from a green CI/coverage SHA. | Semantic versioning per [ci_cd.md → Version Numbering](ci_cd.md#version-numbering). The promises in [Version Compatibility](upgrade_guide.md#version-compatibility) apply **between tagged releases**, not between arbitrary `main` commits. |

The CP↔DP gRPC protocol is the one compatibility contract enforced in code
today: a DP and CP must share the same **major.minor** version
(`check_version_compatibility`; patch differences are allowed). Mixed-version
CP/DP fleets outside that window are rejected at connect time.

### When V002+ migrations start (the schema freeze)

Today there is exactly one core migration, `V001` (`initial_schema`), and all
built-in schema changes are folded into it rather than shipped as `V002`,
`V003`, … The transition from *fold-into-baseline* to *incremental migrations*
happens at a single, declared point:

> **The `V001` baseline freezes at the first tagged release designated stable —
> the first `v1.0.0`, or an earlier `vX.Y.Z` whose release notes explicitly
> declare the stable schema baseline.** From that release onward, any change to
> a built-in table/column/index ships as a new versioned migration (`V002`+, per
> [Writing New Migrations](#writing-new-migrations-developer-guide)), and the
> fold-into-`V001` and no-legacy-shims allowances are retired. Before that
> release, `V001` remains editable and breaking, as above.

Until that release is cut, "add a `V002`" is **not** the workflow — update the
`V001` baseline in `v001_initial_schema.rs` / `sql_dialect.rs`. The `V002+`
developer guide below exists for the migration framework and the post-freeze
path, not for routine build-out schema work.

### How breaking changes are announced

- **Between tagged releases:** breaking schema / config / env / API changes are
  called out in that release's GitHub Release notes, keyed to the migration or
  the env/config surface that changed. Operators upgrade tag-to-tag using
  [upgrade_guide.md](upgrade_guide.md) (back up → dry-run migrate → validate on
  non-production ports → cut over).
- **On `main` / build-out branches:** there is no per-commit changelog promise.
  New `FERRUM_*` env vars land with `docs/configuration.md` + `ferrum.conf`
  updates in the same change, and schema-affecting changes update the `V001`
  baseline and its tests. The authoritative "we are still folding" statement is
  the [Build-Out Schema Policy](#build-out-schema-policy) above; its end
  condition is the schema freeze defined here.

## Database Migrations

### How It Works

When Ferrum Edge starts in `database`, `cp`, or `migrate` mode, it runs the **MigrationRunner** which:

1. Acquires a cross-process migration lock (`pg_try_advisory_lock` polling on
   PostgreSQL, `GET_LOCK` on MySQL, and `BEGIN IMMEDIATE` on SQLite)
2. Creates the `_ferrum_migrations` tracking table if it doesn't exist
3. Checks which migrations have been applied by reading `_ferrum_migrations`
4. Runs any pending migrations in order
5. Records each applied migration with its version, name, timestamp, checksum, and execution time

The applied-version read happens after the lock is acquired. When two replicas
start together, the waiter therefore observes the winner's committed tracking
row and skips the migration instead of racing the tracking insert. MongoDB
index migration uses a renewable lease document in `_ferrum_migration_locks`.
On real MongoDB, lease expiry and renewal are evaluated with the MongoDB server
clock (an aggregation-pipeline `$$NOW` update), so client clock skew cannot let
one replica take over another's still-active lease; a crashed owner stops
renewing and its lease expires server-side. AWS DocumentDB does not support
aggregation-pipeline-form updates, so on that backend Ferrum detects the
rejection on the first acquire and falls back to a classic operator update
stamped from the *client* clock for the whole migration run — same 120s window,
ownership fencing, and safe release, but skew-safe only as far as the replicas'
clocks agree (keep them on NTP). See [mongodb.md](mongodb.md#aws-documentdb).

### Migration Tracking Table

```sql
CREATE TABLE _ferrum_migrations (
    version INTEGER PRIMARY KEY,    -- Monotonically increasing migration number
    name TEXT NOT NULL,             -- Human-readable name (e.g., "initial_schema")
    applied_at TEXT NOT NULL,       -- ISO 8601 timestamp of when it was applied
    checksum TEXT NOT NULL,         -- Integrity check for the migration source
    execution_time_ms INTEGER NOT NULL  -- How long the migration took to run
);
```

### Upgrading from Pre-Migration Versions

Databases that predate migration tracking are not auto-bootstrapped. Back up the database and rebuild it from the current baseline before starting a current binary against it.

Build-out caveat: newer development snapshots may intentionally fold schema
changes into the baseline instead of adding an upgrade migration. In that case,
operators running those snapshots need to recreate or rebuild the database
schema as described in [Build-Out Schema Policy](#build-out-schema-policy).

### Cross-Database Support

SQL migrations work across all supported SQL databases:
- **SQLite** (default)
- **PostgreSQL**
- **MySQL**

Each migration is a Rust function that can dispatch different SQL based on the database type when needed, ensuring DDL compatibility across all three SQL backends.

**MongoDB** does not use SQL migrations. When `FERRUM_DB_TYPE=mongodb`, the migration runner creates indexes instead (idempotent `createIndex` operations). See the [MongoDB Migrations](#mongodb-migrations) section below.

### Checksum Validation

Each migration has a checksum. V001 uses a `sha256:<hex>` digest derived from
the V001 wrapper and dialect schema source, so changing the baseline changes the
stored value and makes later source tampering visible. When the gateway starts,
it compares the checksum of each applied migration against the expected
checksum in the code. If a mismatch is detected, a warning is logged. This is a
diagnostic aid, not a hard error. During build-out there is deliberately no
compatibility shim for the former fixed `v001_initial_schema` label.

## Custom Plugin Migrations

Custom plugins can declare their own database migrations that run alongside core gateway migrations. This allows plugins to create and manage private tables without modifying any core source files. **Note:** The custom plugin migration system is SQL-only. For MongoDB, see [MongoDB Custom Plugin Storage](#mongodb-custom-plugin-storage) below.

### How It Works

1. A custom plugin exports a `plugin_migrations()` function from its `.rs` file in `custom_plugins/`
2. The build script detects this function automatically and generates a collector
3. When `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` is run, plugin migrations execute **after** core migrations
4. Plugin migrations are tracked in `_ferrum_plugin_migrations` (separate from `_ferrum_migrations`)

### Plugin Migration Tracking Table

```sql
CREATE TABLE _ferrum_plugin_migrations (
    plugin_name TEXT NOT NULL,          -- Plugin name (matches .rs file name)
    version INTEGER NOT NULL,           -- Migration version within the plugin
    name TEXT NOT NULL,                 -- Human-readable migration name
    applied_at TEXT NOT NULL,           -- ISO 8601 timestamp
    checksum TEXT NOT NULL,             -- Integrity check
    execution_time_ms INTEGER NOT NULL, -- Execution duration
    PRIMARY KEY (plugin_name, version)
);
```

The composite primary key `(plugin_name, version)` means each plugin maintains its own independent migration sequence. Plugin versions never conflict with core gateway migration versions.

### Defining Plugin Migrations

In your custom plugin file, export a `plugin_migrations()` function:

```rust
use crate::config::migrations::CustomPluginMigration;

pub fn plugin_migrations() -> Vec<CustomPluginMigration> {
    vec![
        CustomPluginMigration {
            version: 1,
            name: "create_my_table",
            checksum: "v1_create_my_table_a1b2c3",
            sql: "CREATE TABLE IF NOT EXISTS my_plugin_data (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            sql_postgres: None,  // Use default SQL for PostgreSQL
            sql_mysql: None,     // Use default SQL for MySQL
        },
    ]
}
```

### Cross-Database SQL Support

Each `CustomPluginMigration` has three SQL fields:

| Field | Purpose |
|-------|---------|
| `sql` | Default SQL used for all databases (must work for SQLite at minimum) |
| `sql_postgres` | Optional PostgreSQL override (for `JSONB`, `TIMESTAMPTZ`, etc.) |
| `sql_mysql` | Optional MySQL override (for `JSON`, `DATETIME(3)`, `VARCHAR` PKs, etc.) |

When `sql_postgres` or `sql_mysql` is `Some(...)`, that SQL is used instead of `sql` for that database. When `None`, the default `sql` is used.

### Multi-Statement Migrations

SQL statements separated by semicolons are executed independently:

```rust
sql: r#"
    CREATE TABLE IF NOT EXISTS my_cache (key TEXT PRIMARY KEY, value TEXT);
    CREATE INDEX IF NOT EXISTS idx_my_cache_key ON my_cache (key)
"#,
```

Dialect transactionality for custom-plugin migrations:

- **SQLite:** statements and the tracking-row insert run inside the migration
  lock transaction and roll back together on failure.
- **PostgreSQL (ordinary DDL):** statements and the tracking-row insert run in
  one explicit transaction on the lock session.
- **PostgreSQL (top-level DDL):** statements that must run outside a
  transaction are detected automatically, including `CREATE INDEX CONCURRENTLY`,
  `DROP INDEX CONCURRENTLY`, concurrent `REINDEX`, `VACUUM`, database creation
  or deletion, and `ALTER SYSTEM`. Ferrum executes every statement first and
  records `_ferrum_plugin_migrations` only after all statements succeed. A
  failed statement therefore never creates a tracking row; because PostgreSQL
  cannot roll back this class of DDL as one unit, authors should keep these
  migrations idempotent and use one top-level operation per migration where
  practical.
- **MySQL:** DDL implicitly commits
  ([MySQL manual](https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html)),
  and the runner always executes MySQL custom-plugin migrations outside an
  enclosing transaction so statement/tracking boundaries never become
  ambiguously half-transactional. **All MySQL custom migrations — including
  DML-only bodies — are therefore non-atomic with the tracking insert and must
  be idempotent / re-runnable.** Pre-existing DML-only MySQL custom migrations written under the older per-migration atomic contract must be reviewed for re-run safety under this runner. For a plugin-owned index that must recover
  across every statement boundary, pair `DROP INDEX name ON table` immediately
  with the exact `CREATE INDEX` definition. The runner tolerates only
  structured MySQL error `1091` (missing key) on a two-token `DROP INDEX name ON table` statement (the `ALTER TABLE ... DROP INDEX` spelling is not tolerated); every
  creation failure remains fatal. A retry then either removes the prior
  definition or observes a missing index before reconstructing the intended
  one. Prefer idempotent table DDL (`CREATE TABLE IF NOT EXISTS`) and
  plugin-prefixed names, and do not use this pattern to replace indexes owned
  by another plugin or by the gateway core.

### Checksum Validation

Like core migrations, checksums are validated on each run. If a plugin migration's checksum differs from what was recorded when it was applied, a warning is logged. This helps detect unintended modifications to already-applied migrations.

### Table Naming Convention

Prefix custom tables to avoid collisions with core gateway tables (`proxies`, `consumers`, `upstreams`, `plugin_configs`, `proxy_plugins`) and other plugins.

### Complete Example

See `custom_plugins/examples/example_audit_plugin.rs` for a full working
example with multi-version migrations, PostgreSQL/MySQL overrides, and
multi-statement SQL. Build with
`FERRUM_CUSTOM_PLUGINS=example_audit_plugin` (examples are opt-in).

See [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md#database-migrations) for the complete developer guide.

## Configuration File Migrations

### Version Field

Configuration files (YAML or JSON) require a `version` field:

```yaml
version: "1"
proxies:
  - id: "proxy-1"
    # ...
consumers: []
plugin_configs: []
```

When the `version` field is absent, validation fails before migrations run. New configs should declare the current schema explicitly.

### How Config Migrations Work

**During normal startup** (`FERRUM_MODE=file`):
- The config file is loaded and its version is detected
- If the version is behind the current expected version, the configuration is migrated **in memory** before being used
- The original file on disk is **not modified**
- A warning is logged advising the operator to run `FERRUM_MODE=migrate` to persist the migration

**During explicit migration** (`FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config`):
- The config file is read and its version is detected
- A timestamped backup is created (e.g., `config.yaml.backup.20250101120000`)
- The migration chain is applied in sequence (V1 to V2, V2 to V3, etc.)
- The migrated configuration is written back to disk in the original format (YAML or JSON)

### Backup Strategy

Before modifying any config file, the migrator creates a backup at `{filename}.backup.{YYYYMMDDHHMMSS}` in the same directory. If something goes wrong, you can restore from the backup.

## Running Migrations Explicitly

Use `FERRUM_MODE=migrate` to run migrations without starting the gateway.

On Kubernetes, neither the `ferrum-gateway` nor `ferrum-mesh` Helm chart accepts
`mode=migrate`. Run the same env contract as an **external pre-deploy Job**
using the manifests under
[`charts/ferrum-gateway/examples/migrate-job-*.yaml`](../charts/ferrum-gateway/examples/)
(see
[docs/kubernetes_deployment.md § Explicit migrate mode](kubernetes_deployment.md#explicit-migrate-mode-external-job)).
`database` / `cp` chart installs still auto-apply pending core schema migrations
on startup; the Job path is for `status`, dry-run, and operator-controlled
`up` / `config`.

### Run Pending Database Migrations

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge
```

`status` is strictly read-only. If the core or plugin tracking table does not
exist, Ferrum reports every known migration as pending without creating either
tracking table.

### Check Migration Status

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge
```

Example output:
```
=== Ferrum Edge Migration Status ===

Applied migrations:
  V1: initial_schema (applied: 2025-01-15T10:30:00Z, checksum: sha256:<64 hex characters>)

Pending migrations: (none — schema is up to date)

=== Custom Plugin Migration Status ===

Applied plugin migrations:
  [example_audit_plugin] V1: create_audit_log (applied: 2025-01-15T10:30:01Z, checksum: v1_create_audit_log_f8a3e1)

Pending plugin migrations: (none — all plugins up to date)
```

### Migrate a Config File

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=config \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ferrum-edge
```

### Dry Run

Add `FERRUM_MIGRATE_DRY_RUN=true` to any migrate command to see what would be done without making changes:

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge
```

Database dry-run uses the same read-only status path: it does not create core
or custom-plugin tracking tables, schema objects, collections, or indexes.

## Environment Variables Reference

| Variable | Values | Description |
|----------|--------|-------------|
| `FERRUM_MODE` | `migrate` | Activates the migration CLI mode |
| `FERRUM_MIGRATE_ACTION` | `up` (default), `status`, `config` | What migration action to perform |
| `FERRUM_MIGRATE_DRY_RUN` | `true` / `false` | Preview changes without applying |
| `FERRUM_DB_TYPE` | `sqlite`, `postgres`, `mysql` | Required for `up` and `status` actions |
| `FERRUM_DB_URL` | Database connection URL | Required for `up` and `status` actions |
| `FERRUM_FILE_CONFIG_PATH` | Path to config file | Required for `config` action |

## Writing New Migrations (Developer Guide)

### Adding a Database Migration

Do not add new core schema migrations during the active build-out phase. For
new built-in tables, columns, or indexes, update the baseline schema in
`src/config/migrations/v001_initial_schema.rs` /
`src/config/migrations/sql_dialect.rs` and the corresponding tests. Add a new
versioned core migration only after the schema is declared stable (see
[When V002+ migrations start](#when-v002-migrations-start-the-schema-freeze)),
or when a task explicitly asks for an upgrade path.

The steps below are retained for post-stabilization core migrations and for
reference when working on the migration framework itself.

1. Create a new file `src/config/migrations/v002_your_migration_name.rs`:

```rust
use sqlx::AnyPool;
use super::Migration;

pub struct V002YourMigrationName;

impl Migration for V002YourMigrationName {
    fn version(&self) -> i64 { 2 }
    fn name(&self) -> &str { "your_migration_name" }
    fn checksum(&self) -> &str { "v002_your_migration_name_<hash>" }
}

impl V002YourMigrationName {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        // Use db_type to handle SQL dialect differences if needed
        let sql = match db_type {
            "postgres" => "ALTER TABLE proxies ADD COLUMN new_field TEXT DEFAULT ''",
            "mysql"    => "ALTER TABLE proxies ADD COLUMN new_field TEXT DEFAULT ''",
            _          => "ALTER TABLE proxies ADD COLUMN new_field TEXT DEFAULT ''",
        };
        sqlx::query(sql).execute(pool).await?;
        Ok(())
    }
}
```

2. Register it in `src/config/migrations/mod.rs`:
   - Add `pub mod v002_your_migration_name;` at the top
   - Create a `MigrationEntryV002` wrapper struct (following the V001 pattern)
   - Add it to the `all_migrations()` vec

3. Update `CURRENT_CONFIG_VERSION` in `src/config/types.rs` if the schema change also affects config files.

### Adding a Config File Migration

1. In `src/config/config_migration.rs`, add a migration function:

```rust
fn migrate_v1_to_v2(value: &mut serde_json::Value) -> Result<(), anyhow::Error> {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("version".to_string(), serde_json::json!("2"));
        // Transform fields as needed...
    }
    Ok(())
}
```

2. Register it in `ConfigMigrator::migration_chain()`:

```rust
fn migration_chain() -> Vec<(&'static str, &'static str, ConfigMigrationFn)> {
    vec![
        ("1", "2", migrate_v1_to_v2 as ConfigMigrationFn),
    ]
}
```

3. Update `CURRENT_CONFIG_VERSION` in `src/config/types.rs` to `"2"`.

## Troubleshooting

### "No config migration path from version X to Y"

This means the migration chain has a gap. Every version must have a migration step to the next version. Check that all migration functions are registered in `migration_chain()`.

### Migration checksum mismatch warning

This means a migration's source code was modified after it was already applied to the database. This is a warning only — the migration is not re-run. If the change was intentional (e.g., fixing a comment), the warning can be safely ignored.

### "Database has duplicate listen_path values"

This is a data integrity error, not a migration error. It means two proxies in the database have the same `listen_path`. Fix this by removing or updating one of the conflicting proxies via the Admin API.

### Recovering from a failed migration

If a migration fails partway through:
1. Check the error message for the specific SQL that failed
2. Inspect the database to see what state it's in
3. For **MySQL custom-plugin** migrations, remember DDL auto-commits: indexes
   may already exist without a `_ferrum_plugin_migrations` row. Re-running
   `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` is the supported recovery.
   Migrations using the documented paired `DROP INDEX` / exact `CREATE INDEX`
   pattern rebuild their plugin-owned definitions; the runner tolerates only a
   structured missing-key error (`1091`) on the drop before continuing
4. Fix any remaining underlying issue (e.g., data that violates a new constraint)
5. Re-run the migration — it will skip already-applied migrations and retry the failed one

For config files, restore from the `.backup.*` file that was created before the migration started.

## MongoDB Migrations

MongoDB does not use SQL migrations. Instead, `MongoStore::run_migrations()` creates indexes using idempotent `createIndex` operations. Running the same migration multiple times is safe — `createIndex` is a no-op if the index already exists.

### What Gets Created

| Collection | Indexes |
|-----------|---------|
| `proxies` | `(namespace, name)` unique sparse, `updated_at`, `upstream_id`, `(namespace, listen_port)` unique sparse, `namespace`, `(namespace, updated_at)` |
| `consumers` | `(namespace, username)` unique, `(namespace, custom_id)` unique sparse, `updated_at`, `namespace`, `(namespace, updated_at)` |
| `plugin_configs` | `proxy_id`, `updated_at`, `namespace`, `(namespace, updated_at)`, `(namespace, scope)`, `(namespace, plugin_name)` |
| `upstreams` | `(namespace, name)` unique sparse, `updated_at`, `namespace`, `(namespace, updated_at)` |

### Running MongoDB Migrations

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=mongodb \
  FERRUM_DB_URL="mongodb://localhost:27017" \
  FERRUM_MONGO_DATABASE=ferrum \
  ferrum-edge
```

### Schema Differences from SQL

- **No junction tables**: SQL uses `proxy_plugins` to associate proxies with plugins. MongoDB embeds plugin associations directly in proxy documents.
- **No migration tracking table**: SQL tracks applied migrations in `_ferrum_migrations`. MongoDB indexes are idempotent and don't need tracking.
- **Automatic field propagation**: New fields added to domain types (`Proxy`, `Consumer`, etc.) are automatically persisted to MongoDB via serde BSON serialization — no ALTER TABLE equivalent needed.

### MongoDB Custom Plugin Storage

The `CustomPluginMigration` system (using SQL `CREATE TABLE` statements) is **SQL-only**. When `FERRUM_DB_TYPE=mongodb`, custom plugin SQL migrations are skipped.

Custom plugins that need MongoDB-specific collections or indexes should:
1. Create collections/indexes in their `create_plugin()` initialization function
2. Use the MongoDB driver's `createIndex` (idempotent) to ensure indexes exist
3. Prefix collection names with the plugin name to avoid collisions (e.g., `my_plugin_audit_log`)
