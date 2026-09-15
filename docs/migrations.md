# Ferrum Edge Database Baselines and Initialization

Ferrum Edge is in active build-out with no deployed-user compatibility obligation.
Core schema changes update the initial baseline directly; breaking changes are expected.
This guide covers database initialization, integrity checks, and independently
owned custom-plugin migrations.

## Overview

- SQL databases initialize from one core baseline, `V001`, tracked in
  `_ferrum_migrations` with a content-derived checksum.
- MongoDB initializes from one canonical index plan.
- `database` and `cp` startup initialize fresh databases automatically;
  `FERRUM_MODE=migrate` provides explicit `up`, `status`, and dry-run actions.
- A changed SQL baseline requires a fresh database. Startup does not alter old
  columns, replace indexes, backfill old records, or rewrite migration history.

## Build-Out Schema Policy

Ferrum Edge is still in active build-out. During this phase, core database
schema changes are folded into the current baseline schema (`V001`) instead of
being added as new core schema migrations (`V002`, `V003`, etc.). Breaking
database-schema changes are acceptable during build-out, and compatibility
shims for legacy columns, fields, environment variables, config shapes, or
database values are not required unless explicitly requested.

Operationally, anyone running a build-out branch or recent `main` snapshot
should treat core schema changes as requiring a fresh database or an explicit
operator-managed rebuild of the affected tables. The canonical procedure is
[upgrade_guide.md → Build-Out Database Upgrade](upgrade_guide.md#build-out-database-upgrade-postgresql-mysql-sqlite-mongodb).
Custom plugin migrations still use the plugin migration system because plugin
storage is independently owned.

### Canonical schema locations

| Storage | Complete baseline |
|---|---|
| PostgreSQL, MySQL, SQLite | `src/config/migrations/v001_initial_schema.rs` delegates to `src/config/migrations/sql_dialect.rs` for the complete dialect-specific schema and initial `ferrum` namespace |
| MongoDB | `src/config/mongo_index_plan.rs`; `MongoStore` initializes an empty namespace registry with `ferrum` |
| ClickHouse chargeback sink | [`schemas/clickhouse/charges.sql`](../schemas/clickhouse/charges.sql), applied separately to the external analytics database |
| Custom plugins | `plugin_migrations()` in each compiled `custom_plugins/*.rs`; independent plugin-owned tables |

There is no separate core SQL patch directory or startup compatibility pass.
The `migrations` module name and `migrate` mode describe the initialization and
tracking framework; they do not imply a supported upgrade chain for core data.

## Stability & Upgrade Contract

Ferrum Edge is in active build-out (crate version `0.9.x`, DB baseline `V001`).
This section states, in one place, what stability you can rely on across
branches and releases, when the schema freeze happens, and how breaking changes
are announced.

### What each channel guarantees

| Channel | What it is | Schema / config / API stability |
|---|---|---|
| `main` / build-out branches | Main CI validates each push and publishes no production artifacts (see [ci_cd.md](ci_cd.md)); historical `latest` images are not refreshed. | **No cross-commit stability.** Core schema changes are folded into the `V001` baseline (see [Build-Out Schema Policy](#build-out-schema-policy)); breaking changes to schema, env vars, config shapes, and DB values are acceptable and are **not** shimmed. Treat any schema change as requiring a fresh database or an operator-managed rebuild. Do not run `latest` in production with data you cannot recreate. |
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
> a built-in table/column/index ships as a new versioned migration (`V002`+), and the
> fold-into-`V001` and no-legacy-shims allowances are retired. Before that
> release, `V001` remains editable and breaking, as above.

Until that release is cut, "add a `V002`" is **not** the workflow — update the
`V001` baseline in `v001_initial_schema.rs` / `sql_dialect.rs`. The `V002+`
workflow is deferred until that policy change is explicitly declared.

### How breaking changes are announced

- **Between tagged releases:** breaking schema / config / env / API changes are
  called out in that release's GitHub Release notes, keyed to the migration or
  the env/config surface that changed. Operators upgrade tag-to-tag using
  [upgrade_guide.md](upgrade_guide.md) (during build-out:
  [fresh-database rebuild](upgrade_guide.md#build-out-database-upgrade-postgresql-mysql-sqlite-mongodb);
  after the schema freeze: versioned forward migrations).
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
2. Reads any existing core and compiled custom-plugin tracking history and
   fails closed if an applied checksum differs from the current binary
3. Creates missing migration tracking tables
4. Checks which migrations have been applied
5. Runs any pending migrations in order
6. Records each applied migration with its version, name, timestamp, checksum, and execution time
7. On MySQL only, probes identity-bearing column collations against
   `utf8mb4_0900_bin` and emits a structured startup warning with exact
   `ALTER TABLE ... CONVERT TO` remediation when a database
   carries a stale collation (warn-and-continue; never refuses startup — see
   [configuration.md → MySQL minimum version](configuration.md#mysql-minimum-version))

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

### Migration History Integrity

Each migration has a checksum. V001 uses a `sha256:<hex>` digest derived from
the V001 wrapper and dialect schema source, so changing the baseline changes the
stored value and makes later source tampering visible. Before any write, Ferrum
first requires unique namespaces, unique version IDs in the inclusive
`1..=2147483647` tracking-column range, and increasing
declaration order. It then requires every applied namespace to be an exact
checksum-matching prefix of the binary's declarations. An unknown applied ID,
a missing earlier row before a later applied version, a duplicate/ambiguous
declaration or history identifier, checksum drift, or custom-plugin history
whose plugin is absent from the compiled binary is a blocking integrity error.
A declaration suffix after the applied prefix remains legitimately pending.

Ferrum does not apply pending core or plugin migrations, create tracking
tables, overwrite history, or re-run changed migration source after a refusal.
Automatic `database` / `cp` startup and
explicit `up`, `status`, and database dry-run commands all return an error;
command-line use therefore exits non-zero. During build-out there is
deliberately no compatibility shim for the former fixed
`v001_initial_schema` label and no migration-integrity override.

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

SQL statements separated by semicolons are executed independently. Ferrum splits
custom-plugin migration SQL with a shared, fail-closed parser (not a raw
`split(';')`), so classification and execution use the same statement
boundaries. The full migration body must parse successfully before statement
one runs.

The splitter preserves semicolons inside:

- single-quoted strings with doubled quotes (`''`); MySQL strings and explicit
  PostgreSQL `E'…'` / `U&'…'` strings also recognize backslash escapes
- double-quoted identifiers/strings with doubled quotes (`""`); MySQL and
  explicit PostgreSQL `U&"…"` forms also recognize backslash escapes
- backtick identifiers (MySQL / SQLite), including MySQL backslash escapes
- `--` / `/* … */` comments (plus MySQL `#` line comments and PostgreSQL
  nested block comments); MySQL `--` requires following whitespace/control
- PostgreSQL dollar-quoted bodies (`$tag$ … $tag$`)
- `BEGIN … END` compound bodies (SQLite triggers, MySQL routines)

MySQL compound routines may also use the mysql-client `DELIMITER` convention:

```sql
DELIMITER //
CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW
BEGIN
  SET NEW.id = 1;
END //
DELIMITER ;
```

`DELIMITER` lines are client meta-commands and are not sent to the server. If a
dialect construct cannot be parsed safely (unclosed quotes/comments/dollar
tags, unclosed `BEGIN … END`, or a MySQL `DELIMITER` that is never restored),
registration/apply fails before any statement executes.

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

### Migration History Integrity

Like core migrations, each applied plugin sequence is validated on every status
or apply run. Ferrum validates all declarations and histories before applying
work for any one plugin, and explicit `migrate up` validates both core and
plugin history before applying either. Unknown, missing, duplicate, and drifted
history is blocking even when no migration is pending and regardless of
`FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS`; it never updates history or runs changed
migration source. A history namespace for a plugin absent from the compiled
declaration list is orphaned and unverifiable, so it is fatal rather than
silently ignored.

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

### Current Config Format

The current format is `version: "1"`. `ConfigMigrator::migration_chain()` is
empty: there are no shipped config transforms or older formats to upgrade.
`FERRUM_MIGRATE_ACTION=config` reports no migration for a current-version file;
unsupported versions fail. During build-out, edit configuration to the current
shape and run `ferrum-edge validate` before starting the gateway. Do not add
legacy field aliases or speculative migration steps.

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
  ferrum-edge run
```

`status` is strictly read-only. If the core or plugin tracking table does not
exist, Ferrum reports every known migration as pending without creating either
tracking table. If any applied sequence is unknown, incomplete, duplicate,
orphaned, or checksum-drifted, `status` returns an integrity error and exits
non-zero instead of reporting the database as healthy.

### Check Migration Status

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge run
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
  ferrum-edge run
```

### Dry Run

Add `FERRUM_MIGRATE_DRY_RUN=true` to any migrate command to see what would be done without making changes:

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge run
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

## Updating Baselines (Developer Guide)

### Updating the Core Baseline

1. Edit the complete table/column/index definition in
   `src/config/migrations/sql_dialect.rs`. Keep PostgreSQL, MySQL, and SQLite
   aligned; `V001InitialSchema` remains the sole core declaration.
2. Update persistence, config types, validation, documentation, and OpenAPI
   where the changed field is exposed.
3. Test fresh initialization, relevant CRUD behavior, and repeated startup.
   Do not add `V002` files, `ALTER`-based startup repairs, namespace backfills,
   or compatibility tracking tables.
4. Recreate development databases after baseline changes. Keep checksum
   validation intact; do not edit applied tracking rows to disguise a mismatch.

Update MongoDB indexes in `src/config/mongo_index_plan.rs` and external
ClickHouse DDL in `schemas/clickhouse/charges.sql` directly. Their storage is
separate from the core SQL database. Custom-plugin changes follow
[Custom Plugin Migrations](#custom-plugin-migrations).

### Updating Config Files

Update the current config shape and its validation directly during build-out.
No compatibility transform is required. Document breaking changes and update
examples alongside the implementation.

## Troubleshooting

### "No config migration path from version X to Y"

Only config version `"1"` is currently supported, and no migration chain is shipped. Update the file to the current documented shape and validate it; changing its version label alone does not convert its contents.

### Migration history integrity error

This means the current binary cannot prove that applied history is an exact
prefix of its immutable declarations. Possible causes include an unknown or
duplicate version, a missing earlier row, duplicate compiled plugin/version
IDs, checksum drift, a divergent build or deployment, a database restored from
incompatible provenance, a changed tracking row, or orphan plugin history after
that plugin was omitted from the binary. Ferrum stops before tracking-table,
schema or later migration writes and does not rewrite history.

Treat the mismatch as an incident until provenance is understood:

1. Stop the rollout and preserve a database backup plus the exact binary/build
   metadata that observed the failure.
2. Compare the deployed artifact (including its compiled custom-plugin list),
   immutable migration declarations, database backup, and tracking history to
   identify the unknown, missing, duplicate, orphaned, or drifted entry. Do not
   place database credentials, migration SQL, or secrets in shared diagnostics.
3. Restore the original immutable migration/binary that matches the applied
   database, or restore the correct database backup for the intended binary.
4. For an intentional build-out baseline change, rebuild the core database
   from the current schema. Do not add a forward repair migration. Independently
   owned custom-plugin histories remain immutable; restore their matching code
   or use their own versioned migration mechanism.
5. Re-run `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=status`, then `up`, only
   after the immutable history and database agree.

For orphan plugin history, restore a trusted binary that includes the matching
plugin declarations and keep those declarations compiled for that database, or
restore/rebuild a database whose verified history matches the intended binary.
Do not merely delete the orphan rows. Never repair an integrity failure by
manually inserting/deleting tracking rows, overwriting a stored checksum, or
changing and re-running an already-applied migration. Ferrum intentionally
provides no emergency bypass for this integrity check.

### MySQL stale identity collation warning

On MySQL, after migrations, Ferrum inspects Ferrum identity-bearing columns
for `utf8mb4_0900_bin`. A structured `warn!` listing
affected `table.column` pairs and the exact
`ALTER TABLE <name> CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`
statements means an upgraded database still uses an older collation (for
example `utf8mb4_general_ci` or `utf8mb4_0900_as_cs`). Until those ALTERs run,
DB uniqueness can silently diverge from the runtime's byte-keyed indexes.
Startup is not blocked. See
[configuration.md → MySQL minimum version](configuration.md#mysql-minimum-version).

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

MongoDB does not use SQL migrations. Instead, `MongoStore::run_migrations()`
creates indexes from the canonical plan in
`src/config/mongo_index_plan.rs` using idempotent `createIndex` operations.
Conflicting existing index options fail initialization and require a fresh
build-out database; Ferrum never drops an old index automatically.
Running the same baseline multiple times is safe — `createIndex` is a no-op if
the full index spec (keys + options) already matches. Migrate dry-run prints
that same plan without connecting; migrate status connects, runs `listIndexes`,
and reports each required index as present, missing, or mismatched, plus whether
the required guard-collection shells exist (connectivity or authentication
failures return nonzero).

### What Gets Created

The authoritative index and empty-shell collection list lives only in
`src/config/mongo_index_plan.rs` (`required_mongo_indexes` /
`REQUIRED_GUARD_COLLECTIONS`). Do not maintain a second summary of keys or
options here — it will drift. Collections covered by the baseline plan include
`proxies`, `consumers`, `consumer_identity_index`, `plugin_configs`,
`upstreams`, `api_specs`, `audit_events`, `config_changes`,
`gateway_trust_bundles`, plus the guard collections `proxy_route_locks`,
`upstream_ref_guards`, and `mtls_dns_admission_locks`.

`gateway_trust_bundles` keys documents by namespace (`_id` IS the namespace), so
the implicit `_id` index is what enforces one trust-bundle record per namespace;
the plan adds only a `{namespace, id}` compound index for addressed admin reads
and deletes. See [CP/DP mode](cp_dp_mode.md#trust-bundle-config-store-capabilities).

### Running MongoDB Migrations

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=mongodb \
  FERRUM_DB_URL="mongodb://localhost:27017" \
  FERRUM_MONGO_DATABASE=ferrum \
  ferrum-edge run
```

Preview the canonical plan without connecting:

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=mongodb \
  ferrum-edge run
```

Compare live indexes to the plan (connects; does not mutate):

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=mongodb \
  FERRUM_DB_URL="mongodb://localhost:27017" \
  FERRUM_MONGO_DATABASE=ferrum \
  ferrum-edge run
```

### Schema Differences from SQL

- **No junction tables**: SQL uses `proxy_plugins` — keyed `(namespace, proxy_id, plugin_config_id)` — to associate proxies with plugins. MongoDB embeds plugin associations directly in proxy documents.
- **Composite document keys**: the `proxies`, `upstreams`, `plugin_configs`, `api_specs`, and `consumers` collections use `_id = "{namespace}:{id}"`, matching the SQL `PRIMARY KEY (namespace, id)`. Hand-written queries must build that key, not the bare resource id.
- **No migration tracking table**: SQL tracks applied migrations in `_ferrum_migrations`. MongoDB indexes are idempotent and don't need tracking.
- **Automatic field propagation**: New fields added to domain types (`Proxy`, `Consumer`, etc.) are automatically persisted to MongoDB via serde BSON serialization — no ALTER TABLE equivalent needed.

### MongoDB Custom Plugin Storage

The `CustomPluginMigration` system (using SQL `CREATE TABLE` statements) is **SQL-only**. When `FERRUM_DB_TYPE=mongodb`, custom plugin SQL migrations are skipped.

Custom plugins that need MongoDB-specific collections or indexes should:
1. Create collections/indexes in their `create_plugin()` initialization function
2. Use the MongoDB driver's `createIndex` (idempotent) to ensure indexes exist
3. Prefix collection names with the plugin name to avoid collisions (e.g., `my_plugin_audit_log`)
