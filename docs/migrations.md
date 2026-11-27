# Ferrum Edge Database Baselines and Migrations

This guide covers database initialization, forward-only core schema
migrations, migration-history integrity checks, and independently owned
custom-plugin migrations.

## Overview

- SQL databases initialize from one frozen core baseline, `V001`, tracked in
  `_ferrum_migrations`. Its checksum is derived from the canonical DDL it
  executes, not from Rust source text.
- From 1.0.0 onward, every core schema change ships as a new forward migration
  (`V002`, `V003`, ...) that runs after `V001`; shipped migrations are never
  edited.
- MongoDB applies a versioned, forward-only index plan and records the plan
  version it applied.
- `database` and `cp` startup apply pending core migrations automatically;
  `FERRUM_MODE=migrate` provides explicit `up`, `status`, `config`, and dry-run
  actions.
- Startup never alters schema outside a declared migration, never backfills
  outside one, and never rewrites migration history. A database whose history
  the binary cannot verify (an unknown, missing, or changed migration) refuses
  to start.

## Schema Compatibility Policy

From 1.0.0 onward, the database schema is a compatibility surface:

- The `V001` baseline is frozen. Its identity is pinned by the committed
  constant `V001_BASELINE_CHECKSUM` and the golden test
  `tests/unit/config/v001_baseline_golden_tests.rs`, which fails on any change
  to the statements `V001` executes.
- Every change to a built-in table, column, or index ships as the next forward
  migration. See [Adding a forward migration](#adding-a-forward-migration).
- A shipped migration is never edited, reordered, or removed: its recorded
  checksum makes an edit a fatal integrity error on every database that already
  applied it.
- An older binary refuses a database that a newer release migrated (an unknown
  applied version), so a downgrade means restoring the matching binary or the
  pre-upgrade backup.
- Stored database values, like environment variables and config shapes, change
  only with a documented deprecation path; see the compatibility policy in
  [CLAUDE.md](../CLAUDE.md#compatibility-policy).

MongoDB follows the same rule through its versioned index plan; see
[MongoDB Migrations](#mongodb-migrations). Custom plugin migrations keep their
own versioned sequences because plugin storage is independently owned.

### Build-Out Schema Policy

Releases before 1.0.0 (the 0.9.x line and earlier `main` snapshots) had no
deployed-user compatibility obligation. Core schema changes were folded into
the editable `V001` baseline instead of being shipped as `V002`+ migrations,
and any baseline change required a fresh database or an operator-managed
rebuild. That policy ends at 1.0.0.

**Upgrading any 0.9.x database to 1.0.0 is a final rebuild-and-restore.** The
1.0.0 baseline identity differs from every identity a 0.9.x release recorded:
1.0.0 derives the `V001` checksum from canonical DDL instead of source text, and
the baseline itself changed after v0.9.21 (#7485 added
`config_change_locks.changes_since_compaction` and a MySQL `listen_path`
collation; #7504 changed the source text 0.9.x hashed). A 1.0.0 binary started
against a 0.9.x SQL database
therefore refuses it with a `V001` checksum-mismatch integrity error, by
design. Export a namespace-complete logical backup with the 0.9.x binary,
initialize an empty database with 1.0.0, and restore into it, as described in
[admin_backup_restore.md](admin_backup_restore.md) and the step-by-step
[database rebuild procedure](upgrade_guide.md#build-out-database-upgrade-postgresql-mysql-sqlite-mongodb).
MongoDB databases take the same path. From 1.0.0 onward, upgrades between
releases apply forward migrations in place.

### Canonical schema locations

| Storage | Complete baseline |
|---|---|
| PostgreSQL, MySQL, SQLite | `src/config/migrations/v001_initial_schema.rs` (identity, `V001_BASELINE_CHECKSUM`) delegates to `src/config/migrations/sql_dialect.rs` for the complete dialect-specific schema and initial `ferrum` namespace; forward migrations are appended in `MigrationRunner::shipped_migrations()` (`src/config/migrations/mod.rs`) |
| MongoDB | `src/config/mongo_index_plan.rs` (`MONGO_INDEX_PLAN_VERSION`, `required_mongo_indexes`, `RETIRED_MONGO_INDEXES`); `MongoStore` initializes an empty namespace registry with `ferrum` |
| ClickHouse chargeback sink | [`schemas/clickhouse/charges.sql`](../schemas/clickhouse/charges.sql), applied separately to the external analytics database |
| Custom plugins | `plugin_migrations()` in each compiled `custom_plugins/*.rs`; independent plugin-owned tables |

There is no separate core SQL patch directory or startup compatibility pass:
the ordered migration list is the only way schema changes reach a database.

## Stability & Upgrade Contract

This section states, in one place, what stability you can rely on across
branches and releases, when the schema freeze happens, and how breaking changes
are announced.

### What each channel guarantees

| Channel | What it is | Schema / config / API stability |
|---|---|---|
| `main` | Main CI validates each push and publishes no production artifacts (see [ci_cd.md](ci_cd.md)); the `latest` / `main-<sha>` container tags are development builds of `main` commits that passed CI. | No promise between arbitrary commits: a forward migration can still change shape before it is first released. From 1.0.0 onward, `main` never edits `V001` or a released migration, so a database created by a tagged release keeps upgrading forward. Before 1.0.0, schema changes were folded into `V001` (see [Build-Out Schema Policy](#build-out-schema-policy)). Do not run `latest` in production with data you cannot recreate. |
| Tagged release `vX.Y.Z` | A `v*` tag cuts a versioned GitHub Release + Docker tags from a green CI/coverage SHA. | Semantic versioning per [ci_cd.md → Version Numbering](ci_cd.md#version-numbering). The promises in [Version Compatibility](upgrade_guide.md#version-compatibility) apply **between tagged releases**, not between arbitrary `main` commits. |

The CP↔DP gRPC protocol requires CP and DP to run the **same build**; mixed
CP/DP builds, including patch-level differences, are not supported. The
ConfigSync build-identity gate rejects any other build at `Subscribe` (see
[Build Identity Gate](upgrade_guide.md#build-identity-gate)).

### When V002+ migrations start (the schema freeze)

> **The `V001` baseline freezes at 1.0.0.** From 1.0.0 onward, any change to a
> built-in table, column, or index ships as a new versioned forward migration
> (`V002`+), and the fold-into-`V001` and no-legacy-shims allowances are
> retired. Releases before 1.0.0 edited `V001` in place, as described in
> [Build-Out Schema Policy](#build-out-schema-policy).

The runner, its integrity checks, and the `migrate status` / `up` reports
already handle `V002`+: the forward path is exercised against SQLite,
PostgreSQL, and MySQL by `tests/service_integration/forward_migrations_sqlite_postgres_mysql.rs`
with a test-only `V002`. No shipped `V002` exists until the first schema change
after 1.0.0 needs one.

### How breaking changes are announced

- **Between tagged releases:** breaking schema / config / env / API changes are
  called out in that release's GitHub Release notes, keyed to the migration or
  the env/config surface that changed. Operators upgrade tag-to-tag using
  [upgrade_guide.md](upgrade_guide.md): from 1.0.0 onward through versioned
  forward migrations applied at startup or by `migrate up`; from any 0.9.x
  release to 1.0.0 through the one-time
  [rebuild-and-restore](#build-out-schema-policy).
- **On `main`:** there is no per-commit changelog promise. New `FERRUM_*` env
  vars land with `docs/configuration.md` + `ferrum.conf` updates in the same
  change, and schema-affecting changes add a forward migration and its tests.

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

Ferrum does not detect or special-case untracked schemas. When
`_ferrum_migrations` is missing or empty, `V001` is simply pending and runs
like it would on a fresh database. Its schema statements use
`CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` (on MySQL, an
already-existing unique index is tolerated), and the default-namespace seed
does nothing if the row already exists. As a result:

- **Compatible untracked schema:** if the existing tables already have every
  column and index the current baseline references, `V001` completes and its
  tracking row is recorded. The database is adopted as-is. Ferrum does not
  compare live table definitions against the baseline, so success does not
  prove they match.
- **Incompatible untracked schema:** if a baseline statement references a
  column or table shape the existing schema lacks (for example an older
  pre-tracking layout), `V001` fails, startup or `up` returns an error, and
  no tracking row is recorded, so `V001` stays pending.

Do not rely on adoption. Back up the database and rebuild it from the current
baseline before starting a current binary against a database that predates
migration tracking. The same applies to every database created by a release
before 1.0.0 (see [Build-Out Schema Policy](#build-out-schema-policy)).
Once tracking rows exist, the history checks in
[Migration History Integrity](#migration-history-integrity) apply instead. The
stored `V001` checksum identifies the baseline DDL the binary executes, not the
live schema, so a database recorded with a different baseline is refused as
checksum drift.

### Cross-Database Support

SQL migrations work across all supported SQL databases:
- **SQLite** (default)
- **PostgreSQL**
- **MySQL**

Each migration is a Rust function that can dispatch different SQL based on the database type when needed, ensuring DDL compatibility across all three SQL backends.

**MongoDB** does not use SQL migrations. When `FERRUM_DB_TYPE=mongodb`, the migration runner creates indexes instead (idempotent `createIndex` operations). See the [MongoDB Migrations](#mongodb-migrations) section below.

### Migration History Integrity

Each migration has a checksum. Core migrations use a `sha256:<hex>` digest of
their canonical DDL: every statement the migration executes on PostgreSQL,
MySQL, and SQLite, in order, exactly as sent (MySQL index statements without
`IF NOT EXISTS`), with runs of whitespace collapsed. Comments, formatting, and
helper refactors in the Rust source do not change it; any change to an executed
statement does. `V001`'s value is committed as `V001_BASELINE_CHECKSUM` and
pinned by a golden test. Before any write, Ferrum
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
command-line use therefore exits non-zero. There is deliberately no
compatibility shim for the former fixed `v001_initial_schema` label or for
0.9.x source-derived `V001` checksums, and no migration-integrity override.
An unknown applied core version is how a binary downgrade surfaces: the older
binary reports `kind=unknown_applied_version` with the version it does not
know and refuses to start.

## Custom Plugin Migrations

Custom plugins can declare their own database migrations that run alongside core gateway migrations. This allows plugins to create and manage private tables without modifying any core source files. **Note:** The custom plugin migration system is SQL-only. For MongoDB, see [MongoDB Custom Plugin Storage](#mongodb-custom-plugin-storage) below.

### How It Works

1. A custom plugin exports a `plugin_migrations()` function from its `.rs` file in `custom_plugins/`
2. The build script detects this function automatically and generates a collector
3. When `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` is run, plugin migrations execute **after** core migrations
4. At `database` / `cp` startup, pending plugin migrations are only logged as a
   warning unless `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true`, which applies them
   before config is loaded (a failure is then fatal)
5. Plugin migrations are tracked in `_ferrum_plugin_migrations` (separate from `_ferrum_migrations`)

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

The runner owns every transaction boundary (the SQLite migration lock is itself
a `BEGIN IMMEDIATE` transaction, and PostgreSQL bodies share one transaction
with their tracking row), so custom-plugin SQL must not contain top-level
transaction-control statements: `BEGIN`, `START TRANSACTION`, `COMMIT`, `END`,
`ROLLBACK` (other than `ROLLBACK … TO` a savepoint), PostgreSQL `ABORT` /
`PREPARE TRANSACTION`, or MySQL `XA`. A body containing one is rejected, for
every dialect, before any statement executes. `SAVEPOINT`, `RELEASE`, and
`ROLLBACK TO` are allowed, as is transaction control inside a stored routine
body.

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
  or deletion, and `ALTER SYSTEM`. Detection reads SQL keywords only, ignoring
  comments and quoted text: `CREATE /* online */ INDEX CONCURRENTLY` is
  detected, while a `/* CONCURRENTLY */` comment or a `'CONCURRENTLY'` literal
  does not select top-level execution. Ferrum executes every statement first and
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
  be idempotent / re-runnable.** For a plugin-owned index that must recover
  across every statement boundary, pair `DROP INDEX name ON table` immediately
  with the exact `CREATE INDEX` definition. The runner tolerates only
  structured MySQL error `1091` (missing key) on a two-token
  `DROP INDEX name ON table` statement (not the `ALTER TABLE ... DROP INDEX`
  spelling); every creation failure remains fatal. A retry then either removes the prior
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
unsupported versions fail. Run `ferrum-edge validate` before starting the
gateway on a changed file. From 1.0.0 onward the `version: "1"` shape is a
compatibility surface: a change that would reject existing files needs a
documented deprecation path (or a new config version with a `ConfigMigrator`
step). Do not add speculative migration steps before a change needs one.

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

### Check Migration Status

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge run
```

`status` is strictly read-only. If the core or plugin tracking table does not
exist, Ferrum reports every known migration as pending without creating either
tracking table. If any applied sequence is unknown, incomplete, duplicate,
orphaned, or checksum-drifted, `status` returns an integrity error and exits
non-zero instead of reporting the database as healthy.

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

Config dry-run (`FERRUM_MIGRATE_ACTION=config`) checks the migration path the
same way a real run does: a current-version file reports no migration, and a
version with no migration path (for example `version: "0"`) fails with the
same error a real run returns. It never creates a backup or rewrites the file.

## Environment Variables Reference

| Variable | Values | Description |
|----------|--------|-------------|
| `FERRUM_MODE` | `migrate` | Activates the migration CLI mode |
| `FERRUM_MIGRATE_ACTION` | `up` (default), `status`, `config` | What migration action to perform |
| `FERRUM_MIGRATE_DRY_RUN` | `true` / `false` | Preview changes without applying |
| `FERRUM_DB_TYPE` | `sqlite`, `postgres`, `mysql`, `mongodb` | Required for `up` and `status` actions |
| `FERRUM_DB_URL` | Database connection URL | Required for `up` and `status` actions (including MongoDB dry-run) |
| `FERRUM_MONGO_DATABASE` | Database name (default `ferrum`) | MongoDB database to index |
| `FERRUM_FILE_CONFIG_PATH` | Path to config file | Required for `config` action |
| `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS` | `true` / `false` (default) | `database` / `cp` startup only: apply pending custom-plugin migrations instead of warning |

## Changing the Schema (Developer Guide)

### Adding a forward migration

From 1.0.0 onward, a core SQL schema change never edits `sql_dialect.rs`'s
`V001` statements. Instead:

1. Declare the next migration as a `SqlMigration` (`src/config/migrations/mod.rs`)
   with the next unused `version`, a `name`, and the statements for each of
   PostgreSQL, MySQL, and SQLite. Keep the dialects aligned the way the `V001`
   baseline does. Use a dedicated `MigrationEntry` only when plain DDL is not
   enough (for example a data backfill).
2. Append it to `MigrationRunner::shipped_migrations()`. Never reorder, edit, or
   remove a shipped entry; the next change is another migration.
3. Make every statement safe to re-run after a partial failure: MySQL commits
   DDL implicitly and PostgreSQL runs these statements outside an explicit
   transaction, and the tracking row is written only after every statement
   succeeds. Use `IF NOT EXISTS` forms where the dialect has them. On MySQL a
   `CREATE [UNIQUE] INDEX` that hits duplicate-key-name error 1061 and a
   two-token `DROP INDEX name ON table` that hits missing-key error 1091 are
   tolerated, exactly as for `V001` and custom-plugin migrations.
4. Update persistence, config types, validation, documentation, and OpenAPI
   where the changed field is exposed, and document the change in the release
   notes and upgrade guide.
5. Test the migration on a database created at the previous release's schema.
   `tests/service_integration/forward_migrations_sqlite_postgres_mysql.rs` shows the pattern
   (SQLite plus PostgreSQL and MySQL containers) through the production runner.

The golden test `tests/unit/config/v001_baseline_golden_tests.rs` fails if a
change alters what `V001` executes; its message points back here.

### Refreshing the V001 golden checksum (before 1.0.0 only)

Releases before 1.0.0 changed the baseline in place. To record a deliberate
pre-1.0.0 baseline change, copy the value the failing golden test prints
(`computed: sha256:...`, also shown as a ready-to-paste
`pub const V001_BASELINE_CHECKSUM` line in the CI log of the Unit Tests job)
into `V001_BASELINE_CHECKSUM` in
`src/config/migrations/v001_initial_schema.rs`. That one line is the only edit.
After 1.0.0 is tagged this constant never changes again.

### Other stores

MongoDB index changes follow the versioned plan rules in
[MongoDB Migrations](#mongodb-migrations). External ClickHouse DDL in
`schemas/clickhouse/charges.sql` is applied separately to the analytics
database. Custom-plugin changes follow
[Custom Plugin Migrations](#custom-plugin-migrations).

### Updating Config Files

Update the config shape, its validation, and the examples together. From 1.0.0
onward a change that existing files would fail is a compatibility break: give
it a deprecation path and call it out in the release notes and upgrade guide.

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
4. A `V001` checksum mismatch on a database created by a release before
   1.0.0 is expected when that database meets a 1.0.0 or later binary: take
   the one-time [rebuild-and-restore](#build-out-schema-policy) path. From
   1.0.0 onward `V001` and every released migration are immutable, so a
   mismatch between two releases is never an expected upgrade outcome. An
   unknown applied version means the binary is older than the database:
   run the newer release or restore the pre-upgrade backup. Independently
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
applies the versioned index plan in `src/config/mongo_index_plan.rs` under the
migration lease:

1. Read the recorded plan version from the `_ferrum_migrations` collection
   (document `_id: "core_index_plan"`, field `version`). If it is newer than
   the binary's `MONGO_INDEX_PLAN_VERSION`, refuse before any write: an older
   binary must not run against a database a newer release upgraded. A record
   that is not a positive integer is also refused.
2. Create the guard collections.
3. Drop, by exact name, each index in `RETIRED_MONGO_INDEXES` whose
   `retired_in` version is above the recorded version (an index that is already
   absent is fine). Nothing else is ever dropped.
4. Ensure every planned index with idempotent `createIndex` operations.
5. Seed the namespace registry, then record the plan version.

A failure before step 5 leaves the old version recorded, so the next run
repeats the same idempotent forward step. A database with no record (fresh, or
initialized by a release before 1.0.0) is treated as version 0. Conflicting
existing index options still fail initialization: `createIndex` is a no-op only
when the full index spec (keys + options) matches. Migrate dry-run prints the
plan without connecting; migrate status connects, runs `listIndexes`, reports
the recorded and binary plan versions and each required index as present,
missing, or mismatched, plus whether the required guard-collection shells
exist. Status also refuses a newer recorded plan version, and connectivity or
authentication failures return nonzero.

### Changing the MongoDB index plan

Each change bumps `MONGO_INDEX_PLAN_VERSION` by one in the release that makes it:

- **Add an index:** add it to `required_mongo_indexes()`.
- **Drop an index:** remove it from the plan and add a `RetiredMongoIndex`
  with its exact index name and `retired_in` set to the new version.
- **Replace an index** (new keys or options): retire the old name and add the
  new definition. Retirements are dropped before the plan is ensured, so the
  replacement may reuse the old name; a unique constraint is absent between
  that drop and the create.

Never edit an existing plan entry's keys or options in place (MongoDB refuses
a same-key index with different options) and never edit or remove a shipped
retirement. Upgrading a MongoDB database created before 1.0.0 to 1.0.0 follows
the same one-time [rebuild-and-restore](#build-out-schema-policy) as SQL.

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

Preview the canonical plan without connecting (`FERRUM_DB_URL` is still
required by startup validation):

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=mongodb \
  FERRUM_DB_URL="mongodb://localhost:27017" \
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
- **Plan version instead of a migration ledger**: SQL tracks every applied migration in the `_ferrum_migrations` table. MongoDB records only the applied index-plan version, in the `_ferrum_migrations` collection (`_id: "core_index_plan"`).
- **Automatic field propagation**: New fields added to domain types (`Proxy`, `Consumer`, etc.) are automatically persisted to MongoDB via serde BSON serialization — no ALTER TABLE equivalent needed. See [mongodb.md](mongodb.md#adding-new-fields).

### MongoDB Custom Plugin Storage

The `CustomPluginMigration` system (using SQL `CREATE TABLE` statements) is **SQL-only**. When `FERRUM_DB_TYPE=mongodb`, custom plugin SQL migrations are skipped.

Custom plugins that need MongoDB-specific collections or indexes should:
1. Create collections/indexes in their `create_plugin()` initialization function
2. Use the MongoDB driver's `createIndex` (idempotent) to ensure indexes exist
3. Prefix collection names with the plugin name to avoid collisions (e.g., `my_plugin_audit_log`)
