# Ferrum Edge Migration & Upgrade Guide

This document explains how Ferrum Edge handles upgrades between versions, including database schema migrations and configuration file migrations.

## Overview

Ferrum Edge uses a versioned migration system that:

- **Tracks applied database migrations** in a `_ferrum_migrations` table
- **Versions configuration files** with a `version` field
- **Auto-migrates on startup** (no manual intervention required for normal operation)
- **Provides a CLI mode** for operators who want explicit control

## Database Migrations

### How It Works

When Ferrum Edge starts in `database`, `cp`, or `migrate` mode, it runs the **MigrationRunner** which:

1. Creates the `_ferrum_migrations` tracking table if it doesn't exist
2. Detects pre-migration databases (databases created before the migration system was added) and bootstraps them by marking the initial schema as "already applied"
3. Checks which migrations have been applied by reading `_ferrum_migrations`
4. Runs any pending migrations in order
5. Records each applied migration with its version, name, timestamp, checksum, and execution time

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

If you're upgrading from a version of Ferrum Edge that predates the migration system (any version before this feature was added), the process is automatic:

1. The MigrationRunner detects that the `proxies` table exists but `_ferrum_migrations` does not contain any records
2. It marks the V1 (initial_schema) migration as already applied
3. Any subsequent migrations (V2, V3, etc.) are then applied normally

**No manual intervention is required.** Just upgrade the binary and start it.

### Cross-Database Support

SQL migrations work across all supported SQL databases:
- **SQLite** (default)
- **PostgreSQL**
- **MySQL**

Each migration is a Rust function that can dispatch different SQL based on the database type when needed, ensuring DDL compatibility across all three SQL backends.

**MongoDB** does not use SQL migrations. When `FERRUM_DB_TYPE=mongodb`, the migration runner creates indexes instead (idempotent `createIndex` operations). See the [MongoDB Migrations](#mongodb-migrations) section below.

### Checksum Validation

Each migration has a compile-time checksum. When the gateway starts, it compares the checksum of each applied migration against the expected checksum in the code. If a mismatch is detected (indicating the migration source was modified after being applied), a warning is logged. This is a diagnostic aid, not a hard error.

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

### Checksum Validation

Like core migrations, checksums are validated on each run. If a plugin migration's checksum differs from what was recorded when it was applied, a warning is logged. This helps detect unintended modifications to already-applied migrations.

### Table Naming Convention

Prefix custom tables to avoid collisions with core gateway tables (`proxies`, `consumers`, `upstreams`, `plugin_configs`, `proxy_plugins`) and other plugins.

### Complete Example

See `custom_plugins/example_audit_plugin.rs` for a full working example with multi-version migrations, PostgreSQL/MySQL overrides, and multi-statement SQL.

See [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md#database-migrations) for the complete developer guide.

## Configuration File Migrations

### Version Field

Configuration files (YAML or JSON) support an optional `version` field:

```yaml
version: "1"
proxies:
  - id: "proxy-1"
    # ...
consumers: []
plugin_configs: []
```

When the `version` field is absent, the config is treated as version `"1"` (the original format). This ensures backwards compatibility with existing configuration files.

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

### Run Pending Database Migrations

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  ferrum-edge
```

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
  V1: initial_schema (applied: 2025-01-15T10:30:00Z, checksum: v001_initial_schema_a1b2c3d4)

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
3. Fix the underlying issue (e.g., data that violates a new constraint)
4. Re-run the migration — it will skip already-applied migrations and retry the failed one

For config files, restore from the `.backup.*` file that was created before the migration started.

## MongoDB Migrations

MongoDB does not use SQL migrations. Instead, `MongoStore::run_migrations()` creates indexes using idempotent `createIndex` operations. Running the same migration multiple times is safe — `createIndex` is a no-op if the index already exists.

### What Gets Created

| Collection | Indexes |
|-----------|---------|
| `proxies` | `name` (unique), `updated_at`, `upstream_id`, `listen_port` |
| `consumers` | `username` (unique), `custom_id` (unique sparse), `updated_at` |
| `plugin_configs` | `proxy_id`, `updated_at` |
| `upstreams` | `name` (unique), `updated_at` |

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
