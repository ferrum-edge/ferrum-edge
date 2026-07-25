//! Migration mode — database schema and config file version migrations.
//!
//! Three sub-actions selected by `FERRUM_MIGRATE_ACTION`:
//! - `up` — apply pending SQL schema migrations (creates tables, indexes, columns)
//! - `status` — show which migrations are applied/pending without making changes
//! - `config` — migrate a YAML/JSON config file to the current format version
//!
//! This mode exits after completion (no long-running process).

use sqlx::Executor;
use tracing::{error, info};

use crate::config::EnvConfig;
use crate::config::config_migration::ConfigMigrator;
use crate::config::migrations::MigrationRunner;
use crate::config::types::CURRENT_CONFIG_VERSION;

fn sql_migration_pool_options(db_type: &str) -> sqlx::any::AnyPoolOptions {
    let mut options = sqlx::any::AnyPoolOptions::new().max_connections(5);
    if db_type == "sqlite" {
        options = options.after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("PRAGMA foreign_keys = ON").await?;
                Ok(())
            })
        });
    }
    options
}

pub async fn run(
    env_config: EnvConfig,
    _shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let action = &env_config.migrate_action;
    let dry_run = env_config.migrate_dry_run;

    match action.as_str() {
        "up" => run_db_migrations(&env_config, dry_run).await,
        "status" => show_db_status(&env_config).await,
        "config" => run_config_migration(&env_config, dry_run),
        _ => {
            // `migrate_action` is lowercased at parse time, so both renderings
            // are transformed forms; withhold by key rather than relying on the
            // length-bounded textual pass.
            let shown = crate::secrets::quoted_env_value("FERRUM_MIGRATE_ACTION", action);
            error!("Unknown migrate action: {}", shown);
            anyhow::bail!(
                "Invalid FERRUM_MIGRATE_ACTION {}. Expected: up, status, config",
                shown
            );
        }
    }
}

async fn run_db_migrations(env_config: &EnvConfig, dry_run: bool) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    info!("Connecting to database (type={})...", db_type);

    // MongoDB: index creation via MongoStore::run_migrations()
    if db_type == "mongodb" {
        if dry_run {
            for line in crate::config::mongo_index_plan::dry_run_lines() {
                println!("{line}");
            }
            return Ok(());
        }
        let store = crate::config::mongo_store::MongoStore::connect(
            &effective_url,
            &env_config.mongo_database,
            env_config.mongo_app_name.as_deref(),
            env_config.mongo_replica_set.as_deref(),
            env_config.mongo_auth_mechanism.as_deref(),
            env_config.mongo_server_selection_timeout_seconds,
            env_config.mongo_connect_timeout_seconds,
            env_config.db_tls_enabled(),
            env_config.db_tls_ca_cert_path.as_deref(),
            env_config.db_tls_client_cert_path.as_deref(),
            env_config.db_tls_client_key_path.as_deref(),
            env_config.mongodb_tls_allows_invalid_certs(),
        )
        .await?;
        use crate::config::db_backend::DatabaseBackend;
        store.run_migrations().await?;
        println!("MongoDB indexes ensured successfully.");
        return Ok(());
    }

    // SQL databases: run schema migrations
    // Connect without running migrations automatically
    sqlx::any::install_default_drivers();

    let pool = crate::config::db_loader::connect_any_pool_with_timeout(
        sql_migration_pool_options(db_type),
        &effective_url,
        db_type,
        env_config.db_pool_connect_timeout_seconds,
    )
    .await?;

    let runner = MigrationRunner::new(pool, db_type.to_string());

    if dry_run {
        info!("Dry run mode — checking pending migrations without applying");
        let status = runner.status().await?;

        if status.pending.is_empty() {
            println!("Database schema is up to date. No pending migrations.");
        } else {
            println!("Pending migrations that would be applied:");
            for m in &status.pending {
                println!("  V{}: {}", m.version, m.name);
            }
        }

        // Custom plugin migrations (dry run)
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if !plugin_migrations.is_empty() {
            let plugin_status = runner.plugin_status(&plugin_migrations).await?;
            if plugin_status.pending.is_empty() {
                println!("\nCustom plugin migrations are up to date. No pending migrations.");
            } else {
                println!("\nPending custom plugin migrations that would be applied:");
                for m in &plugin_status.pending {
                    println!("  [{}] V{}: {}", m.plugin_name, m.version, m.name);
                }
            }
        }
    } else {
        info!("Running pending database migrations...");
        let applied = runner.run_pending().await?;

        if applied.is_empty() {
            println!("Database schema is up to date. No migrations applied.");
        } else {
            println!("Applied {} migration(s):", applied.len());
            for m in &applied {
                println!("  V{}: {} ({}ms)", m.version, m.name, m.execution_time_ms);
            }
        }

        // Custom plugin migrations
        let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
        if !plugin_migrations.is_empty() {
            info!("Running pending custom plugin migrations...");
            let plugin_applied = runner.run_plugin_pending(&plugin_migrations).await?;

            if plugin_applied.is_empty() {
                println!("\nCustom plugin migrations are up to date. No migrations applied.");
            } else {
                println!(
                    "\nApplied {} custom plugin migration(s):",
                    plugin_applied.len()
                );
                for m in &plugin_applied {
                    println!(
                        "  [{}] V{}: {} ({}ms)",
                        m.plugin_name, m.version, m.name, m.execution_time_ms
                    );
                }
            }
        }
    }

    Ok(())
}

async fn show_db_status(env_config: &EnvConfig) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    info!("Connecting to database (type={})...", db_type);

    // MongoDB: connect and non-mutatingly compare live indexes to the
    // canonical plan. Connectivity/authentication failures return Err.
    if db_type == "mongodb" {
        let store = crate::config::mongo_store::MongoStore::connect(
            &effective_url,
            &env_config.mongo_database,
            env_config.mongo_app_name.as_deref(),
            env_config.mongo_replica_set.as_deref(),
            env_config.mongo_auth_mechanism.as_deref(),
            env_config.mongo_server_selection_timeout_seconds,
            env_config.mongo_connect_timeout_seconds,
            env_config.db_tls_enabled(),
            env_config.db_tls_ca_cert_path.as_deref(),
            env_config.db_tls_client_cert_path.as_deref(),
            env_config.db_tls_client_key_path.as_deref(),
            env_config.mongodb_tls_allows_invalid_certs(),
        )
        .await?;

        let status = store.migration_status().await?;
        use crate::config::mongo_index_plan::IndexPresence;

        println!("=== Ferrum Edge Migration Status (MongoDB) ===\n");
        println!("MongoDB uses idempotent index creation instead of versioned migrations.");
        println!(
            "Compared live indexes and guard collections to the canonical plan \
             (listIndexes/listCollections only; no mutations).\n"
        );

        let mut present = 0usize;
        let mut missing = 0usize;
        let mut mismatched = 0usize;
        for entry in &status.indexes {
            match &entry.presence {
                IndexPresence::Present => {
                    present += 1;
                    println!("  [present]    {}.{}", entry.collection, entry.summary);
                }
                IndexPresence::Missing => {
                    missing += 1;
                    println!("  [missing]    {}.{}", entry.collection, entry.summary);
                }
                IndexPresence::Mismatched { detail } => {
                    mismatched += 1;
                    println!(
                        "  [mismatched] {}.{} ({detail})",
                        entry.collection, entry.summary
                    );
                }
            }
        }

        let mut guard_collections_present = 0usize;
        let mut guard_collections_missing = 0usize;
        println!("\nRequired guard collections:");
        for entry in &status.guard_collections {
            if entry.present {
                guard_collections_present += 1;
                println!("  [present]    {}", entry.collection);
            } else {
                guard_collections_missing += 1;
                println!("  [missing]    {}", entry.collection);
            }
        }

        println!(
            "\nSummary: indexes: {present} present, {missing} missing, {mismatched} mismatched \
             (of {} required); guard collections: {guard_collections_present} present, \
             {guard_collections_missing} missing (of {} required).",
            status.indexes.len(),
            status.guard_collections.len()
        );
        if missing > 0 || mismatched > 0 || guard_collections_missing > 0 {
            println!("Run 'FERRUM_MIGRATE_ACTION=up' to ensure the full plan exists.");
        } else {
            println!("All required indexes and guard collections are present.");
        }
        return Ok(());
    }

    sqlx::any::install_default_drivers();

    let pool = crate::config::db_loader::connect_any_pool_with_timeout(
        sql_migration_pool_options(db_type),
        &effective_url,
        db_type,
        env_config.db_pool_connect_timeout_seconds,
    )
    .await?;

    let runner = MigrationRunner::new(pool, db_type.to_string());
    let status = runner.status().await?;

    println!("=== Ferrum Edge Migration Status ===\n");

    if status.applied.is_empty() {
        println!("Applied migrations: (none)");
    } else {
        println!("Applied migrations:");
        for m in &status.applied {
            println!(
                "  V{}: {} (applied: {}, checksum: {})",
                m.version, m.name, m.applied_at, m.checksum
            );
        }
    }

    println!();

    if status.pending.is_empty() {
        println!("Pending migrations: (none — schema is up to date)");
    } else {
        println!("Pending migrations:");
        for m in &status.pending {
            println!("  V{}: {}", m.version, m.name);
        }
    }

    // Custom plugin migration status
    let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
    if !plugin_migrations.is_empty() {
        let plugin_status = runner.plugin_status(&plugin_migrations).await?;

        println!("\n=== Custom Plugin Migration Status ===\n");

        if plugin_status.applied.is_empty() {
            println!("Applied plugin migrations: (none)");
        } else {
            println!("Applied plugin migrations:");
            for m in &plugin_status.applied {
                println!(
                    "  [{}] V{}: {} (applied: {}, checksum: {})",
                    m.plugin_name, m.version, m.name, m.applied_at, m.checksum
                );
            }
        }

        println!();

        if plugin_status.pending.is_empty() {
            println!("Pending plugin migrations: (none — all plugins up to date)");
        } else {
            println!("Pending plugin migrations:");
            for m in &plugin_status.pending {
                println!("  [{}] V{}: {}", m.plugin_name, m.version, m.name);
            }
        }
    }

    Ok(())
}

fn run_config_migration(env_config: &EnvConfig, dry_run: bool) -> Result<(), anyhow::Error> {
    let config_path = env_config.file_config_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("FERRUM_FILE_CONFIG_PATH is required for config migration")
    })?;

    let current_version = ConfigMigrator::detect_version(config_path)?;
    println!(
        "Config file: {}\nCurrent version: {}\nTarget version: {}",
        config_path, current_version, CURRENT_CONFIG_VERSION
    );

    if current_version == CURRENT_CONFIG_VERSION {
        println!("\nConfig file is already at the current version. No migration needed.");
        return Ok(());
    }

    if dry_run {
        println!(
            "\nDry run mode — config file would be migrated from version {} to {}.",
            current_version, CURRENT_CONFIG_VERSION
        );
        println!("A backup would be created before migration.");
    } else {
        let result = ConfigMigrator::migrate_file(config_path)?;
        if result.migrations_applied > 0 {
            println!(
                "\nMigrated config from version {} to {} ({} step(s))",
                result.from_version, result.to_version, result.migrations_applied
            );
            if let Some(backup) = result.backup_path {
                println!("Backup saved to: {}", backup);
            }
        } else {
            println!("\nNo migration needed.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn sqlite_migration_pool_enables_foreign_keys_per_connection() {
        sqlx::any::install_default_drivers();
        let pool = crate::config::db_loader::connect_any_pool_with_timeout(
            sql_migration_pool_options("sqlite"),
            "sqlite::memory:",
            "sqlite",
            10,
        )
        .await
        .expect("connect sqlite migration pool");

        let row = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .expect("read foreign_keys pragma");
        let enabled: i64 = row.try_get(0).expect("pragma integer");

        assert_eq!(enabled, 1);
    }
}
