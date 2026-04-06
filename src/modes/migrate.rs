//! Migration mode — database schema and config file version migrations.
//!
//! Three sub-actions selected by `FERRUM_MIGRATE_ACTION`:
//! - `up` — apply pending SQL schema migrations (creates tables, indexes, columns)
//! - `status` — show which migrations are applied/pending without making changes
//! - `config` — migrate a YAML/JSON config file to the current format version
//!
//! This mode exits after completion (no long-running process).

use tracing::{error, info};

use crate::config::EnvConfig;
use crate::config::config_migration::ConfigMigrator;
use crate::config::migrations::MigrationRunner;
use crate::config::types::CURRENT_CONFIG_VERSION;

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
            error!("Unknown migrate action: {}", action);
            anyhow::bail!(
                "Invalid FERRUM_MIGRATE_ACTION '{}'. Expected: up, status, config",
                action
            );
        }
    }
}

async fn run_db_migrations(env_config: &EnvConfig, dry_run: bool) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    info!("Connecting to database (type={})...", db_type);

    // MongoDB: index creation via MongoStore::run_migrations()
    if db_type == "mongodb" {
        if dry_run {
            println!("MongoDB dry run: indexes would be created/verified on collections");
            println!("  proxies: name (unique), updated_at, upstream_id, listen_port");
            println!("  consumers: username (unique), custom_id (unique sparse), updated_at");
            println!("  plugin_configs: proxy_id, updated_at");
            println!("  upstreams: name (unique), updated_at");
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
            env_config.db_tls_enabled,
            env_config.db_tls_ca_cert_path.as_deref(),
            env_config.db_tls_client_cert_path.as_deref(),
            env_config.db_tls_client_key_path.as_deref(),
            env_config.db_tls_insecure,
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

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(5)
        .connect(&effective_url)
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
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    info!("Connecting to database (type={})...", db_type);

    // MongoDB: no SQL migration tracking — indexes are idempotent
    if db_type == "mongodb" {
        println!("=== Ferrum Edge Migration Status (MongoDB) ===\n");
        println!("MongoDB uses idempotent index creation instead of versioned migrations.");
        println!("Run 'FERRUM_MIGRATE_ACTION=up' to ensure all indexes exist.");
        return Ok(());
    }

    sqlx::any::install_default_drivers();

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(5)
        .connect(&effective_url)
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
