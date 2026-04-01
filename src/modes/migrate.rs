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
    }

    Ok(())
}

async fn show_db_status(env_config: &EnvConfig) -> Result<(), anyhow::Error> {
    let effective_url = env_config
        .effective_db_url()
        .unwrap_or_else(|| "sqlite://ferrum.db".to_string());
    let db_type = env_config.db_type.as_deref().unwrap_or("sqlite");

    info!("Connecting to database (type={})...", db_type);

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
