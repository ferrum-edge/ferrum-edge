//! Config file version migrations using a chain-of-responsibility pattern.
//!
//! Each migration step transforms a `serde_json::Value` from version N to N+1.
//! The chain is walked linearly: v1→v2→v3→...→current. If the chain is broken
//! (missing step), migration fails fast. `migrate_file()` creates a timestamped
//! backup of the original file before writing the migrated version.

use std::path::Path;
use tracing::{info, warn};

use crate::config::stable_file::{
    MAX_GATEWAY_CONFIG_FILE_BYTES, StableFileReadOptions, read_stable_file,
    stable_file_error_anyhow,
};
use crate::config::types::CURRENT_CONFIG_VERSION;
use crate::config::yaml_alias_budget::admit_yaml_alias_expansion;
use crate::util::deserialization as config_decode;

/// Type alias for a config migration step function.
/// Each function transforms a `serde_json::Value` from version N to version N+1.
type ConfigMigrationFn = fn(&mut serde_json::Value) -> Result<(), anyhow::Error>;

/// Manages config file versioning and migration.
pub struct ConfigMigrator;

/// Result of a config file migration operation.
#[derive(Debug)]
pub struct ConfigMigrateResult {
    pub from_version: String,
    pub to_version: String,
    pub backup_path: Option<String>,
    pub migrations_applied: u32,
}

impl ConfigMigrator {
    /// No config transforms are shipped during build-out. Update the current
    /// config shape directly instead of adding legacy compatibility steps.
    fn migration_chain() -> Vec<(&'static str, &'static str, ConfigMigrationFn)> {
        vec![]
    }

    /// Migrate a `serde_json::Value` config from its current version to the target version.
    ///
    /// Returns the number of migration steps applied. If the config is already at or
    /// beyond the target version, returns 0.
    pub fn migrate_value(
        value: &mut serde_json::Value,
        target_version: &str,
    ) -> Result<u32, anyhow::Error> {
        let current_version = value
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Config is missing required `version` field"))?
            .to_string();

        if current_version == target_version {
            return Ok(0);
        }

        // Validate the full path before mutating anything so an unsupported
        // source version leaves the value untouched.
        Self::plan_migration_steps(&current_version, target_version)?;

        let chain = Self::migration_chain();
        let mut version = current_version;
        let mut steps_applied = 0u32;

        while version != target_version {
            let Some((from, to, migrate_fn)) = chain.iter().find(|(from, _, _)| *from == version)
            else {
                anyhow::bail!(
                    "Config migration chain broken at version (<redacted scalar>) (target: {})",
                    target_version
                );
            };
            info!("Migrating config from version {} to {}", from, to);
            migrate_fn(value)?;
            version = to.to_string();
            steps_applied += 1;
        }

        Ok(steps_applied)
    }

    /// Walk the migration chain from `from_version` to `target_version`
    /// without applying any transform.
    ///
    /// Returns the number of steps a real migration would apply (0 when the
    /// versions are equal). Fails with the same errors as [`Self::migrate_value`]
    /// when no complete path exists, so dry-runs reject exactly what a real
    /// migration rejects.
    pub fn plan_migration_steps(
        from_version: &str,
        target_version: &str,
    ) -> Result<u32, anyhow::Error> {
        let chain = Self::migration_chain();
        let mut version = from_version;
        let mut steps = 0u32;

        while version != target_version {
            // A well-formed chain visits each step at most once; anything longer
            // is a cycle and can never reach the target.
            if steps as usize > chain.len() {
                anyhow::bail!(
                    "Config migration chain broken at version (<redacted scalar>) (target: {})",
                    target_version
                );
            }
            match chain.iter().find(|(from, _, _)| *from == version) {
                Some((_, to, _)) => {
                    version = *to;
                    steps += 1;
                }
                None if steps == 0 => {
                    anyhow::bail!(
                        "No config migration path from version (<redacted scalar>) to {}",
                        target_version
                    );
                }
                None => {
                    anyhow::bail!(
                        "Config migration chain broken at version (<redacted scalar>) (target: {})",
                        target_version
                    );
                }
            }
        }

        Ok(steps)
    }

    /// Dry-run counterpart of [`Self::migrate_file`]: reads the file's version
    /// and validates that a migration path to the current version exists,
    /// without creating a backup or writing anything.
    ///
    /// Returns the result a real migration would produce, with
    /// `backup_path = None` and `migrations_applied` holding the planned step
    /// count. Unsupported versions are rejected with the same error as
    /// [`Self::migrate_file`].
    pub fn plan_file(path: &str) -> Result<ConfigMigrateResult, anyhow::Error> {
        let from_version = Self::detect_version(path)?;
        let target = CURRENT_CONFIG_VERSION;
        let steps = Self::plan_migration_steps(&from_version, target)?;
        let to_version = if steps == 0 {
            from_version.clone()
        } else {
            target.to_string()
        };
        Ok(ConfigMigrateResult {
            from_version,
            to_version,
            backup_path: None,
            migrations_applied: steps,
        })
    }

    /// Migrate a config file in-place, creating a backup first.
    ///
    /// The backup is stored as `{path}.backup.{timestamp}` in the same directory.
    pub fn migrate_file(path: &str) -> Result<ConfigMigrateResult, anyhow::Error> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            anyhow::bail!("Configuration file not found: {:?}", path);
        }

        let content = read_config_migration_file(file_path)?;
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Parse to serde_json::Value (works for both YAML and JSON)
        let mut value: serde_json::Value = match ext.as_str() {
            "json" => config_decode::from_json_str(&content)?,
            _ => parse_yaml_value(&content)?,
        };
        drop(content);

        let from_version = value
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Config is missing required `version` field"))?
            .to_string();

        let target = CURRENT_CONFIG_VERSION;

        if from_version == target {
            info!(
                "Config file is already at version {}, no migration needed",
                target
            );
            return Ok(ConfigMigrateResult {
                from_version: from_version.clone(),
                to_version: from_version,
                backup_path: None,
                migrations_applied: 0,
            });
        }

        let steps = Self::migrate_value(&mut value, target)?;
        if steps == 0 {
            return Ok(ConfigMigrateResult {
                from_version: from_version.clone(),
                to_version: from_version,
                backup_path: None,
                migrations_applied: 0,
            });
        }

        // Create backup
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let backup_path = format!("{}.backup.{}", path, timestamp);
        std::fs::copy(file_path, &backup_path)?;
        info!(
            "Created config backup at {}",
            crate::startup::sanitize_startup_cause(format!("{backup_path:?}"), &[])
        );

        // Write migrated content back in the original format
        let migrated_content = match ext.as_str() {
            "json" => serde_json::to_string_pretty(&value)?,
            _ => {
                // Convert back to YAML
                let yaml_val: serde_yaml::Value = config_decode::from_json_value(value)?;
                serde_yaml::to_string(&yaml_val)?
            }
        };

        std::fs::write(file_path, migrated_content)?;
        info!(
            "Config file migrated from version (<redacted scalar>) to {} ({} steps)",
            target, steps
        );

        Ok(ConfigMigrateResult {
            from_version,
            to_version: target.to_string(),
            backup_path: Some(backup_path),
            migrations_applied: steps,
        })
    }

    /// Check what version a config file is at without modifying it.
    pub fn detect_version(path: &str) -> Result<String, anyhow::Error> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            anyhow::bail!("Configuration file not found: {:?}", path);
        }

        let content = read_config_migration_file(file_path)?;
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let value: serde_json::Value = match ext.as_str() {
            "json" => config_decode::from_json_str(&content)?,
            _ => parse_yaml_value(&content)?,
        };
        drop(content);

        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Config is missing required `version` field"))?
            .to_string();

        Ok(version)
    }

    /// Migrate a serde_json::Value in memory (for use during config loading).
    /// Returns the migrated value, or the original if no migration was needed.
    pub fn migrate_in_memory(value: &mut serde_json::Value) -> Result<u32, anyhow::Error> {
        let target = CURRENT_CONFIG_VERSION;
        let current = value
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Config is missing required `version` field"))?
            .to_string();

        if current == target {
            return Ok(0);
        }

        let steps = Self::migrate_value(value, target)?;
        if steps > 0 {
            warn!(
                "Config was at version (<redacted scalar>), migrated to {} in memory ({} steps). \
                 Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config to persist.",
                target, steps
            );
        }
        Ok(steps)
    }
}

fn read_config_migration_file(path: &Path) -> Result<String, anyhow::Error> {
    let options = StableFileReadOptions::new(
        MAX_GATEWAY_CONFIG_FILE_BYTES,
        "configuration migration file",
    );
    read_stable_file(path, options).map_err(|error| stable_file_error_anyhow(path, options, error))
}

fn parse_yaml_value(content: &str) -> Result<serde_json::Value, anyhow::Error> {
    admit_yaml_alias_expansion(content)?;
    let yaml_val: serde_yaml::Value = config_decode::from_yaml_str(content)?;
    Ok(serde_json::to_value(yaml_val)?)
}
