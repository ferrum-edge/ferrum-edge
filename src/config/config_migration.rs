use std::path::Path;
use tracing::{info, warn};

use crate::config::types::CURRENT_CONFIG_VERSION;

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
    /// Get the ordered list of config migration steps.
    ///
    /// Each entry is `(from_version, to_version, migration_fn)`.
    /// To add a new migration, append to this list:
    ///
    /// ```ignore
    /// ("1", "2", migrate_v1_to_v2 as ConfigMigrationFn),
    /// ("2", "3", migrate_v2_to_v3 as ConfigMigrationFn),
    /// ```
    fn migration_chain() -> Vec<(&'static str, &'static str, ConfigMigrationFn)> {
        vec![
            // Future migrations go here. Example:
            // ("1", "2", migrate_v1_to_v2 as ConfigMigrationFn),
        ]
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
            .unwrap_or("1")
            .to_string();

        if current_version == target_version {
            return Ok(0);
        }

        let chain = Self::migration_chain();
        let mut version = current_version.clone();
        let mut steps_applied = 0u32;

        loop {
            if version == target_version {
                break;
            }

            let step = chain.iter().find(|(from, _, _)| *from == version);

            match step {
                Some((from, to, migrate_fn)) => {
                    info!("Migrating config from version {} to {}", from, to);
                    migrate_fn(value)?;
                    version = to.to_string();
                    steps_applied += 1;
                }
                None => {
                    if steps_applied == 0 {
                        // No migration path found from the current version
                        anyhow::bail!(
                            "No config migration path from version '{}' to '{}'",
                            current_version,
                            target_version
                        );
                    }
                    // We've applied some steps but can't reach the target
                    anyhow::bail!(
                        "Config migration chain broken at version '{}' (target: '{}')",
                        version,
                        target_version
                    );
                }
            }
        }

        Ok(steps_applied)
    }

    /// Migrate a config file in-place, creating a backup first.
    ///
    /// The backup is stored as `{path}.backup.{timestamp}` in the same directory.
    pub fn migrate_file(path: &str) -> Result<ConfigMigrateResult, anyhow::Error> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            anyhow::bail!("Configuration file not found: {}", path);
        }

        let content = std::fs::read_to_string(file_path)?;
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Parse to serde_json::Value (works for both YAML and JSON)
        let mut value: serde_json::Value = match ext.as_str() {
            "json" => serde_json::from_str(&content)?,
            _ => {
                // YAML (or unknown — try YAML first)
                let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;
                serde_json::to_value(yaml_val)?
            }
        };

        let from_version = value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
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
        info!("Created config backup at {}", backup_path);

        // Write migrated content back in the original format
        let migrated_content = match ext.as_str() {
            "json" => serde_json::to_string_pretty(&value)?,
            _ => {
                // Convert back to YAML
                let yaml_val: serde_yaml::Value = serde_json::from_value(value)?;
                serde_yaml::to_string(&yaml_val)?
            }
        };

        std::fs::write(file_path, migrated_content)?;
        info!(
            "Config file migrated from version {} to {} ({} steps)",
            from_version, target, steps
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
            anyhow::bail!("Configuration file not found: {}", path);
        }

        let content = std::fs::read_to_string(file_path)?;
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let value: serde_json::Value = match ext.as_str() {
            "json" => serde_json::from_str(&content)?,
            _ => {
                let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;
                serde_json::to_value(yaml_val)?
            }
        };

        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
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
            .unwrap_or("1")
            .to_string();

        if current == target {
            return Ok(0);
        }

        let steps = Self::migrate_value(value, target)?;
        if steps > 0 {
            warn!(
                "Config was at version {}, migrated to {} in memory ({} steps). \
                 Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config to persist.",
                current, target, steps
            );
        }
        Ok(steps)
    }
}

// ---- Future migration functions go here ----
// Example:
//
// fn migrate_v1_to_v2(value: &mut serde_json::Value) -> Result<(), anyhow::Error> {
//     // Add a new required field with a default value
//     if let Some(obj) = value.as_object_mut() {
//         obj.insert("version".to_string(), serde_json::json!("2"));
//         // ... transform fields as needed
//     }
//     Ok(())
// }
