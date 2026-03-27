use crate::config::config_migration::ConfigMigrator;
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use std::path::Path;
use tracing::{error, info, warn};

/// Load configuration from a YAML or JSON file.
///
/// If the config file is at an older version than `CURRENT_CONFIG_VERSION`,
/// the config is migrated **in memory** before deserialization. The file on
/// disk is not modified — use `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config`
/// to persist config file migrations.
pub fn load_config_from_file(path: &str) -> Result<GatewayConfig, anyhow::Error> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        anyhow::bail!("Configuration file not found: {}", file_path.display());
    }

    let content = std::fs::read_to_string(file_path)?;
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Determine if this is YAML or JSON
    let is_yaml = match ext.as_str() {
        "yaml" | "yml" => true,
        "json" => false,
        _ => {
            // Heuristic: try YAML parse to detect format
            serde_yaml::from_str::<serde_yaml::Value>(&content).is_ok()
        }
    };

    if is_yaml {
        info!("Loading YAML configuration from {}", file_path.display());
    } else {
        info!("Loading JSON configuration from {}", file_path.display());
    }

    // For version detection and migration, parse to serde_json::Value
    let mut value: serde_json::Value = if is_yaml {
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;
        serde_json::to_value(yaml_val)?
    } else {
        serde_json::from_str(&content)?
    };

    // Detect config version and migrate in memory if needed
    let file_version = value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("1")
        .to_string();

    if file_version != CURRENT_CONFIG_VERSION {
        warn!(
            "Config file is at version {}, current is {}. Migrating in memory.",
            file_version, CURRENT_CONFIG_VERSION
        );
        ConfigMigrator::migrate_in_memory(&mut value)?;
    }

    // Deserialize from the original format to preserve YAML-specific features
    // (like tags for enum variants). Only fall back to JSON deserialization if
    // a migration was applied (since migrations operate on serde_json::Value).
    let mut config: GatewayConfig = if is_yaml && file_version == CURRENT_CONFIG_VERSION {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_value(value)?
    };

    // Validate resource ID format
    if let Err(errors) = config.validate_resource_ids() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid resource ID(s) found",
            errors.len()
        );
    }

    // Validate resource ID uniqueness
    if let Err(dupes) = config.validate_unique_resource_ids() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate resource ID(s) found",
            dupes.len()
        );
    }

    // Normalize and validate host entries
    config.normalize_hosts();
    if let Err(errors) = config.validate_hosts() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid host(s) found",
            errors.len()
        );
    }

    // Validate regex listen_paths compile correctly
    if let Err(errors) = config.validate_regex_listen_paths() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid regex listen_path(s) found",
            errors.len()
        );
    }

    // Validate host+listen_path uniqueness
    if let Err(dupes) = config.validate_unique_listen_paths() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate listen_path(s) found",
            dupes.len()
        );
    }

    // Validate consumer username/custom_id uniqueness
    if let Err(dupes) = config.validate_unique_consumer_identities() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate consumer identity(ies) found. \
             Each consumer must have a unique username and unique custom_id.",
            dupes.len()
        );
    }

    // Validate consumer credential (keyauth API key) uniqueness
    if let Err(dupes) = config.validate_unique_consumer_credentials() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate consumer credential(s) found. \
             Each consumer must have a unique keyauth API key.",
            dupes.len()
        );
    }

    // Validate upstream name uniqueness
    if let Err(dupes) = config.validate_unique_upstream_names() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate upstream name(s) found",
            dupes.len()
        );
    }

    // Validate proxy name uniqueness
    if let Err(dupes) = config.validate_unique_proxy_names() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate proxy name(s) found",
            dupes.len()
        );
    }

    // Validate upstream references exist
    if let Err(errors) = config.validate_upstream_references() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid upstream reference(s) found",
            errors.len()
        );
    }

    // Validate plugin name uniqueness per proxy
    if let Err(errors) = config.validate_unique_plugins_per_proxy() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate plugin(s) per proxy found",
            errors.len()
        );
    }

    // Validate stream proxy (TCP/UDP) configuration
    if let Err(errors) = config.validate_stream_proxies() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} stream proxy error(s) found",
            errors.len()
        );
    }

    // Normalize stream proxy listen_paths to synthetic values (__tcp:PORT, __udp:PORT)
    config.normalize_stream_proxy_paths();

    info!(
        "Configuration loaded (version {}): {} proxies, {} consumers, {} plugin configs",
        config.version,
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len()
    );

    Ok(config)
}

/// Reload config from file, returning the new config or an error.
pub fn reload_config_from_file(path: &str) -> Result<GatewayConfig, anyhow::Error> {
    info!("Reloading configuration from file: {}", path);
    load_config_from_file(path)
}
