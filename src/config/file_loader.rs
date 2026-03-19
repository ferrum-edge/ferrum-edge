use crate::config::types::GatewayConfig;
use std::path::Path;
use tracing::{error, info};

/// Load configuration from a YAML or JSON file.
pub fn load_config_from_file(path: &str) -> Result<GatewayConfig, anyhow::Error> {
    let path = Path::new(path);
    if !path.exists() {
        anyhow::bail!("Configuration file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let config: GatewayConfig = match ext.as_str() {
        "yaml" | "yml" => {
            info!("Loading YAML configuration from {}", path.display());
            serde_yaml::from_str(&content)?
        }
        "json" => {
            info!("Loading JSON configuration from {}", path.display());
            serde_json::from_str(&content)?
        }
        _ => {
            // Try YAML first, then JSON
            info!(
                "Attempting to parse config file {} (unknown extension)",
                path.display()
            );
            serde_yaml::from_str(&content).or_else(|_| {
                serde_json::from_str(&content).map_err(|e| serde_yaml::Error::custom(e.to_string()))
            })?
        }
    };

    // Validate listen_path uniqueness
    if let Err(dupes) = config.validate_unique_listen_paths() {
        for msg in &dupes {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} duplicate listen_path(s) found",
            dupes.len()
        );
    }

    info!(
        "Configuration loaded: {} proxies, {} consumers, {} plugin configs",
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

use serde::de::Error as _;
