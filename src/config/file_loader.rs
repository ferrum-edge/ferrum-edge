//! YAML/JSON configuration file loader for file mode.
//!
//! Uses a two-pass deserialization strategy:
//! 1. Parse to `serde_json::Value` for version detection and in-memory migration.
//! 2. Deserialize from the original format (YAML or JSON) to `GatewayConfig`.
//!
//! The file on disk is never modified — in-memory migration preserves the
//! original format. Use `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config`
//! to persist config file version upgrades.
//!
//! Validation is strict in file mode (errors fail startup) vs. warn-only in
//! database mode (stale config is better than no config).

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
pub fn load_config_from_file(
    path: &str,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendAllowIps,
    namespace: &str,
) -> Result<GatewayConfig, anyhow::Error> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        anyhow::bail!("Configuration file not found: {}", file_path.display());
    }

    // Warn if the config file is world-readable (may contain credentials)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let mode = metadata.permissions().mode();
            if mode & 0o004 != 0 {
                warn!(
                    "Config file {} is world-readable (mode {:o}). Consider restricting permissions as it may contain credentials.",
                    file_path.display(),
                    mode & 0o777
                );
            }
        }
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

    // Validate all field-level constraints (lengths, ranges, nested configs)
    if let Err(errors) =
        config.validate_all_fields_with_ip_policy(cert_expiry_warning_days, backend_allow_ips)
    {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid field(s) found",
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

    // Normalize canonical in-memory fields before cross-resource validation.
    config.normalize_fields();
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

    // Validate plugin config targets and proxy/plugin association integrity.
    if let Err(errors) = config.validate_plugin_references() {
        for msg in &errors {
            error!("{}", msg);
        }
        anyhow::bail!(
            "Configuration validation failed: {} invalid plugin reference(s) found",
            errors.len()
        );
    }

    // Validate each plugin config by instantiating the plugin.
    // This catches invalid config values (missing required fields, bad types, etc.)
    // at startup rather than at request time.
    {
        let mut plugin_errors = Vec::new();
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if let Err(err) = crate::plugins::validate_plugin_config(&pc.plugin_name, &pc.config) {
                plugin_errors.push(format!(
                    "Plugin '{}' (id={}): {}",
                    pc.plugin_name, pc.id, err
                ));
            }
        }
        if !plugin_errors.is_empty() {
            for msg in &plugin_errors {
                error!("{}", msg);
            }
            anyhow::bail!(
                "Configuration validation failed: {} plugin config error(s) found",
                plugin_errors.len()
            );
        }
    }

    // Validate plugin file dependencies (e.g., geo_restriction .mmdb files).
    // Fatal in file mode — the gateway should not start with missing files.
    {
        let file_dep_errors = config.validate_plugin_file_dependencies();
        if !file_dep_errors.is_empty() {
            for msg in &file_dep_errors {
                error!("{}", msg);
            }
            anyhow::bail!(
                "Configuration validation failed: {} plugin file dependency error(s) found",
                file_dep_errors.len()
            );
        }
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

    // Capture all distinct namespaces before filtering so `GET /namespaces`
    // can return the full set even though only one namespace's resources are kept.
    {
        let mut ns_set = std::collections::HashSet::new();
        for p in &config.proxies {
            ns_set.insert(p.namespace.clone());
        }
        for c in &config.consumers {
            ns_set.insert(c.namespace.clone());
        }
        for pc in &config.plugin_configs {
            ns_set.insert(pc.namespace.clone());
        }
        for u in &config.upstreams {
            ns_set.insert(u.namespace.clone());
        }
        let mut known: Vec<String> = ns_set.into_iter().collect();
        known.sort();
        config.known_namespaces = known;
    }

    // Filter resources to only those matching the configured namespace.
    let pre_filter_counts = (
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len(),
        config.upstreams.len(),
    );
    config.proxies.retain(|p| p.namespace == namespace);
    config.consumers.retain(|c| c.namespace == namespace);
    config.plugin_configs.retain(|pc| pc.namespace == namespace);
    config.upstreams.retain(|u| u.namespace == namespace);

    let filtered_out = pre_filter_counts.0 - config.proxies.len() + pre_filter_counts.1
        - config.consumers.len()
        + pre_filter_counts.2
        - config.plugin_configs.len()
        + pre_filter_counts.3
        - config.upstreams.len();
    if filtered_out > 0 {
        info!(
            "Namespace filter '{}': excluded {} resources from other namespaces",
            namespace, filtered_out
        );
    }

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
#[cfg(unix)]
pub fn reload_config_from_file(
    path: &str,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendAllowIps,
    namespace: &str,
) -> Result<GatewayConfig, anyhow::Error> {
    info!("Reloading configuration from file: {}", path);
    load_config_from_file(path, cert_expiry_warning_days, backend_allow_ips, namespace)
}
