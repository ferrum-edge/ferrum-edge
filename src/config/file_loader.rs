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
//!
//! # Atomicity / stability contract
//!
//! File-mode startup and SIGHUP reload refuse to admit a candidate whose bytes
//! were observed mid-update. The loader:
//!
//! 1. Opens only regular files (rejecting FIFOs/devices/directories; Unix opens
//!    are non-blocking so a raced special file cannot wedge the worker).
//! 2. Reads the opened handle, then re-fstats that handle and re-stats the
//!    configured path so symlink/rename swaps mid-read fail closed.
//! 3. Performs a second independent open/read and requires **byte-identical**
//!    content plus matching file identity. Size/metadata agreement alone is
//!    not treated as proof of content stability (same-size in-place rewrites
//!    and paused torn truncations can keep metadata unchanged).
//! 4. Retries a bounded number of times on instability, then fails closed.
//!    Reload keeps the last known-good live generation; startup aborts.
//!
//! Operators should publish updates with write-temp → fsync → `rename(2)` (or
//! an equivalent atomic replace such as a Kubernetes ConfigMap symlink swap).
//! Optional top-level `resource_counts` seals trailing list sections against
//! settled truncations that survive the stability window.

use crate::config::config_migration::ConfigMigrator;
use crate::config::stable_file::{
    MAX_GATEWAY_CONFIG_FILE_BYTES, StableFileReadOptions, detect_json_or_yaml_extension,
    read_stable_file, stable_file_error_anyhow,
};
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::config::validation_pipeline::{ValidationAction, ValidationPipeline};
use serde::Deserialize;
use std::path::Path;
use tracing::{info, warn};

/// Hard ceiling on a single file-mode config document. Bounds allocation before
/// YAML/JSON parse of a hostile or accidentally enormous path target.
const MAX_CONFIG_FILE_BYTES: u64 = MAX_GATEWAY_CONFIG_FILE_BYTES;

/// Optional file-mode integrity seal stripped before `GatewayConfig`
/// deserialization (`deny_unknown_fields`). Validated against pre-namespace-
/// filter resource lengths so a trailing `plugin_configs` truncation that still
/// parses cannot silently drop auth/ACL plugins when the operator declares
/// expected counts near the top of the document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResourceCounts {
    proxies: usize,
    consumers: usize,
    plugin_configs: usize,
    #[serde(default)]
    upstreams: usize,
}

/// Read the config path with the shared bounded stability/atomicity contract.
fn read_stable_config_file(path: &Path) -> Result<String, anyhow::Error> {
    let options = StableFileReadOptions::new(MAX_CONFIG_FILE_BYTES, "configuration file");
    read_stable_file(path, options).map_err(|error| stable_file_error_anyhow(path, options, error))
}

fn take_resource_counts_from_json(
    value: &mut serde_json::Value,
) -> Result<Option<ResourceCounts>, anyhow::Error> {
    let Some(object) = value.as_object_mut() else {
        return Ok(None);
    };
    let Some(raw) = object.remove("resource_counts") else {
        return Ok(None);
    };
    serde_json::from_value(raw)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("invalid resource_counts: {error}"))
}

fn strip_resource_counts_from_yaml(yaml_value: &mut Option<serde_yaml::Value>) {
    if let Some(serde_yaml::Value::Mapping(mapping)) = yaml_value.as_mut() {
        mapping.remove(serde_yaml::Value::String("resource_counts".to_string()));
    }
}

fn validate_resource_counts(
    config: &GatewayConfig,
    expected: &ResourceCounts,
) -> Result<(), anyhow::Error> {
    let observed = ResourceCounts {
        proxies: config.proxies.len(),
        consumers: config.consumers.len(),
        plugin_configs: config.plugin_configs.len(),
        upstreams: config.upstreams.len(),
    };
    if &observed == expected {
        return Ok(());
    }
    anyhow::bail!(
        "resource_counts mismatch: declared proxies={}, consumers={}, plugin_configs={}, \
         upstreams={} but file contains proxies={}, consumers={}, plugin_configs={}, \
         upstreams={}. A torn or truncated trailing section (commonly plugin_configs) \
         can parse as valid YAML while silently dropping resources; refuse the candidate.",
        expected.proxies,
        expected.consumers,
        expected.plugin_configs,
        expected.upstreams,
        observed.proxies,
        observed.consumers,
        observed.plugin_configs,
        observed.upstreams
    );
}

/// Load configuration from a YAML or JSON file.
///
/// If the config file is at an older version than `CURRENT_CONFIG_VERSION`,
/// the config is migrated **in memory** before deserialization. The file on
/// disk is not modified — use `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=config`
/// to persist config file migrations.
pub fn load_config_from_file(
    path: &str,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
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

    let content = read_stable_config_file(file_path)?;
    // Extension only; unknown/extensionless paths use YAML, which also admits
    // ordinary JSON without a separate full-document detection parse.
    let is_yaml = detect_json_or_yaml_extension(file_path);

    if is_yaml {
        info!("Loading YAML configuration from {}", file_path.display());
    } else {
        info!("Loading JSON configuration from {}", file_path.display());
    }

    // For version detection and migration, parse to serde_json::Value. Retain
    // the YAML value tree as well so accepting an integer version does not
    // force an otherwise-current YAML document through JSON and discard
    // YAML-specific tags.
    let (mut value, mut yaml_value): (serde_json::Value, Option<serde_yaml::Value>) = if is_yaml {
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)?;
        (serde_json::to_value(&yaml_val)?, Some(yaml_val))
    } else {
        (serde_json::from_str(&content)?, None)
    };

    // Optional file-mode integrity seal. Strip before GatewayConfig
    // deserialization so deny_unknown_fields stays authoritative for the
    // runtime domain model; validate against observed lengths below.
    let resource_counts = take_resource_counts_from_json(&mut value)?;
    strip_resource_counts_from_yaml(&mut yaml_value);

    // Detect config version and migrate in memory if needed.
    //
    // The canonical version is the string "1", but the natural YAML/JSON
    // spelling `version: 1` parses as a number. Accept both the string form and
    // the canonical unsigned-integer form; reject any other type (float, bool,
    // null, array, object, negative) with a precise diagnostic rather than a
    // misleading "missing field" error.
    //
    // When the integer form is accepted, rewrite it to a string in the JSON
    // migration value and, for YAML, in the retained YAML tree before
    // `GatewayConfig` deserialization (which expects `version: String`).
    let file_version = match value.get_mut("version") {
        None => anyhow::bail!("Configuration file missing required 'version' field"),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => {
            if let Some(n) = other.as_u64() {
                let s = n.to_string();
                *other = serde_json::Value::String(s.clone());
                if let Some(serde_yaml::Value::Mapping(mapping)) = yaml_value.as_mut()
                    && let Some(yaml_version) =
                        mapping.get_mut(serde_yaml::Value::String("version".to_string()))
                {
                    *yaml_version = serde_yaml::Value::String(s.clone());
                }
                s
            } else {
                let value_type = match other {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(number) if number.is_i64() => "negative integer",
                    serde_json::Value::Number(_) => "floating-point number",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::String(_) => "string",
                };
                anyhow::bail!(
                    "field 'version' must be a string or non-negative integer (got {value_type}); use version: \"1\" or version: 1"
                );
            }
        }
    };

    if file_version != CURRENT_CONFIG_VERSION {
        warn!(
            "Config file is at version {}, current is {}. Migrating in memory.",
            file_version, CURRENT_CONFIG_VERSION
        );
        ConfigMigrator::migrate_in_memory(&mut value)?;
    }

    // Deserialize current YAML from its retained value tree to preserve
    // YAML-specific features (including tagged enum variants). The only
    // mutations are the accepted integer-to-string version rewrite and the
    // optional resource_counts strip above. Migrations still operate on
    // serde_json::Value, which remains authoritative for older versions.
    let mut config: GatewayConfig = if is_yaml && file_version == CURRENT_CONFIG_VERSION {
        serde_yaml::from_value(yaml_value.ok_or_else(|| {
            anyhow::anyhow!("internal error: parsed YAML value was not retained")
        })?)?
    } else {
        serde_json::from_value(value)?
    };

    if let Some(ref expected) = resource_counts {
        validate_resource_counts(&config, expected)?;
    }

    ValidationPipeline::new(&mut config)
        .validate_resource_ids(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid resource ID(s) found",
        ))
        .validate_all_fields_with_ip_policy(
            cert_expiry_warning_days,
            backend_allow_ips,
            ValidationAction::FatalCount(
                "Configuration validation failed: {} invalid field(s) found",
            ),
        )
        .validate_unique_resource_ids(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate resource ID(s) found",
        ))
        .normalize_fields()
        .resolve_upstream_tls()
        .validate_hosts(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid host(s) found",
        ))
        .validate_regex_listen_paths(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid regex listen_path(s) found",
        ))
        .validate_listen_path_encodings(ValidationAction::FatalCount(
            "Configuration validation failed: {} non-canonical listen_path(s) found",
        ))
        .run()?;

    let plaintext_basic_auth_consumers: Vec<&str> = config
        .consumers
        .iter()
        .filter(|consumer| {
            consumer
                .credentials
                .get("basicauth")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|entries| entries.iter().any(|entry| entry.get("password").is_some()))
        })
        .map(|consumer| consumer.id.as_str())
        .collect();
    if !plaintext_basic_auth_consumers.is_empty() {
        anyhow::bail!(
            "Configuration validation failed: file-mode Basic-auth credentials must use \
             'password_hash'; plaintext 'password' is accepted only by Admin API writes \
             (consumer IDs: {})",
            plaintext_basic_auth_consumers.join(", ")
        );
    }

    // Reject mesh-projected upstream fields on this operator-provided file load.
    // File config is operator-authored, so (like the admin write path) it must not
    // carry reserved `mesh.*` target tags or `Upstream.{port_overrides, source_locality, source_labels,
    // locality_lb_strict, locality_lb_setting}` — those are owned by the mesh
    // slice-apply layer and are
    // not persisted/round-tripped here. This is deliberately OUTSIDE the shared
    // validation pipeline (which also runs on the mesh slice-apply path, where the
    // mesh layer legitimately projects these fields); only operator entry points
    // call it. Fatal in file mode, matching the rest of file-mode validation.
    if let Err(errors) = config.validate_operator_provided_fields() {
        anyhow::bail!(
            "Configuration validation failed: {} mesh-projected upstream field(s) \
             cannot be set in file config: {}",
            errors.len(),
            errors.join("; ")
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
    //
    // The filter runs BEFORE cross-resource uniqueness validators
    // (listen_path, listen_port, consumer identity, upstream/proxy name,
    // reference-integrity) so that sibling-namespace resources never
    // participate in those checks. The admin API and SQL unique indexes
    // treat those fields as `(namespace, value)`-scoped; running the
    // in-memory validators on a pre-filter multi-namespace view would
    // spuriously reject configs that are perfectly valid — e.g., two
    // proxies in different namespaces sharing `listen_path: /api`.
    //
    // Field-level validators (`validate_all_fields_*`, `validate_hosts`,
    // `validate_regex_listen_paths`, `validate_unique_resource_ids`, etc.)
    // stay above this filter because they enforce properties that should
    // hold for every namespace in the file, not just the active one.
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

    ValidationPipeline::new(&mut config)
        .validate_unique_listen_paths(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate listen_path(s) found",
        ))
        .validate_unique_consumer_identities(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate consumer identity(ies) found. Each consumer must have a unique username and unique custom_id.",
        ))
        .validate_unique_consumer_credentials(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate consumer credential(s) found. Each consumer must have a unique keyauth API key.",
        ))
        .validate_unique_upstream_names(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate upstream name(s) found",
        ))
        .validate_unique_proxy_names(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate proxy name(s) found",
        ))
        .validate_upstream_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid upstream reference(s) found",
        ))
        .validate_mesh_route_dispatch_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid mesh_route_dispatch upstream reference(s) found",
        ))
        .validate_plugin_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid plugin reference(s) found",
        ))
        .validate_plugin_configs(
            backend_allow_ips,
            ValidationAction::FatalCount(
            "Configuration validation failed: {} plugin config error(s) found",
        ))
        .validate_plugin_file_dependencies(ValidationAction::FatalCount(
            "Configuration validation failed: {} plugin file dependency error(s) found",
        ))
        .validate_stream_proxies(ValidationAction::FatalCount(
            "Configuration validation failed: {} stream proxy error(s) found",
        ))
        .run()?;

    info!(
        "Configuration loaded (version {}): {} proxies, {} consumers, {} plugin configs",
        config.version,
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len()
    );

    Ok(config)
}

/// Decode and validate a config document from in-memory bytes.
///
/// Skips filesystem stability and plugin file-dependency checks, plus namespace
/// filtering. Intended for the adversarial fuzz lane and deterministic parser
/// tests — not production load. Keeping this entry point free of file reads
/// prevents generated paths from turning a pure parser target into runner I/O.
#[cfg(feature = "fuzzing")]
pub fn decode_and_validate_config_document(
    content: &str,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<GatewayConfig, anyhow::Error> {
    if content.len() as u64 > MAX_CONFIG_FILE_BYTES {
        anyhow::bail!("config document exceeds maximum size of {MAX_CONFIG_FILE_BYTES} bytes");
    }

    let is_yaml = serde_yaml::from_str::<serde_yaml::Value>(content).is_ok()
        && !content.trim_start().starts_with('{');

    let (mut value, mut yaml_value): (serde_json::Value, Option<serde_yaml::Value>) = if is_yaml {
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(content)?;
        (serde_json::to_value(&yaml_val)?, Some(yaml_val))
    } else {
        (serde_json::from_str(content)?, None)
    };

    let resource_counts = take_resource_counts_from_json(&mut value)?;
    strip_resource_counts_from_yaml(&mut yaml_value);

    let file_version = match value.get_mut("version") {
        None => anyhow::bail!("Configuration file missing required 'version' field"),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => {
            if let Some(n) = other.as_u64() {
                let s = n.to_string();
                *other = serde_json::Value::String(s.clone());
                if let Some(serde_yaml::Value::Mapping(mapping)) = yaml_value.as_mut()
                    && let Some(yaml_version) =
                        mapping.get_mut(serde_yaml::Value::String("version".to_string()))
                {
                    *yaml_version = serde_yaml::Value::String(s.clone());
                }
                s
            } else {
                let value_type = match other {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(number) if number.is_i64() => "negative integer",
                    serde_json::Value::Number(_) => "floating-point number",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::String(_) => "string",
                };
                anyhow::bail!(
                    "field 'version' must be a string or non-negative integer (got {value_type}); use version: \"1\" or version: 1"
                );
            }
        }
    };

    if file_version != CURRENT_CONFIG_VERSION {
        ConfigMigrator::migrate_in_memory(&mut value)?;
    }

    let mut config: GatewayConfig = if is_yaml && file_version == CURRENT_CONFIG_VERSION {
        serde_yaml::from_value(yaml_value.ok_or_else(|| {
            anyhow::anyhow!("internal error: parsed YAML value was not retained")
        })?)?
    } else {
        serde_json::from_value(value)?
    };

    if let Some(ref expected) = resource_counts {
        validate_resource_counts(&config, expected)?;
    }

    ValidationPipeline::new(&mut config)
        .validate_resource_ids(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid resource ID(s) found",
        ))
        .validate_all_fields_with_ip_policy(
            cert_expiry_warning_days,
            backend_allow_ips,
            ValidationAction::FatalCount(
                "Configuration validation failed: {} invalid field(s) found",
            ),
        )
        .validate_unique_resource_ids(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate resource ID(s) found",
        ))
        .normalize_fields()
        .resolve_upstream_tls()
        .validate_hosts(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid host(s) found",
        ))
        .validate_regex_listen_paths(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid regex listen_path(s) found",
        ))
        .validate_listen_path_encodings(ValidationAction::FatalCount(
            "Configuration validation failed: {} non-canonical listen_path(s) found",
        ))
        .run()?;

    let plaintext_basic_auth_consumers: Vec<&str> = config
        .consumers
        .iter()
        .filter(|consumer| {
            consumer
                .credentials
                .get("basicauth")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|entries| entries.iter().any(|entry| entry.get("password").is_some()))
        })
        .map(|consumer| consumer.id.as_str())
        .collect();
    if !plaintext_basic_auth_consumers.is_empty() {
        anyhow::bail!(
            "Configuration validation failed: file-mode Basic-auth credentials must use \
             'password_hash'; plaintext 'password' is accepted only by Admin API writes \
             (consumer IDs: {})",
            plaintext_basic_auth_consumers.join(", ")
        );
    }

    if let Err(errors) = config.validate_operator_provided_fields() {
        anyhow::bail!(
            "Configuration validation failed: {} mesh-projected upstream field(s) \
             cannot be set in file config: {}",
            errors.len(),
            errors.join("; ")
        );
    }

    ValidationPipeline::new(&mut config)
        .validate_unique_listen_paths(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate listen_path(s) found",
        ))
        .validate_unique_consumer_identities(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate consumer identity(ies) found. Each consumer must have a unique username and unique custom_id.",
        ))
        .validate_unique_consumer_credentials(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate consumer credential(s) found. Each consumer must have a unique keyauth API key.",
        ))
        .validate_unique_upstream_names(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate upstream name(s) found",
        ))
        .validate_unique_proxy_names(ValidationAction::FatalCount(
            "Configuration validation failed: {} duplicate proxy name(s) found",
        ))
        .validate_upstream_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid upstream reference(s) found",
        ))
        .validate_mesh_route_dispatch_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid mesh_route_dispatch upstream reference(s) found",
        ))
        .validate_plugin_references(ValidationAction::FatalCount(
            "Configuration validation failed: {} invalid plugin reference(s) found",
        ))
        .validate_plugin_configs(
            backend_allow_ips,
            ValidationAction::FatalCount(
                "Configuration validation failed: {} plugin config error(s) found",
            ),
        )
        .validate_stream_proxies(ValidationAction::FatalCount(
            "Configuration validation failed: {} stream proxy error(s) found",
        ))
        .run()?;

    Ok(config)
}

/// Load and validate an owned file-mode candidate without blocking an async
/// runtime worker on filesystem parsing or MMDB verification.
pub async fn load_config_from_file_off_thread(
    path: String,
    cert_expiry_warning_days: u64,
    backend_allow_ips: crate::config::BackendEgressPolicy,
    namespace: String,
) -> Result<GatewayConfig, anyhow::Error> {
    tokio::task::spawn_blocking(move || {
        load_config_from_file(
            &path,
            cert_expiry_warning_days,
            &backend_allow_ips,
            &namespace,
        )
    })
    .await
    .map_err(|error| anyhow::anyhow!("Configuration file validation worker failed: {error}"))?
}

/// Reload config from file, returning the new config or an error.
#[cfg(unix)]
pub fn reload_config_from_file(
    path: &str,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
    namespace: &str,
) -> Result<GatewayConfig, anyhow::Error> {
    info!("Reloading configuration from file: {}", path);
    load_config_from_file(path, cert_expiry_warning_days, backend_allow_ips, namespace)
}

/// Async-runtime wrapper for [`reload_config_from_file`].
#[cfg(unix)]
pub async fn reload_config_from_file_off_thread(
    path: String,
    cert_expiry_warning_days: u64,
    backend_allow_ips: crate::config::BackendEgressPolicy,
    namespace: String,
) -> Result<GatewayConfig, anyhow::Error> {
    tokio::task::spawn_blocking(move || {
        reload_config_from_file(
            &path,
            cert_expiry_warning_days,
            &backend_allow_ips,
            &namespace,
        )
    })
    .await
    .map_err(|error| anyhow::anyhow!("Configuration file reload worker failed: {error}"))?
}
