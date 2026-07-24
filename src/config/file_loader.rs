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
//! ## Atomic updates
//!
//! Operators must publish config via atomic rename (write temp → `rename(2)`)
//! or an atomic ConfigMap/symlink swap. In-place editors, shell `>` redirection,
//! and non-atomic `cp` onto the live path can expose a torn read window. This
//! loader uses bounded metadata/content stability checks with a short retry
//! budget and fails closed when the file keeps changing mid-read, so a
//! syntactically valid truncated tail is never applied. A completed
//! non-atomic truncate that leaves a stable shorter file still parses; prefer
//! rename-only updates so last-known-good reload behavior is never asked to
//! accept a silently shortened resource list.

use crate::config::config_migration::ConfigMigrator;
use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::config::validation_pipeline::{ValidationAction, ValidationPipeline};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

/// How many times to retry a config-file read when metadata/content changes
/// mid-load (non-atomic writer still flushing).
const CONFIG_FILE_STABILITY_MAX_ATTEMPTS: u32 = 3;
/// Delay between stability retries. Short enough for atomic renames to win
/// quickly; long enough for a slow in-place writer to finish or keep moving.
const CONFIG_FILE_STABILITY_RETRY_DELAY: Duration = Duration::from_millis(25);

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

    let content = read_config_file_stable(file_path)?;
    parse_config_content(
        &content,
        file_path,
        cert_expiry_warning_days,
        backend_allow_ips,
        namespace,
    )
}

/// Options for the bounded config-file stability read.
#[derive(Debug, Clone, Copy)]
pub struct StableFileReadOptions {
    pub max_attempts: u32,
    pub retry_delay: Duration,
}

impl Default for StableFileReadOptions {
    fn default() -> Self {
        Self {
            max_attempts: CONFIG_FILE_STABILITY_MAX_ATTEMPTS,
            retry_delay: CONFIG_FILE_STABILITY_RETRY_DELAY,
        }
    }
}

/// Read a config file with bounded metadata/content stability checks.
///
/// Stats size (+ mtime when available), reads, re-stats, and re-reads; any
/// mismatch retries up to [`StableFileReadOptions::max_attempts`]. Persistent
/// instability fails closed so a torn non-atomic write cannot be applied.
pub fn read_config_file_stable(path: &Path) -> Result<String, anyhow::Error> {
    read_config_file_stable_with(path, StableFileReadOptions::default(), &mut || {})
}

/// Like [`read_config_file_stable`], but invokes `between_checks` between the
/// first metadata snapshot and the content reads. Production callers pass an
/// empty closure; tests use this hook to deterministically mutate the file
/// mid-check and assert fail-closed rejection.
pub fn read_config_file_stable_with<F>(
    path: &Path,
    options: StableFileReadOptions,
    between_checks: &mut F,
) -> Result<String, anyhow::Error>
where
    F: FnMut(),
{
    let attempts = options.max_attempts.max(1);
    let mut last_unstable: Option<anyhow::Error> = None;
    for attempt in 0..attempts {
        match try_read_config_file_stable_once(path, between_checks) {
            Ok(content) => return Ok(content),
            Err(err) if is_unstable_config_file_error(&err) => {
                last_unstable = Some(err);
                if attempt + 1 < attempts {
                    std::thread::sleep(options.retry_delay);
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_unstable.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Configuration file {} changed while being read (unstable/torn write); \
             publish via atomic rename or ConfigMap symlink swap and retry",
            path.display()
        )
    }))
}

fn is_unstable_config_file_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("changed while being read")
}

fn try_read_config_file_stable_once<F>(
    path: &Path,
    between_checks: &mut F,
) -> Result<String, anyhow::Error>
where
    F: FnMut(),
{
    let meta_before = std::fs::metadata(path)?;
    let len_before = meta_before.len();
    let mtime_before = meta_before.modified().ok();

    // Test hook: mutate the live path between the opening stat and the reads.
    between_checks();

    let content = std::fs::read_to_string(path)?;
    let meta_mid = std::fs::metadata(path)?;
    let len_mid = meta_mid.len();
    let mtime_mid = meta_mid.modified().ok();

    if content.len() as u64 != len_before
        || len_mid != len_before
        || mtime_mid != mtime_before
    {
        anyhow::bail!(
            "Configuration file {} changed while being read (unstable/torn write); \
             publish via atomic rename or ConfigMap symlink swap and retry",
            path.display()
        );
    }

    // Second read catches same-length rewrites that flip content without a
    // detectable size change between the first pair of stats.
    let content_again = std::fs::read_to_string(path)?;
    let meta_after = std::fs::metadata(path)?;
    if content_again != content
        || meta_after.len() != len_before
        || meta_after.modified().ok() != mtime_before
    {
        anyhow::bail!(
            "Configuration file {} changed while being read (unstable/torn write); \
             publish via atomic rename or ConfigMap symlink swap and retry",
            path.display()
        );
    }

    Ok(content)
}

fn parse_config_content(
    content: &str,
    file_path: &Path,
    cert_expiry_warning_days: u64,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
    namespace: &str,
) -> Result<GatewayConfig, anyhow::Error> {
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
            serde_yaml::from_str::<serde_yaml::Value>(content).is_ok()
        }
    };

    if is_yaml {
        info!("Loading YAML configuration from {}", file_path.display());
    } else {
        info!("Loading JSON configuration from {}", file_path.display());
    }

    // For version detection and migration, parse to serde_json::Value
    let mut value: serde_json::Value = if is_yaml {
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(content)?;
        serde_json::to_value(yaml_val)?
    } else {
        serde_json::from_str(content)?
    };

    // Detect config version and migrate in memory if needed
    let file_version = value
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Configuration file missing required 'version' field"))?
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
        serde_yaml::from_str(content)?
    } else {
        serde_json::from_value(value)?
    };

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
            "Configuration validation failed: {} listen_path(s) contain encoded slashes",
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

    // Reject mesh-PROJECTED upstream fields on this operator-provided file load.
    // File config is operator-authored, so (like the admin write path) it must not
    // carry `Upstream.{port_overrides, source_locality, locality_lb_strict,
    // locality_lb_setting}` — those are owned by the mesh slice-apply layer and are
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
