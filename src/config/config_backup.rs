use crate::config::types::GatewayConfig;
use std::path::Path;
use tracing::{error, info, warn};

/// Attempt to load a GatewayConfig from an externally provided backup JSON file.
/// This is used as a startup fallback in database mode when the DB is unreachable
/// (e.g. K8S pod restart while DB is down). The file is expected to be provided
/// externally (e.g. via ConfigMap, PersistentVolume, or sidecar export).
///
/// Returns None if the file doesn't exist or fails to parse.
pub fn load_config_backup(path: &str) -> Option<GatewayConfig> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        warn!("No config backup file found at {}", path);
        return None;
    }

    match std::fs::read_to_string(file_path) {
        Ok(content) => match serde_json::from_str::<GatewayConfig>(&content) {
            Ok(mut config) => {
                // Normalize stream proxy paths (same as file_loader)
                config.normalize_stream_proxy_paths();
                info!(
                    "Config backup loaded: {} proxies, {} consumers from {}",
                    config.proxies.len(),
                    config.consumers.len(),
                    path
                );
                Some(config)
            }
            Err(e) => {
                error!("Failed to parse config backup at {}: {}", path, e);
                None
            }
        },
        Err(e) => {
            error!("Failed to read config backup at {}: {}", path, e);
            None
        }
    }
}
