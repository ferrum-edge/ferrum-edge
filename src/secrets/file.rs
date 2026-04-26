//! File-based secret resolution (`_FILE` suffix convention).
//!
//! When `FERRUM_X_FILE=/path/to/secret` is set, the secret value is read from
//! that file. Supports Docker secrets (`/run/secrets/`), Kubernetes volume mounts,
//! and Vault Agent file injection.

use std::env;

/// Check if the `{key}_FILE` env var is set and non-empty.
/// Returns the file path if so.
/// Used by the registry's single-key `resolve_secret()` path and its tests.
#[allow(dead_code)]
pub fn resolve_ref(key: &str) -> Option<String> {
    let file_key = format!("{}_FILE", key);
    env::var(&file_key).ok().filter(|s| !s.is_empty())
}

/// Read a secret value from a file path. Trims trailing whitespace
/// (trailing newlines are common in Docker secrets and heredocs).
/// Returns an error if the file cannot be read or is empty after trimming.
pub fn read_secret(path: &str, key: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}_FILE from '{}': {}", key, path, e))?;

    let trimmed = content.trim_end().to_string();
    if trimmed.is_empty() {
        return Err(format!(
            "File '{}' (from {}_FILE) is empty after trimming",
            path, key
        ));
    }

    Ok(trimmed)
}
