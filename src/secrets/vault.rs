//! HashiCorp Vault secret resolution (requires `secrets-vault` feature).

use std::env;

/// Check if the `{key}_VAULT` env var is set and non-empty.
/// Returns the Vault path reference (e.g. `secret/data/gateway#field`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let vault_key = format!("{}_VAULT", key);
    env::var(&vault_key).ok().filter(|s| !s.is_empty())
}

/// Fetch a secret value from HashiCorp Vault.
///
/// The `reference` format is `<mount>/data/<path>#<json_key>` for KV v2,
/// where `#<json_key>` is optional (returns the first key if omitted).
///
/// Connection is configured via standard Vault env vars:
/// - `VAULT_ADDR` — Vault server URL (required)
/// - `VAULT_TOKEN` — authentication token (required)
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    // Parse the reference: path#json_key
    let (path, json_key) = match reference.split_once('#') {
        Some((p, k)) => (p, Some(k)),
        None => (reference, None),
    };

    // Get Vault connection settings from env
    let vault_addr = env::var("VAULT_ADDR")
        .map_err(|_| format!("VAULT_ADDR must be set to resolve {} from Vault", key))?;
    let vault_token = env::var("VAULT_TOKEN")
        .map_err(|_| format!("VAULT_TOKEN must be set to resolve {} from Vault", key))?;

    // Build client — inject custom CA bundle if configured
    let mut settings_builder = vaultrs::client::VaultClientSettingsBuilder::default();
    settings_builder.address(&vault_addr).token(&vault_token);

    if let Ok(ca_path) = env::var("FERRUM_TLS_CA_BUNDLE_PATH")
        && !ca_path.is_empty()
    {
        settings_builder.ca_certs(vec![ca_path]);
    }

    let settings = settings_builder
        .build()
        .map_err(|e| format!("Failed to build Vault client for {}: {}", key, e))?;

    let client = vaultrs::client::VaultClient::new(settings)
        .map_err(|e| format!("Failed to create Vault client for {}: {}", key, e))?;

    // Parse mount and path from the reference
    // Format: <mount>/data/<secret_path> (KV v2 convention)
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 3 || parts[1] != "data" {
        return Err(format!(
            "Invalid Vault KV v2 reference for {}: '{}'. \
             Expected format: <mount>/data/<path>#<json_key>",
            key, reference
        ));
    }
    let mount = parts[0];
    let secret_path = parts[2];

    let secret: std::collections::HashMap<String, String> =
        vaultrs::kv2::read(&client, mount, secret_path)
            .await
            .map_err(|e| format!("Failed to read {} from Vault path '{}': {}", key, path, e))?;

    match json_key {
        Some(jk) => secret.get(jk).cloned().ok_or_else(|| {
            format!(
                "Vault secret at '{}' does not contain key '{}' for {}",
                path, jk, key
            )
        }),
        None => secret
            .into_values()
            .next()
            .ok_or_else(|| format!("Vault secret at '{}' is empty for {}", path, key)),
    }
}
