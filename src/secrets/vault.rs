//! HashiCorp Vault secret resolution (requires `secrets-vault` feature).

use std::env;

/// Check if the `{key}_VAULT` env var is set and non-empty.
/// Returns the Vault path reference (e.g. `secret/data/gateway#field`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let vault_key = format!("{}_VAULT", key);
    env::var(&vault_key).ok().filter(|s| !s.is_empty())
}

/// Reusable Vault client for batch secret resolution.
/// Created once and shared across multiple Vault secret fetches.
pub struct VaultClientWrapper {
    client: vaultrs::client::VaultClient,
}

impl VaultClientWrapper {
    /// Create a new Vault client from standard env vars (`VAULT_ADDR`, `VAULT_TOKEN`).
    pub fn new() -> Result<Self, String> {
        let vault_addr = env::var("VAULT_ADDR")
            .map_err(|_| "VAULT_ADDR must be set to resolve secrets from Vault".to_string())?;
        let vault_token = env::var("VAULT_TOKEN")
            .map_err(|_| "VAULT_TOKEN must be set to resolve secrets from Vault".to_string())?;

        let mut settings_builder = vaultrs::client::VaultClientSettingsBuilder::default();
        settings_builder.address(&vault_addr).token(&vault_token);

        if let Ok(ca_path) = env::var("FERRUM_TLS_CA_BUNDLE_PATH")
            && !ca_path.is_empty()
        {
            settings_builder.ca_certs(vec![ca_path]);
        }

        let settings = settings_builder
            .build()
            .map_err(|e| format!("Failed to build Vault client settings: {}", e))?;

        let client = vaultrs::client::VaultClient::new(settings)
            .map_err(|e| format!("Failed to create Vault client: {}", e))?;

        Ok(Self { client })
    }

    /// Fetch a secret value from Vault using this client.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<String, String> {
        fetch_with_client(&self.client, reference, key).await
    }
}

/// Fetch a single secret from Vault (creates a new client).
/// For batch resolution, use `VaultClientWrapper`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    let wrapper = VaultClientWrapper::new()?;
    wrapper.fetch_secret(reference, key).await
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_client(
    client: &vaultrs::client::VaultClient,
    reference: &str,
    key: &str,
) -> Result<String, String> {
    // Parse the reference: path#json_key
    let (path, json_key) = match reference.split_once('#') {
        Some((p, k)) => (p, Some(k)),
        None => (reference, None),
    };

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
        vaultrs::kv2::read(client, mount, secret_path)
            .await
            .map_err(|e| format!("Failed to read {} from Vault path '{}': {}", key, path, e))?;

    match json_key {
        Some(jk) => secret.get(jk).cloned().ok_or_else(|| {
            format!(
                "Vault secret at '{}' does not contain key '{}' for {}",
                path, jk, key
            )
        }),
        None => {
            // Without an explicit #json_key, require exactly one key to avoid
            // non-deterministic results from HashMap iteration order.
            if secret.len() != 1 {
                return Err(format!(
                    "Vault secret at '{}' for {} contains {} keys — \
                     specify which key to use with #<json_key> suffix",
                    path,
                    key,
                    secret.len()
                ));
            }
            secret
                .into_values()
                .next()
                .ok_or_else(|| format!("Vault secret at '{}' is empty for {}", path, key))
        }
    }
}
