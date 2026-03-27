//! Azure Key Vault secret resolution (requires `secrets-azure` feature).
//!
//! Authentication uses `ClientSecretCredential` via env vars:
//! - `AZURE_TENANT_ID` — Azure AD tenant ID
//! - `AZURE_CLIENT_ID` — Application (service principal) client ID
//! - `AZURE_CLIENT_SECRET` — Application client secret

use std::env;
use std::sync::Arc;

/// Check if the `{key}_AZURE` env var is set and non-empty.
/// Returns the Azure Key Vault secret URL
/// (e.g. `https://<vault>.vault.azure.net/secrets/<name>`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let azure_key = format!("{}_AZURE", key);
    env::var(&azure_key).ok().filter(|s| !s.is_empty())
}

/// Fetch a secret value from Azure Key Vault.
///
/// The `reference` format is `https://<vault-name>.vault.azure.net/secrets/<secret-name>`.
/// Authentication is via `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`
/// environment variables (service principal / client secret credential).
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    // Parse the reference URL to extract vault URL and secret name
    let url = url::Url::parse(reference)
        .map_err(|e| format!("Invalid Azure Key Vault URL for {}: {}", key, e))?;

    let vault_url = format!(
        "{}://{}",
        url.scheme(),
        url.host_str()
            .ok_or_else(|| format!("Azure Key Vault URL for {} has no host", key))?
    );

    let path_segments: Vec<&str> = url.path().trim_matches('/').split('/').collect();
    if path_segments.len() < 2 || path_segments[0] != "secrets" {
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: expected format \
             https://<vault>.vault.azure.net/secrets/<name>",
            key
        ));
    }
    let secret_name = path_segments[1];

    // Build credential from env vars
    let tenant_id = env::var("AZURE_TENANT_ID")
        .map_err(|_| format!("AZURE_TENANT_ID must be set to resolve {} from Azure", key))?;
    let client_id = env::var("AZURE_CLIENT_ID")
        .map_err(|_| format!("AZURE_CLIENT_ID must be set to resolve {} from Azure", key))?;
    let client_secret = env::var("AZURE_CLIENT_SECRET").map_err(|_| {
        format!(
            "AZURE_CLIENT_SECRET must be set to resolve {} from Azure",
            key
        )
    })?;

    let credential: Arc<dyn azure_core::credentials::TokenCredential> =
        azure_identity::ClientSecretCredential::new(
            &tenant_id,
            client_id,
            client_secret.into(),
            None,
        )
        .map_err(|e| format!("Failed to create Azure credentials for {}: {}", key, e))?;

    let client =
        azure_security_keyvault_secrets::SecretClient::new(&vault_url, credential, None)
            .map_err(|e| format!("Failed to create Azure Key Vault client for {}: {}", key, e))?;

    let response = client.get_secret(secret_name, None).await.map_err(|e| {
        format!(
            "Failed to get Azure secret '{}' for {}: {}",
            secret_name, key, e
        )
    })?;

    let secret = response.into_model().map_err(|e| {
        format!(
            "Failed to parse Azure secret '{}' for {}: {}",
            secret_name, key, e
        )
    })?;

    secret
        .value
        .ok_or_else(|| format!("Azure secret '{}' for {} has no value", secret_name, key))
}
