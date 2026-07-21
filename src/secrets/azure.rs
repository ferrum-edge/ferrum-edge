//! Azure Key Vault secret resolution (requires `secrets-azure` feature).
//!
//! Authentication uses `ClientSecretCredential` via env vars:
//! - `AZURE_TENANT_ID` — Azure AD tenant ID
//! - `AZURE_CLIENT_ID` — Application (service principal) client ID
//! - `AZURE_CLIENT_SECRET` — Application client secret
//!
//! A pre-acquired bearer token may be supplied instead via
//! `AZURE_KEY_VAULT_BEARER_TOKEN` (sidecar / federated injection / local fakes).
//! When that variable is set and non-empty it takes precedence over the
//! client-secret credential chain and performs no Entra ID round trip.
//!
//! # Reference grammar
//!
//! Key Vault secret URLs follow:
//! - `https://<vault>/secrets/<name>` — fetch the latest version
//! - `https://<vault>/secrets/<name>/<version>` — fetch exactly that version
//!
//! Extra path segments beyond the optional version are rejected. A versioned
//! URL never silently falls back to latest.
//!
//! Typed TLS `azure://` sources may also carry `?version=<id>`. When both a
//! path version and `?version=` are present they must match; conflicts fail
//! closed. The configured source identity (`CertSource` identifier + options)
//! is never rewritten by fetch normalization.

use std::env;
use std::sync::Arc;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_security_keyvault_secrets::ResourceExt;
use azure_security_keyvault_secrets::models::SecretClientGetSecretOptions;

/// Check if the `{key}_AZURE` env var is set and non-empty.
/// Returns the Azure Key Vault secret URL
/// (e.g. `https://<vault>.vault.azure.net/secrets/<name>`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let azure_key = format!("{}_AZURE", key);
    env::var(&azure_key).ok().filter(|s| !s.is_empty())
}

/// A secret value fetched from Azure Key Vault, with the version the service
/// actually returned when available.
#[derive(Debug, Clone)]
pub struct AzureSecret {
    pub value: String,
    pub version: Option<String>,
}

/// Reusable Azure credentials for batch secret resolution.
/// The credential is created once and shared across fetches from multiple
/// vault URLs, avoiding repeated OAuth token acquisition.
pub struct AzureCredentials {
    credential: Arc<dyn TokenCredential>,
}

impl AzureCredentials {
    /// Create Azure credentials from standard env vars.
    ///
    /// When `AZURE_KEY_VAULT_BEARER_TOKEN` is set and non-empty, a static
    /// bearer-token credential is used instead of the client-secret chain.
    pub fn new() -> Result<Self, String> {
        if let Ok(token) = env::var("AZURE_KEY_VAULT_BEARER_TOKEN") {
            let token = token.trim();
            if !token.is_empty() {
                return Ok(Self::from_static_token(token.to_string()));
            }
        }

        let tenant_id = env::var("AZURE_TENANT_ID").map_err(|_| {
            "AZURE_TENANT_ID must be set to resolve secrets from Azure Key Vault".to_string()
        })?;
        let client_id = env::var("AZURE_CLIENT_ID").map_err(|_| {
            "AZURE_CLIENT_ID must be set to resolve secrets from Azure Key Vault".to_string()
        })?;
        let client_secret = env::var("AZURE_CLIENT_SECRET").map_err(|_| {
            "AZURE_CLIENT_SECRET must be set to resolve secrets from Azure Key Vault".to_string()
        })?;

        let credential: Arc<dyn TokenCredential> = azure_identity::ClientSecretCredential::new(
            &tenant_id,
            client_id,
            client_secret.into(),
            None,
        )
        .map_err(|e| format!("Failed to create Azure credentials: {}", e))?;

        Ok(Self { credential })
    }

    /// Build credentials from a pre-acquired bearer token instead of acquiring
    /// one from Entra ID.
    ///
    /// This supports environments where a valid Key Vault access token is
    /// obtained out of band — e.g. a workload-identity sidecar, a federated
    /// token file, or an IMDS proxy — and only the Key Vault data-plane call
    /// needs to be made in-process. The credential performs no Entra ID round
    /// trip of its own; it simply replays the supplied token when the Key Vault
    /// pipeline requests one (including after an authentication challenge).
    pub fn from_static_token(token: impl Into<String>) -> Self {
        Self {
            credential: Arc::new(StaticTokenCredential::new(token)),
        }
    }

    /// Fetch a secret value from Azure Key Vault using these credentials.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<AzureSecret, String> {
        fetch_with_credential(&self.credential, reference, key).await
    }
}

/// Fetch a single secret from Azure Key Vault (creates new credentials).
/// For batch resolution, use `AzureCredentials`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<AzureSecret, String> {
    let creds = AzureCredentials::new()?;
    creds.fetch_secret(reference, key).await
}

/// Parsed Key Vault secret reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVaultReference {
    pub vault_url: String,
    pub secret_name: String,
    pub version: Option<String>,
}

impl KeyVaultReference {
    /// Reconstruct a canonical secret URL (without query/fragment).
    pub fn to_reference_url(&self) -> String {
        match &self.version {
            Some(version) => {
                format!("{}/secrets/{}/{}", self.vault_url, self.secret_name, version)
            }
            None => format!("{}/secrets/{}", self.vault_url, self.secret_name),
        }
    }
}

/// Parse a Key Vault secret reference URL into vault URL, secret name, and
/// optional version.
///
/// The returned `vault_url` preserves the scheme, host **and port** of the
/// reference. Dropping the port (the previous behavior) silently rewrote a URL
/// like `http://127.0.0.1:12345/secrets/admin-jwt` to `http://127.0.0.1`, which
/// breaks any vault served on a non-default port — including local fakes,
/// emulators, and sidecar/proxy front ends.
///
/// Path grammar:
/// - `/secrets/<name>` — latest version (`version = None`)
/// - `/secrets/<name>/<version>` — pinned version
/// - any additional path segment — rejected (fail closed)
pub fn parse_keyvault_reference(
    reference: &str,
    key: &str,
) -> Result<(String, String, Option<String>), String> {
    let parsed = parse_keyvault_reference_parts(reference, key)?;
    Ok((parsed.vault_url, parsed.secret_name, parsed.version))
}

/// Parse a Key Vault secret reference into structured parts.
pub fn parse_keyvault_reference_parts(
    reference: &str,
    key: &str,
) -> Result<KeyVaultReference, String> {
    let url = url::Url::parse(reference)
        .map_err(|e| format!("Invalid Azure Key Vault URL for {}: {}", key, e))?;

    let host = url
        .host_str()
        .ok_or_else(|| format!("Azure Key Vault URL for {} has no host", key))?;

    // Preserve an explicit port when present so non-standard ports survive.
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let vault_url = format!("{}://{}", url.scheme(), authority);

    // Strip one leading slash. A single trailing slash on an otherwise valid
    // unversioned/versioned path is ignored so `/secrets/name/` keeps working
    // as latest; empty *interior* segments still fail closed.
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    let mut path_segments: Vec<&str> = path.split('/').collect();
    if path_segments.last() == Some(&"") {
        path_segments.pop();
    }
    if path_segments.len() < 2 || path_segments[0] != "secrets" {
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: expected format \
             https://<vault>.vault.azure.net/secrets/<name>[/<version>]",
            key
        ));
    }
    if path_segments.len() > 3 {
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: unexpected path segments after \
             /secrets/<name>/<version>",
            key
        ));
    }

    let secret_name = path_segments[1];
    if secret_name.is_empty() {
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: secret name must not be empty",
            key
        ));
    }

    let version = if path_segments.len() == 3 {
        let version = path_segments[2];
        if version.is_empty() {
            return Err(format!(
                "Invalid Azure Key Vault URL for {}: version segment must not be empty",
                key
            ));
        }
        Some(version.to_string())
    } else {
        None
    };

    Ok(KeyVaultReference {
        vault_url,
        secret_name: secret_name.to_string(),
        version,
    })
}

/// Merge a typed TLS `?version=` option into an Azure Key Vault reference.
///
/// - Path version only, or `?version=` only → that version is used for fetch.
/// - Both present and equal → accepted (reference left unchanged when the path
///   already carries the version; otherwise the path is rewritten for fetch).
/// - Both present and unequal → rejected (fail closed).
///
/// The returned string is the reference passed to the Azure data plane. It must
/// not replace configured source identity (`CertSource` identifier / options).
pub fn apply_tls_version_option(
    reference: &str,
    tls_query_version: Option<&str>,
    key: &str,
) -> Result<String, String> {
    let parsed = parse_keyvault_reference_parts(reference, key)?;
    let query_version = match tls_query_version.map(str::trim) {
        Some("") => {
            return Err(format!(
                "Invalid Azure Key Vault version option for {}: version must not be empty",
                key
            ));
        }
        Some(version) => Some(version),
        None => None,
    };

    let effective_version = match (parsed.version.as_deref(), query_version) {
        (Some(path_version), Some(query_version)) if path_version != query_version => {
            return Err(format!(
                "Conflicting Azure Key Vault versions for {}: URL path and ?version= do not match",
                key
            ));
        }
        (Some(version), _) | (_, Some(version)) => Some(version.to_string()),
        (None, None) => None,
    };

    Ok(KeyVaultReference {
        vault_url: parsed.vault_url,
        secret_name: parsed.secret_name,
        version: effective_version,
    }
    .to_reference_url())
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_credential(
    credential: &Arc<dyn TokenCredential>,
    reference: &str,
    key: &str,
) -> Result<AzureSecret, String> {
    let parsed = parse_keyvault_reference_parts(reference, key)?;

    let client =
        azure_security_keyvault_secrets::SecretClient::new(&parsed.vault_url, credential.clone(), None)
            .map_err(|e| format!("Failed to create Azure Key Vault client for {}: {}", key, e))?;

    // Errors name the base key and the failure class only — the vault URL and
    // secret name are the source reference and are treated as sensitive. The
    // registry additionally redacts any residual occurrence echoed back by the
    // SDK error itself.
    let options = parsed.version.as_ref().map(|version| SecretClientGetSecretOptions {
        secret_version: Some(version.clone()),
        ..Default::default()
    });
    let response = client
        .get_secret(&parsed.secret_name, options)
        .await
        .map_err(|e| format!("Failed to get Azure secret for {}: {}", key, e))?;

    let secret = response
        .into_model()
        .map_err(|e| format!("Failed to parse Azure secret for {}: {}", key, e))?;

    let value = secret
        .value
        .ok_or_else(|| format!("Azure secret for {} has no value", key))?;

    let fetched_version = secret
        .resource_id()
        .ok()
        .and_then(|id| id.version)
        .or_else(|| parsed.version.clone());

    if let (Some(requested), Some(returned)) = (parsed.version.as_deref(), fetched_version.as_deref())
    {
        if requested != returned {
            return Err(format!(
                "Azure secret for {} returned a different version than requested",
                key
            ));
        }
    }

    Ok(AzureSecret {
        value,
        version: fetched_version,
    })
}

/// A [`TokenCredential`] backed by a fixed, pre-acquired bearer token.
///
/// Used by [`AzureCredentials::from_static_token`]; performs no token
/// acquisition of its own and simply replays the supplied token.
#[derive(Debug)]
struct StaticTokenCredential {
    token: String,
}

impl StaticTokenCredential {
    fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait::async_trait]
impl TokenCredential for StaticTokenCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        // The token is supplied externally and is not refreshed in-process;
        // hand back a generous expiry so the pipeline treats it as valid.
        let expires_on = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        Ok(AccessToken::new(self.token.clone(), expires_on))
    }
}
