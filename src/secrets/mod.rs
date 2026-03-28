//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself:
//!
//! - `FERRUM_X_FILE=/path` — read from file (always available)
//! - `FERRUM_X_VAULT=secret/data/app#key` — HashiCorp Vault (requires `secrets-vault`)
//! - `FERRUM_X_AWS=arn:...` — AWS Secrets Manager (requires `secrets-aws`)
//! - `FERRUM_X_GCP=projects/...` — GCP Secret Manager (requires `secrets-gcp`)
//! - `FERRUM_X_AZURE=https://...` — Azure Key Vault (requires `secrets-azure`)
//!
//! At startup, `resolve_all_env_secrets()` scans the environment for any
//! `FERRUM_*` suffixed variables, resolves them, and returns the results.
//! The caller injects them into the process environment before config loading.
//!
//! Only variables with the `FERRUM_` prefix are scanned, preventing accidental
//! resolution of unrelated application env vars.
//!
//! If both the base variable and a suffixed variant are set, startup fails
//! with a conflict error.

mod env;
mod file;

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
#[cfg(feature = "secrets-gcp")]
mod gcp;
#[cfg(feature = "secrets-vault")]
mod vault;

use std::collections::HashMap;
use tracing::info;

/// Only scan environment variables with this prefix.
const FERRUM_PREFIX: &str = "FERRUM_";

/// Timeout for individual secret fetch operations from cloud backends.
#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
const SECRET_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Secret backend identified during env var scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecretBackend {
    File,
    #[cfg(feature = "secrets-vault")]
    Vault,
    #[cfg(feature = "secrets-aws")]
    Aws,
    #[cfg(feature = "secrets-gcp")]
    Gcp,
    #[cfg(feature = "secrets-azure")]
    Azure,
}

/// A pending secret to resolve.
struct PendingSecret {
    base_key: String,
    reference: String,
    suffixed_key: String,
    backend: SecretBackend,
}

/// Match a raw env var key against known secret suffixes.
/// Returns `(base_key, backend)` if the key ends with a recognized suffix.
fn match_suffix(raw_key: &str) -> Option<(&str, SecretBackend)> {
    // Check longer suffixes first to avoid false prefix matches.
    #[cfg(feature = "secrets-azure")]
    if let Some(base) = raw_key.strip_suffix("_AZURE") {
        return Some((base, SecretBackend::Azure));
    }
    #[cfg(feature = "secrets-vault")]
    if let Some(base) = raw_key.strip_suffix("_VAULT") {
        return Some((base, SecretBackend::Vault));
    }
    if let Some(base) = raw_key.strip_suffix("_FILE") {
        return Some((base, SecretBackend::File));
    }
    #[cfg(feature = "secrets-aws")]
    if let Some(base) = raw_key.strip_suffix("_AWS") {
        return Some((base, SecretBackend::Aws));
    }
    #[cfg(feature = "secrets-gcp")]
    if let Some(base) = raw_key.strip_suffix("_GCP") {
        return Some((base, SecretBackend::Gcp));
    }
    None
}

/// The result of resolving all env-based secrets at startup.
pub struct ResolvedEnvSecrets {
    /// Resolved `(base_key, value)` pairs to inject into the environment.
    pub vars: Vec<(String, String)>,
    /// Suffixed source keys (e.g., `FERRUM_X_FILE`) to remove from the environment.
    pub source_keys_to_remove: Vec<String>,
}

/// A successfully resolved secret value with its source for logging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedSecret {
    pub value: String,
    /// Human-readable source description (e.g. "env", "file:/run/secrets/jwt").
    /// Never contains the secret value itself.
    pub source: String,
}

/// Scan the environment for all `FERRUM_*_{FILE,VAULT,AWS,GCP,AZURE}` variables,
/// resolve each one, and return the results for the caller to inject into the
/// process environment.
///
/// This must be called **before** `EnvConfig::from_env()` so that the config
/// loader sees the resolved values as plain env vars.
///
/// Only variables with the `FERRUM_` prefix are scanned, preventing accidental
/// resolution of unrelated application env vars.
pub async fn resolve_all_env_secrets() -> Result<ResolvedEnvSecrets, String> {
    // Collect all suffixed env vars (avoid mutating env while iterating)
    let mut to_resolve: HashMap<String, Vec<(SecretBackend, String, String)>> = HashMap::new();

    for (raw_key, value) in std::env::vars() {
        if !raw_key.starts_with(FERRUM_PREFIX) {
            continue;
        }
        if let Some((base_key, backend)) = match_suffix(&raw_key) {
            if base_key.is_empty() || value.is_empty() {
                continue;
            }
            to_resolve.entry(base_key.to_string()).or_default().push((
                backend,
                raw_key.clone(),
                value,
            ));
        }
    }

    // Check for conflicts and build the pending list
    let mut pending: Vec<PendingSecret> = Vec::new();

    for (base_key, sources) in &to_resolve {
        let direct_set = std::env::var(base_key)
            .ok()
            .filter(|s| !s.is_empty())
            .is_some();

        let total_sources = sources.len() + if direct_set { 1 } else { 0 };

        if total_sources > 1 {
            let mut names: Vec<String> = Vec::new();
            if direct_set {
                names.push("direct env var".to_string());
            }
            for (_, suffixed_key, _) in sources {
                names.push(suffixed_key.clone());
            }
            return Err(format!(
                "Multiple secret sources configured for {}: {}. Only one source is allowed.",
                base_key,
                names.join(", ")
            ));
        }

        let (backend, suffixed_key, reference) = &sources[0];
        pending.push(PendingSecret {
            base_key: base_key.clone(),
            reference: reference.clone(),
            suffixed_key: suffixed_key.clone(),
            backend: backend.clone(),
        });
    }

    // Resolve secrets, grouped by backend for client reuse
    let mut results = ResolvedEnvSecrets {
        vars: Vec::new(),
        source_keys_to_remove: Vec::new(),
    };

    // File secrets (no client needed, no timeout needed)
    for s in pending.iter().filter(|s| s.backend == SecretBackend::File) {
        let value = file::read_secret(&s.reference, &s.base_key)?;
        info!("Loaded {} from file", s.base_key);
        results.vars.push((s.base_key.clone(), value));
        results.source_keys_to_remove.push(s.suffixed_key.clone());
    }

    // Vault secrets (single client, shared across all Vault refs)
    #[cfg(feature = "secrets-vault")]
    {
        let vault_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Vault)
            .collect();
        if !vault_secrets.is_empty() {
            let client = vault::VaultClientWrapper::new()?;
            for s in vault_secrets {
                let value = tokio::time::timeout(
                    SECRET_FETCH_TIMEOUT,
                    client.fetch_secret(&s.reference, &s.base_key),
                )
                .await
                .map_err(|_| {
                    format!(
                        "Timeout resolving {} from Vault after {}s",
                        s.base_key,
                        SECRET_FETCH_TIMEOUT.as_secs()
                    )
                })??;
                info!("Loaded {} from Vault", s.base_key);
                results.vars.push((s.base_key.clone(), value));
                results.source_keys_to_remove.push(s.suffixed_key.clone());
            }
        }
    }

    // AWS secrets (single client, shared across all AWS refs)
    #[cfg(feature = "secrets-aws")]
    {
        let aws_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Aws)
            .collect();
        if !aws_secrets.is_empty() {
            let client = aws::AwsClientWrapper::new().await;
            for s in aws_secrets {
                let value = tokio::time::timeout(
                    SECRET_FETCH_TIMEOUT,
                    client.fetch_secret(&s.reference, &s.base_key),
                )
                .await
                .map_err(|_| {
                    format!(
                        "Timeout resolving {} from AWS Secrets Manager after {}s",
                        s.base_key,
                        SECRET_FETCH_TIMEOUT.as_secs()
                    )
                })??;
                info!("Loaded {} from AWS Secrets Manager", s.base_key);
                results.vars.push((s.base_key.clone(), value));
                results.source_keys_to_remove.push(s.suffixed_key.clone());
            }
        }
    }

    // GCP secrets (single client, shared across all GCP refs)
    #[cfg(feature = "secrets-gcp")]
    {
        let gcp_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Gcp)
            .collect();
        if !gcp_secrets.is_empty() {
            let client = gcp::GcpClientWrapper::new().await?;
            for s in gcp_secrets {
                let value = tokio::time::timeout(
                    SECRET_FETCH_TIMEOUT,
                    client.fetch_secret(&s.reference, &s.base_key),
                )
                .await
                .map_err(|_| {
                    format!(
                        "Timeout resolving {} from GCP Secret Manager after {}s",
                        s.base_key,
                        SECRET_FETCH_TIMEOUT.as_secs()
                    )
                })??;
                info!("Loaded {} from GCP Secret Manager", s.base_key);
                results.vars.push((s.base_key.clone(), value));
                results.source_keys_to_remove.push(s.suffixed_key.clone());
            }
        }
    }

    // Azure secrets (single credential, shared across all Azure refs)
    #[cfg(feature = "secrets-azure")]
    {
        let azure_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Azure)
            .collect();
        if !azure_secrets.is_empty() {
            let creds = azure::AzureCredentials::new()?;
            for s in azure_secrets {
                let value = tokio::time::timeout(
                    SECRET_FETCH_TIMEOUT,
                    creds.fetch_secret(&s.reference, &s.base_key),
                )
                .await
                .map_err(|_| {
                    format!(
                        "Timeout resolving {} from Azure Key Vault after {}s",
                        s.base_key,
                        SECRET_FETCH_TIMEOUT.as_secs()
                    )
                })??;
                info!("Loaded {} from Azure Key Vault", s.base_key);
                results.vars.push((s.base_key.clone(), value));
                results.source_keys_to_remove.push(s.suffixed_key.clone());
            }
        }
    }

    Ok(results)
}

/// Resolve a single secret by key name, checking all enabled backends.
///
/// This is the lower-level API used by tests and specific call sites.
/// For bulk resolution at startup, prefer `resolve_all_env_secrets()`.
#[allow(dead_code)]
pub async fn resolve_secret(key: &str) -> Result<Option<ResolvedSecret>, String> {
    let mut sources: Vec<(&str, String)> = Vec::new();

    // Always-available backends
    if let Some(val) = env::resolve(key) {
        sources.push(("direct", val));
    }
    if let Some(path) = file::resolve_ref(key) {
        sources.push(("file", path));
    }

    // Feature-gated backends
    #[cfg(feature = "secrets-vault")]
    if let Some(vault_ref) = vault::resolve_ref(key) {
        sources.push(("vault", vault_ref));
    }
    #[cfg(feature = "secrets-aws")]
    if let Some(aws_ref) = aws::resolve_ref(key) {
        sources.push(("aws", aws_ref));
    }
    #[cfg(feature = "secrets-gcp")]
    if let Some(gcp_ref) = gcp::resolve_ref(key) {
        sources.push(("gcp", gcp_ref));
    }
    #[cfg(feature = "secrets-azure")]
    if let Some(azure_ref) = azure::resolve_ref(key) {
        sources.push(("azure", azure_ref));
    }

    if sources.len() > 1 {
        let names: Vec<&str> = sources.iter().map(|(name, _)| *name).collect();
        return Err(format!(
            "Multiple secret sources configured for {}: {}. Only one source is allowed.",
            key,
            names.join(", ")
        ));
    }

    let Some((backend, reference)) = sources.into_iter().next() else {
        return Ok(None);
    };

    match backend {
        "direct" => Ok(Some(ResolvedSecret {
            value: reference,
            source: "env".to_string(),
        })),
        "file" => {
            let value = file::read_secret(&reference, key)?;
            info!("Loaded {} from file", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("file:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-vault")]
        "vault" => {
            let value =
                tokio::time::timeout(SECRET_FETCH_TIMEOUT, vault::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Vault after {}s",
                            key,
                            SECRET_FETCH_TIMEOUT.as_secs()
                        )
                    })??;
            info!("Loaded {} from Vault", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("vault:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-aws")]
        "aws" => {
            let value =
                tokio::time::timeout(SECRET_FETCH_TIMEOUT, aws::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from AWS Secrets Manager after {}s",
                            key,
                            SECRET_FETCH_TIMEOUT.as_secs()
                        )
                    })??;
            info!("Loaded {} from AWS Secrets Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("aws:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-gcp")]
        "gcp" => {
            let value =
                tokio::time::timeout(SECRET_FETCH_TIMEOUT, gcp::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from GCP Secret Manager after {}s",
                            key,
                            SECRET_FETCH_TIMEOUT.as_secs()
                        )
                    })??;
            info!("Loaded {} from GCP Secret Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("gcp:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-azure")]
        "azure" => {
            let value =
                tokio::time::timeout(SECRET_FETCH_TIMEOUT, azure::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Azure Key Vault after {}s",
                            key,
                            SECRET_FETCH_TIMEOUT.as_secs()
                        )
                    })??;
            info!("Loaded {} from Azure Key Vault", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("azure:{}", reference),
            }))
        }
        _ => Err(format!("Unknown secret backend '{}' for {}", backend, key)),
    }
}
