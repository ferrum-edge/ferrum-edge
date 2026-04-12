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

mod aws;
mod azure;
mod env;
mod file;
mod gcp;
mod vault;

use std::collections::HashMap;
use tracing::info;

/// Only scan environment variables with this prefix.
const FERRUM_PREFIX: &str = "FERRUM_";

/// Default timeout (seconds) for individual secret fetch operations from cloud backends.
const DEFAULT_SECRET_FETCH_TIMEOUT_SECS: u64 = 30;

/// Read the secret fetch timeout from `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` env var,
/// falling back to the default. Called before EnvConfig is parsed (secrets are
/// resolved first), so this reads the env var directly.
fn secret_fetch_timeout() -> std::time::Duration {
    let secs = crate::config::conf_file::resolve_ferrum_var("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECRET_FETCH_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

/// Secret backend identified during env var scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecretBackend {
    File,
    Vault,
    Aws,
    Gcp,
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
    if let Some(base) = raw_key.strip_suffix("_AZURE") {
        return Some((base, SecretBackend::Azure));
    }
    if let Some(base) = raw_key.strip_suffix("_VAULT") {
        return Some((base, SecretBackend::Vault));
    }
    if let Some(base) = raw_key.strip_suffix("_FILE") {
        return Some((base, SecretBackend::File));
    }
    if let Some(base) = raw_key.strip_suffix("_AWS") {
        return Some((base, SecretBackend::Aws));
    }
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

    // Read the configurable timeout once for all backend fetches.
    let fetch_timeout = secret_fetch_timeout();

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

    // Vault secrets (single client, all fetches concurrent via join_all)
    {
        let vault_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Vault)
            .collect();
        if !vault_secrets.is_empty() {
            let client = vault::VaultClientWrapper::new()?;
            let futs: Vec<_> = vault_secrets
                .iter()
                .map(|s| async {
                    let value = tokio::time::timeout(
                        fetch_timeout,
                        client.fetch_secret(&s.reference, &s.base_key),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Vault after {}s",
                            s.base_key,
                            fetch_timeout.as_secs()
                        )
                    })??;
                    Ok::<_, String>((s.base_key.clone(), value, s.suffixed_key.clone()))
                })
                .collect();
            for result in futures_util::future::join_all(futs).await {
                let (base_key, value, suffixed_key) = result?;
                info!("Loaded {} from Vault", base_key);
                results.vars.push((base_key, value));
                results.source_keys_to_remove.push(suffixed_key);
            }
        }
    }

    // AWS secrets (single client, all fetches concurrent via join_all)
    {
        let aws_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Aws)
            .collect();
        if !aws_secrets.is_empty() {
            let client = aws::AwsClientWrapper::new().await;
            let futs: Vec<_> = aws_secrets
                .iter()
                .map(|s| async {
                    let value = tokio::time::timeout(
                        fetch_timeout,
                        client.fetch_secret(&s.reference, &s.base_key),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from AWS Secrets Manager after {}s",
                            s.base_key,
                            fetch_timeout.as_secs()
                        )
                    })??;
                    Ok::<_, String>((s.base_key.clone(), value, s.suffixed_key.clone()))
                })
                .collect();
            for result in futures_util::future::join_all(futs).await {
                let (base_key, value, suffixed_key) = result?;
                info!("Loaded {} from AWS Secrets Manager", base_key);
                results.vars.push((base_key, value));
                results.source_keys_to_remove.push(suffixed_key);
            }
        }
    }

    // GCP secrets (single client, all fetches concurrent via join_all)
    {
        let gcp_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Gcp)
            .collect();
        if !gcp_secrets.is_empty() {
            let client = gcp::GcpClientWrapper::new().await?;
            let futs: Vec<_> = gcp_secrets
                .iter()
                .map(|s| async {
                    let value = tokio::time::timeout(
                        fetch_timeout,
                        client.fetch_secret(&s.reference, &s.base_key),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from GCP Secret Manager after {}s",
                            s.base_key,
                            fetch_timeout.as_secs()
                        )
                    })??;
                    Ok::<_, String>((s.base_key.clone(), value, s.suffixed_key.clone()))
                })
                .collect();
            for result in futures_util::future::join_all(futs).await {
                let (base_key, value, suffixed_key) = result?;
                info!("Loaded {} from GCP Secret Manager", base_key);
                results.vars.push((base_key, value));
                results.source_keys_to_remove.push(suffixed_key);
            }
        }
    }

    // Azure secrets (single credential, all fetches concurrent via join_all)
    {
        let azure_secrets: Vec<&PendingSecret> = pending
            .iter()
            .filter(|s| s.backend == SecretBackend::Azure)
            .collect();
        if !azure_secrets.is_empty() {
            let creds = azure::AzureCredentials::new()?;
            let futs: Vec<_> = azure_secrets
                .iter()
                .map(|s| async {
                    let value = tokio::time::timeout(
                        fetch_timeout,
                        creds.fetch_secret(&s.reference, &s.base_key),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Azure Key Vault after {}s",
                            s.base_key,
                            fetch_timeout.as_secs()
                        )
                    })??;
                    Ok::<_, String>((s.base_key.clone(), value, s.suffixed_key.clone()))
                })
                .collect();
            for result in futures_util::future::join_all(futs).await {
                let (base_key, value, suffixed_key) = result?;
                info!("Loaded {} from Azure Key Vault", base_key);
                results.vars.push((base_key, value));
                results.source_keys_to_remove.push(suffixed_key);
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

    // Cloud backends
    if let Some(vault_ref) = vault::resolve_ref(key) {
        sources.push(("vault", vault_ref));
    }
    if let Some(aws_ref) = aws::resolve_ref(key) {
        sources.push(("aws", aws_ref));
    }
    if let Some(gcp_ref) = gcp::resolve_ref(key) {
        sources.push(("gcp", gcp_ref));
    }
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
        "vault" => {
            let value =
                tokio::time::timeout(secret_fetch_timeout(), vault::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Vault after {}s",
                            key,
                            secret_fetch_timeout().as_secs()
                        )
                    })??;
            info!("Loaded {} from Vault", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("vault:{}", reference),
            }))
        }
        "aws" => {
            let value =
                tokio::time::timeout(secret_fetch_timeout(), aws::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from AWS Secrets Manager after {}s",
                            key,
                            secret_fetch_timeout().as_secs()
                        )
                    })??;
            info!("Loaded {} from AWS Secrets Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("aws:{}", reference),
            }))
        }
        "gcp" => {
            let value =
                tokio::time::timeout(secret_fetch_timeout(), gcp::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from GCP Secret Manager after {}s",
                            key,
                            secret_fetch_timeout().as_secs()
                        )
                    })??;
            info!("Loaded {} from GCP Secret Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("gcp:{}", reference),
            }))
        }
        "azure" => {
            let value =
                tokio::time::timeout(secret_fetch_timeout(), azure::fetch_secret(&reference, key))
                    .await
                    .map_err(|_| {
                        format!(
                            "Timeout resolving {} from Azure Key Vault after {}s",
                            key,
                            secret_fetch_timeout().as_secs()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_suffix_file() {
        let (base, backend) = match_suffix("FERRUM_DB_URL_FILE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend, SecretBackend::File);
    }

    #[test]
    fn match_suffix_vault() {
        let (base, backend) = match_suffix("FERRUM_JWT_SECRET_VAULT").unwrap();
        assert_eq!(base, "FERRUM_JWT_SECRET");
        assert_eq!(backend, SecretBackend::Vault);
    }

    #[test]
    fn match_suffix_aws() {
        let (base, backend) = match_suffix("FERRUM_DB_URL_AWS").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend, SecretBackend::Aws);
    }

    #[test]
    fn match_suffix_gcp() {
        let (base, backend) = match_suffix("FERRUM_DB_URL_GCP").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend, SecretBackend::Gcp);
    }

    #[test]
    fn match_suffix_azure() {
        let (base, backend) = match_suffix("FERRUM_DB_URL_AZURE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend, SecretBackend::Azure);
    }

    #[test]
    fn match_suffix_no_match() {
        assert!(match_suffix("FERRUM_DB_URL").is_none());
        assert!(match_suffix("FERRUM_DB_URL_ETCD").is_none());
        assert!(match_suffix("").is_none());
        assert!(match_suffix("RANDOM_KEY").is_none());
    }

    #[test]
    fn match_suffix_bare_suffix_returns_empty_base() {
        let (base, backend) = match_suffix("_FILE").unwrap();
        assert_eq!(base, "");
        assert_eq!(backend, SecretBackend::File);
    }

    #[test]
    fn match_suffix_azure_checked_before_file() {
        // Ensure _AZURE is matched correctly (not confused with other suffixes)
        let (base, backend) = match_suffix("FERRUM_X_AZURE").unwrap();
        assert_eq!(base, "FERRUM_X");
        assert_eq!(backend, SecretBackend::Azure);
    }

    #[test]
    fn match_suffix_case_sensitive() {
        // Lowercase suffixes should NOT match
        assert!(match_suffix("FERRUM_DB_URL_file").is_none());
        assert!(match_suffix("FERRUM_DB_URL_vault").is_none());
        assert!(match_suffix("FERRUM_DB_URL_aws").is_none());
    }
}
