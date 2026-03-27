//! Secret resolution with pluggable backends.
//!
//! Any environment variable can be loaded from an external source by setting
//! a suffixed variant instead of the variable itself:
//!
//! - `FERRUM_X_FILE=/path` — read from file (always available)
//! - `FERRUM_X_VAULT=secret/data/app#key` — HashiCorp Vault (requires `secrets-vault`)
//! - `FERRUM_X_AWS=arn:...` — AWS Secrets Manager (requires `secrets-aws`)
//! - `FERRUM_X_GCP=projects/...` — GCP Secret Manager (requires `secrets-gcp`)
//! - `FERRUM_X_AZURE=https://...` — Azure Key Vault (requires `secrets-azure`)
//!
//! At startup, `resolve_all_env_secrets()` scans the environment for any
//! suffixed variables, resolves them, and injects the result into the base
//! env var. After this runs, the rest of the config loading reads plain
//! env vars as usual — no code changes needed per config key.
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

/// Known suffixes for external secret sources.
const SUFFIXES: &[&str] = &[
    "_FILE",
    #[cfg(feature = "secrets-vault")]
    "_VAULT",
    #[cfg(feature = "secrets-aws")]
    "_AWS",
    #[cfg(feature = "secrets-gcp")]
    "_GCP",
    #[cfg(feature = "secrets-azure")]
    "_AZURE",
];

/// A successfully resolved secret value with its source for logging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedSecret {
    pub value: String,
    /// Human-readable source description (e.g. "env", "file:/run/secrets/jwt").
    /// Never contains the secret value itself.
    pub source: String,
}

/// Scan the environment for all `*_FILE`, `*_VAULT`, `*_AWS`, `*_GCP`, `*_AZURE`
/// variables, resolve each one, and inject the result into the corresponding
/// base env var.
///
/// This must be called **before** `EnvConfig::from_env_unvalidated()` so that
/// the config loader sees the resolved values as plain env vars.
///
/// Returns the number of secrets resolved from external sources.
pub async fn resolve_all_env_secrets() -> Result<usize, String> {
    // Collect all suffixed env vars first (avoid mutating env while iterating)
    let mut to_resolve: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for (raw_key, value) in std::env::vars() {
        for suffix in SUFFIXES {
            if let Some(base_key) = raw_key.strip_suffix(suffix)
                && !base_key.is_empty()
                && !value.is_empty()
            {
                to_resolve
                    .entry(base_key.to_string())
                    .or_default()
                    .push((format!("{suffix} ({raw_key})"), value.clone()));
            }
        }
    }

    let mut resolved_count = 0;

    for (base_key, sources) in &to_resolve {
        // Check if the base env var is also set (conflict)
        let direct_set = std::env::var(base_key)
            .ok()
            .filter(|s| !s.is_empty())
            .is_some();

        let total_sources = sources.len() + if direct_set { 1 } else { 0 };

        if total_sources > 1 {
            let mut names: Vec<&str> = Vec::new();
            if direct_set {
                names.push("direct env var");
            }
            for (suffix_desc, _) in sources {
                names.push(suffix_desc);
            }
            return Err(format!(
                "Multiple secret sources configured for {}: {}. Only one source is allowed.",
                base_key,
                names.join(", ")
            ));
        }

        // Resolve the single external source
        let (suffix_desc, reference) = &sources[0];
        let value = resolve_from_suffix(suffix_desc, reference, base_key).await?;

        // SAFETY: Called during single-threaded startup before any concurrent
        // env var reads. The tokio runtime is up but no worker tasks are
        // reading env vars yet.
        unsafe {
            std::env::set_var(base_key, &value);
        }
        resolved_count += 1;
    }

    Ok(resolved_count)
}

/// Resolve a single secret from a specific suffix source.
async fn resolve_from_suffix(
    suffix_desc: &str,
    reference: &str,
    base_key: &str,
) -> Result<String, String> {
    if suffix_desc.contains("_FILE") {
        let value = file::read_secret(reference, base_key)?;
        info!("Loaded {} from file", base_key);
        Ok(value)
    } else if cfg!(feature = "secrets-vault") && suffix_desc.contains("_VAULT") {
        #[cfg(feature = "secrets-vault")]
        {
            let value = vault::fetch_secret(reference, base_key).await?;
            info!("Loaded {} from Vault", base_key);
            Ok(value)
        }
        #[cfg(not(feature = "secrets-vault"))]
        unreachable!()
    } else if cfg!(feature = "secrets-aws") && suffix_desc.contains("_AWS") {
        #[cfg(feature = "secrets-aws")]
        {
            let value = aws::fetch_secret(reference, base_key).await?;
            info!("Loaded {} from AWS Secrets Manager", base_key);
            Ok(value)
        }
        #[cfg(not(feature = "secrets-aws"))]
        unreachable!()
    } else if cfg!(feature = "secrets-gcp") && suffix_desc.contains("_GCP") {
        #[cfg(feature = "secrets-gcp")]
        {
            let value = gcp::fetch_secret(reference, base_key).await?;
            info!("Loaded {} from GCP Secret Manager", base_key);
            Ok(value)
        }
        #[cfg(not(feature = "secrets-gcp"))]
        unreachable!()
    } else if cfg!(feature = "secrets-azure") && suffix_desc.contains("_AZURE") {
        #[cfg(feature = "secrets-azure")]
        {
            let value = azure::fetch_secret(reference, base_key).await?;
            info!("Loaded {} from Azure Key Vault", base_key);
            Ok(value)
        }
        #[cfg(not(feature = "secrets-azure"))]
        unreachable!()
    } else {
        Err(format!(
            "Unknown secret source suffix '{}' for {}",
            suffix_desc, base_key
        ))
    }
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
            let value = vault::fetch_secret(&reference, key).await?;
            info!("Loaded {} from Vault", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("vault:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-aws")]
        "aws" => {
            let value = aws::fetch_secret(&reference, key).await?;
            info!("Loaded {} from AWS Secrets Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("aws:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-gcp")]
        "gcp" => {
            let value = gcp::fetch_secret(&reference, key).await?;
            info!("Loaded {} from GCP Secret Manager", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("gcp:{}", reference),
            }))
        }
        #[cfg(feature = "secrets-azure")]
        "azure" => {
            let value = azure::fetch_secret(&reference, key).await?;
            info!("Loaded {} from Azure Key Vault", key);
            Ok(Some(ResolvedSecret {
                value,
                source: format!("azure:{}", reference),
            }))
        }
        _ => Err(format!("Unknown secret backend '{}' for {}", backend, key)),
    }
}
