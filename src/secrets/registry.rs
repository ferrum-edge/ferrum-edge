//! Registry-backed secret resolution for env and external secret backends.
//!
//! The registry keeps backend-specific client/init logic inside each provider
//! module while centralizing suffix matching, conflict detection, and startup
//! ordering in one place.

use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use tracing::info;

#[cfg(feature = "secrets-aws")]
use super::aws;
#[cfg(feature = "secrets-azure")]
use super::azure;
#[cfg(feature = "secrets-gcp")]
use super::gcp;
#[cfg(feature = "secrets-vault")]
use super::vault;
use super::{env, file};

/// Only scan environment variables with this prefix.
const FERRUM_PREFIX: &str = "FERRUM_";

/// Default timeout (seconds) for individual secret fetch operations from cloud backends.
const DEFAULT_SECRET_FETCH_TIMEOUT_SECS: u64 = 30;

/// Read the secret fetch timeout from `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` env var,
/// falling back to the default. Called before EnvConfig is parsed (secrets are
/// resolved first), so this reads the env var directly.
fn secret_fetch_timeout() -> Duration {
    let secs = crate::config::conf_file::resolve_ferrum_var("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECRET_FETCH_TIMEOUT_SECS);
    Duration::from_secs(secs)
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

/// The result of resolving all env-based secrets at startup.
pub struct ResolvedEnvSecrets {
    /// Resolved `(base_key, value)` pairs to inject into the environment.
    pub vars: Vec<(String, String)>,
    /// Suffixed source keys (e.g., `FERRUM_X_FILE`) to remove from the environment.
    pub source_keys_to_remove: Vec<String>,
    /// `(base_key, backend display name)` pairs to log once tracing is initialized.
    pub loaded_sources: Vec<(String, &'static str)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BackendKind {
    DirectEnv,
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

#[derive(Clone)]
pub(crate) struct PendingSecret {
    base_key: String,
    reference: String,
    suffixed_key: String,
    backend_kind: BackendKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPendingSecret {
    base_key: String,
    value: String,
    suffixed_key: String,
}

#[async_trait]
pub(crate) trait SecretBackend: Sync + Send {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn suffix(&self) -> Option<&'static str> {
        None
    }
    #[allow(dead_code)]
    fn resolve_ref(&self, key: &str) -> Option<String>;
    #[allow(dead_code)]
    fn source(&self, reference: &str) -> String;
    fn log_loaded(&self) -> bool {
        self.name() != "environment"
    }

    fn matches_suffix<'a>(&self, raw_key: &'a str) -> Option<&'a str> {
        self.suffix()
            .and_then(|suffix| raw_key.strip_suffix(suffix))
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String>;

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        // Apply the same timeout envelope to every backend, including file
        // reads, so startup cannot hang indefinitely on a blocked mount/FIFO.
        let mut resolved = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let value = tokio::time::timeout(
                timeout,
                self.resolve_one(&secret.reference, &secret.base_key),
            )
            .await
            .map_err(|_| {
                format!(
                    "Timeout resolving {} from {} after {}s",
                    secret.base_key,
                    self.display_name(),
                    timeout.as_secs()
                )
            })??;
            resolved.push(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            });
        }
        Ok(resolved)
    }
}

#[allow(dead_code)]
struct DirectEnvBackend;
struct FileBackend;

#[cfg(feature = "secrets-vault")]
struct VaultBackend;
#[cfg(feature = "secrets-aws")]
struct AwsBackend;
#[cfg(feature = "secrets-gcp")]
struct GcpBackend;
#[cfg(feature = "secrets-azure")]
struct AzureBackend;

#[allow(dead_code)]
static DIRECT_ENV_BACKEND: DirectEnvBackend = DirectEnvBackend;
static FILE_BACKEND: FileBackend = FileBackend;
#[cfg(feature = "secrets-vault")]
static VAULT_BACKEND: VaultBackend = VaultBackend;
#[cfg(feature = "secrets-aws")]
static AWS_BACKEND: AwsBackend = AwsBackend;
#[cfg(feature = "secrets-gcp")]
static GCP_BACKEND: GcpBackend = GcpBackend;
#[cfg(feature = "secrets-azure")]
static AZURE_BACKEND: AzureBackend = AzureBackend;

#[allow(dead_code)]
fn all_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&DIRECT_ENV_BACKEND, &FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn startup_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn suffix_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-azure")]
    backends.insert(0, &AZURE_BACKEND);
    #[cfg(feature = "secrets-vault")]
    backends.insert(
        #[cfg(feature = "secrets-azure")]
        1,
        #[cfg(not(feature = "secrets-azure"))]
        0,
        &VAULT_BACKEND,
    );
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    backends
}

#[allow(dead_code)]
fn timeout_error(key: &str, backend_name: &str, timeout: Duration) -> String {
    format!(
        "Timeout resolving {} from {} after {}s",
        key,
        backend_name,
        timeout.as_secs()
    )
}

#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
async fn resolve_many_concurrent<C, F>(
    secrets: &[PendingSecret],
    timeout: Duration,
    backend_name: &'static str,
    client: &C,
    fetch: F,
) -> Result<Vec<ResolvedPendingSecret>, String>
where
    C: Sync,
    F: for<'a> Fn(
        &'a C,
        &'a str,
        &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<String, String>>,
{
    let futs: Vec<_> = secrets
        .iter()
        .map(|secret| async {
            let value =
                tokio::time::timeout(timeout, fetch(client, &secret.reference, &secret.base_key))
                    .await
                    .map_err(|_| timeout_error(&secret.base_key, backend_name, timeout))??;
            Ok::<_, String>(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            })
        })
        .collect();

    let mut resolved = Vec::with_capacity(secrets.len());
    for item in futures_util::future::join_all(futs).await {
        resolved.push(item?);
    }
    Ok(resolved)
}

fn match_suffix(raw_key: &str) -> Option<(&'static dyn SecretBackend, &str)> {
    for backend in suffix_backends() {
        if let Some(base) = backend.matches_suffix(raw_key) {
            return Some((backend, base));
        }
    }
    None
}

pub async fn resolve_all_env_secrets() -> Result<ResolvedEnvSecrets, String> {
    let mut to_resolve: HashMap<String, Vec<(String, String, BackendKind)>> = HashMap::new();

    for (raw_key, value) in std::env::vars() {
        if !raw_key.starts_with(FERRUM_PREFIX) {
            continue;
        }
        if let Some((backend, base_key)) = match_suffix(&raw_key) {
            if base_key.is_empty() || value.is_empty() {
                continue;
            }
            to_resolve.entry(base_key.to_string()).or_default().push((
                raw_key.clone(),
                value,
                backend.kind(),
            ));
        }
    }

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
            for (suffixed_key, _, _) in sources {
                names.push(suffixed_key.clone());
            }
            return Err(format!(
                "Multiple secret sources configured for {}: {}. Only one source is allowed.",
                base_key,
                names.join(", ")
            ));
        }

        let (suffixed_key, reference, backend) = &sources[0];
        pending.push(PendingSecret {
            base_key: base_key.clone(),
            reference: reference.clone(),
            suffixed_key: suffixed_key.clone(),
            backend_kind: *backend,
        });
    }

    let fetch_timeout = secret_fetch_timeout();

    let mut results = ResolvedEnvSecrets {
        vars: Vec::new(),
        source_keys_to_remove: Vec::new(),
        loaded_sources: Vec::new(),
    };

    for backend in startup_backends() {
        let backend_pending: Vec<PendingSecret> = pending
            .iter()
            .filter(|s| s.backend_kind == backend.kind())
            .cloned()
            .collect();
        if backend_pending.is_empty() {
            continue;
        }

        let resolved = backend
            .resolve_many(&backend_pending, fetch_timeout)
            .await?;
        for item in resolved {
            if backend.log_loaded() {
                results
                    .loaded_sources
                    .push((item.base_key.clone(), backend.display_name()));
            }
            results.vars.push((item.base_key, item.value));
            results.source_keys_to_remove.push(item.suffixed_key);
        }
    }

    Ok(results)
}

#[allow(dead_code)]
/// Resolve a single secret key across all configured backends.
///
/// Startup uses `resolve_all_env_secrets()` for bulk env injection; this helper
/// remains for the existing single-key tests and ad-hoc secret lookups.
pub async fn resolve_secret(key: &str) -> Result<Option<ResolvedSecret>, String> {
    let mut sources: Vec<(&'static dyn SecretBackend, String)> = Vec::new();

    for backend in all_backends() {
        if let Some(reference) = backend.resolve_ref(key) {
            sources.push((backend, reference));
        }
    }

    if sources.len() > 1 {
        let names: Vec<&str> = sources.iter().map(|(backend, _)| backend.name()).collect();
        return Err(format!(
            "Multiple secret sources configured for {}: {}. Only one source is allowed.",
            key,
            names.join(", ")
        ));
    }

    let Some((backend, reference)) = sources.into_iter().next() else {
        return Ok(None);
    };

    let value = tokio::time::timeout(secret_fetch_timeout(), backend.resolve_one(&reference, key))
        .await
        .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))??;

    if backend.log_loaded() {
        info!("Loaded {} from {}", key, backend.display_name());
    }

    Ok(Some(ResolvedSecret {
        value,
        source: backend.source(&reference),
    }))
}

#[async_trait]
impl SecretBackend for DirectEnvBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::DirectEnv
    }

    fn name(&self) -> &'static str {
        "direct"
    }

    fn display_name(&self) -> &'static str {
        "environment"
    }

    fn log_loaded(&self) -> bool {
        false
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        env::resolve(key)
    }

    fn source(&self, _reference: &str) -> String {
        "env".to_string()
    }

    async fn resolve_one(&self, _reference: &str, key: &str) -> Result<String, String> {
        env::resolve(key).ok_or_else(|| {
            format!(
                "Environment variable {} was not set when resolving direct env secret",
                key
            )
        })
    }
}

#[async_trait]
impl SecretBackend for FileBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::File
    }

    fn name(&self) -> &'static str {
        "file"
    }

    fn display_name(&self) -> &'static str {
        "file"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_FILE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        file::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("file:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        let reference = reference.to_string();
        let key = key.to_string();
        let key_for_error = key.clone();

        tokio::task::spawn_blocking(move || file::read_secret(&reference, &key))
            .await
            .map_err(|err| {
                format!(
                    "Blocking file secret read task failed for {}: {}",
                    key_for_error, err
                )
            })?
    }
}

#[cfg(feature = "secrets-vault")]
#[async_trait]
impl SecretBackend for VaultBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vault
    }

    fn name(&self) -> &'static str {
        "vault"
    }

    fn display_name(&self) -> &'static str {
        "Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_VAULT")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        vault::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("vault:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        vault::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = vault::VaultClientWrapper::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-aws")]
#[async_trait]
impl SecretBackend for AwsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Aws
    }

    fn name(&self) -> &'static str {
        "aws"
    }

    fn display_name(&self) -> &'static str {
        "AWS Secrets Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AWS")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        aws::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("aws:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        aws::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = aws::AwsClientWrapper::new().await;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-gcp")]
#[async_trait]
impl SecretBackend for GcpBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Gcp
    }

    fn name(&self) -> &'static str {
        "gcp"
    }

    fn display_name(&self) -> &'static str {
        "GCP Secret Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_GCP")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        gcp::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("gcp:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        gcp::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = gcp::GcpClientWrapper::new().await?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-azure")]
#[async_trait]
impl SecretBackend for AzureBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Azure
    }

    fn name(&self) -> &'static str {
        "azure"
    }

    fn display_name(&self) -> &'static str {
        "Azure Key Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AZURE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        azure::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("azure:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        azure::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let creds = azure::AzureCredentials::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &creds,
            |creds, reference, key| Box::pin(creds.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn match_suffix_file() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_FILE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-vault")]
    #[test]
    fn match_suffix_vault() {
        let (backend, base) = match_suffix("FERRUM_JWT_SECRET_VAULT").unwrap();
        assert_eq!(base, "FERRUM_JWT_SECRET");
        assert_eq!(backend.name(), "vault");
    }

    #[cfg(feature = "secrets-aws")]
    #[test]
    fn match_suffix_aws() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AWS").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "aws");
    }

    #[cfg(feature = "secrets-gcp")]
    #[test]
    fn match_suffix_gcp() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_GCP").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "gcp");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AZURE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "azure");
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
        let (backend, base) = match_suffix("_FILE").unwrap();
        assert_eq!(base, "");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure_checked_before_file() {
        let (backend, base) = match_suffix("FERRUM_X_AZURE").unwrap();
        assert_eq!(base, "FERRUM_X");
        assert_eq!(backend.name(), "azure");
    }

    #[test]
    fn match_suffix_case_sensitive() {
        assert!(match_suffix("FERRUM_DB_URL_file").is_none());
        assert!(match_suffix("FERRUM_DB_URL_vault").is_none());
        assert!(match_suffix("FERRUM_DB_URL_aws").is_none());
    }

    #[test]
    fn startup_backends_have_distinct_kinds() {
        let kinds: Vec<BackendKind> = startup_backends()
            .iter()
            .map(|backend| backend.kind())
            .collect();
        let unique: HashSet<BackendKind> = kinds.iter().copied().collect();
        assert_eq!(kinds.len(), unique.len());
    }
}
