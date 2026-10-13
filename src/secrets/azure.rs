//! Azure Key Vault secret resolution (requires `secrets-azure` feature).
//!
//! Authentication uses `ClientSecretCredential` via env vars:
//! - `AZURE_TENANT_ID` — Azure AD tenant ID
//! - `AZURE_CLIENT_ID` — Application (service principal) client ID
//! - `AZURE_CLIENT_SECRET` — Application client secret
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
//!
//! # TLS
//!
//! Vault URLs must use `https://`. The 1.x Azure SDK refuses to attach a
//! bearer token to a non-TLS request and has no loopback exception, so a
//! plain-`http://` reference is rejected here, at parse time, with a clear
//! error instead of failing inside the SDK pipeline. To target an emulator,
//! sidecar, or private endpoint whose certificate is not publicly trusted,
//! point `FERRUM_TLS_CA_BUNDLE_PATH` at a PEM CA bundle: those roots are
//! trusted for Key Vault data-plane calls **in addition to** the platform
//! roots (the same additive rule the Vault backend uses), so public Key Vault
//! endpoints keep working with the bundle set.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::http::{ClientOptions, Transport};
use azure_security_keyvault_secrets::models::SecretClientGetSecretOptions;
use azure_security_keyvault_secrets::{ResourceExt, SecretClientOptions};

/// Environment variable naming an extra PEM CA bundle to trust for Key Vault
/// data-plane TLS (shared with the Vault backend and the gateway's outbound
/// TLS configuration).
const CA_BUNDLE_PATH_ENV: &str = "FERRUM_TLS_CA_BUNDLE_PATH";

/// Mirrors the Azure SDK's default `reqwest` transport timeouts
/// (`typespec_client_core` 1.x) so a custom-CA transport behaves like the
/// default one. The registry's `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` envelope
/// still bounds every fetch as a whole.
const KEYVAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const KEYVAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Key Vault transport. `None` uses the SDK's default `reqwest` client;
    /// `Some` carries the extra `FERRUM_TLS_CA_BUNDLE_PATH` roots. Built once
    /// per credential set so batch resolution shares one connection pool.
    transport: Option<Transport>,
}

impl AzureCredentials {
    /// Create Azure credentials from standard env vars.
    ///
    /// Also loads `FERRUM_TLS_CA_BUNDLE_PATH` (when set) for the Key Vault
    /// transport; an unreadable or invalid bundle is an error rather than a
    /// silent fallback to platform roots only. The bundle is read on a detached
    /// thread, so callers bound construction with the secret fetch timeout.
    pub async fn new() -> Result<Self, String> {
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

        Ok(Self {
            credential,
            transport: keyvault_transport().await?,
        })
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
    ///
    /// Like [`AzureCredentials::new`], this loads `FERRUM_TLS_CA_BUNDLE_PATH`
    /// for the Key Vault transport and fails if the bundle is unusable.
    pub async fn from_static_token(token: impl Into<String>) -> Result<Self, String> {
        let credential: Arc<dyn TokenCredential> = Arc::new(StaticTokenCredential::new(token));
        Ok(Self {
            credential,
            transport: keyvault_transport().await?,
        })
    }

    /// Fetch a secret value from Azure Key Vault using these credentials.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<AzureSecret, String> {
        fetch_with_credential(&self.credential, self.transport.as_ref(), reference, key).await
    }
}

/// Fetch a single secret from Azure Key Vault (creates new credentials).
/// For batch resolution, use `AzureCredentials`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<AzureSecret, String> {
    let creds = AzureCredentials::new().await?;
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
                format!(
                    "{}/secrets/{}/{}",
                    self.vault_url, self.secret_name, version
                )
            }
            None => format!("{}/secrets/{}", self.vault_url, self.secret_name),
        }
    }
}

/// Build the Key Vault transport from `FERRUM_TLS_CA_BUNDLE_PATH`.
///
/// Unset or empty: `Ok(None)`, so the SDK builds its default `reqwest` client.
/// Set: a `reqwest` client with the SDK's default timeouts and redirect policy
/// whose trust store is the platform roots **plus** the bundle's roots. The
/// client is `https_only`, matching the vault-URL rule enforced at parse time.
/// Errors name the variable and the failure class, never the path or bytes.
async fn keyvault_transport() -> Result<Option<Transport>, String> {
    let Some(path) = env::var_os(CA_BUNDLE_PATH_ENV).filter(|path| !path.is_empty()) else {
        return Ok(None);
    };
    let pem = read_ca_bundle_detached(path).await?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
        format!("{CA_BUNDLE_PATH_ENV} is not a valid PEM CA bundle (Azure Key Vault TLS)")
    })?;
    if certs.is_empty() {
        return Err(format!(
            "{CA_BUNDLE_PATH_ENV} contains no certificates (Azure Key Vault TLS)"
        ));
    }
    let client = reqwest::Client::builder()
        .connect_timeout(KEYVAULT_CONNECT_TIMEOUT)
        .read_timeout(KEYVAULT_READ_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .tls_certs_merge(certs)
        .build()
        .map_err(|_| {
            format!("Failed to build the Azure Key Vault TLS client from {CA_BUNDLE_PATH_ENV}")
        })?;
    Ok(Some(Transport::new(Arc::new(client))))
}

/// Upper bound on the CA bundle, matching the default TLS material ceiling
/// (`FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES`).
const CA_BUNDLE_MAX_BYTES: usize = crate::config::env_config::DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES;

/// Process-wide admission gate for CA bundle reader threads: at most one
/// native reader exists at a time.
static CA_READ_PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

/// Test seam: hold the CA reader admission permit, as a stalled reader thread
/// would. Not part of the supported API.
#[doc(hidden)]
pub async fn hold_ca_bundle_reader_permit_for_test() -> tokio::sync::OwnedSemaphorePermit {
    CA_READ_PERMITS
        .clone()
        .acquire_owned()
        .await
        .expect("the CA reader semaphore is never closed")
}

/// Read the CA bundle on a detached OS thread.
///
/// The open is non-blocking and the opened descriptor must be a regular file,
/// so a FIFO, socket, or device fails at once instead of blocking. The read is
/// capped at [`CA_BUNDLE_MAX_BYTES`]. A stalled mount can still hold the
/// detached thread, but not a Tokio worker; the registry's fetch timeout
/// bounds the caller (the same model as `credential_file`'s detached reader).
///
/// Admission is gated by [`CA_READ_PERMITS`]. The permit is acquired before
/// the thread is spawned and moved into it, so a caller that times out and
/// drops this future does not release capacity: the permit is returned only
/// when the native read itself finishes. Repeated refreshes against a stalled
/// filesystem therefore wait for admission (and time out) instead of piling up
/// blocked threads and descriptors.
async fn read_ca_bundle_detached(path: std::ffi::OsString) -> Result<Vec<u8>, String> {
    let permit = CA_READ_PERMITS.clone().acquire_owned().await.map_err(|_| {
        format!("The {CA_BUNDLE_PATH_ENV} reader for Azure Key Vault TLS is closed")
    })?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ferrum-azure-ca-read".to_string())
        .spawn(move || {
            // Held until the native open/read returns, even if the caller is gone.
            let _permit = permit;
            let _ = tx.send(read_ca_bundle(std::path::Path::new(&path)));
        })
        .map_err(|_| {
            format!("Failed to start the {CA_BUNDLE_PATH_ENV} reader for Azure Key Vault TLS")
        })?;
    rx.await.map_err(|_| {
        format!("The {CA_BUNDLE_PATH_ENV} reader for Azure Key Vault TLS exited unexpectedly")
    })?
}

fn read_ca_bundle(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let io_error = |e: std::io::Error| {
        format!(
            "Failed to read {CA_BUNDLE_PATH_ENV} for Azure Key Vault TLS: {}",
            e.kind()
        )
    };
    let not_regular =
        || format!("{CA_BUNDLE_PATH_ENV} must name a regular file (Azure Key Vault TLS)");
    let oversized = || {
        format!(
            "{CA_BUNDLE_PATH_ENV} exceeds the {CA_BUNDLE_MAX_BYTES}-byte limit (Azure Key Vault TLS)"
        )
    };

    // Fast-reject a non-regular, non-symlink path before `open(2)`; a symlink
    // (e.g. a projected Kubernetes secret) is typed after open instead.
    let link_meta = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !link_meta.file_type().is_symlink() && !link_meta.is_file() {
        return Err(not_regular());
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(io_error)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).map_err(io_error)?;

    let meta = file.metadata().map_err(io_error)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > CA_BUNDLE_MAX_BYTES as u64 {
        return Err(oversized());
    }
    let mut bytes = Vec::new();
    file.take(CA_BUNDLE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > CA_BUNDLE_MAX_BYTES {
        return Err(oversized());
    }
    Ok(bytes)
}

/// Parse a Key Vault secret reference URL into vault URL, secret name, and
/// optional version.
///
/// The reference must use `https://`: the Azure SDK only sends the Entra
/// bearer token over TLS, so a plain-`http://` vault URL is refused here with
/// an explicit error (fail closed, before any client is built).
///
/// The returned `vault_url` preserves the scheme, host **and port** of the
/// reference. Dropping the port silently rewrote a URL like
/// `https://127.0.0.1:12345/secrets/admin-jwt` to `https://127.0.0.1`, which
/// breaks any vault served on a non-default port — including local emulators
/// and sidecar/proxy front ends.
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

    if url.scheme() != "https" {
        // Name the scheme class only; the URL itself is the source reference.
        return Err(format!(
            "Invalid Azure Key Vault URL for {}: the vault URL must use https:// \
             (plain http and other schemes are refused; the Azure SDK sends the \
             bearer token only over TLS)",
            key
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| format!("Azure Key Vault URL for {} has no host", key))?;

    // Preserve an explicit port when present so non-standard ports survive.
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let vault_url = format!("https://{authority}");

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
    transport: Option<&Transport>,
    reference: &str,
    key: &str,
) -> Result<AzureSecret, String> {
    let parsed = parse_keyvault_reference_parts(reference, key)?;

    let options = SecretClientOptions {
        client_options: ClientOptions {
            transport: transport.cloned(),
            ..Default::default()
        },
        ..Default::default()
    };
    let client = azure_security_keyvault_secrets::SecretClient::new(
        &parsed.vault_url,
        credential.clone(),
        Some(options),
    )
    .map_err(|e| format!("Failed to create Azure Key Vault client for {}: {}", key, e))?;

    // Errors name the base key and the failure class only — the vault URL and
    // secret name are the source reference and are treated as sensitive. The
    // registry additionally redacts any residual occurrence echoed back by the
    // SDK error itself.
    let options = parsed
        .version
        .as_ref()
        .map(|version| SecretClientGetSecretOptions {
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

    let fetched_version = secret
        .resource_id()
        .ok()
        .and_then(|id| id.version)
        .or_else(|| parsed.version.clone());

    let value = secret
        .value
        .ok_or_else(|| format!("Azure secret for {} has no value", key))?;

    if let (Some(requested), Some(returned)) =
        (parsed.version.as_deref(), fetched_version.as_deref())
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
