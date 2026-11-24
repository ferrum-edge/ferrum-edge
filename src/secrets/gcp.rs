//! GCP Secret Manager secret resolution (requires `secrets-gcp` feature).
//!
//! Authentication uses Application Default Credentials (ADC):
//! - `GOOGLE_APPLICATION_CREDENTIALS` — path to a service account JSON key file
//! - GCE metadata service (Compute Engine, GKE, Cloud Run) is used automatically
//! - `gcloud auth application-default login` for local development

use std::env;

/// Optional override for the Secret Manager service endpoint.
///
/// When `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` is set, the client is built against
/// that base URL instead of `secretmanager.googleapis.com`. This is the seam
/// used to point the real client at a local fake/emulator (or an in-cluster
/// proxy) without changing any other behavior. When unset, the standard
/// Application Default Credentials path is used unchanged.
///
/// Resolved through the conf-file-aware helper (the same one used for the
/// *runtime* `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS`) so the value is honored
/// whether it is set in the process environment or in `ferrum.conf`. Secret
/// resolution runs before `EnvConfig` is parsed, so this cannot read it from
/// `EnvConfig`.
///
/// **Only for the runtime direct-reference path.** See [`endpoint_override_from_env`].
fn endpoint_override() -> Option<String> {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_GCP_SECRET_MANAGER_ENDPOINT")
        .filter(|s| !s.is_empty())
}

/// The same override, read from the process environment **only**, for startup
/// resolution.
///
/// Identical reasoning to `registry::startup_secret_fetch_timeout`, and the
/// same trap: `conf_file::resolve_ferrum_var` initializes the process-wide
/// `CONF_FILE_CACHE` on its first miss, from whatever `FERRUM_CONF_PATH` says at
/// that moment. Startup GCP client construction happens *while*
/// `resolve_all_env_secrets` is still running, so it precedes the point where a
/// `FERRUM_CONF_PATH_FILE` is materialized into `FERRUM_CONF_PATH` — priming the
/// cache here would silently pin the default/discovered settings file for the
/// rest of the process and make `validate`/`run` ignore the externally resolved
/// settings path. Any `_GCP` secret at all is enough to trigger it, because the
/// client is built before the first fetch.
///
/// So, exactly as for the startup fetch timeout, `env > conf file` is
/// deliberately narrowed for this one variable at this one stage: set
/// `FERRUM_GCP_SECRET_MANAGER_ENDPOINT` in the environment to steer startup
/// resolution. See `docs/configuration.md`.
fn endpoint_override_from_env() -> Option<String> {
    env::var("FERRUM_GCP_SECRET_MANAGER_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Reusable GCP Secret Manager client for batch secret resolution.
/// Created once and shared across multiple GCP secret fetches.
pub struct GcpClientWrapper {
    client: google_cloud_secretmanager_v1::client::SecretManagerService,
}

impl GcpClientWrapper {
    /// Create a new GCP Secret Manager client.
    ///
    /// Without an endpoint override this uses Application Default Credentials
    /// against the production endpoint. With `FERRUM_GCP_SECRET_MANAGER_ENDPOINT`
    /// set, it targets that endpoint using anonymous credentials so the client
    /// does not attempt to discover ADC for a non-Google host.
    ///
    /// Runtime path: the override may come from `ferrum.conf`. Startup
    /// resolution must use [`Self::new_for_startup`] instead.
    pub async fn new() -> Result<Self, String> {
        Self::build(endpoint_override()).await
    }

    /// Startup variant: reads the endpoint override from the process
    /// environment only, never through the conf-file cache.
    ///
    /// See [`endpoint_override_from_env`] for why priming `CONF_FILE_CACHE`
    /// here would discard an externally resolved `FERRUM_CONF_PATH`.
    pub async fn new_for_startup() -> Result<Self, String> {
        Self::build(endpoint_override_from_env()).await
    }

    async fn build(endpoint: Option<String>) -> Result<Self, String> {
        let mut builder = google_cloud_secretmanager_v1::client::SecretManagerService::builder();
        if let Some(endpoint) = endpoint {
            builder = builder.with_endpoint(endpoint).with_credentials(
                google_cloud_auth::credentials::anonymous::Builder::new().build(),
            );
        }
        let client = builder
            .build()
            .await
            .map_err(|e| format!("Failed to build GCP Secret Manager client: {}", e))?;
        Ok(Self { client })
    }

    /// Fetch a secret value from GCP Secret Manager using this client.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<String, String> {
        fetch_with_client(&self.client, reference, key).await
    }
}

/// Fetch a single secret from GCP Secret Manager (creates a new client).
/// For batch resolution, use `GcpClientWrapper`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    let wrapper = GcpClientWrapper::new().await?;
    wrapper.fetch_secret(reference, key).await
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_client(
    client: &google_cloud_secretmanager_v1::client::SecretManagerService,
    reference: &str,
    key: &str,
) -> Result<String, String> {
    let response = client
        .access_secret_version()
        .set_name(reference)
        .send()
        .await
        // Errors name the base key and the failure class only — the resource
        // name is the source reference and is treated as sensitive. The
        // registry additionally redacts any residual occurrence echoed back by
        // the SDK error itself.
        .map_err(|e| format!("Failed to access GCP secret for {}: {}", key, e))?;

    let payload = response
        .payload
        .ok_or_else(|| format!("GCP secret for {} has no payload", key))?;

    String::from_utf8(payload.data.to_vec())
        .map_err(|e| format!("GCP secret for {} is not valid UTF-8: {}", key, e))
}
