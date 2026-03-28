//! GCP Secret Manager secret resolution (requires `secrets-gcp` feature).
//!
//! Authentication uses Application Default Credentials (ADC):
//! - `GOOGLE_APPLICATION_CREDENTIALS` — path to a service account JSON key file
//! - GCE metadata service (Compute Engine, GKE, Cloud Run) is used automatically
//! - `gcloud auth application-default login` for local development

use std::env;

/// Check if the `{key}_GCP` env var is set and non-empty.
/// Returns the GCP resource name (e.g. `projects/P/secrets/S/versions/V`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let gcp_key = format!("{}_GCP", key);
    env::var(&gcp_key).ok().filter(|s| !s.is_empty())
}

/// Reusable GCP Secret Manager client for batch secret resolution.
/// Created once and shared across multiple GCP secret fetches.
pub struct GcpClientWrapper {
    client: google_cloud_secretmanager_v1::client::SecretManagerService,
}

impl GcpClientWrapper {
    /// Create a new GCP Secret Manager client using Application Default Credentials.
    pub async fn new() -> Result<Self, String> {
        let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
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
        .map_err(|e| {
            format!(
                "Failed to access GCP secret '{}' for {}: {}",
                reference, key, e
            )
        })?;

    let payload = response
        .payload
        .ok_or_else(|| format!("GCP secret '{}' has no payload for {}", reference, key))?;

    String::from_utf8(payload.data.to_vec()).map_err(|e| {
        format!(
            "GCP secret '{}' for {} is not valid UTF-8: {}",
            reference, key, e
        )
    })
}
