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

/// Fetch a secret value from GCP Secret Manager.
///
/// The `reference` format is `projects/<project>/secrets/<secret>/versions/<version>`.
/// Uses Application Default Credentials (ADC) for authentication.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    use google_cloud_secretmanager_v1::client::SecretManagerService;

    let client = SecretManagerService::builder().build().await.map_err(|e| {
        format!(
            "Failed to build GCP Secret Manager client for {}: {}",
            key, e
        )
    })?;

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
