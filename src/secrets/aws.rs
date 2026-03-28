//! AWS Secrets Manager secret resolution (requires `secrets-aws` feature).
//!
//! Authentication uses the standard AWS credential chain (`aws-config`):
//! - `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` — static IAM credentials
//! - `AWS_SESSION_TOKEN` — (optional) session token for temporary credentials
//! - `AWS_PROFILE` — named profile from `~/.aws/credentials`
//! - `AWS_REGION` or `AWS_DEFAULT_REGION` — region where the secret is stored
//! - EC2 instance profile, ECS task role, or EKS IRSA are used automatically

use std::env;

/// Check if the `{key}_AWS` env var is set and non-empty.
/// Returns the AWS secret ARN or name (optionally with `#json_key`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let aws_key = format!("{}_AWS", key);
    env::var(&aws_key).ok().filter(|s| !s.is_empty())
}

/// Reusable AWS Secrets Manager client for batch secret resolution.
/// Created once and shared across multiple AWS secret fetches.
pub struct AwsClientWrapper {
    client: aws_sdk_secretsmanager::Client,
}

impl AwsClientWrapper {
    /// Create a new AWS Secrets Manager client using the standard credential chain.
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: aws_sdk_secretsmanager::Client::new(&config),
        }
    }

    /// Fetch a secret value from AWS Secrets Manager using this client.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<String, String> {
        fetch_with_client(&self.client, reference, key).await
    }
}

/// Fetch a single secret from AWS Secrets Manager (creates a new client).
/// For batch resolution, use `AwsClientWrapper`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    let wrapper = AwsClientWrapper::new().await;
    wrapper.fetch_secret(reference, key).await
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_client(
    client: &aws_sdk_secretsmanager::Client,
    reference: &str,
    key: &str,
) -> Result<String, String> {
    let (secret_id, json_key) = match reference.split_once('#') {
        Some((id, k)) => (id, Some(k)),
        None => (reference, None),
    };

    let resp = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch {} from AWS Secrets Manager: {}", key, e))?;

    let secret_string = resp
        .secret_string()
        .ok_or_else(|| {
            format!(
                "AWS secret '{}' for {} is binary (not a string secret)",
                secret_id, key
            )
        })?
        .to_string();

    match json_key {
        Some(jk) => {
            let parsed: serde_json::Value = serde_json::from_str(&secret_string).map_err(|e| {
                format!(
                    "AWS secret '{}' for {} is not valid JSON (needed for #{}): {}",
                    secret_id, key, jk, e
                )
            })?;
            let field = parsed.get(jk).ok_or_else(|| {
                format!(
                    "AWS secret '{}' does not contain key '{}' for {}",
                    secret_id, jk, key
                )
            })?;
            // Use the string value directly if available, otherwise convert
            // non-string JSON values (numbers, booleans) to their string form.
            match field.as_str() {
                Some(s) => Ok(s.to_string()),
                None => Ok(field.to_string()),
            }
        }
        None => Ok(secret_string),
    }
}
