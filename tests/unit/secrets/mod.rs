#[cfg(feature = "secrets-aws")]
mod aws_tests;
#[cfg(feature = "secrets-azure")]
mod azure_tests;
mod credential_file_tests;
mod fetch_timeout_tests;
mod file_tests;
#[cfg(feature = "secrets-gcp")]
mod gcp_tests;
mod redaction_tests;
mod resolve_tests;
#[cfg(feature = "secrets-vault")]
mod vault_tests;

/// Resolve the external source of one base key the way startup does
/// (`resolve_all_env_secrets`), returning its value, or `None` when no external
/// source is configured for it. Callers hold the env lock.
async fn resolve_env_secret(key: &str) -> Result<Option<String>, String> {
    let resolved = ferrum_edge::secrets::resolve_all_env_secrets().await?;
    Ok(resolved
        .vars
        .into_iter()
        .find_map(|(base_key, value)| (base_key == key).then_some(value)))
}
