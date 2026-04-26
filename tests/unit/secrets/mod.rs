#[cfg(feature = "secrets-aws")]
mod aws_tests;
#[cfg(feature = "secrets-azure")]
mod azure_tests;
mod env_tests;
mod file_tests;
#[cfg(feature = "secrets-gcp")]
mod gcp_tests;
mod resolve_tests;
#[cfg(feature = "secrets-vault")]
mod vault_tests;
