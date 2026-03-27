mod resolve_tests;

#[cfg(feature = "secrets-aws")]
mod aws_tests;
#[cfg(feature = "secrets-azure")]
mod azure_tests;
#[cfg(feature = "secrets-gcp")]
mod gcp_tests;
#[cfg(feature = "secrets-vault")]
mod vault_tests;
