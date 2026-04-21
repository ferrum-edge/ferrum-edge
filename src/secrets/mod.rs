//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup resolution stays single-threaded so environment mutation remains
//! safe before the multi-threaded runtime is created.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
mod env;
mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[allow(unused_imports)]
pub use registry::{ResolvedEnvSecrets, ResolvedSecret, resolve_all_env_secrets, resolve_secret};
