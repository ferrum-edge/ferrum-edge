//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup secret resolution finishes before non-blocking logging and the
//! multi-threaded gateway runtime, and its temporary runtime is dropped before
//! env mutation happens.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
pub mod env;
pub mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[allow(unused_imports)]
pub use registry::{ResolvedEnvSecrets, ResolvedSecret, resolve_all_env_secrets, resolve_secret};
