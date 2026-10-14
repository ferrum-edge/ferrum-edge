//! Functional tests for Ferrum's external secret-provider integrations.
//!
//! These exercise the REAL secret-resolution code paths
//! (`ferrum_edge::secrets::resolve_all_env_secrets()` and the per-provider
//! fetch paths) against LOCAL mocks and emulators — never real cloud accounts:
//!
//!   - **file**  — `tempfile` on disk.
//!   - **vault** — HashiCorp Vault dev server (testcontainers/Docker).
//!   - **aws**   — LocalStack Secrets Manager (testcontainers/Docker).
//!   - **gcp**   — in-process `wiremock` REST fake (no official emulator exists).
//!   - **azure** — in-process `wiremock` Key Vault fake behind an in-process
//!     TLS terminator with a per-fake test CA (trusted via
//!     `FERRUM_TLS_CA_BUNDLE_PATH`); dummy bearer token, no real Entra ID.
//!
//! Every env-mutating test is `#[serial]` and isolates the process environment
//! with `common::env::EnvGuard`. Container-backed tests self-skip (with a
//! printed notice) when Docker is unavailable, so the suite is safe to run
//! locally without Docker and without any cloud credentials.
//!
//! Run per backend (see also the CI feature matrix):
//!   cargo test --test secrets_functional file_backend
//!   cargo test --features secrets-vault --test secrets_functional vault_backend
//!   cargo test --features secrets-aws   --test secrets_functional aws_backend
//!   cargo test --features secrets-gcp   --test secrets_functional gcp_backend
//!   cargo test --features secrets-azure --test secrets_functional azure_backend

mod common;

mod cross_backend;
mod file_backend;
mod startup_smoke;

#[cfg(feature = "secrets-aws")]
mod aws_backend;
#[cfg(feature = "secrets-azure")]
mod azure_backend;
#[cfg(feature = "secrets-gcp")]
mod gcp_backend;
#[cfg(feature = "secrets-vault")]
mod vault_backend;
