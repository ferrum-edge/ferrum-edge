//! File-based secret resolution (`_FILE` suffix convention).
//!
//! When `FERRUM_X_FILE=/path/to/secret` is set, the secret value is read from
//! that file. Supports Docker secrets (`/run/secrets/`), Kubernetes volume mounts,
//! and Vault Agent file injection.
//!
//! Blocking reads run on a **detached OS thread** ([`read_secret_detached`]), not
//! `tokio::task::spawn_blocking`. A FIFO with no writer or a stalled mount blocks
//! uninterruptibly; timing out a `spawn_blocking` join handle returns on schedule
//! but runtime teardown then waits for the blocking pool, so `run`/`validate`
//! hung after honoring `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS`. A detached thread is
//! owned by no runtime and is not joined at process exit.
//!
//! The open/read itself goes through [`crate::secrets::credential_file`]: regular
//! file type check on the opened descriptor, metadata fast-reject, and a
//! `limit + 1` streaming ceiling so an oversized regular file cannot allocate
//! unbounded memory before the caller's timeout.

use super::credential_file::{
    self, CredentialFileError, CredentialTrim, DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
};

fn map_file_secret_error(key: &str, error: CredentialFileError) -> String {
    match error {
        CredentialFileError::Empty => {
            format!("{}_FILE source is empty after trimming", key)
        }
        other => format!("Failed to read {}_FILE: {}", key, other),
    }
}

/// Read a `_FILE` secret on a **detached OS thread**.
///
/// Startup batch resolution and the runtime direct-reference caller
/// (`resolve_external_reference`) both go through this helper
/// via `FileBackend::resolve_one`, so every `_FILE` path shares the same
/// timeout-safe teardown behavior.
///
/// The future completes when the read finishes, or when the caller drops it
/// (for example via `tokio::time::timeout`). Dropping does not interrupt the
/// kernel-level open/read; the abandoned thread stays parked until the read
/// completes or the process exits. Because the thread is owned by no Tokio
/// runtime, dropping a temporary secret-resolution runtime after a timeout
/// returns immediately instead of waiting on a blocked blocking-pool worker.
///
/// Non-regular sources and known-oversized regular files are rejected by the
/// shared credential reader without leaving a blocked reader behind (Unix open
/// uses `O_NONBLOCK`; size checks terminate at metadata or `limit + 1`).
///
/// **Residual, deliberate and bounded:** a stalled mount can still park the
/// detached opener until the mount responds. Startup treats a fetch timeout as
/// fatal, so `run`/`validate` abandon at most one thread per configured `_FILE`
/// source in the run that is about to exit non-zero. There is no per-request
/// loop that can accumulate abandoned readers.
pub async fn read_secret_detached(path: &str, key: &str) -> Result<String, String> {
    credential_file::read_credential_file_detached(
        path,
        DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
        CredentialTrim::TrailingWhitespace,
        "ferrum-secret-file",
    )
    .await
    .map_err(|error| map_file_secret_error(key, error))
}
