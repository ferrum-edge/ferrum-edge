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

use std::env;

/// Check if the `{key}_FILE` env var is set and non-empty.
/// Returns the file path if so.
/// Used by the registry's single-key `resolve_secret()` path and its tests.
#[allow(dead_code)]
pub fn resolve_ref(key: &str) -> Option<String> {
    let file_key = format!("{}_FILE", key);
    env::var(&file_key).ok().filter(|s| !s.is_empty())
}

/// Read a secret value from a file path. Trims trailing whitespace
/// (trailing newlines are common in Docker secrets and heredocs).
/// Returns an error if the file cannot be read or is empty after trimming.
///
/// The errors name the suffixed variable and the `io::Error` reason ("No such
/// file or directory", "Permission denied") but never the path itself: a
/// secret's source reference is treated as sensitive alongside its value, and
/// `run` logs / `validate` prints this text. `std::fs::read_to_string` does not
/// attach the path to its `io::Error`, so the reason is safe to forward
/// verbatim.
///
/// Prefer [`read_secret_detached`] on async paths so a blocked open/read cannot
/// pin Tokio runtime teardown after the configured fetch timeout.
pub fn read_secret(path: &str, key: &str) -> Result<String, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}_FILE: {}", key, e))?;

    let trimmed = content.trim_end().to_string();
    if trimmed.is_empty() {
        return Err(format!("{}_FILE source is empty after trimming", key));
    }

    Ok(trimmed)
}

/// Read a `_FILE` secret on a **detached OS thread**.
///
/// Startup batch resolution and the single-key / runtime callers
/// (`resolve_secret`, `resolve_external_reference`) both go through this helper
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
/// **Residual, deliberate and bounded:** startup treats a fetch timeout as
/// fatal, so `run`/`validate` abandon at most one thread per configured `_FILE`
/// source in the run that is about to exit non-zero. There is no per-request
/// loop that can accumulate abandoned readers.
pub async fn read_secret_detached(path: &str, key: &str) -> Result<String, String> {
    let path = path.to_string();
    let key = key.to_string();
    let key_for_error = key.clone();

    let (sender, receiver) = tokio::sync::oneshot::channel();
    let join_handle = std::thread::Builder::new()
        .name("ferrum-secret-file".to_string())
        .spawn(move || {
            // The receiver is gone when the caller timed out; the result is
            // then simply dropped.
            let _ = sender.send(read_secret(&path, &key));
        })
        .map_err(|err| {
            format!(
                "Failed to start file secret read thread for {}: {}",
                key_for_error, err
            )
        })?;

    // Dropping `JoinHandle` detaches the thread. Do not join: a blocked
    // open/read must not pin runtime teardown after the caller's timeout.
    drop(join_handle);

    receiver.await.map_err(|_| {
        format!(
            "File secret read for {} ended without producing a result",
            key_for_error
        )
    })?
}
