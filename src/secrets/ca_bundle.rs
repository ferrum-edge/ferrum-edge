//! Hardened read of `FERRUM_TLS_CA_BUNDLE_PATH` for secret-provider transports
//! (Azure Key Vault and HashiCorp Vault).
//!
//! Startup secret resolution runs before config load on a single-threaded
//! runtime, so a plain `std::fs::read` of the bundle on that runtime lets a
//! FIFO or a stalled mount block it uninterruptibly: the per-fetch timeout can
//! never fire. Every provider that trusts the bundle therefore reads it here:
//! a detached OS thread, a non-blocking open, a regular-file check on the
//! opened descriptor, a size cap, and errors that name the variable and the
//! failure class but never the path or the bytes.

use std::sync::Arc;

/// The variable every provider transport reads its extra trust roots from.
pub(super) const CA_BUNDLE_PATH_ENV: &str = "FERRUM_TLS_CA_BUNDLE_PATH";

/// Upper bound on the CA bundle, matching the default TLS material ceiling
/// (`FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES`).
const CA_BUNDLE_MAX_BYTES: usize = crate::config::env_config::DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES;

/// Process-wide admission gate for CA bundle reader threads: at most one
/// native reader exists at a time, across every provider (they all read the
/// same path).
static CA_READ_PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

/// Test seam: hold the CA reader admission permit, as a stalled reader thread
/// would. Not part of the supported API.
#[doc(hidden)]
pub async fn hold_ca_bundle_reader_permit_for_test() -> tokio::sync::OwnedSemaphorePermit {
    CA_READ_PERMITS
        .clone()
        .acquire_owned()
        .await
        .expect("the CA reader semaphore is never closed")
}

/// Read the CA bundle on a detached OS thread.
///
/// The open is non-blocking and the opened descriptor must be a regular file,
/// so a FIFO, socket, or device fails at once instead of blocking. The read is
/// capped at [`CA_BUNDLE_MAX_BYTES`]. A stalled mount can still hold the
/// detached thread, but not a Tokio worker; the registry's fetch timeout
/// bounds the caller (the same model as `credential_file`'s detached reader).
///
/// Admission is gated by [`CA_READ_PERMITS`]. The permit is acquired before
/// the thread is spawned and moved into it, so a caller that times out and
/// drops this future does not release capacity: the permit is returned only
/// when the native read itself finishes. Repeated refreshes against a stalled
/// filesystem therefore wait for admission (and time out) instead of piling up
/// blocked threads and descriptors.
///
/// `label` names the consuming provider transport in diagnostics (for example
/// `Azure Key Vault TLS`); it is a fixed string, never configuration.
pub(super) async fn read_ca_bundle_detached(
    path: std::ffi::OsString,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    let permit = CA_READ_PERMITS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| format!("The {CA_BUNDLE_PATH_ENV} reader for {label} is closed"))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ferrum-ca-bundle-read".to_string())
        .spawn(move || {
            // Held until the native open/read returns, even if the caller is gone.
            let _permit = permit;
            let _ = tx.send(read_ca_bundle(std::path::Path::new(&path), label));
        })
        .map_err(|_| format!("Failed to start the {CA_BUNDLE_PATH_ENV} reader for {label}"))?;
    rx.await
        .map_err(|_| format!("The {CA_BUNDLE_PATH_ENV} reader for {label} exited unexpectedly"))?
}

fn read_ca_bundle(path: &std::path::Path, label: &'static str) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let io_error =
        |e: std::io::Error| format!("Failed to read {CA_BUNDLE_PATH_ENV} for {label}: {}", e.kind());
    let not_regular = || format!("{CA_BUNDLE_PATH_ENV} must name a regular file ({label})");
    let oversized =
        || format!("{CA_BUNDLE_PATH_ENV} exceeds the {CA_BUNDLE_MAX_BYTES}-byte limit ({label})");

    // Fast-reject a non-regular, non-symlink path before `open(2)`; a symlink
    // (e.g. a projected Kubernetes secret) is typed after open instead.
    let link_meta = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !link_meta.file_type().is_symlink() && !link_meta.is_file() {
        return Err(not_regular());
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(io_error)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).map_err(io_error)?;

    let meta = file.metadata().map_err(io_error)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > CA_BUNDLE_MAX_BYTES as u64 {
        return Err(oversized());
    }
    let mut bytes = Vec::new();
    file.take(CA_BUNDLE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > CA_BUNDLE_MAX_BYTES {
        return Err(oversized());
    }
    Ok(bytes)
}
