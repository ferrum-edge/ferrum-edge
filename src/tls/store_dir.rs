//! Private store-directory creation for TLS persistent stores.
//!
//! TLS material files are written at mode `0600` via [`crate::tls::private_file`],
//! but unqualified `create_dir_all` leaves store directories at the process
//! umask (typically `0755`). This module centralizes owner-only `0700` creation
//! and startup warnings for pre-existing permissive directories.

use std::path::Path;
use tracing::warn;

/// Create `path` and its parents, enforcing owner-only `0700` on Unix.
///
/// A directory that already existed and is more permissive than `0700` is left
/// unchanged and reported with `warn!` so operators can tighten permissions
/// manually.
pub(crate) fn create_private_store_dir(path: &Path) -> std::io::Result<()> {
    let existed = std::fs::symlink_metadata(path).is_ok();
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    enforce_private_store_dir_mode(path, existed)?;
    #[cfg(not(unix))]
    let _ = existed;
    Ok(())
}

#[cfg(unix)]
fn enforce_private_store_dir_mode(path: &Path, existed: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if existed {
        if mode & 0o077 != 0 {
            warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "TLS store directory is more permissive than 0700; tighten permissions manually"
            );
        }
        return Ok(());
    }
    if mode != 0o700 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
