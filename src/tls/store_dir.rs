//! Private store-directory creation for TLS persistent stores.
//!
//! New Unix directories (including missing parents) are created with mode
//! `0700`, subject only to further restriction by the process umask. No umask
//! change or path-based chmod is used. Existing permissive directories remain
//! warning-only. Operators must secure the existing ancestor chain: callers
//! retain paths, not directory capabilities, for subsequent store operations.

use std::path::Path;

/// Create `path` and missing parents privately on Unix.
///
/// The leaf must be a real directory, never a symlink. Existing legitimate
/// directories are not chmodded. An overly restrictive umask can make creation
/// fail; the helper never widens permissions to recover. See `docs/frontend_tls.md`
/// for ancestor, ACL, and post-return path-replacement responsibilities.
pub(crate) fn create_private_store_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        unix::create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use tracing::warn;

    pub(super) fn create(path: &Path) -> io::Result<()> {
        // Strip trailing separators / `.` components so `link/` and `link/.`
        // cannot bypass the kernel's final-component O_NOFOLLOW check. An empty
        // parent from a relative event-log filename means the current directory.
        let normalized: PathBuf = path.components().collect();
        let normalized = if normalized.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &normalized
        };
        open_or_create(normalized, true).map(|_| ())
    }

    fn open_or_create(path: &Path, leaf: bool) -> io::Result<File> {
        match std::fs::symlink_metadata(path) {
            Ok(before) => {
                if leaf && !before.is_dir() {
                    return Err(unsafe_directory());
                }
                // Existing ancestors may include administrator-managed links
                // (e.g. /var on macOS). Their trust is the operator's boundary.
                let flags = libc::O_DIRECTORY | if leaf { libc::O_NOFOLLOW } else { 0 };
                let directory = OpenOptions::new()
                    .read(true)
                    .custom_flags(flags)
                    .open(path)?;
                if leaf {
                    let opened = directory.metadata()?;
                    if !same_directory(&before, &opened) {
                        return Err(unsafe_directory());
                    }
                    verify_path(path, &opened)?;
                    warn_if_permissive(path, &opened);
                }
                return Ok(directory);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let parent = path.parent().ok_or_else(unsafe_directory)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let parent = open_or_create(parent, false)?;
        let name = path.file_name().ok_or_else(unsafe_directory)?;
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "TLS store path contains a NUL")
        })?;
        // SAFETY: the parent descriptor and NUL-terminated name remain alive
        // through this call. mkdirat applies the private mode at creation.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        // A concurrent creator is allowed only if the resulting directory is
        // equally private and owned by this effective uid. In particular, an
        // EEXIST race is not the warning-only pre-existing-directory case.
        open_created_dir(&parent, &name, path)
    }

    pub(super) fn open_created_dir(parent: &File, name: &CString, path: &Path) -> io::Result<File> {
        // SAFETY: live directory descriptor and NUL-terminated name; no pointer
        // is retained. O_NOFOLLOW rejects a symlink planted after mkdirat.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat just returned a fresh descriptor owned by this call.
        let directory = unsafe { File::from_raw_fd(fd) };
        let opened = directory.metadata()?;
        // SAFETY: geteuid has no preconditions and does not modify process state.
        let effective_uid = unsafe { libc::geteuid() };
        if opened.uid() != effective_uid || opened.permissions().mode() & 0o777 != 0o700 {
            return Err(unsafe_directory());
        }
        verify_path(path, &opened)?;
        Ok(directory)
    }

    fn same_directory(left: &Metadata, right: &Metadata) -> bool {
        left.is_dir() && right.is_dir() && left.dev() == right.dev() && left.ino() == right.ino()
    }

    pub(super) fn verify_path(path: &Path, opened: &Metadata) -> io::Result<()> {
        if !same_directory(&std::fs::symlink_metadata(path)?, opened) {
            return Err(unsafe_directory());
        }
        Ok(())
    }

    fn unsafe_directory() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS store directory failed identity, ownership, or permission checks",
        )
    }

    fn warn_if_permissive(path: &Path, metadata: &Metadata) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "TLS store directory is more permissive than 0700; tighten permissions manually"
            );
        }
    }
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/tls/store_dir_race_tests.rs"]
mod race_tests;
