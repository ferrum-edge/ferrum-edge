//! Private, durable file publication for TLS material stores.
//!
//! Writes use `0600` on Unix, `create_new` temps, fsync, an atomic replacement
//! of the destination, and a parent directory fsync so readers observe either
//! the prior durable file or the fully committed replacement. Temporary files
//! are removed on every failure path without masking the primary error.
//! Post-replacement durability failures roll the visible destination back; only
//! after that rollback succeeds is the parent directory fsynced so the rollback
//! itself is durable. A failed rollback keeps the primary publish error, appends
//! the restore failure as secondary context, and does not attempt a parent
//! durability sync that could commit the failed destination.
//!
//! # The replacement is atomic on every supported target
//!
//! Publication *must* replace an existing destination without ever unlinking
//! it first: a shared managed-TLS/ACME store is read concurrently by other
//! replicas and by this process's own lock-free readers, and a remove-then-move
//! sequence would expose a window in which the store appears absent — which the
//! shared-store reader is required to interpret as an empty document. So there
//! is no remove-then-rename fallback anywhere in this module.
//!
//! * **Unix** uses `rename(2)`, which POSIX defines to replace an existing
//!   destination atomically.
//! * **Windows** uses `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING |
//!   MOVEFILE_WRITE_THROUGH` (`replace_file_atomically`). This is called
//!   explicitly rather than through [`std::fs::rename`] for two reasons. The
//!   replace-existing behaviour becomes a contract of *this* module rather than
//!   an unspecified platform detail of the standard library — `fs::rename`'s
//!   overwrite semantics on Windows are documented as platform-specific and are
//!   not something a TLS-material store should depend on implicitly. And
//!   `MOVEFILE_WRITE_THROUGH` makes the move reach disk before the call
//!   returns, which is the only durability barrier available on a platform that
//!   offers no parent-directory fsync (`sync_parent_dir_inner` is a no-op off
//!   Unix).
//!
//! Windows additionally cannot replace a destination that some handle holds
//! open without `FILE_SHARE_DELETE`. Rust's [`std::fs::OpenOptions`] does
//! request that share mode (it defaults to `FILE_SHARE_READ | FILE_SHARE_WRITE
//! | FILE_SHARE_DELETE`), so a handle this crate retains through
//! `File::open` does not block a replacement — but that is a property of the
//! standard library rather than of this module, so it is pinned by a test
//! (`replacement_succeeds_while_a_reader_holds_the_previous_generation_open`)
//! instead of assumed. A handle opened by anything that does *not* request
//! share-delete still blocks the move, which is reported as an ordinary write
//! failure and fails the mutation closed. Independently of that,
//! `tls::shared_store` retains a store handle only where the platform exposes a
//! file identity that makes pinning meaningful (Unix) and drops it elsewhere,
//! so a non-Unix target holds no long-lived handle on the destination at all.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use uuid::Uuid;

#[cfg(test)]
use std::cell::Cell;

/// Injectable failure points for durable private-file publication.
///
/// Available only in unit tests. Arm a single fault through
/// [`inject_private_file_fault_for_tests`]. [`PrivateFileFault::DirSync`] is
/// one-shot: after the initial post-rename parent sync fails, the fault clears
/// so rollback can attempt a real parent-directory durability sync.
/// [`PrivateFileFault::Restore`] also fails that initial parent sync, but keeps
/// itself armed so the subsequent rollback restore fails (and no rollback
/// parent sync is attempted).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PrivateFileFault {
    #[default]
    None,
    Create,
    Write,
    Sync,
    Rename,
    DirSync,
    Restore,
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAULT: Cell<PrivateFileFault> = const { Cell::new(PrivateFileFault::None) };
}

#[cfg(test)]
fn injected_fault() -> PrivateFileFault {
    INJECTED_FAULT.with(Cell::get)
}

/// Arm a one-thread private-file fault until the returned guard drops.
#[cfg(test)]
pub(crate) fn inject_private_file_fault_for_tests(
    fault: PrivateFileFault,
) -> PrivateFileFaultGuard {
    INJECTED_FAULT.with(|cell| cell.set(fault));
    PrivateFileFaultGuard { active: true }
}

/// Clears an injected [`PrivateFileFault`] on drop.
#[cfg(test)]
#[must_use = "the fault is cleared when this guard is dropped"]
pub(crate) struct PrivateFileFaultGuard {
    active: bool,
}

#[cfg(test)]
impl PrivateFileFaultGuard {
    /// Disarm early so subsequent writes in the same test run for real.
    pub(crate) fn disarm(mut self) {
        self.clear();
        self.active = false;
    }

    fn clear(&self) {
        INJECTED_FAULT.with(|cell| cell.set(PrivateFileFault::None));
    }
}

#[cfg(test)]
impl Drop for PrivateFileFaultGuard {
    fn drop(&mut self) {
        if self.active {
            self.clear();
        }
    }
}

/// Write `bytes` to a new private file at `path` (typically a temp name).
///
/// A create failure returns without touching `path`, because an existing path
/// belongs to another writer. After Ferrum successfully creates the file,
/// write/sync failures remove only that owned file while preserving the
/// original I/O error.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if injected_fault() == PrivateFileFault::Create {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "injected fault: failed to create private temp file '{}'",
                path.display()
            ),
        ));
    }

    let mut file = create_private_file(path)?;
    let result = write_private_file_inner(path, bytes, &mut file);
    // Windows cannot unlink an open file. Close the handle before cleaning up
    // an owned partial write on every platform.
    drop(file);
    match result {
        Ok(()) => Ok(()),
        Err(error) => remove_path_preserving_primary(path, error),
    }
}

fn write_private_file_inner(_path: &Path, bytes: &[u8], file: &mut File) -> io::Result<()> {
    #[cfg(test)]
    match injected_fault() {
        PrivateFileFault::Write => {
            return Err(io::Error::other(format!(
                "injected fault: failed to write private temp file '{}'",
                _path.display()
            )));
        }
        PrivateFileFault::Sync => {
            file.write_all(bytes)?;
            return Err(io::Error::other(format!(
                "injected fault: failed to fsync private temp file '{}'",
                _path.display()
            )));
        }
        PrivateFileFault::None
        | PrivateFileFault::Create
        | PrivateFileFault::Rename
        | PrivateFileFault::DirSync
        | PrivateFileFault::Restore => {}
    }

    file.write_all(bytes)?;
    file.sync_all()
}

fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create_new(true).write(true).open(path)
    }
}

/// Atomically publish `bytes` at `final_path`.
///
/// Sequence: private temp → write → fsync → rename → parent-directory fsync.
/// Temporary files are removed on every failure. If rename succeeded but the
/// parent-directory fsync failed, the prior durable contents of `final_path`
/// are restored (or the new file is removed on create). When that rollback
/// succeeds, the parent directory is fsynced again so the rollback itself is
/// durable. When rollback fails, the primary error is preserved with the
/// restore failure as secondary context and no rollback parent sync is
/// attempted.
pub(crate) fn replace_private_file(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no parent directory",
        )
    })?;
    let file_name = final_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no file name",
        )
    })?;
    let tmp_path = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        Uuid::new_v4().simple()
    ));

    let previous = read_previous_snapshot(final_path)?;

    write_private_file(&tmp_path, bytes)?;

    if let Err(error) = rename_temp_into_place(&tmp_path, final_path) {
        return remove_path_preserving_primary(&tmp_path, error);
    }

    if let Err(error) = sync_parent_dir(parent) {
        return restore_previous_after_publish_failure(final_path, previous.as_deref(), error);
    }

    Ok(())
}

fn read_previous_snapshot(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn rename_temp_into_place(tmp_path: &Path, final_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if injected_fault() == PrivateFileFault::Rename {
        return Err(io::Error::other(format!(
            "injected fault: failed to rename private temp file '{}' to '{}'",
            tmp_path.display(),
            final_path.display()
        )));
    }
    replace_file_atomically(tmp_path, final_path)
}

/// Move `tmp_path` onto `final_path`, replacing any existing destination in one
/// step.
///
/// There is deliberately no remove-then-move path: unlinking the destination
/// first would make the store momentarily absent, and an absent store document
/// is a *successful empty* read for every reader. See the module header for the
/// per-target primitives.
fn replace_file_atomically(tmp_path: &Path, final_path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows_atomic::replace_existing(tmp_path, final_path)
    }
    #[cfg(not(windows))]
    {
        fs::rename(tmp_path, final_path)
    }
}

/// Atomic replace-existing move for Windows targets.
///
/// `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` is the documented Win32
/// primitive for replacing a destination in a single operation;
/// `MOVEFILE_WRITE_THROUGH` additionally makes it durable before returning,
/// standing in for the parent-directory fsync Windows does not provide.
///
/// Bound directly rather than through a new dependency: this is one function
/// from `kernel32`, and the store's publication path is exactly where an
/// unaudited transitive addition is least welcome.
#[cfg(windows)]
mod windows_atomic {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    /// NUL-terminated UTF-16 for a path, failing closed on an interior NUL.
    ///
    /// An interior NUL would silently truncate the path Win32 acts on, which on
    /// a publication path means writing somewhere other than the store.
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut encoded: Vec<u16> = OsStr::new(path).encode_wide().collect();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path contains an interior NUL",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }

    pub(super) fn replace_existing(tmp_path: &Path, final_path: &Path) -> io::Result<()> {
        let existing = wide(tmp_path)?;
        let replacement = wide(final_path)?;
        // SAFETY: both buffers are NUL-terminated UTF-16 owned by this frame and
        // therefore outlive the call, and the flag values are the documented
        // `MOVEFILE_*` constants. `MoveFileExW` reads the buffers and does not
        // retain them.
        let moved = unsafe {
            MoveFileExW(
                existing.as_ptr(),
                replacement.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    sync_parent_dir_inner(parent, /*allow_injected_fault=*/ true)
}

/// Parent-directory durability sync used after rollback. Never consults the
/// injected DirSync fault so a one-shot publish failure can still exercise a
/// real rollback durability attempt.
fn sync_parent_dir_after_rollback(parent: &Path) -> io::Result<()> {
    sync_parent_dir_inner(parent, /*allow_injected_fault=*/ false)
}

fn sync_parent_dir_inner(parent: &Path, allow_injected_fault: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        #[cfg(test)]
        if allow_injected_fault && take_dir_sync_fault() {
            return Err(io::Error::other(format!(
                "injected fault: failed to fsync parent directory '{}' after rename",
                parent.display()
            )));
        }
        #[cfg(not(test))]
        let _ = allow_injected_fault;
        let dir = File::open(parent)?;
        dir.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        #[cfg(test)]
        if allow_injected_fault && take_dir_sync_fault() {
            return Err(io::Error::other(
                "injected fault: failed to fsync parent directory after rename",
            ));
        }
        #[cfg(not(test))]
        let _ = allow_injected_fault;
        // Directory fsync is not available; file sync + rename is the durability
        // boundary on these platforms.
        Ok(())
    }
}

/// Consume a pending DirSync fault (one-shot) so rollback can sync for real.
///
/// [`PrivateFileFault::Restore`] also trips this path but stays armed so the
/// rollback restore can fail afterward.
#[cfg(test)]
fn take_dir_sync_fault() -> bool {
    INJECTED_FAULT.with(|cell| match cell.get() {
        PrivateFileFault::DirSync => {
            cell.set(PrivateFileFault::None);
            true
        }
        PrivateFileFault::Restore => true,
        _ => false,
    })
}

/// Consume a pending Restore fault so rollback restore fails deterministically.
#[cfg(test)]
fn take_restore_fault() -> bool {
    INJECTED_FAULT.with(|cell| {
        if cell.get() == PrivateFileFault::Restore {
            cell.set(PrivateFileFault::None);
            true
        } else {
            false
        }
    })
}

fn restore_previous_after_publish_failure(
    final_path: &Path,
    previous: Option<&[u8]>,
    primary: io::Error,
) -> io::Result<()> {
    let restore_result = match previous {
        Some(bytes) => restore_private_file_best_effort(final_path, bytes),
        None => rollback_failed_create_publish(final_path),
    };

    match restore_result {
        Ok(()) => {
            // Only fsync the parent after rollback itself succeeded. Syncing
            // after a failed restore can durably commit the failed destination.
            let mut extras = Vec::new();
            if let Some(parent) = final_path.parent()
                && let Err(sync_error) = sync_parent_dir_after_rollback(parent)
            {
                extras.push(format!(
                    "also failed to fsync parent directory after rollback: {sync_error}"
                ));
            }
            if extras.is_empty() {
                Err(primary)
            } else {
                Err(io::Error::new(
                    primary.kind(),
                    format!("{primary}; {}", extras.join("; ")),
                ))
            }
        }
        Err(restore_error) => Err(io::Error::new(
            primary.kind(),
            format!("{primary}; also failed to restore prior state: {restore_error}"),
        )),
    }
}

/// Remove a just-published create when post-rename parent sync failed.
fn rollback_failed_create_publish(final_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if take_restore_fault() {
        return Err(io::Error::other(format!(
            "injected fault: failed to remove published private file '{}' during create rollback",
            final_path.display()
        )));
    }
    match fs::remove_file(final_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Best-effort rewrite used only to undo a post-rename durability failure.
///
/// Does not consult create/write/sync/rename faults: the caller is already
/// returning the primary durability error. The test-only
/// [`PrivateFileFault::Restore`] seam can still fail this path. Parent-directory
/// durability sync is performed by [`restore_previous_after_publish_failure`]
/// only after this restore (or a create rollback removal) succeeds.
fn restore_private_file_best_effort(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if take_restore_fault() {
        return Err(io::Error::other(format!(
            "injected fault: failed to restore prior private file '{}'",
            final_path.display()
        )));
    }
    let parent = match final_path.parent() {
        Some(parent) => parent,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path has no parent directory",
            ));
        }
    };
    let file_name = match final_path.file_name() {
        Some(name) => name,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path has no file name",
            ));
        }
    };
    let tmp_path = parent.join(format!(
        ".{}.restore-{}",
        file_name.to_string_lossy(),
        Uuid::new_v4().simple()
    ));
    match restore_write_private_file(&tmp_path, bytes) {
        Ok(()) => {}
        Err(error) => return remove_path_preserving_primary(&tmp_path, error),
    }
    // Same atomic replace-existing primitive as publication: the rollback is
    // restoring a *live* destination other replicas may be reading, so it must
    // not expose an absence window either.
    match replace_file_atomically(&tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(error) => remove_path_preserving_primary(&tmp_path, error),
    }
}

fn restore_write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_path_preserving_primary(path: &Path, primary: io::Error) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Err(primary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(primary),
        Err(cleanup_error) => Err(io::Error::new(
            primary.kind(),
            format!("{primary}; also failed to remove temporary file: {cleanup_error}"),
        )),
    }
}

/// Return paths under `dir` whose names look like private-file temps.
#[cfg(test)]
pub(crate) fn private_temp_artifacts_for_tests(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains(".tmp-") || name.contains(".restore-") {
            artifacts.push(entry.path());
        }
    }
    artifacts.sort();
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn with_fault<T>(fault: PrivateFileFault, f: impl FnOnce() -> T) -> T {
        let guard = inject_private_file_fault_for_tests(fault);
        let result = f();
        guard.disarm();
        result
    }

    #[test]
    fn create_collision_never_removes_an_unowned_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("existing-temp");
        fs::write(&path, b"other-writer").expect("seed colliding file");

        let error = write_private_file(&path, b"ferrum-data")
            .expect_err("create_new must reject a colliding path");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&path).expect("colliding file preserved"),
            b"other-writer"
        );
    }

    #[test]
    fn dir_sync_failure_restores_prior_file_and_syncs_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("material.json");
        replace_private_file(&path, b"version-a").expect("seed");

        let err = with_fault(PrivateFileFault::DirSync, || {
            replace_private_file(&path, b"version-b")
        })
        .expect_err("dir sync fault must fail publish");
        assert!(
            err.to_string()
                .contains("injected fault: failed to fsync parent directory"),
            "primary dir-sync error must be preserved: {err}"
        );
        assert!(
            !err.to_string().contains("also failed to"),
            "successful rollback must not append secondary errors: {err}"
        );
        assert_eq!(fs::read(&path).expect("restored"), b"version-a");
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty()
        );
        // DirSync is one-shot: a subsequent publish must succeed with a real
        // parent sync (proving the rollback path cleared the injected fault).
        replace_private_file(&path, b"version-c").expect("publish after one-shot dir sync");
        assert_eq!(fs::read(&path).expect("updated"), b"version-c");
    }

    #[test]
    fn dir_sync_failure_removes_new_create_and_syncs_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new-material.json");
        assert!(!path.exists());

        let err = with_fault(PrivateFileFault::DirSync, || {
            replace_private_file(&path, b"brand-new")
        })
        .expect_err("dir sync fault must fail create");
        assert!(
            err.to_string()
                .contains("injected fault: failed to fsync parent directory"),
            "primary dir-sync error must be preserved: {err}"
        );
        assert!(
            !err.to_string().contains("also failed to"),
            "successful create-rollback must not append secondary errors: {err}"
        );
        assert!(
            !path.exists(),
            "failed create must remove the visible destination"
        );
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty()
        );
    }

    #[test]
    fn dir_sync_then_restore_failure_preserves_primary_without_rollback_sync() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("material.json");
        replace_private_file(&path, b"version-a").expect("seed");

        let err = with_fault(PrivateFileFault::Restore, || {
            replace_private_file(&path, b"version-b")
        })
        .expect_err("restore fault must fail publish after dir sync");
        let message = err.to_string();
        assert!(
            message.contains("injected fault: failed to fsync parent directory"),
            "primary dir-sync error must be preserved: {message}"
        );
        assert!(
            message.contains("also failed to restore prior state")
                && message.contains("injected fault: failed to restore prior private file"),
            "rollback failure must be secondary context: {message}"
        );
        assert!(
            !message.contains("also failed to fsync parent directory after rollback"),
            "failed rollback must not attempt or claim a rollback durability sync: {message}"
        );
        // Restore failed, so the renamed destination remains at the unpublished bytes.
        assert_eq!(fs::read(&path).expect("destination"), b"version-b");
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty()
        );
    }

    /// Repeated replacement of an existing destination must keep working.
    ///
    /// This is the regression that a Windows target most needs: a publication
    /// path that can only *create* leaves the first write looking healthy and
    /// fails every shared-store mutation afterwards. It is a plain
    /// cross-platform assertion on purpose, so the target-specific primitive
    /// selected by `replace_file_atomically` is exercised by whichever host CI
    /// compiles it.
    #[test]
    fn replacement_overwrites_an_existing_destination_repeatedly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.json");

        for generation in 0..5u8 {
            let payload = format!("generation-{generation}");
            replace_private_file(&path, payload.as_bytes()).expect("publish generation");
            assert_eq!(
                fs::read(&path).expect("read published generation"),
                payload.as_bytes()
            );
        }
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty(),
            "no temp artifacts may survive repeated replacement"
        );
    }

    /// The destination is never unlinked, so a reader can never observe its
    /// absence between two committed generations.
    #[test]
    fn replacement_never_exposes_an_absent_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.json");
        replace_private_file(&path, b"generation-a").expect("seed");

        let writing = Arc::new(AtomicBool::new(true));
        let observer = {
            let path = path.clone();
            let writing = Arc::clone(&writing);
            std::thread::spawn(move || {
                let mut absent = 0usize;
                let mut observations = 0usize;
                while writing.load(Ordering::Relaxed) {
                    if !path.exists() {
                        absent += 1;
                    }
                    observations += 1;
                }
                (absent, observations)
            })
        };

        for generation in 0..200u16 {
            replace_private_file(&path, format!("generation-{generation}").as_bytes())
                .expect("publish generation");
        }
        writing.store(false, Ordering::Relaxed);

        let (absent, observations) = observer.join().expect("observer thread");
        assert!(
            observations > 0,
            "the observer must have sampled the destination at least once"
        );
        assert_eq!(
            absent, 0,
            "the destination must never be observably absent during replacement"
        );
    }

    /// A retained open handle on the destination must not block replacement.
    ///
    /// Unix cares because the shared store pins the inode it last read; Windows
    /// cares far more, because a handle opened without `FILE_SHARE_DELETE`
    /// makes `MoveFileExW` fail outright. Whichever target CI runs, a store
    /// mutation must still succeed while a reader holds the previous
    /// generation open.
    #[test]
    fn replacement_succeeds_while_a_reader_holds_the_previous_generation_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.json");
        replace_private_file(&path, b"generation-a").expect("seed");

        let retained = File::open(&path).expect("hold the published generation open");

        replace_private_file(&path, b"generation-b")
            .expect("replacement must not be blocked by a retained reader handle");
        assert_eq!(fs::read(&path).expect("read replacement"), b"generation-b");

        drop(retained);
    }

    #[test]
    fn fault_injection_apis_are_crate_private_test_only() {
        // Compiling this module under `cfg(test)` is the seam: production builds
        // omit PrivateFileFault / inject / artifact helpers entirely.
        let _ = PrivateFileFault::None;
        let guard = inject_private_file_fault_for_tests(PrivateFileFault::None);
        guard.disarm();
        let _ = private_temp_artifacts_for_tests(std::path::Path::new("."));
    }
}
