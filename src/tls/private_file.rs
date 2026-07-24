use std::io;
use std::io::Write;
use std::path::Path;

use uuid::Uuid;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static INJECTED_REPLACE_FAILURE: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Inject a one-shot failure into the next [`replace_private_file`] call.
///
/// `stage` must be `"write"` or `"rename"`. Intended for store coherence tests.
#[cfg(test)]
pub(crate) fn inject_replace_failure(stage: &'static str) {
    INJECTED_REPLACE_FAILURE.with(|cell| cell.set(Some(stage)));
}

#[cfg(test)]
fn take_injected_replace_failure() -> Option<&'static str> {
    INJECTED_REPLACE_FAILURE.with(|cell| cell.take())
}

#[cfg(unix)]
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Atomically replace `path` with `bytes` via a private temporary file.
///
/// On any write/sync/rename failure the temporary file is removed without
/// masking the primary error. After a successful rename the parent directory
/// is synced best-effort for crash durability of the directory entry.
pub(crate) fn replace_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
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

    #[cfg(test)]
    let injected = take_injected_replace_failure();

    let result = (|| {
        #[cfg(test)]
        if injected == Some("write") {
            return Err(io::Error::other("injected write failure"));
        }
        write_private_file(&tmp_path, bytes)?;
        #[cfg(test)]
        if injected == Some("rename") {
            return Err(io::Error::other("injected rename failure"));
        }
        std::fs::rename(&tmp_path, path)?;
        // Rename already committed the new bytes; parent sync is best-effort so a
        // sync failure cannot leave live memory diverged from the durable file.
        let _ = sync_dir(parent);
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}
