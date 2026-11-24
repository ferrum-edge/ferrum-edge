//! Shared bounded reader for small file-backed credentials.
//!
//! Used by generic `_FILE` startup secrets, `FERRUM_DP_CP_GRPC_TOKEN_FILE`,
//! `FERRUM_MESH_STOCK_XDS_TOKEN_FILE`, and the Kubernetes discovery in-cluster
//! service-account token (and any future scalar credential path that must not
//! allocate or block on a non-regular source). TLS material sources keep their
//! own caps in `tls::source` (#3754); this module is the non-TLS credential
//! surface.
//!
//! Contract:
//! - Open the path (Unix: `O_NONBLOCK` so FIFO/device open cannot stall).
//! - Require a **regular file** via metadata on the opened descriptor (symlink
//!   pathnames are allowed; the opened target is what is typed).
//! - Metadata length is a fast-reject only; the streaming read still uses
//!   `Read::take(limit + 1)` so concurrent growth / inaccurate metadata cannot
//!   allocate past the ceiling.
//! - Validate UTF-8, reject empty content after the chosen trim policy.
//! - Diagnostics never include the source path or credential bytes.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Default ceiling for scalar credentials (JWTs, ordinary secrets).
pub const DEFAULT_CREDENTIAL_FILE_MAX_BYTES: usize = 64 * 1024;

/// Hard maximum any caller may request. Classes that need more must use a
/// separately reviewed reader (for example TLS material sources).
pub const HARD_MAX_CREDENTIAL_FILE_MAX_BYTES: usize = 64 * 1024;

/// How trailing / surrounding whitespace is removed after a successful read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialTrim {
    /// `str::trim_end` — Docker secrets / Kubernetes projected files often add
    /// a trailing newline; the historical `_FILE` contract also strips other
    /// trailing ASCII whitespace while preserving leading bytes.
    TrailingWhitespace,
    /// `str::trim` — external bearer tokens treat surrounding whitespace as
    /// non-content so an all-whitespace file is empty.
    Ends,
}

/// Failure classes for [`read_credential_file`]. Display text never includes a
/// path or credential value.
#[derive(Debug)]
pub enum CredentialFileError {
    /// Open or read failed. The `io::Error` reason is safe to forward: Rust's
    /// `File::open` / `Read` errors do not embed the pathname.
    ///
    /// Open-time [`std::io::ErrorKind::NotFound`] (broken projected symlink,
    /// raced unlink of an existing pathname) stays here — distinct from
    /// [`Self::PathNotFound`].
    Io(std::io::Error),
    /// Configured pathname was absent at the pre-open `symlink_metadata` step.
    /// Callers that treat absence as optional (Kubernetes `KUBE_TOKEN` fallback)
    /// must match only this variant; an existing-but-invalid source must not.
    PathNotFound,
    /// Opened descriptor is not a regular file (FIFO, socket, device, dir, …).
    NotRegularFile,
    /// Content exceeded `max_bytes` (metadata precheck or limit+1 read).
    Oversized { max_bytes: usize },
    /// Bytes were not valid UTF-8.
    InvalidUtf8,
    /// Empty after applying the trim policy.
    Empty,
    /// Caller requested a zero or above-hard-max ceiling.
    InvalidLimit { max_bytes: usize },
}

impl std::fmt::Display for CredentialFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "{source}"),
            Self::PathNotFound => f.write_str("credential path not found"),
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::Oversized { max_bytes } => {
                write!(
                    f,
                    "credential file exceeds the maximum of {max_bytes} bytes"
                )
            }
            Self::InvalidUtf8 => f.write_str("content is not valid UTF-8"),
            Self::Empty => f.write_str("credential file is empty"),
            Self::InvalidLimit { max_bytes } => {
                write!(
                    f,
                    "credential file size limit {max_bytes} is invalid (must be 1..={})",
                    HARD_MAX_CREDENTIAL_FILE_MAX_BYTES
                )
            }
        }
    }
}

impl std::error::Error for CredentialFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

/// Validate and clamp a caller-supplied ceiling. Zero is refused (not
/// "unlimited"); values above the hard max are refused rather than silently
/// raised so misconfiguration fails closed.
pub fn validate_credential_file_max_bytes(max_bytes: usize) -> Result<usize, CredentialFileError> {
    if max_bytes == 0 || max_bytes > HARD_MAX_CREDENTIAL_FILE_MAX_BYTES {
        return Err(CredentialFileError::InvalidLimit { max_bytes });
    }
    Ok(max_bytes)
}

/// Streaming seam used after any metadata precheck: read at most
/// `max_bytes + 1` and reject without retaining an unbounded buffer.
pub fn read_bounded_credential_bytes<R: Read>(
    reader: R,
    max_bytes: usize,
) -> Result<Vec<u8>, CredentialFileError> {
    let max_bytes = validate_credential_file_max_bytes(max_bytes)?;
    let limit_plus_one = (max_bytes as u64).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit_plus_one)
        .read_to_end(&mut bytes)
        .map_err(CredentialFileError::Io)?;
    if bytes.len() > max_bytes {
        return Err(CredentialFileError::Oversized { max_bytes });
    }
    Ok(bytes)
}

fn decode_and_trim(bytes: Vec<u8>, trim: CredentialTrim) -> Result<String, CredentialFileError> {
    let content = String::from_utf8(bytes).map_err(|_| CredentialFileError::InvalidUtf8)?;
    let trimmed = match trim {
        CredentialTrim::TrailingWhitespace => content.trim_end(),
        CredentialTrim::Ends => content.trim(),
    };
    if trimmed.is_empty() {
        return Err(CredentialFileError::Empty);
    }
    Ok(trimmed.to_string())
}

/// Open `path` for reading. On Unix, `O_NONBLOCK` so a FIFO/socket without a
/// peer cannot block the opener before the regular-file check runs.
fn open_credential_file(path: &Path) -> Result<File, CredentialFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(CredentialFileError::Io)
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(CredentialFileError::Io)
    }
}

/// Fast-reject known non-regular path kinds before `open(2)` so sockets, FIFOs,
/// devices, and directories fail as [`CredentialFileError::NotRegularFile`]
/// without a blocking open. Symlinked credential pathnames are left to open so
/// the opened target remains authoritative against races.
///
/// [`CredentialFileError::PathNotFound`] is reserved for genuine pathname
/// absence at this `symlink_metadata` step. A projected-secret symlink whose
/// target is missing still reaches `open` and surfaces as
/// [`CredentialFileError::Io`] with [`std::io::ErrorKind::NotFound`].
fn reject_non_regular_path_before_open(path: &Path) -> Result<(), CredentialFileError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CredentialFileError::PathNotFound);
        }
        Err(error) => return Err(CredentialFileError::Io(error)),
    };
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(CredentialFileError::NotRegularFile);
    }
    Ok(())
}

fn require_regular_file(file: &File) -> Result<std::fs::Metadata, CredentialFileError> {
    let metadata = file.metadata().map_err(CredentialFileError::Io)?;
    if !metadata.is_file() {
        return Err(CredentialFileError::NotRegularFile);
    }
    Ok(metadata)
}

/// Read a small credential file with type check, byte ceiling, UTF-8, and trim.
///
/// Symlinked pathnames (Kubernetes projected secrets) are followed by open; the
/// **opened target** must be a regular file. Diagnostics never include `path`.
pub fn read_credential_file(
    path: &str,
    max_bytes: usize,
    trim: CredentialTrim,
) -> Result<String, CredentialFileError> {
    let max_bytes = validate_credential_file_max_bytes(max_bytes)?;
    let path = Path::new(path);
    reject_non_regular_path_before_open(path)?;
    let file = open_credential_file(path)?;
    let metadata = require_regular_file(&file)?;
    // Fast-reject known-oversized regular files (including sparse files whose
    // logical size exceeds the ceiling) without reading their contents.
    if metadata.len() > max_bytes as u64 {
        return Err(CredentialFileError::Oversized { max_bytes });
    }
    let bytes = read_bounded_credential_bytes(file, max_bytes)?;
    decode_and_trim(bytes, trim)
}

/// Same as [`read_credential_file`], but the open/read runs on a **detached OS
/// thread** so a stalled mount cannot pin a Tokio worker or runtime teardown.
///
/// Dropping the returned future (for example via `tokio::time::timeout`) does
/// not interrupt the kernel open/read; the abandoned thread stays parked until
/// the operation completes or the process exits. Type and size rejections
/// complete without leaving a blocked reader: non-regular sources are refused
/// after a non-blocking open, and oversized sources terminate at metadata or
/// `limit + 1` bytes.
///
/// Prefer this for every async credential path. Do not replace it with
/// `tokio::task::spawn_blocking` for `_FILE` startup — see `secrets::file`.
pub async fn read_credential_file_detached(
    path: &str,
    max_bytes: usize,
    trim: CredentialTrim,
    thread_name: &str,
) -> Result<String, CredentialFileError> {
    read_credential_file_detached_inner(path, max_bytes, trim, thread_name, None).await
}

/// Detached credential read whose caller-supplied permit remains owned by the
/// OS thread until the kernel open/read actually returns. This lets reconnect
/// loops bound abandoned readers even after their async timeout drops the
/// receiving future.
pub(crate) async fn read_credential_file_detached_guarded(
    path: &str,
    max_bytes: usize,
    trim: CredentialTrim,
    thread_name: &str,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<String, CredentialFileError> {
    read_credential_file_detached_inner(path, max_bytes, trim, thread_name, Some(permit)).await
}

async fn read_credential_file_detached_inner(
    path: &str,
    max_bytes: usize,
    trim: CredentialTrim,
    thread_name: &str,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<String, CredentialFileError> {
    let path = path.to_string();
    let thread_name = thread_name.to_string();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let join_handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            // The permit belongs to the blocking operation, not the awaiting
            // future. If the caller times out, later attempts remain fenced
            // until this detached read really exits.
            let _permit = permit;
            let _ = sender.send(read_credential_file(&path, max_bytes, trim));
        })
        .map_err(CredentialFileError::Io)?;

    // Dropping `JoinHandle` detaches the thread. Do not join: a blocked
    // open/read must not pin runtime teardown after the caller's timeout.
    drop(join_handle);

    receiver.await.map_err(|_| {
        CredentialFileError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "credential file read ended without producing a result",
        ))
    })?
}

/// Test-only helper: write `bytes` then extend the file to `logical_len` so the
/// logical size exceeds the payload (sparse / holey file). Used by external
/// tests to prove metadata fast-reject without allocating the full length.
#[doc(hidden)]
pub(crate) fn write_sparse_credential_fixture(
    path: &Path,
    prefix: &[u8],
    logical_len: u64,
) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(prefix)?;
    file.set_len(logical_len)?;
    Ok(())
}
