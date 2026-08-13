//! Bounded stable-file reader for authoritative configuration documents.
//!
//! Shared by file-mode gateway config, `ferrum.conf`, and localized mesh policy
//! files. The contract:
//!
//! 1. Open first and validate the **opened** target as a regular file
//!    (Kubernetes/projected-secret symlinks are allowed when the target is
//!    regular). FIFOs, sockets, directories, and devices are rejected without
//!    waiting for EOF.
//! 2. Unix opens use `O_NONBLOCK` so a raced special file cannot wedge the
//!    caller.
//! 3. Metadata fast-rejects known oversized files; reads still stream through
//!    `max_bytes + 1` so growth or inaccurate metadata cannot bypass the
//!    ceiling.
//! 4. Two independent open/read cycles must observe matching file identity and
//!    **byte-identical** content. Size/metadata agreement alone is not success.
//! 5. Instability retries a bounded number of times, then fails closed.
//! 6. Only the FIRST probe's absence is an authoritative [`StableFileError::NotFound`]
//!    (the `absent_ok` signal). A path that disappears after a probe already
//!    proved it existed is transient instability, so it takes the bounded retry
//!    instead of failing closed as a terminal absence.
//! 7. Errors name the logical source and never include file contents.

use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// Hard ceiling for ordinary file-mode gateway configuration documents.
pub const MAX_GATEWAY_CONFIG_FILE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Hard ceiling for the optional `ferrum.conf` defaults file.
pub const MAX_FERRUM_CONF_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Hard ceiling for localized mesh policy / file-source documents.
pub const MAX_MESH_CONFIG_FILE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Default open/read/compare cycles before failing closed.
pub const STABLE_FILE_MAX_ATTEMPTS: usize = 5;

/// Settle delay between unstable attempts.
pub const STABLE_FILE_RETRY_DELAY: Duration = Duration::from_millis(20);

/// Caller-supplied bounds and diagnostics for a stable read.
#[derive(Debug, Clone, Copy)]
pub struct StableFileReadOptions<'a> {
    /// Maximum admitted UTF-8 document size in bytes.
    pub max_bytes: u64,
    /// Logical source name for redacted operator diagnostics (never a path).
    pub source_name: &'a str,
    /// How many open/read/compare cycles to attempt.
    pub max_attempts: usize,
    /// Delay between unstable attempts.
    pub retry_delay: Duration,
}

impl<'a> StableFileReadOptions<'a> {
    /// Construct options with the shared default retry policy.
    pub const fn new(max_bytes: u64, source_name: &'a str) -> Self {
        Self {
            max_bytes,
            source_name,
            max_attempts: STABLE_FILE_MAX_ATTEMPTS,
            retry_delay: STABLE_FILE_RETRY_DELAY,
        }
    }
}

/// Filesystem identity captured around a stable read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(metadata),
            #[cfg(unix)]
            changed_seconds: std::os::unix::fs::MetadataExt::ctime(metadata),
            #[cfg(unix)]
            changed_nanoseconds: std::os::unix::fs::MetadataExt::ctime_nsec(metadata),
        }
    }
}

/// Fail-closed outcomes for a bounded stable read.
#[derive(Debug)]
pub enum StableFileError {
    /// Path does not exist.
    NotFound,
    /// Underlying filesystem/open/read failure (not NotFound).
    Io(std::io::Error),
    /// Opened target is not a regular file.
    NotRegularFile,
    /// Document exceeds the caller ceiling (metadata and/or streamed bytes).
    TooLarge {
        /// Observed size in bytes, or a lower bound when `len_is_lower_bound`.
        len: u64,
        /// Configured ceiling.
        max_bytes: u64,
        /// `true` when the read stopped at `max_bytes + 1` and the real size is
        /// only known to be at least `len`. Streamed refusals must not report a
        /// lower bound as if it were the exact file size.
        len_is_lower_bound: bool,
    },
    /// Consecutive probes disagreed on identity or content.
    Unstable(&'static str),
    /// Bytes were not valid UTF-8.
    NotUtf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for StableFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "path not found"),
            Self::Io(error) => write!(f, "{error}"),
            Self::NotRegularFile => write!(f, "path exists but is not a regular file"),
            Self::TooLarge {
                len,
                max_bytes,
                len_is_lower_bound,
            } => {
                if *len_is_lower_bound {
                    write!(
                        f,
                        "file is at least {len} bytes; maximum supported size is {max_bytes} bytes"
                    )
                } else {
                    write!(
                        f,
                        "file is {len} bytes; maximum supported size is {max_bytes} bytes"
                    )
                }
            }
            Self::Unstable(reason) => write!(f, "{reason}"),
            Self::NotUtf8(error) => write!(f, "file is not valid UTF-8: {error}"),
        }
    }
}

impl std::error::Error for StableFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::NotUtf8(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StableFileError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::NotFound
        } else {
            Self::Io(error)
        }
    }
}

#[cfg(unix)]
fn open_path(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        // A regular-file path can be replaced with a FIFO/device after the
        // pre-open metadata check. Non-blocking open makes that race safe; the
        // opened-handle file-type/identity checks below still reject it.
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_path(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn require_regular_file(metadata: &std::fs::Metadata) -> Result<(), StableFileError> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(StableFileError::NotRegularFile)
    }
}

fn map_io(error: std::io::Error) -> StableFileError {
    StableFileError::from(error)
}

fn read_opened_file(
    path: &Path,
    file: &mut std::fs::File,
    identity: &FileIdentity,
    max_bytes: u64,
) -> Result<Vec<u8>, StableFileError> {
    if identity.len > max_bytes {
        return Err(StableFileError::TooLarge {
            len: identity.len,
            max_bytes,
            len_is_lower_bound: false,
        });
    }

    let mut bytes = Vec::new();
    {
        // Always stream through the configured ceiling (+1), not merely the
        // metadata snapshot, so growth or inaccurate metadata cannot allocate
        // past the hard maximum.
        let mut bounded = file.take(max_bytes.saturating_add(1));
        bounded.read_to_end(&mut bytes).map_err(map_io)?;
    }
    if bytes.len() as u64 > max_bytes {
        // The read deliberately stopped at `max_bytes + 1`, so this is a lower
        // bound on the real size, not a measurement of it.
        return Err(StableFileError::TooLarge {
            len: max_bytes.saturating_add(1),
            max_bytes,
            len_is_lower_bound: true,
        });
    }
    if bytes.len() as u64 != identity.len {
        return Err(StableFileError::Unstable(
            "byte length diverged from metadata while reading",
        ));
    }

    let after = file.metadata().map_err(map_io)?;
    require_regular_file(&after)?;
    let after_identity = FileIdentity::from_metadata(&after);
    if &after_identity != identity {
        return Err(StableFileError::Unstable(
            "opened file identity changed while reading",
        ));
    }

    let path_metadata = std::fs::metadata(path).map_err(map_io)?;
    require_regular_file(&path_metadata)?;
    let path_identity = FileIdentity::from_metadata(&path_metadata);
    if path_identity != *identity {
        return Err(StableFileError::Unstable(
            "configured path target changed while reading (symlink or rename swap)",
        ));
    }

    Ok(bytes)
}

/// Reclassify a failure observed **after** a probe already proved the path
/// existed.
///
/// Only the first metadata probe is authoritative for absence — that is the
/// signal `absent_ok` callers key on. Once the path has been seen, a `NotFound`
/// from a later open/metadata probe means the target was replaced or removed
/// mid-read (an atomic-publish or delete/recreate window), which is transient
/// instability and belongs to the bounded retry. Returning terminal `NotFound`
/// there would make a momentary republish look like a permanently absent file.
pub fn classify_error_after_first_probe(error: StableFileError) -> StableFileError {
    match error {
        StableFileError::NotFound => StableFileError::Unstable(
            "configured path disappeared after a probe already observed it",
        ),
        other => other,
    }
}

fn read_snapshot(path: &Path, max_bytes: u64) -> Result<(FileIdentity, Vec<u8>), StableFileError> {
    // The FIRST metadata probe is the only authoritative absence signal.
    let path_metadata_before = std::fs::metadata(path).map_err(map_io)?;
    require_regular_file(&path_metadata_before)?;
    let path_identity_before = FileIdentity::from_metadata(&path_metadata_before);

    // Everything below has already seen the path exist, so a disappearance is
    // instability rather than terminal absence.
    (|| {
        let mut file = open_path(path).map_err(map_io)?;
        let opened_metadata = file.metadata().map_err(map_io)?;
        require_regular_file(&opened_metadata)?;
        let opened_identity = FileIdentity::from_metadata(&opened_metadata);
        if opened_identity != path_identity_before {
            return Err(StableFileError::Unstable(
                "path target changed before the file handle was opened",
            ));
        }

        let bytes = read_opened_file(path, &mut file, &opened_identity, max_bytes)?;
        Ok((opened_identity, bytes))
    })()
    .map_err(classify_error_after_first_probe)
}

/// Read `path` under the shared bounded stability/atomicity contract.
///
/// Two independent open/read cycles must observe the same file identity and
/// byte-identical contents. Metadata/size agreement without content equality
/// is insufficient and is not treated as success.
pub fn read_stable_file(
    path: &Path,
    options: StableFileReadOptions<'_>,
) -> Result<String, StableFileError> {
    let display_path = path.display();
    let mut last_reason = "unknown instability";

    for attempt in 1..=options.max_attempts {
        match (|| -> Result<String, StableFileError> {
            let (first_identity, first_bytes) = read_snapshot(path, options.max_bytes)?;
            // The first probe already proved the path exists, so a second-probe
            // absence is a replacement window, not a terminal `NotFound`.
            let (second_identity, second_bytes) =
                read_snapshot(path, options.max_bytes).map_err(classify_error_after_first_probe)?;
            if second_identity != first_identity {
                return Err(StableFileError::Unstable(
                    "file identity changed between consecutive stable-read probes",
                ));
            }
            if second_bytes != first_bytes {
                return Err(StableFileError::Unstable(
                    "file content changed between consecutive stable-read probes",
                ));
            }
            String::from_utf8(first_bytes).map_err(StableFileError::NotUtf8)
        })() {
            Ok(content) => {
                if attempt > 1 {
                    info!(
                        attempt,
                        path = %display_path,
                        source = options.source_name,
                        "Configuration file stabilized after retry"
                    );
                }
                return Ok(content);
            }
            Err(StableFileError::Unstable(reason)) => {
                last_reason = reason;
                warn!(
                    attempt,
                    max_attempts = options.max_attempts,
                    path = %display_path,
                    source = options.source_name,
                    reason,
                    "Configuration file read was unstable; retrying"
                );
                if attempt < options.max_attempts {
                    std::thread::sleep(options.retry_delay);
                }
            }
            Err(other) => return Err(other),
        }
    }

    // Only reachable after exhausting Unstable retries (or max_attempts == 0).
    Err(StableFileError::Unstable(last_reason))
}

/// Format a stable-file failure as an owned string (for `ferrum.conf` and other
/// non-anyhow callers). Does not include file contents.
pub fn format_stable_file_error(
    path: &Path,
    options: StableFileReadOptions<'_>,
    error: &StableFileError,
) -> String {
    match error {
        StableFileError::Unstable(reason) => format!(
            "{} {} remained unstable after {} read attempts ({}). Publish updates \
             with an atomic replace (write a temp file, fsync, rename over the \
             path) or equivalent; reload keeps the last known-good live \
             generation when this guard fails closed.",
            options.source_name,
            path.display(),
            options.max_attempts,
            reason
        ),
        other => format!(
            "Failed to read {} {}: {other}",
            options.source_name,
            path.display()
        ),
    }
}

/// Convert a stable-file failure into an `anyhow::Error` with source-specific
/// wording. Exhausted instability retries include the atomic-replace guidance.
///
/// Delegates to [`format_stable_file_error`] so the two operator-facing
/// renderings cannot drift apart.
pub fn stable_file_error_anyhow(
    path: &Path,
    options: StableFileReadOptions<'_>,
    error: StableFileError,
) -> anyhow::Error {
    anyhow::anyhow!("{}", format_stable_file_error(path, options, &error))
}

/// Select JSON vs YAML from a file extension.
///
/// `.yaml`/`.yml` and unknown or extensionless paths select YAML; only `.json`
/// selects the JSON parser. YAML is a superset of JSON, so an unknown-extension
/// path holding an ordinary JSON document still parses — but the parser really
/// is YAML, and a JSON-only shape YAML rejects (for example a mapping key past
/// libyaml's 1024-byte simple-key limit) fails closed. There is deliberately no
/// content sniffing and no JSON fallback: detection must not parse a large
/// document once to classify it and again to deserialize it.
pub fn detect_json_or_yaml_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "yaml" | "yml" => true,
        "json" => false,
        _ => true,
    }
}
