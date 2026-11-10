//! Durable Ferrum CNI attachment ownership for CNI 1.1 GC.
//!
//! Successful CNI ADD records that claim GC ownership are persisted next to the
//! configured node-agent CNI socket so a process crash/restart can rehydrate
//! `(containerID, ifname) -> pod UID` identity **and** the exact cleanup
//! snapshot needed to tear down Ferrum-owned eBPF maps/rules before GC clears
//! ownership. The on-disk document is bounded, crash-safe (temp + fsync +
//! rename), and fail-closed on malformed, oversized, truncated, non-regular,
//! hard-linked, symlinked, or path-like input. Hostile bytes are never echoed
//! into errors or logs.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::spec::{
    MAX_CNI_ATTACHMENT_FIELD_BYTES, MAX_CNI_GC_ATTACHMENTS, is_safe_cni_container_id,
    is_safe_cni_ifname, is_safe_cni_network_name,
};
use crate::fips::approved::Sha256;
use crate::tls::private_file::replace_private_file_with_snapshot;

/// On-disk schema version. Unknown versions fail closed. This branch replaces
/// the prior identity-only document in place (no legacy shim).
pub const CNI_OWNERSHIP_STORE_VERSION: u32 = 2;

/// Filename prefix for the durable ownership store. The full name binds a
/// SHA-256 identity of the exact configured socket path so two sockets that
/// share a parent directory cannot clobber each other.
pub const CNI_OWNERSHIP_STORE_FILENAME_PREFIX: &str = "cni-owned-attachments.";

/// Filename suffix encoding the schema generation.
pub const CNI_OWNERSHIP_STORE_FILENAME_SUFFIX: &str = ".v2";

/// Hex length of the socket-path digest embedded in the store filename
/// (16 bytes → 32 hex chars). Enough to avoid collisions without exposing
/// path-controlled content.
const CNI_OWNERSHIP_STORE_ID_HEX_LEN: usize = 32;

/// Hard cap on durable store file size. Dense-node attachment counts stay under
/// [`MAX_CNI_GC_ATTACHMENTS`]; this bound rejects hostile oversized files before
/// JSON parse.
pub const MAX_CNI_OWNERSHIP_STORE_BYTES: usize = 8 * 1024 * 1024;

/// Bound on persisted cgroup inode keys per attachment (pod + descendants).
pub const MAX_CNI_OWNERSHIP_CGROUP_IDS: usize = 256;

/// Bound on persisted node-probe ports per attachment.
pub const MAX_CNI_OWNERSHIP_PROBE_PORTS: usize = 64;

/// Bound on persisted inbound redirect ports per attachment.
pub const MAX_CNI_OWNERSHIP_INBOUND_PORTS: usize = 64;

/// Cleanup projection of [`crate::ebpf::PodAttachmentState`] sufficient to
/// drive Ferrum-owned teardown after a process restart when live `pod_states`
/// is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCniCleanupSnapshot {
    pub attached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_ip: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_ip6: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_ports_cgroup_ids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload_identity_cgroup_ids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_probe_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_redirect_ports: Vec<u16>,
}

/// One Ferrum-owned CNI attachment identity plus its cleanup snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCniOwnershipRecord {
    pub network_name: String,
    pub container_id: String,
    pub ifname: String,
    pub pod_uid: String,
    #[serde(deserialize_with = "crate::util::json_object::deserialize_object")]
    pub cleanup: DurableCniCleanupSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableCniOwnershipDocument {
    version: u32,
    #[serde(deserialize_with = "crate::util::json_object::deserialize_object_vec")]
    attachments: Vec<DurableCniOwnershipRecord>,
}

/// Why durable ownership state was rejected. Messages are sanitized — they must
/// never include raw file contents or attacker-controlled identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CniOwnershipStoreError {
    Path,
    Symlink,
    NotRegular,
    Io,
    Oversized,
    TruncatedOrInvalid,
    UnsupportedVersion,
    TooManyAttachments,
    InvalidRecord,
}

impl CniOwnershipStoreError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "cni ownership store path is invalid",
            Self::Symlink => "cni ownership store refuses symlinked durable state",
            Self::NotRegular => {
                "cni ownership store refuses non-regular or hard-linked durable state"
            }
            Self::Io => "cni ownership store I/O failure",
            Self::Oversized => "cni ownership store exceeds size cap",
            Self::TruncatedOrInvalid => "cni ownership store is truncated or malformed",
            Self::UnsupportedVersion => "cni ownership store version is unsupported",
            Self::TooManyAttachments => "cni ownership store exceeds attachment cap",
            Self::InvalidRecord => "cni ownership store contains an invalid record",
        }
    }

    /// Whether a load that failed with this error may succeed on retry without
    /// operator repair. Only a failed filesystem operation is transient; every
    /// other variant classifies the durable file's location, shape, or content,
    /// which re-reading cannot change.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Io => true,
            Self::Path
            | Self::Symlink
            | Self::NotRegular
            | Self::Oversized
            | Self::TruncatedOrInvalid
            | Self::UnsupportedVersion
            | Self::TooManyAttachments
            | Self::InvalidRecord => false,
        }
    }
}

impl std::fmt::Display for CniOwnershipStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CniOwnershipStoreError {}

/// Stable store filename identity derived from the exact configured socket path.
///
/// Rejects surrounding whitespace and digests the exact socket path so hostile
/// path bytes never appear in the filename while distinct socket identities do
/// not collapse.
pub fn ownership_store_id_for_socket(socket_path: &str) -> Option<String> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() || trimmed != socket_path {
        return None;
    }
    let digest = Sha256::digest(socket_path.as_bytes());
    Some(hex::encode(&digest[..(CNI_OWNERSHIP_STORE_ID_HEX_LEN / 2)]))
}

/// Derive the durable ownership path from the configured CNI socket path.
///
/// Returns `None` when the socket path has no usable parent directory.
pub fn ownership_store_path_for_socket(socket_path: &str) -> Option<PathBuf> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() || trimmed != socket_path {
        return None;
    }
    let path = Path::new(socket_path);
    if !path.is_absolute() {
        return None;
    }
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    let id = ownership_store_id_for_socket(socket_path)?;
    Some(parent.join(format!(
        "{CNI_OWNERSHIP_STORE_FILENAME_PREFIX}{id}{CNI_OWNERSHIP_STORE_FILENAME_SUFFIX}"
    )))
}

/// Validate a Kubernetes pod UID for durable ownership identity.
///
/// Rejects empty, oversized, path-like, and non-ASCII-safe values without
/// echoing the input.
pub fn is_safe_cni_pod_uid(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES {
        return false;
    }
    if value.contains('/') || value.contains('\\') || value.contains("..") || value.contains('\0') {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_cleanup(cleanup: &DurableCniCleanupSnapshot) -> Result<(), CniOwnershipStoreError> {
    // A durable claim is created only after a successful CNI ADD has published
    // an attached PodAttachmentState. Accepting `attached = false` would make
    // rehydrated teardown skip every persisted map/rule key and then authorize
    // ownership removal, so reject the impossible production-owned shape on
    // both decode and encode.
    if !cleanup.attached {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if cleanup.include_ports_cgroup_ids.len() > MAX_CNI_OWNERSHIP_CGROUP_IDS
        || cleanup.workload_identity_cgroup_ids.len() > MAX_CNI_OWNERSHIP_CGROUP_IDS
    {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if cleanup.node_probe_ports.len() > MAX_CNI_OWNERSHIP_PROBE_PORTS
        || cleanup.inbound_redirect_ports.len() > MAX_CNI_OWNERSHIP_INBOUND_PORTS
    {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_record(record: &DurableCniOwnershipRecord) -> Result<(), CniOwnershipStoreError> {
    if !is_safe_cni_network_name(&record.network_name)
        || !is_safe_cni_container_id(&record.container_id)
        || record.container_id.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES
    {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if !is_safe_cni_ifname(&record.ifname) {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    if !is_safe_cni_pod_uid(&record.pod_uid) {
        return Err(CniOwnershipStoreError::InvalidRecord);
    }
    validate_cleanup(&record.cleanup)?;
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<(), CniOwnershipStoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CniOwnershipStoreError::Symlink),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CniOwnershipStoreError::Io),
    }
}

fn require_real_directory(path: &Path) -> Result<(), CniOwnershipStoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CniOwnershipStoreError::Symlink),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(CniOwnershipStoreError::NotRegular),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(CniOwnershipStoreError::Path),
        Err(_) => Err(CniOwnershipStoreError::Io),
    }
}

/// Open `path` without following symlinks and require a single-link regular file.
///
/// Returns `Ok(None)` when the path is absent. Closes the TOCTOU window between
/// an lstat-style check and a path-based read by validating metadata on the
/// opened descriptor (Unix: `O_NOFOLLOW` + `nlink == 1`).
fn open_durable_ownership_file(path: &Path) -> Result<Option<File>, CniOwnershipStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => {
                let meta = file.metadata().map_err(|_| CniOwnershipStoreError::Io)?;
                if !meta.file_type().is_file() || meta.nlink() != 1 {
                    return Err(CniOwnershipStoreError::NotRegular);
                }
                Ok(Some(file))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => {
                if err.raw_os_error() == Some(libc::ELOOP) {
                    return Err(CniOwnershipStoreError::Symlink);
                }
                Err(CniOwnershipStoreError::Io)
            }
        }
    }
    #[cfg(not(unix))]
    {
        refuse_symlink(path)?;
        match OpenOptions::new().read(true).open(path) {
            Ok(file) => {
                let meta = file.metadata().map_err(|_| CniOwnershipStoreError::Io)?;
                if !meta.file_type().is_file() {
                    return Err(CniOwnershipStoreError::NotRegular);
                }
                Ok(Some(file))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(CniOwnershipStoreError::Io),
        }
    }
}

fn read_bounded_file(file: &mut File) -> Result<Vec<u8>, CniOwnershipStoreError> {
    let mut buf = Vec::new();
    let mut limited = file.take((MAX_CNI_OWNERSHIP_STORE_BYTES as u64).saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .map_err(|_| CniOwnershipStoreError::Io)?;
    if buf.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    Ok(buf)
}

/// Load and validate durable ownership records from `path`.
///
/// A missing file yields an empty list. Any validation or I/O failure returns a
/// sanitized error and must not be treated as authoritative ownership.
pub fn load_durable_cni_ownership(
    path: &Path,
) -> Result<Vec<DurableCniOwnershipRecord>, CniOwnershipStoreError> {
    let Some(mut file) = open_durable_ownership_file(path)? else {
        return Ok(Vec::new());
    };
    let bytes = read_bounded_file(&mut file)?;
    parse_durable_cni_ownership_bytes(&bytes)
}

/// Parse validated ownership records from already-read bytes.
pub fn parse_durable_cni_ownership_bytes(
    bytes: &[u8],
) -> Result<Vec<DurableCniOwnershipRecord>, CniOwnershipStoreError> {
    if bytes.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    if crate::util::json_dup_keys::slice_ambiguity(bytes).is_some() {
        return Err(CniOwnershipStoreError::TruncatedOrInvalid);
    }
    let doc: DurableCniOwnershipDocument = match serde_json::from_slice(bytes) {
        Ok(doc) => doc,
        Err(_) => return Err(CniOwnershipStoreError::TruncatedOrInvalid),
    };
    if doc.version != CNI_OWNERSHIP_STORE_VERSION {
        return Err(CniOwnershipStoreError::UnsupportedVersion);
    }
    if doc.attachments.len() > MAX_CNI_GC_ATTACHMENTS {
        return Err(CniOwnershipStoreError::TooManyAttachments);
    }
    let mut seen = HashSet::with_capacity(doc.attachments.len());
    let mut cleanup_by_pod = HashMap::new();
    let mut out = Vec::with_capacity(doc.attachments.len());
    for record in doc.attachments {
        validate_record(&record)?;
        let key = (
            record.network_name.clone(),
            record.container_id.clone(),
            record.ifname.clone(),
        );
        if !seen.insert(key) {
            return Err(CniOwnershipStoreError::InvalidRecord);
        }
        if cleanup_by_pod
            .insert(record.pod_uid.clone(), record.cleanup.clone())
            .is_some_and(|cleanup| cleanup != record.cleanup)
        {
            return Err(CniOwnershipStoreError::InvalidRecord);
        }
        out.push(record);
    }
    Ok(out)
}

fn encode_durable_cni_ownership(
    records: &[DurableCniOwnershipRecord],
) -> Result<Vec<u8>, CniOwnershipStoreError> {
    if records.len() > MAX_CNI_GC_ATTACHMENTS {
        return Err(CniOwnershipStoreError::TooManyAttachments);
    }
    let mut seen = HashSet::with_capacity(records.len());
    let mut cleanup_by_pod = HashMap::new();
    for record in records {
        validate_record(record)?;
        let key = (
            record.network_name.as_str(),
            record.container_id.as_str(),
            record.ifname.as_str(),
        );
        if !seen.insert(key) {
            // Encoder must refuse duplicate attachment identity so a reused
            // `(container_id, ifname)` cannot persist a self-rejecting file.
            return Err(CniOwnershipStoreError::InvalidRecord);
        }
        if cleanup_by_pod
            .insert(record.pod_uid.as_str(), &record.cleanup)
            .is_some_and(|cleanup| cleanup != &record.cleanup)
        {
            return Err(CniOwnershipStoreError::InvalidRecord);
        }
    }
    let doc = DurableCniOwnershipDocument {
        version: CNI_OWNERSHIP_STORE_VERSION,
        attachments: records.to_vec(),
    };
    let bytes = serde_json::to_vec(&doc).map_err(|_| CniOwnershipStoreError::Io)?;
    if bytes.len() > MAX_CNI_OWNERSHIP_STORE_BYTES {
        return Err(CniOwnershipStoreError::Oversized);
    }
    Ok(bytes)
}

/// Atomically replace durable ownership state at `path`.
pub fn store_durable_cni_ownership(
    path: &Path,
    records: &[DurableCniOwnershipRecord],
) -> Result<(), CniOwnershipStoreError> {
    let parent = path.parent().ok_or(CniOwnershipStoreError::Path)?;
    if parent.as_os_str().is_empty() {
        return Err(CniOwnershipStoreError::Path);
    }
    // Refuse a symlinked or non-directory parent so writes cannot be redirected
    // off the configured Ferrum CNI runtime directory.
    match fs::symlink_metadata(parent) {
        Ok(_) => require_real_directory(parent)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|_| CniOwnershipStoreError::Io)?;
        }
        Err(_) => return Err(CniOwnershipStoreError::Io),
    }
    // Re-check after create: a raced symlink or non-directory must not become
    // authoritative.
    require_real_directory(parent)?;
    refuse_symlink(path)?;
    // Validate and snapshot an existing destination through the same bounded,
    // no-follow descriptor used for reads. Passing that snapshot into the
    // publisher prevents a second pathname read from reopening a symlink,
    // FIFO, hard-link, or oversized-file TOCTOU window before replacement.
    let mut previous_file = open_durable_ownership_file(path)?;
    let previous = match previous_file.as_mut() {
        Some(file) => Some(read_bounded_file(file)?),
        None => None,
    };
    let bytes = encode_durable_cni_ownership(records)?;
    replace_private_file_with_snapshot(path, &bytes, previous.as_deref())
        .map_err(|_| CniOwnershipStoreError::Io)
}

/// Lifecycle of the process-global durable ownership store for the live
/// node-agent CNI generation.
///
/// ```text
/// configure(None) ──▶ Disabled
/// configure(Some) ──▶ Configured ──load ok──────────────▶ Loaded
///                         │      ──load, transient I/O──▶ Unavailable ──load──▶ Loaded | Unavailable | Rejected
///                         └──────load, invalid content──▶ Rejected (never re-read)
/// ```
///
/// Only `Disabled`, `Configured`, and `Loaded` admit ownership claims, GC, and
/// CNI STATUS ([`Self::refusal`]). `Configured` exists only between
/// configuration and the startup rehydrate that immediately follows it.
/// `Unavailable` keeps the load retryable; `Rejected` means the durable file
/// itself is invalid, so only operator repair plus a node-agent restart (which
/// reconfigures the store) can clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CniOwnershipStoreState {
    /// Durable persistence is disabled (in-memory ownership only).
    Disabled,
    /// A durable path is configured but has not been loaded yet.
    Configured { path: PathBuf },
    /// The durable state at `path` was loaded and is authoritative.
    Loaded { path: PathBuf },
    /// The last load failed on a filesystem operation; a later load may succeed.
    Unavailable {
        path: PathBuf,
        error: CniOwnershipStoreError,
    },
    /// The durable state's shape or content was rejected.
    Rejected {
        path: PathBuf,
        error: CniOwnershipStoreError,
    },
}

impl CniOwnershipStoreState {
    /// Configured durable path, if any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Disabled => None,
            Self::Configured { path }
            | Self::Loaded { path }
            | Self::Unavailable { path, .. }
            | Self::Rejected { path, .. } => Some(path.as_path()),
        }
    }

    /// Sanitized reason this store refuses ownership claims, GC, and STATUS,
    /// or `None` when it admits them. Never carries the path or file content.
    pub fn refusal(&self) -> Option<&'static str> {
        match self {
            Self::Disabled | Self::Configured { .. } | Self::Loaded { .. } => None,
            Self::Unavailable { .. } => Some("unavailable"),
            Self::Rejected { .. } => Some("rejected"),
        }
    }

    /// Whether a later load may leave this state without operator repair.
    pub fn load_is_retryable(&self) -> bool {
        match self {
            Self::Unavailable { .. } => true,
            Self::Disabled
            | Self::Configured { .. }
            | Self::Loaded { .. }
            | Self::Rejected { .. } => false,
        }
    }

    /// The load transition. Reads the configured durable file and returns the
    /// next state with the load outcome: `Ok(None)` when durability is
    /// disabled, `Ok(Some(records))` on success (a missing file is empty),
    /// `Unavailable` on a transient I/O error, and `Rejected` on invalid shape
    /// or content. A `Rejected` store is never re-read.
    pub fn load(&self) -> (Self, CniOwnershipLoad) {
        let path = match self {
            Self::Disabled => return (Self::Disabled, Ok(None)),
            Self::Rejected { error, .. } => return (self.clone(), Err(error.clone())),
            Self::Configured { path } | Self::Loaded { path } | Self::Unavailable { path, .. } => {
                path.clone()
            }
        };
        match load_durable_cni_ownership(&path) {
            Ok(records) => (Self::Loaded { path }, Ok(Some(records))),
            Err(error) if error.is_transient() => (
                Self::Unavailable {
                    path,
                    error: error.clone(),
                },
                Err(error),
            ),
            Err(error) => (
                Self::Rejected {
                    path,
                    error: error.clone(),
                },
                Err(error),
            ),
        }
    }
}

/// Outcome of [`CniOwnershipStoreState::load`].
pub type CniOwnershipLoad = Result<Option<Vec<DurableCniOwnershipRecord>>, CniOwnershipStoreError>;

static CNI_OWNERSHIP_RUNTIME: Mutex<CniOwnershipStoreState> =
    Mutex::new(CniOwnershipStoreState::Disabled);

fn lock_runtime() -> std::sync::MutexGuard<'static, CniOwnershipStoreState> {
    CNI_OWNERSHIP_RUNTIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Configure the durable ownership path for this node-agent CNI generation.
///
/// Passing `None` disables durable persistence (in-memory ownership only). Used
/// by production startup and tests; discards any previous load outcome.
pub fn configure_cni_ownership_store(path: Option<PathBuf>) {
    *lock_runtime() = match path {
        Some(path) => CniOwnershipStoreState::Configured { path },
        None => CniOwnershipStoreState::Disabled,
    };
}

/// Snapshot of the durable store lifecycle for the current configuration.
pub fn cni_ownership_store_state() -> CniOwnershipStoreState {
    lock_runtime().clone()
}

/// Load durable records for the configured path and advance the process-global
/// store state through [`CniOwnershipStoreState::load`]. Either error makes
/// claims, GC, and STATUS fail closed.
pub fn load_configured_cni_ownership() -> CniOwnershipLoad {
    let mut runtime = lock_runtime();
    let (next, outcome) = runtime.load();
    *runtime = next;
    outcome
}

/// Persist `records` to the configured path. No-op success when durability is
/// disabled. Refuses with the load error while the store is unavailable or
/// rejected; a failed write leaves the store state unchanged (callers retain
/// in-memory ownership and retry).
pub fn persist_configured_cni_ownership(
    records: &[DurableCniOwnershipRecord],
) -> Result<(), CniOwnershipStoreError> {
    let runtime = lock_runtime();
    let path = match &*runtime {
        CniOwnershipStoreState::Disabled => return Ok(()),
        CniOwnershipStoreState::Configured { path } | CniOwnershipStoreState::Loaded { path } => {
            path
        }
        CniOwnershipStoreState::Unavailable { error, .. }
        | CniOwnershipStoreState::Rejected { error, .. } => return Err(error.clone()),
    };
    store_durable_cni_ownership(path, records)
}

/// Reset runtime state for tests.
pub fn reset_cni_ownership_store_for_tests() {
    configure_cni_ownership_store(None);
}
