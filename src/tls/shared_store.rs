//! Cross-instance coherent persistence for file-backed TLS material stores.
//!
//! Managed TLS records, ACME certificates/orders/accounts, and renewal leases
//! are all small JSON documents that several gateway replicas may share through
//! one writable volume. Each document is wrapped in a [`SharedStoreFile`],
//! which provides the three properties a process-local `OnceLock` cache plus a
//! whole-map rewrite cannot (issue #2409):
//!
//! * **Authoritative reads.** [`SharedStoreFile::snapshot`] revalidates the
//!   cached document against the file's identity stamp on every call, so a
//!   record another replica committed becomes visible without a restart and
//!   without a bespoke watcher. The existing `managed://` / `acme://` material
//!   poll loops (`tls::source::subscription`) therefore observe cross-instance
//!   rotations through their ordinary refresh path.
//! * **Conflict-safe writes.** [`SharedStoreFile::mutate`] takes an exclusive
//!   advisory file lock, re-reads the document *under that lock*, applies the
//!   caller's mutation to that fresh state, and only then republishes. The
//!   read-modify-write is serialized across processes, so a concurrent writer's
//!   committed record can never be erased by a stale in-memory map, and
//!   existence decisions (create-without-overwrite, kind conflicts, lease
//!   ownership) are evaluated against authoritative state.
//! * **Fail-closed ambiguity.** A lock that cannot be taken within
//!   `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`, an unreadable or unparseable
//!   file, or a poisoned in-process guard is an error — never a silent
//!   local-only write.
//!
//! # Readers never wait on a writer
//!
//! Reads are deliberately **lock-free with respect to writer contention**.
//! ACME HTTP-01 and TLS-ALPN-01 challenge lookups happen on the request path
//! and admin reads run on Tokio workers, so making a reader poll a contended
//! advisory lock for up to `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS` would let a
//! slow writer stall runtime threads — a denial-of-service amplification.
//!
//! That is safe because publication is `create_new` temp file + fsync +
//! `rename` (`tls::private_file`): the destination path always names a
//! *complete* document, never a partially written one. A reader therefore
//! opens either the previous or the replacement inode, and reads the whole of
//! whichever it got. A reader that loses the race with a rename returns the
//! previous complete generation **once**; because its cached stamp is taken
//! from the open handle it read (not from a later `stat` of the path), the very
//! next observation compares the pinned old identity against the new one and
//! re-reads. Corruption is never papered over: a document that does not parse
//! is an error, not an empty map.
//!
//! Writers still take the exclusive advisory lock, because a read-modify-write
//! must be serialized across processes.
//!
//! Nothing here logs document contents. Managed records and ACME accounts hold
//! private key material, so errors carry only the operator-configured store
//! path (local configuration, not a secret-provider reference) and an
//! I/O/parse failure class.

use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Retry cadence while waiting for a contended advisory lock.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Fixed diagnostic for a poisoned in-process guard. Never includes contents.
const POISONED_GUARD: &str = "in-process store guard is poisoned";

/// Fixed diagnostic when a candidate document exceeds the byte ceiling.
const OVERSIZED_DOCUMENT: &str = "shared TLS store document exceeds the configured byte ceiling";

/// Fixed set of persistent TLS documents that share the byte-bounded I/O path.
///
/// Labels are operator-facing metric dimensions only — never record IDs, domains,
/// paths, or account identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TlsPersistentStoreKind {
    Managed = 0,
    AcmeCertificates = 1,
    AcmeOrders = 2,
    AcmeAccounts = 3,
    Leases = 4,
    Events = 5,
}

impl TlsPersistentStoreKind {
    pub const ALL: [Self; 6] = [
        Self::Managed,
        Self::AcmeCertificates,
        Self::AcmeOrders,
        Self::AcmeAccounts,
        Self::Leases,
        Self::Events,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::AcmeCertificates => "acme_certificates",
            Self::AcmeOrders => "acme_orders",
            Self::AcmeAccounts => "acme_accounts",
            Self::Leases => "leases",
            Self::Events => "events",
        }
    }

    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Direction of an oversized-document observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TlsStoreIoDirection {
    Read = 0,
    Write = 1,
}

impl TlsStoreIoDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Logical admission refusal reason (fixed cardinality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TlsStoreAdmissionReason {
    RecordLimit = 0,
    DocumentBytes = 1,
}

impl TlsStoreAdmissionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordLimit => "record_limit",
            Self::DocumentBytes => "document_bytes",
        }
    }
}

#[derive(Debug, Error)]
pub enum SharedStoreError {
    #[error("failed to read shared TLS store '{path}': {details}")]
    Read { path: String, details: String },
    #[error("failed to write shared TLS store '{path}': {details}")]
    Write { path: String, details: String },
    #[error("failed to parse shared TLS store '{path}': {details}")]
    Parse { path: String, details: String },
    #[error(
        "timed out after {seconds}s waiting for exclusive access to shared TLS store '{path}'; another instance may be holding it"
    )]
    LockTimeout { path: String, seconds: u64 },
    /// A setting the shared store depends on is present but unusable. Carries
    /// the rule that was broken, never the configured value.
    #[error("invalid shared TLS store configuration: {details}")]
    InvalidConfig { details: String },
    /// On-disk or candidate document exceeds `FERRUM_TLS_STORE_MAX_DOCUMENT_BYTES`.
    ///
    /// Deliberately content-free apart from the operator-configured path and the
    /// numeric ceiling: never echoes document bytes or parsed fields.
    #[error("{OVERSIZED_DOCUMENT} ('{path}', max {max_bytes} bytes)")]
    Oversized {
        path: String,
        max_bytes: usize,
        direction: TlsStoreIoDirection,
    },
}

impl SharedStoreError {
    fn read(path: &Path, details: impl fmt::Display) -> Self {
        Self::Read {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }

    fn write(path: &Path, details: impl fmt::Display) -> Self {
        Self::Write {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }

    fn parse(path: &Path, details: impl fmt::Display) -> Self {
        Self::Parse {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }

    fn oversized(path: &Path, max_bytes: usize, direction: TlsStoreIoDirection) -> Self {
        Self::Oversized {
            path: path.display().to_string(),
            max_bytes,
            direction,
        }
    }
}

/// A JSON document that carries a monotonic store version.
///
/// The version is bumped by every committed write. Correctness does not depend
/// on it — the exclusive-lock read-modify-write is what prevents lost updates —
/// but it gives operators and tests a cheap, non-secret way to observe that a
/// write landed and to tell two generations of a document apart.
pub trait VersionedStoreFile:
    Default + Clone + Serialize + DeserializeOwned + Send + Sync + 'static
{
    fn store_version(&self) -> u64;
    fn set_store_version(&mut self, version: u64);
    /// Logical record cardinality published on successful authoritative reads
    /// and successful durable publishes. Must not advance on a rejected
    /// candidate.
    fn logical_record_count(&self) -> u64;
}

/// Whether the filesystem exposes an exact *replacement identity* for the store
/// document, i.e. a value that is guaranteed to differ between two generations
/// of the file.
///
/// Change detection must be deterministic: a missed replacement means an
/// instance serves another replica's superseded TLS material indefinitely. So
/// there is no probabilistic middle ground here — either the platform gives an
/// exact identity and the cheap `stat` fast path is used, or every read
/// re-reads the (small) document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIdentityMode {
    /// Use the platform's file identity: Unix `st_dev` + `st_ino`, pinned by an
    /// open handle so the inode number cannot be recycled underneath the cache.
    Native,
    /// No usable replacement identity. Every read re-reads the document.
    Unavailable,
}

impl StoreIdentityMode {
    /// Identity support on the target this build runs on.
    pub const fn platform_default() -> Self {
        if cfg!(unix) {
            Self::Native
        } else {
            Self::Unavailable
        }
    }
}

/// Exact identity of one generation of the on-disk document.
///
/// Only meaningful while the corresponding open handle is retained: publication
/// is temp-file + `rename`, and an inode number is reusable once the old inode
/// is both unlinked and closed. [`Cached::pinned`] keeps the handle open, so the
/// inode we last read cannot be handed to a later temp file and an equal
/// `(device, inode)` therefore proves the path still names the bytes we hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata, mode: StoreIdentityMode) -> Option<Self> {
        if mode == StoreIdentityMode::Unavailable {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }
}

/// State of the on-disk document at the moment it was last loaded.
///
/// `identity` is the load-bearing field. `len` and `modified` are a secondary
/// check against an in-place rewrite by something other than Ferrum; they are
/// never sufficient on their own, because two atomic replacements can share a
/// length and a coarse-granularity `mtime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    identity: Option<FileIdentity>,
}

impl FileStamp {
    fn from_metadata(metadata: &std::fs::Metadata, mode: StoreIdentityMode) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            identity: FileIdentity::from_metadata(metadata, mode),
        }
    }
}

struct Cached<T> {
    value: Arc<T>,
    /// `None` means the document did not exist at the last load.
    stamp: Option<FileStamp>,
    /// Open handle to exactly the inode `stamp` describes, retained so the
    /// identity stays unique. Never read from again.
    ///
    /// Retained **only** when the stamp actually carries an identity, i.e. on a
    /// platform with [`StoreIdentityMode::Native`]. Without an identity the
    /// handle secures nothing — every read re-reads regardless — so holding one
    /// would be a file descriptor kept open for the process lifetime for no
    /// benefit, on exactly the targets (Windows) where an open handle on a
    /// destination is most likely to interfere with replacing it.
    _pinned: Option<File>,
}

/// Releases an advisory file lock on drop.
struct FileLockGuard {
    file: File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // Best effort: the lock is also released when the handle closes.
        let _ = self.file.unlock();
    }
}

/// One shared JSON document with cross-process coherent reads and writes.
pub struct SharedStoreFile<T: VersionedStoreFile> {
    path: PathBuf,
    lock_path: PathBuf,
    lock_timeout: Duration,
    identity_mode: StoreIdentityMode,
    store_kind: TlsPersistentStoreKind,
    max_document_bytes: usize,
    cached: RwLock<Cached<T>>,
    /// Serializes writers inside this process before they contend for the
    /// cross-process advisory lock.
    write_gate: Mutex<()>,
}

impl<T: VersionedStoreFile> fmt::Debug for SharedStoreFile<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedStoreFile")
            .field("path", &self.path)
            .field("store_kind", &self.store_kind.as_str())
            .field("max_document_bytes", &self.max_document_bytes)
            .finish_non_exhaustive()
    }
}

impl<T: VersionedStoreFile> SharedStoreFile<T> {
    /// Open (or adopt) the shared document at `path`.
    ///
    /// A missing document is an empty store; an unreadable, unparseable, or
    /// oversized one is an error, so a corrupt shared volume is never silently
    /// replaced by an empty local map.
    pub fn open(
        path: PathBuf,
        store_kind: TlsPersistentStoreKind,
    ) -> Result<Self, SharedStoreError> {
        Self::open_with_identity_mode(path, StoreIdentityMode::platform_default(), store_kind)
    }

    /// [`Self::open`] with an explicit replacement-identity mode.
    ///
    /// [`StoreIdentityMode::Unavailable`] is the always-correct fallback used on
    /// platforms without file identity; it is exposed so the no-identity path
    /// can be exercised (and regression-tested) on any target.
    pub fn open_with_identity_mode(
        path: PathBuf,
        identity_mode: StoreIdentityMode,
        store_kind: TlsPersistentStoreKind,
    ) -> Result<Self, SharedStoreError> {
        let max_document_bytes = crate::config::env_config::tls_store_max_document_bytes_from_env()
            .map_err(|details| SharedStoreError::InvalidConfig { details })?;
        Self::open_with_limits(path, identity_mode, store_kind, max_document_bytes)
    }

    /// Open with an explicit document byte ceiling (tests and injectors).
    ///
    /// Rejects `0` and caps values above the hard maximum before any store I/O
    /// so a hostile ceiling cannot make the bounded reader practically
    /// unbounded.
    pub fn open_with_limits(
        path: PathBuf,
        identity_mode: StoreIdentityMode,
        store_kind: TlsPersistentStoreKind,
        max_document_bytes: usize,
    ) -> Result<Self, SharedStoreError> {
        let max_document_bytes = validate_explicit_store_max_document_bytes(max_document_bytes)?;
        let lock_path = lock_path_for(&path)?;
        // Fail closed on a malformed bound rather than opening the store on a
        // default the operator never asked for: this setting is the only thing
        // standing between a wedged shared volume and an unbounded wait, so a
        // silent substitution would make it unauditable.
        let lock_timeout = crate::config::env_config::tls_store_lock_timeout_from_env()
            .map_err(|details| SharedStoreError::InvalidConfig { details })?;
        let store = Self {
            path,
            lock_path,
            lock_timeout,
            identity_mode,
            store_kind,
            max_document_bytes,
            cached: RwLock::new(Cached {
                value: Arc::new(T::default()),
                stamp: None,
                _pinned: None,
            }),
            write_gate: Mutex::new(()),
        };
        store.read_authoritative()?;
        Ok(store)
    }

    /// Configured whole-document byte ceiling for this store handle.
    #[allow(dead_code)] // External unit tests call this through the library target.
    pub fn max_document_bytes(&self) -> usize {
        self.max_document_bytes
    }

    /// Fixed store kind used for observability.
    #[allow(dead_code)] // External unit tests call this through the library target.
    pub fn store_kind(&self) -> TlsPersistentStoreKind {
        self.store_kind
    }

    /// Committed version of the current authoritative document.
    ///
    /// Diagnostic surface only; the store's correctness comes from the
    /// exclusive-lock read-modify-write, not from this counter.
    #[allow(dead_code)]
    pub fn version(&self) -> Result<u64, SharedStoreError> {
        Ok(self.snapshot()?.store_version())
    }

    /// The authoritative document, re-read whenever the file changed.
    ///
    /// Never waits on the advisory lock: see the module header. A reader that
    /// races a writer's `rename` observes one complete generation or the other,
    /// and the stamp it caches guarantees the next call notices the newer one.
    pub fn snapshot(&self) -> Result<Arc<T>, SharedStoreError> {
        if let Some(value) = self.cached_if_fresh()? {
            return Ok(value);
        }
        self.read_authoritative()
    }

    /// Serialized read-modify-write against authoritative shared state.
    ///
    /// `apply` runs under the exclusive cross-process lock and sees the current
    /// committed document, so its decisions are made against what every other
    /// instance has actually written. The result is published only after the
    /// durable replacement succeeds; a failed publish leaves both readers and
    /// the on-disk document on the prior committed state.
    pub fn mutate<R, E>(&self, apply: impl FnOnce(&mut T) -> Result<R, E>) -> Result<R, E>
    where
        E: From<SharedStoreError>,
    {
        self.mutate_if(|document| apply(document).map(|outcome| (true, outcome)))
    }

    /// [`Self::mutate`] for callers whose decision may be "no change".
    ///
    /// `apply` returns `(committed, outcome)`; a `false` flag republishes
    /// nothing, which keeps read-only outcomes (a denied lease acquisition, a
    /// renewal for a claim already taken over) from rewriting the shared
    /// document on every attempt. The exclusive lock still covers the whole
    /// decision, so it is made against authoritative state either way.
    pub fn mutate_if<R, E>(
        &self,
        apply: impl FnOnce(&mut T) -> Result<(bool, R), E>,
    ) -> Result<R, E>
    where
        E: From<SharedStoreError>,
    {
        let _local = self.write_gate.lock().map_err(|_| self.poisoned())?;
        let _lock = self.lock_exclusive()?;
        let current = self.read_authoritative()?;
        let mut candidate = (*current).clone();
        let (committed, outcome) = apply(&mut candidate)?;
        if !committed {
            return Ok(outcome);
        }
        let next = current.store_version().saturating_add(1);
        candidate.set_store_version(next);
        self.persist_locked(&candidate)?;
        Ok(outcome)
    }

    fn poisoned(&self) -> SharedStoreError {
        SharedStoreError::write(&self.path, POISONED_GUARD)
    }

    /// Cached document when the on-disk identity provably still matches it.
    ///
    /// Deterministic in both directions. Absence is exact (`NotFound` against a
    /// cache that recorded absence). Presence is trusted only when an exact
    /// replacement identity is available *and* equal; without one — a non-Unix
    /// target, or [`StoreIdentityMode::Unavailable`] — the answer is always
    /// "re-read", because equal length and equal (possibly coarse) `mtime` do
    /// not imply equal contents and a missed write would be permanent.
    fn cached_if_fresh(&self) -> Result<Option<Arc<T>>, SharedStoreError> {
        let cached = self.cached.read().map_err(|_| self.poisoned())?;
        let current = match std::fs::metadata(&self.path) {
            Ok(metadata) => {
                // Metadata is a fast reject only. Growth/TOCTOU still terminate
                // through the bounded reader on the authoritative path.
                if metadata.len() > self.max_document_bytes as u64 {
                    record_store_oversized(self.store_kind, TlsStoreIoDirection::Read);
                    return Err(SharedStoreError::oversized(
                        &self.path,
                        self.max_document_bytes,
                        TlsStoreIoDirection::Read,
                    ));
                }
                Some(FileStamp::from_metadata(&metadata, self.identity_mode))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(SharedStoreError::read(&self.path, error)),
        };
        let unchanged = match (cached.stamp, current) {
            (None, None) => true,
            (Some(previous), Some(current)) => previous.identity.is_some() && previous == current,
            _ => false,
        };
        if unchanged {
            Ok(Some(cached.value.clone()))
        } else {
            Ok(None)
        }
    }

    /// Read the authoritative document from disk and republish the cache.
    ///
    /// Takes no advisory lock. Writers call it while already holding the
    /// exclusive lock; readers call it unlocked, which is safe because the
    /// destination path only ever names a complete, atomically renamed
    /// document.
    fn read_authoritative(&self) -> Result<Arc<T>, SharedStoreError> {
        let mut file = match open_authoritative_document_file(&self.path)? {
            Some(file) => file,
            None => {
                let value = Arc::new(T::default());
                self.publish_cached(value.clone(), None, None)?;
                record_store_document_bytes(self.store_kind, 0);
                record_store_record_count(self.store_kind, value.logical_record_count());
                return Ok(value);
            }
        };
        // Stamp from the open handle so it describes exactly the bytes read,
        // not whatever the path may point at by the time the read finishes.
        let stamp = file.metadata().ok();
        if let Some(metadata) = stamp.as_ref()
            && metadata.len() > self.max_document_bytes as u64
        {
            record_store_oversized(self.store_kind, TlsStoreIoDirection::Read);
            return Err(SharedStoreError::oversized(
                &self.path,
                self.max_document_bytes,
                TlsStoreIoDirection::Read,
            ));
        }
        let stamp = stamp
            .as_ref()
            .map(|metadata| FileStamp::from_metadata(metadata, self.identity_mode));
        let bytes =
            match read_bounded_document_bytes(&mut file, &self.path, self.max_document_bytes) {
                Ok(bytes) => bytes,
                Err(error @ SharedStoreError::Oversized { .. }) => {
                    record_store_oversized(self.store_kind, TlsStoreIoDirection::Read);
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
        // A document that does not parse is an error. A partially written one
        // cannot be observed (rename is atomic), so this is real corruption and
        // must never degrade to an empty local map.
        let parsed = serde_json::from_slice::<T>(&bytes)
            .map_err(|error| SharedStoreError::parse(&self.path, error))?;
        let value = Arc::new(parsed);
        record_store_document_bytes(self.store_kind, bytes.len() as u64);
        record_store_record_count(self.store_kind, value.logical_record_count());
        self.publish_cached(value.clone(), stamp, Some(file))?;
        Ok(value)
    }

    fn persist_locked(&self, value: &T) -> Result<(), SharedStoreError> {
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        if payload.len() > self.max_document_bytes {
            record_store_oversized(self.store_kind, TlsStoreIoDirection::Write);
            record_store_admission_rejected(
                self.store_kind,
                TlsStoreAdmissionReason::DocumentBytes,
            );
            // Fail before rename so the previous authoritative document and the
            // in-process cache remain intact. Rejected candidates must not move
            // the record-count gauge ahead of durable state.
            return Err(SharedStoreError::oversized(
                &self.path,
                self.max_document_bytes,
                TlsStoreIoDirection::Write,
            ));
        }
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        // Pin the freshly published inode the same way a read does. If it
        // cannot be reopened the cache simply records no stamp, which makes
        // every later read re-read — degraded, never stale.
        let pinned = open_authoritative_document_file(&self.path)
            .ok()
            .and_then(|opened| opened);
        let stamp = pinned
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map(|metadata| FileStamp::from_metadata(&metadata, self.identity_mode));
        record_store_document_bytes(self.store_kind, payload.len() as u64);
        record_store_record_count(self.store_kind, value.logical_record_count());
        self.publish_cached(Arc::new(value.clone()), stamp, pinned)
    }

    /// Republish the cache, retaining the open handle only where it is
    /// load-bearing.
    ///
    /// A handle is worth keeping for exactly one reason: it stops the inode
    /// number in `stamp` from being recycled, which is what makes an equal
    /// identity a proof. When the stamp has no identity there is nothing to
    /// protect, so the handle is dropped here rather than held for the
    /// process's lifetime.
    fn publish_cached(
        &self,
        value: Arc<T>,
        stamp: Option<FileStamp>,
        pinned: Option<File>,
    ) -> Result<(), SharedStoreError> {
        let identity_is_load_bearing = stamp.is_some_and(|stamp| stamp.identity.is_some());
        let pinned = if identity_is_load_bearing {
            pinned
        } else {
            None
        };
        let mut cached = self.cached.write().map_err(|_| self.poisoned())?;
        *cached = Cached {
            value,
            stamp,
            _pinned: pinned,
        };
        Ok(())
    }

    /// Take the cross-process advisory lock for a read-modify-write.
    ///
    /// Only writers call this. The bounded poll loop sleeps a thread, which is
    /// why no read path may reach it.
    fn lock_exclusive(&self) -> Result<FileLockGuard, SharedStoreError> {
        let file = self.open_lock_file()?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(FileLockGuard { file }),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(self.lock_timed_out());
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Error(error)) => {
                    return Err(SharedStoreError::write(&self.lock_path, error));
                }
            }
        }
    }

    fn lock_timed_out(&self) -> SharedStoreError {
        SharedStoreError::LockTimeout {
            path: self.path.display().to_string(),
            seconds: self.lock_timeout.as_secs(),
        }
    }

    fn open_lock_file(&self) -> Result<File, SharedStoreError> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&self.lock_path)
            .map_err(|error| SharedStoreError::write(&self.lock_path, error))
    }
}

/// Validate an explicit document ceiling before any store I/O.
pub fn validate_explicit_store_max_document_bytes(
    max_bytes: usize,
) -> Result<usize, SharedStoreError> {
    if max_bytes < crate::config::env_config::MIN_TLS_STORE_MAX_DOCUMENT_BYTES {
        return Err(SharedStoreError::InvalidConfig {
            details: format!(
                "{} must be at least {} bytes; 0 is not unlimited",
                crate::config::env_config::TLS_STORE_MAX_DOCUMENT_BYTES_KEY,
                crate::config::env_config::MIN_TLS_STORE_MAX_DOCUMENT_BYTES
            ),
        });
    }
    Ok(max_bytes.min(crate::config::env_config::HARD_MAX_TLS_STORE_MAX_DOCUMENT_BYTES))
}

/// Open a durable TLS document for an authoritative bounded read.
///
/// Returns `Ok(None)` when the path is absent. On Unix the open uses
/// `O_NONBLOCK` so a FIFO/special path cannot hang before the post-open
/// regular-file check and bounded `limit+1` reader run. The regular-file
/// verdict comes from the opened descriptor's own metadata (not a racy path
/// precheck). Errors are content-free aside from the operator-configured path.
pub fn open_authoritative_document_file(path: &Path) -> Result<Option<File>, SharedStoreError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(SharedStoreError::read(path, error)),
        }
    };
    #[cfg(not(unix))]
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SharedStoreError::read(path, error)),
    };

    let metadata = file
        .metadata()
        .map_err(|error| SharedStoreError::read(path, error))?;
    if !metadata.is_file() {
        // Stable, content-free refusal: never echo whatever a special file
        // might produce if a blocking open had succeeded.
        return Err(SharedStoreError::read(path, "path is not a regular file"));
    }
    Ok(Some(file))
}

/// Read at most `max_bytes + 1` from `reader`, rejecting without retaining an
/// unbounded buffer. Used after any metadata precheck so growth/TOCTOU and
/// non-regular files still terminate.
pub fn read_bounded_document_bytes<R: Read>(
    reader: &mut R,
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, SharedStoreError> {
    let max_bytes = validate_explicit_store_max_document_bytes(max_bytes)?;
    let limit_plus_one = (max_bytes as u64).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit_plus_one)
        .read_to_end(&mut bytes)
        .map_err(|error| SharedStoreError::read(path, error))?;
    if bytes.len() > max_bytes {
        return Err(SharedStoreError::oversized(
            path,
            max_bytes,
            TlsStoreIoDirection::Read,
        ));
    }
    Ok(bytes)
}

fn record_store_document_bytes(kind: TlsPersistentStoreKind, bytes: u64) {
    crate::plugins::prometheus_metrics::global_registry().set_tls_store_document_bytes(kind, bytes);
}

fn record_store_oversized(kind: TlsPersistentStoreKind, direction: TlsStoreIoDirection) {
    crate::plugins::prometheus_metrics::global_registry()
        .record_tls_store_oversized(kind, direction);
}

/// Record a fixed-cardinality logical admission rejection.
pub fn record_store_admission_rejected(
    kind: TlsPersistentStoreKind,
    reason: TlsStoreAdmissionReason,
) {
    crate::plugins::prometheus_metrics::global_registry()
        .record_tls_store_admission_rejected(kind, reason);
}

/// Publish the current logical record count for a store.
pub fn record_store_record_count(kind: TlsPersistentStoreKind, count: u64) {
    crate::plugins::prometheus_metrics::global_registry().set_tls_store_record_count(kind, count);
}

/// Count terminal ACME order history pruned under the exclusive mutation lock.
pub fn record_store_pruned(count: u64) {
    if count == 0 {
        return;
    }
    crate::plugins::prometheus_metrics::global_registry().record_tls_store_pruned(count);
}

/// Sidecar advisory-lock path for a store document.
///
/// The lock lives beside the document rather than on it because publication
/// replaces the document by rename: a lock taken on the old inode would not be
/// seen by a writer that opened the new one.
fn lock_path_for(path: &Path) -> Result<PathBuf, SharedStoreError> {
    let missing_parent = || SharedStoreError::write(path, "store path has no parent directory");
    let missing_name = || SharedStoreError::write(path, "store path has no file name");
    let parent = path.parent().ok_or_else(missing_parent)?;
    let file_name = path.file_name().ok_or_else(missing_name)?;
    Ok(parent.join(format!(".{}.lock", file_name.to_string_lossy())))
}
