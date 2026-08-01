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
            .finish_non_exhaustive()
    }
}

impl<T: VersionedStoreFile> SharedStoreFile<T> {
    /// Open (or adopt) the shared document at `path`.
    ///
    /// A missing document is an empty store; an unreadable or unparseable one
    /// is an error, so a corrupt shared volume is never silently replaced by an
    /// empty local map.
    pub fn open(path: PathBuf) -> Result<Self, SharedStoreError> {
        Self::open_with_identity_mode(path, StoreIdentityMode::platform_default())
    }

    /// [`Self::open`] with an explicit replacement-identity mode.
    ///
    /// [`StoreIdentityMode::Unavailable`] is the always-correct fallback used on
    /// platforms without file identity; it is exposed so the no-identity path
    /// can be exercised (and regression-tested) on any target.
    pub fn open_with_identity_mode(
        path: PathBuf,
        identity_mode: StoreIdentityMode,
    ) -> Result<Self, SharedStoreError> {
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
            Ok(metadata) => Some(FileStamp::from_metadata(&metadata, self.identity_mode)),
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
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let value = Arc::new(T::default());
                self.publish_cached(value.clone(), None, None)?;
                return Ok(value);
            }
            Err(error) => return Err(SharedStoreError::read(&self.path, error)),
        };
        // Stamp from the open handle so it describes exactly the bytes read,
        // not whatever the path may point at by the time the read finishes.
        let stamp = file.metadata().ok();
        let stamp = stamp
            .as_ref()
            .map(|metadata| FileStamp::from_metadata(metadata, self.identity_mode));
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| SharedStoreError::read(&self.path, error))?;
        // A document that does not parse is an error. A partially written one
        // cannot be observed (rename is atomic), so this is real corruption and
        // must never degrade to an empty local map.
        let parsed = serde_json::from_slice::<T>(&bytes)
            .map_err(|error| SharedStoreError::parse(&self.path, error))?;
        let value = Arc::new(parsed);
        self.publish_cached(value.clone(), stamp, Some(file))?;
        Ok(value)
    }

    fn persist_locked(&self, value: &T) -> Result<(), SharedStoreError> {
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        // Pin the freshly published inode the same way a read does. If it
        // cannot be reopened the cache simply records no stamp, which makes
        // every later read re-read — degraded, never stale.
        let pinned = File::open(&self.path).ok();
        let stamp = pinned
            .as_ref()
            .and_then(|file| file.metadata().ok())
            .map(|metadata| FileStamp::from_metadata(&metadata, self.identity_mode));
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
