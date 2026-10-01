//! Durable, bounded on-disk spool for admin audit evidence (issue #2421).
//!
//! # Two-phase durability
//!
//! An audited admin mutation is durable **before** it is performed:
//!
//! 1. `prepare` writes a *prepared* record — the minimal audit request context
//!    (authenticated actor, method, sanitized path and namespace, canonical
//!    source address, bounded request id)
//!    under a stable event id — and fsyncs both the file and its directory.
//!    Only then may the mutation run.
//! 2. `finalize` rewrites that same stable id as a *finalized* record carrying
//!    the real outcome (`success` / `failure`) and diff, publishes it into
//!    `pending/` with an fsynced rename, and only then unlinks the prepared
//!    file.
//!
//! A crash anywhere in between leaves the prepared record on disk. Its outcome
//! is genuinely unknowable, so a later process replays it as an explicit
//! [`crate::admin::audit::AuditOutcome::UnknownOutcome`] event. It is never
//! deleted silently and never promoted to a known success or failure.
//!
//! # Ownership across processes
//!
//! Several gateway processes may share one configured spool root, so records
//! live under a per-process-generation instance directory whose `owner.lock` is
//! held with an exclusive, non-blocking OS lock for the process lifetime:
//!
//! ```text
//! <root>/instances/<generation>/owner.lock        held while the process runs
//! <root>/instances/<generation>/prepared/<id>.json
//! <root>/instances/<generation>/pending/<id>.json
//! <root>/instances/<generation>/tmp/<uuid>.tmp
//! <root>/failed/<id>.json                          retained operator evidence
//! ```
//!
//! A process only ever *claims* an instance directory whose lock it can take,
//! which is precisely the set of generations that are no longer running. It can
//! therefore never classify or replay its own in-flight prepared record, and two
//! live processes can never race for the same record.
//!
//! Every record also carries a **non-secret destination identity** (database
//! type, namespace, and a salt-free digest of the redacted connection URL). A
//! claimed record whose destination does not match the claiming process is
//! quarantined into `failed/` rather than delivered, so reconfiguring a gateway
//! cannot replay another deployment's audit evidence into the wrong database or
//! namespace. The digest is what is stored; the connection secret never is.
//!
//! # Bounds and hostile input
//!
//! Every entry point is bounded: record bytes, prepared/pending/retained record
//! counts, and directory-walk entries. Record filenames derive from the event
//! UUID and are validated against a strict charset before any path join, so no
//! actor- or operator-controlled string reaches the filesystem. Directories are
//! created owner-only and re-validated as non-symlink real directories; record
//! files are opened `O_NOFOLLOW` and rejected unless they are single-link
//! regular files. Temporary files are created `O_EXCL` under a per-write UUID
//! and published with an atomic same-directory rename. Directory syncs are
//! *checked*: an fsync failure is a durability failure, not a warning.
//!
//! Nothing in this module logs an actor subject, a diff body, a token, a
//! connection string, or a filesystem path. Errors carry a static reason label.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::admin::audit::{AuditEvent, AuditOutcome};
use crate::sync_compat::AtomicUpdate;

/// On-disk record format version. A record with any other version is corrupt.
pub const AUDIT_SPOOL_RECORD_VERSION: u32 = 2;

/// Hard ceiling for one serialized spool record, independent of configuration.
/// Larger admin bodies are still audited: the diff is replaced by a redacted
/// placeholder so the event identity stays durable (see
/// [`SpooledAuditRecord::with_bounded_diff`]).
pub const AUDIT_SPOOL_MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// Ceiling for a single directory walk. Prevents an unbounded `read_dir` on a
/// spool that another process filled.
pub const AUDIT_SPOOL_MAX_SCAN_ENTRIES: usize = 100_000;

/// Ceiling on instance directories inspected in one claim sweep.
pub const AUDIT_SPOOL_MAX_INSTANCE_SCAN: usize = 4_096;

/// Longest accepted record-id string (a UUID is 36 characters).
const MAX_RECORD_ID_LEN: usize = 64;

const INSTANCES_DIR: &str = "instances";
const PREPARED_DIR: &str = "prepared";
const PENDING_DIR: &str = "pending";
const FAILED_DIR: &str = "failed";
const TMP_DIR: &str = "tmp";
const OWNER_LOCK_FILE: &str = "owner.lock";
const RECORD_EXTENSION: &str = ".json";
const TMP_EXTENSION: &str = ".tmp";

/// Placeholder substituted for a diff that would exceed the record ceiling.
/// The event identity (who/what/when/where) stays durable and auditable.
pub const AUDIT_DIFF_OMITTED_MARKER: &str = "diff_exceeded_max_record_bytes";

/// Static, operator-facing reason labels. Never interpolate a path, an actor
/// subject, a connection string, or an OS error into a log line or metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolErrorKind {
    /// The spool root could not be prepared, locked, or is not usable.
    Unavailable,
    /// A record ceiling is reached; no further durable handoff.
    Saturated,
    /// A filesystem write, rename, unlink, or **fsync** failed.
    Io,
    /// The record could not be serialized or its id is not a legal filename.
    InvalidRecord,
    /// A stored record is unparseable, truncated, oversized, or mismatched.
    Corrupt,
    /// A stored record belongs to a different audit destination/instance.
    DestinationMismatch,
}

impl SpoolErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SpoolErrorKind::Unavailable => "spool_unavailable",
            SpoolErrorKind::Saturated => "spool_saturated",
            SpoolErrorKind::Io => "spool_io_error",
            SpoolErrorKind::InvalidRecord => "invalid_record",
            SpoolErrorKind::Corrupt => "corrupt_record",
            SpoolErrorKind::DestinationMismatch => "destination_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolError {
    pub kind: SpoolErrorKind,
}

impl SpoolError {
    fn new(kind: SpoolErrorKind) -> Self {
        Self { kind }
    }

    pub fn reason(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately reason-only: the caller logs this, and the underlying OS
        // error can carry a filesystem path.
        f.write_str(self.kind.as_str())
    }
}

impl std::error::Error for SpoolError {}

/// One durable audit record.
///
/// A record is *prepared* (`finalized == false`) before the mutation runs and
/// *finalized* (`finalized == true`) once the mutation's outcome is known.
/// `attempts` is advisory delivery bookkeeping used to decide when an event has
/// exhausted its bounded retry budget across process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpooledAuditRecord {
    /// On-disk format version. Fail closed on anything but the current value.
    pub v: u32,
    /// Non-secret audit destination identity this record was created against.
    pub destination: String,
    /// Process generation that created the record.
    pub generation: String,
    /// True once the mutation's outcome is known and written.
    #[serde(default)]
    pub finalized: bool,
    pub event: AuditEvent,
    /// Delivery attempts already burned against this record.
    #[serde(default)]
    pub attempts: u32,
    /// Unix milliseconds when the record was first made durable.
    #[serde(default)]
    pub first_spooled_unix_ms: i64,
    /// Set when the diff was replaced by [`AUDIT_DIFF_OMITTED_MARKER`].
    #[serde(default)]
    pub diff_omitted: bool,
}

impl SpooledAuditRecord {
    /// Build a record whose serialized form is guaranteed to fit the ceiling.
    ///
    /// An oversized diff is replaced by a redacted marker rather than dropping
    /// the event: losing *that a change happened* is the failure mode #2421 is
    /// about, and the resource identity is what makes the record reconcilable.
    pub fn with_bounded_diff(
        event: AuditEvent,
        destination: &str,
        generation: &str,
        finalized: bool,
        max_record_bytes: u64,
    ) -> Self {
        let mut record = Self {
            v: AUDIT_SPOOL_RECORD_VERSION,
            destination: destination.to_string(),
            generation: generation.to_string(),
            finalized,
            event,
            attempts: 0,
            first_spooled_unix_ms: chrono::Utc::now().timestamp_millis(),
            diff_omitted: false,
        };
        let fits = serde_json::to_vec(&record)
            .map(|bytes| bytes.len() as u64 <= max_record_bytes)
            .unwrap_or(false);
        if !fits {
            record.event.diff = serde_json::json!({ "omitted": AUDIT_DIFF_OMITTED_MARKER });
            record.diff_omitted = true;
        }
        record
    }

    pub fn id(&self) -> &str {
        &self.event.id
    }
}

/// O(1) snapshot of spool state for health/status and metrics.
///
/// Backed entirely by admission counters; reading it never touches the
/// filesystem, so `/health` and `/metrics` stay constant-time no matter how
/// large the backlog is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SpoolStats {
    pub prepared_records: u64,
    pub pending_records: u64,
    pub retained_records: u64,
    /// True when the last background rescan stopped at
    /// [`AUDIT_SPOOL_MAX_SCAN_ENTRIES`], so the counts above are floors.
    pub scan_truncated: bool,
}

/// Outcome of one bounded claim sweep over abandoned instance directories.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClaimReport {
    /// Prepared records adopted as `unknown_outcome` evidence.
    pub unknown_outcome: u64,
    /// Finalized records adopted for delivery.
    pub adopted_pending: u64,
    /// Records quarantined because they target a different destination.
    pub destination_mismatch: u64,
    /// Records quarantined because they are unparseable or malformed.
    pub corrupt: u64,
    /// Records discarded because retained capacity was already exhausted.
    pub capacity_discarded: u64,
    /// Instance directories still owned by a live process (left untouched).
    pub live_instances: u64,
}

/// What happened to a record handed to [`AuditSpool::retain_unrecoverable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainOutcome {
    /// The record is in `failed/` for operator remediation.
    Retained,
    /// An earlier exhausted attempt already moved this stable id to `failed/`.
    /// No new retention occurred, so counters must not increment again.
    AlreadyRetained,
    /// Retained capacity was already exhausted, so the record was discarded.
    /// This is real, permanent evidence loss.
    Discarded,
    /// There was nothing to retain: an earlier delivery of the same stable id
    /// already settled and removed the record. Distinguished from `Discarded`
    /// because reporting a discard here would latch permanent `evidence_lost`
    /// for a record that was never actually lost.
    AlreadySettled,
}

/// Exclusive, process-lifetime ownership lock over one instance directory.
#[derive(Debug)]
pub struct OwnerLock {
    _file: File,
}

/// A prepared, bounded audit spool rooted at an operator-configured directory.
///
/// `prepared_count` / `pending_count` / `retained_count` are O(1) admission
/// counters seeded by one bounded scan at [`AuditSpool::open`] and maintained
/// incrementally afterwards. Without them every committed admin mutation — and
/// every `/health` probe — would pay an O(backlog) `read_dir`. A counter that
/// reports "full" is always confirmed by a real scan before a handoff is
/// refused, so the cheap path is never the one that loses an event.
#[derive(Debug)]
pub struct AuditSpool {
    root: PathBuf,
    instance_dir: PathBuf,
    generation: String,
    destination: String,
    max_pending_records: u64,
    max_retained_records: u64,
    max_record_bytes: u64,
    /// Serializes the capacity check with publication of a new prepared intent.
    /// Without this, concurrent admin mutations could all observe the same
    /// below-ceiling counters and each publish a record, exceeding the configured
    /// per-generation disk bound before any atomic increment became visible.
    prepare_admission: Mutex<()>,
    prepared_count: AtomicU64,
    pending_count: AtomicU64,
    retained_count: AtomicU64,
    scan_truncated: AtomicBool,
    /// Held for the lifetime of the spool; released when the process exits.
    _owner: OwnerLock,
}

impl AuditSpool {
    /// Prepare this process generation's spool tree and take its ownership lock.
    ///
    /// Returns an error when the root cannot be created, hardened, locked, or
    /// written. Callers decide the policy consequence (fail open with a
    /// degraded pipeline, or fail closed and refuse audited mutations).
    pub fn open(
        root: impl Into<PathBuf>,
        generation: impl Into<String>,
        destination: impl Into<String>,
        max_pending_records: u64,
        max_retained_records: u64,
    ) -> Result<Self, SpoolError> {
        let root = root.into();
        let generation = generation.into();
        if !is_valid_record_id(&generation) {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        let instance_dir = root.join(INSTANCES_DIR).join(&generation);

        prepare_directory(&root)?;
        prepare_directory(&root.join(FAILED_DIR))?;
        prepare_directory(&root.join(INSTANCES_DIR))?;
        prepare_directory(&instance_dir)?;
        for sub in [PREPARED_DIR, PENDING_DIR, TMP_DIR] {
            prepare_directory(&instance_dir.join(sub))?;
        }

        let owner = match acquire_owner_lock(&instance_dir.join(OWNER_LOCK_FILE))? {
            Some(owner) => owner,
            // Our generation id is a fresh UUID, so a contended lock means the
            // directory is not ours to use. Fail closed rather than sharing.
            None => return Err(SpoolError::new(SpoolErrorKind::Unavailable)),
        };

        let spool = Self {
            root,
            instance_dir,
            generation,
            destination: destination.into(),
            max_pending_records: max_pending_records.max(1),
            max_retained_records: max_retained_records.max(1),
            max_record_bytes: AUDIT_SPOOL_MAX_RECORD_BYTES,
            prepare_admission: Mutex::new(()),
            prepared_count: AtomicU64::new(0),
            pending_count: AtomicU64::new(0),
            retained_count: AtomicU64::new(0),
            scan_truncated: AtomicBool::new(false),
            _owner: owner,
        };
        spool.probe_writable()?;
        spool.reconcile_tmp_dir()?;
        spool.resync_counts();
        Ok(spool)
    }

    pub fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }

    #[allow(dead_code)] // External audit pipeline tests inspect the owned generation; the bin does not.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    #[allow(dead_code)] // External audit pipeline tests inspect destination isolation; the bin does not.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    fn prepared_dir(&self) -> PathBuf {
        self.instance_dir.join(PREPARED_DIR)
    }

    fn pending_dir(&self) -> PathBuf {
        self.instance_dir.join(PENDING_DIR)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.instance_dir.join(TMP_DIR)
    }

    fn failed_dir(&self) -> PathBuf {
        self.root.join(FAILED_DIR)
    }

    /// Verify the tree is actually writable *and syncable* now rather than
    /// discovering it on the first audited mutation.
    fn probe_writable(&self) -> Result<(), SpoolError> {
        let probe = self
            .tmp_dir()
            .join(format!("probe-{}{TMP_EXTENSION}", uuid_text()));
        let result = (|| -> Result<(), SpoolError> {
            write_new_owner_only_file(&probe, b"ok")?;
            sync_dir(&self.tmp_dir())
        })();
        let _ = fs::remove_file(&probe);
        result.map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))
    }

    /// Remove temp files abandoned by a crash mid-write inside **our own**
    /// instance directory. A temp file was never renamed into `prepared/` or
    /// `pending/`, so it was never acknowledged and carries no obligation.
    fn reconcile_tmp_dir(&self) -> Result<(), SpoolError> {
        let tmp = self.tmp_dir();
        let Ok(entries) = fs::read_dir(&tmp) else {
            return Ok(());
        };
        let mut removed = false;
        for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
            let path = entry.path();
            let is_tmp = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(TMP_EXTENSION));
            if is_tmp && fs::remove_file(&path).is_ok() {
                removed = true;
            }
        }
        if removed { sync_dir(&tmp) } else { Ok(()) }
    }

    // -----------------------------------------------------------------------
    // Two-phase durability
    // -----------------------------------------------------------------------

    /// Durably create the pre-mutation intent. Returns once the record bytes and
    /// the `prepared/` directory entry are both on stable storage.
    pub fn prepare(&self, record: &SpooledAuditRecord) -> Result<(), SpoolError> {
        // The configured record ceiling is a hard storage bound, not a sampled
        // gauge. Hold the admission lock through publication and its counter
        // increment so concurrent requests cannot all pass one stale check.
        let _admission = self
            .prepare_admission
            .lock()
            .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
        if record.finalized {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        let id = record.id().to_string();
        let target = record_path(&self.prepared_dir(), &id)?;
        if self.capacity_exhausted() {
            return Err(SpoolError::new(SpoolErrorKind::Saturated));
        }
        self.publish(record, &target, &self.prepared_dir())?;
        self.prepared_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Durably finalize a previously prepared record with its known outcome.
    ///
    /// Publishes into `pending/` first, then unlinks the prepared file. If the
    /// unlink or its directory sync fails, the finalized record is still durable
    /// and the leftover prepared record is dropped by a later claim in favor of
    /// the finalized one — a known outcome always beats `unknown_outcome`.
    pub fn finalize(&self, record: &SpooledAuditRecord) -> Result<(), SpoolError> {
        if !record.finalized {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        let id = record.id().to_string();
        let target = record_path(&self.pending_dir(), &id)?;
        self.publish(record, &target, &self.pending_dir())?;
        self.pending_count.fetch_add(1, Ordering::Relaxed);
        let prepared = record_path(&self.prepared_dir(), &id)?;
        match fs::remove_file(&prepared) {
            Ok(()) => {
                sync_dir(&self.prepared_dir())?;
                decrement(&self.prepared_count);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SpoolError::new(SpoolErrorKind::Io)),
        }
        Ok(())
    }

    /// Write `record` into `dir` under `target` atomically and durably.
    fn publish(
        &self,
        record: &SpooledAuditRecord,
        target: &Path,
        dir: &Path,
    ) -> Result<(), SpoolError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|_| SpoolError::new(SpoolErrorKind::InvalidRecord))?;
        if bytes.len() as u64 > self.max_record_bytes {
            // `with_bounded_diff` already collapses oversized diffs, so this is
            // an identity field that is itself hostile-sized.
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        let tmp = self
            .tmp_dir()
            .join(format!("{}{TMP_EXTENSION}", uuid_text()));
        let published = (|| -> Result<(), SpoolError> {
            write_new_owner_only_file(&tmp, &bytes)?;
            // The temp directory entry itself must be durable before the rename
            // so a crash cannot leave the rename pointing at nothing.
            sync_dir(&self.tmp_dir())?;
            fs::rename(&tmp, target).map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
            sync_dir(dir)
        })();
        if published.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        published
    }

    /// Rewrite an existing pending record in place (attempt bookkeeping).
    ///
    /// Best-effort at the call site: a failure here only costs retry-budget
    /// accuracy, never the record itself.
    pub fn update_attempts(&self, record: &SpooledAuditRecord) -> Result<(), SpoolError> {
        let id = record.id().to_string();
        let target = record_path(&self.pending_dir(), &id)?;
        if !target.exists() {
            return Ok(());
        }
        self.publish(record, &target, &self.pending_dir())
    }

    /// Delete a delivered record. Idempotent: a missing file is success.
    pub fn remove_pending(&self, id: &str) -> Result<(), SpoolError> {
        let pending = record_path(&self.pending_dir(), id)?;
        match fs::remove_file(&pending) {
            Ok(()) => {
                sync_dir(&self.pending_dir())?;
                decrement(&self.pending_count);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SpoolError::new(SpoolErrorKind::Io)),
        }
    }

    /// Move a pending record into operator-visible retention.
    ///
    /// Discarding the *newest* arrival preserves the oldest evidence, which is
    /// what an operator reconciling a gap needs first. An id that is no longer
    /// pending is distinguished as already retained when its failed record
    /// exists, or already settled when neither record exists. At-least-once
    /// delivery means either can race another attempt for the same stable id;
    /// neither is a new retention or new evidence loss.
    pub fn retain_unrecoverable(&self, id: &str) -> Result<RetainOutcome, SpoolError> {
        let pending = record_path(&self.pending_dir(), id)?;
        let failed = record_path(&self.failed_dir(), id)?;
        if !pending.exists() {
            return Ok(if failed.exists() {
                RetainOutcome::AlreadyRetained
            } else {
                RetainOutcome::AlreadySettled
            });
        }
        if self.retained_capacity_exhausted() {
            self.remove_pending(id)?;
            return Ok(RetainOutcome::Discarded);
        }
        fs::rename(&pending, &failed).map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        sync_dir(&self.pending_dir())?;
        sync_dir(&self.failed_dir())?;
        decrement(&self.pending_count);
        self.retained_count.fetch_add(1, Ordering::Relaxed);
        Ok(RetainOutcome::Retained)
    }

    /// Read one pending record.
    ///
    /// Any corruption — bad version, oversized file, unparseable JSON, an
    /// embedded id that disagrees with the filename, a non-finalized body, or a
    /// foreign destination — quarantines the file into `failed/` and reports the
    /// matching error. Such a record is never replayed and never silently
    /// deleted while retention capacity remains.
    pub fn read_pending(&self, id: &str) -> Result<SpooledAuditRecord, SpoolError> {
        let pending = record_path(&self.pending_dir(), id)?;
        match self.read_record_at(&pending, id) {
            Ok(record) if !record.finalized => {
                let _ = self.quarantine(&pending);
                Err(SpoolError::new(SpoolErrorKind::Corrupt))
            }
            Ok(record) if record.destination != self.destination => {
                let _ = self.quarantine(&pending);
                Err(SpoolError::new(SpoolErrorKind::DestinationMismatch))
            }
            Ok(record) => Ok(record),
            Err(error) => {
                if matches!(
                    error.kind,
                    SpoolErrorKind::Corrupt | SpoolErrorKind::DestinationMismatch
                ) {
                    let _ = self.quarantine(&pending);
                }
                Err(error)
            }
        }
    }

    fn read_record_at(
        &self,
        path: &Path,
        expected_id: &str,
    ) -> Result<SpooledAuditRecord, SpoolError> {
        let mut file = match open_regular_nofollow(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SpoolError::new(SpoolErrorKind::Unavailable));
            }
            Err(_) => return Err(SpoolError::new(SpoolErrorKind::Corrupt)),
        };
        let metadata = file
            .metadata()
            .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        validate_opened_record_metadata(&metadata)?;
        if metadata.len() > self.max_record_bytes {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        // Bounded read: never trust `metadata.len()` alone against a file that
        // grew between stat and read.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(metadata.len().min(64 * 1024) as usize)
            .map_err(|_| SpoolError::new(SpoolErrorKind::Corrupt))?;
        std::io::Read::by_ref(&mut file)
            .take(self.max_record_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        if bytes.len() as u64 > self.max_record_bytes {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        let record: SpooledAuditRecord =
            serde_json::from_slice(&bytes).map_err(|_| SpoolError::new(SpoolErrorKind::Corrupt))?;
        if record.v != AUDIT_SPOOL_RECORD_VERSION || record.event.id != expected_id {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        Ok(record)
    }

    /// Move a record file into shared retention under its own filename.
    ///
    /// Quarantine preserves evidence: the file is discarded only when retained
    /// capacity is already exhausted, and that discard is reported to the caller
    /// as permanent evidence loss.
    fn quarantine(&self, path: &Path) -> Result<bool, SpoolError> {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        };
        let Some(id) = record_id_from_file_name(name) else {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        };
        let failed = record_path(&self.failed_dir(), &id)?;
        let from_pending = path.starts_with(self.pending_dir());
        let from_prepared = path.starts_with(self.prepared_dir());
        if self.retained_capacity_exhausted() {
            let removed = fs::remove_file(path).is_ok();
            if removed {
                if from_pending {
                    decrement(&self.pending_count);
                }
                if from_prepared {
                    decrement(&self.prepared_count);
                }
            }
            return Ok(false);
        }
        fs::rename(path, &failed).map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        if let Some(parent) = path.parent() {
            sync_dir(parent)?;
        }
        sync_dir(&self.failed_dir())?;
        if from_pending {
            decrement(&self.pending_count);
        }
        if from_prepared {
            decrement(&self.prepared_count);
        }
        self.retained_count.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// List up to `limit` pending record ids from this process's instance.
    ///
    /// Entries whose name is not `<valid-id>.json` are ignored (and stray temp
    /// files removed), so a hostile or foreign file in the spool directory can
    /// neither be replayed nor wedge the scan.
    pub fn list_pending_ids(&self, limit: usize) -> Vec<String> {
        let limit = limit.min(AUDIT_SPOOL_MAX_SCAN_ENTRIES);
        let mut ids = Vec::new();
        let Ok(entries) = fs::read_dir(self.pending_dir()) else {
            return ids;
        };
        for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
            if ids.len() >= limit {
                break;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            match record_id_from_file_name(name) {
                Some(id) => ids.push(id),
                None => {
                    if name.ends_with(TMP_EXTENSION) {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
        ids
    }

    // -----------------------------------------------------------------------
    // Cross-process claim of abandoned generations
    // -----------------------------------------------------------------------

    /// Adopt every instance directory whose ownership lock can be taken.
    ///
    /// A lock we can take belongs to a generation that is no longer running, so
    /// this can never touch our own in-flight prepared records nor another live
    /// process's. Prepared records become explicit `unknown_outcome` evidence;
    /// finalized records are adopted for delivery; anything bound to a different
    /// destination is quarantined instead of misdelivered.
    pub fn claim_abandoned(&self) -> ClaimReport {
        // Order startup adoption with new-intent admission. The inherited
        // obligations themselves are never discarded to satisfy this
        // generation's admission ceiling, but once they are counted no new
        // prepare may slip through a stale below-ceiling observation.
        let _admission = match self.prepare_admission.lock() {
            Ok(admission) => admission,
            // Preserve already-durable evidence even if an earlier prepare
            // panicked while holding the ordering lock. Future prepares still
            // fail closed on the poisoned lock.
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut report = ClaimReport::default();
        let instances = self.root.join(INSTANCES_DIR);
        let Ok(entries) = fs::read_dir(&instances) else {
            return report;
        };
        for entry in entries.take(AUDIT_SPOOL_MAX_INSTANCE_SCAN).flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name == self.generation || !is_valid_record_id(name) {
                continue;
            }
            if !fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                continue;
            }
            match acquire_owner_lock(&path.join(OWNER_LOCK_FILE)) {
                Ok(Some(lock)) => {
                    self.claim_instance(&path, &mut report);
                    drop(lock);
                    // The directory is drained; remove it so the sweep stays
                    // bounded across many restarts. Leftovers are harmless.
                    let _ = fs::remove_file(path.join(OWNER_LOCK_FILE));
                    for sub in [PREPARED_DIR, PENDING_DIR, TMP_DIR] {
                        let _ = fs::remove_dir(path.join(sub));
                    }
                    let _ = fs::remove_dir(&path);
                }
                Ok(None) => report.live_instances = report.live_instances.saturating_add(1),
                Err(_) => report.live_instances = report.live_instances.saturating_add(1),
            }
        }
        let _ = sync_dir(&instances);
        report
    }

    fn claim_instance(&self, instance: &Path, report: &mut ClaimReport) {
        // Abandoned temp files were never published; they carry no obligation.
        if let Ok(entries) = fs::read_dir(instance.join(TMP_DIR)) {
            for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
        // Finalized records first: a known outcome must win over the prepared
        // twin a partial finalize may have left behind.
        self.claim_dir(&instance.join(PENDING_DIR), false, report);
        self.claim_dir(&instance.join(PREPARED_DIR), true, report);
    }

    fn claim_dir(&self, dir: &Path, prepared: bool, report: &mut ClaimReport) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(id) = record_id_from_file_name(name) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            let record = match self.read_record_at(&path, &id) {
                Ok(record) => record,
                Err(_) => {
                    report.corrupt = report.corrupt.saturating_add(1);
                    if let Ok(false) = self.quarantine(&path) {
                        report.capacity_discarded = report.capacity_discarded.saturating_add(1);
                    }
                    continue;
                }
            };
            if record.destination != self.destination {
                report.destination_mismatch = report.destination_mismatch.saturating_add(1);
                if let Ok(false) = self.quarantine(&path) {
                    report.capacity_discarded = report.capacity_discarded.saturating_add(1);
                }
                continue;
            }
            let target = match record_path(&self.pending_dir(), &id) {
                Ok(target) => target,
                Err(_) => continue,
            };
            if prepared {
                if target.exists() {
                    // A finalized twin already carries the real outcome.
                    let _ = fs::remove_file(&path);
                    continue;
                }
                let mut adopted = record;
                adopted.finalized = true;
                adopted.generation = self.generation.clone();
                adopted.event.outcome = AuditOutcome::UnknownOutcome.as_str().to_string();
                adopted.event.diff = serde_json::json!({
                    "outcome_evidence": "prior_process_generation_did_not_finalize",
                });
                if self.publish(&adopted, &target, &self.pending_dir()).is_ok() {
                    self.pending_count.fetch_add(1, Ordering::Relaxed);
                    report.unknown_outcome = report.unknown_outcome.saturating_add(1);
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            if record.finalized {
                let mut adopted = record;
                adopted.generation = self.generation.clone();
                if self.publish(&adopted, &target, &self.pending_dir()).is_ok() {
                    self.pending_count.fetch_add(1, Ordering::Relaxed);
                    report.adopted_pending = report.adopted_pending.saturating_add(1);
                    let _ = fs::remove_file(&path);
                }
            } else {
                // A non-finalized body found under `pending/` is malformed.
                report.corrupt = report.corrupt.saturating_add(1);
                if let Ok(false) = self.quarantine(&path) {
                    report.capacity_discarded = report.capacity_discarded.saturating_add(1);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bounds and counters
    // -----------------------------------------------------------------------

    /// Whether the durable ceiling is reached, confirmed by a real scan before
    /// a committed mutation's evidence is refused.
    fn capacity_exhausted(&self) -> bool {
        let counted = self
            .prepared_count
            .load(Ordering::Relaxed)
            .saturating_add(self.pending_count.load(Ordering::Relaxed));
        if counted < self.max_pending_records {
            return false;
        }
        let (prepared, prepared_truncated) = count_dir(&self.prepared_dir());
        let (pending, pending_truncated) = count_dir(&self.pending_dir());
        self.prepared_count.store(prepared, Ordering::Relaxed);
        self.pending_count.store(pending, Ordering::Relaxed);
        prepared.saturating_add(pending) >= self.max_pending_records
            || prepared_truncated
            || pending_truncated
    }

    /// Whether retained storage is full, confirmed by a scan before discarding.
    fn retained_capacity_exhausted(&self) -> bool {
        if self.retained_count.load(Ordering::Relaxed) < self.max_retained_records {
            return false;
        }
        let (retained, truncated) = count_dir(&self.failed_dir());
        self.retained_count.store(retained, Ordering::Relaxed);
        retained >= self.max_retained_records || truncated
    }

    /// O(1) counters for health/status and metrics. Never touches the disk.
    pub fn stats(&self) -> SpoolStats {
        SpoolStats {
            prepared_records: self.prepared_count.load(Ordering::Relaxed),
            pending_records: self.pending_count.load(Ordering::Relaxed),
            retained_records: self.retained_count.load(Ordering::Relaxed),
            scan_truncated: self.scan_truncated.load(Ordering::Relaxed),
        }
    }

    /// Reconcile the O(1) counters against disk. Background use only: this is a
    /// bounded directory walk and must never run on an admin request path.
    pub fn resync_counts(&self) {
        let (prepared, prepared_truncated) = count_dir(&self.prepared_dir());
        let (pending, pending_truncated) = count_dir(&self.pending_dir());
        let (retained, retained_truncated) = count_dir(&self.failed_dir());
        if !prepared_truncated {
            self.prepared_count.store(prepared, Ordering::Relaxed);
        }
        if !pending_truncated {
            self.pending_count.store(pending, Ordering::Relaxed);
        }
        if !retained_truncated {
            self.retained_count.store(retained, Ordering::Relaxed);
        }
        self.scan_truncated.store(
            prepared_truncated || pending_truncated || retained_truncated,
            Ordering::Relaxed,
        );
    }
}

/// Accepted record-id charset: UUID text only. Anything else — including path
/// separators, `.`, and non-ASCII — is rejected before any path join.
pub fn is_valid_record_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RECORD_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Extract a validated record id from a `<id>.json` filename.
pub fn record_id_from_file_name(name: &str) -> Option<String> {
    let id = name.strip_suffix(RECORD_EXTENSION)?;
    is_valid_record_id(id).then(|| id.to_string())
}

/// Join a validated record id under `dir`.
///
/// The charset check is the path-traversal boundary: `..`, `/`, and every
/// separator are rejected before the join, so the result is always a direct
/// child of `dir`.
fn record_path(dir: &Path, id: &str) -> Result<PathBuf, SpoolError> {
    if !is_valid_record_id(id) {
        return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
    }
    Ok(dir.join(format!("{id}{RECORD_EXTENSION}")))
}

fn uuid_text() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Saturating decrement for an admission counter.
fn decrement(counter: &AtomicU64) {
    let _ = counter.update_with(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

/// Count `*.json` entries in a spool directory, stopping at the scan ceiling.
/// The bool reports whether the ceiling truncated the walk.
fn count_dir(dir: &Path) -> (u64, bool) {
    let Ok(entries) = fs::read_dir(dir) else {
        return (0, false);
    };
    let mut count = 0u64;
    for (index, entry) in entries.enumerate() {
        if index >= AUDIT_SPOOL_MAX_SCAN_ENTRIES {
            return (count, true);
        }
        let matched = entry
            .ok()
            .and_then(|entry| {
                entry
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.ends_with(RECORD_EXTENSION))
            })
            .unwrap_or(false);
        if matched {
            count = count.saturating_add(1);
        }
    }
    (count, false)
}

/// Create (if absent) and validate one owner-only spool directory.
///
/// Fails closed on a symlink or a non-directory at the path, and re-validates
/// after creation so a raced replacement cannot slip through.
fn prepare_directory(dir: &Path) -> Result<(), SpoolError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(SpoolError::new(SpoolErrorKind::Unavailable));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
            let meta = fs::symlink_metadata(dir)
                .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(SpoolError::new(SpoolErrorKind::Unavailable));
            }
        }
        Err(_) => return Err(SpoolError::new(SpoolErrorKind::Unavailable)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
    }
    Ok(())
}

/// Create a new owner-only file, write `body`, and fsync it.
///
/// `create_new` plus `O_NOFOLLOW` means an attacker-planted symlink or an
/// existing file at the temp path fails the write rather than redirecting it.
fn write_new_owner_only_file(path: &Path, body: &[u8]) -> Result<(), SpoolError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
    file.write_all(body)
        .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
    // Content durability is a hard requirement, not best effort.
    file.sync_all()
        .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
    Ok(())
}

/// Open a spool record for reading without following a final-path symlink.
fn open_regular_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Validate opened-handle metadata for a spool record file.
fn validate_opened_record_metadata(meta: &fs::Metadata) -> Result<(), SpoolError> {
    if !meta.file_type().is_file() {
        return Err(SpoolError::new(SpoolErrorKind::Corrupt));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
    }
    Ok(())
}

/// Directory fsync so a rename is durable across a power loss.
///
/// A failure here is a **durability failure**: the caller must not report the
/// record as durable. Windows cannot open a directory as a file, so the rename
/// ordering guarantee stands on its own there.
fn sync_dir(dir: &Path) -> Result<(), SpoolError> {
    #[cfg(unix)]
    {
        let handle = File::open(dir).map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        handle
            .sync_all()
            .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Take an exclusive, non-blocking ownership lock over an instance directory.
///
/// `Ok(None)` means another live process still owns it. `Err` means the lock
/// could not be evaluated at all, which is treated as "not ours".
#[cfg(unix)]
fn acquire_owner_lock(lock_path: &Path) -> Result<Option<OwnerLock>, SpoolError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
    let meta = file
        .metadata()
        .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
    // Reject hard-linked or non-regular targets before chmod/flock can affect
    // an unrelated inode that merely shares this pathname.
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(SpoolError::new(SpoolErrorKind::Unavailable));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;

    // SAFETY: `file` owns a valid descriptor for the lifetime of the guard and
    // `flock` touches no Rust-managed memory. `LOCK_NB` fails immediately on
    // contention so startup cannot block behind a live sibling process.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        let errno = error.raw_os_error();
        if errno == Some(libc::EWOULDBLOCK) || errno == Some(libc::EAGAIN) {
            return Ok(None);
        }
        return Err(SpoolError::new(SpoolErrorKind::Unavailable));
    }
    Ok(Some(OwnerLock { _file: file }))
}

/// Windows ownership lock: `share_mode(0)` denies all sharing for the handle's
/// lifetime, which is an exclusive cross-process critical section, and the open
/// fails immediately when another holder exists (no wait).
#[cfg(windows)]
fn acquire_owner_lock(lock_path: &Path) -> Result<Option<OwnerLock>, SpoolError> {
    use std::os::windows::fs::OpenOptionsExt;

    // FILE_FLAG_OPEN_REPARSE_POINT: never traverse a planted reparse point.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(lock_path)
    {
        Ok(file) => {
            let meta = file
                .metadata()
                .map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
            if !meta.file_type().is_file() {
                return Err(SpoolError::new(SpoolErrorKind::Unavailable));
            }
            Ok(Some(OwnerLock { _file: file }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(None),
        Err(_) => Err(SpoolError::new(SpoolErrorKind::Unavailable)),
    }
}

#[cfg(not(any(unix, windows)))]
fn acquire_owner_lock(_lock_path: &Path) -> Result<Option<OwnerLock>, SpoolError> {
    // Without cross-process exclusion the ownership model is unenforceable, and
    // claiming another generation's records could race a live process. Fail
    // closed rather than pretend.
    Err(SpoolError::new(SpoolErrorKind::Unavailable))
}
