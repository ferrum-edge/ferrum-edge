//! Admin API audit logging.
//!
//! # Durable evidence for audited mutations (issue #2421)
//!
//! An audited admin mutation is durable **before it happens**, not after:
//!
//! 1. The admin write gate durably prepares an *audit intent* — a stable event
//!    id plus the minimal audit request context (authenticated actor subject,
//!    method, sanitized path/namespace, canonical socket source address,
//!    bounded request id) — fsyncing
//!    both the record and its directory before the mutation is invoked.
//! 2. Once the mutation returns, the same stable id is durably finalized with
//!    the real outcome (`success` or `failure`) and diff, and only then is the
//!    prepared record unlinked.
//! 3. Delivery into `audit_events` happens asynchronously afterwards, with
//!    bounded exponential backoff and replay, and the durable record is removed
//!    only once the backend has accepted the event.
//!
//! There is therefore no window in which a configuration mutation is committed
//! with no durable audit evidence. A crash between commit and finalize leaves
//! the prepared record on disk; its outcome is genuinely unknowable, so a later
//! process generation replays it as an explicit
//! [`AuditOutcome::UnknownOutcome`] event. It is never deleted silently and
//! never promoted to a known success or failure.
//!
//! ## Ownership
//!
//! Each process generation owns an instance directory under the spool root and
//! holds its lock for the process lifetime, so a process can never classify its
//! own in-flight prepared record, and several gateways may share one configured
//! spool. Every record is bound to a non-secret audit-destination identity
//! (database type, namespace, and a digest of the redacted connection URL), so
//! reconfiguration cannot replay one deployment's evidence into another's
//! database. The connection secret itself is never stored or logged.
//!
//! ## Delivery semantics
//!
//! **At-least-once with a stable identity.** Every backend insert is
//! insert-only and idempotent on that id (PostgreSQL/SQLite
//! `ON CONFLICT (id) DO NOTHING`, MySQL `ON DUPLICATE KEY UPDATE id = id`,
//! MongoDB `insert_one` with duplicate-key treated as success), so a replayed
//! event converges to exactly one immutable durable row. A duplicate delivery
//! is success, never replacement.
//!
//! ## Unavailability policy
//!
//! `FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY` selects what happens when the
//! pre-mutation handoff fails:
//!
//! - `fail_closed` — the mutation is refused with `503` before it runs.
//! - `fail_open` — the mutation proceeds, but only after a fixed-cardinality
//!   warning and a dedicated counter; the pipeline stops claiming durable audit
//!   coverage (`available: false` on `/health` and `ferrum_admin_audit_available
//!   0`).
//!
//! ## Observability
//!
//! Health and metrics reads are O(1): they load atomics and cached background
//! state only. No admin request path performs a filesystem walk or blocking
//! database work for audit observability. Evidence of corrupt, unrecoverable,
//! or capacity-discarded records is **sticky** — a later successful delivery
//! does not clear it; only resolving the retained evidence does, and a record
//! actually discarded for capacity is permanent.
//!
//! Nothing on this path logs an actor token, a secret, a request body, a
//! connection string, or credential metadata. Failure surfaces carry a static
//! reason label and the audit event id only.

use crate::admin::audit_spool::{
    AuditSpool, RetainOutcome, SpoolError, SpoolErrorKind, SpooledAuditRecord,
};
use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, TryLockError, Weak};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};
use tracing::{error, info, warn};
use uuid::Uuid;

const AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS: u64 = 60;
/// Max accepted client-supplied admin request/correlation ID length.
pub const AUDIT_REQUEST_ID_MAX_LEN: usize = 128;
/// Bound on local fallback events retained on disk (newest kept).
pub const AUDIT_LOCAL_FALLBACK_CAPACITY: usize = 4_096;
/// Hard ceiling on local fallback file bytes admitted into memory.
///
/// Event count is separately capped by [`AUDIT_LOCAL_FALLBACK_CAPACITY`]. This
/// bound rejects a hostile or corrupt on-disk file before allocation/parse so
/// the admit/list path cannot grow unboundedly. Sized as 4 KiB average
/// headroom per retained event (16 MiB at the current capacity).
pub const AUDIT_LOCAL_FALLBACK_MAX_BYTES: usize = AUDIT_LOCAL_FALLBACK_CAPACITY * 4 * 1024;
const AUDIT_LOCAL_FALLBACK_FILE_NAME: &str = "admin-audit-fallback.json";
const AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME: &str = "admin-audit-fallback.lock";
/// Default on-disk location when `FERRUM_ADMIN_AUDIT_FALLBACK_PATH` is unset.
///
/// Kept CWD-relative deliberately: an absolute default such as
/// `/var/lib/ferrum/...` would break relative deployments and require a
/// writable system path that many file-mode / container layouts do not have,
/// while a process-scoped temp dir would discard security records across
/// restarts. Operators who need an absolute or shared path set
/// `FERRUM_ADMIN_AUDIT_FALLBACK_PATH` explicitly. Test suites must not share
/// this default — they pass a per-test directory on `AdminState`.
const AUDIT_LOCAL_FALLBACK_DEFAULT_DIR: &str = "./ferrum-admin-audit";
/// Combined bound for in-process + cross-process local-fallback lock waits.
///
/// A waiter is not queued behind a lock handoff: the holder owns both locks
/// for a complete read/modify/write critical section that reads the retained
/// store, publishes a temp file, `fsync`s it, renames it into place, and
/// `fsync`s the parent directory. On loaded, virtualized, or network-backed
/// storage that is routinely tens to hundreds of milliseconds, and concurrent
/// admits (every security-sensitive `GET /backup` reaching the fallback
/// serializes here) each wait for whole critical sections ahead of them. A
/// sub-second bound therefore cannot distinguish a busy holder from a wedged
/// one, and refuses an event that was perfectly admissible — the spurious
/// fail-closed behavior issue #3573 set out to remove. Five seconds is far
/// above any healthy critical section, still bounds the `spawn_blocking`
/// thread so a wedged holder cannot hang `GET /backup` unboundedly, and stays
/// within typical admin request timeouts. Both lock acquisitions share one
/// deadline so the caller-visible worst case stays this bound, not the product
/// of two independent waits.
const LOCAL_FALLBACK_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Sleep between non-blocking lock retries. Short enough that a just-released
/// holder is noticed quickly; long enough to avoid a tight spin.
const LOCAL_FALLBACK_LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(1);
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// Win32 `ERROR_SHARING_VIOLATION` — another handle holds exclusive share mode.
#[cfg(windows)]
const WIN32_ERROR_SHARING_VIOLATION: i32 = 32;

/// Closed allow-list of backup resource filter names persisted in audit events.
pub const BACKUP_AUDIT_RESOURCE_NAMES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "api_specs",
];
/// Fixed non-sensitive sentinel when a filter contained unknown tokens.
pub const BACKUP_RESOURCES_INVALID_SENTINEL: &str = "invalid";
/// Fixed-cardinality marker when `X-Ferrum-Namespace` failed validation on an
/// authenticated backup attempt. The raw invalid namespace is never stored.
pub const BACKUP_NAMESPACE_STATUS_INVALID: &str = "invalid";

/// Fixed-cardinality outcomes stored on [`AuditEvent::outcome`].
///
/// Typed so callers cannot persist arbitrary outcome strings through the
/// security-sensitive builder API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    /// The mutation returned an error. The change did not take effect, but the
    /// attempt is evidence and is recorded.
    Failure,
    Denied,
    ValidationFailed,
    Unavailable,
    /// A prepared record lost its trustworthy outcome observer (process exit or
    /// request-task cancellation before settlement ownership). The mutation
    /// may or may not have committed; the outcome is recorded as unknowable,
    /// never inferred (issue #2421).
    UnknownOutcome,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::ValidationFailed => "validation_failed",
            Self::Unavailable => "unavailable",
            Self::UnknownOutcome => "unknown_outcome",
        }
    }
}

/// Fixed-cardinality failure categories for backup audit `diff` payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupFailureCategory {
    Forbidden,
    NamespaceDenied,
    ValidationFailed,
    Unavailable,
}

impl BackupFailureCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::NamespaceDenied => "namespace_denied",
            Self::ValidationFailed => "validation_failed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Convenience aliases for closed backup audit outcomes.
pub mod outcome {
    use super::AuditOutcome;
    pub const SUCCESS: AuditOutcome = AuditOutcome::Success;
    pub const DENIED: AuditOutcome = AuditOutcome::Denied;
    pub const VALIDATION_FAILED: AuditOutcome = AuditOutcome::ValidationFailed;
    pub const UNAVAILABLE: AuditOutcome = AuditOutcome::Unavailable;
}

/// Convenience aliases for closed backup failure categories.
pub mod failure_category {
    use super::BackupFailureCategory;
    pub const FORBIDDEN: BackupFailureCategory = BackupFailureCategory::Forbidden;
    pub const NAMESPACE_DENIED: BackupFailureCategory = BackupFailureCategory::NamespaceDenied;
    pub const VALIDATION_FAILED: BackupFailureCategory = BackupFailureCategory::ValidationFailed;
    pub const UNAVAILABLE: BackupFailureCategory = BackupFailureCategory::Unavailable;
}

/// Upper bound for `FERRUM_AUDIT_RETENTION_DAYS` (100 years).
pub const AUDIT_RETENTION_DAYS_MAX: u64 = 36_500;
/// Upper bound for `FERRUM_AUDIT_RETENTION_MAX_ROWS` per namespace.
pub const AUDIT_RETENTION_MAX_ROWS_CAP: u64 = 10_000_000;
/// Default durable audit-event cap per namespace. Audit logging must not remain
/// unbounded merely because the operator did not discover a retention knob.
pub const AUDIT_RETENTION_MAX_ROWS_DEFAULT: u64 = 100_000;
/// Rows deleted per prune statement so a multi-million-row backlog cannot hold
/// a write lock for one unbounded DELETE / deleteMany.
pub const AUDIT_RETENTION_PRUNE_BATCH_SIZE: u64 = 1_000;
/// Max DELETE batches per prune call so insert-path piggyback stays bounded.
pub const AUDIT_RETENTION_PRUNE_MAX_BATCHES: u32 = 8;
/// Soft-cap cadence for max-row boundary scans on the insert path.
///
/// Finding the excess boundary requires newest-first `OFFSET max_rows`, which
/// is O(max_rows) index work. Steady-state inserts therefore skip that scan
/// until this many additional inserts (per gateway instance, per namespace)
/// have landed since the last verified at-or-under-cap check — unless the
/// namespace has not been checked yet or a prior prune hit the per-call batch
/// budget. Equals the prune batch size so soft overshoot stays small and
/// deterministic.
pub const AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL: u64 = AUDIT_RETENTION_PRUNE_BATCH_SIZE;
/// Max per-gateway-instance namespaces tracked for insert-path max-row prune
/// cadence. When the map is full and a namespace has no entry, inserts behave
/// as if the gate required a boundary scan (no new entry is inserted).
pub const AUDIT_MAX_ROWS_PRUNE_GATES_CAP: usize = 256;

static AUDIT_SINKS: LazyLock<DashMap<usize, AuditSinkEntry>> = LazyLock::new(DashMap::new);

/// Per-namespace insert-path gate for max-row retention scans.
///
/// `FERRUM_AUDIT_RETENTION_MAX_ROWS` is a soft cap: after a verified
/// at-or-under-cap observation, one gateway instance may admit up to
/// [`audit_retention_max_rows_check_interval`] further inserts for that
/// namespace before the next O(max_rows) boundary scan. When a scan finds
/// excess and the bounded delete budget is exhausted, `scan_pending` keeps
/// subsequent inserts pruning immediately so backlog drains promptly. A new
/// gate also starts pending so the first successful insert checks any backlog
/// that predates this process. Explicit `prune_audit_events` calls always force
/// a scan. Multiple gateway instances each keep their own gate, so worst-case
/// soft overshoot scales with instance count × interval; deletes remain
/// namespace-scoped and idempotent.
#[derive(Debug, Clone)]
pub struct AuditMaxRowsPruneGate {
    inserts_since_check: u64,
    scan_pending: bool,
}

impl Default for AuditMaxRowsPruneGate {
    fn default() -> Self {
        Self {
            inserts_since_check: 0,
            scan_pending: true,
        }
    }
}

impl AuditMaxRowsPruneGate {
    /// Whether this insert (or forced prune) should run the max-rows boundary scan.
    pub fn should_run_max_rows_prune(&mut self, max_rows: u64, force: bool) -> bool {
        if force || self.scan_pending {
            return true;
        }
        self.inserts_since_check = self.inserts_since_check.saturating_add(1);
        self.inserts_since_check >= audit_retention_max_rows_check_interval(max_rows)
    }

    /// Record the outcome of a max-rows prune so the next insert can either
    /// resume soft-cap cadence or keep draining.
    pub fn note_max_rows_prune_result(&mut self, hit_batch_budget: bool) {
        self.inserts_since_check = 0;
        self.scan_pending = hit_batch_budget;
    }
}

/// Resolve whether insert-path max-row pruning should run for `namespace`.
///
/// When the gate map is at [`AUDIT_MAX_ROWS_PRUNE_GATES_CAP`] and `namespace`
/// has no entry, returns `true` without inserting so every insert pays the
/// bounded boundary query (cheap for low-row namespaces).
pub fn audit_max_rows_prune_gate_should_run(
    gates: &DashMap<String, AuditMaxRowsPruneGate>,
    namespace: &str,
    max_rows: u64,
    force: bool,
) -> bool {
    if force {
        return true;
    }
    if let Some(mut gate) = gates.get_mut(namespace) {
        return gate.should_run_max_rows_prune(max_rows, false);
    }
    if gates.len() >= AUDIT_MAX_ROWS_PRUNE_GATES_CAP {
        return true;
    }
    let mut gate = gates.entry(namespace.to_string()).or_default();
    gate.should_run_max_rows_prune(max_rows, false)
}

/// Soft-overshoot interval for a configured per-namespace max-row cap.
pub fn audit_retention_max_rows_check_interval(max_rows: u64) -> u64 {
    AUDIT_RETENTION_MAX_ROWS_CHECK_INTERVAL.min(max_rows).max(1)
}

/// True when a prune deleted a full per-call budget and may still have excess.
pub fn audit_retention_hit_prune_batch_budget(deleted: u64) -> bool {
    deleted
        >= AUDIT_RETENTION_PRUNE_BATCH_SIZE
            .saturating_mul(u64::from(AUDIT_RETENTION_PRUNE_MAX_BATCHES))
}

/// Per-namespace audit-event retention policy from env/config.
///
/// Distinct from delivery-loss hardening (#2421): this only bounds durable
/// `audit_events` growth after successful inserts. Unset fields disable that
/// half of the policy. When both are unset, stores skip prune work entirely.
///
/// Max-row retention is a soft cap enforced with a bounded per-instance insert
/// cadence (see [`AuditMaxRowsPruneGate`]); age retention uses strict
/// `ts < cutoff` on every piggybacked prune.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionPolicy {
    /// Delete events older than this many days (strict `ts < cutoff`).
    pub retention_days: Option<u64>,
    /// Soft per-namespace row cap: keep the newest N events by `(ts, id)`,
    /// allowing a documented bounded overshoot between insert-path checks.
    pub max_rows_per_namespace: Option<u64>,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: None,
            max_rows_per_namespace: Some(AUDIT_RETENTION_MAX_ROWS_DEFAULT),
        }
    }
}

impl AuditRetentionPolicy {
    pub fn is_enabled(&self) -> bool {
        self.retention_days.is_some() || self.max_rows_per_namespace.is_some()
    }

    /// Emit one startup log line when a retention policy is active.
    pub fn log_if_enabled(&self) {
        if self.is_enabled() {
            info!(
                retention_days = ?self.retention_days,
                max_rows_per_namespace = ?self.max_rows_per_namespace,
                "Audit event retention policy active"
            );
        }
    }

    /// Validate operator-supplied optional retention knobs.
    pub fn from_parts(
        retention_days: Option<u64>,
        max_rows_per_namespace: Option<u64>,
    ) -> Result<Self, String> {
        if let Some(days) = retention_days {
            if days == 0 {
                return Err(
                    "FERRUM_AUDIT_RETENTION_DAYS must be greater than zero when set".to_string(),
                );
            }
            if days > AUDIT_RETENTION_DAYS_MAX {
                return Err(format!(
                    "FERRUM_AUDIT_RETENTION_DAYS must not exceed {AUDIT_RETENTION_DAYS_MAX}"
                ));
            }
        }
        let max_rows_per_namespace = match max_rows_per_namespace {
            Some(0) => None,
            Some(max_rows) => {
                if max_rows > AUDIT_RETENTION_MAX_ROWS_CAP {
                    return Err(format!(
                        "FERRUM_AUDIT_RETENTION_MAX_ROWS must not exceed \
                         {AUDIT_RETENTION_MAX_ROWS_CAP}"
                    ));
                }
                Some(max_rows)
            }
            None => None,
        };
        Ok(Self {
            retention_days,
            max_rows_per_namespace,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub namespace: String,
    /// Canonical peer/source address for the admin connection. Never derived
    /// from client-spoofable forwarding headers. Empty for legacy mutation
    /// events that predate request-context capture.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_address: String,
    /// Bounded request/correlation ID (client-supplied when valid, otherwise
    /// generated). Empty for legacy mutation events.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// Fixed-cardinality outcome (`success`, `failure`, `denied`,
    /// `validation_failed`, `unavailable`, or `unknown_outcome`). Empty for
    /// legacy mutation events that only recorded successful commits. Set only
    /// through [`AuditEvent::with_outcome`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    pub diff: Value,
}

/// Trustworthy per-request context carried through the admin dispatcher into
/// security-sensitive audit events. Source address is always the socket peer;
/// request IDs are validated/bounded before storage.
#[derive(Debug, Clone)]
pub struct AuditRequestContext {
    pub source_address: String,
    pub request_id: String,
}

impl AuditRequestContext {
    pub fn from_peer_and_headers(peer: IpAddr, headers: &hyper::HeaderMap) -> Self {
        Self {
            source_address: crate::util::client_identity::canonical_ip_string(peer),
            request_id: extract_or_generate_request_id(headers),
        }
    }
}

impl AuditEvent {
    pub fn new(
        actor: &AuditActor,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        namespace: impl Into<String>,
        diff: Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now(),
            actor: actor.sub.clone(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            namespace: namespace.into(),
            source_address: String::new(),
            request_id: String::new(),
            outcome: String::new(),
            diff,
        }
    }

    pub fn with_request_context(mut self, ctx: &AuditRequestContext) -> Self {
        self.source_address = ctx.source_address.clone();
        self.request_id = ctx.request_id.clone();
        self
    }

    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome.as_str().to_string();
        self
    }
}

#[derive(Debug, Clone)]
pub struct AuditActor {
    pub sub: String,
    pub role: AdminRole,
    /// Namespaces authorized by the token's optional `ns` claim. Parsed
    /// fail-closed at authentication time (a malformed claim rejects the
    /// token); only *enforced* against `X-Ferrum-Namespace` when
    /// `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`.
    pub allowed_namespaces: crate::grpc::auth::AllowedNamespaces,
}

impl AuditActor {
    pub fn from_claims(claims: &AdminClaims) -> Result<Self, String> {
        Ok(Self {
            sub: claims.sub.clone(),
            role: claims.admin_role()?,
            allowed_namespaces: claims.allowed_namespaces()?,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditListFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub limit: u32,
    pub offset: u32,
}

// ---------------------------------------------------------------------------
// Delivery target
// ---------------------------------------------------------------------------

/// Terminal sink for a durable audit event.
///
/// Production delivery is [`DatabaseBackend::insert_audit_event`]; the trait
/// exists so queue-saturation, backend-failure, replay, and shutdown behavior
/// can be exercised by external tests without a full database backend. Every
/// implementation must be **insert-only and idempotent on `event.id`**, because
/// replay after a crash or a partial failure re-delivers the same identity and
/// an audit row is immutable.
#[async_trait]
pub trait AuditEventDelivery: Send + Sync {
    async fn deliver(&self, event: &AuditEvent) -> Result<(), anyhow::Error>;
}

struct DatabaseAuditDelivery {
    db: Weak<dyn DatabaseBackend>,
}

#[async_trait]
impl AuditEventDelivery for DatabaseAuditDelivery {
    async fn deliver(&self, event: &AuditEvent) -> Result<(), anyhow::Error> {
        let Some(db) = self.db.upgrade() else {
            return Err(anyhow!("audit delivery backend is no longer available"));
        };
        db.insert_audit_event(event).await
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default durable spool root. Mirrors the chargeback sink's managed-state
/// convention so operators mount one writable state volume.
pub const AUDIT_SPOOL_DIR_DEFAULT: &str = "/var/lib/ferrum/audit-spool";
/// Default bounded in-memory hand-off queue depth.
pub const AUDIT_QUEUE_CAPACITY_DEFAULT: usize = 1024;
/// Accepted range for `FERRUM_ADMIN_AUDIT_QUEUE_CAPACITY`.
pub const AUDIT_QUEUE_CAPACITY_MIN: usize = 1;
pub const AUDIT_QUEUE_CAPACITY_MAX: usize = 65_536;
/// Default durable record ceiling (prepared + pending).
pub const AUDIT_SPOOL_MAX_RECORDS_DEFAULT: u64 = 100_000;
pub const AUDIT_SPOOL_MAX_RECORDS_MAX: u64 = 10_000_000;
/// Default ceiling for retained unrecoverable records.
pub const AUDIT_RETAINED_MAX_RECORDS_DEFAULT: u64 = 10_000;
pub const AUDIT_RETAINED_MAX_RECORDS_MAX: u64 = 1_000_000;
/// Default bounded delivery-attempt budget per event, across restarts.
pub const AUDIT_MAX_DELIVERY_ATTEMPTS_DEFAULT: u32 = 10;
pub const AUDIT_MAX_DELIVERY_ATTEMPTS_MAX: u32 = 1_000;

/// Max characters of a request path retained on an audit intent.
pub const AUDIT_INTENT_PATH_MAX_LEN: usize = 256;
/// Fixed marker substituted for a request path that fails validation. The raw
/// hostile bytes are never stored or logged.
pub const AUDIT_INTENT_PATH_INVALID: &str = "invalid";
/// Fixed resource type recorded on a pre-mutation audit intent.
pub const AUDIT_INTENT_RESOURCE_TYPE: &str = "admin_mutation";

/// First retry delay after a transient delivery failure.
const AUDIT_RETRY_BASE_DELAY_MS: u64 = 250;
/// Ceiling for the exponential retry delay.
const AUDIT_RETRY_MAX_DELAY_MS: u64 = 30_000;
/// Cadence of the durable-spool replay scan.
const AUDIT_REPLAY_INTERVAL_SECONDS: u64 = 30;
/// Records admitted per replay scan so a huge backlog stays incremental and a
/// shutdown signal is still observed promptly.
const AUDIT_REPLAY_BATCH: usize = 256;

/// What the admin write gate does when the audit pipeline cannot durably
/// record events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditUnavailablePolicy {
    /// The mutation proceeds after an explicit warning + counter, and the
    /// pipeline stops claiming durable audit coverage.
    #[default]
    FailOpen,
    /// The mutation is refused with `503` before it is performed.
    FailClosed,
}

impl AuditUnavailablePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditUnavailablePolicy::FailOpen => "fail_open",
            AuditUnavailablePolicy::FailClosed => "fail_closed",
        }
    }

    /// Parse an operator-supplied value. Unknown values fail closed at startup
    /// rather than silently selecting a permissive default.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fail_open" | "fail-open" | "open" => Ok(AuditUnavailablePolicy::FailOpen),
            "fail_closed" | "fail-closed" | "closed" => Ok(AuditUnavailablePolicy::FailClosed),
            _ => Err(
                "FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY must be 'fail_open' or 'fail_closed'"
                    .to_string(),
            ),
        }
    }
}

/// Non-secret identity of the audit destination a durable record targets.
///
/// A record may only be delivered to the destination it was created against, so
/// a reconfigured gateway cannot replay another deployment's evidence into the
/// wrong database or namespace. The connection string is never stored: only the
/// backend type, the namespace, and a SHA-256 digest of the **redacted** URL
/// (credentials already stripped) participate.
pub fn audit_destination_identity(
    db_type: Option<&str>,
    db_url: Option<&str>,
    namespace: &str,
) -> String {
    use crate::fips::approved::Sha256;
    let db_type = db_type.unwrap_or("none");
    let redacted = db_url
        .map(crate::config::db_backend::redact_url)
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(db_type.as_bytes());
    hasher.update(b"|");
    hasher.update(namespace.as_bytes());
    hasher.update(b"|");
    hasher.update(redacted.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{db_type}:{namespace}:{}", &digest[..32])
}

/// Operator-configured audit delivery pipeline settings.
#[derive(Debug, Clone)]
pub struct AuditPipelineConfig {
    pub enabled: bool,
    /// Durable spool root. `None` disables the durable handoff entirely and is
    /// rejected when the policy is `fail_closed`.
    pub spool_dir: Option<PathBuf>,
    pub policy: AuditUnavailablePolicy,
    /// Non-secret destination identity from [`audit_destination_identity`].
    pub destination: String,
    pub queue_capacity: usize,
    pub spool_max_records: u64,
    pub retained_max_records: u64,
    pub max_delivery_attempts: u32,
}

impl Default for AuditPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            spool_dir: Some(PathBuf::from(AUDIT_SPOOL_DIR_DEFAULT)),
            policy: AuditUnavailablePolicy::FailOpen,
            destination: audit_destination_identity(None, None, "ferrum"),
            queue_capacity: AUDIT_QUEUE_CAPACITY_DEFAULT,
            spool_max_records: AUDIT_SPOOL_MAX_RECORDS_DEFAULT,
            retained_max_records: AUDIT_RETAINED_MAX_RECORDS_DEFAULT,
            max_delivery_attempts: AUDIT_MAX_DELIVERY_ATTEMPTS_DEFAULT,
        }
    }
}

impl AuditPipelineConfig {
    /// Validate operator input. Bounds are ranges, not silent truncations: an
    /// out-of-range value is an error at startup.
    pub fn validate(&self) -> Result<(), String> {
        if !(AUDIT_QUEUE_CAPACITY_MIN..=AUDIT_QUEUE_CAPACITY_MAX).contains(&self.queue_capacity) {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_QUEUE_CAPACITY must be between {AUDIT_QUEUE_CAPACITY_MIN} \
                 and {AUDIT_QUEUE_CAPACITY_MAX}"
            ));
        }
        if self.spool_max_records == 0 || self.spool_max_records > AUDIT_SPOOL_MAX_RECORDS_MAX {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_SPOOL_MAX_RECORDS must be between 1 and \
                 {AUDIT_SPOOL_MAX_RECORDS_MAX}"
            ));
        }
        if self.retained_max_records == 0
            || self.retained_max_records > AUDIT_RETAINED_MAX_RECORDS_MAX
        {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_RETAINED_MAX_RECORDS must be between 1 and \
                 {AUDIT_RETAINED_MAX_RECORDS_MAX}"
            ));
        }
        if self.max_delivery_attempts == 0
            || self.max_delivery_attempts > AUDIT_MAX_DELIVERY_ATTEMPTS_MAX
        {
            return Err(format!(
                "FERRUM_ADMIN_AUDIT_MAX_DELIVERY_ATTEMPTS must be between 1 and \
                 {AUDIT_MAX_DELIVERY_ATTEMPTS_MAX}"
            ));
        }
        if self.enabled
            && self.policy == AuditUnavailablePolicy::FailClosed
            && self.spool_dir.is_none()
        {
            return Err(
                "FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_closed requires a durable \
                 FERRUM_ADMIN_AUDIT_SPOOL_DIR"
                    .to_string(),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unavailability reasons and metrics
// ---------------------------------------------------------------------------

/// Closed set of operator-facing pipeline failure reasons.
///
/// Kept as a fixed enum so it is safe both as a Prometheus label value (bounded
/// cardinality) and as a health-surface string (no OS error text, no path, no
/// actor identity, no connection string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditUnavailableReason {
    None = 0,
    SpoolUnavailable = 1,
    SpoolSaturated = 2,
    SpoolIo = 3,
    InvalidRecord = 4,
    CorruptRecord = 5,
    QueueSaturated = 6,
    WorkerUnavailable = 7,
    DeliveryExhausted = 8,
    RetainedCapacity = 9,
    NoDurableSpool = 10,
    DestinationMismatch = 11,
    PrepareFailed = 12,
}

impl AuditUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditUnavailableReason::None => "none",
            AuditUnavailableReason::SpoolUnavailable => "spool_unavailable",
            AuditUnavailableReason::SpoolSaturated => "spool_saturated",
            AuditUnavailableReason::SpoolIo => "spool_io_error",
            AuditUnavailableReason::InvalidRecord => "invalid_record",
            AuditUnavailableReason::CorruptRecord => "corrupt_record",
            AuditUnavailableReason::QueueSaturated => "queue_saturated",
            AuditUnavailableReason::WorkerUnavailable => "worker_unavailable",
            AuditUnavailableReason::DeliveryExhausted => "delivery_exhausted",
            AuditUnavailableReason::RetainedCapacity => "retained_capacity",
            AuditUnavailableReason::NoDurableSpool => "no_durable_spool",
            AuditUnavailableReason::DestinationMismatch => "destination_mismatch",
            AuditUnavailableReason::PrepareFailed => "prepare_failed",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => AuditUnavailableReason::SpoolUnavailable,
            2 => AuditUnavailableReason::SpoolSaturated,
            3 => AuditUnavailableReason::SpoolIo,
            4 => AuditUnavailableReason::InvalidRecord,
            5 => AuditUnavailableReason::CorruptRecord,
            6 => AuditUnavailableReason::QueueSaturated,
            7 => AuditUnavailableReason::WorkerUnavailable,
            8 => AuditUnavailableReason::DeliveryExhausted,
            9 => AuditUnavailableReason::RetainedCapacity,
            10 => AuditUnavailableReason::NoDurableSpool,
            11 => AuditUnavailableReason::DestinationMismatch,
            12 => AuditUnavailableReason::PrepareFailed,
            _ => AuditUnavailableReason::None,
        }
    }

    fn from_spool_error(error: &SpoolError) -> Self {
        match error.kind {
            SpoolErrorKind::Unavailable => AuditUnavailableReason::SpoolUnavailable,
            SpoolErrorKind::Saturated => AuditUnavailableReason::SpoolSaturated,
            SpoolErrorKind::Io => AuditUnavailableReason::SpoolIo,
            SpoolErrorKind::InvalidRecord => AuditUnavailableReason::InvalidRecord,
            SpoolErrorKind::Corrupt => AuditUnavailableReason::CorruptRecord,
            SpoolErrorKind::DestinationMismatch => AuditUnavailableReason::DestinationMismatch,
        }
    }
}

/// Lock-free process-wide audit pipeline counters.
#[derive(Debug, Default)]
pub struct AuditPipelineMetrics {
    accepted: AtomicU64,
    prepared: AtomicU64,
    finalized: AtomicU64,
    unknown_outcome: AtomicU64,
    enqueued: AtomicU64,
    delivered: AtomicU64,
    retries: AtomicU64,
    delivery_failures: AtomicU64,
    retained: AtomicU64,
    replayed: AtomicU64,
    corrupt: AtomicU64,
    destination_mismatch: AtomicU64,
    truncated_diffs: AtomicU64,
    dropped_handoff: AtomicU64,
    dropped_no_spool: AtomicU64,
    dropped_retained_capacity: AtomicU64,
    fail_open_unaudited: AtomicU64,
    fail_closed_rejections: AtomicU64,
    queue_depth: AtomicU64,
    delivery_in_flight: AtomicU64,
    spool_prepared: AtomicU64,
    spool_pending: AtomicU64,
    spool_retained: AtomicU64,
}

/// Point-in-time counters for `/health`, `/status`, and `/metrics`.
///
/// Counts and static reason labels only — never an actor subject, a token, a
/// request body, a diff, a connection string, or a filesystem path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AuditPipelineMetricsSnapshot {
    pub accepted_total: u64,
    pub prepared_total: u64,
    pub finalized_total: u64,
    pub unknown_outcome_total: u64,
    pub enqueued_total: u64,
    pub delivered_total: u64,
    pub retries_total: u64,
    pub delivery_failures_total: u64,
    pub retained_total: u64,
    pub replayed_total: u64,
    pub corrupt_records_total: u64,
    pub destination_mismatch_total: u64,
    pub truncated_diffs_total: u64,
    pub dropped_durable_handoff_failed_total: u64,
    pub dropped_no_durable_spool_total: u64,
    pub dropped_retained_capacity_total: u64,
    pub fail_open_unaudited_mutations_total: u64,
    pub fail_closed_rejections_total: u64,
    pub queue_depth: u64,
    pub delivery_in_flight: u64,
    pub spool_prepared_records: u64,
    pub spool_pending_records: u64,
    pub spool_retained_records: u64,
}

/// Saturating decrement for a gauge that several tasks adjust concurrently.
fn saturating_decrement(gauge: &AtomicU64) {
    let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

impl AuditPipelineMetrics {
    pub fn snapshot(&self) -> AuditPipelineMetricsSnapshot {
        AuditPipelineMetricsSnapshot {
            accepted_total: self.accepted.load(Ordering::Relaxed),
            prepared_total: self.prepared.load(Ordering::Relaxed),
            finalized_total: self.finalized.load(Ordering::Relaxed),
            unknown_outcome_total: self.unknown_outcome.load(Ordering::Relaxed),
            enqueued_total: self.enqueued.load(Ordering::Relaxed),
            delivered_total: self.delivered.load(Ordering::Relaxed),
            retries_total: self.retries.load(Ordering::Relaxed),
            delivery_failures_total: self.delivery_failures.load(Ordering::Relaxed),
            retained_total: self.retained.load(Ordering::Relaxed),
            replayed_total: self.replayed.load(Ordering::Relaxed),
            corrupt_records_total: self.corrupt.load(Ordering::Relaxed),
            destination_mismatch_total: self.destination_mismatch.load(Ordering::Relaxed),
            truncated_diffs_total: self.truncated_diffs.load(Ordering::Relaxed),
            dropped_durable_handoff_failed_total: self.dropped_handoff.load(Ordering::Relaxed),
            dropped_no_durable_spool_total: self.dropped_no_spool.load(Ordering::Relaxed),
            dropped_retained_capacity_total: self.dropped_retained_capacity.load(Ordering::Relaxed),
            fail_open_unaudited_mutations_total: self.fail_open_unaudited.load(Ordering::Relaxed),
            fail_closed_rejections_total: self.fail_closed_rejections.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            delivery_in_flight: self.delivery_in_flight.load(Ordering::Relaxed),
            spool_prepared_records: self.spool_prepared.load(Ordering::Relaxed),
            spool_pending_records: self.spool_pending.load(Ordering::Relaxed),
            spool_retained_records: self.spool_retained.load(Ordering::Relaxed),
        }
    }
}

/// Durability mode actually in force, independent of what was configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDurabilityMode {
    /// Intents are fsynced before the mutation and finalized after it.
    Spool,
    /// No usable spool: bounded in-memory queue only, with no crash coverage.
    Memory,
    /// Auditing is disabled.
    Disabled,
}

impl AuditDurabilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditDurabilityMode::Spool => "spool",
            AuditDurabilityMode::Memory => "memory",
            AuditDurabilityMode::Disabled => "disabled",
        }
    }
}

/// Health/status projection of pipeline state.
#[derive(Debug, Clone, Serialize)]
pub struct AuditPipelineStatus {
    pub enabled: bool,
    pub durability: &'static str,
    pub policy: &'static str,
    /// Whether a committed mutation can be durably audited right now. Drives
    /// the `fail_closed` write gate.
    pub available: bool,
    pub last_unavailable_reason: &'static str,
    /// Sticky evidence that records were corrupted, retained as unrecoverable,
    /// or discarded for capacity. A later successful delivery does not clear
    /// this; only resolving the retained evidence does.
    pub degraded: bool,
    pub degraded_reason: &'static str,
    /// True once evidence has been permanently discarded. Never clears.
    pub evidence_lost: bool,
    pub queue_capacity: u64,
    pub spool_max_records: u64,
    pub retained_max_records: u64,
    pub max_delivery_attempts: u32,
    #[serde(flatten)]
    pub metrics: AuditPipelineMetricsSnapshot,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Process-wide durable audit pipeline state: configuration, spool handle,
/// counters, and the availability flag the admin write gate reads.
#[derive(Debug)]
pub struct AuditPipeline {
    config: AuditPipelineConfig,
    /// Unique identity of this process generation. Owns its spool instance
    /// directory so no other process can classify its in-flight records.
    generation: String,
    spool: Option<Arc<AuditSpool>>,
    metrics: Arc<AuditPipelineMetrics>,
    /// `None` means durable admission is available; every other value is the
    /// exact reason the fail-closed gate must refuse the next audited mutation.
    /// One atomic keeps the availability bit and reason from contradicting one
    /// another in health snapshots.
    last_unavailable_reason: AtomicU8,
    /// Sticky degradation, deliberately *not* cleared by a later delivery.
    degraded_reason: AtomicU8,
    evidence_lost: AtomicBool,
    draining: AtomicBool,
    /// Cancellation signal for every waiting delivery/replay task.
    cancel: Notify,
}

impl AuditPipeline {
    /// Build a pipeline, preparing the durable spool when one is configured.
    ///
    /// A spool that cannot be prepared is fatal under `fail_closed` and
    /// degrades to memory-only under `fail_open` (loudly, and visible on
    /// `/health` and `/metrics`).
    pub fn new(config: AuditPipelineConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(AuditPipelineMetrics::default());
        let generation = Uuid::new_v4().to_string();
        let mut spool = None;
        let mut reason = AuditUnavailableReason::None;

        if config.enabled
            && let Some(dir) = config.spool_dir.as_ref()
        {
            match AuditSpool::open(
                dir.clone(),
                generation.clone(),
                config.destination.clone(),
                config.spool_max_records,
                config.retained_max_records,
            ) {
                Ok(prepared) => spool = Some(Arc::new(prepared)),
                Err(error) => {
                    if config.policy == AuditUnavailablePolicy::FailClosed {
                        return Err(format!(
                            "admin audit spool could not be prepared ({}) and \
                             FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_closed",
                            error.reason()
                        ));
                    }
                    reason = AuditUnavailableReason::from_spool_error(&error);
                    error!(
                        surface = "audit_spool_open",
                        reason = error.reason(),
                        "Admin audit durable spool is unusable; audit delivery is memory-only \
                         until the spool directory is writable"
                    );
                }
            }
        } else if config.enabled {
            reason = AuditUnavailableReason::NoDurableSpool;
            warn!(
                surface = "audit_spool_disabled",
                "Admin audit durable spool is disabled; committed mutations can lose audit \
                 events across a crash"
            );
        }

        let pipeline = Self {
            config,
            generation,
            spool,
            metrics,
            last_unavailable_reason: AtomicU8::new(reason as u8),
            degraded_reason: AtomicU8::new(AuditUnavailableReason::None as u8),
            evidence_lost: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            cancel: Notify::new(),
        };
        pipeline.refresh_spool_gauges();
        Ok(pipeline)
    }

    /// Raw counters. Used by external tests; the binary target otherwise flags
    /// it as dead code.
    #[allow(dead_code)]
    pub fn metrics(&self) -> &Arc<AuditPipelineMetrics> {
        &self.metrics
    }

    /// This process generation's spool ownership identity.
    #[allow(dead_code)]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Non-secret audit destination identity bound to every durable record.
    #[allow(dead_code)]
    pub fn destination(&self) -> &str {
        &self.config.destination
    }

    /// This generation's durable spool, when one is configured.
    ///
    /// Callers must not perform filesystem work through it on an admin request
    /// path: the observability surfaces read [`Self::status`] instead, which is
    /// O(1). Used by the delivery worker and by external tests.
    #[allow(dead_code)]
    pub fn spool(&self) -> Option<&Arc<AuditSpool>> {
        self.spool.as_ref()
    }

    pub fn durability_mode(&self) -> AuditDurabilityMode {
        if !self.config.enabled {
            AuditDurabilityMode::Disabled
        } else if self.spool.is_some() {
            AuditDurabilityMode::Spool
        } else {
            AuditDurabilityMode::Memory
        }
    }

    /// True when a committed mutation can still be durably audited.
    pub fn is_available(&self) -> bool {
        !self.config.enabled
            || self.last_unavailable_reason.load(Ordering::Acquire)
                == AuditUnavailableReason::None as u8
    }

    pub fn last_unavailable_reason(&self) -> AuditUnavailableReason {
        AuditUnavailableReason::from_u8(self.last_unavailable_reason.load(Ordering::Relaxed))
    }

    pub fn degraded_reason(&self) -> AuditUnavailableReason {
        AuditUnavailableReason::from_u8(self.degraded_reason.load(Ordering::Relaxed))
    }

    /// Sticky evidence-integrity degradation.
    pub fn is_degraded(&self) -> bool {
        self.degraded_reason() != AuditUnavailableReason::None
    }

    fn mark_unavailable(&self, reason: AuditUnavailableReason) {
        self.last_unavailable_reason
            .store(reason as u8, Ordering::Release);
    }

    /// Record sticky evidence damage.
    ///
    /// Deliberately independent of [`Self::mark_available`]: a later successful
    /// delivery of *another* record says nothing about the corrupt, retained,
    /// or discarded evidence this flag stands for. The first reason wins so the
    /// operator sees the original cause rather than the most recent one.
    fn mark_degraded(&self, reason: AuditUnavailableReason) {
        let _ = self.degraded_reason.compare_exchange(
            AuditUnavailableReason::None as u8,
            reason as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Clear sticky degradation once the underlying evidence is actually gone.
    ///
    /// Only the background reconciler calls this, and only when retention is
    /// empty and nothing was ever permanently discarded. A capacity discard is
    /// real evidence loss and can never be resolved by later activity.
    fn clear_degraded_if_resolved(&self) {
        if self.evidence_lost.load(Ordering::Relaxed) {
            return;
        }
        if self.metrics.spool_retained.load(Ordering::Relaxed) != 0 {
            return;
        }
        self.degraded_reason
            .store(AuditUnavailableReason::None as u8, Ordering::Relaxed);
    }

    /// Restore availability after a successful durable prepare.
    ///
    /// Memory-only mode never becomes "available": there is no durable handoff
    /// to recover, so a delivered event must not paper over the fact that a
    /// crash can still lose committed mutations' audit events. Sticky
    /// degradation is untouched here by design.
    fn mark_available(&self) {
        if self.spool.is_none() && self.config.enabled {
            return;
        }
        self.last_unavailable_reason
            .store(AuditUnavailableReason::None as u8, Ordering::Release);
    }

    /// Finalization proves the spool is writable but does not free a record
    /// slot: prepared evidence merely becomes pending evidence. It can recover
    /// an I/O failure, but never a saturation failure.
    fn mark_available_after_finalize(&self) {
        let observed = self.last_unavailable_reason.load(Ordering::Acquire);
        if observed == AuditUnavailableReason::SpoolSaturated as u8
            || observed == AuditUnavailableReason::NoDurableSpool as u8
        {
            return;
        }
        let _ = self.last_unavailable_reason.compare_exchange(
            observed,
            AuditUnavailableReason::None as u8,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    /// Delivery or retention removes a pending record and therefore resolves
    /// an observed pending-capacity failure. It must not clear an unrelated
    /// spool I/O failure.
    fn mark_capacity_available(&self) {
        let _ = self.last_unavailable_reason.compare_exchange(
            AuditUnavailableReason::SpoolSaturated as u8,
            AuditUnavailableReason::None as u8,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    /// Whether the admin write gate must refuse audited mutations right now.
    ///
    /// Observationally pure: `/health` calls the same gate, so counting a
    /// rejection here would inflate the counter on every probe. Real admission
    /// attempts call [`Self::note_fail_closed_rejection`] instead.
    pub fn fail_closed_block_reason(&self) -> Option<&'static str> {
        if self.config.policy != AuditUnavailablePolicy::FailClosed || self.is_available() {
            return None;
        }
        Some(self.last_unavailable_reason().as_str())
    }

    /// Count one refused admin mutation. Called only from the admission paths.
    pub fn note_fail_closed_rejection(&self) {
        if self.fail_closed_block_reason().is_some() {
            self.metrics
                .fail_closed_rejections
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Copy the spool's O(1) counters into the exported gauges.
    ///
    /// This is itself O(1): [`AuditSpool::stats`] reads atomics. The spool's
    /// counters are reconciled against disk only by the background worker.
    fn refresh_spool_gauges(&self) {
        let Some(spool) = self.spool.as_ref() else {
            return;
        };
        let stats = spool.stats();
        self.metrics
            .spool_prepared
            .store(stats.prepared_records, Ordering::Relaxed);
        self.metrics
            .spool_pending
            .store(stats.pending_records, Ordering::Relaxed);
        self.metrics
            .spool_retained
            .store(stats.retained_records, Ordering::Relaxed);
    }

    pub fn status(&self) -> AuditPipelineStatus {
        self.refresh_spool_gauges();
        AuditPipelineStatus {
            enabled: self.config.enabled,
            durability: self.durability_mode().as_str(),
            policy: self.config.policy.as_str(),
            available: self.is_available(),
            last_unavailable_reason: self.last_unavailable_reason().as_str(),
            degraded: self.is_degraded(),
            degraded_reason: self.degraded_reason().as_str(),
            evidence_lost: self.evidence_lost.load(Ordering::Relaxed),
            queue_capacity: self.config.queue_capacity as u64,
            spool_max_records: self.config.spool_max_records,
            retained_max_records: self.config.retained_max_records,
            max_delivery_attempts: self.config.max_delivery_attempts,
            metrics: self.metrics.snapshot(),
        }
    }

    fn build_record(&self, event: AuditEvent, finalized: bool) -> SpooledAuditRecord {
        let max_bytes = self
            .spool
            .as_ref()
            .map(|spool| spool.max_record_bytes())
            .unwrap_or(crate::admin::audit_spool::AUDIT_SPOOL_MAX_RECORD_BYTES);
        let record = SpooledAuditRecord::with_bounded_diff(
            event,
            &self.config.destination,
            &self.generation,
            finalized,
            max_bytes,
        );
        if record.diff_omitted {
            self.metrics.truncated_diffs.fetch_add(1, Ordering::Relaxed);
        }
        record
    }

    /// Durably create a pre-mutation audit intent.
    ///
    /// Returns the stable event id that the matching finalize must reuse.
    pub fn prepare_intent(&self, event: AuditEvent) -> Result<String, AuditUnavailableReason> {
        let record = self.build_record(event, /* finalized */ false);
        let id = record.id().to_string();
        let Some(spool) = self.spool.as_ref() else {
            return Err(AuditUnavailableReason::NoDurableSpool);
        };
        match spool.prepare(&record) {
            Ok(()) => {
                self.metrics.prepared.fetch_add(1, Ordering::Relaxed);
                self.refresh_spool_gauges();
                self.mark_available();
                Ok(id)
            }
            Err(error) => {
                let reason = AuditUnavailableReason::from_spool_error(&error);
                self.metrics.dropped_handoff.fetch_add(1, Ordering::Relaxed);
                self.mark_unavailable(reason);
                Err(reason)
            }
        }
    }

    /// Durably finalize an event with its now-known outcome.
    ///
    /// Returns the record so the caller can hand it to a delivery worker. In
    /// memory-only mode nothing is durable, so the record is returned unwritten
    /// and the drop accounting happens at enqueue/retry-exhaustion instead.
    pub fn finalize_event(
        &self,
        event: AuditEvent,
    ) -> Result<SpooledAuditRecord, AuditUnavailableReason> {
        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        let record = self.build_record(event, /* finalized */ true);
        let Some(spool) = self.spool.as_ref() else {
            return Ok(record);
        };
        match spool.finalize(&record) {
            Ok(()) => {
                self.metrics.finalized.fetch_add(1, Ordering::Relaxed);
                self.refresh_spool_gauges();
                self.mark_available_after_finalize();
                Ok(record)
            }
            Err(error) => {
                let reason = AuditUnavailableReason::from_spool_error(&error);
                self.metrics.dropped_handoff.fetch_add(1, Ordering::Relaxed);
                self.mark_unavailable(reason);
                Err(reason)
            }
        }
    }

    /// Finish one event: remove it from the spool after acceptance.
    ///
    /// Blocking filesystem work (unlink + directory fsync). Callers run it on
    /// the blocking pool through `settle_delivered`.
    fn note_delivered(&self, event_id: &str) {
        self.metrics.delivered.fetch_add(1, Ordering::Relaxed);
        if let Some(spool) = self.spool.as_ref() {
            if spool.remove_pending(event_id).is_err() {
                // The record stays durable and will be replayed; a duplicate
                // insert is a no-op because delivery is idempotent on the id.
                warn!(
                    audit_event_id = %event_id,
                    surface = "audit_spool_remove",
                    "Delivered admin audit event could not be removed from the spool; it will \
                     be replayed idempotently"
                );
            } else {
                self.mark_capacity_available();
            }
            self.refresh_spool_gauges();
        }
    }

    /// Move an event that exhausted its retry budget into operator-visible
    /// retention. Never silently deletes while retention capacity remains.
    ///
    /// Blocking filesystem work (rename + directory fsyncs). Callers run it on
    /// the blocking pool through `settle_unrecoverable`.
    fn note_unrecoverable(&self, event_id: &str) {
        let Some(spool) = self.spool.as_ref() else {
            self.mark_degraded(AuditUnavailableReason::DeliveryExhausted);
            self.metrics
                .dropped_no_spool
                .fetch_add(1, Ordering::Relaxed);
            self.evidence_lost.store(true, Ordering::Relaxed);
            error!(
                audit_event_id = %event_id,
                surface = "audit_event_unrecoverable",
                reason = AuditUnavailableReason::DeliveryExhausted.as_str(),
                "Admin audit event exhausted delivery retries with no durable spool configured"
            );
            return;
        };
        let outcome = spool.retain_unrecoverable(event_id);
        if !matches!(outcome, Ok(RetainOutcome::AlreadySettled)) {
            // Sticky degradation is first-reason-wins, so raise the cause the
            // caller observed before any more specific escalation below.
            self.mark_degraded(AuditUnavailableReason::DeliveryExhausted);
        }
        match outcome {
            Ok(RetainOutcome::AlreadySettled) => {
                // Another delivery attempt for this stable id already succeeded
                // and removed the record. Nothing was retained and nothing was
                // lost, so this must not latch sticky degraded/evidence-lost
                // health for evidence that is in fact in the backend.
                self.mark_capacity_available();
            }
            Ok(RetainOutcome::Retained) => {
                self.metrics.retained.fetch_add(1, Ordering::Relaxed);
                self.mark_capacity_available();
                error!(
                    audit_event_id = %event_id,
                    surface = "audit_event_unrecoverable",
                    reason = AuditUnavailableReason::DeliveryExhausted.as_str(),
                    "Admin audit event exhausted delivery retries and was retained for operator \
                     remediation"
                );
            }
            Ok(RetainOutcome::AlreadyRetained) => {
                // Another exhausted attempt already retained this stable id.
                // Preserve degraded health, but do not count one retained
                // record more than once.
                self.mark_capacity_available();
            }
            Ok(RetainOutcome::Discarded) => {
                self.mark_capacity_available();
                self.metrics
                    .dropped_retained_capacity
                    .fetch_add(1, Ordering::Relaxed);
                self.evidence_lost.store(true, Ordering::Relaxed);
                self.mark_degraded(AuditUnavailableReason::RetainedCapacity);
                error!(
                    audit_event_id = %event_id,
                    surface = "audit_event_unrecoverable",
                    reason = AuditUnavailableReason::RetainedCapacity.as_str(),
                    "Admin audit retained-record capacity is exhausted; the newest unrecoverable \
                     event was discarded to preserve older evidence"
                );
            }
            Err(error) => {
                self.mark_unavailable(AuditUnavailableReason::from_spool_error(&error));
                self.mark_degraded(AuditUnavailableReason::from_spool_error(&error));
                error!(
                    audit_event_id = %event_id,
                    surface = "audit_event_unrecoverable",
                    reason = error.reason(),
                    "Admin audit event could not be moved into retained state"
                );
            }
        }
        self.refresh_spool_gauges();
    }

    /// Account for a memory-only record whose retry wait was interrupted by
    /// shutdown. It cannot be deferred to a later process and was never placed
    /// in retained storage, so report a real drop rather than inflating the
    /// retained counter.
    fn note_shutdown_memory_loss(&self, record: &SpooledAuditRecord) {
        self.metrics
            .dropped_no_spool
            .fetch_add(1, Ordering::Relaxed);
        self.mark_unavailable(AuditUnavailableReason::NoDurableSpool);
        self.evidence_lost.store(true, Ordering::Relaxed);
        self.mark_degraded(AuditUnavailableReason::NoDurableSpool);
        error!(
            audit_event_id = %record.id(),
            surface = "audit_shutdown",
            reason = AuditUnavailableReason::NoDurableSpool.as_str(),
            "Admin audit shutdown interrupted delivery of a memory-only event; the event \
             cannot survive process exit"
        );
    }

    /// Account for a finalized memory-only record that could not enter a live
    /// delivery queue. The event has no durable representation, so returning a
    /// successful handoff would be a silent audit gap.
    fn note_memory_enqueue_loss(
        &self,
        reason: AuditUnavailableReason,
        event_id: &str,
    ) -> Result<(), anyhow::Error> {
        self.metrics
            .dropped_no_spool
            .fetch_add(1, Ordering::Relaxed);
        self.mark_unavailable(reason);
        self.evidence_lost.store(true, Ordering::Relaxed);
        self.mark_degraded(AuditUnavailableReason::NoDurableSpool);
        Err(anyhow!(
            "admin audit event {} was not enqueued ({})",
            event_id,
            reason.as_str()
        ))
    }

    /// Adopt records abandoned by prior process generations.
    ///
    /// Blocking filesystem work: callers run it on the blocking pool. Prepared
    /// records become `unknown_outcome` evidence; foreign-destination records
    /// are quarantined rather than misdelivered.
    pub fn claim_abandoned(&self) {
        let Some(spool) = self.spool.as_ref() else {
            return;
        };
        let report = spool.claim_abandoned();
        if report.unknown_outcome > 0 {
            self.metrics
                .unknown_outcome
                .fetch_add(report.unknown_outcome, Ordering::Relaxed);
            warn!(
                surface = "audit_spool_claim",
                unknown_outcome = report.unknown_outcome,
                "Adopted admin audit intents from a prior process generation; their mutation \
                 outcome is unknowable and is recorded as unknown_outcome"
            );
        }
        if report.corrupt > 0 {
            self.metrics
                .corrupt
                .fetch_add(report.corrupt, Ordering::Relaxed);
            self.mark_degraded(AuditUnavailableReason::CorruptRecord);
        }
        if report.destination_mismatch > 0 {
            self.metrics
                .destination_mismatch
                .fetch_add(report.destination_mismatch, Ordering::Relaxed);
            self.mark_degraded(AuditUnavailableReason::DestinationMismatch);
            error!(
                surface = "audit_spool_claim",
                reason = AuditUnavailableReason::DestinationMismatch.as_str(),
                records = report.destination_mismatch,
                "Durable admin audit records target a different audit destination and were \
                 quarantined instead of delivered"
            );
        }
        if report.capacity_discarded > 0 {
            self.metrics
                .dropped_retained_capacity
                .fetch_add(report.capacity_discarded, Ordering::Relaxed);
            self.evidence_lost.store(true, Ordering::Relaxed);
            self.mark_degraded(AuditUnavailableReason::RetainedCapacity);
        }
        spool.resync_counts();
        self.refresh_spool_gauges();
    }

    /// Background reconciliation of the O(1) gauges against disk.
    pub fn reconcile(&self) {
        if let Some(spool) = self.spool.as_ref() {
            spool.resync_counts();
            let stats = spool.stats();
            if stats.prepared_records.saturating_add(stats.pending_records)
                < self.config.spool_max_records
            {
                self.mark_capacity_available();
            }
        }
        self.refresh_spool_gauges();
        self.clear_degraded_if_resolved();
    }
}

// ---------------------------------------------------------------------------
// Global pipeline installation
// ---------------------------------------------------------------------------

static AUDIT_PIPELINE: OnceLock<Arc<AuditPipeline>> = OnceLock::new();

static DISABLED_PIPELINE: LazyLock<Arc<AuditPipeline>> = LazyLock::new(|| {
    // Non-serving callers (tests, tooling) that never called `initialize` see a
    // disabled pipeline rather than an implicit spool on the local filesystem.
    Arc::new(AuditPipeline {
        config: AuditPipelineConfig {
            enabled: false,
            spool_dir: None,
            ..AuditPipelineConfig::default()
        },
        generation: Uuid::new_v4().to_string(),
        spool: None,
        metrics: Arc::new(AuditPipelineMetrics::default()),
        last_unavailable_reason: AtomicU8::new(AuditUnavailableReason::None as u8),
        degraded_reason: AtomicU8::new(AuditUnavailableReason::None as u8),
        evidence_lost: AtomicBool::new(false),
        draining: AtomicBool::new(false),
        cancel: Notify::new(),
    })
});

/// Install the process audit pipeline. Called once from `main` before mode
/// dispatch, so a fail-closed deployment refuses to start with an unusable
/// spool rather than discovering it on the first mutation.
pub fn initialize(config: AuditPipelineConfig) -> Result<(), String> {
    let pipeline = Arc::new(AuditPipeline::new(config)?);
    if pipeline.config.enabled {
        info!(
            durability = pipeline.durability_mode().as_str(),
            policy = pipeline.config.policy.as_str(),
            queue_capacity = pipeline.config.queue_capacity,
            spool_max_records = pipeline.config.spool_max_records,
            retained_max_records = pipeline.config.retained_max_records,
            max_delivery_attempts = pipeline.config.max_delivery_attempts,
            "Admin audit delivery pipeline active"
        );
    }
    // A second install in one process (in-process harnesses) keeps the first
    // pipeline rather than orphaning workers that already hold its spool.
    let _ = AUDIT_PIPELINE.set(pipeline);
    Ok(())
}

/// The installed pipeline, or a disabled one when `initialize` never ran.
pub fn pipeline() -> Arc<AuditPipeline> {
    AUDIT_PIPELINE
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::clone(&DISABLED_PIPELINE))
}

/// Reason the admin write gate must refuse an audited mutation, if any.
/// Pure: safe to call from `/health` as well as from the admission path.
pub fn fail_closed_block_reason() -> Option<&'static str> {
    pipeline().fail_closed_block_reason()
}

/// Count one admin mutation refused by the fail-closed policy.
pub fn note_fail_closed_rejection() {
    pipeline().note_fail_closed_rejection();
}

/// Sanitized request fields for read-only rejection logging.
///
/// Returns `None` outside an active admin request scope. Admission paths are
/// always scoped, so observe-only gates never call this.
pub fn read_only_rejection_log_context() -> Option<(String, String, String)> {
    let slot = current_slot()?;
    slot.with(|inner| {
        (
            inner.method.clone(),
            inner.path.clone(),
            inner.namespace.clone(),
        )
    })
}

/// Cheap availability check for callers that must not pay a backlog rescan
/// (notably the unauthenticated `/health` tier). O(1): one atomic load.
pub fn pipeline_available() -> bool {
    pipeline().is_available()
}

/// Sticky evidence-integrity degradation. O(1).
pub fn pipeline_degraded() -> bool {
    pipeline().is_degraded()
}

/// Health/status projection of the installed pipeline. O(1): atomics only.
pub fn pipeline_status() -> AuditPipelineStatus {
    pipeline().status()
}

/// Counter snapshot for the Prometheus exposition. O(1): atomics only.
pub fn pipeline_metrics_snapshot() -> AuditPipelineMetricsSnapshot {
    let pipeline = pipeline();
    pipeline.refresh_spool_gauges();
    pipeline.metrics.snapshot()
}

// ---------------------------------------------------------------------------
// Per-request audit intent
// ---------------------------------------------------------------------------

/// The prepared, not yet finalized intent for the in-flight admin request.
#[derive(Debug, Clone)]
struct PreparedIntent {
    id: String,
    action: String,
    resource_id: String,
}

#[derive(Debug, Default)]
struct AuditRequestSlotInner {
    method: String,
    path: String,
    namespace: String,
    actor: Option<String>,
    source_address: String,
    request_id: String,
    prepared: Option<PreparedIntent>,
}

/// Per-request audit state carried through the admin dispatcher.
///
/// The dispatcher scopes one of these around every admin request. It is
/// populated with the trustworthy request context after authentication and
/// consumed by the write gate (which prepares the durable intent) and by
/// [`record`] (which finalizes it).
#[derive(Debug, Default)]
pub struct AuditRequestSlot {
    inner: Mutex<AuditRequestSlotInner>,
    /// A cancellation-safe settlement task owns finalization once true. The
    /// parent request must then leave the prepared intent alone if it is
    /// cancelled while that task continues.
    cancellation_transferred: AtomicBool,
    /// The request scope disappeared before a settlement task took ownership.
    /// A detached prepare task checks this after its blocking fsync completes,
    /// closing the race where cancellation observed an empty slot immediately
    /// before that task installed the now-durable intent.
    scope_cancelled_without_settlement_owner: AtomicBool,
}

impl AuditRequestSlot {
    fn with<T>(&self, f: impl FnOnce(&mut AuditRequestSlotInner) -> T) -> Option<T> {
        // A poisoned slot means another task panicked mid-request. Treat it as
        // "no intent" rather than propagating a panic onto the admin path.
        self.inner.lock().ok().map(|mut guard| f(&mut guard))
    }
}

tokio::task_local! {
    static AUDIT_REQUEST_SLOT: Arc<AuditRequestSlot>;
}

/// Sanitize a request path for durable storage.
///
/// Only a conservative printable allow-list is accepted, bounded by
/// [`AUDIT_INTENT_PATH_MAX_LEN`]. Anything else collapses to a fixed marker —
/// the hostile bytes are never stored, logged, or echoed.
pub fn sanitize_audit_path(path: &str) -> String {
    if path.is_empty() || path.len() > AUDIT_INTENT_PATH_MAX_LEN {
        return AUDIT_INTENT_PATH_INVALID.to_string();
    }
    let safe = path.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' | b':' | b'~'
        )
    });
    if safe && !path.contains("..") {
        path.to_string()
    } else {
        AUDIT_INTENT_PATH_INVALID.to_string()
    }
}

/// Sanitize an `X-Ferrum-Namespace` value for durable storage.
pub fn sanitize_audit_namespace(namespace: &str) -> String {
    if namespace.is_empty() || namespace.len() > 128 {
        return BACKUP_NAMESPACE_STATUS_INVALID.to_string();
    }
    let safe = namespace
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
    if safe {
        namespace.to_string()
    } else {
        BACKUP_NAMESPACE_STATUS_INVALID.to_string()
    }
}

/// Create the per-request audit slot for one admin request.
pub fn new_request_slot(method: &str, path: &str, namespace: &str) -> Arc<AuditRequestSlot> {
    let slot = Arc::new(AuditRequestSlot::default());
    slot.with(|inner| {
        inner.method = method.to_string();
        inner.path = sanitize_audit_path(path);
        inner.namespace = sanitize_audit_namespace(namespace);
    });
    slot
}

struct AuditScopeCompletion {
    slot: Arc<AuditRequestSlot>,
    completed: bool,
    owns_transferred_cancellation: bool,
}

impl Drop for AuditScopeCompletion {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if !self.owns_transferred_cancellation
            && self.slot.cancellation_transferred.load(Ordering::Acquire)
        {
            return;
        }
        self.slot
            .scope_cancelled_without_settlement_owner
            .store(true, Ordering::Release);
        let slot = Arc::clone(&self.slot);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // The prepared record remains durable and will be claimed as an
            // unknown outcome by the next process generation.
            return;
        };
        // Drop detaches only this tiny cancellation finalizer; its durable
        // input already exists on disk, so runtime shutdown still leaves the
        // next process able to adopt it.
        std::mem::drop(runtime.spawn(async move {
            finalize_unconsumed_intent_with_evidence(
                &slot,
                AuditOutcome::UnknownOutcome,
                "request_task_cancelled_before_outcome_was_observed",
                None,
            )
            .await;
        }));
    }
}

/// Run `future` with `slot` installed as the current request's audit slot.
pub async fn scope_request<F: std::future::Future>(
    slot: Arc<AuditRequestSlot>,
    future: F,
) -> F::Output {
    scope_request_with_cancellation_ownership(slot, future, false).await
}

async fn scope_request_with_cancellation_ownership<F: std::future::Future>(
    slot: Arc<AuditRequestSlot>,
    future: F,
    owns_transferred_cancellation: bool,
) -> F::Output {
    let mut completion = AuditScopeCompletion {
        slot: Arc::clone(&slot),
        completed: false,
        owns_transferred_cancellation,
    };
    let output = AUDIT_REQUEST_SLOT.scope(slot, future).await;
    completion.completed = true;
    output
}

/// Spawn mutation-owned work with the current request's audit slot installed.
///
/// Tokio task-local state is not inherited by `tokio::spawn`. Admin CRUD and
/// API-spec persistence deliberately outlive cancellation of the request task,
/// so they must carry this slot explicitly or their successful audit event
/// cannot adopt the pre-mutation intent's stable id.
pub fn spawn_with_request_slot<F>(future: F) -> JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let slot = current_slot();
    if let Some(slot) = slot.as_ref() {
        // Transfer cancellation responsibility before spawning so the parent
        // cannot race task scheduling and finalize the same intent first.
        slot.cancellation_transferred.store(true, Ordering::Release);
    }
    tokio::spawn(async move {
        match slot {
            Some(slot) => {
                let output =
                    scope_request_with_cancellation_ownership(Arc::clone(&slot), future, true)
                        .await;
                // The parent request can be cancelled while this settlement
                // task intentionally keeps running. If persistence did not
                // emit a detailed success event, finalize the intent here as a
                // failed persistence attempt so it cannot remain stranded in
                // a live generation forever.
                finalize_unconsumed_intent_with_evidence(
                    &slot,
                    AuditOutcome::Failure,
                    "spawned_mutation_persistence_did_not_emit_success_event",
                    None,
                )
                .await;
                output
            }
            None => future.await,
        }
    })
}

fn current_slot() -> Option<Arc<AuditRequestSlot>> {
    AUDIT_REQUEST_SLOT.try_with(Arc::clone).ok()
}

/// Attach the authenticated actor and trustworthy request context to the
/// current request's audit slot. Called once, after JWT verification.
pub fn note_request_actor(actor: &AuditActor, ctx: &AuditRequestContext) {
    let Some(slot) = current_slot() else {
        return;
    };
    slot.with(|inner| {
        inner.actor = Some(actor.sub.clone());
        inner.source_address = ctx.source_address.clone();
        inner.request_id = ctx.request_id.clone();
    });
}

/// Run a blocking intent prepare in a detached settlement task.
///
/// Dropping a Tokio join handle does not cancel its `spawn_blocking` work. The
/// task therefore installs the prepared id into the request slot itself, rather
/// than asking the possibly-cancelled caller to do so after the await. If the
/// request scope disappeared while the fsync was in flight, the same task
/// immediately finalizes the intent as `unknown_outcome`; it cannot remain
/// stranded under a still-live process generation until restart.
pub(crate) async fn prepare_request_intent_cancellation_safe<F>(
    pipeline: Arc<AuditPipeline>,
    slot: Arc<AuditRequestSlot>,
    action: String,
    resource_id: String,
    prepare: F,
) -> Result<String, AuditUnavailableReason>
where
    F: FnOnce() -> Result<String, AuditUnavailableReason> + Send + 'static,
{
    let prepare_slot = Arc::clone(&slot);
    let finalizer_pipeline = Arc::clone(&pipeline);
    let prepare_task = tokio::spawn(async move {
        let outcome = tokio::task::spawn_blocking(prepare)
            .await
            .unwrap_or(Err(AuditUnavailableReason::PrepareFailed));
        let id = match outcome {
            Ok(id) => id,
            Err(reason) => return Err(reason),
        };
        if prepare_slot
            .with(|inner| {
                inner.prepared = Some(PreparedIntent {
                    id: id.clone(),
                    action,
                    resource_id,
                });
            })
            .is_none()
        {
            return Err(AuditUnavailableReason::PrepareFailed);
        }
        if prepare_slot
            .scope_cancelled_without_settlement_owner
            .load(Ordering::Acquire)
        {
            finalize_unconsumed_intent_with_pipeline(
                finalizer_pipeline,
                &prepare_slot,
                AuditOutcome::UnknownOutcome,
                "request_task_cancelled_while_audit_intent_prepare_was_in_flight",
                None,
            )
            .await;
        }
        Ok(id)
    });
    prepare_task
        .await
        .unwrap_or(Err(AuditUnavailableReason::PrepareFailed))
}

/// Durably prepare the pre-mutation audit intent for the current request.
///
/// Called by the admin write gate **before** the mutation is invoked. Returns
/// the closed-set reason when `fail_closed` must refuse the mutation; returns
/// `None` when the mutation may proceed.
///
/// Under `fail_open`, a failed handoff proceeds but emits a fixed-cardinality
/// warning plus `ferrum_admin_audit_fail_open_unaudited_mutations_total`, and
/// the pipeline stops reporting durable coverage.
pub async fn prepare_request_intent(enabled: bool) -> Option<&'static str> {
    if !enabled {
        return None;
    }
    let pipeline = pipeline();
    if !pipeline.config.enabled {
        return None;
    }
    let Some(slot) = current_slot() else {
        return note_prepare_context_failure(&pipeline);
    };
    // A poisoned slot or missing authenticated actor may not bypass a
    // fail-closed audit policy.
    let event = match slot.with(build_intent_event) {
        Some(Some(Some(event))) => event,
        // This request already prepared an intent (a handler that takes the
        // write gate more than once reuses the same stable id).
        Some(Some(None)) => return None,
        None | Some(None) => return note_prepare_context_failure(&pipeline),
    };
    let action = event.action.clone();
    let resource_id = event.resource_id.clone();
    let pipeline_for_task = Arc::clone(&pipeline);
    // The durable write is blocking filesystem work. This is the admin mutation
    // path, never a proxy hot path. The detached settlement wrapper keeps the
    // fsync and slot installation cancellation-safe while the request waits for
    // durability.
    let outcome = prepare_request_intent_cancellation_safe(
        Arc::clone(&pipeline),
        Arc::clone(&slot),
        action,
        resource_id,
        move || pipeline_for_task.prepare_intent(event),
    )
    .await;
    match outcome {
        Ok(_) => None,
        Err(reason) => {
            if pipeline.config.policy == AuditUnavailablePolicy::FailClosed {
                return Some(reason.as_str());
            }
            pipeline
                .metrics
                .fail_open_unaudited
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                surface = "audit_intent_prepare",
                reason = reason.as_str(),
                policy = AuditUnavailablePolicy::FailOpen.as_str(),
                "Admin mutation proceeding without durable pre-mutation audit evidence \
                 (FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_open)"
            );
            None
        }
    }
}

/// Refuse or explicitly account for an audited mutation whose trustworthy
/// request context could not be prepared. This is an invariant failure, not a
/// reason to turn a `fail_closed` deployment into fail-open behavior.
fn note_prepare_context_failure(pipeline: &Arc<AuditPipeline>) -> Option<&'static str> {
    let reason = AuditUnavailableReason::PrepareFailed;
    pipeline
        .metrics
        .dropped_handoff
        .fetch_add(1, Ordering::Relaxed);
    if pipeline.config.policy == AuditUnavailablePolicy::FailClosed {
        pipeline
            .metrics
            .fail_closed_rejections
            .fetch_add(1, Ordering::Relaxed);
        return Some(reason.as_str());
    }
    pipeline
        .metrics
        .fail_open_unaudited
        .fetch_add(1, Ordering::Relaxed);
    warn!(
        surface = "audit_intent_prepare",
        reason = reason.as_str(),
        policy = AuditUnavailablePolicy::FailOpen.as_str(),
        "Admin mutation proceeding without trustworthy pre-mutation audit context \
         (FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY=fail_open)"
    );
    None
}

/// Build the intent event from slot state.
///
/// `None` means the slot has no authenticated actor; `Some(None)` means this
/// request already prepared an intent.
fn build_intent_event(inner: &mut AuditRequestSlotInner) -> Option<Option<AuditEvent>> {
    if inner.prepared.is_some() {
        return Some(None);
    }
    let actor = inner.actor.clone()?;
    let action = format!("{} {}", inner.method, inner.path);
    Some(Some(AuditEvent {
        id: Uuid::new_v4().to_string(),
        ts: Utc::now(),
        actor,
        action,
        resource_type: AUDIT_INTENT_RESOURCE_TYPE.to_string(),
        resource_id: inner.path.clone(),
        namespace: inner.namespace.clone(),
        source_address: inner.source_address.clone(),
        request_id: inner.request_id.clone(),
        outcome: String::new(),
        diff: json!({ "phase": "prepared" }),
    }))
}

/// Adopt the prepared intent's stable id (and request context) onto `event`.
fn adopt_prepared_intent(event: &mut AuditEvent) -> bool {
    let Some(slot) = current_slot() else {
        return false;
    };
    let taken = slot.with(|inner| {
        let prepared = inner.prepared.take()?;
        Some((
            prepared,
            inner.source_address.clone(),
            inner.request_id.clone(),
        ))
    });
    let Some(Some((prepared, source_address, request_id))) = taken else {
        return false;
    };
    // The stable id is what makes the prepared record and the delivered row the
    // same evidence. `action`/`resource_id` from the intent are only used when
    // the caller left them empty.
    event.id = prepared.id;
    if event.action.is_empty() {
        event.action = prepared.action;
    }
    if event.resource_id.is_empty() {
        event.resource_id = prepared.resource_id;
    }
    if event.source_address.is_empty() {
        event.source_address = source_address;
    }
    if event.request_id.is_empty() {
        event.request_id = request_id;
    }
    true
}

/// Durably finalize an intent that no handler turned into an audit event.
///
/// Called from the admin dispatcher once the response is known. The mutation
/// *returned*, so the outcome is knowable: a 2xx response finalizes as success
/// and anything else as failure. The already-registered backend worker accepts
/// the finalized record without requiring this path to retain a database
/// handle; a durable record can still defer to replay if the worker is gone.
pub async fn finalize_unconsumed_intent(slot: &Arc<AuditRequestSlot>, status: u16) {
    let (outcome, evidence) = if (200..400).contains(&status) {
        (
            AuditOutcome::Success,
            "mutation_completed_without_handler_audit_event",
        )
    } else {
        (AuditOutcome::Failure, "mutation_did_not_complete")
    };
    finalize_unconsumed_intent_with_evidence(slot, outcome, evidence, Some(status)).await;
}

async fn finalize_unconsumed_intent_with_evidence(
    slot: &Arc<AuditRequestSlot>,
    outcome: AuditOutcome,
    evidence: &'static str,
    status: Option<u16>,
) {
    finalize_unconsumed_intent_with_pipeline(pipeline(), slot, outcome, evidence, status).await;
}

async fn finalize_unconsumed_intent_with_pipeline(
    pipeline: Arc<AuditPipeline>,
    slot: &Arc<AuditRequestSlot>,
    outcome: AuditOutcome,
    evidence: &'static str,
    status: Option<u16>,
) {
    if !pipeline.config.enabled {
        return;
    }
    let taken = slot.with(|inner| {
        let prepared = inner.prepared.take()?;
        Some((prepared, std::mem::take(&mut inner.namespace)))
    });
    let Some(Some((prepared, namespace))) = taken else {
        return;
    };
    let Some(actor) = slot.with(|inner| inner.actor.clone()).flatten() else {
        return;
    };
    let unknown_outcome = outcome == AuditOutcome::UnknownOutcome;
    let mut diff = json!({ "outcome_evidence": evidence });
    if let Some(status) = status {
        diff["status"] = json!(status);
    }
    let event = AuditEvent {
        id: prepared.id,
        ts: Utc::now(),
        actor,
        action: prepared.action,
        resource_type: AUDIT_INTENT_RESOURCE_TYPE.to_string(),
        resource_id: prepared.resource_id,
        namespace,
        source_address: slot
            .with(|inner| inner.source_address.clone())
            .unwrap_or_default(),
        request_id: slot
            .with(|inner| inner.request_id.clone())
            .unwrap_or_default(),
        outcome: outcome.as_str().to_string(),
        diff,
    };
    let event_id = event.id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let record = pipeline.finalize_event(event).map_err(|reason| {
            anyhow!(
                "admin audit intent finalization failed ({})",
                reason.as_str()
            )
        })?;
        if unknown_outcome {
            pipeline
                .metrics
                .unknown_outcome
                .fetch_add(1, Ordering::Relaxed);
        }
        enqueue_finalized_without_db(&pipeline, record)
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        warn!(
            audit_event_id = %event_id,
            surface = "audit_intent_finalize",
            detail_withheld = true,
            "Prepared admin audit intent could not be finalized; it replays as unknown_outcome"
        );
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

struct AuditEnvelope {
    record: SpooledAuditRecord,
}

/// One delivery worker: a bounded queue, its task, and the shutdown handle.
pub struct AuditWorker {
    pipeline: Arc<AuditPipeline>,
    tx: Mutex<Option<mpsc::Sender<AuditEnvelope>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl AuditWorker {
    /// Spawn a worker delivering into `delivery`.
    ///
    /// `on_target_lost` runs when the delivery target's `Weak` can no longer be
    /// upgraded, so the process-global registry can drop the stale entry.
    pub fn spawn(
        pipeline: Arc<AuditPipeline>,
        delivery: Arc<dyn AuditEventDelivery>,
        alive: Option<Weak<dyn DatabaseBackend>>,
        on_target_lost: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Arc<Self> {
        let capacity = pipeline.config.queue_capacity.max(AUDIT_QUEUE_CAPACITY_MIN);
        let (tx, rx) = mpsc::channel::<AuditEnvelope>(capacity);
        let worker_pipeline = Arc::clone(&pipeline);
        let join = tokio::spawn(async move {
            run_worker(worker_pipeline, delivery, alive, on_target_lost, rx).await;
        });
        Arc::new(Self {
            pipeline,
            tx: Mutex::new(Some(tx)),
            join: Mutex::new(Some(join)),
        })
    }

    /// Spawn a worker over an arbitrary delivery target.
    ///
    /// External tests drive queue saturation, backend failure/recovery, replay,
    /// idempotency, and shutdown through this entry point; the binary target
    /// otherwise flags it as dead code.
    #[allow(dead_code)]
    pub fn spawn_for_delivery(
        pipeline: Arc<AuditPipeline>,
        delivery: Arc<dyn AuditEventDelivery>,
    ) -> Arc<Self> {
        Self::spawn(pipeline, delivery, None, None)
    }

    fn sender(&self) -> Option<mpsc::Sender<AuditEnvelope>> {
        self.tx.lock().ok().and_then(|guard| {
            if self.pipeline.draining.load(Ordering::Acquire) {
                None
            } else {
                guard.clone()
            }
        })
    }

    /// Durable finalize + enqueue. Errors only when the *durable* step failed.
    ///
    /// A full or closed queue is not an error once the record is on disk: the
    /// replay scan picks it up, so back-pressure degrades latency rather than
    /// integrity.
    pub fn record(&self, event: AuditEvent) -> Result<(), anyhow::Error> {
        let event_id = event.id.clone();
        let record = match self.pipeline.finalize_event(event) {
            Ok(record) => record,
            Err(reason) => {
                return Err(anyhow!(
                    "admin audit durable handoff failed ({}) for audit event {}",
                    reason.as_str(),
                    event_id
                ));
            }
        };
        self.enqueue_finalized(record)
    }

    /// Enqueue a record whose outcome representation was already finalized.
    /// Used by the dispatcher fallback as well as ordinary handler events so
    /// memory-only mode never relies on a replay scan that does not exist.
    fn enqueue_finalized(&self, record: SpooledAuditRecord) -> Result<(), anyhow::Error> {
        let event_id = record.id().to_string();
        let durable = self.pipeline.spool.is_some();
        let Some(tx) = self.sender() else {
            return self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::WorkerUnavailable,
                &event_id,
            );
        };
        match tx.try_send(AuditEnvelope { record }) {
            Ok(()) => {
                self.pipeline
                    .metrics
                    .enqueued
                    .fetch_add(1, Ordering::Relaxed);
                self.pipeline.metrics.queue_depth.store(
                    (self
                        .pipeline
                        .config
                        .queue_capacity
                        .saturating_sub(tx.capacity())) as u64,
                    Ordering::Relaxed,
                );
                Ok(())
            }
            Err(TrySendError::Full(_)) => self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::QueueSaturated,
                &event_id,
            ),
            Err(TrySendError::Closed(_)) => self.note_enqueue_failure(
                durable,
                AuditUnavailableReason::WorkerUnavailable,
                &event_id,
            ),
        }
    }

    fn note_enqueue_failure(
        &self,
        durable: bool,
        reason: AuditUnavailableReason,
        event_id: &str,
    ) -> Result<(), anyhow::Error> {
        if durable {
            // Already fsynced; the replay scan owns delivery from here.
            warn!(
                audit_event_id = %event_id,
                surface = "audit_enqueue",
                reason = reason.as_str(),
                "Admin audit event deferred to durable spool replay"
            );
            return Ok(());
        }
        self.pipeline.note_memory_enqueue_loss(reason, event_id)
    }

    /// Close admission and drain within `timeout`.
    ///
    /// Cancellation-aware: the drain signal interrupts every retry wait and
    /// replay loop instead of letting a 30 s backoff outlive the shutdown
    /// budget, while closing the sender makes the worker consume every already
    /// accepted queue entry before it exits. If the deadline still expires, the
    /// task is explicitly aborted **and joined** — it is never detached.
    /// Durable records stay in the spool for the next process. Memory-only
    /// records are explicitly counted as lost and latch degraded health.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.pipeline.draining.store(true, Ordering::Release);
        // Wake every task parked on a retry backoff or a replay tick.
        self.pipeline.cancel.notify_waiters();
        if let Ok(mut guard) = self.tx.lock() {
            let _ = guard.take();
        }
        let handle = self.join.lock().ok().and_then(|mut guard| guard.take());
        let Some(mut handle) = handle else {
            return true;
        };
        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(_) => true,
            Err(_) => {
                let queued = self.pipeline.metrics.queue_depth.load(Ordering::Relaxed);
                let in_flight = self
                    .pipeline
                    .metrics
                    .delivery_in_flight
                    .load(Ordering::Relaxed);
                let undelivered = queued.saturating_add(in_flight);
                if self.pipeline.spool.is_some() {
                    warn!(
                        surface = "audit_shutdown",
                        queued,
                        in_flight,
                        "Admin audit drain deadline expired; aborting the delivery worker. \
                         Undelivered events remain durable and replayable"
                    );
                } else {
                    self.pipeline
                        .metrics
                        .dropped_no_spool
                        .fetch_add(undelivered, Ordering::Relaxed);
                    self.pipeline
                        .mark_unavailable(AuditUnavailableReason::NoDurableSpool);
                    self.pipeline.evidence_lost.store(true, Ordering::Relaxed);
                    self.pipeline
                        .mark_degraded(AuditUnavailableReason::NoDurableSpool);
                    error!(
                        surface = "audit_shutdown",
                        queued,
                        in_flight,
                        "Admin audit drain deadline expired with no durable spool; aborting the \
                         delivery worker and recording undelivered events as lost"
                    );
                }
                handle.abort();
                // Join the aborted task rather than dropping the handle: a
                // dropped handle detaches the task, which is exactly the
                // silently-abandoned work this drain exists to prevent.
                let _ = handle.await;
                self.pipeline
                    .metrics
                    .queue_depth
                    .store(0, Ordering::Relaxed);
                self.pipeline
                    .metrics
                    .delivery_in_flight
                    .store(0, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Exponential backoff for attempt `attempt` (1-based), capped.
fn retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let millis = AUDIT_RETRY_BASE_DELAY_MS
        .saturating_mul(1u64 << shift)
        .min(AUDIT_RETRY_MAX_DELAY_MS);
    Duration::from_millis(millis)
}

enum DeliveryOutcome {
    Delivered,
    Retained,
    Dropped,
    /// Shutdown interrupted the retry loop; the record stays durable.
    Deferred,
}

/// Longest a retry backoff may run before it re-observes the drain flag.
const AUDIT_CANCEL_POLL_MS: u64 = 250;

/// Cancellation-aware sleep. Returns `false` when shutdown interrupted the wait.
///
/// The wait is both notified and sliced: `Notify::notify_waiters` only wakes
/// waiters that are already registered, so a drain signal raised in the window
/// before registration would otherwise leave a 30 s backoff outliving the whole
/// shutdown budget. Re-checking the flag every [`AUDIT_CANCEL_POLL_MS`] bounds
/// that race deterministically.
async fn sleep_unless_draining(pipeline: &Arc<AuditPipeline>, delay: Duration) -> bool {
    let slice = Duration::from_millis(AUDIT_CANCEL_POLL_MS);
    let deadline = Instant::now() + delay;
    loop {
        if pipeline.draining.load(Ordering::Acquire) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        tokio::select! {
            biased;
            _ = pipeline.cancel.notified() => return false,
            _ = tokio::time::sleep(remaining.min(slice)) => {}
        }
    }
}

async fn deliver_record(
    pipeline: &Arc<AuditPipeline>,
    delivery: &Arc<dyn AuditEventDelivery>,
    mut record: SpooledAuditRecord,
) -> DeliveryOutcome {
    pipeline
        .metrics
        .delivery_in_flight
        .fetch_add(1, Ordering::Relaxed);
    let outcome = deliver_record_inner(pipeline, delivery, &mut record).await;
    saturating_decrement(&pipeline.metrics.delivery_in_flight);
    outcome
}

/// Settle a delivered record's durable half on the blocking pool.
///
/// `remove_pending`, `retain_unrecoverable`, and `update_attempts` unlink,
/// rename, or rewrite a record and then **fsync** a directory. That is real
/// filesystem latency, and the delivery worker shares the serving runtime with
/// the data plane, so it belongs on the blocking pool exactly like the
/// prepare/finalize/list/read paths. A failed offload only happens while the
/// runtime is stopping; the record stays durable and replays idempotently.
async fn settle_delivered(pipeline: &Arc<AuditPipeline>, event_id: &str) {
    let settle_pipeline = Arc::clone(pipeline);
    let id = event_id.to_string();
    if tokio::task::spawn_blocking(move || settle_pipeline.note_delivered(&id))
        .await
        .is_err()
    {
        warn!(
            audit_event_id = %event_id,
            surface = "audit_spool_remove",
            "Delivered admin audit event could not be settled; it stays durable and replays \
             idempotently"
        );
    }
}

/// Retain an exhausted record on the blocking pool. See `settle_delivered`.
async fn settle_unrecoverable(pipeline: &Arc<AuditPipeline>, event_id: &str) {
    let settle_pipeline = Arc::clone(pipeline);
    let id = event_id.to_string();
    if tokio::task::spawn_blocking(move || settle_pipeline.note_unrecoverable(&id))
        .await
        .is_err()
    {
        warn!(
            audit_event_id = %event_id,
            surface = "audit_event_unrecoverable",
            "Admin audit event could not be moved into retained state; it stays durable for the \
             next process generation"
        );
    }
}

/// Persist advisory attempt bookkeeping on the blocking pool. Best effort: a
/// failure only costs retry-budget accuracy, never the record itself.
async fn persist_attempts(pipeline: &Arc<AuditPipeline>, record: &SpooledAuditRecord) {
    let Some(spool) = pipeline.spool.clone() else {
        return;
    };
    let snapshot = record.clone();
    let result = tokio::task::spawn_blocking(move || spool.update_attempts(&snapshot)).await;
    if let Ok(Err(error)) = result {
        warn!(
            audit_event_id = %record.event.id,
            surface = "audit_spool_attempts",
            reason = error.reason(),
            "Could not persist admin audit delivery attempt count"
        );
    }
}

async fn deliver_record_inner(
    pipeline: &Arc<AuditPipeline>,
    delivery: &Arc<dyn AuditEventDelivery>,
    record: &mut SpooledAuditRecord,
) -> DeliveryOutcome {
    loop {
        match delivery.deliver(&record.event).await {
            Ok(()) => {
                settle_delivered(pipeline, &record.event.id).await;
                return DeliveryOutcome::Delivered;
            }
            Err(_) => {
                record.attempts = record.attempts.saturating_add(1);
                pipeline
                    .metrics
                    .delivery_failures
                    .fetch_add(1, Ordering::Relaxed);
                error!(
                    audit_event_id = %record.event.id,
                    surface = "audit_event_persist",
                    attempts = record.attempts,
                    detail_withheld = true,
                    "Failed to persist admin audit event; persistence detail withheld"
                );
                if record.attempts >= pipeline.config.max_delivery_attempts {
                    settle_unrecoverable(pipeline, &record.event.id).await;
                    return if pipeline.spool.is_some() {
                        DeliveryOutcome::Retained
                    } else {
                        DeliveryOutcome::Dropped
                    };
                }
                persist_attempts(pipeline, record).await;
                pipeline.metrics.retries.fetch_add(1, Ordering::Relaxed);
                if !sleep_unless_draining(pipeline, retry_delay(record.attempts)).await {
                    if pipeline.spool.is_some() {
                        return DeliveryOutcome::Deferred;
                    }
                    // A memory-only record cannot be deferred across process
                    // shutdown. Account it as unrecoverable now so an accepted
                    // mutation is never silently abandoned.
                    pipeline.note_shutdown_memory_loss(record);
                    return DeliveryOutcome::Dropped;
                }
            }
        }
    }
}

/// Replay durable records that were never enqueued (restart, queue overflow, or
/// a deferred shutdown). Bounded per call so shutdown stays responsive.
async fn replay_spool(pipeline: &Arc<AuditPipeline>, delivery: &Arc<dyn AuditEventDelivery>) {
    let Some(spool) = pipeline.spool.clone() else {
        return;
    };
    let ids = {
        let spool = Arc::clone(&spool);
        match tokio::task::spawn_blocking(move || spool.list_pending_ids(AUDIT_REPLAY_BATCH)).await
        {
            Ok(ids) => ids,
            Err(_) => return,
        }
    };
    for id in ids {
        if pipeline.draining.load(Ordering::Acquire) {
            return;
        }
        let read = {
            let spool = Arc::clone(&spool);
            let id = id.clone();
            tokio::task::spawn_blocking(move || spool.read_pending(&id)).await
        };
        let record = match read {
            Ok(Ok(record)) => record,
            Ok(Err(error)) => {
                match error.kind {
                    SpoolErrorKind::Corrupt => {
                        pipeline.metrics.corrupt.fetch_add(1, Ordering::Relaxed);
                        pipeline.mark_degraded(AuditUnavailableReason::CorruptRecord);
                        error!(
                            audit_event_id = %id,
                            surface = "audit_spool_replay",
                            reason = error.reason(),
                            "Corrupt admin audit spool record quarantined for operator remediation"
                        );
                    }
                    SpoolErrorKind::DestinationMismatch => {
                        pipeline
                            .metrics
                            .destination_mismatch
                            .fetch_add(1, Ordering::Relaxed);
                        pipeline.mark_degraded(AuditUnavailableReason::DestinationMismatch);
                        error!(
                            audit_event_id = %id,
                            surface = "audit_spool_replay",
                            reason = error.reason(),
                            "Durable admin audit record targets a different audit destination \
                             and was quarantined instead of delivered"
                        );
                    }
                    _ => {}
                }
                continue;
            }
            Err(_) => continue,
        };
        if record.attempts >= pipeline.config.max_delivery_attempts {
            settle_unrecoverable(pipeline, &record.event.id).await;
            continue;
        }
        pipeline.metrics.replayed.fetch_add(1, Ordering::Relaxed);
        if matches!(
            deliver_record(pipeline, delivery, record).await,
            DeliveryOutcome::Deferred
        ) {
            return;
        }
    }
}

async fn run_worker(
    pipeline: Arc<AuditPipeline>,
    delivery: Arc<dyn AuditEventDelivery>,
    alive: Option<Weak<dyn DatabaseBackend>>,
    on_target_lost: Option<Box<dyn Fn() + Send + Sync>>,
    mut rx: mpsc::Receiver<AuditEnvelope>,
) {
    let mut stale_check = interval(Duration::from_secs(AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS));
    stale_check.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut replay = interval(Duration::from_secs(AUDIT_REPLAY_INTERVAL_SECONDS));
    replay.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Adopt anything abandoned by a prior process generation before serving new
    // work: prepared intents become explicit `unknown_outcome` evidence and
    // finalized records are queued for delivery. This runs at startup, not on
    // the first mutation, so a process that never receives another mutation
    // still drains the backlog.
    {
        let claim_pipeline = Arc::clone(&pipeline);
        let _ = tokio::task::spawn_blocking(move || claim_pipeline.claim_abandoned()).await;
    }
    replay_spool(&pipeline, &delivery).await;

    loop {
        tokio::select! {
            biased;
            maybe_envelope = rx.recv() => {
                let Some(envelope) = maybe_envelope else {
                    // Admission closed: drain the durable backlog once, then exit.
                    replay_spool(&pipeline, &delivery).await;
                    break;
                };
                saturating_decrement(&pipeline.metrics.queue_depth);
                if matches!(
                    deliver_record(&pipeline, &delivery, envelope.record).await,
                    DeliveryOutcome::Deferred
                ) {
                    // The current record remains durable. Continue consuming
                    // the closed queue so healthy records can still be
                    // delivered and every failed record is left replayable.
                    continue;
                }
            }
            _ = replay.tick() => {
                // Bounded background reconciliation of the O(1) observability
                // gauges. Deliberately off the admin request path.
                let reconcile_pipeline = Arc::clone(&pipeline);
                let _ = tokio::task::spawn_blocking(move || reconcile_pipeline.reconcile()).await;
                replay_spool(&pipeline, &delivery).await;
            }
            _ = stale_check.tick() => {
                if let Some(alive) = alive.as_ref()
                    && alive.upgrade().is_none()
                {
                    if let Some(callback) = on_target_lost.as_ref() {
                        callback();
                    }
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-backend worker registry
// ---------------------------------------------------------------------------

struct AuditSinkEntry {
    backend: Weak<dyn DatabaseBackend>,
    worker: Arc<AuditWorker>,
}

fn db_key(db: &Arc<dyn DatabaseBackend>) -> usize {
    // Handler clones share this inner pointer, so the address is a stable
    // per-backend worker key while the backend Arc is alive. Stale entries are
    // tied to a Weak backend reference and removed once that backend drops.
    Arc::as_ptr(db) as *const () as usize
}

fn remove_stale_sink(key: usize) {
    AUDIT_SINKS.remove_if(&key, |_, entry| entry.backend.upgrade().is_none());
}

fn entry_matches_backend(entry: &AuditSinkEntry, db: &Arc<dyn DatabaseBackend>) -> bool {
    entry
        .backend
        .upgrade()
        .is_some_and(|existing| Arc::ptr_eq(&existing, db))
}

fn spawn_backend_worker(key: usize, db: &Arc<dyn DatabaseBackend>) -> AuditSinkEntry {
    let backend = Arc::downgrade(db);
    let delivery: Arc<dyn AuditEventDelivery> = Arc::new(DatabaseAuditDelivery {
        db: backend.clone(),
    });
    let worker = AuditWorker::spawn(
        pipeline(),
        delivery,
        Some(backend.clone()),
        Some(Box::new(move || remove_stale_sink(key))),
    );
    AuditSinkEntry { backend, worker }
}

/// Enqueue a dispatcher-finalized fallback event without requiring the request
/// path to retain a database handle. Production startup registers the backend
/// worker before serving Admin traffic. A durable record can safely defer when
/// that worker is unavailable; a memory-only record must be counted as lost.
fn enqueue_finalized_without_db(
    pipeline: &Arc<AuditPipeline>,
    record: SpooledAuditRecord,
) -> Result<(), anyhow::Error> {
    let worker = AUDIT_SINKS.iter().find_map(|entry| {
        entry
            .backend
            .upgrade()
            .is_some()
            .then(|| Arc::clone(&entry.worker))
    });
    if let Some(worker) = worker {
        return worker.enqueue_finalized(record);
    }
    if pipeline.spool.is_some() {
        warn!(
            audit_event_id = %record.id(),
            surface = "audit_enqueue",
            reason = AuditUnavailableReason::WorkerUnavailable.as_str(),
            "Finalized admin audit intent deferred to durable spool replay because no live \
             delivery worker is registered"
        );
        return Ok(());
    }
    pipeline.note_memory_enqueue_loss(AuditUnavailableReason::WorkerUnavailable, record.id())
}

fn worker_for_db(db: Arc<dyn DatabaseBackend>) -> Option<Arc<AuditWorker>> {
    if pipeline().draining.load(Ordering::Acquire) {
        return None;
    }
    let key = db_key(&db);
    // Fast path: live entry for this exact backend pointer.
    if let Some(entry) = AUDIT_SINKS.get(&key)
        && entry_matches_backend(&entry, &db)
    {
        return Some(Arc::clone(&entry.worker));
    }

    // Slow path: take the entry write lock so the spawn-and-insert is atomic.
    // Without this, two threads can both miss the `get`, both spawn a worker,
    // and only one survives — leaving the other's mpsc Sender to be dropped at
    // the end of `record`, which closes that orphan worker before its event is
    // processed. Holding the entry lock across the live-check + spawn + insert
    // guarantees one worker per backend Arc.
    let entry = AUDIT_SINKS
        .entry(key)
        .or_insert_with(|| spawn_backend_worker(key, &db));
    if entry_matches_backend(&entry, &db) {
        return Some(Arc::clone(&entry.worker));
    }

    // The existing entry references a different (stale) backend at the same
    // address — drop it and retry. Calling `remove` while still holding the
    // RefMut would deadlock, so release it first.
    drop(entry);
    AUDIT_SINKS.remove(&key);
    let entry = spawn_backend_worker(key, &db);
    let worker = Arc::clone(&entry.worker);
    AUDIT_SINKS.insert(key, entry);
    Some(worker)
}

/// Start durable audit delivery for `db` during production startup.
///
/// Discovery, claim of abandoned prior-generation records, and replay all begin
/// here rather than waiting for a later mutation to lazily spawn the worker: a
/// process that never receives another mutation must still drain the backlog it
/// inherited (issue #2421).
pub fn start_delivery(enabled: bool, db: Arc<dyn DatabaseBackend>) {
    if !enabled || !pipeline().config.enabled {
        return;
    }
    let _ = worker_for_db(db);
}

/// Durably record an audited admin mutation.
///
/// When the admin write gate prepared an intent for this request, the event
/// adopts that stable id so the pre-mutation evidence and the delivered row are
/// the same record. Returns `Ok(())` once the event is on stable storage (or,
/// in memory-only mode, once it is queued). An error means the durable handoff
/// did not happen; callers log it and, under `fail_closed`, the write gate
/// refuses subsequent audited mutations.
pub async fn record(
    enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    mut event: AuditEvent,
) -> Result<(), anyhow::Error> {
    if !enabled {
        return Ok(());
    }
    adopt_prepared_intent(&mut event);
    if event.outcome.is_empty() {
        // A handler-emitted mutation event is by construction the record of a
        // mutation that returned. Outcome is never inferred before that.
        event.outcome = AuditOutcome::Success.as_str().to_string();
    }

    let pipeline = pipeline();
    let worker = worker_for_db(db);
    // The durable write is blocking filesystem work. This is the admin mutation
    // path, never a proxy hot path, so moving it onto the blocking pool is the
    // correct trade: it keeps the reactor free while the response waits for
    // durability.
    tokio::task::spawn_blocking(move || match worker {
        Some(worker) => worker.record(event),
        None => {
            let event_id = event.id.clone();
            let record = pipeline.finalize_event(event).map_err(|reason| {
                anyhow!(
                    "admin audit durable handoff failed ({}) for audit event {}",
                    reason.as_str(),
                    event_id
                )
            })?;
            if pipeline.spool.is_some() {
                warn!(
                    audit_event_id = %event_id,
                    surface = "audit_enqueue",
                    reason = AuditUnavailableReason::WorkerUnavailable.as_str(),
                    "Admin audit delivery is draining; finalized event deferred to durable \
                     spool replay"
                );
                Ok(())
            } else {
                pipeline.note_shutdown_memory_loss(&record);
                Err(anyhow!(
                    "admin audit event {} could not be retained after delivery admission closed",
                    event_id
                ))
            }
        }
    })
    .await
    .unwrap_or_else(|error| Err(anyhow!("admin audit durable handoff task failed: {error}")))
}

/// Drain every registered audit worker within `timeout`.
///
/// Called from each serving mode's shutdown path **before** the database Arc is
/// dropped. Anything still undelivered stays in the durable spool; explicitly
/// configured memory-only work is accounted as lost if the deadline expires.
pub async fn shutdown(timeout: Duration) {
    // Close process-wide worker admission before taking the registry snapshot.
    // Mutation settlement tasks intentionally survive request cancellation; a
    // late success can still finalize into the durable spool, but it must not
    // create an untracked worker after this drain has begun.
    pipeline().draining.store(true, Ordering::Release);
    let workers: Vec<Arc<AuditWorker>> = AUDIT_SINKS
        .iter()
        .map(|entry| Arc::clone(&entry.worker))
        .collect();
    if workers.is_empty() {
        return;
    }
    let deadline = Instant::now() + timeout;
    for worker in workers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        worker.shutdown(remaining).await;
    }
    AUDIT_SINKS.clear();
}

pub fn create_diff(after: Value) -> Value {
    json!({ "after": after })
}

pub fn update_diff(before: Value, after: Value) -> Value {
    json!({ "before": before, "after": after })
}

pub fn credential_update_diff(credential_type: &str, before: Value, after: Value) -> Value {
    json!({
        "credential_type": credential_type,
        "credential_change": "[REDACTED]",
        "before": before,
        "after": after,
    })
}

pub fn delete_diff(before: Value) -> Value {
    json!({ "before": before })
}

/// Which durable sink admitted a security-sensitive audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAdmitSink {
    /// Synchronous insert into the primary audit store.
    Database,
    /// Bounded local fallback file (used when the primary store is absent or
    /// rejected the insert, including cached-backup paths).
    LocalFallback,
}

/// Resolve the local audit fallback directory from env/config, defaulting to
/// [`AUDIT_LOCAL_FALLBACK_DEFAULT_DIR`].
pub fn audit_local_fallback_dir() -> PathBuf {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_ADMIN_AUDIT_FALLBACK_PATH")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(AUDIT_LOCAL_FALLBACK_DEFAULT_DIR))
}

fn audit_local_fallback_file(dir: &Path) -> PathBuf {
    dir.join(AUDIT_LOCAL_FALLBACK_FILE_NAME)
}

/// Extract a bounded request/correlation ID from admin headers, or mint one.
///
/// Accepts `X-Request-Id` or `X-Correlation-Id` only when every character is in
/// a conservative printable allow-list and length ≤ [`AUDIT_REQUEST_ID_MAX_LEN`].
/// Invalid or missing values are replaced with a fresh UUID — the rejected
/// header bytes are never stored or logged.
pub fn extract_or_generate_request_id(headers: &hyper::HeaderMap) -> String {
    for name in ["x-request-id", "x-correlation-id"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok())
            && is_safe_request_id(value)
        {
            return value.to_string();
        }
    }
    Uuid::new_v4().to_string()
}

fn is_safe_request_id(value: &str) -> bool {
    if value.is_empty() || value.len() > AUDIT_REQUEST_ID_MAX_LEN {
        return false;
    }
    value
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b':'))
}

/// Fixed-shape backup success diff. Never includes payload bytes or secrets.
pub fn backup_success_diff(
    data_source: &str,
    resources: Value,
    counts: Value,
    bytes: usize,
) -> Value {
    json!({
        "data_source": data_source,
        "resources": resources,
        "counts": counts,
        "bytes": bytes,
    })
}

/// Fixed-shape backup failure/denied diff. Categories are closed enums only.
pub fn backup_failure_diff(category: BackupFailureCategory, resources: Value) -> Value {
    json!({
        "failure_category": category.as_str(),
        "resources": resources,
    })
}

/// Backup attempt rejected because `X-Ferrum-Namespace` failed validation.
///
/// Persisted under the valid default audit namespace so the event remains
/// queryable via `GET /audit`. Carries only fixed-cardinality metadata — never
/// the raw invalid namespace string.
pub fn backup_namespace_validation_failure_diff(resources: Value) -> Value {
    json!({
        "failure_category": BackupFailureCategory::ValidationFailed.as_str(),
        "resources": resources,
        "namespace_status": BACKUP_NAMESPACE_STATUS_INVALID,
    })
}

/// Whether `name` is a canonical backup resource filter token.
pub fn is_canonical_backup_resource(name: &str) -> bool {
    BACKUP_AUDIT_RESOURCE_NAMES.contains(&name)
}

/// Canonical resource-filter representation for audit events.
///
/// - Unfiltered → `"all"`
/// - Only allow-listed names → sorted JSON array of those names
/// - Any unknown token → fixed `"invalid"` sentinel (never the raw token)
pub fn backup_resources_audit_value(filter: Option<&std::collections::HashSet<&str>>) -> Value {
    match filter {
        None => json!("all"),
        Some(set) => {
            let mut names: Vec<&str> = Vec::with_capacity(set.len());
            for name in set.iter().copied() {
                if is_canonical_backup_resource(name) {
                    names.push(name);
                } else {
                    // Never persist or log the unknown raw token.
                    return json!(BACKUP_RESOURCES_INVALID_SENTINEL);
                }
            }
            names.sort_unstable();
            json!(names)
        }
    }
}

/// Admit a security-sensitive audit event before releasing unredacted material.
///
/// Backup security auditing is unconditional and independent of
/// `FERRUM_ADMIN_AUDIT_ENABLED` (which gates ordinary mutation audit events
/// only):
/// 1. Prefer a synchronous `insert_audit_event` on the provided backend.
/// 2. If no backend is present or the insert fails, append to the bounded local
///    fallback file under `fallback_dir` (or the configured default) on a
///    blocking worker so admin Tokio tasks are not stalled on disk I/O.
/// 3. If neither sink admits the event, return an error so the caller can fail
///    closed without emitting the sensitive response body.
///
/// This is intentionally narrower than #2421 (general mutation durability): it
/// only covers surfaces that must not silently export secrets without a record.
pub async fn admit_security_sensitive_event(
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) -> Result<AuditAdmitSink, anyhow::Error> {
    if let Some(db) = db {
        match db.insert_audit_event(event).await {
            Ok(()) => return Ok(AuditAdmitSink::Database),
            Err(_error) => {
                // Detail withheld: the primary may be the same unavailable store
                // that forced a cached backup. Fall through to local capture.
                warn!(
                    audit_event_id = %event.id,
                    surface = "audit_security_admit_database",
                    detail_withheld = true,
                    "Primary audit store rejected a security-sensitive event; trying local fallback"
                );
            }
        }
    }

    let dir = fallback_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(audit_local_fallback_dir);
    let event_id = event.id.clone();
    let event = event.clone();
    let join = tokio::task::spawn_blocking(move || append_local_fallback_event(&dir, &event)).await;
    match join {
        Ok(Ok(())) => Ok(AuditAdmitSink::LocalFallback),
        Ok(Err(_)) | Err(_) => {
            error!(
                audit_event_id = %event_id,
                surface = "audit_security_admit_local_fallback",
                detail_withheld = true,
                "Failed to admit security-sensitive audit event to local fallback"
            );
            Err(anyhow!(
                "security-sensitive audit event could not be admitted"
            ))
        }
    }
}

/// Best-effort admit for authenticated backup denials/validation failures.
///
/// Uses the same unconditional database/local-fallback path as successful
/// exports. Never changes the caller's HTTP response path on failure — only
/// logs that the security record could not be stored.
pub async fn record_backup_attempt_best_effort(
    db: Option<&Arc<dyn DatabaseBackend>>,
    event: &AuditEvent,
    fallback_dir: Option<&Path>,
) {
    if let Err(_error) = admit_security_sensitive_event(db, event, fallback_dir).await {
        warn!(
            audit_event_id = %event.id,
            surface = "backup_audit_attempt",
            detail_withheld = true,
            "Authenticated backup attempt could not be audited"
        );
    }
}

static LOCAL_FALLBACK_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Cross-process exclusive lock held for the fallback read/modify/write window.
struct FallbackFileLock {
    _file: File,
}

/// Append one event to the bounded local fallback store.
///
/// Enforces a non-symlink directory/data/lock target, owner-only Unix
/// permissions, single-link regular files on Unix (hard links rejected before
/// chmod/flock/read), a [`AUDIT_LOCAL_FALLBACK_MAX_BYTES`] on-disk byte
/// ceiling read through a no-follow open of the exact file, collision-resistant
/// temp publication with same-directory atomic replace (Unix `rename(2)`;
/// Windows `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`), directory sync, and
/// cross-process exclusion where the platform supports it. In-process and
/// cross-process locks retry non-blocking acquisition against a shared
/// [`LOCAL_FALLBACK_LOCK_WAIT`] deadline (`try_lock` / `LOCK_EX|LOCK_NB` on
/// Unix; exclusive `share_mode(0)` open retries on Windows): ordinary
/// contention waits briefly, then fails closed so a wedged holder cannot hang
/// a Tokio blocking-pool thread unboundedly. Callers reach this via
/// [`admit_security_sensitive_event`]'s `spawn_blocking`, so the bounded
/// sleep stays off the async worker. Never logs event contents.
pub fn append_local_fallback_event(dir: &Path, event: &AuditEvent) -> Result<(), anyhow::Error> {
    let deadline = local_fallback_lock_deadline();
    let _process_guard = acquire_local_fallback_process_lock(deadline)?;
    prepare_fallback_directory(dir)?;
    let lock_path = dir.join(AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME);
    let _cross_process = acquire_fallback_file_lock(&lock_path, deadline)?;
    let path = audit_local_fallback_file(dir);
    reject_symlink_or_non_regular_file(&path, "audit local fallback data file")?;
    let mut events = read_local_fallback_events_unlocked(&path)?;
    events.push(event.clone());
    let evicted = if events.len() > AUDIT_LOCAL_FALLBACK_CAPACITY {
        let overflow = events.len() - AUDIT_LOCAL_FALLBACK_CAPACITY;
        events.drain(0..overflow);
        Some(overflow)
    } else {
        None
    };
    write_local_fallback_events_unlocked(dir, &path, &events, || {
        if let Some(overflow) = evicted {
            // The callback runs immediately after atomic publication, before
            // fallible post-publication durability and permission steps.
            // Counts only — never event contents.
            warn!(
                surface = "audit_local_fallback_evicted",
                evicted = overflow,
                retained = AUDIT_LOCAL_FALLBACK_CAPACITY,
                "Local audit fallback store is at capacity; oldest security records were dropped"
            );
        }
    })?;
    Ok(())
}

/// Read all events currently retained in the local fallback store.
///
/// Uses the same bounded process and cross-process lock acquisition as
/// [`append_local_fallback_event`]; contention past the shared deadline fails
/// closed.
// This public library surface is exercised by integration tests but is unused
// when the same module is compiled directly into the `ferrum-edge` binary.
#[allow(dead_code)]
pub fn list_local_fallback_events(dir: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    let deadline = local_fallback_lock_deadline();
    let _process_guard = acquire_local_fallback_process_lock(deadline)?;
    prepare_existing_fallback_directory(dir)?;
    let lock_path = dir.join(AUDIT_LOCAL_FALLBACK_LOCK_FILE_NAME);
    let _cross_process = acquire_fallback_file_lock(&lock_path, deadline)?;
    let path = audit_local_fallback_file(dir);
    reject_symlink_or_non_regular_file(&path, "audit local fallback data file")?;
    read_local_fallback_events_unlocked(&path)
}

fn local_fallback_lock_deadline() -> std::time::Instant {
    std::time::Instant::now() + LOCAL_FALLBACK_LOCK_WAIT
}

fn sleep_until_lock_deadline(deadline: std::time::Instant) -> bool {
    let now = std::time::Instant::now();
    if now >= deadline {
        return false;
    }
    let remaining = deadline.saturating_duration_since(now);
    std::thread::sleep(LOCAL_FALLBACK_LOCK_RETRY.min(remaining));
    true
}

/// Bounded in-process mutex for the local fallback critical section.
///
/// Retries `try_lock` until `deadline` so brief sibling contention can clear.
/// Exhausted deadline and poisoning both return a static, non-sensitive error
/// so security-sensitive admit never waits indefinitely on another holder.
fn acquire_local_fallback_process_lock(
    deadline: std::time::Instant,
) -> Result<MutexGuard<'static, ()>, anyhow::Error> {
    loop {
        match LOCAL_FALLBACK_LOCK.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => {
                if !sleep_until_lock_deadline(deadline) {
                    return Err(anyhow!("audit local fallback process lock contended"));
                }
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("audit local fallback lock poisoned"));
            }
        }
    }
}

/// Test seam: hold the in-process fallback mutex without waiting.
// The library test harness calls this through `src/lib.rs`; the binary target
// compiles the shared module without that harness.
#[allow(dead_code)]
pub(crate) fn hold_local_fallback_process_lock_for_test()
-> Result<MutexGuard<'static, ()>, anyhow::Error> {
    match LOCAL_FALLBACK_LOCK.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => {
            Err(anyhow!("audit local fallback process lock contended"))
        }
        Err(TryLockError::Poisoned(_)) => Err(anyhow!("audit local fallback lock poisoned")),
    }
}

fn prepare_fallback_directory(dir: &Path) -> Result<(), anyhow::Error> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("audit local fallback path must not be a symlink"));
            }
            if !meta.is_dir() {
                return Err(anyhow!("audit local fallback path must be a directory"));
            }
            enforce_owner_only_dir_permissions(dir)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            // Re-validate after create so a raced symlink/non-dir fails closed.
            prepare_existing_fallback_directory(dir)
        }
        Err(error) => Err(error.into()),
    }
}

fn prepare_existing_fallback_directory(dir: &Path) -> Result<(), anyhow::Error> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("audit local fallback path must not be a symlink"));
    }
    if !meta.is_dir() {
        return Err(anyhow!("audit local fallback path must be a directory"));
    }
    enforce_owner_only_dir_permissions(dir)
}

fn enforce_owner_only_dir_permissions(dir: &Path) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let _ = dir;
    Ok(())
}

fn reject_symlink_or_non_regular_file(
    path: &Path,
    label: &'static str,
) -> Result<(), anyhow::Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("{label} must not be a symlink"));
            }
            if !meta.file_type().is_file() {
                return Err(anyhow!("{label} must be a regular file"));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn acquire_fallback_file_lock(
    lock_path: &Path,
    deadline: std::time::Instant,
) -> Result<FallbackFileLock, anyhow::Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    reject_symlink_or_non_regular_file(lock_path, "audit local fallback lock file")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|error| map_fallback_open_error(error, "audit local fallback lock file"))?;
    let lock_metadata = file.metadata()?;
    // Reject hard-linked targets before chmod/flock can affect an unrelated
    // inode that merely shares this pathname via an extra link.
    if !lock_metadata.file_type().is_file() || lock_metadata.nlink() != 1 {
        return Err(anyhow!(
            "audit local fallback lock file must be a single-link regular file"
        ));
    }
    validate_fallback_lock_path_identity(lock_path, &lock_metadata)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;

    loop {
        // SAFETY: `file` owns a valid descriptor for the lifetime of this guard.
        // `flock` does not access Rust-managed memory. Retry `LOCK_NB` against the
        // shared deadline rather than blocking `LOCK_EX` unboundedly (or relying
        // on signal/`alarm` tricks) so the bound stays explicit and portable.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        let errno = error.raw_os_error();
        if errno == Some(libc::EWOULDBLOCK) || errno == Some(libc::EAGAIN) {
            if !sleep_until_lock_deadline(deadline) {
                return Err(anyhow!("audit local fallback cross-process lock contended"));
            }
            continue;
        }
        return Err(anyhow!(
            "failed to acquire audit local fallback cross-process lock: {error}"
        ));
    }

    validate_fallback_lock_path_identity(lock_path, &lock_metadata)?;

    Ok(FallbackFileLock { _file: file })
}

#[cfg(unix)]
fn validate_fallback_lock_path_identity(
    lock_path: &Path,
    opened: &fs::Metadata,
) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::MetadataExt;

    let path_metadata = fs::symlink_metadata(lock_path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err(anyhow!(
            "audit local fallback lock file changed identity during acquisition"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn acquire_fallback_file_lock(
    lock_path: &Path,
    deadline: std::time::Instant,
) -> Result<FallbackFileLock, anyhow::Error> {
    use std::os::windows::fs::OpenOptionsExt;

    reject_symlink_or_non_regular_file(lock_path, "audit local fallback lock file")?;
    // `share_mode(0)` denies all share access for as long as this handle is
    // held — a std-only cross-process exclusive critical section. Open fails
    // immediately on sharing violation; retry against the shared deadline so
    // the bound matches the Unix `LOCK_NB` loop (no unbounded wait).
    let file = loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(lock_path)
        {
            Ok(file) => break file,
            Err(error) if error.raw_os_error() == Some(WIN32_ERROR_SHARING_VIOLATION) => {
                if !sleep_until_lock_deadline(deadline) {
                    return Err(anyhow!("audit local fallback cross-process lock contended"));
                }
            }
            Err(error) => {
                return Err(anyhow!("failed to open audit local fallback lock: {error}"));
            }
        }
    };
    let lock_metadata = file.metadata()?;
    if !lock_metadata.file_type().is_file() {
        return Err(anyhow!(
            "audit local fallback lock file must be a regular file"
        ));
    }
    Ok(FallbackFileLock { _file: file })
}

#[cfg(not(any(unix, windows)))]
fn acquire_fallback_file_lock(
    _lock_path: &Path,
    _deadline: std::time::Instant,
) -> Result<FallbackFileLock, anyhow::Error> {
    Err(anyhow!(
        "audit local fallback cross-process exclusion is unavailable on this platform"
    ))
}

fn read_local_fallback_events_unlocked(path: &Path) -> Result<Vec<AuditEvent>, anyhow::Error> {
    let mut file = match open_fallback_data_file_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(map_fallback_open_error(
                error,
                "audit local fallback data file",
            ));
        }
    };
    let meta = file.metadata().map_err(|error| {
        anyhow!("failed to stat audit local fallback data file handle: {error}")
    })?;
    validate_opened_fallback_data_metadata(&meta, "audit local fallback data file")?;
    confirm_fallback_path_matches_opened(path, &meta, "audit local fallback data file")?;

    let len = meta.len();
    if len > AUDIT_LOCAL_FALLBACK_MAX_BYTES as u64 {
        return Err(anyhow!(
            "audit local fallback data file exceeds maximum size"
        ));
    }
    let size = usize::try_from(len)
        .map_err(|_| anyhow!("audit local fallback data file exceeds maximum size"))?;
    // Reserve exactly the fstat'd size before reading so a hostile multi-GiB
    // file cannot force amortized growth; the take(+1) bound is defense in
    // depth if the inode grows after the size check.
    let mut raw = Vec::new();
    raw.try_reserve_exact(size)
        .map_err(|_| anyhow!("audit local fallback data file exceeds available memory"))?;
    let mut limited = (&mut file).take((AUDIT_LOCAL_FALLBACK_MAX_BYTES as u64).saturating_add(1));
    limited
        .read_to_end(&mut raw)
        .map_err(|error| anyhow!("failed to read audit local fallback data file: {error}"))?;
    if raw.len() > AUDIT_LOCAL_FALLBACK_MAX_BYTES {
        return Err(anyhow!(
            "audit local fallback data file exceeds maximum size"
        ));
    }
    // Re-validate handle + path identity after the read so a replace during
    // the bounded copy cannot silently admit a different object.
    let meta_after = file.metadata().map_err(|error| {
        anyhow!("failed to re-stat audit local fallback data file handle: {error}")
    })?;
    validate_opened_fallback_data_metadata(&meta_after, "audit local fallback data file")?;
    confirm_fallback_path_matches_opened(path, &meta_after, "audit local fallback data file")?;

    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    // Never include raw bytes in the error: hostile content may contain
    // secrets or multi-megabyte junk.
    serde_json::from_slice(&raw).map_err(|_| anyhow!("corrupt audit local fallback store"))
}

/// Open the fallback data file without following a final-path symlink.
fn open_fallback_data_file_nofollow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new().read(true).open(path)
    }
}

fn map_fallback_open_error(error: std::io::Error, label: &'static str) -> anyhow::Error {
    #[cfg(unix)]
    {
        // O_NOFOLLOW reports ELOOP when the final path component is a symlink.
        if error.raw_os_error() == Some(libc::ELOOP) {
            return anyhow!("{label} must not be a symlink");
        }
    }
    anyhow!("failed to open {label}: {error}")
}

/// Validate file-descriptor metadata for a fallback data file.
///
/// Decisions use the opened handle (not path metadata alone): regular file,
/// owner-only mode bits, and (Unix) a single hard link.
fn validate_opened_fallback_data_metadata(
    meta: &fs::Metadata,
    label: &'static str,
) -> Result<(), anyhow::Error> {
    if !meta.file_type().is_file() {
        return Err(anyhow!("{label} must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.nlink() != 1 {
            return Err(anyhow!("{label} must be a single-link regular file"));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!("{label} must have owner-only permissions"));
        }
    }
    Ok(())
}

/// Ensure the path still names the same opened object (and is not a symlink).
fn confirm_fallback_path_matches_opened(
    path: &Path,
    opened: &fs::Metadata,
    label: &'static str,
) -> Result<(), anyhow::Error> {
    let path_meta = fs::symlink_metadata(path)?;
    if path_meta.file_type().is_symlink() {
        return Err(anyhow!("{label} must not be a symlink"));
    }
    if !path_meta.file_type().is_file() {
        return Err(anyhow!("{label} must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_meta.nlink() != 1
            || path_meta.dev() != opened.dev()
            || path_meta.ino() != opened.ino()
        {
            return Err(anyhow!("{label} changed identity during read"));
        }
    }
    #[cfg(not(unix))]
    {
        // Portable platforms lack stable device/inode identity; size is a
        // weak check that still fails closed when the path entry diverges
        // grossly from the opened handle mid-read.
        if path_meta.len() != opened.len() {
            return Err(anyhow!("{label} changed identity during read"));
        }
    }
    Ok(())
}

fn write_local_fallback_events_unlocked(
    dir: &Path,
    path: &Path,
    events: &[AuditEvent],
    on_published: impl FnOnce(),
) -> Result<(), anyhow::Error> {
    let body = serde_json::to_vec_pretty(events)?;
    if body.len() > AUDIT_LOCAL_FALLBACK_MAX_BYTES {
        return Err(anyhow!("audit local fallback payload exceeds maximum size"));
    }
    let tmp_name = format!("{}.{}.tmp", AUDIT_LOCAL_FALLBACK_FILE_NAME, Uuid::new_v4());
    let tmp = dir.join(tmp_name);
    let write_result = write_temp_fallback_file(&tmp, &body);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    // Same-directory replace: never unlink the destination before publish, and
    // never leave a visibility gap. Unix `rename(2)` replaces atomically;
    // Windows uses `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` because
    // `std::fs::rename` does not replace an existing destination there.
    if let Err(error) = replace_local_fallback_file(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    on_published();
    sync_directory(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Atomically publish `temp` over `destination` in the same directory.
///
/// Safety boundary: both paths must already be siblings under the prepared
/// fallback directory (caller holds the process/cross-process locks and wrote
/// `temp` via [`write_temp_fallback_file`]). This never removes `destination`
/// before replacement and never logs path contents.
fn replace_local_fallback_file(temp: &Path, destination: &Path) -> Result<(), anyhow::Error> {
    #[cfg(windows)]
    {
        return replace_local_fallback_file_windows(temp, destination);
    }
    #[cfg(not(windows))]
    {
        fs::rename(temp, destination).map_err(|error| error.into())
    }
}

/// Windows same-directory replacement with replace-existing + write-through.
///
/// `std::fs::rename` maps to `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`,
/// so the first append can succeed while every later append fails closed when
/// the destination already exists. This path uses
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` and propagates Win32
/// failures without deleting the live destination first (no visibility gap).
#[cfg(windows)]
fn replace_local_fallback_file_windows(
    temp: &Path,
    destination: &Path,
) -> Result<(), anyhow::Error> {
    use std::os::windows::ffi::OsStrExt;

    // MOVEFILE_REPLACE_EXISTING = 0x1, MOVEFILE_WRITE_THROUGH = 0x8
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let source: Vec<u16> = temp
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let target: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `source`/`target` are NUL-terminated wide paths owned for the
    // duration of the call. Flags request replace-existing + write-through
    // durability only; no path bytes are logged on failure.
    let ok = unsafe {
        windows_ffi::MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        return Err(anyhow!(
            "failed to replace audit local fallback file: {error}"
        ));
    }
    Ok(())
}

/// Minimal kernel32 bindings for atomic same-directory file replacement.
///
/// Kept local (no `windows-sys` dependency) because this is the only Win32
/// primitive the backup-audit fallback needs today.
#[cfg(windows)]
mod windows_ffi {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub(super) fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }
}

fn write_temp_fallback_file(tmp: &Path, body: &[u8]) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new().write(true).create_new(true).open(tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        Ok(())
    }
}

fn sync_directory(dir: &Path) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        let dir_file = OpenOptions::new().read(true).open(dir)?;
        dir_file.sync_all()?;
    }
    let _ = dir;
    Ok(())
}
