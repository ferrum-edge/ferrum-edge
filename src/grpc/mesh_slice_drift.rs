//! CP-side per-authenticated-DP mesh slice convergence / drift tracking
//! (issue #3265).
//!
//! Complements the DP-local `GET /mesh/config-drift` surface: this registry
//! records what the control plane **desired**, last **sent**, last
//! **accepted** (`acknowledged`: the data plane's install-time verdict), last
//! **applied** (its proxy-runtime verdict), and last **rejected** for each
//! authenticated mesh subscriber so operators can spot stuck, partitioned, or
//! repeatedly rejecting data planes after a successful CP reconciliation.
//!
//! Accepted and applied are deliberately distinct (issue #4812). A data plane
//! ACKs at install time, when the slice has merely become its RECEIVED slice;
//! its proxy runtime is a second, independent gate that can still refuse the
//! slice. Only an **applied** report converges a row — otherwise this surface,
//! which exists to find stuck data planes, would report `converged` for a data
//! plane whose runtime refused the slice.
//!
//! # Identity
//!
//! Entries are keyed by the authenticated JWT `sub` (bound to the
//! `MeshSubscribeRequest.node_id` at subscribe time). Caller-supplied display
//! fields are never trusted as identity.
//!
//! # Session semantics
//!
//! - **Subscribe / replacement**: a new session for the same identity replaces
//!   the prior entry and receives a fresh opaque token. Stale stream drops,
//!   sends, and ACK/NACK reports must match that token.
//! - **Duplicate concurrent streams**: last successful insert wins (same as
//!   [`super::mesh_registry::MeshNodeRegistry`]).
//! - **Send**: advances `sent` for the matching generation only.
//! - **Desired**: advanced only when that DP's projected slice content changes.
//! - **Status**: accepted / applied / rejected reports are recorded only for an
//!   existing identity; malformed reports fail closed with field-specific
//!   diagnostics.
//! - **Disconnect**: marks the entry disconnected but retains it until the
//!   retention TTL so partition/reconnect drift remains visible.
//! - **Retention expiry / cardinality**: expired disconnected entries are
//!   reaped; inserts that would exceed the hard cap first evict the oldest
//!   disconnected entry, otherwise refuse with a bounded error.
//!
//! Hot/admin reads consume an immutable [`MeshSliceDriftSnapshot`] via
//! `ArcSwap` — scrapes never walk the live map.
//!
//! # Posture
//!
//! This registry is **observability only**. Callers on the mesh configuration
//! path must treat every error here as "this data plane is untracked", never
//! as a reason to refuse or tear down a subscription: a bookkeeping refusal
//! (cardinality cap, oversized retained selector) or a poisoned lock must not
//! be able to deny mesh config delivery. See
//! [`super::mesh_server::MeshGrpcServer::mesh_subscribe`].

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use tracing::warn;
use uuid::Uuid;

use super::cp_server::{CpGrpcServer, CpScope};
use crate::config::types::GatewayConfig;
use crate::fips::approved::Sha256;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

/// Retention for disconnected DP drift rows (matches mesh node heartbeat TTL).
pub const MESH_SLICE_DRIFT_RETENTION_SECONDS: i64 = 300;

/// Hard cap on tracked identities. Operator-bounded fleets stay well under
/// this; hostile reconnect storms cannot grow the map unboundedly.
pub const MESH_SLICE_DRIFT_MAX_ENTRIES: usize = 4096;

/// Max accepted slice-version UTF-8 byte length (fail closed above this).
pub const MESH_SLICE_DRIFT_MAX_VERSION_BYTES: usize = 256;

/// Max accepted identity (JWT `sub`) UTF-8 byte length. The gRPC metadata
/// limit alone would let a legitimately authenticated but pathologically long
/// subject dominate retained key bytes at the 4096-identity cap, so the
/// registry bounds it independently of the transport.
pub const MESH_SLICE_DRIFT_MAX_NODE_ID_BYTES: usize = 256;

/// Max retained rejection-reason UTF-8 byte length. Production retains only the
/// closed labels of [`MeshSliceReportRejection`], never caller-supplied text.
pub const MESH_SLICE_DRIFT_MAX_REASON_BYTES: usize = 64;

/// Which of a data plane's two independent gates refused a slice (issue #4812).
pub const MESH_SLICE_DRIFT_STAGE_INSTALL: &str = "install";
pub const MESH_SLICE_DRIFT_STAGE_RUNTIME: &str = "runtime";

/// Closed, compile-time refusal categories retained for a rejected slice.
///
/// The data plane sends a wire enum, never free text, so this is the ENTIRE
/// diagnostic the control plane can record: a rejection reason can never carry
/// credentials, request data, or unbounded caller bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeshSliceReportRejection {
    /// Refused by the DP's receive/install gates (subscription binding,
    /// envelope consistency, or config-revision freshness).
    InstallRefused,
    /// The slice could not be converted into a serving gateway configuration.
    RuntimeConfigBuild,
    /// The DP's proxy runtime refused the converted configuration.
    RuntimeProxyRefused,
    /// Effective gateway trust material for the slice was unusable.
    RuntimeTrustUnusable,
    /// Inbound mTLS live-reload preparation failed on the DP.
    RuntimeTlsReload,
    /// Owner-scoped NodeWaypoint DTLS candidate build failed on the DP.
    RuntimeDtlsCandidate,
}

impl MeshSliceReportRejection {
    /// Fixed, length-bounded label published on the admin surface.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::InstallRefused => "install_refused",
            Self::RuntimeConfigBuild => "runtime_config_build",
            Self::RuntimeProxyRefused => "runtime_proxy_refused",
            Self::RuntimeTrustUnusable => "runtime_trust_unusable",
            Self::RuntimeTlsReload => "runtime_tls_reload",
            Self::RuntimeDtlsCandidate => "runtime_dtls_candidate",
        }
    }

    /// The DP gate that produced the refusal.
    pub const fn stage(self) -> &'static str {
        match self {
            Self::InstallRefused => MESH_SLICE_DRIFT_STAGE_INSTALL,
            Self::RuntimeConfigBuild
            | Self::RuntimeProxyRefused
            | Self::RuntimeTrustUnusable
            | Self::RuntimeTlsReload
            | Self::RuntimeDtlsCandidate => MESH_SLICE_DRIFT_STAGE_RUNTIME,
        }
    }

    /// Every retained label, for exhaustive contract coverage.
    pub const ALL: [Self; 6] = [
        Self::InstallRefused,
        Self::RuntimeConfigBuild,
        Self::RuntimeProxyRefused,
        Self::RuntimeTrustUnusable,
        Self::RuntimeTlsReload,
        Self::RuntimeDtlsCandidate,
    ];
}

/// A data plane's verdict on one delivered slice version (issue #4812).
///
/// `Accepted` and `Applied` are two different gates, not two names for one: a
/// slice that is accepted has merely become the DP's received slice, while an
/// applied slice is the generation the DP is actually serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceReportStatus {
    Accepted,
    Applied,
    Rejected(MeshSliceReportRejection),
}

// Every retained rejection label is compile-time bounded, so the registry can
// never store an oversized reason. Keeping these as real uses of the public
// limit and of `ALL` also prevents the binary's private module graph from
// treating the integration-test contract surface as dead code.
const _: () = assert!(MeshSliceReportRejection::ALL.len() == 6);
const _: () = {
    use MeshSliceReportRejection::*;
    assert!(InstallRefused.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(RuntimeConfigBuild.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(RuntimeProxyRefused.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(RuntimeTrustUnusable.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(RuntimeTlsReload.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(RuntimeDtlsCandidate.as_label().len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
};
const _: () = assert!(MESH_SLICE_DRIFT_STAGE_INSTALL.len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);
const _: () = assert!(MESH_SLICE_DRIFT_STAGE_RUNTIME.len() < MESH_SLICE_DRIFT_MAX_REASON_BYTES);

/// Bound the retained subscription selector used for publication-time projection.
const MESH_SLICE_DRIFT_MAX_PROJECTION_LABELS: usize = 256;
const MESH_SLICE_DRIFT_MAX_PROJECTION_NAMESPACES: usize = 256;
const MESH_SLICE_DRIFT_MAX_PROJECTION_BYTES: usize = 64 * 1024;

/// Fleet size below which every mutation republishes the immutable snapshot
/// immediately. A rebuild is O(tracked identities), so at small/medium fleet
/// sizes it is trivial and the snapshot stays exactly current.
const SNAPSHOT_COALESCE_MIN_ENTRIES: usize = 256;

/// Above [`SNAPSHOT_COALESCE_MIN_ENTRIES`], per-stream send and per-DP ACK/NACK
/// mutations republish at most this often. One CP publication fans out to every
/// connected stream, so without coalescing a single broadcast would rebuild the
/// whole snapshot once per stream (quadratic in fleet size) while holding the
/// registry mutex. Deferred state is always flushed by the next structural
/// mutation (session open/replace, disconnect, publication reconcile) or the
/// periodic retention sweep.
const SNAPSHOT_COALESCE_WINDOW_MS: i64 = 500;

/// Closed-set convergence classification for summary metrics / admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSliceConvergenceState {
    /// Desired, sent, acknowledged, and applied versions all agree and are
    /// present: this data plane is SERVING the desired generation.
    Converged,
    /// The data plane accepted the desired version at install time but has not
    /// reported it as the serving generation. Distinct from `Converged`
    /// (issue #4812): an install ACK is not proof the runtime took the slice.
    Accepted,
    /// Desired differs from sent and/or acknowledged (or ACK is missing while
    /// a desired version exists).
    Drifted,
    /// Last status report was a NACK (rejected version present). Takes
    /// precedence over plain drift so rejecting DPs are obvious.
    Rejecting,
    /// Connected but the CP has not yet stamped a desired version.
    Pending,
    /// Stream gone; row retained until retention expiry.
    Disconnected,
}

impl MeshSliceConvergenceState {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Converged => "converged",
            Self::Accepted => "accepted",
            Self::Drifted => "drifted",
            Self::Rejecting => "rejecting",
            Self::Pending => "pending",
            Self::Disconnected => "disconnected",
        }
    }
}

/// One version watermark with useful age metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceVersionStamp {
    pub version: String,
    pub at: DateTime<Utc>,
    /// `now - at` in seconds, clamped to zero on clock skew.
    pub age_seconds: u64,
}

impl MeshSliceVersionStamp {
    fn from_parts(version: String, at: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        Self {
            version,
            at,
            age_seconds: age_seconds(now, at),
        }
    }
}

/// Immutable per-DP row exposed on the admin snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftEntry {
    /// Authenticated DP identity (JWT `sub`).
    pub node_id: String,
    pub namespace: String,
    pub connected: bool,
    pub session_connected_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired: Option<MeshSliceVersionStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<MeshSliceVersionStamp>,
    /// The data plane's INSTALL-time acceptance watermark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<MeshSliceVersionStamp>,
    /// The data plane's PROXY-RUNTIME acceptance watermark: the generation it
    /// reported as actually serving (issue #4812).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<MeshSliceVersionStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected: Option<MeshSliceRejectedStamp>,
    pub convergence: MeshSliceConvergenceState,
    pub drift: MeshSliceDriftFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshSliceRejectedStamp {
    pub version: String,
    pub at: DateTime<Utc>,
    pub age_seconds: u64,
    /// Which of the data plane's two gates refused the slice: `install` (the
    /// receive/revision gates) or `runtime` (the proxy runtime).
    pub stage: &'static str,
    /// Closed, length-bounded reason label. Never caller-supplied text.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftFlags {
    pub desired_vs_sent: bool,
    pub desired_vs_acknowledged: bool,
    pub sent_vs_acknowledged: bool,
    /// The desired generation is not the one the data plane's proxy runtime
    /// reported as serving (issue #4812).
    pub desired_vs_applied: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftSummary {
    pub tracked: usize,
    pub connected: usize,
    pub converged: usize,
    pub accepted: usize,
    pub drifted: usize,
    pub rejecting: usize,
    pub pending: usize,
    pub disconnected: usize,
}

/// Immutable admin/metrics view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshSliceDriftSnapshot {
    pub generated_at: DateTime<Utc>,
    pub data_planes: Vec<MeshSliceDriftEntry>,
    pub summary: MeshSliceDriftSummary,
}

#[derive(Clone)]
struct LiveEntry {
    node_id: String,
    namespace: String,
    connected_at: DateTime<Utc>,
    connected: bool,
    disconnected_at: Option<DateTime<Utc>>,
    desired_version: Option<String>,
    desired_at: Option<DateTime<Utc>>,
    sent_version: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    acknowledged_version: Option<String>,
    acknowledged_at: Option<DateTime<Utc>>,
    applied_version: Option<String>,
    applied_at: Option<DateTime<Utc>>,
    rejected_version: Option<String>,
    rejected_at: Option<DateTime<Utc>>,
    rejected_stage: Option<&'static str>,
    rejected_reason: Option<String>,
    /// Opaque, per-stream generation. Never published or logged.
    session_token: String,
    /// Retained so every row can compare its actual projected slice at CP
    /// publication time, independently of stream polling. The content digest
    /// excludes the observability-only version and ordering revision.
    projection: Option<ProjectionContext>,
    desired_content_digest: Option<[u8; 32]>,
}

#[derive(Clone)]
struct ProjectionContext {
    request: MeshSliceRequest,
    scope: CpScope,
    bearer_namespaces: Option<HashSet<String>>,
}

/// Why a status report or subscribe was refused. Closed, compile-time set —
/// never echoes caller-supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceDriftAdmitError {
    EmptyNodeId,
    NodeIdTooLong,
    EmptyNamespace,
    EmptyVersion,
    VersionTooLong,
    VersionHasSurroundingWhitespace,
    VersionHasControlCharacter,
    UnknownNode,
    DisconnectedNode,
    SessionMismatch,
    VersionMismatch,
    CardinalityExceeded,
    ProjectionContextTooLarge,
    ProjectionFailed,
    /// The report named a lifecycle phase this control plane does not define.
    UnknownStatusPhase,
    /// The report named a refusal category this control plane does not define.
    UnknownRejectReason,
}

impl MeshSliceDriftAdmitError {
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::EmptyNodeId => "authenticated node identity must not be empty",
            Self::NodeIdTooLong => {
                "authenticated node identity exceeds the 256-byte drift-registry maximum"
            }
            Self::EmptyNamespace => "mesh slice drift namespace must not be empty",
            Self::EmptyVersion => "mesh slice status version must not be empty",
            Self::VersionTooLong => "mesh slice status version exceeds the 256-byte maximum",
            Self::VersionHasSurroundingWhitespace => {
                "mesh slice status version must not contain surrounding whitespace"
            }
            Self::VersionHasControlCharacter => {
                "mesh slice status version must not contain control characters"
            }
            Self::UnknownNode => {
                "no mesh slice drift session exists for this authenticated identity"
            }
            Self::DisconnectedNode => "mesh slice drift session is not connected",
            Self::SessionMismatch => "mesh slice status session token is stale or invalid",
            Self::VersionMismatch => {
                "mesh slice status version is not the current version sent on this session"
            }
            Self::CardinalityExceeded => {
                "mesh slice drift registry is at capacity; disconnect idle data planes or raise retention reaping"
            }
            Self::ProjectionContextTooLarge => {
                "mesh subscription projection context exceeds the retained-state bound"
            }
            Self::ProjectionFailed => "mesh slice projection could not be represented",
            Self::UnknownStatusPhase => {
                "mesh slice status phase is not a recognised lifecycle stage"
            }
            Self::UnknownRejectReason => {
                "mesh slice status rejection reason is not a recognised category"
            }
        }
    }

    pub const fn field_name(self) -> &'static str {
        match self {
            Self::EmptyNodeId => "node_id",
            Self::NodeIdTooLong => "node_id",
            Self::EmptyNamespace => "namespace",
            Self::EmptyVersion => "version",
            Self::VersionTooLong => "version",
            Self::VersionHasSurroundingWhitespace => "version",
            Self::VersionHasControlCharacter => "version",
            Self::UnknownNode => "node_id",
            Self::DisconnectedNode => "node_id",
            Self::SessionMismatch => "session_token",
            Self::VersionMismatch => "version",
            Self::CardinalityExceeded => "cardinality",
            Self::ProjectionContextTooLarge => "subscription",
            Self::ProjectionFailed => "projection",
            Self::UnknownStatusPhase => "phase",
            Self::UnknownRejectReason => "reject_reason",
        }
    }
}

/// Process-global summary gauges (closed-set `state` label only). Production
/// has one CP registry; the immutable snapshot also keeps test registries from
/// publishing a summary assembled from multiple generations.
static DRIFT_SUMMARY: LazyLock<ArcSwap<MeshSliceDriftSummary>> =
    LazyLock::new(|| ArcSwap::from_pointee(MeshSliceDriftSummary::default()));

#[derive(Default)]
struct RegistryState {
    entries: HashMap<String, LiveEntry>,
    /// A fan-out mutation changed published state without rebuilding the
    /// immutable snapshot. Cleared by the next publication.
    pending_publish: bool,
    /// Wall clock of the last snapshot publication, used only to bound
    /// fan-out coalescing. `None` until the first publication.
    last_published_at: Option<DateTime<Utc>>,
}

/// Bounded per-authenticated-DP slice-version drift registry. Every mutation,
/// snapshot rebuild, and ArcSwap publication is serialized by `state`; admin
/// and metrics reads remain lock-free through `snapshot`.
pub struct MeshSliceDriftRegistry {
    state: Mutex<RegistryState>,
    snapshot: ArcSwap<MeshSliceDriftSnapshot>,
    max_entries: usize,
}

impl Default for MeshSliceDriftRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshSliceDriftRegistry {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RegistryState::default()),
            snapshot: ArcSwap::from_pointee(MeshSliceDriftSnapshot {
                generated_at: Utc::now(),
                data_planes: Vec::new(),
                summary: MeshSliceDriftSummary::default(),
            }),
            max_entries: MESH_SLICE_DRIFT_MAX_ENTRIES,
        }
    }

    /// Construct a smaller bounded registry for deterministic concurrency
    /// coverage. Production uses [`Self::new`] and the 4096-entry hard cap.
    #[doc(hidden)]
    // `main.rs` compiles a private copy of the module graph while external
    // integration tests consume the library copy of this public helper.
    #[allow(dead_code)]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            state: Mutex::new(RegistryState::default()),
            snapshot: ArcSwap::from_pointee(MeshSliceDriftSnapshot {
                generated_at: Utc::now(),
                data_planes: Vec::new(),
                summary: MeshSliceDriftSummary::default(),
            }),
            max_entries: max_entries.min(MESH_SLICE_DRIFT_MAX_ENTRIES),
        }
    }

    /// Open or replace a local mesh subscription session without retaining a
    /// projection. Intended for focused registry callers; production
    /// MeshSubscribe uses [`Self::open_projected_session`].
    // Public integration-test helper; see `with_max_entries`.
    #[allow(dead_code)]
    pub fn open_session(
        &self,
        node_id: &str,
        namespace: &str,
        connected_at: DateTime<Utc>,
        desired_version: Option<&str>,
    ) -> Result<String, MeshSliceDriftAdmitError> {
        self.open_session_inner(
            node_id,
            namespace,
            connected_at,
            desired_version,
            None,
            None,
        )
    }

    /// Open or replace a production MeshSubscribe session while retaining the
    /// bounded selector needed to keep a disconnected row's desired watermark
    /// accurate across later CP publications.
    #[allow(clippy::too_many_arguments)]
    pub fn open_projected_session(
        &self,
        node_id: &str,
        namespace: &str,
        connected_at: DateTime<Utc>,
        initial_slice: &MeshSlice,
        request: MeshSliceRequest,
        scope: CpScope,
        bearer_namespaces: Option<HashSet<String>>,
    ) -> Result<String, MeshSliceDriftAdmitError> {
        validate_projection_context(&request, &scope, bearer_namespaces.as_ref())?;
        let digest = slice_content_digest(initial_slice)?;
        self.open_session_inner(
            node_id,
            namespace,
            connected_at,
            Some(initial_slice.version.as_str()),
            Some(ProjectionContext {
                request,
                scope,
                bearer_namespaces,
            }),
            Some(digest),
        )
    }

    fn open_session_inner(
        &self,
        node_id: &str,
        namespace: &str,
        connected_at: DateTime<Utc>,
        desired_version: Option<&str>,
        projection: Option<ProjectionContext>,
        desired_content_digest: Option<[u8; 32]>,
    ) -> Result<String, MeshSliceDriftAdmitError> {
        let node_id = validate_identity(node_id)?;
        let namespace = validate_namespace(namespace)?;
        if let Some(version) = desired_version {
            validate_version(version)?;
        }
        let session_token = Uuid::new_v4().simple().to_string();
        let mut state = self.state_locked();
        if !state.entries.contains_key(node_id)
            && state.entries.len() >= self.max_entries
            && !evict_oldest_disconnected(&mut state.entries)
        {
            return Err(MeshSliceDriftAdmitError::CardinalityExceeded);
        }
        let now = connected_at;
        state.entries.insert(
            node_id.to_string(),
            LiveEntry {
                node_id: node_id.to_string(),
                namespace: namespace.to_string(),
                connected_at,
                connected: true,
                disconnected_at: None,
                desired_version: desired_version.map(str::to_string),
                desired_at: desired_version.map(|_| now),
                sent_version: None,
                sent_at: None,
                acknowledged_version: None,
                acknowledged_at: None,
                applied_version: None,
                applied_at: None,
                rejected_version: None,
                rejected_at: None,
                rejected_stage: None,
                rejected_reason: None,
                session_token: session_token.clone(),
                projection,
                desired_content_digest,
            },
        );
        self.publish_locked(&mut state, Utc::now());
        Ok(session_token)
    }

    /// Record the actual projected slice sent on the matching opaque session.
    /// Desired advances independently at publication time, before the stream
    /// is polled, so a connected subscriber stalled by gRPC backpressure still
    /// exposes desired-vs-sent drift instead of appearing converged forever.
    pub fn record_projected_sent(
        &self,
        node_id: &str,
        session_token: &str,
        slice: &MeshSlice,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        self.record_sent_inner(node_id, session_token, &slice.version, at)
    }

    /// Record a sent version for focused registry tests/callers that do not
    /// retain a production projection.
    // Public integration-test helper; see `with_max_entries`.
    #[allow(dead_code)]
    pub fn record_sent(
        &self,
        node_id: &str,
        session_token: &str,
        version: &str,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        self.record_sent_inner(node_id, session_token, version, at)
    }

    fn record_sent_inner(
        &self,
        node_id: &str,
        session_token: &str,
        version: &str,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        validate_version(version)?;
        let mut state = self.state_locked();
        let entry = state
            .entries
            .get_mut(node_id)
            .ok_or(MeshSliceDriftAdmitError::UnknownNode)?;
        validate_live_session(entry, session_token)?;
        entry.sent_version = Some(version.to_string());
        entry.sent_at = Some(at);
        if entry.rejected_version.as_deref() == Some(version) {
            entry.rejected_version = None;
            entry.rejected_at = None;
            entry.rejected_stage = None;
            entry.rejected_reason = None;
        }
        self.publish_fanout_locked(&mut state, Utc::now());
        Ok(())
    }

    /// Recompute every retained projection from the actual published config.
    /// This runs before broadcast delivery so desired remains authoritative
    /// even when a connected stream is not being polled. A version-only/no-op
    /// reload or unrelated namespace mutation leaves desired untouched because
    /// the content digest ignores `MeshSlice.version` and `revision`, matching
    /// `MeshSlice::content_eq`.
    pub fn reconcile_desired(&self, config: &GatewayConfig, at: DateTime<Utc>) -> usize {
        let mut state = self.state_locked();
        let mut changed = 0usize;
        let mut skipped = 0usize;
        for entry in state.entries.values_mut() {
            // One entry whose projection cannot be represented must not abort
            // reconciliation for the rest of the fleet, and must not leave
            // already-mutated rows unpublished.
            match reconcile_entry_desired(entry, config, at) {
                Ok(true) => changed += 1,
                Ok(false) => {}
                Err(_) => skipped += 1,
            }
        }
        if skipped > 0 {
            // One bounded line per publication, never per entry.
            warn!(
                skipped,
                "Skipped mesh slice desired reconciliation for some data planes"
            );
        }
        if changed > 0 || state.pending_publish {
            self.publish_locked(&mut state, at);
        }
        changed
    }

    /// Re-stamp one live session's desired watermark from the currently
    /// published config, under the same lock a publication reconcile uses.
    ///
    /// Subscribe loads the config snapshot **before** the row exists, so a
    /// publication landing in that window reconciles a registry that does not
    /// yet contain this identity — a no-op for it — while the already
    /// subscribed stream still receives (and records as sent) the newer slice.
    /// Without this the row would keep the older desired version and classify
    /// as drifted until the next content-changing publication, which on a
    /// quiet config store may never arrive. Loading inside the lock makes the
    /// outcome ordering-independent: either this observes the newer config, or
    /// the publication's own reconcile runs after this and observes the row.
    pub fn reconcile_session_desired(
        &self,
        node_id: &str,
        session_token: &str,
        config: &ArcSwap<GatewayConfig>,
        at: DateTime<Utc>,
    ) -> bool {
        let mut state = self.state_locked();
        let Some(entry) = state.entries.get_mut(node_id) else {
            return false;
        };
        if entry.session_token != session_token || !entry.connected {
            return false;
        }
        let config = config.load_full();
        let outcome = reconcile_entry_desired(entry, config.as_ref(), at);
        let changed = match outcome {
            Ok(changed) => changed,
            Err(error) => {
                warn!(
                    field = error.field_name(),
                    "Failed to re-reconcile mesh slice desired state at subscribe time"
                );
                return false;
            }
        };
        if changed || state.pending_publish {
            self.publish_locked(&mut state, at);
        }
        changed
    }

    /// Record a data plane's verdict on one delivered slice version.
    ///
    /// Issue #4812: an `Accepted` report is the DP's INSTALL-time verdict and
    /// deliberately does NOT converge the row — only `Applied`, the DP's
    /// proxy-runtime verdict, does. An `Applied` report also stamps the
    /// acceptance watermark: a slice cannot serve without having been
    /// installed, so a lost install ACK must not strand an applied row in
    /// `drifted`.
    pub fn record_status(
        &self,
        node_id: &str,
        session_token: &str,
        version: &str,
        status: MeshSliceReportStatus,
        at: DateTime<Utc>,
    ) -> Result<(), MeshSliceDriftAdmitError> {
        let node_id = validate_identity(node_id)?;
        validate_version(version)?;
        let mut state = self.state_locked();
        let entry = state
            .entries
            .get_mut(node_id)
            .ok_or(MeshSliceDriftAdmitError::UnknownNode)?;
        validate_live_session(entry, session_token)?;
        if entry.sent_version.as_deref() != Some(version) {
            return Err(MeshSliceDriftAdmitError::VersionMismatch);
        }
        match status {
            MeshSliceReportStatus::Accepted => {
                entry.acknowledged_version = Some(version.to_string());
                entry.acknowledged_at = Some(at);
                clear_rejection(entry);
            }
            MeshSliceReportStatus::Applied => {
                entry.acknowledged_version = Some(version.to_string());
                entry.acknowledged_at = Some(at);
                entry.applied_version = Some(version.to_string());
                entry.applied_at = Some(at);
                clear_rejection(entry);
            }
            MeshSliceReportStatus::Rejected(rejection) => {
                // A runtime refusal leaves the install-time acceptance standing:
                // the slice WAS accepted, it simply never started serving. That
                // pairing (acknowledged == desired, applied behind, rejected
                // present) is exactly the stuck data plane this surface exists
                // to show.
                entry.rejected_version = Some(version.to_string());
                entry.rejected_at = Some(at);
                entry.rejected_stage = Some(rejection.stage());
                entry.rejected_reason = Some(rejection.as_label().to_string());
            }
        }
        self.publish_fanout_locked(&mut state, Utc::now());
        Ok(())
    }

    /// Mark a matching opaque session disconnected; retain until reaper expiry.
    // Public integration-test helper; see `with_max_entries`.
    #[allow(dead_code)]
    pub fn mark_disconnected(&self, node_id: &str, session_token: &str, now: DateTime<Utc>) {
        let mut state = self.state_locked();
        let Some(entry) = state.entries.get_mut(node_id) else {
            return;
        };
        if entry.session_token != session_token || !entry.connected {
            return;
        }
        entry.connected = false;
        entry.disconnected_at = Some(now);
        self.publish_locked(&mut state, now);
    }

    /// Production disconnect path. Re-evaluating the projection while marking
    /// the row closes the race where a config swap observes the session as
    /// connected but the stream drops before it emits that update.
    pub fn mark_disconnected_with_config(
        &self,
        node_id: &str,
        session_token: &str,
        config: &ArcSwap<GatewayConfig>,
        now: DateTime<Utc>,
    ) {
        let mut state = self.state_locked();
        let Some(entry) = state.entries.get_mut(node_id) else {
            return;
        };
        if entry.session_token != session_token || !entry.connected {
            return;
        }
        entry.connected = false;
        entry.disconnected_at = Some(now);
        // Load while holding the same mutation lock used by publication
        // reconciliation. If the config swaps first, this observes the new
        // snapshot; if disconnect wins first, the later publication observes
        // the now-disconnected row. Neither ordering can strand old desired
        // content after a newer config was published.
        let config = config.load_full();
        // A projection failure must still leave the row marked disconnected
        // and published; only the desired watermark is skipped.
        if let Err(error) = reconcile_entry_desired(entry, config.as_ref(), now) {
            warn!(
                field = error.field_name(),
                "Skipped mesh slice desired reconciliation while finalizing a disconnect"
            );
        }
        self.publish_locked(&mut state, now);
    }

    /// Remove expired disconnected rows. Returns how many were deleted.
    pub fn reap_expired(&self, now: DateTime<Utc>, retention: chrono::Duration) -> usize {
        let mut state = self.state_locked();
        let stale_before = now - retention;
        let before = state.entries.len();
        state.entries.retain(|_, entry| {
            if entry.connected {
                return true;
            }
            match entry.disconnected_at {
                Some(at) => at >= stale_before,
                None => false,
            }
        });
        let removed = before.saturating_sub(state.entries.len());
        // Maintenance also advances ages for stable non-empty rows and is the
        // backstop that flushes coalesced fan-out state on an otherwise idle
        // registry. Empty, never-coalesced snapshots need no periodic republish.
        if removed > 0 || !state.entries.is_empty() || state.pending_publish {
            self.publish_locked(&mut state, now);
        }
        removed
    }

    /// Lock-free immutable snapshot for admin / metrics.
    pub fn snapshot(&self) -> Arc<MeshSliceDriftSnapshot> {
        self.snapshot.load_full()
    }

    /// Number of identities in the latest immutable registry snapshot.
    #[allow(dead_code)] // Public library API exercised by external test targets.
    pub fn len(&self) -> usize {
        self.snapshot.load().summary.tracked
    }

    /// Whether the latest immutable registry snapshot tracks no identities.
    #[allow(dead_code)] // Public library API exercised by external test targets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The guarded state is observability data only. `std` mutex poisoning is
    /// sticky, so latching it would let one panic under this lock permanently
    /// disable drift tracking — and, before the MeshSubscribe path was made
    /// tolerant, would have denied mesh configuration delivery outright. A
    /// stale or partially updated drift row must never take down the mesh
    /// plane, so poisoning is recovered from instead of propagated.
    fn state_locked(&self) -> MutexGuard<'_, RegistryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Structural publication: always rebuilds and clears any coalesced
    /// fan-out state.
    fn publish_locked(&self, state: &mut RegistryState, now: DateTime<Utc>) {
        state.pending_publish = false;
        state.last_published_at = Some(now);
        self.refresh_snapshot_locked(state, now);
    }

    /// Fan-out publication (per-stream send, per-DP ACK/NACK). One CP
    /// broadcast reaches every connected stream, so republishing on each of
    /// them costs one full snapshot rebuild per stream. Small fleets keep the
    /// exact-current behaviour; larger fleets rebuild at most once per
    /// [`SNAPSHOT_COALESCE_WINDOW_MS`] and are flushed by the next structural
    /// mutation or retention sweep.
    fn publish_fanout_locked(&self, state: &mut RegistryState, now: DateTime<Utc>) {
        // A negative delta means the clock moved backwards (or a caller mixed
        // fixture and wall-clock stamps); publish rather than coalesce so skew
        // can never wedge the snapshot.
        let coalesce = state.entries.len() >= SNAPSHOT_COALESCE_MIN_ENTRIES
            && state.last_published_at.is_some_and(|last| {
                (0..SNAPSHOT_COALESCE_WINDOW_MS)
                    .contains(&now.signed_duration_since(last).num_milliseconds())
            });
        if coalesce {
            state.pending_publish = true;
        } else {
            self.publish_locked(state, now);
        }
    }

    fn refresh_snapshot_locked(&self, state: &RegistryState, now: DateTime<Utc>) {
        let mut data_planes: Vec<MeshSliceDriftEntry> = state
            .entries
            .values()
            .map(|entry| publish_entry(entry, now))
            .collect();
        data_planes.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });

        let mut summary = MeshSliceDriftSummary {
            tracked: data_planes.len(),
            ..MeshSliceDriftSummary::default()
        };
        for entry in &data_planes {
            if entry.connected {
                summary.connected += 1;
            }
            match entry.convergence {
                MeshSliceConvergenceState::Converged => summary.converged += 1,
                MeshSliceConvergenceState::Accepted => summary.accepted += 1,
                MeshSliceConvergenceState::Drifted => summary.drifted += 1,
                MeshSliceConvergenceState::Rejecting => summary.rejecting += 1,
                MeshSliceConvergenceState::Pending => summary.pending += 1,
                MeshSliceConvergenceState::Disconnected => summary.disconnected += 1,
            }
        }

        DRIFT_SUMMARY.store(Arc::new(summary.clone()));

        self.snapshot.store(Arc::new(MeshSliceDriftSnapshot {
            generated_at: now,
            data_planes,
            summary,
        }));
    }
}

fn reconcile_entry_desired(
    entry: &mut LiveEntry,
    config: &GatewayConfig,
    at: DateTime<Utc>,
) -> Result<bool, MeshSliceDriftAdmitError> {
    let Some(projection) = entry.projection.as_ref() else {
        return Ok(false);
    };
    let mut filtered = CpGrpcServer::filter_config_to_mesh_request_for_scope_and_bearer(
        config,
        &projection.request,
        &projection.scope,
        projection.bearer_namespaces.as_ref(),
    );
    filtered.normalize_fields();
    filtered.normalize_mesh_fields();
    let slice = MeshSlice::from_gateway_config(&filtered, projection.request.clone());
    validate_version(&slice.version)?;
    let digest = slice_content_digest(&slice)?;
    if entry.desired_content_digest == Some(digest) {
        return Ok(false);
    }
    entry.desired_content_digest = Some(digest);
    entry.desired_version = Some(slice.version);
    entry.desired_at = Some(at);
    Ok(true)
}

fn evict_oldest_disconnected(entries: &mut HashMap<String, LiveEntry>) -> bool {
    let oldest = entries
        .values()
        .filter_map(|entry| {
            if entry.connected {
                None
            } else {
                entry.disconnected_at.map(|at| (entry.node_id.clone(), at))
            }
        })
        .min_by_key(|(_, at)| *at);
    if let Some((node_id, _)) = oldest {
        entries.remove(&node_id);
        true
    } else {
        false
    }
}

fn clear_rejection(entry: &mut LiveEntry) {
    entry.rejected_version = None;
    entry.rejected_at = None;
    entry.rejected_stage = None;
    entry.rejected_reason = None;
}

fn publish_entry(entry: &LiveEntry, now: DateTime<Utc>) -> MeshSliceDriftEntry {
    let desired = entry
        .desired_version
        .as_ref()
        .zip(entry.desired_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let sent = entry
        .sent_version
        .as_ref()
        .zip(entry.sent_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let acknowledged = entry
        .acknowledged_version
        .as_ref()
        .zip(entry.acknowledged_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let applied = entry
        .applied_version
        .as_ref()
        .zip(entry.applied_at)
        .map(|(v, at)| MeshSliceVersionStamp::from_parts(v.clone(), at, now));
    let rejected = entry.rejected_version.as_ref().map(|version| {
        let at = entry.rejected_at.unwrap_or(now);
        MeshSliceRejectedStamp {
            version: version.clone(),
            at,
            age_seconds: age_seconds(now, at),
            stage: entry
                .rejected_stage
                .unwrap_or(MESH_SLICE_DRIFT_STAGE_INSTALL),
            reason: entry
                .rejected_reason
                .clone()
                .unwrap_or_else(|| "unspecified".to_string()),
        }
    });

    let drift = MeshSliceDriftFlags {
        desired_vs_sent: versions_differ(
            desired.as_ref().map(|s| s.version.as_str()),
            sent.as_ref().map(|s| s.version.as_str()),
        ),
        desired_vs_acknowledged: versions_differ(
            desired.as_ref().map(|s| s.version.as_str()),
            acknowledged.as_ref().map(|s| s.version.as_str()),
        ),
        sent_vs_acknowledged: versions_differ(
            sent.as_ref().map(|s| s.version.as_str()),
            acknowledged.as_ref().map(|s| s.version.as_str()),
        ),
        desired_vs_applied: versions_differ(
            desired.as_ref().map(|s| s.version.as_str()),
            applied.as_ref().map(|s| s.version.as_str()),
        ),
    };

    let convergence = classify(
        entry.connected,
        &desired,
        &sent,
        &acknowledged,
        &applied,
        &rejected,
        drift,
    );

    MeshSliceDriftEntry {
        node_id: entry.node_id.clone(),
        namespace: entry.namespace.clone(),
        connected: entry.connected,
        session_connected_at: entry.connected_at,
        disconnected_at: entry.disconnected_at,
        desired,
        sent,
        acknowledged,
        applied,
        rejected,
        convergence,
        drift,
    }
}

fn classify(
    connected: bool,
    desired: &Option<MeshSliceVersionStamp>,
    sent: &Option<MeshSliceVersionStamp>,
    acknowledged: &Option<MeshSliceVersionStamp>,
    applied: &Option<MeshSliceVersionStamp>,
    rejected: &Option<MeshSliceRejectedStamp>,
    drift: MeshSliceDriftFlags,
) -> MeshSliceConvergenceState {
    if !connected {
        return MeshSliceConvergenceState::Disconnected;
    }
    if rejected.is_some() {
        return MeshSliceConvergenceState::Rejecting;
    }
    if desired.is_none() {
        return MeshSliceConvergenceState::Pending;
    }
    if drift.desired_vs_sent
        || drift.desired_vs_acknowledged
        || drift.sent_vs_acknowledged
        || sent.is_none()
        || acknowledged.is_none()
    {
        return MeshSliceConvergenceState::Drifted;
    }
    // Issue #4812: the install-time ACK is not proof the proxy runtime took the
    // slice. Convergence requires the DP to have reported the desired
    // generation as the one it is SERVING; anything short of that is
    // `accepted`, never `converged`.
    if drift.desired_vs_applied || applied.is_none() {
        return MeshSliceConvergenceState::Accepted;
    }
    MeshSliceConvergenceState::Converged
}

fn versions_differ(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => a != b,
        (None, None) => false,
        _ => true,
    }
}

fn age_seconds(now: DateTime<Utc>, at: DateTime<Utc>) -> u64 {
    now.signed_duration_since(at).num_seconds().max(0) as u64
}

fn validate_identity(node_id: &str) -> Result<&str, MeshSliceDriftAdmitError> {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyNodeId);
    }
    // Retained key bytes are bounded independently of the ~16 KiB gRPC header
    // budget that would otherwise cap an authenticated `sub`.
    if trimmed.len() > MESH_SLICE_DRIFT_MAX_NODE_ID_BYTES {
        return Err(MeshSliceDriftAdmitError::NodeIdTooLong);
    }
    Ok(trimmed)
}

fn validate_namespace(namespace: &str) -> Result<&str, MeshSliceDriftAdmitError> {
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyNamespace);
    }
    Ok(trimmed)
}

/// Canonical mesh slice version admission shared by generated outbound slices
/// and inbound ACK/NACK reports. Versions are exact opaque UTF-8 bytes: no
/// trimming or normalization is permitted.
pub fn validate_version(version: &str) -> Result<(), MeshSliceDriftAdmitError> {
    if version.is_empty() {
        return Err(MeshSliceDriftAdmitError::EmptyVersion);
    }
    if version.len() > MESH_SLICE_DRIFT_MAX_VERSION_BYTES {
        return Err(MeshSliceDriftAdmitError::VersionTooLong);
    }
    if version.trim() != version {
        return Err(MeshSliceDriftAdmitError::VersionHasSurroundingWhitespace);
    }
    if version.chars().any(char::is_control) {
        return Err(MeshSliceDriftAdmitError::VersionHasControlCharacter);
    }
    Ok(())
}

fn validate_live_session(
    entry: &LiveEntry,
    session_token: &str,
) -> Result<(), MeshSliceDriftAdmitError> {
    if !entry.connected {
        return Err(MeshSliceDriftAdmitError::DisconnectedNode);
    }
    if session_token.len() != 32
        || !session_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || entry.session_token != session_token
    {
        return Err(MeshSliceDriftAdmitError::SessionMismatch);
    }
    Ok(())
}

fn validate_projection_context(
    request: &MeshSliceRequest,
    scope: &CpScope,
    bearer_namespaces: Option<&HashSet<String>>,
) -> Result<(), MeshSliceDriftAdmitError> {
    let scope_namespace_count = match scope {
        CpScope::Set(namespaces) => namespaces.len(),
        CpScope::Single(_) | CpScope::All => 0,
    };
    if request.labels.len() > MESH_SLICE_DRIFT_MAX_PROJECTION_LABELS
        || scope_namespace_count > MESH_SLICE_DRIFT_MAX_PROJECTION_NAMESPACES
        || bearer_namespaces
            .is_some_and(|namespaces| namespaces.len() > MESH_SLICE_DRIFT_MAX_PROJECTION_NAMESPACES)
    {
        return Err(MeshSliceDriftAdmitError::ProjectionContextTooLarge);
    }
    let mut bytes = request.node_id.len()
        + request.namespace.len()
        + request.workload_spiffe_id.as_deref().map_or(0, str::len)
        + request.waypoint_name.as_deref().map_or(0, str::len)
        + request.cluster_domain.len();
    bytes = bytes.saturating_add(
        request
            .labels
            .iter()
            .map(|(key, value)| key.len().saturating_add(value.len()))
            .sum::<usize>(),
    );
    bytes = bytes.saturating_add(match scope {
        CpScope::Single(namespace) => namespace.len(),
        CpScope::Set(namespaces) => namespaces.iter().map(String::len).sum(),
        CpScope::All => 0,
    });
    bytes = bytes.saturating_add(
        bearer_namespaces
            .map(|namespaces| namespaces.iter().map(String::len).sum())
            .unwrap_or(0),
    );
    if bytes > MESH_SLICE_DRIFT_MAX_PROJECTION_BYTES {
        return Err(MeshSliceDriftAdmitError::ProjectionContextTooLarge);
    }
    Ok(())
}

#[doc(hidden)]
pub fn slice_content_digest(slice: &MeshSlice) -> Result<[u8; 32], MeshSliceDriftAdmitError> {
    let mut canonical = slice.clone();
    canonical.version.clear();
    canonical.revision = None;
    canonical_content_digest(&canonical)
}

/// Canonical semantic digest of any serializable config payload.
///
/// The digesting core [`slice_content_digest`] uses, factored out so the mesh
/// config-revision gate can bind the SAME canonicalization to content that is
/// not a whole `MeshSlice` — notably the post-validation remote-cluster
/// endpoint set (issue #3611). Callers that need `MeshSlice` semantics must go
/// through [`slice_content_digest`], which additionally clears the
/// observability-only `version` and the ordering-only `revision`.
///
/// The error carries no payload data, so a digest failure can be surfaced
/// without disclosing anything about the content that failed to canonicalize.
#[doc(hidden)]
pub fn canonical_content_digest<T: Serialize>(
    value: &T,
) -> Result<[u8; 32], MeshSliceDriftAdmitError> {
    serde_json::to_value(value)
        .map(canonical_json_value)
        .and_then(|value| serde_json::to_vec(&value))
        .map(Sha256::digest)
        .map_err(|_| MeshSliceDriftAdmitError::ProjectionFailed)
}

/// Recursively sort every JSON object while preserving array order and scalar
/// values. `MeshSlice` contains nested `HashMap`s whose insertion order is not
/// semantic, while its arrays are intentionally order-sensitive.
fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, canonical_json_value(value)))
                .collect();
            let mut canonical = serde_json::Map::with_capacity(sorted.len());
            for (key, value) in sorted {
                canonical.insert(key, value);
            }
            Value::Object(canonical)
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_json_value).collect())
        }
        other => other,
    }
}

fn append_mesh_slice_drift_summary_metrics(
    output: &mut String,
    summary: &MeshSliceDriftSummary,
    gateway_ns_label: &str,
) {
    let tracked = summary.tracked;
    // Only emit when the CP has ever tracked a DP (avoids noise on non-CP
    // processes that share the binary).
    if tracked == 0 {
        return;
    }

    output.push_str(
        "# HELP ferrum_mesh_slice_drift_data_planes Tracked mesh data planes by CP-side slice convergence state.\n",
    );
    output.push_str("# TYPE ferrum_mesh_slice_drift_data_planes gauge\n");
    for (state, value) in [
        (MeshSliceConvergenceState::Converged, summary.converged),
        (MeshSliceConvergenceState::Accepted, summary.accepted),
        (MeshSliceConvergenceState::Drifted, summary.drifted),
        (MeshSliceConvergenceState::Rejecting, summary.rejecting),
        (MeshSliceConvergenceState::Pending, summary.pending),
        (
            MeshSliceConvergenceState::Disconnected,
            summary.disconnected,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_data_planes{{state=\"{}\"{}}} {}\n",
            state.as_metric_label(),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_slice_drift_tracked_data_planes Total mesh data planes retained in the CP slice-drift registry.\n",
    );
    output.push_str("# TYPE ferrum_mesh_slice_drift_tracked_data_planes gauge\n");
    if gateway_ns_label.is_empty() {
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_tracked_data_planes {tracked}\n"
        ));
    } else {
        let label_body = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        output.push_str(&format!(
            "ferrum_mesh_slice_drift_tracked_data_planes{{{label_body}}} {tracked}\n"
        ));
    }
}

/// Render closed-set CP mesh slice convergence gauges from one immutable
/// summary. Production scrapes load the process-global summary published with
/// each registry snapshot.
#[doc(hidden)]
// Public integration-test helper; the production path calls the private
// append function directly through `render_mesh_slice_drift_metrics`.
#[allow(dead_code)]
pub fn render_mesh_slice_drift_summary_metrics(
    output: &mut String,
    summary: &MeshSliceDriftSummary,
    gateway_ns_label: &str,
) {
    append_mesh_slice_drift_summary_metrics(output, summary, gateway_ns_label);
}

/// Render closed-set CP mesh slice convergence gauges into a Prometheus text
/// exposition buffer. Label cardinality is fixed (`state` ∈ six values).
pub fn render_mesh_slice_drift_metrics(output: &mut String, gateway_ns_label: &str) {
    let summary = DRIFT_SUMMARY.load_full();
    append_mesh_slice_drift_summary_metrics(output, &summary, gateway_ns_label);
}
