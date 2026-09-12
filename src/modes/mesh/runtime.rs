//! Shared mesh runtime state.
//!
//! Phase C keeps the live per-node [`MeshSlice`] in an `ArcSwap` slot so
//! listener and plugin paths can read the latest mesh view without locks.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{Notify, watch};
use tracing::{info, warn};

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{
    MeshPolicy, PolicyScope, PolicyTargetAttachment, WaypointAttachment, Workload,
    policy_scope_applies_to_workload,
};
use crate::modes::mesh::config_consumer::stream_lifecycle::MeshConfigStreamStatus;
use crate::modes::mesh::federation::FederationStore;
use crate::modes::mesh::multicluster::RemoteEndpointStore;
use crate::modes::mesh::revision::{
    MeshConfigRevision, MeshRevisionApplyToken, MeshRevisionContentIdentity,
    MeshRevisionDiagnostics, MeshRevisionGate, MeshRevisionPolicy, MeshRevisionRejection,
};
use crate::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};
use crate::plugins::mesh::outbound_registry::OutboundRegistry;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct MeshEgressScopeHealth {
    pub sidecar_admitted_services: u64,
    pub sidecar_denied_services: u64,
}

/// Per-runtime operator surface for the active mesh egress scope.
///
/// Hangs off [`MeshRuntimeState`] so tests get isolated state. Updated only
/// when a mesh slice is accepted by the proxy runtime, never from the request
/// path.
pub struct MeshEgressScopeState {
    current: Arc<ArcSwap<Option<MeshEgressScopeSnapshot>>>,
    /// Cached `OutboundRegistry` built from the accepted snapshot's
    /// `known_destinations`. Rebuilt only when a new slice is accepted so
    /// `POST /mesh/egress-scope/test` does not re-normalise the registry on
    /// every admin call.
    test_registry: Arc<ArcSwap<Option<Arc<OutboundRegistry>>>>,
    sidecar_admitted_services: AtomicU64,
    sidecar_denied_services: AtomicU64,
    dry_run_denials_active: AtomicBool,
}

impl MeshEgressScopeState {
    fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            test_registry: Arc::new(ArcSwap::new(Arc::new(None))),
            sidecar_admitted_services: AtomicU64::new(0),
            sidecar_denied_services: AtomicU64::new(0),
            dry_run_denials_active: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> Option<MeshEgressScopeSnapshot> {
        self.current.load_full().as_ref().clone()
    }

    pub fn health(&self) -> MeshEgressScopeHealth {
        MeshEgressScopeHealth {
            sidecar_admitted_services: self.sidecar_admitted_services.load(Ordering::Relaxed),
            sidecar_denied_services: self.sidecar_denied_services.load(Ordering::Relaxed),
        }
    }

    /// Returns the memoised `OutboundRegistry` matching the current snapshot
    /// for admin-side dry-run lookups, or `None` if no slice has been accepted
    /// yet (or the build failed).
    pub fn test_registry(&self) -> Option<Arc<OutboundRegistry>> {
        self.test_registry.load_full().as_ref().clone()
    }

    pub fn install_from_slice(&self, slice: &MeshSlice) {
        let snapshot = slice.sidecar_egress_scope.clone();
        let admitted = snapshot
            .as_ref()
            .map(|scope| scope.sidecar_admitted_services as u64)
            .unwrap_or(0);
        let denied = snapshot
            .as_ref()
            .map(|scope| scope.sidecar_denied_services as u64)
            .unwrap_or(0);
        self.sidecar_admitted_services
            .store(admitted, Ordering::Relaxed);
        self.sidecar_denied_services
            .store(denied, Ordering::Relaxed);

        let dry_run_denied = snapshot
            .as_ref()
            .is_some_and(|scope| scope.dry_run && scope.sidecar_denied_services > 0);
        let was_active = self
            .dry_run_denials_active
            .swap(dry_run_denied, Ordering::AcqRel);
        if dry_run_denied && !was_active {
            warn!(
                sidecar_admitted_services = admitted,
                sidecar_denied_services = denied,
                "Sidecar egress dry-run would deny services; traffic is still admitted"
            );
        } else if !dry_run_denied && was_active {
            info!("Sidecar egress dry-run denials recovered");
        }

        // Rebuild the test-side OutboundRegistry on each accepted slice. Cold
        // path; per-request admin handlers reuse the resulting Arc.
        let registry = snapshot.as_ref().and_then(|scope| {
            match OutboundRegistry::new(&serde_json::json!({
                "registry": &scope.known_destinations,
            })) {
                Ok(registry) => Some(Arc::new(registry)),
                Err(err) => {
                    warn!(
                        error = %err,
                        "Failed to rebuild mesh egress-scope test registry from accepted slice"
                    );
                    None
                }
            }
        });
        self.test_registry.store(Arc::new(registry));

        self.current.store(Arc::new(snapshot));
    }
}

/// Pre-computed per-pod policy scope identity used by node-waypoint mode.
///
/// Node-waypoint accepts traffic for many pods through one listener, so policy
/// scope selection has to be keyed by the source pod identity. This cache keeps
/// the workload namespace/labels next to the SPIFFE ID and delegates matching
/// to the canonical mesh helper to avoid drift from sidecar and plugin paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyScopeCache {
    pub spiffe_id: SpiffeId,
    pub namespace: String,
    pub labels: HashMap<String, String>,
    /// The MeshService this cache was indexed UNDER, when it was built as a
    /// DESTINATION scope. Empty on every source/attestation scope.
    ///
    /// Set only by [`Self::for_destination_service`], from the Service the
    /// destination-scope index is keyed by — never from `Workload.service_name`,
    /// which names a single projection and cannot disambiguate a pod that
    /// several Services select.
    ///
    /// Leaving it empty on source scopes is load-bearing: `PartialEq` on this
    /// struct is the source-attestation collapse used by ambient UDP source
    /// indexing and NodeWaypoint capture-destination resolution, where duplicate
    /// records for one pod must compare EQUAL. Stamping a per-projection service
    /// name into the shared constructors would make those records diverge and
    /// silently fail closed.
    pub service_name: String,
    /// Namespace of [`Self::service_name`]; empty whenever that is empty.
    pub service_namespace: String,
}

impl PolicyScopeCache {
    pub fn new(
        spiffe_id: SpiffeId,
        namespace: impl Into<String>,
        labels: HashMap<String, String>,
    ) -> Self {
        Self {
            spiffe_id,
            namespace: namespace.into(),
            labels,
            service_name: String::new(),
            service_namespace: String::new(),
        }
    }

    pub fn from_workload(workload: &Workload) -> Self {
        Self {
            spiffe_id: workload.spiffe_id.clone(),
            namespace: workload.namespace.clone(),
            labels: workload.selector.labels.clone(),
            service_name: String::new(),
            service_namespace: String::new(),
        }
    }

    /// Build a DESTINATION scope for `workload` reached through the
    /// `(service_namespace, service_name)` MeshService.
    ///
    /// The service identity is the index key, not a workload field, so a pod
    /// projected through several Services yields one destination scope per
    /// Service and each matches only its own `targetRefs`.
    pub fn for_destination_service(
        workload: &Workload,
        service_namespace: &str,
        service_name: &str,
    ) -> Self {
        Self {
            service_name: service_name.to_string(),
            service_namespace: service_namespace.to_string(),
            ..Self::from_workload(workload)
        }
    }

    pub fn policy_applies(&self, policy: &MeshPolicy) -> bool {
        policy_scope_applies_to_workload(policy, &self.namespace, &self.labels)
    }

    /// Destination-scope applicability inside a waypoint path.
    ///
    /// `waypoint` is the authoritative identity of the proxy evaluating this
    /// request. It is REQUIRED, not optional context: slice retention keeps a
    /// `targetRefs` policy when ANY attachment matches and never prunes the
    /// others, so checking only "is this a Gateway attachment?" would let a
    /// policy targeting `{Service reviews, Gateway waypoint-b}` apply to every
    /// destination at waypoint-a. Both halves re-check exactly:
    ///
    /// * `Service` — exact destination `(namespace, name)` membership; absent
    ///   membership fails closed. Shared pod-selector labels never attach a
    ///   Service A policy to Service B traffic.
    /// * `Gateway` / `GatewayClass` — this exact waypoint / this exact
    ///   `spec.gatewayClassName` ([`WaypointAttachment::matches`]).
    ///
    /// A non-waypoint proxy (`waypoint.name == None`) matches no attachment at
    /// all: Istio applies `targetRefs` policies at waypoint proxies only, so a
    /// targeted policy must not become mesh-wide on a NodeWaypoint or Sidecar
    /// destination path.
    pub fn policy_applies_for_destination(
        &self,
        policy: &MeshPolicy,
        waypoint: WaypointAttachment<'_>,
    ) -> bool {
        match &policy.scope {
            PolicyScope::TargetRefs { attachments } => {
                attachments.iter().any(|attachment| match attachment {
                    PolicyTargetAttachment::Service { namespace, name } => {
                        waypoint.name.is_some()
                            && !self.service_name.is_empty()
                            && namespace == &self.service_namespace
                            && name == &self.service_name
                    }
                    PolicyTargetAttachment::Gateway { .. }
                    | PolicyTargetAttachment::GatewayClass { .. } => waypoint.matches(attachment),
                })
            }
            _ => self.policy_applies(policy),
        }
    }
}

/// Snapshot of the DP's xDS resource-warming convergence state.
///
/// Published by the xDS client on every ADS response and surfaced
/// (JWT-authenticated) under `convergence` on `GET /mesh/config-drift`. It
/// carries the per-type `version_info` strings and which required types are
/// still missing — detail intentionally kept off the unauthenticated
/// `/metrics` surface because version strings embed config-change timestamps
/// plus content digests. `None` on [`MeshRuntimeState`] in native mode (there
/// are no per-type xDS versions to report) and before the first ADS response.
#[derive(Debug, Clone, Default, Serialize)]
pub struct XdsConvergenceSnapshot {
    /// Received `version_info` per subscribed resource type, keyed by short
    /// name (`cds`/`eds`/`lds`/`rds`/`sds`/`ecds`/`rtds`).
    pub per_type_versions: std::collections::BTreeMap<String, String>,
    /// Required mesh-slice types (short names) that have not yet delivered an
    /// initial response. Empty once all required types are present; `converged`
    /// still remains false if those types carry different versions.
    pub missing_required_types: Vec<String>,
    /// True once every required type has delivered the same version (the first
    /// slice can build).
    pub converged: bool,
    /// True when all required types are present but their versions are not
    /// identical. This indicates the DP is waiting for coherent required-type
    /// refresh before applying.
    pub version_skew: bool,
}

/// Closed, non-sensitive category for a proxy-runtime slice refusal
/// (issue #4812).
///
/// Every variant is a compile-time label, so the reason the control plane
/// retains can never carry credentials, request data, or unbounded bytes. The
/// wire form is the `MeshSliceRejectReason` proto enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceRuntimeRejectReason {
    /// The slice could not be converted into a serving gateway configuration.
    ConfigBuild,
    /// `ProxyState::update_mesh_config` refused the converted configuration.
    ProxyRefused,
    /// Effective gateway trust material for this slice was unusable.
    TrustUnusable,
    /// Inbound mTLS live-reload preparation failed, or the slice made an
    /// overridden inbound app port newly selectable while live reload is off.
    TlsReload,
    /// Owner-scoped NodeWaypoint DTLS candidate build failed.
    DtlsCandidate,
}

impl MeshSliceRuntimeRejectReason {
    /// Fixed-cardinality diagnostic label. Never caller-supplied text.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::ConfigBuild => "runtime_config_build",
            Self::ProxyRefused => "runtime_proxy_refused",
            Self::TrustUnusable => "runtime_trust_unusable",
            Self::TlsReload => "runtime_tls_reload",
            Self::DtlsCandidate => "runtime_dtls_candidate",
        }
    }
}

/// The proxy runtime's verdict on a received mesh slice (issue #4812).
///
/// Distinct from [`MeshSliceInstall`]: installing a slice only makes it the
/// RECEIVED slice, while this is the second, independent gate that decides
/// whether it becomes the SERVING generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshSliceRuntimeOutcome {
    /// The slice is the serving generation.
    Applied,
    /// The runtime refused the slice; the previous generation keeps serving.
    Rejected(MeshSliceRuntimeRejectReason),
}

impl MeshSliceRuntimeOutcome {
    pub const fn accepted(self) -> bool {
        matches!(self, Self::Applied)
    }

    pub const fn reject_reason(self) -> Option<MeshSliceRuntimeRejectReason> {
        match self {
            Self::Applied => None,
            Self::Rejected(reason) => Some(reason),
        }
    }
}

/// One published runtime verdict, bound to the exact slice version it judged.
///
/// The version binding is what keeps a late verdict from being reported against
/// a newer slice: the native `MeshSubscribe` client only reports a verdict whose
/// version matches the slice it last installed on its own stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSliceRuntimeVerdict {
    pub version: String,
    pub outcome: MeshSliceRuntimeOutcome,
}

/// Lock-free holder for the current Layer 2 mesh slice.
#[derive(Clone)]
pub struct MeshRuntimeState {
    current: Arc<ArcSwap<Option<MeshSlice>>>,
    applied: Arc<ArcSwap<Option<MeshSlice>>>,
    /// Wall-clock timestamp of the most recent `install_slice` call. Stays in lock-step
    /// with `record_mesh_config_received` (the Prometheus metric backing the
    /// `ferrum_mesh_config_last_received_timestamp_seconds` gauge) so dashboard
    /// staleness alerts observe the same receive events. `None` until the first
    /// slice arrives.
    last_install_at: Arc<ArcSwap<Option<DateTime<Utc>>>>,
    /// Wall-clock timestamp of the most recent slice accepted by the proxy
    /// runtime. This intentionally differs from `last_install_at`: invalid
    /// updates may be received and rejected while the proxy continues serving
    /// the previous accepted slice.
    last_applied_at: Arc<ArcSwap<Option<DateTime<Utc>>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<AtomicBool>,
    revision_tx: Arc<watch::Sender<u64>>,
    applied_revision_tx: Arc<watch::Sender<u64>>,
    egress_scope: Arc<MeshEgressScopeState>,
    federation_store: FederationStore,
    remote_endpoint_store: RemoteEndpointStore,
    /// Latest xDS resource-warming convergence snapshot, published by the xDS
    /// client. `None` in native mode and before the first ADS response.
    xds_convergence: Arc<ArcSwap<Option<Arc<XdsConvergenceSnapshot>>>>,
    /// Closed-set configuration-stream attempt/liveness status published by the
    /// active consumer (issue #3854). `None` until the consumer starts, and for
    /// the localized `file` source, which has no stream at all.
    config_stream: Arc<ArcSwap<Option<MeshConfigStreamStatus>>>,
    /// Authoritative config-revision freshness gate (issue #2473). Every slice
    /// install runs through it BEFORE the `ArcSwap` replacement, so a lagging
    /// fallback CP cannot roll this data plane back to an older generation.
    /// Cold path only — nothing on the proxy request path reads it.
    revision_gate: Arc<MeshRevisionGate>,
    /// Latest proxy-runtime acceptance verdict, published for the CP
    /// slice-status report path (issue #4812). Single-slot `watch`, written
    /// once per apply verdict and read only by the configuration consumer —
    /// never on the proxy request path, and never unbounded: a superseded
    /// verdict is replaced rather than queued.
    runtime_verdict_tx: Arc<watch::Sender<Option<Arc<MeshSliceRuntimeVerdict>>>>,
}

/// Outcome of [`MeshRuntimeState::install_slice`].
///
/// Deliberately NOT `#[must_use]`: local, inherently ordered installers (the
/// file source, tests) legitimately ignore it, while the two control-plane-fed
/// consumers (native `MeshSubscribe`, xDS ADS) match on it. The gate itself is
/// unconditional — the enum only reports what it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshSliceInstall {
    /// The slice replaced live state.
    Installed,
    /// The slice was quarantined; the previously installed slice keeps serving.
    Quarantined(MeshRevisionRejection),
}

impl MeshSliceInstall {
    pub const fn installed(&self) -> bool {
        matches!(self, Self::Installed)
    }

    pub fn rejection(&self) -> Option<&MeshRevisionRejection> {
        match self {
            Self::Installed => None,
            Self::Quarantined(rejection) => Some(rejection),
        }
    }
}

impl MeshRuntimeState {
    pub fn new() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        let (applied_revision_tx, _) = watch::channel(0u64);
        let (runtime_verdict_tx, _) = watch::channel(None);
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            applied: Arc::new(ArcSwap::new(Arc::new(None))),
            last_install_at: Arc::new(ArcSwap::new(Arc::new(None))),
            last_applied_at: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
            applied_revision_tx: Arc::new(applied_revision_tx),
            egress_scope: Arc::new(MeshEgressScopeState::new()),
            federation_store: FederationStore::new(),
            remote_endpoint_store: RemoteEndpointStore::new(),
            xds_convergence: Arc::new(ArcSwap::new(Arc::new(None))),
            config_stream: Arc::new(ArcSwap::new(Arc::new(None))),
            revision_gate: Arc::new(MeshRevisionGate::new()),
            runtime_verdict_tx: Arc::new(runtime_verdict_tx),
        }
    }

    /// Install the operator's revision-gate policy
    /// (`FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS`). Called once during mesh
    /// startup, before any consumer is spawned.
    pub fn set_revision_policy(&self, policy: MeshRevisionPolicy) {
        self.revision_gate.set_policy(policy);
    }

    /// Revision currently admitted into the RECEIVED slot by the freshness
    /// gate, or `None` when no revisioned slice has been admitted. Raw
    /// CP-supplied value — for ordering, not for logging; use
    /// [`Self::revision_diagnostics`] for anything operator-facing.
    pub fn accepted_revision(&self) -> Option<MeshConfigRevision> {
        self.revision_gate.accepted()
    }

    /// Revision of the slice the proxy runtime last accepted — the last-good
    /// generation, and the rollback target for a runtime-refused candidate.
    /// Raw CP-supplied value, same handling rule as [`Self::accepted_revision`].
    pub fn applied_revision(&self) -> Option<MeshConfigRevision> {
        self.revision_gate.applied()
    }

    /// Operator diagnostics for `GET /mesh/config-drift`'s `revision` block.
    pub fn revision_diagnostics(&self) -> MeshRevisionDiagnostics {
        self.revision_gate.diagnostics()
    }

    /// Clear the accepted revision (operator escape hatch behind
    /// `POST /mesh/config-revision/reset`). Returns the cleared revision with
    /// its CP-supplied authority already sanitized for the audit log and the
    /// admin response.
    ///
    /// This is the documented recovery for a sequence rewind INSIDE one
    /// authority — a config store restored from backup without bumping
    /// `FERRUM_MESH_CONFIG_AUTHORITY_ID`. It never installs anything itself: it
    /// only makes the next slice from any authority eligible again.
    pub fn reset_accepted_revision(&self) -> Option<MeshConfigRevision> {
        self.revision_gate.reset()
    }

    /// Publish the latest xDS resource-warming convergence snapshot. Called by
    /// the xDS client on every ADS response (xDS mode only); read
    /// JWT-authenticated by the `/mesh/config-drift` admin handler.
    pub fn set_xds_convergence(&self, snapshot: XdsConvergenceSnapshot) {
        self.xds_convergence
            .store(Arc::new(Some(Arc::new(snapshot))));
    }

    /// Latest xDS convergence snapshot, or `None` in native mode / before the
    /// first ADS response.
    pub fn xds_convergence(&self) -> Option<Arc<XdsConvergenceSnapshot>> {
        self.xds_convergence.load_full().as_ref().clone()
    }

    /// Publish the configuration-stream attempt/liveness status (issue #3854).
    ///
    /// Lock-free `ArcSwap` store on a cold path (once per attempt transition).
    /// Every field is a closed set or a counter — never an endpoint URL, node
    /// id, credential path, or token-derived value.
    pub fn set_config_stream_status(&self, status: MeshConfigStreamStatus) {
        self.config_stream.store(Arc::new(Some(status)));
    }

    /// Latest configuration-stream status, or `None` for the localized `file`
    /// source and before the consumer's first publication.
    pub fn config_stream_status(&self) -> Option<MeshConfigStreamStatus> {
        *self.config_stream.load_full()
    }

    /// Return the latest mesh slice snapshot.
    pub fn snapshot(&self) -> Arc<Option<MeshSlice>> {
        self.current.load_full()
    }

    /// Return the latest slice accepted by the proxy runtime.
    pub fn applied_snapshot(&self) -> Arc<Option<MeshSlice>> {
        self.applied.load_full()
    }

    /// Wall-clock timestamp of the most recent slice install, or `None` if no
    /// slice has been installed yet. Read lock-free by the
    /// `/mesh/config-drift` admin handler to compute slice staleness.
    pub fn last_install_at(&self) -> Option<DateTime<Utc>> {
        *self.last_install_at.load_full().as_ref()
    }

    /// Wall-clock timestamp of the most recent accepted slice, or `None` if
    /// no slice has been accepted by the proxy runtime yet.
    pub fn last_applied_at(&self) -> Option<DateTime<Utc>> {
        *self.last_applied_at.load_full().as_ref()
    }

    /// True once at least one mesh slice has been installed.
    pub fn has_first_slice(&self) -> bool {
        self.has_first.load(Ordering::Acquire)
    }

    /// Subscribe to every slice installation.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Subscribe to slices accepted by the proxy runtime.
    pub fn subscribe_applied(&self) -> watch::Receiver<u64> {
        self.applied_revision_tx.subscribe()
    }

    /// Operator surface for the active mesh egress scope. Updated only when a
    /// new slice is accepted by the proxy runtime.
    pub fn egress_scope_state(&self) -> &MeshEgressScopeState {
        &self.egress_scope
    }

    /// Returns the live federation store. The store is always present, even
    /// when no poller has been spawned — callers that need a "has the poller
    /// actually populated anything" check should consult
    /// [`FederationStore::has_first_success`].
    pub fn federation_store(&self) -> &FederationStore {
        &self.federation_store
    }

    /// Returns the live remote-cluster endpoint store. Always present, even
    /// when no discovery poller has been spawned; in that case its snapshot is
    /// simply empty. The `GET /mesh/remote-clusters` admin handler reads its
    /// `snapshot()` lock-free for the `discovered` view (scoped to the accepted
    /// slice's configured clusters). The store is only mutated by the live
    /// discovery poller — there is no production seeder, so the snapshot can
    /// never be staged through this public accessor.
    pub fn remote_endpoint_store(&self) -> &RemoteEndpointStore {
        &self.remote_endpoint_store
    }

    /// Hot-swap the live mesh slice and notify waiters on the first install.
    ///
    /// Fail-closed on config-revision ordering (issue #2473): the candidate's
    /// [`MeshSlice::revision`] is admitted by the freshness gate BEFORE the
    /// `ArcSwap` replacement, so a slice that is older than — or from a
    /// different ordering domain than — the accepted revision never becomes
    /// live. A quarantined candidate mutates nothing: the previously installed
    /// slice keeps serving, no receive metric is recorded, no `last_install_at`
    /// stamp advances, and no revision watcher is woken. The gate is
    /// unconditional and lives here rather than in any one consumer, so the
    /// native `MeshSubscribe` client, the xDS ADS client, and any future
    /// installer share exactly one ordering decision.
    ///
    /// Admission is PROVISIONAL: it only makes the candidate the received
    /// slice. The watermark is finalized by [`Self::record_applied_slice_with_token`] when
    /// the proxy runtime accepts it, or returned to the last applied generation
    /// by [`Self::record_rejected_slice`] when the runtime refuses it.
    ///
    /// The candidate's semantic content identity (`slice_content_identity`)
    /// is bound to its revision inside the gate (issue #3611), so an equal
    /// revision installs only when it carries identical content. That is what
    /// makes a producer whose scalar revision is not content-unique — a
    /// Kubernetes controller CP publishing the MINIMUM per-scope convergence
    /// watermark while its reflector snapshot already holds later changes from
    /// another scope — unable to roll this data plane back through a lagging
    /// replica at the same sequence.
    pub fn install_slice(&self, slice: MeshSlice) -> MeshSliceInstall {
        let content = slice_content_identity(&slice);
        if let Err(rejection) =
            self.revision_gate
                .admit(slice.revision.as_ref(), content, Utc::now())
        {
            return MeshSliceInstall::Quarantined(rejection);
        }
        crate::plugins::mesh::prometheus_helpers::record_mesh_config_received(&slice.namespace);
        self.current.store(Arc::new(Some(slice)));
        // Stamp the receive timestamp before publishing the revision bump so
        // any observer that reacts to the revision sees a fresh
        // `last_install_at` rather than the stale one.
        self.last_install_at.store(Arc::new(Some(Utc::now())));
        self.revision_tx.send_modify(|revision| *revision += 1);
        let was_first = self.has_first.swap(true, Ordering::AcqRel);
        if !was_first {
            self.first_ready.notify_waiters();
        }
        MeshSliceInstall::Installed
    }

    /// Capture the config-revision apply capability before asynchronous proxy
    /// preparation begins. A concurrent operator reset invalidates the token,
    /// so completion of pre-reset work cannot restore the cleared watermark.
    pub fn begin_revision_apply(&self, slice: &MeshSlice) -> Option<MeshRevisionApplyToken> {
        self.revision_gate
            .begin_apply(slice.revision.as_ref(), slice_content_identity(slice))
    }

    /// Commit a runtime-accepted slice with the capability captured before its
    /// asynchronous apply began.
    ///
    /// A missing token refuses publication and preserves the last committed
    /// snapshot and watermark. Callers must obtain a token before preparing or
    /// publishing a generation. An explicit reset may invalidate a token that
    /// was captured correctly; its cleared watermarks remain cleared while the
    /// snapshot still reflects the proxy's completed apply.
    pub fn record_applied_slice_with_token(
        &self,
        slice: &MeshSlice,
        token: Option<MeshRevisionApplyToken>,
    ) -> bool {
        let Some(token) = token else {
            self.revision_gate
                .reject_missing_apply_token(slice.revision.as_ref());
            return false;
        };
        let content = slice_content_identity(slice);
        let _ = self
            .revision_gate
            .commit_applied(slice.revision.as_ref(), content, token);
        // GAP-3E: refresh RTDS-driven consumers only after proxy config
        // acceptance. Rejected slices must not mutate live log/transformer
        // state while the proxy keeps serving the previous accepted config.
        // Fault percentages are already bound to the candidate plugin cache
        // and request epoch before this post-accept fanout runs.
        #[cfg(test)]
        let _overlay_guard = crate::modes::mesh::runtime_overlay_consumers::test_lock();
        crate::modes::mesh::runtime_overlay_consumers::apply_overlay(&slice.runtime_overlay);
        self.egress_scope.install_from_slice(slice);
        self.applied.store(Arc::new(Some(slice.clone())));
        self.last_applied_at.store(Arc::new(Some(Utc::now())));
        self.applied_revision_tx
            .send_modify(|revision| *revision += 1);
        // Issue #4812: the control plane's slice-drift surface must learn the
        // RUNTIME verdict, not just the install-time one. Publishing here — the
        // single commit point every runtime-acceptance path funnels through —
        // means no future apply stage can forget to report success.
        self.publish_runtime_verdict(&slice.version, MeshSliceRuntimeOutcome::Applied);
        true
    }

    /// Publish the proxy runtime's verdict on `version` for the configuration
    /// consumer to report to the control plane (issue #4812).
    ///
    /// Single-slot and non-blocking: a verdict superseded before the consumer
    /// observes it is replaced, never queued, so a flapping control plane
    /// cannot grow DP memory or add work to the request path. Reporting is
    /// best-effort observability and never gates the apply itself.
    pub fn publish_runtime_verdict(&self, version: &str, outcome: MeshSliceRuntimeOutcome) {
        self.runtime_verdict_tx
            .send_replace(Some(Arc::new(MeshSliceRuntimeVerdict {
                version: version.to_string(),
                outcome,
            })));
    }

    /// Observe runtime verdicts published after this call. The current value is
    /// marked seen, so a consumer attaching to a new stream never replays a
    /// verdict for a slice a previous stream delivered.
    pub fn subscribe_runtime_verdict(
        &self,
    ) -> watch::Receiver<Option<Arc<MeshSliceRuntimeVerdict>>> {
        self.runtime_verdict_tx.subscribe()
    }

    /// Finalize a received candidate the mesh proxy runtime REFUSED.
    ///
    /// The ROLLBACK half of the config-revision lifecycle (issue #2473).
    /// `install_slice` advances the accepted watermark when a candidate enters
    /// the received slot, but the proxy runtime is a second, independent gate:
    /// slice→config preparation or `ProxyState::update_config` can still refuse
    /// it, leaving the previous generation serving. Without this call the
    /// watermark would keep the refused revision, so one runtime-invalid slice
    /// published at a far-future sequence would lock out every valid revision
    /// beneath it — a hostile or buggy control plane could poison the ordering
    /// domain and block recovery with a slice that never served a request.
    ///
    /// `received` must be the exact `Arc` the apply path pulled from
    /// [`Self::snapshot`]. Two independent identity checks make a late
    /// rejection safe against a concurrent newer install:
    ///
    /// 1. Pointer identity against the live received slot — each install
    ///    publishes a fresh `Arc`, and the caller holding this one keeps the
    ///    address from being reused, so a mismatch proves a newer candidate has
    ///    superseded it.
    /// 2. Exact `(authority, sequence)` equality inside the gate lock, which
    ///    closes the window between the pointer check and the rollback.
    ///
    /// Returns whether the watermark was rolled back. Cold path; nothing on the
    /// proxy request path calls it.
    pub fn record_rejected_slice(&self, received: &Arc<Option<MeshSlice>>) -> bool {
        let Some(slice) = received.as_ref().as_ref() else {
            return false;
        };
        if !Arc::ptr_eq(&self.current.load_full(), received) {
            return false;
        }
        self.revision_gate
            .rollback_rejected(slice.revision.as_ref(), slice_content_identity(slice))
    }

    /// Begin a downstream stage's evaluation of the RECEIVED candidate.
    ///
    /// `received` must be the exact `Arc` the stage pulled from
    /// [`Self::snapshot`]: the guard finalizes through
    /// [`Self::record_rejected_slice`], whose two identity checks are what keep
    /// a late refusal from disturbing a newer candidate received meanwhile.
    ///
    /// See [`MeshSliceEvaluation`] for why the verdict is a guard rather than a
    /// call each stage has to remember (issue #4041).
    pub fn evaluate_received_slice(
        &self,
        received: &Arc<Option<MeshSlice>>,
    ) -> MeshSliceEvaluation {
        MeshSliceEvaluation {
            state: self.clone(),
            received: Arc::clone(received),
            resolved: false,
        }
    }

    /// Resolve once the initial mesh slice is available.
    ///
    /// Race-free against concurrent installs: the waiter is registered before
    /// checking the flag, so a first install cannot be missed between load and
    /// await.
    pub async fn wait_for_first_slice(&self) {
        let notified = self.first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.has_first.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// A received mesh slice awaiting the verdict of a downstream pipeline stage.
///
/// [`MeshRuntimeState::install_slice`] advances the accepted watermark
/// PROVISIONALLY: passing the freshness gate only makes a candidate the
/// RECEIVED slice. Whatever stage rules on it next has to finalize that
/// watermark exactly once — and there is more than one such stage:
///
/// * slice→config conversion, materialization, and mesh-field validation in
///   the native / xDS / stock-xDS startup wait (`wait_for_initial_mesh_config`);
/// * the same preparation plus `ProxyState::update_config` in the steady-state
///   apply loop.
///
/// A stage that refuses a candidate without finalizing leaves a slice that
/// never served a request holding the watermark, so every corrected slice at or
/// below its sequence is quarantined and the data plane cannot recover without
/// `POST /mesh/config-revision/reset` (issue #4041).
///
/// This guard makes the finalization structural instead of a rule each stage
/// has to remember: it rolls the watermark back on drop unless [`Self::pass`]
/// was called, so a newly added early return, a `?`, or a whole new stage
/// cannot silently reintroduce that hole. Rollback returns the accepted
/// revision to the last PROXY-APPLIED generation — `None` before the first
/// apply — which is exactly what makes a corrected slice at the SAME sequence
/// as the refused one, or at a lower sequence, eligible again while leaving the
/// last-good guarantee intact: content that diverges from the applied
/// generation at ITS revision is still quarantined.
///
/// Passing is not applying. It records only that this stage did not refuse the
/// candidate; the stage that actually installs the generation still commits
/// through [`MeshRuntimeState::record_applied_slice_with_token`].
#[must_use = "an unresolved evaluation rolls the config-revision watermark back on drop"]
pub struct MeshSliceEvaluation {
    state: MeshRuntimeState,
    received: Arc<Option<MeshSlice>>,
    resolved: bool,
}

impl MeshSliceEvaluation {
    /// Record that this stage did not refuse the candidate, leaving the
    /// provisionally advanced watermark in place for the next stage (or for the
    /// apply commit) to finalize.
    pub fn pass(mut self) {
        self.resolved = true;
    }

    /// Refuse the candidate now, returning the accepted watermark to the last
    /// proxy-applied generation.
    ///
    /// Equivalent to dropping the guard, but returns whether the watermark
    /// actually moved so the refusing stage can say so in its log line. `false`
    /// means a newer candidate has already superseded this one (or the slice
    /// carried no revision to roll back), not that the refusal was ignored.
    pub fn reject(mut self) -> bool {
        self.finalize()
    }

    fn finalize(&mut self) -> bool {
        if self.resolved {
            return false;
        }
        self.resolved = true;
        self.state.record_rejected_slice(&self.received)
    }
}

impl Drop for MeshSliceEvaluation {
    fn drop(&mut self) {
        self.finalize();
    }
}

/// Deterministic semantic content identity of a slice, bound to its config
/// revision by the freshness gate (issue #3611).
///
/// Reuses the canonical CP-side digest
/// ([`crate::grpc::mesh_slice_drift::slice_content_digest`]): it clears the
/// observability-only `version` and the ordering-only `revision`, then
/// canonicalizes the JSON (recursively sorting object keys while preserving
/// array order), so two slices that are semantically identical always produce
/// the same identity regardless of map iteration order or which control plane
/// serialized them. That is what makes a reconnect replay from a DIFFERENT CP
/// replica still count as identical content at an equal revision.
///
/// Both installers — the native `MeshSubscribe` client and the xDS ADS client —
/// reach the gate through [`MeshRuntimeState::install_slice`], so both bind the
/// same identity and neither can be made to disagree with the other.
///
/// A digest failure yields [`MeshRevisionContentIdentity::Unavailable`], which
/// the gate refuses (`unidentified_content`): the error is discarded here
/// precisely so no payload fragment can reach a log line or an admin surface.
/// This is cold path — a config change, never a request.
pub(crate) fn slice_content_identity(slice: &MeshSlice) -> MeshRevisionContentIdentity {
    match crate::grpc::mesh_slice_drift::slice_content_digest(slice) {
        Ok(digest) => MeshRevisionContentIdentity::from_digest(digest),
        Err(_) => MeshRevisionContentIdentity::Unavailable,
    }
}

impl Default for MeshRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{PolicyScope, WorkloadSelector};

    fn install_slice_for_test(state: &MeshRuntimeState, slice: MeshSlice) {
        state.install_slice(slice);
    }

    #[test]
    fn reset_invalidates_an_in_flight_revision_apply_token() {
        let state = MeshRuntimeState::new();
        let candidate = MeshSlice {
            revision: Some(MeshConfigRevision::new("db", 10)),
            ..MeshSlice::default()
        };
        assert!(state.install_slice(candidate.clone()).installed());
        let token = state
            .begin_revision_apply(&candidate)
            .expect("the admitted candidate mints an apply token");

        assert_eq!(
            state.reset_accepted_revision(),
            Some(MeshConfigRevision::new("db", 10))
        );
        state.record_applied_slice_with_token(&candidate, Some(token));

        assert!(
            state.accepted_revision().is_none(),
            "a pre-reset apply completion must not resurrect accepted"
        );
        assert!(
            state.applied_revision().is_none(),
            "a pre-reset apply completion must not recreate the rollback target"
        );
        assert_eq!(
            state
                .applied_snapshot()
                .as_ref()
                .as_ref()
                .and_then(|slice| slice.revision.as_ref()),
            Some(&MeshConfigRevision::new("db", 10)),
            "the proxy-accepted content remains observable even though reset keeps the ordering baseline clear"
        );
    }

    #[test]
    fn xds_convergence_round_trips_and_defaults_none() {
        let state = MeshRuntimeState::new();
        // Native mode / pre-first-response: no snapshot published.
        assert!(state.xds_convergence().is_none());

        state.set_xds_convergence(XdsConvergenceSnapshot {
            per_type_versions: std::collections::BTreeMap::from([(
                "ecds".to_string(),
                "v2".to_string(),
            )]),
            missing_required_types: vec!["eds".to_string()],
            converged: false,
            version_skew: false,
        });

        let snapshot = state.xds_convergence().expect("snapshot published");
        assert!(!snapshot.converged);
        assert_eq!(snapshot.missing_required_types, vec!["eds".to_string()]);
        assert_eq!(
            snapshot.per_type_versions.get("ecds").map(String::as_str),
            Some("v2")
        );
    }

    #[tokio::test]
    async fn wait_for_first_slice_resolves_after_install() {
        let state = MeshRuntimeState::new();
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move {
                state.wait_for_first_slice().await;
                state
                    .snapshot()
                    .as_ref()
                    .as_ref()
                    .map(|slice| slice.version.clone())
            })
        };

        tokio::task::yield_now().await;
        install_slice_for_test(
            &state,
            MeshSlice {
                version: "v1".to_string(),
                ..MeshSlice::default()
            },
        );

        let observed = waiter.await.expect("waiter task should complete");
        assert_eq!(observed.as_deref(), Some("v1"));
    }

    #[tokio::test]
    async fn wait_for_first_slice_returns_immediately_when_already_installed() {
        let state = MeshRuntimeState::new();
        install_slice_for_test(
            &state,
            MeshSlice {
                version: "v1".to_string(),
                ..MeshSlice::default()
            },
        );

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            state.wait_for_first_slice(),
        )
        .await
        .expect("already-installed slice should not block");
    }

    #[tokio::test]
    async fn last_install_at_tracks_each_install() {
        // The receive metric reads this field for the slice staleness signal,
        // so verify it is `None` pre-install, populated after the first install,
        // and advances on each
        // subsequent install (no caching/clamping). Use an explicit
        // delay between installs because two `Utc::now()` calls inside
        // the same nanosecond would compare equal on fast machines and
        // mask a bug where the second install failed to swap the slot.
        let state = MeshRuntimeState::new();
        assert!(state.last_install_at().is_none(), "no slice installed yet");

        install_slice_for_test(
            &state,
            MeshSlice {
                version: "v1".to_string(),
                ..MeshSlice::default()
            },
        );
        let first = state
            .last_install_at()
            .expect("first install must stamp last_install_at");

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        install_slice_for_test(
            &state,
            MeshSlice {
                version: "v2".to_string(),
                ..MeshSlice::default()
            },
        );
        let second = state
            .last_install_at()
            .expect("second install must keep last_install_at populated");

        assert!(
            second > first,
            "second install must advance last_install_at past the first"
        );
    }

    #[tokio::test]
    async fn applied_snapshot_tracks_only_accepted_slices() {
        let state = MeshRuntimeState::new();
        let applied_rx = state.subscribe_applied();
        install_slice_for_test(
            &state,
            MeshSlice {
                version: "received-only".to_string(),
                ..MeshSlice::default()
            },
        );

        assert!(state.applied_snapshot().as_ref().is_none());
        assert!(state.last_applied_at().is_none());
        assert_eq!(
            *applied_rx.borrow(),
            0,
            "received-only slices must not notify applied-slice watchers"
        );

        let accepted = MeshSlice {
            version: "accepted".to_string(),
            ..MeshSlice::default()
        };
        assert!(state.install_slice(accepted.clone()).installed());
        let token = state.begin_revision_apply(&accepted);
        state.record_applied_slice_with_token(&accepted, token);

        assert_eq!(
            state
                .applied_snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("accepted")
        );
        assert!(state.last_applied_at().is_some());
        assert_eq!(
            *applied_rx.borrow(),
            1,
            "accepted slices notify applied-slice watchers"
        );
    }

    #[test]
    fn policy_scope_cache_delegates_to_canonical_helper() {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "reviews".to_string());
        let cache = PolicyScopeCache::new(
            SpiffeId::new("spiffe://td/ns/default/sa/reviews").expect("test SPIFFE ID is valid"),
            "default",
            labels.clone(),
        );
        let policy = MeshPolicy {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: Some("default".to_string()),
                },
            },
            rules: Vec::new(),
        };

        assert!(cache.policy_applies(&policy));
        assert_eq!(
            cache.policy_applies(&policy),
            policy_scope_applies_to_workload(&policy, "default", &cache.labels)
        );
    }
}
