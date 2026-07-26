//! Centralized, fail-closed validation of non-heartbeat `MeshConfigUpdate`
//! frames (issue #2457).
//!
//! Both consumers of `MeshConfigSync.MeshSubscribe` — the local native DP
//! client (`super::native_client`) and the multi-cluster remote-discovery
//! dialer (`crate::modes::mesh::multicluster`) — must bind a response to the
//! exact subscription that opened the stream **before** any slice install or
//! endpoint import. A structurally valid slice for another node, namespace, or
//! workload scope would otherwise replace last-good local state or populate a
//! remote cluster entry with wrong-tenant endpoints.
//!
//! The in-repo CP derives the returned slice from the request
//! (`MeshSlice::from_gateway_config` echoes `node_id` / `namespace` /
//! `workload_spiffe_id` / `waypoint_name` verbatim, and
//! `build_mesh_config_update_from_slice` stamps the envelope `version` from the
//! slice), so this is a consumer-side defense against a cross-wired, skewed,
//! proxied, or independently implemented control plane — not a claim that the
//! current CP emits bad responses.
//!
//! Heartbeats stay explicit: they carry no slice, so callers route them to
//! [`validate_update_ferrum_version`] and never to
//! [`validate_mesh_config_update`], which rejects a heartbeat-marked frame
//! rather than parsing one.

use tracing::warn;

use crate::grpc::dp_client::check_cp_version_compatibility;
use crate::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use crate::modes::mesh::slice::MeshSlice;

/// Maximum characters of a control-plane-supplied value rendered into a
/// diagnostic. Response fields are attacker-influenceable in a cross-wired or
/// hostile-CP scenario, so diagnostics stay bounded instead of echoing an
/// arbitrarily long payload into the logs.
const DIAGNOSTIC_VALUE_MAX_CHARS: usize = 64;

/// Local alias keeping the rejection call sites compact.
type Reason = MeshUpdateRejectReason;

/// Which consumer rejected an update. Used as the bounded `consumer` metric
/// label; both variants are compile-time constants, so the label space cannot
/// grow at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshUpdateConsumer {
    /// Local native `MeshSubscribe` stream feeding `MeshRuntimeState`.
    Native,
    /// One-shot multi-cluster remote-discovery fetch.
    RemoteDiscovery,
}

impl MeshUpdateConsumer {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::RemoteDiscovery => "remote_discovery",
        }
    }
}

/// Why a `MeshConfigUpdate` was refused. Used as the bounded `reason` metric
/// label — a fixed, compile-time set, never a control-plane-supplied string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshUpdateRejectReason {
    /// The response carried no `ferrum_version` at all.
    MissingFerrumVersion,
    /// The CP's `ferrum_version` is not compatible with this binary.
    IncompatibleFerrumVersion,
    /// A frame marked `heartbeat` reached the slice-install path.
    UnexpectedHeartbeat,
    /// `mesh_slice_json` did not parse as a `MeshSlice`.
    InvalidSliceJson,
    /// The envelope `version` disagrees with the embedded `MeshSlice.version`.
    EnvelopeVersionMismatch,
    /// The slice is scoped to a different node than the subscription.
    NodeIdMismatch,
    /// The slice is scoped to a different namespace than the subscription.
    NamespaceMismatch,
    /// The subscription pinned a workload SPIFFE ID the slice does not echo.
    WorkloadScopeMismatch,
    /// The subscription pinned a waypoint the slice does not echo.
    WaypointScopeMismatch,
}

impl MeshUpdateRejectReason {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::MissingFerrumVersion => "missing_ferrum_version",
            Self::IncompatibleFerrumVersion => "incompatible_ferrum_version",
            Self::UnexpectedHeartbeat => "unexpected_heartbeat",
            Self::InvalidSliceJson => "invalid_slice_json",
            Self::EnvelopeVersionMismatch => "envelope_version_mismatch",
            Self::NodeIdMismatch => "node_id_mismatch",
            Self::NamespaceMismatch => "namespace_mismatch",
            Self::WorkloadScopeMismatch => "workload_scope_mismatch",
            Self::WaypointScopeMismatch => "waypoint_scope_mismatch",
        }
    }

    /// Whether a streaming consumer must tear the stream down rather than skip
    /// the frame.
    ///
    /// A **binding** failure (wrong node/namespace/scope, or an incompatible CP
    /// version) means the stream is serving the wrong subscription — nothing
    /// else it sends can be trusted either, so the native client drops it and
    /// lets multi-CP failover move to the next control plane. A **content**
    /// failure (unparseable JSON, envelope/slice version disagreement, a stray
    /// heartbeat-marked frame) is per-frame: drop the frame, keep the last-good
    /// slice, and stay connected so a corrected broadcast still converges.
    /// Neither outcome ever mutates runtime state.
    ///
    /// The one-shot remote-discovery fetch ignores this split and fails the
    /// whole poll on any rejection, preserving last-good endpoints.
    pub const fn terminates_stream(self) -> bool {
        match self {
            Self::MissingFerrumVersion
            | Self::IncompatibleFerrumVersion
            | Self::NodeIdMismatch
            | Self::NamespaceMismatch
            | Self::WorkloadScopeMismatch
            | Self::WaypointScopeMismatch => true,
            Self::UnexpectedHeartbeat | Self::InvalidSliceJson | Self::EnvelopeVersionMismatch => {
                false
            }
        }
    }
}

/// A refused update: a bounded reason label plus a safe, non-secret diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshUpdateRejection {
    reason: MeshUpdateRejectReason,
    detail: String,
}

impl MeshUpdateRejection {
    pub const fn reason(&self) -> MeshUpdateRejectReason {
        self.reason
    }

    /// Human-readable diagnostic. Every control-plane-supplied value inside it
    /// is length-bounded and control-character-stripped; no credential, token,
    /// or slice payload is included.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub const fn terminates_stream(&self) -> bool {
        self.reason.terminates_stream()
    }
}

impl std::fmt::Display for MeshUpdateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_metric_label(), self.detail)
    }
}

impl std::error::Error for MeshUpdateRejection {}

/// The exact subscription context a response must echo.
///
/// Built from the `MeshSubscribeRequest` actually put on the wire
/// ([`Self::from_subscribe_request`]) so the expectation and the request can
/// never drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshUpdateExpectation {
    node_id: String,
    namespace: String,
    workload_spiffe_id: Option<String>,
    waypoint_name: Option<String>,
}

impl MeshUpdateExpectation {
    pub fn from_subscribe_request(request: &MeshSubscribeRequest) -> Self {
        Self {
            node_id: request.node_id.clone(),
            namespace: request.namespace.clone(),
            // Mirror the CP's own request normalization so a faithful echo
            // compares equal: `MeshSliceRequest::from_native` treats an
            // exactly-empty `workload_spiffe_id` as unpinned (`non_empty`)...
            workload_spiffe_id: (!request.workload_spiffe_id.is_empty())
                .then(|| request.workload_spiffe_id.clone()),
            // ...while `with_waypoint_name` treats a whitespace-only
            // `waypoint_name` as unpinned and echoes the raw string otherwise.
            waypoint_name: (!request.waypoint_name.trim().is_empty())
                .then(|| request.waypoint_name.clone()),
        }
    }
}

/// Validate the `ferrum_version` carried by **any** `MeshSubscribe` frame,
/// heartbeat or slice-bearing, under the same compatibility contract the local
/// native client has always applied (`check_cp_version_compatibility`): the
/// field must be present and major/minor-compatible.
///
/// Records the reason-labelled rejection metric and a safe diagnostic before
/// returning `Err`, so no call site can drop a rejection silently.
pub fn validate_update_ferrum_version(
    ferrum_version: &str,
    consumer: MeshUpdateConsumer,
) -> Result<(), MeshUpdateRejection> {
    if ferrum_version.trim().is_empty() {
        let detail = "response carries no ferrum_version".to_string();
        return rejected(consumer, Reason::MissingFerrumVersion, detail);
    }
    if check_cp_version_compatibility(ferrum_version).is_err() {
        // The upstream message embeds the CP-supplied version verbatim, so the
        // diagnostic is rebuilt from a bounded, sanitized rendering instead.
        let detail = format!(
            "control-plane ferrum_version {} is incompatible with data-plane v{}",
            diagnostic_value(ferrum_version),
            crate::FERRUM_VERSION
        );
        return rejected(consumer, Reason::IncompatibleFerrumVersion, detail);
    }
    Ok(())
}

/// Validate a **non-heartbeat** `MeshConfigUpdate` against the subscription
/// that opened the stream and return the parsed slice.
///
/// Every check runs before the caller may install or import anything, so a
/// rejected response can never mutate last-good state. Callers route heartbeat
/// frames to [`validate_update_ferrum_version`] instead; a heartbeat-marked
/// frame reaching here is itself a rejection.
///
/// Records the reason-labelled rejection metric and a safe diagnostic before
/// returning `Err`.
pub fn validate_mesh_config_update(
    update: &MeshConfigUpdate,
    expected: &MeshUpdateExpectation,
    consumer: MeshUpdateConsumer,
) -> Result<MeshSlice, MeshUpdateRejection> {
    validate_update_ferrum_version(&update.ferrum_version, consumer)?;

    if update.heartbeat {
        let detail = "frame is a heartbeat and carries no slice".to_string();
        return rejected(consumer, Reason::UnexpectedHeartbeat, detail);
    }

    let slice = match serde_json::from_str::<MeshSlice>(&update.mesh_slice_json) {
        Ok(slice) => slice,
        Err(e) => {
            // serde's message can quote the offending input, so it is bounded
            // and sanitized like any other control-plane-supplied value.
            let detail = format!(
                "slice JSON did not parse: {}",
                diagnostic_value(&e.to_string())
            );
            return rejected(consumer, Reason::InvalidSliceJson, detail);
        }
    };

    // Identity and scope first: a response bound to the wrong subscription is
    // the strongest signal, and the one that must fail the stream over.
    if slice.node_id != expected.node_id {
        let detail = format!(
            "slice node_id {} does not match subscription node_id {}",
            diagnostic_value(&slice.node_id),
            diagnostic_value(&expected.node_id)
        );
        return rejected(consumer, Reason::NodeIdMismatch, detail);
    }
    if slice.namespace != expected.namespace {
        let detail = format!(
            "slice namespace {} does not match subscription namespace {}",
            diagnostic_value(&slice.namespace),
            diagnostic_value(&expected.namespace)
        );
        return rejected(consumer, Reason::NamespaceMismatch, detail);
    }

    // Echoed scope is validated ONLY where the protocol is unambiguous: when
    // the request pinned the field. A pinned field the response omits is a
    // MISMATCH, never a skipped check — treating an absent echo as a pass would
    // let any response bypass the scope gate by simply dropping the field. When
    // the request pinned nothing there is no unambiguous expectation to compare
    // against, so no check applies.
    if let Some(expected_spiffe) = expected.workload_spiffe_id.as_deref()
        && slice.workload_spiffe_id.as_deref() != Some(expected_spiffe)
    {
        let detail = format!(
            "slice workload_spiffe_id {} does not match pinned identity {}",
            optional_diagnostic_value(slice.workload_spiffe_id.as_deref()),
            diagnostic_value(expected_spiffe)
        );
        return rejected(consumer, Reason::WorkloadScopeMismatch, detail);
    }
    if let Some(expected_waypoint) = expected.waypoint_name.as_deref()
        && slice.waypoint_name.as_deref() != Some(expected_waypoint)
    {
        let detail = format!(
            "slice waypoint_name {} does not match pinned waypoint {}",
            optional_diagnostic_value(slice.waypoint_name.as_deref()),
            diagnostic_value(expected_waypoint)
        );
        return rejected(consumer, Reason::WaypointScopeMismatch, detail);
    }

    // The envelope carries a duplicate of the slice's own version; the two must
    // agree or the frame is internally inconsistent and unusable for
    // version-keyed observability and dedupe.
    if update.version != slice.version {
        let detail = format!(
            "envelope version {} does not match slice version {}",
            diagnostic_value(&update.version),
            diagnostic_value(&slice.version)
        );
        return rejected(consumer, Reason::EnvelopeVersionMismatch, detail);
    }

    Ok(slice)
}

/// Build a rejection, count it under the bounded `{consumer,reason}` label
/// pair, and emit the safe diagnostic. Both labels are `&'static str` values
/// from closed enums, so the metric's cardinality is fixed at compile time.
fn rejected<T>(
    consumer: MeshUpdateConsumer,
    reason: MeshUpdateRejectReason,
    detail: String,
) -> Result<T, MeshUpdateRejection> {
    crate::plugins::mesh::prometheus_helpers::increment_mesh_config_update_rejection(
        consumer.as_metric_label(),
        reason.as_metric_label(),
    );
    warn!(
        consumer = consumer.as_metric_label(),
        reason = reason.as_metric_label(),
        detail = %detail,
        "Rejected MeshSubscribe response before applying it"
    );
    Err(MeshUpdateRejection { reason, detail })
}

/// Render a control-plane-supplied value for a log line: quoted, stripped of
/// control characters (no log-line forgery), and truncated to
/// [`DIAGNOSTIC_VALUE_MAX_CHARS`].
fn diagnostic_value(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('\'');
    let mut truncated = false;
    for (index, ch) in value.chars().enumerate() {
        if index >= DIAGNOSTIC_VALUE_MAX_CHARS {
            truncated = true;
            break;
        }
        rendered.push(if ch.is_control() { '.' } else { ch });
    }
    rendered.push('\'');
    if truncated {
        rendered.push_str(" (truncated)");
    }
    rendered
}

fn optional_diagnostic_value(value: Option<&str>) -> String {
    match value {
        Some(value) => diagnostic_value(value),
        None => "<absent>".to_string(),
    }
}
