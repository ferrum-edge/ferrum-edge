//! NodeWaypoint secured-transport observability contract (issue #3334).
//!
//! Process-static, compile-time-bounded counters for the ADR signal set:
//! HBONE handshake success/failure, asserted source identity accept/reject,
//! destination-policy rejection, missing destination NodeWaypoint metadata,
//! and prohibited plaintext fallback attempts.
//!
//! ## Increment ownership
//!
//! One failed inbound session is counted in exactly one HBONE handshake phase:
//! - `inbound_tls` — TLS accept on a mesh mTLS/HBONE listener while NodeWaypoint
//!   observability is enabled. TLS failures also increment the mesh-wide
//!   umbrella `ferrum_mesh_mtls_handshake_failures_total` (distinct series;
//!   not a second ADR failure class).
//! - `inbound_connect` — HBONE CONNECT admission after TLS succeeded
//!   (authenticated peer / open-relay guard). Never incremented when TLS failed.
//! - `outbound_dial` — source-side secured HBONE dial to a destination
//!   NodeWaypoint, counted once per opened CONNECT tunnel across both egress
//!   entry points: the pooled HTTP/raw-TCP tunnel
//!   (`HboneConnectionPool::get_tunnel_via`) and the 1:1 WebSocket byte tunnel
//!   (`HboneConnectionPool::get_ws_byte_tunnel`). A tunnel opened over an
//!   already-established pooled H2 connection still counts, so this is
//!   "secured dial attempts", not "TLS handshakes". Datagram tunnels are out of
//!   scope: NodeWaypoint UDP/DTLS listeners relay to node-local backends and
//!   never open an HBONE datagram tunnel.
//!   Independent of the destination's inbound phases.
//!
//! Asserted-identity and destination-policy counters are mutually exclusive for
//! a single authz decision: identity rejection is recorded first and skips the
//! destination-policy counter.
//!
//! The transparent inbound capture listener (issue #3287,
//! `crate::proxy::node_waypoint_ingress_capture`) records **only** the
//! destination-policy counter, for the open-relay guard it shares with the HBONE
//! relay. It records no handshake phase: it terminates no TLS and admits no
//! CONNECT, so none of the three phases above describe it.
//!
//! ## Reset / monotonicity
//!
//! Counters are process-static atomics:
//! - config reload / SVID rotation: **do not reset** (monotonic within process);
//! - NodeWaypoint (ambient) process restart: **reset to zero**;
//! - node-agent restart: **does not reset** these proxy counters (different
//!   process). Capture-state / topology-degraded gauges live on the node-agent.
//!
//! Overlapping capture/identity accept drops stay on
//! [`crate::overload::NodeWaypointDropSnapshot`] (`/overload`); do not
//! duplicate them here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use serde::Serialize;

use crate::plugins::prometheus_metrics::escape_label_value;

static ENABLED: AtomicBool = AtomicBool::new(false);

static HBONE_INBOUND_TLS_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_TLS_FAILURE: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_CONNECT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_INBOUND_CONNECT_FAILURE: AtomicU64 = AtomicU64::new(0);
static HBONE_OUTBOUND_DIAL_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HBONE_OUTBOUND_DIAL_FAILURE: AtomicU64 = AtomicU64::new(0);

static ASSERTED_IDENTITY_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_ASSERTION_OUT_OF_SCOPE: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_MALFORMED: AtomicU64 = AtomicU64::new(0);
static ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN: AtomicU64 = AtomicU64::new(0);

static DESTINATION_POLICY_REJECTION_AUTHZ_DENY: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_SCOPE_MISSING: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING: AtomicU64 = AtomicU64::new(0);
static DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED: AtomicU64 = AtomicU64::new(0);

static CAPTURE_ADMISSION_REJECTED_OVERLOAD: AtomicU64 = AtomicU64::new(0);
static CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS_PER_IP: AtomicU64 = AtomicU64::new(0);

/// The capture listener's connection limiter, installed when that listener
/// binds so `/metrics` can publish its occupancy and configured ceilings
/// without the listener owning a rendering path of its own.
static CAPTURE_CONN_LIMITER: OnceLock<Arc<crate::util::conn_limit::ConnLimiter>> = OnceLock::new();

static MISSING_DESTINATION_METADATA: AtomicU64 = AtomicU64::new(0);
static PLAINTEXT_FALLBACK_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// Bounded HBONE handshake phase for NodeWaypoint sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointHboneHandshakePhase {
    InboundTls,
    InboundConnect,
    OutboundDial,
}

impl NodeWaypointHboneHandshakePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InboundTls => "inbound_tls",
            Self::InboundConnect => "inbound_connect",
            Self::OutboundDial => "outbound_dial",
        }
    }
}

/// Bounded asserted-identity rejection reasons (ADR contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointAssertedIdentityRejectReason {
    UntrustedAssertor,
    /// The peer is an admitted assertor but is not authorized to assert the
    /// identity it claimed (issue #4274).
    AssertionOutOfScope,
    TrustDomainMismatch,
    UnauthenticatedHbone,
    Malformed,
    StaleOrUnknown,
}

impl NodeWaypointAssertedIdentityRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedAssertor => "untrusted_assertor",
            Self::AssertionOutOfScope => "assertion_out_of_scope",
            Self::TrustDomainMismatch => "trust_domain_mismatch",
            Self::UnauthenticatedHbone => "unauthenticated_hbone",
            Self::Malformed => "malformed",
            Self::StaleOrUnknown => "stale_or_unknown",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::UntrustedAssertor => &ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR,
            Self::AssertionOutOfScope => &ASSERTED_IDENTITY_REJECTED_ASSERTION_OUT_OF_SCOPE,
            Self::TrustDomainMismatch => &ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH,
            Self::UnauthenticatedHbone => &ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED,
            Self::Malformed => &ASSERTED_IDENTITY_REJECTED_MALFORMED,
            Self::StaleOrUnknown => &ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN,
        }
    }
}

/// Bounded destination-policy rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointDestinationPolicyRejectReason {
    AuthzDeny,
    ScopeMissing,
    DestinationScopeMissing,
    RelayDestinationDenied,
}

impl NodeWaypointDestinationPolicyRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthzDeny => "authz_deny",
            Self::ScopeMissing => "scope_missing",
            Self::DestinationScopeMissing => "destination_scope_missing",
            Self::RelayDestinationDenied => "relay_destination_denied",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::AuthzDeny => &DESTINATION_POLICY_REJECTION_AUTHZ_DENY,
            Self::ScopeMissing => &DESTINATION_POLICY_REJECTION_SCOPE_MISSING,
            Self::DestinationScopeMissing => {
                &DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING
            }
            Self::RelayDestinationDenied => &DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED,
        }
    }
}

/// Why the transparent inbound capture listener refused an accepted socket in
/// the accept loop, before any task existed (issue #4626).
///
/// A closed set: these strings are the only `reason` label values the capture
/// admission family ever carries, and none is derived from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointCaptureAdmissionRejectReason {
    /// The process is shedding new connections under critical overload.
    Overload,
    /// The listener's global connection cap (`FERRUM_MAX_CONNECTIONS`).
    MaxConnections,
    /// The per-source-IP share (`FERRUM_TCP_MAX_CONNECTIONS_PER_IP`).
    MaxConnectionsPerIp,
}

impl NodeWaypointCaptureAdmissionRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overload => "overload",
            Self::MaxConnections => "max_connections",
            Self::MaxConnectionsPerIp => "max_connections_per_ip",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        match self {
            Self::Overload => &CAPTURE_ADMISSION_REJECTED_OVERLOAD,
            Self::MaxConnections => &CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS,
            Self::MaxConnectionsPerIp => &CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS_PER_IP,
        }
    }
}

impl From<crate::util::conn_limit::ConnRejectReason> for NodeWaypointCaptureAdmissionRejectReason {
    fn from(reason: crate::util::conn_limit::ConnRejectReason) -> Self {
        match reason {
            crate::util::conn_limit::ConnRejectReason::MaxConnections => Self::MaxConnections,
            crate::util::conn_limit::ConnRejectReason::MaxConnectionsPerIp => {
                Self::MaxConnectionsPerIp
            }
        }
    }
}

/// Capture-listener admission counters, plus the live limiter view when the
/// listener is running.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct NodeWaypointCaptureAdmissionSnapshot {
    pub rejected_overload: u64,
    pub rejected_max_connections: u64,
    pub rejected_max_connections_per_ip: u64,
    /// Configured global cap; `None` until the capture listener binds.
    pub max_connections: Option<usize>,
    /// Configured per-source-IP cap; `None` until the capture listener binds.
    pub max_connections_per_ip: Option<usize>,
    /// Connections currently holding a permit; `None` until the listener binds.
    pub active_connections: Option<u64>,
}

/// Publish the capture listener's limiter for metrics and diagnostics. Called
/// once, when that listener binds.
pub fn install_capture_conn_limiter(limiter: Arc<crate::util::conn_limit::ConnLimiter>) {
    let _ = CAPTURE_CONN_LIMITER.set(limiter);
}

/// Record one capture-listener admission refusal.
///
/// Deliberately NOT gated on [`is_enabled`]: the capture listener only exists
/// in the NodeWaypoint topology, and a refusal that vanished because a toggle
/// had not been flipped is exactly the signal an operator needs during a flood.
pub fn record_capture_admission_rejection(reason: NodeWaypointCaptureAdmissionRejectReason) {
    reason.counter().fetch_add(1, Ordering::Relaxed);
}

/// Snapshot the capture-listener admission state.
pub fn capture_admission_snapshot() -> NodeWaypointCaptureAdmissionSnapshot {
    let limiter = CAPTURE_CONN_LIMITER.get().map(|limiter| limiter.snapshot());
    NodeWaypointCaptureAdmissionSnapshot {
        rejected_overload: CAPTURE_ADMISSION_REJECTED_OVERLOAD.load(Ordering::Relaxed),
        rejected_max_connections: CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS
            .load(Ordering::Relaxed),
        rejected_max_connections_per_ip: CAPTURE_ADMISSION_REJECTED_MAX_CONNECTIONS_PER_IP
            .load(Ordering::Relaxed),
        max_connections: limiter.map(|snapshot| snapshot.max_connections),
        max_connections_per_ip: limiter.map(|snapshot| snapshot.max_connections_per_ip),
        active_connections: limiter.map(|snapshot| snapshot.active_connections),
    }
}

/// Authenticated admin /health snapshot of the NodeWaypoint ADR counters.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointObservabilitySnapshot {
    pub enabled: bool,
    pub hbone_handshakes: NodeWaypointHboneHandshakeSnapshot,
    pub asserted_identity: NodeWaypointAssertedIdentitySnapshot,
    pub destination_policy_rejections: NodeWaypointDestinationPolicySnapshot,
    pub missing_destination_metadata: u64,
    pub plaintext_fallback_attempts: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointHboneHandshakeSnapshot {
    pub inbound_tls_success: u64,
    pub inbound_tls_failure: u64,
    pub inbound_connect_success: u64,
    pub inbound_connect_failure: u64,
    pub outbound_dial_success: u64,
    pub outbound_dial_failure: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointAssertedIdentitySnapshot {
    pub accepted: u64,
    pub rejected_untrusted_assertor: u64,
    /// Assertions refused because the admitted assertor's grant does not cover
    /// the claimed identity (issue #4274).
    pub rejected_assertion_out_of_scope: u64,
    pub rejected_trust_domain_mismatch: u64,
    pub rejected_unauthenticated_hbone: u64,
    pub rejected_malformed: u64,
    pub rejected_stale_or_unknown: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeWaypointDestinationPolicySnapshot {
    pub authz_deny: u64,
    pub scope_missing: u64,
    pub destination_scope_missing: u64,
    pub relay_destination_denied: u64,
}

/// Enable or disable NodeWaypoint ADR counter producers for this process.
///
/// Called once at mesh startup from the topology. Counters themselves are never
/// cleared by this toggle so a mid-process topology flip (test-only) does not
/// rewrite history.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether NodeWaypoint ADR counter producers are active.
#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Record a NodeWaypoint HBONE handshake outcome for one phase.
pub fn record_hbone_handshake(phase: NodeWaypointHboneHandshakePhase, success: bool) {
    if !is_enabled() {
        return;
    }
    let counter = match (phase, success) {
        (NodeWaypointHboneHandshakePhase::InboundTls, true) => &HBONE_INBOUND_TLS_SUCCESS,
        (NodeWaypointHboneHandshakePhase::InboundTls, false) => &HBONE_INBOUND_TLS_FAILURE,
        (NodeWaypointHboneHandshakePhase::InboundConnect, true) => &HBONE_INBOUND_CONNECT_SUCCESS,
        (NodeWaypointHboneHandshakePhase::InboundConnect, false) => &HBONE_INBOUND_CONNECT_FAILURE,
        (NodeWaypointHboneHandshakePhase::OutboundDial, true) => &HBONE_OUTBOUND_DIAL_SUCCESS,
        (NodeWaypointHboneHandshakePhase::OutboundDial, false) => &HBONE_OUTBOUND_DIAL_FAILURE,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Record an accepted asserted source identity on inbound NodeWaypoint HBONE.
pub fn record_asserted_identity_accepted() {
    if !is_enabled() {
        return;
    }
    ASSERTED_IDENTITY_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}

/// Record a rejected asserted source identity with a bounded reason.
pub fn record_asserted_identity_rejected(reason: NodeWaypointAssertedIdentityRejectReason) {
    if !is_enabled() {
        return;
    }
    reason.counter().fetch_add(1, Ordering::Relaxed);
}

/// Record a destination-policy rejection (AuthorizationPolicy / scope / relay).
pub fn record_destination_policy_rejection(reason: NodeWaypointDestinationPolicyRejectReason) {
    if !is_enabled() {
        return;
    }
    reason.counter().fetch_add(1, Ordering::Relaxed);
}

/// Record a skipped secured-route target because destination NodeWaypoint
/// metadata was absent under an identity-backed posture.
pub fn record_missing_destination_metadata() {
    if !is_enabled() {
        return;
    }
    MISSING_DESTINATION_METADATA.fetch_add(1, Ordering::Relaxed);
}

/// Record that a prohibited plaintext fallback was attempted and blocked.
///
/// Today this is incremented together with
/// [`record_missing_destination_metadata`] when identity-backed materialization
/// skips a metadata-absent target instead of retaining a plaintext backend.
pub fn record_plaintext_fallback_attempt() {
    if !is_enabled() {
        return;
    }
    PLAINTEXT_FALLBACK_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot counters for authenticated admin diagnostics.
pub fn snapshot() -> NodeWaypointObservabilitySnapshot {
    NodeWaypointObservabilitySnapshot {
        enabled: is_enabled(),
        hbone_handshakes: NodeWaypointHboneHandshakeSnapshot {
            inbound_tls_success: HBONE_INBOUND_TLS_SUCCESS.load(Ordering::Relaxed),
            inbound_tls_failure: HBONE_INBOUND_TLS_FAILURE.load(Ordering::Relaxed),
            inbound_connect_success: HBONE_INBOUND_CONNECT_SUCCESS.load(Ordering::Relaxed),
            inbound_connect_failure: HBONE_INBOUND_CONNECT_FAILURE.load(Ordering::Relaxed),
            outbound_dial_success: HBONE_OUTBOUND_DIAL_SUCCESS.load(Ordering::Relaxed),
            outbound_dial_failure: HBONE_OUTBOUND_DIAL_FAILURE.load(Ordering::Relaxed),
        },
        asserted_identity: NodeWaypointAssertedIdentitySnapshot {
            accepted: ASSERTED_IDENTITY_ACCEPTED.load(Ordering::Relaxed),
            rejected_untrusted_assertor: ASSERTED_IDENTITY_REJECTED_UNTRUSTED_ASSERTOR
                .load(Ordering::Relaxed),
            rejected_assertion_out_of_scope: ASSERTED_IDENTITY_REJECTED_ASSERTION_OUT_OF_SCOPE
                .load(Ordering::Relaxed),
            rejected_trust_domain_mismatch: ASSERTED_IDENTITY_REJECTED_TRUST_DOMAIN_MISMATCH
                .load(Ordering::Relaxed),
            rejected_unauthenticated_hbone: ASSERTED_IDENTITY_REJECTED_UNAUTHENTICATED
                .load(Ordering::Relaxed),
            rejected_malformed: ASSERTED_IDENTITY_REJECTED_MALFORMED.load(Ordering::Relaxed),
            rejected_stale_or_unknown: ASSERTED_IDENTITY_REJECTED_STALE_OR_UNKNOWN
                .load(Ordering::Relaxed),
        },
        destination_policy_rejections: NodeWaypointDestinationPolicySnapshot {
            authz_deny: DESTINATION_POLICY_REJECTION_AUTHZ_DENY.load(Ordering::Relaxed),
            scope_missing: DESTINATION_POLICY_REJECTION_SCOPE_MISSING.load(Ordering::Relaxed),
            destination_scope_missing: DESTINATION_POLICY_REJECTION_DESTINATION_SCOPE_MISSING
                .load(Ordering::Relaxed),
            relay_destination_denied: DESTINATION_POLICY_REJECTION_RELAY_DESTINATION_DENIED
                .load(Ordering::Relaxed),
        },
        missing_destination_metadata: MISSING_DESTINATION_METADATA.load(Ordering::Relaxed),
        plaintext_fallback_attempts: PLAINTEXT_FALLBACK_ATTEMPTS.load(Ordering::Relaxed),
    }
}

/// Render NodeWaypoint ADR counters into Prometheus exposition format.
///
/// Always emits HELP/TYPE when the feature is enabled so scrapes expose a
/// stable zero baseline; when disabled, emits nothing (non-NodeWaypoint
/// processes must not advertise the series).
///
/// Callers that serve `/metrics` through [`crate::plugins::prometheus_metrics::MetricsRegistry::render`]
/// append this **outside** the registry render cache so process-static
/// increments remain visible on the next scrape without waiting for
/// `render_cache_ttl_seconds`.
pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    if !is_enabled() {
        return;
    }
    let snap = snapshot();

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_hbone_handshakes_total \
NodeWaypoint HBONE handshake outcomes by phase. One failed session increments \
exactly one phase (inbound_tls XOR inbound_connect on the destination; \
outbound_dial is independent on the source).\n",
    );
    output.push_str("# TYPE ferrum_mesh_node_waypoint_hbone_handshakes_total counter\n");
    for (phase, result, value) in [
        (
            NodeWaypointHboneHandshakePhase::InboundTls,
            "success",
            snap.hbone_handshakes.inbound_tls_success,
        ),
        (
            NodeWaypointHboneHandshakePhase::InboundTls,
            "failure",
            snap.hbone_handshakes.inbound_tls_failure,
        ),
        (
            NodeWaypointHboneHandshakePhase::InboundConnect,
            "success",
            snap.hbone_handshakes.inbound_connect_success,
        ),
        (
            NodeWaypointHboneHandshakePhase::InboundConnect,
            "failure",
            snap.hbone_handshakes.inbound_connect_failure,
        ),
        (
            NodeWaypointHboneHandshakePhase::OutboundDial,
            "success",
            snap.hbone_handshakes.outbound_dial_success,
        ),
        (
            NodeWaypointHboneHandshakePhase::OutboundDial,
            "failure",
            snap.hbone_handshakes.outbound_dial_failure,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_hbone_handshakes_total{{phase=\"{}\",result=\"{}\"{}}} {}\n",
            escape_label_value(phase.as_str()),
            escape_label_value(result),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_asserted_identity_total \
Asserted source-identity decisions on inbound NodeWaypoint HBONE. Rejection \
reasons are compile-time-bounded; SPIFFE IDs never appear as labels.\n",
    );
    output.push_str("# TYPE ferrum_mesh_node_waypoint_asserted_identity_total counter\n");
    output.push_str(&format!(
        "ferrum_mesh_node_waypoint_asserted_identity_total{{result=\"accepted\",reason=\"honored\"{}}} {}\n",
        gateway_ns_label, snap.asserted_identity.accepted
    ));
    // Emit every ADR-bounded reject reason (including reserved Malformed /
    // StaleOrUnknown) so scrapes keep a stable zero baseline. Those two
    // variants are constructed here for label export; mesh_authz currently
    // only produces UntrustedAssertor / AssertionOutOfScope /
    // TrustDomainMismatch / UnauthenticatedHbone, and collapses malformed
    // principal parse / slice
    // unknowns into existing fail-closed paths until dedicated producers land.
    for reason in [
        NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor,
        NodeWaypointAssertedIdentityRejectReason::AssertionOutOfScope,
        NodeWaypointAssertedIdentityRejectReason::TrustDomainMismatch,
        NodeWaypointAssertedIdentityRejectReason::UnauthenticatedHbone,
        NodeWaypointAssertedIdentityRejectReason::Malformed,
        NodeWaypointAssertedIdentityRejectReason::StaleOrUnknown,
    ] {
        let value = match reason {
            NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor => {
                snap.asserted_identity.rejected_untrusted_assertor
            }
            NodeWaypointAssertedIdentityRejectReason::AssertionOutOfScope => {
                snap.asserted_identity.rejected_assertion_out_of_scope
            }
            NodeWaypointAssertedIdentityRejectReason::TrustDomainMismatch => {
                snap.asserted_identity.rejected_trust_domain_mismatch
            }
            NodeWaypointAssertedIdentityRejectReason::UnauthenticatedHbone => {
                snap.asserted_identity.rejected_unauthenticated_hbone
            }
            NodeWaypointAssertedIdentityRejectReason::Malformed => {
                snap.asserted_identity.rejected_malformed
            }
            NodeWaypointAssertedIdentityRejectReason::StaleOrUnknown => {
                snap.asserted_identity.rejected_stale_or_unknown
            }
        };
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_asserted_identity_total{{result=\"rejected\",reason=\"{}\"{}}} {}\n",
            escape_label_value(reason.as_str()),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_destination_policy_rejections_total \
Destination-side AuthorizationPolicy / scope / open-relay rejections on \
NodeWaypoint. Distinct from asserted-identity rejections.\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_destination_policy_rejections_total counter\n");
    for reason in [
        NodeWaypointDestinationPolicyRejectReason::AuthzDeny,
        NodeWaypointDestinationPolicyRejectReason::ScopeMissing,
        NodeWaypointDestinationPolicyRejectReason::DestinationScopeMissing,
        NodeWaypointDestinationPolicyRejectReason::RelayDestinationDenied,
    ] {
        let value = match reason {
            NodeWaypointDestinationPolicyRejectReason::AuthzDeny => {
                snap.destination_policy_rejections.authz_deny
            }
            NodeWaypointDestinationPolicyRejectReason::ScopeMissing => {
                snap.destination_policy_rejections.scope_missing
            }
            NodeWaypointDestinationPolicyRejectReason::DestinationScopeMissing => {
                snap.destination_policy_rejections.destination_scope_missing
            }
            NodeWaypointDestinationPolicyRejectReason::RelayDestinationDenied => {
                snap.destination_policy_rejections.relay_destination_denied
            }
        };
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_destination_policy_rejections_total{{reason=\"{}\"{}}} {}\n",
            escape_label_value(reason.as_str()),
            gateway_ns_label,
            value
        ));
    }

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_missing_destination_metadata_total \
Secured NodeWaypoint service targets skipped because Workload.node_waypoint \
metadata was absent.\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_missing_destination_metadata_total counter\n");
    render_gauge_like_counter(
        output,
        "ferrum_mesh_node_waypoint_missing_destination_metadata_total",
        snap.missing_destination_metadata,
        gateway_ns_label,
    );

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total \
Prohibited plaintext fallback attempts blocked under identity-backed \
NodeWaypoint (fail-closed instead of retaining a plaintext backend).\n",
    );
    output.push_str("# TYPE ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total counter\n");
    render_gauge_like_counter(
        output,
        "ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total",
        snap.plaintext_fallback_attempts,
        gateway_ns_label,
    );

    render_capture_admission(output, gateway_ns_label);
}

/// Render the transparent inbound capture listener's admission families
/// (issue #4626).
///
/// Fixed cardinality: no source-IP label, and the `reason` values come from
/// [`NodeWaypointCaptureAdmissionRejectReason`]. Ceilings and occupancy are
/// emitted only once the listener has bound and installed its limiter, so a
/// NodeWaypoint without inbound capture does not advertise a misleading zero
/// ceiling; the rejection counters always emit a zero baseline.
fn render_capture_admission(output: &mut String, gateway_ns_label: &str) {
    let snap = capture_admission_snapshot();

    output.push_str(
        "# HELP ferrum_mesh_node_waypoint_capture_rejected_connections_total \
Captured inbound connections refused in the accept loop before a task was allocated, by \
bounded reason.\n",
    );
    output
        .push_str("# TYPE ferrum_mesh_node_waypoint_capture_rejected_connections_total counter\n");
    for (reason, value) in [
        (
            NodeWaypointCaptureAdmissionRejectReason::Overload,
            snap.rejected_overload,
        ),
        (
            NodeWaypointCaptureAdmissionRejectReason::MaxConnections,
            snap.rejected_max_connections,
        ),
        (
            NodeWaypointCaptureAdmissionRejectReason::MaxConnectionsPerIp,
            snap.rejected_max_connections_per_ip,
        ),
    ] {
        output.push_str(&format!(
            "ferrum_mesh_node_waypoint_capture_rejected_connections_total{{reason=\"{}\"{}}} {}\n",
            escape_label_value(reason.as_str()),
            gateway_ns_label,
            value
        ));
    }

    if let Some(active) = snap.active_connections {
        output.push_str(
            "# HELP ferrum_mesh_node_waypoint_capture_active_connections Captured inbound \
connections currently holding an admission permit.\n",
        );
        output.push_str("# TYPE ferrum_mesh_node_waypoint_capture_active_connections gauge\n");
        render_gauge_like_counter(
            output,
            "ferrum_mesh_node_waypoint_capture_active_connections",
            active,
            gateway_ns_label,
        );
    }
    if let Some(max) = snap.max_connections {
        output.push_str(
            "# HELP ferrum_mesh_node_waypoint_capture_max_connections Configured capture-listener \
connection cap (0 = unlimited).\n",
        );
        output.push_str("# TYPE ferrum_mesh_node_waypoint_capture_max_connections gauge\n");
        render_gauge_like_counter(
            output,
            "ferrum_mesh_node_waypoint_capture_max_connections",
            max as u64,
            gateway_ns_label,
        );
    }
    if let Some(max) = snap.max_connections_per_ip {
        output.push_str(
            "# HELP ferrum_mesh_node_waypoint_capture_max_connections_per_ip Configured \
per-source-IP capture-listener connection cap (0 = unlimited).\n",
        );
        output.push_str("# TYPE ferrum_mesh_node_waypoint_capture_max_connections_per_ip gauge\n");
        render_gauge_like_counter(
            output,
            "ferrum_mesh_node_waypoint_capture_max_connections_per_ip",
            max as u64,
            gateway_ns_label,
        );
    }
}

fn render_gauge_like_counter(output: &mut String, name: &str, value: u64, gateway_ns_label: &str) {
    if gateway_ns_label.is_empty() {
        output.push_str(&format!("{name} {value}\n"));
    } else {
        let label_body = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        output.push_str(&format!("{name}{{{label_body}}} {value}\n"));
    }
}
