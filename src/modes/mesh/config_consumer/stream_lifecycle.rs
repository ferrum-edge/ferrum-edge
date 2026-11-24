//! Shared mesh configuration-stream attempt and liveness policy (issue #3854).
//!
//! The three mesh configuration consumers — native `MeshSubscribe`
//! ([`super::native_client`]), the Ferrum-private ADS profile
//! ([`super::xds_client`]), and the third-party stock ADS profile
//! ([`super::stock_xds_client`]) — previously each classified a stream ending
//! and each built its own tonic endpoint. They drifted into the same two
//! defects:
//!
//! 1. A remote clean EOF (`Ok(None)` from `message()`) was treated as a
//!    *successful* attempt: backoff reset to the initial delay and the client
//!    stayed on (or returned to) the primary endpoint. A primary that accepts
//!    the RPC and immediately closes therefore pinned the client in a
//!    primary-only hot loop and a healthy fallback was never consulted.
//! 2. The endpoints configured only a **connect** timeout. Once established,
//!    a half-open or blackholed transport left `message().await` pending
//!    forever, so failover never happened and stale mesh state kept serving.
//!
//! This module is the one policy both halves now share. It is deliberately free
//! of gRPC/runtime I/O beyond building a tonic [`Endpoint`], so the
//! classification table is unit-testable without standing up a control plane.
//!
//! ## What is *not* shared
//!
//! Partial-state semantics stay per protocol. The native consumer publishes one
//! whole slice per frame; the two ADS consumers accumulate independent typed
//! responses and only publish once their own required-type gate is satisfied.
//! Nothing here decides when a slice may be built — it decides only what a
//! *stream attempt outcome* means for endpoint rotation and backoff.

use std::time::Duration;

use tonic::transport::Endpoint;

use crate::util::backoff::{BACKOFF_INITIAL_SECS, next_backoff_secs};

/// HTTP/2 PING interval on every mesh configuration stream.
///
/// Matches the hardened DP ConfigSync client
/// (`crate::grpc::configsync_lifecycle::CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS`);
/// the two are intentionally the same policy, not coincidentally equal values.
pub const MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// HTTP/2 PING ack deadline. A missed ack fails the stream, which is what turns
/// a blackholed established transport into an ordinary failover.
pub const MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
/// TCP keepalive idle probe interval for mesh configuration sockets.
pub const MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS: u64 = 30;

/// A control plane that accepts the streaming RPC but never sends a first
/// message is indistinguishable from a blackhole at the application layer.
/// Bounded so a mute primary cannot hold startup.
pub const MESH_CONFIG_STREAM_FIRST_FRAME_TIMEOUT_SECS: u64 = 60;

/// A control plane may answer with frames yet never assemble a **complete**
/// generation (an ADS server that sends CDS and then nothing else). Armed only
/// while the runtime has no first slice at all, so a converged data plane is
/// never torn down for a quiet control plane.
pub const MESH_CONFIG_STREAM_FIRST_SLICE_TIMEOUT_SECS: u64 = 120;

/// Native `MeshSubscribe` application-silence bound.
///
/// Sized above the CP's 60s heartbeat cadence so a healthy idle subscription is
/// never mistaken for a dead one. Armed only once this stream has actually
/// observed a heartbeat, i.e. once the peer has demonstrated it emits them —
/// the same fail-safe shape ConfigSync gets from explicit negotiation.
pub const MESH_SUBSCRIBE_MAX_SILENCE_SECS: u64 = 150;

/// Bound on ONE awaited outbound operation inside a stream loop: an ADS request
/// enqueue, or the native consumer's `ReportMeshSliceStatus` unary RPC.
///
/// Without it, a control plane that accepts the streaming RPC and then simply
/// stops reading (its receive window never opens) — or that leaves the unary
/// status RPC pending forever — suspends the consumer's own receive loop, and
/// every liveness/credential deadline in this module stops being enforced. The
/// awaited work is best-effort by design (ACK/NACK reporting, subscription
/// updates); it must never be able to outrank stream retirement.
pub const MESH_CONFIG_STREAM_OUTBOUND_TIMEOUT_SECS: u64 = 15;

/// ADS apply debounce: a burst of per-type responses for one logical change is
/// collapsed into a single apply once the stream has been quiet this long.
pub const MESH_CONFIG_APPLY_DEBOUNCE_MS: u64 = 25;

/// Cap on how long continuous ADS churn may postpone applying the first staged
/// generation of a burst.
pub const MESH_CONFIG_APPLY_MAX_DELAY_MS: u64 = 500;

/// Per-invocation mesh configuration-stream timing policy.
///
/// Production always uses [`MeshStreamTimings::production`]. The value is
/// ordinary stack state — there is no global, environment, or `cfg` override —
/// so a compressed test value has no path into a production data plane. This
/// mirrors `ConfigSyncStreamTimings`, deliberately: hosted CI must be able to
/// prove first-frame and silence failover without sleeping for production
/// minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshStreamTimings {
    /// Absolute bound from the streaming-RPC-open await through the first
    /// response frame of any subscribed type. The clock is not reset when
    /// headers arrive: a control plane that accepts the authenticated request
    /// and withholds headers is the same mute peer as one that returns headers
    /// and then stays silent.
    pub first_frame: Duration,
    /// Bound from the same attempt origin as [`Self::first_frame`] to the first
    /// *installed* slice, armed only while the runtime has never had one.
    pub first_slice: Duration,
    /// Bound on application silence for consumers with an observed heartbeat.
    pub max_silence: Duration,
    /// HTTP/2 PING interval applied to the tonic endpoint. This is the half of
    /// the policy that detects a blackholed **established** transport with no
    /// application frames at all.
    pub keepalive_interval: Duration,
    /// HTTP/2 PING ack deadline applied to the tonic endpoint.
    pub keepalive_timeout: Duration,
    /// Bound on ONE awaited outbound operation inside the stream loop (an ADS
    /// request enqueue, or the native status-report unary RPC). See
    /// [`MESH_CONFIG_STREAM_OUTBOUND_TIMEOUT_SECS`].
    pub outbound: Duration,
    /// ADS apply debounce (`xds` and `stock_xds`). See
    /// [`MESH_CONFIG_APPLY_DEBOUNCE_MS`].
    pub apply_debounce: Duration,
    /// ADS apply max-delay cap (`xds` and `stock_xds`). See
    /// [`MESH_CONFIG_APPLY_MAX_DELAY_MS`].
    pub apply_max_delay: Duration,
}

impl MeshStreamTimings {
    /// The shipped production policy.
    pub const fn production() -> Self {
        Self {
            first_frame: Duration::from_secs(MESH_CONFIG_STREAM_FIRST_FRAME_TIMEOUT_SECS),
            first_slice: Duration::from_secs(MESH_CONFIG_STREAM_FIRST_SLICE_TIMEOUT_SECS),
            max_silence: Duration::from_secs(MESH_SUBSCRIBE_MAX_SILENCE_SECS),
            keepalive_interval: Duration::from_secs(
                MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS,
            ),
            keepalive_timeout: Duration::from_secs(MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS),
            outbound: Duration::from_secs(MESH_CONFIG_STREAM_OUTBOUND_TIMEOUT_SECS),
            apply_debounce: Duration::from_millis(MESH_CONFIG_APPLY_DEBOUNCE_MS),
            apply_max_delay: Duration::from_millis(MESH_CONFIG_APPLY_MAX_DELAY_MS),
        }
    }

    /// Debounce deadline for a generation staged at `now` whose burst began at
    /// `first_staged_at`: quiet for [`Self::apply_debounce`], but never later
    /// than [`Self::apply_max_delay`] after the burst began.
    pub fn apply_deadline(
        self,
        now: tokio::time::Instant,
        first_staged_at: tokio::time::Instant,
    ) -> tokio::time::Instant {
        std::cmp::min(
            now + self.apply_debounce,
            first_staged_at + self.apply_max_delay,
        )
    }

    /// Upper bound on detecting a half-open established transport under *this*
    /// policy: one PING interval plus one ack deadline.
    pub fn liveness_bound(self) -> Duration {
        self.keepalive_interval
            .saturating_add(self.keepalive_timeout)
    }

    /// The same bound, in whole seconds, for the `/health` projection. Rounded
    /// UP so a sub-second compressed test policy never reports `0`.
    pub fn liveness_bound_seconds(self) -> u64 {
        let bound = self.liveness_bound();
        let secs = bound.as_secs();
        if bound.subsec_nanos() > 0 {
            secs.saturating_add(1)
        } else {
            secs
        }
    }
}

impl Default for MeshStreamTimings {
    fn default() -> Self {
        Self::production()
    }
}

/// Why *this* data plane chose to end an otherwise usable stream.
///
/// Every variant is a local decision. None of them says anything about the
/// remote endpoint's health, so none of them may rotate the endpoint or charge
/// the failure backoff — doing so would punish a healthy control plane for a
/// TLS rotation or a deliberate failback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStreamRetirement {
    /// Process shutdown.
    Shutdown,
    /// gRPC TLS material rotated; reconnect with the new material.
    TlsReload,
    /// The external bearer credential's **content** changed: the configured
    /// source now reads as a different, still-valid token (issue #3852).
    CredentialRotated,
    /// The external bearer credential source became unusable — removed, empty,
    /// non-regular, unreadable, oversized, non-ASCII, or (for a JWT-shaped
    /// token) already expired or unable to leave a positive pre-expiry window
    /// after the configured skew. Reconnection is refused until valid
    /// replacement material appears (issue #3852).
    CredentialSourceInvalid,
    /// The stream reached the credential's absolute local authorization
    /// deadline (issue #3852). Distinct from a rotation: the material on disk
    /// may be unchanged; it is simply no longer allowed to hold this stream.
    CredentialDeadline,
    /// Proactive failback to the primary endpoint after a fallback delivered a
    /// first slice.
    PrimaryRetry,
}

impl MeshStreamRetirement {
    /// Fixed-cardinality label. Never carries an endpoint, node id, credential
    /// path, or any other unbounded value.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::TlsReload => "tls_reload",
            Self::CredentialRotated => "credential_rotated",
            Self::CredentialSourceInvalid => "credential_source_invalid",
            Self::CredentialDeadline => "credential_deadline",
            Self::PrimaryRetry => "primary_retry",
        }
    }

    /// True when this retirement is driven by the external bearer credential.
    /// Such a retirement must also discard every piece of stream state the
    /// retired credential produced (issue #3852).
    pub fn is_credential_retirement(self) -> bool {
        matches!(
            self,
            Self::CredentialRotated | Self::CredentialSourceInvalid | Self::CredentialDeadline
        )
    }
}

/// How one mesh configuration-stream attempt ended.
///
/// The critical distinction is between [`Self::LocalRetirement`] — an
/// intentional local decision — and everything else, which is evidence about
/// the endpoint. A remote clean EOF is **not** success: a configuration stream
/// is meant to stay open, so the peer hanging up before this data plane asked
/// it to is an endpoint failure that must rotate and back off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStreamAttempt {
    /// Intentional local retirement. Never penalizes the endpoint.
    LocalRetirement(MeshStreamRetirement),
    /// The peer closed the stream cleanly (gRPC OK / EOF) without this data
    /// plane asking it to.
    RemoteEof,
    /// Transport or gRPC status failure.
    ///
    /// `delivered_usable_state` records whether this attempt had already
    /// produced usable configuration, which is the same "healthy progress"
    /// split the DP ConfigSync client uses: a long-lived stream that eventually
    /// breaks is not a connect-storm.
    ///
    /// `after_established` records whether the streaming RPC had actually been
    /// opened. That is the honest way to attribute an HTTP/2 keepalive
    /// (PING-ack) failure: it can only be produced by an *established*
    /// transport, so a failure with `after_established == true` is projected as
    /// a liveness failure, while an ordinary connect/dial refusal is not. It is
    /// deliberately NOT called "keepalive timeout" — tonic surfaces a broken
    /// established transport as a generic status, and pretending to know it was
    /// a PING ack would be a dishonest label.
    TransportFailure {
        delivered_usable_state: bool,
        after_established: bool,
    },
    /// No response frame arrived inside [`MeshStreamTimings::first_frame`],
    /// counting from the streaming-RPC-open await. Covers both a peer that
    /// withholds response headers and one that returns headers and then stays
    /// silent.
    FirstFrameTimeout,
    /// Frames arrived but no complete generation was ever installed inside
    /// [`MeshStreamTimings::first_slice`], while the runtime had no slice at
    /// all.
    FirstSliceTimeout,
    /// An established native `MeshSubscribe` stream went silent past
    /// [`MeshStreamTimings::max_silence`] despite a peer that had demonstrably
    /// been emitting heartbeats. This is an APPLICATION-layer silence bound and
    /// is labelled as such: it is not an HTTP/2 keepalive timeout, and the two
    /// must stay distinguishable on `/metrics`.
    HeartbeatSilenceTimeout,
    /// The peer's content was refused by a fail-closed local gate
    /// (subscription binding, config-revision ordering, NACK circuit breaker,
    /// unsolicited resource type). Staying attached would only let it keep
    /// serving refused state.
    PolicyRejected,
    /// The control plane answered the subscribe RPC with `RESOURCE_EXHAUSTED`:
    /// one of its gRPC stream admission budgets (total / per-namespace /
    /// per-principal / per-node / distinct-node) is saturated (issue #4531).
    ///
    /// Deliberately distinct from [`Self::TransportFailure`]: the control plane
    /// is demonstrably alive and answering, and the status message names the
    /// exact budget an operator must raise. The rotate-and-retry disposition is
    /// the same, because another configured CP replica may still have capacity.
    AdmissionRefused,
}

impl MeshStreamAttempt {
    /// Fixed-cardinality metric/log label.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::LocalRetirement(reason) => reason.as_metric_label(),
            Self::RemoteEof => "remote_clean_eof",
            Self::TransportFailure {
                after_established: true,
                ..
            } => "established_transport_failure",
            Self::TransportFailure {
                after_established: false,
                ..
            } => "transport_failure",
            Self::FirstFrameTimeout => "first_frame_timeout",
            Self::FirstSliceTimeout => "first_slice_timeout",
            Self::HeartbeatSilenceTimeout => "heartbeat_silence_timeout",
            Self::PolicyRejected => "policy_rejected",
            Self::AdmissionRefused => "admission_refused",
        }
    }

    /// True when this attempt is evidence *about the endpoint* rather than a
    /// local decision.
    pub fn is_endpoint_failure(self) -> bool {
        !matches!(self, Self::LocalRetirement(_))
    }

    /// True when this attempt is evidence that the *established* stream stopped
    /// being usable, as opposed to never having become usable or a purely local
    /// decision. This is what `/health` reports as `stream_liveness_failed`.
    pub fn is_liveness_failure(self) -> bool {
        matches!(
            self,
            Self::FirstFrameTimeout
                | Self::FirstSliceTimeout
                | Self::HeartbeatSilenceTimeout
                | Self::TransportFailure {
                    after_established: true,
                    ..
                }
        )
    }

    /// What the outer reconnect loop must do next.
    pub fn disposition(self) -> MeshStreamDisposition {
        match self {
            // A local decision proves nothing about the peer.
            Self::LocalRetirement(_) => MeshStreamDisposition {
                advance_endpoint: false,
                increase_backoff: false,
            },
            // Always charge backoff for a clean close. A control plane that
            // accepts and immediately hangs up is the exact shape that produced
            // the primary-only hot loop; resetting to the initial delay here
            // would reintroduce it even though the endpoint now rotates.
            Self::RemoteEof => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: true,
            },
            // A break after real progress is not a connect-storm, so the delay
            // resets — but the endpoint still rotates, because the peer that
            // just failed is the one under suspicion.
            Self::TransportFailure {
                delivered_usable_state,
                ..
            } => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: !delivered_usable_state,
            },
            Self::FirstFrameTimeout
            | Self::FirstSliceTimeout
            | Self::HeartbeatSilenceTimeout
            | Self::PolicyRejected => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: true,
            },
            // Same disposition as a no-progress transport failure: rotate to
            // the next configured CP (a replica may still have capacity) and
            // grow the bounded backoff, so a saturated control plane is not
            // hammered by the whole refused fleet at the initial delay.
            Self::AdmissionRefused => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: true,
            },
        }
    }
}

/// Sleep delay and subsequent stored backoff after one endpoint-failure attempt.
///
/// A usable install on *this* attempt resets to the initial delay before the
/// next sleep, even when earlier no-progress failures grew the shared backoff
/// and even when the terminal classification would otherwise increase it
/// (clean EOF, silence, policy). Repeated no-progress failures keep the
/// current delay for this sleep and grow it afterwards. Local retirements
/// never reach here.
pub fn reconnect_backoff_after_attempt(
    current_secs: u64,
    increase_backoff: bool,
    delivered_usable_state: bool,
) -> (u64, u64) {
    if delivered_usable_state {
        return (BACKOFF_INITIAL_SECS, BACKOFF_INITIAL_SECS);
    }
    let sleep_secs = if increase_backoff {
        current_secs
    } else {
        BACKOFF_INITIAL_SECS
    };
    (sleep_secs, next_backoff_secs(sleep_secs, increase_backoff))
}

/// The outer reconnect loop's next move for one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshStreamDisposition {
    /// Rotate to the next configured endpoint in failover order.
    pub advance_endpoint: bool,
    /// Grow the bounded, jittered backoff instead of resetting it.
    pub increase_backoff: bool,
}

/// Apply the shared bounded transport-liveness policy to a mesh configuration
/// stream endpoint.
///
/// `connect_timeout_seconds` of `0` leaves tonic's explicit connect timeout
/// unset (the existing documented meaning of the mesh knob); the keepalive
/// policy is applied unconditionally because it is what bounds an **already
/// established** stream, which no connect timeout can.
pub fn configure_mesh_config_stream_endpoint(
    endpoint: Endpoint,
    connect_timeout_seconds: u64,
    timings: MeshStreamTimings,
) -> Endpoint {
    let endpoint = if connect_timeout_seconds > 0 {
        endpoint.connect_timeout(Duration::from_secs(connect_timeout_seconds))
    } else {
        endpoint
    };
    // TCP keepalive is a coarse backstop under the H2 policy, so it is never
    // allowed to be looser than the PING interval this invocation enforces.
    let tcp_keepalive = timings
        .keepalive_interval
        .min(Duration::from_secs(MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS));
    endpoint
        .http2_keep_alive_interval(timings.keepalive_interval)
        .keep_alive_timeout(timings.keepalive_timeout)
        // Load-bearing: a standard xDS subscription is legitimately idle
        // between control-plane pushes, and without this tonic stops pinging
        // exactly when a blackhole would be invisible.
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(tcp_keepalive))
}

/// Fixed-cardinality readiness/health classification for the mesh
/// configuration stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigStreamState {
    /// A stream is established and this data plane has usable configuration.
    Connected,
    /// No slice has ever been installed; startup is still blocked.
    NeverReceivedSlice,
    /// The last attempt ended on a transport-liveness bound (keepalive, first
    /// frame, or first complete slice).
    StreamLivenessFailed,
    /// A slice was installed earlier and is still serving while the stream is
    /// down or reconnecting.
    ServingLastGood,
}

impl MeshConfigStreamState {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::NeverReceivedSlice => "never_received_slice",
            Self::StreamLivenessFailed => "stream_liveness_failed",
            Self::ServingLastGood => "serving_last_good",
        }
    }
}

/// Fixed-cardinality external-credential posture for the configuration stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigStreamCredential {
    /// No external bearer credential is configured for this protocol.
    NotConfigured,
    /// A credential source IS configured but has not been observed yet.
    ///
    /// Reported distinctly from [`Self::NotConfigured`] on purpose: telling an
    /// operator "not configured" about a source they *did* configure is a false
    /// statement about their own posture, and it hides the window in which the
    /// very first read has not completed.
    Unobserved,
    /// The configured credential source last read as valid.
    Valid,
    /// The configured credential source is missing, empty, non-regular,
    /// unreadable, oversized, not valid ASCII metadata, or (for a JWT-shaped
    /// token) already past `exp` or unable to leave a positive pre-expiry
    /// window after the configured skew. Reconnection is refused while this
    /// holds (issue #3852).
    SourceInvalid,
}

impl MeshConfigStreamCredential {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Unobserved => "unobserved",
            Self::Valid => "valid",
            Self::SourceInvalid => "source_invalid",
        }
    }
}

/// Operator-visible mesh configuration-stream status.
///
/// Every field is a closed set or a counter. No endpoint URL, node id, token,
/// claim, or credential path may be added here — this rides the authenticated
/// `/health` mesh detail and the reason labels are also used for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MeshConfigStreamStatus {
    /// Which consumer owns the stream: `native`, `xds`, or `stock_xds`.
    pub protocol: &'static str,
    /// Readiness classification ([`MeshConfigStreamState::as_label`]).
    pub state: &'static str,
    /// How the last completed attempt ended
    /// ([`MeshStreamAttempt::as_metric_label`]); `none` before the first one.
    pub last_attempt_outcome: &'static str,
    /// True while the client is attached to a non-primary configured endpoint.
    pub fallback_active: bool,
    /// Consecutive endpoint-failure attempts since the last usable state.
    /// Local retirements do not reset this counter.
    pub consecutive_failures: u32,
    /// External-credential posture
    /// ([`MeshConfigStreamCredential::as_label`]).
    pub credential: &'static str,
    /// Documented bound (seconds) within which a half-open established stream
    /// is detected without any application frames, under the timing policy this
    /// consumer is actually running ([`MeshStreamTimings::liveness_bound_seconds`]).
    pub liveness_bound_seconds: u64,
}

/// Whether a tracked stream is currently attached to its control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStreamAttachment {
    /// The streaming RPC is open and this consumer is reading it.
    Established,
    /// No stream is open: connecting, backing off, or blocked on an invalid
    /// credential source.
    Detached,
}

/// Rolling accounting for one consumer's reconnect loop.
///
/// Keeps the closed-set health projection and the shared backoff/rotation
/// decision in one place so the three consumers cannot drift again.
#[derive(Debug, Clone, Copy)]
pub struct MeshStreamTracker {
    protocol: &'static str,
    credential: MeshConfigStreamCredential,
    last_attempt_outcome: &'static str,
    consecutive_failures: u32,
    endpoint_index: usize,
    attachment: MeshStreamAttachment,
    liveness_failed: bool,
    liveness_bound_seconds: u64,
}

impl MeshStreamTracker {
    pub fn new(
        protocol: &'static str,
        credential: MeshConfigStreamCredential,
        timings: MeshStreamTimings,
    ) -> Self {
        Self {
            protocol,
            credential,
            last_attempt_outcome: "none",
            consecutive_failures: 0,
            endpoint_index: 0,
            attachment: MeshStreamAttachment::Detached,
            liveness_failed: false,
            liveness_bound_seconds: timings.liveness_bound_seconds(),
        }
    }

    /// Update the external-credential posture (issue #3852).
    pub fn set_credential(&mut self, credential: MeshConfigStreamCredential) {
        self.credential = credential;
    }

    /// Record which configured endpoint index the next/current attempt uses.
    ///
    /// This alone does NOT make `fallback_active` true: the schema and the
    /// `/health` body both say "attached to a non-primary endpoint", so the
    /// flag is only raised once the stream on that index is actually
    /// established.
    pub fn set_endpoint_index(&mut self, index: usize) {
        self.endpoint_index = index;
    }

    /// Record whether a streaming RPC is currently open.
    ///
    /// `Established` is published the moment the RPC is accepted and the
    /// consumer begins reading it; `Detached` on every path that leaves that
    /// loop, including an intentional local retirement.
    pub fn set_attachment(&mut self, attachment: MeshStreamAttachment) {
        self.attachment = attachment;
    }

    pub fn is_established(&self) -> bool {
        self.attachment == MeshStreamAttachment::Established
    }

    /// Fold one completed attempt into the rolling view and return what the
    /// outer loop must do.
    ///
    /// Recording an attempt always detaches: the stream that produced it is
    /// over by definition.
    pub fn record(&mut self, attempt: MeshStreamAttempt) -> MeshStreamDisposition {
        self.attachment = MeshStreamAttachment::Detached;
        self.last_attempt_outcome = attempt.as_metric_label();
        // A liveness failure is STICKY until this consumer next installs usable
        // state from an actual stream. Recomputing it per attempt would let the
        // very next ordinary connect refusal erase the operator's only evidence
        // that an established transport went dark.
        if attempt.is_liveness_failure() {
            self.liveness_failed = true;
        }
        if attempt.is_endpoint_failure() {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        // Local retirements (TLS reload, credential rotation/invalidation/
        // deadline, shutdown, primary retry) prove nothing about the endpoint
        // and must not erase the consecutive endpoint-failure run. Only
        // [`Self::record_usable_state`] clears it.
        crate::plugins::mesh::prometheus_helpers::increment_mesh_config_stream_attempt(
            self.protocol,
            attempt.as_metric_label(),
        );
        attempt.disposition()
    }

    /// The stream currently established installed usable configuration; clear
    /// the failure run and the sticky liveness flag.
    pub fn record_usable_state(&mut self) {
        self.consecutive_failures = 0;
        self.liveness_failed = false;
    }

    /// Project the closed-set health view. `has_first_slice` comes from the
    /// mesh runtime, so "serving last good" cannot be claimed without one.
    ///
    /// Order matters. A sticky liveness failure outranks both `connected` and
    /// `never_received_slice`. Opening a replacement RPC after a liveness
    /// failure — even when last-good state still exists — must not report
    /// `connected` until that replacement stream actually installs usable
    /// state. Checking attachment-plus-slice first would hide the failure the
    /// moment a new RPC was accepted, which is exactly when the operator most
    /// needs to see that the previous established transport went dark. The
    /// same flag also outranks `never_received_slice`, so a bounded
    /// first-frame/first-slice/keepalive failure before the first convergence
    /// stays visible instead of looking like ordinary startup.
    pub fn status(&self, has_first_slice: bool) -> MeshConfigStreamStatus {
        let established = self.is_established();
        let state = if self.liveness_failed {
            MeshConfigStreamState::StreamLivenessFailed
        } else if established && has_first_slice {
            MeshConfigStreamState::Connected
        } else if !has_first_slice {
            MeshConfigStreamState::NeverReceivedSlice
        } else {
            MeshConfigStreamState::ServingLastGood
        };
        MeshConfigStreamStatus {
            protocol: self.protocol,
            state: state.as_label(),
            last_attempt_outcome: self.last_attempt_outcome,
            fallback_active: established && self.endpoint_index != 0,
            consecutive_failures: self.consecutive_failures,
            credential: self.credential.as_label(),
            liveness_bound_seconds: self.liveness_bound_seconds,
        }
    }
}

/// Mutable per-attempt progress the inner configuration-stream future writes
/// for the outer lifecycle loop.
///
/// `tracker` is the shared `/health` and metric projection.
/// `delivered_usable_state` records whether this attempt installed a slice, so
/// a later failure does not grow backoff.
/// `stream_established` records whether the streaming RPC opened, so a later
/// transport failure is `established_transport_failure` rather than a dial
/// refusal.
pub(crate) struct MeshStreamAttemptProgress<'a> {
    pub tracker: &'a mut MeshStreamTracker,
    pub delivered_usable_state: &'a mut bool,
    pub stream_established: &'a mut bool,
}
