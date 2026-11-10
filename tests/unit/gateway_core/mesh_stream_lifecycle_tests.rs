//! Mesh configuration-stream hardening: shared attempt/liveness policy
//! (issue #3854), stock xDS transport admission (issue #3853), and the stock
//! bearer credential's finite authorization lifetime (issue #3852).
//!
//! These are the pure-policy halves. The live stream behaviour (clean EOF
//! failover, partial-generation EOF, token rotation retiring a healthy stream)
//! is driven against a scripted third-party ADS server in
//! `tests/integration/mesh_stock_xds_tests.rs`.

use std::time::{Duration, SystemTime};

use base64::Engine as _;

use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
    BearerToken, admit_stock_credential_observation_for_test, attach_stock_authorization,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_credential::{
    DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS, MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
    MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS, StockBearerCredential,
    StockCredentialDeadlineBasis, StockCredentialInvalidReason, StockCredentialLifetimePolicy,
    StockCredentialPublish, StockCredentialState, StockCredentialWatch, StockXdsCredentialSource,
    credential_lifetime, jwt_expiration_hint,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_transport::{
    StockXdsTransport, StockXdsTransportPolicy, StockXdsTransportRefusal,
    admit_stock_xds_endpoints, classify_stock_xds_endpoint, is_loopback_host,
};
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::{
    MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS,
    MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS, MESH_CONFIG_STREAM_OUTBOUND_TIMEOUT_SECS,
    MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS, MeshConfigStreamCredential, MeshStreamAttachment,
    MeshStreamAttempt, MeshStreamRetirement, MeshStreamTimings, MeshStreamTracker,
    reconnect_backoff_after_attempt,
};
use ferrum_edge::util::backoff::{BACKOFF_INITIAL_SECS, BACKOFF_MAX_SECS};

/// Every `MeshStreamRetirement` this build knows about. Kept as one list so a
/// new variant cannot quietly skip the "local decisions never penalize the
/// endpoint" and "labels are a closed set" contracts.
const ALL_RETIREMENTS: [MeshStreamRetirement; 6] = [
    MeshStreamRetirement::Shutdown,
    MeshStreamRetirement::TlsReload,
    MeshStreamRetirement::CredentialRotated,
    MeshStreamRetirement::CredentialSourceInvalid,
    MeshStreamRetirement::CredentialDeadline,
    MeshStreamRetirement::PrimaryRetry,
];

fn tracker(protocol: &'static str, credential: MeshConfigStreamCredential) -> MeshStreamTracker {
    MeshStreamTracker::new(protocol, credential, MeshStreamTimings::production())
}

fn transport_failure(delivered_usable_state: bool, after_established: bool) -> MeshStreamAttempt {
    MeshStreamAttempt::TransportFailure {
        delivered_usable_state,
        after_established,
    }
}

// ── issue #3854: attempt classification ─────────────────────────────────

/// The whole point of the shared policy. Before it, all three consumers mapped
/// a remote `Ok(None)` onto "successful attempt": backoff reset to the initial
/// delay and the client stayed on (or snapped back to) the primary. A control
/// plane that accepted the RPC and immediately closed therefore produced a
/// primary-only reconnect loop that never consulted a healthy fallback.
#[test]
fn remote_clean_eof_rotates_the_endpoint_and_grows_backoff() {
    let disposition = MeshStreamAttempt::RemoteEof.disposition();
    assert!(
        disposition.advance_endpoint,
        "a clean close by the peer must advance to the configured fallback"
    );
    assert!(
        disposition.increase_backoff,
        "repeated clean closes must back off instead of resetting into a hot loop"
    );
    assert!(MeshStreamAttempt::RemoteEof.is_endpoint_failure());
    assert_eq!(
        MeshStreamAttempt::RemoteEof.as_metric_label(),
        "remote_clean_eof"
    );
}

#[test]
fn intentional_local_retirement_never_penalizes_the_endpoint() {
    for reason in ALL_RETIREMENTS {
        let attempt = MeshStreamAttempt::LocalRetirement(reason);
        let disposition = attempt.disposition();
        assert!(
            !attempt.is_endpoint_failure(),
            "{} is a local decision, not evidence about the peer",
            reason.as_metric_label()
        );
        assert!(!disposition.advance_endpoint, "{:?}", reason);
        assert!(!disposition.increase_backoff, "{:?}", reason);
    }
}

/// Mirrors the hardened DP ConfigSync split: a stream that already delivered
/// usable configuration and then broke is not a connect storm, so the delay
/// resets — but the endpoint still rotates, because the peer that just failed
/// is the one under suspicion.
#[test]
fn transport_failure_backoff_depends_on_whether_the_attempt_made_progress() {
    let fresh = transport_failure(false, false).disposition();
    assert!(fresh.advance_endpoint);
    assert!(fresh.increase_backoff);

    let progressed = transport_failure(true, false).disposition();
    assert!(progressed.advance_endpoint);
    assert!(!progressed.increase_backoff);
}

/// A usable install on this attempt must reset the reconnect delay *before*
/// the next sleep. Earlier no-progress failures that grew the shared backoff
/// (possibly to the 30s cap) must not leave that stale delay in front of a
/// stream that already made progress — including when the terminal
/// classification is a clean EOF, which still grows backoff when there was
/// no progress.
#[test]
fn usable_install_resets_reconnect_delay_before_the_next_sleep() {
    let grown = BACKOFF_MAX_SECS;
    let eof = MeshStreamAttempt::RemoteEof.disposition();
    assert!(eof.increase_backoff);

    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(grown, eof.increase_backoff, true);
    assert_eq!(
        sleep_secs, BACKOFF_INITIAL_SECS,
        "progress must not sleep the stale grown delay"
    );
    assert_eq!(next_secs, BACKOFF_INITIAL_SECS);

    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(grown, eof.increase_backoff, false);
    assert_eq!(
        sleep_secs, grown,
        "no-progress EOF must still sleep the current delay"
    );
    assert_eq!(next_secs, BACKOFF_MAX_SECS);

    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(BACKOFF_INITIAL_SECS, eof.increase_backoff, false);
    assert_eq!(sleep_secs, BACKOFF_INITIAL_SECS);
    assert_eq!(next_secs, 2);

    let silence = MeshStreamAttempt::HeartbeatSilenceTimeout.disposition();
    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(grown, silence.increase_backoff, true);
    assert_eq!(sleep_secs, BACKOFF_INITIAL_SECS);
    assert_eq!(next_secs, BACKOFF_INITIAL_SECS);

    let transport = transport_failure(true, true).disposition();
    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(grown, transport.increase_backoff, true);
    assert_eq!(sleep_secs, BACKOFF_INITIAL_SECS);
    assert_eq!(next_secs, BACKOFF_INITIAL_SECS);

    let policy = MeshStreamAttempt::PolicyRejected.disposition();
    assert!(policy.increase_backoff);
    let (sleep_secs, next_secs) =
        reconnect_backoff_after_attempt(grown, policy.increase_backoff, true);
    assert_eq!(sleep_secs, BACKOFF_INITIAL_SECS);
    assert_eq!(next_secs, BACKOFF_INITIAL_SECS);
}

/// Issue #3854 round two. An H2 keepalive (PING-ack) failure surfaces through
/// tonic as an ordinary transport status, so the only honest way to attribute
/// it is "did this failure happen after the streaming RPC was established?".
/// A connect refusal must NOT be dressed up as a keepalive timeout, and an
/// established transport going dark must NOT be reported as a plain connect
/// failure — `/health` distinguishes them and so must the metric label.
#[test]
fn only_a_post_establishment_transport_failure_is_a_liveness_failure() {
    assert!(!transport_failure(false, false).is_liveness_failure());
    assert!(transport_failure(false, true).is_liveness_failure());
    assert!(transport_failure(true, true).is_liveness_failure());

    assert_eq!(
        transport_failure(false, false).as_metric_label(),
        "transport_failure"
    );
    assert_eq!(
        transport_failure(false, true).as_metric_label(),
        "established_transport_failure"
    );

    // The native application-silence bound is NOT an HTTP/2 keepalive timeout
    // and must not be labelled as one.
    assert_eq!(
        MeshStreamAttempt::HeartbeatSilenceTimeout.as_metric_label(),
        "heartbeat_silence_timeout"
    );
    assert!(MeshStreamAttempt::HeartbeatSilenceTimeout.is_liveness_failure());
    assert!(MeshStreamAttempt::FirstFrameTimeout.is_liveness_failure());
    assert!(MeshStreamAttempt::FirstSliceTimeout.is_liveness_failure());
    assert!(!MeshStreamAttempt::RemoteEof.is_liveness_failure());
    assert!(!MeshStreamAttempt::PolicyRejected.is_liveness_failure());
}

/// Issue #3852. The three credential lifecycle events are distinct outcomes.
/// Collapsing them into one `credential_rotation` label would tell an operator
/// that their token changed when in fact the source went missing, or when the
/// stream simply reached its maximum authenticated lifetime.
#[test]
fn credential_retirements_are_three_distinct_outcomes() {
    assert_eq!(
        MeshStreamRetirement::CredentialRotated.as_metric_label(),
        "credential_rotated"
    );
    assert_eq!(
        MeshStreamRetirement::CredentialSourceInvalid.as_metric_label(),
        "credential_source_invalid"
    );
    assert_eq!(
        MeshStreamRetirement::CredentialDeadline.as_metric_label(),
        "credential_deadline"
    );
    for reason in ALL_RETIREMENTS {
        let credential_driven = matches!(
            reason,
            MeshStreamRetirement::CredentialRotated
                | MeshStreamRetirement::CredentialSourceInvalid
                | MeshStreamRetirement::CredentialDeadline
        );
        assert_eq!(
            reason.is_credential_retirement(),
            credential_driven,
            "{}",
            reason.as_metric_label()
        );
    }
}

#[test]
fn liveness_and_policy_outcomes_rotate_and_back_off() {
    for attempt in [
        MeshStreamAttempt::FirstFrameTimeout,
        MeshStreamAttempt::FirstSliceTimeout,
        MeshStreamAttempt::HeartbeatSilenceTimeout,
        MeshStreamAttempt::PolicyRejected,
        MeshStreamAttempt::AdmissionRefused,
    ] {
        let disposition = attempt.disposition();
        assert!(disposition.advance_endpoint, "{:?}", attempt);
        assert!(disposition.increase_backoff, "{:?}", attempt);
        assert!(attempt.is_endpoint_failure(), "{:?}", attempt);
    }
}

/// Fixed cardinality is a security property here, not a tidiness one: these
/// labels go straight onto `/metrics` and the authenticated `/health` mesh
/// detail, and must never be able to carry an endpoint URL or a node id.
#[test]
fn attempt_labels_are_a_closed_set() {
    let mut labels: Vec<&'static str> = ALL_RETIREMENTS
        .iter()
        .map(|reason| MeshStreamAttempt::LocalRetirement(*reason).as_metric_label())
        .collect();
    labels.extend([
        MeshStreamAttempt::RemoteEof.as_metric_label(),
        transport_failure(false, false).as_metric_label(),
        transport_failure(false, true).as_metric_label(),
        MeshStreamAttempt::FirstFrameTimeout.as_metric_label(),
        MeshStreamAttempt::FirstSliceTimeout.as_metric_label(),
        MeshStreamAttempt::HeartbeatSilenceTimeout.as_metric_label(),
        MeshStreamAttempt::PolicyRejected.as_metric_label(),
        MeshStreamAttempt::AdmissionRefused.as_metric_label(),
    ]);
    let mut sorted = labels.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len(), "labels must be distinct");
    for label in labels {
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "'{label}' must be a bare snake_case token"
        );
    }
    // `delivered_usable_state` is a backoff input, not a label dimension.
    assert_eq!(
        transport_failure(true, false).as_metric_label(),
        transport_failure(false, false).as_metric_label()
    );
}

/// The documented half-open detection bound must actually follow from the
/// keepalive constants rather than being an independently drifting number in
/// the docs.
#[test]
fn documented_liveness_bound_matches_the_keepalive_policy() {
    let production = MeshStreamTimings::production();
    assert_eq!(
        production.liveness_bound_seconds(),
        MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS
            + MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS
    );
    // The figure documented in docs/mesh.md, openapi.yaml, and the `/health`
    // `liveness_bound_seconds` field.
    assert_eq!(production.liveness_bound_seconds(), 40);
    assert_eq!(MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS, 30);
    assert_eq!(MESH_CONFIG_STREAM_OUTBOUND_TIMEOUT_SECS, 15);
}

/// A compressed test policy must report the bound it actually enforces, not the
/// production one — otherwise the hosted blackhole test would advertise 40s on
/// `/health` while detecting in well under a second.
#[test]
fn the_reported_liveness_bound_follows_the_invocation_policy() {
    let compressed = MeshStreamTimings {
        keepalive_interval: Duration::from_millis(200),
        keepalive_timeout: Duration::from_millis(200),
        ..MeshStreamTimings::production()
    };
    assert_eq!(compressed.liveness_bound(), Duration::from_millis(400));
    // Rounded up so a sub-second policy never advertises a bound of zero.
    assert_eq!(compressed.liveness_bound_seconds(), 1);

    let reported =
        MeshStreamTracker::new("stock_xds", MeshConfigStreamCredential::Valid, compressed)
            .status(false)
            .liveness_bound_seconds;
    assert_eq!(reported, 1);
}

#[test]
fn production_timings_are_finite_and_ordered() {
    let timings = MeshStreamTimings::production();
    assert!(timings.first_frame > Duration::ZERO);
    assert!(
        timings.first_slice > timings.first_frame,
        "a complete generation legitimately takes longer than a first frame"
    );
    assert!(
        timings.max_silence > Duration::from_secs(60),
        "the silence bound must sit above the 60s heartbeat cadence"
    );
    assert!(timings.keepalive_interval > Duration::ZERO);
    assert!(timings.keepalive_timeout > Duration::ZERO);
    assert!(
        timings.outbound > Duration::ZERO && timings.outbound < timings.first_frame,
        "a best-effort outbound send must never be able to outlast the first-frame bound"
    );
}

// ── issue #3854: readiness projection ───────────────────────────────────

#[test]
fn tracker_reports_never_received_slice_until_one_is_installed() {
    let mut tracker = tracker("stock_xds", MeshConfigStreamCredential::NotConfigured);
    let status = tracker.status(false);
    assert_eq!(status.state, "never_received_slice");
    assert_eq!(status.last_attempt_outcome, "none");
    assert_eq!(status.credential, "not_configured");
    assert_eq!(
        status.liveness_bound_seconds,
        MeshStreamTimings::production().liveness_bound_seconds()
    );

    // An ordinary connect refusal before any slice is still ordinary startup.
    tracker.record(transport_failure(false, false));
    assert_eq!(tracker.status(false).state, "never_received_slice");
}

/// Issue #3854 round two. `never_received_slice` used to outrank every liveness
/// classification, so a data plane that reached a bounded first-frame /
/// first-slice / established-transport failure BEFORE ever converging reported
/// exactly the same readiness as one that was simply still starting up. The
/// failure was invisible for as long as it mattered most.
#[test]
fn a_liveness_failure_is_visible_even_before_the_first_slice() {
    for failure in [
        MeshStreamAttempt::FirstFrameTimeout,
        MeshStreamAttempt::FirstSliceTimeout,
        MeshStreamAttempt::HeartbeatSilenceTimeout,
        transport_failure(false, true),
    ] {
        let mut tracker = tracker("stock_xds", MeshConfigStreamCredential::NotConfigured);
        // Before the failure, startup readiness is the honest answer.
        assert_eq!(tracker.status(false).state, "never_received_slice");
        tracker.record(failure);
        assert_eq!(
            tracker.status(false).state,
            "stream_liveness_failed",
            "{}",
            failure.as_metric_label()
        );
    }
}

#[test]
fn tracker_distinguishes_liveness_failure_from_serving_last_good() {
    let mut tracker = tracker("native", MeshConfigStreamCredential::NotConfigured);

    tracker.record(MeshStreamAttempt::HeartbeatSilenceTimeout);
    let status = tracker.status(true);
    assert_eq!(status.state, "stream_liveness_failed");
    assert_eq!(status.last_attempt_outcome, "heartbeat_silence_timeout");
    assert_eq!(status.consecutive_failures, 1);

    // A sticky liveness flag is deliberate: the very next ordinary failure must
    // not erase the operator's only evidence that the transport went dark.
    tracker.record(MeshStreamAttempt::RemoteEof);
    let status = tracker.status(true);
    assert_eq!(status.state, "stream_liveness_failed");
    assert_eq!(status.last_attempt_outcome, "remote_clean_eof");
    assert_eq!(status.consecutive_failures, 2);

    // Only usable state from an actual stream clears it.
    tracker.set_attachment(MeshStreamAttachment::Established);
    tracker.record_usable_state();
    assert_eq!(tracker.status(true).state, "connected");
    tracker.record(MeshStreamAttempt::RemoteEof);
    assert_eq!(tracker.status(true).state, "serving_last_good");
}

/// After a liveness failure with last-good state, merely opening a replacement
/// RPC must not report `connected`. The sticky flag stays visible until that
/// replacement stream actually installs usable state.
#[test]
fn a_replacement_rpc_stays_liveness_failed_until_it_installs_usable_state() {
    let mut tracker = tracker("stock_xds", MeshConfigStreamCredential::NotConfigured);

    tracker.set_attachment(MeshStreamAttachment::Established);
    tracker.record_usable_state();
    assert_eq!(tracker.status(true).state, "connected");

    tracker.record(MeshStreamAttempt::HeartbeatSilenceTimeout);
    assert_eq!(tracker.status(true).state, "stream_liveness_failed");

    tracker.set_attachment(MeshStreamAttachment::Established);
    assert_eq!(
        tracker.status(true).state,
        "stream_liveness_failed",
        "attachment plus last-good state must not mask a sticky liveness failure"
    );
    assert!(tracker.is_established());

    tracker.record_usable_state();
    assert_eq!(tracker.status(true).state, "connected");
}

/// `record_usable_state` was defined and never called: every production call
/// site passed `connected = false`, so `/health` could not reach `connected` at
/// all and the consecutive-failure run never reset on a healthy stream.
#[test]
fn connected_requires_both_an_established_stream_and_usable_state() {
    let mut tracker = tracker("xds", MeshConfigStreamCredential::NotConfigured);
    assert_eq!(tracker.status(true).state, "serving_last_good");

    tracker.set_attachment(MeshStreamAttachment::Established);
    assert!(tracker.is_established());
    assert_eq!(
        tracker.status(false).state,
        "never_received_slice",
        "an established stream that has delivered nothing is not `connected`"
    );
    assert_eq!(tracker.status(true).state, "connected");

    // Recording ANY attempt means that stream is over, so the projection
    // detaches without the caller having to remember to.
    tracker.record(MeshStreamAttempt::LocalRetirement(
        MeshStreamRetirement::TlsReload,
    ));
    assert!(!tracker.is_established());
    assert_eq!(tracker.status(true).state, "serving_last_good");
}

#[test]
fn tracker_preserves_the_failure_run_on_local_retirement_and_clears_it_on_usable_state() {
    let mut tracker = tracker("xds", MeshConfigStreamCredential::NotConfigured);
    tracker.record(MeshStreamAttempt::RemoteEof);
    tracker.record(MeshStreamAttempt::RemoteEof);
    assert_eq!(tracker.status(true).consecutive_failures, 2);

    for reason in ALL_RETIREMENTS {
        tracker.record(MeshStreamAttempt::LocalRetirement(reason));
        assert_eq!(
            tracker.status(true).consecutive_failures,
            2,
            "{} must not erase consecutive endpoint-failure attempts since last usable state",
            reason.as_metric_label()
        );
        let disposition = MeshStreamAttempt::LocalRetirement(reason).disposition();
        assert!(!disposition.advance_endpoint, "{:?}", reason);
        assert!(!disposition.increase_backoff, "{:?}", reason);
    }

    tracker.record(MeshStreamAttempt::RemoteEof);
    assert_eq!(tracker.status(true).consecutive_failures, 3);
    tracker.set_attachment(MeshStreamAttachment::Established);
    tracker.record_usable_state();
    let status = tracker.status(true);
    assert_eq!(status.consecutive_failures, 0);
    assert_eq!(status.state, "connected");
}

/// The schema and the `/health` body both say "attached to a non-primary
/// endpoint". Selecting an index is not attaching to it, so a client that is
/// merely backing off toward endpoint #1 must not claim the fallback is active.
#[test]
fn fallback_is_reported_only_while_actually_attached_to_a_non_primary_endpoint() {
    let mut tracker = tracker("stock_xds", MeshConfigStreamCredential::NotConfigured);
    tracker.set_endpoint_index(1);
    assert!(
        !tracker.status(true).fallback_active,
        "selecting a fallback index while detached is not fallback activation"
    );

    tracker.set_attachment(MeshStreamAttachment::Established);
    assert!(tracker.status(true).fallback_active);

    tracker.set_endpoint_index(0);
    assert!(!tracker.status(true).fallback_active);

    tracker.set_endpoint_index(1);
    tracker.record(MeshStreamAttempt::RemoteEof);
    assert!(
        !tracker.status(true).fallback_active,
        "the stream ended, so nothing is attached"
    );
}

#[test]
fn the_health_projection_never_carries_an_unbounded_value() {
    let mut tracker = tracker("stock_xds", MeshConfigStreamCredential::SourceInvalid);
    tracker.set_endpoint_index(1);
    tracker.set_attachment(MeshStreamAttachment::Established);
    let rendered =
        serde_json::to_string(&tracker.status(true)).expect("status serializes for /health");
    for forbidden in ["http://", "https://", "://", "token", "/var/run", "Bearer"] {
        assert!(
            !rendered.contains(forbidden),
            "the health projection must stay label-free: {rendered}"
        );
    }
    assert!(rendered.contains("\"credential\":\"source_invalid\""));
}

/// Issue #3852 round two. `Unknown` (configured but not yet read) used to
/// project as `not_configured`, which tells an operator their own configured
/// token file is absent.
#[test]
fn an_unobserved_credential_source_is_not_reported_as_absent() {
    assert_eq!(
        MeshConfigStreamCredential::Unobserved.as_label(),
        "unobserved"
    );
    assert_eq!(
        StockCredentialState::Unknown.health(),
        MeshConfigStreamCredential::Unobserved
    );
    assert_eq!(
        StockCredentialState::NotConfigured.health(),
        MeshConfigStreamCredential::NotConfigured
    );
    let source = StockXdsCredentialSource::new(
        Some("/nonexistent/projected/token".to_string()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(source.initial_state(), StockCredentialState::Unknown);
    assert_eq!(
        tracker("stock_xds", source.initial_state().health())
            .status(false)
            .credential,
        "unobserved"
    );
}

// ── issue #3853: stock xDS transport admission ──────────────────────────

fn policy(token: bool, production: bool, allow_plaintext: bool) -> StockXdsTransportPolicy {
    StockXdsTransportPolicy {
        token_configured: token,
        production_mode: production,
        allow_loopback_plaintext: allow_plaintext,
    }
}

#[test]
fn https_endpoints_are_admitted_as_authenticated_tls() {
    let admitted = admit_stock_xds_endpoints(
        &[
            "https://istiod.istio-system.svc:15012".to_string(),
            "https://istiod-backup.istio-system.svc:15012".to_string(),
        ],
        policy(true, true, false),
    )
    .expect("an all-https set with a bearer is the production posture");
    assert_eq!(
        admitted,
        vec![
            StockXdsTransport::AuthenticatedTls,
            StockXdsTransport::AuthenticatedTls
        ]
    );
    assert!(StockXdsTransport::AuthenticatedTls.allows_authorization_metadata());
    assert!(!StockXdsTransport::LoopbackPlaintextDev.allows_authorization_metadata());
}

/// A bearer credential over h2c is the disclosure this gate exists to stop.
/// Loopback is not an exception: the credential still leaves the process.
#[test]
fn a_bearer_token_refuses_plaintext_even_on_loopback_with_the_dev_switch_on() {
    let refusal =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(true, false, true))
            .expect_err("a bearer must never ride h2c");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::PlaintextWithBearerToken
    );
}

#[test]
fn production_mode_refuses_plaintext_without_a_bearer_too() {
    let refusal =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(false, true, true))
            .expect_err("production mode requires TLS with or without a credential");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::PlaintextInProduction
    );
}

#[test]
fn plaintext_is_off_by_default_and_loopback_only_when_enabled() {
    let disabled =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(false, false, false))
            .expect_err("plaintext must be opt-in");
    assert_eq!(
        disabled.refusal,
        StockXdsTransportRefusal::PlaintextNotEnabled
    );

    let remote_url = "http://istiod.istio-system.svc:15012";
    let remote = classify_stock_xds_endpoint(0, remote_url, policy(false, false, true))
        .expect_err("the development switch is loopback-only");
    assert_eq!(
        remote.refusal,
        StockXdsTransportRefusal::PlaintextNotLoopback
    );

    for loopback in [
        "http://127.0.0.1:15012",
        "http://127.0.0.5:15012",
        "http://localhost:15012",
        "http://[::1]:15012",
    ] {
        assert_eq!(
            classify_stock_xds_endpoint(0, loopback, policy(false, false, true))
                .expect("loopback development plaintext is admissible"),
            StockXdsTransport::LoopbackPlaintextDev,
            "{loopback}"
        );
    }
}

/// Per-endpoint admission alone cannot guarantee failover does not downgrade,
/// so the WHOLE set is refused when it mixes postures.
#[test]
fn a_mixed_secure_and_plaintext_set_is_refused_as_a_whole() {
    let refusal = admit_stock_xds_endpoints(
        &[
            "https://istiod.istio-system.svc:15012".to_string(),
            "http://127.0.0.1:15012".to_string(),
        ],
        policy(false, false, true),
    )
    .expect_err("a secure primary must not be able to fail over to plaintext");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::MixedTransportPosture
    );
    assert_eq!(refusal.index, 1);

    // Order must not matter: a plaintext PRIMARY with a TLS fallback is the
    // same refusal.
    let reversed = admit_stock_xds_endpoints(
        &[
            "http://127.0.0.1:15012".to_string(),
            "https://istiod.istio-system.svc:15012".to_string(),
        ],
        policy(false, false, true),
    )
    .expect_err("a mixed set is refused whichever way round it is written");
    assert_eq!(
        reversed.refusal,
        StockXdsTransportRefusal::MixedTransportPosture
    );
}

#[test]
fn malformed_ambiguous_and_credential_bearing_urls_are_refused() {
    let cases = [
        (
            "istiod.istio-system.svc:15012",
            StockXdsTransportRefusal::MissingScheme,
        ),
        (
            "grpc://istiod:15012",
            StockXdsTransportRefusal::UnsupportedScheme,
        ),
        // `http::Uri` rejects the scheme-only string before a host can be
        // inspected, so the honest closed-set classification is MalformedUri
        // rather than MissingHost. Admission still fails closed.
        ("https://", StockXdsTransportRefusal::MalformedUri),
        (
            "https://user:secret@istiod:15012",
            StockXdsTransportRefusal::EmbeddedCredentials,
        ),
        (
            "https://istiod:15012/ads",
            StockXdsTransportRefusal::UnsupportedUriShape,
        ),
        (
            "https://istiod:15012/?token=super-secret",
            StockXdsTransportRefusal::UnsupportedUriShape,
        ),
    ];
    for (url, expected) in cases {
        let refusal =
            classify_stock_xds_endpoint(0, url, policy(false, false, true)).expect_err(url);
        assert_eq!(refusal.refusal, expected, "{url}");
    }

    assert_eq!(
        classify_stock_xds_endpoint(
            0,
            "https://istiod.istio-system.svc:15012/",
            policy(false, true, false),
        )
        .expect("a conventional root slash is still an origin URL"),
        StockXdsTransport::AuthenticatedTls,
    );
}

/// A configured ADS URL is operator-authored but unbounded, and may carry a
/// query or userinfo. Refusals must therefore identify it by index and closed-set
/// classification only.
#[test]
fn refusal_diagnostics_never_echo_the_configured_url() {
    let url = "http://secret-host.internal.example:15012/?token=super-secret";
    let refusal = classify_stock_xds_endpoint(3, url, policy(true, true, false))
        .expect_err("plaintext with a bearer is refused");
    let rendered = refusal.to_string();
    assert!(rendered.contains("endpoint #3"), "{rendered}");
    assert!(rendered.contains("scheme=\"http\""), "{rendered}");
    assert!(!rendered.contains("secret-host"), "{rendered}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(!rendered.contains(url), "{rendered}");
    assert_eq!(refusal.scheme(), "http");
    assert_eq!(refusal.host_class(), "remote");
}

#[test]
fn loopback_classification_does_not_resolve_hostnames() {
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("127.9.9.9"));
    assert!(is_loopback_host("::1"));
    assert!(is_loopback_host("[::1]"));
    assert!(is_loopback_host("LOCALHOST"));
    // A name that merely resolves to loopback is not a configuration property.
    assert!(!is_loopback_host("localhost.localdomain"));
    assert!(!is_loopback_host("istiod.istio-system.svc"));
    assert!(!is_loopback_host("0.0.0.0"));
}

/// Issue #3853, acceptance criterion 4: a defense-in-depth test that BYPASSES
/// top-level endpoint-set admission and proves the credential-INSERTION
/// boundary itself refuses an insecure endpoint.
///
/// Configuring a plaintext URL and observing that no stream opens proves only
/// connect-time classification. This drives the interceptor's own decision with
/// a transport it would never have been handed in production, which is exactly
/// the "an admission path was bypassed" case the gate exists for.
#[test]
fn the_authorization_insertion_boundary_refuses_a_non_tls_transport() {
    let token: BearerToken = "Bearer projected-token".parse().expect("ascii metadata");

    // The bypassed case: a bearer paired with the loopback development
    // plaintext posture. Top-level admission would have refused this set.
    let mut request = tonic::Request::new(());
    let status = attach_stock_authorization(
        Some(&(token.clone(), StockXdsTransport::LoopbackPlaintextDev)),
        &mut request,
    )
    .expect_err("a bearer must never be attached to a plaintext endpoint");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        request.metadata().get("authorization").is_none(),
        "no authorization metadata may survive the refusal"
    );
    // The refusal message is a fixed constant and never echoes the credential.
    assert!(!status.message().contains("projected-token"));

    // The admitted case attaches exactly the materialized value.
    let mut request = tonic::Request::new(());
    attach_stock_authorization(
        Some(&(token, StockXdsTransport::AuthenticatedTls)),
        &mut request,
    )
    .expect("authenticated TLS may carry the bearer");
    assert_eq!(
        request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer projected-token")
    );

    // No credential configured: no metadata, on either transport.
    for transport in [
        StockXdsTransport::AuthenticatedTls,
        StockXdsTransport::LoopbackPlaintextDev,
    ] {
        let _ = transport;
        let mut request = tonic::Request::new(());
        attach_stock_authorization(None, &mut request).expect("no credential is always admissible");
        assert!(request.metadata().get("authorization").is_none());
    }
}

// ── issue #3852: credential lifetime ────────────────────────────────────

fn jwt_with_exp(exp_epoch_secs: i64) -> String {
    jwt_with_exp_lexeme(&exp_epoch_secs.to_string())
}

fn jwt_with_exp_lexeme(exp_lexeme: &str) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
        r#"{{"exp":{exp_lexeme},"sub":"system:serviceaccount:x:y"}}"#
    ));
    format!("{header}.{payload}.c2ln")
}

fn lifetime_policy(max: u64, skew: u64) -> StockCredentialLifetimePolicy {
    StockCredentialLifetimePolicy {
        max_stream_lifetime: Duration::from_secs(max),
        refresh_skew: Duration::from_secs(skew),
        watch_interval: Duration::from_secs(10),
    }
}

#[test]
fn an_opaque_token_gets_the_operator_visible_maximum_stream_lifetime() {
    let (lifetime, basis) = credential_lifetime(
        "an-opaque-projected-token",
        lifetime_policy(900, 60),
        SystemTime::now(),
    )
    .expect("an opaque token is admissible");
    assert_eq!(lifetime, Duration::from_secs(900));
    assert_eq!(basis, StockCredentialDeadlineBasis::MaxStreamLifetime);
    assert_eq!(basis.as_metric_label(), "max_stream_lifetime");
}

#[test]
fn a_jwt_shaped_token_reconnects_before_exp_with_the_configured_skew() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(1_000_600);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 60), now)
        .expect("a JWT with a positive post-skew window is admissible");
    assert_eq!(
        lifetime,
        Duration::from_secs(540),
        "600s until exp, minus the 60s skew"
    );
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
    assert!(
        lifetime < Duration::from_secs(600),
        "the deadline must fall strictly before exp"
    );
}

/// Issue #3852. A programmatic policy may set `refresh_skew = 0` so a hosted
/// test can prove deadline retirement without waiting for the operator 60s
/// skew. Retirement must still fall strictly before `exp`: otherwise the next
/// attempt fail-closed-refuses the same token as expired and never reconnects.
#[test]
fn a_jwt_with_zero_skew_still_reconnects_strictly_before_exp() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(1_000_003);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 0), now)
        .expect("a 3s JWT with zero skew is admissible");
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
    assert!(
        lifetime < Duration::from_secs(3),
        "zero skew must not schedule retirement at exp: {lifetime:?}"
    );
    assert!(
        lifetime > Duration::ZERO,
        "the scheduled window must stay positive: {lifetime:?}"
    );

    let at_deadline = now + lifetime;
    let (remaining, _) = credential_lifetime(&token, lifetime_policy(3600, 0), at_deadline)
        .expect("the next attempt must still admit the same not-yet-expired token");
    assert!(
        remaining > Duration::ZERO,
        "reconnect at the scheduled deadline must observe a positive remaining window"
    );
}

/// Issue #3852 round two. A short-lived JWT is legitimate material and must be
/// used with a correspondingly short deadline — NOT clamped up to a reconnect
/// floor, which is what let a stream outlive `exp`.
#[test]
fn a_short_lived_jwt_keeps_its_short_deadline_instead_of_being_clamped_up() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    // 90s until exp, 30s skew: a 60s usable window, well under any floor that
    // a 3600s maximum-lifetime policy would otherwise suggest.
    let token = jwt_with_exp(1_000_090);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 30), now)
        .expect("a 60s post-skew window is admissible");
    assert_eq!(lifetime, Duration::from_secs(60));
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);

    // And an even shorter one: 5s until exp with a 1s skew is 4s, not 60s.
    let token = jwt_with_exp(1_000_005);
    let (lifetime, _) = credential_lifetime(&token, lifetime_policy(3600, 1), now)
        .expect("a 4s post-skew window is admissible");
    assert_eq!(lifetime, Duration::from_secs(4));
}

/// The `exp` is only ever a scheduling hint. A long-lived JWT must still be
/// reauthenticated at the operator-visible maximum, which is what stops a
/// peer-issued claim from silently extending Ferrum's own bound.
#[test]
fn the_maximum_stream_lifetime_caps_a_far_future_jwt_exp() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(1_000_000 + 86_400);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(600, 60), now)
        .expect("a far-future JWT is admissible, just capped");
    assert_eq!(lifetime, Duration::from_secs(600));
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
}

/// Issue #3852 round two — the core fix.
///
/// An already-expired JWT used to be mapped onto a 60s reconnect FLOOR, which
/// meant Ferrum knowingly opened an authenticated stream with expired material
/// and held it open for a further minute. It is now refused outright and moves
/// the source into the closed invalid state, where the bounded invalid-source
/// retry (and the watcher's wakeup on replacement material) prevents a hot loop
/// WITHOUT admitting the stale token.
#[test]
fn an_already_expired_jwt_is_refused_rather_than_clamped_to_a_floor() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let reason = credential_lifetime(&jwt_with_exp(999_000), lifetime_policy(3600, 60), now)
        .expect_err("expired material must never yield a lifetime");
    assert_eq!(reason, StockCredentialInvalidReason::Expired);
    assert_eq!(reason.as_metric_label(), "token_expired");

    // Exactly at `exp` is also expired.
    let reason = credential_lifetime(&jwt_with_exp(1_000_000), lifetime_policy(3600, 0), now)
        .expect_err("a token at exp is expired");
    assert_eq!(reason, StockCredentialInvalidReason::Expired);
}

/// A token that has not expired yet but cannot leave a positive window once the
/// operator's skew is applied would schedule the retirement AT OR AFTER `exp`.
/// That is the same defect with one extra step, so it is refused too.
#[test]
fn a_jwt_that_cannot_clear_the_skew_is_refused() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for remaining in [1u64, 30, 60] {
        let reason = credential_lifetime(
            &jwt_with_exp(1_000_000 + remaining as i64),
            lifetime_policy(3600, 60),
            now,
        )
        .expect_err("a non-positive post-skew window is refused");
        assert_eq!(
            reason,
            StockCredentialInvalidReason::ExpiresWithinSkew,
            "{remaining}s remaining vs a 60s skew"
        );
        assert_eq!(reason.as_metric_label(), "token_expires_within_skew");
    }
    // One second past the skew is admissible again.
    let (lifetime, _) =
        credential_lifetime(&jwt_with_exp(1_000_061), lifetime_policy(3600, 60), now)
            .expect("a 1s post-skew window is still a positive window");
    assert_eq!(lifetime, Duration::from_secs(1));
}

/// Issue #3852 round two. Materialization happens BEFORE the channel is dialed,
/// so a deadline derived from stream-open time would be extended by connect,
/// TLS handshake, and RPC-setup latency — silently pushing a JWT past `exp`.
/// The deadline is absolute and stamped at admission, so elapsed connect time
/// SPENDS it.
#[tokio::test]
async fn the_absolute_deadline_is_stamped_at_admission_not_at_stream_open() {
    let credential = StockBearerCredential::admit("opaque-projected-token", lifetime_policy(60, 5))
        .expect("valid ascii");
    let deadline = credential.deadline();
    assert!(!credential.deadline_reached());

    // Stand in for dial + TLS handshake + RPC setup.
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(
        deadline,
        credential.deadline(),
        "connect latency must not move the deadline"
    );
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    assert!(
        remaining < credential.lifetime(),
        "the elapsed connect time must have been spent, not added: {remaining:?} vs {:?}",
        credential.lifetime()
    );
    assert!(remaining > Duration::from_secs(58), "{remaining:?}");
}

/// The connect path refuses to attach a credential whose absolute deadline has
/// already passed, rather than opening a stream it would have to retire in the
/// same breath.
#[tokio::test]
async fn a_credential_whose_deadline_elapsed_during_connect_refuses_to_attach() {
    // The minimum admissible maximum stream lifetime is 60s, so drive the
    // elapsed-deadline case through a JWT whose post-skew window is 1s.
    let now = SystemTime::now();
    let exp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as i64
        + 1;
    let credential = StockBearerCredential::admit(&jwt_with_exp(exp), lifetime_policy(3600, 0))
        .expect("a 1s window is admissible at admission time");
    assert!(!credential.deadline_reached());
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        credential.deadline_reached(),
        "a credential that expired during the dial must refuse to open a stream"
    );
    assert_eq!(
        StockCredentialInvalidReason::DeadlineReached.as_metric_label(),
        "token_deadline_reached"
    );
}

/// The opaque bound stays finite; the UPPER clamp is the security property and
/// is enforced in code unconditionally, so an opaque bearer can never hold a
/// stream indefinitely. The operator-facing 60s minimum is enforced where an
/// operator can actually set it (`FERRUM_MESH_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECONDS`
/// admission), not by silently rounding a programmatic policy up.
#[test]
fn the_opaque_maximum_stays_finite_and_capped() {
    let now = SystemTime::now();
    let (as_configured, _) = credential_lifetime("opaque", lifetime_policy(2, 0), now)
        .expect("an opaque token is always admissible");
    assert_eq!(as_configured, Duration::from_secs(2));

    // Zero is refused as a deadline: it would be already elapsed.
    let (floored, _) = credential_lifetime("opaque", lifetime_policy(0, 0), now)
        .expect("an opaque token is always admissible");
    assert_eq!(floored, Duration::from_secs(1));

    let (too_large, _) = credential_lifetime("opaque", lifetime_policy(999_999, 0), now)
        .expect("an opaque token is always admissible");
    assert_eq!(
        too_large,
        Duration::from_secs(MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS)
    );
    const { assert!(MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS == 60) };
}

#[test]
fn jwt_expiration_hint_is_bounded_and_refuses_non_jws_shapes() {
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp(2_000_000_000)),
        Some(2_000_000_000)
    );
    // Not three segments.
    assert!(jwt_expiration_hint("opaque").is_none());
    assert!(jwt_expiration_hint("a.b").is_none());
    assert!(jwt_expiration_hint("a.b.c.d").is_none());
    // Empty payload/signature.
    assert!(jwt_expiration_hint("a..c").is_none());
    assert!(jwt_expiration_hint("a.b.").is_none());
    // Not base64url.
    assert!(jwt_expiration_hint("a.!!!!.c").is_none());
    // Valid base64url that is not JSON.
    let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"plain text");
    assert!(jwt_expiration_hint(&format!("a.{not_json}.c")).is_none());
    // JSON without `exp` is no hint. A syntactically valid NumericDate `exp`
    // of zero or a negative value is a hint that the token is already
    // expired, not "no hint". Fractional forms are covered below.
    let no_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
    assert!(jwt_expiration_hint(&format!("a.{no_exp}.c")).is_none());
    let zero_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":0}"#);
    assert_eq!(jwt_expiration_hint(&format!("a.{zero_exp}.c")), Some(0));
    let negative_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":-1}"#);
    assert_eq!(
        jwt_expiration_hint(&format!("a.{negative_exp}.c")),
        Some(-1)
    );
    // An oversized payload segment is not parsed at all.
    let oversized = "A".repeat(9 * 1024);
    assert!(jwt_expiration_hint(&format!("a.{oversized}.c")).is_none());
    // The segment cap alone bounds the decoded payload: an exactly 8 KiB
    // segment (6 KiB of JSON) is still parsed, one byte more is not.
    let mut padded = br#"{"exp":2000000000,"pad":""#.to_vec();
    padded.resize(6 * 1024 - 2, b'p');
    padded.extend_from_slice(br#""}"#);
    let at_cap = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&padded);
    assert_eq!(at_cap.len(), 8 * 1024);
    assert_eq!(
        jwt_expiration_hint(&format!("a.{at_cap}.c")),
        Some(2_000_000_000)
    );
    assert!(jwt_expiration_hint(&format!("a.{at_cap}A.c")).is_none());
}

/// Unix epoch zero and negative NumericDate values are plainly expired. They
/// must fail closed as `Expired` rather than granting the opaque maximum, and
/// the conversion must not wrap a negative `i64` into a far-future `u64`.
#[test]
fn jwt_shaped_tokens_with_zero_or_negative_exp_are_expired_not_opaque() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for exp in [0_i64, -1, -3_600, i64::MIN] {
        assert_eq!(
            jwt_expiration_hint(&jwt_with_exp(exp)),
            Some(exp),
            "exp={exp}"
        );
        let reason = credential_lifetime(&jwt_with_exp(exp), lifetime_policy(3600, 0), now)
            .expect_err("zero/negative NumericDate must never yield a lifetime");
        assert_eq!(
            reason,
            StockCredentialInvalidReason::Expired,
            "exp={exp} must not be treated as opaque"
        );
    }
}

#[test]
fn jwt_shaped_tokens_with_zero_or_negative_exp_are_refused_at_admission() {
    for exp in [0_i64, -1, -3_600, i64::MIN] {
        let reason = StockBearerCredential::admit(&jwt_with_exp(exp), lifetime_policy(3600, 0))
            .expect_err("zero/negative NumericDate must not be admitted");
        assert_eq!(reason, StockCredentialInvalidReason::Expired, "exp={exp}");
    }
}

/// RFC 7519 NumericDate permits non-integer JSON numbers. A present valid
/// number must never become "no hint": that used to grant the opaque maximum
/// and could hold a stock-xDS stream past authoritative `exp`.
#[test]
fn jwt_expiration_hint_floors_a_fractional_numeric_date() {
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000000.9")),
        Some(1_000_000)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000000.1")),
        Some(1_000_000)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000000.0")),
        Some(1_000_000)
    );
    // Immediately below the next integer: must not round up.
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000000.999")),
        Some(1_000_000)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000000.999999999")),
        Some(1_000_000)
    );
    // Integer-valued fractions stay pinned to the integer.
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1000600.0")),
        Some(1_000_600)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp(1_000_600)),
        Some(1_000_600)
    );
}

#[test]
fn jwt_expiration_hint_accepts_json_exponent_notation() {
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1e6")),
        Some(1_000_000)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1E6")),
        Some(1_000_000)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1.0006009e6")),
        Some(1_000_600)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("1.0006e+6")),
        Some(1_000_600)
    );
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("10000000e-1")),
        Some(1_000_000)
    );
}

#[test]
fn jwt_shaped_tokens_with_zero_or_negative_fractional_exp_are_expired_not_opaque() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for lexeme in ["0.0", "0.9", "-0.1", "-1.5", "-1e-1", "-1.0"] {
        let token = jwt_with_exp_lexeme(lexeme);
        let hint = jwt_expiration_hint(&token).expect("a present JSON-number exp is a hint");
        assert!(hint <= 0, "lexeme={lexeme} hint={hint}");
        let reason = credential_lifetime(&token, lifetime_policy(3600, 0), now)
            .expect_err("zero/negative fractional NumericDate must never yield a lifetime");
        assert_eq!(
            reason,
            StockCredentialInvalidReason::Expired,
            "lexeme={lexeme} must not be treated as opaque"
        );
    }
}

/// Issue #3852 follow-up: a fractional `exp` used to fail `JwtExpClaim { exp:
/// Option<i64> }` as a shape mismatch, so `credential_lifetime` granted the
/// opaque maximum and could hold the stream past authoritative expiry.
#[test]
fn a_fractional_jwt_exp_cannot_fall_through_to_the_opaque_maximum() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp_lexeme("1000600.9");
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 60), now)
        .expect("a fractional exp with a positive post-skew window is admissible");
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
    assert_eq!(
        lifetime,
        Duration::from_secs(540),
        "floor(1000600.9)=1000600 → 600s minus 60s skew, not the 3600s opaque max"
    );
    assert!(
        lifetime < Duration::from_secs(3600),
        "the opaque maximum must not win past a present fractional exp"
    );

    let (lifetime, basis) = credential_lifetime(
        &jwt_with_exp_lexeme("1.0006009e6"),
        lifetime_policy(3600, 0),
        now,
    )
    .expect("exponent-notation fractional exp is a JWT hint");
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
    assert!(
        lifetime < Duration::from_secs(601),
        "scheduled lifetime must be no later than the floored exp: {lifetime:?}"
    );
    assert!(
        lifetime < Duration::from_secs(3600),
        "exponent notation must not fall through to the opaque maximum"
    );
}

#[test]
fn a_fractional_exp_immediately_below_now_is_expired_not_opaque() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    // 1000000.999 floors to 1000000, remaining 0 → Expired. An f64 round-up
    // would have scheduled a 1s lifetime.
    let reason = credential_lifetime(
        &jwt_with_exp_lexeme("1000000.999"),
        lifetime_policy(3600, 0),
        now,
    )
    .expect_err("a fractional exp that floors to now is already expired");
    assert_eq!(reason, StockCredentialInvalidReason::Expired);
}

#[test]
fn huge_numeric_date_hints_do_not_overflow_or_become_a_negative_deadline() {
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme("1e30")).is_none());
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme("1.5e30")).is_none());
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme("9223372036854775808")).is_none());
    assert_eq!(
        jwt_expiration_hint(&jwt_with_exp_lexeme("9223372036854775807")),
        Some(i64::MAX)
    );

    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let (lifetime, basis) =
        credential_lifetime(&jwt_with_exp_lexeme("1e30"), lifetime_policy(3600, 0), now)
            .expect("an unrepresentable positive hint is admissible as the opaque cap");
    assert_eq!(lifetime, Duration::from_secs(3600));
    assert_eq!(basis, StockCredentialDeadlineBasis::MaxStreamLifetime);

    let hint = jwt_expiration_hint(&jwt_with_exp_lexeme("-1e30")).expect("negative hint");
    assert!(hint < 0);
    let reason = credential_lifetime(&jwt_with_exp_lexeme("-1e30"), lifetime_policy(3600, 0), now)
        .expect_err("a huge negative NumericDate is expired");
    assert_eq!(reason, StockCredentialInvalidReason::Expired);
}

#[test]
fn non_number_exp_shapes_remain_opaque() {
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme(r#""soon""#)).is_none());
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme("true")).is_none());
    assert!(jwt_expiration_hint(&jwt_with_exp_lexeme("[]")).is_none());
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let (lifetime, basis) = credential_lifetime(
        &jwt_with_exp_lexeme(r#""soon""#),
        lifetime_policy(3600, 0),
        now,
    )
    .expect("a non-number exp stays opaque");
    assert_eq!(lifetime, Duration::from_secs(3600));
    assert_eq!(basis, StockCredentialDeadlineBasis::MaxStreamLifetime);
}

#[test]
fn credential_fingerprints_distinguish_rotation_from_an_unchanged_token() {
    let policy = lifetime_policy(3600, 60);
    let first = StockBearerCredential::admit("projected-token-a", policy).expect("valid ascii");
    let same = StockBearerCredential::admit("projected-token-a", policy).expect("valid ascii");
    let rotated = StockBearerCredential::admit("projected-token-b", policy).expect("valid ascii");

    assert_eq!(
        first.fingerprint(),
        same.fingerprint(),
        "an unchanged token must not churn the ADS stream"
    );
    assert_ne!(first.fingerprint(), rotated.fingerprint());
    assert_eq!(
        first.token().to_str().expect("ascii metadata"),
        "Bearer projected-token-a"
    );
}

/// A digest of a secret is still an offline oracle for it, so the fingerprint
/// must not be renderable — not even through `Debug`.
#[test]
fn credential_debug_output_never_carries_token_material() {
    let credential =
        StockBearerCredential::admit("super-secret-projected-token", lifetime_policy(3600, 60))
            .expect("valid ascii");
    let rendered = format!("{credential:?}");
    assert!(
        !rendered.contains("super-secret-projected-token"),
        "{rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let fingerprint = format!("{:?}", credential.fingerprint());
    assert_eq!(fingerprint, "StockCredentialFingerprint(<redacted>)");
}

/// The credential pathname is metadata. `Debug` of the source — and of the
/// client config that embeds it — must report only whether a source is
/// configured plus safe policy fields.
#[test]
fn stock_credential_source_debug_never_renders_the_path() {
    use std::collections::BTreeMap;

    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::StockXdsClientConfig;
    use ferrum_edge::xds::stock::StockXdsLimits;

    let path = "/var/run/secrets/tokens/istio-token";
    let source = StockXdsCredentialSource::new(
        Some(path.to_string()),
        StockCredentialLifetimePolicy::default(),
    );
    let rendered = format!("{source:?}");
    assert!(
        !rendered.contains(path),
        "source Debug leaked the credential path: {rendered}"
    );
    assert!(
        !rendered.contains("istio-token"),
        "source Debug leaked a path fragment: {rendered}"
    );
    assert!(
        !rendered.contains("path"),
        "source Debug must not name the path field: {rendered}"
    );
    assert!(
        rendered.contains("configured: true"),
        "source Debug must say whether a source is configured: {rendered}"
    );

    let unconfigured = StockXdsCredentialSource::unauthenticated();
    let unconfigured_rendered = format!("{unconfigured:?}");
    assert!(
        unconfigured_rendered.contains("configured: false"),
        "{unconfigured_rendered}"
    );
    assert!(!unconfigured_rendered.contains("path"));

    let config = StockXdsClientConfig {
        xds_urls: vec!["https://127.0.0.1:15010".to_string()],
        node_id: "sidecar".to_string(),
        cluster: "default".to_string(),
        namespace: "default".to_string(),
        node_metadata: BTreeMap::new(),
        credential: source,
        allow_loopback_plaintext: false,
        stream_channel_capacity: 32,
        primary_retry_secs: 0,
        connect_timeout_seconds: 5,
        limits: StockXdsLimits::default(),
        timings: MeshStreamTimings::production(),
    };
    let config_rendered = format!("{config:?}");
    assert!(
        !config_rendered.contains(path),
        "client-config Debug leaked the credential path: {config_rendered}"
    );
    assert!(
        !config_rendered.contains("istio-token"),
        "client-config Debug leaked a path fragment: {config_rendered}"
    );
}

#[test]
fn a_non_ascii_token_is_refused_without_echoing_it() {
    let reason = StockBearerCredential::admit("tökén-with-non-ascii", lifetime_policy(3600, 60))
        .expect_err("gRPC metadata is ASCII");
    assert_eq!(reason, StockCredentialInvalidReason::NotAsciiMetadata);
    let rendered = reason.to_string();
    assert_eq!(rendered, "token_source_not_ascii_metadata");
    assert!(!rendered.contains("tökén"));
}

#[test]
fn invalid_reason_labels_are_a_closed_snake_case_set() {
    let reasons = [
        StockCredentialInvalidReason::Missing,
        StockCredentialInvalidReason::NotRegularFile,
        StockCredentialInvalidReason::Unreadable,
        StockCredentialInvalidReason::Empty,
        StockCredentialInvalidReason::Oversized,
        StockCredentialInvalidReason::InvalidEncoding,
        StockCredentialInvalidReason::NotAsciiMetadata,
        StockCredentialInvalidReason::ReadTimeout,
        StockCredentialInvalidReason::ReaderUnavailable,
        StockCredentialInvalidReason::Expired,
        StockCredentialInvalidReason::ExpiresWithinSkew,
        StockCredentialInvalidReason::DeadlineReached,
    ];
    let mut labels: Vec<&str> = reasons.iter().map(|r| r.as_metric_label()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), reasons.len());
    for label in labels {
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "'{label}'"
        );
    }
    // Every invalid reason projects onto the SAME closed health value, so a new
    // reason can never widen the authenticated `/health` surface.
    for reason in reasons {
        assert_eq!(
            (StockCredentialState::Invalid { reason }).health(),
            MeshConfigStreamCredential::SourceInvalid
        );
    }
}

#[test]
fn the_credential_watch_only_advances_its_generation_on_a_real_change() {
    let credential = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert_eq!(watch.latest().generation, 0);

    assert!(watch.publish(credential.observed_state()));
    assert_eq!(watch.latest().generation, 1);

    // Re-reading the SAME token must not retire a healthy stream.
    assert!(!watch.publish(credential.observed_state()));
    assert_eq!(watch.latest().generation, 1);

    assert!(watch.publish(rotated.observed_state()));
    assert_eq!(watch.latest().generation, 2);

    assert!(watch.publish(StockCredentialState::Invalid {
        reason: StockCredentialInvalidReason::Missing
    }));
    assert_eq!(watch.latest().generation, 3);
    assert!(watch.latest().state.is_invalid());
    assert_eq!(
        watch.latest().state.health(),
        MeshConfigStreamCredential::SourceInvalid
    );
}

/// The reconnect path can finish an older serialized read, drop the reader
/// permit, and publish after a newer read has already been published. The
/// older observation must not resurrect.
#[tokio::test]
async fn an_older_serialized_read_cannot_overwrite_a_newer_valid_observation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    std::fs::write(&path, b"token-a").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let older = source.observe().await;
    std::fs::write(&path, b"token-b").expect("write");
    let newer = source.observe().await;
    assert_ne!(older.observed_state(), newer.observed_state());

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(
        watch
            .publish_observed(newer.epoch(), newer.observed_state())
            .generation_changed()
    );
    let generation = watch.latest().generation;
    let published = watch.latest().state;
    assert_eq!(
        watch.publish_observed(older.epoch(), older.observed_state()),
        StockCredentialPublish::Superseded {
            state: published,
            generation,
        }
    );
    assert_eq!(watch.latest().generation, generation);
    assert_eq!(watch.latest().state, published);
    assert_eq!(
        watch.publish_observed(None, older.observed_state()),
        StockCredentialPublish::Superseded {
            state: published,
            generation,
        }
    );
}

#[tokio::test]
async fn an_older_valid_read_cannot_overwrite_a_newer_invalid_observation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    std::fs::write(&path, b"token-a").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let older = source.observe().await;
    std::fs::remove_file(&path).expect("unlink");
    let newer = source.observe().await;
    assert!(
        matches!(newer.observed_state(), StockCredentialState::Invalid { .. }),
        "deleting the source must fail closed"
    );

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(
        watch
            .publish_observed(newer.epoch(), newer.observed_state())
            .generation_changed()
    );
    let generation = watch.latest().generation;
    let published = watch.latest().state;
    assert_eq!(
        watch.publish_observed(older.epoch(), older.observed_state()),
        StockCredentialPublish::Superseded {
            state: published,
            generation,
        }
    );
    assert_eq!(watch.latest().generation, generation);
    assert!(watch.latest().state.is_invalid());
}

#[tokio::test]
async fn an_older_invalid_read_cannot_overwrite_a_newer_valid_observation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let older = source.observe().await;
    assert!(matches!(
        older.observed_state(),
        StockCredentialState::Invalid {
            reason: StockCredentialInvalidReason::Missing,
        }
    ));
    std::fs::write(&path, b"token-b").expect("write");
    let newer = source.observe().await;
    assert!(matches!(
        newer.observed_state(),
        StockCredentialState::Valid { .. }
    ));

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(
        watch
            .publish_observed(newer.epoch(), newer.observed_state())
            .generation_changed()
    );
    let generation = watch.latest().generation;
    let published = watch.latest().state;
    assert_eq!(
        watch.publish_observed(older.epoch(), older.observed_state()),
        StockCredentialPublish::Superseded {
            state: published,
            generation,
        }
    );
    assert_eq!(watch.latest().generation, generation);
    assert_eq!(watch.latest().state, published);
}

#[tokio::test]
async fn an_older_read_of_the_same_token_does_not_churn_generation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    std::fs::write(&path, b"token-unchanged").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let first = source.observe().await;
    let second = source.observe().await;
    assert_eq!(first.observed_state(), second.observed_state());

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(
        watch
            .publish_observed(first.epoch(), first.observed_state())
            .generation_changed()
    );
    let generation = watch.latest().generation;
    assert!(
        !watch
            .publish_observed(second.epoch(), second.observed_state())
            .generation_changed()
    );
    assert_eq!(watch.latest().generation, generation);
    assert_eq!(
        watch.publish_observed(first.epoch(), first.observed_state()),
        StockCredentialPublish::Accepted {
            generation,
            generation_changed: false,
        }
    );
    assert_eq!(
        admit_stock_credential_observation_for_test(&watch, first.epoch(), first.observed_state(),),
        Ok(generation)
    );
}

#[tokio::test]
async fn an_older_valid_read_cannot_bind_a_stream_after_a_newer_valid_observation_wins() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    std::fs::write(&path, b"token-a").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let older = source.observe().await;
    std::fs::write(&path, b"token-b").expect("write");
    let newer = source.observe().await;

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    let opened =
        admit_stock_credential_observation_for_test(&watch, newer.epoch(), newer.observed_state())
            .expect("the newest valid observation is admitted");
    assert_eq!(
        admit_stock_credential_observation_for_test(&watch, older.epoch(), older.observed_state(),),
        Err(MeshStreamRetirement::CredentialRotated)
    );
    assert_eq!(watch.latest().generation, opened);
    assert_eq!(watch.latest().state, newer.observed_state());
}

#[tokio::test]
async fn an_older_valid_read_cannot_bind_a_stream_after_a_newer_invalid_observation_wins() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("token");
    std::fs::write(&path, b"token-a").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(path.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let older = source.observe().await;
    std::fs::remove_file(&path).expect("unlink");
    let newer = source.observe().await;

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    let opened =
        admit_stock_credential_observation_for_test(&watch, newer.epoch(), newer.observed_state())
            .expect("the newest invalid observation is admitted");
    assert_eq!(
        admit_stock_credential_observation_for_test(&watch, older.epoch(), older.observed_state(),),
        Err(MeshStreamRetirement::CredentialSourceInvalid)
    );
    assert_eq!(watch.latest().generation, opened);
    assert!(watch.latest().state.is_invalid());
}

#[tokio::test]
async fn a_not_configured_observation_still_obeys_read_epoch_order() {
    let source = StockXdsCredentialSource::unauthenticated();
    let older = source.observe().await;
    let newer = source.observe().await;
    assert_eq!(older.observed_state(), StockCredentialState::NotConfigured);
    assert_eq!(newer.observed_state(), StockCredentialState::NotConfigured);

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(
        watch
            .publish_observed(newer.epoch(), newer.observed_state())
            .generation_changed()
    );
    let generation = watch.latest().generation;
    assert_eq!(
        watch.publish_observed(older.epoch(), older.observed_state()),
        StockCredentialPublish::Accepted {
            generation,
            generation_changed: false,
        }
    );
    assert_eq!(watch.latest().generation, generation);
    assert_eq!(watch.latest().state, StockCredentialState::NotConfigured);
}

#[test]
fn an_unconfigured_credential_source_reports_not_configured() {
    let source = StockXdsCredentialSource::unauthenticated();
    assert!(!source.is_configured());
    assert_eq!(source.initial_state(), StockCredentialState::NotConfigured);
    assert_eq!(
        StockCredentialState::NotConfigured.health(),
        MeshConfigStreamCredential::NotConfigured
    );
}

#[test]
fn a_configured_source_starts_unobserved_rather_than_assumed_valid() {
    let source = StockXdsCredentialSource::new(
        Some("/var/run/secrets/tokens/istio-token".to_string()),
        StockCredentialLifetimePolicy::default(),
    );
    assert!(source.is_configured());
    assert_eq!(source.initial_state(), StockCredentialState::Unknown);
    // An unobserved source must not be advertised as valid on `/health` — nor
    // as absent, which would misreport the operator's own configuration.
    assert_eq!(
        StockCredentialState::Unknown.health(),
        MeshConfigStreamCredential::Unobserved
    );
}

#[test]
fn the_default_lifetime_policy_stays_inside_the_documented_bounds() {
    let policy = StockCredentialLifetimePolicy::default();
    assert_eq!(
        policy.max_stream_lifetime.as_secs(),
        DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
    );
    assert!(
        policy.max_stream_lifetime.as_secs() >= MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
            && policy.max_stream_lifetime.as_secs() <= MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
    );
    assert!(policy.refresh_skew < policy.max_stream_lifetime);
    assert!(policy.watch_interval > Duration::ZERO);
}

// ── invalid-source reads through the real hardened boundary ─────────────

#[tokio::test]
async fn every_invalid_credential_source_shape_fails_closed_with_a_bounded_reason() {
    let temp = tempfile::tempdir().expect("temp dir");

    let missing = temp.path().join("absent-token");
    let source = StockXdsCredentialSource::new(
        Some(missing.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("absent source"),
        StockCredentialInvalidReason::Missing
    );

    let empty = temp.path().join("empty-token");
    std::fs::write(&empty, b"   \n\t ").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(empty.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("empty source"),
        StockCredentialInvalidReason::Empty
    );

    let directory = temp.path().join("token-dir");
    std::fs::create_dir(&directory).expect("mkdir");
    let source = StockXdsCredentialSource::new(
        Some(directory.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("non-regular source"),
        StockCredentialInvalidReason::NotRegularFile
    );

    let oversized = temp.path().join("oversized-token");
    std::fs::write(
        &oversized,
        vec![b'x'; ferrum_edge::secrets::credential_file::DEFAULT_CREDENTIAL_FILE_MAX_BYTES + 1],
    )
    .expect("write");
    let source = StockXdsCredentialSource::new(
        Some(oversized.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("oversized source"),
        StockCredentialInvalidReason::Oversized
    );

    let non_ascii = temp.path().join("non-ascii-token");
    std::fs::write(&non_ascii, "tökén".as_bytes()).expect("write");
    let source = StockXdsCredentialSource::new(
        Some(non_ascii.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("non-ascii source"),
        StockCredentialInvalidReason::NotAsciiMetadata
    );

    // Invalid UTF-8 is distinguishable from valid-UTF-8-but-not-ASCII: the
    // former never reaches the metadata parser at all.
    let invalid_utf8 = temp.path().join("invalid-utf8-token");
    std::fs::write(&invalid_utf8, [0x74, 0x6f, 0x6b, 0xff, 0xfe]).expect("write");
    let source = StockXdsCredentialSource::new(
        Some(invalid_utf8.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source
            .materialize()
            .await
            .expect_err("invalid utf-8 source"),
        StockCredentialInvalidReason::InvalidEncoding
    );

    // A JWT-shaped token that is already past `exp` reaches the SAME closed
    // invalid state through the real reader, so the fail-closed reconnect gate
    // treats an expired credential exactly like a missing one.
    let expired = temp.path().join("expired-token");
    let past = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as i64
        - 3_600;
    std::fs::write(&expired, jwt_with_exp(past).as_bytes()).expect("write");
    let source = StockXdsCredentialSource::new(
        Some(expired.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("expired source"),
        StockCredentialInvalidReason::Expired
    );

    // Unix epoch zero and a negative NumericDate are expired through the same
    // reader, not opaque material that would be granted the maximum lifetime.
    for exp in [0_i64, -1] {
        let already_expired = temp.path().join(format!("expired-token-{exp}"));
        std::fs::write(&already_expired, jwt_with_exp(exp).as_bytes()).expect("write");
        let source = StockXdsCredentialSource::new(
            Some(already_expired.to_string_lossy().into_owned()),
            StockCredentialLifetimePolicy::default(),
        );
        assert_eq!(
            source
                .materialize()
                .await
                .expect_err("zero/negative NumericDate source"),
            StockCredentialInvalidReason::Expired,
            "exp={exp}"
        );
    }

    // Unreadable-where-portable: a mode-000 regular file. Skipped when the test
    // runs as root, where the mode is not enforced.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let unreadable = temp.path().join("unreadable-token");
        std::fs::write(&unreadable, b"projected-token").expect("write");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let source = StockXdsCredentialSource::new(
            Some(unreadable.to_string_lossy().into_owned()),
            StockCredentialLifetimePolicy::default(),
        );
        let outcome = source.materialize().await;
        match outcome {
            Err(reason) => assert_eq!(reason, StockCredentialInvalidReason::Unreadable),
            // Running as root: the mode is advisory, so the read succeeds.
            Ok(_) => assert!(
                nix_running_as_root(),
                "a mode-000 credential file must be refused for a non-root reader"
            ),
        }
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600));
    }
}

/// The unreadable-source case is only meaningful for a non-root reader; hosted
/// CI containers sometimes run as uid 0, where the file mode is advisory.
#[cfg(unix)]
fn nix_running_as_root() -> bool {
    // SAFETY: `geteuid` is always safe; it takes no arguments, reads process
    // credentials, and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// A projected Kubernetes secret rotates by swapping a symlink, not by
/// rewriting the file in place. Detection must therefore be content-based.
#[tokio::test]
async fn a_projected_symlink_swap_is_observed_as_a_content_rotation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let first = temp.path().join("..data-1");
    let second = temp.path().join("..data-2");
    std::fs::write(&first, b"projected-token-one\n").expect("write");
    std::fs::write(&second, b"projected-token-two\n").expect("write");
    let link = temp.path().join("token");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&first, &link).expect("symlink");
    #[cfg(not(unix))]
    std::fs::copy(&first, &link).expect("copy");

    let source = StockXdsCredentialSource::new(
        Some(link.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let before = source
        .materialize()
        .await
        .expect("readable")
        .expect("configured");

    #[cfg(unix)]
    {
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(&second, &link).expect("relink");
    }
    #[cfg(not(unix))]
    std::fs::copy(&second, &link).expect("copy");

    let after = source
        .materialize()
        .await
        .expect("readable")
        .expect("configured");
    assert_ne!(
        before.fingerprint(),
        after.fingerprint(),
        "a symlink swap must be observed as a rotation"
    );

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(before.observed_state()));
    assert!(watch.publish(after.observed_state()));
    assert_eq!(watch.latest().generation, 2);
}

/// The commit fence retains the watch observation lock across the synchronous
/// install, so a concurrent publish cannot land a new generation between the
/// check and `install_slice`.
#[test]
fn stock_credential_commit_holds_the_watch_lock_across_install() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::run_under_stock_credential_commit_admission_for_test;
    use ferrum_edge::modes::mesh::runtime::{MeshRuntimeState, MeshSliceInstall};
    use ferrum_edge::modes::mesh::slice::MeshSlice;

    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    let state = MeshRuntimeState::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    // Completion is observed on this channel, not via a nested `watch.latest()`
    // inside the guarded commit. The production admission guard already holds
    // the watch read lock; a queued `publish` writer plus a second borrow can
    // deadlock under writer-preferring RwLock behavior.
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    std::thread::scope(|scope| {
        let publisher_watch = &watch;
        let publisher = scope.spawn(move || {
            entered_rx
                .recv()
                .expect("commit holds the observation lock");
            let published = publisher_watch.publish(rotated.observed_state());
            let _ = done_tx.send(published);
            published
        });

        let installed = run_under_stock_credential_commit_admission_for_test(
            &watch,
            opened,
            None,
            true,
            || {
                entered_tx.send(()).expect("publisher may attempt publish");
                assert_eq!(
                    done_rx.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    "a concurrent publish must not complete while the commit guard is held"
                );
                let installed = state.install_slice(MeshSlice {
                    version: "v-committed".to_string(),
                    ..MeshSlice::default()
                });
                assert_eq!(
                    done_rx.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    "a concurrent publish must not complete while the commit guard is held"
                );
                installed
            },
        )
        .expect("the opened generation is still current");

        assert!(matches!(installed, MeshSliceInstall::Installed));
        assert!(
            publisher.join().expect("publisher thread"),
            "the publish must land only after the commit guard drops"
        );
    });

    assert_eq!(watch.latest().generation, opened + 1);
    assert_eq!(
        state
            .snapshot()
            .as_ref()
            .as_ref()
            .map(|slice| slice.version.as_str()),
        Some("v-committed")
    );
}

#[test]
fn stock_credential_commit_refuses_a_rotated_generation_without_installing() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::run_under_stock_credential_commit_admission_for_test;

    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    assert!(watch.publish(rotated.observed_state()));

    let err =
        run_under_stock_credential_commit_admission_for_test(&watch, opened, None, true, || {
            panic!("a rotated generation must not reach the install callback")
        })
        .expect_err("stale generation is refused");
    assert_eq!(err, MeshStreamRetirement::CredentialRotated);
}

fn filled_stock_outbound_channel() -> (
    tokio::sync::mpsc::Sender<ferrum_edge::xds::proto::DiscoveryRequest>,
    tokio::sync::mpsc::Receiver<ferrum_edge::xds::proto::DiscoveryRequest>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.try_send(ferrum_edge::xds::proto::DiscoveryRequest::default())
        .expect("fill the single-slot channel so the next send parks");
    (tx, rx)
}

/// A blocked initial-style enqueue (filled mpsc, receiver held) must retire
/// with the credential outcome, not `request_enqueue_timeout`.
#[tokio::test]
async fn a_blocked_stock_outbound_enqueue_loses_to_credential_rotation() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockOutboundAdmission, send_stock_outbound_racing_credential_for_test,
    };

    let (tx, _rx) = filled_stock_outbound_channel();
    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    let mut task_rx = watch.receiver();
    let _ = task_rx.borrow_and_update();
    let (parked_tx, mut parked_rx) = tokio::sync::watch::channel(false);
    let watch_for_task = watch.clone();
    let tx_for_task = tx.clone();

    let send = tokio::spawn(async move {
        send_stock_outbound_racing_credential_for_test(
            &tx_for_task,
            ferrum_edge::xds::proto::DiscoveryRequest::default(),
            Duration::from_secs(30),
            &watch_for_task,
            opened,
            None,
            true,
            &mut task_rx,
            Some(&parked_tx),
        )
        .await
    });

    parked_rx.changed().await.expect("send reaches the wait");
    assert!(
        *parked_rx.borrow(),
        "the production send must signal after admission and before the enqueue wait"
    );
    assert!(watch.publish(rotated.observed_state()));
    assert_eq!(
        send.await.expect("send task"),
        StockOutboundAdmission::Retired(MeshStreamRetirement::CredentialRotated)
    );
}

#[tokio::test]
async fn a_blocked_stock_outbound_enqueue_loses_to_credential_invalidation() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockOutboundAdmission, send_stock_outbound_racing_credential_for_test,
    };

    let (tx, _rx) = filled_stock_outbound_channel();
    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    let mut task_rx = watch.receiver();
    let _ = task_rx.borrow_and_update();
    let (parked_tx, mut parked_rx) = tokio::sync::watch::channel(false);
    let watch_for_task = watch.clone();
    let tx_for_task = tx.clone();

    let send = tokio::spawn(async move {
        send_stock_outbound_racing_credential_for_test(
            &tx_for_task,
            ferrum_edge::xds::proto::DiscoveryRequest::default(),
            Duration::from_secs(30),
            &watch_for_task,
            opened,
            None,
            true,
            &mut task_rx,
            Some(&parked_tx),
        )
        .await
    });

    parked_rx.changed().await.expect("send reaches the wait");
    assert!(watch.publish(StockCredentialState::Invalid {
        reason: StockCredentialInvalidReason::Missing,
    }));
    assert_eq!(
        send.await.expect("send task"),
        StockOutboundAdmission::Retired(MeshStreamRetirement::CredentialSourceInvalid)
    );
}

#[tokio::test]
async fn a_blocked_stock_outbound_enqueue_loses_to_an_already_elapsed_deadline() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockOutboundAdmission, send_stock_outbound_racing_credential_for_test,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    let mut credential_rx = watch.receiver();
    let _ = credential_rx.borrow_and_update();

    let result = send_stock_outbound_racing_credential_for_test(
        &tx,
        ferrum_edge::xds::proto::DiscoveryRequest::default(),
        Duration::from_secs(30),
        &watch,
        opened,
        Some(tokio::time::Instant::now()),
        true,
        &mut credential_rx,
        None,
    )
    .await;
    assert_eq!(
        result,
        StockOutboundAdmission::Retired(MeshStreamRetirement::CredentialDeadline)
    );
    assert!(
        rx.try_recv().is_err(),
        "an already-elapsed deadline must not enqueue the request"
    );
}

/// Response-driven ACK/NACK/dependency sends share the same enqueue helper as
/// the initial CDS/LDS subscriptions. An already-observed rotation must win
/// before the send is even attempted, so a ready channel cannot smuggle a
/// retired-credential ACK through.
#[tokio::test]
async fn an_already_observed_rotation_wins_over_a_ready_outbound_enqueue() {
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockOutboundAdmission, send_stock_outbound_racing_credential_for_test,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let first = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();
    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(first.observed_state()));
    let opened = watch.latest().generation;
    assert!(watch.publish(rotated.observed_state()));
    let mut credential_rx = watch.receiver();
    let _ = credential_rx.borrow_and_update();

    let result = send_stock_outbound_racing_credential_for_test(
        &tx,
        ferrum_edge::xds::proto::DiscoveryRequest::default(),
        Duration::from_secs(30),
        &watch,
        opened,
        None,
        true,
        &mut credential_rx,
        None,
    )
    .await;
    assert_eq!(
        result,
        StockOutboundAdmission::Retired(MeshStreamRetirement::CredentialRotated)
    );
    assert!(
        rx.try_recv().is_err(),
        "a retired credential must not enqueue even when the channel has capacity"
    );
}

fn mesh_runtime_env_config() -> ferrum_edge::config::EnvConfig {
    ferrum_edge::config::EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        dp_cp_grpc_urls: vec!["http://127.0.0.1:1".to_string()],
        ..Default::default()
    }
}

#[test]
fn mesh_runtime_config_rejects_malformed_stock_xds_allow_plaintext() {
    use ferrum_edge::modes::mesh::MeshRuntimeConfig;

    use crate::unit::env_lock::EnvGuard;

    let env = EnvGuard::new(&["FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT"]);
    env.set("FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT", "tru");

    let err = MeshRuntimeConfig::from_env_config(&mesh_runtime_env_config())
        .expect_err("malformed explicit bool must fail closed");
    assert!(err.contains("FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT"));
    assert!(err.contains("true, false, 1, or 0"));
}

#[test]
fn mesh_runtime_config_parses_stock_xds_allow_plaintext_canonical_forms() {
    use ferrum_edge::modes::mesh::MeshRuntimeConfig;

    use crate::unit::env_lock::EnvGuard;

    let cases = [
        (None, false),
        (Some("   "), false),
        (Some("false"), false),
        (Some("0"), false),
        (Some("TRUE"), true),
        (Some("1"), true),
    ];

    for (value, expected) in cases {
        let env = EnvGuard::new(&["FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT"]);
        match value {
            Some(raw) => env.set("FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT", raw),
            None => env.unset("FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT"),
        }

        let runtime = MeshRuntimeConfig::from_env_config(&mesh_runtime_env_config())
            .unwrap_or_else(|err| panic!("canonical form {:?} must parse: {err}", value));
        assert_eq!(
            runtime.stock_xds_allow_plaintext, expected,
            "value {:?}",
            value
        );
    }
}

/// Issue #7237: `FERRUM_MESH_DNS_PROXY_ENABLED` used to treat anything other
/// than `true`/`1` as `false`, so `yes` silently disabled the DNS proxy. It now
/// parses like every sibling mesh bool.
#[test]
fn mesh_runtime_config_rejects_malformed_dns_proxy_enabled() {
    use ferrum_edge::modes::mesh::MeshRuntimeConfig;

    use crate::unit::env_lock::EnvGuard;

    for raw in ["yes", "on", "tru"] {
        let env = EnvGuard::new(&["FERRUM_MESH_DNS_PROXY_ENABLED"]);
        env.set("FERRUM_MESH_DNS_PROXY_ENABLED", raw);

        let err = MeshRuntimeConfig::from_env_config(&mesh_runtime_env_config())
            .expect_err("malformed explicit bool must fail startup");
        assert!(err.contains("FERRUM_MESH_DNS_PROXY_ENABLED"), "{err}");
        assert!(err.contains("true, false, 1, or 0"), "{err}");
    }
}

#[test]
fn mesh_runtime_config_parses_dns_proxy_enabled_canonical_forms() {
    use ferrum_edge::modes::mesh::MeshRuntimeConfig;

    use crate::unit::env_lock::EnvGuard;

    let cases = [
        (None, false),
        (Some("   "), false),
        (Some("false"), false),
        (Some("0"), false),
        (Some("TRUE"), true),
        (Some(" True "), true),
        (Some("1"), true),
    ];

    for (value, expected) in cases {
        let env = EnvGuard::new(&["FERRUM_MESH_DNS_PROXY_ENABLED"]);
        match value {
            Some(raw) => env.set("FERRUM_MESH_DNS_PROXY_ENABLED", raw),
            None => env.unset("FERRUM_MESH_DNS_PROXY_ENABLED"),
        }

        let runtime = MeshRuntimeConfig::from_env_config(&mesh_runtime_env_config())
            .unwrap_or_else(|err| panic!("canonical form {:?} must parse: {err}", value));
        assert_eq!(runtime.dns_enabled, expected, "value {:?}", value);
    }
}

/// Issue #4531. A CP that answers `RESOURCE_EXHAUSTED` is demonstrably alive:
/// its stream admission controller refused this workload for capacity or
/// tenancy reasons and named the saturated budget in the status message.
/// Collapsing that into `transport_failure` would tell an operator their
/// control plane is unreachable and discard the only actionable detail, so the
/// refusal is its own closed-set outcome — and, because it is not an
/// established stream going dark, it is not a liveness failure either.
#[test]
fn admission_refusal_is_its_own_outcome_and_not_a_liveness_failure() {
    let refused = MeshStreamAttempt::AdmissionRefused;
    assert_eq!(refused.as_metric_label(), "admission_refused");
    assert_ne!(
        refused.as_metric_label(),
        transport_failure(false, false).as_metric_label()
    );
    assert_ne!(
        refused.as_metric_label(),
        MeshStreamAttempt::PolicyRejected.as_metric_label()
    );
    assert!(!refused.is_liveness_failure());
    assert!(refused.is_endpoint_failure());

    // Rotate-and-retry, matching a no-progress transport failure: another CP
    // replica may still have capacity, and a saturated one must not be hammered
    // by the whole refused fleet at the initial delay.
    let disposition = refused.disposition();
    assert_eq!(disposition, transport_failure(false, false).disposition());
    assert!(disposition.advance_endpoint);
    assert!(disposition.increase_backoff);
}
