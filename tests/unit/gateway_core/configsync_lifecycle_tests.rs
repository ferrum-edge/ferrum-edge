//! External unit tests for DP ConfigSync lifecycle policy helpers.
//!
//! Covers silent-partition/keepalive constants, multi-CP backoff continuity,
//! FULL_SNAPSHOT fencing (including complete-payload trust equivalence for the
//! older-cross-source identical-fallback exception, with Unknown trust remaining
//! non-comparable until an explicit Clear/Replace), monotonic watermarks,
//! version/`loaded_at` reconcile, subscription base gating, SemVer negotiation,
//! delta-rejection divergence, connection-state staleness preservation, and
//! namespace-qualified removal filtering surfaces exposed for deterministic
//! verification without standing up a live CP.

use chrono::{TimeZone, Utc};
use ferrum_edge::FERRUM_VERSION;
use ferrum_edge::config::db_loader::{IncrementalResult, NamespacedResourceId};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::configsync_lifecycle::{
    AppliedSnapshotAuthority, CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS,
    CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, CONFIGSYNC_MAX_FUTURE_SKEW_SECS,
    CONFIGSYNC_MAX_SILENCE_SECS, CONFIGSYNC_TCP_KEEPALIVE_SECS, ConfigSyncAttemptOutcome,
    ConfigSyncDivergenceMetrics, DeltaRefuse, DeltaRejectionKind, DeltaRejectionStreamDisposition,
    FullSnapshotStreamDisposition, GatewayTrustEquivalenceState, MultiCpBackoffState,
    SnapshotFailureStreamDisposition, StaleSnapshotReject, SubscriptionApplyState,
    VersionCompatError, VersionReconcileError, advance_authority_from_committed,
    advance_multi_cp_backoff, authoritative_snapshot_payload_matches, backoff_max_secs,
    check_peer_version_compatibility, connection_error_outcome, cp_endpoints_same_source,
    delta_rejection_stream_disposition, evaluate_delta_against_subscription_base,
    evaluate_full_snapshot_authority, evaluate_snapshot_clock_skew, failure_backoff_sequence,
    full_snapshot_stream_disposition, gateway_config_content_matches,
    gateway_trust_equivalence_state, grow_backoff_after_failure_sleep, heartbeat_frame_admissible,
    monotonic_watermark, reconcile_snapshot_version, record_applied_gateway_trust,
    resolve_authority_trust_after_snapshot, resource_delta_advances_authority,
    silence_exceeds_liveness, silence_watchdog_armed, snapshot_failure_stream_disposition,
    snapshot_requires_older_payload_exception, stale_reject_from_reconcile,
};
use ferrum_edge::grpc::dp_client::{
    DpCpConnectionState, check_cp_version_compatibility, configure_configsync_endpoint,
    filter_incremental_to_namespace,
};
use ferrum_edge::identity::{TrustBundle, TrustBundleSet as RuntimeTrustBundleSet, TrustDomain};
use ferrum_edge::util::backoff::BACKOFF_INITIAL_SECS;
use tonic::transport::Channel;

#[test]
fn configsync_keepalive_constants_are_bounded_and_ordered() {
    assert_eq!(CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS, 30);
    assert_eq!(CONFIGSYNC_HTTP2_KEEPALIVE_TIMEOUT_SECS, 10);
    assert_eq!(CONFIGSYNC_TCP_KEEPALIVE_SECS, 30);
    const {
        assert!(CONFIGSYNC_MAX_SILENCE_SECS > CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS);
        assert!(
            CONFIGSYNC_MAX_SILENCE_SECS
                > ferrum_edge::grpc::configsync_lifecycle::CONFIGSYNC_HEARTBEAT_INTERVAL_SECS
        );
    }
    assert!(!silence_exceeds_liveness(CONFIGSYNC_MAX_SILENCE_SECS - 1));
    assert!(silence_exceeds_liveness(CONFIGSYNC_MAX_SILENCE_SECS));
}

#[test]
fn configsync_endpoint_builder_applies_keepalive() {
    let endpoint = configure_configsync_endpoint(
        Channel::from_shared("http://127.0.0.1:50051".to_string()).expect("uri"),
    );
    // Endpoint does not expose getters; constructing with keepalive settings
    // without error is the compile/runtime contract. Re-configure to prove the
    // helper is callable and returns an Endpoint.
    let _ = endpoint.connect_timeout(std::time::Duration::from_secs(10));
}

#[test]
fn multi_cp_failure_backoff_reaches_max_without_resetting_on_switch() {
    let sleeps = failure_backoff_sequence(2, 12);
    assert_eq!(sleeps.first().copied(), Some(BACKOFF_INITIAL_SECS));
    assert!(
        sleeps.iter().any(|s| *s == backoff_max_secs()),
        "expected multi-CP failure sequence to reach {backoff}, got {sleeps:?}",
        backoff = backoff_max_secs()
    );
    // Switching CP must not reset: sequence is strictly non-decreasing until cap.
    for window in sleeps.windows(2) {
        assert!(window[1] >= window[0]);
    }
}

#[test]
fn zero_message_clean_close_grows_backoff_like_error() {
    let mut state = MultiCpBackoffState::new();
    assert!(advance_multi_cp_backoff(
        &mut state,
        1,
        ConfigSyncAttemptOutcome::CleanCloseWithoutConfig
    ));
    assert_eq!(state.backoff_secs, BACKOFF_INITIAL_SECS);
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 2);

    let mut ok = MultiCpBackoffState {
        backoff_secs: 16,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(
        &mut ok,
        1,
        ConfigSyncAttemptOutcome::CleanCloseAfterConfig
    ));
    assert_eq!(ok.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn connection_error_after_accepted_config_resets_backoff() {
    // Issue #2968 / root review: a transport failure after the attempt already
    // delivered accepted config counts as healthy progress for backoff.
    assert_eq!(
        connection_error_outcome(false),
        ConfigSyncAttemptOutcome::ConnectionError
    );
    assert_eq!(
        connection_error_outcome(true),
        ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
    );

    let mut before = MultiCpBackoffState {
        backoff_secs: 16,
        current_cp_index: 0,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut before,
        2,
        ConfigSyncAttemptOutcome::ConnectionError
    ));
    assert_eq!(before.current_cp_index, 1);
    assert_eq!(before.backoff_secs, 16);
    grow_backoff_after_failure_sleep(&mut before);
    assert_eq!(before.backoff_secs, backoff_max_secs());

    let mut after = MultiCpBackoffState {
        backoff_secs: 16,
        current_cp_index: 0,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut after,
        2,
        ConfigSyncAttemptOutcome::ConnectionErrorAfterConfig
    ));
    assert_eq!(
        after.current_cp_index, 0,
        "post-config transport failure must not fail over CP index"
    );
    assert_eq!(after.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn reconcile_snapshot_version_requires_envelope_loaded_at_parity() {
    let loaded_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    assert_eq!(
        reconcile_snapshot_version(&loaded_at.to_rfc3339(), loaded_at).unwrap(),
        loaded_at
    );
    assert!(matches!(
        reconcile_snapshot_version("garbage", loaded_at),
        Err(VersionReconcileError::UnparseableEnvelope)
    ));
    let other = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    assert!(matches!(
        reconcile_snapshot_version(&other.to_rfc3339(), loaded_at),
        Err(VersionReconcileError::Inconsistent { .. })
    ));
    assert!(matches!(
        stale_reject_from_reconcile(VersionReconcileError::UnparseableEnvelope),
        StaleSnapshotReject::UnparseableVersion
    ));
}

#[test]
fn full_snapshot_fencing_rejects_older_cross_source() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();

    let rejected = evaluate_full_snapshot_authority(
        Some(&authority),
        older,
        "http://cp-fallback:50051",
        false,
    );
    assert!(matches!(
        rejected,
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));

    // Same-source recovery remains accepted, but the watermark stays monotonic
    // at the newest known ordering (does not drop to the older recovery body).
    let same_source =
        evaluate_full_snapshot_authority(Some(&authority), older, "http://cp-primary:50051", false)
            .expect("same-source recovery snapshots remain accepted");
    assert_eq!(same_source, applied);

    let newer = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    let accepted = evaluate_full_snapshot_authority(
        Some(&authority),
        newer,
        "http://cp-fallback:50051",
        false,
    )
    .expect("newer failover snapshot is accepted");
    assert_eq!(accepted, newer);
}

#[test]
fn same_source_recovery_watermark_is_monotonic() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-a:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let newer = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();

    assert_eq!(
        evaluate_full_snapshot_authority(Some(&authority), older, "http://cp-a:50051", false,)
            .unwrap(),
        applied
    );
    assert_eq!(
        evaluate_full_snapshot_authority(Some(&authority), newer, "http://cp-a:50051", false,)
            .unwrap(),
        newer
    );
    assert_eq!(monotonic_watermark(Some(applied), older), applied);
    assert_eq!(monotonic_watermark(None, older), older);
}

#[test]
fn fenced_full_snapshot_disposition_terminates_stream() {
    // Issue #2970: a fenced cross-source snapshot must map to a stream-terminating
    // refusal, NOT a skippable message. If it were skippable, the DP would keep
    // reading from the stale fallback CP and apply its next delta against newer
    // config. This asserts the terminate contract at the pure decision seam the
    // stream loop actually calls.
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };

    match full_snapshot_stream_disposition(
        Some(&authority),
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap(),
        "http://cp-fallback:50051",
        false,
    ) {
        FullSnapshotStreamDisposition::RefuseAndTerminate(
            StaleSnapshotReject::OlderThanApplied {
                applied: fenced_applied,
                incoming,
            },
        ) => {
            assert_eq!(fenced_applied, applied);
            assert_eq!(
                incoming,
                Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
            );
        }
        other => panic!("older cross-source snapshot must terminate the stream, got {other:?}"),
    }
}

#[test]
fn accepted_full_snapshot_disposition_applies_and_adopts_version() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };

    // A newer cross-source failover snapshot applies and adopts its version.
    assert_eq!(
        full_snapshot_stream_disposition(
            Some(&authority),
            Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            "http://cp-fallback:50051",
            false,
        ),
        FullSnapshotStreamDisposition::Apply {
            version: Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
        }
    );

    // A same-source recovery snapshot always applies, even when older, but the
    // watermark remains at the prior high-water mark.
    assert_eq!(
        full_snapshot_stream_disposition(
            Some(&authority),
            Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap(),
            "http://cp-primary:50051",
            false,
        ),
        FullSnapshotStreamDisposition::Apply { version: applied }
    );

    // The first snapshot (no applied authority yet) applies and adopts its
    // committed stamp.
    let first = Utc.with_ymd_and_hms(2026, 7, 20, 0, 0, 0).unwrap();
    assert_eq!(
        full_snapshot_stream_disposition(None, first, "http://cp-a:50051", false),
        FullSnapshotStreamDisposition::Apply { version: first }
    );
}

#[test]
fn equivalent_older_cross_source_snapshot_establishes_safe_base() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    let mut current = GatewayConfig {
        loaded_at: applied,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    assert!(gateway_config_content_matches(&current, &incoming));
    assert!(authoritative_snapshot_payload_matches(
        &current,
        &GatewayTrustEquivalenceState::Absent,
        &incoming,
        Some(&GatewayTrustEquivalenceState::Absent),
    ));
    assert_eq!(
        evaluate_full_snapshot_authority(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            true,
        )
        .expect("equivalent older failover snapshot establishes a safe delta base"),
        applied
    );

    current.version = "different-content".to_string();
    assert!(!gateway_config_content_matches(&current, &incoming));
    assert!(!authoritative_snapshot_payload_matches(
        &current,
        &GatewayTrustEquivalenceState::Absent,
        &incoming,
        Some(&GatewayTrustEquivalenceState::Absent),
    ));
    assert!(matches!(
        evaluate_full_snapshot_authority(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            false,
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));
}

fn test_runtime_trust(domain: &str, ders: &[&[u8]]) -> RuntimeTrustBundleSet {
    RuntimeTrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new(domain).expect("test trust domain"),
            x509_authorities: ders.iter().map(|der| der.to_vec()).collect(),
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Default::default(),
    }
}

#[test]
fn older_cross_source_same_config_different_trust_is_fenced() {
    // Security: GatewayConfig-only equality must NOT bypass fencing when the
    // CP trust side channel differs (or clear-vs-present). Otherwise an older
    // fallback snapshot would apply stale trust anchors.
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let current_trust = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[1, 2, 3, 4]],
    )));
    let stale_trust = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[9, 9, 9, 9]],
    )));
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: current_trust.clone(),
    };
    let current = GatewayConfig {
        loaded_at: applied,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    assert!(gateway_config_content_matches(&current, &incoming));
    assert!(
        !authoritative_snapshot_payload_matches(
            &current,
            &current_trust,
            &incoming,
            Some(&stale_trust),
        ),
        "different trust material must not match"
    );
    assert!(
        !authoritative_snapshot_payload_matches(
            &current,
            &current_trust,
            &incoming,
            Some(&GatewayTrustEquivalenceState::Absent),
        ),
        "clear-vs-present trust must not match"
    );
    assert!(
        !authoritative_snapshot_payload_matches(&current, &current_trust, &incoming, None),
        "unknown/unparseable trust side channel must fail closed"
    );

    assert!(matches!(
        evaluate_full_snapshot_authority(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            false,
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));
    assert_eq!(
        full_snapshot_stream_disposition(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            false,
        ),
        FullSnapshotStreamDisposition::RefuseAndTerminate(StaleSnapshotReject::OlderThanApplied {
            applied,
            incoming: older,
        })
    );
}

#[test]
fn older_cross_source_same_config_equivalent_trust_establishes_safe_base() {
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let trust_a = test_runtime_trust("cluster.local", &[&[1, 2, 3, 4], &[5, 6, 7, 8]]);
    // Same material with reordered x509 authorities must still fingerprint equal.
    let trust_b = test_runtime_trust("cluster.local", &[&[5, 6, 7, 8], &[1, 2, 3, 4]]);
    let current_trust = gateway_trust_equivalence_state(Some(&trust_a));
    let incoming_trust = gateway_trust_equivalence_state(Some(&trust_b));
    assert_eq!(current_trust, incoming_trust);

    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: current_trust.clone(),
    };
    let current = GatewayConfig {
        loaded_at: applied,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    assert!(authoritative_snapshot_payload_matches(
        &current,
        &current_trust,
        &incoming,
        Some(&incoming_trust),
    ));
    assert_eq!(
        evaluate_full_snapshot_authority(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            true,
        )
        .expect("complete equivalent payload establishes a safe delta base"),
        applied
    );
}

#[test]
fn trust_only_update_keeps_authority_trust_equivalence_in_sync() {
    let t0 = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let initial_trust = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[1, 2, 3, 4]],
    )));
    let rotated_trust = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[5, 6, 7, 8]],
    )));

    let mut authority = Some(AppliedSnapshotAuthority {
        version: Some(t0),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: initial_trust.clone(),
    });

    // Accepted trust-only Replace keeps the watermark but refreshes trust view.
    record_applied_gateway_trust(&mut authority, rotated_trust.clone());
    assert_eq!(authority.as_ref().unwrap().version, Some(t0));
    assert_eq!(authority.as_ref().unwrap().gateway_trust, rotated_trust);

    let current = GatewayConfig {
        loaded_at: t0,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    // Stale snapshot carrying the pre-rotation trust must not match after the
    // trust-only update synchronized authority equivalence state.
    assert!(!authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&initial_trust),
    ));
    assert!(matches!(
        evaluate_full_snapshot_authority(
            authority.as_ref(),
            older,
            "http://cp-fallback:50051",
            false,
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));

    // Equivalent complete trust after rotation still establishes the safe base.
    assert!(authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&rotated_trust),
    ));

    // Clear also stays in sync.
    record_applied_gateway_trust(&mut authority, GatewayTrustEquivalenceState::Absent);
    assert_eq!(
        authority.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Absent
    );
    assert!(authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&GatewayTrustEquivalenceState::Absent),
    ));
}

#[test]
fn accepted_resource_delta_advances_authority_trust_only_and_reject_do_not() {
    let t0 = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let t1 = Utc.with_ymd_and_hms(2026, 7, 1, 13, 0, 0).unwrap();
    let mut authority = Some(AppliedSnapshotAuthority {
        version: Some(t0),
        source_cp_url: "http://cp-a:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Unknown,
    });

    assert!(resource_delta_advances_authority(true, false));
    assert!(!resource_delta_advances_authority(true, true));
    assert!(!resource_delta_advances_authority(false, false));

    advance_authority_from_committed(&mut authority, "http://cp-a:50051", t1);
    assert_eq!(authority.as_ref().unwrap().version, Some(t1));
    assert_eq!(
        authority.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Unknown,
        "resource-delta watermark advances must preserve Unknown trust state"
    );

    // A later older stamp must not lower the watermark.
    advance_authority_from_committed(&mut authority, "http://cp-a:50051", t0);
    assert_eq!(authority.as_ref().unwrap().version, Some(t1));
    assert_eq!(
        authority.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Unknown
    );

    // Creating authority from a resource commit alone must not invent Absent.
    let mut fresh = None;
    advance_authority_from_committed(&mut fresh, "http://cp-b:50051", t0);
    assert_eq!(
        fresh.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Unknown,
        "resource-delta-only authority construction must leave trust Unknown"
    );
}

#[test]
fn unchanged_full_snapshot_authority_trust_stays_unknown_not_absent() {
    // Root follow-up: an empty/Unchanged trust side channel must not record
    // Absent. Absent is established only by an accepted explicit Clear.
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();

    let gateway_trust = resolve_authority_trust_after_snapshot(None, None);
    assert_eq!(gateway_trust, GatewayTrustEquivalenceState::Unknown);
    assert!(!gateway_trust.is_comparable());

    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-primary:50051".to_string(),
        gateway_trust: gateway_trust.clone(),
    };
    let current = GatewayConfig {
        loaded_at: applied,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    // Unknown authority must not treat an older explicit Clear as equivalent.
    assert!(
        !authoritative_snapshot_payload_matches(
            &current,
            &authority.gateway_trust,
            &incoming,
            Some(&GatewayTrustEquivalenceState::Absent),
        ),
        "Unknown authority must not match explicit Clear"
    );
    // Unknown authority must not treat an older explicit Replace as equivalent.
    let replace_trust = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[1, 2, 3, 4]],
    )));
    assert!(
        !authoritative_snapshot_payload_matches(
            &current,
            &authority.gateway_trust,
            &incoming,
            Some(&replace_trust),
        ),
        "Unknown authority must not match explicit Replace"
    );
    // Unknown vs Unknown is also non-comparable.
    assert!(
        !authoritative_snapshot_payload_matches(
            &current,
            &GatewayTrustEquivalenceState::Unknown,
            &incoming,
            Some(&GatewayTrustEquivalenceState::Unknown),
        ),
        "Unknown vs Unknown must fail closed"
    );
    assert!(matches!(
        evaluate_full_snapshot_authority(
            Some(&authority),
            older,
            "http://cp-fallback:50051",
            false,
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));

    // A later Unchanged snapshot preserves Unknown rather than inventing Absent.
    let preserved = resolve_authority_trust_after_snapshot(Some(&authority), None);
    assert_eq!(preserved, GatewayTrustEquivalenceState::Unknown);
}

#[test]
fn trust_only_clear_or_replace_establishes_comparability_from_unknown() {
    let t0 = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let older = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let mut authority = Some(AppliedSnapshotAuthority {
        version: Some(t0),
        source_cp_url: "http://cp-primary:50051".to_string(),
        // First Unchanged full snapshot left trust unestablished.
        gateway_trust: resolve_authority_trust_after_snapshot(None, None),
    });
    assert_eq!(
        authority.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Unknown
    );

    let current = GatewayConfig {
        loaded_at: t0,
        ..GatewayConfig::default()
    };
    let incoming = GatewayConfig {
        loaded_at: older,
        ..current.clone()
    };

    // Accepted trust-only Clear establishes Absent and enables the safe base.
    record_applied_gateway_trust(&mut authority, GatewayTrustEquivalenceState::Absent);
    assert_eq!(
        authority.as_ref().unwrap().gateway_trust,
        GatewayTrustEquivalenceState::Absent
    );
    assert!(authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&GatewayTrustEquivalenceState::Absent),
    ));
    assert_eq!(
        evaluate_full_snapshot_authority(
            authority.as_ref(),
            older,
            "http://cp-fallback:50051",
            true,
        )
        .expect("explicit Clear establishes comparable Absent for identical fallback"),
        t0
    );

    // Accepted trust-only Replace establishes Present and enables the safe base.
    let present = gateway_trust_equivalence_state(Some(&test_runtime_trust(
        "cluster.local",
        &[&[5, 6, 7, 8]],
    )));
    record_applied_gateway_trust(&mut authority, present.clone());
    assert!(authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&present),
    ));
    assert!(!authoritative_snapshot_payload_matches(
        &current,
        &authority.as_ref().unwrap().gateway_trust,
        &incoming,
        Some(&GatewayTrustEquivalenceState::Absent),
    ));
}

#[test]
fn delta_after_resource_advances_fences_older_cross_source_snapshot() {
    // Blocker 1: accepted resource deltas move the active config ahead; the
    // watermark must follow so a later cross-source snapshot between those
    // versions is refused rather than rolling config back.
    let snapshot = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let after_delta = Utc.with_ymd_and_hms(2026, 7, 1, 14, 0, 0).unwrap();
    let stale_failover = Utc.with_ymd_and_hms(2026, 7, 1, 13, 0, 0).unwrap();

    let mut authority = None;
    advance_authority_from_committed(&mut authority, "http://cp-primary:50051", snapshot);
    advance_authority_from_committed(&mut authority, "http://cp-primary:50051", after_delta);

    assert!(matches!(
        evaluate_full_snapshot_authority(
            authority.as_ref(),
            stale_failover,
            "http://cp-fallback:50051",
            false,
        ),
        Err(StaleSnapshotReject::OlderThanApplied { .. })
    ));
}

#[test]
fn subscription_requires_valid_snapshot_base_before_delta() {
    assert_eq!(
        evaluate_delta_against_subscription_base(false),
        Err(DeltaRefuse::BeforeSnapshotBase)
    );
    assert!(evaluate_delta_against_subscription_base(true).is_ok());

    // Unusable FULL_SNAPSHOT always terminates — including after a prior base.
    assert_eq!(
        snapshot_failure_stream_disposition(false),
        SnapshotFailureStreamDisposition::TerminateAndReconnect
    );
    assert_eq!(
        snapshot_failure_stream_disposition(true),
        SnapshotFailureStreamDisposition::TerminateAndReconnect
    );
}

#[test]
fn no_startup_flag_still_requires_full_snapshot_before_delta() {
    // Root review: `startup_ready = None` must not initialize the subscription
    // base as already applied. Library/test callers skip startup-only work, but
    // every new subscription still starts without a committed FULL_SNAPSHOT.
    let mut subscription = SubscriptionApplyState::new();
    assert!(
        !subscription.base_applied,
        "new subscriptions must start without a base even when startup_ready is absent"
    );
    assert_eq!(
        evaluate_delta_against_subscription_base(subscription.base_applied),
        Err(DeltaRefuse::BeforeSnapshotBase)
    );
    subscription.note_full_snapshot_accepted();
    assert!(subscription.base_applied);
    assert!(evaluate_delta_against_subscription_base(subscription.base_applied).is_ok());
}

#[test]
fn mid_stream_unusable_snapshot_and_delta_rejection_force_resync() {
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::ParseFailure),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::InvalidTrustSideChannel),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );
    assert_eq!(
        delta_rejection_stream_disposition(DeltaRejectionKind::NonEmptyApplyRejected),
        DeltaRejectionStreamDisposition::TerminateAndResync
    );

    let mut state = MultiCpBackoffState {
        backoff_secs: 8,
        current_cp_index: 1,
        full_cycle_count: 0,
    };
    assert!(advance_multi_cp_backoff(
        &mut state,
        2,
        ConfigSyncAttemptOutcome::ResyncAfterAcceptedConfig
    ));
    assert_eq!(state.current_cp_index, 1, "resync retries the same CP");
    assert_eq!(state.backoff_secs, BACKOFF_INITIAL_SECS);
}

#[test]
fn rejected_delta_marks_divergence_until_full_snapshot_recovery() {
    // Issue #2394: rejection terminates before a later delta can apply; sticky
    // divergence clears only after an authoritative FULL_SNAPSHOT recovery.
    let metrics = ConfigSyncDivergenceMetrics::default();
    assert!(!metrics.is_diverged());
    metrics.record_rejection();
    assert!(metrics.is_diverged());
    let snap = metrics.snapshot();
    assert_eq!(snap.rejected_nonempty_deltas_total, 1);
    assert_eq!(snap.recoveries_total, 0);

    // A second rejection before recovery keeps the sticky flag and increments.
    metrics.record_rejection();
    assert!(metrics.is_diverged());
    assert_eq!(metrics.snapshot().rejected_nonempty_deltas_total, 2);

    assert!(metrics.record_recovery_after_full_snapshot());
    assert!(!metrics.is_diverged());
    assert_eq!(metrics.snapshot().recoveries_total, 1);
    // Idempotent clear when already converged.
    assert!(!metrics.record_recovery_after_full_snapshot());
    assert_eq!(metrics.snapshot().recoveries_total, 1);
}

#[test]
fn semver_version_negotiation_rejects_empty_malformed_and_incompatible() {
    // Issue #2395: fail closed on missing/malformed; allow patch/prerelease.
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, ""),
        Err(VersionCompatError::Missing)
    ));
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, "1"),
        Err(VersionCompatError::Malformed { .. })
    ));
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, "garbage"),
        Err(VersionCompatError::Malformed { .. })
    ));
    assert!(check_peer_version_compatibility(FERRUM_VERSION, FERRUM_VERSION).is_ok());

    let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
    assert!(parts.len() >= 2);
    let patch_ok = format!("{}.{}.99", parts[0], parts[1]);
    assert!(check_peer_version_compatibility(FERRUM_VERSION, &patch_ok).is_ok());
    let prerelease_ok = format!("{}.{}.0-rc.1", parts[0], parts[1]);
    assert!(check_peer_version_compatibility(FERRUM_VERSION, &prerelease_ok).is_ok());
    let minor_bad = format!(
        "{}.{}.0",
        parts[0],
        parts[1].parse::<u64>().unwrap_or(0) + 1
    );
    assert!(matches!(
        check_peer_version_compatibility(FERRUM_VERSION, &minor_bad),
        Err(VersionCompatError::Incompatible { .. })
    ));

    // DP helper surfaces the same policy.
    assert!(check_cp_version_compatibility("").is_err());
    assert!(check_cp_version_compatibility("1").is_err());
    assert!(check_cp_version_compatibility("garbage").is_err());
    assert!(check_cp_version_compatibility(FERRUM_VERSION).is_ok());
    assert!(check_cp_version_compatibility(&patch_ok).is_ok());
    assert!(check_cp_version_compatibility(&minor_bad).is_err());
}

#[test]
fn stale_snapshot_fenced_outcome_fails_over_without_resetting_backoff() {
    // A fenced snapshot must account like a connection failure: advance to the
    // next CP, keep sleeping, and NEVER reset backoff (a stale fallback CP is
    // not healthy progress). Contrast CleanCloseAfterConfig, which does reset.
    let fenced = ConfigSyncAttemptOutcome::StaleSnapshotFenced;
    let mut state = MultiCpBackoffState {
        backoff_secs: 8,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(&mut state, 2, fenced));
    assert_eq!(
        state.current_cp_index, 1,
        "fencing must fail over to the next CP"
    );
    assert_eq!(state.backoff_secs, 8, "fencing must not reset backoff");
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(
        state.backoff_secs, 16,
        "backoff must keep growing after a fence"
    );
}

#[test]
fn invalid_subscription_base_outcome_fails_over_with_backoff() {
    let mut state = MultiCpBackoffState {
        backoff_secs: 4,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(
        &mut state,
        2,
        ConfigSyncAttemptOutcome::InvalidSubscriptionBase
    ));
    assert_eq!(state.current_cp_index, 1);
    assert_eq!(state.backoff_secs, 4);
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 8);
}

#[test]
fn invalid_delta_freshness_outcome_fails_over_with_backoff() {
    let mut state = MultiCpBackoffState {
        backoff_secs: 4,
        ..MultiCpBackoffState::new()
    };
    assert!(advance_multi_cp_backoff(
        &mut state,
        2,
        ConfigSyncAttemptOutcome::InvalidDeltaFreshness
    ));
    assert_eq!(state.current_cp_index, 1);
    assert_eq!(state.backoff_secs, 4);
    grow_backoff_after_failure_sleep(&mut state);
    assert_eq!(state.backoff_secs, 8);
}

#[test]
fn repeated_fencing_reaches_backoff_cap_and_cycles_cps() {
    // A permanently stale fallback that keeps getting fenced must not busy-loop:
    // backoff still climbs to the cap and the DP still cycles across CP URLs.
    let fenced = ConfigSyncAttemptOutcome::StaleSnapshotFenced;
    let mut state = MultiCpBackoffState::new();
    let mut reached_cap = false;
    let mut cycled = false;
    for _ in 0..24 {
        assert!(advance_multi_cp_backoff(&mut state, 2, fenced));
        if state.full_cycle_count > 0 {
            cycled = true;
        }
        grow_backoff_after_failure_sleep(&mut state);
        if state.backoff_secs == backoff_max_secs() {
            reached_cap = true;
        }
    }
    assert!(
        reached_cap,
        "repeated fencing must still reach the backoff cap"
    );
    assert!(
        cycled,
        "repeated fencing across 2 CPs must cycle back to primary"
    );
}

#[test]
fn unknown_prior_authority_still_accepts_cross_source() {
    // An authority recorded without a comparable timestamp cannot fence; a
    // real failover snapshot is accepted and its committed stamp adopted.
    let authority = AppliedSnapshotAuthority {
        version: None,
        source_cp_url: "http://cp-a:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    let newer = Utc.with_ymd_and_hms(2026, 7, 20, 0, 0, 0).unwrap();
    let accepted =
        evaluate_full_snapshot_authority(Some(&authority), newer, "http://cp-b:50051", false)
            .expect("a real failover snapshot must not be fenced by an unknown authority");
    assert_eq!(accepted, newer);
}

#[test]
fn reconnect_preserves_last_config_received_at_and_divergence() {
    // Exercises the production reconnect copy (`DpCpConnectionState::reconnected`)
    // instead of mirroring the field-carry logic in the test. A reconnect
    // (including CP failover) preserves applied-config age and sticky divergence
    // while marking the new stream connected to the new target.
    let stamp = Utc.with_ymd_and_hms(2026, 7, 24, 1, 2, 3).unwrap();
    let diverged_since = Utc.with_ymd_and_hms(2026, 7, 24, 1, 0, 0).unwrap();
    let connected_since = Utc.with_ymd_and_hms(2026, 7, 24, 2, 0, 0).unwrap();
    let prev = DpCpConnectionState {
        connected: false,
        cp_url: "http://cp-old:50051".to_string(),
        is_primary: true,
        last_config_received_at: Some(stamp),
        connected_since: None,
        config_diverged: true,
        config_diverged_since: Some(diverged_since),
        config_divergence_recoveries_total: 2,
    };

    let connected = prev.reconnected("http://cp-new:50051", false, connected_since);

    // Marked connected to the new (fallback) target.
    assert!(connected.connected);
    assert_eq!(connected.cp_url, "http://cp-new:50051");
    assert!(!connected.is_primary);
    assert_eq!(connected.connected_since, Some(connected_since));
    // Preserved across the reconnect — never reset by a mere transport reconnect.
    assert_eq!(connected.last_config_received_at, Some(stamp));
    assert!(connected.config_diverged);
    assert_eq!(connected.config_diverged_since, Some(diverged_since));
    assert_eq!(connected.config_divergence_recoveries_total, 2);
}

#[test]
fn namespace_qualified_removals_are_fail_closed_on_mismatch() {
    // Exercises the production defense-in-depth filter
    // (`dp_client::filter_incremental_to_namespace`) directly instead of
    // reimplementing the retain logic. A delta carrying same-id removals across
    // namespaces must keep only the DP's own namespace keys.
    let mut delta = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![
            NamespacedResourceId::new("production", "shared-id"),
            NamespacedResourceId::new("staging", "shared-id"),
        ],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![NamespacedResourceId::new("staging", "pc1")],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new("production", "u1")],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };

    let filtered = filter_incremental_to_namespace(&mut delta, "production");

    // Two staging removal keys (proxy `shared-id`, plugin_config `pc1`) dropped.
    assert_eq!(filtered, 2);
    assert_eq!(
        delta.removed_proxy_ids,
        vec![NamespacedResourceId::new("production", "shared-id")]
    );
    assert!(delta.removed_plugin_config_ids.is_empty());
    assert_eq!(
        delta.removed_upstream_ids,
        vec![NamespacedResourceId::new("production", "u1")]
    );
}

#[test]
fn future_skew_tolerance_is_bounded_and_positive() {
    // 300s (5 minutes) — the established Kerberos/JWT NTP-drift leeway. Generous
    // enough that realistic DP↔CP clock differences never false-reject a
    // legitimate snapshot, tight enough that watermark poisoning is bounded.
    assert_eq!(CONFIGSYNC_MAX_FUTURE_SKEW_SECS, 300);
    // Positivity is asserted behaviorally rather than as `assert!(CONST > 0)`,
    // which trips `clippy::assertions_on_constants` under `-D warnings`. A stamp
    // one second ahead of `now` is admitted only when the tolerance is strictly
    // positive, so this pins the same contract through the guard itself.
    let now = Utc.with_ymd_and_hms(2026, 7, 24, 12, 0, 0).unwrap();
    assert!(evaluate_snapshot_clock_skew(now + chrono::Duration::seconds(1), now).is_ok());
}

#[test]
fn clock_skew_guard_refuses_implausibly_future_committed_stamp() {
    // Issue M1: a CP-clock-stamped committed timestamp far in the DP's future
    // would poison the monotonic freshness watermark. Admit stamps at/behind now
    // and within tolerance; fail closed (never clamp) beyond tolerance.
    let now = Utc.with_ymd_and_hms(2026, 7, 24, 12, 0, 0).unwrap();

    assert!(evaluate_snapshot_clock_skew(now, now).is_ok());
    let past = now - chrono::Duration::seconds(10_000);
    assert!(evaluate_snapshot_clock_skew(past, now).is_ok());

    // Exactly at the tolerance boundary is still admitted (realistic NTP drift).
    let within = now + chrono::Duration::seconds(CONFIGSYNC_MAX_FUTURE_SKEW_SECS);
    assert!(evaluate_snapshot_clock_skew(within, now).is_ok());

    // One second beyond tolerance is refused, and the reject carries the exact
    // untrusted stamp / reference time / tolerance — never a clamped value.
    let beyond = now + chrono::Duration::seconds(CONFIGSYNC_MAX_FUTURE_SKEW_SECS + 1);
    match evaluate_snapshot_clock_skew(beyond, now) {
        Err(StaleSnapshotReject::ImplausiblyFutureStamp {
            committed,
            now: reported_now,
            tolerance_secs,
        }) => {
            assert_eq!(committed, beyond);
            assert_eq!(reported_now, now);
            assert_eq!(tolerance_secs, CONFIGSYNC_MAX_FUTURE_SKEW_SECS);
        }
        other => panic!("expected ImplausiblyFutureStamp, got {other:?}"),
    }
}

#[test]
fn fenced_full_snapshot_counter_increments_independently_of_divergence() {
    // Fixed-cardinality operator signal for fenced snapshots. Fencing keeps
    // last-known-good config and must NOT raise sticky delta-rejection divergence.
    let metrics = ConfigSyncDivergenceMetrics::default();
    assert_eq!(metrics.snapshot().fenced_full_snapshots_total, 0);
    assert!(!metrics.is_diverged());

    metrics.record_fenced_snapshot();
    metrics.record_fenced_snapshot();

    let snap = metrics.snapshot();
    assert_eq!(snap.fenced_full_snapshots_total, 2);
    assert!(!snap.diverged);
    assert_eq!(snap.rejected_nonempty_deltas_total, 0);
}

#[test]
fn older_payload_exception_is_required_only_for_cross_source_strictly_older() {
    // Nit N1: the expensive complete-payload equivalence is consulted by the
    // disposition in exactly one case — a cross-source candidate strictly older
    // than a parseable applied watermark. The predicate gates the two canonical
    // JSON conversions to that case; every other case is decided without them.
    let applied = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let authority = AppliedSnapshotAuthority {
        version: Some(applied),
        source_cp_url: "http://cp-a:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    let older = applied - chrono::Duration::seconds(3600);
    let newer = applied + chrono::Duration::seconds(3600);

    // Required: cross-source, strictly older, parseable applied version.
    assert!(snapshot_requires_older_payload_exception(
        Some(&authority),
        older,
        "http://cp-b:50051"
    ));

    // Not required for any other case (disposition ignores the flag there):
    assert!(!snapshot_requires_older_payload_exception(
        None,
        older,
        "http://cp-b:50051"
    ));
    assert!(!snapshot_requires_older_payload_exception(
        Some(&authority),
        older,
        "http://cp-a:50051/" // same source (canonicalized trailing slash)
    ));
    assert!(!snapshot_requires_older_payload_exception(
        Some(&authority),
        newer, // not strictly older
        "http://cp-b:50051"
    ));
    let unknown_version = AppliedSnapshotAuthority {
        version: None,
        source_cp_url: "http://cp-a:50051".to_string(),
        gateway_trust: GatewayTrustEquivalenceState::Absent,
    };
    assert!(!snapshot_requires_older_payload_exception(
        Some(&unknown_version),
        older,
        "http://cp-b:50051"
    ));
}

#[test]
fn cp_endpoint_same_source_canonicalizes_equivalent_spellings() {
    // Nit N3: harmless equivalent spellings are the same source; distinct
    // scheme/host/port stay distinct; malformed URLs fail closed to exact match.
    assert!(cp_endpoints_same_source(
        "http://cp-a:50051",
        "http://cp-a:50051/"
    ));
    assert!(cp_endpoints_same_source(
        "http://cp-a:50051/",
        "http://cp-a:50051"
    ));
    // Case-insensitive scheme/host.
    assert!(cp_endpoints_same_source(
        "HTTP://CP-A:50051",
        "http://cp-a:50051"
    ));
    // Implicit vs explicit default port folds.
    assert!(cp_endpoints_same_source("http://cp-a", "http://cp-a:80"));
    assert!(cp_endpoints_same_source("https://cp-a", "https://cp-a:443"));

    // Distinct host / port / scheme are never merged.
    assert!(!cp_endpoints_same_source(
        "http://cp-a:50051",
        "http://cp-b:50051"
    ));
    assert!(!cp_endpoints_same_source(
        "http://cp-a:50051",
        "http://cp-a:50052"
    ));
    assert!(!cp_endpoints_same_source(
        "http://cp-a:50051",
        "https://cp-a:50051"
    ));

    // Malformed / uncanonicalizable input: only a byte-identical spelling counts
    // as same source, so a parse failure never merges two distinct endpoints.
    assert!(!cp_endpoints_same_source("not a url", "http://cp-a:50051"));
    assert!(!cp_endpoints_same_source("not a url", "also not a url"));
    assert!(cp_endpoints_same_source("not a url", "not a url"));
}

#[test]
fn tls_reload_during_failure_backoff_preserves_accumulated_backoff() {
    // Issue L2: build the accumulated failure backoff the reconnect loop carries
    // into a sleep after repeated ConnectionErrors against a still-failing CP.
    let mut state = MultiCpBackoffState::new();
    for _ in 0..4 {
        assert!(advance_multi_cp_backoff(
            &mut state,
            1,
            ConfigSyncAttemptOutcome::ConnectionError
        ));
        grow_backoff_after_failure_sleep(&mut state);
    }
    let accumulated = state.backoff_secs;
    assert!(
        accumulated > BACKOFF_INITIAL_SECS,
        "precondition: repeated failures have grown backoff"
    );

    // A TLS material rotation mid-backoff reconnects immediately with rotated
    // material but must PRESERVE this accumulated delay. The production loop does
    // that by NOT routing the interruption through `advance_multi_cp_backoff` — it
    // just reconnects, leaving `backoff_secs` untouched. Prove the anti-regression
    // by showing the pre-fix path (IntentionalDisconnect) erases it to 1s.
    let mut regressed = state.clone();
    let should_sleep = advance_multi_cp_backoff(
        &mut regressed,
        1,
        ConfigSyncAttemptOutcome::IntentionalDisconnect,
    );
    assert!(!should_sleep);
    assert_eq!(
        regressed.backoff_secs, BACKOFF_INITIAL_SECS,
        "pre-fix IntentionalDisconnect path erased accumulated backoff (the L2 bug)"
    );

    // Post-fix: the loop leaves backoff state untouched on a TLS-reload interruption.
    assert_eq!(state.backoff_secs, accumulated);
}

#[test]
fn silence_watchdog_arms_only_when_silence_is_actually_anomalous() {
    // Issue #2395 mixed-version safety: heartbeats are capability-negotiated, so
    // a stream from a CP that never confirmed them is legitimately idle-silent
    // and must NOT be torn down on the application silence bound. Transport
    // keepalive still covers it.
    assert!(!silence_watchdog_armed(false, true));

    // Once the CP confirms heartbeat support, continued silence means the
    // keepalive it promised stopped arriving — arm the watchdog.
    assert!(silence_watchdog_armed(true, true));

    // Issue #2967: before the first message, silence is anomalous at ANY peer
    // version — every CP sends its initial FULL_SNAPSHOT immediately on
    // Subscribe. Without this the DP would hang forever in `message().await`
    // on a blackholed reconnect and never reach a fallback CP.
    assert!(silence_watchdog_armed(false, false));
    assert!(silence_watchdog_armed(true, false));
}

#[test]
fn heartbeat_frames_require_an_accepted_negotiated_snapshot_base() {
    assert!(!heartbeat_frame_admissible(false, false));
    assert!(!heartbeat_frame_admissible(false, true));
    assert!(!heartbeat_frame_admissible(true, false));
    assert!(heartbeat_frame_admissible(true, true));
}

#[test]
fn configsync_stream_timings_default_to_the_shipped_production_policy() {
    // The timing policy is a per-invocation stack value with no global or env
    // override, so a compressed test bound cannot leak into a production DP.
    // Both the explicit constructor and `Default` must be the shipped constants.
    use ferrum_edge::grpc::configsync_lifecycle::ConfigSyncStreamTimings;

    let production = ConfigSyncStreamTimings::production();
    assert_eq!(
        production.max_silence,
        std::time::Duration::from_secs(CONFIGSYNC_MAX_SILENCE_SECS)
    );
    assert_eq!(ConfigSyncStreamTimings::default(), production);
}

/// Build a delta whose removal keys are namespace-qualified for `namespace`.
fn qualified_removal_delta(namespace: &str) -> IncrementalResult {
    IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![NamespacedResourceId::new(namespace, "p1")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![NamespacedResourceId::new(namespace, "c1")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![NamespacedResourceId::new(namespace, "pc1")],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new(namespace, "u1")],
        sequence_cursor: 7,
        poll_timestamp: Utc.with_ymd_and_hms(2026, 7, 24, 12, 0, 0).unwrap(),
    }
}

#[test]
fn delta_wire_body_keeps_legacy_bare_id_removal_arrays_for_older_peers() {
    // Issue #2395 / rolling upgrade: `IncrementalResult` JSON is the CP→DP DELTA
    // body, so its shape is a same-major.minor compatibility contract. A peer
    // that predates namespace-qualified removals must still be able to parse the
    // body, which means the historical arrays keep their bare-string element
    // type and the qualified keys travel in ADDITIVE `removed_*_keys` arrays.
    let wire = serde_json::to_value(qualified_removal_delta("production")).unwrap();

    for legacy_field in [
        "removed_proxy_ids",
        "removed_plugin_config_ids",
        "removed_upstream_ids",
    ] {
        let array = wire[legacy_field].as_array().expect(legacy_field);
        assert_eq!(array.len(), 1, "{legacy_field} must carry the removal");
        assert!(
            array[0].is_string(),
            "{legacy_field} must stay a bare-ID string array for older peers, got {:?}",
            array[0]
        );
    }
    for keyed_field in [
        "removed_proxy_keys",
        "removed_plugin_config_keys",
        "removed_upstream_keys",
    ] {
        let array = wire[keyed_field].as_array().expect(keyed_field);
        assert_eq!(array[0]["namespace"], "production");
        assert!(array[0]["id"].is_string());
    }
    // Consumers already shipped the qualified object shape on this major.minor,
    // so they keep it (no additive array) rather than regressing to bare IDs.
    assert_eq!(wire["removed_consumer_ids"][0]["namespace"], "production");
    assert!(wire.get("removed_consumer_keys").is_none());
}

#[test]
fn delta_wire_body_round_trips_namespace_qualified_removals() {
    // New CP → new DP must be lossless: the additive keys win over the legacy
    // bare-ID arrays, so no namespace qualification is lost on the wire.
    let original = qualified_removal_delta("production");
    let json = serde_json::to_string(&original).unwrap();
    let mut decoded: IncrementalResult = serde_json::from_str(&json).unwrap();

    assert_eq!(
        decoded.qualify_unqualified_removals("ferrum"),
        0,
        "a fully qualified delta must need no namespace qualification"
    );
    assert_eq!(
        decoded.removed_proxy_ids,
        vec![NamespacedResourceId::new("production", "p1")]
    );
    assert_eq!(
        decoded.removed_consumer_ids,
        vec![NamespacedResourceId::new("production", "c1")]
    );
    assert_eq!(
        decoded.removed_plugin_config_ids,
        vec![NamespacedResourceId::new("production", "pc1")]
    );
    assert_eq!(
        decoded.removed_upstream_ids,
        vec![NamespacedResourceId::new("production", "u1")]
    );
    assert_eq!(decoded.sequence_cursor, 7);
}

#[test]
fn legacy_bare_id_delta_decodes_and_scopes_to_the_authorized_namespace() {
    // Issue #2395, new DP ← legacy CP: a CP that predates qualified removals
    // sends bare ID strings in every removal array (consumers included). Those
    // decode without a namespace and are then scoped to the DP's own already
    // authorized subscription namespace, reproducing the legacy semantics
    // exactly without widening reach.
    let legacy = serde_json::json!({
        "added_or_modified_proxies": [],
        "removed_proxy_ids": ["p1"],
        "added_or_modified_consumers": [],
        "removed_consumer_ids": ["c1"],
        "added_or_modified_plugin_configs": [],
        "removed_plugin_config_ids": ["pc1"],
        "added_or_modified_upstreams": [],
        "removed_upstream_ids": ["u1"],
        "poll_timestamp": "2026-07-24T12:00:00Z",
    });

    let mut decoded: IncrementalResult = serde_json::from_value(legacy).unwrap();
    // Before qualification the keys carry no namespace, so the DP namespace
    // filter would fail them closed rather than deleting anything.
    let mut unqualified = decoded.clone();
    assert_eq!(
        filter_incremental_to_namespace(&mut unqualified, "production"),
        4
    );

    assert_eq!(decoded.qualify_unqualified_removals("production"), 4);
    assert_eq!(
        decoded.removed_proxy_ids,
        vec![NamespacedResourceId::new("production", "p1")]
    );
    assert_eq!(
        decoded.removed_consumer_ids,
        vec![NamespacedResourceId::new("production", "c1")]
    );
    assert_eq!(
        decoded.removed_plugin_config_ids,
        vec![NamespacedResourceId::new("production", "pc1")]
    );
    assert_eq!(
        decoded.removed_upstream_ids,
        vec![NamespacedResourceId::new("production", "u1")]
    );
    // Scoping is to the subscription namespace only: nothing survives a filter
    // for a different tenant, so #2974's cross-namespace guarantee holds.
    assert_eq!(filter_incremental_to_namespace(&mut decoded, "staging"), 4);
    assert!(decoded.is_empty());
}

#[test]
fn qualified_removal_from_a_foreign_namespace_is_never_requalified() {
    // Defense in depth (#2974): a misrouted or adversarial delta that explicitly
    // names another tenant must NOT be rewritten into this DP's namespace — it
    // must stay foreign so the namespace filter drops it.
    let mut delta = qualified_removal_delta("staging");
    assert_eq!(
        delta.qualify_unqualified_removals("production"),
        0,
        "explicitly qualified keys must never be re-scoped"
    );
    assert_eq!(filter_incremental_to_namespace(&mut delta, "production"), 4);
    assert!(delta.is_empty());
}
