//! Unit tests for CP mesh-slice convergence tracking (issue #3265).

use chrono::{Duration, TimeZone, Utc};
use ferrum_edge::grpc::mesh_registry::MeshNodeRegistry;
use ferrum_edge::grpc::mesh_slice_convergence::{
    MESH_SLICE_CONVERGENCE_MAX_IDENTITIES, MESH_SLICE_CONVERGENCE_MAX_REASON_BYTES,
    MESH_SLICE_CONVERGENCE_RETENTION_SECS, MeshSliceConvergenceTracker, MeshSliceStatusOutcome,
};

fn tracker() -> MeshSliceConvergenceTracker {
    MeshSliceConvergenceTracker::new()
}

#[test]
fn applied_ack_marks_convergence_for_exact_sent_version() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    tracker.note_sent("dp-a", "v1", t0);

    assert_eq!(
        tracker.note_status_report("dp-a", "dp-a", "v1", None, t0 + Duration::seconds(1)),
        MeshSliceStatusOutcome::Applied
    );

    let snap = tracker.snapshot_for("dp-a", t0 + Duration::seconds(2)).unwrap();
    assert!(snap.converged);
    assert_eq!(snap.acknowledged_version.as_deref(), Some("v1"));
    assert_eq!(snap.sent_version.as_deref(), Some("v1"));
    assert_eq!(snap.desired_version.as_deref(), Some("v1"));
}

#[test]
fn rejection_records_bounded_reason_without_marking_converged() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    tracker.note_sent("dp-a", "v2", t0);

    let hostile = format!("bad\u{0007}-{}", "x".repeat(300));
    assert_eq!(
        tracker.note_status_report(
            "dp-a",
            "dp-a",
            "v2",
            Some(&hostile),
            t0 + Duration::seconds(1)
        ),
        MeshSliceStatusOutcome::Rejected
    );

    let snap = tracker.snapshot_for("dp-a", t0 + Duration::seconds(2)).unwrap();
    assert!(!snap.converged);
    assert_eq!(snap.rejected_version.as_deref(), Some("v2"));
    let reason = snap.rejected_reason.unwrap();
    assert!(reason.len() <= MESH_SLICE_CONVERGENCE_MAX_REASON_BYTES);
    assert!(!reason.chars().any(|ch| ch.is_control()));
    assert!(reason.starts_with("bad-"));
}

#[test]
fn stale_or_forged_ack_does_not_mark_convergence() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    tracker.note_sent("dp-a", "v3", t0);

    assert_eq!(
        tracker.note_status_report("dp-a", "dp-a", "v-old", None, t0),
        MeshSliceStatusOutcome::StaleVersion
    );
    assert_eq!(
        tracker.note_status_report("dp-a", "dp-a", "never-sent", None, t0),
        MeshSliceStatusOutcome::StaleVersion
    );
    assert_eq!(
        tracker.note_status_report("other", "dp-a", "v3", None, t0),
        MeshSliceStatusOutcome::IdentityMismatch
    );
    assert_eq!(
        tracker.note_status_report("ghost", "ghost", "v3", None, t0),
        MeshSliceStatusOutcome::UnknownIdentity
    );

    let snap = tracker.snapshot_for("dp-a", t0).unwrap();
    assert!(!snap.converged);
    assert!(snap.acknowledged_version.is_none());
}

#[test]
fn reconnect_reuses_retained_watermarks() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    tracker.note_sent("dp-a", "v4", t0);
    assert_eq!(
        tracker.note_status_report("dp-a", "dp-a", "v4", None, t0),
        MeshSliceStatusOutcome::Applied
    );
    let generation = tracker.connected_generation("dp-a").unwrap();
    tracker.note_disconnected("dp-a", Some(generation), t0 + Duration::seconds(5));

    let mid = tracker.snapshot_for("dp-a", t0 + Duration::seconds(6)).unwrap();
    assert!(!mid.connected);
    assert_eq!(mid.acknowledged_version.as_deref(), Some("v4"));
    assert!(mid.retention_deadline_at.is_some());

    assert!(tracker.note_connected("dp-a", "ferrum", t0 + Duration::seconds(10)));
    let after = tracker.snapshot_for("dp-a", t0 + Duration::seconds(11)).unwrap();
    assert!(after.connected);
    assert_eq!(after.acknowledged_version.as_deref(), Some("v4"));
    assert_eq!(after.sent_version.as_deref(), Some("v4"));
}

#[test]
fn published_advances_desired_while_sent_stays_until_emit() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    tracker.note_sent("dp-a", "v1", t0);
    assert_eq!(
        tracker.note_status_report("dp-a", "dp-a", "v1", None, t0),
        MeshSliceStatusOutcome::Applied
    );

    tracker.note_published("v2", t0 + Duration::seconds(30));
    let snap = tracker.snapshot_for("dp-a", t0 + Duration::seconds(31)).unwrap();
    assert_eq!(snap.desired_version.as_deref(), Some("v2"));
    assert_eq!(snap.sent_version.as_deref(), Some("v1"));
    assert!(snap.converged); // still ack'd last sent
    assert_eq!(tracker.published_version().as_deref(), Some("v2"));
}

#[test]
fn retained_entries_evict_after_retention_window() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();
    assert!(tracker.note_connected("dp-a", "ferrum", t0));
    let generation = tracker.connected_generation("dp-a").unwrap();
    tracker.note_disconnected("dp-a", Some(generation), t0);

    let before_deadline = t0 + Duration::seconds(MESH_SLICE_CONVERGENCE_RETENTION_SECS - 1);
    assert_eq!(tracker.reap_expired(before_deadline), 0);
    assert!(tracker.snapshot_for("dp-a", before_deadline).is_some());

    let after_deadline = t0 + Duration::seconds(MESH_SLICE_CONVERGENCE_RETENTION_SECS + 1);
    assert_eq!(tracker.reap_expired(after_deadline), 1);
    assert!(tracker.snapshot_for("dp-a", after_deadline).is_none());
}

#[test]
fn cardinality_ceiling_evicts_retained_before_refusing() {
    let tracker = tracker();
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap();

    // Fill to the ceiling with disconnected retained identities.
    for i in 0..MESH_SLICE_CONVERGENCE_MAX_IDENTITIES {
        let id = format!("node-{i}");
        assert!(tracker.note_connected(&id, "ferrum", t0));
        let generation = tracker.connected_generation(&id).unwrap();
        tracker.note_disconnected(&id, Some(generation), t0 + Duration::seconds(i as i64));
    }
    assert_eq!(tracker.len(), MESH_SLICE_CONVERGENCE_MAX_IDENTITIES);

    assert!(tracker.note_connected("newcomer", "ferrum", t0 + Duration::seconds(10_000)));
    assert!(tracker.len() <= MESH_SLICE_CONVERGENCE_MAX_IDENTITIES);
    assert!(tracker.snapshot_for("newcomer", t0 + Duration::seconds(10_000)).is_some());
}

#[test]
fn registry_surfaces_convergence_snapshot_for_cluster() {
    let registry = MeshNodeRegistry::new();
    registry.insert_with_convergence(
        ferrum_edge::grpc::mesh_registry::MeshNodeInfo {
            node_id: "mesh-1".to_string(),
            version: "0.9.0".to_string(),
            namespace: "ferrum".to_string(),
            connected_at: Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            last_heartbeat_at: Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            last_update_at: Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
        },
        true,
    );
    registry.note_published("2026-08-01T12:00:00Z");
    registry.note_sent("mesh-1", "2026-08-01T12:00:00Z");
    assert_eq!(
        registry.note_status_report("mesh-1", "mesh-1", "2026-08-01T12:00:00Z", None),
        MeshSliceStatusOutcome::Applied
    );

    let snap = registry.convergence_for("mesh-1").unwrap();
    assert!(snap.converged);
    assert!(snap.connected);

    let all = registry.convergence_snapshot();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].node_id, "mesh-1");
}
