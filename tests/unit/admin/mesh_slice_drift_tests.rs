//! Unit coverage for CP-side mesh slice drift tracking (issue #3265).

use std::sync::{Arc, Barrier};

use arc_swap::ArcSwap;
use chrono::{Duration, TimeZone, Utc};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::CpScope;
use ferrum_edge::grpc::mesh_slice_drift::{
    MESH_SLICE_DRIFT_MAX_ENTRIES, MESH_SLICE_DRIFT_MAX_NODE_ID_BYTES,
    MESH_SLICE_DRIFT_MAX_REASON_BYTES, MESH_SLICE_DRIFT_REJECTION_REASON,
    MeshSliceConvergenceState, MeshSliceDriftAdmitError, MeshSliceDriftRegistry,
    MeshSliceDriftSummary, render_mesh_slice_drift_summary_metrics, sanitize_reason,
    slice_content_digest, validate_version,
};
use ferrum_edge::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, second).unwrap()
}

fn open(registry: &MeshSliceDriftRegistry, node_id: &str, when: chrono::DateTime<Utc>) -> String {
    registry
        .open_session(node_id, "ferrum", when, Some("v1"))
        .expect("open")
}

#[test]
fn desired_sent_ack_converges_and_drift_flags_clear() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = at(0);
    let token = open(&registry, "dp-a", connected_at);
    registry
        .record_sent("dp-a", &token, "v1", connected_at)
        .expect("sent");
    registry
        .record_status(
            "dp-a",
            &token,
            "v1",
            None,
            connected_at + Duration::seconds(1),
        )
        .expect("ack");

    let snap = registry.snapshot();
    assert_eq!(snap.summary.tracked, 1);
    assert_eq!(snap.summary.converged, 1);
    let entry = &snap.data_planes[0];
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Converged);
    assert!(!entry.drift.desired_vs_sent);
    assert!(!entry.drift.desired_vs_acknowledged);
    assert!(!entry.drift.sent_vs_acknowledged);
}

#[test]
fn reports_require_connected_current_session_and_current_sent_version() {
    let registry = MeshSliceDriftRegistry::new();
    let first = at(0);
    let second = at(1);
    let first_token = open(&registry, "dp-a", first);
    registry
        .record_sent("dp-a", &first_token, "v1", first)
        .unwrap();

    // Replacement can deliver the same version, so time/version alone cannot
    // bind a delayed report. Only the new opaque token is authoritative.
    let second_token = open(&registry, "dp-a", second);
    registry
        .record_sent("dp-a", &second_token, "v1", second)
        .unwrap();
    assert_ne!(first_token, second_token);
    assert_eq!(
        registry
            .record_status("dp-a", &first_token, "v1", None, second)
            .expect_err("stale replacement report"),
        MeshSliceDriftAdmitError::SessionMismatch
    );
    assert_eq!(
        registry
            .record_status("dp-a", &second_token, "v0", None, second)
            .expect_err("not current sent version"),
        MeshSliceDriftAdmitError::VersionMismatch
    );
    assert!(registry.snapshot().data_planes[0].acknowledged.is_none());

    registry.mark_disconnected("dp-a", &second_token, second);
    assert_eq!(
        registry
            .record_status("dp-a", &second_token, "v1", None, second)
            .expect_err("disconnected report"),
        MeshSliceDriftAdmitError::DisconnectedNode
    );
}

#[test]
fn nack_reason_discards_caller_text_and_is_strictly_bounded() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = at(0);
    let token = open(&registry, "dp-a", connected_at);
    registry
        .record_sent("dp-a", &token, "v1", connected_at)
        .unwrap();
    let secret_bearing = "Bearer secret-token\npassword=hunter2\u{0000}";
    registry
        .record_status("dp-a", &token, "v1", Some(secret_bearing), connected_at)
        .unwrap();

    let rejected = registry.snapshot().data_planes[0]
        .rejected
        .clone()
        .expect("rejected");
    assert_eq!(rejected.reason, MESH_SLICE_DRIFT_REJECTION_REASON);
    assert!(rejected.reason.len() <= MESH_SLICE_DRIFT_MAX_REASON_BYTES);
    assert!(!rejected.reason.contains("secret"));
    assert_eq!(
        sanitize_reason("\u{0000}"),
        MESH_SLICE_DRIFT_REJECTION_REASON
    );
    assert_eq!(sanitize_reason("   "), MESH_SLICE_DRIFT_REJECTION_REASON);
    assert_eq!(sanitize_reason(""), "unspecified");
}

#[test]
fn version_validation_is_exact_control_safe_and_byte_bounded() {
    assert_eq!(
        validate_version(" v1").unwrap_err(),
        MeshSliceDriftAdmitError::VersionHasSurroundingWhitespace
    );
    assert_eq!(
        validate_version("v1 ").unwrap_err(),
        MeshSliceDriftAdmitError::VersionHasSurroundingWhitespace
    );
    assert_eq!(
        validate_version("v\u{007f}1").unwrap_err(),
        MeshSliceDriftAdmitError::VersionHasControlCharacter
    );
    assert!(validate_version(&"x".repeat(256)).is_ok());
    assert!(validate_version(&"é".repeat(128)).is_ok());
    assert_eq!(
        validate_version(&"é".repeat(129)).unwrap_err(),
        MeshSliceDriftAdmitError::VersionTooLong
    );
    let oversized_whitespace = format!("{}v1{}", " ".repeat(4096), " ".repeat(4096));
    assert_eq!(
        validate_version(&oversized_whitespace).unwrap_err(),
        MeshSliceDriftAdmitError::VersionTooLong
    );
}

#[test]
fn maintenance_republishes_advancing_ages_without_removal() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = at(0);
    let token = open(&registry, "dp-a", connected_at);
    registry
        .record_sent("dp-a", &token, "v1", connected_at)
        .unwrap();
    registry
        .record_status("dp-a", &token, "v1", None, connected_at)
        .unwrap();

    let maintenance_at = connected_at + Duration::seconds(42);
    assert_eq!(
        registry.reap_expired(maintenance_at, Duration::seconds(300)),
        0
    );
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.generated_at, maintenance_at);
    assert_eq!(
        snapshot.data_planes[0].sent.as_ref().unwrap().age_seconds,
        42
    );
    assert_eq!(
        snapshot.data_planes[0]
            .acknowledged
            .as_ref()
            .unwrap()
            .age_seconds,
        42
    );
}

#[test]
fn disconnect_retention_and_reap_are_session_safe() {
    let registry = MeshSliceDriftRegistry::new();
    let connected_at = at(0);
    let stale_token = open(&registry, "dp-a", connected_at);
    let current_token = open(&registry, "dp-a", at(1));
    registry.mark_disconnected("dp-a", &stale_token, at(1));
    assert!(registry.snapshot().data_planes[0].connected);
    registry.mark_disconnected("dp-a", &current_token, at(1));

    let removed = registry.reap_expired(
        connected_at + Duration::seconds(302),
        Duration::seconds(300),
    );
    assert_eq!(removed, 1);
    assert!(registry.is_empty());
}

#[test]
fn hard_cardinality_cap_is_serialized_under_concurrent_admission() {
    const CAP: usize = 8;
    const CONTENDERS: usize = 32;
    let registry = Arc::new(MeshSliceDriftRegistry::with_max_entries(CAP));
    let barrier = Arc::new(Barrier::new(CONTENDERS));
    let mut handles = Vec::new();
    for index in 0..CONTENDERS {
        let registry = registry.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let node_id = format!("dp-{index}");
            let admitted = registry.open_session(&node_id, "ferrum", at(0), Some("v1"));
            if let Ok(token) = admitted.as_ref() {
                registry
                    .record_sent(&node_id, token, "v1", at(0))
                    .expect("admitted send");
                registry
                    .record_status(&node_id, token, "v1", None, at(0))
                    .expect("admitted ack");
            }
            admitted
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("admission thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), CAP);
    assert_eq!(registry.len(), CAP);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| *error == MeshSliceDriftAdmitError::CardinalityExceeded)
    );
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.summary.tracked, CAP);
    assert_eq!(snapshot.summary.converged, CAP);
    assert_eq!(snapshot.data_planes.len(), CAP);
}

#[test]
fn production_cap_evicts_only_a_disconnected_victim() {
    let registry = MeshSliceDriftRegistry::new();
    let base = at(0);
    let mut first_token = None;
    for index in 0..MESH_SLICE_DRIFT_MAX_ENTRIES {
        let token = registry
            .open_session(&format!("dp-{index}"), "ferrum", base, Some("v1"))
            .unwrap();
        if index == 0 {
            first_token = Some(token);
        }
    }
    assert_eq!(
        registry
            .open_session("overflow", "ferrum", base, Some("v1"))
            .unwrap_err(),
        MeshSliceDriftAdmitError::CardinalityExceeded
    );
    registry.mark_disconnected("dp-0", first_token.as_deref().unwrap(), base);
    registry
        .open_session("replacement", "ferrum", base, Some("v1"))
        .expect("disconnected eviction");
    assert_eq!(registry.len(), MESH_SLICE_DRIFT_MAX_ENTRIES);
}

fn service(name: &str, namespace: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: Vec::new(),
        protocol_overrides: std::collections::HashMap::new(),
        uid: None,
    }
}

fn projected_config(second: u32, services: Vec<MeshService>) -> GatewayConfig {
    GatewayConfig {
        loaded_at: at(second),
        mesh: Some(Box::new(MeshConfig {
            services,
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    }
}

fn service_with_protocol_overrides(overrides: Vec<(u16, AppProtocol)>) -> MeshService {
    let mut service = service("api", "ferrum");
    let mut ports: Vec<_> = overrides
        .iter()
        .map(|(port, protocol)| ServicePort {
            port: *port,
            protocol: *protocol,
            name: Some(format!("port-{port}")),
            target_port: None,
        })
        .collect();
    ports.sort_by_key(|port| port.port);
    service.ports = ports;
    service.protocol_overrides = overrides.into_iter().collect();
    service
}

#[test]
fn projected_digest_recursively_canonicalizes_nested_maps() {
    let request = MeshSliceRequest {
        node_id: "dp-a".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    };
    let overrides: Vec<_> = (9000..9016).map(|port| (port, AppProtocol::Grpc)).collect();
    let first_config =
        projected_config(0, vec![service_with_protocol_overrides(overrides.clone())]);
    let first_slice = MeshSlice::from_gateway_config(&first_config, request.clone());
    let mut reordered = overrides.clone();
    reordered.reverse();
    let reordered_config = projected_config(1, vec![service_with_protocol_overrides(reordered)]);
    let reordered_slice = MeshSlice::from_gateway_config(&reordered_config, request.clone());
    let mut changed_overrides = overrides;
    changed_overrides[0].1 = AppProtocol::Tcp;
    let changed_config =
        projected_config(33, vec![service_with_protocol_overrides(changed_overrides)]);
    let changed_slice = MeshSlice::from_gateway_config(&changed_config, request.clone());

    assert!(first_slice.content_eq(&reordered_slice));
    assert_eq!(
        slice_content_digest(&first_slice).unwrap(),
        slice_content_digest(&reordered_slice).unwrap(),
        "nested map insertion order is not semantic"
    );
    assert!(!first_slice.content_eq(&changed_slice));
    assert_ne!(
        slice_content_digest(&first_slice).unwrap(),
        slice_content_digest(&changed_slice).unwrap(),
        "a protocol change is semantic"
    );

    let registry = MeshSliceDriftRegistry::new();
    let token = registry
        .open_projected_session(
            "dp-a",
            "ferrum",
            at(0),
            &first_slice,
            request,
            CpScope::Single("ferrum".to_string()),
            None,
        )
        .unwrap();
    registry.mark_disconnected("dp-a", &token, at(0));

    assert_eq!(
        registry.reconcile_desired(&reordered_config, at(1)),
        0,
        "content-equal reordered maps must not advance desired"
    );
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        first_slice.version
    );
    assert_eq!(
        registry.reconcile_desired(&changed_config, at(2)),
        1,
        "semantic changes must advance desired"
    );
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        changed_slice.version
    );
}

/// A CP publication that lands between the subscribe path's config load and its
/// registry insert reconciles a registry that does not yet contain the new
/// identity, so it cannot stamp that row. The stream still receives (and
/// records as sent) the newer slice, which would leave the row permanently
/// `desired = old` / `sent = acked = new` — drifted until the next
/// content-changing publication, which on a quiet config store may never come.
/// The connect-side re-reconcile closes that window.
#[test]
fn subscribe_publication_race_repairs_desired_from_the_published_config() {
    let registry = MeshSliceDriftRegistry::new();
    let request = MeshSliceRequest {
        node_id: "dp-a".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    };
    // What the subscribe path loaded before the row existed.
    let loaded = projected_config(0, vec![service("api", "ferrum")]);
    let loaded_slice = MeshSlice::from_gateway_config(&loaded, request.clone());
    // What the CP published inside the race window.
    let published = projected_config(1, vec![service("api-v2", "ferrum")]);
    let published_slice = MeshSlice::from_gateway_config(&published, request.clone());
    let config = ArcSwap::from_pointee(published.clone());

    assert_eq!(
        registry.reconcile_desired(&published, at(1)),
        0,
        "the publication cannot stamp a row that does not exist yet"
    );

    let token = registry
        .open_projected_session(
            "dp-a",
            "ferrum",
            at(1),
            &loaded_slice,
            request,
            CpScope::Single("ferrum".to_string()),
            None,
        )
        .unwrap();
    registry
        .record_projected_sent("dp-a", &token, &loaded_slice, at(1))
        .unwrap();
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        loaded_slice.version,
        "the row starts on the pre-publication projection"
    );

    assert!(
        registry.reconcile_session_desired("dp-a", &token, &config, at(2)),
        "the connect-side repair re-stamps desired from the published config"
    );
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        published_slice.version
    );

    // The already-subscribed stream then delivers and the DP acknowledges the
    // same published slice, so the row converges instead of staying drifted.
    registry
        .record_projected_sent("dp-a", &token, &published_slice, at(2))
        .unwrap();
    registry
        .record_status("dp-a", &token, &published_slice.version, None, at(2))
        .unwrap();
    let entry = &registry.snapshot().data_planes[0];
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Converged);
    assert!(!entry.drift.desired_vs_sent);
    assert!(!entry.drift.desired_vs_acknowledged);

    // Idempotent, and never mutates a row it does not own.
    assert!(!registry.reconcile_session_desired("dp-a", &token, &config, at(3)));
    assert!(!registry.reconcile_session_desired("dp-a", &"0".repeat(32), &config, at(3)));
    assert!(!registry.reconcile_session_desired("dp-unknown", &token, &config, at(3)));
}

#[test]
fn identity_length_is_bounded_independently_of_the_transport() {
    let registry = MeshSliceDriftRegistry::new();
    let longest = "d".repeat(MESH_SLICE_DRIFT_MAX_NODE_ID_BYTES);
    let token = registry
        .open_session(&longest, "ferrum", at(0), Some("v1"))
        .expect("the maximum identity length is admitted");
    assert!(!token.is_empty());

    let oversized = "d".repeat(MESH_SLICE_DRIFT_MAX_NODE_ID_BYTES + 1);
    assert_eq!(
        registry
            .open_session(&oversized, "ferrum", at(0), Some("v1"))
            .unwrap_err(),
        MeshSliceDriftAdmitError::NodeIdTooLong
    );
    assert_eq!(
        registry
            .record_status(&oversized, &token, "v1", None, at(0))
            .unwrap_err(),
        MeshSliceDriftAdmitError::NodeIdTooLong
    );
    assert_eq!(registry.len(), 1);
}

fn assert_rendered_summary_is_coherent(output: &str, summary: &MeshSliceDriftSummary) {
    if summary.tracked == 0 {
        assert!(output.is_empty());
        return;
    }

    let mut tracked = None;
    let mut states = Vec::new();
    for line in output.lines() {
        if line.starts_with("ferrum_mesh_slice_drift_data_planes{") {
            states.push(
                line.rsplit_once(' ')
                    .expect("state metric value")
                    .1
                    .parse::<usize>()
                    .expect("state metric integer"),
            );
        } else if line.starts_with("ferrum_mesh_slice_drift_tracked_data_planes ") {
            tracked = Some(
                line.rsplit_once(' ')
                    .expect("tracked metric value")
                    .1
                    .parse::<usize>()
                    .expect("tracked metric integer"),
            );
        }
    }
    let tracked = tracked.expect("tracked summary metric");
    assert_eq!(states.len(), 5);
    assert_eq!(tracked, states.into_iter().sum::<usize>());
}

fn assert_published_summary_is_coherent(registry: &MeshSliceDriftRegistry) {
    let summary = registry.snapshot().summary.clone();
    assert_eq!(
        summary.tracked,
        summary.converged
            + summary.drifted
            + summary.rejecting
            + summary.pending
            + summary.disconnected,
        "immutable snapshot summary must not mix convergence generations"
    );
    let mut output = String::new();
    render_mesh_slice_drift_summary_metrics(&mut output, &summary, "");
    assert_rendered_summary_is_coherent(&output, &summary);
}

#[test]
fn prometheus_summary_publication_is_coherent_during_registry_mutations() {
    let registry = MeshSliceDriftRegistry::new();
    assert_published_summary_is_coherent(&registry);

    let converged_token = open(&registry, "dp-converged", at(0));
    registry
        .record_sent("dp-converged", &converged_token, "v1", at(0))
        .unwrap();
    assert_published_summary_is_coherent(&registry);
    registry
        .record_status("dp-converged", &converged_token, "v1", None, at(1))
        .unwrap();
    assert_published_summary_is_coherent(&registry);

    let drifted_token = open(&registry, "dp-drifted", at(0));
    registry
        .record_sent("dp-drifted", &drifted_token, "v2", at(0))
        .unwrap();
    assert_published_summary_is_coherent(&registry);

    registry.mark_disconnected("dp-converged", &converged_token, at(2));
    assert_published_summary_is_coherent(&registry);

    let rejecting_token = open(&registry, "dp-rejecting", at(0));
    registry
        .record_sent("dp-rejecting", &rejecting_token, "v1", at(0))
        .unwrap();
    registry
        .record_status(
            "dp-rejecting",
            &rejecting_token,
            "v1",
            Some("caller detail"),
            at(0),
        )
        .unwrap();
    assert_published_summary_is_coherent(&registry);

    registry
        .open_session("dp-pending", "ferrum", at(0), None)
        .unwrap();
    assert_published_summary_is_coherent(&registry);
}

#[test]
fn retained_projection_context_fails_closed_at_count_bounds() {
    let registry = MeshSliceDriftRegistry::new();
    let config = projected_config(0, Vec::new());
    let mut request = MeshSliceRequest {
        node_id: "dp-a".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    };
    for index in 0..257 {
        request
            .labels
            .insert(format!("label-{index}"), "value".to_string());
    }
    let slice = MeshSlice::from_gateway_config(&config, request.clone());
    assert_eq!(
        registry
            .open_projected_session(
                "dp-a",
                "ferrum",
                at(0),
                &slice,
                request,
                CpScope::Single("ferrum".to_string()),
                None,
            )
            .unwrap_err(),
        MeshSliceDriftAdmitError::ProjectionContextTooLarge
    );

    let request = MeshSliceRequest {
        node_id: "dp-b".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    };
    let slice = MeshSlice::from_gateway_config(&config, request.clone());
    let namespaces = (0..257).map(|index| format!("ns-{index}")).collect();
    assert_eq!(
        registry
            .open_projected_session(
                "dp-b",
                "ferrum",
                at(0),
                &slice,
                request,
                CpScope::Set(namespaces),
                None,
            )
            .unwrap_err(),
        MeshSliceDriftAdmitError::ProjectionContextTooLarge
    );
}

#[test]
fn desired_tracks_projected_content_for_connected_and_retained_disconnected_rows() {
    let registry = MeshSliceDriftRegistry::new();
    let request = MeshSliceRequest {
        node_id: "dp-a".to_string(),
        namespace: "ferrum".to_string(),
        ..MeshSliceRequest::default()
    };
    let initial_config = projected_config(0, vec![service("api", "ferrum")]);
    let initial_slice = MeshSlice::from_gateway_config(&initial_config, request.clone());
    let token = registry
        .open_projected_session(
            "dp-a",
            "ferrum",
            at(0),
            &initial_slice,
            request.clone(),
            CpScope::Single("ferrum".to_string()),
            None,
        )
        .unwrap();
    registry
        .record_projected_sent("dp-a", &token, &initial_slice, at(0))
        .unwrap();
    registry
        .record_status("dp-a", &token, &initial_slice.version, None, at(0))
        .unwrap();

    let related = projected_config(1, vec![service("api-v2", "ferrum")]);
    assert_eq!(registry.reconcile_desired(&related, at(1)), 1);
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        related.loaded_at.to_rfc3339(),
        "publication advances desired even when a connected stream is backpressured"
    );
    let connected = &registry.snapshot().data_planes[0];
    assert_eq!(
        connected.sent.as_ref().unwrap().version,
        initial_slice.version
    );
    assert_eq!(connected.convergence, MeshSliceConvergenceState::Drifted);
    assert!(connected.drift.desired_vs_sent);

    let current_config = ArcSwap::from_pointee(related.clone());
    registry.mark_disconnected_with_config("dp-a", &token, &current_config, at(1));
    assert_eq!(
        registry.snapshot().data_planes[0]
            .desired
            .as_ref()
            .unwrap()
            .version,
        related.loaded_at.to_rfc3339(),
        "disconnect closes the publish-before-drop race from current config"
    );
    let no_op = projected_config(2, vec![service("api-v2", "ferrum")]);
    assert_eq!(registry.reconcile_desired(&no_op, at(2)), 0);
    let unrelated = projected_config(
        3,
        vec![service("api-v2", "ferrum"), service("other", "other")],
    );
    assert_eq!(registry.reconcile_desired(&unrelated, at(3)), 0);
    let next_related = projected_config(4, vec![service("api-v3", "ferrum")]);
    assert_eq!(registry.reconcile_desired(&next_related, at(4)), 1);
    let entry = &registry.snapshot().data_planes[0];
    assert_eq!(
        entry.desired.as_ref().unwrap().version,
        next_related.loaded_at.to_rfc3339()
    );
    assert_eq!(entry.sent.as_ref().unwrap().version, initial_slice.version);
    assert_eq!(entry.convergence, MeshSliceConvergenceState::Disconnected);
    assert!(entry.drift.desired_vs_sent);
}
