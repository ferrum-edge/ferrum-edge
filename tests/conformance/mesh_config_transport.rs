//! Native MeshSubscribe config-transport conformance (GA contract row
//! `mesh.config_transport.native_subscribe`).
//!
//! Pins the *semantics* of the Ferrum-native CP→DP config transport — the
//! `MeshConfigSync.MeshSubscribe` gRPC stream served by `MeshGrpcServer`
//! (`src/grpc/mesh_server.rs`) and consumed by the native client
//! (`src/modes/mesh/config_consumer/native_client.rs`) — hermetically (no
//! gRPC, no CP process):
//!
//! 1. The namespace-scoped `MeshSlice` snapshot build: `MeshSubscribe`
//!    answers every subscriber (initial snapshot and each broadcast) with
//!    `MeshSlice::from_gateway_config(config, request)`, which admits only
//!    resources in the subscriber's namespace for a plain sidecar request.
//! 2. Update dedupe: the server suppresses no-op pushes via
//!    `MeshSlice::content_eq`, which ignores the transport version stamp
//!    (`GatewayConfig.loaded_at`) but detects real workload/service changes.
//! 3. Slice apply on the DP: `NativeMeshConfigConsumer::apply_update` parses
//!    the wire `mesh_slice_json` and installs it into `MeshRuntimeState`;
//!    a malformed or empty (heartbeat-shaped) payload errors WITHOUT
//!    clobbering the last accepted slice — the fail-closed contract that
//!    keeps a bad CP push from blanking a serving mesh.
//!
//! The *runtime* half of this row (a real CP in a kind cluster serving the
//! K8s-built mesh model over MeshSubscribe to a sidecar DP whose captured
//! inbound datapath then serves traffic) is live-gated by
//! `sidecar.config.native_subscribe_delivered` in the `mesh-e2e-sidecar`
//! suite (issue #2002).

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::proto::MeshConfigUpdate;
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::config_consumer::native_client::NativeMeshConfigConsumer;
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "mesh_config_transport";
const TRUST_DOMAIN: &str = "mesh-e2e.test";

fn capp_spiffe(namespace: &str) -> String {
    format!("spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/capp")
}

/// A mesh model spanning two namespaces, shaped like the K8s pod-discovery
/// translation the live fixture's CP serves (per-pod `Workload` + a
/// `MeshService` referencing it by SPIFFE ID).
fn two_namespace_mesh(namespace: &str, other: &str) -> MeshConfig {
    let doc = serde_json::json!({
        "workloads": [
            {
                "spiffe_id": capp_spiffe(namespace),
                "service_name": "capp",
                "namespace": namespace,
                "trust_domain": TRUST_DOMAIN,
                "service_account": "capp",
                "addresses": ["10.244.0.10"],
                "ports": [{"port": 8080, "protocol": "http", "name": "http"}],
                "selector": {"labels": {"app": "capp"}, "namespace": namespace}
            },
            {
                "spiffe_id": format!("spiffe://{TRUST_DOMAIN}/ns/{other}/sa/outsider"),
                "service_name": "outsider",
                "namespace": other,
                "trust_domain": TRUST_DOMAIN,
                "service_account": "outsider",
                "addresses": ["10.244.9.9"],
                "ports": [{"port": 8080, "protocol": "http", "name": "http"}],
                "selector": {"labels": {"app": "outsider"}, "namespace": other}
            }
        ],
        "services": [
            {
                "name": "capp",
                "namespace": namespace,
                "ports": [{"port": 8080, "protocol": "http", "name": "http"}],
                "workloads": [{"spiffe_id": capp_spiffe(namespace)}]
            },
            {
                "name": "outsider",
                "namespace": other,
                "ports": [{"port": 8080, "protocol": "http", "name": "http"}],
                "workloads": [
                    {"spiffe_id": format!("spiffe://{TRUST_DOMAIN}/ns/{other}/sa/outsider")}
                ]
            }
        ]
    });
    serde_json::from_value(doc).expect("mesh fixture document parses")
}

fn gateway_config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

fn capp_request(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest::from_native(
        "capp-node".to_string(),
        namespace.to_string(),
        capp_spiffe(namespace),
        HashMap::new(),
    )
}

fn build_slice(config: &GatewayConfig, namespace: &str) -> MeshSlice {
    MeshSlice::from_gateway_config(config, capp_request(namespace))
}

/// The snapshot every MeshSubscribe stream is fed from is namespace-scoped:
/// a plain sidecar request admits only its own namespace's workloads and
/// services (no waypoint narrowing in play). A meshless CP config yields an
/// empty — but still versioned — slice, which is what an early subscriber
/// sees before the CP's first K8s reconcile populates `config.mesh`.
#[test]
fn namespace_scoped_slice_snapshot_build() {
    register_feature!(
        category = CATEGORY,
        feature = "namespace-scoped MeshSlice snapshot build",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "MeshSlice::from_gateway_config(config, request) — the builder MeshSubscribe \
                 serves snapshots and broadcasts from — admits only the subscriber namespace's \
                 workloads/services for a plain sidecar request; a meshless config yields an \
                 empty versioned slice. Live-gated via \
                 sidecar.config.native_subscribe_delivered in mesh-e2e-sidecar.",
    );

    let config = gateway_config_with_mesh(two_namespace_mesh("ferrum", "other"));
    let slice = build_slice(&config, "ferrum");

    assert_eq!(slice.namespace, "ferrum");
    assert_eq!(
        slice.workload_spiffe_id.as_deref(),
        Some(capp_spiffe("ferrum")).as_deref()
    );
    assert!(
        slice
            .workloads
            .iter()
            .any(|w| w.spiffe_id.as_str() == capp_spiffe("ferrum")),
        "subscriber-namespace workload must ride the slice"
    );
    assert!(
        slice.workloads.iter().all(|w| w.namespace == "ferrum"),
        "no foreign-namespace workload may leak into the slice: {:?}",
        slice
            .workloads
            .iter()
            .map(|w| w.namespace.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        slice
            .services
            .iter()
            .any(|s| s.name == "capp" && s.namespace == "ferrum"),
        "subscriber-namespace service must ride the slice"
    );
    assert!(
        slice.services.iter().all(|s| s.namespace == "ferrum"),
        "no foreign-namespace service may leak into the slice"
    );

    // Meshless CP config (pre-first-reconcile): empty but versioned.
    let empty = build_slice(&GatewayConfig::default(), "ferrum");
    assert!(empty.workloads.is_empty() && empty.services.is_empty());
    assert!(
        !empty.version.is_empty(),
        "even an empty slice carries the transport version stamp"
    );
}

/// MeshSubscribe pushes an update only when `content_eq` says the slice
/// changed: two builds of the SAME mesh under different `loaded_at` stamps
/// (different `version`) compare equal, while a real workload/service change
/// does not — so config-poll churn never re-pushes identical slices but a
/// model change always propagates.
#[test]
fn subscribe_update_dedupe_ignores_version_stamp() {
    register_feature!(
        category = CATEGORY,
        feature = "MeshSubscribe update dedupe via content_eq",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "MeshSlice::content_eq ignores the transport version stamp (loaded_at) so \
                 no-op broadcasts are suppressed, and detects workload/service content \
                 changes so real model updates always push. Live-gated via \
                 sidecar.config.native_subscribe_delivered in mesh-e2e-sidecar.",
    );

    let mut config_a = gateway_config_with_mesh(two_namespace_mesh("ferrum", "other"));
    config_a.loaded_at = chrono::DateTime::parse_from_rfc3339("2026-07-03T00:00:00Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);
    let mut config_b = config_a.clone();
    config_b.loaded_at = chrono::DateTime::parse_from_rfc3339("2026-07-03T00:05:00Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);

    let slice_a = build_slice(&config_a, "ferrum");
    let slice_b = build_slice(&config_b, "ferrum");
    assert_ne!(
        slice_a.version, slice_b.version,
        "the two builds must differ in transport version"
    );
    assert!(
        slice_a.content_eq(&slice_b),
        "a version-only difference must dedupe (no re-push)"
    );

    // A real model change (the capp workload moved to a new pod IP) must NOT
    // dedupe.
    let mut changed_mesh = two_namespace_mesh("ferrum", "other");
    changed_mesh
        .workloads
        .iter_mut()
        .filter(|w| w.spiffe_id.as_str() == capp_spiffe("ferrum"))
        .for_each(|w| w.addresses = vec!["10.244.0.99".to_string()]);
    let changed = build_slice(&gateway_config_with_mesh(changed_mesh), "ferrum");
    assert!(
        !slice_a.content_eq(&changed),
        "a workload change must be detected as new content"
    );

    // Dropping a service must likewise push.
    let mut fewer_services_mesh = two_namespace_mesh("ferrum", "other");
    fewer_services_mesh.services.retain(|s| s.name != "capp");
    let fewer = build_slice(&gateway_config_with_mesh(fewer_services_mesh), "ferrum");
    assert!(
        !slice_a.content_eq(&fewer),
        "a service change must be detected as new content"
    );
}

/// The DP-side apply path: `apply_update` parses the wire `mesh_slice_json`
/// and installs it into the shared `MeshRuntimeState` (the same
/// `install_slice` the file source uses, so materialization downstream is
/// protocol-agnostic). Malformed JSON and empty heartbeat-shaped payloads
/// error and MUST NOT clobber the last accepted slice.
#[test]
fn native_slice_apply_and_malformed_update_fail_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "native slice apply + malformed-update fail-closed",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "NativeMeshConfigConsumer::apply_update installs a parsed MeshSlice into \
                 MeshRuntimeState (same install_slice as the file source); malformed or \
                 empty payloads return Err and retain the last accepted slice. Live-gated \
                 via sidecar.config.native_subscribe_delivered in mesh-e2e-sidecar.",
    );

    let consumer = NativeMeshConfigConsumer::new(MeshRuntimeState::new());
    assert!(
        consumer.state().snapshot().as_ref().is_none(),
        "no slice before the first update"
    );

    let config = gateway_config_with_mesh(two_namespace_mesh("ferrum", "other"));
    let slice = build_slice(&config, "ferrum");
    let update = MeshConfigUpdate {
        version: slice.version.clone(),
        mesh_slice_json: serde_json::to_string(&slice).expect("slice serializes"),
        ..MeshConfigUpdate::default()
    };
    let applied = consumer
        .apply_update(update)
        .expect("a valid MeshSubscribe update applies");
    assert!(
        applied.content_eq(&slice),
        "the wire round-trip must preserve slice content"
    );
    let installed = consumer.state().snapshot();
    assert!(
        installed
            .as_ref()
            .as_ref()
            .is_some_and(|s| s.content_eq(&slice)),
        "the applied slice must be installed into the runtime state"
    );

    // Malformed CP payload: rejected, last good slice retained.
    let malformed = MeshConfigUpdate {
        mesh_slice_json: "{not json".to_string(),
        ..MeshConfigUpdate::default()
    };
    assert!(
        consumer.apply_update(malformed).is_err(),
        "malformed slice JSON must be rejected"
    );

    // Heartbeat-shaped payload (empty mesh_slice_json): the stream loop skips
    // heartbeats before apply; if one ever reached apply it must also fail
    // closed rather than install an empty slice.
    let heartbeat_shaped = MeshConfigUpdate {
        heartbeat: true,
        ..MeshConfigUpdate::default()
    };
    assert!(
        consumer.apply_update(heartbeat_shaped).is_err(),
        "an empty heartbeat-shaped payload must never install"
    );

    let retained = consumer.state().snapshot();
    assert!(
        retained
            .as_ref()
            .as_ref()
            .is_some_and(|s| s.content_eq(&slice)),
        "bad updates must retain the last accepted slice"
    );
}
