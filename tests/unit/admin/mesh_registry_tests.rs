use chrono::{TimeZone, Utc};
use ferrum_edge::grpc::mesh_registry::{MeshNodeInfo, MeshNodeRegistry};

#[test]
fn equal_subjects_remain_separate_between_namespaces() {
    let registry = MeshNodeRegistry::new();
    let connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
    let first = MeshNodeInfo {
        node_id: "shared-subject".to_string(),
        version: "v1".to_string(),
        namespace: "ferrum".to_string(),
        connected_at,
        last_heartbeat_at: connected_at,
        last_update_at: connected_at,
    };
    let mut second = first.clone();
    second.namespace = "other-tenant".to_string();

    registry.insert(first);
    registry.insert(second);

    assert_eq!(registry.len(), 2);
    registry.remove_if_stale("ferrum", "shared-subject", connected_at);
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.snapshot()[0].namespace, "other-tenant");
}
