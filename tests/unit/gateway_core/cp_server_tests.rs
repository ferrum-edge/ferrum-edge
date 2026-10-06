//! Tests for CP gRPC server public API (DpNodeRegistry).

use chrono::{Duration, Utc};
use ferrum_edge::grpc::cp_server::{DpNodeInfo, DpNodeRegistry};

fn make_node(id: &str) -> DpNodeInfo {
    let now = Utc::now();
    DpNodeInfo {
        node_id: id.to_string(),
        version: "0.9.0".to_string(),
        namespace: "ferrum".to_string(),
        connected_at: now,
        last_update_at: now,
        backend_egress_policy: None,
    }
}

#[test]
fn registry_new_is_empty() {
    let registry = DpNodeRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.snapshot().is_empty());
}

#[test]
fn registry_register_and_snapshot() {
    let registry = DpNodeRegistry::new();
    registry.register_stream("node-1", make_node("node-1"));
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].node_id, "node-1");
}

#[test]
fn registry_keeps_every_stream_of_one_node_id() {
    let registry = DpNodeRegistry::new();
    let mut node1 = make_node("node-1");
    node1.version = "0.9.0".to_string();
    let first = registry.register_stream("node-1", node1);

    let mut node1_v2 = make_node("node-1");
    node1_v2.version = "0.9.1".to_string();
    let second = registry.register_stream("node-1", node1_v2);

    // A second stream never replaces the first one's entry.
    assert_ne!(first.stream_seq, second.stream_seq);
    assert_eq!(registry.len(), 2);
    let snapshot = registry.snapshot();
    let mut versions: Vec<&str> = snapshot.iter().map(|n| n.version.as_str()).collect();
    versions.sort();
    assert_eq!(versions, ["0.9.0", "0.9.1"]);
}

#[test]
fn registry_stream_key_carries_namespace_principal_and_node_id() {
    let registry = DpNodeRegistry::new();
    let mut node = make_node("node-1");
    node.namespace = "tenant-b".to_string();
    let key = registry.register_stream("principal-1", node);
    assert_eq!(key.namespace, "tenant-b");
    assert_eq!(key.principal, "principal-1");
    assert_eq!(key.node_id, "node-1");
}

#[test]
fn registry_same_node_id_in_two_namespaces_is_tracked_separately() {
    let registry = DpNodeRegistry::new();
    let mut tenant_a = make_node("dp-1");
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = make_node("dp-1");
    tenant_b.namespace = "tenant-b".to_string();
    let key_a = registry.register_stream("dp-1", tenant_a);
    let key_b = registry.register_stream("dp-1", tenant_b);
    assert_eq!(registry.len(), 2);

    // Namespace B's disconnect removes only its own stream.
    registry.remove_stream(&key_b);
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].namespace, "tenant-a");
    registry.remove_stream(&key_a);
    assert!(registry.is_empty());
}

#[test]
fn registry_remove_stream_removes_only_that_stream() {
    let registry = DpNodeRegistry::new();
    let mut older = make_node("node-1");
    older.version = "older".to_string();
    registry.register_stream("node-1", older);
    let mut newer = make_node("node-1");
    newer.version = "newer".to_string();
    let newer_key = registry.register_stream("node-1", newer);

    // The newer stream drops first: the older stream stays registered.
    registry.remove_stream(&newer_key);
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].version, "older");
}

#[test]
fn registry_remove_stream_is_idempotent() {
    let registry = DpNodeRegistry::new();
    let key = registry.register_stream("node-1", make_node("node-1"));
    registry.remove_stream(&key);
    registry.remove_stream(&key);
    assert!(registry.is_empty());
}

#[test]
fn registry_touch_all_updates_last_update_at() {
    let registry = DpNodeRegistry::new();
    let mut node = make_node("node-1");
    let old_time = Utc::now() - Duration::hours(1);
    node.last_update_at = old_time;
    registry.register_stream("node-1", node);

    registry.touch_all();

    let snap = registry.snapshot();
    assert!(snap[0].last_update_at > old_time);
}

#[test]
fn registry_multiple_nodes() {
    let registry = DpNodeRegistry::new();
    registry.register_stream("node-1", make_node("node-1"));
    registry.register_stream("node-2", make_node("node-2"));
    registry.register_stream("node-3", make_node("node-3"));

    assert_eq!(registry.len(), 3);
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 3);
    let ids: Vec<&str> = snap.iter().map(|n| n.node_id.as_str()).collect();
    assert!(ids.contains(&"node-1"));
    assert!(ids.contains(&"node-2"));
    assert!(ids.contains(&"node-3"));
}
