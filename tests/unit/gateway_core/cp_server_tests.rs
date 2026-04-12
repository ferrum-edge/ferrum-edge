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
fn registry_insert_and_snapshot() {
    let registry = DpNodeRegistry::new();
    registry.insert(make_node("node-1"));
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].node_id, "node-1");
}

#[test]
fn registry_insert_overwrites_same_node_id() {
    let registry = DpNodeRegistry::new();
    let mut node1 = make_node("node-1");
    node1.version = "0.9.0".to_string();
    registry.insert(node1);

    let mut node1_v2 = make_node("node-1");
    node1_v2.version = "0.9.1".to_string();
    registry.insert(node1_v2);

    assert_eq!(registry.len(), 1);
    let snap = registry.snapshot();
    assert_eq!(snap[0].version, "0.9.1");
}

#[test]
fn registry_remove_if_stale_removes_when_timestamps_match() {
    let registry = DpNodeRegistry::new();
    let node = make_node("node-1");
    let connected_at = node.connected_at;
    registry.insert(node);

    registry.remove_if_stale("node-1", connected_at);
    assert!(registry.is_empty());
}

#[test]
fn registry_remove_if_stale_does_not_remove_when_timestamps_differ() {
    let registry = DpNodeRegistry::new();
    let node = make_node("node-1");
    registry.insert(node);

    // Try to remove with a different timestamp (stale stream drop scenario)
    let stale_timestamp = Utc::now() - Duration::hours(1);
    registry.remove_if_stale("node-1", stale_timestamp);

    // Node should still be there
    assert_eq!(registry.len(), 1);
}

#[test]
fn registry_remove_if_stale_nonexistent_node_is_noop() {
    let registry = DpNodeRegistry::new();
    registry.remove_if_stale("nonexistent", Utc::now());
    assert!(registry.is_empty());
}

#[test]
fn registry_touch_all_updates_last_update_at() {
    let registry = DpNodeRegistry::new();
    let mut node = make_node("node-1");
    let old_time = Utc::now() - Duration::hours(1);
    node.last_update_at = old_time;
    registry.insert(node);

    registry.touch_all();

    let snap = registry.snapshot();
    assert!(snap[0].last_update_at > old_time);
}

#[test]
fn registry_multiple_nodes() {
    let registry = DpNodeRegistry::new();
    registry.insert(make_node("node-1"));
    registry.insert(make_node("node-2"));
    registry.insert(make_node("node-3"));

    assert_eq!(registry.len(), 3);
    let snap = registry.snapshot();
    assert_eq!(snap.len(), 3);
    let ids: Vec<&str> = snap.iter().map(|n| n.node_id.as_str()).collect();
    assert!(ids.contains(&"node-1"));
    assert!(ids.contains(&"node-2"));
    assert!(ids.contains(&"node-3"));
}
