//! Registry of connected mesh config-stream nodes.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;

use super::mesh_slice_drift::MeshSliceDriftRegistry;

pub const MESH_NODE_REGISTRY_STALE_TTL_SECONDS: i64 = 300;
pub const MESH_NODE_REGISTRY_REAPER_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

pub fn mesh_node_registry_stale_ttl() -> chrono::Duration {
    chrono::Duration::seconds(MESH_NODE_REGISTRY_STALE_TTL_SECONDS)
}

#[derive(Clone, Serialize)]
pub struct MeshNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_heartbeat_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

/// Online mesh subscribers plus the optional CP-side slice-drift tracker
/// (issue #3265). Drift is shared with [`super::mesh_server::MeshGrpcServer`]
/// so broadcasts can reconcile retained disconnected projections without
/// threading a second handle through every publish site.
#[derive(Default)]
pub struct MeshNodeRegistry {
    nodes: DashMap<String, MeshNodeInfo>,
    drift: Option<Arc<MeshSliceDriftRegistry>>,
}

impl MeshNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            drift: None,
        }
    }

    /// Attach the CP slice-drift registry. Idempotent replacement is fine;
    /// production wiring attaches once at CP startup.
    pub fn with_drift(mut self, drift: Arc<MeshSliceDriftRegistry>) -> Self {
        self.drift = Some(drift);
        self
    }

    pub fn drift(&self) -> Option<&MeshSliceDriftRegistry> {
        self.drift.as_deref()
    }

    pub fn insert(&self, info: MeshNodeInfo) {
        let key = super::admission::authenticated_principal_key(&info.namespace, &info.node_id);
        self.nodes.insert(key, info);
    }

    pub fn remove_if_stale(
        &self,
        namespace: &str,
        node_id: &str,
        expected_connected_at: DateTime<Utc>,
    ) {
        let key = super::admission::authenticated_principal_key(namespace, node_id);
        self.nodes
            .remove_if(&key, |_, info| info.connected_at == expected_connected_at);
    }

    pub fn touch_heartbeat(
        &self,
        namespace: &str,
        node_id: &str,
        expected_connected_at: DateTime<Utc>,
    ) {
        let key = super::admission::authenticated_principal_key(namespace, node_id);
        if let Some(mut entry) = self.nodes.get_mut(&key)
            && entry.connected_at == expected_connected_at
        {
            entry.last_heartbeat_at = Utc::now();
        }
    }

    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    pub fn remove_stale_heartbeats(&self, now: DateTime<Utc>, ttl: chrono::Duration) -> usize {
        let stale_before = now - ttl;
        let mut removed = 0usize;
        self.nodes.retain(|_, info| {
            let keep = info.last_heartbeat_at >= stale_before;
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    pub fn snapshot(&self) -> Vec<MeshNodeInfo> {
        self.nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn registry_info(node_id: &str, version: &str, connected_at: DateTime<Utc>) -> MeshNodeInfo {
        MeshNodeInfo {
            node_id: node_id.to_string(),
            version: version.to_string(),
            namespace: "ferrum".to_string(),
            connected_at,
            last_heartbeat_at: connected_at,
            last_update_at: connected_at,
        }
    }

    #[test]
    fn mesh_registry_insert_replaces_same_node() {
        let registry = MeshNodeRegistry::new();
        let first_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let second_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", first_connected_at));
        registry.insert(registry_info("node-a", "new-version", second_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, second_connected_at);
    }

    #[test]
    fn mesh_registry_keeps_equal_subjects_in_separate_namespaces() {
        let registry = MeshNodeRegistry::new();
        let connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let first = registry_info("shared-subject", "v1", connected_at);
        let mut second = first.clone();
        second.namespace = "other-tenant".to_string();

        registry.insert(first.clone());
        registry.insert(second);

        assert_eq!(registry.len(), 2);
        registry.remove_if_stale("ferrum", "shared-subject", connected_at);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.snapshot()[0].namespace, "other-tenant");
    }

    #[test]
    fn mesh_registry_stale_drop_does_not_remove_newer_entry() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", old_connected_at));
        registry.insert(registry_info("node-a", "new-version", new_connected_at));
        registry.remove_if_stale("ferrum", "node-a", old_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, new_connected_at);
    }

    #[test]
    fn mesh_registry_removes_matching_entry() {
        let registry = MeshNodeRegistry::new();
        let connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();

        registry.insert(registry_info("node-a", "mesh-version", connected_at));
        assert_eq!(registry.len(), 1);

        registry.remove_if_stale("ferrum", "node-a", connected_at);
        assert!(registry.is_empty());
    }

    #[test]
    fn mesh_registry_touch_heartbeat_updates_matching_entry_only() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "mesh-version", new_connected_at));
        registry.touch_heartbeat("ferrum", "node-a", old_connected_at);
        let before = registry.snapshot()[0].last_heartbeat_at;

        registry.touch_heartbeat("ferrum", "node-a", new_connected_at);

        let after = registry.snapshot()[0].last_heartbeat_at;
        assert_eq!(before, new_connected_at);
        assert!(after >= before);
    }

    #[test]
    fn mesh_registry_removes_stale_heartbeats() {
        let registry = MeshNodeRegistry::new();
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 10, 0).unwrap();
        let fresh_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 9, 0).unwrap();
        let stale_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();

        registry.insert(registry_info("fresh", "mesh-version", fresh_connected_at));
        registry.insert(registry_info("stale", "mesh-version", stale_connected_at));

        let removed = registry.remove_stale_heartbeats(now, chrono::Duration::minutes(5));

        assert_eq!(removed, 1);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].node_id, "fresh");
    }
}
