//! Registry of connected mesh config-stream nodes.

use crate::time_compat::UtcTimestamp;
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;

use super::mesh_slice_drift::MeshSliceDriftRegistry;

pub const MESH_NODE_REGISTRY_STALE_TTL_SECONDS: i64 = 300;
pub const MESH_NODE_REGISTRY_REAPER_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

pub fn mesh_node_registry_stale_ttl() -> ::time::SignedDuration {
    ::time::SignedDuration::seconds(MESH_NODE_REGISTRY_STALE_TTL_SECONDS)
}

#[derive(Clone, Serialize)]
pub struct MeshNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: UtcTimestamp,
    pub last_heartbeat_at: UtcTimestamp,
    pub last_update_at: UtcTimestamp,
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
        expected_connected_at: UtcTimestamp,
    ) {
        let key = super::admission::authenticated_principal_key(namespace, node_id);
        self.remove_if_stale_key(&key, expected_connected_at);
    }

    pub(crate) fn remove_if_stale_key(&self, key: &str, expected_connected_at: UtcTimestamp) {
        self.nodes
            .remove_if(key, |_, info| info.connected_at == expected_connected_at);
    }

    pub fn touch_heartbeat(
        &self,
        namespace: &str,
        node_id: &str,
        expected_connected_at: UtcTimestamp,
    ) {
        let key = super::admission::authenticated_principal_key(namespace, node_id);
        self.touch_heartbeat_key(&key, expected_connected_at);
    }

    pub(crate) fn touch_heartbeat_key(&self, key: &str, expected_connected_at: UtcTimestamp) {
        if let Some(mut entry) = self.nodes.get_mut(key)
            && entry.connected_at == expected_connected_at
        {
            entry.last_heartbeat_at = UtcTimestamp::now();
        }
    }

    pub fn touch_all(&self) {
        let now = UtcTimestamp::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    pub fn remove_stale_heartbeats(&self, now: UtcTimestamp, ttl: ::time::SignedDuration) -> usize {
        // An unrepresentable cutoff means no heartbeat can be older than it.
        let stale_before = now.checked_sub(ttl);
        let mut removed = 0usize;
        self.nodes.retain(|_, info| {
            let keep = stale_before.is_none_or(|cutoff| info.last_heartbeat_at >= cutoff);
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

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_info(node_id: &str, version: &str, connected_at: UtcTimestamp) -> MeshNodeInfo {
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
        let first_connected_at = "2026-05-05T12:00:01Z".parse::<UtcTimestamp>().unwrap();
        let second_connected_at = "2026-05-05T12:00:02Z".parse::<UtcTimestamp>().unwrap();

        registry.insert(registry_info("node-a", "old-version", first_connected_at));
        registry.insert(registry_info("node-a", "new-version", second_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, second_connected_at);
    }

    #[test]
    fn mesh_registry_stale_drop_does_not_remove_newer_entry() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = "2026-05-05T12:00:01Z".parse::<UtcTimestamp>().unwrap();
        let new_connected_at = "2026-05-05T12:00:02Z".parse::<UtcTimestamp>().unwrap();

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
        let connected_at = "2026-05-05T12:00:01Z".parse::<UtcTimestamp>().unwrap();

        registry.insert(registry_info("node-a", "mesh-version", connected_at));
        assert_eq!(registry.len(), 1);

        registry.remove_if_stale("ferrum", "node-a", connected_at);
        assert!(registry.is_empty());
    }

    #[test]
    fn mesh_registry_touch_heartbeat_updates_matching_entry_only() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = "2026-05-05T12:00:01Z".parse::<UtcTimestamp>().unwrap();
        let new_connected_at = "2026-05-05T12:00:02Z".parse::<UtcTimestamp>().unwrap();

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
        let now = "2026-05-05T12:10:00Z".parse::<UtcTimestamp>().unwrap();
        let fresh_connected_at = "2026-05-05T12:09:00Z".parse::<UtcTimestamp>().unwrap();
        let stale_connected_at = "2026-05-05T12:00:00Z".parse::<UtcTimestamp>().unwrap();

        registry.insert(registry_info("fresh", "mesh-version", fresh_connected_at));
        registry.insert(registry_info("stale", "mesh-version", stale_connected_at));

        let removed = registry.remove_stale_heartbeats(now, ::time::SignedDuration::minutes(5));

        assert_eq!(removed, 1);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].node_id, "fresh");
    }
}
