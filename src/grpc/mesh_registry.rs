//! Registry of connected mesh config-stream nodes.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;

use super::mesh_slice_convergence::{
    MeshSliceConvergenceSnapshot, MeshSliceConvergenceTracker, MeshSliceStatusOutcome,
};

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

#[derive(Default)]
pub struct MeshNodeRegistry {
    nodes: DashMap<String, MeshNodeInfo>,
    convergence: Arc<MeshSliceConvergenceTracker>,
}

impl MeshNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            convergence: Arc::new(MeshSliceConvergenceTracker::new()),
        }
    }

    pub fn convergence(&self) -> Arc<MeshSliceConvergenceTracker> {
        self.convergence.clone()
    }

    pub fn insert(&self, info: MeshNodeInfo) {
        self.insert_with_convergence(info, true);
    }

    pub fn insert_with_convergence(&self, info: MeshNodeInfo, track_convergence: bool) {
        if track_convergence {
            let now = Utc::now();
            if !self
                .convergence
                .note_connected(&info.node_id, &info.namespace, now)
            {
                tracing::warn!(
                    node_id = %info.node_id,
                    max_identities =
                        crate::grpc::mesh_slice_convergence::MESH_SLICE_CONVERGENCE_MAX_IDENTITIES,
                    "Mesh slice convergence tracker at cardinality ceiling; identity not retained"
                );
            }
        }
        self.nodes.insert(info.node_id.clone(), info);
    }

    pub fn remove_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        let generation = self.convergence.connected_generation(node_id);
        let removed = self.nodes.remove_if(node_id, |_, info| {
            info.connected_at == expected_connected_at
        });
        if removed.is_some() {
            self.convergence
                .note_disconnected(node_id, generation, Utc::now());
        }
    }

    pub fn touch_heartbeat(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        if let Some(mut entry) = self.nodes.get_mut(node_id)
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
        let mut stale_ids: Vec<(String, Option<u64>)> = Vec::new();
        self.nodes.retain(|node_id, info| {
            let keep = info.last_heartbeat_at >= stale_before;
            if !keep {
                removed += 1;
                stale_ids.push((
                    node_id.clone(),
                    self.convergence.connected_generation(node_id),
                ));
            }
            keep
        });
        for (node_id, generation) in stale_ids {
            self.convergence
                .note_disconnected(&node_id, generation, now);
        }
        let _ = self.convergence.reap_expired(now);
        removed
    }

    pub fn note_published(&self, version: &str) {
        self.convergence.note_published(version, Utc::now());
    }

    pub fn note_sent(&self, node_id: &str, version: &str) {
        self.convergence.note_sent(node_id, version, Utc::now());
    }

    pub fn note_status_report(
        &self,
        authenticated_subject: &str,
        node_id: &str,
        version: &str,
        rejected_reason: Option<&str>,
    ) -> MeshSliceStatusOutcome {
        self.convergence.note_status_report(
            authenticated_subject,
            node_id,
            version,
            rejected_reason,
            Utc::now(),
        )
    }

    pub fn convergence_snapshot(&self) -> Vec<MeshSliceConvergenceSnapshot> {
        self.convergence.snapshot(Utc::now())
    }

    pub fn convergence_for(&self, node_id: &str) -> Option<MeshSliceConvergenceSnapshot> {
        self.convergence.snapshot_for(node_id, Utc::now())
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
    fn mesh_registry_stale_drop_does_not_remove_newer_entry() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", old_connected_at));
        registry.insert(registry_info("node-a", "new-version", new_connected_at));
        registry.remove_if_stale("node-a", old_connected_at);

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

        registry.remove_if_stale("node-a", connected_at);
        assert!(registry.is_empty());
    }

    #[test]
    fn mesh_registry_touch_heartbeat_updates_matching_entry_only() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "mesh-version", new_connected_at));
        registry.touch_heartbeat("node-a", old_connected_at);
        let before = registry.snapshot()[0].last_heartbeat_at;

        registry.touch_heartbeat("node-a", new_connected_at);

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
