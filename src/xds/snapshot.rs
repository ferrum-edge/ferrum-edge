use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XdsConfigFingerprint(Arc<str>);

impl XdsConfigFingerprint {
    pub(crate) fn new(value: String) -> Self {
        Self(Arc::from(value))
    }
}

// `proto::Any` is Ferrum's minimal wire-compatible xDS surface, not the
// generated `google.protobuf.Any` type.
/// One xDS resource encoded as an Any payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsResource {
    pub name: String,
    pub type_url: String,
    pub version: String,
    pub value: Vec<u8>,
}

impl XdsResource {
    pub fn to_any(&self) -> proto::Any {
        proto::Any {
            type_url: self.type_url.clone(),
            value: self.value.clone(),
        }
    }

    pub fn to_delta_resource(&self) -> proto::Resource {
        proto::Resource {
            version: self.version.clone(),
            resource: Some(self.to_any()),
            name: self.name.clone(),
            aliases: Vec::new(),
        }
    }
}

/// Full xDS snapshot for one node ID. Node ID is a security boundary:
/// snapshots are never shared across nodes even when their resources happen
/// to be byte-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsSnapshot {
    pub node_id: String,
    pub version: String,
    resources_by_type: HashMap<String, Vec<XdsResource>>,
}

impl XdsSnapshot {
    pub fn new(node_id: String, version: String, resources: Vec<XdsResource>) -> Self {
        let mut resources_by_type: HashMap<String, Vec<XdsResource>> = HashMap::new();
        for resource in resources {
            resources_by_type
                .entry(resource.type_url.clone())
                .or_default()
                .push(resource);
        }
        for resources in resources_by_type.values_mut() {
            resources.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Self {
            node_id,
            version,
            resources_by_type,
        }
    }

    pub fn resources(&self, type_url: &str) -> &[XdsResource] {
        self.resources_by_type
            .get(type_url)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn filtered_resources(
        &self,
        type_url: &str,
        names: &[String],
        wildcard: bool,
    ) -> Vec<XdsResource> {
        let resources = self.resources(type_url);
        if wildcard {
            return resources.to_vec();
        }
        if names.is_empty() {
            return Vec::new();
        }
        let wanted: HashSet<&str> = names.iter().map(String::as_str).collect();
        resources
            .iter()
            .filter(|resource| wanted.contains(resource.name.as_str()))
            .cloned()
            .collect()
    }

    pub fn removed_resource_names(&self, next: &Self, type_url: &str) -> Vec<String> {
        let next_names: HashSet<String> = next
            .resources(type_url)
            .iter()
            .map(|resource| resource.name.clone())
            .collect();
        let mut removed: Vec<String> = self
            .resources(type_url)
            .iter()
            .filter_map(|resource| {
                if next_names.contains(&resource.name) {
                    None
                } else {
                    Some(resource.name.clone())
                }
            })
            .collect();
        removed.sort();
        removed
    }
}

/// Lock-free per-node snapshot cache for ADS.
#[derive(Default)]
pub struct XdsSnapshotCache {
    // ADS is gated by FERRUM_XDS_ENABLED and Phase B keeps node cardinality low.
    // Use DashMap's default sharding here; revisit with util::sharding when
    // mesh node counts become hot-path scale in later phases.
    snapshots: DashMap<String, CachedXdsSnapshot>,
}

struct CachedXdsSnapshot {
    fingerprint: Option<XdsConfigFingerprint>,
    snapshot: Arc<XdsSnapshot>,
}

impl XdsSnapshotCache {
    pub fn new() -> Self {
        Self {
            snapshots: DashMap::new(),
        }
    }

    pub fn get(&self, node_id: &str) -> Option<Arc<XdsSnapshot>> {
        self.snapshots
            .get(node_id)
            .map(|cached| Arc::clone(&cached.snapshot))
    }

    pub(crate) fn get_if_fingerprint(
        &self,
        node_id: &str,
        fingerprint: &XdsConfigFingerprint,
    ) -> Option<Arc<XdsSnapshot>> {
        self.snapshots.get(node_id).and_then(|cached| {
            (cached.fingerprint.as_ref() == Some(fingerprint)).then(|| Arc::clone(&cached.snapshot))
        })
    }

    pub fn insert(&self, snapshot: XdsSnapshot) -> Arc<XdsSnapshot> {
        let node_id = snapshot.node_id.clone();
        let snapshot = Arc::new(snapshot);
        self.snapshots.insert(
            node_id,
            CachedXdsSnapshot {
                fingerprint: None,
                snapshot: Arc::clone(&snapshot),
            },
        );
        snapshot
    }

    pub(crate) fn insert_with_fingerprint(
        &self,
        snapshot: XdsSnapshot,
        fingerprint: XdsConfigFingerprint,
    ) -> Arc<XdsSnapshot> {
        let cache_key = snapshot.node_id.clone();
        self.insert_with_fingerprint_for_key(cache_key, snapshot, fingerprint)
    }

    pub(crate) fn insert_with_fingerprint_for_key(
        &self,
        cache_key: String,
        snapshot: XdsSnapshot,
        fingerprint: XdsConfigFingerprint,
    ) -> Arc<XdsSnapshot> {
        let snapshot = Arc::new(snapshot);
        self.snapshots.insert(
            cache_key,
            CachedXdsSnapshot {
                fingerprint: Some(fingerprint),
                snapshot: Arc::clone(&snapshot),
            },
        );
        snapshot
    }

    pub fn remove(&self, node_id: &str) -> Option<(String, Arc<XdsSnapshot>)> {
        self.snapshots
            .remove(node_id)
            .map(|(node_id, cached)| (node_id, cached.snapshot))
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}
