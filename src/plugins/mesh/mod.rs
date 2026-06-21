//! Mesh-specific plugins and plugin helpers.

use std::collections::HashMap;

pub mod authz;
pub mod bpf_metrics;
pub mod outbound_registry;
pub mod prometheus_helpers;
pub mod service_graph;
pub mod spiffe_identity;
pub mod workload_metrics;

/// Static mesh-observability maps cannot consume the runtime env override, but
/// they still need the same auto-sized hot-path shard formula used by
/// `FERRUM_POOL_SHARD_AMOUNT=0`.
fn observability_shard_amount() -> usize {
    crate::util::sharding::pool_shard_amount(0)
}

/// Extract mesh-prefixed metadata entries as OpenTelemetry attribute pairs,
/// sorted by key for deterministic span output.
pub fn mesh_trace_attributes(metadata: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut attributes: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("mesh."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    attributes.sort_by(|left, right| left.0.cmp(&right.0));
    attributes
}

#[cfg(test)]
mod tests {
    #[test]
    fn observability_shard_amount_uses_hot_path_auto_sizing() {
        let shards = super::observability_shard_amount();
        assert_eq!(shards, crate::util::sharding::pool_shard_amount(0));
        assert!(shards.is_power_of_two());
        assert!(shards >= 64);
    }
}
