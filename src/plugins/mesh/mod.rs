//! Mesh-specific plugins and plugin helpers.

use std::collections::HashMap;

pub mod authz;
pub mod bpf_metrics;
pub(crate) mod diagnostics;
pub mod ext_authz;
pub mod outbound_registry;
pub mod prometheus_helpers;
pub mod service_graph;
pub mod spiffe_identity;
pub mod workload_metrics;

pub(crate) const CUSTOM_TRACE_ATTRIBUTES_METADATA: &str = "workload_metrics.trace_attributes";

/// Static mesh-observability maps cannot consume the runtime env override, but
/// they still need the same auto-sized hot-path shard formula used by
/// `FERRUM_POOL_SHARD_AMOUNT=0`.
fn observability_shard_amount() -> usize {
    crate::util::sharding::pool_shard_amount(0)
}

/// Extract mesh-prefixed metadata entries as OpenTelemetry attribute pairs,
/// sorted by key for deterministic span output.
///
/// Both branches apply the shared metadata sensitivity decision, so a
/// `mesh.*` key that names a credential (`mesh.session_id`,
/// `mesh.private_key`) is never exported to a trace even though it carries
/// the mesh prefix (issue #6619).
pub fn mesh_trace_attributes(metadata: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut attributes: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| {
            key.starts_with("mesh.")
                && !key.starts_with("mesh.metrics.")
                && !crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key(key)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if let Some(custom_names) = metadata.get(CUSTOM_TRACE_ATTRIBUTES_METADATA) {
        attributes.extend(
            custom_names
                .split(',')
                .take(32)
                .filter(|key| custom_trace_attribute_name_allowed(key))
                .filter_map(|key| {
                    metadata
                        .get(key)
                        .map(|value| (key.to_string(), value.clone()))
                }),
        );
    }
    attributes.sort_by(|left, right| left.0.cmp(&right.0));
    attributes.dedup_by(|left, right| left.0 == right.0);
    attributes
}

fn custom_trace_attribute_name_allowed(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !key.starts_with("mesh.")
        && !key.starts_with("mesh_authz.")
        && !key.starts_with("workload_metrics.")
        && !matches!(
            key,
            "trace_id"
                | "span_id"
                | "parent_span_id"
                | "trace_sampled"
                | "traceparent"
                | "tracestate"
                | "peer_spiffe_id"
                | "request_protocol"
                | "response_flags"
        )
        && !crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key(key)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn observability_shard_amount_uses_hot_path_auto_sizing() {
        let shards = super::observability_shard_amount();
        assert_eq!(shards, crate::util::sharding::pool_shard_amount(0));
        assert!(shards.is_power_of_two());
        assert!(shards >= 64);
    }

    #[test]
    fn trace_attributes_never_export_credential_shaped_keys() {
        let metadata = HashMap::from([
            ("mesh.source.workload".to_string(), "frontend".to_string()),
            ("mesh.session_id".to_string(), "session-secret".to_string()),
            ("mesh.private_key".to_string(), "key-secret".to_string()),
            ("tenant".to_string(), "acme".to_string()),
            (
                "x-session-id".to_string(),
                "custom-session-secret".to_string(),
            ),
            (
                super::CUSTOM_TRACE_ATTRIBUTES_METADATA.to_string(),
                "tenant,x-session-id".to_string(),
            ),
        ]);

        assert_eq!(
            super::mesh_trace_attributes(&metadata),
            vec![
                ("mesh.source.workload".to_string(), "frontend".to_string()),
                ("tenant".to_string(), "acme".to_string()),
            ]
        );
    }

    #[test]
    fn trace_attributes_include_declared_custom_tags_but_not_internal_plans() {
        let metadata = HashMap::from([
            ("mesh.source.workload".to_string(), "frontend".to_string()),
            (
                "mesh.metrics.disabled".to_string(),
                "request_count".to_string(),
            ),
            (
                "mesh.metrics.cel.request_host".to_string(),
                "attacker-controlled.example".to_string(),
            ),
            ("tenant".to_string(), "acme".to_string()),
            (
                super::CUSTOM_TRACE_ATTRIBUTES_METADATA.to_string(),
                "tenant".to_string(),
            ),
        ]);

        assert_eq!(
            super::mesh_trace_attributes(&metadata),
            vec![
                ("mesh.source.workload".to_string(), "frontend".to_string()),
                ("tenant".to_string(), "acme".to_string()),
            ]
        );
    }

    #[test]
    fn trace_attribute_marker_cannot_expose_sensitive_metadata() {
        let metadata = HashMap::from([
            ("authorization".to_string(), "Bearer secret".to_string()),
            (
                super::CUSTOM_TRACE_ATTRIBUTES_METADATA.to_string(),
                "authorization".to_string(),
            ),
        ]);

        assert!(super::mesh_trace_attributes(&metadata).is_empty());
    }
}
