use crate::fips::approved::Sha256;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NonceKey {
    node_id: String,
    type_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NonceState {
    last_issued_nonce: String,
    last_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    Nacked { message: String },
    MissingNonce,
    StaleNonce { expected: String, actual: String },
    UnknownNonce,
    VersionDrift { expected: String, actual: String },
}

/// Per `(node_id, type_url)` ACK/NACK nonce machine.
///
/// xDS ACK state is intentionally not global: a NACK for RDS must not poison
/// an LDS update on the same node, and two nodes must never share nonce state.
#[derive(Default)]
pub struct XdsNonceTracker {
    // ADS is opt-in and nonce state is one entry per active `(node, type_url)`.
    // Default DashMap sharding keeps Phase B small; revisit for very large mesh
    // fleets if this becomes an operator-visible pressure point.
    states: DashMap<NonceKey, NonceState>,
    counter: AtomicU64,
}

impl XdsNonceTracker {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
            counter: AtomicU64::new(0),
        }
    }

    pub fn issue_nonce(&self, node_id: &str, type_url: &str, version: &str) -> String {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let nonce = opaque_nonce(node_id, type_url, version, sequence);
        let key = NonceKey {
            node_id: node_id.to_string(),
            type_url: type_url.to_string(),
        };
        self.states.insert(
            key,
            NonceState {
                last_issued_nonce: nonce.clone(),
                last_version: version.to_string(),
            },
        );
        nonce
    }

    pub fn record_response(
        &self,
        node_id: &str,
        type_url: &str,
        response_nonce: &str,
        version_info: &str,
        error_message: Option<&str>,
    ) -> AckOutcome {
        if response_nonce.is_empty() {
            return AckOutcome::MissingNonce;
        }

        let key = NonceKey {
            node_id: node_id.to_string(),
            type_url: type_url.to_string(),
        };
        let Some(state) = self.states.get(&key) else {
            return AckOutcome::UnknownNonce;
        };

        // `actual` in `StaleNonce` / `VersionDrift` is peer-supplied and is
        // Debug-formatted into the server's "ACK ignored" warn line, so it is
        // bounded here like the NACK message below. The `expected` halves are
        // server-generated.
        if state.last_issued_nonce != response_nonce {
            return AckOutcome::StaleNonce {
                expected: state.last_issued_nonce.clone(),
                actual: super::bounded_xds_log_value(response_nonce),
            };
        }

        if let Some(message) = error_message {
            // Bound the peer-supplied NACK message at the boundary so the value
            // surfaced to the server's warn lines stays bounded regardless of
            // input length (issue #4813).
            return AckOutcome::Nacked {
                message: super::bounded_xds_log_value(message),
            };
        }

        if !version_info.is_empty() && version_info != state.last_version {
            return AckOutcome::VersionDrift {
                expected: state.last_version.clone(),
                actual: super::bounded_xds_log_value(version_info),
            };
        }

        AckOutcome::Acked
    }

    pub fn remove_node(&self, node_id: &str) {
        // Phase B cardinality is tiny: one entry per active `(node, type_url)`
        // and xDS is gated off by default. Before large-fleet deployment,
        // replace this O(n) retain with a per-node key index or hierarchical
        // map so stream teardown does not scan unrelated nodes.
        self.states.retain(|key, _| key.node_id != node_id);
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

fn opaque_nonce(node_id: &str, type_url: &str, version: &str, sequence: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update([0]);
    hasher.update(type_url.as_bytes());
    hasher.update([0]);
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(sequence.to_be_bytes());
    format!("n1:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_nonce_is_opaque_and_unique() {
        let tracker = XdsNonceTracker::new();

        let first = tracker.issue_nonce(
            "spiffe://cluster.local/ns/prod/sa/api",
            "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            "2026-05-06T00:00:00Z",
        );
        let second = tracker.issue_nonce(
            "spiffe://cluster.local/ns/prod/sa/api",
            "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            "2026-05-06T00:00:00Z",
        );

        assert_ne!(first, second);
        assert!(first.starts_with("n1:"));
        assert!(!first.contains("spiffe://"));
        assert!(!first.contains("envoy.config.cluster"));
        assert!(!first.contains("2026-05-06"));
    }

    #[test]
    fn opaque_nonce_still_drives_ack_state_machine() {
        let tracker = XdsNonceTracker::new();
        let nonce = tracker.issue_nonce("node-a", "type-a", "v1");

        assert_eq!(
            tracker.record_response("node-a", "type-a", &nonce, "v1", None),
            AckOutcome::Acked
        );
    }

    #[test]
    fn hostile_megabyte_nack_message_is_bounded_in_the_outcome() {
        let tracker = XdsNonceTracker::new();
        let nonce = tracker.issue_nonce("node-a", "type-a", "v1");
        let hostile = "n".repeat(1024 * 1024);

        let outcome = tracker.record_response("node-a", "type-a", &nonce, "", Some(&hostile));

        let AckOutcome::Nacked { message } = outcome else {
            panic!("expected a NACK outcome for an error message");
        };
        assert!(
            message.len() <= crate::xds::MAX_XDS_LOG_VALUE_CHARS + "(truncated)".len(),
            "the NACK message must be bounded, got {} bytes",
            message.len()
        );
        assert!(message.ends_with("(truncated)"));
    }
}
