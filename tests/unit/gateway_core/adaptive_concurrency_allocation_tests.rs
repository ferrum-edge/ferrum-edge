//! Count production limiter allocations after each key scope has warmed up.

use std::sync::Arc;

use ferrum_edge::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimiter,
};
use ferrum_edge::config::types::{Proxy, UpstreamTarget};
use serde_json::json;

use super::response_coalescing_allocation_tests::measure;

#[test]
fn adaptive_concurrency_existing_targets_allocate_only_the_admission_permit() {
    let target: UpstreamTarget = serde_json::from_value(json!({
        "host": "backend.local", "port": 8080, "weight": 1
    }))
    .expect("target");
    for (key_by, upstream_id) in [
        (AdaptiveConcurrencyKeyBy::Proxy, None),
        (AdaptiveConcurrencyKeyBy::Backend, None),
        (AdaptiveConcurrencyKeyBy::Upstream, Some("upstream-1")),
        (AdaptiveConcurrencyKeyBy::Upstream, None),
    ] {
        let proxy: Proxy = serde_json::from_value(json!({
            "id": "allocation-proxy", "namespace": "default",
            "backend_host": "backend.local", "backend_port": 8080,
            "upstream_id": upstream_id,
        }))
        .expect("proxy");
        let config = Arc::new(AdaptiveConcurrencyConfig {
            key_by,
            initial_limit: 1,
            min_limit: 1,
            max_limit: 1,
            max_tracked_keys: 100,
            min_samples: 1,
            baseline_window_samples: 1000,
            target_latency_multiplier: 1.5,
            decrease_ratio: 0.5,
            increase_step: 1,
            shadow_mode: false,
            expose_headers: false,
        });
        let limiter = AdaptiveConcurrencyLimiter::new(4);
        let ((cold_allocations, _), cold) =
            measure(|| limiter.try_acquire(&proxy, Some(&target), Arc::clone(&config)));
        drop(cold.expect("warm the target and thread-local scope scratch"));
        assert!(
            cold_allocations > 1,
            "first insert must allocate target state"
        );

        for _ in 0..8 {
            let ((allocations, _), admitted) =
                measure(|| limiter.try_acquire(&proxy, Some(&target), Arc::clone(&config)));
            let permit = admitted.expect("existing target admits");
            assert_eq!(
                allocations, 1,
                "{key_by:?}/{upstream_id:?}: only the returned Arc permit may allocate"
            );
            let ((allocations, bytes), rejected) =
                measure(|| limiter.try_acquire(&proxy, Some(&target), Arc::clone(&config)));
            assert!(rejected.is_err(), "the held permit fills the limit");
            assert_eq!(
                (allocations, bytes),
                (0, 0),
                "{key_by:?}/{upstream_id:?}: rejection needs neither a permit nor an owned key"
            );
            drop(permit);
        }
        assert_eq!(limiter.tracked_keys_count(), 1);
    }
}
