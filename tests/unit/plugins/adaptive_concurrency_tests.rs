use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use ferrum_edge::_test_support::{
    AdaptiveConcurrencyDecreaseHarness, AdaptiveConcurrencyTransitionHarness,
};
use ferrum_edge::PluginCache;
use ferrum_edge::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimiter,
};
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::{GatewayConfig, Proxy, UpstreamTarget};
use ferrum_edge::plugins::adaptive_concurrency::AdaptiveConcurrency;
use ferrum_edge::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, BackendAdmissionOutcome,
    BackendAdmissionPermit, Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
};
use ferrum_edge::retry::ErrorClass;
use serde_json::json;

fn proxy() -> Proxy {
    serde_json::from_value(json!({
        "id": "proxy-1",
        "namespace": "default",
        "backend_host": "backend.local",
        "backend_port": 8080
    }))
    .expect("minimal proxy should deserialize")
}

fn limiter_config(initial_limit: u64) -> Arc<AdaptiveConcurrencyConfig> {
    Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit,
        max_limit: initial_limit.max(1),
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    })
}

fn growth_config(initial_limit: u64, max_limit: u64) -> Arc<AdaptiveConcurrencyConfig> {
    Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit,
        max_limit,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    })
}

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    }
}

fn cache_config(scope: &str, plugin_config: serde_json::Value) -> GatewayConfig {
    let proxy_id = (scope == "proxy").then_some("proxy-1");
    let proxy_plugins = if scope == "global" {
        json!([])
    } else {
        json!([{"plugin_config_id": "adaptive-1"}])
    };
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "namespace": "default",
            "listen_path": "/",
            "backend_host": "backend.local",
            "backend_port": 8080,
            "plugins": proxy_plugins
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "adaptive-1",
            "namespace": "default",
            "plugin_name": "adaptive_concurrency",
            "scope": scope,
            "proxy_id": proxy_id,
            "enabled": true,
            "config": plugin_config
        }]
    }))
    .expect("adaptive cache config should deserialize")
}

fn acquire_from_cache(cache: &PluginCache, config: &GatewayConfig) -> BackendAdmissionDecision {
    let plugin = adaptive_plugin_for_proxy(cache, "proxy-1");
    acquire_from_plugin(&plugin, &config.proxies[0], None)
}

fn adaptive_plugin_from_cache(cache: &PluginCache) -> Arc<dyn Plugin> {
    adaptive_plugin_for_proxy(cache, "proxy-1")
}

fn adaptive_plugin_for_proxy(cache: &PluginCache, proxy_id: &str) -> Arc<dyn Plugin> {
    cache
        .get_plugins("default", proxy_id)
        .iter()
        .find(|plugin| plugin.name() == "adaptive_concurrency")
        .cloned()
        .expect("adaptive plugin should be cached")
}

fn acquire_from_plugin(
    plugin: &Arc<dyn Plugin>,
    proxy: &Proxy,
    upstream_target: Option<&UpstreamTarget>,
) -> BackendAdmissionDecision {
    let ctx = RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
    let admission = BackendAdmissionContext {
        proxy,
        upstream_target,
        protocol: ProxyProtocol::Http,
    };
    plugin.try_backend_admission(&ctx, &admission)
}

fn expect_admitted(decision: BackendAdmissionDecision) -> Arc<dyn BackendAdmissionPermit> {
    match decision {
        BackendAdmissionDecision::Admit(permit) => permit,
        _ => panic!("request should be admitted"),
    }
}

fn assert_rejected(decision: BackendAdmissionDecision) {
    match decision {
        BackendAdmissionDecision::Reject { status_code, .. } => assert_eq!(status_code, 503),
        _ => panic!("request should be rejected"),
    }
}

fn assert_generation_handoff_rejected_without_headers(decision: BackendAdmissionDecision) {
    match decision {
        BackendAdmissionDecision::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 503);
            assert!(
                !headers.contains_key("x-adaptive-concurrency-limit"),
                "a generation handoff has no truthful per-target limit"
            );
            assert!(
                !headers.contains_key("x-adaptive-concurrency-inflight"),
                "a generation handoff has no truthful per-target in-flight count"
            );
        }
        _ => panic!("retired generation should be rejected"),
    }
}

#[test]
fn adaptive_concurrency_structural_reset_owner_is_exclusive() {
    let transition = AdaptiveConcurrencyTransitionHarness::new();
    let writer = transition.begin_structural_reset();
    assert!(
        transition.try_begin_structural_reset().is_none(),
        "a second writer must not replace the active reset owner"
    );
    assert!(
        !transition.is_active(),
        "admission must remain fail-closed until the reset owner commits"
    );
    assert!(transition.finish_reset(writer));
    assert!(transition.is_active());
}

#[test]
fn adaptive_concurrency_stale_reset_token_cannot_reactivate_newer_writer() {
    let transition = AdaptiveConcurrencyTransitionHarness::new();
    let first_writer = transition.begin_structural_reset();
    assert!(transition.finish_reset(first_writer));
    let newer_writer = transition.begin_structural_reset();
    assert!(
        !transition.finish_reset(first_writer),
        "an older epoch token must not reactivate a newer reset"
    );
    assert!(!transition.is_active());
    assert!(transition.finish_reset(newer_writer));
    assert!(transition.is_active());
}

#[test]
fn adaptive_concurrency_rejects_when_limit_is_full_and_releases_on_drop() {
    let plugin = AdaptiveConcurrency::new(
        &json!({
            "initial_limit": 1,
            "max_limit": 1
        }),
        PluginHttpClient::default(),
    )
    .expect("config should be valid");
    let proxy = proxy();
    let ctx = RequestContext::new("192.0.2.10".to_string(), "GET".to_string(), "/".to_string());
    let admission = BackendAdmissionContext {
        proxy: &proxy,
        upstream_target: None,
        protocol: ProxyProtocol::Http,
    };

    let first = match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Admit(permit) => permit,
        _ => panic!("first request should be admitted"),
    };

    match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(body, br#"{"error":"Upstream concurrency limit reached"}"#);
        }
        _ => panic!("second concurrent request should be rejected"),
    }

    drop(first);

    match plugin.try_backend_admission(&ctx, &admission) {
        BackendAdmissionDecision::Admit(_) => {}
        _ => panic!("slot should be released when the permit drops"),
    }
}

#[test]
fn adaptive_concurrency_records_failure_by_shrinking_limit() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(5),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 2);
    assert_eq!(snapshot.in_flight, 1);

    drop(permit);

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should still exist after release");
    assert_eq!(snapshot.in_flight, 0);
}

#[test]
fn adaptive_concurrency_concurrent_failures_each_apply_backoff() {
    let limiter = Arc::new(AdaptiveConcurrencyDecreaseHarness::new(100, 1, 100, 0.8));
    let observed_limit = limiter.limit();
    let start = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();

    for _ in 0..2 {
        let limiter = Arc::clone(&limiter);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            limiter.decrease_from_observed_limit(observed_limit);
        }));
    }
    start.wait();
    for worker in workers {
        worker
            .join()
            .expect("concurrent failure callback should not panic");
    }

    assert_eq!(
        limiter.limit(),
        64,
        "two callbacks that observed 100 must each apply their 0.8 backoff"
    );
}

#[test]
fn adaptive_concurrency_concurrent_failure_backoff_stops_at_minimum() {
    let limiter = AdaptiveConcurrencyDecreaseHarness::new(5, 4, 5, 0.8);
    let observed_limit = limiter.limit();

    limiter.decrease_from_observed_limit(observed_limit);
    limiter.decrease_from_observed_limit(observed_limit);

    assert_eq!(limiter.limit(), 4);
}

#[test]
fn adaptive_concurrency_ignores_client_deadline_even_with_synthetic_5xx() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    permit.record_backend_outcome(BackendAdmissionOutcome {
        // The gRPC dispatch error path uses a synthetic 502 for permit
        // accounting, but ClientDisconnect remains authoritative and must be
        // checked before the generic >= 500 shrink branch.
        response_status: 502,
        connection_error: true,
        error_class: Some(ErrorClass::ClientDisconnect),
        backend_elapsed: Duration::from_millis(50),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 4);
    assert_eq!(snapshot.samples, 0);
}

#[test]
fn adaptive_concurrency_caps_tracked_target_keys() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Backend,
        max_tracked_keys: 1,
        min_limit: 1,
        initial_limit: 2,
        max_limit: 2,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    });
    let first_target = target("a1.example.com", 8080);
    let second_target = target("a2.example.com", 8080);

    let first = limiter
        .try_acquire(&proxy, Some(&first_target), Arc::clone(&config))
        .expect("first distinct backend key should be admitted");
    let same_key = limiter
        .try_acquire(&proxy, Some(&first_target), Arc::clone(&config))
        .expect("existing backend key should not consume another tracked-key slot");
    assert_eq!(limiter.tracked_keys_count(), 1);

    // A new target beyond the cap fails OPEN — admitted with an untracked permit
    // rather than rejected — so the key cap can never black-hole a new target.
    // The overflow key is not inserted, so tracked_keys stays at the cap.
    let overflow = limiter
        .try_acquire(&proxy, Some(&second_target), Arc::clone(&config))
        .expect("a new target beyond the cap must fail open, not reject");
    assert_eq!(limiter.tracked_keys_count(), 1);

    drop(first);
    drop(same_key);
    drop(overflow);
}

#[test]
fn adaptive_concurrency_supports_http_family_backend_admission() {
    let plugin = AdaptiveConcurrency::new(&json!({}), PluginHttpClient::default())
        .expect("default config should be valid");

    assert!(plugin.is_backend_admission_plugin());
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Http));
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
    assert!(
        plugin
            .supported_protocols()
            .contains(&ProxyProtocol::WebSocket)
    );
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Tcp));
}

#[test]
fn adaptive_concurrency_validates_bounds() {
    let err = match AdaptiveConcurrency::new(
        &json!({
            "min_limit": 4,
            "initial_limit": 2,
            "max_limit": 8
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("invalid bounds should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("initial_limit"));

    let err = match AdaptiveConcurrency::new(
        &json!({
            "key_by": "consumer"
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("unsupported key_by should be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unsupported key_by"));
}

#[test]
fn adaptive_concurrency_ignores_request_body_too_large_samples() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // An oversized *client* upload surfaces as a gateway 413
    // (`RequestBodyTooLarge`): it is the request's fault, not the backend's, so
    // it must neither grow nor shrink the limit and must not record a sample.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 413,
        connection_error: false,
        error_class: Some(ErrorClass::RequestBodyTooLarge),
        backend_elapsed: Duration::from_millis(50),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 4);
    assert_eq!(snapshot.samples, 0);

    drop(permit);
}

#[test]
fn adaptive_concurrency_shrinks_on_oversized_backend_response() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // A backend response that overflows the configured max body size is a
    // backend fault even though the status line (200) looked healthy before the
    // overflow was detected: it must shrink the limit, not be counted as a fast
    // success. Mirrors the gateway sending a 502 to the client.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: Some(ErrorClass::ResponseBodyTooLarge),
        backend_elapsed: Duration::from_millis(5),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.limit, 2);
    assert_eq!(snapshot.samples, 0);

    drop(permit);
}

#[test]
fn adaptive_concurrency_completed_success_grows_limit_at_capacity() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = growth_config(1, 4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // in_flight == limit == 1: a completed, fast success probes for more
    // capacity and grows the limit (standard additive increase). This is the
    // baseline that the WebSocket holding path below must NOT trigger.
    permit.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(
        snapshot.limit, 2,
        "a completed success at capacity grows the limit"
    );

    drop(permit);
}

#[test]
fn adaptive_concurrency_held_session_success_does_not_grow_limit() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = growth_config(1, 4);
    let permit = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("request should be admitted");

    // A WebSocket handshake records its outcome while the session's permit is
    // still held (in_flight stays 1 == limit). Growing here would ratchet the
    // limit up on every concurrent session and defeat the in-flight session
    // cap, so the holding variant records the latency sample but must NOT grow
    // the limit. Contrast with `..._completed_success_grows_limit_at_capacity`,
    // which uses the identical config and does grow.
    permit.record_backend_outcome_holding(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(
        snapshot.limit, 1,
        "a held (long-lived session) success must not grow the limit"
    );
    assert_eq!(
        snapshot.samples, 1,
        "the handshake latency sample is still recorded"
    );

    drop(permit);
}

#[test]
fn adaptive_concurrency_shrinks_on_high_latency_samples() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit: 4,
        max_limit: 4,
        min_samples: 2,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    });

    // Sample 1 establishes the baseline (1ms). Below min_samples, no decision.
    let first = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("first request admitted");
    first.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });
    drop(first);

    // Sample 2 is far above target (baseline * 1.5): the EWMA crosses the target
    // and the limit shrinks. This exercises the latency control path directly,
    // not a 5xx / oversized-body failure outcome.
    let second = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("second request admitted");
    second.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(100),
    });
    drop(second);

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(snapshot.samples, 2);
    assert_eq!(
        snapshot.limit, 2,
        "a high-latency healthy sample must shrink the limit via the EWMA path"
    );
}

#[test]
fn adaptive_concurrency_shadow_mode_admits_past_limit() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit: 1,
        max_limit: 1,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: true,
        expose_headers: false,
    });

    let first = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("first request admitted");
    // in_flight (1) >= limit (1), but shadow mode must never reject.
    let second = limiter
        .try_acquire(&proxy, None, Arc::clone(&config))
        .expect("shadow mode must admit past the limit");

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("state should exist after acquire");
    assert_eq!(
        snapshot.in_flight, 2,
        "both requests are counted in shadow mode"
    );
    assert_eq!(snapshot.rejections, 0, "shadow mode records no rejections");

    drop(first);
    drop(second);
}

#[test]
fn adaptive_concurrency_shadow_mode_fails_open_at_key_cap() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Backend,
        max_tracked_keys: 1,
        min_limit: 1,
        initial_limit: 1,
        max_limit: 1,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: true,
        expose_headers: false,
    });
    let first_target = target("a1.example.com", 8080);
    let second_target = target("a2.example.com", 8080);

    let _first = limiter
        .try_acquire(&proxy, Some(&first_target), Arc::clone(&config))
        .expect("first key tracked");
    // The cap is exhausted; shadow mode must never reject, so the new target
    // fails open rather than emitting a 503.
    let _overflow = limiter
        .try_acquire(&proxy, Some(&second_target), Arc::clone(&config))
        .expect("shadow mode must never reject, even at the key cap");
    assert_eq!(limiter.tracked_keys_count(), 1);
}

#[test]
fn adaptive_concurrency_upstream_scope_shares_limit_across_proxies() {
    // Two distinct proxies sharing one upstream share a single upstream-scoped
    // limit for a given backend target.
    let proxy_a: Proxy = serde_json::from_value(json!({
        "id": "proxy-a",
        "namespace": "default",
        "upstream_id": "up-1",
        "backend_host": "backend.local",
        "backend_port": 8080
    }))
    .expect("proxy a should deserialize");
    let proxy_b: Proxy = serde_json::from_value(json!({
        "id": "proxy-b",
        "namespace": "default",
        "upstream_id": "up-1",
        "backend_host": "backend.local",
        "backend_port": 8080
    }))
    .expect("proxy b should deserialize");
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Upstream,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit: 1,
        max_limit: 1,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.5,
        increase_step: 1,
        shadow_mode: false,
        expose_headers: false,
    });
    let tgt = target("backend.local", 8080);

    let first = limiter
        .try_acquire(&proxy_a, Some(&tgt), Arc::clone(&config))
        .expect("first admitted under the shared upstream scope");
    // Same upstream + same target via a different proxy resolves to the same key,
    // so it hits the shared limit and is rejected.
    let second = limiter.try_acquire(&proxy_b, Some(&tgt), Arc::clone(&config));
    assert!(
        second.is_err(),
        "a second proxy sharing the upstream must hit the shared limit"
    );
    // Exactly one tracked key — shared across both proxies, not one per proxy.
    assert_eq!(limiter.tracked_keys_count(), 1);

    drop(first);
}

#[test]
fn adaptive_concurrency_rejects_every_unknown_policy_key() {
    for unknown in [
        "key_byy",
        "max_tracked_key",
        "min_limt",
        "initial_limt",
        "max_limt",
        "min_sample",
        "target_latency_multipler",
        "decrease_raio",
        "increase_setp",
        "shadow_mod",
        "expose_header",
    ] {
        let mut config = serde_json::Map::new();
        config.insert(unknown.to_string(), json!(1));
        let error = AdaptiveConcurrency::new(
            &serde_json::Value::Object(config),
            PluginHttpClient::default(),
        )
        .err()
        .expect("unknown adaptive policy key must be rejected");
        assert!(
            error.contains(unknown),
            "unexpected validation error: {error}"
        );
        assert!(
            error.contains("allowed keys"),
            "unexpected validation error: {error}"
        );
    }
}

#[test]
fn adaptive_concurrency_old_cohort_cannot_undo_failure_decrease() {
    let proxy = proxy();
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = Arc::new(AdaptiveConcurrencyConfig {
        key_by: AdaptiveConcurrencyKeyBy::Proxy,
        max_tracked_keys: 10_000,
        min_limit: 1,
        initial_limit: 100,
        max_limit: 100,
        min_samples: 1,
        target_latency_multiplier: 1.5,
        decrease_ratio: 0.8,
        increase_step: 10,
        shadow_mode: false,
        expose_headers: false,
    });
    let mut old_cohort = Vec::new();
    for _ in 0..100 {
        old_cohort.push(
            limiter
                .try_acquire(&proxy, None, Arc::clone(&config))
                .expect("the initial cohort should fill the limit"),
        );
    }

    // A healthy completion ordered before the failure may observe saturation,
    // but cannot grow past max_limit. The following failure is the backoff
    // linearization point for every still-live member of this cohort.
    old_cohort[0].record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });
    old_cohort[1].record_backend_outcome(BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });
    for permit in &old_cohort[2..12] {
        permit.record_backend_outcome(BackendAdmissionOutcome {
            response_status: 200,
            connection_error: false,
            error_class: None,
            backend_elapsed: Duration::from_millis(1),
        });
    }

    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("cohort state should exist");
    assert_eq!(snapshot.limit, 80);

    drop(old_cohort);
    let mut recovery_cohort = Vec::new();
    for _ in 0..80 {
        recovery_cohort.push(
            limiter
                .try_acquire(&proxy, None, Arc::clone(&config))
                .expect("the reduced limit should admit a new cohort"),
        );
    }
    recovery_cohort[0].record_backend_outcome(BackendAdmissionOutcome {
        response_status: 200,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });
    let snapshot = limiter
        .snapshot(&proxy, None, AdaptiveConcurrencyKeyBy::Proxy)
        .expect("recovery state should exist");
    assert_eq!(snapshot.limit, 90);
}

#[test]
fn adaptive_concurrency_incremental_reload_keeps_streaming_permit_accounted() {
    let config = cache_config(
        "proxy",
        json!({"min_limit": 1, "initial_limit": 1, "max_limit": 1}),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let held = expect_admitted(acquire_from_cache(&cache, &config));
    held.record_backend_outcome_holding(BackendAdmissionOutcome {
        response_status: 101,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let mut reloaded = config.clone();
    reloaded.proxies[0].name = Some("unrelated proxy rename".to_string());
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("unrelated proxy reload should rebuild the plugin list");

    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(held);
    let released = expect_admitted(acquire_from_cache(&cache, &reloaded));
    drop(released);
}

#[test]
fn adaptive_concurrency_global_rebuild_keeps_old_session_accounted() {
    let config = cache_config(
        "global",
        json!({"min_limit": 1, "initial_limit": 1, "max_limit": 1}),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let held = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "logging-1",
            "namespace": "default",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {}
        }))
        .expect("sibling global plugin should deserialize"),
    );
    cache
        .apply_delta(&reloaded, &HashSet::new(), &[], true)
        .expect("global plugin generation should rebuild");

    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(held);
    let released = expect_admitted(acquire_from_cache(&cache, &reloaded));
    drop(released);
}

#[tokio::test]
async fn adaptive_concurrency_global_route_refresh_preserves_unrelated_global_state() {
    let mut config = cache_config(
        "global",
        json!({
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2,
            "shadow_mode": true
        }),
    );
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "rate-limit-1",
            "namespace": "default",
            "plugin_name": "rate_limiting",
            "scope": "global",
            "enabled": true,
            "config": {
                "limit_by": "ip",
                "limits": [{
                    "scope": "default",
                    "window_seconds": 60,
                    "max_requests": 1
                }]
            }
        }))
        .expect("rate limiting config should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let original_rate_limiter = cache
        .get_plugins("default", "proxy-1")
        .iter()
        .find(|plugin| plugin.name() == "rate_limiting")
        .cloned()
        .expect("global rate limiter should be cached");
    let mut original_request =
        RequestContext::new("192.0.2.20".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        original_rate_limiter
            .on_request_received(&mut original_request)
            .await,
        PluginResult::Continue
    ));
    let held = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.proxies[0].backend_host = "replacement.local".to_string();
    cache
        .apply_delta(&reloaded, &HashSet::new(), &[], false)
        .expect("global adaptive route refresh should publish");

    let replacement_rate_limiter = cache
        .get_plugins("default", "proxy-1")
        .iter()
        .find(|plugin| plugin.name() == "rate_limiting")
        .cloned()
        .expect("global rate limiter should remain cached");
    assert!(
        Arc::ptr_eq(&original_rate_limiter, &replacement_rate_limiter),
        "adaptive-only route refresh must preserve unrelated global instances"
    );
    let mut replacement_request =
        RequestContext::new("192.0.2.20".to_string(), "GET".to_string(), "/".to_string());
    assert!(matches!(
        replacement_rate_limiter
            .on_request_received(&mut replacement_request)
            .await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));
    let replacement_adaptive = expect_admitted(acquire_from_cache(&cache, &reloaded));
    drop(replacement_adaptive);
    drop(held);
}

#[test]
fn adaptive_concurrency_compatible_reload_keeps_pinned_old_view_admitted() {
    let config = cache_config(
        "proxy",
        json!({"min_limit": 1, "initial_limit": 2, "max_limit": 2}),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_view = adaptive_plugin_from_cache(&cache);

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config["max_limit"] = json!(3);
    cache
        .rebuild(&reloaded)
        .expect("compatible bounds change should publish");

    let old_view_permit = expect_admitted(acquire_from_plugin(&old_view, &config.proxies[0], None));
    let new_view_permit = expect_admitted(acquire_from_cache(&cache, &reloaded));
    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(old_view_permit);
    drop(new_view_permit);
}

#[test]
fn adaptive_concurrency_pinned_old_view_uses_replacement_admission_bounds() {
    let config = cache_config(
        "proxy",
        json!({
            "min_limit": 10,
            "initial_limit": 10,
            "max_limit": 10,
            "shadow_mode": true
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_view = adaptive_plugin_from_cache(&cache);

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config = json!({
        "min_limit": 1,
        "initial_limit": 1,
        "max_limit": 1,
        "shadow_mode": false
    });
    cache
        .rebuild(&reloaded)
        .expect("compatible emergency limit decrease should publish");

    let held = expect_admitted(acquire_from_plugin(&old_view, &config.proxies[0], None));
    assert_rejected(acquire_from_plugin(&old_view, &config.proxies[0], None));
    drop(held);
}

#[test]
fn adaptive_concurrency_pinned_old_view_uses_replacement_header_policy() {
    let config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1,
            "expose_headers": true
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_view = adaptive_plugin_from_cache(&cache);

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config["expose_headers"] = json!(false);
    cache
        .rebuild(&reloaded)
        .expect("compatible header policy change should publish");

    let held = expect_admitted(acquire_from_plugin(&old_view, &config.proxies[0], None));
    match acquire_from_plugin(&old_view, &config.proxies[0], None) {
        BackendAdmissionDecision::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 503);
            assert!(
                !headers.contains_key("x-adaptive-concurrency-limit"),
                "the replacement policy disabled adaptive limit headers"
            );
            assert!(
                !headers.contains_key("x-adaptive-concurrency-inflight"),
                "the replacement policy disabled adaptive in-flight headers"
            );
        }
        _ => panic!("the pinned old view should enforce the replacement limit"),
    }
    drop(held);
}

#[test]
fn adaptive_concurrency_scoped_detach_and_reattach_starts_fresh_state() {
    for scope in ["proxy", "proxy_group"] {
        let config = cache_config(
            scope,
            json!({"min_limit": 1, "initial_limit": 1, "max_limit": 1}),
        );
        let cache = PluginCache::new(&config).expect("initial cache should build");
        let detached_generation = expect_admitted(acquire_from_cache(&cache, &config));

        let mut detached = config.clone();
        detached.proxies[0].plugins.clear();
        cache
            .apply_delta(
                &detached,
                &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
                &[],
                false,
            )
            .expect("last scoped association should detach");
        assert!(
            cache
                .get_plugins("default", "proxy-1")
                .iter()
                .all(|plugin| plugin.name() != "adaptive_concurrency"),
            "{scope} policy should be absent after its last association is removed"
        );

        cache
            .apply_delta(
                &config,
                &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
                &[],
                false,
            )
            .expect("scoped policy should reattach");
        let fresh_generation = expect_admitted(acquire_from_cache(&cache, &config));
        drop(fresh_generation);
        drop(detached_generation);
    }
}

#[test]
fn adaptive_concurrency_structural_config_change_does_not_wait_for_old_permits() {
    let config = cache_config(
        "proxy",
        json!({
            "key_by": "proxy_target",
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2,
            "shadow_mode": true,
            "expose_headers": true
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_view = adaptive_plugin_from_cache(&cache);
    let held = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config["key_by"] = json!("backend_target");
    cache
        .rebuild(&reloaded)
        .expect("valid key-space change should publish");

    // The replacement has an independent tracking space. A long-lived permit
    // from the retired space must not pin the structural handoff.
    let new_generation = expect_admitted(acquire_from_cache(&cache, &reloaded));
    assert_generation_handoff_rejected_without_headers(acquire_from_plugin(
        &old_view,
        &config.proxies[0],
        None,
    ));
    drop(new_generation);
    drop(held);
    drop(old_view);
}

#[test]
fn adaptive_concurrency_lower_key_cap_uses_independent_tracking_space() {
    let config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 2,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_view = adaptive_plugin_from_cache(&cache);
    let retired_permit = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config["max_tracked_keys"] = json!(1);
    cache
        .rebuild(&reloaded)
        .expect("lower key cap should publish an independent tracking space");

    let replacement = expect_admitted(acquire_from_cache(&cache, &reloaded));
    assert_rejected(acquire_from_cache(&cache, &reloaded));
    assert_rejected(acquire_from_plugin(&old_view, &config.proxies[0], None));
    drop(replacement);
    drop(retired_permit);
}

#[test]
fn adaptive_concurrency_replacement_uses_its_own_target_headers() {
    let config = cache_config(
        "proxy",
        json!({
            "key_by": "proxy_target",
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 100,
            "expose_headers": true
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let held = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config["key_by"] = json!("backend_target");
    cache
        .rebuild(&reloaded)
        .expect("structural key-space change should publish");

    let replacement_permit = expect_admitted(acquire_from_cache(&cache, &reloaded));
    match acquire_from_cache(&cache, &reloaded) {
        BackendAdmissionDecision::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(
                headers
                    .get("x-adaptive-concurrency-limit")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(
                headers
                    .get("x-adaptive-concurrency-inflight")
                    .map(String::as_str),
                Some("1")
            );
        }
        _ => panic!("a genuine per-target limit rejection should expose target headers"),
    }
    drop(replacement_permit);
    drop(held);
}

#[test]
fn adaptive_concurrency_overlapping_structural_reloads_remain_independent() {
    let config = cache_config(
        "proxy",
        json!({
            "key_by": "proxy_target",
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let oldest_view = adaptive_plugin_from_cache(&cache);
    let retired_permit = expect_admitted(acquire_from_cache(&cache, &config));

    let mut first_reload = config.clone();
    first_reload.plugin_configs[0].config["key_by"] = json!("backend_target");
    cache
        .rebuild(&first_reload)
        .expect("first structural generation should publish");
    let middle_view = adaptive_plugin_from_cache(&cache);
    let middle_permit = expect_admitted(acquire_from_cache(&cache, &first_reload));

    let mut newest_reload = first_reload.clone();
    newest_reload.plugin_configs[0].config["key_by"] = json!("upstream_target");
    cache
        .rebuild(&newest_reload)
        .expect("overlapping structural generation should publish");
    let newest_permit = expect_admitted(acquire_from_cache(&cache, &newest_reload));
    assert_rejected(acquire_from_plugin(&oldest_view, &config.proxies[0], None));
    assert_rejected(acquire_from_plugin(
        &middle_view,
        &first_reload.proxies[0],
        None,
    ));
    assert_rejected(acquire_from_cache(&cache, &newest_reload));
    drop(newest_permit);
    drop(middle_permit);
    drop(retired_permit);
}

#[test]
fn adaptive_concurrency_direct_target_reload_reclaims_retired_key_capacity() {
    let config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let retired_permit = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.proxies[0].backend_host = "replacement.local".to_string();
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("direct target change should publish");

    let held = expect_admitted(acquire_from_cache(&cache, &reloaded));
    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(held);
    drop(retired_permit);
}

#[test]
fn adaptive_concurrency_upstream_target_reload_reclaims_retired_key_capacity() {
    let mut config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1,
            "expose_headers": true
        }),
    );
    config.proxies[0].upstream_id = Some("upstream-1".to_string());
    config.upstreams.push(
        serde_json::from_value(json!({
            "id": "upstream-1",
            "namespace": "default",
            "targets": [{"host": "first.local", "port": 8080}]
        }))
        .expect("upstream should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let first_target = config.upstreams[0].targets[0].clone();
    let plugin = adaptive_plugin_from_cache(&cache);
    let retired_permit = expect_admitted(acquire_from_plugin(
        &plugin,
        &config.proxies[0],
        Some(&first_target),
    ));

    let mut reloaded = config.clone();
    reloaded.upstreams[0].targets[0].host = "replacement.local".to_string();
    cache
        .apply_delta(&reloaded, &HashSet::new(), &[], false)
        .expect("upstream-only target change should rebuild the adaptive policy");

    let replacement_target = &reloaded.upstreams[0].targets[0];
    let replacement_plugin = adaptive_plugin_from_cache(&cache);
    let held = expect_admitted(acquire_from_plugin(
        &replacement_plugin,
        &reloaded.proxies[0],
        Some(replacement_target),
    ));
    match acquire_from_plugin(
        &replacement_plugin,
        &reloaded.proxies[0],
        Some(replacement_target),
    ) {
        BackendAdmissionDecision::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 503);
            assert_eq!(
                headers
                    .get("x-adaptive-concurrency-limit")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(
                headers
                    .get("x-adaptive-concurrency-inflight")
                    .map(String::as_str),
                Some("1")
            );
        }
        _ => panic!("replacement target should enforce its independent limit"),
    }
    drop(held);
    drop(retired_permit);
}

#[test]
fn adaptive_concurrency_configured_upstream_scale_out_keeps_old_permit_active() {
    let mut config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 2,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    config.proxies[0].upstream_id = Some("upstream-1".to_string());
    config.upstreams.push(
        serde_json::from_value(json!({
            "id": "upstream-1",
            "namespace": "default",
            "targets": [{"host": "first.local", "port": 8080}]
        }))
        .expect("upstream should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let first_target = config.upstreams[0].targets[0].clone();
    let held_old_target = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &config.proxies[0],
        Some(&first_target),
    ));

    let mut reloaded = config.clone();
    reloaded.upstreams[0]
        .targets
        .push(target("second.local", 8080));
    cache
        .apply_delta(&reloaded, &HashSet::new(), &[], false)
        .expect("configured upstream scale-out should publish");

    let added_target = &reloaded.upstreams[0].targets[1];
    let added_target_permit = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &reloaded.proxies[0],
        Some(added_target),
    ));
    drop(added_target_permit);
    drop(held_old_target);
}

#[test]
fn adaptive_concurrency_proxy_group_association_growth_keeps_old_permit_active() {
    let config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "proxy-1",
                "namespace": "default",
                "listen_path": "/one",
                "backend_host": "first.local",
                "backend_port": 8080,
                "plugins": [{"plugin_config_id": "adaptive-1"}]
            },
            {
                "id": "proxy-2",
                "namespace": "default",
                "listen_path": "/two",
                "backend_host": "second.local",
                "backend_port": 8080,
                "plugins": []
            }
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "adaptive-1",
            "namespace": "default",
            "plugin_name": "adaptive_concurrency",
            "scope": "proxy_group",
            "enabled": true,
            "config": {
                "max_tracked_keys": 2,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }
        }]
    }))
    .expect("proxy-group scale-out config should deserialize");
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let held_old_target = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_for_proxy(&cache, "proxy-1"),
        &config.proxies[0],
        None,
    ));

    let mut reloaded = config.clone();
    reloaded.proxies[1].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "adaptive-1"}))
            .expect("proxy-group association should deserialize"),
    );
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-2")]),
            &[],
            false,
        )
        .expect("proxy-group association scale-out should publish");

    let added_target_permit = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_for_proxy(&cache, "proxy-2"),
        &reloaded.proxies[1],
        None,
    ));
    drop(added_target_permit);
    drop(held_old_target);
}

#[test]
fn adaptive_concurrency_upstream_port_scope_change_resets_key_space() {
    let mut config = cache_config(
        "proxy",
        json!({
            "key_by": "backend_target",
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2,
            "shadow_mode": true,
            "expose_headers": true
        }),
    );
    config.proxies[0].upstream_id = Some("upstream-1".to_string());
    config.proxies[0].backend_port = 8080;
    config.upstreams.push(
        serde_json::from_value(json!({
            "id": "upstream-1",
            "namespace": "default",
            "targets": [
                {"host": "first.local", "port": 8080},
                {"host": "second.local", "port": 9090}
            ],
            "port_overrides": {
                "8080": {"connect_timeout_ms": 100},
                "9090": {"connect_timeout_ms": 100}
            }
        }))
        .expect("multi-port upstream should deserialize"),
    );
    config.resolve_dispatch_port_overrides();
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let retired_view = adaptive_plugin_from_cache(&cache);
    let first_target = config.upstreams[0].targets[0].clone();
    let held = expect_admitted(acquire_from_plugin(
        &retired_view,
        &config.proxies[0],
        Some(&first_target),
    ));

    let mut reloaded = config.clone();
    reloaded.proxies[0].backend_port = 9090;
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("effective upstream port lane change should publish");

    let second_target = &reloaded.upstreams[0].targets[1];
    assert_generation_handoff_rejected_without_headers(acquire_from_plugin(
        &retired_view,
        &config.proxies[0],
        Some(&first_target),
    ));
    let replacement_view = adaptive_plugin_from_cache(&cache);
    let first_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &reloaded.proxies[0],
        Some(second_target),
    ));
    let second_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &reloaded.proxies[0],
        Some(second_target),
    ));
    let shadow_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &reloaded.proxies[0],
        Some(second_target),
    ));
    drop(shadow_replacement);
    drop(first_replacement);
    drop(second_replacement);
    drop(held);
}

#[test]
fn adaptive_concurrency_global_inventory_excludes_scoped_overrides() {
    let config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "proxy-1",
                "namespace": "default",
                "listen_path": "/one",
                "backend_host": "one.local",
                "backend_port": 8080,
                "plugins": []
            },
            {
                "id": "proxy-2",
                "namespace": "default",
                "listen_path": "/two",
                "backend_host": "two.local",
                "backend_port": 8080,
                "plugins": []
            }
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "adaptive-global",
            "namespace": "default",
            "plugin_name": "adaptive_concurrency",
            "scope": "global",
            "enabled": true,
            "config": {
                "max_tracked_keys": 1,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }
        }]
    }))
    .expect("two-proxy global config should deserialize");
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let proxy_two_plugin = adaptive_plugin_for_proxy(&cache, "proxy-2");
    drop(expect_admitted(acquire_from_plugin(
        &proxy_two_plugin,
        &config.proxies[1],
        None,
    )));

    let mut reloaded = config.clone();
    reloaded.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "adaptive-proxy-two",
            "namespace": "default",
            "plugin_name": "adaptive_concurrency",
            "scope": "proxy",
            "proxy_id": "proxy-2",
            "enabled": true,
            "config": {
                "max_tracked_keys": 1,
                "min_limit": 1,
                "initial_limit": 1,
                "max_limit": 1
            }
        }))
        .expect("scoped override should deserialize"),
    );
    reloaded.proxies[1].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "adaptive-proxy-two"}))
            .expect("scoped association should deserialize"),
    );
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-2")]),
            &[],
            false,
        )
        .expect("scoped adaptive override should publish");

    let proxy_one_plugin = adaptive_plugin_for_proxy(&cache, "proxy-1");
    let held = expect_admitted(acquire_from_plugin(
        &proxy_one_plugin,
        &reloaded.proxies[0],
        None,
    ));
    assert_rejected(acquire_from_plugin(
        &proxy_one_plugin,
        &reloaded.proxies[0],
        None,
    ));
    drop(held);
}

#[test]
fn adaptive_concurrency_route_override_change_resets_target_key_space() {
    let mut config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "route-dispatch-1",
            "namespace": "default",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy_group",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "first-override.local",
                        "backend_port": 8080
                    }
                }]
            }
        }))
        .expect("route dispatch config should deserialize"),
    );
    config.proxies[0].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "route-dispatch-1"}))
            .expect("route dispatch association should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let plugin = adaptive_plugin_from_cache(&cache);
    let mut first_effective_proxy = config.proxies[0].clone();
    first_effective_proxy.backend_host = "first-override.local".to_string();
    drop(expect_admitted(acquire_from_plugin(
        &plugin,
        &first_effective_proxy,
        None,
    )));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[1].config["rules"][0]["destination"]["backend_host"] =
        json!("replacement-override.local");
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("route override change should publish");

    let replacement_plugin = adaptive_plugin_from_cache(&cache);
    let mut replacement_effective_proxy = reloaded.proxies[0].clone();
    replacement_effective_proxy.backend_host = "replacement-override.local".to_string();
    let held = expect_admitted(acquire_from_plugin(
        &replacement_plugin,
        &replacement_effective_proxy,
        None,
    ));
    assert_rejected(acquire_from_plugin(
        &replacement_plugin,
        &replacement_effective_proxy,
        None,
    ));
    drop(held);
}

#[test]
fn adaptive_concurrency_unchanged_upstream_subset_stays_compatible() {
    let mut config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2
        }),
    );
    config.proxies[0].upstream_id = Some("shared-upstream".to_string());
    config.proxies[0].upstream_subset = Some("blue".to_string());
    config.upstreams.push(
        serde_json::from_value(json!({
            "id": "shared-upstream",
            "namespace": "default",
            "targets": [
                {
                    "host": "blue.local",
                    "port": 8080,
                    "tags": {"version": "blue"}
                },
                {
                    "host": "green.local",
                    "port": 8080,
                    "tags": {"version": "green"}
                }
            ],
            "subsets": [
                {"name": "blue", "labels": {"version": "blue"}},
                {"name": "green", "labels": {"version": "green"}}
            ]
        }))
        .expect("shared upstream should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let blue_target = config.upstreams[0].targets[0].clone();
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &config.proxies[0],
        Some(&blue_target),
    ));

    let mut reloaded = config.clone();
    reloaded.upstreams[0].targets[1].host = "replacement-green.local".to_string();
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("unchanged subset reload should publish");

    let second = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &reloaded.proxies[0],
        Some(&blue_target),
    ));
    drop(second);
    drop(held);
}

#[test]
fn adaptive_concurrency_route_non_destination_change_stays_compatible() {
    let mut config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2
        }),
    );
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "route-dispatch-1",
            "namespace": "default",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy_group",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "override.local",
                        "backend_port": 8080
                    }
                }]
            }
        }))
        .expect("route dispatch config should deserialize"),
    );
    config.proxies[0].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "route-dispatch-1"}))
            .expect("route dispatch association should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let mut effective_proxy = config.proxies[0].clone();
    effective_proxy.backend_host = "override.local".to_string();
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &effective_proxy,
        None,
    ));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[1].config["rules"][0]["rewrite"] = json!({"uri": "/rewritten"});
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("non-destination route edit should publish");

    let second = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &effective_proxy,
        None,
    ));
    drop(second);
    drop(held);
}

#[test]
fn adaptive_concurrency_mesh_direct_host_normalization_stays_compatible() {
    let mut config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2
        }),
    );
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "route-dispatch-1",
            "namespace": "default",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy_group",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "override.local",
                        "backend_port": 8080
                    }
                }]
            }
        }))
        .expect("route dispatch config should deserialize"),
    );
    config.proxies[0].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "route-dispatch-1"}))
            .expect("route dispatch association should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let mut effective_proxy = config.proxies[0].clone();
    effective_proxy.backend_host = "override.local".to_string();
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &effective_proxy,
        None,
    ));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[1].config["rules"][0]["destination"]["backend_host"] =
        json!("  OVERRIDE.Local  ");
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("normalized-equivalent direct host reload should publish");

    let replacement = adaptive_plugin_from_cache(&cache);
    let second = expect_admitted(acquire_from_plugin(&replacement, &effective_proxy, None));
    assert_rejected(acquire_from_plugin(&replacement, &effective_proxy, None));
    drop(second);
    drop(held);
}

#[test]
fn adaptive_concurrency_mesh_direct_tls_identity_change_resets_key_space() {
    let mut config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 2,
            "max_limit": 2,
            "shadow_mode": true,
            "expose_headers": true
        }),
    );
    config.plugin_configs.push(
        serde_json::from_value(json!({
            "id": "route-dispatch-1",
            "namespace": "default",
            "plugin_name": "mesh_route_dispatch",
            "scope": "proxy_group",
            "enabled": true,
            "config": {
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "override.local",
                        "backend_port": 443,
                        "backend_tls": {"sni": "FIRST.Route.Local"}
                    }
                }]
            }
        }))
        .expect("route dispatch config should deserialize"),
    );
    config.proxies[0].plugins.push(
        serde_json::from_value(json!({"plugin_config_id": "route-dispatch-1"}))
            .expect("route dispatch association should deserialize"),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let mut effective_proxy = config.proxies[0].clone();
    effective_proxy.backend_host = "override.local".to_string();
    effective_proxy.backend_port = 443;
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &effective_proxy,
        None,
    ));

    let mut normalized_equivalent = config.clone();
    normalized_equivalent.plugin_configs[1].config["rules"][0]["destination"]["backend_tls"]["sni"] =
        json!("first.route.local");
    cache
        .apply_delta(
            &normalized_equivalent,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("normalized-equivalent TLS identity should publish");
    drop(expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &effective_proxy,
        None,
    )));
    let retired_view = adaptive_plugin_from_cache(&cache);

    let mut replacement = normalized_equivalent.clone();
    replacement.plugin_configs[1].config["rules"][0]["destination"]["backend_tls"]["sni"] =
        json!("second.route.local");
    cache
        .apply_delta(
            &replacement,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("changed TLS identity should publish");
    assert_generation_handoff_rejected_without_headers(acquire_from_plugin(
        &retired_view,
        &effective_proxy,
        None,
    ));
    let replacement_view = adaptive_plugin_from_cache(&cache);
    let first_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &effective_proxy,
        None,
    ));
    let second_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &effective_proxy,
        None,
    ));
    let shadow_replacement = expect_admitted(acquire_from_plugin(
        &replacement_view,
        &effective_proxy,
        None,
    ));
    drop(shadow_replacement);
    drop(first_replacement);
    drop(second_replacement);
    drop(held);
}

#[test]
fn adaptive_concurrency_ai_and_mcp_non_destination_changes_stay_compatible() {
    for (plugin_name, route_config, host, port) in [
        (
            "ai_stream_router",
            json!({
                "providers": [{
                    "name": "test",
                    "provider_type": "openai",
                    "endpoint": "https://ai.example/v1/chat/completions",
                    "api_key": "sk-test",
                    "model_patterns": ["gpt-*"]
                }]
            }),
            "ai.example",
            443,
        ),
        (
            "mcp_gateway",
            json!({
                "mode": "transparent_proxy",
                "endpoint": {"path": "/mcp"},
                "servers": {
                    "tools": {
                        "upstream_url": "http://mcp.example:8081/mcp",
                        "namespace": "tools"
                    }
                }
            }),
            "mcp.example",
            8081,
        ),
    ] {
        let mut config = cache_config(
            "proxy",
            json!({
                "min_limit": 1,
                "initial_limit": 2,
                "max_limit": 2
            }),
        );
        config.plugin_configs.push(
            serde_json::from_value(json!({
                "id": "route-override-1",
                "namespace": "default",
                "plugin_name": plugin_name,
                "scope": "proxy_group",
                "enabled": true,
                "config": route_config
            }))
            .expect("route override config should deserialize"),
        );
        config.proxies[0].plugins.push(
            serde_json::from_value(json!({"plugin_config_id": "route-override-1"}))
                .expect("route override association should deserialize"),
        );
        let cache = PluginCache::new(&config).expect("initial cache should build");
        let mut effective_proxy = config.proxies[0].clone();
        effective_proxy.backend_host = host.to_string();
        effective_proxy.backend_port = port;
        let held = expect_admitted(acquire_from_plugin(
            &adaptive_plugin_from_cache(&cache),
            &effective_proxy,
            None,
        ));

        let mut reloaded = config.clone();
        match plugin_name {
            "ai_stream_router" => {
                reloaded.plugin_configs[1].config["inject_usage_options"] = json!(false);
            }
            "mcp_gateway" => {
                reloaded.plugin_configs[1].config["observability"] =
                    json!({"emit_metadata": false});
            }
            _ => unreachable!("test cases cover only route-override plugins"),
        }
        cache
            .apply_delta(
                &reloaded,
                &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
                &[],
                false,
            )
            .unwrap_or_else(|error| {
                panic!("{plugin_name} non-destination edit should publish: {error}")
            });

        let second = expect_admitted(acquire_from_plugin(
            &adaptive_plugin_from_cache(&cache),
            &effective_proxy,
            None,
        ));
        drop(second);
        drop(held);
    }
}

#[test]
fn adaptive_concurrency_route_priority_change_resets_winning_destination() {
    let mut config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    for (id, host, priority) in [
        ("route-dispatch-1", "first.local", 2994),
        ("route-dispatch-2", "second.local", 2996),
    ] {
        config.plugin_configs.push(
            serde_json::from_value(json!({
                "id": id,
                "namespace": "default",
                "plugin_name": "mesh_route_dispatch",
                "scope": "proxy_group",
                "enabled": true,
                "priority_override": priority,
                "config": {
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {
                            "backend_host": host,
                            "backend_port": 8080
                        }
                    }]
                }
            }))
            .expect("route dispatch config should deserialize"),
        );
        config.proxies[0].plugins.push(
            serde_json::from_value(json!({"plugin_config_id": id}))
                .expect("route dispatch association should deserialize"),
        );
    }
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let mut second_effective_proxy = config.proxies[0].clone();
    second_effective_proxy.backend_host = "second.local".to_string();
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &second_effective_proxy,
        None,
    ));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[1].priority_override = Some(2996);
    reloaded.plugin_configs[2].priority_override = Some(2994);
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("route priority change should publish");

    let mut first_effective_proxy = reloaded.proxies[0].clone();
    first_effective_proxy.backend_host = "first.local".to_string();
    let replacement = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &first_effective_proxy,
        None,
    ));
    assert_rejected(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &first_effective_proxy,
        None,
    ));
    drop(replacement);
    drop(held);
}

#[test]
fn adaptive_concurrency_route_association_order_resets_winning_destination() {
    let mut config = cache_config(
        "proxy",
        json!({
            "max_tracked_keys": 1,
            "min_limit": 1,
            "initial_limit": 1,
            "max_limit": 1
        }),
    );
    for (id, host) in [
        ("route-dispatch-1", "first.local"),
        ("route-dispatch-2", "second.local"),
    ] {
        config.plugin_configs.push(
            serde_json::from_value(json!({
                "id": id,
                "namespace": "default",
                "plugin_name": "mesh_route_dispatch",
                "scope": "proxy_group",
                "enabled": true,
                "config": {
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {
                            "backend_host": host,
                            "backend_port": 8080
                        }
                    }]
                }
            }))
            .expect("route dispatch config should deserialize"),
        );
        config.proxies[0].plugins.push(
            serde_json::from_value(json!({"plugin_config_id": id}))
                .expect("route dispatch association should deserialize"),
        );
    }
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let mut second_effective_proxy = config.proxies[0].clone();
    second_effective_proxy.backend_host = "second.local".to_string();
    let held = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &second_effective_proxy,
        None,
    ));

    let mut reloaded = config.clone();
    reloaded.proxies[0].plugins.swap(1, 2);
    cache
        .apply_delta(
            &reloaded,
            &HashSet::from([NamespacedResourceId::new("default", "proxy-1")]),
            &[],
            false,
        )
        .expect("route association reorder should publish");

    let mut first_effective_proxy = reloaded.proxies[0].clone();
    first_effective_proxy.backend_host = "first.local".to_string();
    let replacement = expect_admitted(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &first_effective_proxy,
        None,
    ));
    assert_rejected(acquire_from_plugin(
        &adaptive_plugin_from_cache(&cache),
        &first_effective_proxy,
        None,
    ));
    drop(replacement);
    drop(held);
}

#[test]
fn adaptive_concurrency_limit_change_counts_and_clamps_old_permits() {
    let config = cache_config(
        "proxy",
        json!({"min_limit": 1, "initial_limit": 2, "max_limit": 2}),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let first = expect_admitted(acquire_from_cache(&cache, &config));
    let second = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config = json!({"min_limit": 1, "initial_limit": 1, "max_limit": 1});
    cache
        .rebuild(&reloaded)
        .expect("valid limit decrease should publish");

    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(first);
    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(second);
    let replacement = expect_admitted(acquire_from_cache(&cache, &reloaded));
    drop(replacement);
}

#[test]
fn adaptive_concurrency_stale_generation_feedback_cannot_mutate_new_bounds() {
    let config = cache_config(
        "proxy",
        json!({
            "min_limit": 1,
            "initial_limit": 4,
            "max_limit": 4,
            "decrease_ratio": 0.5
        }),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let old_generation = expect_admitted(acquire_from_cache(&cache, &config));

    let mut reloaded = config.clone();
    reloaded.plugin_configs[0].config = json!({
        "min_limit": 4,
        "initial_limit": 4,
        "max_limit": 4,
        "decrease_ratio": 0.5
    });
    cache
        .rebuild(&reloaded)
        .expect("valid bounds change should publish");
    old_generation.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(1),
    });

    let mut new_generation = Vec::new();
    for _ in 0..3 {
        new_generation.push(expect_admitted(acquire_from_cache(&cache, &reloaded)));
    }
    assert_rejected(acquire_from_cache(&cache, &reloaded));
    drop(old_generation);
    drop(new_generation);
}

#[test]
fn adaptive_concurrency_invalid_reload_preserves_last_good_state() {
    let config = cache_config(
        "proxy",
        json!({"min_limit": 1, "initial_limit": 1, "max_limit": 1}),
    );
    let cache = PluginCache::new(&config).expect("initial cache should build");
    let held = expect_admitted(acquire_from_cache(&cache, &config));

    let mut invalid = config.clone();
    invalid.plugin_configs[0].config["max_limt"] = json!(8);
    let error = cache
        .rebuild(&invalid)
        .expect_err("unknown adaptive key must reject reload");
    assert!(
        error.contains("max_limt"),
        "unexpected reload error: {error}"
    );

    assert_rejected(acquire_from_cache(&cache, &config));
    drop(held);
    let released = expect_admitted(acquire_from_cache(&cache, &config));
    drop(released);
}

/// A shared (global / proxy-group) `adaptive_concurrency` instance serves
/// proxies from every namespace through ONE limiter, and `key_by =
/// proxy_target` is the default. The `proxy`-scope cache used to be keyed by
/// the bare `proxy.id` while caching the namespace-qualified
/// `proxy:{namespace}:{id}` scope, so the first tenant to warm the cache handed
/// its own scope to a second tenant's same-id proxy and both were admitted
/// against a single limiter row (issue #3094). Independent rows — and
/// independent in-flight accounting — are the observable.
#[test]
fn proxy_scope_cache_keeps_same_id_proxies_in_two_namespaces_independent() {
    let limiter = AdaptiveConcurrencyLimiter::new(16);
    let config = limiter_config(4);

    let mut tenant_a = proxy();
    tenant_a.namespace = "tenant-a".to_string();
    tenant_a.id = "api".to_string();
    let mut tenant_b = proxy();
    tenant_b.namespace = "tenant-b".to_string();
    tenant_b.id = "api".to_string();

    let backend = target("backend.local", 8080);

    let permit_a = limiter
        .try_acquire(&tenant_a, Some(&backend), Arc::clone(&config))
        .expect("tenant-a request should be admitted");
    assert_eq!(limiter.tracked_keys_count(), 1);

    let permit_b = limiter
        .try_acquire(&tenant_b, Some(&backend), Arc::clone(&config))
        .expect("tenant-b request should be admitted");
    assert_eq!(
        limiter.tracked_keys_count(),
        2,
        "same proxy id in two namespaces must own independent limiter rows"
    );

    let snapshot_a = limiter
        .snapshot(&tenant_a, Some(&backend), AdaptiveConcurrencyKeyBy::Proxy)
        .expect("tenant-a state should exist after acquire");
    let snapshot_b = limiter
        .snapshot(&tenant_b, Some(&backend), AdaptiveConcurrencyKeyBy::Proxy)
        .expect("tenant-b state should exist after acquire");
    assert_eq!(snapshot_a.in_flight, 1);
    assert_eq!(
        snapshot_b.in_flight, 1,
        "tenant-b in-flight must not accumulate onto tenant-a's row"
    );

    // Feedback on one tenant's row must not shrink the other tenant's limit.
    permit_a.record_backend_outcome(BackendAdmissionOutcome {
        response_status: 503,
        connection_error: false,
        error_class: None,
        backend_elapsed: Duration::from_millis(5),
    });
    let after_a = limiter
        .snapshot(&tenant_a, Some(&backend), AdaptiveConcurrencyKeyBy::Proxy)
        .expect("tenant-a state should still exist");
    let after_b = limiter
        .snapshot(&tenant_b, Some(&backend), AdaptiveConcurrencyKeyBy::Proxy)
        .expect("tenant-b state should still exist");
    assert_eq!(after_a.limit, 2, "tenant-a absorbs its own 503 backoff");
    assert_eq!(
        after_b.limit, 4,
        "tenant-b's limit must be untouched by tenant-a's backend failure"
    );

    drop(permit_a);
    drop(permit_b);
}
