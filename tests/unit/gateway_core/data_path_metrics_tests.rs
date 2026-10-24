//! Data-path Prometheus families (issue #4156): load shedding, upstream
//! health, circuit-breaker state, backend retries, pool saturation, and
//! frontend TLS admission.
//!
//! The DOC-10 contract suite already asserts HELP/TYPE/label-key parity for
//! these families against `docs/prometheus_metric_contract.json`. These tests
//! cover the *values* and the cardinality guarantee: an ejected target or an
//! open breaker must be attributable without any label carrying a resolved
//! endpoint address.

use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    CircuitBreakerConfig, GatewayConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Upstream,
    UpstreamTarget,
};
use ferrum_edge::data_path_metrics;
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::overload::OverloadState;
use ferrum_edge::service_discovery::merge_targets;
use std::sync::atomic::Ordering;

const NS_LABEL: &str = ",namespace=\"ferrum\"";

fn upstream_fixture() -> GatewayConfig {
    let json = serde_json::json!({
        "id": "orders",
        "namespace": "ferrum",
        "targets": [
            {"host": "orders-a.internal", "port": 8080},
            {"host": "orders-b.internal", "port": 8080},
            {"host": "orders-c.internal", "port": 8080}
        ]
    });
    let upstream: Upstream = serde_json::from_value(json).expect("upstream fixture");
    let mut config = GatewayConfig::default();
    config.upstreams.push(upstream);
    config
}

fn target_fixture(host: &str) -> UpstreamTarget {
    let json = serde_json::json!({"host": host, "port": 8080});
    serde_json::from_value(json).expect("target fixture")
}

fn passive_fixture() -> PassiveHealthCheck {
    let json = serde_json::json!({"unhealthy_threshold": 1});
    serde_json::from_value(json).expect("passive policy fixture")
}

/// Render the upstream-health families from the load balancer's active
/// target set, exactly as the `/metrics` scrape does.
fn render_health(load_balancer: &LoadBalancerCache, health: &HealthChecker) -> String {
    let mut out = String::new();
    data_path_metrics::render_upstream_health(&mut out, &load_balancer.load(), health, NS_LABEL);
    out
}

/// Every sample line for `metric` in `text`, without the trailing newline.
fn samples<'a>(text: &'a str, metric: &str) -> Vec<&'a str> {
    let with_labels = format!("{metric}{{");
    let bare = format!("{metric} ");
    text.lines()
        .filter(|line| line.starts_with(with_labels.as_str()) || line.starts_with(bare.as_str()))
        .collect()
}

#[test]
fn overload_families_render_the_live_shedding_state() {
    let overload = OverloadState::new();
    overload.reject_new_requests.store(true, Ordering::Relaxed);
    overload.disable_keepalive.store(true, Ordering::Relaxed);
    overload.port_exhaustion_events.store(7, Ordering::Relaxed);
    overload.active_requests.store(41, Ordering::Relaxed);
    overload.fd_current.store(900, Ordering::Relaxed);
    overload.fd_max.store(1000, Ordering::Relaxed);

    let mut out = String::new();
    data_path_metrics::render_overload(&mut out, &overload, NS_LABEL);

    assert!(
        out.contains("ferrum_overload_level{namespace=\"ferrum\"} 2"),
        "critical level must render as 2:\n{out}"
    );
    assert!(
        out.contains(
            "ferrum_overload_shedding_active{action=\"reject_new_requests\",namespace=\"ferrum\"} 1"
        ),
        "engaged action must render as 1:\n{out}"
    );
    assert!(
        out.contains(
            "ferrum_overload_shedding_active{action=\"reject_new_connections\",namespace=\"ferrum\"} 0"
        ),
        "disengaged actions must still render so recovery is a value change:\n{out}"
    );
    assert!(
        out.contains("ferrum_overload_port_exhaustion_events_total{namespace=\"ferrum\"} 7"),
        "{out}"
    );
    assert!(
        out.contains("ferrum_overload_active_requests{namespace=\"ferrum\"} 41"),
        "{out}"
    );
    assert!(
        out.contains("ferrum_overload_resource_current{resource=\"fd\",namespace=\"ferrum\"} 900"),
        "{out}"
    );
    assert!(
        out.contains("ferrum_overload_resource_limit{resource=\"fd\",namespace=\"ferrum\"} 1000"),
        "{out}"
    );

    // The closed action/resource sets must not grow with traffic.
    assert_eq!(samples(&out, "ferrum_overload_shedding_active").len(), 3);
    assert_eq!(samples(&out, "ferrum_overload_resource_current").len(), 3);
    assert_eq!(samples(&out, "ferrum_overload_resource_limit").len(), 3);
}

#[test]
fn overload_families_render_without_a_namespace_label() {
    let overload = OverloadState::new();
    let mut out = String::new();
    data_path_metrics::render_overload(&mut out, &overload, "");

    assert!(out.contains("\nferrum_overload_level 0\n"), "{out}");
    assert!(
        out.contains("ferrum_overload_shedding_active{action=\"disable_keepalive\"} 0"),
        "{out}"
    );
}

#[test]
fn active_and_passive_ejections_render_as_bounded_counts() {
    let config = upstream_fixture();
    let health = HealthChecker::new();
    health
        .active_unhealthy_targets
        .insert("ferrum|orders::orders-b.internal:8080".to_string(), 1);
    let passive = passive_fixture();
    health.report_response(
        "ferrum",
        "checkout-api",
        "orders",
        &target_fixture("orders-a.internal"),
        503,
        false,
        Some(&passive),
    );

    let out = render_health(&LoadBalancerCache::new(&config), &health);

    assert!(
        out.contains(
            "ferrum_upstream_targets{upstream_id=\"orders\",upstream_namespace=\"ferrum\",namespace=\"ferrum\"} 3"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "ferrum_upstream_unhealthy_targets{upstream_id=\"orders\",upstream_namespace=\"ferrum\",namespace=\"ferrum\"} 1"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "ferrum_proxy_passive_unhealthy_targets{proxy_id=\"checkout-api\",proxy_namespace=\"ferrum\",namespace=\"ferrum\"} 1"
        ),
        "{out}"
    );

    // One series per upstream / per proxy, never per target.
    assert_eq!(samples(&out, "ferrum_upstream_unhealthy_targets").len(), 1);
    assert_eq!(
        samples(&out, "ferrum_proxy_passive_unhealthy_targets").len(),
        1
    );
    assert!(
        !out.contains("orders-a.internal") && !out.contains("orders-b.internal"),
        "no target host:port may appear in any label:\n{out}"
    );
}

#[test]
fn a_healthy_upstream_still_publishes_a_zero_unhealthy_series() {
    let config = upstream_fixture();
    let health = HealthChecker::new();

    let out = render_health(&LoadBalancerCache::new(&config), &health);

    assert!(
        out.contains(
            "ferrum_upstream_unhealthy_targets{upstream_id=\"orders\",upstream_namespace=\"ferrum\",namespace=\"ferrum\"} 0"
        ),
        "recovery must be a value change, not a vanishing series:\n{out}"
    );
}

/// A discovery-only upstream with no static targets, a mixed upstream with one
/// static target, and a same-id upstream in another namespace that discovery
/// never touches.
fn discovery_fixture() -> GatewayConfig {
    let mut config = GatewayConfig::default();
    for json in [
        serde_json::json!({"id": "pods", "namespace": "ferrum", "targets": []}),
        serde_json::json!({
            "id": "mixed",
            "namespace": "ferrum",
            "targets": [{"host": "static-a.internal", "port": 8080}]
        }),
        serde_json::json!({
            "id": "pods",
            "namespace": "tenant",
            "targets": [{"host": "tenant-a.internal", "port": 8080}]
        }),
    ] {
        let upstream: Upstream = serde_json::from_value(json).expect("upstream fixture");
        config.upstreams.push(upstream);
    }
    config
}

/// Install `discovered` the way service discovery does: merge it under the
/// upstream's static targets, publish the merged set to the load balancer, and
/// prune active-health state for targets that left it.
fn install_discovered(
    load_balancer: &LoadBalancerCache,
    health: &HealthChecker,
    id: &str,
    static_targets: &[UpstreamTarget],
    discovered: &[UpstreamTarget],
) {
    let merged = merge_targets(static_targets, discovered);
    load_balancer.update_targets(
        "ferrum",
        id,
        merged.clone(),
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );
    health.remove_stale_targets("ferrum", id, &merged);
}

/// The value of one per-upstream gauge sample, if the series is present.
fn upstream_gauge(out: &str, metric: &str, namespace: &str, upstream_id: &str) -> Option<u64> {
    let prefix = format!(
        "{metric}{{upstream_id=\"{upstream_id}\",upstream_namespace=\"{namespace}\",namespace=\"ferrum\"}} "
    );
    out.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|value| value.parse().expect("gauge value"))
}

fn targets_and_unhealthy(out: &str, namespace: &str, upstream_id: &str) -> (u64, u64) {
    let targets = upstream_gauge(out, "ferrum_upstream_targets", namespace, upstream_id);
    let unhealthy = upstream_gauge(
        out,
        "ferrum_upstream_unhealthy_targets",
        namespace,
        upstream_id,
    );
    match (targets, unhealthy) {
        (Some(targets), Some(unhealthy)) => (targets, unhealthy),
        _ => panic!("missing series for {namespace}/{upstream_id}:\n{out}"),
    }
}

/// #6354: the ejection-ratio denominator counts the same merged static +
/// discovered target set the load balancer serves and active probes run
/// against, not only the configured `upstream.targets`.
#[test]
fn upstream_targets_count_the_discovered_active_target_set() {
    let config = discovery_fixture();
    let load_balancer = LoadBalancerCache::new(&config);
    let health = HealthChecker::new();
    let static_mixed = vec![target_fixture("static-a.internal")];

    let out = render_health(&load_balancer, &health);
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "pods"), (0, 0));
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "mixed"), (1, 0));

    install_discovered(
        &load_balancer,
        &health,
        "pods",
        &[],
        &[
            target_fixture("pod-a.internal"),
            target_fixture("pod-b.internal"),
            target_fixture("pod-c.internal"),
        ],
    );
    // The discovered copy of the static target is merged away, exactly as the
    // probe set is.
    install_discovered(
        &load_balancer,
        &health,
        "mixed",
        &static_mixed,
        &[
            target_fixture("static-a.internal"),
            target_fixture("pod-d.internal"),
        ],
    );
    for key in [
        "ferrum|pods::pod-a.internal:8080",
        "ferrum|pods::pod-b.internal:8080",
        "ferrum|mixed::pod-d.internal:8080",
    ] {
        health.active_unhealthy_targets.insert(key.to_string(), 1);
    }

    let out = render_health(&load_balancer, &health);
    assert_eq!(
        targets_and_unhealthy(&out, "ferrum", "pods"),
        (3, 2),
        "a discovery-only upstream must not report a zero denominator:\n{out}"
    );
    assert_eq!(
        targets_and_unhealthy(&out, "ferrum", "mixed"),
        (2, 1),
        "a mixed upstream must count static and discovered targets together:\n{out}"
    );
    assert_eq!(
        targets_and_unhealthy(&out, "tenant", "pods"),
        (1, 0),
        "the same upstream id in another namespace is a distinct series:\n{out}"
    );
    assert_eq!(samples(&out, "ferrum_upstream_targets").len(), 3, "{out}");
    assert!(
        !out.contains(".internal"),
        "no target host may appear in any label:\n{out}"
    );
}

/// #6354: the denominator follows staleness withdrawal, recovery, and endpoint
/// churn, and a withdrawn upstream keeps a zero-valued series.
#[test]
fn upstream_targets_follow_discovery_withdrawal_recovery_and_churn() {
    let config = discovery_fixture();
    let load_balancer = LoadBalancerCache::new(&config);
    let health = HealthChecker::new();
    let static_mixed = vec![target_fixture("static-a.internal")];
    let first = vec![
        target_fixture("pod-a.internal"),
        target_fixture("pod-b.internal"),
    ];

    install_discovered(&load_balancer, &health, "pods", &[], &first);
    install_discovered(&load_balancer, &health, "mixed", &static_mixed, &first);
    health
        .active_unhealthy_targets
        .insert("ferrum|pods::pod-a.internal:8080".to_string(), 1);
    let out = render_health(&load_balancer, &health);
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "pods"), (2, 1));
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "mixed"), (3, 0));

    // Staleness withdrawal republishes the static targets alone.
    install_discovered(&load_balancer, &health, "pods", &[], &[]);
    install_discovered(&load_balancer, &health, "mixed", &static_mixed, &[]);
    let out = render_health(&load_balancer, &health);
    assert_eq!(
        targets_and_unhealthy(&out, "ferrum", "pods"),
        (0, 0),
        "withdrawal must be a value change, not a vanishing series:\n{out}"
    );
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "mixed"), (1, 0));

    // Recovery republishes the discovered set.
    install_discovered(&load_balancer, &health, "pods", &[], &first);
    install_discovered(&load_balancer, &health, "mixed", &static_mixed, &first);
    let out = render_health(&load_balancer, &health);
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "pods"), (2, 0));
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "mixed"), (3, 0));

    // Churn: a replacement endpoint set of a different size. Health state for
    // an endpoint that left the set is pruned with it.
    health
        .active_unhealthy_targets
        .insert("ferrum|pods::pod-a.internal:8080".to_string(), 1);
    install_discovered(
        &load_balancer,
        &health,
        "pods",
        &[],
        &[
            target_fixture("pod-c.internal"),
            target_fixture("pod-d.internal"),
            target_fixture("pod-e.internal"),
        ],
    );
    health
        .active_unhealthy_targets
        .insert("ferrum|pods::pod-c.internal:8080".to_string(), 1);
    let out = render_health(&load_balancer, &health);
    assert_eq!(targets_and_unhealthy(&out, "ferrum", "pods"), (3, 1));
    assert_eq!(targets_and_unhealthy(&out, "tenant", "pods"), (1, 0));
}

#[test]
fn breaker_transitions_render_per_state_without_a_target_label() {
    let cache = CircuitBreakerCache::with_max_entries(64);
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        ..CircuitBreakerConfig::default()
    };
    let tripped = cache.get_or_create(
        "ferrum",
        "checkout-api",
        Some("orders-a.internal:8080"),
        &config,
    );
    let healthy = cache.get_or_create(
        "ferrum",
        "checkout-api",
        Some("orders-b.internal:8080"),
        &config,
    );
    tripped.record_failure(503, false, false);
    assert_eq!(tripped.state_name(), "open");
    assert_eq!(healthy.state_name(), "closed");

    let mut out = String::new();
    data_path_metrics::render_circuit_breakers(&mut out, &cache, NS_LABEL);

    assert!(
        out.contains(
            "ferrum_circuit_breakers{proxy_id=\"checkout-api\",proxy_namespace=\"ferrum\",state=\"open\",namespace=\"ferrum\"} 1"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "ferrum_circuit_breakers{proxy_id=\"checkout-api\",proxy_namespace=\"ferrum\",state=\"closed\",namespace=\"ferrum\"} 1"
        ),
        "{out}"
    );
    assert!(
        out.contains("ferrum_circuit_breaker_cache_entries{namespace=\"ferrum\"} 2"),
        "{out}"
    );
    assert!(
        out.contains("ferrum_circuit_breaker_cache_max_entries{namespace=\"ferrum\"} 64"),
        "{out}"
    );
    assert!(
        out.contains(
            "ferrum_circuit_breaker_cache_admission_refused_total{namespace=\"ferrum\"} 0"
        ),
        "ceiling pressure must be observable even while zero (#4516):\n{out}"
    );

    // Two per-target breakers collapse to exactly three per-proxy series.
    assert_eq!(samples(&out, "ferrum_circuit_breakers").len(), 3);
    assert!(
        !out.contains("orders-a.internal") && !out.contains("orders-b.internal"),
        "breaker target host:port must never become a label:\n{out}"
    );
}

#[test]
fn connection_pool_entries_render_one_series_per_closed_set_pool() {
    let pools = [
        ("http", 4_usize),
        ("grpc", 2),
        ("http2", 1),
        ("http3", 0),
        ("hbone", 0),
        ("mesh_mtls", 0),
    ];
    let mut out = String::new();
    data_path_metrics::render_connection_pools(&mut out, &pools, 32, NS_LABEL);

    assert!(
        out.contains("ferrum_connection_pool_entries{pool=\"http\",namespace=\"ferrum\"} 4"),
        "{out}"
    );
    assert!(
        out.contains("ferrum_connection_pool_max_idle_per_host{namespace=\"ferrum\"} 32"),
        "{out}"
    );
    assert_eq!(samples(&out, "ferrum_connection_pool_entries").len(), 6);
}

#[test]
fn direct_h1_pool_families_render_idle_dials_reuse_and_each_eviction_reason() {
    let stats = ferrum_edge::proxy::http2_pool::Http1PoolStats {
        idle_connections: 37,
        connections_opened: 120,
        connections_reused: 9_880,
        evicted_ceiling: 3,
        evicted_expired: 41,
        evicted_closed: 2,
        evicted_retired: 5,
    };
    let mut out = String::new();
    data_path_metrics::render_direct_h1_pool(&mut out, &stats, NS_LABEL);

    for line in [
        "# TYPE ferrum_connection_pool_h1_idle_connections gauge",
        "ferrum_connection_pool_h1_idle_connections{namespace=\"ferrum\"} 37",
        "# TYPE ferrum_connection_pool_h1_connections_opened_total counter",
        "ferrum_connection_pool_h1_connections_opened_total{namespace=\"ferrum\"} 120",
        "# TYPE ferrum_connection_pool_h1_connections_reused_total counter",
        "ferrum_connection_pool_h1_connections_reused_total{namespace=\"ferrum\"} 9880",
        "# TYPE ferrum_connection_pool_h1_idle_evictions_total counter",
        "ferrum_connection_pool_h1_idle_evictions_total{reason=\"ceiling\",namespace=\"ferrum\"} 3",
        "ferrum_connection_pool_h1_idle_evictions_total{reason=\"expired\",namespace=\"ferrum\"} 41",
        "ferrum_connection_pool_h1_idle_evictions_total{reason=\"closed\",namespace=\"ferrum\"} 2",
        "ferrum_connection_pool_h1_idle_evictions_total{reason=\"retired\",namespace=\"ferrum\"} 5",
    ] {
        assert!(
            out.lines().any(|candidate| candidate == line),
            "missing `{line}`:\n{out}"
        );
    }
    assert_eq!(
        samples(&out, "ferrum_connection_pool_h1_idle_evictions_total").len(),
        4,
        "exactly one series per eviction reason"
    );
}

#[test]
fn process_families_render_both_tls_reason_buckets_and_the_retry_counter() {
    data_path_metrics::record_backend_retry_attempt();
    data_path_metrics::record_frontend_tls_handshake_failure(
        data_path_metrics::FrontendTlsHandshakeFailure::Timeout,
    );
    data_path_metrics::record_frontend_tls_handshake_failure(
        data_path_metrics::FrontendTlsHandshakeFailure::Error,
    );

    let mut out = String::new();
    data_path_metrics::render_process_families(&mut out, NS_LABEL);

    // Values are process-global and other tests in this binary share them, so
    // assert the shape and monotonicity rather than an exact count.
    assert_eq!(
        samples(&out, "ferrum_backend_retry_attempts_total").len(),
        1
    );
    assert_eq!(
        samples(&out, "ferrum_frontend_tls_handshake_failures_total").len(),
        2
    );
    assert!(
        out.contains(
            "ferrum_frontend_tls_handshake_failures_total{reason=\"timeout\",namespace=\"ferrum\"}"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "ferrum_frontend_tls_handshake_failures_total{reason=\"error\",namespace=\"ferrum\"}"
        ),
        "{out}"
    );
    assert!(data_path_metrics::backend_retry_attempts_total() >= 1);
    let (timeouts, errors) = data_path_metrics::frontend_tls_handshake_failures_total();
    assert!(timeouts >= 1 && errors >= 1);
}

#[test]
fn process_families_render_every_backend_tls_reload_validation_kind() {
    use ferrum_edge::data_path_metrics::BackendTlsReloadValidationFailure;
    const FAMILY: &str = "ferrum_backend_tls_reload_validation_failures_total";

    let kind = BackendTlsReloadValidationFailure::RouteDispatchRule;
    let before = data_path_metrics::backend_tls_reload_validation_failures_total(kind);
    data_path_metrics::record_backend_tls_reload_validation_failure(kind);
    let after = data_path_metrics::backend_tls_reload_validation_failures_total(kind);
    assert!(after > before, "the recorded failure is counted");

    let mut out = String::new();
    data_path_metrics::render_process_families(&mut out, NS_LABEL);

    // Closed kind set: every bucket renders, even at zero.
    assert_eq!(samples(&out, FAMILY).len(), 3);
    for kind in ["proxy", "route_dispatch_rule", "route_dispatch_config"] {
        let series = format!("{FAMILY}{{kind=\"{kind}\"{NS_LABEL}}}");
        assert!(out.contains(&series), "missing {series}: {out}");
    }
}
