//! The nine `ferrum_dp_config_*` families are rendered live, outside the
//! `/metrics` render cache (issue #3726).
//!
//! They come from process-static atomics and from the passage of time: snapshot
//! age, the stale/blocked bits, and counters that no registry producer can
//! invalidate the cache for. Memoizing them inside `render_cacheable_body`
//! would report an age and an admission state that are wrong by however long
//! the cache has been held — exactly the window an operator watches during a
//! control-plane outage.

use std::time::{Duration, Instant};

use ferrum_edge::dp_config_freshness::{DpConfigFreshness, StaleAction};
use ferrum_edge::plugins::prometheus_metrics::{
    MetricsRegistry, render_dp_config_freshness_prometheus,
};

const PROMETHEUS_METRICS_SRC: &str = include_str!("../../../src/plugins/prometheus_metrics.rs");

const FAMILIES: [&str; 10] = [
    "ferrum_dp_cp_admission_refused_total",
    "ferrum_dp_config_snapshot_age_seconds",
    "ferrum_dp_config_max_stale_seconds",
    "ferrum_dp_config_stale",
    "ferrum_dp_config_new_traffic_blocked",
    "ferrum_dp_config_cp_connected",
    "ferrum_dp_config_stale_transitions_total",
    "ferrum_dp_config_snapshots_applied_total",
    "ferrum_dp_config_snapshots_rejected_total",
    "ferrum_dp_config_snapshot_apply_failures_total",
];

/// Two scrapes taken while the registry cache is still valid must observe the
/// live state — a growing age, and the admission state flipping at the bound.
#[test]
fn two_scrapes_observe_live_dp_config_state_within_the_cache_ttl() {
    let registry = MetricsRegistry::new();
    // A long TTL: any body `render()` memoizes stays valid across both scrapes.
    registry.configure(300, 300, 0, 64, "");
    let scrape_body_first = registry.render();
    let scrape_body_second = registry.render();
    for family in FAMILIES {
        assert!(
            !scrape_body_first.contains(family) && !scrape_body_second.contains(family),
            "{family} must not appear outside data-plane mode"
        );
    }

    // Do not compare the complete scrapes: other process-global metric
    // families are intentionally appended outside this registry's cache and
    // may move while the parallel unit suite is running. The static contract
    // below separately proves that the DP families are not memoized.

    // The live append is what produces the DP families, and it reflects the
    // tracker at scrape time rather than at cache-fill time.
    let epoch = Instant::now();
    let freshness =
        DpConfigFreshness::new_at(epoch, Duration::from_secs(600), StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(epoch);

    let mut first = scrape_body_first.clone();
    render_dp_config_freshness_prometheus(
        &mut first,
        "",
        Some(&freshness.evaluate_at(epoch + Duration::from_secs(120))),
    );
    let mut second = scrape_body_second.clone();
    render_dp_config_freshness_prometheus(
        &mut second,
        "",
        Some(&freshness.evaluate_at(epoch + Duration::from_secs(601))),
    );

    for family in FAMILIES {
        assert!(
            first.contains(family),
            "{family} missing from the first scrape"
        );
        assert!(
            second.contains(family),
            "{family} missing from the second scrape"
        );
    }
    assert!(first.contains("ferrum_dp_config_snapshot_age_seconds 120\n"));
    assert!(second.contains("ferrum_dp_config_snapshot_age_seconds 601\n"));
    assert!(first.contains("ferrum_dp_config_stale 0\n"));
    assert!(second.contains("ferrum_dp_config_stale 1\n"));
    assert!(first.contains("ferrum_dp_config_new_traffic_blocked 0\n"));
    assert!(
        second.contains("ferrum_dp_config_new_traffic_blocked 1\n"),
        "a scrape after the bound must report the closed admission gate, not a \
         value memoized before it"
    );
    assert_ne!(
        first, second,
        "a cached body plus a live append must still differ between scrapes"
    );
}

#[test]
fn namespace_labelled_series_carry_only_the_namespace_label() {
    let epoch = Instant::now();
    let freshness =
        DpConfigFreshness::new_at(epoch, Duration::from_secs(600), StaleAction::ReadinessOnly);
    let mut output = String::new();
    render_dp_config_freshness_prometheus(
        &mut output,
        ",namespace=\"edge\"",
        Some(&freshness.evaluate_at(epoch)),
    );
    assert!(output.contains(r#"ferrum_dp_config_stale{namespace="edge"} 0"#));
    // Closed-set reason/action labels live on `/health`, never on a series.
    assert!(!output.contains("reason="));
    assert!(!output.contains("stale_action="));
}

#[test]
fn nothing_is_rendered_outside_data_plane_mode() {
    let mut output = String::new();
    render_dp_config_freshness_prometheus(&mut output, "edge", None);
    assert!(output.is_empty());
}

/// Static contract: the families are appended live from both render entry
/// points and are not part of the memoized body.
#[test]
fn the_dp_config_families_are_appended_live_and_never_memoized() {
    let cacheable_start = PROMETHEUS_METRICS_SRC
        .find("fn render_cacheable_body(&self)")
        .expect("render_cacheable_body");
    // The memoized body runs to the next item in the impl block.
    let tail = &PROMETHEUS_METRICS_SRC[cacheable_start + 1..];
    let cacheable_end = [
        "\n    fn ",
        "\n    pub fn ",
        "\n    pub(crate) fn ",
        "\n}\n",
    ]
    .iter()
    .filter_map(|marker| tail.find(marker))
    .min()
    .map_or(PROMETHEUS_METRICS_SRC.len(), |offset| {
        cacheable_start + 1 + offset
    });
    let cacheable_body = &PROMETHEUS_METRICS_SRC[cacheable_start..cacheable_end];
    for family in FAMILIES {
        assert!(
            !cacheable_body.contains(family),
            "{family} must not be rendered inside the memoized body"
        );
    }

    assert_eq!(
        PROMETHEUS_METRICS_SRC
            .matches("self.append_dp_config_freshness_prometheus(&mut output);")
            .count(),
        2,
        "the live append must be composed by both `render()` and `render_uncached()`"
    );
}

/// The memoized `render_cacheable_body` source, from its signature to the next
/// item in the impl block.
fn cacheable_body_source() -> &'static str {
    let cacheable_start = PROMETHEUS_METRICS_SRC
        .find("fn render_cacheable_body(&self)")
        .expect("render_cacheable_body");
    let tail = &PROMETHEUS_METRICS_SRC[cacheable_start + 1..];
    let cacheable_end = [
        "\n    fn ",
        "\n    pub fn ",
        "\n    pub(crate) fn ",
        "\n}\n",
    ]
    .iter()
    .filter_map(|marker| tail.find(marker))
    .min()
    .map_or(PROMETHEUS_METRICS_SRC.len(), |offset| {
        cacheable_start + 1 + offset
    });
    &PROMETHEUS_METRICS_SRC[cacheable_start..cacheable_end]
}

/// Issue #7145: families whose producers live outside the registry and never
/// invalidate `render_cache` are appended live from both render entry points,
/// never memoized.
#[test]
fn externally_sourced_process_families_are_appended_live_and_never_memoized() {
    let cacheable_body = cacheable_body_source();
    for family in [
        "ferrum_service_discovery_tasks",
        "ferrum_service_discovery_last_success_age_seconds_max",
        "ferrum_compression_codec_admitted_total",
        "ferrum_admin_audit_events_accepted_total",
        "ferrum_admin_audit_events_dropped_total",
        "ferrum_admin_audit_queue_depth",
        "ferrum_admin_audit_evidence_lost",
        "ferrum_udp_amplification_responses_dropped_total",
        "ferrum_gateway_trust_bundle_published_generations_total",
        "ferrum_admin_active_connections",
        "ferrum_cp_grpc_rejected_connections_total",
        "ferrum_node_agent_pods_enrolled_total",
        "ferrum_mesh_node_topology_degraded",
    ] {
        // Match the family name exactly (quoted, or as a HELP line), not as a
        // prefix of a registry-owned sibling such as
        // `ferrum_service_discovery_tasks_started_total`.
        let names_family = |text: &str| {
            text.contains(&format!("\"{family}\"")) || text.contains(&format!("HELP {family} "))
        };
        assert!(
            !names_family(cacheable_body),
            "{family} must not be rendered inside the memoized body"
        );
        assert!(
            names_family(PROMETHEUS_METRICS_SRC),
            "{family} must still be rendered"
        );
    }
    for source in [
        "crate::service_discovery::health::aggregate()",
        "crate::plugins::compression::compression_codec_metrics()",
        "crate::admin::audit::pipeline_metrics_snapshot()",
        "crate::admin::audit::pipeline_status()",
        "crate::udp_amplification::metrics_snapshot()",
        "crate::config::gateway_trust::observability_snapshot()",
        "self.admin_conn_metrics.load_full()",
        "self.cp_grpc_conn_metrics.load_full()",
        "self.node_agent_metrics.load_full()",
    ] {
        assert!(
            !cacheable_body.contains(source),
            "{source} must not be read inside the memoized body"
        );
    }
    assert_eq!(
        PROMETHEUS_METRICS_SRC
            .matches("self.append_external_process_prometheus(&mut output);")
            .count(),
        2,
        "the live append must be composed by both `render()` and `render_uncached()`"
    );
}

/// Issue #7145: a scrape inside the render-cache TTL still observes an
/// externally sourced counter that moved since the previous scrape.
#[test]
fn externally_sourced_counters_move_between_scrapes_inside_the_cache_ttl() {
    fn dropped_total(exposition: &str) -> u64 {
        exposition
            .lines()
            .find_map(|line| {
                line.strip_prefix("ferrum_udp_amplification_responses_dropped_total")
                    .and_then(|rest| rest.rsplit(' ').next())
                    .and_then(|value| value.parse().ok())
            })
            .expect("udp amplification drop counter is always rendered")
    }

    let registry = MetricsRegistry::new();
    // A long TTL: without the live append, the second scrape would replay the
    // first body verbatim.
    registry.configure(3600, 3600, 0, 10_000, "edge");
    let before = dropped_total(&registry.render());
    ferrum_edge::udp_amplification::record_response_dropped();
    let after = dropped_total(&registry.render());
    assert!(
        after > before,
        "the drop counter must move inside the cache TTL ({before} -> {after})"
    );
}
