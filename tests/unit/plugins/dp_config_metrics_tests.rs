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

const FAMILIES: [&str; 9] = [
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

/// Two scrapes taken while a cached body would still be valid must observe the
/// live state — a growing age, and the admission state flipping at the bound.
#[test]
fn two_scrapes_observe_live_dp_config_state_while_the_cached_body_is_unchanged() {
    let registry = MetricsRegistry::new();
    // A long TTL: any body `render()` memoizes stays valid across both scrapes.
    registry.configure(300, 300, 0, 64, "");
    let cached_body_first = registry.render();
    let cached_body_second = registry.render();
    assert_eq!(
        cached_body_first, cached_body_second,
        "the cacheable body is unchanged across the two scrapes"
    );
    for family in FAMILIES {
        assert!(
            !cached_body_first.contains(family),
            "{family} must not appear outside data-plane mode"
        );
    }

    // The live append is what produces the DP families, and it reflects the
    // tracker at scrape time rather than at cache-fill time.
    let epoch = Instant::now();
    let freshness =
        DpConfigFreshness::new_at(epoch, Duration::from_secs(600), StaleAction::FailClosed);
    freshness.record_cp_connected_at(epoch);
    freshness.record_snapshot_applied_at(epoch);
    freshness.record_cp_authority_lost_at(epoch);

    let mut first = cached_body_first.clone();
    render_dp_config_freshness_prometheus(
        &mut first,
        "",
        Some(&freshness.evaluate_at(epoch + Duration::from_secs(120))),
    );
    let mut second = cached_body_second.clone();
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
