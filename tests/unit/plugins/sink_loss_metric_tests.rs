//! Per-plugin logging-sink record-loss accounting (issue #4801).
//!
//! Before this family existed the sinks logged thousands of `ByteBudget` and
//! batch-discard losses while every published drop counter read zero. These
//! tests pin the three properties that make the metric trustworthy: each
//! discard site increments the right closed-set label, `accepted` plus the
//! admission-time reasons accounts for every record offered, and the label set
//! stays bounded under a hostile workload.
//!
//! Counters are process-global by design (a plugin-cache reload must not reset
//! evidence of loss), so every assertion is a delta around the operation under
//! test rather than an absolute value.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::plugins::utils::batching_logger::{
    BatchConfig, BatchingLogger, DeferredBatchingLogger, LoggerHooks, RetryPolicy, TrySendOutcome,
};
use ferrum_edge::plugins::utils::byte_budget::{ByteBudget, RetainedByteCeiling};
use ferrum_edge::plugins::utils::sink_loss::{
    OTHER_PLUGIN, SINK_PLUGINS, SinkLossReason, accepted_total, dropped_total,
    dropped_total_all_reasons, record_dropped, render_prometheus, snapshot,
};

/// Probe identity outside the closed set, so these tests exercise the
/// `other` bucket instead of perturbing a real sink's series.
const PROBE_PLUGIN: &str = "ferrum_sink_loss_probe";

fn leaked_ceiling(max_bytes: usize) -> &'static RetainedByteCeiling {
    Box::leak(Box::new(RetainedByteCeiling::new(max_bytes)))
}

fn probe_batch_config(batch_size: usize, buffer_capacity: usize, attempts: u32) -> BatchConfig {
    BatchConfig {
        batch_size,
        flush_interval: Duration::from_millis(5),
        buffer_capacity,
        retry: RetryPolicy::fixed(attempts, Duration::from_millis(1)),
        plugin_name: PROBE_PLUGIN,
    }
}

fn is_fixed_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
}

#[test]
fn reason_labels_are_a_closed_sorted_set_of_fixed_tokens() {
    assert_eq!(SinkLossReason::ALL.len(), 6);
    let rendered: Vec<&str> = SinkLossReason::ALL
        .iter()
        .map(|reason| reason.as_str())
        .collect();
    let mut sorted = rendered.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 6, "reason labels must be distinct");
    assert_eq!(
        rendered, sorted,
        "reasons must render sorted so the exposition is stable"
    );
    for label in &rendered {
        assert!(is_fixed_token(label), "reason label {label} is not fixed");
    }
}

#[test]
fn plugin_labels_are_a_closed_sorted_set_with_a_catch_all() {
    let rendered = SINK_PLUGINS.to_vec();
    let mut sorted = rendered.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        SINK_PLUGINS.len(),
        "plugin labels must be distinct"
    );
    assert_eq!(
        rendered, sorted,
        "plugins must render sorted so the exposition is stable"
    );
    assert!(
        SINK_PLUGINS.contains(&OTHER_PLUGIN),
        "the closed set needs a catch-all so an unknown sink stays visible"
    );
    for plugin in SINK_PLUGINS {
        assert!(is_fixed_token(plugin), "plugin label {plugin} is not fixed");
    }
}

#[test]
fn hostile_plugin_identities_fold_into_other_without_growing_the_label_set() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::SinkError);
    // Each of these would be its own series if the label were free text.
    for index in 0..512u32 {
        let padding = "A".repeat(index as usize % 32);
        let hostile = format!("tenant-{index}-\u{1f600}-{padding}");
        record_dropped(&hostile, SinkLossReason::SinkError, 1);
    }
    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::SinkError);
    assert_eq!(
        after - before,
        512,
        "unknown sink identities must be counted, not discarded"
    );

    let exposition = render_prometheus();
    let dropped_prefix = "ferrum_plugin_log_sink_records_dropped_total{";
    let accepted_prefix = "ferrum_plugin_log_sink_records_accepted_total{";
    let dropped_series = exposition
        .lines()
        .filter(|line| line.starts_with(dropped_prefix))
        .count();
    let accepted_series = exposition
        .lines()
        .filter(|line| line.starts_with(accepted_prefix))
        .count();
    let expected_dropped = SINK_PLUGINS.len() * SinkLossReason::ALL.len();
    assert_eq!(dropped_series, expected_dropped);
    assert_eq!(accepted_series, SINK_PLUGINS.len());
    assert!(
        !exposition.contains("tenant-"),
        "a hostile identity leaked into the exposition"
    );
}

#[test]
fn zero_record_calls_do_not_manufacture_a_loss() {
    let before = dropped_total_all_reasons(OTHER_PLUGIN);
    record_dropped(PROBE_PLUGIN, SinkLossReason::QueueFull, 0);
    assert_eq!(dropped_total_all_reasons(OTHER_PLUGIN), before);
}

#[test]
fn byte_budget_exhaustion_increments_the_byte_budget_reason() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::ByteBudget);
    let ceiling = leaked_ceiling(1024 * 1024);
    let budget = ByteBudget::with_ceiling(PROBE_PLUGIN, 64, ceiling);
    let held = budget.try_acquire(64).expect("first reservation fits");
    assert!(
        budget.try_acquire(64).is_none(),
        "the per-instance budget must refuse the second reservation"
    );
    drop(held);
    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::ByteBudget);
    assert_eq!(
        after - before,
        1,
        "a refused retained-byte reservation is a lost record"
    );
}

#[test]
fn process_ceiling_exhaustion_also_lands_on_the_byte_budget_reason() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::ByteBudget);
    // The instance budget is generous; the shared ceiling is what refuses.
    let ceiling = leaked_ceiling(32);
    let budget = ByteBudget::with_ceiling(PROBE_PLUGIN, 1024 * 1024, ceiling);
    let held = budget.try_acquire(32).expect("first reservation fits");
    assert!(budget.try_acquire(32).is_none());
    drop(held);
    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::ByteBudget);
    assert_eq!(after - before, 1);
}

#[tokio::test]
async fn buffer_full_counts_queue_full_and_accepted_accounts_for_every_record() {
    let accepted_before = accepted_total(OTHER_PLUGIN);
    let dropped_before = dropped_total(OTHER_PLUGIN, SinkLossReason::QueueFull);

    // Left uncommitted so the flush worker stays dormant and nothing drains
    // the bounded channel; every send after the first is a queue-full loss.
    let logger: BatchingLogger<u64> =
        BatchingLogger::spawn(probe_batch_config(8, 1, 1), |_batch: Arc<Vec<u64>>| async {
            Ok::<(), String>(())
        });

    let mut accepted = 0u64;
    let mut refused = 0u64;
    for value in 0..16u64 {
        match logger.try_send_outcome(value) {
            TrySendOutcome::ChannelAccepted => accepted += 1,
            TrySendOutcome::BufferFull => refused += 1,
            other => panic!("unexpected admission outcome {other:?}"),
        }
    }
    assert_eq!(accepted, 1, "capacity is one slot");
    assert_eq!(refused, 15);

    let accepted_delta = accepted_total(OTHER_PLUGIN) - accepted_before;
    let dropped_after = dropped_total(OTHER_PLUGIN, SinkLossReason::QueueFull);
    let dropped_delta = dropped_after - dropped_before;
    assert_eq!(accepted_delta, accepted);
    assert_eq!(dropped_delta, refused);
    assert_eq!(
        accepted_delta + dropped_delta,
        16,
        "accepted plus admission loss must account for every record offered"
    );
}

#[tokio::test]
async fn a_healthy_sink_reports_accepted_records_and_no_drops() {
    let accepted_before = accepted_total(OTHER_PLUGIN);
    let dropped_before = dropped_total_all_reasons(OTHER_PLUGIN);

    let mut logger: BatchingLogger<u64> = BatchingLogger::spawn(
        probe_batch_config(4, 64, 1),
        |_batch: Arc<Vec<u64>>| async { Ok::<(), String>(()) },
    );
    logger.commit();
    for value in 0..12u64 {
        let outcome = logger.try_send_outcome(value);
        assert_eq!(outcome, TrySendOutcome::ChannelAccepted);
    }
    assert!(logger.close_and_await().await);

    assert_eq!(accepted_total(OTHER_PLUGIN) - accepted_before, 12);
    assert_eq!(
        dropped_total_all_reasons(OTHER_PLUGIN),
        dropped_before,
        "a delivering sink must report zero loss"
    );
}

#[tokio::test]
async fn declined_failed_batch_fallback_counts_every_lost_record() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::BatchDiscard);

    // Merely installing a fallback is not evidence of durable ownership. A
    // hook that declines the batch must leave terminal-loss accounting intact.
    let mut logger: BatchingLogger<u64> = BatchingLogger::spawn_with_hooks(
        probe_batch_config(4, 64, 2),
        LoggerHooks {
            on_failed_batch: Some(Arc::new(|_batch, _error| false)),
            ..LoggerHooks::default()
        },
        |_batch: Arc<Vec<u64>>| async { Err::<(), String>("probe sink is down".to_string()) },
    );
    logger.commit();
    for value in 0..4u64 {
        let outcome = logger.try_send_outcome(value);
        assert_eq!(outcome, TrySendOutcome::ChannelAccepted);
    }
    assert!(logger.close_and_await().await);

    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::BatchDiscard);
    assert_eq!(
        after - before,
        4,
        "the counter must count lost records, not discard events"
    );
}

#[tokio::test]
async fn closed_admission_counts_a_shutdown_loss() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::Shutdown);

    let mut logger: BatchingLogger<u64> = BatchingLogger::spawn(
        probe_batch_config(4, 64, 1),
        |_batch: Arc<Vec<u64>>| async { Ok::<(), String>(()) },
    );
    logger.commit();
    assert!(logger.close_and_await().await);
    let outcome = logger.try_send_outcome(7);
    assert_eq!(outcome, TrySendOutcome::WorkerUnavailable);

    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::Shutdown);
    assert_eq!(after - before, 1);
}

#[test]
fn records_offered_before_staging_are_counted_rather_than_vanishing() {
    let before = dropped_total(OTHER_PLUGIN, SinkLossReason::Shutdown);
    let logger: DeferredBatchingLogger<u64> = DeferredBatchingLogger::for_plugin(PROBE_PLUGIN);
    let outcome = logger.try_send_outcome(1);
    assert_eq!(outcome, TrySendOutcome::WorkerUnavailable);
    assert!(logger.try_reserve().is_none());
    let after = dropped_total(OTHER_PLUGIN, SinkLossReason::Shutdown);
    assert_eq!(
        after - before,
        2,
        "a pre-publication record is lost and must be published as such"
    );
}

#[test]
fn exposition_carries_help_type_and_every_series_even_at_zero() {
    let exposition = render_prometheus();
    for family in [
        "ferrum_plugin_log_sink_records_accepted_total",
        "ferrum_plugin_log_sink_records_dropped_total",
    ] {
        let help = format!("# HELP {family} ");
        let type_line = format!("# TYPE {family} counter\n");
        assert!(exposition.contains(&help), "{family} is missing HELP");
        assert!(exposition.contains(&type_line), "{family} lacks TYPE");
    }
    let accepted_family = "ferrum_plugin_log_sink_records_accepted_total";
    let dropped_family = "ferrum_plugin_log_sink_records_dropped_total";
    for plugin in SINK_PLUGINS {
        let accepted = format!("{accepted_family}{{plugin=\"{plugin}\"}} ");
        assert!(exposition.contains(&accepted), "missing {plugin} accepted");
        for reason in SinkLossReason::ALL {
            let label = reason.as_str();
            let series = format!("{dropped_family}{{plugin=\"{plugin}\",reason=\"{label}\"}} ");
            assert!(
                exposition.contains(&series),
                "missing zero-valued series for {plugin}/{label}"
            );
        }
    }
}

#[test]
fn status_snapshot_lists_only_non_zero_reasons_and_no_free_text() {
    record_dropped(PROBE_PLUGIN, SinkLossReason::RecordTooLarge, 3);
    let projection = snapshot();
    let reasons = projection
        .dropped_by_plugin
        .get(OTHER_PLUGIN)
        .expect("the other bucket has a loss");
    assert!(reasons.contains_key("record_too_large"));
    assert!(
        reasons.values().all(|value| *value > 0),
        "zero reasons must not be listed"
    );
    assert!(projection.dropped_total >= 3);

    let json = serde_json::to_string(&projection).expect("serializes");
    for key in ["dropped_total", "accepted_total", "dropped_by_plugin"] {
        assert!(json.contains(key), "status projection is missing {key}");
    }
    for plugin in projection.dropped_by_plugin.keys() {
        assert!(
            SINK_PLUGINS.contains(plugin),
            "status projection leaked an unbounded identity: {plugin}"
        );
    }
}
