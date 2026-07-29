//! Issue #3330 — backend config-change wake-up plumbing.
//!
//! These cover the parts that decide whether a change-stream notification can
//! ever skip authoritative cursor work: burst coalescing, the wake/interval
//! race, bounded reconnect backoff, bounded failure classification, and the
//! bounded health surface.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::config_change_watch::{
    CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS, ConfigChangeWakeSignal,
    ConfigChangeWatchDegradedReason, ConfigChangeWatchSettings, ConfigChangeWatcherHealth,
    ConfigPollWake, MONGO_ERR_CHANGE_STREAM_FATAL, MONGO_ERR_CHANGE_STREAM_HISTORY_LOST,
    MONGO_ERR_UNAUTHORIZED, WATCH_ERROR_LOG_CHARS, classify_mongo_change_stream_failure,
    config_change_watch_backoff_after_session, next_config_change_watch_backoff_secs,
    truncate_watch_error, wait_for_config_poll_wake,
};

fn armed_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

// ── Coalescing ───────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn burst_of_signals_collapses_into_one_wake() {
    let signal = ConfigChangeWakeSignal::new();
    for _ in 0..25 {
        signal.signal();
    }
    assert_eq!(signal.signals_total(), 25);

    signal.wait().await;
    assert_eq!(signal.wakes_total(), 1);

    // The 24 remaining signals must not have queued 24 more reloads.
    assert!(
        !signal.take_pending(),
        "notifications must coalesce into a single pending permit"
    );
}

#[tokio::test(start_paused = true)]
async fn signal_raised_while_busy_is_retained_not_lost() {
    let signal = ConfigChangeWakeSignal::new();
    // Nothing is waiting yet — this models a commit landing while the poll loop
    // is still applying the previous reload.
    signal.signal();
    // Completes immediately from the retained permit.
    tokio::time::timeout(Duration::from_secs(1), signal.wait())
        .await
        .expect("a signal raised while no waiter existed must not be lost");
}

#[tokio::test(start_paused = true)]
async fn take_pending_drains_exactly_one_permit() {
    let signal = ConfigChangeWakeSignal::new();
    assert!(!signal.take_pending());
    signal.signal();
    assert!(signal.take_pending());
    assert!(!signal.take_pending());
}

// ── Wake vs periodic backstop ────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn without_a_watcher_the_periodic_interval_still_drives_polling() {
    let mut interval = armed_interval(Duration::from_secs(30));
    interval.tick().await; // immediate first tick, as the poll loop does

    let wake =
        wait_for_config_poll_wake(&mut interval, None, Duration::from_millis(250), None).await;
    assert_eq!(wake, ConfigPollWake::Interval);
}

#[tokio::test(start_paused = true)]
async fn watcher_signal_short_circuits_a_long_poll_interval() {
    let signal = Arc::new(ConfigChangeWakeSignal::new());
    let mut interval = armed_interval(Duration::from_secs(3600));
    interval.tick().await;

    signal.signal();
    let started = tokio::time::Instant::now();
    let wake = wait_for_config_poll_wake(
        &mut interval,
        Some(&signal),
        Duration::from_millis(250),
        None,
    )
    .await;

    assert_eq!(wake, ConfigPollWake::ChangeStream);
    // Only the debounce window elapsed, not the hour-long backstop.
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn with_a_watcher_the_interval_remains_the_backstop() {
    let signal = Arc::new(ConfigChangeWakeSignal::new());
    let mut interval = armed_interval(Duration::from_millis(50));
    interval.tick().await;

    // No signal raised: the periodic tick must still fire.
    let wake = wait_for_config_poll_wake(
        &mut interval,
        Some(&signal),
        Duration::from_millis(250),
        None,
    )
    .await;
    assert_eq!(wake, ConfigPollWake::Interval);
}

#[tokio::test(start_paused = true)]
async fn signals_landing_inside_the_debounce_window_are_absorbed() {
    let signal = Arc::new(ConfigChangeWakeSignal::new());
    let mut interval = armed_interval(Duration::from_secs(3600));
    interval.tick().await;

    signal.signal();
    let debounce = Duration::from_millis(250);
    let signal_for_burst = signal.clone();
    tokio::spawn(async move {
        // Land inside the debounce window.
        tokio::time::sleep(Duration::from_millis(10)).await;
        for _ in 0..10 {
            signal_for_burst.signal();
        }
    });

    let wake = wait_for_config_poll_wake(&mut interval, Some(&signal), debounce, None).await;
    assert_eq!(wake, ConfigPollWake::ChangeStream);
    // The single reload about to run covers the whole burst, so no permit may
    // remain to immediately re-trigger another one.
    assert!(
        !signal.take_pending(),
        "the debounce window must drain permits raised during it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_wake_up_cannot_outrun_an_active_rejection_backoff() {
    let signal = Arc::new(ConfigChangeWakeSignal::new());
    let mut interval = armed_interval(Duration::from_secs(3600));
    interval.tick().await;

    // The poll loop rejected the last delta and armed a retry backoff.
    let backoff = Duration::from_secs(10);
    let earliest_wake = tokio::time::Instant::now() + backoff;

    signal.signal();
    let started = tokio::time::Instant::now();
    let wake = wait_for_config_poll_wake(
        &mut interval,
        Some(&signal),
        Duration::from_millis(250),
        Some(earliest_wake),
    )
    .await;

    assert_eq!(wake, ConfigPollWake::ChangeStream);
    assert!(
        started.elapsed() >= backoff,
        "a committed-but-rejected change must not let wake-ups defeat the retry backoff"
    );
}

// ── Bounded reconnect backoff ────────────────────────────────────────────────

#[test]
fn watch_backoff_starts_at_initial_doubles_and_caps() {
    assert_eq!(next_config_change_watch_backoff_secs(0, 1, 30), 1);
    assert_eq!(next_config_change_watch_backoff_secs(1, 1, 30), 2);
    assert_eq!(next_config_change_watch_backoff_secs(2, 1, 30), 4);
    assert_eq!(next_config_change_watch_backoff_secs(16, 1, 30), 30);
    assert_eq!(next_config_change_watch_backoff_secs(30, 1, 30), 30);
}

#[test]
fn watch_backoff_never_exceeds_the_configured_ceiling() {
    for current in [0, 1, 7, 1_000, u64::MAX] {
        for max in [1, 5, 30, 3600] {
            let next = next_config_change_watch_backoff_secs(current, 1, max);
            assert!(next >= 1, "backoff must never hot-loop at zero");
            assert!(next <= max, "backoff {next} exceeded ceiling {max}");
        }
    }
}

#[test]
fn watch_backoff_clamps_an_initial_above_the_ceiling() {
    assert_eq!(next_config_change_watch_backoff_secs(0, 600, 5), 5);
    assert_eq!(next_config_change_watch_backoff_secs(1, 600, 5), 5);
}

#[test]
fn open_then_immediate_failure_keeps_escalating_backoff() {
    // Prior failures left the delay at 4s; a successful open that never
    // delivered a usable event must not clear the failure sequence.
    assert_eq!(
        config_change_watch_backoff_after_session(4, 1, 30, false),
        8
    );
    let mut backoff = 0;
    for expected in [1_u64, 2, 4, 8, 16, 30, 30] {
        backoff = config_change_watch_backoff_after_session(backoff, 1, 30, false);
        assert_eq!(
            backoff, expected,
            "open-then-fail cycles must escalate toward the ceiling"
        );
    }
}

#[test]
fn usable_delivery_resets_failure_sequence_for_next_reconnect() {
    // An escalated delay clears only after healthy delivery; the next reconnect
    // after that session ends restarts at the initial delay.
    assert_eq!(
        config_change_watch_backoff_after_session(16, 1, 30, true),
        1
    );
    assert_eq!(config_change_watch_backoff_after_session(0, 1, 30, true), 1);
}

// ── Bounded failure classification ───────────────────────────────────────────

#[test]
fn history_loss_codes_classify_as_history_lost() {
    for code in [
        MONGO_ERR_CHANGE_STREAM_HISTORY_LOST,
        MONGO_ERR_CHANGE_STREAM_FATAL,
    ] {
        assert_eq!(
            classify_mongo_change_stream_failure(Some(code), false),
            ConfigChangeWatchDegradedReason::HistoryLost,
            "code {code} must drop the retained resume point"
        );
    }
}

#[test]
fn authorization_failures_classify_as_unauthorized() {
    assert_eq!(
        classify_mongo_change_stream_failure(Some(MONGO_ERR_UNAUTHORIZED), false),
        ConfigChangeWatchDegradedReason::Unauthorized
    );
    assert_eq!(
        classify_mongo_change_stream_failure(None, true),
        ConfigChangeWatchDegradedReason::Unauthorized
    );
}

#[test]
fn unknown_failures_fall_back_to_stream_error() {
    assert_eq!(
        classify_mongo_change_stream_failure(Some(9_999), false),
        ConfigChangeWatchDegradedReason::StreamError
    );
    assert_eq!(
        classify_mongo_change_stream_failure(None, false),
        ConfigChangeWatchDegradedReason::StreamError
    );
}

#[test]
fn degraded_reason_labels_round_trip_and_stay_bounded() {
    let reasons = [
        ConfigChangeWatchDegradedReason::None,
        ConfigChangeWatchDegradedReason::ConnectFailed,
        ConfigChangeWatchDegradedReason::StreamError,
        ConfigChangeWatchDegradedReason::HistoryLost,
        ConfigChangeWatchDegradedReason::Invalidated,
        ConfigChangeWatchDegradedReason::Unauthorized,
        ConfigChangeWatchDegradedReason::UnsupportedTopology,
        ConfigChangeWatchDegradedReason::Stopped,
    ];
    assert_eq!(
        reasons.len(),
        CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS.len()
    );
    for reason in reasons {
        assert!(CONFIG_CHANGE_WATCH_DEGRADED_REASON_LABELS.contains(&reason.as_str()));
        assert_eq!(
            ConfigChangeWatchDegradedReason::from_u8(reason as u8),
            reason
        );
    }
    // Out-of-range values must not panic or invent a label.
    assert_eq!(
        ConfigChangeWatchDegradedReason::from_u8(200),
        ConfigChangeWatchDegradedReason::None
    );
}

#[test]
fn logged_backend_error_text_is_bounded() {
    let short = "connection refused";
    assert_eq!(truncate_watch_error(short), short);

    let long = "x".repeat(WATCH_ERROR_LOG_CHARS * 4);
    let truncated = truncate_watch_error(&long);
    assert!(truncated.chars().count() < long.chars().count());
    assert!(truncated.ends_with("(truncated)"));
}

// ── Bounded health surface ───────────────────────────────────────────────────

#[test]
fn health_is_absent_until_a_watcher_starts() {
    let health = ConfigChangeWatcherHealth::new();
    assert!(
        health.snapshot().is_none(),
        "backends without a watcher must not publish watcher fields"
    );

    health.mark_enabled();
    let snapshot = health.snapshot().expect("enabled watcher must publish");
    assert!(snapshot.enabled);
    assert!(!snapshot.connected);
    assert_eq!(snapshot.degraded_reason, "none");
    assert_eq!(snapshot.events_total, 0);
    assert!(snapshot.last_event_at.is_none());
}

#[test]
fn health_tracks_connect_event_and_degrade_transitions() {
    let health = ConfigChangeWatcherHealth::new();
    health.mark_enabled();

    health.mark_connected();
    health.record_event();
    health.record_event();
    let snapshot = health.snapshot().expect("enabled");
    assert!(snapshot.connected);
    assert_eq!(snapshot.degraded_reason, "none");
    assert_eq!(snapshot.events_total, 2);
    assert_eq!(snapshot.reconnects_total, 1);
    assert!(snapshot.last_event_at.is_some());

    health.mark_degraded(ConfigChangeWatchDegradedReason::HistoryLost);
    let snapshot = health.snapshot().expect("enabled");
    assert!(!snapshot.connected);
    assert_eq!(snapshot.degraded_reason, "history_lost");
    assert_eq!(snapshot.history_losses_total, 1);
    // Observed-event history is never rewritten by a later failure.
    assert_eq!(snapshot.events_total, 2);

    health.mark_degraded(ConfigChangeWatchDegradedReason::Invalidated);
    health.mark_connected();
    let snapshot = health.snapshot().expect("enabled");
    assert!(snapshot.connected);
    assert_eq!(snapshot.degraded_reason, "none");
    assert_eq!(snapshot.invalidations_total, 1);
    assert_eq!(snapshot.reconnects_total, 2);
}

#[test]
fn health_snapshot_serializes_only_bounded_fields() {
    let health = ConfigChangeWatcherHealth::new();
    health.mark_enabled();
    health.mark_connected();
    health.set_resume_token_retained(true);
    let snapshot = health.snapshot().expect("enabled");

    let value = serde_json::to_value(&snapshot).expect("serializable");
    let object = value.as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "connected",
            "degraded_reason",
            "enabled",
            "events_total",
            "history_losses_total",
            "invalidations_total",
            "reconnects_total",
            "resume_token_retained",
        ],
        "the watcher surface must stay bounded — no ids, namespaces, tokens, or URLs"
    );
    assert_eq!(object["resume_token_retained"], serde_json::json!(true));
}

// ── Settings ─────────────────────────────────────────────────────────────────

#[test]
fn settings_default_to_opt_out() {
    let settings = ConfigChangeWatchSettings::default();
    assert!(!settings.enabled);
    assert!(!ConfigChangeWatchSettings::from_env(&EnvConfig::default()).enabled);
}

#[test]
fn settings_from_env_keep_initial_backoff_within_the_ceiling() {
    let env_config = EnvConfig {
        mongo_change_stream_enabled: true,
        mongo_change_stream_debounce_ms: 500,
        // Deliberately below the 1s initial backoff.
        mongo_change_stream_max_backoff_seconds: 1,
        ..EnvConfig::default()
    };
    let settings = ConfigChangeWatchSettings::from_env(&env_config);
    assert!(settings.enabled);
    assert_eq!(settings.debounce, Duration::from_millis(500));
    assert_eq!(settings.max_backoff, Duration::from_secs(1));
    assert!(settings.initial_backoff <= settings.max_backoff);
}
