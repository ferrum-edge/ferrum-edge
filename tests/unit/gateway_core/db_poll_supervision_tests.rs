//! Issue #2986: DB/CP config poll-task exit classification and supervision.
//!
//! Panic classification and panic-inducing tests are `panic = "unwind"` only
//! (issue #4166): shipping profiles abort the process before a JoinError.

use ferrum_edge::modes::database::DatabaseDeltaPollMetrics;
use ferrum_edge::modes::db_poll_supervision::{
    DATABASE_POLL_RESPAWN_DELAY, DbPollTaskExitKind, classify_db_poll_task_exit,
    record_unexpected_cp_poll_task_exit, supervise_control_plane_poll_task,
    supervise_database_mode_poll_task_with_delay,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::watch;

#[test]
fn classify_treats_any_join_as_ordinary_when_shutdown_requested() {
    assert_eq!(
        classify_db_poll_task_exit(Ok(()), true),
        DbPollTaskExitKind::OrdinaryShutdown
    );
}

#[test]
fn classify_unexpected_completion_without_shutdown() {
    assert_eq!(
        classify_db_poll_task_exit(Ok(()), false),
        DbPollTaskExitKind::UnexpectedCompletion
    );
}

#[tokio::test]
async fn classify_abort_without_shutdown_is_unexpected() {
    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    handle.abort();
    let result = handle.await;
    assert!(result.is_err());
    assert_eq!(
        classify_db_poll_task_exit(result, false),
        DbPollTaskExitKind::Abort
    );
}

#[cfg(panic = "unwind")]
#[tokio::test]
async fn classify_panic_without_shutdown_is_unexpected() {
    let handle = tokio::spawn(async {
        panic!("intentional poll-task panic for classification test");
    });
    let result = handle.await;
    assert!(result.is_err());
    let err = result.as_ref().unwrap_err();
    assert!(err.is_panic());
    assert_eq!(
        classify_db_poll_task_exit(result, false),
        DbPollTaskExitKind::Panic
    );
}

#[test]
fn record_unexpected_cp_poll_exit_sets_sticky_serving_degraded() {
    let startup_ready = AtomicBool::new(true);
    let serving_degraded = AtomicBool::new(false);
    record_unexpected_cp_poll_task_exit(
        &startup_ready,
        &serving_degraded,
        DbPollTaskExitKind::Abort,
    );
    assert!(serving_degraded.load(Ordering::Acquire));
    assert!(!startup_ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn abort_of_cp_poll_task_flips_serving_degraded() {
    let startup_ready = Arc::new(AtomicBool::new(true));
    let serving_degraded = Arc::new(AtomicBool::new(false));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    handle.abort();

    supervise_control_plane_poll_task(
        handle,
        startup_ready.clone(),
        serving_degraded.clone(),
        shutdown_rx,
    )
    .await;

    assert!(
        serving_degraded.load(Ordering::Acquire),
        "aborted CP poll task must flip sticky serving_degraded"
    );
    assert!(!startup_ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn ordinary_cp_shutdown_does_not_degrade() {
    let startup_ready = Arc::new(AtomicBool::new(true));
    let serving_degraded = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut poll_shutdown = shutdown_tx.subscribe();
    let handle = tokio::spawn(async move {
        let _ = poll_shutdown.changed().await;
    });

    let supervise = tokio::spawn({
        let startup_ready = startup_ready.clone();
        let serving_degraded = serving_degraded.clone();
        async move {
            supervise_control_plane_poll_task(handle, startup_ready, serving_degraded, shutdown_rx)
                .await;
        }
    });

    shutdown_tx.send(true).expect("shutdown send");
    supervise.await.expect("supervisor join");

    assert!(
        !serving_degraded.load(Ordering::Acquire),
        "ordinary shutdown must not mark serving degraded"
    );
    assert!(startup_ready.load(Ordering::Acquire));
}

async fn yield_until(predicate: impl Fn() -> bool, label: &str) {
    for _ in 0..10_000 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {label}");
}

#[tokio::test(start_paused = true)]
async fn database_mode_supervisor_respawns_after_abort_with_delay() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let first_abort = Arc::new(std::sync::Mutex::new(None));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let first_abort_for_factory = first_abort.clone();
    let shutdown_tx_for_poll = shutdown_tx.clone();
    // Production uses DATABASE_POLL_RESPAWN_DELAY (1s); do not weaken it.
    let respawn_delay = DATABASE_POLL_RESPAWN_DELAY;
    assert_eq!(respawn_delay, Duration::from_secs(1));

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
            move || {
                let n = spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                let mut shutdown_rx = shutdown_tx_for_poll.subscribe();
                let handle = tokio::spawn(async move {
                    if n == 0 {
                        std::future::pending::<()>().await;
                    } else {
                        let _ = shutdown_rx.changed().await;
                    }
                });
                if n == 0 {
                    let abort = handle.abort_handle();
                    *first_abort_for_factory
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(abort);
                }
                handle
            },
            shutdown_rx,
            respawn_delay,
        )
        .await;
    });

    yield_until(
        || {
            first_abort
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        },
        "first poll generation",
    )
    .await;
    let abort_handle = first_abort
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .expect("abort handle");
    abort_handle.abort();

    // Supervisor observes abort and enters the respawn delay.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "respawn must wait for the bounded delay"
    );

    tokio::time::advance(respawn_delay).await;
    yield_until(
        || spawn_count.load(Ordering::Acquire) >= 2,
        "respawn after delay",
    )
    .await;

    shutdown_tx.send(true).expect("shutdown");
    supervisor.await.expect("supervisor join");
    assert!(
        spawn_count.load(Ordering::Acquire) >= 2,
        "database-mode supervisor must respawn after unexpected abort"
    );
}

#[tokio::test(start_paused = true)]
async fn database_mode_supervisor_rate_limits_repeated_unexpected_exits() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let respawn_delay = Duration::from_millis(500);

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
            move || {
                spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                // Every generation exits immediately (unexpected completion).
                tokio::spawn(async {})
            },
            shutdown_rx,
            respawn_delay,
        )
        .await;
    });

    yield_until(|| spawn_count.load(Ordering::Acquire) >= 1, "first spawn").await;
    assert_eq!(spawn_count.load(Ordering::Acquire), 1);
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // Before the respawn delay elapses, no second generation.
    tokio::time::advance(respawn_delay - Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "must not tight-loop respawn before delay elapses"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until(|| spawn_count.load(Ordering::Acquire) >= 2, "second spawn").await;
    assert_eq!(spawn_count.load(Ordering::Acquire), 2);
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // Third generation also waits a full delay after the second unexpected exit.
    tokio::time::advance(respawn_delay - Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        2,
        "repeated failures must remain rate-limited"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until(|| spawn_count.load(Ordering::Acquire) >= 3, "third spawn").await;

    shutdown_tx.send(true).expect("shutdown");
    // Allow the supervisor to observe shutdown if it re-entered the delay sleep.
    tokio::time::advance(respawn_delay).await;
    supervisor.await.expect("supervisor join");
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        3,
        "shutdown after third spawn must not start another generation"
    );
}

#[tokio::test(start_paused = true)]
async fn database_mode_shutdown_interrupts_respawn_wait_without_another_generation() {
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let spawn_count_for_factory = spawn_count.clone();
    let respawn_delay = Duration::from_secs(5);

    let supervisor = tokio::spawn(async move {
        supervise_database_mode_poll_task_with_delay(
            move || {
                spawn_count_for_factory.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async {})
            },
            shutdown_rx,
            respawn_delay,
        )
        .await;
    });

    yield_until(|| spawn_count.load(Ordering::Acquire) >= 1, "first spawn").await;
    // Let the supervisor enter the respawn delay after unexpected completion.
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(spawn_count.load(Ordering::Acquire), 1);

    shutdown_tx
        .send(true)
        .expect("shutdown during respawn wait");
    supervisor.await.expect("supervisor join");
    assert_eq!(
        spawn_count.load(Ordering::Acquire),
        1,
        "shutdown during respawn delay must not spawn another generation"
    );
}

/// Simulated poll-tick exit classes matching production wiring: stamp freshness
/// only on normal fallthrough / handled early-continue, never mid-attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulatedPollExit {
    FallthroughSuccess,
    FallthroughEmpty,
    HandledRejectionContinue,
    HandledErrorContinue,
    MidAttemptAbort,
    #[cfg(panic = "unwind")]
    MidAttemptPanic,
    MidAttemptDrop,
}

async fn run_simulated_poll_attempt(metrics: &DatabaseDeltaPollMetrics, exit: SimulatedPollExit) {
    match exit {
        SimulatedPollExit::FallthroughSuccess | SimulatedPollExit::FallthroughEmpty => {
            // Work completes; stamp at normal fallthrough.
            metrics.record_poll_completed();
        }
        SimulatedPollExit::HandledRejectionContinue | SimulatedPollExit::HandledErrorContinue => {
            // Production records immediately before each handled `continue`.
            metrics.record_poll_completed();
        }
        SimulatedPollExit::MidAttemptAbort | SimulatedPollExit::MidAttemptDrop => {
            // In-flight work never reaches record_poll_completed.
            std::future::pending::<()>().await;
        }
        #[cfg(panic = "unwind")]
        SimulatedPollExit::MidAttemptPanic => {
            panic!("intentional mid-poll panic for freshness test");
        }
    }
}

#[tokio::test]
async fn last_poll_completed_at_advances_on_every_normal_completion_exit_class() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    assert_eq!(metrics.last_poll_completed_at_unix_ms(), 0);

    let mut previous = 0u64;
    for exit in [
        SimulatedPollExit::FallthroughSuccess,
        SimulatedPollExit::FallthroughEmpty,
        SimulatedPollExit::HandledRejectionContinue,
        SimulatedPollExit::HandledErrorContinue,
    ] {
        std::thread::sleep(Duration::from_millis(2));
        run_simulated_poll_attempt(metrics.as_ref(), exit).await;
        let stamped = metrics.last_poll_completed_at_unix_ms();
        assert!(stamped > 0, "{exit:?} must stamp last_poll_completed_at");
        assert!(
            stamped >= previous,
            "{exit:?} must advance or retain freshness (prev={previous}, now={stamped})"
        );
        previous = stamped;
        assert!(metrics.snapshot().last_poll_completed_at.is_some());
    }
}

#[tokio::test]
async fn mid_poll_abort_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    run_simulated_poll_attempt(metrics.as_ref(), SimulatedPollExit::FallthroughEmpty).await;
    let before = metrics.last_poll_completed_at_unix_ms();
    assert!(before > 0);

    let metrics_for_task = metrics.clone();
    let handle = tokio::spawn(async move {
        run_simulated_poll_attempt(
            metrics_for_task.as_ref(),
            SimulatedPollExit::MidAttemptAbort,
        )
        .await;
    });
    tokio::task::yield_now().await;
    handle.abort();
    let _ = handle.await;

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "JoinHandle abort mid-poll must leave last_poll_completed_at unchanged"
    );
}

#[cfg(panic = "unwind")]
#[tokio::test]
async fn mid_poll_panic_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    run_simulated_poll_attempt(metrics.as_ref(), SimulatedPollExit::FallthroughEmpty).await;
    let before = metrics.last_poll_completed_at_unix_ms();
    assert!(before > 0);

    let metrics_for_task = metrics.clone();
    let handle = tokio::spawn(async move {
        run_simulated_poll_attempt(
            metrics_for_task.as_ref(),
            SimulatedPollExit::MidAttemptPanic,
        )
        .await;
    });
    let result = handle.await;
    assert!(result.unwrap_err().is_panic());

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "panic mid-poll must leave last_poll_completed_at unchanged"
    );
}

#[tokio::test]
async fn dropping_in_flight_poll_attempt_future_does_not_advance_freshness() {
    let metrics = Arc::new(DatabaseDeltaPollMetrics::default());
    run_simulated_poll_attempt(metrics.as_ref(), SimulatedPollExit::FallthroughEmpty).await;
    let before = metrics.last_poll_completed_at_unix_ms();

    {
        let attempt =
            run_simulated_poll_attempt(metrics.as_ref(), SimulatedPollExit::MidAttemptDrop);
        // Simulate select-cancellation / future drop during an in-flight poll.
        drop(attempt);
    }

    assert_eq!(
        metrics.last_poll_completed_at_unix_ms(),
        before,
        "dropping an in-flight poll attempt must not publish a fresh timestamp"
    );
}

/// Extract the authoritative poll-attempt arm between its wake boundary and
/// the shutdown arm. Database mode may wake from either the periodic backstop
/// or the coalesced MongoDB change-stream signal; control-plane mode uses the
/// periodic tick directly.
fn poll_attempt_body<'a>(source: &'a str, wake_marker: &str, shutdown_marker: &str) -> &'a str {
    let wake = source.find(wake_marker).expect("poll wake arm");
    let shutdown = source[wake..].find(shutdown_marker).expect("shutdown arm") + wake;
    &source[wake..shutdown]
}

fn assert_every_continue_records_completion(tick_body: &str, label: &str) {
    let lines: Vec<&str> = tick_body.lines().collect();
    let mut continues = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        if line.trim() != "continue;" {
            continue;
        }
        continues += 1;
        let prev = lines[..idx]
            .iter()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim())
            .unwrap_or("");
        assert!(
            prev.contains("record_poll_completed()"),
            "{label}: continue at line offset {idx} must be immediately preceded by \
             record_poll_completed(); got prev={prev:?}"
        );
    }
    assert!(
        continues > 0,
        "{label}: expected handled continue exits in poll tick"
    );
}

fn assert_fallthrough_records_completion(tick_body: &str, label: &str) {
    let trimmed = tick_body.trim_end();
    // Last non-empty statement before the tick arm closes should record completion.
    let last_stmt = trimmed
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && *l != "}")
        .unwrap_or("");
    assert!(
        last_stmt.contains("record_poll_completed()"),
        "{label}: normal fallthrough must end with record_poll_completed(); got {last_stmt:?}"
    );
}

#[test]
fn database_poll_tick_records_on_every_normal_exit_without_async_wrapper() {
    let source = include_str!("../../../src/modes/database.rs");
    assert!(
        !source.contains("run_poll_attempt_recording_completion"),
        "database mode must not wrap the poll tick in an async completion helper"
    );
    assert!(
        !source.contains("PollCompletedGuard"),
        "Drop-based poll completion must not return (panic/abort false positives)"
    );

    let tick = poll_attempt_body(
        source,
        "wake = wait_for_config_poll_wake(",
        "_ = poll_shutdown.changed() => {",
    );
    assert!(
        !tick.contains("async {"),
        "database poll tick must not introduce a nested async block around the body"
    );
    assert_every_continue_records_completion(tick, "database");
    assert_fallthrough_records_completion(tick, "database");

    // Topology fencing adds five handled retry exits to base main's eight;
    // keep that deliberate exit-class count pinned as the loop evolves.
    let continue_count = tick.lines().filter(|l| l.trim() == "continue;").count();
    assert_eq!(
        continue_count, 13,
        "database poll tick handled-continue exit count drifted"
    );
    let record_count = tick.matches("record_poll_completed()").count();
    assert_eq!(
        record_count,
        continue_count + 1,
        "database: one record per continue plus fallthrough"
    );
}

#[test]
fn control_plane_poll_tick_records_on_every_normal_exit_without_async_wrapper() {
    let source = include_str!("../../../src/modes/control_plane.rs");
    assert!(
        !source.contains("run_poll_attempt_recording_completion"),
        "control-plane mode must not wrap the poll tick in an async completion helper"
    );

    let tick = poll_attempt_body(
        source,
        "_ = interval.tick() => {",
        "_ = cp_poll_shutdown.changed() => {",
    );
    assert!(
        !tick.contains("async {"),
        "control-plane poll tick must not introduce a nested async block around the body"
    );
    assert_every_continue_records_completion(tick, "control_plane");
    assert_fallthrough_records_completion(tick, "control_plane");

    let continue_count = tick.lines().filter(|l| l.trim() == "continue;").count();
    // 11 in base main, plus the two exits per-namespace isolation added
    // (#2983/#2984): a delta whose namespaces all rejected, and a non-empty
    // delta that partitioned to no attributable namespace. Both still record
    // completion, which `assert_every_continue_records_completion` above proves.
    assert_eq!(
        continue_count, 13,
        "control-plane poll tick handled-continue exit count drifted"
    );
    let record_count = tick.matches("record_poll_completed()").count();
    assert_eq!(
        record_count,
        continue_count + 1,
        "control_plane: one record per continue plus fallthrough"
    );
}

/// Issue #3727: authoritative gateway trust drift must be repaired by the
/// full-reload publication path in the SAME poll tick that detected it.
///
/// Escalating with an early `continue` would satisfy the "record on every
/// normal exit" contract while still leaving revoked roots installed on every
/// subscriber for one whole poll interval, so the accounting test alone cannot
/// prove this. What proves it is control flow: the check is evaluated before
/// the reload decision, nothing between the two ends the tick or starts an
/// incremental poll, and the branch it selects is the full snapshot load.
#[test]
fn gateway_trust_drift_escalates_into_the_same_tick_full_reload() {
    for (label, source, wake_marker, shutdown_marker) in [
        (
            "database",
            include_str!("../../../src/modes/database.rs"),
            "wake = wait_for_config_poll_wake(",
            "_ = poll_shutdown.changed() => {",
        ),
        (
            "control_plane",
            include_str!("../../../src/modes/control_plane.rs"),
            "_ = interval.tick() => {",
            "_ = cp_poll_shutdown.changed() => {",
        ),
    ] {
        let tick = poll_attempt_body(source, wake_marker, shutdown_marker);

        let drift_at = tick
            .find("detect_gateway_trust_drift(")
            .unwrap_or_else(|| panic!("{label}: poll tick must run the trust drift check"));
        let decision_at = tick[drift_at..]
            .find("if force_full_reload {")
            .map(|offset| offset + drift_at)
            .unwrap_or_else(|| {
                panic!("{label}: the drift check must precede the full-reload decision")
            });

        // The escalation must be guarded so an already-pending full reload
        // does not pay for a second authoritative read, and that guard must be
        // the negated one — not the reload branch itself.
        let guard_at = tick[..drift_at]
            .rfind("if !force_full_reload {")
            .unwrap_or_else(|| {
                panic!("{label}: the drift check must be skipped when a reload is already pending")
            });
        assert!(
            !tick[guard_at..drift_at].contains("if force_full_reload {"),
            "{label}: the drift check must run outside the full-reload branch"
        );

        let between = &tick[guard_at..decision_at];
        assert!(
            !between.contains("continue;"),
            "{label}: escalating trust drift must not end the poll tick before the reload"
        );
        assert!(
            !between.contains("record_poll_completed()"),
            "{label}: escalating trust drift must not record a poll completion of its own"
        );
        assert!(
            !between.contains("load_incremental"),
            "{label}: a drifted tick must not fall into incremental polling first"
        );
        assert!(
            tick[decision_at..].contains("load_full_config"),
            "{label}: the branch the escalation selects must be the authoritative full load"
        );
    }
}

#[test]
fn database_poll_respawn_delay_remains_one_second() {
    assert_eq!(DATABASE_POLL_RESPAWN_DELAY, Duration::from_secs(1));
    let source = include_str!("../../../src/modes/db_poll_supervision.rs");
    assert!(
        source.contains("Duration::from_secs(1)"),
        "DATABASE_POLL_RESPAWN_DELAY must stay a 1-second shutdown-aware backoff"
    );
}

/// Issue #4528: every poll-loop path that marks the configuration source
/// unavailable must go through the one helper that flips the shared
/// `db_available` flag AND counts the failure, so
/// `ferrum_database_config_source_connected` and
/// `ferrum_database_poll_failures_total` cannot drift apart.
///
/// The two remaining bare `store(false)` calls in the control-plane tick are
/// deliberate and are NOT failures: both follow a *successful* pool reconnect
/// and mark "a full reload is pending" for one cycle. Counting them would
/// report a poll failure every time database DNS changes.
#[test]
fn poll_loop_availability_writes_go_through_the_counting_helper() {
    for (label, source, wake_marker, shutdown_marker, expected_bare_stores) in [
        (
            "database",
            include_str!("../../../src/modes/database.rs"),
            "wake = wait_for_config_poll_wake(",
            "_ = poll_shutdown.changed() => {",
            0usize,
        ),
        (
            "control_plane",
            include_str!("../../../src/modes/control_plane.rs"),
            "_ = interval.tick() => {",
            "_ = cp_poll_shutdown.changed() => {",
            2usize,
        ),
    ] {
        let tick = poll_attempt_body(source, wake_marker, shutdown_marker);
        assert_eq!(
            tick.matches(".store(false").count(),
            expected_bare_stores,
            "{label}: an unaccounted bare availability write appeared in the poll tick; \
             use record_config_source_unavailable() so the gauge and the counter move together"
        );
        assert!(
            tick.contains("record_config_source_unavailable("),
            "{label}: poll tick must mark outages through the counting helper"
        );
        assert!(
            tick.contains("record_poll_failure("),
            "{label}: poll tick must count classified poll failures"
        );
    }
}

/// The shared flag is the whole point: the metrics struct must hold the SAME
/// `Arc<AtomicBool>` the poll loop and `AdminState` use, so `/metrics` and the
/// admin API can never disagree about database availability.
#[test]
fn config_source_gauge_tracks_the_shared_admin_flag() {
    let flag = Arc::new(AtomicBool::new(true));
    let metrics = DatabaseDeltaPollMetrics::with_config_source_flag(flag.clone());
    assert!(metrics.config_source_connected());
    assert!(metrics.snapshot().config_source_connected);

    // A write from the poll loop's side of the Arc is visible to the metrics.
    flag.store(false, Ordering::Relaxed);
    assert!(!metrics.config_source_connected());
    assert!(!metrics.snapshot().config_source_connected);

    // ...and a write through the metrics helper is visible to the admin side.
    flag.store(true, Ordering::Relaxed);
    metrics.record_config_source_unavailable(
        ferrum_edge::modes::database::DatabasePollFailureReason::Connectivity,
    );
    assert!(!flag.load(Ordering::Relaxed));

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.poll_failures_by_reason.get("connectivity"),
        Some(&1)
    );
    assert_eq!(
        snapshot.poll_failures_by_reason.len(),
        3,
        "the reason label set is closed and always fully populated"
    );
}

/// Default construction owns its own flag, so callers with no poll loop (and
/// the existing tests) keep a sane "connected" starting point.
#[test]
fn default_metrics_own_a_connected_config_source_flag() {
    let metrics = DatabaseDeltaPollMetrics::default();
    assert!(metrics.config_source_connected());
    for reason in ["connectivity", "validation_rejected", "migration_gate"] {
        assert_eq!(
            metrics.snapshot().poll_failures_by_reason.get(reason),
            Some(&0)
        );
    }
}
