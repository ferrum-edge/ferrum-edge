//! Issue #2986: DB/CP config poll-task exit classification and supervision.

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

/// Extract the poll-tick arm body between `interval.tick()` and the shutdown arm.
fn poll_tick_body<'a>(source: &'a str, shutdown_marker: &str) -> &'a str {
    let tick = source
        .find("_ = interval.tick() => {")
        .expect("poll tick arm");
    let shutdown = source[tick..].find(shutdown_marker).expect("shutdown arm") + tick;
    &source[tick..shutdown]
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

    let tick = poll_tick_body(source, "_ = poll_shutdown.changed() => {");
    assert!(
        !tick.contains("async {"),
        "database poll tick must not introduce a nested async block around the body"
    );
    assert_every_continue_records_completion(tick, "database");
    assert_fallthrough_records_completion(tick, "database");

    // Base main had 8 handled continues in this loop; keep that exit class count.
    let continue_count = tick.lines().filter(|l| l.trim() == "continue;").count();
    assert_eq!(
        continue_count, 8,
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

    let tick = poll_tick_body(source, "_ = cp_poll_shutdown.changed() => {");
    assert!(
        !tick.contains("async {"),
        "control-plane poll tick must not introduce a nested async block around the body"
    );
    assert_every_continue_records_completion(tick, "control_plane");
    assert_fallthrough_records_completion(tick, "control_plane");

    let continue_count = tick.lines().filter(|l| l.trim() == "continue;").count();
    assert_eq!(
        continue_count, 11,
        "control-plane poll tick handled-continue exit count drifted"
    );
    let record_count = tick.matches("record_poll_completed()").count();
    assert_eq!(
        record_count,
        continue_count + 1,
        "control_plane: one record per continue plus fallthrough"
    );
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
