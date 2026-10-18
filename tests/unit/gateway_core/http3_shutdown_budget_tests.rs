//! Exercise the production broadcaster and H3/global waiters with virtual time.
use ferrum_edge::_test_support::{
    H3DrainOutcomeForTest as Outcome, shutdown_overload_for_test,
    supervise_shutdown_listeners_for_test, wait_for_h3_close_for_test as close,
    wait_for_h3_drain_for_test as h3_drain,
};
use ferrum_edge::overload::{
    ConnectionGuard, ShutdownSender, begin_drain, wait_for_drain_with_escalation,
};
use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::{Instant, advance, sleep};
use tokio_util::sync::CancellationToken;

const BUDGET: Duration = Duration::from_secs(30);

fn assert_elapsed(start: Instant, expected: Duration) {
    let elapsed = start.elapsed();
    assert!(
        elapsed >= expected && elapsed < expected + Duration::from_millis(150),
        "expected {expected:?}, elapsed {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn h3_and_close_tail_and_global_drain_share_broadcast_deadline() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let _held = ConnectionGuard::new(&state);
    let started = Instant::now();
    shutdown
        .shutdown_after_predrain(Duration::ZERO, &escalation)
        .await;

    // Time spent joining other listeners counts, even before H3 first waits.
    advance(Duration::from_secs(5)).await;
    let local_deadline = Instant::now() + BUDGET;
    assert_eq!(
        h3_drain(&state, || 1, local_deadline, &escalation).await,
        Outcome::TimedOut
    );
    assert_eq!(
        close(&state, local_deadline, &escalation, pending()).await,
        Outcome::TimedOut
    );
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn global_drain_gets_what_the_h3_drain_left() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let _held = ConnectionGuard::new(&state);
    let open = Arc::new(AtomicUsize::new(1));
    let closer = open.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(10)).await;
        closer.store(0, Ordering::Relaxed);
    });
    let started = Instant::now();
    shutdown.shutdown();
    assert_eq!(
        h3_drain(
            &state,
            || open.load(Ordering::Relaxed),
            started + BUDGET,
            &escalation
        )
        .await,
        Outcome::Drained
    );
    assert_elapsed(started, Duration::from_secs(10));
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn listener_retirement_does_not_consume_later_process_budget() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let retired = Instant::now();
    assert_eq!(
        h3_drain(&state, || 1, retired + BUDGET, &escalation).await,
        Outcome::TimedOut
    );
    assert_eq!(
        close(&state, retired + BUDGET, &escalation, pending()).await,
        Outcome::TimedOut
    );
    assert_elapsed(retired, BUDGET);
    assert!(!*shutdown.borrow());
    advance(Duration::from_secs(120)).await;

    let _held = ConnectionGuard::new(&state);
    let started = Instant::now();
    shutdown.shutdown();
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn retirement_during_real_predrain_does_not_start_or_consume_process_budget() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let mut broadcast = shutdown.subscribe();
    let sequencer = shutdown.clone();
    let signal = escalation.clone();
    let sequence = tokio::spawn(async move {
        sequencer
            .shutdown_after_predrain(Duration::from_secs(60), &signal)
            .await;
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(5)).await;
    let retired = Instant::now();
    assert_eq!(
        h3_drain(&state, || 1, retired + BUDGET, &escalation).await,
        Outcome::TimedOut
    );
    assert_elapsed(retired, BUDGET);
    assert!(!*broadcast.borrow());
    broadcast.changed().await.unwrap();
    sequence.await.unwrap();

    let _held = ConnectionGuard::new(&state);
    let started = Instant::now();
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn retirement_in_flight_at_sigterm_observes_deadline_publication() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let sequencer = shutdown.clone();
    let signal = escalation.clone();
    let started = Instant::now();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        sequencer
            .shutdown_after_predrain(Duration::ZERO, &signal)
            .await;
    });
    // A longer local cap makes observing publication essential. With the same
    // configured budget the earlier retirement cap must also remain in force.
    assert_eq!(
        h3_drain(
            &state,
            || 1,
            started + Duration::from_secs(120),
            &escalation
        )
        .await,
        Outcome::TimedOut
    );
    assert_elapsed(started, Duration::from_secs(35));
    assert!(*shutdown.borrow());
}

#[tokio::test(start_paused = true)]
async fn process_shutdown_never_extends_an_earlier_retirement_deadline() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let trigger = shutdown.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        trigger.shutdown();
    });
    let started = Instant::now();
    assert_eq!(
        h3_drain(&state, || 1, started + BUDGET, &escalation).await,
        Outcome::TimedOut
    );
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn endpoint_close_already_waiting_observes_process_deadline() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let trigger = shutdown.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        trigger.shutdown();
    });
    let started = Instant::now();
    let local_deadline = started + Duration::from_secs(120);
    assert_eq!(
        h3_drain(&state, || 0, local_deadline, &escalation).await,
        Outcome::Drained
    );
    assert_eq!(
        close(&state, local_deadline, &escalation, pending()).await,
        Outcome::TimedOut
    );
    assert_elapsed(started, Duration::from_secs(35));
}

#[tokio::test(start_paused = true)]
async fn listener_failure_publishes_the_same_deadline_without_signal_announcement() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let _held = ConnectionGuard::new(&state);
    let escalation = CancellationToken::new();
    let mut receiver = shutdown.subscribe();
    let sibling_state = state.clone();
    let sibling_signal = escalation.clone();
    let sibling = tokio::spawn(async move {
        receiver.changed().await.unwrap();
        assert_eq!(
            h3_drain(
                &sibling_state,
                || 1,
                Instant::now() + BUDGET,
                &sibling_signal
            )
            .await,
            Outcome::TimedOut
        );
        Ok(())
    });
    let failure = tokio::spawn(async { Err(anyhow::anyhow!("listener failed")) });
    let started = Instant::now();
    let result = supervise_shutdown_listeners_for_test(
        vec![("H3".into(), sibling), ("failed".into(), failure)],
        shutdown,
    )
    .await;
    assert!(result.is_err());
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn repeated_signal_cuts_h3_drain_and_close_tail_and_global_wait() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let _held = ConnectionGuard::new(&state);
    let escalation = CancellationToken::new();
    let signal = escalation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(2)).await;
        signal.cancel();
    });
    shutdown.shutdown();
    let started = Instant::now();
    let local_deadline = started + BUDGET;
    assert_eq!(
        h3_drain(&state, || 1, local_deadline, &escalation).await,
        Outcome::Escalated
    );
    assert_eq!(
        close(&state, local_deadline, &escalation, pending()).await,
        Outcome::Escalated
    );
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, BUDGET, escalation).await);
    assert_elapsed(started, Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn escalation_during_endpoint_close_cuts_its_wait() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let signal = escalation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(2)).await;
        signal.cancel();
    });
    let started = Instant::now();
    assert_eq!(
        close(&state, started + BUDGET, &escalation, pending()).await,
        Outcome::Escalated
    );
    assert_elapsed(started, Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn first_publication_wins_even_without_receivers() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let escalation = CancellationToken::new();
    let started = Instant::now();
    shutdown.shutdown();
    advance(Duration::from_secs(10)).await;
    shutdown.clone().shutdown();
    assert!(*shutdown.subscribe().borrow());
    assert_eq!(
        h3_drain(&state, || 1, Instant::now() + BUDGET, &escalation).await,
        Outcome::TimedOut
    );
    assert_elapsed(started, BUDGET);
}

#[tokio::test(start_paused = true)]
async fn final_sender_drop_also_publishes_before_watch_closure() {
    let shutdown = ShutdownSender::new(BUDGET);
    let state = shutdown_overload_for_test(&shutdown);
    let mut receiver = shutdown.subscribe();
    let escalation = CancellationToken::new();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        drop(shutdown);
    });
    let started = Instant::now();
    assert_eq!(
        h3_drain(
            &state,
            || 1,
            started + Duration::from_secs(120),
            &escalation
        )
        .await,
        Outcome::TimedOut
    );
    assert!(receiver.changed().await.is_err());
    assert_elapsed(started, Duration::from_secs(35));
}

#[tokio::test(start_paused = true)]
async fn zero_budget_skips_all_waits_and_idle_h3_still_drains() {
    let shutdown = ShutdownSender::new(Duration::ZERO);
    let state = shutdown_overload_for_test(&shutdown);
    let _held = ConnectionGuard::new(&state);
    let escalation = CancellationToken::new();
    shutdown.shutdown();
    let started = Instant::now();
    assert_eq!(
        h3_drain(&state, || 0, started, &escalation).await,
        Outcome::Drained
    );
    assert_eq!(
        h3_drain(&state, || 1, started, &escalation).await,
        Outcome::TimedOut
    );
    assert_eq!(
        close(&state, started, &escalation, pending()).await,
        Outcome::TimedOut
    );
    begin_drain(&state);
    assert!(!wait_for_drain_with_escalation(&state, Duration::ZERO, escalation).await);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[test]
fn every_process_shutdown_trigger_uses_the_deadline_publishing_sender() {
    for (path, src) in [
        ("database", include_str!("../../../src/modes/database.rs")),
        ("file", include_str!("../../../src/modes/file.rs")),
        ("dp", include_str!("../../../src/modes/data_plane.rs")),
        ("mesh", include_str!("../../../src/modes/mesh/mod.rs")),
    ] {
        assert!(
            src.contains("shutdown_tx: crate::overload::ShutdownSender"),
            "{path}"
        );
        assert_eq!(
            src.matches("overload.attach_shutdown(").count(),
            1,
            "{path}"
        );
        assert!(src.contains("overload::wait_for_drain("), "{path}");
        assert!(!src.contains("watch::Sender<bool>"), "{path}");
        assert!(!src.contains("shutdown_tx.send(true)"), "{path}");
    }
    let entry = include_str!("../../../src/gateway_entry.rs");
    assert!(entry.contains("overload::ShutdownSender::new("));
    assert!(
        entry.find("overload::announce_shutdown_drain();").unwrap()
            < entry.find(".shutdown_after_predrain(").unwrap()
    );
    let h3 = include_str!("../../../src/http3/server.rs");
    assert!(!h3.contains("H3DrainBudget"));
    assert!(!h3.contains("shutdown_drain_announced()"));
    // Keep the response-finalizer integrity test's production/test boundary.
    assert!(!h3.contains("mod shutdown_drain_budget_tests"));
}
