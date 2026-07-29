//! Retention bounds for injected fault delays (GHSA-484w-rxg2-7jg5).
//!
//! Every test here drives `run_fault_delay_in` with a *locally owned* budget
//! and shutdown token. The production entry point uses process-global state,
//! and cancelling a process-global one-shot token from a test would disarm
//! every other fault-delay test in the same binary.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::plugins::utils::fault_delay::{
    DEFAULT_MAX_CONCURRENT_FAULT_DELAYS, FaultDelayAdmission, FaultDelayOutcome, run_fault_delay_in,
};
use ferrum_edge::plugins::utils::fault_roll::MAX_FAULT_DELAY_MS;
use tokio_util::sync::CancellationToken;

/// A cancellation must return far faster than the delay it preempted. Kept
/// generous so a loaded CI runner cannot make it flaky while still failing
/// loudly if the timer is actually being waited out.
const PROMPT: Duration = Duration::from_secs(5);

/// Long enough that completing it would blow past `PROMPT` by orders of
/// magnitude, but still within the configuration ceiling.
const LONG_DELAY_MS: u64 = 60_000;

fn admission(capacity: usize) -> FaultDelayAdmission {
    FaultDelayAdmission::new(capacity)
}

// ── Completion ───────────────────────────────────────────────────────

#[tokio::test]
async fn delay_completes_when_nothing_cancels() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();

    let outcome = run_fault_delay_in(&admission, &shutdown, 1, None).await;

    assert_eq!(outcome, FaultDelayOutcome::Completed);
    assert!(outcome.completed());
    assert_eq!(
        admission.in_flight(),
        0,
        "the permit must be released as soon as the delay ends"
    );
}

#[tokio::test(start_paused = true)]
async fn delay_is_clamped_to_the_configured_ceiling() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();

    // One hour — the pre-advisory maximum. Even if a future call site skips
    // config validation, the runtime must never park work beyond the ceiling.
    let start = tokio::time::Instant::now();
    let outcome = run_fault_delay_in(&admission, &shutdown, 3_600_000, None).await;
    let elapsed = start.elapsed();

    assert_eq!(outcome, FaultDelayOutcome::Completed);
    assert!(
        elapsed >= Duration::from_millis(MAX_FAULT_DELAY_MS)
            && elapsed < Duration::from_millis(MAX_FAULT_DELAY_MS + 1_000),
        "an over-ceiling duration must be clamped to the ceiling, not honored; \
         waited {elapsed:?}"
    );
}

// ── Peer-gone cancellation ───────────────────────────────────────────

#[tokio::test]
async fn peer_gone_cancels_the_delay_promptly_and_releases_the_permit() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();
    let peer = CancellationToken::new();

    let peer_for_task = peer.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        peer_for_task.cancel();
    });

    let peer_gone = peer.clone();
    let start = std::time::Instant::now();
    let outcome = run_fault_delay_in(
        &admission,
        &shutdown,
        LONG_DELAY_MS,
        Some(Box::pin(async move { peer_gone.cancelled().await })),
    )
    .await;
    let elapsed = start.elapsed();

    assert_eq!(outcome, FaultDelayOutcome::CancelledByPeer);
    assert!(
        elapsed < PROMPT,
        "peer departure must end the delay promptly, took {elapsed:?}"
    );
    assert_eq!(admission.in_flight(), 0);
}

#[tokio::test]
async fn an_already_gone_peer_does_not_wait_at_all() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();
    let peer = CancellationToken::new();
    peer.cancel();

    let outcome = run_fault_delay_in(
        &admission,
        &shutdown,
        LONG_DELAY_MS,
        Some(Box::pin(async move { peer.cancelled().await })),
    )
    .await;

    assert_eq!(outcome, FaultDelayOutcome::CancelledByPeer);
    assert_eq!(admission.in_flight(), 0);
}

// ── Shutdown cancellation ────────────────────────────────────────────

#[tokio::test]
async fn shutdown_cancels_the_delay_promptly() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();

    let shutdown_for_task = shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown_for_task.cancel();
    });

    let start = std::time::Instant::now();
    let outcome = run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await;
    let elapsed = start.elapsed();

    assert_eq!(outcome, FaultDelayOutcome::CancelledByShutdown);
    assert!(
        elapsed < PROMPT,
        "drain must not wait out the fault timer, took {elapsed:?}"
    );
    assert_eq!(admission.in_flight(), 0);
}

#[tokio::test]
async fn shutdown_cancels_a_delay_that_also_has_a_peer_watch() {
    let admission = admission(4);
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let peer = CancellationToken::new();

    let outcome = run_fault_delay_in(
        &admission,
        &shutdown,
        LONG_DELAY_MS,
        Some(Box::pin(async move { peer.cancelled().await })),
    )
    .await;

    assert_eq!(outcome, FaultDelayOutcome::CancelledByShutdown);
}

#[tokio::test]
async fn shutdown_cancels_every_outstanding_delay_at_once() {
    let admission = Arc::new(admission(16));
    let shutdown = CancellationToken::new();
    let finished = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let admission = Arc::clone(&admission);
        let shutdown = shutdown.clone();
        let finished = Arc::clone(&finished);
        handles.push(tokio::spawn(async move {
            let outcome = run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await;
            finished.fetch_add(1, Ordering::SeqCst);
            outcome
        }));
    }

    // Let every task reach its timer before draining.
    while admission.in_flight() < 8 {
        tokio::task::yield_now().await;
    }

    let start = std::time::Instant::now();
    shutdown.cancel();
    for handle in handles {
        assert_eq!(
            handle.await.expect("delay task must not panic"),
            FaultDelayOutcome::CancelledByShutdown
        );
    }
    let elapsed = start.elapsed();

    assert_eq!(finished.load(Ordering::SeqCst), 8);
    assert!(elapsed < PROMPT, "drain took {elapsed:?}");
    assert_eq!(
        admission.in_flight(),
        0,
        "every permit must be released once drain cancels the delays"
    );
}

// ── Admission budget ─────────────────────────────────────────────────

#[tokio::test]
async fn budget_exhaustion_skips_the_delay_instead_of_queueing_it() {
    let admission = Arc::new(admission(1));
    let shutdown = CancellationToken::new();

    let holder_admission = Arc::clone(&admission);
    let holder_shutdown = shutdown.clone();
    let holder = tokio::spawn(async move {
        run_fault_delay_in(&holder_admission, &holder_shutdown, LONG_DELAY_MS, None).await
    });

    while admission.in_flight() < 1 {
        tokio::task::yield_now().await;
    }

    // The second delay must be refused outright — not queued behind the first.
    let start = std::time::Instant::now();
    let outcome = run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await;
    let elapsed = start.elapsed();

    assert_eq!(outcome, FaultDelayOutcome::AdmissionExhausted);
    assert!(!outcome.completed());
    assert!(
        elapsed < PROMPT,
        "an exhausted budget must return immediately, took {elapsed:?}"
    );
    assert_eq!(
        admission.in_flight(),
        1,
        "a refused delay must not consume a slot"
    );

    shutdown.cancel();
    assert_eq!(
        holder.await.expect("holder must not panic"),
        FaultDelayOutcome::CancelledByShutdown
    );
    assert_eq!(admission.in_flight(), 0);
}

#[tokio::test]
async fn a_released_slot_is_reusable() {
    let admission = admission(1);
    let shutdown = CancellationToken::new();

    for _ in 0..5 {
        assert_eq!(
            run_fault_delay_in(&admission, &shutdown, 1, None).await,
            FaultDelayOutcome::Completed
        );
        assert_eq!(admission.in_flight(), 0);
    }
}

#[tokio::test]
async fn zero_capacity_admits_nothing() {
    let admission = admission(0);
    let shutdown = CancellationToken::new();

    // Deliberately not the "0 means unlimited" convention used by optional
    // caps: this bound exists to remove a retention amplifier.
    assert_eq!(
        run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await,
        FaultDelayOutcome::AdmissionExhausted
    );
    assert_eq!(admission.in_flight(), 0);
}

#[tokio::test]
async fn capacity_is_reconfigurable_and_bounds_concurrency_exactly() {
    let admission = Arc::new(admission(0));
    admission.set_capacity(2);
    assert_eq!(admission.capacity(), 2);

    let shutdown = CancellationToken::new();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let admission = Arc::clone(&admission);
        let shutdown = shutdown.clone();
        handles.push(tokio::spawn(async move {
            run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await
        }));
    }
    while admission.in_flight() < 2 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        run_fault_delay_in(&admission, &shutdown, LONG_DELAY_MS, None).await,
        FaultDelayOutcome::AdmissionExhausted
    );
    assert_eq!(admission.in_flight(), 2, "the budget must not be exceeded");

    shutdown.cancel();
    for handle in handles {
        assert_eq!(
            handle.await.expect("delay task must not panic"),
            FaultDelayOutcome::CancelledByShutdown
        );
    }
    assert_eq!(admission.in_flight(), 0);
}

// ── Metadata labels ──────────────────────────────────────────────────

#[test]
fn outcome_labels_are_stable_and_carry_no_request_data() {
    assert_eq!(FaultDelayOutcome::Completed.metadata_label(), "completed");
    assert_eq!(
        FaultDelayOutcome::CancelledByPeer.metadata_label(),
        "peer_gone"
    );
    assert_eq!(
        FaultDelayOutcome::CancelledByShutdown.metadata_label(),
        "shutdown"
    );
    assert_eq!(
        FaultDelayOutcome::AdmissionExhausted.metadata_label(),
        "admission_exhausted"
    );
}

#[test]
fn default_budget_is_conservative() {
    assert_eq!(DEFAULT_MAX_CONCURRENT_FAULT_DELAYS, 256);
}

// ── Shutdown wiring ──────────────────────────────────────────────────

#[test]
fn serving_mode_shutdown_cancels_outstanding_fault_delays() {
    // Behavioral cancellation is covered above with a locally owned token.
    // What cannot be exercised without disarming every other test in this
    // binary is the process-global wiring, so it is pinned at the source.
    let overload = include_str!("../../../src/overload.rs");
    let entry = overload
        .find("pub fn begin_shutdown_drain(")
        .expect("begin_shutdown_drain must exist");
    let body = &overload[entry..entry + 400];
    assert!(
        body.contains("begin_drain(state)"),
        "shutdown drain must still set the drain/reject flags"
    );
    assert!(
        body.contains("fault_delay::cancel_fault_delays_for_shutdown()"),
        "shutdown drain must cancel outstanding injected fault delays"
    );

    // Plain `begin_drain` must NOT cancel the global token: ordinary
    // drain-flag tests call it directly, and a one-shot process-global cancel
    // from a test would silently disarm every later fault delay.
    let plain = overload
        .find("pub fn begin_drain(")
        .expect("begin_drain must exist");
    let plain_body = &overload[plain..entry];
    assert!(
        !plain_body.contains("fault_delay_shutdown"),
        "begin_drain must stay free of the process-global fault-delay cancel"
    );

    for (mode, source) in [
        ("database", include_str!("../../../src/modes/database.rs")),
        ("file", include_str!("../../../src/modes/file.rs")),
        (
            "data_plane",
            include_str!("../../../src/modes/data_plane.rs"),
        ),
        ("mesh", include_str!("../../../src/modes/mesh/mod.rs")),
    ] {
        assert!(
            source.contains("overload::begin_shutdown_drain("),
            "{mode} mode must drain through begin_shutdown_drain so injected \
             fault delays are cancelled on shutdown"
        );
        assert!(
            !source.contains("overload::begin_drain("),
            "{mode} mode must not bypass begin_shutdown_drain"
        );
    }
}

// ── Call-site audit ──────────────────────────────────────────────────

/// Every runtime fault-delay await must go through the bounded helper. A new
/// bare `tokio::time::sleep` on a fault duration would silently reintroduce
/// the unbounded retention this module exists to prevent.
#[test]
fn every_fault_delay_call_site_is_bounded() {
    let plugin = include_str!("../../../src/plugins/fault_injection.rs");
    let dispatch = include_str!("../../../src/plugins/mesh_route_dispatch.rs");

    // HTTP-family hook (proxy-scoped) and the route-local fault share one
    // helper, so peer/shutdown cancellation and the budget cannot diverge.
    assert!(
        plugin.contains("pub(crate) async fn run_http_fault_delay("),
        "the shared HTTP fault-delay helper must exist"
    );
    assert_eq!(
        plugin.matches("run_http_fault_delay(ctx, ").count(),
        1,
        "before_proxy must delay through the shared helper exactly once"
    );
    assert!(
        dispatch.contains("run_http_fault_delay(ctx, delay.duration_ms)"),
        "the route-local fault must delay through the shared helper"
    );

    // Stream admission (TCP + UDP/DTLS) and per-datagram UDP/DTLS delays share
    // the bounded helper: shutdown token + process-wide budget. Peer watches
    // are owned by the stream/datagram proxy paths that race or drop the hook.
    assert_eq!(
        plugin
            .matches("run_fault_delay(d.duration_ms, None)")
            .count(),
        2,
        "on_stream_connect and on_udp_datagram must each delay through the bounded helper once"
    );

    for (name, source) in [
        ("fault_injection", plugin),
        ("mesh_route_dispatch", dispatch),
    ] {
        assert!(
            !source.contains("tokio::time::sleep(std::time::Duration::from_millis(d"),
            "{name} must not await a fault duration on a bare timer"
        );
    }
}
