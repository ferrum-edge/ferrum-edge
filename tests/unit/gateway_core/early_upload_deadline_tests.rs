//! Early buffered-upload deadline composition and cancellation contracts.
//!
//! Executable coverage for GHSA-rrx3-m3wf-wg3w / issue #2669: earliest-of
//! operator whole-upload timeout vs absolute `grpc-timeout`, timeout-`0`
//! semantics, prompt cancellation that drops caller-owned buffers, independent
//! concurrent waiters, and multi-consumer prebuffer reuse (no second fresh
//! operator window). Live H1/H2/H3 protocol shaping lives in
//! `tests/functional/functional_early_upload_deadline_test.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::{
    EarlyUploadBoundKind, EarlyUploadWaitError, collect_h1h2_request_body_with_deadline_for_test,
    collect_h3_request_body_with_deadline_for_test, compose_early_upload_bound_for_test,
    early_upload_phase_needs_fresh_drain_for_test,
};

#[test]
fn compose_earliest_of_picks_operator_when_it_is_sooner() {
    let absolute = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("representable");
    let (effective, kind) =
        compose_early_upload_bound_for_test(Some(absolute), 25).expect("bound must exist");
    assert_eq!(kind, EarlyUploadBoundKind::OperatorTimeout);
    assert!(effective <= absolute);
    assert!(
        effective
            <= tokio::time::Instant::now()
                .checked_add(Duration::from_millis(25))
                .expect("representable")
    );
}

#[test]
fn compose_earliest_of_picks_absolute_rpc_deadline_when_sooner() {
    let absolute = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(5))
        .expect("representable");
    let (effective, kind) =
        compose_early_upload_bound_for_test(Some(absolute), 60_000).expect("bound must exist");
    assert_eq!(kind, EarlyUploadBoundKind::RpcDeadline);
    assert_eq!(effective, absolute);
}

#[test]
fn compose_timeout_zero_still_honors_absolute_deadline() {
    let absolute = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(10))
        .expect("representable");
    let (effective, kind) =
        compose_early_upload_bound_for_test(Some(absolute), 0).expect("RPC bound remains");
    assert_eq!(kind, EarlyUploadBoundKind::RpcDeadline);
    assert_eq!(effective, absolute);
}

#[test]
fn compose_timeout_zero_without_deadline_disables_all_bounds() {
    assert!(compose_early_upload_bound_for_test(None, 0).is_none());
}

#[test]
fn later_early_phases_reuse_one_prebuffer_instead_of_a_second_drain() {
    let mut prebuffered: Option<Vec<u8>> = None;
    assert!(early_upload_phase_needs_fresh_drain_for_test(&prebuffered));

    // First consumer (authenticate / authorize / before_proxy) owns the drain.
    prebuffered = Some(vec![1, 2, 3]);
    assert!(
        !early_upload_phase_needs_fresh_drain_for_test(&prebuffered),
        "a second early-phase consumer must reuse the bounded prebuffer"
    );

    // Simulate a second consumer that would otherwise start a fresh operator
    // window: with reuse, composition is never consulted again for that body.
    let absolute = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("representable");
    let first = compose_early_upload_bound_for_test(Some(absolute), 40).expect("first drain bound");
    assert_eq!(first.1, EarlyUploadBoundKind::OperatorTimeout);
    assert!(
        !early_upload_phase_needs_fresh_drain_for_test(&prebuffered),
        "must not deduct a second fresh operator timeout after prebuffering"
    );
}

#[tokio::test(start_paused = true)]
async fn h1h2_and_h3_operator_timeout_caps_a_long_rpc_deadline_without_wall_sleep() {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("representable");

    let h1h2_pending = std::future::pending::<Result<(), ()>>();
    let h1h2_task = tokio::spawn(async move {
        collect_h1h2_request_body_with_deadline_for_test(h1h2_pending, Some(deadline), 10).await
    });
    let h3_pending = std::future::pending::<Result<(), ()>>();
    let h3_task = tokio::spawn(async move {
        collect_h3_request_body_with_deadline_for_test(h3_pending, Some(deadline), 10).await
    });

    // Register timeout_at waiters before advancing paused time.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;

    let h1h2 = h1h2_task.await.expect("join");
    let h3 = h3_task.await.expect("join");
    assert!(matches!(h1h2, Err(EarlyUploadWaitError::TimedOut)));
    assert!(matches!(h3, Err(EarlyUploadWaitError::TimedOut)));
}

#[tokio::test(start_paused = true)]
async fn h1h2_and_h3_rpc_deadline_wins_over_larger_operator_timeout_without_wall_sleep() {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(15))
        .expect("representable");

    let h1h2_pending = std::future::pending::<Result<(), ()>>();
    let h1h2_task = tokio::spawn(async move {
        collect_h1h2_request_body_with_deadline_for_test(h1h2_pending, Some(deadline), 60_000).await
    });
    let h3_pending = std::future::pending::<Result<(), ()>>();
    let h3_task = tokio::spawn(async move {
        collect_h3_request_body_with_deadline_for_test(h3_pending, Some(deadline), 60_000).await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(15)).await;
    tokio::task::yield_now().await;

    assert!(matches!(
        h1h2_task.await.expect("join"),
        Err(EarlyUploadWaitError::DeadlineExceeded)
    ));
    assert!(matches!(
        h3_task.await.expect("join"),
        Err(EarlyUploadWaitError::DeadlineExceeded)
    ));
}

#[tokio::test]
async fn zero_operator_timeout_still_honors_already_expired_rpc_deadline() {
    let deadline = tokio::time::Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("representable");

    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(
        std::future::pending::<Result<(), ()>>(),
        Some(deadline),
        0,
    )
    .await;
    assert!(matches!(h1h2, Err(EarlyUploadWaitError::DeadlineExceeded)));

    let h3 = collect_h3_request_body_with_deadline_for_test(
        std::future::pending::<Result<(), ()>>(),
        Some(deadline),
        0,
    )
    .await;
    assert!(matches!(h3, Err(EarlyUploadWaitError::DeadlineExceeded)));
}

#[tokio::test]
async fn zero_operator_timeout_without_deadline_leaves_completed_upload_unbounded() {
    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(
        std::future::ready::<Result<u8, ()>>(Ok(7)),
        None,
        0,
    )
    .await
    .expect("disabled timeout must not invent an error");
    assert_eq!(h1h2, Ok(7));

    // H3 flattens collect success into Result<T, EarlyUploadWaitError>; after
    // expect the value is T (not a nested Ok), unlike the H1/H2 helper above.
    let h3 = collect_h3_request_body_with_deadline_for_test(
        std::future::ready::<Result<u8, ()>>(Ok(11)),
        None,
        0,
    )
    .await
    .expect("disabled timeout must not invent an error");
    assert_eq!(h3, 11);
}

#[tokio::test(start_paused = true)]
async fn cancelled_pending_upload_drops_future_owned_buffer() {
    let dropped = Arc::new(AtomicBool::new(false));
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let flag = Arc::clone(&dropped);
    let upload = async move {
        let _guard = DropFlag(flag);
        let mut body = vec![0_u8; 64 * 1024];
        std::future::pending::<()>().await;
        // Keep the buffer live across the pending await so cancellation must
        // drop it with the future (owned-drain contract).
        body.fill(1);
        Ok::<Vec<u8>, ()>(body)
    };

    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(20))
        .expect("representable");
    let task = tokio::spawn(async move {
        collect_h3_request_body_with_deadline_for_test(upload, Some(deadline), 0).await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;

    assert!(matches!(
        task.await.expect("join"),
        Err(EarlyUploadWaitError::DeadlineExceeded)
    ));
    assert!(
        dropped.load(Ordering::SeqCst),
        "deadline cancellation must drop the drain-owned buffer promptly"
    );
}

#[tokio::test(start_paused = true)]
async fn one_cancelled_waiter_does_not_block_an_independent_concurrent_waiter() {
    let completed = Arc::new(AtomicUsize::new(0));

    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(10))
        .expect("representable");
    let slow = tokio::spawn(async move {
        collect_h3_request_body_with_deadline_for_test(
            std::future::pending::<Result<(), ()>>(),
            Some(deadline),
            0,
        )
        .await
    });

    let counter = Arc::clone(&completed);
    let fast = tokio::spawn(async move {
        let result = collect_h3_request_body_with_deadline_for_test(
            std::future::ready::<Result<&'static str, ()>>(Ok("ok")),
            None,
            0,
        )
        .await;
        counter.fetch_add(1, Ordering::SeqCst);
        result
    });

    // Fast stream must complete while the slow waiter is still outstanding.
    tokio::task::yield_now().await;
    let fast_result = fast.await.expect("join");
    assert_eq!(fast_result, Ok("ok"));
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert!(!slow.is_finished());

    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    assert!(matches!(
        slow.await.expect("join"),
        Err(EarlyUploadWaitError::DeadlineExceeded)
    ));
}

#[test]
fn h3_early_phases_gate_fresh_drains_on_missing_prebuffer_and_halt_on_cancel() {
    let source = include_str!("../../../src/http3/server.rs");

    for phase in [
        "grpc_deadline_upload_before_authenticate",
        "grpc_deadline_upload_before_authorize",
        "grpc_deadline_upload_before_before_proxy",
        "grpc_deadline_terminal_h3_upload",
        "grpc_deadline_upload_before_dispatch",
        "grpc_deadline_upload_before_cross_protocol_dispatch",
        "grpc_deadline_buffered_h3_upload",
    ] {
        let phase_idx = source
            .find(phase)
            .unwrap_or_else(|| panic!("missing H3 upload phase {phase}"));
        let window = &source[phase_idx.saturating_sub(500)..phase_idx];
        assert!(
            window.contains("halt_cancelled_h3_upload("),
            "phase {phase} must STOP_SENDING before rejection work"
        );
    }

    assert!(
        source.contains("early_upload_phase_needs_fresh_drain(&prebuffered_body_data)"),
        "authorize/before_proxy must gate fresh drains via the shared prebuffer helper"
    );
    assert!(
        source.contains("if !body_was_prebuffered"),
        "later buffered/dispatch phases must skip a second drain when a prebuffer exists"
    );
    assert_eq!(
        source.matches("drain_h3_request_body(&mut stream,").count(),
        7,
        "every native H3 buffered upload site must use the owned-buffer drain"
    );
    assert!(
        !source.contains(
            "let collect = async {\n            while let Some(chunk) = stream.recv_data()"
        ),
        "early/buffered H3 uploads must not accumulate into an outer buffer across cancellation"
    );
}

#[test]
fn h3_cross_protocol_bridge_halts_cancelled_buffered_uploads() {
    let source = include_str!("../../../src/http3/cross_protocol.rs");
    let start = source
        .find("let body = if let Some(buffered) = prebuffered_body")
        .expect("bridge buffered body match");
    let end = source[start..]
        .find("let bytes_sent = if body_was_prebuffered")
        .expect("bridge body match must remain bounded");
    let bridge = &source[start..start + end];
    assert!(bridge.contains("collect_h3_request_body_with_deadline("));
    assert!(bridge.contains("drain_h3_body("));
    assert_eq!(
        bridge.matches("halt_request_body(stream)").count(),
        4,
        "too-large, read, timed-out, and deadline bridge exits must STOP_SENDING promptly"
    );
}
