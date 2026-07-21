//! Early buffered-upload deadline composition and cancellation contracts.
//!
//! Covers H1/H2 and H3 helpers for the shared early body phases (authenticate,
//! authorize, before_proxy) required by GHSA-rrx3-m3wf-wg3w / issue #2669:
//! absolute RPC deadline vs operator whole-upload timeout, timeout-disabled
//! (`0`) semantics, and source-level halt/drain wiring across every H3 phase.

use std::time::Duration;

use ferrum_edge::_test_support::{
    EarlyUploadWaitError, collect_h1h2_request_body_with_deadline_for_test,
    collect_h3_request_body_with_deadline_for_test,
};

#[tokio::test]
async fn h1h2_and_h3_operator_timeout_caps_a_long_rpc_deadline() {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("one minute after now is representable");
    let pending = std::future::pending::<Result<(), ()>>();

    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(pending, Some(deadline), 10).await;
    assert!(matches!(h1h2, Err(EarlyUploadWaitError::TimedOut)));

    let pending = std::future::pending::<Result<(), ()>>();
    let h3 = collect_h3_request_body_with_deadline_for_test(pending, Some(deadline), 10).await;
    assert!(matches!(h3, Err(EarlyUploadWaitError::TimedOut)));
}

#[tokio::test]
async fn h1h2_and_h3_rpc_deadline_wins_over_a_larger_operator_timeout() {
    let deadline = tokio::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("one second before now is representable");

    let pending = std::future::pending::<Result<(), ()>>();
    let h1h2 =
        collect_h1h2_request_body_with_deadline_for_test(pending, Some(deadline), 60_000).await;
    assert!(matches!(h1h2, Err(EarlyUploadWaitError::DeadlineExceeded)));

    let pending = std::future::pending::<Result<(), ()>>();
    let h3 = collect_h3_request_body_with_deadline_for_test(pending, Some(deadline), 60_000).await;
    assert!(matches!(h3, Err(EarlyUploadWaitError::DeadlineExceeded)));
}

#[tokio::test]
async fn zero_operator_timeout_still_honors_rpc_deadline_on_h1h2_and_h3() {
    let deadline = tokio::time::Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("one millisecond before now is representable");

    let pending = std::future::pending::<Result<(), ()>>();
    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(pending, Some(deadline), 0).await;
    assert!(matches!(h1h2, Err(EarlyUploadWaitError::DeadlineExceeded)));

    let pending = std::future::pending::<Result<(), ()>>();
    let h3 = collect_h3_request_body_with_deadline_for_test(pending, Some(deadline), 0).await;
    assert!(matches!(h3, Err(EarlyUploadWaitError::DeadlineExceeded)));
}

#[tokio::test]
async fn zero_operator_timeout_without_deadline_leaves_upload_unbounded_helpers() {
    let upload = std::future::ready::<Result<u8, ()>>(Ok(7));
    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(upload, None, 0)
        .await
        .expect("disabled timeout must not invent an error");
    assert_eq!(h1h2, Ok(7));

    let upload = std::future::ready::<Result<u8, ()>>(Ok(11));
    let h3 = collect_h3_request_body_with_deadline_for_test(upload, None, 0)
        .await
        .expect("disabled timeout must not invent an error");
    assert_eq!(h3, Ok(11));
}

#[tokio::test]
async fn completed_uploads_are_not_failed_by_future_deadlines() {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("thirty seconds after now is representable");

    let upload = std::future::ready::<Result<&'static str, ()>>(Ok("done"));
    let h1h2 = collect_h1h2_request_body_with_deadline_for_test(upload, Some(deadline), 1_000)
        .await
        .expect("completed upload");
    assert_eq!(h1h2, Ok("done"));

    let upload = std::future::ready::<Result<&'static str, ()>>(Ok("done"));
    let h3 = collect_h3_request_body_with_deadline_for_test(upload, Some(deadline), 1_000)
        .await
        .expect("completed upload");
    assert_eq!(h3, Ok("done"));
}

#[tokio::test]
async fn cancelled_pending_upload_does_not_retain_caller_owned_buffer() {
    // Mimic the pre-fix outer-buffer anti-pattern: if the collect future owned
    // the Vec, cancellation would drop it. The H3 drain helper owns the buffer
    // inside the future; this parity check ensures the deadline helper cancels
    // promptly rather than waiting for the pending future forever.
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(20))
        .expect("deadline representable");
    let started = tokio::time::Instant::now();
    let pending = std::future::pending::<Result<Vec<u8>, ()>>();
    let result = collect_h3_request_body_with_deadline_for_test(pending, Some(deadline), 0).await;
    assert!(matches!(result, Err(EarlyUploadWaitError::DeadlineExceeded)));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "deadline cancellation must unbound a stalled upload promptly"
    );
}

#[test]
fn h3_early_phases_use_owned_drain_and_immediate_halt_on_cancel() {
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

    assert!(source.contains("async fn drain_h3_request_body<"));
    assert_eq!(
        source.matches("drain_h3_request_body(&mut stream,").count(),
        7,
        "every native H3 buffered upload site must use the owned-buffer drain"
    );
    assert!(source.contains("pub(crate) async fn drain_h3_request_body<"));
    assert!(
        !source.contains(
            "let collect = async {\n            while let Some(chunk) = stream.recv_data()"
        ),
        "early/buffered H3 uploads must not accumulate into an outer buffer across cancellation"
    );
}

#[test]
fn h1h2_early_phases_compose_absolute_deadline_with_operator_timeout() {
    let source = include_str!("../../../src/proxy/mod.rs");
    for phase in [
        "grpc_deadline_upload_before_authenticate",
        "grpc_deadline_upload_before_authorize",
        "grpc_deadline_upload_before_before_proxy",
    ] {
        assert!(
            source.contains(phase),
            "missing H1/H2 early upload deadline phase {phase}"
        );
    }

    let helper = source
        .split("pub(crate) async fn collect_request_body_with_deadline<")
        .nth(1)
        .expect("H1/H2 deadline helper")
        .split("pub(crate) fn request_may_have_body(")
        .next()
        .expect("bounded H1/H2 deadline helper");
    assert!(helper.contains("timeout_at(effective_deadline, collect)"));
    assert!(helper.contains("RequestBodyWaitError::TimedOut"));
    assert!(helper.contains("RequestBodyWaitError::DeadlineExceeded"));
    assert!(
        helper.contains("request_body_read_timeout_ms > 0"),
        "operator timeout 0 must disable the fresh read bound"
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
