//! Issue #6009 — native-H3 buffered uploads join the shared retained-request
//! contract H1/H2 already enforce: a finite ceiling when the effective limit is
//! `0`, admission against `FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES` before a byte
//! is allocated, growth capped at that ceiling, and release exactly once on
//! every exit.
//!
//! Every test drives the PRODUCTION collector (`H3RetainedUpload`, the value
//! every native-H3 drain site and the H3 bridge own) against an isolated
//! budget, so admission and release are observable under a parallel binary.

use std::time::Duration;

use ferrum_edge::_test_support::{
    H3RetainedUploadProbe, H3UploadWaitOutcomeForTest,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RequestBufferBudgetProbe,
    collect_h3_upload_under_authorization_for_test,
};
use ferrum_edge::proxy::auth_lifetime::ComposedAuthBound;

/// A two-block fallback ceiling inside an eight-block aggregate budget.
fn budget() -> RequestBufferBudgetProbe {
    RequestBufferBudgetProbe::new(2 * UNIT, 8 * UNIT)
}

#[test]
fn a_zero_limit_is_admitted_at_the_finite_fallback_before_any_byte() {
    let budget = budget();
    let total = budget.available_bytes();
    let upload = H3RetainedUploadProbe::admit(&budget, 0).expect("admitted");
    assert_eq!(upload.collected_len(), 0);
    assert_eq!(
        upload.reserved_bytes(),
        2 * UNIT,
        "a `0` limit must charge the finite fallback ceiling, not run unbounded"
    );
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);
    drop(upload);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_zero_limit_upload_is_refused_past_the_fallback_ceiling() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 0).expect("admitted");
    assert!(upload.push(&vec![1u8; 2 * UNIT]));
    assert!(
        !upload.push(&[1u8]),
        "one byte past the fallback ceiling is the 413, never an unbounded Vec"
    );
    drop(upload);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the 413 releases exactly once"
    );
}

#[test]
fn an_exhausted_budget_refuses_admission_before_collection() {
    let budget = budget();
    let held: Vec<_> = (0..4)
        .map(|_| H3RetainedUploadProbe::admit(&budget, 2 * UNIT).expect("admitted"))
        .collect();
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        H3RetainedUploadProbe::admit(&budget, 2 * UNIT).is_none(),
        "a fifth concurrent upload must get the 503 / RESOURCE_EXHAUSTED refusal"
    );
    drop(held);
    assert!(H3RetainedUploadProbe::admit(&budget, 2 * UNIT).is_some());
}

#[test]
fn a_configured_limit_above_the_aggregate_is_never_admissible() {
    let budget = budget();
    assert!(
        H3RetainedUploadProbe::admit(&budget, 64 * UNIT).is_none(),
        "the ceiling is honored as a ceiling, but must still fit the aggregate"
    );
    assert_eq!(budget.available_bytes(), 8 * UNIT);
}

#[test]
fn growth_never_outruns_the_charged_ceiling() {
    let budget = budget();
    let ceiling = UNIT + 17;
    let mut upload = H3RetainedUploadProbe::admit(&budget, ceiling).expect("admitted");
    for _ in 0..ceiling {
        assert!(upload.push(&[3u8]));
    }
    assert!(!upload.push(&[3u8]));
    let mut upload = H3RetainedUploadProbe::admit(&budget, ceiling).expect("admitted");
    let mut pushed = 0;
    while pushed + 100 <= ceiling {
        assert!(upload.push(&[5u8; 100]));
        pushed += 100;
    }
    let (body, permit) = upload.finish();
    assert_eq!(body.len(), pushed);
    assert!(
        body.capacity() <= ceiling,
        "geometric growth must clamp to the charged ceiling"
    );
    assert!(permit.reserved_bytes() >= body.capacity());
}

#[test]
fn a_finished_body_keeps_only_its_resident_charge() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 4 * UNIT).expect("admitted");
    assert!(upload.push(b"small soap envelope"));
    let (body, permit) = upload.finish();
    assert_eq!(body, b"small soap envelope");
    assert_eq!(
        permit.reserved_bytes(),
        UNIT,
        "a small body must not hold a ceiling-sized claim for the whole request"
    );
    assert_eq!(budget.available_bytes(), total - UNIT);
    drop(body);
    drop(permit);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_published_body_is_released_when_its_last_dispatch_copy_drops() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 4 * UNIT).expect("admitted");
    assert!(upload.push(b"small soap envelope"));
    // The production publication native-H3 dispatch and both bridges use: the
    // charge moves onto the body, so no handler-held charge outlives it.
    let body = upload.finish_and_publish();
    assert_eq!(&body[..], b"small soap envelope");
    assert_eq!(budget.available_bytes(), total - UNIT);
    // The first attempt and a retry replay share the one charged allocation.
    let attempt = body.clone();
    let replay = body.clone();
    drop(body);
    drop(attempt);
    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "a live replay copy keeps the allocation charged"
    );
    drop(replay);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the last dispatch copy releases the charge, before any response relay"
    );
}

#[test]
fn an_empty_body_retains_no_charge_after_finish() {
    let budget = budget();
    let total = budget.available_bytes();
    let upload = H3RetainedUploadProbe::admit(&budget, 0).expect("admitted");
    let (body, permit) = upload.finish();
    assert!(body.is_empty());
    assert_eq!(permit.reserved_bytes(), 0);
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test(start_paused = true)]
async fn a_drain_cancelled_by_its_bound_releases_admission_before_the_wait_returns() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT).expect("admitted");
    assert!(upload.push(&[9u8; 1024]));
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    // The partial buffer and its charge live inside the drain future, exactly
    // as `drain_h3_request_body` owns them; a trickling client never finishes.
    let drain = async move {
        let _owned = upload;
        std::future::pending::<Result<(), ()>>().await
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
    let outcome = collect_h3_upload_under_authorization_for_test(
        drain,
        ComposedAuthBound::compose(Some(deadline), None),
        0,
    )
    .await;
    assert_eq!(outcome, H3UploadWaitOutcomeForTest::DeadlineExceeded);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the cancelled drain must release its partial buffer and admission before any \
         rejection hook can run"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_bound_never_polls_the_admitted_drain() {
    let budget = budget();
    let total = budget.available_bytes();
    let upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT).expect("admitted");
    let deadline = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(1)).await;
    let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = std::sync::Arc::clone(&polled);
    let ready_body = async move {
        let _owned = upload;
        seen.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<(), ()>(())
    };
    let outcome = collect_h3_upload_under_authorization_for_test(
        ready_body,
        ComposedAuthBound::compose(Some(deadline), None),
        0,
    )
    .await;
    assert_eq!(outcome, H3UploadWaitOutcomeForTest::DeadlineExceeded);
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn every_native_h3_drain_site_admits_before_it_drains() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    assert_eq!(
        server
            .matches("drain_h3_request_body(&mut stream, upload, &mut retained_request_charge),")
            .count(),
        7,
        "all seven native-H3 drain sites must drain an admitted upload into the handler charge"
    );
    assert_eq!(
        server.matches("H3RetainedUpload::admit(").count(),
        7,
        "each native-H3 drain site must take admission before its drain"
    );
    assert_eq!(
        bridge.matches("H3RetainedUpload::admit(").count(),
        2,
        "both H3 bridge drains must take admission before draining"
    );
    assert!(
        !server.contains("max_bytes > 0 && body.len()"),
        "a `0` limit must never disable the native-H3 retained ceiling again"
    );
}

#[test]
fn every_h3_dispatch_publishes_the_charge_with_the_body() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    for (source, publication) in [
        (
            server,
            "publish_h3_retained_body(body_data, retained_request_charge.take());",
        ),
        (
            server,
            "prebuffered_body_charge: retained_request_charge.take(),",
        ),
        (
            bridge,
            "prebuffered_body_charge.or(mesh_upload_charge.take()),",
        ),
        (
            bridge,
            "publish_h3_retained_body(body, bridge_upload_charge.take());",
        ),
    ] {
        assert!(
            source.contains(publication),
            "the request-buffer charge must ride on the dispatched body: `{publication}`"
        );
    }
}

#[test]
fn every_dispatch_stage_h3_drain_refusal_runs_the_reject_hooks_and_the_log() {
    // Issue #6022: a native-H3 drain after `before_proxy` refuses an oversized
    // upload through the same finalizer as its capacity refusal, so the
    // reject-path hooks, the committed-response hooks, and the transaction log
    // run on the `413` too.
    let server = include_str!("../../../src/http3/server.rs");
    let terminal = server
        .split("async fn finalize_h3_terminal_body_rejection_with_headers(")
        .nth(1)
        .expect("shared terminal-body rejection finalizer")
        .split("/// Optional HTTP/3 listener settings")
        .next()
        .expect("bounded terminal-body rejection finalizer");
    for call in [
        "apply_reject_after_proxy_and_synthetic_body_hooks(",
        "run_h3_reject_response_committed_hooks(",
        "log_rejected_request_with_path(",
    ] {
        assert!(terminal.contains(call), "the finalizer must call `{call}`");
    }
    let refusal = server
        .split("fn boxed_finalize_h3_dispatch_body_refusal<'a>(")
        .nth(1)
        .expect("shared dispatch-stage drain refusal")
        .split("/// Promptly stop a cancelled or rejected H3 upload")
        .next()
        .expect("bounded dispatch-stage drain refusal");
    assert!(refusal.contains("finalize_h3_terminal_body_rejection_with_headers("));
    assert!(refusal.contains("send_h3_plugin_reject_flavor_aware("));

    let sites: Vec<&str> = server
        .split("return boxed_finalize_h3_request_buffer_capacity_rejection(")
        .skip(1)
        .collect();
    assert_eq!(sites.len(), 4, "four dispatch-stage drains refuse capacity");
    for (index, site) in sites.into_iter().enumerate() {
        let oversize = site
            .split("Ok(None) => {")
            .nth(1)
            .unwrap_or_else(|| panic!("drain {index} must have an oversize arm"))
            .split("Err(H3RequestBodyReadError::Read(")
            .next()
            .unwrap_or_else(|| panic!("drain {index} oversize arm must be bounded"));
        assert!(
            oversize.contains("boxed_finalize_h3_request_body_too_large_rejection(")
                || oversize.contains("finalize_h3_terminal_body_read_rejection("),
            "drain {index}: the oversize refusal must commit through the shared finalizer"
        );
        assert!(
            !oversize.contains("send_h3_error_flavor_aware_with_policy("),
            "drain {index}: the oversize refusal must not write an unhooked, unlogged 413"
        );
    }
}

#[test]
fn both_h3_bridge_drain_refusals_run_the_reject_hooks_and_the_log() {
    // Issue #6022: the bridge's own drains refuse capacity and oversize
    // through the shared bridge reject path, which runs the reject-path
    // `after_proxy` hooks and committed observers and logs the rejection, so
    // the frontend does not log a second, generic summary.
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let refusal = bridge
        .split("async fn write_bridge_upload_refusal<S>(")
        .nth(1)
        .expect("shared bridge drain refusal")
        .split("/// How [`write_final_body_reject`] runs")
        .next()
        .expect("bounded bridge drain refusal");
    for call in [
        "write_final_body_reject(",
        "FinalRejectHooks::Standard,",
        "crate::proxy::log_rejected_request(",
        "outcome.rejection_logged = true;",
    ] {
        assert!(refusal.contains(call), "the bridge refusal must use `{call}`");
    }

    let drains: Vec<&str> = bridge.split("H3RetainedUpload::admit(").skip(1).collect();
    assert_eq!(drains.len(), 2, "both H3 bridge drains take admission");
    for (index, drain) in drains.into_iter().enumerate() {
        let refusals = drain
            .split("Err(super::server::H3RequestBodyReadError::")
            .next()
            .unwrap_or_else(|| panic!("bridge drain {index} must be bounded"));
        assert_eq!(
            refusals.matches("Box::pin(write_bridge_upload_refusal(").count(),
            2,
            "bridge drain {index}: the capacity and oversize refusals take the shared path"
        );
        assert!(
            !refusals.contains("write_plain_gateway_error(")
                && !refusals.contains("write_grpc_error_for_request("),
            "bridge drain {index}: no refusal may bypass the reject hooks and the log"
        );
    }
}
