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
fn a_finished_body_keeps_only_its_resident_charge_until_the_owner_drops() {
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
    // Dispatch and retry replay borrow or clone the body while the handler
    // keeps the charge; it is released once, when the owner drops it.
    let replay = body.clone();
    drop(body);
    assert_eq!(budget.available_bytes(), total - UNIT);
    drop(replay);
    drop(permit);
    assert_eq!(budget.available_bytes(), total);
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
