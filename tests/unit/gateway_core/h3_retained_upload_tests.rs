//! Issue #6009 — native-H3 buffered uploads join the shared retained-request
//! contract H1/H2 already enforce: a finite ceiling when the effective limit is
//! `0`, a charge against `FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES` taken before
//! each growth of the buffer is allocated, growth capped at that ceiling, and
//! release exactly once on every exit.
//!
//! The charge tracks the bytes an upload actually retains, never its whole
//! ceiling before the first byte: a stalled upload that has sent nothing holds
//! no budget, so a client cannot refuse every other principal's buffered upload
//! by opening uploads and sending no body.
//!
//! Every test drives the PRODUCTION collector (`H3RetainedUpload`, the value
//! every native-H3 drain site and the H3 bridge own) against an isolated
//! budget, so charging and release are observable under a parallel binary.

use std::time::Duration;

use ferrum_edge::_test_support::{
    H3RetainedUploadProbe, H3UploadWaitOutcomeForTest,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RequestBufferBudgetProbe,
    ResponseBufferRetainRejection, collect_h3_upload_under_authorization_for_test,
};
use ferrum_edge::proxy::auth_lifetime::ComposedAuthBound;

/// A small upload body.
const SOAP: &[u8] = b"small soap envelope";

/// A two-block fallback ceiling inside an eight-block aggregate budget.
fn budget() -> RequestBufferBudgetProbe {
    RequestBufferBudgetProbe::new(2 * UNIT, 8 * UNIT)
}

#[test]
fn a_zero_limit_upload_charges_nothing_before_its_first_byte() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 0);
    assert_eq!(upload.collected_len(), 0);
    assert_eq!(
        upload.reserved_bytes(),
        0,
        "an upload that has sent nothing must not hold any of the shared budget"
    );
    assert_eq!(budget.available_bytes(), total);
    // The `0` limit still folds to the finite fallback ceiling.
    assert_eq!(upload.push(&vec![1u8; 2 * UNIT]), Ok(()));
    assert_eq!(upload.reserved_bytes(), 2 * UNIT);
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);
    drop(upload);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_zero_limit_upload_is_refused_past_the_fallback_ceiling() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 0);
    assert_eq!(upload.push(&vec![1u8; 2 * UNIT]), Ok(()));
    assert_eq!(
        upload.push(&[1u8]),
        Err(ResponseBufferRetainRejection::TooLarge),
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
fn stalled_uploads_hold_no_budget_and_cannot_starve_a_complete_one() {
    // The audit finding: each buffered upload used to reserve its whole
    // ceiling before a byte arrived, so four stalled uploads held this whole
    // eight-block budget and every other upload got the 503.
    let budget = budget();
    let total = budget.available_bytes();
    let stalled: Vec<_> = (0..64)
        .map(|_| H3RetainedUploadProbe::admit(&budget, 2 * UNIT))
        .collect();
    assert!(stalled.iter().all(|upload| upload.reserved_bytes() == 0));
    assert_eq!(
        budget.available_bytes(),
        total,
        "uploads that have sent no body must not hold any of the shared budget"
    );

    // A complete, ceiling-sized upload from someone else still collects.
    let mut honest = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
    assert_eq!(honest.push(&vec![7u8; 2 * UNIT]), Ok(()));
    let (body, permit) = honest.finish();
    assert_eq!(body.len(), 2 * UNIT);
    assert_eq!(permit.reserved_bytes(), 2 * UNIT);
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);
    drop((body, permit));
    drop(stalled);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn an_exhausted_budget_refuses_growth_with_the_capacity_refusal() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
        assert_eq!(upload.push(&vec![1u8; 2 * UNIT]), Ok(()));
        held.push(upload);
    }
    assert_eq!(budget.available_bytes(), 0);

    // Opening a fifth upload is free; growing it is what the budget refuses,
    // and that refusal is the 503, never the 413.
    let mut fifth = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
    assert_eq!(
        fifth.push(b"x"),
        Err(ResponseBufferRetainRejection::BudgetExhausted),
        "a growth the shared budget cannot cover must get the 503 / RESOURCE_EXHAUSTED refusal"
    );
    drop(fifth);
    assert_eq!(budget.available_bytes(), 0);

    drop(held.pop());
    let mut readmitted = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
    assert_eq!(readmitted.push(&vec![1u8; 2 * UNIT]), Ok(()));
    drop(readmitted);
    drop(held);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_configured_limit_above_the_aggregate_is_refused_when_growth_outruns_it() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 64 * UNIT);
    assert_eq!(upload.reserved_bytes(), 0);
    // The ceiling is honored as a ceiling, but the retained bytes must still
    // fit the aggregate: growth past it is the capacity refusal.
    let mut outcome = Ok(());
    for _ in 0..16 {
        outcome = upload.push(&vec![2u8; UNIT]);
        if outcome.is_err() {
            break;
        }
        assert!(upload.reserved_bytes() <= total);
    }
    assert_eq!(
        outcome,
        Err(ResponseBufferRetainRejection::BudgetExhausted),
        "growth past the aggregate budget is the capacity refusal, not a 413"
    );
    drop(upload);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn growth_never_outruns_the_charged_ceiling() {
    let budget = budget();
    let ceiling = UNIT + 17;
    let mut upload = H3RetainedUploadProbe::admit(&budget, ceiling);
    for _ in 0..ceiling {
        assert_eq!(upload.push(&[3u8]), Ok(()));
    }
    assert_eq!(
        upload.push(&[3u8]),
        Err(ResponseBufferRetainRejection::TooLarge)
    );
    let mut upload = H3RetainedUploadProbe::admit(&budget, ceiling);
    let mut pushed = 0;
    while pushed + 100 <= ceiling {
        assert_eq!(upload.push(&[5u8; 100]), Ok(()));
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
    let mut upload = H3RetainedUploadProbe::admit(&budget, 4 * UNIT);
    assert_eq!(upload.push(b"small soap envelope"), Ok(()));
    let (body, permit) = upload.finish();
    assert_eq!(body, b"small soap envelope");
    assert_eq!(
        permit.reserved_bytes(),
        SOAP.len(),
        "a small body is charged exactly its retained bytes, never a ceiling or a block"
    );
    assert_eq!(budget.available_bytes(), total - SOAP.len());
    drop(body);
    drop(permit);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn a_published_body_is_released_when_its_last_dispatch_copy_drops() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 4 * UNIT);
    assert_eq!(upload.push(b"small soap envelope"), Ok(()));
    // The production publication native-H3 dispatch and both bridges use: the
    // charge moves onto the body, so no handler-held charge outlives it.
    let body = upload
        .finish_and_publish()
        .expect("the charge covers the collected body");
    assert_eq!(&body[..], b"small soap envelope");
    assert_eq!(budget.available_bytes(), total - SOAP.len());
    // The first attempt and a retry replay share the one charged allocation.
    let attempt = body.clone();
    let replay = body.clone();
    drop(body);
    drop(attempt);
    assert_eq!(
        budget.available_bytes(),
        total - SOAP.len(),
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
    let upload = H3RetainedUploadProbe::admit(&budget, 0);
    let (body, permit) = upload.finish();
    assert!(body.is_empty());
    assert_eq!(permit.reserved_bytes(), 0);
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test(start_paused = true)]
async fn a_drain_cancelled_by_its_bound_releases_admission_before_the_wait_returns() {
    let budget = budget();
    let total = budget.available_bytes();
    let mut upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
    assert_eq!(upload.push(&[9u8; 1024]), Ok(()));
    assert_eq!(
        budget.available_bytes(),
        total - 1024,
        "the partial upload is charged for what it retains, not for its ceiling"
    );

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
    let upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
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
        "each native-H3 drain site must open a charged upload before its drain"
    );
    assert_eq!(
        bridge.matches("H3RetainedUpload::admit(").count(),
        2,
        "both H3 bridge drains must open a charged upload before draining"
    );
    // A growth the shared budget refuses is answered by every drain site, and
    // an upload is never charged its ceiling before the first byte again.
    assert_eq!(
        server
            .matches("Ok(Err(RetainRejection::BudgetExhausted)) => {")
            .count(),
        7,
        "every native-H3 drain must answer a refused growth with the capacity refusal"
    );
    assert_eq!(
        bridge
            .matches("RetainRejection::BudgetExhausted)) => {")
            .count(),
        2,
        "both H3 bridge drains must answer a refused growth with the capacity refusal"
    );
    assert!(
        !server.contains("let Some(upload) = H3RetainedUpload::admit("),
        "opening a native-H3 upload must not take a ceiling-sized charge"
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
            "publish_h3_retained_body(body_data, retained_request_charge.take())",
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
            "publish_h3_retained_body(body, bridge_upload_charge.take())",
        ),
    ] {
        assert!(
            source.contains(publication),
            "the request-buffer charge must ride on the dispatched body: `{publication}`"
        );
    }
    // Publication fails closed: a body a request-body plugin grew past what
    // the budget can cover is refused, never retained uncharged.
    let charged = "retained_request_charge.as_mut(),\n";
    assert_eq!(
        server.matches(charged).count(),
        4,
        "the native-H3 normalization and all three transforms must charge their replacements"
    );
    for (source, publication) in [
        (server, "Some(mut body_data) = publish_h3_retained_body("),
        (bridge, "Some(buffered_body) = publish_h3_retained_body("),
        (bridge, "Some(body_bytes) = publish_h3_retained_body("),
    ] {
        assert!(
            source.contains(publication),
            "the dispatched body's publication must fail closed: `{publication}`"
        );
    }
}

#[test]
fn failed_h3_uploads_finalize_once_and_bridge_logs_before_sending() {
    let server = include_str!("../../../src/http3/server.rs");
    let arms: Vec<_> = server
        .split("Err(H3RequestBodyReadError::Read(error)) => {")
        .skip(1)
        .collect();
    assert_eq!(arms.len(), 7);
    for arm in arms {
        let arm = arm.split("return Err(error.into());").next().unwrap();
        assert_eq!(
            arm.matches("boxed_finalize_h3_upload_read_failure(")
                .count(),
            1
        );
    }
    // Issue #6772: the buffered drains mint their client-abort evidence through
    // the shared `ProvenClientAbort`, whose predicate is the streamed paths' too.
    let classify = server
        .split("pub(crate) fn proven_client_abort(")
        .nth(1)
        .unwrap()
        .split("/// Drain an H3 request-body")
        .next()
        .unwrap();
    assert!(classify.contains("ProvenClientAbort::from_h3_request_read_error(error)"));
    let client_abort = include_str!("../../../src/proxy/client_abort.rs");
    assert!(client_abort.contains("h3_request_read_error_is_client_abort(error)"));

    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let finalizer = bridge
        .split("async fn write_final_body_reject<S>(")
        .nth(1)
        .unwrap()
        .split("fn normalize_h3_grpc_reject(")
        .next()
        .unwrap();
    let commit = finalizer
        .find("run_cross_protocol_reject_committed_hooks(")
        .unwrap();
    let log = finalizer
        .find("log_client_disconnect_rejection_with_path(")
        .unwrap();
    let send = finalizer
        .find("write_reject_with_headers_and_recv_halt(")
        .unwrap();
    assert!(commit < log && log < send);
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

    // Eight committed capacity refusals: four dispatch-stage drains, the three
    // request-body transforms that replace a charged body, and the fail-closed
    // publication of the dispatched body.
    assert_eq!(
        server
            .matches("return boxed_finalize_h3_request_buffer_capacity_rejection(")
            .count(),
        8
    );
    let drain_capacity_arm = "Ok(Err(RetainRejection::BudgetExhausted)) => {";
    let oversize_arm = "Ok(Err(RetainRejection::TooLarge)) => {";
    let committed = "return boxed_finalize_h3_request_buffer_capacity_rejection(";
    let mut sites = Vec::new();
    for arm in server.split(drain_capacity_arm).skip(1) {
        let capacity = arm.split(oversize_arm).next().unwrap_or_default();
        if capacity.contains(committed) {
            sites.push(arm);
        }
    }
    assert_eq!(sites.len(), 4, "four dispatch-stage drains refuse capacity");
    for (index, site) in sites.into_iter().enumerate() {
        let oversize = site
            .split("Ok(Err(RetainRejection::TooLarge)) => {")
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
        assert!(
            refusal.contains(call),
            "the bridge refusal must use `{call}`"
        );
    }

    let drains: Vec<&str> = bridge.split("H3RetainedUpload::admit(").skip(1).collect();
    assert_eq!(drains.len(), 2, "both H3 bridge drains take admission");
    for (index, drain) in drains.into_iter().enumerate() {
        let refusals = drain
            .split("Err(super::server::H3RequestBodyReadError::")
            .next()
            .unwrap_or_else(|| panic!("bridge drain {index} must be bounded"));
        assert_eq!(
            refusals
                .matches("Box::pin(write_bridge_upload_refusal(")
                .count(),
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

#[test]
fn every_h3_drain_reads_to_the_end_of_the_request_stream() {
    // Issue #6022: `recv_data` also ends at a trailer section, which ends the
    // body but not the stream. Every buffered native-H3 and bridge drain goes
    // through this one function, which must read on to the stream's own end
    // before it hands the body over, so a reset after the trailers is refused.
    // On-the-wire proof: `h3_buffered_drain_refuses_a_reset_after_the_trailer_section`.
    let server = include_str!("../../../src/http3/server.rs");
    let drain = server
        .split("pub(crate) async fn drain_h3_request_body<S>(")
        .nth(1)
        .expect("shared H3 drain")
        .split("\n}\n")
        .next()
        .expect("bounded shared H3 drain");
    let body_loop = drain
        .find("while let Some(chunk) = stream.recv_data().await? {")
        .expect("body loop");
    // `recv_trailers`, not a second `recv_data`: it waits for the FIN and
    // refuses any known frame after the trailers, where a second `recv_data`
    // takes an empty DATA frame or a second HEADERS frame as a clean end.
    let end_of_stream = drain
        .find("stream.recv_trailers().await?;")
        .expect("end-of-stream read after the body loop");
    let finish = drain.find("upload.finish()").expect("upload hand-over");
    assert!(
        body_loop < end_of_stream && end_of_stream < finish,
        "the drain must confirm the stream ended before it hands the body over"
    );
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        bridge.contains("super::server::drain_h3_request_body(stream, upload, charge).await"),
        "the bridge drains must share the native-H3 drain"
    );
}

#[test]
fn many_one_byte_uploads_hold_only_their_bytes_and_a_complete_upload_still_fits() {
    // Charges are byte-granular: a one-byte stalled upload holds one byte of
    // the budget, never a whole reservation block.
    let budget = budget();
    let total = budget.available_bytes();
    let mut trickling = Vec::new();
    for _ in 0..4096 {
        let mut upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
        assert_eq!(upload.push(b"x"), Ok(()));
        trickling.push(upload);
    }
    assert_eq!(budget.available_bytes(), total - 4096);

    // A complete, ceiling-sized upload from someone else still collects.
    let mut honest = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
    assert_eq!(honest.push(&vec![7u8; 2 * UNIT]), Ok(()));
    drop(honest);

    // Genuinely retained bytes still exhaust the budget.
    let mut fill = Vec::new();
    loop {
        let mut upload = H3RetainedUploadProbe::admit(&budget, 2 * UNIT);
        match upload.push(&vec![1u8; 2 * UNIT]) {
            Ok(()) => fill.push(upload),
            Err(rejection) => {
                assert_eq!(rejection, ResponseBufferRetainRejection::BudgetExhausted);
                break;
            }
        }
        assert!(fill.len() <= 4, "the budget must still bound retained bytes");
    }
    drop((trickling, fill));
    assert_eq!(budget.available_bytes(), total);
}
