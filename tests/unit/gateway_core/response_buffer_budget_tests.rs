//! GHSA-pwcm-6rh8-f2gh — aggregate retained-response budget.
//!
//! The properties under test are the ones a collector-local reservation does
//! NOT give you: that the charge survives a successful return, that it is
//! released when the retained allocation is finally dropped, that a cheap clone
//! shares one charge instead of minting a second, that preallocated capacity is
//! charged before it is allocated, and that an exhaustion refusal is classified
//! as gateway-local transient capacity rather than a backend fault.
//!
//! Every test runs against `ResponseBufferBudgetProbe`, which is the production
//! budget type with its own semaphore — same clamping, same non-blocking
//! admission, same charge attachment — so these cannot pass against a parallel
//! implementation of the rules, and they do not race the process-global budget
//! under a parallel test binary.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    BufferedRepresentationOutcome, MAX_DECODED_RESPONSE_INSPECTION_BYTES,
    RESPONSE_BUFFER_OVERLOAD_BODY, RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
    RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS, RESPONSE_BUFFER_OVERLOAD_STATUS,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RESPONSE_DECODE_BROTLI_SCRATCH_BYTES,
    RESPONSE_DECODE_GZIP_SCRATCH_BYTES, ResponseBufferBudgetProbe, ResponseBufferRetainRejection,
    error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    install_response_buffer_capacity_refusal_for_test, projected_decode_output_capacity_for_test,
    set_request_http_flavor_for_test, stamp_original_response_metadata_for_test,
};
use ferrum_edge::HttpFlavor;
use ferrum_edge::plugins::{Plugin, RequestContext, response_transformer::ResponseTransformer};
use ferrum_edge::retry::ErrorClass;

/// 8 blocks of budget, with a 1-block fallback ceiling so the floor does not
/// dominate the total.
fn probe(total_blocks: usize) -> ResponseBufferBudgetProbe {
    ResponseBufferBudgetProbe::new(UNIT, total_blocks * UNIT)
}

// ---------------------------------------------------------------------------
// Lifetime: the charge outlives the collector and follows the allocation.
// ---------------------------------------------------------------------------

#[test]
fn a_charge_survives_the_collectors_successful_return() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Exactly what a collector does: reserve while growing, then publish.
    let body = {
        let mut charge = budget.try_reserve(UNIT).expect("first block admits");
        assert!(budget.grow(&mut charge, 3 * UNIT), "growth admits");
        budget
            .attach(vec![0u8; 3 * UNIT], charge)
            .expect("a covered allocation publishes")
    };

    // The collector frame is gone. If the charge had been a collector local,
    // the budget would be fully available here while 3 blocks stay resident —
    // exactly the bypass this advisory describes.
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the retained body must still be charged after collection returned"
    );
    assert_eq!(body.len(), 3 * UNIT);
}

#[test]
fn dropping_the_retained_body_releases_the_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let body = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("admits");
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    drop(body);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the budget is returned when the retained allocation is dropped"
    );
}

#[test]
fn cheap_clones_share_exactly_one_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let body = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("admits");
    let charged_once = budget.available_bytes();
    assert_eq!(charged_once, total - 2 * UNIT);

    // A cached entry, a dedup replay, and a concurrent delivery are all clones
    // of one immutable allocation. They must not each mint a permit.
    let cache_entry = body.clone();
    let replay = body.clone();
    let slice = body.slice(0..UNIT);
    assert_eq!(
        budget.available_bytes(),
        charged_once,
        "a cheap clone shares the allocation, so it must share the one charge"
    );

    // ...and the charge is held until the LAST handle goes away.
    drop(body);
    drop(replay);
    drop(slice);
    assert_eq!(budget.available_bytes(), charged_once);
    drop(cache_entry);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the last handle's drop is what returns the budget"
    );
}

#[test]
fn an_abandoned_collection_releases_immediately() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Retry abandonment / deadline / cancellation all look like this: the
    // reservation is dropped without ever being attached to bytes.
    {
        let mut charge = budget.try_reserve(UNIT).expect("admits");
        assert!(budget.grow(&mut charge, 4 * UNIT));
        assert_eq!(budget.available_bytes(), total - 4 * UNIT);
    }
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn an_empty_body_retains_nothing_and_holds_no_charge() {
    let budget = probe(4);
    let total = budget.available_bytes();
    let empty = budget.charge_retained_body(Vec::new()).expect("admits");
    assert!(empty.is_empty());
    assert_eq!(
        budget.available_bytes(),
        total,
        "nothing is resident, so nothing stays charged"
    );
}

// ---------------------------------------------------------------------------
// Preallocation: charged before it is allocated.
// ---------------------------------------------------------------------------

#[test]
fn preallocated_capacity_is_charged_before_it_is_allocated() {
    let budget = probe(4);
    let total = budget.available_bytes();

    // A backend that advertises a large `content-length` and then sends no DATA
    // still holds the capacity, so the reservation must precede the allocation.
    let charge = budget.try_reserve(3 * UNIT).expect("prealloc admits");
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the preallocation is charged before the first DATA frame"
    );

    // A headers-only / stalled response never grows, and the charge is released
    // when the collector is abandoned.
    drop(charge);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn growth_past_the_preallocation_is_charged_as_a_delta_not_twice() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let mut charge = budget.try_reserve(2 * UNIT).expect("prealloc admits");
    assert!(budget.grow(&mut charge, 5 * UNIT), "growth admits");
    assert_eq!(
        budget.available_bytes(),
        total - 5 * UNIT,
        "5 blocks resident must cost 5 blocks, not 2 + 5"
    );

    // A shrinking report never releases mid-collection: the peak stays held.
    assert!(budget.grow(&mut charge, UNIT));
    assert_eq!(budget.available_bytes(), total - 5 * UNIT);
}

#[test]
fn an_unaffordable_preallocation_is_refused_rather_than_rounded_away() {
    let budget = probe(2);
    assert!(
        budget.try_reserve(3 * UNIT).is_none(),
        "reservation rounding must not hide a preallocation the budget cannot cover"
    );
    // ...and the refusal left nothing charged.
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

// ---------------------------------------------------------------------------
// Admission: non-blocking, exhaustion is refusal (never a queue).
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_refuses_instead_of_queueing_and_recovers_on_release() {
    let budget = probe(4);

    let first = budget
        .charge_retained_body(vec![0u8; 4 * UNIT])
        .expect("the whole budget admits one response");
    assert_eq!(budget.available_bytes(), 0);

    // Non-blocking: the second caller is refused immediately rather than
    // waiting behind the first and burning its client's deadline.
    assert!(budget.charge_retained_body(vec![0u8; UNIT]).is_none());

    drop(first);
    assert!(
        budget.charge_retained_body(vec![0u8; UNIT]).is_some(),
        "capacity returns as soon as the resident bytes are gone"
    );
}

#[test]
fn concurrent_retained_responses_cannot_exceed_the_aggregate_budget() {
    let budget = probe(8);
    let mut resident = Vec::new();
    // Each response is individually well within any sane per-response ceiling;
    // the aggregate is what bounds them.
    for _ in 0..8 {
        resident.push(
            budget
                .charge_retained_body(vec![0u8; UNIT])
                .expect("within budget"),
        );
    }
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.charge_retained_body(vec![0u8; UNIT]).is_none(),
        "the 9th concurrent retained response must be refused, not admitted"
    );
    assert_eq!(resident.len(), 8);
}

// ---------------------------------------------------------------------------
// Ceilings: zero folds to a finite fallback; a configured ceiling is verbatim.
// ---------------------------------------------------------------------------

#[test]
fn zero_effective_limit_folds_to_the_configured_fallback_ceiling() {
    let budget = ResponseBufferBudgetProbe::new(4 * UNIT, 64 * UNIT);
    assert_eq!(
        budget.buffered_response_body_ceiling(0),
        4 * UNIT,
        "`0 = unlimited` is a streaming policy only"
    );
    assert_eq!(budget.buffered_response_body_ceiling(1234), 1234);
}

#[test]
fn a_fallback_ceiling_below_one_block_is_clamped_up_not_to_zero() {
    // A degenerate configuration must not make every retained response
    // impossible.
    let budget = ResponseBufferBudgetProbe::new(1, 0);
    assert!(budget.buffered_response_body_ceiling(0) >= UNIT);
    assert!(budget.available_bytes() >= UNIT);
}

#[test]
fn the_aggregate_budget_is_not_widened_to_fit_a_larger_per_response_ceiling() {
    // Floor is the FALLBACK ceiling only. A 1 GiB per-response ceiling
    // configured elsewhere does not enlarge a 4-block aggregate budget, so a
    // response above the budget is refused instead of uncapping it.
    let budget = ResponseBufferBudgetProbe::new(UNIT, 4 * UNIT);
    assert_eq!(budget.buffered_response_body_ceiling(1 << 30), 1 << 30);
    assert_eq!(budget.available_bytes(), 4 * UNIT);
    assert!(budget.charge_retained_body(vec![0u8; 5 * UNIT]).is_none());
}

// ---------------------------------------------------------------------------
// Classification: gateway-local capacity, not a backend fault.
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_maps_to_a_neutral_overload_refusal_on_every_transport() {
    // HTTP: 503, not a backend 502.
    assert_eq!(RESPONSE_BUFFER_OVERLOAD_STATUS, 503);
    // gRPC: the resource/capacity status, not UNAVAILABLE (backend down) and
    // not INTERNAL (gateway defect).
    assert_eq!(RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS, 8);
    // Fixed, redaction-safe body: no route, header, credential, or response
    // content can appear in it.
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_BODY,
        r#"{"error":"Response buffering capacity exceeded"}"#
    );
}

#[test]
fn exhaustion_is_backend_health_neutral_and_distinct_from_oversize() {
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::GatewayBufferCapacity
    );
    assert_eq!(
        ErrorClass::GatewayBufferCapacity.as_str(),
        "gateway_buffer_capacity"
    );

    // Neutral: no circuit-breaker trip, no passive-health ding, no
    // adaptive-concurrency shrink for a backend that answered correctly.
    assert!(error_class_is_health_neutral_for_test(
        ErrorClass::GatewayBufferCapacity
    ));
    assert!(!error_class_is_backend_failure_for_test(
        ErrorClass::GatewayBufferCapacity
    ));

    // True per-response overflow stays a backend-attributed failure, so the two
    // conditions remain distinguishable in telemetry and in health accounting.
    assert!(!error_class_is_health_neutral_for_test(
        ErrorClass::ResponseBodyTooLarge
    ));
    assert!(error_class_is_backend_failure_for_test(
        ErrorClass::ResponseBodyTooLarge
    ));
}

// ---------------------------------------------------------------------------
// Allocation-owned accounting: a charge belongs to the allocation it paid for,
// never to the request that produced it.
// ---------------------------------------------------------------------------

/// A plugin-authored REPLACEMENT of the buffered body is a different allocation
/// than the one the collector charged. Its charge must follow the replacement
/// bytes — not the request context — so a copy that outlives the request stays
/// charged and a context that drops (or is cloned) neither releases nor
/// duplicates it.
#[test]
fn a_replacement_allocation_owns_its_own_charge() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Collected body: one charge.
    let collected = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("collected body admits");
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    // A normalizer/transform installs a DIFFERENT allocation. Both are resident
    // for the moment the swap happens, so both are charged.
    let replacement = budget
        .charge_retained_body(vec![1u8; 3 * UNIT])
        .expect("replacement admits");
    assert_eq!(budget.available_bytes(), total - 5 * UNIT);

    // Dropping the superseded body returns only ITS charge.
    drop(collected);
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the replacement must stay charged after the body it replaced is gone"
    );

    // The replacement stays charged for as long as any handle exists — which is
    // what a request-scoped charge could not express, because the request can
    // end while a stored copy of the replacement is still resident.
    let outlives_the_request = replacement.clone();
    drop(replacement);
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "a surviving handle keeps the single charge"
    );
    drop(outlives_the_request);
    assert_eq!(budget.available_bytes(), total, "last handle returns it");
}

/// The `response_caching` entry body is a COPY that outlives the request. It
/// must acquire its own charge and hold it until the entry is evicted and the
/// last clone of it drops — the collector's charge cannot cover it, because the
/// collected body is released when the response finishes.
#[test]
fn a_cache_entry_copy_carries_its_own_charge_through_eviction() {
    let budget = probe(8);
    let total = budget.available_bytes();

    let entry = {
        // The response the client actually receives.
        let collected = budget
            .charge_retained_body(vec![7u8; 2 * UNIT])
            .expect("collected body admits");
        // The store copies it into an entry that will outlive this response.
        let entry = budget
            .charge_retained_copy(&collected)
            .expect("the entry copy is admitted");
        assert_eq!(
            budget.available_bytes(),
            total - 4 * UNIT,
            "the entry copy is charged separately from the collected body"
        );
        entry
    };

    // The request is over and its body is gone; the entry is still resident and
    // still charged.
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "the cache entry must stay charged after the request that stored it ended"
    );

    // A replay hands out a cheap clone: still exactly one charge.
    let replay = entry.clone();
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);

    // Eviction drops the entry, but an in-flight replay still holds the bytes.
    drop(entry);
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "eviction with a live replay must not return the charge early"
    );
    drop(replay);
    assert_eq!(budget.available_bytes(), total, "last handle returns it");
}

/// When the budget cannot admit the entry copy, the store must be skipped —
/// never retained uncharged, and never materialised at all.
#[test]
fn an_unaffordable_cache_entry_copy_is_refused_rather_than_stored() {
    let budget = probe(2);
    let _pinned = budget
        .charge_retained_body(vec![0u8; 2 * UNIT])
        .expect("fills the budget");
    assert_eq!(budget.available_bytes(), 0);

    assert!(
        budget.charge_retained_copy(&[9u8; UNIT]).is_none(),
        "an unaffordable entry copy must be refused so the store is skipped"
    );
    assert_eq!(
        budget.available_bytes(),
        0,
        "a refused copy leaks no partial reservation"
    );
}

/// The eager small-response path drives the PRODUCTION collector, with the
/// declared `Content-Length` as its preallocation hint. The hint is charged
/// BEFORE the buffer exists, and every growth is charged before it is
/// allocated — a declared length is a backend claim, not an allocation-capacity
/// proof, so the eager path may not await an opaque read and reconcile
/// afterwards (GHSA-pwcm-6rh8-f2gh).
#[test]
fn the_eager_path_charges_its_preallocation_before_it_allocates() {
    let budget = probe(8);
    let total = budget.available_bytes();

    // Declared Content-Length becomes the preallocation hint, charged first.
    let mut collector = budget
        .collector_with_preallocation(4 * UNIT, UNIT)
        .expect("the declared length admits");
    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "the preallocation is charged before the buffer is allocated"
    );

    collector
        .append(&[3u8; UNIT])
        .expect("the declared body fits its hint");
    let body = collector
        .into_charged_bytes()
        .expect("the collected body publishes with its charge attached");
    assert_eq!(body.len(), UNIT);
    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "the eagerly collected body stays charged after collection returns"
    );
    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

/// A backend that declares a small `Content-Length` and then sends more does
/// NOT get to retain whatever it sends: the eager collector still enforces the
/// folded per-response retained ceiling, and the overrun is a BACKEND-attributed
/// size refusal rather than a gateway-capacity one.
#[test]
fn the_eager_path_refuses_a_body_that_outruns_its_declared_length() {
    let budget = probe(64);
    let total = budget.available_bytes();

    let mut collector = budget
        .collector_with_preallocation(2 * UNIT, UNIT)
        .expect("the declared length admits");
    assert_eq!(
        collector.append(&[7u8; 3 * UNIT]),
        Err(ResponseBufferRetainRejection::TooLarge),
        "a body past the retained ceiling is a size-policy refusal, not an \
         aggregate-capacity one"
    );
    drop(collector);
    assert_eq!(
        budget.available_bytes(),
        total,
        "a refused eager collection releases everything it had charged"
    );
}

/// The same collection under a spent budget refuses with the gateway-local
/// capacity class instead, so telemetry and health accounting stay honest about
/// which bound was hit.
#[test]
fn the_eager_path_distinguishes_capacity_from_size_policy() {
    let budget = probe(2);
    let held = budget.try_reserve(2 * UNIT).expect("fills the budget");
    assert_eq!(budget.available_bytes(), 0);

    assert_eq!(
        budget.collector_with_preallocation(4 * UNIT, UNIT).err(),
        Some(ResponseBufferRetainRejection::BudgetExhausted),
        "an exhausted aggregate budget is gateway-local transient capacity"
    );
    drop(held);
}

/// Concurrency must not be able to multiply the eager cutoff: once the budget
/// is spent, a further eager buffer is refused up front rather than read.
#[test]
fn eager_buffering_is_refused_once_the_aggregate_budget_is_spent() {
    let budget = probe(2);
    let first = budget.try_reserve(UNIT).expect("first eager read admits");
    let second = budget.try_reserve(UNIT).expect("second eager read admits");
    assert_eq!(budget.available_bytes(), 0);

    assert!(
        budget.try_reserve(UNIT).is_none(),
        "an eager read must be refused, not queued, once the budget is spent"
    );

    drop((first, second));
    assert_eq!(
        budget.available_bytes(),
        2 * UNIT,
        "released eager charges restore capacity"
    );
}

// ---------------------------------------------------------------------------
// Overflow-safe growth.
// ---------------------------------------------------------------------------

/// Collectors compute the prospective retained length ONCE and reuse it for the
/// ceiling check, the budget charge, and the allocation. It saturates, so a
/// hostile length cannot wrap past a finite ceiling (or panic a debug build).
#[test]
fn prospective_retained_length_saturates_instead_of_overflowing() {
    use ferrum_edge::_test_support::prospective_retained_len_for_test as prospective;

    assert_eq!(prospective(0, 0), 0);
    assert_eq!(prospective(10, 32), 42);
    assert_eq!(prospective(usize::MAX, 1), usize::MAX);
    assert_eq!(prospective(usize::MAX - 1, 8), usize::MAX);
    assert_eq!(prospective(usize::MAX, usize::MAX), usize::MAX);

    // Saturation fails closed: the saturated value exceeds every finite
    // ceiling, so the bound check rejects rather than admitting a wrapped sum.
    let ceiling = 10 * UNIT;
    assert!(prospective(usize::MAX - 1, 8) > ceiling);

    // And the budget refuses it rather than rounding it into a small block
    // count.
    let budget = probe(8);
    assert!(
        budget.try_reserve(usize::MAX).is_none(),
        "a saturated prospective length must be refused"
    );
    assert_eq!(budget.available_bytes(), 8 * UNIT);
}

// ---------------------------------------------------------------------------
// The refusal is a gateway-authored overload response, not the backend's status
// over a body the client is not getting.
// ---------------------------------------------------------------------------

fn refusal_headers(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn refusal_ctx() -> ferrum_edge::plugins::RequestContext {
    ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/resource".to_string(),
    )
}

/// An HTTP response whose replacement the budget refuses becomes the gateway's
/// own `503` with the fixed redaction-safe body — never the backend's `200`
/// over bytes the client will not receive — and stale representation metadata
/// that described the discarded bytes is removed.
#[test]
fn a_refused_http_replacement_becomes_a_gateway_503_with_clean_metadata() {
    let mut ctx = refusal_ctx();
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/xml"),
        ("content-encoding", "gzip"),
        ("content-length", "1048576"),
        ("content-range", "bytes 0-9/100"),
        ("transfer-encoding", "chunked"),
        ("etag", "\"v1\""),
        ("digest", "sha-256=abc"),
        ("x-request-id", "keep-me"),
    ]);
    let mut body = bytes::Bytes::from_static(b"backend representation");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        status, RESPONSE_BUFFER_OVERLOAD_STATUS,
        "the backend status must not survive a refusal that discarded its body"
    );
    assert_eq!(
        body,
        bytes::Bytes::from_static(RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes())
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let expected_length = RESPONSE_BUFFER_OVERLOAD_BODY.len().to_string();
    assert_eq!(
        headers.get("content-length"),
        Some(&expected_length),
        "Content-Length must describe the bytes actually emitted"
    );
    for stale in [
        "content-encoding",
        "content-range",
        "transfer-encoding",
        "etag",
        "digest",
    ] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` described bytes the gateway discarded and must be removed"
        );
    }
    assert_eq!(
        headers.get("x-request-id").map(String::as_str),
        Some("keep-me"),
        "unrelated headers are untouched"
    );

    // The fixed body names no route, header, credential, or response content.
    let rendered = String::from_utf8(body.to_vec()).expect("utf-8");
    assert!(!rendered.contains("/api/resource"));
    assert!(!rendered.contains("backend representation"));
}

/// A NATIVE gRPC response terminates through Trailers-Only gRPC status metadata
/// instead: gRPC errors ride HTTP 200, so rewriting the HTTP status would break
/// the protocol contract rather than express the refusal.
///
/// The flavor is taken from the request-scoped inbound classification, never
/// from a response `Content-Type` a hook may have relabelled.
#[test]
fn a_refused_native_grpc_replacement_terminates_through_grpc_metadata() {
    let mut ctx = refusal_ctx();
    ferrum_edge::_test_support::set_request_http_flavor_for_test(
        &mut ctx,
        ferrum_edge::HttpFlavor::Grpc,
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/grpc+proto"),
        ("content-encoding", "gzip"),
        // Terminal metadata the BACKEND authored for a different status. It
        // describes an outcome the client is not getting and must not ship
        // beside RESOURCE_EXHAUSTED.
        ("grpc-status", "0"),
        ("grpc-status-details-bin", "AAAA"),
        ("x-backend-trailer", "leaked"),
        ("set-cookie", "session=abc"),
        ("etag", "\"v1\""),
    ]);
    let mut body = bytes::Bytes::from_static(b"\x00\x00\x00\x00\x05hello");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(status, 200, "a gRPC terminal must stay on HTTP 200");
    assert!(
        body.is_empty(),
        "the refused frame must not reach the client"
    );
    let expected_grpc_status = RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS.to_string();
    assert_eq!(
        headers.get("grpc-status"),
        Some(&expected_grpc_status),
        "the resource/capacity status, not UNAVAILABLE, INTERNAL, or the backend's OK"
    );
    assert!(headers.contains_key("grpc-message"));
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    for stale in [
        "grpc-status-details-bin",
        "x-backend-trailer",
        "set-cookie",
        "etag",
        "content-encoding",
    ] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` describes the discarded backend outcome and must not survive"
        );
    }
}

/// A TRANSLATED gRPC-Web response carries terminal metadata in a body trailer
/// FRAME, never as response header fields. A refusal that wrote `grpc-status`
/// into the header map and emptied the body would emit terminal metadata the
/// client cannot read as the RPC's status.
#[test]
fn a_refused_grpc_web_replacement_terminates_through_a_body_trailer_frame() {
    let mut ctx = refusal_ctx();
    ctx.metadata.insert(
        ferrum_edge::_test_support::GRPC_WEB_RETAINED_RESPONSE_CONTENT_TYPE_METADATA_KEY
            .to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[
        ("content-type", "application/grpc-web+proto"),
        ("grpc-status", "0"),
        ("grpc-status-details-bin", "AAAA"),
        ("etag", "\"v1\""),
    ]);
    let mut body = bytes::Bytes::from_static(b"\x00\x00\x00\x00\x05hello");

    ferrum_edge::_test_support::install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(status, 200, "a gRPC-Web terminal must stay on HTTP 200");
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );

    // The terminal block is FRAMED: a trailer frame (flag byte 0x80) carrying
    // the capacity status, not header fields.
    assert!(
        !body.is_empty(),
        "gRPC-Web terminal metadata must be in the body, not header fields"
    );
    assert_eq!(body[0], 0x80, "leading byte marks a gRPC-Web trailer frame");
    let rendered = String::from_utf8_lossy(&body).to_string();
    let expected_grpc_status = RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS.to_string();
    assert!(
        rendered.contains(&format!("grpc-status: {expected_grpc_status}")),
        "trailer frame must carry the capacity status: {rendered:?}"
    );

    for stale in ["grpc-status-details-bin", "etag"] {
        assert!(
            !headers.contains_key(stale),
            "`{stale}` describes the discarded backend outcome and must not survive"
        );
    }
    assert_ne!(
        headers.get("grpc-status").map(String::as_str),
        Some("0"),
        "the backend's OK status must never survive a refusal"
    );
}

// ---------------------------------------------------------------------------
// Static sweep: every retained-body construction reached by this advisory has
// to acquire a charge. These are source-shape assertions because the paths they
// cover need a live backend to exercise end to end, and a silent regression
// there is exactly the bypass being fixed.
// ---------------------------------------------------------------------------

#[test]
fn every_eager_reqwest_buffer_collects_through_the_charged_collector() {
    let proxy = include_str!("../../../src/proxy/mod.rs");

    // No eager path may await an opaque whole-body read: that allocation exists
    // before anything can measure it (GHSA-pwcm-6rh8-f2gh).
    assert!(
        !proxy.contains("response.bytes(),"),
        "an eager path must not await `Response::bytes()`; it materializes an \
         allocation of opaque capacity before it can be charged"
    );

    // Three eager small-response paths: the retry loop, the limited
    // first-attempt arm, and the unlimited first-attempt arm — plus the
    // definition.
    assert_eq!(
        proxy.matches("eager_collect_charged_backend_body(").count(),
        4,
        "every eager small-response path must collect through the shared \
         charged collector, which charges each growth before allocating it"
    );
    assert_eq!(
        proxy
            .matches("buffered_backend_response_from_eager_collect(")
            .count(),
        4,
        "three call sites plus the definition; each must classify the retained \
         refusals it can produce"
    );

    // The unbounded `0 = unlimited` retained arm must not exist anywhere: every
    // buffered collection goes through the fail-closed ceiling.
    assert_eq!(
        proxy
            .matches("response_buffer_budget::buffered_response_body_ceiling(")
            .count(),
        7,
        "each buffered and eager reqwest collection folds `0` to the \
         fail-closed ceiling"
    );
}

#[test]
fn the_response_cache_entry_copy_is_charged_for_its_own_lifetime() {
    let caching = include_str!("../../../src/plugins/response_caching.rs");
    assert!(
        caching.contains("response_buffer_budget::charge_retained_copy(body)"),
        "the cache entry copy outlives the request, so it must carry its own \
         charge instead of claiming the collector's (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        !caching.contains("Bytes::copy_from_slice(body)"),
        "an uncharged entry copy must not be reintroduced"
    );
}

#[test]
fn the_replacement_charge_is_not_request_scoped() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let proxy = include_str!("../../../src/proxy/mod.rs");
    for source in [plugins, proxy] {
        assert!(
            !source.contains("charge_replacement_response_body"),
            "a replacement charge held by the RequestContext drops with the \
             request and is emptied by its Clone, so it cannot bound a copy \
             that outlives the request (GHSA-pwcm-6rh8-f2gh)"
        );
    }
    assert!(
        plugins.contains("window.as_mut().and_then(|window| window.charge(body))"),
        "the normalizer replacement must be charged out of the window reserved \
         before the hook ran, not after the plugin already allocated it"
    );
    assert!(
        proxy.contains("window.as_mut().and_then(|w| w.charge(transformed))"),
        "the body-transform replacement must be charged out of the window \
         reserved before the hook ran, not after the plugin already allocated it"
    );
    for source in [plugins, proxy] {
        assert!(
            !source.contains("charge_replacement_body("),
            "charging a plugin-produced buffer on arrival is charging AFTER the \
             allocation: concurrent transform outputs would exist outside the \
             aggregate cap (GHSA-pwcm-6rh8-f2gh)"
        );
    }
}

/// Both buffered phases that can be refused after the backend answered must
/// route through the SHARED gateway-terminal helper. A hand-rolled refusal is
/// how the gRPC-Web branch came to emit unframed terminal metadata.
#[test]
fn every_capacity_refusal_uses_the_shared_gateway_terminal() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let proxy = include_str!("../../../src/proxy/mod.rs");
    for source in [plugins, proxy] {
        assert!(
            !source.contains("install_response_buffer_capacity_refusal"),
            "the hand-rolled refusal installer must not return; it wrote gRPC-Web \
             terminal metadata into header fields instead of a body trailer frame \
             (GHSA-pwcm-6rh8-f2gh)"
        );
    }
    assert_eq!(
        proxy
            .matches("replace_buffered_response_with_capacity_refusal(")
            .count(),
        8,
        "one definition, the transform window-open/admission/publication \
         refusals, final gRPC-Web reframe, H1/H2 + native-gRPC on_response_body \
         capacity installers, and the synthetic short-circuit body path; \
         the normalize call site lives in src/plugins/mod.rs"
    );
    assert_eq!(
        proxy
            .matches("replace_buffered_response_with_capacity_refusal_with_policy_source(")
            .count(),
        4,
        "one definition, the prefiltered delegation, the representation gate's \
         CapacityRefused decode path, and the install_decoded_response_body \
         charge refusal — both gate sites are reached from callers holding the \
         unfiltered protocol plugin list, so they cannot use the prefiltered \
         wrapper"
    );
    assert!(
        plugins.contains("replace_buffered_response_with_capacity_refusal("),
        "the normalize phase must use the same shared terminal"
    );
    assert!(
        proxy.contains("crate::plugins::grpc_web::error_response_for_content_type("),
        "a gRPC-Web capacity terminal must be built as a body trailer frame"
    );
}

/// The final response-header phase is the whole basis for releasing a body, so
/// it must run from the one boundary every protocol path funnels through, and
/// the cache's own header effects must live in that hook rather than in a
/// speculative buffering predicate.
#[test]
fn the_final_response_header_phase_runs_at_the_after_proxy_boundary() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let caching = include_str!("../../../src/plugins/response_caching.rs");
    assert_eq!(
        proxy
            .matches("crate::plugins::run_final_response_header_hooks(")
            .count(),
        1,
        "exactly one call site, inside `run_after_proxy_hooks`, so no protocol \
         path can skip it (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        caching.contains("fn on_final_response_headers("),
        "response_caching must own its header-only effects in the header phase"
    );
    assert!(
        caching.contains("fn classify_final_response_headers("),
        "the release predicate must be a pure classification"
    );
    // The speculative predicates must call the PURE classifier, never the
    // effect-taking one: an effect fired from a buffering vote would apply to
    // attempts the proxy never adopts.
    for speculative in [
        "fn should_buffer_response_body_for_content_type(",
        "fn should_release_response_body_under_retries(",
    ] {
        let start = caching.find(speculative).expect(speculative);
        let body: String = caching[start..].chars().take(1400).collect();
        assert!(
            !body.contains("apply_final_response_header_effects("),
            "`{speculative}` is speculative and must take no cache effect"
        );
    }
}

#[test]
fn no_collector_adds_lengths_without_saturating() {
    for source in [
        include_str!("../../../src/proxy/mod.rs"),
        include_str!("../../../src/proxy/grpc_proxy.rs"),
        include_str!("../../../src/http3/client.rs"),
        include_str!("../../../src/http3/cross_protocol.rs"),
    ] {
        for unchecked in [
            "body.len() + chunk.len()",
            "body_bytes.len() + data.len()",
            "body.len() + data.len()",
        ] {
            assert!(
                !source.contains(unchecked),
                "retained-body growth must go through \
                 `response_buffer_budget::prospective_retained_len`, computed \
                 once and reused by the ceiling check and the charge"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The representation gate's decode: the allocation that becomes the retained,
// client-visible body, and the working set that produces it.
//
// This is the residual the first round of the advisory fix left open. The gate
// decodes a protected encoded response and installs the identity bytes as the
// body the client receives; a small compressed response can inflate to the
// decode ceiling, so an uncharged decode let concurrent requests amplify past
// the process aggregate even while their small encoded bodies were charged.
//
// Every test below drives the PRODUCTION gate
// (`evaluate_response_body_policy_posture` + `install_decoded_response_body`)
// with an isolated semaphore bound where the proxy binds the process-global
// one, so admission and release are observable without racing a parallel test
// binary.
// ---------------------------------------------------------------------------

/// A `response_transformer` whose only job is to strip a secret field — the
/// configuration whose bypass the advisory describes, and therefore a policy
/// that genuinely claims the response.
fn redacting_plugins() -> Vec<Arc<dyn Plugin>> {
    vec![Arc::new(
        ResponseTransformer::new(&serde_json::json!({
            "rules": [
                {"operation": "remove", "target": "body", "key": "secret"}
            ]
        }))
        .expect("redacting response_transformer config must be valid"),
    )]
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write must succeed");
    encoder.finish().expect("gzip finish must succeed")
}

/// Default `br`, i.e. the 22-bit window a real encoder picks — well inside the
/// 24-bit ceiling `Content-Encoding: br` permits.
fn brotli(data: &[u8]) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams::default();
    let mut compressed = Vec::new();
    brotli::BrotliCompress(&mut &data[..], &mut compressed, &params)
        .expect("brotli compress must succeed");
    compressed
}

// ---------------------------------------------------------------------------
// Deterministic budget brackets.
//
// A decode's peak is arithmetic, not folklore: it is the ACTIVE codec's scratch
// ceiling plus the reservation covering the previous pass's buffer and this
// pass's output capacity, all rounded to whole 64 KiB blocks. Every bracket
// below is derived from the ACTUAL encoded/intermediate lengths through the
// PRODUCTION growth rule (`projected_decode_output_capacity_for_test`), so a
// change to a codec's output size, to the growth rule, or to a scratch ceiling
// fails with a precise arithmetic mismatch instead of looking like a flaky
// admission assertion.
// ---------------------------------------------------------------------------

fn blocks(bytes: usize) -> usize {
    bytes.div_ceil(UNIT)
}

/// The output-buffer capacity the decode ends up holding for `decoded_len`
/// bytes. The gate's ceiling is 10 MiB here, and every payload in this file is
/// far below it, so the ceiling never clamps the growth.
fn decode_capacity(decoded_len: usize) -> usize {
    projected_decode_output_capacity_for_test(decoded_len, MAX_DECODED_RESPONSE_INSPECTION_BYTES)
}

/// Blocks held at the peak of ONE decode pass: the codec's scratch reservation
/// (a separate permit, so it adds rather than overlaps) plus the output
/// reservation covering `concurrent_bytes` of still-resident input alongside
/// this pass's output capacity.
fn pass_peak_blocks(scratch_bytes: usize, concurrent_bytes: usize, decoded_len: usize) -> usize {
    blocks(scratch_bytes) + blocks(concurrent_bytes + decode_capacity(decoded_len))
}

/// Bytes the budget reports as spent for an allocation of `capacity` bytes —
/// whole blocks, since that is the granularity the semaphore is charged in.
fn charged_for_capacity(capacity: usize) -> usize {
    blocks(capacity) * UNIT
}

/// A JSON document of exactly `payload_bytes` of high-entropy payload.
///
/// The point is not that gzip achieves nothing on it — a 64-symbol alphabet
/// still compresses to roughly three quarters — but that the DECODED size is
/// fixed by construction, so the decoder's working set is predictable instead of
/// being at the mercy of the compressor. Deterministic (a fixed LCG), because a
/// flaky budget assertion is worse than no budget assertion.
fn incompressible_json(payload_bytes: usize) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut payload = Vec::with_capacity(payload_bytes);
    for _ in 0..payload_bytes {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        payload.push(ALPHABET[((state >> 33) % 64) as usize]);
    }
    let mut document = br#"{"secret":"hunter2","filler":""#.to_vec();
    document.extend_from_slice(&payload);
    document.extend_from_slice(br#""}"#);
    document
}

/// Drive the production gate over a backend response, stamping the pristine
/// pre-`after_proxy` snapshot exactly as every buffered path does.
fn admit_backend_representation(
    budget: &ResponseBufferBudgetProbe,
    headers: &mut HashMap<String, String>,
    body: &mut bytes::Bytes,
) -> BufferedRepresentationOutcome {
    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    stamp_original_response_metadata_for_test(&mut ctx, 200, headers);
    budget.admit_buffered_representation(&plugins, &mut ctx, true, 200, headers, body)
}

fn gzip_json_response(payload_bytes: usize) -> (Vec<u8>, HashMap<String, String>, bytes::Bytes) {
    let plain = incompressible_json(payload_bytes);
    let headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("etag".to_string(), "\"v1\"".to_string()),
    ]);
    let body = bytes::Bytes::from(gzip(&plain));
    (plain, headers, body)
}

/// The core residual: the decoded allocation becomes the client-visible body
/// even when NO transform rewrites it afterwards, so it must own an aggregate
/// charge for its whole lifetime — and give it back only when the last clone of
/// those bytes drops.
#[test]
fn decoded_identity_bytes_are_charged_until_their_last_clone_drops() {
    let budget = probe(64);
    let total = budget.available_bytes();
    let (plain, mut headers, mut body) = gzip_json_response(192 * 1024);

    assert!(
        body.len() < plain.len(),
        "the residual is about amplification: the decoded bytes are larger than \
         the encoded ones the collector charged"
    );

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);
    assert_eq!(outcome, BufferedRepresentationOutcome::Decoded);
    assert_eq!(
        body.as_ref(),
        plain.as_slice(),
        "the identity bytes are what the client will receive"
    );

    let charged = total - budget.available_bytes();
    assert!(
        charged >= plain.len(),
        "the retained decoded allocation must be charged for at least its own \
         length; charged {charged}, decoded {}",
        plain.len()
    );

    // A cheap clone shares the one owner. If a clone minted its own charge —
    // or if the charge had been request-scoped — this would move.
    let replica = body.clone();
    assert_eq!(
        budget.available_bytes(),
        total - charged,
        "a clone shares the single charge"
    );

    drop(body);
    assert_eq!(
        budget.available_bytes(),
        total - charged,
        "the charge is owned by the allocation, and a clone is still holding it"
    );
    drop(replica);
    assert_eq!(
        budget.available_bytes(),
        total,
        "the last clone dropping returns the whole charge"
    );
}

/// The no-op-transform path is the one that made this exploitable: the gate
/// installs identity bytes, no configured rule matches them, and they stay
/// client-visible and resident for the rest of the response lifetime. They must
/// arrive charged, with the representation metadata the decode invalidated
/// already refreshed.
#[test]
fn a_decode_no_later_transform_rewrites_is_still_charged_and_reheadered() {
    let budget = probe(64);
    let total = budget.available_bytes();
    // No `secret` key, so every configured body rule is a no-op over these
    // bytes and nothing after the gate will replace the allocation.
    let plain = br#"{"public":"value"}"#.to_vec();
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
        ("etag".to_string(), "\"v1\"".to_string()),
        ("content-length".to_string(), "999".to_string()),
    ]);
    let mut body = bytes::Bytes::from(gzip(&plain));

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);

    assert_eq!(outcome, BufferedRepresentationOutcome::Decoded);
    assert_eq!(body.as_ref(), plain.as_slice());
    assert!(
        budget.available_bytes() < total,
        "identity bytes nothing rewrites are still retained, so they are still \
         charged"
    );
    assert!(
        !headers.contains_key("content-encoding"),
        "the stale coding must not describe identity bytes"
    );
    assert!(
        !headers.contains_key("etag"),
        "a validator for the encoded representation must be invalidated"
    );
    assert_eq!(
        headers.get("content-length"),
        Some(&plain.len().to_string()),
        "the refreshed length must describe the installed bytes"
    );

    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

/// A stacked `Content-Encoding` holds one pass's input and the next pass's
/// output at the same time. Charging only the final decoded body would let that
/// window escape the aggregate bound.
///
/// The pair is self-calibrating: the SAME plaintext under the SAME budget is
/// admitted when it arrives under one coding and refused when it arrives under
/// two, so the refusal can only come from the concurrent working set. Both
/// brackets are derived, not guessed — see [`pass_peak_blocks`].
#[test]
fn a_stacked_decode_charges_its_input_and_output_concurrently() {
    let plain = incompressible_json(300 * 1024);
    let once = gzip(&plain);
    let twice = gzip(&once);

    // Single coding: one pass, nothing else resident.
    let single_peak = pass_peak_blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES, 0, plain.len());
    // Stacked: pass 1 produces the intermediate, then pass 2 decodes it while
    // that intermediate buffer is still held. Its capacity — not its length — is
    // what stays resident.
    let intermediate_capacity = decode_capacity(once.len());
    let stacked_peak = pass_peak_blocks(
        RESPONSE_DECODE_GZIP_SCRATCH_BYTES,
        intermediate_capacity,
        plain.len(),
    );
    assert!(
        single_peak < stacked_peak,
        "this payload must separate the two peaks or the pair proves nothing: \
         single {single_peak} blocks, stacked {stacked_peak} blocks \
         (plaintext {}, once-gzipped {}, intermediate capacity {intermediate_capacity})",
        plain.len(),
        once.len()
    );

    // Sized to admit the single-coding peak and to refuse the stacked one, which
    // is the only difference between the two halves below.
    let budget = probe(stacked_peak - 1);
    let total = budget.available_bytes();
    assert!(
        blocks(total) >= single_peak,
        "the budget must still admit the single-coding decode: {single_peak} \
         blocks needed, {} available",
        blocks(total)
    );

    let headers = || {
        HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-encoding".to_string(), "gzip, gzip".to_string()),
        ])
    };

    let mut single_headers = headers();
    single_headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut single_body = bytes::Bytes::from(once.clone());
    assert_eq!(
        admit_backend_representation(&budget, &mut single_headers, &mut single_body),
        BufferedRepresentationOutcome::Decoded,
        "one decoded copy of this plaintext fits in the budget"
    );
    assert_eq!(
        total - budget.available_bytes(),
        charged_for_capacity(decode_capacity(plain.len())),
        "after publication the surviving charge is exactly the decoded \
         allocation's capacity: the codec scratch and the peak surplus are back. \
         A mismatch here means the allocator returned more capacity than \
         `reserve_exact` was asked for, or the growth rule moved"
    );
    drop(single_body);
    assert_eq!(budget.available_bytes(), total);

    let mut stacked_headers = headers();
    let mut stacked_body = bytes::Bytes::from(twice);
    assert_eq!(
        admit_backend_representation(&budget, &mut stacked_headers, &mut stacked_body),
        BufferedRepresentationOutcome::CapacityRefused,
        "the intermediate and the final buffer are resident at once, so the \
         same plaintext no longer fits"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "a refused decode releases every block it had already taken"
    );
}

/// The codec's OWN heap is not represented by the output buffer and is allocated
/// from the attacker-supplied stream header before any output exists, so it is
/// reserved before the decoder is constructed. A `br` response whose decoded
/// output would fit easily must still be refused when that working set cannot be
/// admitted — and refused as gateway capacity, with the encoded representation
/// left exactly as the backend sent it until the caller replaces it.
#[test]
fn a_brotli_decode_whose_codec_working_set_is_unaffordable_is_refused() {
    let plain = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let output_blocks = blocks(decode_capacity(plain.len()));
    let scratch_blocks = blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES);

    // Room for many copies of the decoded output, and nowhere near the Brotli
    // ring buffer's ceiling — so the refusal can only be the codec scratch.
    let budget = probe(scratch_blocks - 1);
    assert!(
        blocks(budget.available_bytes()) > output_blocks * 8,
        "the payload must be trivially affordable on its own: {output_blocks} \
         output blocks against {} available",
        blocks(budget.available_bytes())
    );
    let total = budget.available_bytes();

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "br".to_string()),
    ]);
    let encoded = bytes::Bytes::from(brotli(&plain));
    let mut body = encoded.clone();

    assert_eq!(
        admit_backend_representation(&budget, &mut headers, &mut body),
        BufferedRepresentationOutcome::CapacityRefused,
        "the decoder's own heap is charged before it is constructed, so a \
         decode the gateway has no room to run is a capacity refusal"
    );
    assert_eq!(
        body, encoded,
        "nothing is installed on the refusal path; the encoded bytes stay \
         untouched until the caller replaces the response"
    );
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("br"),
        "the representation the refusal describes is still the encoded one"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "every permit the refused decode took is released"
    );
}

/// The `br` scratch ceiling must be a bound, not a blanket rejection: the same
/// response decodes and installs normally once the budget can hold the working
/// set, and the working set is returned as soon as the pass ends — only the
/// decoded allocation stays charged.
#[test]
fn a_brotli_decode_that_can_afford_its_working_set_is_admitted_and_gives_it_back() {
    let plain = br#"{"secret":"hunter2","keep":1}"#.to_vec();
    let peak = pass_peak_blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES, 0, plain.len());
    let budget = probe(peak);
    let total = budget.available_bytes();

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "br".to_string()),
    ]);
    let mut body = bytes::Bytes::from(brotli(&plain));

    assert_eq!(
        admit_backend_representation(&budget, &mut headers, &mut body),
        BufferedRepresentationOutcome::Decoded,
        "a budget sized for the derived peak must admit the decode"
    );
    assert_eq!(body.as_ref(), plain.as_slice());
    assert_eq!(
        total - budget.available_bytes(),
        charged_for_capacity(decode_capacity(plain.len())),
        "the codec working set is released when its pass ends; only the \
         decoded allocation stays charged"
    );

    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

/// Large Window Brotli uses the `0x11` window-bits marker; a non-strict decoder
/// then reads six LWB bits and can allocate a ring buffer far beyond any fixed
/// scratch ceiling. `new_strict` must reject the marker as a format-window-bits
/// error before that allocation — and must not be mistaken for a gateway
/// capacity refusal when the budget can afford the ordinary `br` scratch.
#[test]
fn a_large_window_brotli_marker_is_rejected_before_lwb_ring_allocation() {
    const LWB_MARKER_BODY: [u8; 8] = [0x11, 0x1e, 0, 0, 0, 0, 0, 0];
    let scratch_blocks = blocks(RESPONSE_DECODE_BROTLI_SCRATCH_BYTES);
    let budget = probe(scratch_blocks + 4);
    let total = budget.available_bytes();
    assert!(
        blocks(total) >= scratch_blocks,
        "the budget must afford the ordinary `br` codec scratch"
    );

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-encoding".to_string(), "br".to_string()),
    ]);
    let encoded = bytes::Bytes::from_static(&LWB_MARKER_BODY);
    let mut body = encoded.clone();

    assert_eq!(
        admit_backend_representation(&budget, &mut headers, &mut body),
        BufferedRepresentationOutcome::Rejected("malformed_content_coding"),
        "the LWB extension marker must be a format error, not a capacity refusal"
    );
    assert_eq!(
        body, encoded,
        "nothing is installed on the rejection path; the encoded bytes stay \
         untouched until the caller replaces the response"
    );
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("br"),
        "the representation the rejection describes is still the encoded one"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "every permit the failed decode took is released"
    );
}

/// Refusal is a statement about the GATEWAY, not the representation, so it takes
/// the transient-capacity terminal: `503` with the fixed redaction-safe body,
/// `RESOURCE_EXHAUSTED` for gRPC, health-neutral and never retried. A `502`
/// representation error here would blame a backend that answered correctly and
/// poison breaker/passive-health accounting.
#[test]
fn a_refused_decode_fails_closed_as_gateway_capacity_not_a_backend_error() {
    // Deliberately sized to afford the gzip working set and NOT the decoded
    // output, so this covers the output-growth refusal specifically; the codec
    // scratch refusal has its own coverage above.
    let (plain, mut headers, mut body) = gzip_json_response(1024 * 1024);
    let scratch_blocks = blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES);
    let peak = pass_peak_blocks(RESPONSE_DECODE_GZIP_SCRATCH_BYTES, 0, plain.len());
    assert!(
        peak > scratch_blocks + 1,
        "this payload must need more than its codec scratch: peak {peak} \
         blocks, scratch {scratch_blocks}"
    );
    let budget = probe(scratch_blocks + 1);
    let total = budget.available_bytes();
    let encoded = body.clone();

    let outcome = admit_backend_representation(&budget, &mut headers, &mut body);

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::CapacityRefused,
        "an admissible decode the gateway has no memory for is a capacity \
         refusal, not a representation fault"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "the refused decode leaks nothing"
    );
    assert_eq!(
        body, encoded,
        "nothing is installed on the refusal path; the caller replaces the \
         response with the capacity terminal"
    );

    // The terminal the proxy installs for exactly this outcome.
    let mut ctx = make_ctx();
    let mut status = 200u16;
    install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );
    assert_eq!(status, RESPONSE_BUFFER_OVERLOAD_STATUS);
    assert_eq!(body.as_ref(), RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes());
    assert!(error_class_is_health_neutral_for_test(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS
    ));
    assert!(!error_class_is_backend_failure_for_test(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS
    ));
}

/// The important claim-withdrawal behavior must survive the accounting: a decode
/// whose plaintext proves the policy cannot act on it forwards the ORIGINAL
/// encoded bytes untouched — and gives every block the decode took back, since
/// nothing it produced is retained.
#[test]
fn a_withdrawn_claim_forwards_the_encoded_bytes_and_releases_all_decode_capacity() {
    let budget = probe(64);
    let total = budget.available_bytes();

    // The untyped-gRPC shape: the wire bytes are not frames, so a decode is
    // owed; the plaintext IS a complete frame sequence, so the JSON policy
    // withdraws over it.
    let mut framed = vec![0u8];
    framed.extend_from_slice(&2u32.to_be_bytes());
    framed.extend_from_slice(b"\x08\x01");
    let encoded = gzip(&framed);

    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let mut headers = HashMap::from([("content-encoding".to_string(), "gzip".to_string())]);
    let mut body = bytes::Bytes::from(encoded.clone());
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let outcome = budget.admit_buffered_representation(
        &plugins,
        &mut ctx,
        true,
        200,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::Unprotected,
        "a valid RPC reply must not become an error"
    );
    assert_eq!(
        body.as_ref(),
        encoded.as_slice(),
        "the claim was withdrawn, so the original encoded bytes are forwarded"
    );
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "nothing was installed, so the representation is unchanged"
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "the temporary decode capacity is released with the dropped plaintext"
    );
}

/// A rejection after the decode (here: the client refuses identity coding) must
/// release the decode's capacity too. Every non-install exit from the gate is a
/// drop, which is what makes them uniformly leak-free.
#[test]
fn a_rejection_after_the_decode_releases_its_capacity() {
    let budget = probe(64);
    let total = budget.available_bytes();
    let (_, mut headers, mut body) = gzip_json_response(128 * 1024);

    let plugins = redacting_plugins();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "accept-encoding".to_string(),
        "gzip, identity;q=0".to_string(),
    );
    stamp_original_response_metadata_for_test(&mut ctx, 200, &headers);

    let outcome = budget.admit_buffered_representation(
        &plugins,
        &mut ctx,
        true,
        200,
        &mut headers,
        &mut body,
    );

    assert_eq!(
        outcome,
        BufferedRepresentationOutcome::Rejected("identity_coding_unacceptable")
    );
    assert_eq!(
        budget.available_bytes(),
        total,
        "a rejected representation retains nothing, so it must be charged \
         nothing"
    );
}

/// The decoded body must never reach the client uncharged. This pins the one
/// line that publishes it: a plain `Bytes::from(decoded)` is exactly the
/// residual this round repairs.
#[test]
fn the_decoded_body_is_published_through_the_charged_owner() {
    let representation = include_str!("../../../src/plugins/response_representation.rs");
    assert!(
        representation.contains("charged_bytes(self.data, self.reservation)"),
        "the decoded allocation must be published together with the permit that \
         paid for it (GHSA-pwcm-6rh8-f2gh)"
    );
    assert!(
        !representation.contains("*response_body = Bytes::from(decoded);"),
        "an uncharged decoded body must not be reintroduced: it stays \
         client-visible through the no-op-transform path with no permit at all"
    );
    assert!(
        !representation.contains("let mut current = body.to_vec();"),
        "the first decode pass must read the collector-charged wire bytes \
         directly rather than making an uncharged copy of them"
    );
}

/// The handoff that publishes the decoded body must be CHECKED, not merely
/// narrowed. `narrow_to_covered` can only release permits, so describing it as
/// preventing an under-charge is only true while something proves the charge
/// already covers the surviving capacity — which is why it reports failure and
/// why the install is fallible.
#[test]
fn the_final_decode_handoff_is_checked_rather_than_only_narrowed() {
    let representation = include_str!("../../../src/plugins/response_representation.rs");
    let budget = include_str!("../../../src/proxy/response_buffer_budget.rs");

    assert!(
        budget
            .contains("pub(crate) fn narrow_to_covered(&mut self, retained_bytes: usize) -> bool")
            && budget.contains("if wanted > self.blocks {\n            return false;"),
        "narrowing must refuse when the charge does not cover the allocation, \
         rather than silently publishing under-charged bytes"
    );
    assert!(
        !budget.contains("fn release_above("),
        "the unconditional shrink must not come back: it cannot repair an \
         under-charge and reads as though it could"
    );
    assert!(
        representation.contains("if !self.reservation.narrow_to_covered(self.data.capacity())")
            && representation.contains("fn into_charged_bytes(mut self) -> Option<Bytes>"),
        "publication must be gated on the charge covering the ACTUAL capacity"
    );
    assert!(
        representation.contains("out.reserve_exact(grown - out.len());")
            && representation.contains(
                "let allocated = prospective_retained_len(concurrent_bytes, out.capacity());"
            ),
        "`reserve_exact` guarantees at least the requested capacity, so the \
         reservation must be topped up to the capacity that was actually \
         allocated"
    );
}

/// The codec's own heap is reserved BEFORE the decoder exists, and the `br`
/// decoder is the strict one — the crate's default reader admits Large Window
/// Brotli, whose ring buffer is bounded by 1 GiB rather than 16 MiB, which no
/// fixed scratch ceiling could honestly cover.
#[test]
fn the_decoder_working_set_is_reserved_before_the_decoder_is_constructed() {
    let representation = include_str!("../../../src/plugins/response_representation.rs");

    let scratch = representation
        .find("if !scratch.reserve_in(budget, coding.scratch_bytes())")
        .expect("the codec working set must be reserved against the aggregate budget");
    for decoder in [
        "flate2::read::MultiGzDecoder::new(data)",
        "StrictBrotliReader::new(data)",
    ] {
        let constructed = representation
            .find(decoder)
            .unwrap_or_else(|| panic!("`{decoder}` must be the decoder that is constructed"));
        assert!(
            scratch < constructed,
            "`{decoder}` is constructed before its working set is reserved; the \
             first read can allocate that heap before any output-growth \
             reservation happens (GHSA-pwcm-6rh8-f2gh)"
        );
    }
    assert!(
        representation.contains("brotli::BrotliState::new_strict("),
        "the `br` decoder must pin `large_window = false`, or its ring buffer is \
         bounded by 1 GiB and the scratch ceiling is fiction"
    );
    assert!(
        !representation.contains("brotli::Decompressor::new("),
        "`brotli::Decompressor` builds its state with `large_window = true`, so \
         a handful of header bits can ask it for a 1 GiB ring buffer"
    );
}

// ---------------------------------------------------------------------------
// Capacity, not length: what a growing collector actually keeps resident.
//
// `Vec` grows by amortised doubling, so a collector that reserves the
// prospective post-append LENGTH and then calls `extend_from_slice` publishes a
// buffer whose CAPACITY can be far larger than anything the budget was asked
// about. Under concurrency that surplus is exactly the resident memory the
// aggregate cap claims to bound, so the collector must choose its own growth
// target, charge THAT, and only then allocate.
//
// Every test here drives the PRODUCTION collector
// (`ChargedBodyCollector`, the one all five buffered transports use) against an
// isolated semaphore.
// ---------------------------------------------------------------------------

/// The published charge covers the buffer's capacity, not its length.
///
/// The chunk sequence is chosen so the two answers differ by a wide margin: a
/// 3-block append followed by a single byte leaves a length of `3 * UNIT + 1`
/// (4 blocks if you charge the length) inside a doubled `6 * UNIT` allocation
/// (6 blocks if you charge what is resident).
#[test]
fn a_grown_collector_is_charged_for_its_capacity_not_its_length() {
    let budget = probe(16);
    let total = budget.available_bytes();

    let body = {
        let mut collector = budget.collector(8 * UNIT);
        collector
            .append(&vec![0u8; 3 * UNIT])
            .expect("first append admits");
        collector.append(&[1u8]).expect("one more byte admits");
        assert_eq!(
            collector.len(),
            3 * UNIT + 1,
            "the payload is one byte past a three-block boundary"
        );
        collector.into_charged_bytes().expect("publishes")
    };

    let charged = total - budget.available_bytes();
    assert!(
        charged >= 6 * UNIT,
        "the doubled allocation is what stays resident, so it is what must be \
         charged; charging the {}-byte length would leave {} bytes of resident \
         capacity outside the aggregate cap (GHSA-pwcm-6rh8-f2gh) — charged \
         {charged}",
        3 * UNIT + 1,
        2 * UNIT
    );
    assert_eq!(body.len(), 3 * UNIT + 1);

    drop(body);
    assert_eq!(
        budget.available_bytes(),
        total,
        "dropping the published body returns every block it held"
    );
}

/// The charge precedes the allocation: a growth the budget cannot cover is
/// refused INSTEAD of allocated, not discovered after the fact.
///
/// With four blocks left, the doubling step to `6 * UNIT` cannot be paid for.
/// A collector that charged the post-append length would have found `3 * UNIT +
/// 1` affordable at four blocks and gone on to allocate six.
#[test]
fn growth_the_budget_cannot_cover_is_refused_instead_of_allocated() {
    let budget = probe(4);
    let total = budget.available_bytes();

    let mut collector = budget.collector(8 * UNIT);
    collector
        .append(&vec![0u8; 3 * UNIT])
        .expect("first append admits");
    assert_eq!(
        collector.append(&[1u8]),
        Err(ResponseBufferRetainRejection::BudgetExhausted),
        "the growth target must be charged before it is allocated, so an \
         unaffordable doubling is refused rather than discovered afterwards"
    );

    drop(collector);
    assert_eq!(
        budget.available_bytes(),
        total,
        "a refused collector leaks no partial reservation"
    );
}

/// A refusal keeps its attribution. A ceiling overrun is the BACKEND sending
/// more than the operator retains; an exhausted aggregate budget is
/// gateway-local transient capacity and must stay health-neutral.
#[test]
fn collector_refusals_keep_their_backend_versus_gateway_attribution() {
    let budget = probe(16);

    let mut collector = budget.collector(2 * UNIT);
    assert_eq!(
        collector.append(&vec![0u8; 3 * UNIT]),
        Err(ResponseBufferRetainRejection::TooLarge),
        "a body past the per-response ceiling is a backend attribution"
    );

    let spent = probe(1);
    let mut starved = spent.collector(8 * UNIT);
    assert_eq!(
        starved.append(&vec![0u8; 2 * UNIT]),
        Err(ResponseBufferRetainRejection::BudgetExhausted),
        "a body the aggregate budget cannot admit is gateway-local capacity"
    );

    assert!(
        error_class_is_health_neutral_for_test(RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS),
        "the gateway-capacity class must not feed circuit breaker, passive \
         health, or adaptive concurrency"
    );
    assert!(
        !error_class_is_backend_failure_for_test(RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS),
        "the gateway-capacity class must never be read as a backend failure"
    );
}

/// A preallocation hint is resident the instant it is requested, so it is
/// charged before the allocation and an unaffordable hint refuses the response
/// rather than allocating it. A zero hint costs nothing.
#[test]
fn a_preallocation_hint_is_charged_before_it_is_allocated() {
    let budget = probe(4);
    let total = budget.available_bytes();

    let collector = budget
        .collector_with_preallocation(8 * UNIT, 3 * UNIT)
        .expect("an affordable hint admits");
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the hint is charged before the first DATA frame, so a stalled response \
         cannot hold uncharged capacity"
    );
    assert_eq!(collector.len(), 0, "nothing has been appended yet");
    drop(collector);
    assert_eq!(budget.available_bytes(), total);

    assert_eq!(
        budget
            .collector_with_preallocation(8 * UNIT, 5 * UNIT)
            .err(),
        Some(ResponseBufferRetainRejection::BudgetExhausted),
        "an unaffordable hint refuses the response instead of allocating it"
    );

    let empty = budget
        .collector_with_preallocation(8 * UNIT, 0)
        .expect("a zero hint allocates nothing");
    assert_eq!(
        budget.available_bytes(),
        total,
        "a bodyless response must not consume budget it never occupies"
    );
    assert!(
        empty
            .into_charged_bytes()
            .expect("empty publishes")
            .is_empty()
    );
    assert_eq!(budget.available_bytes(), total);
}

/// Growth inside an already-reserved capacity re-charges nothing: a
/// preallocated response is charged once, not once per frame.
#[test]
fn growth_within_reserved_capacity_is_not_charged_twice() {
    let budget = probe(16);
    let total = budget.available_bytes();

    let mut collector = budget
        .collector_with_preallocation(8 * UNIT, 4 * UNIT)
        .expect("hint admits");
    let reserved_after_hint = total - budget.available_bytes();
    for _ in 0..4 {
        collector.append(&vec![7u8; UNIT]).expect("in-hint append");
    }
    assert_eq!(
        total - budget.available_bytes(),
        reserved_after_hint,
        "filling preallocated capacity allocates nothing, so it charges nothing"
    );

    let body = collector.into_charged_bytes().expect("publishes");
    assert_eq!(body.len(), 4 * UNIT);
    drop(body);
    assert_eq!(budget.available_bytes(), total);
}

// ---------------------------------------------------------------------------
// The transform window: a plugin's output cannot exist before its charge does.
// ---------------------------------------------------------------------------

/// The window is reserved BEFORE the producer runs, so an exhausted budget
/// refuses the phase rather than letting a plugin allocate first and charging
/// afterwards.
#[test]
fn a_transform_window_is_refused_before_the_producer_allocates() {
    let budget = probe(2);
    assert!(
        budget.transform_window(4 * UNIT).is_none(),
        "a window larger than the remaining budget must be refused up front; \
         charging after the plugin allocated is the accounting hole \
         (GHSA-pwcm-6rh8-f2gh)"
    );
    assert_eq!(
        budget.available_bytes(),
        2 * UNIT,
        "a refused window leaks no partial reservation"
    );
}

/// Charging an output out of the window is a TRANSFER, not a second
/// acquisition — and `charge` deliberately does NOT refill. The body being
/// replaced is still alive when `charge` returns, so refilling there would hold
/// the old body's blocks and a fresh full window at the same time.
#[test]
fn a_charged_replacement_transfers_blocks_out_of_the_window() {
    let budget = probe(16);
    let total = budget.available_bytes();

    let mut window = budget
        .transform_window(2 * UNIT)
        .expect("the window admits");
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "the whole window is reserved before the producer runs"
    );

    let replacement = window
        .charge(vec![5u8; UNIT])
        .expect("an in-window output publishes");
    assert_eq!(replacement.len(), UNIT);
    assert_eq!(
        budget.available_bytes(),
        total - 2 * UNIT,
        "the published body carries blocks carved OUT of the window, so nothing \
         new was acquired and the window is now short by exactly that much"
    );
    assert_eq!(
        window.available_bytes(),
        UNIT,
        "the window is short until it is explicitly refilled"
    );

    // Refill happens only once the caller has installed the replacement and the
    // body it replaced has dropped its own charge.
    assert!(
        window.ensure_covering_window(),
        "a full window is re-established before the next producer"
    );
    assert_eq!(window.available_bytes(), 2 * UNIT);
    assert_eq!(budget.available_bytes(), total - 3 * UNIT);

    drop(window);
    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "closing the phase returns the window but not the published body"
    );
    drop(replacement);
    assert_eq!(budget.available_bytes(), total);
}

/// The precondition finding: after a first replacement consumes part of the
/// window, a second producer must not be invoked under a PARTIAL window. When
/// the spare budget has been taken in the meantime, `ensure_covering_window`
/// fails and the caller installs the neutral capacity terminal INSTEAD of
/// calling the next producer — so no uncharged output can exist
/// (GHSA-pwcm-6rh8-f2gh).
#[test]
fn a_second_producer_is_never_invoked_under_a_partial_window() {
    // Exactly two blocks of headroom beyond the window itself.
    let budget = probe(3);
    let total = budget.available_bytes();

    let mut window = budget.transform_window(UNIT).expect("the window admits");
    assert_eq!(budget.available_bytes(), total - UNIT);

    // First producer's output is charged out of the window.
    let first = window
        .charge(vec![1u8; UNIT])
        .expect("the first replacement publishes");
    assert_eq!(window.available_bytes(), 0, "the window is now empty");

    // Something else takes the spare budget before the chain continues, and the
    // first replacement is still resident (it is the current response body).
    let competitor = budget
        .try_reserve(2 * UNIT)
        .expect("a concurrent response takes the remaining budget");
    assert_eq!(budget.available_bytes(), 0);

    assert!(
        !window.ensure_covering_window(),
        "a full covering window cannot be re-established, so the next producer \
         must not be invoked at all"
    );
    assert_eq!(
        window.available_bytes(),
        0,
        "a failed refill acquires nothing, so no partial window is presented to \
         a producer"
    );

    drop(competitor);
    drop(window);
    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "only the published first replacement is still charged"
    );
    drop(first);
    assert_eq!(budget.available_bytes(), total);
}

/// An output larger than the window is stopped DURING construction, not after a
/// larger buffer is already resident.
///
/// A full-ceiling window only bounds what may be installed; on its own it does
/// not stop a producer from materialising something bigger first. So the
/// producer builds through the window's ceiling-bounded sink, which refuses the
/// write that would carry the buffer past the bound and releases what it had
/// (GHSA-pwcm-6rh8-f2gh).
#[test]
fn an_output_larger_than_the_window_is_refused_while_it_is_written() {
    let budget = probe(16);
    let total = budget.available_bytes();

    let window = budget.transform_window(UNIT).expect("the window admits");
    let mut sink = window.sink();
    assert_eq!(sink.ceiling(), UNIT, "the sink is sized to the window");

    assert!(sink.push(&[5u8; UNIT]), "an in-ceiling write is accepted");
    assert!(
        !sink.push(&[5u8; 1]),
        "the write that would exceed the retained ceiling is refused BEFORE the \
         allocation it would need"
    );
    assert!(sink.overflowed());
    assert!(
        sink.is_empty(),
        "a refused sink releases what it had written"
    );
    assert!(
        sink.finish().is_none(),
        "an overflowed sink yields no replacement body at all"
    );

    assert_eq!(
        budget.available_bytes(),
        total - UNIT,
        "a refused replacement neither publishes nor over-releases"
    );

    drop(window);
    assert_eq!(budget.available_bytes(), total);
}

/// The installation gate is still checked, so a mis-sized output that somehow
/// reached `charge` is refused rather than installed uncharged.
#[test]
fn an_output_the_window_cannot_cover_is_refused_at_installation() {
    let budget = probe(16);
    let total = budget.available_bytes();

    let mut window = budget.transform_window(UNIT).expect("the window admits");
    assert!(
        window.charge(vec![5u8; 2 * UNIT]).is_none(),
        "a replacement above the per-response retained ceiling must be refused \
         for the same reason a backend body that size would be"
    );
    assert_eq!(budget.available_bytes(), total - UNIT);

    drop(window);
    assert_eq!(budget.available_bytes(), total);
}

/// The JSON materialisation every JSON-producing response transform uses stops
/// serialization at the ceiling instead of building the whole document first.
#[test]
fn bounded_json_materialisation_refuses_an_amplified_document() {
    use ferrum_edge::_test_support::bounded_json_response_body_for_test as bounded_json;

    let small = serde_json::json!({"ok": true});
    let encoded = bounded_json(&small, 64).expect("a small document fits");
    assert_eq!(encoded, br#"{"ok":true}"#.to_vec());

    let big = serde_json::json!({"blob": "x".repeat(4096)});
    assert!(
        bounded_json(&big, 128).is_none(),
        "a document that would exceed the ceiling is refused while it is being \
         serialized, not after a larger buffer exists"
    );
}

// ---------------------------------------------------------------------------
// The producer precondition, evaluated before every invocation.
// ---------------------------------------------------------------------------

/// The exact shape the root review called out: a chain of two producers where
/// the first replacement consumed the window and the spare budget was taken in
/// the meantime. The second producer must NOT be invoked, so no output of its
/// can exist to be charged or refused after the fact
/// (GHSA-pwcm-6rh8-f2gh).
#[test]
fn a_second_producer_is_not_invoked_when_the_window_cannot_be_refilled() {
    use ferrum_edge::_test_support::{
        PRODUCER_REFUSED_UNDECLARED_CONTRACT, PRODUCER_REFUSED_WINDOW_UNAVAILABLE,
        admit_response_body_producer_for_test as admit,
    };
    use ferrum_edge::plugins::ResponseBodyProduction;

    let budget = probe(3);
    let total = budget.available_bytes();
    let mut window = budget.transform_window(UNIT).expect("the window admits");

    // First producer: admitted, because a full covering window exists.
    assert_eq!(
        admit(
            ResponseBodyProduction::BoundedByRetainedCeiling,
            Some(&mut window)
        ),
        None,
        "the first producer runs inside a full covering window"
    );
    let first = window
        .charge(vec![1u8; UNIT])
        .expect("the first replacement publishes");

    // The spare budget is consumed by a concurrent response before the chain
    // reaches the second producer, and the first replacement is still resident.
    let competitor = budget
        .try_reserve(2 * UNIT)
        .expect("a concurrent response takes the rest of the budget");
    assert_eq!(budget.available_bytes(), 0);

    assert_eq!(
        admit(
            ResponseBodyProduction::BoundedByRetainedCeiling,
            Some(&mut window)
        ),
        Some(PRODUCER_REFUSED_WINDOW_UNAVAILABLE),
        "without a full covering window the producer must not be invoked at all"
    );
    assert_eq!(
        window.available_bytes(),
        0,
        "the refused refill acquired nothing, so no partial window exists"
    );

    // A non-producer is still invoked: nothing is reserved on its account.
    assert_eq!(
        admit(ResponseBodyProduction::Never, Some(&mut window)),
        None,
        "a proven non-producer needs no window"
    );

    // An out-of-tree plugin is refused even when the window is full, because
    // the gateway cannot prove its output is bounded.
    drop(competitor);
    assert!(
        window.ensure_covering_window(),
        "the window can refill again"
    );
    assert_eq!(
        admit(ResponseBodyProduction::Undeclared, Some(&mut window)),
        Some(PRODUCER_REFUSED_UNDECLARED_CONTRACT),
        "an undeclared replacement contract fails closed rather than being \
         invoked under a window"
    );

    drop(window);
    assert_eq!(budget.available_bytes(), total - UNIT);
    drop(first);
    assert_eq!(budget.available_bytes(), total);
}

/// A chain that cannot produce reserves no window at all, so validators and
/// header-only plugins do not halve the buffered-response concurrency the
/// aggregate budget supports.
#[test]
fn a_non_producing_plugin_needs_no_window() {
    use ferrum_edge::_test_support::admit_response_body_producer_for_test as admit;
    use ferrum_edge::plugins::ResponseBodyProduction;

    assert!(
        !ResponseBodyProduction::Never.may_replace_response_body(),
        "a proven non-producer must not force a window open"
    );
    assert!(
        ResponseBodyProduction::Undeclared.may_replace_response_body(),
        "an unknown plugin must be treated as potentially rewriting"
    );
    assert!(ResponseBodyProduction::BoundedByRetainedCeiling.may_replace_response_body());

    assert_eq!(
        admit(ResponseBodyProduction::Never, None),
        None,
        "with no window open at all, a non-producer still runs"
    );
}

// ---------------------------------------------------------------------------
// Construction-side bounding, per declared producer.
//
// A window bounds what is INSTALLED. The two-ceiling peak the module documents
// (old body + one covering window) is only true if no producer ever holds a
// complete would-be replacement outside that window — so a producer that builds
// its output in full and then copies it through `bounded_vec_from` bypasses the
// aggregate accounting even though the copy is bounded. These guards pin the
// eight declared producers to construction-side bounding (GHSA-pwcm-6rh8-f2gh).
// ---------------------------------------------------------------------------

/// Every declared producer, with the source it is implemented in.
fn declared_producer_sources() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "ai_response_guard",
            include_str!("../../../src/plugins/ai_response_guard.rs"),
        ),
        (
            "ai_stream_router",
            include_str!("../../../src/plugins/ai_stream_router.rs"),
        ),
        (
            "ai_tool_governor",
            include_str!("../../../src/plugins/ai_tool_governor.rs"),
        ),
        (
            "compression",
            include_str!("../../../src/plugins/compression.rs"),
        ),
        ("grpc_web", include_str!("../../../src/plugins/grpc_web.rs")),
        (
            "mcp_gateway",
            include_str!("../../../src/plugins/mcp_gateway.rs"),
        ),
        (
            "response_transformer",
            include_str!("../../../src/plugins/response_transformer.rs"),
        ),
        ("sse", include_str!("../../../src/plugins/sse.rs")),
    ]
}

/// The guard table below must cover the declared set exactly, so adding a
/// producer to `BUILTIN_RESPONSE_BODY_PRODUCERS` without a construction guard
/// fails here rather than silently.
#[test]
fn every_declared_producer_has_a_construction_guard() {
    use ferrum_edge::plugins::builtin_parity::BUILTIN_RESPONSE_BODY_PRODUCERS;

    let mut guarded: Vec<&str> = declared_producer_sources()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    guarded.sort_unstable();
    let mut declared: Vec<&str> = BUILTIN_RESPONSE_BODY_PRODUCERS.to_vec();
    declared.sort_unstable();
    assert_eq!(
        guarded, declared,
        "the construction-side guards must stay set-equal with the declared \
         response-body producer inventory"
    );
}

/// Every declared producer must reach a ceiling-aware writer at all: a producer
/// with no bounded materialisation point is one that hands the gateway an
/// arbitrary `Vec`.
#[test]
fn every_declared_producer_materialises_through_a_ceiling_aware_writer() {
    for (name, source) in declared_producer_sources() {
        assert!(
            source.contains("BoundedResponseBodySink")
                || source.contains("bounded_json_vec")
                || source.contains("serialize_json_bounded")
                // `response_transformer` reaches the same bounded serializer
                // through the shared JSON body-rule applier.
                || source.contains("apply_body_rules_bounded"),
            "{name} must build its replacement through a ceiling-bounded writer"
        );
    }

    // The shared applier that stands in for `response_transformer` above must
    // itself serialize through the bound, so the indirection stays honest.
    let body_transform = include_str!("../../../src/plugins/utils/body_transform.rs");
    assert!(
        body_transform.contains("bounded_json_vec"),
        "`apply_body_rules_bounded` must serialize the rewritten document \
         through the ceiling-bounded writer"
    );
}

/// The specific build-then-copy shapes the root review found, pinned absent.
///
/// Each entry is a byte sequence that existed before this repair and that
/// re-introducing would mean a complete (or attacker-amplified) replacement is
/// materialised before its retained ceiling is enforced.
#[test]
fn no_declared_producer_builds_a_complete_replacement_before_the_bound() {
    let forbidden: &[(&str, &[&str])] = &[
        (
            "sse",
            // The wrapped event was framed from two whole-body `String` copies
            // (lossy decode, then CR/CRLF normalization) before the sink saw a
            // byte. It is now written incrementally over the input.
            &["= String::from_utf8_lossy(body);", "normalized.lines()"],
        ),
        (
            "ai_stream_router",
            // The upstream-error envelope was built as a complete `Vec` and
            // copied in, and the buffered normalizer was handed the WHOLE body,
            // which accumulates the complete normalized stream in a `String`
            // before returning it.
            &["bounded_vec_from", "normalizer.on_chunk(body)"],
        ),
        (
            "grpc_web",
            // Text mode built a complete binary body, then a complete base64
            // `String`, then copied that into a third bounded buffer.
            &["BASE64.encode(&output)"],
        ),
        (
            "ai_response_guard",
            // The rewritten SSE stream, the expanded plain-text redaction, and
            // the re-encoded protobuf frame were each complete before the bound.
            // The bounded SSE path must also never rebuild a complete event
            // `String` (including via `to_string`) before the sink sees it.
            &[
                "bounded_vec_from(output.as_bytes()",
                "encode_to_vec()",
                "encode_grpc_frame(",
                "ceiling.checked_sub(buffer.len())?",
            ],
        ),
        // The four already-clean producers must stay clean: none of them may
        // acquire a build-then-copy materialisation.
        ("ai_tool_governor", &["bounded_vec_from"]),
        ("compression", &["bounded_vec_from"]),
        ("mcp_gateway", &["bounded_vec_from"]),
        ("response_transformer", &["bounded_vec_from"]),
    ];

    let sources = declared_producer_sources();
    for (name, needles) in forbidden {
        let source = sources
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, source)| *source)
            .unwrap_or_else(|| panic!("{name} must be a declared producer"));
        for needle in *needles {
            assert!(
                !source.contains(needle),
                "{name}: `{needle}` materialises a complete would-be replacement \
                 before its retained ceiling is enforced (GHSA-pwcm-6rh8-f2gh)"
            );
        }
    }
}

/// The construction-side replacements those holes were closed with, pinned
/// present, so the fix cannot be quietly reverted to an equivalent-looking
/// bounded copy.
#[test]
fn the_repaired_producers_construct_through_the_bound() {
    let required: &[(&str, &[&str])] = &[
        (
            "sse",
            &["fn write_lossy_sse_data(", "SSE_DATA_FIELD_PREFIX"],
        ),
        (
            "ai_stream_router",
            &[
                "BUFFERED_NORMALIZE_CHUNK_BYTES",
                "body.chunks(BUFFERED_NORMALIZE_CHUNK_BYTES)",
                "serde_json::to_writer(&mut sink, message)",
            ],
        ),
        (
            "grpc_web",
            &[
                "base64::write::EncoderWriter::new(&mut output, &engine)",
                "fn write_trailer_frame_payload<'a, S: TrailerPayloadSink>(",
            ],
        ),
        (
            "ai_response_guard",
            &[
                "fn rewrite_sse_events_bounded<'a>(",
                "fn rewrite_sse_json_event_into(",
                "serde_json::to_writer(&mut *output, &json)",
                "fn redact_text_bounded(",
                "ceiling.checked_sub(buffer.capacity())?",
                "fn write_pattern_replaced(",
                "fn push_reframed_grpc_message(",
                // The SSE residual candidate is a full would-be client body
                // built OUTSIDE a producer phase, so it takes a real window.
                "ResponseTransformWindow::open(ceiling)",
            ],
        ),
    ];

    let sources = declared_producer_sources();
    for (name, needles) in required {
        let source = sources
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, source)| *source)
            .unwrap_or_else(|| panic!("{name} must be a declared producer"));
        for needle in *needles {
            assert!(
                source.contains(needle),
                "{name}: `{needle}` is the construction-side bound for a hole the \
                 root review found; it must not be removed"
            );
        }
    }
}

/// The reserve-then-fill seam: a producer that knows its output length before it
/// can produce the bytes writes into the sink's OWN buffer, so it never builds a
/// complete replacement beside it. It is fail-closed on a length disagreement
/// and on a failing fill.
#[test]
fn the_reserve_then_fill_seam_is_bounded_and_fail_closed() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    let mut sink = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(sink.append_exact(b"abcd"), "an in-ceiling fill is admitted");
    assert_eq!(sink.len(), 4);
    assert!(
        !sink.append_exact(b"efghi"),
        "the fill that would exceed the ceiling is refused BEFORE the room for \
         it is reserved"
    );
    assert!(sink.overflowed());
    assert!(sink.finish().is_none());

    // A fill that writes less than it declared cannot publish a short buffer.
    let mut short = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(!short.append_declaring(4, b"ab"));
    assert!(short.overflowed());
    assert!(short.finish().is_none());

    // A fill that writes more than it declared cannot publish either.
    let mut long = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(!long.append_declaring(2, b"abcd"));
    assert!(long.overflowed());
    assert!(long.finish().is_none());

    // A failing fill leaves nothing behind.
    let mut failed = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(!failed.append_failing(4));
    assert!(failed.overflowed());
    assert!(failed.finish().is_none());
}

/// The module's operator-facing arithmetic is the two-ceiling peak; the doc must
/// keep saying so, and must keep saying WHY it is exact.
#[test]
fn the_two_ceiling_peak_is_documented_as_exact() {
    let budget = include_str!("../../../src/proxy/response_buffer_budget.rs");
    assert!(
        budget.contains("(2 × ceiling)"),
        "the concurrent-rewrite arithmetic operators are given must stay stated"
    );
    assert!(
        budget.contains("Two is the exact number, not a rounding."),
        "the peak must be stated as exact, with the construction-side reason, \
         so a later build-then-copy producer is visibly a doc violation"
    );
}

/// The reserve-then-fill seam's CONTRACT, stated exactly.
///
/// `append_with` documents that it verifies the produced length and fails
/// closed on a mismatch. A zero-length append used to return `true` without
/// invoking `fill` at all, so the documented failure/length checks did not
/// describe what it did. It now runs the fill and verifies the result for every
/// admitted length, including zero.
#[test]
fn the_reserve_then_fill_seam_honours_its_contract_at_zero_length() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    // A zero-length fill that writes nothing is admitted, and the fill really
    // ran: the observed room is the length it was admitted for.
    let mut empty = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert_eq!(
        empty.append_observing_room(0),
        Some(0),
        "a zero-length append must still invoke the fill"
    );
    assert_eq!(empty.len(), 0);
    assert!(!empty.overflowed());

    // A zero-length fill that FAILS is fail-closed like any other.
    let mut failed = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(!failed.append_failing(0));
    assert!(failed.overflowed());
    assert!(failed.finish().is_none());

    // A zero-length fill that writes anyway is a length mismatch.
    let mut sneaky = BoundedResponseBodySinkProbe::with_ceiling(8);
    assert!(!sneaky.append_declaring(0, b"x"));
    assert!(sneaky.overflowed());
    assert!(sneaky.finish().is_none());
}

/// The fill's target is LIMITED to the room it was admitted for, so a producer
/// cannot grow the sink past its ceiling before the post-fill length check runs.
#[test]
fn the_reserve_then_fill_target_admits_exactly_the_reserved_room() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    let mut sink = BoundedResponseBodySinkProbe::with_ceiling(64);
    assert_eq!(
        sink.append_observing_room(8),
        Some(8),
        "the fill may address exactly the bytes it was admitted for, never the \
         buffer's spare capacity"
    );
    assert_eq!(sink.len(), 8);

    // A second append is limited to its own room, not to the ceiling remainder.
    assert_eq!(sink.append_observing_room(4), Some(4));
    assert_eq!(sink.len(), 12);

    // Room past the ceiling is refused before the target exists at all.
    assert!(sink.append_observing_room(64).is_none());
    assert!(sink.overflowed());
    assert!(sink.finish().is_none());
}

/// Long fills still stream: an append that fills the whole ceiling in one call
/// is admitted, and the one that would cross it is refused with nothing partial
/// retained.
#[test]
fn the_reserve_then_fill_seam_admits_a_full_ceiling_and_refuses_the_next_byte() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    let mut sink = BoundedResponseBodySinkProbe::with_ceiling(4096);
    assert_eq!(sink.append_observing_room(4096), Some(4096));
    assert_eq!(sink.len(), 4096);
    assert!(!sink.overflowed());
    assert!(!sink.append_exact(b"x"));
    assert!(sink.overflowed());
    assert!(sink.finish().is_none());
}

/// The construction-side bounds this repair round added, pinned present so a
/// later change cannot quietly restore a build-then-measure shape.
#[test]
fn the_root_review_repairs_are_pinned_in_source() {
    let grpc_web = include_str!("../../../src/plugins/grpc_web.rs");
    assert!(
        grpc_web.contains("struct CountingTrailerPayloadSink")
            && grpc_web.contains("struct WriterTrailerPayloadSink"),
        "the gRPC-Web trailer frame must be measured by a counting pass and \
         written straight into the final bounded destination"
    );
    assert!(
        !grpc_web.contains("let trailer_payload = payload_sink.finish()?;"),
        "a complete trailer payload must not be materialised beside the output"
    );
    assert!(
        !grpc_web.contains("let mut eligible: Vec<(String, String)> = Vec::new();"),
        "eligible trailer values must not be cloned into an owned vector before \
         the bounded sink applies"
    );
    assert!(
        grpc_web.contains("fn resolve_trailer_frame_value<'a>(")
            && grpc_web.contains(") -> Option<&'a str>"),
        "resolved trailer values must borrow from immutable inputs, not clone \
         upstream-controlled payload segments"
    );
    let resolve_start = grpc_web
        .find("fn resolve_trailer_frame_value")
        .expect("resolve_trailer_frame_value must exist");
    // Match the sync helper by name rather than a brittle `\npub fn` prefix: a
    // narrow `#[allow(dead_code)]` (or `pub(crate)`) may sit on the line before
    // the signature without changing the ordering invariant.
    let resolve_body = grpc_web[resolve_start..]
        .split_once("sync_translated_body_trailer_frame_from_trailers")
        .map(|(body, _)| body)
        .expect("resolve_trailer_frame_value must precede the translated-body sync helper");
    assert!(
        resolve_body.contains(") -> Option<&'a str>"),
        "resolve_trailer_frame_value's borrowed return must still appear before \
         the translated-body sync helper"
    );
    assert!(
        !resolve_body.contains("trailer_value.clone()")
            && !resolve_body.contains("view_value.to_string()")
            && !resolve_body.contains("pre_policy_value.to_string()"),
        "resolve_trailer_frame_value must not clone a complete resolved trailer \
         value before the counting/final sink sees it"
    );

    // Final trailer reconciliation must keep the charged original alive and
    // build any replacement through the bounded sink (GHSA-pwcm-6rh8-f2gh).
    assert!(
        grpc_web.contains("pub(crate) fn sync_translated_body_trailer_frame_into(")
            && grpc_web.contains("stream_decode_base64_groups")
            && grpc_web.contains("rebuild_text_grpc_web_trailer_suffix")
            && grpc_web.contains("rebuild_binary_grpc_web_trailer_suffix"),
        "final reconciliation must stream-decode/rebuild through a ceiling-bounded sink"
    );
    let sync_into = grpc_web
        .split("pub(crate) fn sync_translated_body_trailer_frame_into(")
        .nth(1)
        .expect("sync_translated_body_trailer_frame_into");
    let sync_into_body = sync_into
        .split("\n/// Locate the start of the contiguous trailer-frame suffix")
        .next()
        .expect("sync_into precedes trailing_trailer_suffix_start docs");
    assert!(
        !sync_into_body.contains("BASE64.decode(")
            && !sync_into_body.contains("BASE64.encode(")
            && !sync_into_body.contains("build_trailer_frame(")
            && !sync_into_body.contains("std::mem::take(body)"),
        "final reconciliation must not decode/encode/build-then-measure a complete \
         body-sized replacement beside the sink"
    );

    let proxy = include_str!("../../../src/proxy/mod.rs");
    let store = proxy
        .split("pub(crate) fn store_charged_grpc_web_reframed_body(")
        .nth(1)
        .expect("store_charged_grpc_web_reframed_body");
    let store_body = store
        .split("\n/// The neutral gRPC capacity terminal")
        .next()
        .expect("store precedes capacity terminal helper");
    assert!(
        !store_body.contains("take_buffered_vec")
            && store_body.contains("sync_translated_body_trailer_frame_into")
            && store_body.contains("window.charge(")
            && store_body.contains("grpc_web_reframe_capacity_terminal("),
        "final publication must not copy out of the charged owner; it must build \
         through sync_into, charge the sink-built replacement, and route every \
         refusal through the shared protocol-aware terminal"
    );
    assert!(
        store_body.contains(
            "window = response_buffer_budget::ResponseTransformWindow::open(retained_ceiling);"
        ),
        "the final reframe must reserve its covering window from the allocation-admission callback"
    );
    let admission = sync_into_body
        .find("if !admit_replacement()")
        .expect("replacement admission gate");
    let output = sync_into_body
        .find("let mut output = BoundedResponseBodySink::with_ceiling(ceiling);")
        .expect("bounded output construction");
    assert!(
        admission < output,
        "the covering window must be admitted immediately before bounded output can allocate"
    );
    assert_eq!(
        proxy
            .matches("let retained_ceiling = ctx.retained_response_body_ceiling();")
            .count(),
        2,
        "both H1/H2 final reconciliation call sites must fold unlimited to the finite retained ceiling"
    );
    let h3_cross_protocol = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        h3_cross_protocol.contains("let retained_ceiling = ctx.retained_response_body_ceiling();"),
        "the H3 cross-protocol final reconciliation call site must fold unlimited to the finite retained ceiling"
    );

    let stream_router = include_str!("../../../src/plugins/ai_stream_router.rs");
    assert!(
        stream_router.contains("pub(crate) struct NormalizedSseOut"),
        "normalized SSE bytes must be written through a ceiling-bounded \
         accumulator from the first byte"
    );
    assert!(
        stream_router.contains("NormalizedSseOut::with_ceiling(ceiling)"),
        "the buffered path must bind the accumulator to this response's \
         retained ceiling, not to a constant"
    );
    assert!(
        !stream_router.contains("fn chunk_line(&mut self"),
        "an SSE line must not be built as a complete `String` outside the sink"
    );

    let guard = include_str!("../../../src/plugins/ai_response_guard.rs");
    assert!(
        guard.contains("ai_response_guard_pending_redactions"),
        "a promised redaction must be tracked in typed request state so a \
         refused construction cannot be forwarded as `unchanged`"
    );
    assert!(
        guard.contains("async fn on_final_response_body("),
        "the final verification seam must stay in place"
    );
    assert_eq!(
        guard.matches("ResponseTransformWindow::open(").count(),
        3,
        "every full-size candidate built outside a producer phase — the SSE \
         residual scan, the JSON/content residual scan, and the native-gRPC \
         redaction preflight — must reserve a real window first"
    );

    let budget = include_str!("../../../src/proxy/response_buffer_budget.rs");
    assert!(
        budget.contains("bytes::buf::Limit"),
        "the reserve-then-fill target must be limited to the admitted room"
    );
    assert!(
        !budget.contains("if additional == 0 {\n            return true;\n        }"),
        "the zero-length append must not skip the fill and its length check"
    );
    assert!(
        budget.contains("fn refuse_if_capacity_exceeds_ceiling(&mut self) -> bool")
            && budget.contains("if self.data.capacity() > self.ceiling"),
        "BoundedResponseBodySink must sticky-overflow when reserve_exact returns \
         capacity above the admitted ceiling"
    );
    // Both growth sites must check immediately after reserve_exact.
    let sink_impl = budget
        .split("impl BoundedResponseBodySink {")
        .nth(1)
        .expect("BoundedResponseBodySink impl");
    let push_region = sink_impl
        .split("pub(crate) fn append_with")
        .next()
        .expect("push precedes append_with");
    assert!(
        push_region.contains("self.data.reserve_exact(target - self.data.len());")
            && push_region.contains("if !self.refuse_if_capacity_exceeds_ceiling()"),
        "push must refuse over-ceiling capacity immediately after reserve_exact"
    );
    let append_region = sink_impl
        .split("pub(crate) fn append_with")
        .nth(1)
        .expect("append_with body");
    let append_growth = append_region
        .split("let wrote = {")
        .next()
        .expect("append_with growth precedes fill");
    assert!(
        append_growth.contains("self.data.reserve_exact(target - self.data.len());")
            && append_growth.contains("if !self.refuse_if_capacity_exceeds_ceiling()"),
        "append_with must refuse over-ceiling capacity immediately after reserve_exact"
    );
}

/// Geometric growth leaves capacity above length; that slack is resident and
/// must not mint room for a later sequential redaction pass
/// (GHSA-pwcm-6rh8-f2gh root finding).
#[test]
fn sequential_scratch_budgets_resident_capacity_not_length() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    // Reproduce the sink's geometric growth: many one-byte writes leave
    // capacity well above length once doubling jumps to the ceiling.
    let ceiling = 64usize;
    let mut sink = BoundedResponseBodySinkProbe::with_ceiling(ceiling);
    for _ in 0..33 {
        assert!(sink.push(b"a"));
    }
    assert_eq!(sink.len(), 33);
    assert!(
        sink.capacity() > sink.len(),
        "growth must leave capacity slack above length so the regression is meaningful"
    );
    assert!(
        sink.capacity() <= sink.ceiling(),
        "a successful write must never leave capacity above the admitted ceiling"
    );
    // The capacity-based remainder is strictly smaller than the length-based
    // one whenever slack exists — that gap is what the old arithmetic minted.
    let capacity_room = ceiling.checked_sub(sink.capacity()).expect("in-ceiling");
    let length_room = ceiling.checked_sub(sink.len()).expect("in-ceiling");
    assert!(
        capacity_room < length_room,
        "capacity slack must not be treatable as free room for the next scratch buffer"
    );
}

/// Observed successful writes stay inside the admitted ceiling. This does not
/// invent an allocator over-return; it pins the invariant the sticky-overflow
/// gate upholds whenever growth actually runs.
#[test]
fn bounded_sink_capacity_never_exceeds_ceiling_on_successful_writes() {
    use ferrum_edge::_test_support::BoundedResponseBodySinkProbe;

    let mut sink = BoundedResponseBodySinkProbe::with_ceiling(128);
    // Mix small and medium writes so growth_target runs repeatedly.
    for size in [1usize, 2, 3, 5, 8, 13, 21, 34] {
        let chunk = vec![b'x'; size];
        if sink.len() + size > sink.ceiling() {
            assert!(!sink.push(&chunk));
            assert!(sink.overflowed());
            assert_eq!(
                sink.capacity(),
                0,
                "an overflow must release the partial allocation"
            );
            return;
        }
        assert!(sink.push(&chunk));
        assert!(
            sink.capacity() <= sink.ceiling(),
            "capacity {} exceeded ceiling {} after a successful write",
            sink.capacity(),
            sink.ceiling()
        );
    }
    assert!(!sink.overflowed());
    let finished = sink.finish().expect("in-ceiling writes finish");
    assert!(finished.len() <= 128);
}

// ---------------------------------------------------------------------------
// Normalize-phase capacity terminals are authoritative across every buffered
// frontend call site: later body policy / transform / final-validator phases
// must observe the typed selection signal and leave the terminal alone
// (GHSA-pwcm-6rh8-f2gh).
// ---------------------------------------------------------------------------

#[test]
fn capacity_refusal_records_an_explicit_selection_signal() {
    let mut ctx = refusal_ctx();
    assert!(
        !ferrum_edge::_test_support::gateway_capacity_response_selected_for_test(&ctx),
        "fresh contexts must not look like a capacity terminal"
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[("content-type", "application/json")]);
    let mut body = bytes::Bytes::from_static(b"backend representation");
    install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );
    assert!(
        ferrum_edge::_test_support::gateway_capacity_response_selected_for_test(&ctx),
        "installing the shared capacity terminal must record the typed selection signal"
    );
    assert_eq!(status, RESPONSE_BUFFER_OVERLOAD_STATUS);
    assert_eq!(
        body,
        bytes::Bytes::from_static(RESPONSE_BUFFER_OVERLOAD_BODY.as_bytes())
    );
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::GatewayBufferCapacity
    );
}

#[test]
fn every_buffered_normalize_call_site_honors_capacity_terminal_immutability() {
    let plugins = include_str!("../../../src/plugins/mod.rs");
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let h3_server = include_str!("../../../src/http3/server.rs");
    let h3_cross = include_str!("../../../src/http3/cross_protocol.rs");

    assert!(
        plugins.contains("enum NormalizeResponseBodyOutcome")
            && plugins.contains("CapacityTerminal")
            && plugins.contains("DeadlineTerminal")
            && plugins.contains("Replaced"),
        "normalize must expose an explicit CapacityTerminal outcome distinct from \
         ordinary Replaced and from DeadlineTerminal"
    );
    assert!(
        plugins.contains("gateway_capacity_response_selected")
            && plugins.contains("mark_gateway_capacity_response_selected"),
        "RequestContext must carry a typed capacity-terminal selection signal"
    );
    assert!(
        proxy.contains("ctx.mark_gateway_capacity_response_selected();"),
        "the shared capacity installer must record the selection signal"
    );

    for (label, source) in [
        ("h1/h2 + native grpc", proxy),
        ("h3 native", h3_server),
        ("h3 cross-protocol", h3_cross),
    ] {
        assert!(
            source.contains("capacity_terminal()")
                || source.contains("gateway_capacity_response_selected()"),
            "{label}: every buffered path must consult the capacity-terminal signal \
             rather than treating ordinary normalize success as mutable"
        );
        assert!(
            source.contains("!ctx.gateway_capacity_response_selected()")
                || source.contains("capacity_terminal()"),
            "{label}: transform/final phases must be gated on the capacity signal so a \
             gRPC-Web text capacity trailer cannot be double-encoded or replaced by a \
             later validator"
        );
    }

    // Final validators remain suppressed once capacity selection sets
    // `response_body_rejected` / the typed capacity signal.
    assert!(
        proxy.contains("on_final_response_body")
            && (proxy.contains("!response_body_rejected")
                || proxy.contains("gateway_capacity_response_selected()")),
        "final validators must not replace a selected capacity terminal"
    );
}

#[test]
fn grpc_web_text_capacity_terminal_is_single_layer_base64() {
    use base64::Engine as _;

    let mut ctx = refusal_ctx();
    ctx.metadata.insert(
        ferrum_edge::_test_support::GRPC_WEB_RETAINED_RESPONSE_CONTENT_TYPE_METADATA_KEY
            .to_string(),
        "application/grpc-web-text+proto".to_string(),
    );
    let mut status = 200u16;
    let mut headers = refusal_headers(&[("content-type", "application/grpc")]);
    let mut body = bytes::Bytes::from_static(b"native-grpc-bytes");
    install_response_buffer_capacity_refusal_for_test(
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    );

    assert_eq!(status, 200, "gRPC-Web errors ride HTTP 200");
    assert!(
        ferrum_edge::_test_support::gateway_capacity_response_selected_for_test(&ctx),
        "selection signal must be set for later phases to skip re-framing"
    );
    // Text mode is already base64 of a trailer frame. Later transforms must not
    // encode it again once the capacity signal is set.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .expect("text gRPC-Web capacity body must be single-layer base64");
    assert_eq!(
        decoded.first().copied(),
        Some(0x80),
        "decoded capacity body must start with a gRPC-Web trailer frame flag"
    );
    let rendered = String::from_utf8_lossy(&decoded);
    let expected_grpc_status = RESPONSE_BUFFER_OVERLOAD_GRPC_STATUS.to_string();
    assert!(
        rendered.contains(&format!("grpc-status: {expected_grpc_status}")),
        "trailer frame must carry the capacity status: {rendered:?}"
    );
    assert!(
        base64::engine::general_purpose::STANDARD
            .decode(&decoded)
            .is_err(),
        "capacity text body must not be double-base64-encoded"
    );
}

#[test]
fn ai_response_guard_routes_inspection_window_refusal_to_capacity_not_content() {
    let guard = include_str!("../../../src/plugins/ai_response_guard.rs");
    assert!(
        guard.contains("fn respond_to_inspection_capacity_unavailable("),
        "residual-window budget failure must have a dedicated capacity path"
    );
    assert!(
        guard.contains("mark_gateway_capacity_response_selected()"),
        "AI inspection capacity refusal must select the shared capacity terminal signal"
    );
    assert_eq!(
        guard
            .matches("Self::respond_to_inspection_capacity_unavailable(ctx)")
            .count(),
        3,
        "SSE residual, JSON/content residual, and gRPC redaction preflight must \
         each route window-open failure to capacity"
    );
    assert_eq!(
        RESPONSE_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::GatewayBufferCapacity,
        "capacity classification must remain the health-neutral GatewayBufferCapacity class"
    );
}
