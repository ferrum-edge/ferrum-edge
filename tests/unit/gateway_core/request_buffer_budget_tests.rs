//! Issue #4153 — fail-closed ceiling and aggregate budget for BUFFERED client
//! request bodies.
//!
//! Two properties the request side did not have before, and which the response
//! side already treats as a vulnerability class (GHSA-pwcm-6rh8-f2gh):
//!
//! * a configured request-body limit of `0` ("unlimited") used to take a raw
//!   `body.collect()` on the buffered path, so one upload could grow a single
//!   `Vec` for as long as it kept making progress — reachable
//!   pre-authentication, because `waf` request-body inspection buffers in the
//!   `authenticate` phase;
//! * a finite per-request ceiling still multiplies by concurrency, so N
//!   simultaneous buffered uploads had nothing capping them in aggregate.
//!
//! Every aggregate test runs against `RequestBufferBudgetProbe`, which is the
//! production budget type with its own semaphore — same clamping, same
//! non-blocking admission, same release-on-drop — so these cannot pass against
//! a parallel implementation of the rules, and they do not race the
//! process-global budget under a parallel test binary.

use ferrum_edge::_test_support::{
    DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES, DEFAULT_REQUEST_BUFFER_TOTAL_BYTES,
    REQUEST_BUFFER_OVERLOAD_BODY, REQUEST_BUFFER_OVERLOAD_ERROR_CLASS,
    REQUEST_BUFFER_OVERLOAD_GRPC_STATUS, REQUEST_BUFFER_OVERLOAD_STATUS,
    RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT, RequestBufferBudgetProbe,
    buffered_request_body_ceiling_for_test, effective_request_body_limit_for_test,
    error_class_is_backend_failure_for_test, error_class_is_health_neutral_for_test,
    normalize_reject_response, request_buffer_capacity_backend_response_for_test,
    request_buffer_capacity_reject_headers_for_test, set_request_grpc_web_upload_for_test,
    set_request_http_flavor_for_test,
};
use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::plugins::RequestContext;
use ferrum_edge::retry::ErrorClass;

/// `total_blocks` blocks of budget with a one-block fallback ceiling, so the
/// floor (`Budget::new` raises the total to at least the fallback) does not
/// dominate the total under test.
fn probe(total_blocks: usize) -> RequestBufferBudgetProbe {
    RequestBufferBudgetProbe::new(UNIT, total_blocks * UNIT)
}

// ---------------------------------------------------------------------------
// 1. A limit of 0 is not "unlimited" on the buffered path.
// ---------------------------------------------------------------------------

#[test]
fn a_zero_limit_folds_to_the_finite_fallback_on_the_buffered_path() {
    // The whole point of the issue: `0` used to reach a raw `collect()`.
    assert_eq!(
        buffered_request_body_ceiling_for_test(0),
        DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES,
        "a `0` request-body limit must not produce an unbounded retained buffer"
    );
    const {
        assert!(
            DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES > 0,
            "the fallback must be finite and non-zero or the fold is a no-op"
        )
    };
}

#[test]
fn a_configured_limit_still_wins_over_the_fallback() {
    // The fallback is a fail-closed floor for the `0` case only. An operator
    // who configured a limit keeps exactly that limit — larger or smaller than
    // the fallback.
    assert_eq!(buffered_request_body_ceiling_for_test(1234), 1234);
    assert_eq!(
        buffered_request_body_ceiling_for_test(DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES * 4),
        DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES * 4
    );
}

#[test]
fn a_route_ceiling_survives_an_unlimited_global_and_then_the_fold() {
    // `effective_request_body_limit` folds global + plugin first; the buffered
    // fold runs on the RESULT. A route ceiling under a `0` global therefore
    // stays authoritative and never falls back.
    let effective = effective_request_body_limit_for_test(0, Some(4096));
    assert_eq!(effective, 4096);
    assert_eq!(buffered_request_body_ceiling_for_test(effective), 4096);

    // Only a proxy with no active route ceiling reaches the fallback.
    assert_eq!(
        buffered_request_body_ceiling_for_test(effective_request_body_limit_for_test(0, None)),
        DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES
    );
}

#[test]
fn the_fallback_is_clamped_to_at_least_one_reservation_block() {
    // A zero or sub-block fallback would not cover even one reservation block,
    // which would refuse every buffered upload and take the proxy down.
    let degenerate = RequestBufferBudgetProbe::new(0, 64 * UNIT);
    assert_eq!(degenerate.buffered_request_body_ceiling(0), UNIT);

    let short = RequestBufferBudgetProbe::new(UNIT / 4, 64 * UNIT);
    assert_eq!(short.buffered_request_body_ceiling(0), UNIT);
}

#[test]
fn the_probe_folds_zero_to_its_own_configured_fallback() {
    let budget = RequestBufferBudgetProbe::new(3 * UNIT, 64 * UNIT);
    assert_eq!(budget.buffered_request_body_ceiling(0), 3 * UNIT);
    assert_eq!(budget.buffered_request_body_ceiling(7 * UNIT), 7 * UNIT);
}

// ---------------------------------------------------------------------------
// 2. Aggregate: a finite per-request ceiling still multiplies by concurrency.
// ---------------------------------------------------------------------------

#[test]
fn concurrent_buffered_requests_are_capped_in_aggregate() {
    // Four blocks of budget, one block per request: the fifth concurrent
    // buffered request is refused rather than admitted alongside the others.
    let budget = probe(4);
    let mut admitted = Vec::new();
    for i in 0..4 {
        admitted.push(
            budget
                .try_reserve(UNIT)
                .unwrap_or_else(|| panic!("request {i} must be admitted")),
        );
    }
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "the Nth+1 concurrent buffered request must be refused, not admitted"
    );

    // Each admitted request really holds its block.
    for permit in &admitted {
        assert_eq!(permit.reserved_bytes(), UNIT);
    }

    // Releasing one readmits exactly one.
    drop(admitted.pop());
    assert_eq!(budget.available_bytes(), UNIT);
    let readmitted = budget.try_reserve(UNIT);
    assert!(
        readmitted.is_some(),
        "a released claim must return capacity to the next request"
    );
}

#[test]
fn a_claim_is_returned_by_drop_on_every_exit_path() {
    // The RAII property is what makes success, 413, 499, timeout, deadline,
    // authorization expiry, and cancellation identical: they are all drops.
    let budget = probe(8);
    let total = budget.available_bytes();

    {
        let _claim = budget.try_reserve(3 * UNIT).expect("admits");
        assert_eq!(budget.available_bytes(), total - 3 * UNIT);
        // Scope exit stands in for every early return on the buffered path.
    }

    assert_eq!(
        budget.available_bytes(),
        total,
        "no exit path may leak the aggregate budget"
    );
}

#[test]
fn one_oversized_request_cannot_starve_the_whole_budget_silently() {
    // A per-request ceiling above the aggregate budget is honored as a ceiling
    // but is NOT admissible: the aggregate cap is not widened to fit one huge
    // upload, because that would hand the memory bound back to the client.
    let budget = probe(4);
    assert_eq!(budget.buffered_request_body_ceiling(64 * UNIT), 64 * UNIT);
    assert!(
        budget.try_reserve(64 * UNIT).is_none(),
        "an upload larger than the whole budget is refused, not silently admitted"
    );
    assert_eq!(
        budget.available_bytes(),
        4 * UNIT,
        "a refused reservation must not consume capacity"
    );
}

#[test]
fn the_aggregate_budget_is_floored_at_the_fallback_ceiling() {
    // A degenerate total would otherwise refuse every buffered upload. The
    // floor guarantees one FALLBACK-sized upload is always admissible — and
    // nothing beyond that.
    let budget = RequestBufferBudgetProbe::new(4 * UNIT, 0);
    assert_eq!(budget.available_bytes(), 4 * UNIT);
    assert!(
        budget.try_reserve(4 * UNIT).is_some(),
        "one fallback-sized upload must always be admissible"
    );
}

// ---------------------------------------------------------------------------
// 3. Streaming is unaffected.
// ---------------------------------------------------------------------------

#[test]
fn a_request_that_retains_nothing_takes_no_charge() {
    // The structural reason a STREAMED request cannot be shed by this budget:
    // it never reserves. Even against a fully exhausted budget, a zero-byte
    // claim is admitted and consumes nothing, so adding this budget cannot
    // convert streaming traffic into 503s.
    let budget = probe(2);
    let _exhaust = budget.try_reserve(2 * UNIT).expect("admits");
    assert_eq!(budget.available_bytes(), 0);

    let empty = budget
        .try_reserve(0)
        .expect("a request that retains nothing is always admitted");
    assert_eq!(empty.reserved_bytes(), 0);
    assert_eq!(budget.available_bytes(), 0);
}

// ---------------------------------------------------------------------------
// 4. Refusal shape.
// ---------------------------------------------------------------------------

#[test]
fn exhaustion_is_a_gateway_local_transient_capacity_terminal() {
    // 503, not 4xx: the client's upload is well formed. Not 502: no backend was
    // dialed.
    assert_eq!(REQUEST_BUFFER_OVERLOAD_STATUS, 503);
    // RESOURCE_EXHAUSTED is the gRPC capacity status. UNAVAILABLE would claim
    // the backend is down; INVALID_ARGUMENT would blame a valid upload.
    assert_eq!(REQUEST_BUFFER_OVERLOAD_GRPC_STATUS, 8);
    // Fixed bytes: no route, header, credential, or body content.
    assert_eq!(
        REQUEST_BUFFER_OVERLOAD_BODY,
        r#"{"error":"Request buffering capacity exceeded"}"#
    );
}

#[test]
fn terminal_drain_refusal_is_resource_exhausted_for_grpc() {
    // Issue #6022: the H1/H2 terminal-drain refusal runs the shared reject
    // pipeline, where a bare 503 maps to UNAVAILABLE. It carries the explicit
    // RESOURCE_EXHAUSTED terminal instead, like every other request-buffer
    // capacity refusal, the native H3 one included.
    let status = hyper::StatusCode::SERVICE_UNAVAILABLE;
    let body = REQUEST_BUFFER_OVERLOAD_BODY.as_bytes();
    let headers = request_buffer_capacity_reject_headers_for_test(true);
    let grpc = normalize_reject_response(status, body, &headers, true);
    assert_eq!(grpc.grpc_status, Some(REQUEST_BUFFER_OVERLOAD_GRPC_STATUS));
    assert_eq!(
        grpc.grpc_message.as_deref(),
        Some("Request buffering capacity exceeded")
    );

    // Plain HTTP keeps the 503 and carries no gRPC metadata.
    let headers = request_buffer_capacity_reject_headers_for_test(false);
    assert!(headers.is_empty());
    let http = normalize_reject_response(status, body, &headers, false);
    assert_eq!(http.http_status.as_u16(), REQUEST_BUFFER_OVERLOAD_STATUS);
    assert_eq!(http.grpc_status, None);
    assert!(!http.headers.contains_key("grpc-status"));

    let proxy_source = include_str!("../../../src/proxy/mod.rs");
    assert!(
        proxy_source.contains("request_buffer_capacity_reject_headers(is_grpc_request),"),
        "the H1/H2 terminal-drain refusal must hand these headers to the reject pipeline"
    );
}

#[test]
fn backend_seam_refusal_is_trailers_only_resource_exhausted_for_grpc() {
    // Issue #6022: the backend-dispatch seams (mesh / Unix-socket body
    // preparation, the H1/H2 retry/body-plugin collect, the native-H3 backend
    // collect) answered a bare 503, which a gRPC client reads as UNAVAILABLE.
    // A native gRPC request now gets the same Trailers-Only RESOURCE_EXHAUSTED
    // as the terminal drain and the native H3 refusal.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/rpc".into());
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    // Outbound header transforms cannot change the client-visible protocol.
    ctx.headers
        .insert("content-type".into(), "application/json".into());
    let grpc = request_buffer_capacity_backend_response_for_test(
        Some(&ctx),
        Some("192.0.2.7".to_string()),
    );
    assert_eq!(grpc.status_code, 200, "gRPC errors ride HTTP 200");
    assert_eq!(
        grpc.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        grpc.headers.get("grpc-status").map(String::as_str),
        Some(REQUEST_BUFFER_OVERLOAD_GRPC_STATUS.to_string().as_str())
    );
    assert_eq!(
        grpc.headers.get("grpc-message").map(String::as_str),
        Some("Request buffering capacity exceeded")
    );
    assert!(
        grpc.body_bytes().is_empty(),
        "Trailers-Only carries no body"
    );
    assert_eq!(grpc.error_class, Some(REQUEST_BUFFER_OVERLOAD_ERROR_CLASS));
    assert!(!grpc.connection_error && !grpc.request_on_wire);
    assert_eq!(grpc.backend_resolved_ip.as_deref(), Some("192.0.2.7"));

    // Conversely, a plain request cannot become gRPC by rewriting a header.
    let mut plain = RequestContext::new("127.0.0.1".into(), "POST".into(), "/".into());
    plain
        .headers
        .insert("content-type".into(), "application/grpc".into());
    for ctx in [None, Some(&plain)] {
        let http = request_buffer_capacity_backend_response_for_test(ctx, None);
        assert_eq!(http.status_code, REQUEST_BUFFER_OVERLOAD_STATUS);
        assert_eq!(http.body_bytes(), REQUEST_BUFFER_OVERLOAD_BODY.as_bytes());
        assert!(http.headers.is_empty());
        assert_eq!(http.error_class, Some(REQUEST_BUFFER_OVERLOAD_ERROR_CLASS));
    }
}

#[test]
fn backend_seam_refusal_frames_passthrough_grpc_web_resource_exhausted() {
    use base64::Engine;

    for text_mode in [false, true] {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/rpc".into());
        set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Plain);
        set_request_grpc_web_upload_for_test(&mut ctx, text_mode);
        let response = request_buffer_capacity_backend_response_for_test(Some(&ctx), None);
        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.error_class,
            Some(REQUEST_BUFFER_OVERLOAD_ERROR_CLASS)
        );
        assert!(!response.connection_error && !response.request_on_wire);
        assert!(!response.headers.contains_key("grpc-status"));
        let body = if text_mode {
            base64::engine::general_purpose::STANDARD
                .decode(response.body_bytes())
                .unwrap()
        } else {
            response.body_bytes().to_vec()
        };
        assert_eq!(body[0], 0x80, "exactly one terminal frame");
        assert_eq!(
            u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize,
            body.len() - 5
        );
        let trailers = std::str::from_utf8(&body[5..]).unwrap();
        assert!(trailers.contains("grpc-status: 8\r\n"));
        assert!(trailers.contains("grpc-message: Request buffering capacity exceeded\r\n"));
    }
}

#[test]
fn exhaustion_is_backend_health_neutral_and_distinct_from_oversize() {
    assert_eq!(
        REQUEST_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::GatewayBufferCapacity
    );

    // Neutral: no circuit-breaker trip, no passive-health ding, no
    // adaptive-concurrency shrink for a backend that was never contacted.
    assert!(error_class_is_health_neutral_for_test(
        REQUEST_BUFFER_OVERLOAD_ERROR_CLASS
    ));
    assert!(!error_class_is_backend_failure_for_test(
        REQUEST_BUFFER_OVERLOAD_ERROR_CLASS
    ));

    // A genuine per-request overflow stays its own condition, so the two remain
    // distinguishable in telemetry.
    assert_ne!(
        REQUEST_BUFFER_OVERLOAD_ERROR_CLASS,
        ErrorClass::RequestBodyTooLarge
    );
}

// ---------------------------------------------------------------------------
// 5. Defaults.
// ---------------------------------------------------------------------------

#[test]
fn defaults_are_finite_and_the_total_exceeds_one_request() {
    assert_eq!(DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES, 10 * 1024 * 1024);
    assert_eq!(DEFAULT_REQUEST_BUFFER_TOTAL_BYTES, 256 * 1024 * 1024);
    const {
        assert!(
            DEFAULT_REQUEST_BUFFER_TOTAL_BYTES > DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES,
            "the aggregate default must admit more than a single fallback-sized upload"
        )
    };
}

// ---------------------------------------------------------------------------
// 6. Residency: the charge outlives the collector (issue #4231).
// ---------------------------------------------------------------------------

#[test]
fn sequential_in_dispatch_collections_cannot_exceed_the_aggregate_while_the_first_body_is_alive() {
    // The production in-dispatch collectors publish through
    // `RequestBufferPermit::into_charged_bytes` so the charge travels with the
    // `Bytes` that stay resident for the backend write and retry replay. Two
    // sequential collections against a one-block budget: the second is refused
    // while the first published body is still alive, and admitted after it drops.
    let budget = probe(1);
    let first_body = budget
        .try_reserve(UNIT)
        .expect("first collection admits")
        .into_charged_bytes(vec![0u8; UNIT]);
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "a second in-dispatch collection must be refused while the first body's \
         bytes are still resident"
    );

    drop(first_body);
    assert!(
        budget.try_reserve(UNIT).is_some(),
        "releasing the resident body must return capacity to the next collection"
    );
}

#[test]
fn a_cloned_dispatch_body_keeps_the_charge_until_the_last_handle_drops() {
    // Retry replay and protocol-NACK replay are refcount bumps on the same
    // owner. They must not mint a second permit, and dropping the original
    // handle must not release while a clone is still resident.
    let budget = probe(1);
    let first = budget
        .try_reserve(UNIT)
        .expect("admits")
        .into_charged_bytes(vec![0u8; UNIT]);
    let retry_replay = first.clone();
    assert_eq!(budget.available_bytes(), 0);

    drop(first);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "retry replay must keep the charge after the dispatch-arm handle drops"
    );

    drop(retry_replay);
    assert!(
        budget.try_reserve(UNIT).is_some(),
        "the charge returns when the last clone of the resident body drops"
    );
}

#[test]
fn a_pre_auth_permit_stays_charged_through_dispatch_publication_and_retry_clone() {
    // Pre-auth collect stores the permit on BufferedClientRequestBody for as
    // long as that struct owns the Vec. Dispatch then extracts the Vec and
    // MUST publish through into_charged_bytes — the same seam the in-dispatch
    // collectors use — or the charge drops at extraction while the bytes go
    // on to send and retry replay (issue #4231).
    let budget = probe(1);
    // Phase 1: the pre-auth struct still owns the Vec (permit is a live local).
    let permit = budget.try_reserve(UNIT).expect("pre-auth collect admits");
    let body = vec![0u8; UNIT];
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "capacity must stay charged while the pre-auth body still owns the Vec"
    );

    // Phase 2: dispatch conversion, including a retry clone.
    let published = permit.into_charged_bytes(body);
    let retry_replay = published.clone();
    assert_eq!(budget.available_bytes(), 0);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "a pre-auth body published onto Bytes must keep the charge while those \
         bytes (and their retry clone) are resident"
    );

    drop(published);
    assert!(
        budget.try_reserve(UNIT).is_none(),
        "retry replay must keep the pre-auth charge after the dispatch handle drops"
    );

    drop(retry_replay);
    assert!(
        budget.try_reserve(UNIT).is_some(),
        "the pre-auth charge returns when the last clone of the resident body drops"
    );
}

#[test]
fn publishing_an_empty_body_releases_the_charge() {
    let budget = probe(1);
    let empty = budget
        .try_reserve(UNIT)
        .expect("admits")
        .into_charged_bytes(Vec::new());
    assert!(empty.is_empty());
    assert_eq!(
        budget.available_bytes(),
        UNIT,
        "nothing is retained, so the pre-collect ceiling must not stay charged"
    );
}

#[test]
fn publishing_a_body_smaller_than_the_ceiling_releases_surplus() {
    // The permit is reserved at the collect ceiling. Holding that ceiling for
    // the whole backend/retry lifetime of a much smaller body would over-hold
    // the aggregate. Publication narrows to the surviving allocation.
    let budget = probe(4);
    let body = budget
        .try_reserve(4 * UNIT)
        .expect("admits the ceiling")
        .into_charged_bytes(vec![0u8; UNIT]);
    assert_eq!(
        budget.available_bytes(),
        3 * UNIT,
        "residency must charge the surviving allocation, not the pre-collect ceiling"
    );
    assert!(
        budget.try_reserve(3 * UNIT).is_some(),
        "surplus from a small published body must be available to other collections"
    );
    drop(body);
}

#[test]
fn in_dispatch_collectors_publish_the_permit_onto_the_resident_bytes() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        !proxy.contains("let _request_buffer_permit"),
        "in-dispatch collectors must not hold the permit as a match-arm local \
         that drops before the collected bytes stop being resident (issue #4231)"
    );

    let reqwest = proxy
        .split("async fn proxy_to_backend(")
        .nth(1)
        .expect("reqwest dispatcher")
        .split("\nfn is_streaming_content_type(")
        .next()
        .expect("bounded reqwest dispatcher");
    assert!(
        reqwest.contains("request_buffer_permit.into_charged_bytes(body_bytes)"),
        "the reqwest in-dispatch collector must publish the permit onto the \
         Bytes that stay resident for send and retry replay"
    );

    let reqwest_buffered = reqwest
        .split("ClientRequestBody::Buffered(buffered) => {")
        .nth(1)
        .expect("reqwest buffered arm")
        .split("ClientRequestBody::Streaming(original_req) if stream_request_body")
        .next()
        .expect("bounded reqwest buffered arm");
    assert!(
        reqwest_buffered.contains("buffered.budget"),
        "the reqwest Buffered arm must carry the pre-auth permit to publication"
    );
    assert!(
        reqwest_buffered.contains("permit.into_charged_bytes(body_bytes)"),
        "the reqwest Buffered arm must publish the pre-auth permit onto the \
         Bytes that stay resident for send and retry replay"
    );
    assert!(
        reqwest_buffered.contains("None => Bytes::from(body_bytes)"),
        "a plugin-staged Buffered body with no permit must publish plain Bytes"
    );

    let h3 = proxy
        .split("async fn proxy_to_backend_http3(")
        .nth(1)
        .expect("h3 dispatcher")
        .split("\nfn h3_streaming_backend_response(")
        .next()
        .expect("bounded h3 dispatcher");
    assert!(
        h3.contains("permit.into_charged_bytes(request_body)"),
        "the H3 in-dispatch collector must publish the permit onto the Bytes \
         that stay resident for send and retry replay"
    );
    assert!(
        h3.contains("(body, Some(request_buffer_permit))"),
        "the H3 collect match must hoist the permit out of the Streaming arm \
         so plugin transforms and the backend send stay charged"
    );
    assert!(
        h3.contains("(buffered.body, buffered.budget)"),
        "the H3 Buffered arm must return the pre-auth permit, not discard it"
    );
    assert!(
        !h3.contains("(buffered.body, None)"),
        "the H3 Buffered arm must not drop the pre-auth permit at Vec extraction"
    );
}
