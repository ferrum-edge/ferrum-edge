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

use bytes::Bytes;
use ferrum_edge::_test_support::{
    ChargedRequestCollectOutcomeForTest as Outcome, DEFAULT_BUFFERED_REQUEST_FALLBACK_BYTES,
    DEFAULT_REQUEST_BUFFER_TOTAL_BYTES, REQUEST_BUFFER_OVERLOAD_BODY,
    REQUEST_BUFFER_OVERLOAD_ERROR_CLASS, REQUEST_BUFFER_OVERLOAD_GRPC_STATUS,
    REQUEST_BUFFER_OVERLOAD_STATUS, RESPONSE_BUFFER_RESERVATION_UNIT_BYTES as UNIT,
    RequestBufferBudgetProbe, ResponseBufferRetainRejection,
    buffered_request_body_ceiling_for_test, collect_charged_request_body_for_test,
    effective_request_body_limit_for_test, error_class_is_backend_failure_for_test,
    error_class_is_health_neutral_for_test, normalize_reject_response,
    request_buffer_capacity_backend_response_for_test,
    request_buffer_capacity_reject_headers_for_test, set_request_grpc_web_upload_for_test,
    set_request_http_flavor_for_test,
};
use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::plugins::RequestContext;
use ferrum_edge::proxy::body::ProxyBodyError;
use ferrum_edge::retry::ErrorClass;
use http_body_util::StreamBody;
use hyper::body::Frame;

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
fn backend_seam_refusal_frames_translated_grpc_web_too() {
    // The H1/H2 response pipeline marks this refusal as the gateway capacity
    // terminal, which skips the `grpc_web` translation, so a translated client's
    // terminal is framed here rather than left native with a `grpc-status`
    // header (the Unix-socket h2c translated gRPC-Web functional test).
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/rpc".into());
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Plain);
    set_request_grpc_web_upload_for_test(&mut ctx, false);
    ctx.metadata
        .insert("grpc_web_mode".to_string(), "binary".to_string());
    ctx.metadata.insert(
        "grpc_web_original_ct".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let response = request_buffer_capacity_backend_response_for_test(Some(&ctx), None);
    assert_eq!(response.status_code, 200);
    assert!(!response.headers.contains_key("grpc-status"));
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/grpc-web+proto")
    );
    let body = response.body_bytes().to_vec();
    assert_eq!(body[0], 0x80, "exactly one terminal frame");
    let trailers = std::str::from_utf8(&body[5..]).unwrap();
    assert!(trailers.contains("grpc-status: 8\r\n"));
    assert!(trailers.contains("grpc-message: Request buffering capacity exceeded\r\n"));
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
        .into_charged_bytes(vec![0u8; UNIT])
        .expect("the charge covers the body");
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
        .into_charged_bytes(vec![0u8; UNIT])
        .expect("the charge covers the body");
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
    let published = permit.into_charged_bytes(body).expect("covered");
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
        .into_charged_bytes(Vec::new())
        .expect("the charge covers the body");
    assert!(empty.is_empty());
    assert_eq!(
        budget.available_bytes(),
        UNIT,
        "nothing is retained, so the pre-collect ceiling must not stay charged"
    );
}

#[test]
fn publishing_a_body_smaller_than_the_ceiling_releases_surplus() {
    // A charge larger than the surviving allocation (here taken up front)
    // must not be held for the whole backend/retry lifetime of a much smaller
    // body. Publication narrows to the surviving allocation.
    let budget = probe(4);
    let body = budget
        .try_reserve(4 * UNIT)
        .expect("admits the ceiling")
        .into_charged_bytes(vec![0u8; UNIT])
        .expect("the charge covers the body");
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
        reqwest_buffered.contains("None => Some(Bytes::from(body_bytes))"),
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

#[test]
fn publishing_a_transform_grown_body_tops_the_charge_up_when_the_budget_has_room() {
    // A request-body plugin can replace the collected body with a larger one.
    // Publication charges the larger allocation when the budget has room.
    let budget = probe(4);
    let body = budget
        .try_reserve(UNIT)
        .expect("admits the collected body")
        .into_charged_bytes(vec![0u8; 3 * UNIT])
        .expect("the budget has room for the larger body");
    assert_eq!(body.len(), 3 * UNIT);
    assert_eq!(budget.available_bytes(), UNIT);
    drop(body);
    assert_eq!(budget.available_bytes(), 4 * UNIT);
}

#[test]
fn publishing_a_transform_grown_body_the_budget_cannot_cover_is_refused() {
    // Without room, publication fails closed: the larger body is not retained
    // under a charge that does not cover it, and the collected body's charge
    // is released with it. The caller answers the 503 capacity terminal.
    let budget = probe(2);
    let other = budget.try_reserve(UNIT).expect("another upload");
    let published = budget
        .try_reserve(UNIT)
        .expect("admits the collected body")
        .into_charged_bytes(vec![0u8; 3 * UNIT]);
    assert!(
        published.is_none(),
        "a body the budget cannot cover must not be published"
    );
    assert_eq!(
        budget.available_bytes(),
        UNIT,
        "the refused publication must release the collected body's charge"
    );
    drop(other);
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

#[test]
fn every_request_body_publication_fails_closed() {
    // Each production publication of a charged request body handles the
    // fail-closed refusal with the capacity terminal instead of retaining a
    // transform-grown body the budget does not cover.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert_eq!(
        proxy.matches("permit.into_charged_bytes(").count(),
        7,
        "a new request-body publication must be added to this guard"
    );
    for publication in proxy.split("permit.into_charged_bytes(").skip(1) {
        let handling: String = publication.chars().take(1_200).collect();
        assert!(
            handling.contains("request_buffer_capacity_backend_response(")
                || handling.contains("build_request_buffer_capacity_response("),
            "a request-body publication must answer the capacity terminal when the budget \
             cannot cover the body"
        );
    }
    let budget = include_str!("../../../src/proxy/response_buffer_budget.rs");
    let publish = budget
        .split("fn into_charged_bytes(mut self, data: Vec<u8>) -> Option<Bytes> {")
        .nth(1)
        .expect("fail-closed request publication")
        .split("\n    }\n")
        .next()
        .expect("bounded request publication");
    assert!(publish.contains("if !self.grow_to(data.capacity()) {"));
}

// ---------------------------------------------------------------------------
// 7. The charge tracks retained bytes, not the ceiling.
// ---------------------------------------------------------------------------
//
// Audit finding (request-buffer budget): every buffered collect used to
// reserve its whole retained ceiling before the first byte, including the
// collect that runs before authentication. An anonymous client could open as
// many stalled uploads as the budget holds ceilings, send no body, and refuse
// every other principal's buffered upload with `503` for a whole read
// timeout. The charge now grows with the bytes the collect retains.

/// Two fallback ceilings of budget, the shape the audit record uses.
fn two_ceiling_budget() -> RequestBufferBudgetProbe {
    RequestBufferBudgetProbe::new(2 * UNIT, 4 * UNIT)
}

type FrameResult = Result<Frame<Bytes>, ProxyBodyError>;
type CompleteBody = StreamBody<futures::stream::Iter<std::vec::IntoIter<FrameResult>>>;

fn data_frame(bytes: Vec<u8>) -> FrameResult {
    Ok(Frame::data(Bytes::from(bytes)))
}

/// A client body whose every frame has already arrived.
fn complete_body(frames: Vec<FrameResult>) -> CompleteBody {
    StreamBody::new(futures::stream::iter(frames))
}

#[test]
fn zero_byte_collects_do_not_exhaust_an_isolated_budget() {
    let budget = two_ceiling_budget();
    let total = budget.available_bytes();
    // Before the fix, two of these held the whole budget and the third was
    // refused. Many of them now hold nothing at all.
    let stalled: Vec<_> = (0..16).map(|_| budget.collector(0)).collect();
    assert!(stalled.iter().all(|c| c.reserved_bytes() == 0));
    assert_eq!(
        budget.available_bytes(),
        total,
        "a collect that has retained nothing must hold none of the shared budget"
    );

    // Two complete ceiling-sized uploads still collect beside them.
    let mut first = budget.collector(0);
    assert_eq!(first.append(&vec![1u8; 2 * UNIT]), Ok(()));
    let mut second = budget.collector(0);
    assert_eq!(second.append(&vec![2u8; 2 * UNIT]), Ok(()));
    assert_eq!(budget.available_bytes(), 0);

    // Only retained bytes exhaust it, and a growth it cannot cover is the
    // capacity refusal (503), never the per-request 413.
    let mut third = budget.collector(0);
    assert_eq!(
        third.append(b"x"),
        Err(ResponseBufferRetainRejection::BudgetExhausted)
    );
    drop(third);
    drop((first, second, stalled));
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn the_charge_covers_the_retained_capacity_and_grows_geometrically() {
    let budget = probe(8);
    let total = budget.available_bytes();
    let ceiling = 4 * UNIT;
    let mut collector = budget.collector(ceiling);
    let mut previous_reserved = 0;
    let mut growths = 0;
    for _ in 0..(3 * UNIT + 5) {
        assert_eq!(collector.append(&[9u8]), Ok(()));
        let reserved = collector.reserved_bytes();
        assert!(reserved >= collector.len(), "retained bytes are charged");
        assert!(
            reserved <= 2 * collector.len(),
            "the charge must track retained capacity, not the ceiling or a block"
        );
        if reserved != previous_reserved {
            growths += 1;
            previous_reserved = reserved;
        }
    }
    // Geometric growth: about log2(n) charges for n one-byte chunks, never one
    // per chunk.
    assert!(
        growths <= 20,
        "one-byte chunks must not take a semaphore operation per chunk: {growths} growths"
    );
    let (body, permit) = collector.finish();
    assert_eq!(body.len(), 3 * UNIT + 5);
    assert!(permit.reserved_bytes() >= body.capacity());
    assert_eq!(budget.available_bytes(), total - permit.reserved_bytes());
    drop((body, permit));
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn stalled_h1_h2_collects_hold_no_budget_and_complete_uploads_still_succeed() {
    let budget = two_ceiling_budget();
    let total = budget.available_bytes();

    // Uploads whose headers arrived but whose body never does, held open
    // inside the PRODUCTION H1/H2 collector.
    let mut stalled = Vec::new();
    for _ in 0..8 {
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameResult>(1);
        let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        let mut collect = Box::pin(collect_charged_request_body_for_test(body, &budget, 0));
        assert!(futures::poll!(collect.as_mut()).is_pending());
        stalled.push((tx, collect));
    }
    assert_eq!(
        budget.available_bytes(),
        total,
        "stalled buffered uploads must not hold the shared budget"
    );

    // Another principal's complete, ceiling-sized upload is admitted.
    let victim = complete_body(vec![data_frame(vec![3u8; 2 * UNIT])]);
    let outcome = collect_charged_request_body_for_test(victim, &budget, 0).await;
    let Outcome::Collected { body, permit, .. } = outcome else {
        panic!("a complete upload must be collected while stalled uploads are open");
    };
    assert_eq!(body.len(), 2 * UNIT);
    assert_eq!(permit.reserved_bytes(), 2 * UNIT);
    let published = permit.into_charged_bytes(body).expect("covered");
    assert_eq!(budget.available_bytes(), total - 2 * UNIT);
    drop(published);

    // A stalled upload is still a live collect: its body completes it.
    let (tx, collect) = stalled.pop().expect("a stalled collect");
    tx.send(data_frame(b"late body".to_vec()))
        .await
        .expect("collect still reading");
    drop(tx);
    let Outcome::Collected { body, permit, .. } = collect.await else {
        panic!("a stalled upload that finishes must be collected");
    };
    assert_eq!(body, b"late body");
    assert_eq!(permit.reserved_bytes(), b"late body".len());
    drop((body, permit));

    drop(stalled);
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn h1_h2_collect_terminals_stay_distinct_and_release_their_charge() {
    let budget = RequestBufferBudgetProbe::new(2 * UNIT, 2 * UNIT);
    let mut holder = budget.collector(0);
    assert_eq!(holder.append(&vec![0u8; UNIT]), Ok(()));
    assert_eq!(budget.available_bytes(), UNIT);

    // Within the ceiling, but the budget cannot cover it: 503.
    let body = complete_body(vec![
        data_frame(b"head".to_vec()),
        data_frame(vec![1u8; 2 * UNIT - 4]),
    ]);
    let outcome = collect_charged_request_body_for_test(body, &budget, 0).await;
    assert!(matches!(outcome, Outcome::BufferCapacityExceeded));
    assert_eq!(
        budget.available_bytes(),
        UNIT,
        "a refused collect must release what it had charged"
    );

    // Over the ceiling: 413, before any charge for the oversized chunk.
    let body = complete_body(vec![data_frame(vec![1u8; 2 * UNIT + 1])]);
    let outcome = collect_charged_request_body_for_test(body, &budget, 0).await;
    assert!(matches!(outcome, Outcome::TooLarge));

    // A client failure mid-upload: 499.
    let body = complete_body(vec![data_frame(b"partial".to_vec()), Err("reset".into())]);
    let outcome = collect_charged_request_body_for_test(body, &budget, 0).await;
    assert!(matches!(outcome, Outcome::ClientDisconnected));
    assert_eq!(budget.available_bytes(), UNIT);

    // Trailers survive the collect exactly as `Collected` kept them.
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("x-checksum", hyper::header::HeaderValue::from_static("abc"));
    let body = complete_body(vec![
        data_frame(b"payload".to_vec()),
        Ok(Frame::trailers(trailers)),
    ]);
    let outcome = collect_charged_request_body_for_test(body, &budget, 0).await;
    let Outcome::Collected {
        body,
        trailers,
        permit,
    } = outcome
    else {
        panic!("a body with trailers must be collected");
    };
    assert_eq!(body, b"payload");
    assert_eq!(
        trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-checksum"))
            .map(|value| value.as_bytes()),
        Some(&b"abc"[..])
    );
    drop((body, permit, holder));
    assert_eq!(budget.available_bytes(), 2 * UNIT);
}

// ---------------------------------------------------------------------------
// 8. A normalized (decompressed) body is charged before later phases keep it.
// ---------------------------------------------------------------------------

/// A `compression` instance that decodes request bodies before `before_proxy`.
fn decompressing_plugins() -> Vec<std::sync::Arc<dyn ferrum_edge::plugins::Plugin>> {
    let config = serde_json::json!({
        "decompress_request": true,
        "max_decompressed_request_size": 1_048_576,
    });
    let plugin = ferrum_edge::plugins::compression::CompressionPlugin::new(&config)
        .expect("compression config");
    vec![std::sync::Arc::new(plugin)]
}

/// About three blocks of plaintext that gzip shrinks several-fold but well
/// inside the decoder's amplification bound.
fn compressible_plaintext() -> Vec<u8> {
    (0..20_000u32)
        .flat_map(|line| format!("{line:08}\n").into_bytes())
        .collect()
}

fn gzip(plaintext: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plaintext).expect("gzip");
    encoder.finish().expect("gzip")
}

/// A buffered gzip upload as the pre-`before_proxy` phase receives it.
fn gzip_upload(compressed: &[u8]) -> (RequestContext, std::collections::HashMap<String, String>) {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/upload".into());
    ctx.request_body_bytes = Some(Bytes::copy_from_slice(compressed));
    let mut headers = std::collections::HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    (ctx, headers)
}

#[tokio::test]
async fn a_decompressed_body_is_charged_before_any_later_phase_keeps_it() {
    use ferrum_edge::_test_support::{
        ChargedNormalizationOutcomeForTest,
        apply_buffered_request_body_normalization_with_charge_for_test,
    };
    // A small compressed upload expands to several blocks of plaintext. Every
    // later phase (a `before_proxy` hook that pauses, final-body hooks, the
    // backend write) holds that plaintext, so it must be charged as soon as
    // normalization returns, not only when the body is published.
    let plaintext = compressible_plaintext();
    let compressed = gzip(&plaintext);
    let budget = probe(8);
    let total = budget.available_bytes();
    let mut charge = budget
        .try_reserve(compressed.len())
        .expect("the collected compressed body is charged");
    let collected_charge = charge.reserved_bytes();
    assert!(collected_charge < plaintext.len());

    let plugins = decompressing_plugins();
    let (mut ctx, mut headers) = gzip_upload(&compressed);
    let mut body = compressed;
    let outcome = apply_buffered_request_body_normalization_with_charge_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
        &mut charge,
    )
    .await;
    assert_eq!(outcome, ChargedNormalizationOutcomeForTest::Continue);
    assert_eq!(body, plaintext);
    // While any later phase awaits, the enlarged body is fully charged.
    assert!(
        charge.reserved_bytes() >= body.capacity(),
        "the decoded body must be charged before a later phase keeps it"
    );
    assert!(charge.reserved_bytes() > collected_charge);
    assert_eq!(budget.available_bytes(), total - charge.reserved_bytes());

    // The admissible decoded upload is published for dispatch under that charge.
    let published = charge.into_charged_bytes(body).expect("covered");
    assert_eq!(published.len(), plaintext.len());
    drop(published);
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn a_decompressed_body_the_budget_cannot_cover_is_refused_and_dropped() {
    use ferrum_edge::_test_support::{
        ChargedNormalizationOutcomeForTest,
        apply_buffered_request_body_normalization_with_charge_for_test,
    };
    let plaintext = compressible_plaintext();
    let compressed = gzip(&plaintext);
    let budget = probe(8);
    let total = budget.available_bytes();
    let mut charge = budget
        .try_reserve(compressed.len())
        .expect("the collected compressed body is charged");
    let collected_charge = charge.reserved_bytes();
    // Every other block is held by other uploads.
    let other = budget
        .try_reserve(budget.available_bytes())
        .expect("other uploads");
    assert_eq!(budget.available_bytes(), 0);

    let plugins = decompressing_plugins();
    let (mut ctx, mut headers) = gzip_upload(&compressed);
    let mut body = compressed;
    let outcome = apply_buffered_request_body_normalization_with_charge_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
        &mut charge,
    )
    .await;
    assert_eq!(
        outcome,
        ChargedNormalizationOutcomeForTest::BufferCapacityExceeded,
        "a decoded body the budget cannot cover must be refused, not kept uncharged"
    );
    assert!(
        body.is_empty(),
        "the uncovered decoded body must be dropped"
    );
    assert_eq!(body.capacity(), 0);
    drop(charge);
    assert_eq!(budget.available_bytes(), collected_charge);
    drop(other);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn every_body_replacement_is_charged_before_a_later_phase_keeps_it() {
    // Normalizers and request-body transforms can replace the collected body
    // with a larger one. Each replacement is charged before it is installed
    // and before the next await, on both protocol paths, and a refusal leaves
    // nothing of the body behind while the refusal is written.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let normalization = proxy
        .split("async fn apply_buffered_request_body_normalization_before_before_proxy(")
        .nth(1)
        .expect("normalization phase")
        .split("\n}\n")
        .next()
        .expect("bounded normalization phase");
    let normalized = normalization
        .find("let result = result.into_plugin_result(ctx);")
        .expect("normalizer call");
    let covered = normalization
        .find(".is_none_or(|charge| charge.cover(body.capacity()));")
        .expect("normalized body is charged");
    let decode_released = normalization
        .find("drop(decode_charge);")
        .expect("decode charge released");
    assert!(normalized < covered && covered < decode_released);

    let transforms = proxy
        .split("pub(crate) async fn apply_request_body_plugins_with_context(")
        .nth(1)
        .expect("transform chain")
        .split("\n}\n")
        .next()
        .expect("bounded transform chain");
    let covered = transforms
        .find("if !charge_covers(charge.as_deref_mut(), transformed.capacity()) {")
        .expect("each replacement is charged");
    let installed = transforms
        .find("body = transformed;")
        .expect("replacement installed");
    assert!(
        covered < installed,
        "a replacement is charged before it is installed"
    );

    // Every charged body hands its charge to the chain and the normalizer.
    let count = |source: &str, needle: &str| source.matches(needle).count();
    assert_eq!(count(proxy, "buffered.budget.as_mut(),\n"), 5);
    assert_eq!(count(proxy, "Some(&mut request_buffer_permit),\n"), 1);
    assert_eq!(count(proxy, "request_buffer_permit.as_mut(),\n"), 1);
    assert_eq!(count(proxy, "grpc_body_charge.as_mut(),\n"), 1);
    assert_eq!(count(server, "retained_request_charge.as_mut(),\n"), 4);
    assert_eq!(count(bridge, "prebuffered_body_charge.as_mut(),\n"), 1);
    // A refusal that awaits a writer first drops the charge it still owns: the
    // three H3 transforms and the H3 normalization, beside the two existing
    // rejection paths that already released it.
    assert_eq!(count(server, "drop(retained_request_charge.take());"), 6);
    assert_eq!(count(bridge, "drop(prebuffered_body_charge.take());"), 1);
}

// ---------------------------------------------------------------------------
// 9. Each request-body transform replacement is charged before the next runs.
// ---------------------------------------------------------------------------

/// Replaces the body with `size` bytes.
struct ResizeBody {
    size: usize,
}

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for ResizeBody {
    fn name(&self) -> &str {
        "resize_body"
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        Some(vec![b'r'; self.size])
    }
}

/// Holds the transform chain until released, like a slow later hook.
struct PausingTransform {
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl ferrum_edge::plugins::Plugin for PausingTransform {
    fn name(&self) -> &str {
        "pausing_transform"
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    async fn transform_request_body(
        &self,
        _body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.release.notified().await;
        None
    }
}

#[tokio::test]
async fn a_growing_transform_is_charged_while_a_later_transform_is_paused() {
    use ferrum_edge::_test_support::apply_request_body_plugins_with_charge_for_test;
    let budget = probe(8);
    let total = budget.available_bytes();
    let mut charge = budget.try_reserve(UNIT).expect("collected body charged");
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<std::sync::Arc<dyn ferrum_edge::plugins::Plugin>> = vec![
        std::sync::Arc::new(ResizeBody { size: 3 * UNIT }),
        std::sync::Arc::new(PausingTransform {
            release: std::sync::Arc::clone(&release),
        }),
    ];
    let headers = std::collections::HashMap::new();
    let mut chain = Box::pin(apply_request_body_plugins_with_charge_for_test(
        &plugins,
        &headers,
        vec![0u8; UNIT],
        &mut charge,
    ));
    assert!(futures::poll!(chain.as_mut()).is_pending());
    assert_eq!(
        budget.available_bytes(),
        total - 3 * UNIT,
        "the grown intermediate body must be charged while a later transform awaits"
    );
    release.notify_one();
    let body = chain.await.expect("the budget covers the grown body");
    assert_eq!(body.len(), 3 * UNIT);
    assert_eq!(charge.reserved_bytes(), 3 * UNIT);
    drop((body, charge));
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn a_grow_then_shrink_chain_publishes_only_its_final_body() {
    use ferrum_edge::_test_support::apply_request_body_plugins_with_charge_for_test;
    let budget = probe(8);
    let total = budget.available_bytes();
    let mut charge = budget.try_reserve(UNIT).expect("collected body charged");
    let plugins: Vec<std::sync::Arc<dyn ferrum_edge::plugins::Plugin>> = vec![
        std::sync::Arc::new(ResizeBody { size: 3 * UNIT }),
        std::sync::Arc::new(ResizeBody { size: 10 }),
    ];
    let headers = std::collections::HashMap::new();
    let body = apply_request_body_plugins_with_charge_for_test(
        &plugins,
        &headers,
        vec![0u8; UNIT],
        &mut charge,
    )
    .await
    .expect("the budget covers the peak");
    assert_eq!(body.len(), 10);
    // The charge covered the peak; publication narrows it to the final body.
    assert_eq!(charge.reserved_bytes(), 3 * UNIT);
    let published = charge.into_charged_bytes(body).expect("covered");
    assert_eq!(budget.available_bytes(), total - 10);
    drop(published);
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn a_refused_transform_releases_body_and_charge_before_the_refusal_is_written() {
    use ferrum_edge::_test_support::apply_request_body_plugins_with_charge_for_test;
    let budget = probe(4);
    let mut charge = budget.try_reserve(UNIT).expect("collected body charged");
    let other = budget.try_reserve(2 * UNIT).expect("another upload");
    let plugins: Vec<std::sync::Arc<dyn ferrum_edge::plugins::Plugin>> =
        vec![std::sync::Arc::new(ResizeBody { size: 3 * UNIT })];
    let headers = std::collections::HashMap::new();
    let refused = apply_request_body_plugins_with_charge_for_test(
        &plugins,
        &headers,
        vec![0u8; UNIT],
        &mut charge,
    )
    .await;
    assert!(
        refused.is_none(),
        "an uncovered replacement must be refused"
    );
    // The caller still owns the emptied permit while it awaits the refusal
    // writer and its hooks; nothing of the refused body stays charged.
    assert_eq!(charge.reserved_bytes(), 0);
    assert_eq!(
        budget.available_bytes(),
        2 * UNIT,
        "the refused body's charge is released before the refusal is written"
    );
    let writer = tokio::task::yield_now();
    writer.await;
    assert_eq!(budget.available_bytes(), 2 * UNIT);
    drop((charge, other));
    assert_eq!(budget.available_bytes(), 4 * UNIT);
}

#[test]
fn a_refused_pre_dispatch_transform_commits_through_the_reject_pipeline() {
    // After `before_proxy`, a capacity refusal of a transformed body must run
    // the reject-path hooks and log the rejection like the adjacent final-body
    // rejection, after first dropping the refused body.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let refusal = proxy
        .split("// Circuit breaker check")
        .nth(1)
        .expect("pre-dispatch preparation")
        .split("let Ok(transformed) = transformed else {")
        .nth(1)
        .expect("pre-dispatch transform refusal")
        .split("let mut final_body_result = run_final_request_body_hooks(")
        .next()
        .expect("bounded transform refusal");
    for call in [
        "drop(buffered);",
        "boxed_finalize_reject_response(",
        "request_buffer_capacity_reject_headers(is_grpc_request),",
        "boxed_build_grpc_web_reject_response(",
        "boxed_log_rejected_request_with_path(",
        "ctx.terminal_record.mark_counted();",
    ] {
        assert!(refusal.contains(call), "the refusal must use `{call}`");
    }
    let dropped = refusal.find("drop(buffered);").expect("body dropped");
    let first_await = refusal.find(".await").expect("reject pipeline awaits");
    assert!(dropped < first_await);
}

// ---------------------------------------------------------------------------
// 10. Charges are byte-granular.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn many_one_byte_uploads_hold_only_their_bytes_and_a_complete_upload_still_fits() {
    // A block-granular charge rounded every one-byte stalled upload up to a
    // whole 64 KiB block, so a few thousand one-byte streams held the whole
    // budget. Charges now track the retained capacity exactly.
    let budget = two_ceiling_budget();
    let total = budget.available_bytes();
    let mut trickling: Vec<_> = (0..4096).map(|_| budget.collector(0)).collect();
    for collector in &mut trickling {
        assert_eq!(collector.append(b"x"), Ok(()));
    }
    assert_eq!(budget.available_bytes(), total - 4096);

    // The PRODUCTION H1/H2 collector holds one-byte uploads open the same way.
    let mut stalled = Vec::new();
    for _ in 0..64 {
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameResult>(1);
        tx.send(data_frame(b"x".to_vec()))
            .await
            .expect("first byte");
        let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        let mut collect = Box::pin(collect_charged_request_body_for_test(body, &budget, 0));
        assert!(futures::poll!(collect.as_mut()).is_pending());
        stalled.push((tx, collect));
    }
    assert_eq!(budget.available_bytes(), total - 4096 - 64);

    // A complete, ceiling-sized upload from someone else is admitted.
    let victim = complete_body(vec![data_frame(vec![3u8; 2 * UNIT - 8192])]);
    let outcome = collect_charged_request_body_for_test(victim, &budget, 0).await;
    let Outcome::Collected { body, permit, .. } = outcome else {
        panic!("one-byte uploads must not refuse a complete upload");
    };
    assert_eq!(permit.reserved_bytes(), body.capacity());
    drop((body, permit));

    // Genuinely retained bytes still exhaust the budget.
    let mut filler = budget.collector(0);
    assert_eq!(filler.append(&vec![1u8; 2 * UNIT]), Ok(()));
    let mut over = budget.collector(0);
    assert_eq!(
        over.append(&vec![1u8; 2 * UNIT]),
        Err(ResponseBufferRetainRejection::BudgetExhausted),
        "retained bytes must still be bounded by the budget"
    );
    drop((over, filler, stalled, trickling));
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn a_decoded_body_stays_charged_until_its_handed_off_charge_is_released() {
    use ferrum_edge::_test_support::{
        ResponseBufferBudgetProbe, decode_and_hand_off_charge_for_test,
    };
    // The decode charge travels back from the blocking decoder with the
    // plaintext and through the replacement scope, so the completed output is
    // never held uncharged before the buffered-request charge covers it.
    let probe = ResponseBufferBudgetProbe::new(UNIT, 16 * UNIT);
    let total = probe.available_bytes();
    let plaintext = compressible_plaintext();
    let compressed = gzip(&plaintext);
    let handoff =
        decode_and_hand_off_charge_for_test(&probe, &["gzip".to_string()], &compressed, 1_048_576)
            .await
            .expect("decoded");
    assert!(
        total - handoff.available_after_decode >= handoff.plaintext_capacity,
        "the decoded plaintext must come back charged"
    );
    assert_eq!(
        handoff.available_after_handoff, handoff.available_after_decode,
        "the handed-off decode charge must still cover the unconsumed output"
    );
    assert_eq!(handoff.available_after_release, total);
}

// ---------------------------------------------------------------------------
// 11. Permit-count bound, staged plaintext, and native gRPC.
// ---------------------------------------------------------------------------

#[cfg(target_pointer_width = "64")]
#[test]
fn a_single_request_charge_is_capped_at_one_permit_without_wrapping() {
    // One semaphore permit counts at most `u32::MAX` bytes. A larger charge is
    // refused instead of wrapping the permit count (which would leak budget on
    // release), and the retained ceiling is capped at that bound. Nothing is
    // allocated: the budget is only semaphore arithmetic.
    let max = u32::MAX as usize;
    let budget = RequestBufferBudgetProbe::new(UNIT, 2 * max + 2);
    let total = budget.available_bytes();
    assert_eq!(budget.buffered_request_body_ceiling(2 * max), max);
    assert!(budget.try_reserve(max + 1).is_none());
    assert_eq!(budget.available_bytes(), total, "a refusal takes nothing");
    let permit = budget.try_reserve(max).expect("one full permit");
    assert_eq!(permit.reserved_bytes(), max);
    assert_eq!(budget.available_bytes(), total - max);
    drop(permit);
    assert_eq!(budget.available_bytes(), total, "release returns it all");
}

#[tokio::test]
async fn staged_decoded_plaintext_stays_charged_until_its_transform_emits_it() {
    use ferrum_edge::_test_support::{ResponseBufferBudgetProbe, staged_decode_charge_for_test};
    // `compression`'s fallback decode stages plaintext on the request context
    // before the transform that emits it runs; its decode charge travels with
    // it, survives context clones, and is handed to the replacement scope.
    let probe = ResponseBufferBudgetProbe::new(UNIT, 16 * UNIT);
    let total = probe.available_bytes();
    let staged = staged_decode_charge_for_test(&probe, 3 * UNIT)
        .await
        .expect("staged");
    assert_eq!(staged.available_while_staged, total - 3 * UNIT);
    assert_eq!(
        staged.available_after_clone_dropped, staged.available_while_staged,
        "a dropped context clone must not release the staged charge"
    );
    assert_eq!(
        staged.available_after_emit, staged.available_while_staged,
        "the emitted plaintext stays charged until the buffered charge covers it"
    );
    assert_eq!(staged.available_after_release, total);
}

#[tokio::test]
async fn a_stalled_native_grpc_upload_holds_only_its_bytes() {
    use ferrum_edge::_test_support::{
        GrpcChargedCollectOutcomeForTest, collect_grpc_upload_for_test,
    };
    let budget = two_ceiling_budget();
    let total = budget.available_bytes();
    let (tx, rx) = tokio::sync::mpsc::channel::<FrameResult>(1);
    tx.send(data_frame(b"\0\0\0\0\x05hello".to_vec()))
        .await
        .expect("first frame");
    let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut collect = Box::pin(collect_grpc_upload_for_test(body, &budget, 4 * UNIT));
    assert!(futures::poll!(collect.as_mut()).is_pending());
    assert_eq!(
        budget.available_bytes(),
        total - 10,
        "a stalled gRPC upload holds only the bytes it has sent"
    );
    drop(tx);
    assert_eq!(
        collect.await,
        GrpcChargedCollectOutcomeForTest::Collected(10)
    );
    assert_eq!(budget.available_bytes(), total);
}

#[tokio::test]
async fn a_native_grpc_upload_the_budget_cannot_cover_is_a_capacity_refusal() {
    use ferrum_edge::_test_support::{
        GrpcChargedCollectOutcomeForTest, collect_grpc_upload_for_test,
    };
    let budget = two_ceiling_budget();
    let held = budget
        .try_reserve(budget.available_bytes())
        .expect("other uploads hold the budget");
    let body = complete_body(vec![data_frame(vec![0u8; 64])]);
    let outcome = collect_grpc_upload_for_test(body, &budget, 4 * UNIT).await;
    // A distinct capacity refusal, not the oversize RESOURCE_EXHAUSTED: the
    // handler answers it with the gateway-local capacity terminal before any
    // dispatch, so it is never retried or charged to the backend.
    assert_eq!(
        outcome,
        GrpcChargedCollectOutcomeForTest::BufferCapacityExceeded
    );
    drop(held);

    // Over the gRPC ceiling stays the oversize RESOURCE_EXHAUSTED, with its own
    // message.
    let body = complete_body(vec![data_frame(vec![0u8; 101])]);
    let outcome = collect_grpc_upload_for_test(body, &budget, 100).await;
    let expected = GrpcChargedCollectOutcomeForTest::ResourceExhausted(String::from(
        "gRPC request payload size exceeds maximum of 100 bytes",
    ));
    assert_eq!(outcome, expected);
}

#[test]
fn both_native_grpc_collects_answer_a_capacity_refusal_before_dispatch() {
    // The buffered native-gRPC collect's capacity refusal keeps its own type
    // and is answered with the same gateway-local capacity terminal as every
    // other buffered request, before dispatch: it never becomes a
    // `GrpcProxyError` that the retry loop or the backend classifier sees.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let arms: Vec<&str> = proxy
        .split("Err(grpc_proxy::GrpcRequestBodyCollectError::BufferCapacityExceeded) => {")
        .skip(1)
        .collect();
    assert_eq!(
        arms.len(),
        2,
        "the split and the mixed native-gRPC collects"
    );
    for arm in arms {
        let arm = &arm[..arm.find("return Ok(response);").expect("bounded arm")];
        assert!(arm.contains("build_request_buffer_capacity_response("));
        assert!(arm.contains("cb_probe.release_neutral();"));
        assert!(!arm.contains("GrpcProxyError"));
    }
}

#[test]
fn every_request_buffer_capacity_refusal_selects_the_gateway_capacity_terminal() {
    // A capacity refusal that runs reject hooks or the response pipeline marks
    // the gateway-capacity terminal first, as the request-decode refusal does,
    // so a route response-size limit or a rejection-replacement hook cannot
    // turn the fixed `503` into a policy failure. Behavioural proof:
    // `functional_request_buffer_budget_test`.
    const MARK: &str = "ctx.mark_gateway_capacity_response_selected();";
    const TERMINAL: &str = "finalize_terminal_request_body_read_rejection(";
    const REJECT: &str = "boxed_finalize_reject_response(";
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let mut reject_pipeline_sites = 0;
    for (index, _) in proxy.match_indices("REQUEST_BUFFER_OVERLOAD_BODY") {
        let before = &proxy[..index];
        let start = before.char_indices().rev().nth(900).map_or(0, |(i, _)| i);
        let window = &before[start..];
        if window.contains(TERMINAL) || window.contains(REJECT) {
            reject_pipeline_sites += 1;
            assert!(
                window.contains(MARK),
                "an unmarked capacity refusal: {window}"
            );
        }
    }
    assert_eq!(
        reject_pipeline_sites, 3,
        "a new reject-pipeline capacity refusal must be added to this guard"
    );
    // Dispatch-stage refusals reach the response pipeline as a backend
    // response, which marks them before any response hook.
    let dispatch = proxy
        .split("let capacity_class = Some(")
        .nth(1)
        .expect("dispatch outcome");
    let dispatch = &dispatch[..dispatch.find("let mut response_status").expect("bounded")];
    assert!(dispatch.contains("backend_resp.error_class == capacity_class"));
    assert!(dispatch.contains(MARK));

    let server = include_str!("../../../src/http3/server.rs");
    let finalize = server
        .split("fn boxed_finalize_h3_request_buffer_capacity_rejection<'a>(")
        .nth(1)
        .expect("native H3 capacity finalizer")
        .split("\n}\n")
        .next()
        .expect("bounded finalizer");
    assert!(finalize.contains(MARK));

    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let refusal = bridge
        .split("async fn write_bridge_upload_refusal<S>(")
        .nth(1)
        .expect("bridge refusal writer")
        .split("\n}\n")
        .next()
        .expect("bounded writer");
    let marked = refusal.find(MARK).expect("marked");
    let rejected = refusal.find("write_final_body_reject(").expect("reject");
    assert!(marked < rejected);
}

#[test]
fn a_dispatch_stage_capacity_terminal_takes_the_gateway_terminal_hook_path() {
    // Its body transforms are skipped, so its `after_proxy` hooks must run on
    // the gateway-terminal reject path (replacers skipped, rejection marker
    // set) rather than the ordinary backend-response chain, where
    // `compression` could commit a coding the skipped encoder never applies.
    // Behavioural proof: `functional_request_buffer_budget_test`.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let pipeline = proxy
        .split("let capacity_class = Some(")
        .nth(1)
        .expect("dispatch-stage capacity mark");
    let gate = "if ctx.gateway_capacity_response_selected()\n            \
                && let ResponseBody::Buffered(capacity_body) = &mut response_body";
    let gated = pipeline.find(gate).expect("capacity terminal gate");
    let hooks = pipeline
        .find("boxed_after_proxy_hooks_to_gateway_error_terminal(")
        .expect("gateway-terminal hooks");
    let ordinary = pipeline
        .find("run_after_proxy_hooks(&plugins, &mut ctx, response_status")
        .expect("ordinary hooks");
    assert!(gated < hooks && hooks < ordinary);
    let normalize = pipeline
        .find("crate::plugins::normalize_response_body_for_inspection(")
        .expect("response normalization");
    let skipped = pipeline
        .find("&& !ctx.gateway_capacity_response_selected()\n        && !plugins.is_empty()")
        .expect("normalization skips a capacity terminal");
    assert!(skipped < normalize);

    let factory = proxy
        .split("fn boxed_after_proxy_hooks_to_gateway_error_terminal<'a>(")
        .nth(1)
        .expect("boxing factory")
        .split("\n}\n")
        .next()
        .expect("bounded factory");
    assert!(factory.contains("Box::pin(async move {"));
}
