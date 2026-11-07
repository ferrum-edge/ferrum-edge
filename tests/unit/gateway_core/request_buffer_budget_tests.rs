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
            reserved <= (2 * collector.len()).div_ceil(UNIT) * UNIT,
            "the charge must track retained bytes, not the ceiling"
        );
        if reserved != previous_reserved {
            growths += 1;
            previous_reserved = reserved;
        }
    }
    assert!(
        growths <= 4,
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
    assert_eq!(permit.reserved_bytes(), UNIT);
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
    assert!(body.is_empty(), "the uncovered decoded body must be dropped");
    assert_eq!(body.capacity(), 0);
    drop(charge);
    assert_eq!(budget.available_bytes(), collected_charge);
    drop(other);
    assert_eq!(budget.available_bytes(), total);
}

#[test]
fn every_body_replacement_is_charged_before_a_later_phase_keeps_it() {
    // Normalizers and request-body transforms can replace the collected body
    // with a larger one. Each replacement point grows the charge before the
    // next await, on both protocol paths.
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
        .find(".into_plugin_result(ctx);")
        .expect("normalizer call");
    let covered = normalization
        .find("if !charge_covers(charge.as_deref_mut(), body.capacity()) {")
        .expect("normalized body is charged");
    assert!(normalized < covered);
    assert!(proxy.contains("buffered.budget.as_mut(),\n"));
    assert!(server.contains("retained_request_charge.as_mut(),\n"));
    assert_eq!(proxy.matches("if !charge_covers(").count(), 6);
    assert_eq!(proxy.matches("if !request_buffer_permit.cover(").count(), 1);
    assert_eq!(server.matches("if !charge_covers(").count(), 3);
    assert_eq!(
        bridge
            .matches("crate::proxy::response_buffer_budget::charge_covers(")
            .count(),
        1
    );
}
