//! The H3 cross-protocol bridge must reach the SAME buffer/stream answer the
//! H1/H2 dispatch and the native H3 refined path reach for the same response
//! (issues #5097, #5099).
//!
//! Both properties are about ORDER and COUPLING inside one long `async fn`, and
//! neither is observable without a live QUIC frontend plus a live HTTP origin.
//! They are asserted structurally over the production source, the technique
//! `dp_config_admission_sites_tests.rs` already uses, so a refactor that moves
//! the refinement back behind `after_proxy` — or re-couples the response
//! decision to retry configuration — fails here instead of silently reframing
//! (or stalling) event streams in production.

const CROSS_PROTOCOL: &str = include_str!("../../../src/http3/cross_protocol.rs");
const HTTP3_SERVER: &str = include_str!("../../../src/http3/server.rs");

/// The bridge's plain H3→HTTP dispatch, from its signature to the gRPC one.
fn dispatch_plain_body() -> &'static str {
    let start = CROSS_PROTOCOL
        .find("async fn dispatch_plain<S>")
        .expect("dispatch_plain not found");
    let tail = &CROSS_PROTOCOL[start..];
    let end = tail
        .find("\n#[allow(clippy::too_many_arguments)]\nasync fn dispatch_grpc<S>")
        .expect("end of dispatch_plain not found");
    &tail[..end]
}

/// The buffer/stream refinement answers a question about the BACKEND's chosen
/// representation, so it must run over the backend's own header map.
///
/// Running it after `after_proxy` asked the chain about a map the gateway had
/// already rewritten: an `sse` instance with `wrap_non_sse_responses` relabels
/// the response `Content-Type` to `text/event-stream` in `after_proxy`, and the
/// same instance then reports that it has nothing to do with an already-SSE
/// response — so the body was released and streamed out unframed under exactly
/// the label the wrap was supposed to fill.
#[test]
fn h3_plain_bridge_refines_the_response_decision_before_after_proxy() {
    let body = dispatch_plain_body();
    let stamp = body
        .find("stamp_h3_original_response_metadata(ctx, status, &response_headers)")
        .expect("the pristine backend response stamp");
    let refine = body
        .find("crate::proxy::refine_stream_response_for_content_type(")
        .expect("the shared buffer/stream refinement");
    let after_proxy = body
        .find("crate::proxy::run_after_proxy_hooks(plugins, ctx, status, &mut response_headers)")
        .expect("the after_proxy chain");

    assert!(
        stamp < refine,
        "the refinement must see the stamped pristine response metadata"
    );
    assert!(
        refine < after_proxy,
        "the H3 bridge must refine the buffer/stream decision BEFORE `after_proxy` \
         can rewrite the response headers it decides from — this is the ordering \
         the H1/H2 dispatch and the native H3 path already use"
    );
}

/// The sibling that carries the same ordering invariant: the native H3 refined
/// path stamps the pristine backend metadata and refines from it, ahead of its
/// own response-header phase.
///
/// The H1/H2 dispatch has no ordering to preserve — its refinement lives inside
/// backend dispatch, which returns to the handler before the response-header
/// phase runs `run_after_proxy_hooks` at all — so it is named here rather than
/// asserted. The bridge was the one path that had folded the two together.
#[test]
fn the_native_h3_sibling_also_refines_from_the_pristine_backend_headers() {
    let stamp = HTTP3_SERVER
        .find("stamp_h3_original_response_metadata(ctx, response_status, &response_headers)")
        .expect("native H3 refined-path stamp");
    let refine = HTTP3_SERVER
        .find("crate::proxy::refine_stream_response_for_content_type(")
        .expect("native H3 refined-path refinement");
    assert!(
        stamp < refine,
        "the native H3 refined path must stamp before it refines"
    );
}

/// Retry configuration must not force the RESPONSE onto the buffered path.
///
/// This bridge decides every retry from the response STATUS the instant `send()`
/// resolves — with an explicitly empty `BackendResponse` body — and breaks out
/// of the loop before a single body byte is read. Replay therefore needs the
/// REQUEST body preserved, never the response buffered. The gRPC arm of this
/// same file already carries that correction (`stream_grpc_response` is
/// deliberately not gated on `grpc_has_retry`); the plain arm used to keep the
/// coupling, so a default `sse` proxy with `retry.max_retries` set collected an
/// origin event stream to EOF for an H3 client while streaming it for H1/H2.
#[test]
fn h3_plain_bridge_response_buffering_is_not_gated_on_retry_configuration() {
    let body = dispatch_plain_body();
    let marker = "let should_buffer_response = !crate::proxy::should_stream_response_body(";
    assert!(
        body.contains(marker),
        "the plain bridge's pre-flight response decision must come from \
         `should_stream_response_body` alone"
    );

    let assignment_start = body
        .find("let should_buffer_response = ")
        .expect("pre-flight response decision");
    let assignment = &body[assignment_start..];
    let assignment_end = assignment
        .find(";\n")
        .expect("end of the pre-flight response buffering decision");
    let assignment = &assignment[..assignment_end];
    assert!(
        !assignment.contains("retry_config.is_some()"),
        "regression: the plain H3 bridge's response buffering is gated on retry \
         configuration again. Retry replay needs the REQUEST body retained, not \
         the response collected; the retry decision is already taken from the \
         response status before any body byte is read. Offending assignment:\n{assignment}"
    );
}

/// The retry-time refinement still receives the marked decision context, so an
/// active buffering plugin gets its per-response say once headers arrive.
#[test]
fn h3_plain_bridge_still_uses_the_marked_retry_decision_context() {
    let body = dispatch_plain_body();
    assert!(
        body.contains("crate::proxy::retry_response_decision_context(&*ctx)"),
        "retry-enabled H3 plain dispatch must construct the shared marked context"
    );
    assert!(
        body.contains("Some(response_decision_ctx)"),
        "the refinement must receive the marked retry context"
    );
}
